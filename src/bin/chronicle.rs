//! Query the causal graph.
//!
//!   chronicle log   <path>        full history of a file, oldest first
//!   chronicle blame <path>        who last wrote it, and why they existed
//!   chronicle tree  <pid>         processes under one that wrote anything
//!   chronicle stat                graph size
//!
//! Database location, in order: --db <path>, $WHENFS_GRAPH, ./graph.db,
//! /var/lib/whenfs/graph.db.

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use whenfs::graph::{FileEvent, Graph};
use whenfs::revert::{self, Step};

const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

fn find_db(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(PathBuf::from(p));
    }
    if let Ok(p) = env::var("WHENFS_GRAPH") {
        return Some(PathBuf::from(p));
    }
    for cand in ["graph.db", "/var/lib/whenfs/graph.db"] {
        let p = Path::new(cand);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Absolute where possible: the daemon records absolute paths, so a
/// relative argument would silently match nothing.
fn normalize(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

fn who(e: &FileEvent) -> String {
    if !e.comm.is_empty() {
        return e.comm.clone();
    }
    if !e.exe.is_empty() {
        return e.exe.clone();
    }
    // Two different failures, worth distinguishing rather than collapsing
    // into one word. Either is shown loudly rather than left blank, because
    // a write nobody can account for is exactly the interesting case.
    if e.proc_start.is_some() {
        // The process is known -- it has a row, a parent, a place in the
        // tree -- but it exited before /proc could be read for its name.
        // Its ancestry still explains the write.
        format!("{YELLOW}<unnamed>{RESET}")
    } else {
        // No process at all: nothing in the graph accounts for this write.
        format!("{YELLOW}<unattributed>{RESET}")
    }
}

fn print_event(e: &FileEvent) {
    let detail = if e.cmdline.is_empty() {
        String::new()
    } else {
        format!("  {DIM}{}{RESET}", e.cmdline)
    };
    // Only FAN_RENAME carries both ends; without it a rename is two
    // unlinked events and there is nothing to show here.
    if let Some(from) = e.other_path.as_deref() {
        println!(
            "  {CYAN}{}{RESET}  {:<12} {}  {DIM}pid {}{RESET}{}\n      {DIM}renamed from {}{RESET}",
            e.ts,
            e.op,
            who(e),
            e.pid,
            detail,
            from
        );
        return;
    }
    println!(
        "  {CYAN}{}{RESET}  {:<12} {}  {DIM}pid {}{RESET}{}",
        e.ts,
        e.op,
        who(e),
        e.pid,
        detail
    );
}

fn cmd_log(g: &Graph, path: &str) {
    let p = normalize(path);
    match g.log_file(&p) {
        Ok(events) if events.is_empty() => {
            println!("no recorded history for {p}");
        }
        Ok(events) => {
            println!("{BOLD}{p}{RESET}");
            for e in &events {
                print_event(e);
            }
        }
        Err(e) => eprintln!("query failed: {e}"),
    }
}

fn cmd_blame(g: &Graph, path: &str) {
    let p = normalize(path);
    let last = match g.blame(&p) {
        Ok(Some(e)) => e,
        Ok(None) => {
            println!("no recorded history for {p}");
            return;
        }
        Err(e) => {
            eprintln!("query failed: {e}");
            return;
        }
    };

    println!("{BOLD}{p}{RESET}");
    print_event(&last);

    // The ancestry chain is the part that turns attribution into
    // explanation: not just "sh wrote it" but the chain of commands that
    // led to sh existing at all. Uses the event's own proc_start so a
    // recycled pid can't walk up the wrong process's parents.
    let Some(start) = last.proc_start.as_deref() else {
        println!("  {DIM}(writer was never identified — no ancestry){RESET}");
        return;
    };
    match g.ancestry(last.pid, start) {
        Ok(chain) if chain.len() > 1 => {
            let names: Vec<String> = chain
                .iter()
                .map(|p| {
                    if p.comm.is_empty() {
                        format!("pid {}", p.pid)
                    } else {
                        p.comm.clone()
                    }
                })
                .collect();
            println!("  {DIM}because:{RESET}    {}", names.join(" ← "));
            // The chain root is always init, which explains nothing. The
            // useful answer is the nearest ancestor that still knows what
            // it was invoked as -- walking outward from the writer, the
            // first one carrying a real command line.
            if let Some(origin) = chain.iter().skip(1).find(|p| !p.cmdline.is_empty()) {
                println!("  {DIM}started by:{RESET} {}", origin.cmdline);
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("ancestry query failed: {e}"),
    }
}

fn cmd_tree(g: &Graph, pid_arg: &str) {
    let pid: i32 = match pid_arg.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("not a pid: {pid_arg}");
            return;
        }
    };
    // Fall back to the latest incarnation: asking about a process that
    // has already finished is the common case, not an error.
    let start = match g.live_start_ts(pid).and_then(|s| {
        if s.is_some() {
            Ok(s)
        } else {
            g.latest_start_ts(pid)
        }
    }) {
        Ok(Some(s)) => s,
        Ok(None) => {
            println!("no live process recorded with pid {pid}");
            return;
        }
        Err(e) => {
            eprintln!("query failed: {e}");
            return;
        }
    };
    match g.descendants(pid, &start) {
        Ok(procs) if procs.is_empty() => {
            println!("no recorded process tree for pid {pid}");
        }
        Ok(procs) => {
            // Not every process it spawned: processes reach the graph only
            // by writing something, or by being an ancestor of something
            // that did. A shell pipeline that touched no files leaves no
            // trace here, by design -- see whenfs::proctree.
            println!(
                "{BOLD}recorded processes under pid {pid}{RESET}  {DIM}(writers and their ancestors){RESET}"
            );
            for p in &procs {
                println!(
                    "  {CYAN}{}{RESET}  {}  {DIM}{}{RESET}",
                    p.pid, p.comm, p.cmdline
                );
            }
        }
        Err(e) => eprintln!("query failed: {e}"),
    }
}

/// Run a command and report everything it and its descendants touched.
///
/// This is the whole point of recording lineage. A time window alone is
/// useless here -- a browser cache and a dozen system daemons are writing
/// throughout -- so the manifest is scoped by process tree, which is why
/// the fork edge had to be correct before this could exist at all.
///
/// Requires whodidd to be running: this only reads the graph, it does not
/// do any tracing itself. The command runs completely normally, unmodified
/// and unsandboxed; the daemon is already watching everything anyway.
fn cmd_trace(g: &Graph, argv: &[String]) {
    use std::process::Command;

    let Some((prog, args)) = argv.split_first() else {
        eprintln!("nothing to run");
        return;
    };

    let started = std::time::Instant::now();
    let mut child = match Command::new(prog).args(args).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot run {prog}: {e}");
            return;
        }
    };
    let pid = child.id() as i32;

    // The daemon learns about this process asynchronously, over a separate
    // socket. Give it a moment to see the fork -- but keep looking after
    // the child exits too, since a fast command can finish before its own
    // fork message has been read.
    let mut start_ts = None;
    for _ in 0..40 {
        if let Ok(Some(s)) = g.latest_start_ts(pid) {
            start_ts = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    let status = child.wait();
    let elapsed = started.elapsed();

    // Writes are recorded asynchronously as well; without a settle the
    // manifest reports fewer files than the command actually touched.
    std::thread::sleep(std::time::Duration::from_millis(600));
    if start_ts.is_none() {
        start_ts = g.latest_start_ts(pid).ok().flatten();
    }

    let code = match status {
        Ok(s) => s.code().map(|c| c.to_string()).unwrap_or("signal".into()),
        Err(e) => format!("wait failed: {e}"),
    };
    println!(
        "\n{BOLD}traced{RESET} {}  {DIM}exit {}, {:.1}s, pid {}{RESET}",
        argv.join(" "),
        code,
        elapsed.as_secs_f32(),
        pid
    );

    let Some(start) = start_ts else {
        eprintln!(
            "  {YELLOW}the daemon never recorded this process{RESET}
  Is whodidd running, and watching the filesystem this ran on?"
        );
        return;
    };

    let events = match g.events_by_tree(pid, &start) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("query failed: {e}");
            return;
        }
    };
    // Counted from the events, not from the process table. Processes are
    // persisted lazily -- only those that wrote, plus their ancestors --
    // so a table count would answer a different question than the one the
    // label asks.
    let writers: std::collections::HashSet<i32> = events.iter().map(|e| e.pid).collect();
    let procs = writers.len();

    if events.is_empty() {
        println!("  {DIM}no recorded writes{RESET}  {DIM}({procs} processes){RESET}");
        return;
    }

    // One line per path, not per event: a single logical change usually
    // produces several (create, then modify, then close_write), and the
    // useful question is "what did this touch", not "how many syscalls".
    let mut order: Vec<String> = Vec::new();
    let mut ops: HashMap<String, Vec<String>> = HashMap::new();
    let mut by: HashMap<String, String> = HashMap::new();
    for e in &events {
        let entry = ops.entry(e.path.clone()).or_insert_with(|| {
            order.push(e.path.clone());
            Vec::new()
        });
        if !entry.contains(&e.op) {
            entry.push(e.op.clone());
        }
        by.entry(e.path.clone()).or_insert_with(|| who(e));
    }

    println!(
        "  {BOLD}{}{RESET} paths written by {BOLD}{}{RESET} processes\n",
        order.len(),
        procs
    );
    for path in &order {
        let o = ops.get(path).map(|v| v.join("+")).unwrap_or_default();
        let w = by.get(path).cloned().unwrap_or_default();
        println!("  {CYAN}{:<22}{RESET} {}  {DIM}{}{RESET}", o, path, w);
    }
    println!("\n  {DIM}undo:  chronicle revert {pid} --snap <dir> --live <dir>{RESET}");
}

/// Undo a traced command's writes.
///
/// Dry run unless `--apply` is passed. That default is not politeness: this
/// deletes and overwrites files, the plan is derived from a graph that has
/// already been wrong in five distinct ways this project has had to find,
/// and a plan that looks wrong is far cheaper to read than to recover from.
fn cmd_revert(g: &Graph, pid_arg: &str, snap_root: &Path, live_root: &Path, apply: bool) {
    let Ok(pid) = pid_arg.parse::<i32>() else {
        eprintln!("not a pid: {pid_arg}");
        return;
    };
    let Ok(Some(start)) = g.latest_start_ts(pid) else {
        eprintln!("no process recorded with pid {pid}");
        return;
    };
    let events = match g.events_by_tree(pid, &start) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("query failed: {e}");
            return;
        }
    };
    if events.is_empty() {
        println!("nothing recorded for pid {pid} — nothing to undo");
        return;
    }

    let mut snapshots: Vec<String> = std::fs::read_dir(snap_root)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    snapshots.sort();
    if snapshots.is_empty() {
        eprintln!(
            "no snapshots under {} — nothing to restore from",
            snap_root.display()
        );
        return;
    }

    let steps = revert::plan(&events, &snapshots, snap_root, live_root);

    let (mut restores, mut removes, mut skips) = (0, 0, 0);
    println!(
        "\n{BOLD}{}{RESET} undo plan for pid {pid}\n",
        if apply { "applying" } else { "dry run —" }
    );
    for st in &steps {
        match st {
            Step::Restore { path, from } => {
                restores += 1;
                let snap = from
                    .strip_prefix(snap_root)
                    .ok()
                    .and_then(|p| {
                        p.components()
                            .next()
                            .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    })
                    .unwrap_or_default();
                println!(
                    "  {CYAN}restore{RESET}  {}  {DIM}from {}{RESET}",
                    path.display(),
                    snap
                );
            }
            Step::Remove { path } => {
                removes += 1;
                println!(
                    "  {YELLOW}remove {RESET}  {}  {DIM}(created by this command){RESET}",
                    path.display()
                );
            }
            Step::Skip { path, why } => {
                skips += 1;
                println!("  {DIM}skip    {}  — {}{RESET}", path.display(), why);
            }
        }
    }
    println!("\n  {restores} to restore, {removes} to remove, {skips} skipped");

    if !apply {
        println!("  {DIM}dry run: nothing was changed. Re-run with --apply.{RESET}");
        return;
    }

    let (mut ok, mut failed, mut kept) = (0, 0, 0);
    for st in &steps {
        let r = match st {
            Step::Restore { path, from } => path
                .parent()
                .map(std::fs::create_dir_all)
                .unwrap_or(Ok(()))
                .and_then(|_| std::fs::copy(from, path).map(|_| ())),
            Step::Remove { path } => {
                // A command that ran `mkdir -p` created directories, and
                // unlink does not remove those. remove_dir (never
                // remove_dir_all) is the right tool: it refuses a
                // non-empty directory, which is exactly the desired
                // behaviour when something the command did not create is
                // sitting inside one it did.
                let is_dir = std::fs::symlink_metadata(path)
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                let r = if is_dir {
                    std::fs::remove_dir(path)
                } else {
                    std::fs::remove_file(path)
                };
                match r {
                    // Already gone is the desired end state, not a failure.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    other => other,
                }
            }
            Step::Skip { .. } => continue,
        };
        match r {
            Ok(()) => ok += 1,
            Err(e) => {
                // A directory left standing because it still holds files
                // this command did not create is the guard working, not a
                // fault -- reporting it as a failure would train the user
                // to ignore real ones.
                let non_empty = matches!(st, Step::Remove { .. })
                    && st.path().is_dir()
                    && std::fs::read_dir(st.path())
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(false);
                if non_empty {
                    kept += 1;
                    println!(
                        "  {DIM}kept   {} — still holds files this command did not create{RESET}",
                        st.path().display()
                    );
                } else {
                    failed += 1;
                    eprintln!("  {YELLOW}failed{RESET} {}: {e}", st.path().display());
                }
            }
        }
    }
    if kept > 0 {
        println!("  {ok} applied, {kept} kept (not empty), {failed} failed");
    } else {
        println!("  {ok} applied, {failed} failed");
    }
}

/// Drop history older than a time expression.
///
/// Dry run unless `--apply`, for the same reason revert is: this destroys
/// history, and history is the only thing here that cannot be recomputed.
fn cmd_prune(g: &Graph, expr: &str, apply: bool, vacuum: bool) {
    // Reuses the /when path grammar, so retention reads the way the rest of
    // the system already does: `prune --before 30-days-ago`.
    let Some(target) = whenfs::time_expr::resolve_target(expr, chrono::Local::now()) else {
        eprintln!("not a time expression: {expr}  (try: 30-days-ago, last-month, 2026-01-01)");
        return;
    };
    let cutoff = whenfs::time_expr::format_snapshot_name(target);

    let (procs, events) = match g.prune_preview(&cutoff) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("query failed: {e}");
            return;
        }
    };
    let (have_p, have_e) = g.counts().unwrap_or((0, 0));

    println!(
        "\n{BOLD}{}{RESET} history before {CYAN}{cutoff}{RESET}",
        if apply { "pruning" } else { "dry run —" }
    );
    println!("  {events} of {have_e} events");
    println!("  {procs} of {have_p} processes");
    if !apply {
        println!("  {DIM}dry run: nothing was deleted. Re-run with --apply.{RESET}");
        return;
    }
    match g.prune(&cutoff) {
        Ok((p, e)) => println!("  deleted {e} events, {p} processes"),
        Err(e) => {
            eprintln!("prune failed: {e}");
            return;
        }
    }
    if vacuum {
        print!("  reclaiming space... ");
        match g.vacuum() {
            Ok(()) => println!("done"),
            Err(e) => println!("failed: {e}"),
        }
    } else {
        println!("  {DIM}space is reused, not returned to the disk — add --vacuum for that{RESET}");
    }
}

fn cmd_stat(g: &Graph, db: &Path) {
    match g.counts() {
        Ok((procs, events)) => {
            println!("{BOLD}graph{RESET}   {}", db.display());
            println!("  processes  {procs}");
            println!("  events     {events}");
        }
        Err(e) => eprintln!("query failed: {e}"),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage:
  chronicle log   <path>     full history of a file
  chronicle blame <path>     who last wrote it, and why
  chronicle tree  <pid>      processes under one that wrote anything
  chronicle trace -- <cmd>   run a command, report every file it touched
  chronicle revert <pid>     undo a traced command (dry run unless --apply)
                             needs --snap <dir> --live <dir>
  chronicle prune --before <when>   drop history older than that
                             (dry run unless --apply; --vacuum reclaims)
  chronicle stat             graph size

  --db <path>                database location
                             (else $WHENFS_GRAPH, ./graph.db,
                              /var/lib/whenfs/graph.db)"
    );
    std::process::exit(1)
}

fn main() {
    let argv: Vec<String> = env::args().collect();

    let mut db_arg: Option<String> = None;
    let mut snap_arg: Option<String> = None;
    let mut live_arg: Option<String> = None;
    let mut apply = false;
    let mut vacuum = false;
    let mut before_arg: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        // Everything after `trace` belongs to the traced command, so its
        // flags must never be eaten as ours.
        if rest.first().map(String::as_str) == Some("trace") {
            rest.push(argv[i].clone());
            i += 1;
            continue;
        }
        match argv[i].as_str() {
            "--db" if i + 1 < argv.len() => {
                db_arg = Some(argv[i + 1].clone());
                i += 2;
            }
            "--snap" if i + 1 < argv.len() => {
                snap_arg = Some(argv[i + 1].clone());
                i += 2;
            }
            "--live" if i + 1 < argv.len() => {
                live_arg = Some(argv[i + 1].clone());
                i += 2;
            }
            "--apply" => {
                apply = true;
                i += 1;
            }
            "--vacuum" => {
                vacuum = true;
                i += 1;
            }
            "--before" if i + 1 < argv.len() => {
                before_arg = Some(argv[i + 1].clone());
                i += 2;
            }
            _ => {
                rest.push(argv[i].clone());
                i += 1;
            }
        }
    }

    if rest.is_empty() {
        usage();
    }

    let db = match find_db(db_arg.as_deref()) {
        Some(p) => p,
        None => {
            eprintln!(
                "no graph database found. Is whodidd running?
Looked for: $WHENFS_GRAPH, ./graph.db, /var/lib/whenfs/graph.db"
            );
            std::process::exit(1);
        }
    };

    let g = match Graph::open(&db) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("cannot open {}: {e}", db.display());
            std::process::exit(1);
        }
    };

    match (rest[0].as_str(), rest.len()) {
        ("log", 2) => cmd_log(&g, &rest[1]),
        ("blame", 2) => cmd_blame(&g, &rest[1]),
        ("tree", 2) => cmd_tree(&g, &rest[1]),
        ("stat", 1) => cmd_stat(&g, &db),
        ("prune", 1) => {
            let Some(before) = before_arg.as_deref() else {
                eprintln!("prune needs --before <time-expression>, e.g. 30-days-ago");
                std::process::exit(1);
            };
            cmd_prune(&g, before, apply, vacuum);
        }
        ("revert", 2) => {
            let (Some(snap), Some(live)) = (snap_arg.as_deref(), live_arg.as_deref()) else {
                eprintln!("revert needs --snap <snapshot-dir> --live <watched-dir>");
                std::process::exit(1);
            };
            cmd_revert(&g, &rest[1], Path::new(snap), Path::new(live), apply);
        }
        ("trace", n) if n >= 2 => {
            // Everything after `trace` (and an optional `--`) is the
            // command, so its own flags are never parsed as ours.
            let start = if rest.get(1).map(String::as_str) == Some("--") {
                2
            } else {
                1
            };
            cmd_trace(&g, &rest[start..]);
        }
        _ => usage(),
    }
}
