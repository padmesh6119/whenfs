//! Query the causal graph.
//!
//!   chronicle log   <path>        full history of a file, oldest first
//!   chronicle blame <path>        who last wrote it, and why they existed
//!   chronicle tree  <pid>         everything a process and its children touched
//!   chronicle stat                graph size
//!
//! Database location, in order: --db <path>, $WHENFS_GRAPH, ./graph.db,
//! /var/lib/whenfs/graph.db.

use std::env;
use std::path::{Path, PathBuf};
use whenfs::graph::{FileEvent, Graph};

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
    let start = match g.live_start_ts(pid) {
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
            println!("{BOLD}process tree from pid {pid}{RESET}");
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
  chronicle tree  <pid>      everything a process tree touched
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
    let mut rest: Vec<String> = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        if argv[i] == "--db" && i + 1 < argv.len() {
            db_arg = Some(argv[i + 1].clone());
            i += 2;
        } else {
            rest.push(argv[i].clone());
            i += 1;
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
        _ => usage(),
    }
}
