// Query tool over whodidd's event log.
//
//   whodid list <log-path> <target-path>
//   whodid diff <log-path> <snap-root> <when-mount> <live-root> <target-path>
//
// `diff` is the join that doesn't exist anywhere else: for each logged
// change to a file, find the snapshot immediately before it and the one
// immediately after, then diff the file across those two points in time.
// Snapshot names and event timestamps share one format
// (whenfs::time_expr::SNAPSHOT_FMT, zero-padded, Local time), so bracketing
// is a plain lexical comparison — no parsing required.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

struct Event {
    ts: String,
    path: String,
    op: String,
    pid: String,
    comm: String,
    exe: String,
    cmdline: String,
}

/// Extract a `"key":"value"` or `"key":value` field from one JSON line.
/// Only handles our own escaper's output — not general JSON.
fn field(line: &str, key: &str) -> String {
    let needle = format!("\"{key}\":");
    let Some(start) = line.find(&needle) else {
        return String::new();
    };
    let rest = &line[start + needle.len()..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = stripped.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(next) = chars.next() {
                        out.push(match next {
                            'n' => '\n',
                            't' => '\t',
                            '"' => '"',
                            '\\' => '\\',
                            other => other,
                        });
                    }
                }
                '"' => break,
                c => out.push(c),
            }
        }
        out
    } else {
        rest.split([',', '}']).next().unwrap_or("").to_string()
    }
}

fn parse_line(line: &str) -> Option<Event> {
    if line.trim().is_empty() {
        return None;
    }
    Some(Event {
        ts: field(line, "ts"),
        path: field(line, "path"),
        op: field(line, "op"),
        pid: field(line, "pid"),
        comm: field(line, "comm"),
        exe: field(line, "exe"),
        cmdline: field(line, "cmdline"),
    })
}

fn load_events(log_path: &str, target: &str) -> Vec<Event> {
    let target_abs = fs::canonicalize(target)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| target.to_string());

    let content = fs::read_to_string(log_path).unwrap_or_default();
    content
        .lines()
        .filter_map(parse_line)
        .filter(|e| e.path == target || e.path == target_abs)
        .collect()
}

fn cmd_list(log_path: &str, target: &str) {
    let mut events = load_events(log_path, target);
    events.sort_by(|a, b| a.ts.cmp(&b.ts));
    if events.is_empty() {
        println!("no recorded changes to {target}");
        return;
    }
    for e in &events {
        let who = if e.comm.is_empty() {
            e.exe.as_str()
        } else {
            e.comm.as_str()
        };
        println!(
            "{}  {:<10} pid={:<7} {}  ({})",
            e.ts, e.op, e.pid, who, e.cmdline
        );
    }
}

/// Snapshot dir names sort lexically because they're zero-padded and share
/// SNAPSHOT_FMT with event timestamps — no timestamp parsing needed here.
fn bracket(snap_root: &str, ts: &str) -> (Option<String>, Option<String>) {
    let mut names: Vec<String> = fs::read_dir(snap_root)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();

    let before = names.iter().rev().find(|n| n.as_str() <= ts).cloned();
    let after = names.iter().find(|n| n.as_str() > ts).cloned();
    (before, after)
}

fn cmd_diff(log_path: &str, snap_root: &str, when_mount: &str, live_root: &str, target: &str) {
    let mut events = load_events(log_path, target);
    events.sort_by(|a, b| a.ts.cmp(&b.ts));
    // Two independent fanotify groups can each log a distinct op (e.g.
    // "create" from the FID group, "close_write" from the legacy group)
    // for the same real-world write, at one-second timestamp granularity.
    // bracket() depends only on ts, so same-ts entries always produce an
    // identical diff — collapsing them loses no distinct diff output,
    // only the redundant repeat. `whodid list` intentionally does NOT do
    // this: it should still show every distinct logged op.
    events.dedup_by(|a, b| a.ts == b.ts);
    if events.is_empty() {
        println!("no recorded changes to {target}");
        return;
    }

    // `target` is a path under `live_root`; snapshot dirs mirror live_root's
    // *contents*, not its full path, so the join must strip live_root first.
    let rel = Path::new(target)
        .strip_prefix(live_root)
        .unwrap_or(Path::new(target));

    for e in &events {
        let (before, after) = bracket(snap_root, &e.ts);
        let who = if e.comm.is_empty() {
            e.exe.as_str()
        } else {
            e.comm.as_str()
        };
        println!(
            "\n=== {} — {} (pid {}, {}) ===",
            e.ts, who, e.pid, e.cmdline
        );

        match (before, after) {
            (Some(b), Some(a)) => {
                let p1 = Path::new(when_mount).join(&b).join(rel);
                let p2 = Path::new(when_mount).join(&a).join(rel);
                let out = Command::new("diff").arg("-u").arg(&p1).arg(&p2).output();
                match out {
                    Ok(o) if !o.stdout.is_empty() => {
                        print!("{}", String::from_utf8_lossy(&o.stdout));
                    }
                    Ok(_) => println!("(no content difference between bracketing snapshots)"),
                    Err(err) => println!("(diff failed: {err})"),
                }
            }
            (before, after) => {
                println!(
                    "(insufficient bracketing snapshots — before={:?} after={:?})",
                    before, after
                );
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let usage = || {
        eprintln!("usage:");
        eprintln!("  whodid list <log-path> <target-path>");
        eprintln!("  whodid diff <log-path> <snap-root> <when-mount> <live-root> <target-path>");
        std::process::exit(1);
    };

    match args.get(1).map(String::as_str) {
        Some("list") if args.len() == 4 => cmd_list(&args[2], &args[3]),
        Some("diff") if args.len() == 7 => {
            cmd_diff(&args[2], &args[3], &args[4], &args[5], &args[6])
        }
        _ => usage(),
    }
}
