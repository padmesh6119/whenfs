// Attribution daemon: watches a path via fanotify and appends one JSON line
// per filesystem event to a log file.
//
// Runs THREE independent watcher threads. The two fanotify groups each open
// their own append handle to the log (O_APPEND writes of a single small
// line are atomic at the syscall level, so no cross-thread locking is
// needed there); the third maintains a shared, mutex-protected process
// identity table both fanotify groups consult before falling back to a
// direct /proc read:
//
//   1. legacy_watcher  — FAN_MODIFY | FAN_CLOSE_WRITE, no FID reporting.
//      Live-verified: correctly attributes in-place-truncate writes to the
//      process that made them.
//
//   2. fid_watcher     — FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM |
//      FAN_MOVED_TO | FAN_ATTRIB, via FAN_REPORT_DFID_NAME. Live-verified,
//      including a real rename correctly attributed to `mv` rather than
//      the shell that invoked it. Events carry a parent-directory FID +
//      child filename instead of a usable fd, so the path is reconstructed
//      via open_by_handle_at() + reading the /proc/self/fd/<n> magic
//      symlink for the parent, then appending the filename.
//
//   3. proc_connector  — NETLINK_CONNECTOR, PROC_EVENT_FORK/EXEC/EXIT.
//      Two jobs. First, identity: captures a process's exe/comm/cmdline/uid
//      at the instant it execs (guaranteed alive then), so log_event() can
//      look it up rather than reading /proc/<pid> at event-processing time
//      — which a prior live run confirmed can race a short-lived process
//      straight into non-existence (a real `rm` lost its comm/cmdline that
//      way; the pid itself was still captured correctly). Falls back to a
//      direct /proc read for any pid the connector never saw exec (already
//      running before whodidd started) — same exposure as before, narrower.
//
//      Second, lineage: FORK gives the parent→child edge, which nothing
//      else on the system records. That edge is what upgrades attribution
//      into explanation — "sh wrote this" becomes "sh wrote this because
//      you ran that install script" — and it's the primitive the whole
//      causal graph (see whenfs::graph) is built on.
//
//      All three event types update only the in-memory tree. This machine
//      was measured at 16.8 forks/second at idle — 1.45 million a day, and
//      at 193 bytes a row that is 267 MiB/day of process table before a
//      single file event is recorded. Almost none of those processes ever
//      touch a file, so a process is written to SQLite the first time it
//      (or a descendant) produces a write worth attributing, together with
//      its unpersisted ancestors so blame still explains it.
//
// Two sinks, by design. The JSONL log is the append-only audit trail and
// what `whodid` reads; the SQLite graph beside it is the queryable index
// `chronicle` reads, holding the process tree and file events as a real
// DAG. Log plus materialised view, not duplicated state for its own sake.
// The graph is optional: if it can't be opened the daemon degrades to the
// previously live-verified JSONL-only behaviour rather than losing
// attribution entirely over a storage problem.
//
// Known gap this does NOT close: fanotify has no rename cookie linking a
// FAN_MOVED_FROM to its FAN_MOVED_TO the way inotify's IN_MOVED_FROM/TO
// pair does. The two are logged as independent events (op="moved_from" /
// op="moved_to"), not correlated into one "renamed X to Y" record. Doing
// that would mean buffering and matching by timing heuristics — not
// attempted here; each event stands alone in the log, which is still
// strictly more than legacy mode gave for these operations (nothing).
//
// Requires CAP_SYS_ADMIN (root) for the fanotify groups, CAP_NET_ADMIN for
// the connector socket — both satisfied simply by running as root.
//
// usage: whodidd <watch-path> <log-path>

use chrono::Local;
use std::env;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::mem;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use whenfs::graph::Graph;
use whenfs::proctree::{ProcInfo, ProcTree};

/// Event timestamps use the exact same format as snapshot directory names
/// (whenfs::time_expr::SNAPSHOT_FMT), Local time. This makes them directly,
/// lexically comparable to snapshot names with zero parsing — `whodid diff`
/// brackets an event between two snapshots with plain string comparison.
fn now_ts() -> String {
    whenfs::time_expr::format_snapshot_name(Local::now())
}

const BLOCKLIST_SUFFIXES: &[&str] = &[
    "/.git",
    "/target",
    "/.cache",
    "/node_modules",
    ".tmp",
    ".swp",
    ".lock",
];

fn is_blocked(path: &str) -> bool {
    BLOCKLIST_SUFFIXES.iter().any(|s| path.contains(s))
}

/// Our own pid. Every write this daemon makes -- the JSONL log, the SQLite
/// database and its -wal/-shm sidecars -- lands inside the mount it is
/// watching, so recording them creates an unbounded feedback loop: each
/// recorded event is itself a write, which produces another event.
///
/// This is not hypothetical. A live run produced 27231 events in about ten
/// seconds, of which 27214 (99.94%) were this daemon writing to
/// `events.jsonl` and `graph.db-wal`. Left in place it would fill the disk
/// on any machine it ran on persistently.
///
/// Suppressing by pid rather than by path is deliberate: it holds no matter
/// where the log and database are placed, and there is no case where the
/// daemon's own bookkeeping is worth attributing.
static SELF_PID: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

fn is_self(pid: i32) -> bool {
    *SELF_PID.get_or_init(|| std::process::id() as i32) == pid
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn read_proc_str(pid: i32, field: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/{field}"))
        .unwrap_or_default()
        .trim_end_matches('\n')
        .to_string()
}

fn read_cmdline(pid: i32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn read_exe(pid: i32) -> String {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read_uid(pid: i32) -> u32 {
    std::fs::metadata(format!("/proc/{pid}"))
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap_or(u32::MAX)
}

/// The parent pid from /proc/<pid>/stat.
///
/// Field 2 is the executable name in parentheses and may itself contain
/// spaces or parentheses, so the only safe parse is to seek past the final
/// ')' -- splitting the line on whitespace from the left corrupts on any
/// process whose name contains a space.
fn read_ppid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    // after ')' the fields are: state ppid ...
    after.split_whitespace().nth(1)?.parse().ok()
}

/// Seed the graph with every process already running, so writes by
/// long-lived processes are attributable rather than anonymous. See
/// Graph::record_existing for why the daemon's start time is used as
/// their start_ts.
/// Seed the in-memory tree with every process already running.
///
/// Without this the daemon only knows processes that fork after startup,
/// which on a real machine is a small minority of the things writing to
/// disk -- every long-running service, editor and browser is invisible and
/// their writes land unattributed.
///
/// Memory only: these are recorded on disk if and when one of them writes.
/// Persisting all ~400 up front was measurably wasteful, and the same
/// argument applies to them as to forks.
fn bootstrap_process_table(table: &ProcTable) {
    let start_ts = whenfs::graph::now_ts();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        eprintln!("whodidd: [proc] cannot scan /proc; pre-existing processes stay anonymous");
        return;
    };

    let mut seeded = 0usize;
    let mut tree = table.lock().unwrap();
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };

        let comm = read_proc_str(pid, "comm");
        let exe = read_exe(pid);
        let cmdline = read_cmdline(pid);
        // A process that vanished mid-scan leaves nothing worth recording.
        if comm.is_empty() && exe.is_empty() && cmdline.is_empty() {
            continue;
        }
        // start_ts is the daemon's start time, not the process's true
        // birth: "existed as of daemon start" is all that can honestly be
        // asserted, and it satisfies start_ts <= event_ts for everything
        // that follows.
        tree.seed(
            pid,
            read_ppid(pid),
            ProcInfo {
                exe,
                comm,
                cmdline,
                uid: read_uid(pid),
            },
            &start_ts,
        );
        seeded += 1;
    }
    eprintln!("whodidd: [graph] tracking {seeded} already-running processes");
}

fn open_log(log_path: &str) -> File {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("cannot open log file")
}

/// The process tree and its invariants live in `whenfs::proctree`, where
/// they can be tested without a kernel or a database -- see that module for
/// why persistence is deferred until a process actually writes, and for the
/// two invariants (`persisted` implies persisted ancestors; exit marks
/// rather than removes) that the code below relies on.
type ProcTable = Arc<Mutex<ProcTree>>;

/// How long an exited process stays in memory before eviction.
///
/// Not arbitrary: fanotify and the netlink connector are separate sockets
/// on separate threads, and a write can be processed well after its
/// author's exit has been recorded. This window is what keeps such a write
/// attributable, and it is generous because the cost is a few thousand
/// small structs.
const EXITED_GRACE_SECS: i64 = 90;

/// Write `pid` and any unpersisted ancestors to the graph, root-first so
/// parent rows exist before the children referencing them.
fn persist_chain(table: &ProcTable, graph: &Graph, pid: i32) {
    let chain = table.lock().unwrap().unpersisted_chain(pid);
    for (cpid, node) in &chain {
        let id = whenfs::graph::Identity {
            exe: &node.info.exe,
            comm: &node.info.comm,
            cmdline: &node.info.cmdline,
            uid: node.info.uid,
        };
        if graph
            .record_existing(*cpid, node.ppid, id, &node.start_ts)
            .is_ok()
        {
            // Already-exited processes are the common case here: lazy
            // persistence usually writes a process down after it is gone.
            if let Some(exit) = node.exited.as_deref() {
                let _ = graph.record_exit_at(*cpid, &node.start_ts, exit);
            }
            table.lock().unwrap().mark_persisted(*cpid);
        }
    }
}

fn evict_stale(table: &ProcTable) {
    let cutoff = whenfs::time_expr::format_snapshot_name(
        Local::now() - chrono::Duration::seconds(EXITED_GRACE_SECS),
    );
    table.lock().unwrap().evict_stale(&cutoff);
}

/// Optional so the daemon degrades to its previous, live-verified
/// JSONL-only behaviour if the graph database can't be opened, rather
/// than losing attribution entirely over a storage problem.
type SharedGraph = Option<Arc<Graph>>;

fn log_event(
    log: &mut File,
    path: &str,
    op: &str,
    pid: i32,
    table: &ProcTable,
    graph: &SharedGraph,
) {
    // Two sinks, deliberately, not duplication for its own sake: the JSONL
    // file is the append-only audit trail (proven, and what `whodid`
    // reads), the graph is the queryable index built from it. Log plus
    // materialised view.
    //
    // A write is the moment a process stops being a statistic and becomes
    // worth recording, so the chain is persisted here rather than at fork
    // time -- see ProcTable for why that distinction is load-bearing.
    if let Some(g) = graph.as_ref() {
        persist_chain(table, g, pid);
        let _ = g.record_event(path, op, pid);
    }
    let (exe, comm, cmdline, uid) = {
        let cached = table.lock().unwrap().info(pid);
        match cached {
            Some(info) => (info.exe, info.comm, info.cmdline, info.uid),
            // Fallback for any process the connector never saw exec (it
            // was already running before whodidd started) — same
            // exit-race exposure as before the connector existed, just
            // narrower: only processes started before the daemon.
            None => (
                read_exe(pid),
                read_proc_str(pid, "comm"),
                read_cmdline(pid),
                read_uid(pid),
            ),
        }
    };

    let line = format!(
        "{{\"ts\":\"{}\",\"path\":\"{}\",\"op\":\"{}\",\"pid\":{},\"comm\":\"{}\",\"exe\":\"{}\",\"cmdline\":\"{}\",\"uid\":{}}}\n",
        now_ts(),
        json_escape(path),
        op,
        pid,
        json_escape(&comm),
        json_escape(&exe),
        json_escape(&cmdline),
        uid,
    );
    let _ = log.write_all(line.as_bytes());
    let _ = log.flush();
}

fn fanotify_init_or_die(flags: libc::c_uint, watch_path: &str, log_path: &str) -> RawFd {
    let fd = unsafe {
        libc::fanotify_init(
            flags | libc::FAN_CLOEXEC,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("fanotify_init failed: {err}");
        if err.raw_os_error() == Some(libc::EPERM) {
            eprintln!("needs CAP_SYS_ADMIN — run as root: sudo ./whodidd {watch_path} {log_path}");
        }
        std::process::exit(1);
    }
    fd
}

/// FAN_MODIFY | FAN_CLOSE_WRITE, legacy (non-FID) mode. Unchanged from the
/// version confirmed live: correctly attributes in-place-truncate writes.
fn legacy_watcher(watch_path: String, log_path: String, table: ProcTable, graph: SharedGraph) {
    let fd = fanotify_init_or_die(libc::FAN_CLASS_NOTIF, &watch_path, &log_path);

    let watch_cstr = CString::new(watch_path.as_str()).unwrap();
    let mask = libc::FAN_MODIFY | libc::FAN_CLOSE_WRITE;
    let rc = unsafe {
        libc::fanotify_mark(
            fd,
            libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
            mask,
            libc::AT_FDCWD,
            watch_cstr.as_ptr(),
        )
    };
    if rc < 0 {
        eprintln!(
            "fanotify_mark (legacy) failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    let mut log = open_log(&log_path);
    eprintln!("whodidd: [legacy] watching {watch_path} (mount-wide) for modify/close_write");

    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n <= 0 {
            if n < 0 {
                eprintln!("[legacy] read failed: {}", std::io::Error::last_os_error());
            }
            break;
        }
        let mut offset = 0usize;
        while offset < n as usize {
            let meta_ptr =
                unsafe { buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata };
            let meta = unsafe { std::ptr::read_unaligned(meta_ptr) };
            if meta.event_len < mem::size_of::<libc::fanotify_event_metadata>() as u32 {
                break;
            }

            let event_fd = meta.fd;
            if event_fd >= 0 {
                let path = std::fs::read_link(format!("/proc/self/fd/{event_fd}"))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();

                if !path.is_empty() && !is_blocked(&path) && !is_self(meta.pid) {
                    let op = if meta.mask & libc::FAN_CLOSE_WRITE != 0 {
                        "close_write"
                    } else {
                        "modify"
                    };
                    log_event(&mut log, &path, op, meta.pid, &table, &graph);
                }
                unsafe {
                    libc::close(event_fd);
                }
            }

            offset += meta.event_len as usize;
        }
    }
}

fn op_name(mask: u64) -> &'static str {
    if mask & libc::FAN_CREATE != 0 {
        "create"
    } else if mask & libc::FAN_DELETE != 0 {
        "delete"
    } else if mask & libc::FAN_MOVED_FROM != 0 {
        "moved_from"
    } else if mask & libc::FAN_MOVED_TO != 0 {
        "moved_to"
    } else if mask & libc::FAN_ATTRIB != 0 {
        "attrib"
    } else {
        "fid_other"
    }
}

/// FAN_REPORT_DFID_NAME mode: create/delete/rename/attrib, via the dirent
/// event API. Events carry a parent-directory file handle + child filename
/// instead of a directly usable fd — see module doc comment for the shape.
fn fid_watcher(watch_path: String, log_path: String, table: ProcTable, graph: SharedGraph) {
    let fd = fanotify_init_or_die(
        libc::FAN_CLASS_NOTIF | libc::FAN_REPORT_DFID_NAME,
        &watch_path,
        &log_path,
    );

    let watch_cstr = CString::new(watch_path.as_str()).unwrap();
    let mask = libc::FAN_CREATE
        | libc::FAN_DELETE
        | libc::FAN_MOVED_FROM
        | libc::FAN_MOVED_TO
        | libc::FAN_ATTRIB
        | libc::FAN_ONDIR
        | libc::FAN_EVENT_ON_CHILD;
    let rc = unsafe {
        libc::fanotify_mark(
            fd,
            libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
            mask,
            libc::AT_FDCWD,
            watch_cstr.as_ptr(),
        )
    };
    if rc < 0 {
        eprintln!(
            "fanotify_mark (fid) failed: {}",
            std::io::Error::last_os_error()
        );
        eprintln!("[fid] watcher disabled; legacy modify/close_write attribution still runs");
        return;
    }

    // open_by_handle_at needs an fd anchored on the target filesystem to
    // resolve handles against — any open fd on that mount works.
    let mount_fd = unsafe { libc::open(watch_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if mount_fd < 0 {
        eprintln!(
            "[fid] could not open {watch_path} as mount anchor: {}",
            std::io::Error::last_os_error()
        );
        return;
    }

    let mut log = open_log(&log_path);
    eprintln!(
        "whodidd: [fid] watching filesystem containing {watch_path} for create/delete/move/attrib"
    );

    let hdr_size = mem::size_of::<libc::fanotify_event_info_header>();
    let fsid_size = mem::size_of::<libc::__kernel_fsid_t>();

    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n <= 0 {
            if n < 0 {
                eprintln!("[fid] read failed: {}", std::io::Error::last_os_error());
            }
            break;
        }
        let mut offset = 0usize;
        while offset < n as usize {
            let record_base = unsafe { buf.as_ptr().add(offset) };
            let meta = unsafe {
                std::ptr::read_unaligned(record_base as *const libc::fanotify_event_metadata)
            };
            if meta.event_len < mem::size_of::<libc::fanotify_event_metadata>() as u32 {
                break;
            }

            let mut info_offset = meta.metadata_len as usize;
            while info_offset + hdr_size <= meta.event_len as usize {
                let hdr = unsafe {
                    std::ptr::read_unaligned(
                        record_base.add(info_offset) as *const libc::fanotify_event_info_header
                    )
                };
                if hdr.len == 0 {
                    break;
                }
                let record_end = info_offset + hdr.len as usize;
                if record_end > meta.event_len as usize {
                    break;
                }

                if hdr.info_type == libc::FAN_EVENT_INFO_TYPE_DFID_NAME {
                    let fh_hdr_start = info_offset + hdr_size + fsid_size;
                    if fh_hdr_start + 8 <= record_end {
                        let handle_bytes = unsafe {
                            std::ptr::read_unaligned(record_base.add(fh_hdr_start) as *const u32)
                        };
                        let handle_type = unsafe {
                            std::ptr::read_unaligned(record_base.add(fh_hdr_start + 4) as *const i32)
                        };
                        let f_handle_start = fh_hdr_start + 8;
                        let name_start = f_handle_start + handle_bytes as usize;

                        if name_start <= record_end {
                            let mut name_end = name_start;
                            while name_end < record_end
                                && unsafe { *record_base.add(name_end) } != 0
                            {
                                name_end += 1;
                            }
                            let filename = unsafe {
                                String::from_utf8_lossy(std::slice::from_raw_parts(
                                    record_base.add(name_start),
                                    name_end - name_start,
                                ))
                                .into_owned()
                            };

                            let mut fh_buf = vec![0u8; 8 + handle_bytes as usize];
                            fh_buf[0..4].copy_from_slice(&handle_bytes.to_ne_bytes());
                            fh_buf[4..8].copy_from_slice(&handle_type.to_ne_bytes());
                            let raw_handle = unsafe {
                                std::slice::from_raw_parts(
                                    record_base.add(f_handle_start),
                                    handle_bytes as usize,
                                )
                            };
                            fh_buf[8..].copy_from_slice(raw_handle);

                            let dir_fd = unsafe {
                                libc::open_by_handle_at(
                                    mount_fd,
                                    fh_buf.as_mut_ptr() as *mut libc::file_handle,
                                    libc::O_RDONLY,
                                )
                            };
                            if dir_fd >= 0 {
                                let parent = std::fs::read_link(format!("/proc/self/fd/{dir_fd}"));
                                unsafe {
                                    libc::close(dir_fd);
                                }
                                if let Ok(parent) = parent {
                                    let full_path = if filename.is_empty() {
                                        parent.to_string_lossy().into_owned()
                                    } else {
                                        format!("{}/{}", parent.display(), filename)
                                    };
                                    if !is_blocked(&full_path) && !is_self(meta.pid) {
                                        log_event(
                                            &mut log,
                                            &full_path,
                                            op_name(meta.mask),
                                            meta.pid,
                                            &table,
                                            &graph,
                                        );
                                    }
                                }
                            }
                            // stale handle (parent already gone by the time
                            // we process this) — best-effort, skip silently
                        }
                    }
                }

                info_offset = record_end;
            }

            if meta.fd >= 0 {
                unsafe {
                    libc::close(meta.fd);
                }
            }

            offset += meta.event_len as usize;
        }
    }
}

// Group 3: NETLINK_CONNECTOR proc-connector. Not a fanotify group — a
// separate kernel subsystem entirely (linux/connector.h, linux/cn_proc.h).
// Subscribes to PROC_EVENT_EXEC/PROC_EVENT_EXIT multicast notifications and
// maintains `table`, so log_event() can look up a process's identity as
// captured the instant it exec'd, instead of racing a possibly-already-exited
// process by reading /proc/<pid> only once the fanotify event is processed.
//
// cn_msg and proc_event are stable, well-documented kernel UAPI structs not
// exposed by the libc crate (unlike the fanotify structs, which are) — laid
// out here by hand from linux/connector.h and linux/cn_proc.h. Parsed via
// fixed byte offsets rather than a transmuted struct, since proc_event's
// large union only needs two fields read (process_pid, at the same offset
// for both EXEC and EXIT), and manual offsets sidestep needing to replicate
// every union variant's Rust layout correctly.
//
// Buffer layout of one received multicast datagram:
//   [0..16)   nlmsghdr                              (libc::nlmsghdr)
//   [16..36)  cn_msg header (cb_id 8 + seq 4 + ack 4 + len 2 + flags 2 = 20)
//   [36..40)  proc_event.what        (u32)
//   [40..44)  proc_event.cpu         (u32, unused)
//   [44..52)  proc_event.timestamp_ns (u64, unused — 8-aligned within the
//             struct since what+cpu already occupy exactly 8 bytes)
//   [52..56)  union.process_pid      (i32 — same offset for EXEC and EXIT)
//   [56..60)  union.process_tgid     (i32, unused)
fn proc_connector(table: ProcTable, graph: SharedGraph) {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_CONNECTOR) };
    if fd < 0 {
        eprintln!(
            "[proc] socket() failed: {} — process-identity caching disabled, \
             falling back to /proc reads at event-processing time (the pre-connector \
             behavior, and its exit race)",
            std::io::Error::last_os_error()
        );
        return;
    }

    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = libc::CN_IDX_PROC;

    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        eprintln!("[proc] bind() failed: {}", std::io::Error::last_os_error());
        unsafe {
            libc::close(fd);
        }
        return;
    }

    // Subscribe control message: nlmsghdr + cn_msg header (20 bytes) +
    // a u32 payload of PROC_CN_MCAST_LISTEN. The connector stays silent
    // until a listener explicitly asks for multicast delivery this way.
    let cn_hdr_len = 20usize;
    let payload_len = 4usize;
    let total_len = mem::size_of::<libc::nlmsghdr>() + cn_hdr_len + payload_len;
    let mut send_buf = vec![0u8; total_len];

    send_buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
    send_buf[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
    // bytes 6..8 (flags) and 8..12 (seq) stay zero
    let self_pid = unsafe { libc::getpid() } as u32;
    send_buf[12..16].copy_from_slice(&self_pid.to_ne_bytes());

    send_buf[16..20].copy_from_slice(&libc::CN_IDX_PROC.to_ne_bytes());
    send_buf[20..24].copy_from_slice(&libc::CN_VAL_PROC.to_ne_bytes());
    // bytes 24..28 (seq) and 28..32 (ack) stay zero
    send_buf[32..34].copy_from_slice(&(payload_len as u16).to_ne_bytes());
    // bytes 34..36 (flags) stay zero
    send_buf[36..40].copy_from_slice(&libc::PROC_CN_MCAST_LISTEN.to_ne_bytes());

    let sent = unsafe { libc::send(fd, send_buf.as_ptr() as *const _, send_buf.len(), 0) };
    if sent < 0 {
        eprintln!(
            "[proc] send(subscribe) failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe {
            libc::close(fd);
        }
        return;
    }

    eprintln!("whodidd: [proc] connector listening for fork/exec/exit");

    const PROC_EVENT_OFF: usize = 36;
    const UNION_OFF: usize = PROC_EVENT_OFF + 16;
    // fork's union is { parent_pid, parent_tgid, child_pid, child_tgid },
    // so the child sits two i32s past the start of the union — unlike
    // exec/exit, where the pid is the first field.
    const FORK_CHILD_OFF: usize = UNION_OFF + 8;

    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n <= 0 {
            if n < 0 {
                eprintln!("[proc] recv failed: {}", std::io::Error::last_os_error());
            }
            break;
        }
        let n = n as usize;
        if n < UNION_OFF + 4 {
            continue;
        }

        let what =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(PROC_EVENT_OFF) as *const u32) };
        let process_pid =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(UNION_OFF) as *const i32) };

        if what == libc::PROC_EVENT_FORK {
            // The parent→child edge. This is the one fact nothing else on
            // the system records, and the whole causal graph rests on it:
            // without fork edges you can say "sh wrote this" but never
            // "sh wrote this *because* you ran that install script".
            if n < FORK_CHILD_OFF + 4 {
                continue;
            }
            let parent_pid = process_pid;
            let child_pid =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(FORK_CHILD_OFF) as *const i32) };
            // Memory only. At the 16.8 forks/second measured on this
            // machine at idle, writing each one to SQLite costs 267 MiB a
            // day for processes that overwhelmingly never touch a file.
            table
                .lock()
                .unwrap()
                .on_fork(parent_pid, child_pid, &now_ts());
        } else if what == libc::PROC_EVENT_EXEC {
            let info = ProcInfo {
                exe: read_exe(process_pid),
                comm: read_proc_str(process_pid, "comm"),
                cmdline: read_cmdline(process_pid),
                uid: read_uid(process_pid),
            };
            // exec replaces the image, not the process: on_exec keeps the
            // ppid and start_ts recorded at fork so the lineage edge
            // survives. read_ppid only matters if the fork was missed.
            table
                .lock()
                .unwrap()
                .on_exec(process_pid, info, read_ppid(process_pid), &now_ts());
        } else if what == libc::PROC_EVENT_EXIT {
            // Marked, not removed. A write by this process can still be
            // sitting unprocessed in the fanotify queue, and dropping the
            // entry now is exactly how short-lived writers lost their
            // identity before. evict_stale() clears it once the window in
            // which that can happen has passed.
            let exit_ts = now_ts();
            let persisted_start = table.lock().unwrap().on_exit(process_pid, &exit_ts);
            // Only a row already on disk needs its exit written through;
            // an unpersisted one carries its exit in memory until (and if)
            // something makes it worth recording.
            if let (Some(start), Some(g)) = (persisted_start, graph.as_ref()) {
                let _ = g.record_exit_at(process_pid, &start, &exit_ts);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: whodidd <watch-path> <log-path>");
        std::process::exit(1);
    }
    let watch_path = args[1].clone();
    let log_path = args[2].clone();

    // The graph lives beside the JSONL log rather than taking another
    // argument, so existing invocations (services, demo.sh) keep working
    // unchanged and simply gain a graph.
    let graph_path = Path::new(&log_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("graph.db");

    let graph: SharedGraph = match Graph::open(&graph_path) {
        Ok(g) => {
            eprintln!("whodidd: [graph] recording to {}", graph_path.display());
            Some(Arc::new(g))
        }
        Err(e) => {
            // Deliberately non-fatal: attribution to the JSONL log is the
            // proven path and still works without the graph.
            eprintln!("whodidd: [graph] disabled ({e}) — JSONL attribution continues");
            None
        }
    };

    let table: ProcTable = Arc::new(Mutex::new(ProcTree::new()));
    bootstrap_process_table(&table);

    // Bounds the in-memory tree. At ~17 forks/second and a 90s grace this
    // settles around a couple of thousand small structs.
    {
        let t = table.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(std::time::Duration::from_secs(30));
                evict_stale(&t);
            }
        });
    }

    let proc_conn = {
        let t = table.clone();
        let g = graph.clone();
        thread::spawn(move || proc_connector(t, g))
    };
    let legacy = {
        let w = watch_path.clone();
        let l = log_path.clone();
        let t = table.clone();
        let g = graph.clone();
        thread::spawn(move || legacy_watcher(w, l, t, g))
    };
    let fid = thread::spawn(move || fid_watcher(watch_path, log_path, table, graph));

    let _ = proc_conn.join();
    let _ = legacy.join();
    let _ = fid.join();
}
