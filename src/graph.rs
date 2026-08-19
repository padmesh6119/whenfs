//! The causal graph: processes, their lineage, and every file they touched.
//!
//! This is the layer that turns "a pile of snapshots" into something with
//! meaning attached. btrfs can tell you a block changed; only this can tell
//! you *what ran*, *what it descended from*, and *what it wrote*.
//!
//! # Why SQLite and not JSONL
//!
//! The event log started as append-only JSONL, deliberately — no database
//! until grep got slow. A graph changes that calculus: the whole point is
//! transitive queries ("every process descended from this one", "the full
//! ancestry of whatever wrote this file"), and answering those over JSONL
//! means loading all of history into memory and rebuilding the graph on
//! every invocation. Recursive CTEs do it in the storage layer instead.
//!
//! # Process identity
//!
//! PIDs recycle, so a bare pid is not an identity — `(pid, start_ts)` is.
//! fanotify only ever hands us a bare pid, so resolving one means "the
//! currently-live incarnation of that pid", which is why `exit_ts` matters
//! for correctness and not just tidiness: without it, a write by a new
//! process gets attributed to a long-dead one that happened to share a pid.

use chrono::Local;
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

use crate::time_expr;

/// Timestamps use the same format as snapshot directory names so event
/// times and snapshot names stay directly, lexically comparable — the
/// property the whole snapshot-bracketing join depends on.
pub fn now_ts() -> String {
    time_expr::format_snapshot_name(Local::now())
}

pub struct Graph {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub ts: String,
    pub path: String,
    pub op: String,
    pub pid: i32,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    /// Which incarnation of `pid` wrote this. Needed to walk ancestry
    /// correctly — a bare pid is ambiguous once pids recycle. `None` means
    /// the writer was never identified (a hole in the graph).
    pub proc_start: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProcRow {
    pub pid: i32,
    pub start_ts: String,
    pub ppid: Option<i32>,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
}

impl Graph {
    pub fn open(path: &Path) -> rusqlite::Result<Graph> {
        let conn = Connection::open(path)?;

        // WAL: the daemon writes from three threads while `chronicle`
        // reads concurrently from another process. Without WAL those
        // readers block writers and vice versa.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // NORMAL rather than FULL: a crash can lose the last few events,
        // which is an acceptable trade for not fsyncing on every single
        // file write on the machine. FULL makes the daemon a measurable
        // drag on all disk I/O.
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS processes (
                pid       INTEGER NOT NULL,
                start_ts  TEXT    NOT NULL,
                ppid      INTEGER,
                exe       TEXT NOT NULL DEFAULT '',
                comm      TEXT NOT NULL DEFAULT '',
                cmdline   TEXT NOT NULL DEFAULT '',
                uid       INTEGER NOT NULL DEFAULT -1,
                exit_ts   TEXT,
                PRIMARY KEY (pid, start_ts)
            );

            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY,
                ts         TEXT    NOT NULL,
                path       TEXT    NOT NULL,
                op         TEXT    NOT NULL,
                pid        INTEGER NOT NULL,
                proc_start TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_path  ON events(path);
            CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_proc_ppid    ON processes(ppid);
            CREATE INDEX IF NOT EXISTS idx_proc_live    ON processes(pid, exit_ts);
            "#,
        )?;

        Ok(Graph {
            conn: Mutex::new(conn),
        })
    }

    /// A fork gives us the one edge nothing else can: parent → child.
    /// Recorded before exec, so the row usually exists with an empty exe
    /// that `record_exec` fills in a moment later.
    pub fn record_fork(&self, parent_pid: i32, child_pid: i32) -> rusqlite::Result<()> {
        let ts = now_ts();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO processes (pid, start_ts, ppid) VALUES (?1, ?2, ?3)",
            params![child_pid, ts, parent_pid],
        )?;
        Ok(())
    }

    /// exec replaces the process image but not the process — so this
    /// updates the live row rather than creating a new one, preserving the
    /// ppid edge recorded at fork time. If we never saw the fork (daemon
    /// started mid-life), insert a row with an unknown parent instead of
    /// dropping the process on the floor.
    pub fn record_exec(
        &self,
        pid: i32,
        exe: &str,
        comm: &str,
        cmdline: &str,
        uid: u32,
    ) -> rusqlite::Result<()> {
        let ts = now_ts();
        let conn = self.conn.lock().unwrap();

        let updated = conn.execute(
            "UPDATE processes SET exe = ?1, comm = ?2, cmdline = ?3, uid = ?4
             WHERE pid = ?5 AND exit_ts IS NULL",
            params![exe, comm, cmdline, uid as i64, pid],
        )?;

        if updated == 0 {
            conn.execute(
                "INSERT OR IGNORE INTO processes
                   (pid, start_ts, ppid, exe, comm, cmdline, uid)
                 VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6)",
                params![pid, ts, exe, comm, cmdline, uid as i64],
            )?;
        }
        Ok(())
    }

    /// Closing out a process is what keeps pid reuse from corrupting
    /// attribution — see the module docs.
    pub fn record_exit(&self, pid: i32) -> rusqlite::Result<()> {
        let ts = now_ts();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE processes SET exit_ts = ?1 WHERE pid = ?2 AND exit_ts IS NULL",
            params![ts, pid],
        )?;
        Ok(())
    }

    /// Bind a file event to the live incarnation of `pid`. `proc_start` may
    /// be NULL when the writer was never seen forking or execing (already
    /// running before the daemon started, or gone before we could look) —
    /// that's a hole in the graph, recorded honestly rather than guessed at.
    pub fn record_event(&self, path: &str, op: &str, pid: i32) -> rusqlite::Result<()> {
        let ts = now_ts();
        let conn = self.conn.lock().unwrap();

        let proc_start: Option<String> = conn
            .query_row(
                "SELECT start_ts FROM processes
                 WHERE pid = ?1 AND exit_ts IS NULL
                 ORDER BY start_ts DESC LIMIT 1",
                params![pid],
                |r| r.get(0),
            )
            .ok();

        conn.execute(
            "INSERT INTO events (ts, path, op, pid, proc_start) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ts, path, op, pid, proc_start],
        )?;
        Ok(())
    }

    /// The start_ts of the live incarnation of `pid`, which is what turns
    /// a bare pid from the command line into a graph identity.
    pub fn live_start_ts(&self, pid: i32) -> rusqlite::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT start_ts FROM processes
                 WHERE pid = ?1 AND exit_ts IS NULL
                 ORDER BY start_ts DESC LIMIT 1",
                params![pid],
                |r| r.get(0),
            )
            .ok())
    }

    /// Full history of one path, oldest first.
    pub fn log_file(&self, path: &str) -> rusqlite::Result<Vec<FileEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT e.ts, e.path, e.op, e.pid,
                    COALESCE(p.comm, ''), COALESCE(p.exe, ''), COALESCE(p.cmdline, ''),
                    e.proc_start
             FROM events e
             LEFT JOIN processes p
               ON p.pid = e.pid AND p.start_ts = e.proc_start
             WHERE e.path = ?1
             ORDER BY e.ts ASC, e.id ASC",
        )?;
        let rows = stmt.query_map(params![path], |r| {
            Ok(FileEvent {
                ts: r.get(0)?,
                path: r.get(1)?,
                op: r.get(2)?,
                pid: r.get(3)?,
                comm: r.get(4)?,
                exe: r.get(5)?,
                cmdline: r.get(6)?,
                proc_start: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    /// Most recent writer of a path.
    pub fn blame(&self, path: &str) -> rusqlite::Result<Option<FileEvent>> {
        Ok(self.log_file(path)?.pop())
    }

    /// Walk ppid edges upward: the chain that explains *why* a process
    /// existed. This is what turns "written by sh" into
    /// "written by sh ← curl ← the command you actually typed".
    pub fn ancestry(&self, pid: i32, start_ts: &str) -> rusqlite::Result<Vec<ProcRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            WITH RECURSIVE chain(pid, start_ts, ppid, exe, comm, cmdline, depth) AS (
                SELECT pid, start_ts, ppid, exe, comm, cmdline, 0
                  FROM processes WHERE pid = ?1 AND start_ts = ?2
                UNION ALL
                SELECT p.pid, p.start_ts, p.ppid, p.exe, p.comm, p.cmdline, c.depth + 1
                  FROM processes p
                  JOIN chain c ON p.pid = c.ppid AND p.exit_ts IS NULL
                 WHERE c.depth < 64
            )
            SELECT pid, start_ts, ppid, exe, comm, cmdline FROM chain ORDER BY depth ASC
            "#,
        )?;
        let rows = stmt.query_map(params![pid, start_ts], |r| {
            Ok(ProcRow {
                pid: r.get(0)?,
                start_ts: r.get(1)?,
                ppid: r.get(2)?,
                exe: r.get(3)?,
                comm: r.get(4)?,
                cmdline: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    /// Transitive closure downward: every process descended from this one.
    /// Not used by `log`/`blame`, but this is the primitive the whole
    /// trace-and-revert idea rests on — "what did that install script and
    /// everything it spawned actually touch" is this query joined against
    /// events.
    pub fn descendants(&self, pid: i32, start_ts: &str) -> rusqlite::Result<Vec<ProcRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            WITH RECURSIVE tree(pid, start_ts, ppid, exe, comm, cmdline, depth) AS (
                SELECT pid, start_ts, ppid, exe, comm, cmdline, 0
                  FROM processes WHERE pid = ?1 AND start_ts = ?2
                UNION ALL
                SELECT p.pid, p.start_ts, p.ppid, p.exe, p.comm, p.cmdline, t.depth + 1
                  FROM processes p
                  JOIN tree t ON p.ppid = t.pid
                 WHERE t.depth < 256
            )
            SELECT pid, start_ts, ppid, exe, comm, cmdline FROM tree ORDER BY depth ASC
            "#,
        )?;
        let rows = stmt.query_map(params![pid, start_ts], |r| {
            Ok(ProcRow {
                pid: r.get(0)?,
                start_ts: r.get(1)?,
                ppid: r.get(2)?,
                exe: r.get(3)?,
                comm: r.get(4)?,
                cmdline: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    /// Everything written by a process tree — the manifest of what a
    /// command actually did to the machine.
    pub fn events_by_tree(&self, pid: i32, start_ts: &str) -> rusqlite::Result<Vec<FileEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            WITH RECURSIVE tree(pid, start_ts, depth) AS (
                SELECT pid, start_ts, 0
                  FROM processes WHERE pid = ?1 AND start_ts = ?2
                UNION ALL
                SELECT p.pid, p.start_ts, t.depth + 1
                  FROM processes p
                  JOIN tree t ON p.ppid = t.pid
                 WHERE t.depth < 256
            )
            SELECT e.ts, e.path, e.op, e.pid,
                   COALESCE(p.comm, ''), COALESCE(p.exe, ''), COALESCE(p.cmdline, ''),
                   e.proc_start
              FROM events e
              JOIN tree t ON e.pid = t.pid AND e.proc_start = t.start_ts
              LEFT JOIN processes p ON p.pid = e.pid AND p.start_ts = e.proc_start
             ORDER BY e.ts ASC, e.id ASC
            "#,
        )?;
        let rows = stmt.query_map(params![pid, start_ts], |r| {
            Ok(FileEvent {
                ts: r.get(0)?,
                path: r.get(1)?,
                op: r.get(2)?,
                pid: r.get(3)?,
                comm: r.get(4)?,
                exe: r.get(5)?,
                cmdline: r.get(6)?,
                proc_start: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn counts(&self) -> rusqlite::Result<(i64, i64)> {
        let conn = self.conn.lock().unwrap();
        let procs: i64 = conn.query_row("SELECT COUNT(*) FROM processes", [], |r| r.get(0))?;
        let events: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok((procs, events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

    /// Each test gets its own database. Keying only on process id meant
    /// every test in the binary shared one directory, and since cargo runs
    /// them in parallel threads they deleted each other's file mid-run.
    fn mem_graph() -> Graph {
        let n = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("chronicle-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Graph::open(&dir.join("g.db")).unwrap()
    }

    #[test]
    fn fork_then_exec_keeps_one_row_and_preserves_parent() {
        let g = mem_graph();
        g.record_fork(100, 200).unwrap();
        g.record_exec(200, "/bin/sh", "sh", "sh install.sh", 1000)
            .unwrap();

        // exec must UPDATE the forked row, not create a second one —
        // otherwise the ppid edge recorded at fork time is orphaned.
        let (procs, _) = g.counts().unwrap();
        assert_eq!(procs, 1);

        let anc = {
            let conn = g.conn.lock().unwrap();
            conn.query_row("SELECT ppid, exe FROM processes WHERE pid = 200", [], |r| {
                Ok((r.get::<_, Option<i32>>(0)?, r.get::<_, String>(1)?))
            })
            .unwrap()
        };
        assert_eq!(anc.0, Some(100));
        assert_eq!(anc.1, "/bin/sh");
    }

    #[test]
    fn exec_without_prior_fork_still_records_the_process() {
        // Daemon started after the process was already alive.
        let g = mem_graph();
        g.record_exec(300, "/bin/vim", "vim", "vim x", 1000)
            .unwrap();
        let (procs, _) = g.counts().unwrap();
        assert_eq!(procs, 1);
    }

    #[test]
    fn events_bind_to_the_live_incarnation_not_a_dead_one() {
        let g = mem_graph();
        // First life of pid 500, then it exits.
        g.record_fork(1, 500).unwrap();
        g.record_exec(500, "/bin/old", "old", "old", 1000).unwrap();
        g.record_exit(500).unwrap();

        // pid recycled into a completely different process.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        g.record_fork(1, 500).unwrap();
        g.record_exec(500, "/bin/new", "new", "new", 1000).unwrap();

        g.record_event("/tmp/f", "modify", 500).unwrap();

        let log = g.log_file("/tmp/f").unwrap();
        assert_eq!(log.len(), 1);
        // Must resolve to the live one; attributing this to "old" would be
        // exactly the pid-reuse bug the exit_ts column exists to prevent.
        assert_eq!(log[0].comm, "new");
    }

    #[test]
    fn unattributed_write_is_recorded_not_dropped() {
        let g = mem_graph();
        g.record_event("/tmp/ghost", "delete", 9999).unwrap();
        let log = g.log_file("/tmp/ghost").unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].pid, 9999);
        assert_eq!(log[0].comm, ""); // hole in the graph, honestly empty
    }

    #[test]
    fn ancestry_walks_the_whole_chain() {
        let g = mem_graph();
        g.record_fork(1, 10).unwrap();
        g.record_exec(10, "/bin/bash", "bash", "bash", 1000)
            .unwrap();
        g.record_fork(10, 20).unwrap();
        g.record_exec(20, "/usr/bin/curl", "curl", "curl get.sh", 1000)
            .unwrap();
        g.record_fork(20, 30).unwrap();
        g.record_exec(30, "/bin/sh", "sh", "sh", 1000).unwrap();

        let start: String = {
            let conn = g.conn.lock().unwrap();
            conn.query_row("SELECT start_ts FROM processes WHERE pid = 30", [], |r| {
                r.get(0)
            })
            .unwrap()
        };
        let chain = g.ancestry(30, &start).unwrap();
        let comms: Vec<String> = chain.into_iter().map(|p| p.comm).collect();
        assert_eq!(comms, vec!["sh", "curl", "bash"]);
    }

    #[test]
    fn tree_collects_writes_from_every_descendant() {
        let g = mem_graph();
        g.record_fork(1, 10).unwrap();
        g.record_exec(10, "/bin/sh", "sh", "install.sh", 1000)
            .unwrap();
        g.record_fork(10, 11).unwrap();
        g.record_exec(11, "/bin/cp", "cp", "cp a b", 1000).unwrap();
        g.record_fork(11, 12).unwrap();
        g.record_exec(12, "/bin/ln", "ln", "ln -s", 1000).unwrap();

        g.record_event("/usr/bin/thing", "create", 11).unwrap();
        g.record_event("/etc/thing.conf", "create", 12).unwrap();

        // An unrelated process writing at the same time must NOT be swept in.
        g.record_fork(1, 99).unwrap();
        g.record_exec(99, "/usr/bin/firefox", "firefox", "firefox", 1000)
            .unwrap();
        g.record_event("/home/u/.cache/x", "modify", 99).unwrap();

        let start: String = {
            let conn = g.conn.lock().unwrap();
            conn.query_row("SELECT start_ts FROM processes WHERE pid = 10", [], |r| {
                r.get(0)
            })
            .unwrap()
        };
        let manifest = g.events_by_tree(10, &start).unwrap();
        let paths: Vec<String> = manifest.into_iter().map(|e| e.path).collect();
        assert_eq!(paths, vec!["/usr/bin/thing", "/etc/thing.conf"]);
    }
}
