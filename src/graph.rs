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

/// Grouped so the three adjacent strings can't be passed in the wrong
/// order at a call site -- exe/comm/cmdline are all &str and a swap would
/// be silent, surfacing much later as mislabelled attribution.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    pub exe: &'a str,
    pub comm: &'a str,
    pub cmdline: &'a str,
    pub uid: u32,
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

    /// Record a process that was already running when the daemon started.
    ///
    /// Without this the graph only ever knows processes that fork *after*
    /// startup, which on a real machine is a small minority of the things
    /// actually writing to disk -- every long-running service, editor and
    /// browser is invisible, and their writes land unattributed.
    ///
    /// `start_ts` is the daemon's own start time rather than the process's
    /// true birth: the claim being recorded is "this existed as of daemon
    /// start", which is all that can be honestly asserted, and it satisfies
    /// the `start_ts <= event_ts` resolution for every event that follows.
    /// A later incarnation of the same pid gets a strictly later start_ts,
    /// so `ORDER BY start_ts DESC` still picks the right one.
    pub fn record_existing(
        &self,
        pid: i32,
        ppid: Option<i32>,
        id: Identity<'_>,
        start_ts: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO processes
               (pid, start_ts, ppid, exe, comm, cmdline, uid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                pid,
                start_ts,
                ppid,
                id.exe,
                id.comm,
                id.cmdline,
                id.uid as i64
            ],
        )?;
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

    /// Record an exit for one specific incarnation.
    ///
    /// `record_exit` targets whichever incarnation is currently live, which
    /// is right when the connector reports an exit as it happens. Lazy
    /// persistence needs the other shape: a process is written to disk only
    /// once it matters, often *after* it already exited, so the exit time
    /// has to be attached to the incarnation being written rather than
    /// looked up.
    pub fn record_exit_at(&self, pid: i32, start_ts: &str, exit_ts: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE processes SET exit_ts = ?1 WHERE pid = ?2 AND start_ts = ?3",
            params![exit_ts, pid, start_ts],
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

        // Resolve the pid to an incarnation by TIME WINDOW, not liveness.
        //
        // The obvious query — `WHERE exit_ts IS NULL` — is wrong, and a
        // live run proved it catastrophically so: 27228 of 27231 events
        // came back unattributed. fanotify and the netlink connector are
        // two independent sockets read by two independent threads, with no
        // ordering guarantee between them, so a short-lived process (`cp`,
        // `rm`, anything in a shell pipeline) is routinely recorded as
        // exited before its own write event gets processed. Filtering on
        // liveness then discards the very attribution we exist to capture.
        //
        // Matching the event against each incarnation's [start, exit]
        // window instead is correct for both cases it has to serve: pid
        // reuse (distinct incarnations occupy disjoint windows) and
        // short-lived processes (already exited, but the window still
        // contains the event).
        let proc_start: Option<String> = conn
            .query_row(
                "SELECT start_ts FROM processes
                 WHERE pid = ?1
                   AND start_ts <= ?2
                   AND (exit_ts IS NULL OR exit_ts >= ?2)
                 ORDER BY start_ts DESC LIMIT 1",
                params![pid, ts],
                |r| r.get(0),
            )
            .ok()
            // Timestamps are second-granularity and assigned when we
            // *process* an event, not when it occurred, so a write can be
            // stamped a tick after the writer's recorded exit. Fall back to
            // the newest incarnation that started before the event rather
            // than losing attribution to a rounding edge. Misattribution
            // here would require a full pid wraparound inside that gap,
            // which is not a realistic race.
            .or_else(|| {
                conn.query_row(
                    "SELECT start_ts FROM processes
                     WHERE pid = ?1 AND start_ts <= ?2
                     ORDER BY start_ts DESC LIMIT 1",
                    params![pid, ts],
                    |r| r.get(0),
                )
                .ok()
            });

        conn.execute(
            "INSERT INTO events (ts, path, op, pid, proc_start) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ts, path, op, pid, proc_start],
        )?;
        Ok(())
    }

    /// The most recent incarnation of `pid`, alive or not.
    ///
    /// Distinct from `live_start_ts` on purpose: anything asking about a
    /// command that has already finished -- `trace`, or `tree` on a process
    /// that has since exited -- must not filter on liveness, which is the
    /// same mistake that cost attribution twice already.
    pub fn latest_start_ts(&self, pid: i32) -> rusqlite::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT start_ts FROM processes WHERE pid = ?1
                 ORDER BY start_ts DESC LIMIT 1",
                params![pid],
                |r| r.get(0),
            )
            .ok())
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
        // Resolve the writer at QUERY time, not record time.
        //
        // Binding eagerly in record_event races the connector: fanotify and
        // netlink are separate sockets on separate threads, and a process
        // that forks, writes and exits in microseconds can have its write
        // processed before its fork message is even read -- so proc_start is
        // NULL for exactly the short-lived processes worth identifying. A
        // live run showed this: the writing `cp` was present in `processes`
        // with the right parent, while its own events pointed at nothing.
        //
        // By query time both streams have long since settled, so falling
        // back to a window match recovers them. The stored proc_start is
        // still preferred when present -- it was correct when it was
        // written, and trusting it keeps this cheap in the common case.
        let mut stmt = conn.prepare(
            "WITH resolved AS (
               SELECT e.id, e.ts, e.path, e.op, e.pid,
                      COALESCE(e.proc_start, (
                        SELECT MAX(p2.start_ts) FROM processes p2
                         WHERE p2.pid = e.pid
                           AND p2.start_ts <= e.ts
                           AND (p2.exit_ts IS NULL OR p2.exit_ts >= e.ts)
                      )) AS rstart
                 FROM events e
                WHERE e.path = ?1
             )
             SELECT r.ts, r.path, r.op, r.pid,
                    COALESCE(p.comm, ''), COALESCE(p.exe, ''), COALESCE(p.cmdline, ''),
                    r.rstart
               FROM resolved r
               LEFT JOIN processes p
                 ON p.pid = r.pid AND p.start_ts = r.rstart
              ORDER BY r.ts ASC, r.id ASC",
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
                -- Match the parent incarnation whose lifetime contained the
                -- child's birth. Filtering on `exit_ts IS NULL` here (the
                -- original form) truncated the chain at the first ancestor
                -- that had since exited -- which, walking up from a
                -- short-lived process, is usually the very first hop.
                SELECT p.pid, p.start_ts, p.ppid, p.exe, p.comm, p.cmdline, c.depth + 1
                  FROM processes p
                  JOIN chain c
                    ON p.pid = c.ppid
                   AND p.start_ts <= c.start_ts
                   AND (p.exit_ts IS NULL OR p.exit_ts >= c.start_ts)
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
                   t.start_ts
              FROM events e
              -- Same lazy resolution as log_file: match the event against
              -- the incarnation's window rather than requiring the eager
              -- binding to have won its race.
              JOIN tree t
                ON e.pid = t.pid
               AND (e.proc_start = t.start_ts
                    OR (e.proc_start IS NULL AND t.start_ts <= e.ts))
              LEFT JOIN processes p ON p.pid = t.pid AND p.start_ts = t.start_ts
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

    /// How much history predates `before_ts` — the dry run for `prune`.
    pub fn prune_preview(&self, before_ts: &str) -> rusqlite::Result<(i64, i64)> {
        let conn = self.conn.lock().unwrap();
        let events: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE ts < ?1",
            params![before_ts],
            |r| r.get(0),
        )?;
        let procs: i64 = conn.query_row(
            "SELECT COUNT(*) FROM processes p
              WHERE p.exit_ts IS NOT NULL AND p.exit_ts < ?1
                AND NOT EXISTS (SELECT 1 FROM events e
                                 WHERE e.pid = p.pid AND e.ts >= ?1)",
            params![before_ts],
            |r| r.get(0),
        )?;
        Ok((procs, events))
    }

    /// Drop history older than `before_ts`.
    ///
    /// A process is kept if any *retained* event shares its pid, even when
    /// that event's `proc_start` is NULL: lazy resolution means such an
    /// event can still bind to it at query time, and deleting the row would
    /// silently turn an attributed write back into an anonymous one. Being
    /// over-retentive here costs a few rows; being under-retentive
    /// destroys attribution that still has a live consumer.
    ///
    /// Pruning necessarily truncates ancestry chains that reach back past
    /// the cutoff — a retained event may end up explained only as far as
    /// the oldest surviving ancestor. That is the cost of bounded history,
    /// not a defect.
    pub fn prune(&self, before_ts: &str) -> rusqlite::Result<(i64, i64)> {
        let conn = self.conn.lock().unwrap();
        // Processes first, while the events that pin them still exist.
        let procs = conn.execute(
            "DELETE FROM processes
              WHERE exit_ts IS NOT NULL AND exit_ts < ?1
                AND NOT EXISTS (SELECT 1 FROM events e
                                 WHERE e.pid = processes.pid AND e.ts >= ?1)",
            params![before_ts],
        )? as i64;
        let events = conn.execute("DELETE FROM events WHERE ts < ?1", params![before_ts])? as i64;
        Ok((procs, events))
    }

    /// Reclaim the space freed by a prune. Separate because it rewrites the
    /// whole file and can take a while on a large database.
    pub fn vacuum(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("VACUUM")?;
        Ok(())
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
        // Must resolve to the second incarnation; attributing this to
        // "old" would be exactly the pid-reuse bug being guarded against.
        assert_eq!(log[0].comm, "new");
    }

    #[test]
    fn short_lived_process_is_still_attributed_after_it_exits() {
        // The live-run regression: fanotify and the connector are separate
        // sockets, so the exit is routinely recorded before the write event
        // is processed. Resolving on liveness lost 99.99% of attribution.
        let g = mem_graph();
        g.record_fork(1, 700).unwrap();
        g.record_exec(700, "/bin/cp", "cp", "cp a b", 1000).unwrap();
        g.record_exit(700).unwrap();

        // Write processed only after the process is already gone.
        g.record_event("/tmp/copied", "create", 700).unwrap();

        let log = g.log_file("/tmp/copied").unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].comm, "cp", "a dead writer must still be named");
        assert!(log[0].proc_start.is_some(), "must bind to an incarnation");
    }

    #[test]
    fn bootstrapped_process_can_be_attributed_and_is_not_duplicated() {
        // A long-running process that predates the daemon must still be
        // nameable, or on a real machine almost every write is anonymous.
        let g = mem_graph();
        // Must be genuinely in the past: resolution requires
        // start_ts <= event_ts, and the event is stamped with the real clock.
        let boot = "2000-01-01T00-00-00";
        let id = Identity {
            exe: "/usr/bin/nginx",
            comm: "nginx",
            cmdline: "nginx -g",
            uid: 0,
        };
        g.record_existing(400, Some(1), id, boot).unwrap();
        g.record_event("/var/log/nginx/access.log", "modify", 400)
            .unwrap();

        let log = g.log_file("/var/log/nginx/access.log").unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].comm, "nginx");

        // Re-seeding (daemon restart) must not create a second row for the
        // same incarnation.
        g.record_existing(400, Some(1), id, boot).unwrap();
        let (procs, _) = g.counts().unwrap();
        assert_eq!(procs, 1);
    }

    #[test]
    fn write_processed_before_its_fork_message_is_still_attributed() {
        // The live regression. fanotify and the netlink connector are
        // separate sockets on separate threads, so the write can be
        // processed before the fork that created its writer is even read.
        // Eager binding leaves proc_start NULL for precisely the
        // short-lived processes worth naming; query-time resolution has
        // both streams settled and recovers them.
        let g = mem_graph();

        // Event arrives FIRST -- no process row exists yet.
        g.record_event("/tmp/raced", "create", 800).unwrap();
        assert!(
            g.log_file("/tmp/raced").unwrap()[0].proc_start.is_none(),
            "precondition: eager binding found nothing"
        );

        // The connector catches up afterwards.
        g.record_fork(1, 800).unwrap();
        g.record_exec(800, "/bin/cp", "cp", "cp a b", 1000).unwrap();
        g.record_exit(800).unwrap();

        let log = g.log_file("/tmp/raced").unwrap();
        assert_eq!(log[0].comm, "cp", "query-time resolution must recover it");
        assert!(log[0].proc_start.is_some());
    }

    #[test]
    fn ancestry_walks_through_ancestors_that_have_already_exited() {
        // Walking up from a short-lived process, the first hop is usually
        // an ancestor that has itself exited. Filtering the recursive join
        // on liveness truncated the chain immediately.
        let g = mem_graph();
        g.record_fork(1, 10).unwrap();
        g.record_exec(10, "/bin/bash", "bash", "bash run.sh", 1000)
            .unwrap();
        g.record_fork(10, 20).unwrap();
        g.record_exec(20, "/bin/sh", "sh", "sh -c cp", 1000)
            .unwrap();
        g.record_fork(20, 30).unwrap();
        g.record_exec(30, "/bin/cp", "cp", "cp a b", 1000).unwrap();

        // Every ancestor exits before the query runs.
        g.record_exit(30).unwrap();
        g.record_exit(20).unwrap();
        g.record_exit(10).unwrap();

        let start = g.live_start_ts(30).unwrap().unwrap_or_else(|| {
            let conn = g.conn.lock().unwrap();
            conn.query_row("SELECT start_ts FROM processes WHERE pid=30", [], |r| {
                r.get(0)
            })
            .unwrap()
        });
        let chain: Vec<String> = g
            .ancestry(30, &start)
            .unwrap()
            .into_iter()
            .map(|p| p.comm)
            .collect();
        assert_eq!(chain, vec!["cp", "sh", "bash"]);
    }

    #[test]
    fn latest_start_ts_finds_exited_processes_but_live_start_ts_does_not() {
        // trace asks about a command that has, by definition, just
        // finished. Reusing the liveness-filtered lookup there would
        // repeat the mistake that cost attribution twice already.
        let g = mem_graph();
        g.record_fork(1, 900).unwrap();
        g.record_exec(900, "/bin/sh", "sh", "sh install.sh", 1000)
            .unwrap();
        assert!(g.live_start_ts(900).unwrap().is_some());

        g.record_exit(900).unwrap();
        assert!(
            g.live_start_ts(900).unwrap().is_none(),
            "live lookup must not resurrect a dead process"
        );
        assert!(
            g.latest_start_ts(900).unwrap().is_some(),
            "trace must still find the command it just ran"
        );
    }

    #[test]
    fn prune_drops_old_history_but_keeps_what_retained_events_still_need() {
        let g = mem_graph();
        let old = "2020-01-01T00-00-00";
        let new = "2030-01-01T00-00-00";
        let cutoff = "2025-01-01T00-00-00";

        // Fully historical: exited long ago, only old events.
        g.record_existing(
            10,
            Some(1),
            Identity {
                exe: "/bin/old",
                comm: "old",
                cmdline: "old",
                uid: 0,
            },
            old,
        )
        .unwrap();
        {
            let c = g.conn.lock().unwrap();
            c.execute("UPDATE processes SET exit_ts=?1 WHERE pid=10", params![old])
                .unwrap();
            c.execute(
                "INSERT INTO events (ts,path,op,pid,proc_start) VALUES (?1,'/tmp/a','create',10,?1)",
                params![old],
            )
            .unwrap();
            // Long-exited, but a retained event still names its pid.
            c.execute(
                "INSERT INTO processes (pid,start_ts,ppid,exe,comm,cmdline,uid,exit_ts)
                 VALUES (20,?1,1,'/bin/keep','keep','keep',0,?1)",
                params![old],
            )
            .unwrap();
            c.execute(
                "INSERT INTO events (ts,path,op,pid,proc_start) VALUES (?1,'/tmp/b','create',20,NULL)",
                params![new],
            )
            .unwrap();
        }

        let (p_prev, e_prev) = g.prune_preview(cutoff).unwrap();
        assert_eq!(e_prev, 1, "one event predates the cutoff");
        assert_eq!(p_prev, 1, "only the process with no retained events");

        let (procs, events) = g.prune(cutoff).unwrap();
        assert_eq!((procs, events), (1, 1));

        let c = g.conn.lock().unwrap();
        let kept: i64 = c
            .query_row("SELECT COUNT(*) FROM processes WHERE pid=20", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            kept, 1,
            "a process a retained event can still bind to must survive"
        );
        let gone: i64 = c
            .query_row("SELECT COUNT(*) FROM processes WHERE pid=10", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(gone, 0);
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
