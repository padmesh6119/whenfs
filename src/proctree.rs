//! The in-memory process tree.
//!
//! Everything forks. Measured on an idle desktop: 16.8 forks/second, or
//! 1.45 million a day, and at 193 bytes a row that is 267 MiB/day of
//! process table before a single file event is recorded. Writing every fork
//! to SQLite is not viable for a daemon meant to run unattended.
//!
//! Almost none of those processes ever touch a file. So the tree lives
//! here, cheaply, and persistence is deferred until a process (or a
//! descendant) actually produces a write worth attributing.
//!
//! This module holds the tree logic and none of the storage, so the two
//! invariants it rests on can be tested without a database or a kernel:
//!
//! 1. **Persisted implies every ancestor was persisted in the same pass.**
//!    That is what lets [`ProcTree::unpersisted_chain`] stop climbing at the
//!    first persisted ancestor rather than walking to init on every write.
//! 2. **Exit marks, it does not remove.** A write can still be sitting
//!    unprocessed in the fanotify queue when the connector reports the exit
//!    — separate sockets, separate threads, no ordering between them. This
//!    project lost short-lived writers' identities twice by assuming
//!    otherwise, so entries linger for a grace window instead.

use std::collections::HashMap;

/// Identity as captured at exec time, when the process is guaranteed alive.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub exe: String,
    pub comm: String,
    pub cmdline: String,
    pub uid: u32,
}

#[derive(Clone, Debug)]
pub struct ProcNode {
    pub ppid: Option<i32>,
    pub start_ts: String,
    pub info: ProcInfo,
    /// Set on exit; the entry survives until [`ProcTree::evict_stale`].
    pub exited: Option<String>,
    pub persisted: bool,
}

/// Guards against a malformed or cyclic parent chain costing an unbounded
/// walk. Real chains are a handful deep.
const MAX_CHAIN: usize = 64;

#[derive(Default)]
pub struct ProcTree {
    procs: HashMap<i32, ProcNode>,
}

impl ProcTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    pub fn get(&self, pid: i32) -> Option<&ProcNode> {
        self.procs.get(&pid)
    }

    pub fn info(&self, pid: i32) -> Option<ProcInfo> {
        self.procs.get(&pid).map(|n| n.info.clone())
    }

    pub fn start_ts(&self, pid: i32) -> Option<String> {
        self.procs.get(&pid).map(|n| n.start_ts.clone())
    }

    /// A process the daemon did not watch start — from the `/proc` scan at
    /// startup. `start_ts` is the daemon's start time: "existed as of
    /// then" is all that can honestly be claimed, and it satisfies
    /// `start_ts <= event_ts` for everything that follows.
    pub fn seed(&mut self, pid: i32, ppid: Option<i32>, info: ProcInfo, start_ts: &str) {
        self.procs.insert(
            pid,
            ProcNode {
                ppid,
                start_ts: start_ts.to_string(),
                info,
                exited: None,
                persisted: false,
            },
        );
    }

    pub fn on_fork(&mut self, parent: i32, child: i32, ts: &str) {
        self.procs.insert(
            child,
            ProcNode {
                ppid: Some(parent),
                start_ts: ts.to_string(),
                info: ProcInfo::default(),
                exited: None,
                persisted: false,
            },
        );
    }

    /// exec replaces the process image, not the process — so this updates
    /// in place, preserving the ppid and start_ts recorded at fork. Losing
    /// those would orphan the lineage edge that makes `blame` an
    /// explanation rather than just a name.
    pub fn on_exec(&mut self, pid: i32, info: ProcInfo, ppid_if_new: Option<i32>, ts: &str) {
        match self.procs.get_mut(&pid) {
            Some(node) => node.info = info,
            None => {
                self.procs.insert(
                    pid,
                    ProcNode {
                        ppid: ppid_if_new,
                        start_ts: ts.to_string(),
                        info,
                        exited: None,
                        persisted: false,
                    },
                );
            }
        }
    }

    /// Returns the node's start_ts if it was already persisted, so the
    /// caller can write the exit through to storage immediately.
    pub fn on_exit(&mut self, pid: i32, ts: &str) -> Option<String> {
        let node = self.procs.get_mut(&pid)?;
        node.exited = Some(ts.to_string());
        node.persisted.then(|| node.start_ts.clone())
    }

    /// The chain that must be written before `pid`'s events can be
    /// attributed, **root first** so parent rows exist before the children
    /// referencing them.
    ///
    /// Stops at the first already-persisted ancestor: by invariant 1 above,
    /// everything past it is already stored.
    pub fn unpersisted_chain(&self, pid: i32) -> Vec<(i32, ProcNode)> {
        let mut chain = Vec::new();
        let mut cur = pid;
        for _ in 0..MAX_CHAIN {
            let Some(node) = self.procs.get(&cur) else {
                break;
            };
            if node.persisted {
                break;
            }
            chain.push((cur, node.clone()));
            match node.ppid {
                // `p != cur` guards a self-parent; a longer cycle is caught
                // by MAX_CHAIN.
                Some(p) if p != cur => cur = p,
                _ => break,
            }
        }
        chain.reverse();
        chain
    }

    pub fn mark_persisted(&mut self, pid: i32) {
        if let Some(n) = self.procs.get_mut(&pid) {
            n.persisted = true;
        }
    }

    /// Drop processes that exited before `cutoff_ts`.
    ///
    /// Persisted ones are safe to forget: they are on disk, and invariant 1
    /// means a later descendant still links to them correctly through the
    /// stored `ppid`.
    pub fn evict_stale(&mut self, cutoff_ts: &str) -> usize {
        let before = self.procs.len();
        self.procs
            .retain(|_, n| n.exited.as_deref().is_none_or(|e| e >= cutoff_ts));
        before - self.procs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(comm: &str) -> ProcInfo {
        ProcInfo {
            exe: format!("/bin/{comm}"),
            comm: comm.into(),
            cmdline: comm.into(),
            uid: 1000,
        }
    }

    fn names(chain: &[(i32, ProcNode)]) -> Vec<String> {
        chain.iter().map(|(_, n)| n.info.comm.clone()).collect()
    }

    #[test]
    fn exec_preserves_the_fork_edge() {
        // Replacing the node on exec would orphan the ppid recorded at fork,
        // which is the whole basis of ancestry.
        let mut t = ProcTree::new();
        t.on_fork(1, 10, "2026-01-01T00-00-00");
        t.on_exec(10, info("sh"), None, "2026-01-01T00-00-01");

        let n = t.get(10).unwrap();
        assert_eq!(n.ppid, Some(1), "parent must survive exec");
        assert_eq!(n.start_ts, "2026-01-01T00-00-00", "birth time must survive");
        assert_eq!(n.info.comm, "sh");
        assert_eq!(t.len(), 1, "exec must not create a second entry");
    }

    #[test]
    fn exec_without_a_prior_fork_still_registers() {
        // The daemon started mid-life; better an unknown parent than no row.
        let mut t = ProcTree::new();
        t.on_exec(10, info("vim"), Some(1), "2026-01-01T00-00-00");
        assert_eq!(t.get(10).unwrap().ppid, Some(1));
    }

    #[test]
    fn exit_marks_rather_than_removes() {
        // The regression this exists to prevent: a write still queued in
        // fanotify when the connector reports the exit.
        let mut t = ProcTree::new();
        t.on_fork(1, 10, "2026-01-01T00-00-00");
        t.on_exec(10, info("rm"), None, "2026-01-01T00-00-00");
        t.on_exit(10, "2026-01-01T00-00-01");

        assert!(t.get(10).is_some(), "entry must survive its own exit");
        assert_eq!(t.info(10).unwrap().comm, "rm", "identity must survive too");
    }

    #[test]
    fn exit_reports_start_ts_only_when_already_persisted() {
        let mut t = ProcTree::new();
        t.on_fork(1, 10, "2026-01-01T00-00-00");
        assert_eq!(
            t.on_exit(10, "2026-01-01T00-00-05"),
            None,
            "nothing on disk to update yet"
        );

        t.on_fork(1, 11, "2026-01-01T00-00-00");
        t.mark_persisted(11);
        assert_eq!(
            t.on_exit(11, "2026-01-01T00-00-05").as_deref(),
            Some("2026-01-01T00-00-00"),
            "a persisted row needs its exit written through"
        );
    }

    #[test]
    fn chain_is_root_first_so_parents_exist_before_children() {
        let mut t = ProcTree::new();
        t.on_fork(1, 10, "t0");
        t.on_exec(10, info("bash"), None, "t0");
        t.on_fork(10, 20, "t1");
        t.on_exec(20, info("curl"), None, "t1");
        t.on_fork(20, 30, "t2");
        t.on_exec(30, info("sh"), None, "t2");

        assert_eq!(names(&t.unpersisted_chain(30)), vec!["bash", "curl", "sh"]);
    }

    #[test]
    fn chain_stops_at_the_first_persisted_ancestor() {
        // Invariant 1. Without this every write walks to init.
        let mut t = ProcTree::new();
        t.on_fork(1, 10, "t0");
        t.on_exec(10, info("bash"), None, "t0");
        t.on_fork(10, 20, "t1");
        t.on_exec(20, info("curl"), None, "t1");
        t.on_fork(20, 30, "t2");
        t.on_exec(30, info("sh"), None, "t2");

        t.mark_persisted(10);
        assert_eq!(
            names(&t.unpersisted_chain(30)),
            vec!["curl", "sh"],
            "bash is already stored; climbing past it is wasted work"
        );
    }

    #[test]
    fn chain_of_an_already_persisted_process_is_empty() {
        let mut t = ProcTree::new();
        t.on_fork(1, 10, "t0");
        t.mark_persisted(10);
        assert!(t.unpersisted_chain(10).is_empty());
    }

    #[test]
    fn chain_terminates_on_a_self_parent() {
        let mut t = ProcTree::new();
        t.on_fork(5, 5, "t0"); // pathological, but must not hang
        assert_eq!(t.unpersisted_chain(5).len(), 1);
    }

    #[test]
    fn chain_terminates_on_a_cycle() {
        let mut t = ProcTree::new();
        t.on_fork(20, 10, "t0");
        t.on_fork(10, 20, "t0"); // 10 -> 20 -> 10 -> ...
        assert!(t.unpersisted_chain(10).len() <= MAX_CHAIN);
    }

    #[test]
    fn eviction_removes_only_processes_that_exited_before_the_cutoff() {
        let mut t = ProcTree::new();
        t.on_fork(1, 10, "t0"); // still running
        t.on_fork(1, 20, "t0");
        t.on_exit(20, "2026-01-01T00-00-00"); // long gone
        t.on_fork(1, 30, "t0");
        t.on_exit(30, "2026-01-01T00-09-99"); // just now

        let removed = t.evict_stale("2026-01-01T00-05-00");
        assert_eq!(removed, 1);
        assert!(t.get(10).is_some(), "a live process must never be evicted");
        assert!(t.get(20).is_none(), "long-exited should go");
        assert!(
            t.get(30).is_some(),
            "recently exited must stay — its write may still be queued"
        );
    }
}
