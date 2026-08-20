//! Planning the undo of a traced command.
//!
//! Deliberately split in two: building a plan is pure with respect to the
//! filesystem's *contents* (it only asks what exists) and is unit-tested;
//! applying it is the part that destroys things and lives in the CLI. Any
//! judgement about what should happen is therefore testable without a
//! single file being harmed to find out.
//!
//! # What "revert" can and cannot mean
//!
//! Only filesystem state. A command that sent a packet, charged a card or
//! dropped a table is not undone by any of this, and nothing here pretends
//! otherwise. Within the filesystem the model is simple: for each path the
//! command touched, restore whatever the newest snapshot taken *before* the
//! command holds -- and if that snapshot has no such file, the command
//! created it, so removing it is the restoration.

use std::path::{Path, PathBuf};

use crate::graph::FileEvent;

/// Paths whose reversal would do more harm than the change being undone.
///
/// Package manager databases are the sharp one: a command that ran
/// `apt install` leaves both files on disk and rows in dpkg's database, and
/// restoring the files underneath it produces a system whose package
/// manager confidently believes things that are no longer true. That has to
/// be undone *through* the package manager or not at all, so the honest
/// move is to refuse and say why.
const REFUSED_PREFIXES: &[&str] = &[
    "/var/lib/dpkg",
    "/var/lib/rpm",
    "/var/lib/pacman",
    "/var/db/xbps",
    "/var/lib/xbps",
    "/nix/store",
    "/proc",
    "/sys",
    "/dev",
    "/run",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The file existed before the command; put that version back.
    Restore { path: PathBuf, from: PathBuf },
    /// The file did not exist before the command; it created it.
    Remove { path: PathBuf },
    /// Left alone, with a reason the user can weigh.
    Skip { path: PathBuf, why: String },
}

impl Step {
    pub fn path(&self) -> &Path {
        match self {
            Step::Restore { path, .. } | Step::Remove { path } | Step::Skip { path, .. } => path,
        }
    }
}

fn refused(path: &Path) -> Option<String> {
    let s = path.to_string_lossy();
    REFUSED_PREFIXES
        .iter()
        .find(|p| s.starts_with(**p))
        .map(|p| {
            if p.contains("dpkg") || p.contains("rpm") || p.contains("pacman") || p.contains("xbps")
            {
                format!("package manager state ({p}) — undo via the package manager instead")
            } else {
                format!("not real persistent state ({p})")
            }
        })
}

/// Newest snapshot at or before `ts`.
///
/// Snapshot directory names share their format with event timestamps
/// specifically so this is a lexical comparison and not a date-parsing
/// problem — the same property `whodid diff` relies on.
fn snapshot_before<'a>(snapshots: &'a [String], ts: &str) -> Option<&'a String> {
    snapshots
        .iter()
        .filter(|s| s.as_str() <= ts)
        .max_by(|a, b| a.cmp(b))
}

/// Build the undo plan for a traced command.
///
/// `events` is the command's manifest, `snapshots` the available snapshot
/// directory names, `live_root` the tree those snapshots mirror.
pub fn plan(
    events: &[FileEvent],
    snapshots: &[String],
    snap_root: &Path,
    live_root: &Path,
) -> Vec<Step> {
    // First touch per path: the pre-image is the state before the command
    // began interfering with that file, not before its last write.
    let mut order: Vec<String> = Vec::new();
    let mut first_ts: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let touch = |path: &str,
                 ts: &str,
                 order: &mut Vec<String>,
                 first: &mut std::collections::HashMap<String, String>| {
        if !first.contains_key(path) {
            order.push(path.to_string());
            first.insert(path.to_string(), ts.to_string());
        }
    };
    for e in events {
        touch(&e.path, &e.ts, &mut order, &mut first_ts);
        // A rename reported atomically by FAN_RENAME arrives as one event
        // naming both ends. Undoing it means touching both: the source is
        // restored and the destination removed, exactly as the two separate
        // moved_from/moved_to events would have produced. Missing this
        // would silently leave the source deleted.
        if let Some(other) = e.other_path.as_deref() {
            touch(other, &e.ts, &mut order, &mut first_ts);
        }
    }

    let mut steps = Vec::with_capacity(order.len());
    for path_s in order {
        let path = PathBuf::from(&path_s);

        if let Some(why) = refused(&path) {
            steps.push(Step::Skip { path, why });
            continue;
        }

        // Refuse anything outside the tree the snapshots actually cover.
        // Without this a command that wrote to /etc while being traced
        // against a lab directory would have /etc "restored" from a
        // snapshot that never contained it — which is to say, deleted.
        let Ok(rel) = path.strip_prefix(live_root) else {
            steps.push(Step::Skip {
                path,
                why: format!("outside the snapshotted tree ({})", live_root.display()),
            });
            continue;
        };

        let ts = &first_ts[&path_s];
        let Some(snap) = snapshot_before(snapshots, ts) else {
            steps.push(Step::Skip {
                path,
                why: "no snapshot predates this change — nothing to restore from".into(),
            });
            continue;
        };

        let from = snap_root.join(snap).join(rel);
        if from.exists() {
            steps.push(Step::Restore { path, from });
        } else {
            steps.push(Step::Remove { path });
        }
    }

    // Return in an order that is safe to apply top to bottom.
    //
    // Removals must run deepest-first: a command that ran `mkdir -p a/b`
    // produces create events for both, and first-touch order lists the
    // parent first -- so removing `a` before `a/b` cannot work. Sorting by
    // path depth descending makes each directory empty before its own
    // removal is attempted.
    //
    // Restores go first so that a file being restored into a directory the
    // command created survives: the later attempt to remove that directory
    // then fails as not-empty, which is the correct outcome rather than a
    // race to see which wins.
    let depth = |p: &Path| p.components().count();
    let mut ordered: Vec<Step> = Vec::with_capacity(steps.len());
    ordered.extend(
        steps
            .iter()
            .filter(|s| matches!(s, Step::Restore { .. }))
            .cloned(),
    );
    let mut removes: Vec<Step> = steps
        .iter()
        .filter(|s| matches!(s, Step::Remove { .. }))
        .cloned()
        .collect();
    removes.sort_by_key(|s| std::cmp::Reverse(depth(s.path())));
    ordered.extend(removes);
    ordered.extend(steps.into_iter().filter(|s| matches!(s, Step::Skip { .. })));
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(path: &str, ts: &str) -> FileEvent {
        ev_op(path, ts, "create")
    }

    fn ev_op(path: &str, ts: &str, op: &str) -> FileEvent {
        FileEvent {
            ts: ts.into(),
            path: path.into(),
            op: op.into(),
            pid: 1,
            comm: "sh".into(),
            exe: String::new(),
            cmdline: String::new(),
            proc_start: None,
            other_path: None,
        }
    }

    fn lab() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "revert-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn file_present_before_the_command_is_restored_from_that_snapshot() {
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        std::fs::create_dir_all(snap_root.join("2026-01-01T00-00-00")).unwrap();
        std::fs::write(snap_root.join("2026-01-01T00-00-00").join("a.conf"), "old").unwrap();

        let steps = plan(
            &[ev(
                &format!("{}/a.conf", live.display()),
                "2026-01-02T00-00-00",
            )],
            &["2026-01-01T00-00-00".into()],
            &snap_root,
            &live,
        );
        match &steps[0] {
            Step::Restore { from, .. } => assert!(from.ends_with("a.conf")),
            other => panic!("expected Restore, got {other:?}"),
        }
    }

    #[test]
    fn file_absent_before_the_command_is_removed_because_it_created_it() {
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        std::fs::create_dir_all(snap_root.join("2026-01-01T00-00-00")).unwrap();

        let steps = plan(
            &[ev(
                &format!("{}/new.conf", live.display()),
                "2026-01-02T00-00-00",
            )],
            &["2026-01-01T00-00-00".into()],
            &snap_root,
            &live,
        );
        assert!(matches!(steps[0], Step::Remove { .. }), "{:?}", steps[0]);
    }

    #[test]
    fn the_pre_image_is_the_snapshot_before_the_first_touch_not_the_last() {
        // A command that writes a file repeatedly must be undone to its
        // state before the command started, not to some intermediate value
        // the command itself produced.
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        for s in ["2026-01-01T00-00-00", "2026-01-03T00-00-00"] {
            std::fs::create_dir_all(snap_root.join(s)).unwrap();
            std::fs::write(snap_root.join(s).join("a.conf"), s).unwrap();
        }
        let p = format!("{}/a.conf", live.display());
        let steps = plan(
            &[ev(&p, "2026-01-02T00-00-00"), ev(&p, "2026-01-04T00-00-00")],
            &["2026-01-01T00-00-00".into(), "2026-01-03T00-00-00".into()],
            &snap_root,
            &live,
        );
        assert_eq!(steps.len(), 1, "one step per path, not per event");
        match &steps[0] {
            Step::Restore { from, .. } => assert!(
                from.to_string_lossy().contains("2026-01-01"),
                "restored from {from:?}, wanted the pre-command snapshot"
            ),
            other => panic!("expected Restore, got {other:?}"),
        }
    }

    #[test]
    fn removals_are_ordered_deepest_first_so_directories_can_be_emptied() {
        // `mkdir -p a/b` creates events for the parent first, but removing
        // the parent before its child cannot work.
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        std::fs::create_dir_all(snap_root.join("2026-01-01T00-00-00")).unwrap();

        let steps = plan(
            &[
                ev(&format!("{}/opt", live.display()), "2026-01-02T00-00-00"),
                ev(
                    &format!("{}/opt/thing", live.display()),
                    "2026-01-02T00-00-00",
                ),
                ev(
                    &format!("{}/opt/thing/bin", live.display()),
                    "2026-01-02T00-00-00",
                ),
            ],
            &["2026-01-01T00-00-00".into()],
            &snap_root,
            &live,
        );
        let paths: Vec<String> = steps
            .iter()
            .map(|s| s.path().to_string_lossy().into_owned())
            .collect();
        let idx = |suffix: &str| paths.iter().position(|p| p.ends_with(suffix)).unwrap();
        assert!(
            idx("opt/thing/bin") < idx("opt/thing") && idx("opt/thing") < idx("opt"),
            "children must precede parents, got {paths:?}"
        );
    }

    #[test]
    fn restores_are_ordered_before_removals() {
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        let snap = snap_root.join("2026-01-01T00-00-00");
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(snap.join("kept.conf"), "old").unwrap();

        let steps = plan(
            &[
                ev(&format!("{}/made", live.display()), "2026-01-02T00-00-00"),
                ev(
                    &format!("{}/kept.conf", live.display()),
                    "2026-01-02T00-00-00",
                ),
            ],
            &["2026-01-01T00-00-00".into()],
            &snap_root,
            &live,
        );
        assert!(matches!(steps[0], Step::Restore { .. }), "{:?}", steps);
    }

    #[test]
    fn a_rename_is_undone_by_the_content_model_without_special_casing() {
        // `mv a b` emits moved_from(a) and moved_to(b). Nothing here knows
        // what a rename is, and it does not need to: the pre-image decides.
        // `a` existed before the command, so it is restored; `b` did not, so
        // it is removed. The pair reconstitutes the original state, which is
        // why fanotify's missing rename cookie is not a correctness problem
        // for undo -- only for *describing* the change as a rename.
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        let snap = snap_root.join("2026-01-01T00-00-00");
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(snap.join("a.conf"), "original").unwrap();

        let steps = plan(
            &[
                ev_op(
                    &format!("{}/a.conf", live.display()),
                    "2026-01-02T00-00-00",
                    "moved_from",
                ),
                ev_op(
                    &format!("{}/b.conf", live.display()),
                    "2026-01-02T00-00-00",
                    "moved_to",
                ),
            ],
            &["2026-01-01T00-00-00".into()],
            &snap_root,
            &live,
        );

        let restored: Vec<_> = steps
            .iter()
            .filter_map(|s| match s {
                Step::Restore { path, .. } => Some(path.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        let removed: Vec<_> = steps
            .iter()
            .filter_map(|s| match s {
                Step::Remove { path } => Some(path.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();

        assert_eq!(restored.len(), 1, "the source must come back: {steps:?}");
        assert!(restored[0].ends_with("a.conf"));
        assert_eq!(removed.len(), 1, "the destination must go: {steps:?}");
        assert!(removed[0].ends_with("b.conf"));
    }

    #[test]
    fn an_atomic_rename_event_undoes_both_ends() {
        // FAN_RENAME reports a rename as a single event naming both paths.
        // Handling only `path` would restore nothing and leave the source
        // gone -- worse than the two-event form it replaces.
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        let snap = snap_root.join("2026-01-01T00-00-00");
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(snap.join("a.conf"), "original").unwrap();

        let mut e = ev_op(
            &format!("{}/b.conf", live.display()),
            "2026-01-02T00-00-00",
            "renamed",
        );
        e.other_path = Some(format!("{}/a.conf", live.display()));

        let steps = plan(&[e], &["2026-01-01T00-00-00".into()], &snap_root, &live);
        assert_eq!(steps.len(), 2, "both ends must appear: {steps:?}");

        let restored = steps
            .iter()
            .any(|s| matches!(s, Step::Restore { path, .. } if path.ends_with("a.conf")));
        let removed = steps
            .iter()
            .any(|s| matches!(s, Step::Remove { path } if path.ends_with("b.conf")));
        assert!(restored, "the source must come back: {steps:?}");
        assert!(removed, "the destination must go: {steps:?}");
    }

    #[test]
    fn package_manager_state_is_refused_rather_than_corrupted() {
        let root = lab();
        let steps = plan(
            &[ev("/var/lib/dpkg/status", "2026-01-02T00-00-00")],
            &["2026-01-01T00-00-00".into()],
            &root.join("snap"),
            Path::new("/"),
        );
        match &steps[0] {
            Step::Skip { why, .. } => assert!(why.contains("package manager"), "{why}"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn paths_outside_the_snapshotted_tree_are_refused_not_deleted() {
        // The dangerous case: without this guard, a file the snapshots
        // never covered resolves to a non-existent pre-image and would be
        // "restored" by deleting it.
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        std::fs::create_dir_all(snap_root.join("2026-01-01T00-00-00")).unwrap();

        let steps = plan(
            &[ev("/etc/passwd", "2026-01-02T00-00-00")],
            &["2026-01-01T00-00-00".into()],
            &snap_root,
            &live,
        );
        match &steps[0] {
            Step::Skip { why, .. } => assert!(why.contains("outside"), "{why}"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn a_change_with_no_snapshot_before_it_is_refused() {
        let root = lab();
        let (snap_root, live) = (root.join("snap"), root.join("live"));
        let steps = plan(
            &[ev(
                &format!("{}/a.conf", live.display()),
                "2026-01-01T00-00-00",
            )],
            &["2026-06-01T00-00-00".into()],
            &snap_root,
            &live,
        );
        match &steps[0] {
            Step::Skip { why, .. } => assert!(why.contains("no snapshot"), "{why}"),
            other => panic!("expected Skip, got {other:?}"),
        }
    }
}
