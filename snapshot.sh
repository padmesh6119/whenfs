#!/usr/bin/env bash
# Takes one snapshot of LIVE into SNAP_ROOT/<timestamp>. Three modes via
# SNAPSHOT_MODE, in increasing order of correctness and decreasing
# portability:
#
#   (default)  cp -al   hardlink clone. Any filesystem, no privilege, no
#                        setup. Caveat: shares inodes with the live tree, so
#                        an in-place truncate write (`echo x > file`, as
#                        opposed to write-temp-then-rename) mutates every
#                        past snapshot that hardlinks that file too.
#   full       cp -a    real independent copy. Immune to the above, but
#                        doesn't scale — full copy cost every snapshot.
#                        Small demo/test trees only.
#   btrfs      btrfs subvolume snapshot -r   instant, true copy-on-write,
#                        no per-file copy cost regardless of tree size, and
#                        genuinely immune to the hardlink caveat — CoW means
#                        a later write to LIVE never touches a snapshot's
#                        blocks. The `-r` flag makes the snapshot read-only
#                        at the filesystem level, on top of (not instead of)
#                        whenfs's own EROFS enforcement. Requires LIVE to
#                        already be a btrfs subvolume (`btrfs subvolume
#                        create "$LIVE"`, not `mkdir`) on a mounted btrfs
#                        filesystem.
set -euo pipefail

LIVE="$1"
SNAP_ROOT="$2"
MODE="${SNAPSHOT_MODE:-hardlink}"

mkdir -p "$SNAP_ROOT"

# Snapshot names have one-second resolution. Two calls within the same
# second would otherwise silently collide: `cp -al`/`cp -a` treat an
# existing destination directory as "copy source INTO it", nesting the
# real content one level deep (SNAP_ROOT/$TS/live/... instead of
# SNAP_ROOT/$TS/...) with no error at all — found via testing, not
# hypothetical. Not a concern at the intended 5-minute daemon cadence, but
# a real risk for manual/rapid invocation (testing, a future "snapshot
# now" trigger). Wait out the collision rather than corrupt or silently
# drop the requested snapshot.
TS="$(date +%Y-%m-%dT%H-%M-%S)"
RETRIES=0
while [ -e "$SNAP_ROOT/$TS" ]; do
    RETRIES=$((RETRIES + 1))
    if [ "$RETRIES" -gt 3 ]; then
        echo "snapshot.sh: $SNAP_ROOT/$TS still occupied after $RETRIES retries, giving up" >&2
        exit 1
    fi
    sleep 1
    TS="$(date +%Y-%m-%dT%H-%M-%S)"
done

case "$MODE" in
    btrfs)
        btrfs subvolume snapshot -r "$LIVE" "$SNAP_ROOT/$TS" >/dev/null
        ;;
    full)
        cp -a "$LIVE" "$SNAP_ROOT/$TS"
        ;;
    hardlink)
        cp -al "$LIVE" "$SNAP_ROOT/$TS"
        ;;
    *)
        echo "unknown SNAPSHOT_MODE: $MODE (want: hardlink, full, or btrfs)" >&2
        exit 1
        ;;
esac

echo "snapshot: $SNAP_ROOT/$TS"
