#!/usr/bin/env bash
# Validates the btrfs backend added to snapshot.sh: a real loopback btrfs
# volume, a real subvolume, real `btrfs subvolume snapshot -r`, verified
# through a real whenfs mount — same shape as demo.sh, different substrate.
#
# Builds as your own user first, then re-execs itself under sudo for the
# mount-dependent part only. Two things this avoids, both found by testing:
#   - `sudo ./btrfs-test.sh` directly: sudo strips PATH, so `cargo` (in
#     ~/.cargo/bin via rustup) isn't found — this is the exact failure
#     demo.sh's design already avoided for the same reason.
#   - Building under sudo at all: `cargo build` running as root would leave
#     root-owned artifacts in target/, in your own repo, for every later
#     unprivileged build to trip over.
# The loopback mount itself genuinely needs CAP_SYS_ADMIN — confirmed this
# session that not even an unprivileged user namespace can route around
# that here (`/dev/loop-control` isn't group-writable) — so unlike demo.sh,
# this script's second half has to actually run as root, not just escalate
# one internal process.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${WHENFS_PROFILE:-debug}"
BIN="$DIR/target/$PROFILE"

if [ "$(id -u)" -ne 0 ]; then
    echo "== building ($PROFILE), as your own user =="
    if [ "$PROFILE" = "release" ]; then
        (cd "$DIR" && cargo build --release 2>&1 | tail -5)
    else
        (cd "$DIR" && cargo build 2>&1 | tail -5)
    fi
    echo "== re-executing under sudo for the loopback btrfs mount (will prompt) =="
    exec sudo WHENFS_PROFILE="$PROFILE" "$DIR/$(basename "$0")" "$@"
fi

# --- everything below runs as root, against the already-built binary ---

IMG="/tmp/whenfs-btrfs-test.img"
MNT="/tmp/whenfs-btrfs-mnt"
LIVE="$MNT/live"
SNAP="$MNT/snap"
WHENMNT="$DIR/.btrfs-test-mnt"

cleanup() {
    fusermount3 -u "$WHENMNT" 2>/dev/null || true
    umount "$MNT" 2>/dev/null || true
    rm -f "$IMG"
    rmdir "$MNT" "$WHENMNT" 2>/dev/null || true
}
trap cleanup EXIT

echo "== creating 512M loopback btrfs volume at $IMG =="
truncate -s 512M "$IMG"
mkfs.btrfs -q "$IMG"
mkdir -p "$MNT" "$WHENMNT"
mount -o loop "$IMG" "$MNT"

echo "== creating live subvolume (not a plain directory — snapshot needs a subvolume) =="
btrfs subvolume create "$LIVE" >/dev/null
mkdir -p "$SNAP"

echo "== writing v1, snapshotting via SNAPSHOT_MODE=btrfs =="
echo "config v1" > "$LIVE/config.txt"
SNAPSHOT_MODE=btrfs "$DIR/snapshot.sh" "$LIVE" "$SNAP"
sleep 1.1

echo "== editing to v2 IN PLACE — no rename workaround needed this time =="
echo "== (true CoW: a later write to LIVE can't touch a snapshot's blocks, =="
echo "==  unlike the cp -al hardlink-clone dev backend's documented caveat) =="
echo "config v2" > "$LIVE/config.txt"
SNAPSHOT_MODE=btrfs "$DIR/snapshot.sh" "$LIVE" "$SNAP"

set -- "$SNAP"/*
N0=$(basename "$1")
N1=$(basename "$2")

echo
echo "############################################################"
echo "# confirming btrfs itself rejects a write to a -r snapshot"
echo "# (before whenfs's own EROFS enforcement even gets involved)"
echo "############################################################"
if echo x > "$SNAP/$N0/config.txt" 2>&1; then
    echo "UNEXPECTED: write to a -r snapshot succeeded"
else
    echo "confirmed: filesystem-level read-only, independent of whenfs"
fi

echo
echo "== mounting whenfs over the btrfs snapshot directory =="
"$BIN/whenfs" "$SNAP" "$WHENMNT" &
sleep 1

echo
echo "############################################################"
echo "# diff across the two btrfs snapshots, via /when"
echo "############################################################"
diff "$WHENMNT/$N0/config.txt" "$WHENMNT/$N1/config.txt" || true

echo
echo "############################################################"
echo "# confirming true independence: editing LIVE again after both"
echo "# snapshots exist must not retroactively change either one"
echo "############################################################"
echo "config v3 - post-snapshot edit" > "$LIVE/config.txt"
echo "N0 (should still read v1):"
cat "$WHENMNT/$N0/config.txt"
echo "N1 (should still read v2):"
cat "$WHENMNT/$N1/config.txt"
echo "live (should read v3):"
cat "$LIVE/config.txt"

echo
echo "== btrfs backend verified =="
