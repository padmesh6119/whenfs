#!/usr/bin/env bash
# Daemon-mode wrapper around snapshot.sh: take a snapshot every INTERVAL
# seconds. This is the process a runit service script will supervise later.
set -euo pipefail

LIVE="$1"
SNAP_ROOT="$2"
INTERVAL="${3:-300}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "snapshot-loop: $LIVE -> $SNAP_ROOT every ${INTERVAL}s"
while true; do
    "$DIR/snapshot.sh" "$LIVE" "$SNAP_ROOT"
    sleep "$INTERVAL"
done
