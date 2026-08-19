#!/usr/bin/env bash
# End-to-end demo: builds a fresh lab, takes real snapshots across real time
# gaps, mounts whenfs, and runs the exact commands from ARCHITECTURE.md.
#
# Runs entirely as your normal user — never invoke this with sudo directly,
# `cargo` and the FUSE mount need to stay in your own account. Only whodidd
# (attribution) needs CAP_SYS_ADMIN, so this script shells out to `sudo` for
# just that one process and will prompt for your password at that point.
# Pass --no-attribution to skip it and skip the sudo prompt entirely.
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "don't run this with sudo — it escalates only whodidd internally." >&2
    echo "just run: ./demo.sh" >&2
    exit 1
fi

WANT_ATTRIBUTION=1
[ "${1:-}" = "--no-attribution" ] && WANT_ATTRIBUTION=0

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$DIR/.demo-lab"
PROFILE="${WHENFS_PROFILE:-debug}"
BIN="$DIR/target/$PROFILE"

cleanup() {
    fusermount3 -u "$LAB/mnt" 2>/dev/null || true
    [ -n "${WHODIDD_PID:-}" ] && sudo kill "$WHODIDD_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$LAB"
mkdir -p "$LAB/live" "$LAB/snap" "$LAB/mnt"

echo "== building ($PROFILE) =="
if [ "$PROFILE" = "release" ]; then
    (cd "$DIR" && cargo build --release 2>&1 | tail -5)
else
    (cd "$DIR" && cargo build 2>&1 | tail -5)
fi

RUNNING_AS_ROOT=0
if [ "$WANT_ATTRIBUTION" -eq 1 ]; then
    # Authenticate synchronously, in the foreground, BEFORE backgrounding
    # anything. A fixed sleep after `sudo whodidd & ` is not a reliable
    # readiness check — the clock starts before the password prompt is even
    # answered, so slow typing means files get written while whodidd is
    # still sitting at the prompt, and every event is silently missed. This
    # happened in testing: whodidd never started fanotify_mark at all before
    # the first edit landed. `sudo -v` here means the `sudo -n` below starts
    # immediately with a cached credential and no further prompt delay.
    echo "== authenticating for whodidd (live attribution) =="
    sudo -v

    WHODIDD_LOG="$LAB/whodidd.log"
    sudo -n "$BIN/whodidd" "$LAB/live" "$LAB/events.jsonl" >"$WHODIDD_LOG" 2>&1 &
    WHODIDD_PID=$!

    echo "== waiting for whodidd to arm both fanotify groups =="
    ARMED=0
    for _ in $(seq 1 50); do
        if ! kill -0 "$WHODIDD_PID" 2>/dev/null; then
            break
        fi
        if grep -q '\[legacy\] watching' "$WHODIDD_LOG" 2>/dev/null; then
            ARMED=1
            break
        fi
        sleep 0.1
    done

    if [ "$ARMED" -eq 1 ]; then
        RUNNING_AS_ROOT=1
        # give the fid thread a moment to finish its own mark call too —
        # its readiness or failure line isn't required to proceed, legacy
        # alone is enough to unblock the main demo, but this keeps the two
        # threads' startup output from interleaving with the edits below
        sleep 0.3
        cat "$WHODIDD_LOG"
    else
        echo "== whodidd failed to start — continuing without attribution =="
        cat "$WHODIDD_LOG" 2>/dev/null || true
    fi
else
    echo "== skipping whodidd (--no-attribution) =="
fi
if [ "$RUNNING_AS_ROOT" -eq 0 ]; then
    touch "$LAB/events.jsonl"
fi

# In-place truncate writes (not write-temp-then-rename), on purpose: v0
# attribution only sees FAN_CLOSE_WRITE under the filename actually
# written, and a rename-based save fires that event on the temp name
# instead — see whodidd.rs's top comment. SNAPSHOT_MODE=full makes each
# snapshot a true independent copy rather than a hardlink clone, so the
# later in-place truncate can't retroactively mutate the earlier snapshot
# (see the caveat in snapshot.sh) — correctness over snapshot cheapness in
# this small demo tree; real deployment on btrfs doesn't have this tension.
echo "== writing config v1, snapshotting =="
echo "server_name demo.local;" > "$LAB/live/nginx.conf"
SNAPSHOT_MODE=full "$DIR/snapshot.sh" "$LAB/live" "$LAB/snap" >/dev/null
sleep 1.5

echo "== editing config to v2, snapshotting =="
echo "server_name demo.local; # added TLS block" > "$LAB/live/nginx.conf"
SNAPSHOT_MODE=full "$DIR/snapshot.sh" "$LAB/live" "$LAB/snap" >/dev/null
sleep 0.5

echo "== mounting whenfs at $LAB/mnt =="
"$BIN/whenfs" "$LAB/snap" "$LAB/mnt" &
sleep 1

echo
echo "############################################################"
echo "# cat /when/now/nginx.conf"
echo "############################################################"
cat "$LAB/mnt/now/nginx.conf"

FIRST_SNAP=$(basename "$(ls -d "$LAB"/snap/*/ | head -1)")
LAST_SNAP=$(basename "$(ls -d "$LAB"/snap/*/ | tail -1)")

echo
echo "############################################################"
echo "# diff /when/$FIRST_SNAP/nginx.conf /when/$LAST_SNAP/nginx.conf"
echo "############################################################"
diff "$LAB/mnt/$FIRST_SNAP/nginx.conf" "$LAB/mnt/$LAST_SNAP/nginx.conf" || true

echo
echo "############################################################"
echo "# echo x > /when/$LAST_SNAP/nginx.conf   (should be rejected)"
echo "############################################################"
if echo x > "$LAB/mnt/$LAST_SNAP/nginx.conf" 2>&1; then
    echo "UNEXPECTED: write succeeded"
else
    echo "write correctly rejected: read-only past"
fi

if [ "$RUNNING_AS_ROOT" -eq 1 ]; then
    echo
    echo "############################################################"
    echo "# whodid diff — who changed nginx.conf, and what changed"
    echo "############################################################"
    "$BIN/whodid" diff "$LAB/events.jsonl" "$LAB/snap" "$LAB/mnt" "$LAB/live" "$LAB/live/nginx.conf"

    # FID-mode section: exercises exactly what legacy mode cannot see —
    # a rename-based save, and create/delete attribution.
    echo
    echo "== testing FID-mode: rename-based save (the pattern legacy mode misses) =="
    echo "server_name demo.local; # v3 via atomic rename" > "$LAB/live/nginx.conf.tmp"
    mv -f "$LAB/live/nginx.conf.tmp" "$LAB/live/nginx.conf"
    sleep 0.5

    echo
    echo "############################################################"
    echo "# whodid list nginx.conf — should now include a moved_to event"
    echo "############################################################"
    "$BIN/whodid" list "$LAB/events.jsonl" "$LAB/live/nginx.conf"

    echo
    echo "== testing FID-mode: create + delete attribution =="
    echo "scratch" > "$LAB/live/scratch.txt"
    sleep 0.3
    rm -f "$LAB/live/scratch.txt"
    sleep 0.3

    echo
    echo "############################################################"
    echo "# whodid list scratch.txt — should show create, then delete"
    echo "############################################################"
    "$BIN/whodid" list "$LAB/events.jsonl" "$LAB/live/scratch.txt"

    # ---- causal graph ----------------------------------------------
    # Everything above queries the JSONL log. This section queries the
    # SQLite graph instead, and is the part that needs real fanotify +
    # PROC_EVENT_FORK traffic to mean anything: the ancestry chain can
    # only exist if the daemon actually saw this shell fork its children.
    GRAPH="$LAB/graph.db"

    echo
    echo "############################################################"
    echo "# chronicle stat — did the daemon actually populate a graph?"
    echo "############################################################"
    if [ ! -s "$GRAPH" ]; then
        echo "NO GRAPH at $GRAPH — whodidd did not create one"
    else
        "$BIN/chronicle" --db "$GRAPH" stat

        # A write from a process the daemon watched fork, so the lineage
        # is real rather than reconstructed: a subshell running a
        # separate binary, several levels below demo.sh.
        ( sh -c "cp '$LAB/live/nginx.conf' '$LAB/live/traced.conf'" )
        sleep 0.5

        echo
        echo "############################################################"
        echo "# chronicle log traced.conf"
        echo "############################################################"
        "$BIN/chronicle" --db "$GRAPH" log "$LAB/live/traced.conf"

        echo
        echo "############################################################"
        echo "# chronicle blame traced.conf"
        echo "#   ancestry is the claim under test. Note it stops at the"
        echo "#   first process whodidd never saw fork: this script was"
        echo "#   already running before the daemon started, so the chain"
        echo "#   climbs only as far as the daemon actually observed."
        echo "############################################################"
        "$BIN/chronicle" --db "$GRAPH" blame "$LAB/live/traced.conf"

        echo
        echo "############################################################"
        echo "# chronicle tree \$\$ — every process this demo spawned."
        echo "#   Works even though the script predates the daemon: the"
        echo "#   /proc bootstrap seeds already-running processes at start."
        echo "############################################################"
        "$BIN/chronicle" --db "$GRAPH" tree "$$" 2>&1 | head -20

        # ---- trace ---------------------------------------------------
        # The payoff. A throwaway "installer" that scatters files around
        # and spawns children, run under trace: the manifest must contain
        # exactly what it touched and nothing from the rest of the machine,
        # which only works because the scoping is by process tree.
        cat > "$LAB/fake-install.sh" <<'INSTALLER'
#!/bin/sh
mkdir -p "$1/opt/thing"
echo "binary"  > "$1/opt/thing/thing"
echo "cfg"     > "$1/etc-thing.conf"
sh -c "echo 'from a grandchild' > '$1/nested.conf'"
cp "$1/etc-thing.conf" "$1/etc-thing.conf.bak"
rm -f "$1/etc-thing.conf.bak"
INSTALLER
        chmod +x "$LAB/fake-install.sh"

        echo
        echo "############################################################"
        echo "# chronicle trace -- sh fake-install.sh"
        echo "#   every path the script and its children touched, scoped"
        echo "#   by lineage. Unrelated writes elsewhere on the machine"
        echo "#   must NOT appear."
        echo "############################################################"
        TRACE_OUT="$("$BIN/chronicle" --db "$GRAPH" trace -- sh "$LAB/fake-install.sh" "$LAB/live" 2>&1)"
        echo "$TRACE_OUT"
        TPID="$(printf '%s' "$TRACE_OUT" | grep -oE 'pid [0-9]+' | head -1 | awk '{print $2}')"

        # ---- revert --------------------------------------------------
        # The whole point, end to end: undo exactly what that command did
        # and nothing else. Dry run first -- this deletes and overwrites
        # files, so seeing the plan before it runs is the default.
        if [ -n "$TPID" ]; then
            echo
            echo "############################################################"
            echo "# chronicle revert $TPID   (dry run — changes nothing)"
            echo "############################################################"
            "$BIN/chronicle" --db "$GRAPH" revert "$TPID" \
                --snap "$LAB/snap" --live "$LAB/live"

            echo
            echo "== files the installer created, before undo =="
            ls "$LAB/live" 2>/dev/null

            echo
            echo "############################################################"
            echo "# chronicle revert $TPID --apply"
            echo "############################################################"
            "$BIN/chronicle" --db "$GRAPH" revert "$TPID" \
                --snap "$LAB/snap" --live "$LAB/live" --apply

            echo
            echo "== after undo: the installer's files should be gone, =="
            echo "==            nginx.conf should still be here        =="
            ls "$LAB/live" 2>/dev/null
        else
            echo "could not determine traced pid — skipping revert"
        fi
    fi
fi

echo
echo "== demo complete =="
