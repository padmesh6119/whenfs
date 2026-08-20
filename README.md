# whenfs

Time is a directory.

```
cat  /when/yesterday/etc/nginx.conf
diff /when/last-week/etc/fstab /etc/fstab
rg   "api_key" /when/3-days-ago/home/pontiff/
```

A FUSE filesystem where the first path component is a time expression. Every
existing tool — `cat`, `grep`, `diff`, `vim`, `git` — becomes time-aware with
zero modification. Paired with `whodid`, which answers a question no OS
currently can: *what process changed this file, when, and what exactly did
it change.*

And with `chronicle`, which answers the one after it — **why**:

```
$ chronicle blame /etc/sudoers.d/99-thing
/etc/sudoers.d/99-thing
  2026-08-20T09-00-04  create  sh  pid 1002
  because:      sh ← curl ← bash
  root command: curl -fsSL https://get.example.com | sh
```

That chain is the causal graph: not just *who* wrote a file, but the lineage
of commands that led to that process existing at all. Snapshots record
state; only a live daemon watching fork/exec can record cause.

**Verified live**, not just in tests: `./demo.sh` mounts a real `whenfs`, runs a real
`whodidd` under `sudo`, and `whodid diff`/`whodid list` correctly attributed real edits,
a real rename, and a real create+delete to the exact processes that made them — down to
telling `mv` apart from the shell that invoked it.

See `../ARCHITECTURE.md` for the full design and rationale.

## What's here

- `whenfs` — the FUSE filesystem. Read-only passthrough over a directory of
  timestamped snapshot directories, with a time-expression resolver as the
  root lookup.
- `whodidd` — attribution daemon. Three watcher threads: two independent
  fanotify groups, both live-verified (legacy mode for modify/close_write,
  FID mode for create/delete/rename/attrib), plus a `NETLINK_CONNECTOR`
  proc-connector that caches process identity at exec time — live-verified
  to genuinely help (a real `mv`'s full cmdline, previously lost, is now
  captured) without fully closing the race for very short-lived processes
  (a real `rm` still lost its identity — see below). Also records
  `PROC_EVENT_FORK`, which supplies the parent→child edges the causal
  graph is built from. Writes to two sinks: the JSONL audit log and the
  SQLite graph beside it.
- `whodid` — query tool over the JSONL log. `list` shows history for a
  file; `diff` brackets each logged change between the snapshots on either
  side and shows the real content diff.
- `chronicle` — query tool over the causal graph.
  - `trace -- <cmd>` runs a command and reports **every path it and its
    descendants touched**. Scoped by process tree, not by time window —
    which is the only thing that works, since a browser cache and a dozen
    daemons are writing throughout. This is what the fork edge was for.
  - `blame <path>` — who last wrote a file, *and the ancestry chain
    explaining why that process existed*.
  - `log <path>` — full per-file history.
  - `tree <pid>` — every process descended from one.
  - `revert <pid>` — undo a traced command: restore each path it touched
    from the newest snapshot predating the command, and delete what it
    created. **Dry run unless `--apply`.** Refuses package-manager state
    (restoring files under dpkg/xbps leaves its database confidently wrong
    — that has to be undone *through* the package manager) and refuses
    anything outside the snapshotted tree, where a missing pre-image would
    otherwise be "restored" by deletion.
  - `stat` — graph size.

## Undo

```
$ chronicle trace -- sh install.sh
traced sh install.sh  exit 0, 0.3s, pid 4821
  5 paths touched by 4 processes
  ...

$ chronicle revert 4821 --snap /snap --live /home
dry run — undo plan for pid 4821

  restore  /home/app/config.toml   from 2026-08-20T09-14-00
  remove   /home/app/new-binary    (created by this command)
  skip     /var/lib/dpkg/status    — package manager state
  skip     /etc/hosts              — outside the snapshotted tree

  1 to restore, 1 to remove, 2 skipped
  dry run: nothing was changed. Re-run with --apply.
```

Only filesystem state. A command that sent a packet or charged a card is
not undone by any of this. Within the filesystem the model is: for each
path touched, restore whatever the newest snapshot *before* the command
holds — and if it holds no such file, the command created it, so removing
it is the restoration.

The pre-image is the snapshot before the **first** touch, not the last: a
command that writes a file repeatedly must be undone to its state before
the command began, not to some intermediate value the command produced.

Re-applying is safe — a file already removed is the desired end state, not
an error.

**Renames need no special handling.** `mv a b` emits `moved_from(a)` and
`moved_to(b)`. Nothing in the planner knows what a rename is, and it does
not need to: `a` existed before the command so it is restored, `b` did not
so it is removed, and the pair reconstitutes the original state. fanotify's
missing rename cookie is a problem for *describing* the change, never for
reversing it.

**Undo granularity is bounded by snapshot cadence.** The pre-image is the
newest snapshot *predating* the command — so anything changed after the
last snapshot but before the command is rolled back along with the
command's own work. Take a snapshot immediately before tracing if the
boundary needs to be exact rather than "within the last five minutes".

Removals run deepest-first, because a command that ran `mkdir -p a/b`
produces create events with the parent listed first, and `a` cannot be
removed before `a/b`. Directories are removed with `remove_dir`, never
`remove_dir_all`: a directory the command created but that now holds files
it did not is **kept**, and reported as kept rather than failed. Recursive
deletion there would destroy exactly the data the undo exists to protect.
- `snapshot.sh` — three interchangeable backends via `SNAPSHOT_MODE`, all
  live-verified: `hardlink` (default, `cp -al`, any filesystem, no
  privilege), `full` (`cp -a`, real independent copy, small trees only),
  `btrfs` (`btrfs subvolume snapshot -r`, true copy-on-write — confirmed a
  post-snapshot edit to the live tree cannot retroactively touch a
  snapshot, the property the other two modes can't give you).
- `snapshot-loop.sh` — runs `snapshot.sh` on an interval; the process a
  service supervisor (runit) will own later.
- `demo.sh` — builds a fresh lab, takes real snapshots across real time
  gaps, and runs every command above end-to-end.
- `btrfs-test.sh` — same shape as `demo.sh`, verifying the `btrfs` backend
  against a real loopback btrfs volume. Builds unprivileged, then
  re-execs itself under `sudo` for the mount step only (the loopback mount
  itself needs `CAP_SYS_ADMIN`) — just run `./btrfs-test.sh`, no `sudo`
  prefix needed, it self-elevates and prompts at the right point.

## Try it

```
./demo.sh                             # full demo — prompts sudo just for whodidd
./demo.sh --no-attribution            # time-travel only, no sudo prompt at all
WHENFS_PROFILE=release ./demo.sh      # against the optimized build
```

Never run the whole script with `sudo` — it builds and mounts as your own user, and
escalates only the one process that needs `CAP_SYS_ADMIN` (`whodidd`), prompting for your
password at that point.

## Path grammar

| Form | Example | Resolves to |
|---|---|---|
| Absolute (exact snapshot) | `/when/2026-08-19T03-08-27/…` | That exact snapshot |
| Date | `/when/2026-08-01/…` | Last snapshot of that day |
| Relative | `/when/3-days-ago/…`, `/when/2h-ago/…` | Evaluated at lookup time |
| Colloquial | `/when/yesterday/…`, `/when/last-month/…` | Evaluated at lookup time |
| Weekday | `/when/tuesday/…`, `/when/last-tuesday/…` | Most recent past occurrence |
| Named | `/when/<any-literal-dir-name>/…` | Exact match, falls through if no time expression matched |

Every form reduces to a target instant; the resolver picks the newest
snapshot at or before it. Full parser in `src/time_expr.rs`, with unit
tests (`cargo test --lib`) covering the boundary cases — weekday-equals-today,
month arithmetic, snapshot-bracket edges.

## The causal graph

`whodidd` maintains a SQLite graph (`graph.db`, beside the JSONL log):

| | |
|---|---|
| `processes` | keyed on `(pid, start_ts)` — a bare pid is **not** an identity, because pids recycle |
| `events` | every file write, bound to the *live incarnation* of the writing pid |
| fork edge | `ppid`, from `PROC_EVENT_FORK` — the parent→child link nothing else on the system records |

Transitive queries (ancestry upward, descendants downward) run as recursive
CTEs in SQLite rather than by loading all of history into memory — which is
why this moved off JSONL. The append-only log is still the audit trail; the
graph is the queryable index built from it.

Correctness properties covered by tests (`cargo test --lib`):

- a recycled pid never inherits a dead process's identity (`exit_ts` is
  load-bearing, not hygiene)
- `fork` then `exec` produces **one** process row, preserving the parent
  edge — exec replaces the image, not the process
- a write by an unidentified process is recorded with NULL attribution
  rather than dropped or guessed at; a hole in the graph is itself
  information
- process-tree scoping excludes unrelated concurrent writers, verified with
  a decoy process writing at the same moment

## Known v0 limitations

- **Two live runs, five real bugs.** Documented because they are the useful
  part. The first run's fixes were confirmed against the second run's real
  database; the second run's fixes (4 and 5 below) are verified by replaying
  the fixed binary over that same captured data, not yet by a third run.

  1. *Self-write feedback loop.* The daemon writes its log and database
     inside the mount it watches, so each recorded event was itself a write
     that produced another event. The run generated 27231 events in ~10
     seconds, **27214 of them (99.94%) the daemon recording itself**. Fixed
     by suppressing events from its own pid -- by pid rather than by path,
     so it holds wherever the files are placed.
  2. *pid resolution used liveness, not time.* `record_event` bound a pid
     with `WHERE exit_ts IS NULL`. fanotify and the netlink connector are
     independent sockets on independent threads, so a short-lived process
     is routinely recorded as exited before its own write is processed,
     and attribution was discarded. Now resolved against each incarnation's
     `[start_ts, exit_ts]` window, correct for both pid reuse and
     short-lived writers.
  3. *Nothing that predated the daemon was known.* Only processes forking
     after startup were recorded, so on a real machine almost every writer
     -- services, editors, browsers -- was anonymous. The daemon now seeds
     the table from `/proc` at startup.

  4. *Eager binding raced the fork message.* `record_event` resolved the
     writer at record time, but fanotify and the connector are separate
     sockets on separate threads: a process that forks, writes and exits in
     microseconds gets its write processed before its fork message is even
     read. The writing `cp` was present in `processes` with the correct
     parent while its own events pointed at nothing. Resolution now happens
     at **query** time, when both streams have settled.
  5. *Ancestry stopped at the first exited ancestor.* The recursive walk
     joined on `exit_ts IS NULL`, so climbing from a short-lived process --
     whose parents have usually also exited -- truncated at the first hop.
     Now matches the parent incarnation whose lifetime contained the
     child's birth.

  Worth noting the unit tests passed throughout all five. They called
  `record_event` before `record_exit` and before `record_fork`; real kernel
  ordering is the reverse of both. Only live traffic exposed it.

  What the fixes recovered, on the same data that previously returned
  nothing at all:

  ```
  $ chronicle blame .../live/traced.conf
    2026-08-20T02-02-26  create  <unnamed>  pid 16710
    because:    pid 16710 ← pid 16709 ← bash ← zsh ← x-terminal-emul ← systemd
    started by: bash ./demo.sh
  ```

  The two fastest processes still lost their *names* to the exit race
  (`<unnamed>` -- known process, unknown identity, distinct from
  `<unattributed>` where no process is known at all). Their ancestry still
  explains the write completely.
- **Recording every fork is untested at scale.** A busy machine forks
  constantly. Process rows are small and the edge is essential, but growth
  under real load is unmeasured -- and the one measurement taken so far was
  dominated by the feedback loop above, so it says nothing useful yet.
- **No rename-cookie correlation.** fanotify doesn't pair `FAN_MOVED_FROM`
  with its matching `FAN_MOVED_TO` the way inotify does; each is logged as
  an independent event rather than one "renamed X to Y" record. This
  affects *describing* a change, not undoing one — see below. (`FAN_RENAME`
  on Linux 5.17+ reports both halves in a single event and would fix the
  description; not implemented.)
- **Proc-connector narrows the exit race, doesn't close it.** Live-verified
  in both directions on the same run: a real `mv`'s identity, empty before
  the connector existed, is now fully captured including complete cmdline.
  A real `rm` in the same run still lost its identity. The connector reads
  `/proc/<pid>` right after receiving `PROC_EVENT_EXEC` instead of
  whenever the fanotify event happens to get processed — sooner, but not
  instantaneous, and a process short-lived enough (fork+exec+work+exit
  faster than notify-wake-parse-read) can still finish first. Fully
  closing this needs synchronous capture (seccomp/ptrace), not attempted.
- **`whodid diff` dedupes same-timestamp events; `whodid list` doesn't.**
  A new file's first write fires both `create` (FID group) and
  `close_write` (legacy group) within the same one-second timestamp
  granularity — `list` correctly shows both as distinct logged ops, `diff`
  collapses them since `bracket()` depends only on `ts` and would otherwise
  print the identical diff twice.
- **`whodidd` needs root** (`CAP_SYS_ADMIN` for `fanotify_init`). No way
  around this on stock Linux. `demo.sh` never runs as root itself — it
  shells out to `sudo` for just that one process.
- **`readdir /when` lists a curated shortcut set**, not the raw snapshot
  list — matches the `.zfs/snapshot`-style Unix idiom where lookup works
  even for entries `ls` won't show.
- **Snapshot-name collisions within the same second are handled by
  waiting, not by higher-resolution names.** A real bug (`cp -al`/`cp -a`
  silently nesting content one directory level deep when the destination
  already exists) was found and fixed this way rather than by changing
  the timestamp format, since `whodidd`'s event timestamps deliberately
  share that exact format for lexical bracketing in `whodid diff`.
