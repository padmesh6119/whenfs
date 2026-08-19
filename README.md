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
- `chronicle` — query tool over the causal graph. `blame <path>` shows who
  last wrote a file *and the ancestry chain explaining why that process
  existed*; `log <path>` is full per-file history; `tree <pid>` lists every
  process descended from one, which is the primitive a future
  trace-and-revert would scope itself with; `stat` shows graph size.
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

- **The causal graph has not been live-verified yet.** Its logic is covered
  by unit tests and the `chronicle` CLI was exercised end-to-end against a
  seeded database, but no run has yet had `whodidd` populate a graph from
  real fanotify + fork traffic under root. Every prior component here
  produced real bugs only once it met real kernel events, so treat the
  graph as unproven until that run happens.
- **Recording every fork is untested at scale.** A busy machine forks
  constantly (every shell pipeline stage). Process rows are small and the
  edge is essential, but growth rate and the resulting SQLite size under
  real load are unmeasured.
- **No rename-cookie correlation.** fanotify doesn't pair `FAN_MOVED_FROM`
  with its matching `FAN_MOVED_TO` the way inotify does; each is logged as
  an independent event rather than one "renamed X to Y" record.
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
