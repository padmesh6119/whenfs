# runit service scripts (reference, untested)

Written against runit's conventions but not exercised — this dev session has no Void/runit
system to run them on. Correct shape, unverified behavior. Verify service directory
ownership/permission rules (usually root-owned, mode 755) against current runit docs before
installing for real.

Layout matches what `sv` / `runsvdir` expect: `<service>/run` is the supervised process,
executed directly (not through a shell wrapper) so runit's supervisor can signal it.

- `whodidd/run` — attribution daemon. Needs root (`CAP_SYS_ADMIN`); the service directory
  itself should not run under `chpst -u` to a lesser user.
- `snapshot-loop/run` — periodic snapshotter. No special privilege needed beyond write
  access to the watched tree and snapshot root.

To install (once on a real runit system):

```
ln -s /path/to/whenfs/runit/whodidd /var/service/
ln -s /path/to/whenfs/runit/snapshot-loop /var/service/
```

Both scripts read their paths from environment variables rather than hardcoding them, so
set `WHEN_LIVE_ROOT` / `WHEN_SNAP_ROOT` / `WHEN_LOG_PATH` in the service's `env/` directory
(runit convention) or edit the `run` scripts directly for a single-machine setup.
