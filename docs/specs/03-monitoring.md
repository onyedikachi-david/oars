# Spec 03 — Infra Monitoring

**Status:** 📋 · **Depends on:** 02 (exec) · **Spec owner:** core + frontend

## 1. Overview

Live health of every server, drawn as gauges: CPU, memory, disk, and top
processes. Agentless — Zig execs the same read-only commands the user would
type, parses them, and serves a cached snapshot to the UI on demand.

## 2. Goals / non-goals

**Goals**
- CPU utilization, load average, RAM, and disk gauges with threshold coloring,
  refreshed every 2 s.
- Top-10 processes, sortable by CPU% / Mem%.
- Advanced **Drop filesystem caches** diagnostics and a disk-space analyzer
  with itemized, approval-gated cleanup actions.
- Per-server sparkline history (client-side ring buffer).
- (Oars+) PM2 process list with restart/stop; (Oars+) threshold alerts.

**Non-goals**
- No long-term history, no fleet aggregation dashboards (v1), no
  Prometheus/Grafana replacement, no alert delivery outside the app (v1).

## 3. User stories

- I glance at my server list and see which box is at 95% disk without opening anything.
- A runaway process appears in the top-10 with its PID; I hand it to the AI terminal.
- My disk fills up; one click (after confirm) reclaims space.

## 4. UI/UX

### 4.1 Monitor view (per-server tab)
- Three gauge cards in a row: **Processor** (CPU utilization, 1/5/15-minute
  load average, uptime, cores), **Memory** (used/total, available, swap), and
  **Storage** (used/total, available).
- Below: **Top Processes** table (PID, process, CPU%, Mem%) — click column header to sort; and a sparkline strip (last 120 samples, canvas).
- Refresh indicator: "auto-refresh · 2s" with manual Refresh button.
- Gauge band colors (shared token set, spec 16):
  `0–60 healthy (accent/blue) · 60–80 watch (amber) · 80–90 tight (orange) · 90+ critical (red)`
- **Drop filesystem caches** remains available under Advanced diagnostics. It
  is hidden from the normal monitoring flow. Its confirmation explains that
  Linux reclaims caches automatically, the action can cause extra I/O and CPU,
  and it is intended for testing or diagnosis. Show memory before and after,
  but never describe the difference as a lasting performance improvement.
- **Analyze disk space** lists candidates and estimated reclaim size. The user
  selects exact categories before Oars runs any cleanup. Oars never deletes
  `/tmp`, application logs, or package data by age from one broad command.
- Per-process **→ AI** affordance (copies PID into the AI terminal prompt).

### 4.2 Oars+ PM2 panel (planned)
- Card listing PM2 processes: name, id, status, restarts, cpu/mem, uptime; actions Restart / Stop / Start (confirm for stop). Built from `pm2 jlist`.

### 4.3 Oars+ alerts (planned)
- Settings: per-server thresholds (cpu/disk default 90%), check on each snapshot; breach → red banner in the monitor header + sidebar dot turns red; dismiss per server.

## 5. Bridge API

### `oars.monitor.poll` `{server_id}` → snapshot (cached, ≤ 2 s old)
```json
{"ok":true,"ts":1754…,
 "cpu":{"utilization_pct":12.7,"load_1":0.25,"load_5":0.20,"load_15":0.18,
        "uptime_sec":19500000,"cores":2},
 "mem":{"used_bytes":4.63e9,"total_bytes":7.64e9,"available_bytes":3.01e9,
        "swap_used_bytes":0,"swap_total_bytes":0},
 "disk":{"used_bytes":20e9,"total_bytes":29e9,"available_bytes":8.8e9},
 "processes":[{"pid":39660,"name":"node","cpu":2.2,"mem":3.3}],
 "probe_error":null}
```
- `probe_error` set when the probe command fails (e.g. permission) — UI shows a degraded state, never a crash.

### `oars.monitor.probe` `{server_id}` (internal) — runs the command set, parses
Probe commands (read-only, one exec):
```
cat /proc/stat; cat /proc/loadavg; nproc; cat /proc/uptime; cat /proc/meminfo;
df -kP /; ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu | head -n 11
```
- CPU utilization is computed from deltas between the current and previous
  cached `/proc/stat` samples. The first valid probe returns
  `utilization_pct:null` with `cpu_warming:true`; it does not invent a
  percentage from load average.
  `/proc/loadavg` is reported as load average and is never labeled as a
  percentage. Parsing uses capability-specific command variants for procps and
  BusyBox; it does not assume one `ps -o` form works on both.
- Oars+ PM2: `oars.monitor.pm2` `{server_id}` → `pm2 jlist` parsed to a bounded array; `oars.monitor.pm2Action` `{server_id, action: restart|stop|start, name}` — approval-gated.

## 6. Zig core design

- `src/monitor.zig` — probe runner + parsers (`parseProcLoadAvg`, `parseMemInfo`, `parseDf`, `parsePs`), each pure + unit-tested with fixture strings.
- `MonitorCache` per session: `{snapshot, previous_cpu_sample,
  probe_in_flight, last_probe_ns}` guarded by a spinlock. A poll returns the
  current snapshot immediately and enqueues one worker probe when the cache is
  stale and no probe is already running. Thus a visible view can refresh every
  2 s, while a session with no monitor poll generates no probe traffic.
- Probe runs on the session worker via the exec path (channel opened, output captured until EOF; bounded read).
- Disk cleanup uses separate fixed action plans. Examples are archived-journal
  vacuuming and package-cache cleanup. Each plan has its own preview, required
  privilege, command, result, and audit record. Log and temporary-file cleanup
  is out of scope until Oars can prove ownership and show every affected path.
- Drop-caches diagnostics run `sync` first, then write the selected documented
  value (`1`, `2`, or `3`) to `/proc/sys/vm/drop_caches` with approved root or
  non-interactive sudo authority. The default is `3`, matching the product's
  combined page-cache and reclaimable-slab action. Record the exact choice and
  before/after snapshot in audit history.

## 7. Data model

- No persistence in v1 (snapshots are ephemeral). Planned alert settings use
  `settings.json` in the app data directory; PM2 state is live-only.

## 8. Security

- Probe commands are read-only by construction (no pipes to `rm`/`sh -c` with user input; paths are fixed strings).
- Clean-disk, cache-drop, and PM2 actions are mutating. Each action needs its
  own confirmation and audit entry (spec 15).

## 9. Performance

- Measure probe cost under 50 connected servers before setting the default
  cadence. The target parser budget is 1 ms per snapshot; it is a target, not a
  verified result.
- Poll returns the cached snapshot (no exec on the bridge path — the main thread never waits on the network).
- Sparklines: 120 samples × 3 metrics in a canvas; no DOM churn.

## 10. Edge cases

- Server without `/proc` (containers) → `probe_error: "no /proc"`, gauges show "—".
- Busybox `ps` without `--sort` → fallback `ps -eo pid,comm,%cpu,%mem` unsorted (parse both).
- Huge process table → bounded to 10 rows after parse.
- Monitor requested before `ready` → `{"status":"not_ready"}`; UI shows "waiting for connection".
- First CPU sample → utilization shows "warming up" until the next valid
  delta; load average and other gauges still render.
- Disk at 100% → parse still works; gauges clamp to 100.

## 11. Testing

- Unit: each parser against fixtures (procps, busybox, weird whitespace, missing fields).
- Integration: run probes against dockerized sshd container; verify numbers vs `top` inside container.
- Manual: gauge color transitions, sort, drop-caches warning and result,
  disk-analysis preview, PM2 actions.

## 12. Acceptance criteria

- [ ] Gauges + top-10 render live for a connected server, refresh ≤ 2 s.
- [ ] Parser fixtures green for procps + busybox variants.
- [ ] Disk analysis is read-only. Each selected cleanup runs only after confirm
      and writes an audit entry.
- [ ] Drop filesystem caches is hidden under Advanced diagnostics, requires an
      explicit warning confirmation and privilege check, and records the exact
      operation and before/after snapshot.
- [ ] Idle servers consume no probe traffic (no poll → no exec).
- [ ] PM2 list/restart/stop work against a container running PM2.

## 13. Research & References

- **`/proc` sources** — verified against the Linux kernel documentation
  (`https://www.kernel.org/doc/html/latest/filesystems/proc.html`):
  - `/proc/loadavg` = "Load average of last 1, 5 & 15 minutes; number of
    processes currently runnable (running or on ready queue); total
    number of processes in system; last pid created. … separated by a
    slash ('/')… Example: `0.61 0.61 0.55 3/828 22084`". This matches
    our probe's parse of the first three fields as 1/5/15-min load.
  - `/proc/meminfo` = memory utilization; fields `MemTotal`, `MemFree`,
    `MemAvailable` ("an estimate of how much memory is available for
    starting new applications, without swapping" — the right value for
    our "available" gauge), `SwapTotal`, `SwapFree`. Units are kB.
  - `/proc/uptime` = "wall clock since boot, combined idle time of all
    cpus" (seconds).
  - Containers without `/proc` are a real failure mode the spec handles
  via `probe_error`.
  `/proc/loadavg` is not CPU utilization. This review added `/proc/stat`
  delta sampling and split the API fields so the UI cannot label load average
  as a percent.
- **`nproc`** — GNU coreutils (manual:
  `https://www.gnu.org/software/coreutils/manual/html_node/nproc-invocation.html`),
  prints the number of processing units available to the current process
  (respects taskset/affinity).
- **`df -kP`** — verified in the GNU coreutils manual
  (`https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html`):
  `-k` prints sizes in 1024-byte blocks; `-P` selects the POSIX output
  format (each file system on exactly one line, POSIX headers). Both
  flags exist on GNU df; busybox `df` supports `-kP` too (busybox
  applet docs) — the parser tolerates both.
- **`ps`** — verified against the procps-ng man page
  (`https://man7.org/linux/man-pages/man1/ps.1.html`): `-e` selects all
  processes; `-o` user-defined format with keywords `pid`, `comm`
  (executable name), `%cpu`/`pcpu` (cputime/realtime ratio), `%mem`/
  `pmem` (RSS/total ratio); `--sort` takes `[+|-]key` where key is a
  format specifier (e.g. `--sort=-%cpu`). `comm` vs `args`: comm is the
  executable name only — matches our "process" column. Busybox `ps`
  lacks `--sort` and `-o %cpu` variations — the fallback path in §6 is
  verified as necessary (busybox ps supports `-o` with limited fields
  and no GNU-style sorting).
- **Cache and cleanup safety** — the Linux kernel documentation for
  `drop_caches` says that it is not a cache-growth control and that use outside
  testing or debugging is not recommended because rebuilding caches can cost
  significant I/O and CPU. Oars therefore keeps the planned feature as an
  advanced diagnostic with the kernel warning and explicit privilege approval,
  rather than presenting it as routine cleanup. `journalctl --vacuum-time` and
  `apt-get clean` remain possible itemized actions; the previous broad
  age-based `find -delete` command was removed because it could delete
  application-owned files.
  See the kernel VM sysctl documentation
  (`https://www.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html#drop-caches`),
  systemd `journalctl --vacuum-time`
  (`https://www.freedesktop.org/software/systemd/man/latest/journalctl.html`),
  and Debian's `apt-get clean` reference
  (`https://manpages.debian.org/testing/apt/apt-get.8.en.html`).
- **PM2 jlist/actions** — `pm2 list`/`pm2 restart <name>`/`pm2 stop
  <name>` verified in PM2's official docs
  (`https://pm2.keymetrics.io/docs/usage/process-management/`); `pm2
  jlist` (JSON output for programmatic use) is the documented machine
  interface in the PM2 CLI reference
  (`https://pm2.keymetrics.io/docs/usage/pm2-doc-single-page/`).

Sources: kernel docs (proc.html), GNU coreutils manual (df/nproc),
procps-ng ps(1), GNU findutils find(1), systemd journalctl(1), PM2 docs.
