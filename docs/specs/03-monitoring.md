# Spec 03 — Infra Monitoring

**Status:** 📋 · **Depends on:** 02 (exec) · **Spec owner:** core + frontend

## 1. Overview

Live health of every server, drawn as gauges: CPU, memory, disk, and top
processes. Agentless — Zig execs the same read-only commands the user would
type, parses them, and serves a cached snapshot to the UI on demand.

## 2. Goals / non-goals

**Goals**
- CPU/RAM/disk gauges with threshold coloring, refreshed every 2 s.
- Top-10 processes, sortable by CPU% / Mem%.
- One-click **Clear Buffer/Cache** and **Clean Disk Space** (approval-gated).
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
- Three gauge cards in a row: **Processor** (load %, uptime, cores), **Memory** (used/total, available, swap), **Storage** (used/total, available).
- Below: **Top Processes** table (PID, process, CPU%, Mem%) — click column header to sort; and a sparkline strip (last 120 samples, canvas).
- Refresh indicator: "auto-refresh · 2s" with manual Refresh button.
- Gauge band colors (shared token set, spec 16):
  `0–60 healthy (accent/blue) · 60–80 watch (amber) · 80–90 tight (orange) · 90+ critical (red)`
- **Clear Buffer/Cache** (Memory card): one click + confirm; shows reclaimed delta ("Memory 61% → 34%").
- **Clean Disk Space** (Storage card): confirm dialog listing what will be swept; shows reclaimed amount.
- Per-process **→ AI** affordance (copies PID into the AI terminal prompt).

### 4.2 Oars+ PM2 panel (pending)
- Card listing PM2 processes: name, id, status, restarts, cpu/mem, uptime; actions Restart / Stop / Start (confirm for stop). Built from `pm2 jlist`.

### 4.3 Oars+ alerts (pending)
- Settings: per-server thresholds (cpu/disk default 90%), check on each snapshot; breach → red banner in the monitor header + sidebar dot turns red; dismiss per server.

## 5. Bridge API

### `oars.monitor.poll` `{server_id}` → snapshot (cached, ≤ 2 s old)
```json
{"ok":true,"ts":1754…,
 "cpu":{"load":12.7,"uptime_sec":19500000,"cores":2},
 "mem":{"used_bytes":4.63e9,"total_bytes":7.64e9,"available_bytes":3.01e9,"swap_bytes":0},
 "disk":{"used_bytes":20e9,"total_bytes":29e9,"available_bytes":8.8e9},
 "processes":[{"pid":39660,"name":"node","cpu":2.2,"mem":3.3}],
 "probe_error":null}
```
- `probe_error` set when the probe command fails (e.g. permission) — UI shows a degraded state, never a crash.

### `oars.monitor.probe` `{server_id}` (internal) — runs the command set, parses
Probe commands (read-only, one exec):
```
cat /proc/loadavg; nproc; cat /proc/uptime; cat /proc/meminfo;
df -kP /; ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu | head -n 11
```
- Parsing tolerates procps vs busybox variants (whitespace-flexible, unit handling).
- Oars+ PM2: `oars.monitor.pm2` `{server_id}` → `pm2 jlist` parsed to a bounded array; `oars.monitor.pm2Action` `{server_id, action: restart|stop|start, name}` — approval-gated.

## 6. Zig core design

- `src/monitor.zig` — probe runner + parsers (`parseProcLoadAvg`, `parseMemInfo`, `parseDf`, `parsePs`), each pure + unit-tested with fixture strings.
- `MonitorCache` per session: `{snapshot, last_probe_ns}` guarded by a spinlock; worker probes on a 2 s cadence **only while a poll is outstanding** (probe-on-demand with refresh-if-stale) to avoid burning CPU on idle servers. Simpler v1: probe every 2 s while session `ready`; stop on disconnect.
- Probe runs on the session worker via the exec path (channel opened, output captured until EOF; bounded read).
- Clean Disk Space implementation (exec, approval-gated): `find /var/log -name '*.log' -mtime +2 -delete; journalctl --vacuum-time=3d; find /tmp /var/tmp -type f -mtime +2 -delete; apt-get clean` — configurable scope per server, dry-run first showing reclaim estimate (`du -sh` of targets), then execute.

## 7. Data model

- No persistence in v1 (snapshots are ephemeral). Alert settings (pending): `settings.json` in app data dir; PM2 state is live-only.

## 8. Security

- Probe commands are read-only by construction (no pipes to `rm`/`sh -c` with user input; paths are fixed strings).
- Clean-disk and cache-clear are mutating → confirm dialog; audit entry written (spec 15).

## 9. Performance

- Probe exec every 2 s per connected server: negligible CPU; parse in Zig < 1 ms.
- Poll returns the cached snapshot (no exec on the bridge path — the main thread never waits on the network).
- Sparklines: 120 samples × 3 metrics in a canvas; no DOM churn.

## 10. Edge cases

- Server without `/proc` (containers) → `probe_error: "no /proc"`, gauges show "—".
- Busybox `ps` without `--sort` → fallback `ps -eo pid,comm,%cpu,%mem` unsorted (parse both).
- Huge process table → bounded to 10 rows after parse.
- Monitor requested before `ready` → `{"status":"not_ready"}`; UI shows "waiting for connection".
- Disk at 100% → parse still works; gauges clamp to 100.

## 11. Testing

- Unit: each parser against fixtures (procps, busybox, weird whitespace, missing fields).
- Integration: run probes against dockerized sshd container; verify numbers vs `top` inside container.
- Manual: gauge color transitions, sort, clean-disk dry run, PM2 actions.

## 12. Acceptance criteria

- [ ] Gauges + top-10 render live for a connected server, refresh ≤ 2 s.
- [ ] Parser fixtures green for procps + busybox variants.
- [ ] Clear cache and clean disk run only after confirm and write audit entries.
- [ ] Idle servers consume no probe traffic (no poll → no exec).
- [ ] PM2 list/restart/stop work against a container running PM2.
