import { useCallback, useEffect, useRef, useState } from "react";
import { api, BridgeError } from "./bridge";
import type { MonitorSnapshot } from "./types";

function bytesToGiB(b: number): string {
  return (b / (1024 ** 3)).toFixed(1);
}

function pctColor(pct: number | null): string {
  if (pct === null) return "var(--gauge-muted)";
  if (pct >= 90) return "var(--gauge-critical)";
  if (pct >= 80) return "var(--gauge-tight)";
  if (pct >= 60) return "var(--gauge-watch)";
  return "var(--gauge-healthy)";
}

function Gauge({ label, pct, detail }: { label: string; pct: number | null; detail: string }) {
  const color = pctColor(pct);
  const width = pct === null ? 0 : Math.min(100, Math.max(0, pct));
  return (
    <div className="gauge-card">
      <div className="gauge-header">
        <span>{label}</span>
        <span className="gauge-pct" style={{ color }}>
          {pct === null ? "—" : `${pct.toFixed(1)}%`}
        </span>
      </div>
      <div className="gauge-bar">
        <div className="gauge-fill" style={{ width: `${width}%`, background: color }} />
      </div>
      <div className="gauge-detail">{detail}</div>
    </div>
  );
}

function Sparkline({ values }: { values: number[] }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    if (values.length < 2) return;
    const max = Math.max(...values, 100);
    ctx.beginPath();
    ctx.strokeStyle = "var(--gauge-healthy)";
    ctx.lineWidth = 1.5;
    values.forEach((v, i) => {
      const x = (i / (values.length - 1)) * w;
      const y = h - (v / max) * h;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }, [values]);
  return <canvas ref={ref} width={240} height={40} className="sparkline" />;
}

export function MonitorTab({ serverId }: { serverId: string }) {
  const [snap, setSnap] = useState<MonitorSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"cpu" | "mem">("cpu");
  const [history, setHistory] = useState<number[]>([]);
  const timerRef = useRef<number | null>(null);

  const fetch = useCallback(async () => {
    try {
      const r = await api.monitor.poll(serverId);
      if ((r as any).status === "not_ready") {
        setError("Waiting for connection…");
        return;
      }
      setSnap(r);
      setError(r.probe_error);
      if (r.cpu?.utilization_pct !== null && r.cpu?.utilization_pct !== undefined) {
        setHistory((prev) => {
          const next = [...prev, r.cpu!.utilization_pct!];
          return next.length > 120 ? next.slice(-120) : next;
        });
      }
    } catch (e) {
      setError(e instanceof BridgeError ? e.message : String(e));
    }
  }, [serverId]);

  useEffect(() => {
    fetch();
    timerRef.current = window.setInterval(fetch, 2000);
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
  }, [fetch]);

  if (!snap) {
    return (
      <div className="monitor">
        <div className="monitor-header">
          <span>auto-refresh · 2s</span>
          <button className="btn" onClick={fetch}>Refresh</button>
        </div>
        {error ? <div className="form-error">{error}</div> : <div className="muted">Loading…</div>}
      </div>
    );
  }

  const cpuPct = snap.cpu?.utilization_pct ?? null;
  const memPct =
    snap.mem && snap.mem.total_bytes > 0
      ? (snap.mem.used_bytes / snap.mem.total_bytes) * 100
      : null;
  const diskPct =
    snap.disk && snap.disk.total_bytes > 0
      ? (snap.disk.used_bytes / snap.disk.total_bytes) * 100
      : null;

  const sorted = [...snap.processes].sort((a, b) => {
    const av = sortBy === "cpu" ? a.cpu ?? -1 : a.mem ?? -1;
    const bv = sortBy === "cpu" ? b.cpu ?? -1 : b.mem ?? -1;
    return bv - av;
  });

  return (
    <div className="monitor">
      <div className="monitor-header">
        <span>auto-refresh · 2s</span>
        <span className="muted">
          {snap.cpu
            ? `load ${snap.cpu.load_1.toFixed(2)} ${snap.cpu.load_5.toFixed(2)} ${snap.cpu.load_15.toFixed(2)} · ${snap.cpu.cores} cores · up ${Math.floor((snap.cpu.uptime_sec ?? 0) / 86400)}d`
            : "—"}
        </span>
        <button className="btn" onClick={fetch}>Refresh</button>
      </div>
      {error && <div className="form-error">{error}</div>}
      {snap.probe_error && <div className="form-error">Probe: {snap.probe_error}</div>}

      <div className="gauges">
        <Gauge
          label="Processor"
          pct={cpuPct}
          detail={
            snap.cpu?.cpu_warming
              ? "warming…"
              : snap.cpu
                ? `${cpuPct?.toFixed(1) ?? "—"}% · ${snap.cpu.cores} cores`
                : "—"
          }
        />
        <Gauge
          label="Memory"
          pct={memPct}
          detail={
            snap.mem
              ? `${bytesToGiB(snap.mem.used_bytes)} / ${bytesToGiB(snap.mem.total_bytes)} GiB · avail ${bytesToGiB(snap.mem.available_bytes)} GiB`
              : "—"
          }
        />
        <Gauge
          label="Storage"
          pct={diskPct}
          detail={
            snap.disk
              ? `${bytesToGiB(snap.disk.used_bytes)} / ${bytesToGiB(snap.disk.total_bytes)} GiB · avail ${bytesToGiB(snap.disk.available_bytes)} GiB`
              : "—"
          }
        />
      </div>

      <div className="sparkline-row">
        <span className="muted">CPU last 120 samples</span>
        <Sparkline values={history} />
      </div>

      <div className="table-wrap">
        <table className="proc-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>Process</th>
              <th className={sortBy === "cpu" ? "sorted" : ""} onClick={() => setSortBy("cpu")} role="button">
                CPU% {sortBy === "cpu" ? "▼" : ""}
              </th>
              <th className={sortBy === "mem" ? "sorted" : ""} onClick={() => setSortBy("mem")} role="button">
                Mem% {sortBy === "mem" ? "▼" : ""}
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.slice(0, 10).map((p) => (
              <tr key={p.pid}>
                <td>{p.pid}</td>
                <td>{p.name}</td>
                <td>{p.cpu === null ? "—" : p.cpu.toFixed(1)}</td>
                <td>{p.mem === null ? "—" : p.mem.toFixed(1)}</td>
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">No processes</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
