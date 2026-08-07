import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  Clock3,
  Cpu,
  FlaskConical,
  HardDrive,
  MemoryStick,
  RefreshCw,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import { api, BridgeError } from "./bridge";
import { Button } from "./components/ui/button";
import type { MonitorSnapshot, Server } from "./types";

type GaugeTone = "healthy" | "watch" | "tight" | "critical" | "muted";
type DiskPlan = "journal" | "apt";
type RunStatus = "idle" | "running" | "success" | "error";

interface RunState {
  status: RunStatus;
  output: string;
  exitCode: number | null;
}

interface PlanState {
  estimate: RunState;
  cleanup: RunState;
}

type PlanStates = Record<DiskPlan, PlanState>;

interface MonitorHistory {
  cpu: number[];
  memory: number[];
  storage: number[];
}

type Approval =
  | { kind: "cleanup"; plan: DiskPlan }
  | { kind: "drop-caches" };

const DISK_PLANS: Record<
  DiskPlan,
  { title: string; description: string; estimateCommand: string; cleanupCommand: string }
> = {
  journal: {
    title: "System journal",
    description: "Review current journal use, then remove archived entries older than three days.",
    estimateCommand: "journalctl --disk-usage",
    cleanupCommand: "journalctl --vacuum-time=3d",
  },
  apt: {
    title: "APT package cache",
    description: "Review the package download cache, then remove cached package files.",
    estimateCommand: "du -sb /var/cache/apt",
    cleanupCommand: "apt-get clean",
  },
};

function emptyRun(): RunState {
  return { status: "idle", output: "", exitCode: null };
}

function emptyPlans(): PlanStates {
  return {
    journal: { estimate: emptyRun(), cleanup: emptyRun() },
    apt: { estimate: emptyRun(), cleanup: emptyRun() },
  };
}

function emptyHistory(): MonitorHistory {
  return { cpu: [], memory: [], storage: [] };
}

function bytesToGiB(bytes: number): string {
  return (bytes / 1024 ** 3).toFixed(1);
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  if (days > 0) return `${days}d`;
  const hours = Math.floor(seconds / 3600);
  if (hours > 0) return `${hours}h`;
  return `${Math.floor(seconds / 60)}m`;
}

function snapshotMilliseconds(timestamp: number): number {
  if (timestamp > 1e15) return timestamp / 1e6;
  if (timestamp > 1e12) return timestamp;
  return timestamp * 1000;
}

function formatSnapshotAge(timestamp: number): string {
  if (!timestamp) return "Waiting for first sample";
  const ageSeconds = Math.max(0, Math.round((Date.now() - snapshotMilliseconds(timestamp)) / 1000));
  if (ageSeconds < 5) return "Updated just now";
  if (ageSeconds < 60) return `Updated ${ageSeconds}s ago`;
  return `Updated ${Math.floor(ageSeconds / 60)}m ago`;
}

function gaugeTone(percent: number | null): GaugeTone {
  if (percent === null) return "muted";
  if (percent >= 90) return "critical";
  if (percent >= 80) return "tight";
  if (percent >= 60) return "watch";
  return "healthy";
}

function toneLabel(tone: GaugeTone): string {
  return {
    healthy: "Healthy",
    watch: "Watch",
    tight: "Tight",
    critical: "Critical",
    muted: "Waiting",
  }[tone];
}

function highestTone(tones: GaugeTone[]): GaugeTone {
  const priority: GaugeTone[] = ["critical", "tight", "watch", "healthy", "muted"];
  return priority.find((tone) => tones.includes(tone)) ?? "muted";
}

function messageOf(error: unknown): string {
  return error instanceof BridgeError ? error.message : String(error);
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function ResourceMetric({
  icon: Icon,
  title,
  percent,
  summary,
  facts,
  waitingLabel,
}: {
  icon: React.ComponentType<{ size?: number; className?: string }>;
  title: string;
  percent: number | null;
  summary: string;
  facts: Array<{ label: string; value: string }>;
  waitingLabel?: string;
}) {
  const tone = gaugeTone(percent);
  const width = percent === null ? 0 : Math.min(100, Math.max(0, percent));
  return (
    <section className={`monitor-metric monitor-tone-${tone}`} aria-label={`${title} resource use`}>
      <header className="monitor-metric-header">
        <span className="monitor-metric-icon" aria-hidden><Icon size={17} /></span>
        <span className="monitor-metric-title">{title}</span>
        <span className="monitor-state"><span className="monitor-state-dot" aria-hidden />{toneLabel(tone)}</span>
      </header>
      <div className="monitor-metric-value">
        {percent === null ? <span className="monitor-metric-waiting">{waitingLabel ?? "—"}</span> : <>{percent.toFixed(1)}<small>%</small></>}
      </div>
      <p className="monitor-metric-summary">{summary}</p>
      <div
        className="monitor-meter"
        role="progressbar"
        aria-label={`${title} use`}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent === null ? undefined : Math.round(width)}
      >
        <span style={{ width: `${width}%` }} />
      </div>
      <dl className="monitor-metric-facts">
        {facts.map((fact) => (
          <div key={fact.label}>
            <dt>{fact.label}</dt>
            <dd>{fact.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function Sparkline({ series }: { series: Array<{ values: number[]; color: string }> }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;

    const draw = () => {
      const context = canvas.getContext("2d");
      if (!context) return;
      const width = Math.max(1, Math.round(canvas.clientWidth));
      const height = Math.max(1, Math.round(canvas.clientHeight));
      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      context.clearRect(0, 0, width, height);

      const styles = getComputedStyle(canvas);
      const grid = styles.getPropertyValue("--gauge-grid").trim() || "rgba(0,0,0,0.08)";
      context.strokeStyle = grid;
      context.lineWidth = 1;
      context.setLineDash([3, 5]);
      for (const percent of [60, 90]) {
        const y = height - (percent / 100) * (height - 10) - 5;
        context.beginPath();
        context.moveTo(0, y);
        context.lineTo(width, y);
        context.stroke();
      }

      const sampleSpacing = width / 119;
      context.setLineDash([]);
      series.forEach(({ values, color }) => {
        if (values.length < 2) return;
        context.strokeStyle = styles.getPropertyValue(color).trim() || "#5a8a7a";
        context.lineWidth = 2;
        context.lineJoin = "round";
        context.lineCap = "round";
        context.beginPath();
        values.forEach((value, index) => {
          const x = width - (values.length - 1 - index) * sampleSpacing;
          const y = height - (Math.min(100, Math.max(0, value)) / 100) * (height - 10) - 5;
          if (index === 0) context.moveTo(x, y);
          else context.lineTo(x, y);
        });
        context.stroke();
      });
    };

    draw();
    const observer = new ResizeObserver(draw);
    observer.observe(canvas);
    return () => observer.disconnect();
  }, [series]);

  return <canvas ref={ref} className="monitor-sparkline" role="img" aria-label="Processor, memory, and storage use over the last 120 samples" />;
}

async function readExecChannel(
  serverId: string,
  channel: number,
  onChunk: (output: string) => void,
  isActive: () => boolean,
): Promise<{ output: string; exitCode: number | null }> {
  let cursor = 0;
  let output = "";
  let missingPolls = 0;

  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (!isActive()) throw new Error("Operation canceled");
    const result = await api.ssh.poll(serverId, [{ channel, cursor }], false);
    const current = result.channels.find((entry) => entry.id === channel);
    if (!current) {
      missingPolls += 1;
      if (missingPolls >= 8) throw new Error("Command output channel was not available");
      await wait(250);
      continue;
    }
    missingPolls = 0;
    if (current.data) {
      output += current.data;
      output = output.slice(-6000);
      onChunk(output);
    }
    cursor = current.cursor;
    if (current.eof) return { output, exitCode: current.exit };
    await wait(250);
  }
  throw new Error("Command output timed out");
}

function MonitorApprovalDialog({
  approval,
  server,
  dropLevel,
  busy,
  onCancel,
  onConfirm,
}: {
  approval: Approval;
  server: Server;
  dropLevel: 1 | 2 | 3;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const isCleanup = approval.kind === "cleanup";
  const plan = isCleanup ? DISK_PLANS[approval.plan] : null;
  const title = isCleanup ? `Run ${plan!.title.toLowerCase()} cleanup?` : "Drop filesystem caches?";
  const command = isCleanup ? plan!.cleanupCommand : `sync; echo ${dropLevel} > /proc/sys/vm/drop_caches`;

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const dialog = dialogRef.current;
    dialogRef.current?.querySelector<HTMLButtonElement>("[data-monitor-confirm]")?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) {
        event.preventDefault();
        onCancel();
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => {
      window.removeEventListener("keydown", handleKey);
      previous?.focus();
    };
  }, [busy, onCancel]);

  return (
    <div className="oars-modal-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onCancel(); }}>
      <div ref={dialogRef} className="oars-modal oars-modal-narrow monitor-approval" role="dialog" aria-modal="true" aria-labelledby="monitor-approval-title" aria-describedby="monitor-approval-description">
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon oars-modal-icon-danger"><AlertTriangle /></span>
            <div>
              <h2 id="monitor-approval-title">{title}</h2>
              <p id="monitor-approval-description" className="oars-modal-subtitle">
                {isCleanup
                  ? "Oars will run one fixed cleanup command. The action is recorded in the local audit log."
                  : "This diagnostic can increase disk I/O and CPU while Linux rebuilds its caches."}
              </p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onCancel} disabled={busy}><X /></Button>
          </div>
        </header>
        <div className="oars-modal-body monitor-approval-body">
          <div className="monitor-affected-resource">
            <strong>{server.name}</strong>
            <span>{server.user}@{server.host}:{server.port}</span>
          </div>
          <div className="monitor-command-preview">
            <span>Command</span>
            <code>{command}</code>
          </div>
          {!isCleanup && (
            <p className="monitor-approval-warning">
              Linux reclaims caches automatically. Use this action only for testing or diagnosis. The before and after memory values are audited, but the change is not a lasting performance improvement.
            </p>
          )}
        </div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-right">
            <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel</Button>
            <Button data-monitor-confirm variant={isCleanup ? "default" : "destructive"} onClick={onConfirm} disabled={busy}>
              {busy ? "Starting…" : isCleanup ? "Run cleanup" : "Drop caches"}
            </Button>
          </div>
        </footer>
      </div>
    </div>
  );
}

export function MonitorTab({ server }: { server: Server }) {
  const serverId = server.id;
  const [snapshot, setSnapshot] = useState<MonitorSnapshot | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notReady, setNotReady] = useState(false);
  const [sortBy, setSortBy] = useState<"cpu" | "mem">("cpu");
  const [history, setHistory] = useState<MonitorHistory>(emptyHistory);
  const [refreshing, setRefreshing] = useState(false);
  const [storageOpen, setStorageOpen] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [plans, setPlans] = useState<PlanStates>(emptyPlans);
  const [dropLevel, setDropLevel] = useState<1 | 2 | 3>(3);
  const [dropRun, setDropRun] = useState<RunState>(emptyRun);
  const [dropBefore, setDropBefore] = useState<string | null>(null);
  const [approval, setApproval] = useState<Approval | null>(null);
  const [approvalBusy, setApprovalBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);
  const requestActiveRef = useRef(false);
  const mountedRef = useRef(true);
  const noticeTimerRef = useRef<number | null>(null);

  const loadSnapshot = useCallback(async (): Promise<MonitorSnapshot | null> => {
    if (requestActiveRef.current) return null;
    requestActiveRef.current = true;
    try {
      const result = await api.monitor.poll(serverId);
      if (result.status === "not_ready") {
        if (mountedRef.current) {
          setNotReady(true);
          setLoadError(null);
        }
        return null;
      }
      if (mountedRef.current) {
        setNotReady(false);
        setLoadError(null);
        setSnapshot(result);
        const cpu = result.cpu?.utilization_pct ?? null;
        const memory = result.mem && result.mem.total_bytes > 0 ? (result.mem.used_bytes / result.mem.total_bytes) * 100 : null;
        const storage = result.disk && result.disk.total_bytes > 0 ? (result.disk.used_bytes / result.disk.total_bytes) * 100 : null;
        setHistory((current) => ({
          cpu: cpu === null ? current.cpu : [...current.cpu, cpu].slice(-120),
          memory: memory === null ? current.memory : [...current.memory, memory].slice(-120),
          storage: storage === null ? current.storage : [...current.storage, storage].slice(-120),
        }));
      }
      return result;
    } catch (error) {
      if (mountedRef.current) setLoadError(messageOf(error));
      return null;
    } finally {
      requestActiveRef.current = false;
    }
  }, [serverId]);

  useEffect(() => {
    mountedRef.current = true;
    setSnapshot(null);
    setHistory(emptyHistory());
    setLoadError(null);
    setNotReady(false);
    setPlans(emptyPlans());
    setDropRun(emptyRun());
    setDropBefore(null);

    let canceled = false;
    const tick = async () => {
      await loadSnapshot();
      if (!canceled) timerRef.current = window.setTimeout(tick, 2000);
    };
    void tick();
    return () => {
      canceled = true;
      mountedRef.current = false;
      if (timerRef.current) window.clearTimeout(timerRef.current);
      if (noticeTimerRef.current) window.clearTimeout(noticeTimerRef.current);
    };
  }, [loadSnapshot]);

  const showNotice = useCallback((text: string) => {
    setNotice(text);
    if (noticeTimerRef.current) window.clearTimeout(noticeTimerRef.current);
    noticeTimerRef.current = window.setTimeout(() => setNotice(null), 2600);
  }, []);

  const closeApproval = useCallback(() => setApproval(null), []);

  const handleRefresh = async () => {
    if (refreshing) return;
    setRefreshing(true);
    const previousTimestamp = snapshot?.ts ?? 0;
    try {
      await api.monitor.probe(serverId);
      for (let attempt = 0; attempt < 9; attempt += 1) {
        await wait(300);
        const next = await loadSnapshot();
        if (next && next.ts !== previousTimestamp) break;
      }
    } catch (error) {
      setLoadError(messageOf(error));
    } finally {
      if (mountedRef.current) setRefreshing(false);
    }
  };

  const updatePlanRun = (plan: DiskPlan, stage: keyof PlanState, next: RunState) => {
    setPlans((current) => ({
      ...current,
      [plan]: { ...current[plan], [stage]: next },
    }));
  };

  const runEstimate = async (plan: DiskPlan) => {
    updatePlanRun(plan, "estimate", { status: "running", output: "", exitCode: null });
    updatePlanRun(plan, "cleanup", emptyRun());
    try {
      const response = await api.monitor.cleanDiskEstimate(serverId, plan);
      const result = await readExecChannel(
        serverId,
        response.channel,
        (output) => updatePlanRun(plan, "estimate", { status: "running", output, exitCode: null }),
        () => mountedRef.current,
      );
      updatePlanRun(plan, "estimate", { status: "success", output: result.output || "Estimate completed with no output.", exitCode: result.exitCode });
    } catch (error) {
      updatePlanRun(plan, "estimate", { status: "error", output: messageOf(error), exitCode: null });
    }
  };

  const runCleanup = async (plan: DiskPlan) => {
    updatePlanRun(plan, "cleanup", { status: "running", output: "", exitCode: null });
    try {
      const response = await api.monitor.cleanDisk(serverId, plan);
      const result = await readExecChannel(
        serverId,
        response.channel,
        (output) => updatePlanRun(plan, "cleanup", { status: "running", output, exitCode: null }),
        () => mountedRef.current,
      );
      const failed = result.exitCode !== null && result.exitCode !== 0;
      updatePlanRun(plan, "cleanup", {
        status: failed ? "error" : "success",
        output: result.output || (failed ? `Command exited with code ${result.exitCode}.` : "Cleanup completed."),
        exitCode: result.exitCode,
      });
      if (!failed) {
        showNotice(`${DISK_PLANS[plan].title} cleanup completed and was added to the audit log.`);
        window.setTimeout(() => { if (mountedRef.current) void loadSnapshot(); }, 800);
      }
    } catch (error) {
      updatePlanRun(plan, "cleanup", { status: "error", output: messageOf(error), exitCode: null });
    }
  };

  const runDropCaches = async () => {
    const before = snapshot?.mem
      ? `${bytesToGiB(snapshot.mem.used_bytes)} GiB used · ${bytesToGiB(snapshot.mem.available_bytes)} GiB available`
      : "Memory snapshot unavailable";
    setDropBefore(before);
    setDropRun({ status: "running", output: "", exitCode: null });
    try {
      const response = await api.monitor.dropCaches(serverId, dropLevel);
      const result = await readExecChannel(
        serverId,
        response.channel,
        (output) => setDropRun({ status: "running", output, exitCode: null }),
        () => mountedRef.current,
      );
      const failed = result.exitCode !== null && result.exitCode !== 0;
      setDropRun({
        status: failed ? "error" : "success",
        output: result.output || (failed ? `Command exited with code ${result.exitCode}.` : "Cache diagnostic completed."),
        exitCode: result.exitCode,
      });
      if (!failed) {
        showNotice("Cache diagnostic completed. Before and after values are recorded in the audit log.");
        window.setTimeout(() => { if (mountedRef.current) void loadSnapshot(); }, 1200);
      }
    } catch (error) {
      setDropRun({ status: "error", output: messageOf(error), exitCode: null });
    }
  };

  const handleApproval = async () => {
    if (!approval) return;
    const selected = approval;
    setApprovalBusy(true);
    setApproval(null);
    try {
      if (selected.kind === "cleanup") await runCleanup(selected.plan);
      else await runDropCaches();
    } finally {
      if (mountedRef.current) setApprovalBusy(false);
    }
  };

  const handleAi = async (pid: number, name: string) => {
    const text = `PID ${pid} — ${name}`;
    try {
      await navigator.clipboard.writeText(text);
      showNotice(`Copied ${text} for the AI prompt.`);
    } catch {
      showNotice(`${text}. Clipboard access was not available.`);
    }
  };

  const noSample = snapshot?.ts === 0 && snapshot.probe_error === "no sample yet";
  if (!snapshot || noSample) {
    const title = notReady ? "Waiting for connection" : loadError ? "Monitoring is unavailable" : "Collecting the first sample";
    const detail = notReady
      ? "Monitoring starts when the SSH session is connected."
      : loadError
        ? loadError
        : "Oars is reading processor, memory, storage, and process data from the server.";
    return (
      <section className="monitor" aria-label="System health">
        <header className="monitor-overview monitor-overview-compact">
          <div>
            <div className="monitor-kicker"><Activity size={15} /> System health</div>
            <h2>{title}</h2>
            <p>{detail}</p>
          </div>
          <Button variant="outline" onClick={handleRefresh} disabled={refreshing || notReady}>
            <RefreshCw className={refreshing ? "spin" : ""} /> {refreshing ? "Refreshing…" : "Refresh"}
          </Button>
        </header>
        <div className="monitor-skeleton" aria-hidden={!loadError}>
          {[0, 1, 2].map((item) => <span key={item} />)}
        </div>
        {loadError && <Button variant="ghost" size="sm" onClick={() => void loadSnapshot()}>Try again</Button>}
      </section>
    );
  }

  const cpuPercent = snapshot.cpu?.utilization_pct ?? null;
  const memoryPercent = snapshot.mem && snapshot.mem.total_bytes > 0
    ? (snapshot.mem.used_bytes / snapshot.mem.total_bytes) * 100
    : null;
  const storagePercent = snapshot.disk && snapshot.disk.total_bytes > 0
    ? (snapshot.disk.used_bytes / snapshot.disk.total_bytes) * 100
    : null;
  const overallTone = snapshot.probe_error
    ? "watch"
    : highestTone([gaugeTone(cpuPercent), gaugeTone(memoryPercent), gaugeTone(storagePercent)]);

  const processes = [...snapshot.processes].sort((left, right) => {
    const leftValue = sortBy === "cpu" ? (left.cpu ?? -1) : (left.mem ?? -1);
    const rightValue = sortBy === "cpu" ? (right.cpu ?? -1) : (right.mem ?? -1);
    return rightValue - leftValue;
  });
  const historyCount = Math.max(history.cpu.length, history.memory.length, history.storage.length);
  const historySeries = [
    { values: history.cpu, color: "--monitor-line-cpu" },
    { values: history.memory, color: "--monitor-line-memory" },
    { values: history.storage, color: "--monitor-line-storage" },
  ];

  return (
    <section className="monitor" aria-label="System health">
      <header className="monitor-overview">
        <div>
          <div className="monitor-kicker"><Activity size={15} /> System health</div>
          <div className="monitor-title-row">
            <h2>Live resource use</h2>
            <span className={`monitor-health monitor-tone-${notReady ? "muted" : overallTone}`}>
              <span className="monitor-state-dot" aria-hidden />
              {notReady ? "Paused" : snapshot.probe_error ? "Needs attention" : toneLabel(overallTone)}
            </span>
          </div>
          <p>{formatSnapshotAge(snapshot.ts)} · Refreshes every 2 seconds while this view is open.</p>
        </div>
        <Button variant="outline" onClick={handleRefresh} disabled={refreshing || notReady} aria-label="Refresh monitoring snapshot">
          <RefreshCw className={refreshing ? "spin" : ""} /> {refreshing ? "Refreshing…" : "Refresh"}
        </Button>
      </header>

      {notReady && (
        <div className="monitor-banner monitor-banner-neutral" role="status">
          <Clock3 /> <div><strong>Monitoring paused</strong><span>Reconnect this server to resume live samples.</span></div>
        </div>
      )}
      {snapshot.probe_error && (
        <div className="monitor-banner monitor-banner-warn" role="status">
          <AlertTriangle /> <div><strong>Some health data is unavailable</strong><span>{snapshot.probe_error}</span></div>
        </div>
      )}
      {loadError && <div className="monitor-error" role="alert">{loadError}</div>}
      {notice && <div className="monitor-toast" role="status">{notice}</div>}

      <div className="monitor-metrics">
        <ResourceMetric
          icon={Cpu}
          title="Processor"
          percent={cpuPercent}
          waitingLabel={snapshot.cpu?.cpu_warming ? "Warming up" : "Unavailable"}
          summary={snapshot.cpu ? `${snapshot.cpu.cores} cores · Uptime ${formatUptime(snapshot.cpu.uptime_sec)}` : "Processor details unavailable"}
          facts={[
            { label: "1 min load", value: snapshot.cpu ? snapshot.cpu.load_1.toFixed(2) : "—" },
            { label: "5 min load", value: snapshot.cpu ? snapshot.cpu.load_5.toFixed(2) : "—" },
            { label: "15 min load", value: snapshot.cpu ? snapshot.cpu.load_15.toFixed(2) : "—" },
          ]}
        />
        <ResourceMetric
          icon={MemoryStick}
          title="Memory"
          percent={memoryPercent}
          summary={snapshot.mem ? `${bytesToGiB(snapshot.mem.used_bytes)} of ${bytesToGiB(snapshot.mem.total_bytes)} GiB used` : "Memory details unavailable"}
          facts={[
            { label: "Available", value: snapshot.mem ? `${bytesToGiB(snapshot.mem.available_bytes)} GiB` : "—" },
            { label: "Swap used", value: snapshot.mem && snapshot.mem.swap_total_bytes > 0 ? `${bytesToGiB(snapshot.mem.swap_used_bytes)} GiB` : "None" },
            { label: "Swap total", value: snapshot.mem && snapshot.mem.swap_total_bytes > 0 ? `${bytesToGiB(snapshot.mem.swap_total_bytes)} GiB` : "—" },
          ]}
        />
        <ResourceMetric
          icon={HardDrive}
          title="Storage"
          percent={storagePercent}
          summary={snapshot.disk ? `${bytesToGiB(snapshot.disk.used_bytes)} of ${bytesToGiB(snapshot.disk.total_bytes)} GiB used` : "Storage details unavailable"}
          facts={[
            { label: "Available", value: snapshot.disk ? `${bytesToGiB(snapshot.disk.available_bytes)} GiB` : "—" },
            { label: "Mount", value: "/" },
            { label: "State", value: toneLabel(gaugeTone(storagePercent)) },
          ]}
        />
      </div>

      <section className="monitor-history" aria-labelledby="monitor-history-title">
        <header>
          <div>
            <h3 id="monitor-history-title">Recent resource activity</h3>
            <p>Up to 120 local samples. Nothing is stored after this view closes.</p>
          </div>
          <span>{historyCount} of 120 samples</span>
        </header>
        <div className="monitor-history-legend" aria-label="Chart legend">
          <span className="monitor-legend-cpu">Processor <strong>{cpuPercent === null ? "—" : `${cpuPercent.toFixed(1)}%`}</strong></span>
          <span className="monitor-legend-memory">Memory <strong>{memoryPercent === null ? "—" : `${memoryPercent.toFixed(1)}%`}</strong></span>
          <span className="monitor-legend-storage">Storage <strong>{storagePercent === null ? "—" : `${storagePercent.toFixed(1)}%`}</strong></span>
        </div>
        <div className="monitor-history-chart">
          <Sparkline series={historySeries} />
          {historyCount < 2 && <span>Waiting for the next sample</span>}
        </div>
        <div className="monitor-history-scale" aria-hidden><span>0%</span><span>60%</span><span>90%</span><span>100%</span></div>
      </section>

      <section className="panel monitor-processes" aria-labelledby="monitor-processes-title">
        <header className="monitor-panel-header">
          <div>
            <h3 id="monitor-processes-title">Top processes</h3>
            <p>Current process use from the latest read-only probe.</p>
          </div>
          <div className="monitor-mobile-sort" role="group" aria-label="Sort processes">
            <button type="button" aria-pressed={sortBy === "cpu"} onClick={() => setSortBy("cpu")}>Processor</button>
            <button type="button" aria-pressed={sortBy === "mem"} onClick={() => setSortBy("mem")}>Memory</button>
          </div>
        </header>
        {processes.length > 0 ? (
          <div className="table-wrap">
            <table className="monitor-process-table">
              <thead>
                <tr>
                  <th>PID</th>
                  <th>Process</th>
                  <th><button type="button" className={sortBy === "cpu" ? "is-active" : ""} onClick={() => setSortBy("cpu")}>CPU <ChevronDown /></button></th>
                  <th><button type="button" className={sortBy === "mem" ? "is-active" : ""} onClick={() => setSortBy("mem")}>Memory <ChevronDown /></button></th>
                  <th><span className="sr-only">AI action</span></th>
                </tr>
              </thead>
              <tbody>
                {processes.slice(0, 10).map((process) => (
                  <tr key={process.pid}>
                    <td data-label="PID" className="monitor-mono">{process.pid}</td>
                    <td data-label="Process" className="monitor-process-name" title={process.name}>{process.name}</td>
                    <td data-label="CPU" className="monitor-mono">{process.cpu === null ? "—" : `${process.cpu.toFixed(1)}%`}</td>
                    <td data-label="Memory" className="monitor-mono">{process.mem === null ? "—" : `${process.mem.toFixed(1)}%`}</td>
                    <td className="monitor-process-action">
                      <Button variant="ghost" size="sm" onClick={() => handleAi(process.pid, process.name)} aria-label={`Copy PID ${process.pid} for AI`}>
                        <Sparkles /> Copy for AI
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="monitor-process-empty">
            <strong>No process metrics were returned</strong>
            <span>Restricted and BusyBox systems can omit processor and memory columns.</span>
          </div>
        )}
        <footer className="monitor-panel-footer">Showing {Math.min(10, processes.length)} of {processes.length} processes</footer>
      </section>

      <section className="monitor-tools" aria-label="Diagnostics">
        <div className={`monitor-tool ${storageOpen ? "is-open" : ""}`}>
          <button className="monitor-disclosure" type="button" onClick={() => setStorageOpen((current) => !current)} aria-expanded={storageOpen}>
            <span className="monitor-disclosure-icon"><HardDrive /></span>
            <span><strong>Storage diagnostics</strong><small>Preview exact categories before any cleanup runs.</small></span>
            <ChevronDown className="monitor-disclosure-chevron" />
          </button>
          {storageOpen && (
            <div className="monitor-tool-body">
              <p className="monitor-tool-intro">Oars does not remove temporary files, application logs, or package data by age. Each option below uses one fixed backend plan and creates its own result.</p>
              <div className="monitor-plan-list">
                {(Object.keys(DISK_PLANS) as DiskPlan[]).map((planKey) => {
                  const plan = DISK_PLANS[planKey];
                  const state = plans[planKey];
                  const estimateReady = state.estimate.status === "success";
                  return (
                    <article className="monitor-plan" key={planKey}>
                      <div className="monitor-plan-copy">
                        <h4>{plan.title}</h4>
                        <p>{plan.description}</p>
                        <code>{plan.estimateCommand}</code>
                      </div>
                      <div className="monitor-plan-actions">
                        <Button variant="outline" size="sm" onClick={() => void runEstimate(planKey)} disabled={state.estimate.status === "running" || state.cleanup.status === "running"}>
                          {state.estimate.status === "running" ? <><RefreshCw className="spin" /> Estimating…</> : "Estimate"}
                        </Button>
                        <Button size="sm" onClick={() => setApproval({ kind: "cleanup", plan: planKey })} disabled={!estimateReady || state.cleanup.status === "running"} title={!estimateReady ? "Run the estimate first" : undefined}>
                          <Trash2 /> {state.cleanup.status === "running" ? "Running…" : "Run cleanup"}
                        </Button>
                      </div>
                      {(state.estimate.status !== "idle" || state.cleanup.status !== "idle") && (
                        <div className="monitor-plan-results">
                          {state.estimate.status !== "idle" && (
                            <div className={`monitor-run monitor-run-${state.estimate.status}`}>
                              <span>Estimate</span><pre>{state.estimate.output || "Waiting for command output…"}</pre>
                            </div>
                          )}
                          {state.cleanup.status !== "idle" && (
                            <div className={`monitor-run monitor-run-${state.cleanup.status}`}>
                              <span>Cleanup</span><pre>{state.cleanup.output || "Waiting for command output…"}</pre>
                            </div>
                          )}
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        <div className={`monitor-tool monitor-tool-advanced ${advancedOpen ? "is-open" : ""}`}>
          <button className="monitor-disclosure" type="button" onClick={() => setAdvancedOpen((current) => !current)} aria-expanded={advancedOpen}>
            <span className="monitor-disclosure-icon"><FlaskConical /></span>
            <span><strong>Advanced diagnostics</strong><small>Cache controls for controlled tests and diagnosis.</small></span>
            <ChevronDown className="monitor-disclosure-chevron" />
          </button>
          {advancedOpen && (
            <div className="monitor-tool-body">
              <div className="monitor-caution">
                <AlertTriangle />
                <div><strong>Linux normally manages these caches for you.</strong><p>Dropping them can cause extra disk I/O and processor use while the data is rebuilt.</p></div>
              </div>
              <div className="monitor-drop-row">
                <label htmlFor="drop-level"><span>Cache type</span><select id="drop-level" value={dropLevel} onChange={(event) => setDropLevel(Number(event.target.value) as 1 | 2 | 3)} disabled={dropRun.status === "running"}>
                  <option value={1}>Page cache</option>
                  <option value={2}>Reclaimable slab</option>
                  <option value={3}>Both (default)</option>
                </select></label>
                <Button variant="destructive" onClick={() => setApproval({ kind: "drop-caches" })} disabled={dropRun.status === "running"}>
                  {dropRun.status === "running" ? <><RefreshCw className="spin" /> Running…</> : "Review and run"}
                </Button>
              </div>
              {dropBefore && <p className="monitor-before-after"><strong>Before:</strong> {dropBefore}</p>}
              {dropRun.status !== "idle" && <div className={`monitor-run monitor-run-${dropRun.status}`}><span>Diagnostic output</span><pre>{dropRun.output || "Waiting for command output…"}</pre></div>}
              {snapshot.mem && dropBefore && dropRun.status === "success" && <p className="monitor-before-after"><strong>Latest sample:</strong> {bytesToGiB(snapshot.mem.used_bytes)} GiB used · {bytesToGiB(snapshot.mem.available_bytes)} GiB available</p>}
            </div>
          )}
        </div>
      </section>

      {approval && (
        <MonitorApprovalDialog
          approval={approval}
          server={server}
          dropLevel={dropLevel}
          busy={approvalBusy}
          onCancel={closeApproval}
          onConfirm={() => void handleApproval()}
        />
      )}
    </section>
  );
}
