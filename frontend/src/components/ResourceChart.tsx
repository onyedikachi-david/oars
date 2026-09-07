import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ResourceSample } from "../resource-history";

const lines = [
  { key: "cpu", name: "Processor", color: "var(--monitor-line-cpu)", dash: undefined },
  { key: "memory", name: "Memory", color: "var(--monitor-line-memory)", dash: "5 3" },
  { key: "storage", name: "Storage", color: "var(--monitor-line-storage)", dash: "2 3" },
] as const;
const timeLabel = (value: number) => new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export default function ResourceChart({ samples, compact = false }: { samples: ResourceSample[]; compact?: boolean }) {
  const last = samples.at(-1);
  return <div className={`resource-chart ${compact ? "resource-chart-compact" : ""}`}>
    <div className="resource-chart-legend" aria-label="Resource readings">
      {lines.map(line => <span key={line.key}><svg width="16" height="8" aria-hidden="true"><line x1="0" x2="16" y1="4" y2="4" stroke={line.color} strokeWidth="2" strokeDasharray={line.dash} /></svg>{line.name}<strong>{last?.[line.key] == null ? "—" : `${last[line.key]!.toFixed(1)}%`}</strong></span>)}
    </div>
    {samples.length ? <ResponsiveContainer width="100%" height={compact ? 132 : 220} minWidth={0}>
      <LineChart data={samples} margin={{ top: 12, right: 12, bottom: 0, left: 0 }} accessibilityLayer title="Resource use over time. Use the arrow keys to inspect samples.">
        <CartesianGrid vertical={false} stroke="var(--border)" />
        <XAxis dataKey="time" type="number" scale="time" domain={([min, max]) => min === max ? [min - 5000, max + 5000] : [min, max]} tickFormatter={timeLabel} minTickGap={compact ? 40 : 70} tick={{ fill: "var(--muted-foreground)", fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis domain={[0, 100]} ticks={compact ? [0, 100] : [0, 25, 50, 75, 100]} width={38} tickFormatter={value => `${value}%`} tick={{ fill: "var(--muted-foreground)", fontSize: 10 }} axisLine={false} tickLine={false} />
        <Tooltip isAnimationActive={false} labelFormatter={value => timeLabel(Number(value))} formatter={(value, name) => [typeof value === "number" ? `${value.toFixed(1)}%` : "Unavailable", name]} contentStyle={{ background: "var(--popover)", color: "var(--foreground)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 }} />
        {lines.map(line => <Line key={line.key} dataKey={line.key} name={line.name} type="linear" stroke={line.color} strokeWidth={1.7} strokeDasharray={line.dash} dot={samples.length === 1 ? { r: 3 } : false} activeDot={{ r: 4 }} connectNulls={false} isAnimationActive={false} />)}
      </LineChart>
    </ResponsiveContainer> : <div className="resource-chart-empty">Waiting for resource samples.</div>}
  </div>;
}
