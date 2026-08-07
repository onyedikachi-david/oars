import { Radio } from "lucide-react";

interface OarsLoadingStateProps {
  title: string;
  detail?: string;
  compact?: boolean;
  className?: string;
}

export function OarsLoadingState({
  title,
  detail,
  compact = false,
  className = "",
}: OarsLoadingStateProps) {
  return (
    <div
      className={`oars-loading-state ${compact ? "oars-loading-compact" : ""} ${className}`.trim()}
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <div className="oars-loading-signal" aria-hidden>
        <Radio />
        <span className="oars-loading-bar" />
        <span className="oars-loading-bar" />
        <span className="oars-loading-bar" />
      </div>
      <div className="oars-loading-copy">
        <strong>{title}</strong>
        {detail && <span>{detail}</span>}
      </div>
      <div className="oars-loading-rails" aria-hidden>
        <span />
        <span />
        <span />
      </div>
    </div>
  );
}

export function OarsRefreshStatus({ label = "Updating" }: { label?: string }) {
  return (
    <span className="oars-refresh-status" role="status" aria-live="polite">
      <span aria-hidden />
      {label}
    </span>
  );
}
