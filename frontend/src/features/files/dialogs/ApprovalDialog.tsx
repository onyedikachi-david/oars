import { X } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { ApplicationOverlay } from "../../../components/ApplicationPortal";
import { useModalFocus } from "../../../components/useModalFocus";

export interface ApprovalDialogProps {
  className?: string;
  quietOverlay?: boolean;
  icon: React.ReactNode;
  iconClass: string;
  title: string;
  subtitle: React.ReactNode;
  children?: React.ReactNode;
  actions: React.ReactNode;
  onCancel: () => void;
  busy?: boolean;
  labelledBy: string;
  describedBy?: string;
  initialFocusSelector?: string;
}

export function ApprovalDialog({
  className = "",
  quietOverlay = true,
  icon,
  iconClass,
  title,
  subtitle,
  children,
  actions,
  onCancel,
  busy = false,
  labelledBy,
  describedBy,
  initialFocusSelector,
}: ApprovalDialogProps) {
  const descId = describedBy ?? `${labelledBy}-desc`;
  const dialogRef = useModalFocus(onCancel, initialFocusSelector, !busy);

  return (
    <ApplicationOverlay
      quiet={quietOverlay}
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onCancel();
      }}
    >
      <div
        ref={dialogRef}
        className={`oars-modal oars-modal-narrow refined-dialog ${className}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={descId}
      >
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className={`oars-modal-icon ${iconClass}`}>{icon}</span>
            <div>
              <h2 id={labelledBy}>{title}</h2>
              <p id={descId} className="oars-modal-subtitle">{subtitle}</p>
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              className="oars-modal-close"
              onClick={onCancel}
              disabled={busy}
              aria-label="Close dialog"
            >
              <X />
            </Button>
          </div>
        </header>
        <div className="oars-modal-body">{children}</div>
        <footer className="oars-modal-actions">
          <div className="oars-modal-actions-left" />
          <div className="oars-modal-actions-right">{actions}</div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}
