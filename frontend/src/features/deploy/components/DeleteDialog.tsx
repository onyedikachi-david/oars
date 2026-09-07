import { LoaderCircle, Server, Trash2 } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { ApplicationOverlay } from "../../../components/ApplicationPortal";
import { useModalFocus } from "../../../components/useModalFocus";
import type { DeleteState } from "../types";

export interface DeleteDialogProps {
  state: DeleteState;
  onCancel: () => void;
  onConfirm: () => void;
}

export function DeleteDialog({ state, onCancel, onConfirm }: DeleteDialogProps) {
  const dialogRef = useModalFocus(onCancel, "[data-delete-confirm]", !state.busy);

  return (
    <ApplicationOverlay
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !state.busy) onCancel();
      }}
    >
      <div
        ref={dialogRef}
        className="oars-modal oars-modal-narrow"
        role="dialog"
        aria-modal="true"
        aria-labelledby="deploy-delete-title"
        aria-describedby="deploy-delete-desc"
      >
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon oars-modal-icon-danger">
              <Trash2 />
            </span>
            <div>
              <h2 id="deploy-delete-title">Delete {state.app.name}?</h2>
              <p id="deploy-delete-desc" className="oars-modal-subtitle">
                Oars will remove the local application definition and its Keychain values. Deployment history stays
                available.
              </p>
            </div>
          </div>
        </header>
        <div className="oars-modal-body">
          <div className="deploy-delete-resource">
            <Server />
            <div>
              <strong>{state.app.name}</strong>
              <span>{state.app.repo.url}</span>
            </div>
          </div>
          {state.error && (
            <p className="oars-modal-error" role="alert">
              {state.error}
            </p>
          )}
        </div>
        <footer className="oars-modal-actions oars-modal-footer">
          <div className="oars-modal-actions-right">
            <Button variant="outline" onClick={onCancel} disabled={state.busy}>
              Keep application
            </Button>
            <Button
              data-delete-confirm
              variant="destructive"
              onClick={onConfirm}
              disabled={state.busy}
            >
              {state.busy ? (
                <>
                  <LoaderCircle className="is-spinning" />
                  Deleting
                </>
              ) : (
                "Delete application"
              )}
            </Button>
          </div>
        </footer>
      </div>
    </ApplicationOverlay>
  );
}
