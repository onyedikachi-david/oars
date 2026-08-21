import { LoaderCircle, Rocket, X } from "lucide-react";
import { Button } from "../../../components/ui/button";
import { ApplicationOverlay } from "../../../components/ApplicationPortal";
import { useModalFocus } from "../../../components/useModalFocus";
import type { BulkImportResult } from "../../../deploy-state";
import type { EditorState } from "../types";
import { DeployEnvSection } from "./DeployEnvSection";
import { DeployGeneralSection } from "./DeployGeneralSection";
import { DeployRepoSection } from "./DeployRepoSection";
import { DeployRuntimeSection } from "./DeployRuntimeSection";
import { DeployServiceSection } from "./DeployServiceSection";

export interface DeployEditorModalProps {
  editor: EditorState;
  setEditor: (value: EditorState) => void;
  busy: boolean;
  error: string | null;
  bulkText: string;
  setBulkText: (value: string) => void;
  bulkPreview: BulkImportResult | null;
  onPreview: () => void;
  onApplyPreview: () => void;
  onCancel: () => void;
  onSave: () => void;
}

export function DeployEditorModal({
  editor,
  setEditor,
  busy,
  error,
  bulkText,
  setBulkText,
  bulkPreview,
  onPreview,
  onApplyPreview,
  onCancel,
  onSave,
}: DeployEditorModalProps) {
  const dialogRef = useModalFocus(onCancel, "#deploy-app-name", !busy);

  return (
    <ApplicationOverlay
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
    >
      <div
        ref={dialogRef}
        className="oars-modal deploy-editor-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="deploy-editor-title"
        aria-describedby="deploy-editor-desc"
      >
          <header className="oars-modal-header">
            <div className="oars-modal-title-row">
              <span className="oars-modal-icon">
                <Rocket />
              </span>
              <div>
                <h2 id="deploy-editor-title">{editor.id ? "Edit application" : "New application"}</h2>
                <p id="deploy-editor-desc" className="oars-modal-subtitle">
                  Application metadata stays local. Secret values go to the system Keychain.
                </p>
              </div>
              <Button size="icon-sm" variant="ghost" aria-label="Close editor" onClick={onCancel} disabled={busy}>
                <X />
              </Button>
            </div>
          </header>

          <div className="oars-modal-body deploy-editor-body">
            <DeployGeneralSection editor={editor} setEditor={setEditor} />
            <DeployRepoSection editor={editor} setEditor={setEditor} />
            <DeployRuntimeSection editor={editor} setEditor={setEditor} />
            <DeployEnvSection
              editor={editor}
              setEditor={setEditor}
              bulkText={bulkText}
              setBulkText={setBulkText}
              bulkPreview={bulkPreview}
              onPreview={onPreview}
              onApplyPreview={onApplyPreview}
            />
            <DeployServiceSection editor={editor} setEditor={setEditor} />

            {error && (
              <p className="oars-modal-error" role="alert">
                {error}
              </p>
            )}
          </div>

          <footer className="oars-modal-actions oars-modal-footer">
            <div className="oars-modal-actions-right">
              <Button variant="outline" onClick={onCancel} disabled={busy}>
                Cancel
              </Button>
              <Button onClick={onSave} disabled={busy}>
                {busy ? (
                  <>
                    <LoaderCircle className="is-spinning" />
                    Saving
                  </>
                ) : (
                  "Save application"
                )}
              </Button>
            </div>
          </footer>
      </div>
    </ApplicationOverlay>
  );
}
