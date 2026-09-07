import { useState } from "react";
import { AlertTriangle, FileText, Loader2, X, XCircle } from "lucide-react";
import { OarsLoadingState } from "../../components/OarsLoadingState";
import { ApplicationOverlay } from "../../components/ApplicationPortal";
import { Button } from "../../components/ui/button";
import { useModalFocus } from "../../components/useModalFocus";
import { EditorDiscardDialog, EditorSaveDialog } from "./dialogs/EditorApprovalDialogs";
import { fmtBytes, fmtTime } from "./formatters";
import type { EditorState } from "./types";

export interface EditorModalProps {
  editor: EditorState;
  onClose: () => void;
  onSave: () => void;
  onReload: () => void;
  onDiscard: () => void;
  onCancelDiscard: () => void;
  onDismissConflict: () => void;
  dirtyCloseOpen: boolean;
  onChange: (content: string) => void;
}

export function EditorModal({
  editor,
  onClose,
  onSave,
  onReload,
  onDiscard,
  onCancelDiscard,
  onDismissConflict,
  dirtyCloseOpen,
  onChange,
}: EditorModalProps) {
  const busy = editor.phase === "saving" || editor.phase === "loading";
  const [saveApprovalOpen, setSaveApprovalOpen] = useState(false);
  const dialogRef = useModalFocus(onClose, "textarea", !busy);

  return (
    <ApplicationOverlay
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="oars-modal fs-editor-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="fs-editor-title"
        aria-describedby="fs-editor-desc"
      >
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon">
              <FileText />
            </span>
            <div style={{ minWidth: 0 }}>
              <h2 id="fs-editor-title">{editor.display}</h2>
              <p id="fs-editor-desc" className="oars-modal-subtitle">
                {editor.dirty ? "Unsaved changes" : editor.phase === "editing" ? "Text file" : ""}
                {editor.dirty && editor.phase === "editing" ? " — " : ""}
                {Boolean(editor.entry && editor.entry.size > 0) &&
                  `opened ${fmtBytes(editor.entry.size)} · ${fmtTime(editor.entry.mtime)}`}
              </p>
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              className="oars-modal-close"
              onClick={onClose}
              disabled={busy}
              aria-label="Close editor"
            >
              <X />
            </Button>
          </div>
        </header>
        <div className="oars-modal-body fs-editor-body">
          {editor.conflict && (
            <div className="fs-conflict-banner" role="alert">
              <AlertTriangle size={15} />
              <div>
                <strong>This file changed on the server since you opened it.</strong>
                <p>{editor.conflict.replace(/^conflict:\s*/, "")}</p>
                <div className="fs-conflict-actions">
                  <Button size="xs" variant="default" onClick={onReload}>
                    Reload from server
                  </Button>
                  <Button size="xs" variant="ghost" onClick={onDismissConflict}>
                    Cancel
                  </Button>
                </div>
              </div>
            </div>
          )}
          {editor.error && (
            <div className="fs-editor-error" role="alert">
              <XCircle size={15} />
              <span>{editor.error}</span>
            </div>
          )}
          {editor.phase === "loading" ? (
            <OarsLoadingState
              compact
              title="Reading file"
              detail="Oars is loading the file content in 64 KB chunks."
            />
          ) : editor.phase === "error" ? (
            <div className="fs-editor-error-state">
              <p className="muted">{editor.error}</p>
              <Button size="sm" variant="outline" onClick={onClose}>
                Close
              </Button>
            </div>
          ) : (
            <textarea
              className="fs-editor-textarea"
              value={editor.content}
              onChange={(e) => onChange(e.target.value)}
              spellCheck={false}
              autoFocus
              aria-label="File content"
            />
          )}
        </div>
        {editor.phase !== "error" && (
          <footer className="oars-modal-actions">
            <div className="oars-modal-actions-left">
              <span className="fs-editor-status">
                {editor.phase === "saving"
                  ? "Saving…"
                  : editor.dirty
                    ? `${fmtBytes(new TextEncoder().encode(editor.content).length)} · unsaved`
                    : "Saved"}
              </span>
            </div>
            <div className="oars-modal-actions-right">
              <Button variant="ghost" size="sm" onClick={onClose} disabled={busy}>
                Close
              </Button>
              <Button
                variant="default"
                size="sm"
                onClick={() => setSaveApprovalOpen(true)}
                disabled={busy || !editor.dirty || editor.phase !== "editing"}
              >
                {editor.phase === "saving" ? <Loader2 size={14} className="fs-spin" /> : null}
                Save
              </Button>
            </div>
          </footer>
        )}
      </div>

      <EditorDiscardDialog
        open={dirtyCloseOpen}
        display={editor.display}
        onCancel={onCancelDiscard}
        onDiscard={onDiscard}
      />

      <EditorSaveDialog
        open={saveApprovalOpen}
        path={editor.path}
        contentLength={new TextEncoder().encode(editor.content).length}
        busy={busy}
        onCancel={() => setSaveApprovalOpen(false)}
        onConfirm={() => {
          setSaveApprovalOpen(false);
          onSave();
        }}
      />
    </ApplicationOverlay>
  );
}
