import { Plus, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "../../../components/ui/button";
import type { BulkImportResult } from "../../../deploy-state";
import type { DeployEnvVar } from "../../../types";
import type { EditorState } from "../types";

export interface DeployEnvSectionProps {
  editor: EditorState;
  setEditor: (editor: EditorState) => void;
  bulkText: string;
  setBulkText: (text: string) => void;
  bulkPreview: BulkImportResult | null;
  onPreview: () => void;
  onApplyPreview: () => void;
}

export function DeployEnvSection({
  editor,
  setEditor,
  bulkText,
  setBulkText,
  bulkPreview,
  onPreview,
  onApplyPreview,
}: DeployEnvSectionProps) {
  const updateEnv = (index: number, patch: Partial<DeployEnvVar>) =>
    setEditor({
      ...editor,
      env_vars: editor.env_vars.map((row, rowIndex) => (rowIndex === index ? { ...row, ...patch } : row)),
    });

  return (
    <section className="deploy-form-section">
      <div className="deploy-form-section-heading">
        <div>
          <h3>Environment variables</h3>
          <p>Secret is the safe default. Values remain masked and local.</p>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() =>
            setEditor({
              ...editor,
              env_vars: [...editor.env_vars, { name: "", secret: true, value: "", has_value: false }],
            })
          }
        >
          <Plus />
          Add variable
        </Button>
      </div>
      <div className="deploy-env-table">
        {editor.env_vars.map((row, index) => (
          <div key={`${index}-${row.name}`} className="deploy-env-row">
            <label>
              <span>Name</span>
              <input
                aria-label={`Variable ${index + 1} name`}
                value={row.name}
                onChange={(event) => updateEnv(index, { name: event.target.value })}
              />
            </label>
            <label>
              <span>Value</span>
              <input
                aria-label={`${row.name || `Variable ${index + 1}`} value`}
                type={row.secret ? "password" : "text"}
                autoComplete="off"
                placeholder={row.secret && row.has_value ? "Stored — unchanged" : "Value"}
                value={row.value}
                onChange={(event) => updateEnv(index, { value: event.target.value })}
              />
            </label>
            <label className="deploy-secret-switch">
              <input
                type="checkbox"
                checked={row.secret}
                onChange={(event) =>
                  updateEnv(index, {
                    secret: event.target.checked,
                    has_value: event.target.checked ? row.has_value : row.value.length > 0,
                  })
                }
              />
              <span>
                <ShieldCheck />
                Secret
              </span>
            </label>
            <Button
              size="icon-sm"
              variant="ghost"
              aria-label={`Remove ${row.name || `variable ${index + 1}`}`}
              onClick={() =>
                setEditor({
                  ...editor,
                  env_vars: editor.env_vars.filter((_, rowIndex) => rowIndex !== index),
                })
              }
            >
              <Trash2 />
            </Button>
          </div>
        ))}
        {!editor.env_vars.length && <div className="deploy-env-empty">No environment variables configured.</div>}
      </div>
      <div className="deploy-bulk-import">
        <label htmlFor="deploy-bulk-env">
          <span>Import from .env</span>
          <textarea
            id="deploy-bulk-env"
            rows={4}
            value={bulkText}
            placeholder={"API_URL=https://example.com\nDATABASE_URL=postgres://…"}
            onChange={(event) => setBulkText(event.target.value)}
          />
        </label>
        <Button size="sm" variant="outline" onClick={onPreview} disabled={!bulkText}>
          Review import
        </Button>
        {bulkPreview && (
          <div className="deploy-import-preview">
            <strong>Masked import preview</strong>
            <pre>{bulkPreview.preview || "No valid variables found."}</pre>
            {bulkPreview.duplicates.length > 0 && (
              <p role="alert">
                Duplicate names: {bulkPreview.duplicates.join(", ")}. Existing rows were not replaced.
              </p>
            )}
            {bulkPreview.rejected.length > 0 && (
              <p role="alert">
                Rejected {bulkPreview.rejected.length} invalid line{bulkPreview.rejected.length === 1 ? "" : "s"}.
              </p>
            )}
            <Button
              size="sm"
              onClick={onApplyPreview}
              disabled={
                !bulkPreview.rows.length ||
                bulkPreview.duplicates.length > 0 ||
                bulkPreview.rejected.length > 0
              }
            >
              Add reviewed variables
            </Button>
          </div>
        )}
      </div>
    </section>
  );
}
