import { ShieldCheck } from "lucide-react";
import type { EditorState } from "../types";

export interface DeployServiceSectionProps {
  editor: EditorState;
  setEditor: (editor: EditorState) => void;
}

export function DeployServiceSection({ editor, setEditor }: DeployServiceSectionProps) {
  return (
    <section className="deploy-form-section">
      <h3>Public service</h3>
      <div className="deploy-form-grid">
        <label className="deploy-field-wide" htmlFor="deploy-domains">
          <span>Domains</span>
          <input
            id="deploy-domains"
            value={editor.domains.join(", ")}
            placeholder="example.com, www.example.com"
            onChange={(event) =>
              setEditor({
                ...editor,
                domains: event.target.value.split(",").map((item) => item.trim()).filter(Boolean),
              })
            }
          />
        </label>
        {(editor.runtime.type === "node" || editor.runtime.type === "next") && (
          <label htmlFor="deploy-port">
            <span>Application port</span>
            <input
              id="deploy-port"
              type="number"
              min={1}
              max={65535}
              value={editor.app_port}
              onChange={(event) => setEditor({ ...editor, app_port: Number(event.target.value) })}
            />
          </label>
        )}
        <label className="deploy-secret-switch deploy-ssl-switch">
          <input
            type="checkbox"
            checked={editor.ssl}
            onChange={(event) => setEditor({ ...editor, ssl: event.target.checked })}
          />
          <span>
            <ShieldCheck />
            Issue SSL certificate
          </span>
        </label>
        {editor.ssl && (
          <label className="deploy-field-wide" htmlFor="deploy-email">
            <span>Certificate email</span>
            <input
              id="deploy-email"
              type="email"
              value={editor.email}
              onChange={(event) => setEditor({ ...editor, email: event.target.value })}
            />
          </label>
        )}
      </div>
    </section>
  );
}
