import type { EditorState } from "../types";
import { OarsSelect } from "../../../components/ui/select";

export interface DeployGeneralSectionProps {
  editor: EditorState;
  setEditor: (editor: EditorState) => void;
}

export function DeployGeneralSection({ editor, setEditor }: DeployGeneralSectionProps) {
  return (
    <section className="deploy-form-section">
      <h3>Application</h3>
      <div className="deploy-form-grid">
        <label htmlFor="deploy-app-name">
          <span>Name</span>
          <input
            id="deploy-app-name"
            value={editor.name}
            onChange={(event) => setEditor({ ...editor, name: event.target.value })}
          />
        </label>
        <label htmlFor="deploy-environment">
          <span>Environment</span>
          <OarsSelect
            id="deploy-environment"
            value={editor.environment}
            onValueChange={(environment) =>
              setEditor({ ...editor, environment: environment as EditorState["environment"] })
            }
            options={[
              { value: "development", label: "Development" },
              { value: "staging", label: "Staging" },
              { value: "production", label: "Production" },
            ]}
          />
        </label>
        <label className="deploy-field-wide" htmlFor="deploy-folder">
          <span>Server folder</span>
          <input
            id="deploy-folder"
            placeholder="/home/deploy/apps/storefront"
            value={editor.folder}
            onChange={(event) => setEditor({ ...editor, folder: event.target.value })}
          />
          <small>Use an absolute path. A folder under the connected user’s home usually needs fewer privileges.</small>
        </label>
      </div>
    </section>
  );
}
