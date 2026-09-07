import type { EditorState } from "../types";
import { OarsSelect } from "../../../components/ui/select";

export interface DeployRepoSectionProps {
  editor: EditorState;
  setEditor: (editor: EditorState) => void;
}

export function DeployRepoSection({ editor, setEditor }: DeployRepoSectionProps) {
  const updateRepo = (patch: Partial<EditorState["repo"]>) =>
    setEditor({ ...editor, repo: { ...editor.repo, ...patch } });

  return (
    <section className="deploy-form-section">
      <h3>Repository</h3>
      <div className="deploy-form-grid">
        <label className="deploy-field-wide" htmlFor="deploy-repo">
          <span>Repository URL</span>
          <input
            id="deploy-repo"
            value={editor.repo.url}
            placeholder="git@github.com:team/storefront.git"
            onChange={(event) => updateRepo({ url: event.target.value })}
          />
        </label>
        <label htmlFor="deploy-transport">
          <span>Transport</span>
          <OarsSelect
            id="deploy-transport"
            value={editor.repo.transport}
            onValueChange={(transport) =>
              updateRepo({ transport: transport as EditorState["repo"]["transport"] })
            }
            options={[
              { value: "https", label: "Public HTTPS" },
              { value: "ssh", label: "Deploy key (SSH)" },
            ]}
          />
        </label>
        <label htmlFor="deploy-branch">
          <span>Branch</span>
          <input
            id="deploy-branch"
            value={editor.repo.branch}
            onChange={(event) => updateRepo({ branch: event.target.value })}
          />
        </label>
      </div>
    </section>
  );
}
