import type { EditorState } from "../types";
import { OarsSelect } from "../../../components/ui/select";

export interface DeployRuntimeSectionProps {
  editor: EditorState;
  setEditor: (editor: EditorState) => void;
}

export function DeployRuntimeSection({ editor, setEditor }: DeployRuntimeSectionProps) {
  const updateRuntime = (patch: Partial<EditorState["runtime"]>) =>
    setEditor({ ...editor, runtime: { ...editor.runtime, ...patch } });

  const changeRuntimeType = (type: EditorState["runtime"]["type"]) => {
    const defaults =
      type === "next"
        ? {
            build: "npm run build",
            entry: "node_modules/next/dist/bin/next",
            args: "start",
            start_command: "",
            build_folder: ".next",
          }
        : type === "node"
          ? { build: "", entry: "server.js", args: "", start_command: "", build_folder: "" }
          : type === "react"
            ? { build: "npm run build", entry: "", args: "", start_command: "", build_folder: "dist" }
            : { build: "", entry: "", args: "", start_command: "", build_folder: "dist" };
    updateRuntime({ type, ...defaults });
  };

  return (
    <section className="deploy-form-section">
      <h3>Runtime</h3>
      <div className="deploy-form-grid deploy-form-grid-three">
        <label htmlFor="deploy-type">
          <span>Application type</span>
          <OarsSelect
            id="deploy-type"
            value={editor.runtime.type}
            onValueChange={(type) => changeRuntimeType(type as EditorState["runtime"]["type"])}
            options={[
              { value: "node", label: "Node" },
              { value: "next", label: "Next.js" },
              { value: "react", label: "React SPA" },
              { value: "static", label: "Static files" },
            ]}
          />
        </label>
        <label htmlFor="deploy-node">
          <span>Node LTS major</span>
          <OarsSelect
            id="deploy-node"
            value={editor.runtime.node_version}
            onValueChange={(nodeVersion) => updateRuntime({ node_version: nodeVersion })}
            options={[
              { value: "22", label: "22 (Maintenance LTS)" },
              { value: "24", label: "24 (Active LTS)" },
            ]}
          />
          <small>Preflight resolves the latest patch and checksum.</small>
        </label>
        <label htmlFor="deploy-package-manager">
          <span>Package manager</span>
          <OarsSelect
            id="deploy-package-manager"
            value={editor.runtime.package_manager}
            onValueChange={(packageManager) =>
              updateRuntime({ package_manager: packageManager as EditorState["runtime"]["package_manager"] })
            }
            options={[
              { value: "auto", label: "Detect from lockfile" },
              { value: "npm", label: "npm" },
              { value: "pnpm", label: "pnpm" },
              { value: "yarn", label: "Yarn" },
            ]}
          />
        </label>
        {(editor.runtime.type === "node" || editor.runtime.type === "next") && (
          <>
            <label htmlFor="deploy-entry">
              <span>Process entry</span>
              <input
                id="deploy-entry"
                value={editor.runtime.entry}
                onChange={(event) => updateRuntime({ entry: event.target.value })}
              />
            </label>
            <label htmlFor="deploy-args">
              <span>Entry arguments</span>
              <input
                id="deploy-args"
                value={editor.runtime.args}
                onChange={(event) => updateRuntime({ args: event.target.value })}
              />
            </label>
            <label className="deploy-field-wide" htmlFor="deploy-start-command">
              <span>Start command override</span>
              <input
                id="deploy-start-command"
                value={editor.runtime.start_command}
                placeholder="Leave empty to use the structured entry and arguments"
                onChange={(event) => updateRuntime({ start_command: event.target.value })}
              />
              <small>A start override is shell code. Preflight shows it exactly before approval.</small>
            </label>
          </>
        )}
        {(editor.runtime.type === "react" || editor.runtime.type === "static") && (
          <label htmlFor="deploy-build-folder">
            <span>Build folder</span>
            <input
              id="deploy-build-folder"
              value={editor.runtime.build_folder}
              onChange={(event) => updateRuntime({ build_folder: event.target.value })}
            />
          </label>
        )}
        <label className="deploy-field-wide" htmlFor="deploy-install">
          <span>Install command override</span>
          <input
            id="deploy-install"
            value={editor.runtime.install}
            placeholder="Leave empty for the frozen lockfile command"
            onChange={(event) => updateRuntime({ install: event.target.value })}
          />
        </label>
        <label className="deploy-field-wide" htmlFor="deploy-build">
          <span>Build command</span>
          <input
            id="deploy-build"
            value={editor.runtime.build}
            placeholder="npm run build"
            onChange={(event) => updateRuntime({ build: event.target.value })}
          />
        </label>
      </div>
    </section>
  );
}
