import { useEffect, useId, useState } from "react";
import { Download, Upload, LockKeyhole, FileCheck2 } from "lucide-react";
import { api, pickFile, pickSaveFile } from "./bridge";
import type { VaultImportParams, VaultPreview } from "./types";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";

const sections = [
  ["servers", "Servers, groups and tags"], ["scripts", "Scripts"], ["logs", "Log sources"],
  ["apps", "Applications"], ["access_identities", "Access identities"], ["backup_jobs", "Backup jobs"],
  ["ai_provider", "AI provider settings"], ["deploy_runs", "Deployment history"],
  ["backup_runs", "Backup history"], ["history", "Command history"], ["audit", "Audit journal"],
] as const;
const historySections = new Set(["deploy_runs", "backup_runs", "history", "audit"]);

export function VaultTab({ onImported, onBusyChange }: { onImported?: () => void; onBusyChange?: (busy: boolean) => void }) {
  const id = useId();
  const [mode, setMode] = useState<"export" | "import">("export");
  const [format, setFormat] = useState("encrypted");
  const [selected, setSelected] = useState<string[]>(sections.map(([key]) => key));
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [importPassword, setImportPassword] = useState("");
  const [source, setSource] = useState<VaultImportParams | null>(null);
  const [preview, setPreview] = useState<VaultPreview | null>(null);
  const [choices, setChoices] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  useEffect(() => { onBusyChange?.(busy); }, [busy, onBusyChange]);
  const encrypted = format === "encrypted";
  const available = sections.filter(([key]) => encrypted || !historySections.has(key));

  async function perform(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setStatus("");
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  function cancelPreview() {
    setSource(null); setPreview(null); setChoices({}); setImportPassword(""); setStatus("Import cancelled. No changes were applied.");
  }

  return <div className="oars-data-view vault-transfer">
    <nav className="transfer-tabs" aria-label="Data transfer direction"><button type="button" aria-pressed={mode === "export"} disabled={busy || preview !== null} onClick={() => { setMode("export"); setError(""); setStatus(""); }}><Download size={15} />Export</button><button type="button" aria-pressed={mode === "import"} disabled={busy || preview !== null} onClick={() => { setMode("import"); setError(""); setStatus(""); }}><Upload size={15} />Import</button></nav>
    {mode === "export" && <section className="transfer-section">
      <h2>Export configuration</h2>
      <p className="muted">Save a portable copy of your Oars configuration.</p>
      <div className="transfer-note"><LockKeyhole size={15} aria-hidden /><span>Saved passwords and private keys are excluded. Key paths remain specific to this device.</span></div>
      <fieldset className="transfer-form" disabled={busy}>
        <label htmlFor={`${id}-format`}>Format</label>
        <OarsSelect id={`${id}-format`} value={format} onValueChange={setFormat} options={[{ value: "encrypted", label: "Encrypted vault" }, { value: "plain", label: "Plain JSON" }]} />
        {!encrypted && <p className="muted">Plain JSON excludes command history, audit details and run output.</p>}
        {encrypted && <div className="transfer-passwords"><div>
          <label htmlFor={`${id}-password`}>Export password (at least 12 characters)</label>
          <input id={`${id}-password`} type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} />
          </div><div><label htmlFor={`${id}-repeat`}>Repeat export password</label>
          <input id={`${id}-repeat`} type="password" autoComplete="new-password" value={repeat} onChange={e => setRepeat(e.target.value)} />
        </div></div>}
        <details className="transfer-includes"><summary>Include sections <span>{available.filter(([key]) => selected.includes(key)).length} selected</span></summary>
          {([false, true] as const).map(isHistory => { const items = available.filter(([key]) => historySections.has(key) === isHistory); return items.length > 0 && <div className="transfer-section-group" key={String(isHistory)}><h3>{isHistory ? "History and journals" : "Configuration"}</h3><div className="transfer-checkboxes">{items.map(([key, label]) => <label key={key}><input type="checkbox" checked={selected.includes(key)} onChange={e => setSelected(current => e.target.checked ? [...current, key] : current.filter(item => item !== key))} />{label}</label>)}</div></div>; })}
        </details>
        <Button size="sm" onClick={() => void perform(async () => {
          if (encrypted && (password.length < 12 || password !== repeat)) throw new Error("Use at least 12 characters and enter the same password twice.");
          const included = available.map(([key]) => key).filter(key => selected.includes(key));
          if (!included.length) throw new Error("Select at least one section.");
          const path = await pickSaveFile("Export Oars configuration", encrypted ? "oars.oarsvault" : "oars.json");
          if (!path) return;
          const result = await api.vault.export({ path, ...(encrypted ? { password } : {}), sections: included });
          setStatus(`Exported ${result.exported} sections to ${path}. Saved secrets were excluded.`);
          setPassword(""); setRepeat("");
        })}>Export…</Button>
      </fieldset>
    </section>}
    {mode === "import" && <section className="transfer-section">
      <h2>Import configuration</h2>
      <p className="muted">Preview changes before applying them. Imported connections can ask for passwords on first use.</p>
      {!preview && <fieldset className="transfer-import-form" disabled={busy}>
        <label htmlFor={`${id}-import-password`}>Import password (leave empty for plain JSON)</label>
        <input id={`${id}-import-password`} type="password" autoComplete="off" value={importPassword} onChange={e => setImportPassword(e.target.value)} />
        <Button size="sm" variant="outline" onClick={() => void perform(async () => {
          const path = await pickFile("Select an Oars vault or JSON file");
          if (!path) return;
          const params = { path, ...(importPassword ? { password: importPassword } : {}) };
          const result = await api.vault.import(params);
          setSource(params); setPreview(result.preview); setChoices({}); setImportPassword("");
          setStatus("Preview ready. No changes have been applied.");
        })}>Pick &amp; preview</Button>
      </fieldset>}
      {preview && source && <>
        <div className="transfer-review-heading"><FileCheck2 size={18} aria-hidden /><div><h3>Review incoming changes</h3><p>Your configuration is unchanged until you confirm.</p></div></div>
        <p className="oars-data-path">Source: {source.path}</p>
        {preview.errors.map((item, index) => <p role="alert" key={index}>{item.key}: {item.reason}</p>)}
        <div className="transfer-review-columns" aria-hidden><span>Section</span><span>Incoming</span><span>New</span><span>Updates</span></div>
        {preview.reports.map(report => <section className="transfer-report" key={report.name}>
          <div className="transfer-report-row"><h3>{sections.find(([key]) => key === report.name)?.[1] ?? report.name}</h3><span aria-label={`${report.incoming} incoming`}>{report.incoming}</span><span aria-label={`${report.new} new`}>{report.new}</span><span aria-label={`${report.updated} updates`}>{report.updated}</span></div>
          {report.conflicts.map(conflict => <div key={conflict.key} className="oars-data-conflict">
            <label htmlFor={`${id}-${conflict.key}`}>{conflict.reason}</label><code className="transfer-conflict-key">{conflict.key}</code>
            <OarsSelect id={`${id}-${conflict.key}`} disabled={busy} value={choices[conflict.key] ?? "keep"} onValueChange={value => setChoices(current => ({ ...current, [conflict.key]: value }))} options={[{ value: "keep", label: "Keep local" }, { value: "new", label: "Import as new" }]} />
          </div>)}
        </section>)}
        <div className="oars-data-actions transfer-review-actions">
          <Button size="sm" variant="ghost" disabled={busy} onClick={cancelPreview}>Cancel</Button>
          <Button size="sm" disabled={busy || preview.errors.length > 0} onClick={() => void perform(async () => {
            const conflicts = preview.reports.flatMap(report => report.conflicts.map(conflict => conflict.key));
            const result = await api.vault.importConfirm({ ...source, keep_local: conflicts.filter(key => choices[key] !== "new"), import_as_new: conflicts.filter(key => choices[key] === "new") });
            setSource(null); setPreview(null); setChoices({});
            setStatus(`Import applied. ${result.result.notes.join(" ")}`);
            onImported?.();
          })}>Confirm import</Button>
        </div>
      </>}
    </section>}
    <div role="status">{busy ? "Working…" : status}</div>
    {error && <div className="oars-form-error" role="alert">{error}</div>}
  </div>;
}
