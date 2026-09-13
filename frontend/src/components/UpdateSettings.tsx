import { useEffect, useId, useState } from "react";
import { AlertCircle, ArrowUpRight, CheckCircle2, Download, PauseCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "./ui/button";
import { ApplicationNotice } from "./ApplicationPortal";
import { updateApi, useUpdates, type UpdateStatus } from "../updates";

const appIcon = new URL("../../../assets/icon.png", import.meta.url).href;
function statusText(status: UpdateStatus): string {
  switch (status.state) {
    case "unavailable": return "Updates are available in installed release builds.";
    case "checking": return "Checking for updates…";
    case "downloading": return "Downloading the update in the background…";
    case "verifying": return "Verifying the downloaded update…";
    case "ready": return "The update is ready. It will install when you quit Oars.";
    case "blocked": return "Finish active work and disconnect sessions before restarting.";
    case "available": return `Oars ${status.latest_version} is available.`;
    case "error": return status.error || "Could not check for updates. Try again.";
    default: return "";
  }
}
function Preference({ id, title, description, checked, disabled, onChange }: {
  id: string; title: string; description: string; checked: boolean; disabled: boolean; onChange: (checked: boolean) => void;
}) {
  return <label className="update-preference" htmlFor={id} data-disabled={disabled || undefined}>
    <span className="update-preference-copy"><span id={`${id}-label`}>{title}</span><span id={`${id}-description`}>{description}</span></span>
    <span className="update-toggle"><input id={id} type="checkbox" role="switch" aria-labelledby={`${id}-label`} aria-describedby={`${id}-description`} checked={checked} disabled={disabled} onChange={event => onChange(event.target.checked)} /><span className="update-toggle-track" aria-hidden="true" /></span>
  </label>;
}
export function UpdateSettings() {
  const id = useId();
  const status = useUpdates();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [optimistic, setOptimistic] = useState<{ checks: boolean; downloads: boolean } | null>(null);
  useEffect(() => {
    if (optimistic && status?.automatic_checks === optimistic.checks && status?.automatic_downloads === optimistic.downloads) setOptimistic(null);
  }, [status?.automatic_checks, status?.automatic_downloads, optimistic]);
  async function perform(action: () => Promise<unknown>) {
    setPending(true); setError("");
    try { await action(); } catch (e) { setOptimistic(null); setError(e instanceof Error ? e.message : "The update action failed. Try again."); }
    finally { setPending(false); }
  }
  function save(checks: boolean, downloads: boolean) {
    setOptimistic({ checks, downloads });
    void perform(() => updateApi.preferences(checks, downloads));
  }
  const checks = optimistic?.checks ?? status?.automatic_checks ?? false;
  const downloads = optimistic?.downloads ?? status?.automatic_downloads ?? false;
  const updating = status && ["checking", "downloading", "verifying"].includes(status.state);
  const StateIcon = status?.state === "error" ? AlertCircle : status?.state === "blocked" ? PauseCircle : status?.state === "ready" ? CheckCircle2 : updating ? RefreshCw : Download;
  const showState = status && status.state !== "idle";
  return <div className="update-settings">
    <header className="update-heading"><h3>Updates</h3><p>Keep your workspace up to date.</p></header>
    <div className="update-version-row">
      <span className="update-brand-icon"><img src={appIcon} alt="" width={78} height={78} /></span>
      <div className="update-version-copy"><strong>Oars</strong><span>{status ? `Version ${status.current_version}` : "Desktop application"}</span></div>
      <Button variant="outline" size="sm" disabled={pending || !status?.can_check} onClick={() => void perform(updateApi.check)}><RefreshCw data-icon="inline-start" className={status?.state === "checking" ? "update-spinner" : undefined} />{status?.state === "checking" ? "Checking…" : status?.state === "ready" && status.mode === "sparkle" ? "Review update" : "Check for updates"}</Button>
    </div>
    {!status && <p className="update-unavailable">Update controls are available in the desktop app.</p>}
    {showState && <div className="update-state" data-state={status.state} role="status">
      <StateIcon aria-hidden="true" className={updating ? "update-spinner" : undefined} /><p>{statusText(status)}</p>
      {status.can_resume && <Button size="sm" disabled={pending || status.busy} onClick={() => void perform(updateApi.resume)}>Restart to update</Button>}
    </div>}
    {status && status.mode !== "unavailable" && <>
      <fieldset className="update-preferences" disabled={pending}>
        <legend>Update preferences</legend>
        <Preference id={`${id}-checks`} title="Check for updates automatically" description="Look for new releases while Oars is open." checked={checks} disabled={pending} onChange={value => save(value, downloads)} />
        {status.mode === "sparkle" && <Preference id={`${id}-downloads`} title="Download updates in the background" description="Keep working while updates download." checked={downloads} disabled={pending} onChange={value => save(checks, value)} />}
      </fieldset>
      {status.mode === "sparkle" && <div className="update-install-note"><ShieldCheck aria-hidden="true" /><p>Updates are verified before installation. Install when you quit, or restart when your work is finished.</p></div>}
      {status.mode === "homebrew" && <div className="update-managed"><strong>Managed by Homebrew</strong><p>Finish active work and quit Oars, then run:</p><pre>brew update{"\n"}brew upgrade --cask onyedikachi-david/tap/oars</pre></div>}
      {status.mode === "manual" && <div className="update-managed"><strong>Update from a download</strong><p>Download the latest Linux package from the releases page. Finish active work and quit Oars before replacing the installed files. Your settings and server data stay in place.</p></div>}
      <div className="update-links"><Button variant="link" size="sm" disabled={pending} onClick={() => void perform(updateApi.releaseNotes)}>Release notes <ArrowUpRight data-icon="inline-end" /></Button></div>
    </>}
    {error && <p className="oars-form-error update-action-error" role="alert">{error}</p>}
  </div>;
}
export function UpdateNotice({ onOpen }: { onOpen: () => void }) {
  const status = useUpdates();
  const [dismissed, setDismissed] = useState("");
  if (!status || !["available", "ready", "blocked"].includes(status.state) || !status.latest_version || dismissed === status.latest_version) return null;
  return <ApplicationNotice><div className="oars-update-notice" role="status"><Download aria-hidden="true" /><span>{status.state === "blocked" ? "Finish active work and disconnect sessions before updating." : `Oars ${status.latest_version} is available.`}</span><Button size="sm" variant="outline" onClick={onOpen}>View update</Button><Button size="sm" variant="ghost" onClick={() => setDismissed(status.latest_version)}>Later</Button></div></ApplicationNotice>;
}
