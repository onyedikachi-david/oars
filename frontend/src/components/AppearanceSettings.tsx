import { useEffect, useId, useRef, useState } from "react";
import { Terminal } from "xterm";
import { Check, Database, Monitor, Moon, Sun, TerminalSquare, X, ArrowUpRight } from "lucide-react";
import { FitAddon } from "@xterm/addon-fit";
import { useAppearance, updateAppearance, terminalTheme, terminalFont, type Appearance } from "../appearance";
import { ApplicationOverlay } from "./ApplicationPortal";
import { useModalFocus } from "./useModalFocus";
import { Button } from "./ui/button";
import { OarsSelect } from "./ui/select";

function TerminalPreview({ settings }: { settings: Appearance }) {
  const host = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  useEffect(() => {
    if (!host.current) return;
    const term = new Terminal({ rows: 4, cols: 50, disableStdin: true, scrollback: 0, fontSize: settings.fontSize, fontFamily: terminalFont(settings.font), theme: terminalTheme(settings) });
    const addon = new FitAddon(); term.loadAddon(addon); term.open(host.current);
    terminal.current = term; fit.current = addon;
    term.write("demo@server $ ls\r\n\x1b[34mapplications\x1b[0m  \x1b[32mdeploy.sh\x1b[0m  notes.txt\r\n");
    const observer = new ResizeObserver(() => { try { addon.fit(); } catch {} }); observer.observe(host.current);
    return () => { observer.disconnect(); term.dispose(); terminal.current = null; fit.current = null; };
  }, []);
  useEffect(() => {
    if (!terminal.current) return;
    terminal.current.options.theme = terminalTheme(settings);
    terminal.current.options.fontFamily = terminalFont(settings.font);
    terminal.current.options.fontSize = settings.fontSize;
    try { fit.current?.fit(); } catch {}
  }, [settings]);
  return <div className="prefs-preview" style={{ background: terminalTheme(settings).background }}><div ref={host} aria-label="Live terminal appearance preview" /></div>;
}

type Section = "appearance" | "terminal" | "data";
export function AppearanceSettings({ onClose, onData }: { onClose: () => void; onData?: () => void }) {
  const id = useId();
  const ref = useModalFocus(onClose);
  const settings = useAppearance();
  const [section, setSection] = useState<Section>("appearance");
  const [error, setError] = useState("");
  const save = (patch: Partial<Appearance>) => setError(updateAppearance(patch) ? "" : "Changed for this session. Device storage is unavailable.");
  const sections = [{ id: "appearance" as const, title: "Appearance", icon: Monitor }, { id: "terminal" as const, title: "Terminal", icon: TerminalSquare }, ...(onData ? [{ id: "data" as const, title: "Data", icon: Database }] : [])];
  return <ApplicationOverlay quiet><div ref={ref} role="dialog" aria-modal="true" aria-labelledby={`${id}-title`} className="oars-modal preferences-dialog">
    <header className="preferences-header"><h2 id={`${id}-title`}>Settings</h2><Button size="icon-sm" variant="ghost" aria-label="Close settings" onClick={onClose}><X /></Button></header>
    <div className="preferences-layout">
      <nav className="preferences-nav" aria-label="Settings sections">{sections.map(item => <button key={item.id} type="button" aria-pressed={section === item.id} aria-controls={`${id}-content`} onClick={() => setSection(item.id)}><item.icon size={16} aria-hidden />{item.title}</button>)}<span>On this device</span></nav>
      <section id={`${id}-content`} className="preferences-content" aria-label={`${sections.find(item => item.id === section)?.title} settings`}>
        {section === "appearance" && <>
          <header><h3>Appearance</h3><p>Make the workspace comfortable to read.</p></header>
          <fieldset className="prefs-theme"><legend>Theme</legend><div>{(["light", "dark"] as const).map(theme => <label key={theme} className={`prefs-theme-option prefs-theme-${theme}`}><input type="radio" name={`${id}-theme`} value={theme} checked={settings.theme === theme} onChange={() => save({ theme })} /><span className="prefs-theme-sample" aria-hidden>{theme === "light" ? <Sun size={22} /> : <Moon size={22} />}</span><span className="prefs-theme-caption">{theme === "light" ? "Light" : "Dark"}{settings.theme === theme && <Check size={14} aria-hidden />}</span></label>)}</div></fieldset>
          <fieldset className="prefs-accents"><legend>Accent color</legend><div>{(["studio", "blue", "violet", "amber", "rose"] as const).map(accent => <label key={accent} className={`prefs-accent prefs-accent-${accent}`}><input type="radio" name={`${id}-accent`} value={accent} checked={settings.accent === accent} onChange={() => save({ accent })} /><span className="prefs-color" aria-hidden>{settings.accent === accent && <Check size={14} />}</span><span>{accent === "studio" ? "Default" : accent[0].toUpperCase() + accent.slice(1)}</span></label>)}</div></fieldset>
        </>}
        {section === "terminal" && <>
          <header><h3>Terminal</h3><p>Changes apply to open terminals immediately.</p></header>
          <div className="prefs-form-row"><label htmlFor={`${id}-scheme`}>Color scheme</label><OarsSelect id={`${id}-scheme`} value={settings.terminalScheme} onValueChange={terminalScheme => save({ terminalScheme: terminalScheme as Appearance["terminalScheme"] })} options={[{ value: "oars", label: "Oars Dark" }, { value: "one-dark", label: "One Dark" }, { value: "solarized", label: "Solarized" }, { value: "ansi", label: "Plain ANSI" }]} /></div>
          <div className="prefs-form-row"><label htmlFor={`${id}-font`}>Font</label><OarsSelect id={`${id}-font`} value={settings.font} onValueChange={font => save({ font: font as Appearance["font"] })} options={[{ value: "system", label: "System monospace" }, { value: "menlo", label: "Menlo / Monaco" }, { value: "monospace", label: "Browser monospace" }]} /></div>
          <div className="prefs-form-row"><label htmlFor={`${id}-size`}>Font size</label><div className="prefs-font-size"><input id={`${id}-size`} type="number" min={10} max={24} value={settings.fontSize} onChange={event => { const size = Number(event.target.value); if (Number.isInteger(size) && size >= 10 && size <= 24) save({ fontSize: size }); }} /><span>px</span></div></div>
          <TerminalPreview settings={settings} />
        </>}
        {section === "data" && <>
          <header><h3>Data</h3><p>Move your configuration between devices.</p></header>
          <div className="prefs-data-row"><Database size={20} aria-hidden /><div><h4>Export and import</h4><p>Connection profiles, scripts, and local journals.</p></div></div>
          <p className="prefs-data-note">Choose what to export, or review an import before applying it.</p>
          <Button variant="outline" onClick={onData}>Open data transfer <ArrowUpRight /></Button>
        </>}
        {error && <p className="oars-form-error" role="alert">{error}</p>}
      </section>
    </div>
    <footer className="preferences-footer"><span>{error ? "Changes are not saved" : "Saved automatically"}</span><Button size="sm" variant="outline" onClick={onClose}>Done</Button></footer>
  </div></ApplicationOverlay>;
}
