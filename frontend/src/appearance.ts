import { useSyncExternalStore } from "react";
import { OARS_TERMINAL_THEME, ONE_DARK, PLAIN_ANSI, solarized } from "./terminal-themes";
export interface Appearance {
  theme: "light" | "dark";
  accent: "studio" | "blue" | "violet" | "amber" | "rose";
  terminalScheme: "oars" | "one-dark" | "solarized" | "ansi";
  font: "system" | "menlo" | "monospace";
  fontSize: number;
}
export function readAppearance(): Appearance {
  let raw: Partial<Appearance> = {};
  let legacy: string | null = null;
  try { raw = JSON.parse(localStorage.getItem("oars.theme") ?? "{}") ?? {}; legacy = localStorage.getItem("oars:theme"); } catch {}
  const theme = raw.theme ?? legacy;
  return {
    theme: theme === "light" || theme === "dark" ? theme : window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
    accent: ["studio", "blue", "violet", "amber", "rose"].includes(raw.accent ?? "") ? raw.accent! : "studio",
    terminalScheme: ["oars", "one-dark", "solarized", "ansi"].includes(raw.terminalScheme ?? "") ? raw.terminalScheme! : "oars",
    font: ["system", "menlo", "monospace"].includes(raw.font ?? "") ? raw.font! : "system",
    fontSize: Number.isInteger(raw.fontSize) && raw.fontSize! >= 10 && raw.fontSize! <= 24 ? raw.fontSize! : 13,
  };
}
let current = readAppearance();
const listeners = new Set<() => void>();
export function updateAppearance(patch: Partial<Appearance>): boolean {
  current = { ...current, ...patch };
  let saved = true;
  try { localStorage.setItem("oars.theme", JSON.stringify(current)); localStorage.setItem("oars:theme", current.theme); } catch { saved = false; }
  document.documentElement.dataset.accent = current.accent;
  listeners.forEach(listener => listener());
  return saved;
}
function subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; }
export function useAppearance() { return useSyncExternalStore(subscribe, () => current); }
window.addEventListener("storage", event => {
  if (event.key !== "oars.theme" && event.key !== "oars:theme") return;
  current = readAppearance(); document.documentElement.dataset.accent = current.accent; listeners.forEach(listener => listener());
});
export function terminalFont(font: Appearance["font"]) { return font === "menlo" ? "Menlo, Monaco, monospace" : font === "monospace" ? "monospace" : 'ui-monospace, "SF Mono", SFMono-Regular, Menlo, monospace'; }
export function terminalTheme(settings: Pick<Appearance, "terminalScheme" | "theme">) {
  if (settings.terminalScheme === "one-dark") return ONE_DARK;
  if (settings.terminalScheme === "solarized") return solarized(settings.theme === "light");
  if (settings.terminalScheme === "ansi") return PLAIN_ANSI;
  return OARS_TERMINAL_THEME;
}
