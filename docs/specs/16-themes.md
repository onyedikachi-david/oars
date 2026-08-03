# Spec 16 — Themes & Terminal Appearance

**Status:** 📋 · **Depends on:** — (frontend-only) · **Spec owner:** frontend

## 1. Overview

A token-driven appearance system: light and dark themes, accent choice,
and terminal color schemes. UI polish that CtrlOps (dark-only, fixed
accent) doesn't offer. Design rule from the product brief: **no teal/green
in the UI palette** — the accent family is blue; amber = pending/warning;
red = error. (Terminal ANSI palette keeps standard green because it
renders the remote server's content, not our UI.)

## 2. Goals / non-goals

**Goals**
- Theme: Dark (default) / Light; accent: Blue (default) / Violet / Amber / Rose.
- Terminal schemes: Oars Dark, One Dark, Solarized (dark+light), plain ANSI.
- All colors via CSS custom properties; `prefers-color-scheme` honored at first launch.
- Persist per-user; apply instantly without reload.

**Non-goals**
- No full editor-theme engine, no user-defined arbitrary palettes (v1; the token set is the extension point), no per-server themes (v1).

## 3. User stories

- I open the app at night → dark; I switch to light for daytime.
- I prefer a violet accent; every button, dot, and selection follows.
- My terminal uses One Dark to match my editor.

## 4. UI/UX

### 4.1 Settings (⌘, → Appearance)
- Theme radio (Dark/Light/System), accent swatches (4), terminal scheme select with live preview (mini xterm sample).
- Changes apply immediately; terminal tabs re-theme in place (xterm `options.theme` update without reconnect — supported by xterm.js).

### 4.2 Token set (index.css `:root` + `[data-theme="light"]`)
```css
--bg --bg-elevated --bg-hover --bg-active --border --border-strong
--text --text-secondary --text-faint
--accent --accent-strong --accent-dim --accent-border
--amber --amber-dim --red --red-dim
--mono --ui --radius
```
- Semantic status colors stay fixed across themes (amber/red/blue) so
  "connecting/error" is never theme-dependent.
- Accent swap = three property overrides (`--accent*`); components never
  hardcode colors (audit rule: no `#hex` outside the token block).

### 4.3 Terminal schemes
- Stored as JSON in `localStorage` (`oars.theme.terminal`); xterm theme object generated from the scheme + current theme background.

## 5. Bridge API

None — localStorage only. (If a future "theme per machine" need arises, it
becomes a settings file via the store; deliberately not built now.)

## 6. Zig core design

None.

## 7. Data model

- `localStorage: oars.theme = {theme, accent, terminalScheme}`.

## 8. Security

- N/A (no server interaction). Contrast: both themes meet WCAG AA for
  body text (token pairs chosen accordingly; checked in CI lint later).

## 9. Performance

- Theme switch = attribute flip + one re-render; xterm theme update is O(colors), no reconnect.

## 10. Edge cases

- System theme changes at runtime → live-follow when "System" selected (`matchMedia` listener).
- Terminal scheme with unreadable colors on light bg → schemes define bg+fg pairs together (never mixed).
- Accent contrast on buttons → accent-strong on dark, darker accent on light (token pair, not single value).

## 11. Testing

- Manual: switch all combos; verify terminal in-place re-theme; verify status colors unchanged across themes.
- Lint (later): grep for stray hex colors outside the token block.

## 12. Acceptance criteria

- [ ] Dark/Light + 4 accents + 4 terminal schemes all work and persist.
- [ ] No UI color outside the token set (except terminal ANSI).
- [ ] Status vocabulary (amber/blue/red) identical in both themes.
- [ ] Theme switch never interrupts sessions.
