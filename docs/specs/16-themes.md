# Spec 16 — Themes & Terminal Appearance

**Status:** 📋 · **Depends on:** — (frontend-only) · **Spec owner:** frontend

## 1. Overview

A token-driven appearance system: light and dark themes, accent choice,
and terminal color schemes. The comparison target's current public docs do not
state a theme contract, so this is an Oars product choice, not a verified
competitor gap. Design rule from the product brief: **no teal/green
in the UI palette** — the accent family is blue; amber = pending/warning;
red = error. (Terminal ANSI palette keeps standard green because it
renders the remote server's content, not our UI.)

## 2. Goals / non-goals

**Goals**
- Theme: Dark (default) / Light; accent: Blue (default) / Violet / Amber / Rose.
- Terminal schemes: Oars Dark, One Dark, Solarized, and plain ANSI. Solarized
  selects its dark or light palette to match the chosen app theme.
- All colors use CSS custom properties. On first launch,
  `prefers-color-scheme` can choose the initial Dark or Light value; after that,
  the explicit user choice is authoritative.
- Persist per-user; apply instantly without reload.

**Non-goals**
- No full editor-theme engine, no user-defined arbitrary palettes (v1; the token set is the extension point), no per-server themes (v1).

## 3. User stories

- I open the app at night → dark; I switch to light for daytime.
- I prefer a violet accent; every button, dot, and selection follows.
- My terminal uses One Dark to match my editor.

## 4. UI/UX

### 4.1 Settings (⌘, → Appearance)
- Theme radio (Dark/Light), accent swatches (4), terminal scheme select with live preview (mini xterm sample).
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

- N/A (no server interaction). Normal text must meet 4.5:1 and large text
  3:1 under WCAG 2.2 SC 1.4.3. UI component boundaries and meaningful
  graphics must meet 3:1 under SC 1.4.11.

## 9. Performance

- Theme switch = attribute flip + one re-render; xterm theme update is O(colors), no reconnect.

## 10. Edge cases

- The OS theme changes after first launch → keep the user's stored choice. A
  future System mode needs an explicit product decision; it is not implied by
  reading `prefers-color-scheme` once.
- Terminal scheme with unreadable colors on light bg → schemes define bg+fg pairs together (never mixed).
- Accent contrast on buttons → accent-strong on dark, darker accent on light (token pair, not single value).

## 11. Testing

- Manual: switch all combos; verify terminal in-place re-theme; verify status colors unchanged across themes.
- Lint (later): parse CSS and reject color declarations outside approved token
  definitions. A text grep is not a reliable CSS validator.

## 12. Acceptance criteria

- [ ] Dark/Light + 4 accents + 4 terminal schemes work and persist.
- [ ] No UI color outside the token set (except terminal ANSI).
- [ ] Status vocabulary (amber/blue/red) identical in both themes.
- [ ] Theme switch never interrupts sessions.

## 13. Research & References

- **xterm.js live re-theme** — verified against the installed typings
  `frontend/node_modules/xterm/typings/xterm.d.ts` (package `xterm`
  5.3.0): `ITerminalOptions.theme?: ITheme` (L246) and `options` is
  the live terminal options object — assigning
  `term.options.theme = {…}` re-themes the terminal in place without
  recreating the Terminal instance (no reconnect, no data loss). This
  is the documented mechanism the spec's "apply instantly without
  reload" depends on.
- **Contrast (WCAG AA)** — WCAG 2.2 SC 1.4.3 sets 4.5:1 for normal text
  and 3:1 for large text. UI component and meaningful graphical-object
  contrast is covered separately by SC 1.4.11 at 3:1. The earlier text
  incorrectly put UI components under SC 1.4.3
  (`https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html` and
  `https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html`).
  Token contrast must be tested;
  a planned grep is not proof that the current palette passes.
- **`prefers-color-scheme`** — the CSS media query supplies the initial choice
  only. The prior review invented a persistent System mode that the product
  contract did not request, so it was removed.
- **Scheme palette data** — terminal schemes (One Dark, Solarized) are
  conventional ANSI-16 palettes; stored as JSON in localStorage;
  xterm's `theme` object maps ANSI indexes 0–15 + `background`/
  `foreground` (per xterm typings `ITheme`).
- **No teal/green** — product constraint (spec §1); the terminal ANSI
  palette keeps standard green because it renders remote content, not
  app UI.

Sources: xterm 5.3.0 typings, WCAG 2.2 SC 1.4.3 and 1.4.11, CSS media queries.
