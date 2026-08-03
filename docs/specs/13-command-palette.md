# Spec 13 — Command Palette & Keyboard UX

**Status:** 📋 · **Depends on:** everything (palette indexes all features) · **Spec owner:** frontend

## 1. Overview

`⌘K` opens a fuzzy-search palette over the whole app: servers, scripts,
actions, tabs, and history. The keyboard is the primary input surface —
every action reachable without the mouse. This is the Oars+ answer to
CtrlOps's form-and-mouse-heavy UI.

## 2. Goals / non-goals

**Goals**
- Global palette: open server, run script, jump to tab, invoke actions (add server, scan logs, offboard…), search history.
- Keyboard model: platform-specific palette shortcut, arrows, enter, escape,
  `>`-prefixed command mode, `/` server-list filter, and tab switching.
- Recents + fuzzy ranking; palette state preserved per session.
- Actions registry: every feature registers palette entries declaratively.

**Non-goals**
- No CLI shell, no scripting via the palette (scripts are the feature for that), no OS-global shortcuts beyond the app window.

## 3. User stories

- I press `⌘K`, type "pro", hit enter — prod-api-01 opens.
- I press `⌘K`, type ">run tail-error", pick it, choose a server — the script runs.
- I press `⌘2` to jump to my second tab.
- I type "offboard" in the palette and land on the access action.

## 4. UI/UX

### 4.1 Palette
- Overlay centered-top, input + results list (max 8 visible), footer hints (`↑↓ navigate · ↵ run · esc close`).
- Item schema: `{id, group, title, subtitle, keywords[], icon?, action(), danger?: bool}`.
- Groups rendered with headers; fuzzy match highlights characters.
- Recents section (last 5 executed) above results when the query is empty.
- Danger actions show a red-tinted row and require `↵` twice (first press selects, second confirms) — the palette's guardrail.

### 4.2 Command mode
- Prefix `>` filters to actions only; `@` filters servers; `#` filters scripts; `/` filters history entries (spec 15) with a "re-run" action.

### 4.3 Keyboard map

Linux and Windows do not map every Command shortcut to Ctrl because Ctrl+W,
Ctrl+T, Ctrl+K, and Ctrl+L are shell-editing inputs.

| Action | macOS | Linux/Windows |
|---|---|---|
| Toggle palette | `⌘K` | `Ctrl+Shift+P` |
| Switch to tab 1–9 | `⌘1`–`⌘9` | `Alt+1`–`Alt+9` |
| Close current tab | `⌘W` | `Ctrl+Shift+W` |
| New terminal tab | `⌘T` | `Ctrl+Shift+T` |
| Re-open last closed tab | `⌘⇧T` | `Ctrl+Shift+R` |
| Filter server list while the sidebar has focus | `/` | `/` |
| Settings | `⌘,` | `Ctrl+,` |
| File manager for current server | `⌘E` | `Ctrl+Shift+E` |
| Focus log search outside the terminal | `⌘L` | `Ctrl+Shift+L` |

Escape closes the top app overlay when one is open. Otherwise, a focused
terminal receives Escape unchanged.

## 5. Bridge API

The palette is a **frontend registry** with no new bridge surface. Actions call
existing commands. Recents are frontend state, not an `oars.*` command.

## 6. Zig core design

None — pure frontend (`src/palette.tsx` + `actions.ts` registry). The
registry is a single module every feature imports to register entries;
keeps coupling one-way.

## 7. Data model

- Recents + last query: localStorage (`oars.palette`). No server data.

## 8. Security

- Danger actions get the double-enter guard; destructive actions inherit
  their feature's own confirms (type-to-confirm flows can't be bypassed
  by the palette — the palette only opens the flow).

## 9. Performance

- Fuzzy index built lazily per keystroke over ≤ 2,000 entries; ranking in
  < 5 ms (simple substring+prefix scoring, no heavy deps).

## 10. Edge cases

- No servers yet → palette still lists actions (add server) — empty states everywhere.
- Terminal focused: use xterm's custom key handler to reserve only documented
  app shortcuts. Do not intercept Ctrl+K on Linux or Windows because shells use
  it for line editing.
- Palette open while a dialog is open → dialogs win (palette suppressed).
- Long script list → `#` prefix + fuzzy covers it.

## 11. Testing

- Unit: ranking order fixtures, command-mode parsing, double-enter guard.
- Manual: every chord above on macOS, Linux, and Windows, including terminal
  focus; palette with 200+ synthetic entries.

## 12. Acceptance criteria

- [ ] Every primary action in the app is palette-reachable.
- [ ] Keyboard map works in terminal focus without conflicts.
- [ ] Danger double-enter guard verified.
- [ ] Fuzzy ranking feels right on realistic names.

## 13. Research & References

- **`⌘K` palette as an app-shell pattern** — the palette-over-app
  pattern (fuzzy search over commands/objects, `>` command mode) is a
  well-established desktop convention (VS Code Command Palette,
  Raycast, Linear); no external protocol to cite — the registry design
  is internal.
- **Keyboard conflicts with xterm.js** — global key handling must
  intercept `metaKey` chords before xterm's keydown handler. xterm.js
  documents its `attachCustomKeyEventHandler` hook for exactly this
  (filtering/replacing key events before terminal processing) —
  verified in the installed typings
  `frontend/node_modules/xterm/typings/xterm.d.ts`
  (`attachCustomKeyEventHandler` is part of the public `Terminal`
  API). The palette listens on `window` with `metaKey` checks so the
  terminal never sees `⌘K`.
- **Fuzzy ranking** — client-side substring/prefix scoring; no external
  dependency (no fuse.js etc. — kept dependency-free per project
  convention).
- **Shortcut correction** — `⌘K` opens the palette everywhere on macOS.
  Linux and Windows use `Ctrl+Shift+P`, and their other app shortcuts avoid
  common Ctrl-based shell editing inputs. Log-search shortcuts apply only
  outside terminal focus.

Sources: xterm.js typings (`frontend/node_modules/xterm/typings/xterm.d.ts`),
internal design decisions.
