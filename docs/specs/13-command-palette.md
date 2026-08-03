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
- Keyboard model: `⌘K` toggle, arrows, enter, escape, `>`-prefixed command mode, `/` server-list filter, `⌘1..9` tab switching.
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

### 4.3 Keyboard map (global)
| Chord | Action |
|---|---|
| `⌘K` | toggle palette |
| `⌘1`–`⌘9` | switch to tab N |
| `⌘W` | close current tab |
| `⌘T` | new terminal tab (current server or picker) |
| `⌘⇧T` | re-open last closed tab |
| `/` | filter server list (sidebar focus) |
| `⌘,` | settings (provider, themes, alerts) |
| `⌘E` | open file manager tab for current server |
| `⌘L` | focus log search |
| `esc` | close palette/dialogs; `shift+esc` in terminal sends real escape |

## 5. Bridge API

The palette is a **frontend registry** — no new bridge surface. Actions
call existing commands. The only new piece:

### `oars.palette.recents` → client-side localStorage (no bridge needed)
(Registry is in code; see §6.)

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
- Terminal focused: `⌘K` must not be swallowed by xterm (global keydown on window, `metaKey` checks).
- Palette open while a dialog is open → dialogs win (palette suppressed).
- Long script list → `#` prefix + fuzzy covers it.

## 11. Testing

- Unit: ranking order fixtures, command-mode parsing, double-enter guard.
- Manual: every chord above on macOS; palette with 200+ synthetic entries.

## 12. Acceptance criteria

- [ ] Every primary action in the app is palette-reachable.
- [ ] Keyboard map works in terminal focus without conflicts.
- [ ] Danger double-enter guard verified.
- [ ] Fuzzy ranking feels right on realistic names.
