# Oars Design Specification

> Source of truth for the interface language, visual identity, layout, and interaction patterns.
> Every frontend change must satisfy this document. Where a feature spec (§4 UI/UX) and this file overlap, this file governs *how* it looks; the feature spec governs *what* it does.

## 1. Product Direction

Oars is a **calm infrastructure studio** for managing Linux servers locally.

It should feel like:

- A premium desktop operations tool
- A quiet editorial workspace
- A trustworthy control room
- A place for deliberate decisions, not constant alerts

It should not feel like:

- A terminal emulator
- A hacker-themed dashboard
- A generic SaaS admin panel
- A neon DevOps console
- A dense spreadsheet

The interface should make complex infrastructure feel understandable, composed, and safe.

---

## 2. Core Design Principles

### Calm over urgency

Use restrained visual emphasis. Not every metric, warning, or action should compete for attention.

### Progressive disclosure

Show the most important information first. Reveal advanced controls only when users enter a focused workflow.

### Spatial hierarchy

Use generous spacing and clear grouping. Screens should have one obvious primary focus.

### Human language

Prefer:

- "Needs attention"
- "Last backup"
- "Connection profile"
- "Run cleanup"
- "System health"

Avoid:

- `NODE_STATUS`
- `EXEC_CHANNEL`
- `CPU_UTIL`
- `SSH_READY`
- `POLLING`

Technical details may appear in secondary metadata, but never as the primary language.

### Local and trustworthy

The UI should communicate that data is private, local, and under the user's control without making security feel alarming.

---

## 3. Visual Identity

### 3.1 Light Theme — Mineral Paper

Warm mineral paper workspace.

| Token | Purpose | Character |
|-------|---------|-----------|
| Background | App canvas | Warm mineral paper |
| Foreground | Primary text | Deep ink |
| Card | Elevated surfaces | Soft ivory |
| Primary | Primary actions | Muted cobalt |
| Accent | Selected states | Mineral teal |
| Success | Healthy systems | Moss green |
| Warning | Attention states | Soft amber |
| Destructive | Dangerous actions | Muted clay red |
| Border | Separation | Warm gray |

Never use pure white and pure black together. Background is warm gray-beige; cards are slightly lighter; text is dark ink, not black; status colors are low saturation; borders are subtle and warm.

### 3.2 Dark Theme — Paper Night

Not blue-charcoal. A dark brown-gray reading room — warm ink on tobacco paper, a premium editorial application at night.

| Token | Purpose | Character |
|-------|---------|-----------|
| Background | App canvas | Warm ink-black |
| Foreground | Primary text | Soft ivory |
| Card | Elevated surfaces | Tobacco paper |
| Primary | Primary actions | Muted brass |
| Accent | Selected states | Burnished brown |
| Success | Healthy systems | Soft moss |
| Warning | Attention states | Warm amber |
| Destructive | Dangerous actions | Muted copper red |
| Border | Separation | Warm graphite |

Avoid: blue backgrounds, cyan highlights, neon green, purple gradients, pure black surfaces, bright white text.

---

## 4. Typography

Two families max:

1. **Geist Sans** — all interface text
2. **Geist Mono** — only technical metadata, commands, IP addresses, ports, logs, hashes, code. Never the whole app.

| Use | Size | Weight |
|-----|------|--------|
| Page title | 36–48px | 600–700 |
| Section title | 20–24px | 600 |
| Card title | 15–18px | 600 |
| Body text | 13–15px | 400 |
| Secondary text | 11–12px | 400 |
| Metadata | 10–11px | 500 |
| Technical metadata | 10–12px | 450 |

Rules: sentence case; avoid all-caps except tiny eyebrows; headings compact and confident; `text-pretty`/`text-balance` for important headings; relaxed line-height for body; avoid excessive bold.

---

## 5. Layout System

```
┌─────────────────────────────────────────────┐
│ Sidebar │ Topbar                             │
│         ├─────────────────────────────────────┤
│         │ Main workspace                      │
│         │                                     │
└─────────┴─────────────────────────────────────┘
```

**Sidebar** 232–260px, fixed, warm tinted, minimal border; logo + workspace switcher at top; grouped nav; user + local status at bottom.
**Topbar** 72–88px, breadcrumb/page context left, search + status right, translucent blurred, no excess controls.
**Main workspace** max 1440px, horizontal 32–48px, vertical 40–56px, generous gaps over heavy borders.

Tablet: sidebar becomes drawer, two-cols → one-col, tables scroll. Mobile: compact top bar, sidebar sheet, cards stack, dense tables become list rows, primary actions at top or bottom.

---

## 6. Spacing

| Token | Value | Use |
|-------|-------|-----|
| space-1 | 4px | Micro |
| space-2 | 8px | Compact controls |
| space-3 | 12px | Related items |
| space-4 | 16px | Card internal |
| space-5 | 20px | Section internals |
| space-6 | 24px | Card groups |
| space-8 | 32px | Major gaps |
| space-10 | 40px | Page sections |
| space-12 | 48px | Hero separation |

No arbitrary spacing unless necessary.

---

## 7. Surfaces and Cards

Gently elevated paper, not boxed containers. Radius 10–14px, subtle low-contrast border, soft broad shadow, no accent stripes, avoid excessive nesting. Three levels only: Canvas → Surface → Raised (dialogs/popovers).

---

## 8. Navigation

Groups — Workspace (Overview, Servers, Activity), Operations (Automation, Files, Logs, Deployments), Protection (Security, Backups, Vault), Intelligence (AI Context). Active item: filled soft accent surface (color + shape, not left border), outline icons, sentence case, counts only when useful.

---

## 9. Iconography

One icon library (lucide-react). Outline, moderate stroke, 16–20px standard. Icons aid recognition, not decoration. No emojis. Status icons support text, never replace it.

---

## 10. Status System

Understandable without color alone: text label + small dot/icon + optional detail. No unexplained color-only indicators.

| State | Label | Visual |
|-------|-------|--------|
| Healthy | Healthy | Moss green dot |
| Attention | Needs attention | Amber dot |
| Degraded | Degraded | Copper/amber dot |
| Offline | Offline | Muted gray dot |
| Running | Running | Brass or cobalt dot |
| Paused | Paused | Neutral dot |
| Failed | Failed | Clay red dot |

---

## 11–26. Screen Guidance

Condensed here; each later section of the original spec (Overview, Servers, Activity, Automation, Files, Logs, Security, Backups, Vault, AI Context, Forms/Dialogs, Buttons, Tables, Empty/Loading/Error, Motion, Accessibility) is normative. Key points referenced when building: one primary focus per screen; four or fewer primary metrics with context; attention queue over decorative charts; table ≤7 cols; skeletons not full-screen spinners; 150–220ms motion; never rely on color alone; dialogs have title + one-sentence explanation + affected resource + primary/cancel.

---

## 27. Theme Consistency Rules

Both themes share layout, typography, spacing, component shapes, navigation, interaction, and status semantics. Only surface colors, text/border contrast, shadows, and accent intensity change. Light = mineral paper, dark = paper night — two lighting conditions for the same premium workspace, not separate products.

---

## Implementation notes

- Tokens live in `frontend/src/index.css` (`:root` / `.dark` / `html.light` override). The shipped palettes already satisfy §3; do not introduce blue-charcoal dark or cyan highlights.
- The log viewer is the only place that uses `Geist Mono` for body text; every other surface uses `Geist Sans`.
- Spec 01–18 §4 UI descriptions must be interpreted through this document's language and density rules (human labels, restrained emphasis, progressive disclosure).
