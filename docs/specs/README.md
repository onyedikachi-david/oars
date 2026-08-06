# Oars — Feature Specifications

One spec file per product feature. These are the working contracts for
implementation: bridge payloads, UI states, Zig-side design, security
bounds, and acceptance criteria. The body of each spec defines the target
product. A gap in the current code must not remove or narrow that target.
Each status describes verified code in this checkout. `Partial` means that
some code exists, but at least one required behavior is missing. `📋` means
Planned: the file is an implementation contract, not a claim that the feature
already exists.

| # | Spec | Status |
|---|------|--------|
| 01 | [Multi-Server Management](01-multi-server.md) | Partial: CRUD, UI, and store hardening (perms, quarantine, save semantics) land; fingerprint migration (02) and grouping pending |
| 02 | [Terminal (SSH)](02-terminal.md) | Partial: shell, exec, trust, per-tab cursors, resize, canonical fingerprints land; exec/trust UI and mirrored-tab wiring pending |
| 03 | [Infra Monitoring](03-monitoring.md) | ✅ backend in (UI pending): parsers, /proc/stat deltas, probe-on-demand cache, cleanup plans, drop-caches audit |
| 04 | [Log Management](04-logs.md) | ✅ backend in (UI pending): NUL-delimited scan with busybox fallback, read, follow channels, identity-bound SFTP clear + audit, per-server source store |
| 05 | [File Manager (SFTP)](05-file-manager.md) | 📋 |
| 06 | [Scripts + Safe Broadcast](06-scripts.md) | 📋 |
| 07 | [One-Click Deployment](07-deployment.md) | 📋 |
| 08 | [SSH Management](08-ssh-management.md) | 📋 |
| 09 | [Access Management](09-access.md) | 📋 |
| 10 | [Backups](10-backups.md) | 📋 |
| 11 | [AI Terminal](11-ai-terminal.md) | 📋 |
| 12 | [Remote Desktop (VNC)](12-vnc.md) | 📋 (packaged macOS WebView transport verified; implementation planned) |
| 13 | [Command Palette & Keyboard UX](13-command-palette.md) | 📋 (Oars+) |
| 14 | [Server Groups & Fleet Views](14-groups.md) | ✅ backend in (UI pending): group/tags validation + normalization on `servers.save` (one-level path rule, case-insensitive dedupe) |
| 15 | [Command History & Audit](15-history.md) | ✅ backend in (UI pending): history/audit journals with write-time redaction, tracked-exec capture, replay, type-to-confirm clear |
| 16 | [Themes & Terminal Appearance](16-themes.md) | 📋 (Oars+) |
| 17 | [Export / Import (Vault)](17-export-import.md) | ✅ backend in (UI pending): AES-256-GCM vault + plain JSON export/import, merge preview, credential-binding conflicts, atomic write-back |
| 18 | [SSH Agent & Jump Hosts](18-agent-jump-hosts.md) | 📋 (Oars+) |

## Template used by every spec

1. **Overview** — one paragraph, the job this feature does
2. **Goals / non-goals** — what it is and is not
3. **User stories** — the flows that must work
4. **UI/UX** — layout, states, interactions, keyboard, empty/error states
5. **Bridge API** — exact command names, payloads, responses
6. **Zig core design** — modules, threading, algorithms
7. **Data model & persistence** — what is stored where (secrets → Keychain)
8. **Security** — trust bounds, approvals, redaction
9. **Performance** — budgets and how they are met
10. **Edge cases** — the failure modes that must be handled
11. **Testing** — unit, integration, and acceptance checks
12. **Acceptance criteria** — the definition of done
13. **Research & References** — every external claim cited to a primary
    source (URL and/or local file with line refs), and any corrections
    the research forced on the draft. Required for every spec; a spec
    without references is unfinished.

## Cross-cutting conventions

- **Implementation truth:** a module name in a planned spec is a proposed
  file. It is not proof that the file exists. A feature becomes complete only
  after its acceptance checks pass against the current checkout.
- **Streams:** all streaming output uses the non-destructive cursor-delta
  protocol established for `oars.ssh.poll`. Each consumer supplies its own
  absolute per-channel cursor; `dropped` reports that consumer's gap and
  `rewind` starts it at retained-buffer start. New streaming features reuse it.
- **Secrets:** passwords, passphrases, API keys, and bucket keys persist locally
  in the OS Keychain via `native-sdk.credentials.*`, keyed per owner
  (`<server_id>`, `vnc:<server_id>`, `ai:<provider>`…). Local app config files
  never contain them. A feature that must copy a secret elsewhere, such as a
  server-side rclone config for unattended cron, must state the destination,
  protection, and approval in its own contract.
- **Dangerous actions:** anything that mutates a server is approval-gated;
  destructive operations additionally require type-to-confirm or an
  explicit destructive warning. Every executed command goes to command
  history; every mutating product action also gets an audit entry (spec 15).
- **Errors:** bridge handlers return `{"ok":false,"error":"human message"}`
  for user-facing failures; the framework rejects on transport errors.
- **Remote commands:** SSH exec accepts one shell command string. It does not
  carry an argv array. Any value from a user, server profile, file path,
  domain, or model must go through one shared POSIX-shell quoting function, or
  through a protocol such as SFTP that does not invoke a shell. A spec must
  not call a command "argv-safe" unless a real argv transport exists.
- **Cancellation:** closing an SSH channel stops Oars from using that channel.
  It does not prove that the remote process stopped. A feature that needs a
  hard stop must start and track a remote process group, send a signal, and
  verify termination.
- **Research rule:** no spec claim is written from memory. Commands,
  flags, formats, and APIs are verified against primary sources (RFCs,
  GNU/OpenBSD man pages, official project docs) and the vendored/installed
  code (`third_party/`, `frontend/node_modules/`, the Native SDK), then
  cited in §13 with URLs and line refs. When research contradicts the
  draft, the spec body is corrected and the correction is noted in §13
  (e.g. spec 17's PBKDF2 count, spec 18's agent-forwarding API, spec 12's
  noVNC scaling API).
- **Threading:** one worker thread per SSH session owns all libssh2 calls;
  the runtime main thread never blocks on the network (spec 02, §6).

## Verification baseline

This set was reviewed on 2026-08-03 against the current Zig and React source,
the vendored libssh2 and mbedTLS headers, installed frontend packages, current
official OpenAI API schema, Node.js release schedule, Linux kernel guidance,
OWASP guidance, rclone documentation, and CtrlOps public docs and changelog.
External product facts can change. Recheck them before using a competitor
claim or version list to make a product decision.
