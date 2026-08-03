# Oars — Feature Specifications

One spec file per product feature. These are the working contracts for
implementation: bridge payloads, UI states, Zig-side design, security
bounds, and acceptance criteria. Where a feature already exists (marked
`✅ core in`), the spec documents the current behavior plus planned
improvements; everything else is the design to build against.

| # | Spec | Status |
|---|------|--------|
| 01 | [Multi-Server Management](01-multi-server.md) | ✅ core in (groups pending) |
| 02 | [Terminal (SSH)](02-terminal.md) | ✅ core in (history pending) |
| 03 | [Infra Monitoring](03-monitoring.md) | 📋 |
| 04 | [Log Management](04-logs.md) | 📋 |
| 05 | [File Manager (SFTP)](05-file-manager.md) | 📋 |
| 06 | [Scripts + Safe Broadcast](06-scripts.md) | 📋 |
| 07 | [One-Click Deployment](07-deployment.md) | 📋 |
| 08 | [SSH Management](08-ssh-management.md) | 📋 |
| 09 | [Access Management](09-access.md) | 📋 |
| 10 | [Backups](10-backups.md) | 📋 |
| 11 | [AI Terminal](11-ai-terminal.md) | 📋 |
| 12 | [Remote Desktop (VNC)](12-vnc.md) | 📋 (research done) |
| 13 | [Command Palette & Keyboard UX](13-command-palette.md) | 📋 (Oars+) |
| 14 | [Server Groups & Fleet Views](14-groups.md) | 📋 (Oars+) |
| 15 | [Command History & Audit](15-history.md) | 📋 (Oars+) |
| 16 | [Themes & Terminal Appearance](16-themes.md) | 📋 (Oars+) |
| 17 | [Export / Import (Vault)](17-export-import.md) | 📋 (Oars+) |
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

## Cross-cutting conventions

- **Streams:** all streaming output uses the cursor-delta protocol
  established for `oars.ssh.poll` (per-channel buffer, cursor, `dropped`
  counter, `rewind`). New streaming features reuse it.
- **Secrets:** passwords, passphrases, API keys, and bucket keys live in
  the OS Keychain via `native-sdk.credentials.*`, keyed per owner
  (`<server_id>`, `vnc:<server_id>`, `ai:<provider>`…). Config files
  never contain secrets.
- **Dangerous actions:** anything that mutates a server is approval-gated;
  destructive operations additionally require type-to-confirm or an
  explicit destructive warning. Every executed command is appended to the
  audit history (spec 15).
- **Errors:** bridge handlers return `{"ok":false,"error":"human message"}`
  for user-facing failures; the framework rejects on transport errors.
- **Threading:** one worker thread per SSH session owns all libssh2 calls;
  the runtime main thread never blocks on the network (spec 02, §6).
