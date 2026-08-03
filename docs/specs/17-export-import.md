# Spec 17 — Export / Import (Vault)

**Status:** 📋 · **Depends on:** 01, 06, 10, 11, 15 · **Spec owner:** core

## 1. Overview

Move your whole Oars world between machines — or back it up — with one
file: servers (minus secrets), scripts, groups, AI provider config (minus
keys), backup jobs (minus bucket keys), and history/audit. Two formats:
**encrypted vault** (password-derived key, AES-256-GCM via the vendored
mbedTLS) and **plain JSON** (no secrets, for sharing/review).

## 2. Goals / non-goals

**Goals**
- Export: encrypted `.oarsvault` (all data) or plain `.json` (secrets stripped, redacted audit).
- Import: validate, merge (by id: existing → update, new → add), report conflicts; never overwrite silently.
- Export the *template*: a vault with zero servers still imports cleanly.

**Non-goals**
- No cloud sync, no auto-backup of the vault, no per-item selective export (v1 exports all-or-scoped-by-section), no key export (SSH private keys stay where they are; paths are exported, files are not).

## 3. User stories

- I get a new laptop: export vault → import → all my servers and scripts are there; I re-enter Keychain-backed secrets on first connect.
- A teammate wants my script library: I export plain JSON (no secrets) and share it.
- I want a monthly backup of my config: vault file on my own disk.

## 4. UI/UX

### 4.1 Settings → Data
- **Export**: format picker (Encrypted vault · Plain JSON) → save dialog → summary (what's inside + counts).
- Vault password: two-field entry with strength hint (min 8 chars; enforced 12).
- **Import**: file picker → password prompt (vault) → preview screen: "4 servers (2 new, 2 updated) · 12 scripts (12 new) · 3 groups" → conflicts listed → Import / Cancel.
- Import result screen with per-section counts + "first connect will ask for secrets".

### 4.2 Secret handling on import
- Imported servers have no passwords — the Keychain is never imported (per-OS). First connect prompts (spec 01 flow). Documented on the preview screen.

## 5. Bridge API

### `oars.vault.export` `{path, password?}` → `{ok, summary}`
- `password` present → encrypted vault; absent → plain JSON. Server-side (Zig) builds the payload from the stores; path from save dialog (frontend picks via `native-sdk.dialog.saveFile`).
### `oars.vault.import` `{path, password?}` → `{ok, preview}` (dry run)
### `oars.vault.importConfirm` `{path, password?, options?}` → `{ok, result}`
- Import happens in two steps so the user sees the preview before any write.

## 6. Zig core design

- `src/vault.zig`:
  - **Payload model:** `{version:1, exported_at, servers[], scripts[], backup_jobs[], ai_provider{}, history[], audit[], groups_derived}` — secrets stripped by construction (Keychain values are never exported; placeholders `{"password":"<keychain>"}` mark what to re-enter).
  - **Encryption:** password → PBKDF2-HMAC-SHA256 (mbedTLS, 210k iterations — OWASP current) → AES-256-GCM (mbedTLS), random 12-byte IV per export, file format: magic `OARSVAULT1`, IV, ciphertext, tag (header in plaintext, no metadata inside).
  - **Import:** parse+decrypt (streaming for large audits), validate against `Payload` schema (strict: unknown fields ignored with a warning list), merge by id with conflict reporting, atomic write-back per store (same temp+rename discipline as spec 08).
- mbedTLS is already linked for libssh2 — `pk_*`/`gcm`/`pbkdf2` APIs available; wrap in `src/crypto.zig` with unit tests against known vectors.

## 7. Data model

- Export sources: `servers.json`, `scripts.json`, `backups.json`, `ai.json`, `history.json`, `audit.json`. Secrets excluded by design.

## 8. Security

- Vault: AES-256-GCM with PBKDF2 (210k) — brute-force cost is the password's; strength hint enforced (min 12).
- Plain export never contains secrets (redaction re-applied on history/audit).
- Import never touches the Keychain; no secret material is read, only placeholders.
- Vault file format versioned (`magic + version`) so future formats fail loudly instead of mis-parsing.

## 9. Performance

- Export of 5,000 audit entries + 2,000 history entries: JSON build + AES ≈ < 1 s. Import same order. Streaming for files > 50 MB (unlikely; cap audit export at 50 MB with warning).

## 10. Edge cases

- Wrong password → decrypt fails with clear "wrong password or corrupt file" (GCM auth tag catches both).
- Vault from a newer version → "file version 2 not supported by this build".
- Duplicate ids across sources (server appears twice) → dedupe by id, keep latest.
- Import into a non-empty app → merge preview shows all collisions; user can't be surprised.
- Path contains non-UTF8 → vault stores bytes as base64 where needed (paths, script bodies) — v1 keeps everything UTF-8-validated with clear errors otherwise.

## 11. Testing

- Unit: PBKDF2/AES-GCM against RFC/NIST vectors, file format round-trip, merge/conflict logic, redaction re-check on export output (assert no secret values present).
- Integration: export vault → wipe data dir → import → servers/scripts present; wrong password rejected; plain export contains no secrets (grep fixtures).

## 12. Acceptance criteria

- [ ] Encrypted vault round-trips all sections; plain export contains zero secrets (tested).
- [ ] Import previews conflicts and never overwrites silently.
- [ ] Wrong password / tampered file → explicit error, no partial writes.
- [ ] Crypto unit tests green against known vectors.
