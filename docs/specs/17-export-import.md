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
  - **Encryption:** password → PBKDF2-HMAC-SHA256 (mbedTLS, **600,000 iterations — OWASP's current recommendation**, see §13) → AES-256-GCM (mbedTLS), random 12-byte IV per export, file format: magic `OARSVAULT1`, IV, ciphertext, tag (header in plaintext, no metadata inside).
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

## 13. Research & References

- **PBKDF2 iteration count — CORRECTED.** The spec previously said
  "210k iterations — OWASP current". The OWASP Password Storage Cheat
  Sheet (fetched 2026-08-03,
  `https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html`)
  currently recommends **PBKDF2-HMAC-SHA256: 600,000 iterations**
  ("If FIPS-140 compliance is required, use PBKDF2 with a work factor
  of 600,000 or more and set with an internal hash function of
  HMAC-SHA-256"). The cheat sheet also advises a hash should take
  under one second on the target hardware. **Action: use 600,000
  iterations** (with a test-vector fixture at a smaller iteration
  count for speed, plus one full-cost timing test). The KDF itself is
  standardized by RFC 8018 (PKCS #5 v2.1,
  `https://www.rfc-editor.org/rfc/rfc8018`).
- **AES-256-GCM** — authenticated encryption per NIST SP 800-38D
  (`https://csrc.nist.gov/pubs/sp/800/38d/final`); 12-byte IV is the
  recommended default (96-bit, SP 800-38D §8.2). GCM's auth tag is
  what makes "wrong password or corrupt file" a single explicit error
  (decrypt+verify fails atomically — no partial plaintext).
- **mbedTLS APIs** — verified in the vendored headers:
  - `mbedtls_pkcs5_pbkdf2_hmac_ext(md_type, password, plen, salt,
    slen, iteration_count, key_length, output)` —
    `third_party/mbedtls/include/mbedtls/pkcs5.h` L149–153 (the old
    `mbedtls_pkcs5_pbkdf2_hmac` is deprecated, L173–180).
  - GCM: `mbedtls_gcm_setkey(ctx, cipher, key, keybits)` (gcm.h
    L110–113), `mbedtls_gcm_crypt_and_tag(…)` (L166–176, encrypts and
    writes the tag), `mbedtls_gcm_auth_decrypt(…)` (L211–220,
    authenticates then decrypts).
  - mbedTLS is already linked for libssh2 (build.zig
    `buildVendoredLibraries`) — no new dependency.
- **Key-derivation test vectors** — PBKDF2-HMAC-SHA256 vectors from
  RFC 7914 §11 (the scrypt RFC's PBKDF2 appendix) and the NIST CAVP
  suite; AES-GCM vectors from NIST SP 800-38D Appendix B / the
  GCM spec's test cases.
- **File format** — magic+version header (`OARSVAULT1`) in plaintext,
  IV + ciphertext + tag after: the standard envelope pattern; version
  prefix means future formats fail loudly (§8). Secrets are excluded
  by construction (Keychain is per-OS and never exported — the
  Keychain API itself provides no portable export, so placeholders
  are the only honest option).

Sources: OWASP Password Storage Cheat Sheet (2026), RFC 8018, NIST SP
800-38D, RFC 7914 §11, `third_party/mbedtls/include/mbedtls/{pkcs5,gcm}.h`.
