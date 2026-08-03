# Spec 17 — Export / Import (Vault)

**Status:** 📋 · **Depends on:** 01, 04, 06, 07, 09, 10, 11, 15 · **Spec owner:** core

## 1. Overview

Move Oars operational configuration between machines — or back it up — with
one file: servers, scripts, groups/tags, custom log sources, deployment apps,
access identities, AI provider config, and backup jobs, with portable secrets
removed. An encrypted vault can also include run history and audit data. Two
formats:
**encrypted vault** (password-derived key, AES-256-GCM via the vendored
mbedTLS) and **plain JSON** (no secrets, for sharing/review).

## 2. Goals / non-goals

**Goals**
- Export: encrypted `.oarsvault` (operational configuration plus selected
  histories) or plain `.json` (portable configuration only by default).
- Import: validate, merge (by id: existing → update, new → add), report conflicts; never overwrite silently.
- Export the *template*: a vault with zero servers still imports cleanly.

**Non-goals**
- No cloud sync, no auto-backup of the vault, and no SSH private-key export.
  Key paths can be exported but are marked machine-specific on import.

## 3. User stories

- I get a new laptop: export vault → import → all my servers and scripts are there; I re-enter Keychain-backed secrets on first connect.
- A teammate wants my script library: I export a plain JSON configuration with
  the Scripts section selected and no histories or captured output.
- I want a monthly backup of my config: vault file on my own disk.

## 4. UI/UX

### 4.1 Settings → Data
- **Export**: format picker (Encrypted vault · Plain JSON) → section picker →
  save dialog → summary of included records and excluded secret-bearing fields.
  Plain JSON leaves history, audit details, deploy output, and backup logs off by
  default because best-effort redaction cannot prove arbitrary text is clean.
- Vault password: two-field entry with strength hint (min 8 chars; enforced 12).
- **Import**: file picker → password prompt (vault) → preview screen: "4 servers (2 new, 2 updated) · 12 scripts (12 new) · 3 groups" → conflicts listed → Import / Cancel.
- Import result screen with per-section counts + "first connect will ask for secrets".

### 4.2 Secret handling on import
- Imported servers have no passwords — the Keychain is never imported (per-OS). First connect prompts (spec 01 flow). Documented on the preview screen.

## 5. Bridge API

### `oars.vault.export` `{path, password?, sections[]}` → `{ok, summary}`
- `password` present → encrypted vault; absent → plain JSON. Server-side (Zig) builds the payload from the stores; path from save dialog (frontend picks via `native-sdk.dialog.saveFile`).
### `oars.vault.import` `{path, password?}` → `{ok, preview}` (dry run)
### `oars.vault.importConfirm` `{path, password?, options?}` → `{ok, result}`
- Import happens in two steps so the user sees the preview before any write.

## 6. Zig core design

- `src/vault.zig`:
  - **Payload model:** `{version:1, exported_at, servers[], scripts[], log_sources[], apps[], deploy_runs[], access_identities[], backup_jobs[], backup_runs[], ai_provider{}, history[], audit[]}`. Groups and tags travel in each server record. Optional sections are named in the authenticated manifest.
  - **Secret boundary:** Keychain values, SSH private-key files, deployment
    secret values, backup credentials, AI keys, and VNC passwords are never
    read into the exporter. Records carry typed `needs_secret` metadata rather
    than fake password values.
  - **Encryption:** password → PBKDF2-HMAC-SHA256 with a random 16-byte salt
    and 600,000 iterations → AES-256-GCM with a random 12-byte nonce. Store the
    KDF id, iteration count, salt, nonce, and payload length in the versioned
    header. Authenticate the full header as GCM additional authenticated data.
    File order: magic/version, parameters, ciphertext, 16-byte tag.
  - **Import:** cap the file at 50 MB, authenticate and decrypt the whole
    ciphertext before parsing or writing any store, validate referential
    integrity, then merge by id with conflict reporting and atomic write-back.
    Never stream unauthenticated plaintext into a parser or destination store.
  - **Credential-binding conflicts:** an imported server id with a different
    host, port, user, or auth method cannot update in place and inherit the
    destination machine's existing Keychain entry. The preview offers Keep
    local or Import as new id. Apply the same rule to app and backup-job ids
    when their server or destination identity changes.
- mbedTLS is already linked for libssh2 — `pk_*`/`gcm`/`pbkdf2` APIs available; wrap in `src/crypto.zig` with unit tests against known vectors.

## 7. Data model

- Export sources: `servers.json`, `logs.json`, `scripts.json`, `apps.json`,
  `deploy_runs.json`, `access_identities.json`, `backups.json`,
  `backup_runs.json`, `ai.json`, `history.jsonl`, and `audit.jsonl`.
  Histories and run logs are encrypted-vault sections only in v1.

## 8. Security

- Vault: AES-256-GCM with PBKDF2-HMAC-SHA256, random per-file salt, 600,000
  iterations, and minimum 12-character password. The header is authenticated.
- Plain export contains only structured configuration fields from an explicit
  allowlist. It excludes history, audit details, output snippets, and run logs
  in v1; redaction is not used as proof that arbitrary text is secret-free.
- Import never touches the Keychain; no secret material is read, only placeholders.
- Vault file format versioned (`magic + version`) so future formats fail loudly instead of mis-parsing.

## 9. Performance

- Target under one second for the KDF plus encryption on supported hardware,
  but benchmark it. Files larger than 50 MB are rejected in v1 so import can
  authenticate before parsing without unbounded memory use.

## 10. Edge cases

- Wrong password → decrypt fails with clear "wrong password or corrupt file" (GCM auth tag catches both).
- Vault from a newer version → "file version 2 not supported by this build".
- Duplicate ids inside one imported section are a validation error. Oars does
  not guess which duplicate is newer.
- Import into a non-empty app → merge preview shows all collisions; user can't be surprised.
- Path contains non-UTF8 → vault stores bytes as base64 where needed (paths, script bodies) — v1 keeps everything UTF-8-validated with clear errors otherwise.

## 11. Testing

- Unit: PBKDF2/AES-GCM against RFC/NIST vectors, file format round-trip,
  duplicate-id rejection, endpoint/credential-binding conflicts, and a plain-
  export schema test that rejects history, output, log, and secret fields.
- Integration: export vault → wipe data dir → import → servers/scripts present; wrong password rejected; plain export contains no secrets (grep fixtures).

## 12. Acceptance criteria

- [ ] Encrypted vault round-trips every selected section. Plain export uses a
      configuration-only allowlist and contains no history or captured output.
- [ ] Group paths, tags, and explicit person-to-fingerprint mappings survive a
      vault round trip.
- [ ] Saved applications, custom log sources, and backup jobs survive a vault
      round trip without their Keychain-backed values.
- [ ] Import previews conflicts and never overwrites silently.
- [ ] A colliding imported id cannot attach an existing local credential to a
      changed server, app target, or backup destination.
- [ ] Wrong password / tampered file → explicit error, no partial writes.
- [ ] Crypto unit tests green against known vectors.
- [ ] Two exports with the same password have different salts and nonces; a
      changed header, ciphertext, or tag is rejected before any store write.

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
  OWASP also requires a unique salt. The previous body omitted salt from the
  file format; this review added a random 16-byte salt and stored KDF
  parameters in the authenticated header.
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
- **Export confidentiality boundary** — redaction can remove known secrets but
  cannot prove that arbitrary command text and output contain none. The plain
  format therefore uses a structured configuration allowlist and excludes
  histories and run output. This is an Oars security decision, not an external
  standard claim.
- **File format** — the plaintext header carries only version and cryptographic
  parameters and is authenticated as GCM AAD. Salt and nonce are distinct
  random values. Secrets are excluded by construction because Keychain has no
  portable export path in this design.

Sources: OWASP Password Storage Cheat Sheet (2026), RFC 8018, NIST SP
800-38D, RFC 7914 §11, `third_party/mbedtls/include/mbedtls/{pkcs5,gcm}.h`.
