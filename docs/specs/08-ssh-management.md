# Spec 08 — SSH Management (per-server)

**Status:** 📋 · **Depends on:** 02 (exec/SFTP), 01 · **Spec owner:** core

## 1. Overview

The key registry for a single box: every key in that server's
`authorized_keys`, readable at a glance; add, revoke, and rotate keys;
create read-only and read-write access roles without touching visudo;
generate keys and GitHub deploy keys. The fleet-wide view is spec 09.

## 2. Goals / non-goals

**Goals**
- List + parse `~/.ssh/authorized_keys` (options, type, base64, comment).
- Add a key (paste or generate), revoke one, rotate (replace) one.
- Roles: **read-only** and **read-write** system users, created without visudo.
- Generate ed25519 keypairs in-app (local + server-side for deploy keys).
- Show per-key metadata: type, bits, comment, fingerprint (sha256).

**Non-goals**
- No central SSO/LDAP integration, no per-key expiry enforcement (v1), no audit of *logins* (v1 — see history spec for command audit).

## 3. User stories

- I open a server's SSH tab and see "3 keys: you, contractor, ci-bot" with fingerprints.
- A contractor leaves → I revoke their key on this one server in one click.
- I need a read-only user for a new hire → I pick "read-only role" and the user is created with a restricted shell.
- I want a GitHub deploy key → generated here, public half copied.

## 4. UI/UX

### 4.1 SSH tab (per server)
- **Authorized Keys** table: comment (identity) · type/bits (SSH-ED25519 256) · fingerprint (SHA256:…) · added (from options or first-seen) · actions (Revoke, Rotate).
- **Add Key**: paste public key textarea (validated) or "Generate new key" (ed25519, local machine — saves to ~/.ssh with passphrase prompt stored in Keychain).
- **Roles** section: list of role users (name, shell, access scope); create role (name + read-only/read-write); role users get `authorized_keys` per-user files.
- **Deploy keys**: generated ed25519, public half copy button, "how to add to GitHub" hint.
- All mutations → confirm; revoke → type key comment to confirm.

### 4.2 Role implementation (read-only)
- Read-only user: `useradd -m -s /usr/bin/rbash <name>` + `authorized_keys` for that user + restricted PATH via `.bash_profile` (`export PATH=$HOME/bin`), rbash blocks `cd`/redirects.
- Read-write user: `useradd -m -s /bin/bash <name>` + key installed.
- "Without touching visudo" = we never grant sudo for read-only; read-write = plain user (sudo remains separate, shown in access map spec 09).
- Implementation via exec (argv-safe) + SFTP writes; every action approval-gated + audited.

## 5. Bridge API

### `oars.sshkeys.list` `{server_id}` → `{ok, keys}`
```json
[{"line_index":2,"options":"no-port-forwarding","type":"ssh-ed25519",
  "key":"AAAAC3Nza…","comment":"hiren@macmini",
  "fingerprint_sha256":"SHA256:abc…","bits":256}]
```
- Parse: split options before type (commas), base64 decode to count bits, comment = trailing field. No shell needed (read file via SFTP).
### `oars.sshkeys.add` `{server_id, public_key, comment?}` → `{ok, line_index}` (SFTP append with newline guard)
### `oars.sshkeys.revoke` `{server_id, line_index}` → `{ok}` (SFTP rewrite, atomic temp+rename)
### `oars.sshkeys.rotate` `{server_id, line_index, new_public_key}` → `{ok}` (replace line, atomic)
### `oars.sshkeys.generate` `{type?, passphrase?}` → `{ok, public_key, private_path}` (local; ed25519; passphrase stored in Keychain under `localkey:<fingerprint>`)
### `oars.sshkeys.roles.list` `{server_id}` → `{ok, roles:[{name, shell, read_only, users:[…]}]}`
### `oars.sshkeys.roles.create` `{server_id, name, read_only}` → `{ok}` (exec useradd; idempotent)
### `oars.sshkeys.roles.delete` `{server_id, name}` → `{ok}` (approval; leaves home dir)
### `oars.sshkeys.deployKey.generate` `{server_id}` → `{ok, public_key}` (server-side ed25519 in `~/.ssh/<app>_deploy` + authorized_keys NOT touched; pubkey returned for GitHub)

## 6. Zig core design

- `src/sshkeys.zig` — `AuthorizedKeys` parser (pure, unit-tested: options, quoted comments, trailing whitespace, empty lines, `from=` restrictions), writer (line-preserving except target), fingerprint computation (SHA-256 of base64-decoded key via std crypto).
- Operations are SFTP read/modify/write with **atomic temp+rename** (write `authorized_keys.tmp.<pid>`, chmod 600, rename over).
- Key generation: local via `ssh-keygen` subprocess? No — use Zig std crypto: ed25519 keygen is available in std (`std.crypto.sign.Ed25519`); write OpenSSH format manually (PEM/openssh-key-v1) — **pending decision:** v1 shells out to `ssh-keygen` (present on macOS/Linux) for format correctness; note migration path.

## 7. Data model

- Nothing new persisted (server config only). Role definitions live on the server (system users) — no local mirror needed; `roles.list` reads live state.

## 8. Security

- All mutations approval-gated; revoke/rotate are atomic (no mid-write lockouts).
- Never `chmod 666`; enforce 600/700 on `.ssh` dir (`chmod 700 ~/.ssh` as part of role setup).
- Keys are the session user's — no sudo escalation in v1; sudo visibility is spec 09's job.

## 9. Performance

- Listing ≤ 1 s (single SFTP read of a small file).
- Parser handles 10k-line files without issue (line-by-line scan).

## 10. Edge cases

- `authorized_keys` missing → create with 600; empty → empty list state.
- Malformed line (bad base64) → surfaced as `{"parsed":false,"raw":"…"}` row, never crashes the list.
- Comment quoting with spaces → preserved exactly (parse: options are before type; comment is everything after the key base64).
- Concurrent external edit → our atomic rename wins; re-list to reconcile (snapshot semantics, same as spec 09).

## 11. Testing

- Unit: parser fixtures (options, quotes, CRLF, trailing spaces, invalid), fingerprint vector (known key → known SHA256), atomic-write temp naming.
- Integration (container): add key → ssh in with it → revoke → ssh fails; role create read-only → verify rbash + PATH restriction; deploy-key generate → verify file + format.
- Manual: generate local key → add to server → connect with it.

## 12. Acceptance criteria

- [ ] List/add/revoke/rotate work and are atomic.
- [ ] Read-only role provably restricts shell (tested over SSH).
- [ ] Fingerprints match `ssh-keygen -lf` output.
- [ ] All mutations audited.
