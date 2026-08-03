# Spec 08 — SSH Management (per-server)

**Status:** 📋 · **Depends on:** 02 (exec/SFTP), 01 · **Spec owner:** core

## 1. Overview

The key registry for a single box: every key in that server's
`authorized_keys`, readable at a glance; add, revoke, and rotate keys;
create read-write and read-only access roles without adding sudo grants;
generate keys and GitHub deploy keys. The fleet-wide view is spec 09.

## 2. Goals / non-goals

**Goals**
- List + parse `~/.ssh/authorized_keys` (options, type, base64, comment).
- Add a key (paste or generate), revoke one, rotate (replace) one.
- Roles: **read-write** standard users and **read-only** forced-command SFTP
  users. Do not use `rbash` as the read-only security boundary.
- Generate ed25519 keypairs in-app (local + server-side for deploy keys).
- Show per-key metadata: type, bits, comment, fingerprint (sha256).

**Non-goals**
- No central SSO/LDAP integration, no per-key expiry enforcement (v1), no audit of *logins* (v1 — see history spec for command audit).

## 3. User stories

- I open a server's SSH tab and see "3 keys: you, contractor, ci-bot" with fingerprints.
- A contractor leaves → I revoke their key on this one server in one click.
- I need a new hire to inspect server files without changing them → I create a
  read-only role backed by OpenSSH's read-only SFTP mode.
- I want a GitHub deploy key → generated here, public half copied.

## 4. UI/UX

### 4.1 SSH tab (per server)
- **Authorized Keys** table: comment (display label, not identity) · type/bits
  · fingerprint (SHA256:…) · options · actions (Revoke, Rotate). OpenSSH does
  not store an added timestamp in this file.
- **Add Key**: paste public key textarea (validated) or "Generate new key"
  (Ed25519 on the local machine). The user chooses the destination and whether
  Oars remembers the passphrase in Keychain.
- **Roles** section: list role users (name, read-only/read-write, policy, access
  scope); create either role; role users get per-user `authorized_keys` files.
- **Deploy keys**: generated ed25519, public half copy button, "how to add to GitHub" hint.
- All mutations require confirmation. Revoke uses the stable fingerprint in
  its confirmation; a duplicate or empty comment cannot weaken the guard.

### 4.2 Role implementation
- Read-write role: `useradd -m -s /bin/bash <name>` plus a per-user
  `authorized_keys` file. It is a standard account and gets no sudo grant.
- Read-only role: each authorized key uses a forced
  `command="internal-sftp -R"` plus `restrict`. It provides SFTP file
  inspection, denies filesystem-changing SFTP requests, and provides no PTY,
  arbitrary command, or forwarding channel. Capability-detect `internal-sftp`
  and read-only mode before offering the role.
- A read-only interactive shell is not part of this v1 role. If Oars later
  offers read-only command execution, it needs a separate sandbox/helper
  contract and adversarial tests; `rbash` and a short PATH are insufficient.
- User creation requires root or allowed non-interactive sudo. The UI shows the
  exact privileged commands and stops when that authority is not available.

## 5. Bridge API

### `oars.sshkeys.list` `{server_id}` → `{ok, keys}`
```json
[{"line_index":2,"options":"no-port-forwarding","type":"ssh-ed25519",
  "key":"AAAAC3Nza…","comment":"hiren@macmini",
  "fingerprint_sha256":"SHA256:abc…","bits":256}]
```
- Parse the OpenSSH grammar, not whitespace alone: scan quoted and escaped
  authorized-key options until the first supported key-type token, then read
  one base64 key blob and preserve the rest of the line as its comment. Decode
  the SSH wire-format blob to verify that its embedded type matches the text
  type, compute the fingerprint over the full decoded blob, and derive key size
  only for formats whose structure is understood. Unknown valid key types are
  preserved and shown without an invented bit count. No shell is needed.
### `oars.sshkeys.add` `{server_id, public_key, comment?}` → `{ok, line_index}` (SFTP append with newline guard)
### `oars.sshkeys.revoke` `{server_id, fingerprint, expected_line_hash}` → `{ok}`
### `oars.sshkeys.rotate` `{server_id, fingerprint, expected_line_hash, new_public_key}` → `{ok}`
- A line index is not stable after an external edit. The writer compares the
  expected file metadata and line hash before replacement. A mismatch returns
  a conflict and asks the user to refresh.
### `oars.sshkeys.generate` `{destination, comment?, passphrase?, remember_passphrase}` → `{ok, public_key, private_path}`
- Generate Ed25519 with the installed OpenSSH `ssh-keygen`. Create the key in
  an owner-only temporary location on the destination filesystem. Install each
  output with a no-clobber filesystem operation, roll back a partial pair, and
  refuse an existing destination. Do not claim that two files can move as one
  atomic operation.
- A non-empty passphrase goes only through a private pseudo-terminal connected
  to the documented `ssh-keygen` prompt. It never appears in process arguments,
  environment variables, logs, history, or audit text. Set `LC_ALL=C`, validate
  the expected prompts, and abort on any unexpected prompt or output.
- Store the passphrase in Keychain under `localkey:<fingerprint>` only when
  `remember_passphrase` is true. If `ssh-keygen` is unavailable, return a clear
  dependency error; do not fall back to a hand-written private-key encoder.
### `oars.sshkeys.roles.list` `{server_id}` → `{ok, roles:[{name, shell, read_only, users:[…]}]}`
### `oars.sshkeys.roles.create` `{server_id, name, read_only}` → `{ok}` (exec useradd; idempotent)
### `oars.sshkeys.roles.delete` `{server_id, name}` → `{ok}` (approval; leaves home dir)
### `oars.sshkeys.deployKey.generate` `{server_id}` → `{ok, public_key}` (server-side ed25519 in `~/.ssh/<app>_deploy` + authorized_keys NOT touched; pubkey returned for GitHub)

## 6. Zig core design

- `src/sshkeys.zig` — `AuthorizedKeys` parser (pure, unit-tested: options, quoted comments, trailing whitespace, empty lines, `from=` restrictions), writer (line-preserving except target), fingerprint computation (SHA-256 of base64-decoded key via std crypto).
- Operations are SFTP read/modify/write with a temp file in the same directory,
  preserved owner and mode, and the server's atomic-rename extension. If the
  extension is unavailable, fail safely instead of making a non-atomic
  replacement that can lock out the user.
- `src/keygen.zig` launches the detected OpenSSH `ssh-keygen` through a private
  pseudo-terminal. Oars supplies `-q -t ed25519 -f <temporary-path>` and an
  optional comment, validates the prompt sequence, and sends the passphrase to
  the terminal only. It verifies the generated public key and private-file mode
  before no-clobber installation at the approved destination.

## 7. Data model

- Nothing new persisted (server config only). Role definitions live on the server (system users) — no local mirror needed; `roles.list` reads live state.

## 8. Security

- All mutations approval-gated; revoke/rotate are atomic (no mid-write lockouts).
- Never `chmod 666`; enforce 600/700 on `.ssh` dir (`chmod 700 ~/.ssh` as part of role setup).
- Editing the connected account's keys needs no escalation. Creating users or
  editing another account needs root or explicit non-interactive sudo.
- Treat key-generation passphrases as secrets. They cannot enter argv,
  environment variables, telemetry, history, or audit records, and Oars clears
  its temporary input buffer after the child process exits.

## 9. Performance

- Listing ≤ 1 s (single SFTP read of a small file).
- Parser handles 10k-line files without issue (line-by-line scan).

## 10. Edge cases

- `authorized_keys` missing → create with 600; empty → empty list state.
- Malformed line (bad base64) → surfaced as `{"parsed":false,"raw":"…"}` row, never crashes the list.
- Comment quoting with spaces → preserved exactly (parse: options are before type; comment is everything after the key base64).
- Concurrent external edit → compare metadata and expected line hash, then
  return a conflict. Never overwrite the other edit silently.

## 11. Testing

- Unit: parser fixtures (options, quotes, CRLF, trailing spaces, invalid),
  fingerprint vector (known key → known SHA256), atomic-write temp naming, and
  key-generation prompt state-machine fixtures.
- Integration: add key → connect with it → revoke → connection fails; create a
  read-only role → verify SFTP reads and reject shell, forwarding, and all
  filesystem mutations; generate local keys with empty and non-empty
  passphrases → verify OpenSSH can read them, the private mode is 0600, an
  existing destination is not overwritten, and the passphrase is absent from
  process listings and captured logs; generate a deploy key → verify
  private-file mode and public-key format.
- Manual: generate local key → add to server → connect with it.

## 12. Acceptance criteria

- [ ] List/add/revoke/rotate work and are atomic.
- [ ] Read-only role permits SFTP reads and rejects an interactive shell,
      forwarding, file creation, write, rename, remove, and permission changes
      in integration tests.
- [ ] Fingerprints match `ssh-keygen -lf` output.
- [ ] Generated keys are readable by OpenSSH, never overwrite an existing path,
      and never expose a passphrase through argv, environment, logs, history,
      audit, or telemetry.
- [ ] All mutations audited.

## 13. Research & References

- **authorized_keys format** — verified against the authoritative
  OpenSSH `sshd(8)` man page (`https://man.openbsd.org/sshd.8`, section
  AUTHORIZED_KEYS FILE FORMAT): "Each line of the file contains one key
  (empty lines and lines starting with a '#' are ignored as comments).
  Public keys consist of the following space-separated fields: options,
  keytype, base64-encoded key, comment. The options field is optional."
  Supported key types include `ssh-ed25519`, `ssh-rsa`,
  `ecdsa-sha2-nistp256/384/521` (and FIDO `sk-*` variants). Options are
  comma-separated with **no spaces except within double quotes**
  (matching our parser's split rule); documented options include
  `no-port-forwarding`, `from="pattern-list"`, `command="…"`,
  `restrict`, `permitopen`, `expiry-time`. Lines can be several hundred
  bytes long; sshd enforces a minimum RSA modulus of 1024 bits.
- **File permissions** — `~/.ssh/authorized_keys` recommended
  permissions are read/write for the user and not accessible by others
  (i.e. 0600); under `StrictModes`, sshd refuses the file if the file,
  `~/.ssh`, or the home directory are group/world-writable (sshd(8)
  FILES section). This validates the spec's `chmod 600/700` discipline
  while avoiding a false claim about every other mode.
  A group/world-writable file can be rejected under `StrictModes`. A 0644 file
  is not group/world-writable and does not automatically stop working, so the
  previous statement to that effect was removed. Oars still creates 0600 files
  to reduce disclosure.
- **Fingerprints** — `ssh-keygen -l -f <keyfile>` prints the SHA-256
  fingerprint by default (ssh(1), VERIFYING HOST KEYS;
  `https://man.openbsd.org/ssh.1`); our SHA-256 fingerprint must match
  that output byte-for-byte for the acceptance criterion.
- **Key generation** — the authoritative OpenSSH `ssh-keygen(1)` manual
  (`https://man.openbsd.org/ssh-keygen.1`) documents Ed25519 generation, the
  output filename, comments, passphrase prompting, and `-N new_passphrase`.
  Oars delegates the OpenSSH private-key format to that tool. It deliberately
  does not put a non-empty secret in `-N`, because command arguments can be
  visible to other local inspection and logging facilities. A private
  pseudo-terminal preserves the normal prompt path without exposing the secret
  in argv or the environment.
- **rbash (restricted shell)** — verified against the GNU Bash manual
  §6.10 The Restricted Shell
  (`https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html`):
  started as `rbash` or with `-r`; restrictions include: `cd` builtin
  disabled; cannot set/unset `SHELL`, `PATH`, `HISTFILE`, `ENV`,
  `BASH_ENV`; command names containing slashes rejected; output
  redirection `>`, `>|`, `<>`, `>&`, `&>`, `>>` disabled; `exec`
  disabled; cannot leave restricted mode (`set +r` / `shopt -u
  restricted_shell`). The manual also states the restricted shell
  "should be accompanied by setting PATH to a value that allows
  execution of only a few verified commands." The manual also calls rbash only
  one component of a restricted environment. **Correction:** rbash is not
  strong enough for a
  product role named read-only. The read-only feature remains in the product,
  but its v1 enforcement contract now uses forced read-only SFTP with
  restrictive authorized-key options.
- **Read-only SFTP** — OpenSSH `sftp-server(8)`
  (`https://man.openbsd.org/sftp-server.8`) documents `-R` as read-only mode:
  opens for writing and other filesystem-changing operations are denied.
  `sshd_config(5)` documents `internal-sftp` as the in-process forced
  command. The `restrict` authorized-key option from `sshd(8)` disables PTY
  allocation and forwarding. Together these define the v1 role precisely;
  they do not claim to provide a read-only interactive shell.
- **Ed25519 parser boundary** — `ssh-ed25519` is a first-class OpenSSH key
  type. The current `src/openssh.zig` reads `openssh-key-v1` private keys for
  authentication, but it has no private-key encoder. That parser is not
  evidence that Oars should write the format itself; v1 generation delegates
  to `ssh-keygen` as specified above.
- **Deploy keys** — GitHub's documented deploy-key model: an SSH key
  pair added to a repo with read/write or read-only access; public half
  pasted at repo Settings → Deploy keys (GitHub docs,
  `https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys`).
  The public key is shown for GitHub. The private key persists on the target
  server with mode 0600 so that future pulls work; it never enters Oars config
  or logs.

Sources: OpenBSD sshd(8), ssh(1), GNU Bash manual §6.10, GitHub deploy
keys docs, `src/openssh.zig`, Zig std crypto.
