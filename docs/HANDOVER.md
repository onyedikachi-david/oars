# Oars — Agent Handover & Implementation Charter

This file is the standing brief for any agent implementing Oars features.
Read it fully before touching code. It encodes the project's standards, the
verified technical constraints, and the hard-won pitfalls of this codebase.
Where this file and a spec disagree, the **spec is the contract** — but fix
the spec (and note the correction in its §13) rather than silently diverging.

---

## 1. Mission and the standard

Oars is an **open-source, local-first Linux server management desktop app** —
a CtrlOps-class product (more features, better UI/UX, fully open source):
SSH terminals, monitoring, logs, SFTP file manager, scripts, one-click
deploy, access management, backups, AI terminal, VNC. Keys and credentials
never leave the user's machine.

**We write production-ready code, judged as strictly and thoroughly as
Linus Torvalds would judge a kernel patch.** Concretely:

1. **Code is judged by its worst line.** One sloppy line in a diff makes the
   whole change unacceptable. No TODOs left behind, no dead code, no
   commented-out blocks, no debug prints shipped.
2. **No lies in code.** Never swallow an error to make a path "work". Every
   failure is handled, surfaced to the user honestly, or deliberately
   degraded *and marked as such* (e.g. the monitor's `probe_error` field).
   Never report success that wasn't achieved — this is why specs 03/04/10
   have explicit "honest failure" and "zero files ≠ success" requirements.
3. **Review your own diff like a hostile stranger.** Read it back before
   finishing. If you would object to a line, fix it before anyone else sees
   it. Ask "what breaks if this input is hostile?" for every input.
4. **Tests must prove.** A test that passes when the code is wrong is worse
   than no test. Write the assertion that fails against the bug you're
   fixing. Run the full validation suite after *every* change (see §8) —
   Zig's lazy analysis means code you didn't touch can silently break.
5. **Minimal, focused diffs.** Change only what the task requires. If you
   spot an unrelated bug, note it in your summary — do not fix it silently
   in the same diff.
6. **No speculative complexity, no broken shortcuts.** Match the existing
   patterns of the codebase. Prefer the boring, correct solution that
   reuses what exists (streams, approval cards, exec path) over novel
   machinery. But never take a shortcut that trades away correctness,
   atomicity, or error visibility.
7. **Security posture is default-paranoid.** Never trust bridge payloads,
   never interpolate user strings into shell commands (argv or quoting
   discipline), keep secrets in the Keychain, audit every mutation,
   origin-gate everything.
8. **Comments explain *why*.** Never restate what the code does.

## 2. State of the world (verified 2026-08-03)

- **Stage 1 (Foundation) is implemented and green:** Zig core (`ssh`,
  `sessions`, `servers`, `bridge`, `main`, `runner`), React/xterm.js
  terminal UI, host-key trust flow, config store, tests pass.
- **All 18 feature specs exist** in `docs/specs/` (`01`–`18`), each with
  acceptance criteria (§12) and a **Research & References section (§13)**
  citing primary sources with URLs and line refs. Claims were verified
  against live sources (RFC 6455, GNU/OpenBSD man pages, official docs,
  vendored libssh2/mbedTLS headers, noVNC source, the installed Native
  SDK). **Do not re-verify §13 claims from memory — trust them, but if a
  claim looks wrong, re-check the cited source and correct the spec.**
- **Pending before Stage 2:** Stage 1 end-to-end verification against a
  dockerized sshd (key auth, password auth, trust flow, exec) — the
  `scripts/dev-sshd.sh` helper from spec 02 §11 does not exist yet; build
  it. ~~Repo hygiene~~ **Done 2026-08-03:** git repo initialized and
  `.gitignore` written (with user approval). Key auth, trust flow and the
  interactive shell were verified live against a real server on the same
  date (§11); password auth and exec still need their container pass.
- **Stage 1 truth gaps — landed 2026-08-03 (session 2):** real PTY resize
  (verified with `stty size` in the container), per-tab poll cursors
  (non-destructive stream reads), `SHA256:` base64 fingerprints with hex
  migration, idempotent connect, cancelable DNS + stop-aware loops,
  owner-only store permissions, corrupt-file quarantine, save semantics,
  tags/via validation. The dockerized sshd container pass is green
  (`scripts/dev-sshd.sh` + `scripts/integration-test.sh`). The one
  documented limit: the std Io has no non-blocking TCP connect, so a
  dead-IP connect is kernel-bounded (~75 s on macOS).
- **Implementation order (ROADMAP §4):** Stage 2 (specs 03 + 04) →
  Stage 3 (spec 12) → Stage 4 (spec 05) → Stage 5 (specs 06 + 07) →
  Stage 6 (specs 09 + 08 + 10) → Stage 7 (spec 11) → Stage 8 (specs 13,
  14, 16, 15, 17 — palette/groups/themes/history/vault, plus packaging
  and CI). Specs 13–18 are marked Oars+ in the README table; still
  implement them in order after the core stages.

## 3. Stack and layout

- **Core:** Zig 0.16 (native, hermetic build — no Homebrew/system deps),
  shelled by the **Native SDK** WebView (`native dev`/`native build`
  workflows, `build.zig`).
- **Vendored C:** `third_party/libssh2` (1.11.1, BSD-3) +
  `third_party/mbedtls` (3.6.2, Apache-2.0), compiled via `zig cc`
  (`buildVendoredLibraries` + `linkSshStack` in `build.zig`).
- **Frontend:** React + TypeScript + Vite (rolldown), xterm.js 5.3.0
  (package name is `xterm`, CSS at `xterm/css/xterm.css`), noVNC 1.7.0
  (`@novnc/novnc`) already installed for spec 12.
- Key files: `src/{main,runner,bridge,sessions,servers,ssh,openssh}.zig`,
  `frontend/src/{App,TerminalTab,ServerModal}.tsx`, `frontend/src/{bridge,types}.ts`,
  `frontend/src/index.css`, `app.zon`, `build.zig`.

## 4. Non-negotiable Zig 0.16 idioms

Old 0.15 code will not compile. These are verified against the installed
toolchain:

- `main(init: std.process.Init)`; allocators from `init.gpa` /
  `init.arena.allocator()`.
- File IO is on `std.Io.Dir`, **not** `std.fs`: `cwd()`,
  `readFileAlloc(io, path, allocator, .limited(n))`, `createDirPath`
  (mkdir -p), `writeFile`.
- `std.ArrayList(T)` is **unmanaged**: `.empty` and pass the allocator to
  every call.
- `std.json`: `parseFromSlice` is zero-copy/alloc-if-needed — **keep the
  input buffer alive** (see `servers.zig` `Loaded`); stringify via
  `std.json.Stringify.value(v, .{}, &writer)` + `json.fmt` (0.16 has **no**
  `stringifyAlloc`).
- Timers/sockets/sleep take `std.Io`; threaded IO via
  `std.Io.Threaded.init(allocator, .{})` and `.io()`.
- `std.atomic.Mutex` is a spinlock (`.unlocked`), **only `tryLock()`** —
  no blocking `.lock()`. Use the existing `lockSpin` helper pattern.
- `error` is a reserved word: enum member must be `@"error"`.
- The SDK root does **not** re-export `json` — `bridge.zig` has its own
  `writeJsonString`.
- `std.posix.getpid` / `std.posix.close` do not exist as expected — use
  `std.Io.Timestamp.now` for unique test dirs and
  `io.vtable.netClose(io.userdata, &.{fd})` to close sockets.

## 5. Native SDK contract (the installed SDK is the docs)

SDK (global npm install):
`/Users/onyedikachi/.nvm/versions/node/v24.18.0/lib/node_modules/@native-sdk/cli`
Key references: `src/bridge/root.zig` (protocol — `dispatch` at L142,
raw-result wrapping at L163/L223), `src/runtime/flow.zig` (dispatch),
`examples/webview` (runWithOptions + bridge policy), `examples/capabilities`
(permissions).

- Bridge is **invoke/response only; no native→JS push** → the frontend
  polls (80 ms, cursor-delta streams, 4 MB cap). New streaming features
  reuse the poll pattern — do not invent push.
- Handlers return **raw result JSON**; `dispatch` wraps it. Double-wrapping
  causes an `@memcpy` alias panic (see §7).
- User-facing failures = `{"ok":false,"error":"human message"}` envelope;
  framework rejects on transport errors (`payload_too_large`,
  `permission_denied`, `unknown_command`, `handler_failed`).
- `native-sdk.credentials.*` and `native-sdk.dialog.*` builtins require
  explicit permission + policy entries in **both** `src/main.zig`
  (`builtin_policies`) **and** `app.zon` (permissions/capabilities).
  Missing one side = silent permission denial.

## 6. Cross-cutting conventions (all specs)

- **Secrets:** SSH passwords, key passphrases, VNC passwords
  (`vnc:<server_id>`), AI keys (`ai:<base_url>`), backup keys, deploy env
  secrets → Keychain via `native-sdk.credentials.*`. **Never** in config
  JSON. Config files never contain secrets.
- **Approval + audit:** every mutating server action is approval-gated;
  destructive operations add type-to-confirm or an explicit warning. Every
  executed command lands in history/audit (spec 15 machinery).
- **Streams:** cursor-delta protocol from `oars.ssh.poll` (per-channel
  buffer, absolute cursor, `dropped` counter, `rewind`). Reuse it for
  logs, deploy output, broadcast, backups.
- **Threading:** one worker thread per SSH session owns *all* libssh2
  calls (libssh2 is not thread-safe); the main thread never blocks on the
  network; bridge handlers only touch spin-locked buffers.
- **Commands to servers:** build argv arrays or quote properly; never
  shell-interpolate user strings. Single-quote escaping for `{{vars}}`
  (Bash §3.1.2.2). Fixed-string probe commands (specs 03/04).
- **UI:** dark ops theme, **electric-blue accent — no teal/green in the
  UI palette** (terminal ANSI keeps standard green: it renders remote
  content). Status vocabulary: amber pulse = connecting, blue = ready,
  red = error. Keyboard-first, `⌘K`-reachable.
- **Errors in UI:** never a spinner where state can be shown; unreadable
  files/servers produce explicit reasons (specs 03/04/09 `sync_error`s).

## 7. Hard-won pitfalls (do not repeat)

1. **`std.json.parseFromSlice` strings alias the input buffer.** The
   naive fix caused `0xAA` poisoned-memory bugs in tests. Keep the file
   buffer alive alongside the parsed value (`servers.zig` `Loaded`).
2. **Bridge double-wrap:** handlers return raw JSON; `dispatch` wraps via
   `writeSuccessResponse`. Pre-wrapping aliases the response buffer →
   `@memcpy` alias panic.
3. **`Stream.cursor` is absolute** (`start_abs` + bytes read). A
   `readAvailable` after overflow returns more than the cap — a test
   asserting otherwise is wrong, not the code.
4. **libssh2 via cImport:** header inline helpers (`libssh2_channel_shell`,
   `libssh2_channel_exec`) don't translate (usize→c_uint sizeof casts) —
   call `libssh2_channel_process_startup` directly with `"shell"`/`"exec"`
   and explicit lengths.
5. **`HAVE_CONFIG_H` must be defined** for libssh2 to read our config
   (`src/c/libssh2_config.h`); without it, `struct iovec` errors. Leave
   `explicit_bzero`/`memset_s` undefined on macOS (feature-test-gated;
   libssh2 has fallbacks).
6. **xterm CSS:** `xterm/css/xterm.css` — the installed package layout
   uses `xterm`, not `@xterm/xterm`. Vite/rolldown CSS resolution is
   strict: verify package export maps before importing.
7. **Worker-loop discipline:** run loop is one thread doing non-blocking
   reads/writes with ~10 ms sleep; EAGAIN-tolerant buffered writes; never
   block the loop on a socket.
8. **JSON stringify in 0.16:** no `stringifyAlloc`; use the writer API or
   the bridge's own `writeJsonString`.
9. **Hermetic build:** no system libraries; new deps must be vendored with
   provenance notes in `third_party/`.
10. **`zig build` is lazy:** code only one path touches can silently break.
    Run **both** `zig build` and `zig build test` after every change, plus
    `npm --prefix frontend run build`.

## 8. Validation protocol (every change, in order)

1. `zig build` — must compile clean (no warnings ignored).
2. `zig build test` — full suite green. Tests use `std.testing.allocator`
   to catch leaks/double-frees.
3. `npm --prefix frontend run build` — frontend compiles.
4. Feature-specific: integration against the dockerized sshd container
   (spec 02 §11) once `scripts/dev-sshd.sh` exists; later stages add their
   own containers (MinIO for backups, x11vnc for VNC — see each spec §11).
5. Check `docs/specs/README.md` acceptance: tick nothing unless you
   actually ran it and saw it pass. Update spec status fields when a
   feature lands.

## 9. Per-feature procedure

1. Read the spec's §1–§12 and §13. Understand the bridge payloads exactly —
   they are the API contract between `bridge.ts`/`types.ts` and the Zig
   handlers; they must match byte-for-byte.
2. Check what already exists (streams, exec path, approval card, audit
   hook, stores) and reuse it. New modules follow the existing shape
   (`src/<feature>.zig` with pure functions + fixture tests; store via
   the `servers.zig` `Loaded` pattern; session work via the worker op
   queue).
3. Implement. Production quality: bounded buffers, no unbounded growth,
   atomic writes (temp+rename), argv-safe commands, approval + audit on
   every mutation, honest error surfaces.
4. Unit-test the pure parts with fixtures (parsers, codecs, expansion,
   redaction). Integration-test against the container where the spec
   requires it.
5. Run §8 validation. Then walk the spec's §12 acceptance list; anything
   you cannot verify, say so explicitly in your summary — never claim it.
6. If reality contradicts the spec (API names, command flags, formats):
   fix the spec body, and record the correction in §13 with the source.
   That is the established workflow — the specs are living contracts.

## 10. Definition of done

A feature is done only when:

- [ ] Every §12 acceptance criterion is met (or explicitly marked
      unverifiable with the reason in the summary).
- [ ] `zig build`, `zig build test`, and the frontend build are green.
- [ ] Secrets never touch config JSON (Keychain only).
- [ ] Every mutation is approval-gated and audited; no silent success.
- [ ] Unreadable/unreachable targets surface explicit errors, never hangs
      or fake success.
- [ ] New tests fail against the bug they guard, and pass with the fix.
- [ ] The diff contains no TODOs, dead code, debug prints, or unrelated
      changes.
- [ ] The spec's status line and the README table reflect reality.

---

## 11. Session handover — 2026-08-03: Stage 1 live verification and the auth-stack rebuild

Session goal was "it gets stuck after I connect an account". It became a
full rebuild of the key-auth path plus a frontend lifecycle fix. Verified
end-to-end against a live Contabo VPS (OpenSSH, `ssh-ed25519` passphrase
key): handshake, host-key trust, decrypt, sign, shell — all green.

### 11.1 What was broken (symptom → root cause)

1. **Stuck at "Connecting…" with `[connection closed]` printed** →
   `TerminalTab` never connected on mount; its poll loop saw no session,
   got `status:"closed"`, printed the message and **stopped polling
   permanently**. A later manual Connect updated React state but the dead
   loop never ran again.
2. **Panic (`accessAbsolute` assert) killing the whole app** → key path
   stored as `~/.ssh/...`: (a) `~` was never expanded, (b) the assert
   fired on the SSH worker thread and a Zig panic on *any* thread takes
   down the process.
3. **`cannot read private key file '<path> ro…'`** → the saved key path
   was the entire paste `~/.ssh/beacon_contabo root@169.58.54.48 `. Never
   trust user-entered paths: trim and validate at save time.
4. **`PK - Read/write of file failed` / `AuthFailed (Callback returned
   error)`** → the vendored libssh2 is built on mbedTLS 3.6.2, which
   **cannot parse OpenSSH-format private keys** (`BEGIN OPENSSH PRIVATE
   KEY` — the ssh-keygen default since 7.8), and `libssh2_userauth_
   publickey_fromfile_ex` was also being fed non-null-terminated Zig
   slices for paths/passphrase (libssh2 `strlen`s them).
5. **`Invalid signature for supplied public key`** → the final, subtle
   one: libssh2's mbedTLS backend has **no Ed25519 at all**
   (`third_party/libssh2/src/mbedtls.h`: `LIBSSH2_ED25519 0`), so Ed25519
   auth is implemented natively via `libssh2_userauth_publickey`'s sign
   callback — and the callback's contract is to return **only the raw
   64-byte signature**; userauth.c wraps `string(method)||string(sig)`
   itself (`userauth.c` L1811–L1830). The first implementation returned
   the full 83-byte SSH blob → server-side signature failure.

### 11.2 The fixes (where)

- **`frontend/src/TerminalTab.tsx`** — auto-connect on mount; poll loop
  gated on `sawSession` (only treat `closed` as terminal after a live
  session was seen) and restartable via `connectRef`; disconnect stale
  error/closed sessions before reconnecting (`Manager.connect` returns
  `AlreadyConnected` for anything not `.closed`); `[connection closed]`
  only printed after a real session; explicit errors when the Keychain
  has no password/passphrase stored.
- **`frontend/src/main.tsx`** — StrictMode removed: its double-mount
  caused double connects and double Keychain prompts. This is a desktop
  shell, not a library — do not re-add.
- **`frontend/src/bridge.ts`** — `vault` secrets cached in memory per
  run: on unsigned (debug) builds macOS re-prompts Keychain access on
  *every* read, so read once and cache. `set`/`delete` keep it coherent.
- **`frontend/src/ServerModal.tsx`** — `key_path` trimmed on save.
- **`src/openssh.zig` (new)** — `openssh-key-v1` parser: PEM decode,
  container parse, bcrypt KDF via the vendored `_libssh2_bcrypt_pbkdf`
  extern (already linked into libssh2.a), AES-256-CTR via
  `std.crypto.core.aes` (`AesEncryptCtx.xor` *is* CTR mode), checkint
  comparison → `error.WrongPassphrase`. Unit-tested with a hand-built
  container.
- **`src/ssh.zig`** — `authEd25519`: generic publickey auth with a
  `callconv(.c)` sign callback backed by `std.crypto.sign.Ed25519`
  (`KeyPair.generateDeterministic(seed)`); sig buffer via
  `std.heap.c_allocator` (libssh2 frees with `free`). `authKeyFile`
  deleted (useless on mbedTLS for modern keys). `Session` gained
  `socket_open`/`session_open` flags; `disconnect` is idempotent and
  releases only what `connect` established (previously a handshake
  failure → use-after-free + double-close of the fd). `Channel.read`:
  only `LIBSSH2_ERROR_EAGAIN` → `.again`; other negatives → `.eof` (a
  dead transport used to spin the run loop forever). `authError` maps
  `PUBLICKEY_UNVERIFIED`/`FILE` → `AuthFailed` so users get the real
  libssh2 message.
- **`src/sessions.zig`** — key auth rewritten: expand `~/` against
  `Manager.home` (threaded from `environ_map` `HOME`), read key into
  memory, dispatch by format — Ed25519 → native signer; RSA/ECDSA
  OpenSSH → `authKeyMemory` (libssh2's own OpenSSH parser in `pem.c`
  handles these from memory); classic PEM → `authKeyMemory`. `.pub`
  sidecar read when present. `Manager.trust` no longer holds
  `trust.mutex` while taking the manager mutex — that lock order
  deadlocked against `disconnect`'s join and the worker's trust-wait
  spin.
- **`src/bridge.zig`** — `oars.servers.save` trims `key_path` and
  refuses to persist a key file it cannot read (error names the resolved
  absolute path).
- **`src/servers.zig`** — `expandHome` helper (`~` is a shell
  convention; libssh2 and the filesystem know nothing about it).
- **`src/runner.zig`** — `shouldTrace` drops `platform.event`,
  `runtime.frame`, `bridge.dispatch` under the default `events` level:
  the 80 ms poll loop otherwise logs ~30 lines/sec continuously.
  `-Dtrace=all` restores everything.

### 11.3 Verification (what was actually run)

- `zig build`, `zig build test`, `npm --prefix frontend run build` —
  green after every change (§8).
- Live probes against the real server (throwaway ed25519 key, known
  passphrase): parse + decrypt round-trip; wrong passphrase →
  `WrongPassphrase`; derived public key matches ssh-keygen's `.pub`;
  callback signature verifies against the public key with an independent
  verifier; wire blob shape matches RFC 4253 §6.6.
- Full user path on the shipped app: trust dialog → Keychain →
  authenticated shell on Ubuntu 24.04 (`ssh-ed25519` + passphrase).

### 11.4 New pitfalls (extend §7 — do not repeat)

11. **A passing auth probe can lie about coverage.** An *unauthorized*
    key is rejected at the offer stage ("Username/PublicKey combination
    invalid") and **never exercises the signature path** — the 83-byte
    blob bug shipped behind a green probe. Only an *authorized* key
    reaches signature verification; test sign paths with a key the
    server trusts, or verify the signature locally against the public
    key.
12. **Never pass `slice.ptr` to libssh2 C-string parameters.** Paths,
    passphrases, and `libssh2_userauth_publickey`'s username take no
    length — libssh2 `strlen`s them. `dupeZ` or pass null.
13. **mbedTLS-backend libssh2 ≠ OpenSSL-backend.** No OpenSSH key
    format via fromfile, no Ed25519 anywhere. Check
    `third_party/libssh2/src/mbedtls.h` capability macros
    (`LIBSSH2_ED25519`, `LIBSSH2_ECDSA`) before assuming an algorithm
    works; the from-memory path uses libssh2's *own* OpenSSH parser
    (`pem.c`) for RSA/ECDSA only.
14. **A Zig panic on a worker thread kills the app.** `accessAbsolute`
    asserts on relative input; the SSH worker must never call APIs that
    can assert on user data. `std.Io.Dir.cwd().access` accepts both
    relative and absolute paths — use it.
15. **macOS Keychain prompts are per-binary-signature.** Unsigned dev
    builds re-prompt on every rebuild and every read; React StrictMode
    doubled reads. Cache secrets per run; document "Always Allow"; real
    fix is a stable signing identity at packaging time (Stage 8).
16. **Frontend state machines die silently.** A poll loop that stops on
    a transient "no such session" response can never recover. Gate
    terminal states on evidence (`sawSession`), and make every loop
    restartable from the Connect path.

### 11.5 Still open for Stage 1 sign-off

- ~~Password-auth path untested live~~ **Done 2026-08-03 (session 2):** the
  dockerized sshd pass covers password auth, key auth, trust, shell
  round-trip, exec exit codes, `stty size` resize verification, duplicate
  connect, changed host keys, and prompt disconnect (spec 02 §11).
- Reconnect-after-error now works via frontend disconnect-first; a
  backend-side recycle of errored sessions would be belt-and-braces but
  is not required.
- The remaining documented limit is the kernel-bounded TCP connect
  (std Io TODO); see spec 02 §13.

---

## 12. Session handover — 2026-08-03 (session 2): Stage 1 truth gaps + container pass

### 12.1 What landed (commits `051a917`, and the spec 02 commit)

**Spec 01 backend** (`051a917`): `tags` + `via_server_id` model fields with
save-time chain validation (existing refs, no self-links, depth ≤ 3, no
cycles); save semantics (created_at preserved, fingerprint kept only while
host+port are unchanged, trailing-slash host and port 0 rejected, tags
normalized); 0600 store permissions with permissive-file tightening; corrupt
store quarantine to `servers.json.corrupt-<ts>` with `recovery_error` in
`oars.servers.list`. Fixed two pre-existing leaks (upsert copies,
loadParsed's eager empty parse).

**Spec 02 backend:** per-tab poll cursors (`oars.ssh.poll` takes
`cursors:[{channel,cursor}]`; `Stream.readAt`/`view` are non-destructive);
exec channels survive EOF until drained (bounded to 64 completed); real PTY
resize with failure surfacing; `SHA256:` base64 fingerprints with legacy-hex
compare + migration; idempotent connect returning live status;
`oars.ssh.closeChannel`; libssh2 global init once (thread-safe guard);
cancelable DNS via `Io.concurrent` future + stop-aware deadline loops;
Store gained a mutex (the worker now writes during fingerprint migration).

### 12.2 New pitfalls (extend §7)

17. **`ArenaAllocator.allocator()` captures the arena's address.** Returning a
    struct that embeds an arena (or a pointer into it) by value from an init
    function leaves dangling pointers (poisoned allocator vtable → segfault
    in `rawAlloc`). Init in place: `var app: T = undefined; try app.init();`.
18. **`std.json` static parse of `std.json.ObjectMap` fields is unsupported**
    (its `[*]u8` metadata trips `@compileError`). Use plain structs/arrays
    for payload fields.
19. **`std.once` does not exist in 0.16.** Implement once-guards with an
    atomic + spinlock. `libssh2_init`'s counter is not thread-safe, so a
    once-guard is required before worker threads start.
20. **Discarding an error union needs `catch {}`, not `_ =`** (0.16
    "error union is discarded").
21. **`std.Io.net.IpAddress.resolve` handles only IP literals** — hostnames
    fail with `ParseFailed`. Hostname resolution must go through
    `HostName.lookup` (async, io-thread-backed, cancelable via
    `Io.concurrent` futures). This was a real bug: hostname servers could
    never connect.
22. **There is no non-blocking/timeout TCP connect in std.Io**
    (`netConnectIpPosix` panics on `options.timeout`). Dead-IP connects are
    kernel-bounded; document rather than fight it.
23. **Exec output was lost on EOF:** the old eof branch freed exec streams
    immediately (its comment claimed otherwise), racing the frontend's
    drain. Entries now persist until teardown/eviction.

### 12.3 Next

Spec 03 (Infra Monitoring) backend: `/proc/stat` CPU delta utilization,
probe-on-demand cache, itemized cleanup plans, drop-caches diagnostic,
audit store (`audit.jsonl`, spec 15 shape).

### 12.4 Spec 03 landed (same day, third commit)

`src/monitor.zig` (parsers + snapshot model + per-session cache), probe
machinery in the session worker (internal channel, marker-delimited
output, CPU delta vs the previous sample, warming state), bridge handlers
`oars.monitor.{poll,probe,cleanDiskEstimate,cleanDisk,dropCaches}`, and
`src/audit.zig` (jsonl, fsync'd appends, spec 15 shape). Cleanup is
itemized fixed plans (journal vacuum, apt clean) — no broad `find -delete`.
Drop-caches audits the exact level + before snapshot at issue time and the
after snapshot when the forced probe lands. Busybox `ps` (verified live)
can't emit CPU%/Mem%, so the fallback is `ps -eo pid,comm` and the payload
carries nulls. Container pass green: idle → no probe, warming → utilization
delta, snapshot freeze, forced refresh, cleanup + audit trail.

---

## 13. Session handover — 2026-08-03 (session 3): spec 04 logs backend + the integration suite was never running

### 13.1 The discovery that changes every past claim

`zig build test` had been green through specs 01–03 with the container
"passing" — but **the env-gated integration tests were never compiled, so
never run**. Zig 0.16 collects test blocks only from files that are actually
analyzed, and `const integration = @import("integration.zig")` in `main.zig`
was never *used*, so the file was never analyzed. Proof: once forced to
compile (`comptime { _ = integration; }`), HEAD crashed or failed everywhere
(the fixes in §13.2). The fix is in `src/main.zig`; keep it. Any future
feature test module needs the same reference.

Also learned: `zig build` run steps are content-cached and env vars are NOT
part of the cache key — an env-less run is replayed for later env-ful runs.
Bust the run cache (change a source file) when switching env; use
`--summary all` to see the real test count and runtime.

### 13.2 What landed (spec 04) and what was fixed

**Spec 04 backend:** `src/logs.zig` (NUL-record parser, grouping, display
names, path validation, readability mapping, `logs.json` source store,
60 s scan cache), `src/shellquote.zig` (POSIX single-quote with a real
`/bin/sh` round-trip test), bridge handlers `oars.logs.{scan,read,follow,
clear,addSource}`, session-worker support (`Op.follow`/`Op.clear`, follow
channels with kind `log`, `execWait`, identity-bound SFTP truncate in
`clearLogFile` with conflict refusal + audit, `ScanCache` per session,
`ssh.Session.sftpInit/sftpShutdown`). Verified live against the container:
scan (busybox `-print0`+`stat` fallback), read, follow + appended lines,
clear conflict → re-scan → fresh clear + audit, closeChannel. See spec 04
§11–13 for the verified command strings.

**Pre-existing rot exposed by the now-running integration suite (fixed):**
- `@memcpy(&trust.fingerprint, fp)` panicked: the buffer is 64 bytes (legacy
  hex) but canonical fingerprints are 50 (`SHA256:` base64). Now length-aware
  (`fingerprint_len`).
- `handleMonitorPoll` emitted invalid JSON (`{"ok":true,{…}}` — the SDK
  rejects it) — now a flat payload per spec 03 §5.
- `Manager.trust` duped the fingerprint but left `session.server`'s old
  pointer dangling and leaked — the session copy now owns it; `upsert`
  duplicates for the store.
- Worker re-read closed channels: `libssh2_channel_free` nulls the channel's
  session pointer, and the read loop hit every channel each pass → segfault
  on exec/follow EOF. Closed entries are now skipped (`raw_closed`).
- `Channel.close` leaked the Zig handle — it now destroys it (safe: all
  teardown paths are `raw_closed`-guarded).
- ops/channels lists leaked on teardown (`clearRetainingCapacity` → `deinit`);
  shell-setup error paths close the channel.
- The stty resize assertion expected `100 40` — busybox prints `40 100`
  (rows cols) and its `stty` has no `size` command at all (verified live:
  busybox 1.36 stty supports only `-a`/`-g`/settings); the test now asserts
  the busybox order. Spec 02 §12 note added.
- Test rig: integration tests freed literal-backed `Server` structs
  (`defer server.deinit` → bus error) — removed; the manager copies.

### 13.3 New pitfalls (extend §7)

24. **Zig 0.16 drops tests from unused imports.** An import that nothing
    references is never analyzed, and its test blocks silently disappear
    from `zig build test`. Force collection: `comptime { _ = integration; }`.
25. **`zig build` run steps cache by content, not environment.** A run done
    without `OARS_TEST_SSH_*` is replayed with the env set. Bust the cache
    (touch a source) or read the `--summary all` runtime — a 1 s "pass" is
    a skip.
26. **`std.Thread.sleep` does not exist in 0.16.** Use
    `std.Io.sleep(io, std.Io.Duration.fromMilliseconds(n), .awake)`.
27. **busybox printf rejects `%B`-style directives** (prints nothing +
    "invalid format" to stderr). Markers must use `%%` escapes — this also
    affected the spec-03 probe command (fixed, see spec 03 §13).
28. **busybox `stty` has no `size` command** and `-a` prints no rows/cols.
    Resize verification must use the busybox `rows cols` order or a
    different mechanism; do not assert `stty size` output.
29. **A green `zig build test` proves nothing about env-gated tests.**
    Verify by forcing the run (content change) and reading the runtime;
    the integration tests are in the binary only because of pitfall 24's
    fix.
30. **`defer` inside a loop body runs at the end of each iteration.** A
    buffer retained across iterations (e.g. a component list for a path
    walk) dangles the moment the next iteration starts. Own such buffers
    at function scope and free them in a function-level `defer`.
31. **SFTP paths are server-cwd-relative.** A `mkdir -p`-style walk over
    absolute paths must start at `/`; a relative walk silently builds a
    parallel tree under the home directory (the unzip dest bug).
32. **busybox `ls` exits 1 (not GNU's 2) on missing paths** — assert exit
    1 in container tests.
33. **Zig 0.16 API drift:** `Io.File.writeStreamingAll` (no `writeAll`),
    `std.mem.trimStart` (no `trimLeft`), `Io.Dir.renameAbsolute` is a
    namespace function, `Channel.exitStatus()` returns plain `i32`,
    `readFileAlloc` takes `Io.Limit` (`.limited(n)`), `free` on a `?[]u8`
    is a compile error, and `@intCast` into C `unsigned int` params needs
    an explicit `@as(c_uint, …)` when the callee is `anytype`.
34. **`std.json.ObjectMap`-typed struct fields break the 0.16 static
    parser** (`field.defaultValue()` comptime error, even without a
    default). Parse maps as `std.json.Value = .null` and read them via
    `.object` (a StringArrayHashMap of `Value`).
35. **Zig keyword field names** (e.g. `error`) are legal as `@"error"` —
    used for the broadcastPoll per-server error field.
36. **Free a `poll.data` slice before serializing it** — `ChannelPoll`
    deinit owns the data buffer; writing it into a response after the
    frees emits DebugAllocator's 0xAA fill (the container test caught it
    as invalid UTF-8).
37. **`defer` inside a loop body runs at the end of each iteration** —
    correct when nothing retains the buffer (e.g. a per-iteration quoted
    string copied via `appendSlice`), fatal when a list keeps pointers
    into it (see pitfall 30).

### 13.4 Next

Spec 05 (File Manager / SFTP) backend — the SFTP subsystem now initializes
in the session (`sftpInit`), and spec 04's `clearLogFile` is the working
pattern for identity-bound SFTP handles. Keep the spec-04 convention: every
new feature module imported by `main.zig` must be referenced (pitfall 24),
and every new integration test must be observed running with the container
up (pitfall 25).

## 14. Session handover — 2026-08-03 (session 4): spec 05 file-manager backend

### 14.1 What landed

**`src/sftp.zig` (new):** `RemotePath` codec (`utf8`/`base64`), path
validation (control chars; traversal is the server's boundary per spec 05
§8), `Entry` model with custom JSON (name `{utf8,base64}`, display, kind,
size, mtime, mode string, uid/gid, link_target), `Transfers` registry
(spin-locked, bounded completed history, client-chosen upload ids), the
ZIP central-directory preflight (`findEndRecord` EOCD scan — the std
`findBuffer` is compile-broken in 0.16 — + entry/path/depth/size/ratio
limits), and `buildStoredZip` for tests.

**`src/sessions.zig`:** 13 `Op.sftp_*` variants + the worker ops
(`sftpOpLs/Stat/Read/WriteChunk/Save/Mkdir/Rm/Rename/Chmod/Download/
Unzip/…`), `SftpOutcome` (worker-built JSON, bounded wait), `Transfers`
per session, folder-size cache, `execSync`, `sftpStreamRemoteToLocal`
(`<local>.partial` → no-clobber rename), `sftpDeleteRecursive`, ZIP
preflight + extraction (stored and raw-deflate), `commonDir`, shell-quoted
`zip -r` staging with cleanup in success AND failure.

**`src/bridge.zig`:** 15 handlers `oars.sftp.{ls,stat,read,write,save,
download,mkdir,rm,rename,chmod,unzip,zipDownload,folderSize,poll,cancel}`
(handler_count 21 → 36). Sync ops wait on the outcome (bounded) and copy
the worker's JSON into the result buffer; async ops create the transfer
record and return `{ok, op_id}` immediately. `folderSize` runs quoted
`du -sb` with a 5 min per-path cache.

**Tests:** dispatcher-level validation suite (all 15 handlers: not
connected, bad base64, bad max/mode/local path, overwrite refusal, zero
transfer id); a full container integration test — mkdir → 2-chunk upload
→ read → ls → stat → rename → chmod (verified via `stat -c %a`) → editor
save → folderSize → download + local byte check → cancel (partial deleted)
→ unzip fixture + conflict refusal → zipDownload (staging cleaned up) →
recursive rm. **67/67 pass, leak-checked, container up.**

`scripts/dev-sshd/Dockerfile` now installs `zip` (busybox lacks it).

### 14.2 Bugs the integration test found (all fixed)

- `sftpMkdirP` walked absolute paths as cwd-relative components → a
  parallel tree under `/root`; plus a `defer`-in-loop dangled the
  component list (pitfall 30). Both fixed; unzip now extracts to the
  absolute dest.
- `commonDir` returned the file path itself for single-path
  zipDownloads → `cd <file>` → `zip` exit 2. It now returns the
  containing directory when the prefix equals one of the paths.
- `buildStoredZip`'s local header wrote 4 bytes for the 2-byte
  extra-length field, shifting extracted data by 2.
- `sftpOpRead` leaked its base64 buffer (the JSON copies the bytes; the
  worker owns the base64 itself).
- busybox `ls` exits 1 (not 2) on missing paths — assertion fixed.

### 14.3 Next

Spec 05 frontend UI (file manager pane, transfers drawer, editor) — the
bridge contract in spec 05 §5 is the wire format. Or spec 06 (scripts).
The transfer poll is non-destructive; two views may poll freely.

## 15. Session handover — 2026-08-03 (session 5): spec 06 scripts + safe broadcast backend

### 15.1 What landed

**`src/scripts.zig` (new):** the Script model, the persistent store
(`scripts.json`, 0600, quarantine-on-corrupt like the servers store), and
the shell-aware `{{variable}}` template expansion. The lexer tracks
single/double quotes, backticks, comments, `$(…)`/`${…}` nesting, and
word/command/redirection/assignment position; every ambiguous context is
rejected before expansion (spec 06 §5). Accepted placeholders are replaced
with single-quoted literals (the spec's own `/var/log/{{service}}`
mid-word form works — the quoted value merges into the word safely);
missing variables block with no partial substitution; multiline values are
refused; secret values are masked as `***` in a second (audit) command.

**`src/broadcast.zig` (new):** pure run-state machine — queued/running/
done/failed/canceled/skipped per server, dedupe, bounded completed-run
history, at-most-4 concurrent.

**`src/bridge.zig`:** 7 handlers `oars.scripts.{list,save,delete,run,
broadcast,broadcastPoll,broadcastCancel}` (handler_count 36 → 43). Runs
expand once, audit per server (redacted command + variable names; secrets
never written), `bash -n -c` syntax-check each server before exec, bump
run stats, and stream per-server deltas with the spec-02 cursor protocol.
`src/sessions.zig` owns the `broadcasts` registry (Manager field).
`scripts.json` is wired into App/TestApp/TestRig alongside the other
stores.

**Tests:** 8 unit (store round trip + validation + quarantine, lexer
boundaries, injection literals, secrets, missing vars, multiline), 4
broadcast-state unit, 3 dispatcher suites, and one container integration
test: run with vars, injection value (`'; touch /tmp/oars-pwned` — stays
literal, no file), missing-variable block, `bash -n` refusal of a broken
body, 2-server broadcast with per-server exit 0 + output, secret value
absent from audit.jsonl, run_count/last_run_at persistence, and cancel
(`canceled` + "cancel requested"). **83/83 pass, leak-checked, container
up.**

`scripts/dev-sshd/Dockerfile` now installs `bash` (the `bash -n` check).

### 15.2 Bugs the integration test found (all fixed)

- The poll handler serialized a channel's `data` AFTER freeing the polls
  (pitfall 36) — the response carried DebugAllocator's 0xAA fill, caught
  as invalid UTF-8 by the test's JSON parse.
- A done broadcast server was polled again on the next poll (late cursors
  still drain retained data) and decremented `run.running` twice —
  integer overflow; the transition is now guarded.

### 15.3 Next

Spec 06 frontend UI (script library, variable prompt, broadcast preview /
side-by-side streams). Or spec 07 (deployment). The broadcast wire format
in spec 06 §5 is final; `broadcastPoll` cursors are per-view absolute
positions.

## 16. Session handover — 2026-08-04 (session 6): spec 07 one-click deployment backend

### 16.1 What landed

**`src/deploy.zig` (new):** the App model + `AppStore` (`apps.json`, 0600,
quarantine-on-corrupt), the six-step planner (`buildPlan`: clone/pull
recheck → lockfile install → build → pm2 → nginx → certbot, every dynamic
value shell-quoted), the file builders (`nginxConfig`, `envFile`,
`ecosystemFile` — valid JSON), the run state machine (`Run`/`Runs`: steps,
step_index, protected `secrets`, masked bounded output, `env_written`
flag, owned app snapshot per run), `maskSecrets` (longest-first), and the
`HistoryStore` (`deploy_runs.json`, 200-run cap, `history_list_limit` 10).
Secret env values never enter the store; the run keeps them in protected
memory and frees them at eviction.

**`src/bridge.zig`:** 7 handlers `oars.deploy.{apps.list, apps.save,
apps.delete, run, poll, cancel, history}` (handler_count 43 → 50). The
pipeline is poll-driven with zero extra threads: `run` validates the app
and the secret names (every supplied name must match a declared secret
field), audits the command list (the Create/Update click is the approval),
and registers the run; `poll` starts/advances steps sequentially — after
clone, `.env` is written via SFTP (before install or build, whichever runs
first); before pm2 the ecosystem file, before nginx `mkdir -p` + the site
config — then execs the step on the session worker. Step EOF with exit 0
advances; non-zero fails the run; a vanished session marks it `interrupted`
(spec 07 §10); cancel closes the current channel and reports `canceled`
("cancel requested"). Poll responses mask every data delta with the run's
secret values and carry per-caller absolute cursors (spec 02 protocol).
`sessions.Manager` owns the `deploys` registry; `apps.json` +
`deploy_runs.json` are wired into App/TestApp/TestRig.

**Tests:** 10 deploy unit tests (store round trip — secret value never
persisted; validation; six-step plan + quoting + no `|| npm install`
fallback; ssl-off skips certbot but keeps nginx; well-formed
nginx/ecosystem/env files; maskSecrets longest-first; run capture
mask+truncate; history persists + prunes), 2 dispatcher suites (apps
CRUD round trip; run validation — unknown app / wrong server / unknown
secret / not connected / empty history), and one full container
integration test: save → run with a secret value → poll to `done` (clone
→ install → build → pm2 → nginx, certbot skipped) → site live through
PM2 and nginx → `.env` on the server carries the real value → the value
never appears in apps.json, audit, poll data, or history (build step
greps the .env: `DATABASE_URL=***`) → re-deploy after a new commit
serves v2 → history newest-first → broken build (`build=false`) fails the
run with the step red → cancel of a `sleep 30` build reports `canceled`.
**94/94 pass, leak-checked, container up.**

`scripts/dev-sshd/Dockerfile` now installs `git`, `nodejs`, `npm`, `nginx`,
`curl` + global `pm2`, a Debian-style `sites-available`/`sites-enabled`
nginx.conf, and a fixture repo (`/srv/fixture.git` — a bare clone of a
node app serving `fixture.txt` on 127.0.0.1:3000).

### 16.2 Bugs the integration test found (all fixed)

- `parsePs` (spec 03) failed the whole ps section on comm names containing
  spaces — the pm2 daemon's real name is `PM2 v7.0.3: God`, and `npm start`
  is a 3-token busybox row. The parser now labels trailing float pairs as
  cpu/mem, joins spaced comms into the name, and still refuses a 3-token
  row whose third token is a float (unlabelable).
- The clone recheck's dirty test flagged Oars' own untracked files
  (`.env`, `.oars-pm2.json`, `package-lock.json` from npm) → every
  re-deploy refused. The check now uses `--untracked-files=no` (modified
  tracked files still refuse; git itself refuses a pull that would
  overwrite an untracked file — honesty preserved, spec 07 §10).
- `deployWriteFile` leaked the worker's success JSON (freed in
  `sftpSyncOutcome`, not in the deploy helper).
- The deploy audit truncated the clone command at 300 chars, cutting off
  the `git clone` line the test asserts; caps raised (600/step, 3800 total).
- The fixture commits must be pushed to the *bare* repo the deploy clones
  from; the integration test's v1/v2 transitions are now idempotent across
  container reuse (no commit when nothing changed; `pgrep nginx || nginx`
  instead of a blind start; fixture reset to v1 at test start).

### 16.3 Next

Spec 07 frontend UI (app form, step rail, deploy view, history). Or spec
08 (SSH key management — the deploy flow's `GIT_SSH_COMMAND` scoped-key
piece is designed but not implemented: per-app `known_hosts` + deploy key
+ `IdentitiesOnly=yes`, spec 07 §6). The deploy wire format in spec 07 §5
is final; `deploy.poll` cursors are per-view absolute positions like the
broadcast poll.

## 17. Session handover — 2026-08-04 (session 7): spec 08 SSH key management backend

### 17.1 What landed

**`src/sshkeys.zig` (new):** the pure authorized_keys parser — no shell.
Line split (CRLF, comments, empties; a trailing newline does not produce a
phantom line), the OpenSSH options field (comma-separated, quote-aware,
no spaces outside quotes), key-type detection, base64 blob, and comment;
embedded-type verification against the decoded SSH wire blob; `bits`
derived only for understood formats (ed25519 256, rsa via mpint, ecdsa via
curve point length); `fingerprint` → `SHA256:<base64>` matching
`ssh-keygen -lf` byte-for-byte; `lineHash` (lowercase hex, stable per
line); `rewrite` (line-preserving drop/replace of the target line only);
`normalizePublicKey` (parse + fingerprint of a pasted/generated public
key). Unit vectors include a known ed25519, rsa, and padded-ecdsa key.

**`src/keygen.zig` (new):** in-app key generation via the installed
OpenSSH `ssh-keygen`. `promptAction` is a prompt state machine that
matches the documented prompts by suffix (`(empty for no passphrase): `
embeds the key path, so full-text matching is wrong) and detects the
passphrase-mismatch loop by counting prompt occurrences in the
accumulated PTY output. `runSshKeygen` drives a private PTY
(posix_openpt/grantpt/unlockpt, fork, setsid + TIOCSCTTY, dup2, execve)
with hand-declared async-signal-safe externs; a non-empty passphrase goes
only to the terminal — never argv, env, or audit — and the scratch
buffer is scrubbed with `secureZero`. `generate` validates the
destination (absolute, sane, existing dir), writes to a same-dir
`.oars-tmp-<ns>` pair, verifies mode 0600 + public-key parseability, and
installs with no-clobber renames (private first, rollback on failure).
Empty passphrase uses `-N ""` and skips the PTY entirely.

**`src/bridge.zig`:** 9 handlers (handler_count 50 → 59):
`oars.sshkeys.{list, add, revoke, rotate, generate, roles.list,
roles.create, roles.delete, deployKey.generate}`, all approval-gated in
`policies`. `add`/`revoke`/`rotate` take `user?` (default: the connected
account) and guard every write with the fingerprint + expected line hash
(a stale hash is a conflict, never a silent overwrite); `rotate`
preserves the line's options and comment. Role handlers run through exec
(root): `roles.create` is idempotent, capability-detects `internal-sftp
-R` before offering read-only, creates the user with
`useradd -m -s /bin/bash -p ''` (an empty password keeps the account
*unlocked* for key auth while password auth stays refused — a default
`useradd` leaves the account locked and sshd refuses it), chowns `.ssh`
and `authorized_keys` to the role user, and records the marker in
`/etc/oars-roles.json`; `roles.delete` removes user + marker entry;
`roles.list` reads the marker + live `getent passwd`. Read-only role keys
are written with `restrict,command="internal-sftp -R"` (spec 08 §4.2 —
no `rbash`). `deployKey.generate` is an idempotent server-side ed25519
at `~/.ssh/oars_deploy` (0600) that never touches `authorized_keys`.
`generate` responds with `keychain_account: "localkey:<fingerprint>"`
when the passphrase should be remembered — the bridge never holds it.

**Tests:** 10 sshkeys parser/keygen unit tests, 2 dispatcher suites (the
9 handlers reject ghost servers and bad role names; generate makes a
0600 key, refuses dupes and relative destinations, and keeps the
passphrase out of response + audit), and one container integration test
taking the whole spec end to end: generate a local key → add → list
(fingerprint matches `ssh-keygen -lf`) → connect with it → revoke
(connect now fails; stale line hash is a conflict) → rotate (old
fingerprint gone, options preserved) → create the read-only role → list
roles → add a key to the role (forced command auto-applied) → as the
role user: SFTP reads OK, shell/exec refused, every filesystem mutation
(save/mkdir/rm/rename/chmod) refused, and `ssh -W` (a direct-tcpip-only
channel) refused with "administratively prohibited" → roles.delete
(login now fails) → deploy key generated (0600, idempotent,
authorized_keys untouched) → every mutation present in the audit store.
The container's own key is restored at the end so the earlier key-auth
test stays green on the next run. **109/109 pass, leak-checked, two
consecutive container runs green.**

`scripts/dev-sshd/Dockerfile` now installs `shadow` (useradd/userdel for
roles).

### 17.2 Bugs the integration test found (all fixed)

- **Revoked-account denial:** a fresh `useradd` (no `-p`) leaves the
  account *locked* — sshd refuses key auth with "account is locked".
  Fixed with `useradd -m -s /bin/bash -p '' <name>`.
- **Ownership:** sshd reads the role user's `authorized_keys` after the
  privilege drop; a root-owned 0700 `.ssh` blocks it. Role setup and
  every `sshkeysWrite` to a role user's file now `chown` to that user.
- **Dangling home:** `sshkeysPath` returned a slice into the freed exec
  output buffer → garbage SFTP paths. The home is now duped while the
  output lives.
- **Memory leaks:** `trust()`'s fingerprint dupe left the session's
  `host_fingerprint` dangling (now owned by the session copy);
  `Channel` allocations were never freed (close() now self-destroys);
  ops/channels lists deinit instead of clearing; marker entries freed
  their duped strings; a padded-base64 decode must be re-sliced to the
  padded size before copy (DebugAllocator).
- **Prompt matching:** matching the full "Enter passphrase …" text is
  wrong — the prompt embeds the key path. Match the `(empty for no
  passphrase): ` suffix and *count* occurrences to detect the mismatch
  loop.
- **Defer restore after disconnect (this session):** the test restored
  the container's `authorized_keys` in a `defer`, but the explicit
  `disconnect` is the last statement — the defer ran *after* it and
  silently failed (`catch {}`), leaving the rotated key in the file and
  breaking the earlier key-auth test on the next run. Restore now runs
  explicitly before the disconnect; the defer remains as a safety net
  for mid-test failures (the session is still connected then).
- **Silent `userdel` failure:** shadow's `userdel` refuses (e.g. a user
  it considers logged in) and the test swallowed the exit code, leaving
  a stale two-key `authorized_keys` that failed the roles assertions.
  Cleanup is now belt-and-braces: `userdel -r …; rm -rf /home/…;
  rm -f /etc/oars-roles.json`.
- **Forwarding probe placement:** exec as the read-only user is replaced
  by the forced command, so a forwarding test *from that session* tests
  nothing. The probe runs from the root session: `ssh -W` (which opens
  only a direct-tcpip channel) authenticates as the role user with the
  uploaded role key, and the assertions check the refusal message
  ("administratively prohibited", "open failed") and `rc=255` — so the
  refusal is about `restrict`, not about auth.

### 17.3 Next

Spec 07 frontend UI (app form, step rail, deploy view, history). Or spec
09 (fleet-wide access view — it can reuse `sshkeys.list` + role markers
per server). The `GIT_SSH_COMMAND` scoped-key piece of spec 07 §6
(per-app `known_hosts` + the spec-08 `oars_deploy` key +
`IdentitiesOnly=yes`) is still unimplemented backend work if taken
before the frontend.
