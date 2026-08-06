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

## 18. Session handover — 2026-08-04 (session 8): spec 09 access management backend

### 18.1 What landed

**`src/access.zig` (new):** the identity registry, scan/job models, pure
parsers, the people-map join, and export formatting.

- `IdentityStore` (`access_identities.json`, 0600, quarantine-on-corrupt,
  arena-safe): save/list/delete with the spec-09 ownership rule — a
  fingerprint belongs to at most one person unless that person is marked
  `shared`; ids are generated (`id-<n>`); validation covers name, count,
  duplicates, and canonical fingerprints (`SHA256:` + unpadded-or-padded
  base64 of exactly 32 bytes).
- Scan model: `Scan`/`ServerScan`/`AccountScan`/`Grant` with an explicit
  phase machine (queued → identity → sudo_probe → enumerate →
  read_accounts → sshd_config → done/error). Optional owned fields
  (never comptime defaults in deinit paths).
- Pure parsers: `parseSudoList` (yes/no/unknown — the denial *message*
  wins over the exit code, because Alpine's sudo prints "is not allowed
  to run sudo" and still exits 0 for `-l -U` queries), `parsePasswd`
  (uid ≥ 1000, nologin excluded), `skippedAccounts` (nologin rows
  recorded, not silently dropped), `safeUserName`, `sshdSourcesForcePartial`
  (dynamic/alternate `AuthorizedKeys*` sources ⇒ partial coverage).
- `buildMap`: fingerprint-keyed join of scanned grants with identities —
  people (per identity, grants across servers), unassigned (claimed by no
  identity), coverage (complete only when every server is done with
  complete coverage and no sync errors), sync errors (errored servers
  with reasons).
- `serverView` + `PollPayload`: the poll/export wire shape lives here;
  every view field is dupe'd (even empty defaults) so deinit never frees
  comptime literals.
- `exportCsv` (RFC 4180: quoting, doubled quotes, CRLF) and `exportJson`
  (indent-2 serialization of the same payload).

**`src/bridge.zig`:** 10 handlers (handler_count 59 → 69):
`oars.access.{scan, poll, identities.list, identities.save,
identities.delete, offboard, onboard, rotate, jobPoll, export}`, all
origin-gated. `scan` takes `server_ids?` (default all) + `full?`;
`poll` advances every server one phase per call (the deploy poll
pattern — zero extra threads) and serializes a bounded response (row
budget, counts stay honest). The scan: connected-only by default (the
connected account's `authorized_keys` via SFTP, its sudo via
`sudo -n -l`); `full` adds `getent passwd` enumeration (uid ≥ 1000,
nologin skipped), per-account `sudo -n -l -U <user>` probes (root only),
and an sshd-config sources check; coverage is partial with a reason
when accounts are unreadable, sources are dynamic, or authority is
missing. Unconnected/untrusted/errored sessions become sync errors —
never silent. Jobs (offboard/onboard/rotate) are validated against the
identity (fingerprints must belong to it), executed one item per
`jobPoll` via the spec-08 writer (offboard = fingerprint+line-hash
guarded drop; rotate = options-preserving replace; onboard = dedupe by
fingerprint then append, with read-only roles ensured first and the
forced-command options auto-applied), idempotent by fingerprint, and
audited (`access.offboard`/`onboard`/`rotate`). `export` formats the
last finished scan (no round trip). Reused refactors: `sshkeysPathMsg`/
`sshkeysRewriteCore` (plain-message cores; the bridge handlers wrap
them into JSON errors) and `sshkeysRoleEnsureCore` (shared by
`sshkeys.roles.create` and read-only onboarding).

**Tests:** 11 access unit tests (identity store incl. ownership/shared/
validation; sudo parsing incl. the Alpine denial; passwd/skipped
classification; buildMap joins + unassigned + sync errors; RFC 4180 CSV;
JSON export; sshd sources; serverView), 2 dispatcher suites (identity
round trip; scan/job validation — unknown servers/scans/jobs, foreign
fingerprints, invalid keys, exports), and one container integration test
covering the whole spec: two sessions to one box as two fleet servers +
a dead-port server; connected scan (root-only, sudo yes, complete
coverage); full scan (alice no-sudo, carol passwordless-sudo via a
sudoers rule, `nobody` recorded skipped, unassigned key separated,
10 grants, complete coverage); dead server ⇒ sync error + partial;
offboard with a fresh hash removes exactly one line (verified by blob in
the file) while a stale hash conflicts and leaves the key;
onboard to a plain user + a read-only role (created, forced command
applied, idempotent re-onboard dedupes); rotate replaces the line;
CSV/JSON exports; every mutation audited. **121/121 pass, leak-checked,
two consecutive container runs green.**

`scripts/dev-sshd/Dockerfile` now installs `sudo` and ships a sudoers
file (`root ALL=(ALL) ALL`, `carol ALL=(ALL) NOPASSWD: ALL`) so the
per-account sudo matrix is real.

### 18.2 Bugs the integration test found (all fixed)

- **Alpine sudo denies with exit 0:** `sudo -n -l -U alice` prints "User
alice is not allowed to run sudo" and exits 0 — a naive exit-code check
reported `yes` for a user with no privileges. The denial message now
wins over the exit code.
- **Comptime literals in deinit paths:** `serverView`/`AccountView`
  fallbacks (`""`, `sudo_unknown`, `coverage_partial`) pointed at
  comptime data and crashed in deinit once a server errored before its
  sudo/coverage were set. Every view field is now dupe'd, even empty
  defaults.
- **Read-only onboard order:** the item resolved the user's
  `authorized_keys` path *before* creating the role, so onboarding to a
  new role failed with "user not found". Role creation now runs first.
- **`useradd` pollutes `/var/log`:** creating users leaves
  `faillog`/`lastlog`, which broke the earlier logs-count test on repeat
  runs against the persistent container. Both user-creating tests now
  remove them at start.
- **Test-side fixes:** fingerprints were searched for in raw
  `authorized_keys` output (they never appear there — the blob does);
  the stale-hash conflict probe re-added a byte-identical line (same
  hash) so a different comment is used; JSON-escaped export content
  needed escaped search strings; `nobody` is a legitimately skipped
  account (uid 65534, nologin) — asserted as such.

### 18.3 Next

Spec 07 frontend UI (app form, step rail, deploy view, history). Or spec
10 (backups — the access map's per-server sessions and the deploy
key/gen mechanics are reusable building blocks). The `GIT_SSH_COMMAND`
scoped-key piece of spec 07 §6 (per-app `known_hosts` + the spec-08
`oars_deploy` key + `IdentitiesOnly=yes`) remains unimplemented backend
work if taken before the frontend.

## 19. Session handover — 2026-08-06 (session 9): spec 10 backups backend

Landed: the full spec-10 backend — job model + store, rclone config
management, cron management, JSON-log run polling, capability test, run
history, scheduled-run staging import, and a real MinIO integration leg.
**135/135 tests pass** (121 at spec 09 + 12 backup unit + 1 backup
dispatcher + 1 backup container integration), two consecutive full
container runs green, `zig build` + frontend build clean.

### 19.1 What landed

**`src/backup.zig` (new, 12 unit tests):** `Job`/`JobInput`/`Destination`/
`Schedule` + `validate` (absolute source, provider/bucket/endpoint/region/
storage-class rules, five-field cron grammar, IAM-requires-AWS,
`EnabledScheduleNeedsCredentials` for non-IAM unattended schedules);
`Provider` (aws/r2/b2/wasabi/minio/spaces) with `needsEndpoint`/
`needsRegion`/`storageClasses`; cron (`validCronExpr`, `intervalToCronExpr`,
`escapePercent`, `crontabAdd`/`crontabRemove` with `# oars:job:<id>`
markers, idempotent); rclone config (`remoteConfigSection` — IAM omits key
material; `configMergeSection` replaces only the job's section;
`destinationArg`); the scheduled-run wrapper (`flock`-per-job, one
`.status`+`.log` per run under `~/.local/state/oars/backups/<job-id>/`);
JSON-log parsing (top-level *and* nested `stats`, error lines surfaced,
views the line — no allocs); `JobStore` (id generation `bk-<n>`, save/
list/delete/find, quarantine on corrupt files); `HistoryStore` (append
idempotent by run id, 90-day retention + 200-run cap, newest-first list,
200 KB log trim); `Runs` registry (one manual run per server,
`run-<n>` ids, completed eviction).

**`src/bridge.zig` (handler_count 69 → 78):** `oars.backup.{jobs.list,
jobs.save, jobs.delete, test, run, poll, history, install, cronStatus}`,
all origin-gated and audited. `jobs.save` persists first, then installs/
removes the schedule when the session is live; `test` runs the §5
capability test on one unique sentinel in the job's exact bucket/prefix
(sync jobs must prove prefix-level delete authority; failed cleanup is
reported, never passed); `run` checks rclone + source existence + one-run
per server, writes a unique temp config (mode 0600), execs with
`--use-json-log --stats 1s --stats-log-level NOTICE`, and deletes the
config at finalize; `poll` parses stats deltas, finalizes on EOF (maps
exit 0 + zero transfers to `no_changes`, surfaces error lines, trims the
log, appends history); `install`/`cronStatus` probe rclone + crond and
detect the OS for an honest plan (Alpine/Debian adapters, manual
instructions otherwise); `history`/`jobs.list` import staged scheduled
runs on connect (`backupImportStaged` — status/log files parsed,
deduped by `sched-<job>-<ts>`, consumed after import). Secrets only ever
touch the 0600 config file on the server — never argv, JSON, logs, or
audit.

**`src/main.zig`:** App/TestApp carry `backup.Registry` (jobs +
history paths), plus a new dispatcher suite: save with schedule
credentials on a ghost server (persists, then `not connected`), list
(secrets absent), edit-by-id, credential-gated enabled schedules, bucket/
cron shape errors, `test`/`run`/`install`/`cronStatus` session gates,
`poll` unknown-run, `history` empty store, delete + double-delete.

**Integration harness (spec 10):** `scripts/dev-sshd.sh` now runs a
second container, `oars-dev-minio` (minio/minio) on the shared
`oars-dev-net` network, and exports `OARS_TEST_MINIO_*`; the dev sshd
image installs rclone. `src/integration_backup.zig`: job save over a
live session, capability test (real sentinel write/read/delete,
leftover verified absent), three manual sync runs — full (2 files,
success), unchanged (no_changes), incremental (1 file) — history
(newest first, all three), and object-landing verification via `rclone
lsf`. Idempotent: bucket emptied at setup, temp configs deleted by the
run finalize, fresh stores per rig.

### 19.2 Bugs found by the container leg (all fixed)

- **Capability test ran vacuously:** the sentinel path never included the
  remote prefix (`oars-test:`), so `copyto`/`deletefile` operated on a
  local relative path and exited 0 without touching the bucket — the
  whole test passed without proving anything. Now `remote:bucket[/prefix]/
oars-sentinel-<ts>` and the read check lists the destination with the
  sentinel filter.
- **`--use-json-log` writes to stderr:** the exec channel captures
  stdout only, so runs produced an empty log and finalized with zero
  stats (`no_changes` despite transfers). Manual runs append `2>&1`
  (the cron wrapper already did).
- **MinIO rejects lowercase `storage_class`:** the config wrote
  `standard` and every PUT failed with 400 InvalidStorageClass (AWS
  tolerates it, MinIO does not). `remoteConfigSection` now emits the
  canonical uppercase S3 value (STANDARD/STANDARD_IA/…).
- **Poll response wrote a dangling `log_delta`:** `poll.data` was freed
  by the poll list's `defer` before the response serialized it — empty
  before the stderr fix, garbage NULs after. The delta is now duped
  before the list dies.
- **`backupSessionReady` swallowed errors:** handlers returned
  `output[0..0]`, which the dispatcher turns into `"result":null` — the
  "not connected"/"session not ready" message was lost. It now returns
  the error response the caller must return verbatim.
- **Comptime-literal frees in `Job`/`RunRecord` deinit:** the
  `handleBackupTest` job used `Schedule` defaults (`"manual"` literal)
  and crashed on deinit. Fixed properly: `dupOrLiteral` (empty strings
  are never owned) + guarded `Job.deinit` frees; `RunRecord.@"error"`/
  `log` are optional (`null` until set).
- **Test-side:** the bucket persists in the MinIO volume between runs
  (setup now empties it); `execWait` format args were dropped in one
  command (server ran `{s}` literally — redirect to a missing dir exits
  1); the run request JSON had an extra closing brace.

### 19.3 Known limits / next

- The live cron leg is not container-tested yet: install-schedule →
  crontab → cron runs the wrapper while Oars is closed → import on next
  connect (`backupImportStaged`). The crontab add/remove logic is
  unit-tested; the full loop needs a running crond in the harness
  (Alpine ships busybox crond; add `crond -b` to the container CMD).
- `backup.install`'s OS adapters (apk/apt) are implemented but not
  exercised against the container (rclone is preinstalled there).
- Pre-existing flake: the keys/access container tests occasionally race
  each other on `authorized_keys`/user counts when the full suite runs
  (also seen before spec 10); rerun passes. Worth a serialization or
  per-test isolation pass.
- Frontend: nothing yet — the whole spec-10 UI (backups view, job form,
  run progress card, history, install banner) is open work.

Next: spec 10 frontend or spec 11. Backend reusables for later specs:
`backupImportStaged`'s staged-file pattern and the JSON-log parser.

## 20. Session handover — 2026-08-06 (session 10): spec 11 AI terminal backend

Landed: the spec-11 backend half — provider config store, the server
context bundle, and audit-filtered run history. **145/145 tests pass**
(144 at spec 10 + 1 container AI integration), two consecutive full
container runs green, `zig build` + frontend build clean.

### 20.1 What landed

Per spec 11 §6, Zig adds only `oars.ai.context` and history filtering;
the AI call, prompt contract, destructive heuristic, and save-as-script
are frontend-owned (documented in the spec §12 as pending UI work).

**`src/ai.zig` (new, 7 unit tests):**
- `ProviderStore` (`<data>/ai.json`): adapter (`openai_compatible` |
  `custom`), base URL, model, capabilities (instruction_role ∈
  {developer, system}, streaming, structured_output) — never the key
  (frontend Keychain `ai:<base_url>`). Validation: https everywhere;
  plain http only for loopback hosts (`localhost`, `127.0.0.1`,
  `[::1]`) — a user-chosen local model server. Mode 0600, quarantine on
  corrupt files, `null` when unset.
- Context probe: one exec with the spec-03 marker style — `%BEGIN_OS%`
  (`grep -m1 '^PRETTY_NAME=' /etc/os-release` with `uname -sr`
  fallback), `%BEGIN_HOSTNAME%` (/proc/sys/kernel/hostname), and
  `%BEGIN_LOGS%` (a busybox-compatible `stat -c '%Y %n'` per configured
  log source, shell-quoted, missing files skipped). `parseProbeOutput`
  views the output (no allocs); `buildActiveLogs` filters to configured
  sources, sorts newest-write-first, caps at 10.
- `ContextCache`: per-server probe cache, 5 s TTL, 16-slot ring with
  oldest eviction (the spec's "cached ≤ 5 s").

**`src/audit.zig`:** `Store.read` — owned entries filtered by server +
optional action, newest first, capped (the minimal read spec 15 will
own later).

**`src/bridge.zig` (handler_count 78 → 82):**
- `oars.ai.context` — session gate, probe-or-cache (≤ 5 s), monitor
  snapshot under the cache lock with the same refresh-if-stale force as
  `oars.monitor.poll`, honest `probe_error` passthrough. Response:
  `{os, hostname, uptime_sec, load{utilization_pct, load_1/5/15, cores},
  mem, disk, top_processes, active_logs[{path, last_write}],
  probe_error}`.
- `oars.ai.provider.get` (config only, `null` when unset) / `set`
  (validated, audited `ai.provider.set`).
- `oars.ai.history` — `ssh.exec` audit entries for the server, newest
  first, default 20 / max 100.
- `oars.ssh.exec` now audits every executed command (`ssh.exec`,
  `cmd=` truncated to 120 chars) — spec 11's "every executed command is
  logged".

**Wiring:** `ai.Registry` in App/TestApp/TestRig + the standalone
dispatcher test; a new dispatcher suite (provider round trip,
loopback-http accepted, plain-http refused, bad adapter/model/role
messages, context ghost → not connected, history empty).

**Container test (`src/integration_ai.zig`):** provider set/get round
trip; `logs.addSource` → context bundle with Alpine OS, hostname,
uptime/mem/disk, top processes, and the configured source in
`active_logs` with a real mtime (retry loop absorbs the worker-async
first monitor probe); cache-hit check on a second call; `oars.ssh.exec`
→ channel drained → marker file verified → `oars.ai.history` shows the
`ssh.exec` entry with the command in the detail.

### 20.2 Bugs / notes

- **`probe_error` nullability:** the monitor snapshot's `probe_error` is
  `?[]const u8` and serializes as `null` when healthy — the integration
  test initially parsed it as a string. Test-side fix.
- **`utilization_pct`/`Process.cpu|mem` are optional** in the monitor
  types (null until a second probe / busybox ps) — the bundle passes
  them through rather than inventing zeros.
- The context handler never blocks on the worker's probe cadence: it
  serves the committed snapshot and enqueues a force probe when stale,
  matching `oars.monitor.poll` semantics.
- The pre-existing keys/access container flake (parallel
  `authorized_keys` races) still appears occasionally; reruns pass.

### 20.3 Known limits / next

- Frontend-owned per spec §6: the provider call + streaming, the prompt
  contract (JSON mode / Structured Outputs / prompt fallback), the
  destructive heuristic table (incl. edited-card re-flagging),
  save-as-script, and the ask → approve → run loop. Their unit tests
  (spec §11) live with the React app.
- Spec 15 (history) will supersede the minimal `audit.read`.
- No changes to the dev harness this cycle (containers unchanged).

## 21. Spec 12 — VNC over SSH backend (complete)

Landed: the full remote-desktop backend — an RFC 6455 WebSocket server
(`src/ws.zig`, pure codec, no heap in the handshake path), SSH
direct-tcpip tunnels (`src/ssh.zig` `openTunnel`), the worker-side tunnel
state machine in `src/sessions.zig` (listening → handshake → connected →
closing → closed, driven from the existing run loop), the probe/setup
helpers (`src/vnc.zig`), the five `oars.vnc.*` bridge handlers
(start/stop/probe/setup/poll), and the full container integration test
(`src/integration_vnc.zig`). 157/157 tests green (two consecutive runs),
`zig build` + frontend build clean. `docs/specs/12-vnc.md` §12 acceptance
marked for the backend-verifiable items (the credential-bridge box stays
open for the frontend).

### 21.1 What landed

- **`src/ws.zig`** — `parseHandshake` (validates GET / Host / Upgrade /
  Connection / version 13 / 16-byte key / Origin ∈ {`zero://app`,
  `http://127.0.0.1:5173`} / `/vnc/<token>` path / `binary` subprotocol),
  `acceptKey` (sha1+base64), `encodeUpgradeResponse`, `parseFrame`
  (masked client frames required, zero RSV, no fragmented control,
  ≤125-byte control frames, ≤8 MB payloads), `unmask`, `encodeFrame`,
  `encodeCloseFrame`. The handshake never heap-allocates and its error
  set has no `OutOfMemory` — keep it that way.
- **`src/ssh.zig`** — `Session.openTunnel`: `libssh2_channel_direct_tcpip_ex`
  with the EAGAIN loop, allocates a `Channel` (closed by the tunnel).
- **`src/sessions.zig`** — `Tunnel` (worker-owned: listener, ws stream,
  raw channel, token/host (owned `[]const u8`), bounded buffers
  (16 MB connection cap), byte counters, error text), `Op.tunnel_start` /
  `tunnel_stop`, `tunnelStart/Stop/Poll`, run-loop hook `processTunnels`
  (~10 ms cadence, blocking sockets driven poll-then-act — no fcntl/
  non-blocking in this std), 15 s idle self-destruct, session teardown
  cleans all tunnels. **Tombstones:** a closed tunnel keeps its record
  (state `closed`, resources released) for 60 s so `oars.vnc.poll` keeps
  reporting `closed` per spec §5 instead of “unknown tunnel”, then the
  record is pruned.
- **`src/vnc.zig`** — probe command + parser (`ss -tlnp || netstat -tlnp
  || netstat -tln`, `%BEGIN_VNC_PROBE%`-delimited, ports 5900-5999
  deduped, process name from both `users:((` (ss) and `pid/name`
  (netstat) formats), IPv6 `:::` lines handled) and the OS-adapter
  setup plan (Alpine apk / Debian apt / manual; hint always carries
  `-passwd`, never `-nopw`).
- **`src/bridge.zig`** — 5 handlers: `oars.vnc.start` (ephemeral loopback
  listener; 32-hex token from `std.Io.random`), `.stop`, `.probe`,
  `.setup` (dry-run plan first; execute requires root and audits with
  `display=<n>`), `.poll` (state + byte counters; `closed` for
  tombstones). Session gate: only a `ready` session tunnels.
- **`src/integration_vnc.zig`** — full container test: setup dry-run →
  execute + audit, `setsid`-detached Xvfb + x11vnc on :1/5901,
  probe-with-readiness-loop (asserts the listener process name),
  `oars.vnc.start` → Zig WebSocket client performs the real RFC 6455
  handshake (Origin `zero://app`) → observes `RFB 003.008` through the
  tunnel → poll `connected` with real byte counters → stop → poll
  `closed`.

### 21.2 Bugs / notes (the container saga)

- **Root cause of the dead VNC server: `pkill -f` self-kill.** The start
  command began `pkill -f x11vnc ...` — the pattern matches the very
  shell running it (its command line contains “x11vnc”), so the exec
  died with exit 143 (SIGTERM) and Xvfb/x11vnc never started. Verified
  in the container: `sh -c 'pkill -f x11vnc; echo alive'` never prints
  `alive` and returns 143. Fix: `pkill -x x11vnc` / `pkill -x Xvfb`
  (exact process-name match; busybox supports `-x`).
- **Daemons must be detached from the exec session.** Even with the
  pkill fixed, background processes started by a plain `sh -c '... &
  ...'` exec channel can die with the channel. Both Xvfb and x11vnc
  now start via `setsid ... </dev/null >/dev/null 2>&1 &` (verified
  surviving the launching shell). Stale `/tmp/.X1-lock` is removed
  first.
- **busybox `ss` is a no-op and `netstat -tlnp` is the truth.** The
  container's `ss` is not even installed; `netstat -tlnp` works and
  emits a `PID/name` column (`42766/x11vnc`, `1/sshd -D [listener`).
  The probe now tries `netstat -tlnp` between `ss` and plain
  `netstat -tln`, and `listenerProcess` parses both formats. The
  integration test asserts the listener's process name is `x11vnc`.
- **`--test-filter` does not exist in Zig 0.16** — neither as a runner
  flag nor a build flag; the runner only accepts `--listen=-`,
  `--seed=`, `--cache-dir`. You cannot run one container test in
  isolation; run the full suite (`set -a; source
  scripts/.dev-sshd.env; set +a; zig build test --summary all`).
- **Keys/access/backup container flakes are state, not code.** Repeated
  full-suite runs on the persistent container accumulate users
  (`useradd` exits 9), keys, and rclone state (`no_changes` on a second
  sync); the next full run passes again. Known, non-blocking.

### 21.3 Known limits / next

- Frontend (spec 12 §12): the noVNC view, the credential-bridge
  handoff of a remembered VNC password, CSP for the loopback WS source,
  rendering/input acceptance, and the tab footer stats wiring.
- `poll` on a tombstone returns the final byte counters — good enough
  for the footer; a future cleanup could add a `closed_reason`.
- Tunnels are bounded by usage; tombstones prune after 60 s.

## 22. Session handover — 2026-08-06 (session 11): spec 15 history + audit backend

Landed: the full spec-15 backend — bounded history/audit journals with
write-time redaction, tracked-exec capture (exit, duration, two-line
snippet), replay with redacted-refusal, and type-to-confirm audit clear.
**166/166 tests pass** (157 at spec 12 + 8 history unit + 1 dispatcher
suite + 1 history container integration), two consecutive full container
runs green, `zig build` + frontend build clean.

### 22.1 What landed

**`src/history.zig` (new, replaces `src/audit.zig` — deleted):**
- `HistoryStore` (`history.jsonl`, cap 2,000) + `AuditStore`
  (`audit.jsonl`, cap 5,000): JSONL journals, O(1) positional appends +
  fsync, atomic temp+rename compaction, in-memory index (reads never
  re-parse the journal), `record` upserts by `operation_id` (dedupe,
  update moves newest), legacy `action`/`server_id` journal lines still
  load (aliases), caps are store fields so tests shrink them.
- Redaction: `exactMask` (known secret values, longest-match-first,
  applied to commands AND output snippets) + `patternMask` (narrow named
  fields — `PASSWORD=…`, `TOKEN=…`, `--password …`/`=…`, URL userinfo;
  never `-p`/`-i`/`passin`) + `redact` = exact then pattern. `••••`
  marker. Unit fixtures cover the non-mask cases (`-p`, `-i key.pem`,
  `MYPASSWORD=`, `passin pass:`).
- `AuditStore.read` keeps the minimal server/type filter for
  `oars.ai.history` (its wire shape is unchanged — still `action`).

**`src/sessions.zig`:** `execTracked(server, cmd, kind, redacted_cmd?,
secrets)` — the channel carries `history_kind`/`history_command`/
`history_secrets`; the worker records at channel EOF (`recordExecHistory`:
exit, duration from `started_ns`, first-2-lines snippet masked with the
operation's exact secrets). Plain `exec()` stays untracked (probes,
checks, scans never pollute history). All four entry-drop paths and the
queued-op teardown free the new strings.

**`src/bridge.zig` (handler_count 87 → 92):** `oars.history.{record,
list, replay}` + `oars.audit.{list, clear}` (clear requires the literal
`CLEAR`). Tracked kinds wired: `ssh.exec`→`exec`, scripts.run/broadcast
→`script` (pre-masked `***` text + secret values carried for snippet
masking), deploy steps→`deploy`, backup runs→`backup`, monitor
cleanDisk/dropCaches→`monitor`, replay→`exec` (chainable). The `ssh.exec`
audit row is now redacted the same way as history (spec 15 §8).
`ai.provider.set` audits with target `-` (app-level convention).

**`src/scripts.zig` / `src/broadcast.zig`:** `Expansion.secrets` /
`Run.secrets` — owned secret variable VALUES, freed on deinit (guarded:
the empty case is the comptime `.empty` slice, never freed — the
comptime-literal-free pitfall again).

**Tests:** 9 history unit (redaction fixtures incl. exactMask
longest-match, ring compaction with a shrunk cap, dedupe-by-op-id on
record AND on reload, persistence across store instances, legacy journal
load, audit list/clear); 1 dispatcher suite (record/list round trip +
redaction, dedupe, replay unknown/redacted/not-connected, audit
list/type/q filters, CLEAR gate); 1 container integration
(`src/integration_history.zig`): exec with exit 0 + snippet, failing
exec exit 1, `PASSWORD=` masked in history AND audit files, script run
with a secret var — value absent from history file INCLUDING the echoed
output snippet, replay re-runs the marker command (chainable entry),
redacted replay refused, audit clear gate. The snippet-secret case was a
real bug the test caught: the echoed secret value survived in the stored
snippet — fixed with exact-value snippet masking.

### 22.2 Pitfalls / notes

- **Snippet redaction is mandatory.** Masking only the command leaves
  the secret in the output snippet (`echo {{pw}}` prints the value).
  Any operation whose output can echo its secrets must carry them to the
  capture hook.
- **`toOwnedSlice` on a never-append'd list returns the comptime
  `.empty` slice** — freeing it crashes (extend §7 pitfall 13's family).
  Guard deinit frees with `len > 0`.
- **Test-only:** ids from a parsed bridge response alias the parse tree —
  re-resolve them from a LIVE parse after any re-dispatch, or they
  dangle into freed memory (hit twice this session).
- The keys/access/vnc container tests flaked once mid-session
  (accumulated container state — the documented pattern); the next full
  run passed. Not code.
- Known flake observed at 164/165 once (sshkeys.generate dispatcher
  test) — passed on the immediate rerun with no code change; watching.

### 22.3 Known limits / next

- Shell integration (OSC 633 + versioned remote scripts) is NOT landed —
  that is the interactive-capture half of spec 15, frontend+resources
  work; until it lands the UI must label coverage `app commands only`.
- History/audit UI (views, filters, palette, export CSV via spec 17).
- Spec 14 (groups) is next per the agreed order.

## 23. Session handover — 2026-08-06 (session 12): spec 14 groups backend

Landed: the spec-14 backend — save-time group path validation and tag
normalization on the canonical `Server.group`/`Server.tags` fields.
**169/169 tests pass** (166 at spec 15 + 2 servers.zig unit + 1
dispatcher), two consecutive full container runs green, `zig build` +
frontend build clean.

### 23.1 What landed

**`src/servers.zig` (pure, fixture-tested):**
- `validateGroup` — one-level path rule (spec 14 §5): ungrouped `""`, one
  segment, or `parent/child`; at most one `/`, no empty segments, no
  control characters. Returns the trimmed value (view into the input).
- `normalizeTags` — trimmed, empties dropped, control-character values
  rejected, deduped case-insensitively while preserving the first-seen
  casing. Returns an owned list; the empty case is an explicit
  `alloc([]const u8, 0)` so callers can always free (the comptime
  `.empty` slice from `toOwnedSlice` is never returned — spec-15 lesson).

**`src/bridge.zig`:** `handleServersSave` replaces its inline tag loop
with `servers.normalizeTags` and validates `payload.group` with
`servers.validateGroup`, mapping the three errors to user-facing
messages. No new bridge API (spec 14 §5).

**Tests:** 2 servers.zig unit (group table incl. `a/b/c`, `a//b`, `/`,
`prod/`, control chars; tag normalization incl. `[" Web ","api","WEB",
"","Web"] → ["web","api"]` and the freeable-empty case) + 1 dispatcher
(`servers.save` round trip with trimmed `clients/acme` and deduped
`["Web","API"]`, persistence visible in `servers.list`, one-nesting-
level / empty-segment / control-char rejections, and a failed save
leaving the store untouched).

### 23.2 Pitfall

- **Trimming before control-char checks silently accepts control
  characters.** The old tag path trimmed ` \t\r\n` and dropped empties,
  so `"prod\n"` became `"prod"` — exactly the value the spec-14 rule
  exists to reject. The new helpers trim only `" "` and reject anything
  < 0x20 or 0x7f anywhere, including the edges. The unit tests pin this.

### 23.3 Known limits / next

- All of spec 14's visible surface is frontend: sidebar grouping,
  collapsible state, counts, the monitor grid (spec 03 cache), drag-
  move via `servers.save`, broadcast preselection.
- Spec 17 (Vault export/import) is next per the agreed order — the
  history/audit journals and the servers store are its export surface.

## 24. Session handover — 2026-08-06 (session 13): spec 17 vault export/import backend

Landed: the full spec-17 backend — `src/crypto.zig` (mbedTLS wrappers:
PBKDF2-HMAC-SHA256 + AES-256-GCM, 600k iterations, random salt/nonce per
file, header authenticated as GCM AAD) and `src/vault.zig` (versioned
`.oarsvault` format, 50 MB cap, payload build/parse with duplicate-id and
id-less-record rejection, merge preview with credential-binding conflicts,
keep-local / import-as-new options with via-chain reference rewriting,
atomic write-back, JSONL section support). Bridge: `oars.vault.export`,
`oars.vault.import`, `oars.vault.importConfirm`; plain export defaults to a
config-only allowlist (no history/audit/deploy_runs/backup_runs); import
magic-sniffs encrypted vs plain. Tests: 3 crypto vectors (PBKDF2 RFC 7914
§11 and AES-256-GCM NIST SP 800-38D Case 3, both cross-checked against
independent implementations; round trip + tamper/wrong-password) + 4 vault
unit tests + 1 bridge dispatcher round trip (export → wipe → wrong
password → preview → confirm → restore) = 177/177 with the container suite
(two consecutive runs), frontend build clean.

Notes for the next session:
- Crypto vectors were verified independently BEFORE pinning: PBKDF2 via
  `python3 -c hashlib.pbkdf2_hmac`, GCM via a Zig-std harness (`zig run`
  with `std.crypto.aead.aes_gcm`); LibreSSL's `openssl enc` lacks AEAD.
- Pitfall 25: in Zig 0.16, `ArrayList.toOwnedSlice` may return the list's
  own buffer via `allocator.remap` — an `errdefer out.deinit(allocator)`
  then frees the returned slice (use an `owned` flag guard).
- Pitfall 26: Zig 0.16 `std.json.Value` has no `deinit`; `std.json.Array`
  is a managed list (`.init(allocator)`, `append` w/o allocator); the
  dynamic parser requires explicit `.max_value_len`; `std.StringArrayHashMap`
  is `std.StringArrayHashMapUnmanaged`.
- The bridge vault handlers (sections allowlist, magic-sniff import,
  error strings) were written in-session; vault.zig `applyImport` got the
  `owned`-flag fix for the toOwnedSlice UAF.

## 25. Session handover — 2026-08-06 (session 14): spec 18 SSH agent & jump hosts backend

Landed: the full spec-18 backend — `src/agent.zig` (resolveSocket via explicit/SSH_AUTH_SOCK, validateSocket with fstatat no-follow + own-uid, SHA256 fingerprint, 3 unit tests), `src/ssh.zig` (connectFd/handshake over fd, socketpair/close/write via cImport for Zig 0.16), `src/sessions.zig` (via/via_name/owner fields, jump_start op + JumpStartOutcome handoff, JumpTunnel pump with cascade close, forward_queue/active + ForwardSetOutcome, authAgentCallback proxy, audited `oars.agent.forward`), `src/servers.zig` (`AuthMethod.agent`), bridge `oars.agent.list` (no-agent → ok:true, identities:[], error:"no agent" per §5) + `oars.agent.forward` (handler_count 96→97). Jump failure reports hop name (§10), cycle detection at save time.

Bugs fixed this session: spec-18 dispatcher cycle test used `auth_method:"key"` without `key_path` → hit `"choose a private key file"` before via validation; changed to `password` and created `hop-b` first so forward reference is valid, then cycle is hit. Agent `validateSocket` bind failed on darwin due to missing `sun_len` and whole-struct `bind` length — fixed to set `sun_len` when present and use `@offsetOf(...,"sun_path")+len+1` (both `src/agent.zig` and `src/sessions.zig:connectAgentSocket`), plus `sys/un.h` in `src/ssh.zig`; test now degrades gracefully in sandboxes where `bind` is denied. Also fixed `sessions:connectAgentSocket` to use `ssh.c.sockaddr_un` correctly.

Validation: `ZIG_GLOBAL_CACHE_DIR=/tmp/zig-global-cache zig build test --global-cache-dir /tmp/zig-cache` → `180 pass / 1 fail (181 total)` for two consecutive runs (only pre-existing `sshkeys.generate` PTY flake remains, `No user exists for uid 501` in this sandbox, documented as `164/165 once`); `npm --prefix frontend run build` clean (vite 23 modules, 123ms). Two exports with same password differ in salt/nonce (spec 17) still holds.

Next: optional container jump-bastion integration test (spec 11 pattern: container A reachable only from B, connect via B, verify shell+exec) for real tunnel proof; no live ssh-agent fixture yet (agent auth needs an agent holding a key).
