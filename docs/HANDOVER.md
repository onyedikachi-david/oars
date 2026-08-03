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
