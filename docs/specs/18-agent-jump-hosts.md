# Spec 18 — SSH Agent & Jump Hosts

**Status:** 📋 · **Depends on:** 02, 12 (tunnel machinery) · **Spec owner:** core

## 1. Overview

Two connection superpowers for real fleets: authenticate through the
user's **SSH agent** (so an already-unlocked key can be reused), and
reach servers **behind bastions** (jump hosts) by chaining tunnels. Both
reuse machinery we already have: libssh2 agent support for the former,
the direct-tcpip tunnel from spec 12 for the latter.

## 2. Goals / non-goals

**Goals**
- Agent auth: use keys held by the local ssh-agent through `SSH_AUTH_SOCK` or
  an explicit user-selected socket, with an identity list in the connect
  dialog.
- Agent forwarding through libssh2's auth-agent request plus an explicit proxy
  from accepted auth-agent channels to the configured local agent socket.
- Jump hosts: `Server.via_server_id` → connect to the jump first, then tunnel
  `target:22` through it and run the target session over the tunnel.
- Jump chains (jump → jump → target) up to depth 3.

**Non-goals**
- No agent management UI (adding keys to the agent is the OS's job), no
  proxy-command-style config generation, no dynamic (SSH config) host
  resolution (v1).

## 3. User stories

- My key lives in the agent (added once, passphrase unlocked): connecting to any server just works.
- My DB box is only reachable via `bastion`: I set the jump host once; Oars chains automatically.
- I need `ssh-add -L`-style visibility of what the agent offers before choosing.

## 4. UI/UX

### 4.1 Connect dialog additions (server modal + connect flow)
- Auth method gains a third option: **SSH agent** (shows agent identities from
  `oars.agent.list`; default = Automatic, which tries agent identities in
  order, with an optional exact identity selection).
- Server modal gains: **Jump host** select (other servers) — "connect via" with depth indicator (jump → target).

### 4.2 Status
- Session header shows the chain when applicable: `bastion → db-prod`; agent auth shows `auth · agent (ssh-ed25519 SHA256:ab12…)` (parity with CtrlOps's connection detail line, but truthful).

## 5. Bridge API

### `oars.agent.list` → `{ok, identities:[{type, fingerprint_sha256, comment}]}`
- Via `SSH_AUTH_SOCK` (macOS: ssh-agent or Keychain-agent path); missing agent → `{ok, identities: [], error:"no agent"}` (not a failure).
### `oars.agent.forward` `{server_id, on: bool}` → enables forwarding for a new shell channel
- `libssh2_channel_request_auth_agent(channel)` requests forwarding. Oars must
  also register the libssh2 auth-agent callback, accept each incoming
  `auth-agent@openssh.com` channel, and proxy its bytes to the selected local
  agent socket. The request alone does not complete that data path.
- Forwarding is set when a shell channel is created. Turning it off closes the
  forwarding-capable shell and opens a new shell without the request; it is not
  a simple live toggle on an existing remote listener.
- Audited when enabled; failure surfaces as "agent forwarding
  refused" with the sshd policy hint, toggle returns to off.
### `oars.ssh.connect` gains `{auth_method:"agent"}` and `{via_server_id?}` (jump chain)

## 6. Zig core design

- **Agent auth** (`src/agent.zig`): libssh2 agent API
  (`libssh2_agent_init`, `libssh2_agent_connect`,
  `libssh2_agent_list_identities`, `libssh2_agent_userauth`). Use
  `SSH_AUTH_SOCK` or an explicit user-selected socket path. Do not scan
  `$TMPDIR` for sockets: stale or attacker-created paths can select the wrong
  agent.
- **Agent forwarding proxy:** register `LIBSSH2_CALLBACK_AUTHAGENT`, queue
  accepted channels to the session worker, connect only to the already
  validated local agent socket, and copy bounded protocol frames in both
  directions. `libssh2_channel_direct_streamlocal_ex` opens a remote Unix
  socket and is not the agent-forwarding mechanism.
- **Jump hosts** (reuses spec 12 tunnel): connect to the jump server
  recursively (depth ≤ 3), then open `direct_tcpip` to the target. Bridge the
  channel to an owner-only local Unix socket on macOS/Linux. If a platform must
  use `127.0.0.1:0`, require a random one-use capability handshake before any
  SSH bytes pass, so an unrelated local process cannot claim the listener. The
  target worker connects through that authenticated local hop and gives the
  resulting stream to libssh2. The target holds the tunnel reference;
  disconnecting a jump cascades a clear close state to dependants.
- `Session` gains `via: ?*Session` (owned ref) + `depth`; the manager builds the chain graph and validates cycles.

## 7. Data model

- `Server.via_server_id: ?string` (new field in servers.json; export/import carries it — spec 17).
- Agent state is ephemeral (OS-owned).

## 8. Security

- Agent auth leaves private-key operations in the selected agent. Oars receives
  public identities and signatures, but it does not read the private key.
- Validate that the selected agent path is a Unix socket owned by the current
  user before connecting. A locked key or an agent key constrained with
  confirmation can still require OS/user interaction; Oars does not bypass it.
- Jump hosts: credentials for the jump are the user's own; traffic to the target is double-encrypted (target SSH inside jump SSH).
- Forwarding is opt-in per session (toggle), audited when enabled.
- Chain cycle detection prevents self-referential jumps.

## 9. Performance

- Chain connect is bounded per hop after DNS/TCP cancellation is fixed in spec
  02. Measure added latency; do not promise a sub-millisecond tunnel cost.

## 10. Edge cases

- Agent socket missing/stale → explicit error with `ssh-agent` / `ssh-add` hint
  and an option to select a socket. No directory scan fallback.
- Agent key is locked or confirmation-constrained → surface the agent result
  and let the OS agent complete its normal approval flow where available.
- Jump host down → target session error says which hop failed ("bastion unreachable").
- Cycle in config (A via B via A) → validation error at save time.
- Agent has multiple identities → Automatic tries them in agent order; an
  exact selection tries only that fingerprint and surfaces its auth error.
- Jump host's own auth is password → works (its session is a normal session).

## 11. Testing

- Unit: chain resolution + cycle detection, agent socket path resolution fixtures.
- Integration: container A (target) reachable only from container B (jump) — docker network without published ports for A; connect via B; verify shell + exec; agent auth tested against a local ssh-agent (`ssh-agent` + `ssh-add` fixture key) in CI if available, else manual.

## 12. Acceptance criteria

- [ ] Agent auth works when an agent holds the key (macOS + Linux).
- [ ] Jump chain (depth 2, then 3) connects, shells, and execs.
- [ ] Cycle configs are rejected at save.
- [ ] Jump failure reports the failing hop.
- [ ] Forwarding toggle is opt-in, audited, and degrades gracefully when unsupported.

## 13. Research & References

- **libssh2 agent API** — verified against the vendored header
  `third_party/libssh2/include/libssh2.h`: `libssh2_agent_init` L1352,
  `libssh2_agent_list_identities` L1372, `libssh2_agent_userauth`
  L1400 (agent-initiated public-key auth: the private key never
  touches Oars — matches §8's "best-case posture").
- **Agent forwarding request — API verified, proxy still required.**
  `libssh2_channel_request_auth_agent(LIBSSH2_CHANNEL *)` is confirmed
  in `libssh2.h` (declared immediately before
  `libssh2_channel_request_pty_ex`, L879–886 region) **and used by
  libssh2's own upstream code**: `example/ssh2_agent_forwarding.c`
  L212–216 (loop on `LIBSSH2_ERROR_EAGAIN`) and
  `tests/test_agent_forward_ok.c` L47–51, both vendored in
  `third_party/libssh2/`. This sends the request, but vendored
  `packet.c` only accepts an incoming agent channel when
  `session->authagent` is registered and then calls that callback. The spec now
  includes the required local-socket proxy instead of treating the request as
  a complete implementation.
- **SSH agent environment** — `SSH_AUTH_SOCK` "identifies the path of
  a Unix-domain socket used to communicate with the agent" (OpenSSH
  `ssh(1)` ENVIRONMENT section, `https://man.openbsd.org/ssh.1`);
  `ssh-add -L` prints agent-held public keys (`ssh-add(1)`, same
  manpage family) — the identity list for the connect dialog.
- **Agent forwarding semantics & caution** — `ssh -A` "enables
  forwarding of connections from an authentication agent"; the man
  page's warning is the exact rationale for §8's opt-in toggle:
  "Users with the ability to bypass file permissions on the remote
  host… can access the local agent through the forwarded connection…
  they can perform operations on the keys that enable them to
  authenticate using the identities loaded into the agent. A safer
  alternative may be to use a jump host (see -J)." Server-side
  gating: `AllowAgentForwarding` (sshd_config(5)) and the
  `no-agent-forwarding` authorized_keys option (sshd(8), spec 08 §13).
- **Jump hosts** — `ssh -J destination` "connect to the target host by
  first making an ssh connection to the jump host… Multiple jump hops
  may be specified separated by comma characters" (ssh(1), `-J`
  option) — the CLI analog of our chain design (depth ≤ 3 matches the
  documented comma-separated multi-hop model). Our implementation
  reuses `libssh2_channel_direct_tcpip_ex` (libssh2.h L850–854, with
  the convenience macro L852) — the same tunnel primitive spec 12
  uses; traffic to the target is double-encrypted (target SSH inside
  jump SSH, §8).
- **Agent discovery correction** — `SSH_AUTH_SOCK` identifies the agent socket.
  A path can also be selected explicitly. OpenSSH documentation does not make
  arbitrary `$TMPDIR/ssh-*` scanning an authentication rule, and such a scan
  can select a stale or hostile socket, so it was removed.
- **Cycle detection** — `Server.via_server_id` graph: reject cycles at
  save (a via-chain must be a DAG); this is plain graph validation,
  no external reference needed.

Sources: `third_party/libssh2/include/libssh2.h`, OpenBSD ssh(1)/sshd(8),
ssh-agent(1), spec 12 §13.
