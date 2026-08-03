# Spec 18 — SSH Agent & Jump Hosts

**Status:** 📋 · **Depends on:** 02, 12 (tunnel machinery) · **Spec owner:** core

## 1. Overview

Two connection superpowers for real fleets: authenticate through the
user's **SSH agent** (so keys with passphrases never need re-entry), and
reach servers **behind bastions** (jump hosts) by chaining tunnels. Both
reuse machinery we already have: libssh2 agent support for the former,
the direct-tcpip tunnel from spec 12 for the latter.

## 2. Goals / non-goals

**Goals**
- Agent auth: use keys held by the local ssh-agent (via `SSH_AUTH_SOCK` / `~/.ssh/agent.sock`), with agent identity list in the connect dialog.
- Agent forwarding (remote agent access) via `libssh2_channel_direct_streamlocal_ex` (later refinement).
- Jump hosts: `Server.jump_server_id` → connect to the jump first, then tunnel `target:22` through it and run the session over the tunnel.
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
- Auth method gains a third option: **SSH agent** (shows agent identities from `oars.agent.list`; default = first identity).
- Server modal gains: **Jump host** select (other servers) — "connect via" with depth indicator (jump → target).

### 4.2 Status
- Session header shows the chain when applicable: `bastion → db-prod`; agent auth shows `auth · agent (ssh-ed25519 SHA256:ab12…)` (parity with CtrlOps's connection detail line, but truthful).

## 5. Bridge API

### `oars.agent.list` → `{ok, identities:[{type, fingerprint_sha256, comment}]}`
- Via `SSH_AUTH_SOCK` (macOS: ssh-agent or Keychain-agent path); missing agent → `{ok, identities: [], error:"no agent"}` (not a failure).
### `oars.agent.forward` `{server_id, on: bool}` → toggles `AgentForwarding` on the session (request via channel `auth-agent-req@openssh.com` — libssh2 exposes `libssh2_channel_forward_agent`? — pending: implement via `libssh2_channel_request_auth_agent`? Verify at build; else shell `ssh -A`-style not available — **fallback:** mark unsupported in this build if libssh2 lacks the API, surface as disabled toggle).
### `oars.ssh.connect` gains `{auth_method:"agent"}` and `{via_server_id?}` (jump chain)

## 6. Zig core design

- **Agent auth** (`src/agent.zig`): libssh2 agent API (`libssh2_agent_init`, `libssh2_agent_list_identities`, `libssh2_agent_userauth`); socket path resolution (env `SSH_AUTH_SOCK`, fallback `~/.ssh/agent.sock`, macOS `$TMPDIR/ssh-*/agent.*` scan); auth happens on the session worker like other methods.
- **Jump hosts** (reuses spec 12 tunnel): connect to jump server (recursively, depth ≤ 3) → on its session worker, open `direct_tcpip(jump, target_host, 22, …)` → bridge to a local `127.0.0.1:0` listener → the *target* session's worker connects `std.Io.net` to that local port and hands the fd to libssh2. Chain lifecycle: target session holds the tunnel; disconnecting the jump tears down dependents (cascade close with clear status).
- `Session` gains `via: ?*Session` (owned ref) + `depth`; the manager builds the chain graph and validates cycles.

## 7. Data model

- `Server.via_server_id: ?string` (new field in servers.json; export/import carries it — spec 17).
- Agent state is ephemeral (OS-owned).

## 8. Security

- Agent auth means the private key never touches Oars at all — best-case posture; document it as such.
- Jump hosts: credentials for the jump are the user's own; traffic to the target is double-encrypted (target SSH inside jump SSH).
- Forwarding is opt-in per session (toggle), audited when enabled.
- Chain cycle detection prevents self-referential jumps.

## 9. Performance

- Chain connect = sum of hops (each ≤ 20 s timeout); local tunnel hop adds < 1 ms latency.

## 10. Edge cases

- Agent socket missing/stale → explicit error with "start ssh-agent / ssh-add" hint.
- Jump host down → target session error says which hop failed ("bastion unreachable").
- Cycle in config (A via B via A) → validation error at save time.
- Agent has multiple identities → picker defaults to first; wrong identity → auth fails with agent error text.
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
