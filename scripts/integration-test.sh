#!/usr/bin/env bash
# One-shot integration pass against the dockerized sshd.
# Brings the container up, runs `zig build test` with the OARS_TEST_SSH_*
# env vars exported (the env-gated integration tests in src/integration.zig
# skip unless they are set), and tears the container down afterwards.
#
# Usage: scripts/integration-test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

AGENT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/oars-test-agent.XXXXXX")"
cleanup() {
    if [ -n "${OARS_AGENT_PID:-}" ]; then kill "$OARS_AGENT_PID" >/dev/null 2>&1 || true; fi
    rm -rf "$AGENT_DIR"
    "$SCRIPT_DIR/dev-sshd.sh" down
}
trap cleanup EXIT
# A dedicated agent with one disposable key; never forward the user's agent.
eval "$(ssh-agent -a "$AGENT_DIR/socket" -s)" >/dev/null
OARS_AGENT_PID="$SSH_AGENT_PID"
ssh-keygen -q -t ed25519 -N '' -C oars-forward-test -f "$AGENT_DIR/key"
ssh-add "$AGENT_DIR/key" >/dev/null 2>&1
export OARS_TEST_AGENT=1
"$SCRIPT_DIR/dev-sshd.sh" up

set -a
# shellcheck disable=SC1091
source "$SCRIPT_DIR/.dev-sshd.env"
set +a

# The integration cases share one disposable remote host. Run one test at a
# time so account, key, process, and object-store mutations cannot overlap.
zig build -j1 test --summary all "$@"
