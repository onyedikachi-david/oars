#!/usr/bin/env bash
# One-shot integration pass against the dockerized sshd.
# Brings the container up, runs `zig build test` with the OARS_TEST_SSH_*
# env vars exported (the env-gated integration tests in src/integration.zig
# skip unless they are set), and tears the container down afterwards.
#
# Usage: scripts/integration-test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/dev-sshd.sh" up
trap '"$SCRIPT_DIR/dev-sshd.sh" down' EXIT

set -a
# shellcheck disable=SC1091
source "$SCRIPT_DIR/.dev-sshd.env"
set +a

# The integration cases share one disposable remote host. Run one test at a
# time so account, key, process, and object-store mutations cannot overlap.
zig build -j1 test
