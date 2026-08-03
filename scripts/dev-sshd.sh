#!/usr/bin/env bash
# Development sshd container for Oars integration tests (spec 02 §11,
# spec 03 §11). Fixed test credentials only — never for real use.
#
# Usage:
#   scripts/dev-sshd.sh up      build + start, write scripts/.dev-sshd.env
#   scripts/dev-sshd.sh down    stop and remove the container
#   scripts/dev-sshd.sh status  print the container state
#   scripts/dev-sshd.sh env     print the connection env file
#
# The container listens on 127.0.0.1:2222 (override with OARS_DEV_SSHD_PORT).
# The generated ed25519 key is copied to scripts/.dev-sshd-key so the
# Zig integration tests can exercise the full key-auth path.
#
# Integration tests read the OARS_TEST_SSH_* variables; see
# scripts/integration-test.sh for the one-shot driver.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="oars-dev-sshd"
IMAGE="oars-dev-sshd"
PORT="${OARS_DEV_SSHD_PORT:-2222}"
ENV_FILE="$SCRIPT_DIR/.dev-sshd.env"
KEY_FILE="$SCRIPT_DIR/.dev-sshd-key"

up() {
    docker build -q -t "$IMAGE" "$SCRIPT_DIR/dev-sshd" >/dev/null
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" -p "127.0.0.1:$PORT:22" "$IMAGE" >/dev/null

    # Wait until sshd accepts TCP connections (30 s budget). A connect
    # probe is the honest readiness check: the process may be up while
    # the listener is still starting.
    deadline=$((SECONDS + 30))
    until (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; do
        if ((SECONDS >= deadline)); then
            echo "error: sshd did not accept connections in the container" >&2
            docker logs "$NAME" >&2 || true
            docker rm -f "$NAME" >/dev/null 2>&1 || true
            exit 1
        fi
        sleep 1
    done
    exec 3>&- 3<&-

    docker cp "$NAME:/root/.ssh/id_ed25519" "$KEY_FILE"
    chmod 600 "$KEY_FILE"

    {
        echo "OARS_TEST_SSH_HOST=127.0.0.1"
        echo "OARS_TEST_SSH_PORT=$PORT"
        echo "OARS_TEST_SSH_USER=root"
        echo "OARS_TEST_SSH_PASSWORD=oars-test-password"
        echo "OARS_TEST_SSH_KEY_PATH=$KEY_FILE"
        echo "OARS_TEST_SSH_PASSPHRASE=oars-test-passphrase"
    } > "$ENV_FILE"

    echo "dev sshd up: 127.0.0.1:$PORT (root / oars-test-password; key $KEY_FILE)"
    echo "connection env: $ENV_FILE"
}

down() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "dev sshd down"
}

status() {
    docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null || echo "not running"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    env) cat "$ENV_FILE" ;;
    *)
        echo "usage: $0 up|down|status|env" >&2
        exit 1
        ;;
esac
