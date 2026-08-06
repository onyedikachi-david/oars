#!/usr/bin/env bash
# Development sshd container for Oars integration tests (spec 02 §11,
# spec 03 §11). Fixed test credentials only — never for real use.
#
# Usage:
#   scripts/dev-sshd.sh up      build + start, write scripts/.dev-sshd.env
#   scripts/dev-sshd.sh down    stop and remove the containers
#   scripts/dev-sshd.sh status  print the container state
#   scripts/dev-sshd.sh env     print the connection env file
#
# The container listens on 127.0.0.1:2222 (override with OARS_DEV_SSHD_PORT).
# The generated ed25519 key is copied to scripts/.dev-sshd-key so the
# Zig integration tests can exercise the full key-auth path.
#
# Spec 10 adds a second container, oars-dev-minio (minio/minio), on the
# shared oars-dev-net network. The sshd container reaches it as
# http://oars-dev-minio:9000 — the endpoint the backup integration tests
# write into job configs.
#
# Integration tests read the OARS_TEST_SSH_* and OARS_TEST_MINIO_*
# variables; see scripts/integration-test.sh for the one-shot driver.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="oars-dev-sshd"
IMAGE="oars-dev-sshd"
NETWORK="oars-dev-net"
MINIO_NAME="oars-dev-minio"
MINIO_IMAGE="minio/minio"
PORT="${OARS_DEV_SSHD_PORT:-2222}"
MINIO_PORT="${OARS_DEV_MINIO_PORT:-9000}"
ENV_FILE="$SCRIPT_DIR/.dev-sshd.env"
KEY_FILE="$SCRIPT_DIR/.dev-sshd-key"

up() {
    docker network create "$NETWORK" >/dev/null 2>&1 || true
    docker build -q -t "$IMAGE" "$SCRIPT_DIR/dev-sshd" >/dev/null
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --network "$NETWORK" -p "127.0.0.1:$PORT:22" "$IMAGE" >/dev/null

    docker rm -f "$MINIO_NAME" >/dev/null 2>&1 || true
    docker run -d --name "$MINIO_NAME" --network "$NETWORK" -p "127.0.0.1:$MINIO_PORT:9000" \
        -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
        "$MINIO_IMAGE" server /data >/dev/null

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

    # MinIO readiness: the S3 API is live once /minio/health/live returns 200.
    deadline=$((SECONDS + 60))
    until curl -fsS "http://127.0.0.1:$MINIO_PORT/minio/health/live" >/dev/null 2>&1; do
        if ((SECONDS >= deadline)); then
            echo "error: MinIO did not become ready" >&2
            docker logs "$MINIO_NAME" >&2 || true
            docker rm -f "$MINIO_NAME" >/dev/null 2>&1 || true
            exit 1
        fi
        sleep 1
    done

    docker cp "$NAME:/root/.ssh/id_ed25519" "$KEY_FILE"
    chmod 600 "$KEY_FILE"

    {
        echo "OARS_TEST_SSH_HOST=127.0.0.1"
        echo "OARS_TEST_SSH_PORT=$PORT"
        echo "OARS_TEST_SSH_USER=root"
        echo "OARS_TEST_SSH_PASSWORD=oars-test-password"
        echo "OARS_TEST_SSH_KEY_PATH=$KEY_FILE"
        echo "OARS_TEST_SSH_PASSPHRASE=oars-test-passphrase"
        echo "OARS_TEST_MINIO_ENDPOINT=http://oars-dev-minio:9000"
        echo "OARS_TEST_MINIO_ACCESS=minioadmin"
        echo "OARS_TEST_MINIO_SECRET=minioadmin"
    } > "$ENV_FILE"

    echo "dev sshd up: 127.0.0.1:$PORT (root / oars-test-password; key $KEY_FILE)"
    echo "dev minio up: 127.0.0.1:$MINIO_PORT (minioadmin / minioadmin; endpoint http://oars-dev-minio:9000)"
    echo "connection env: $ENV_FILE"
}

down() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker rm -f "$MINIO_NAME" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
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
