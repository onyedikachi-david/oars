#!/usr/bin/env bash
set -euo pipefail
# Pinned distribution: verifies the download before any tool is executed.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-$ROOT/.zig-cache/sparkle/2.9.6}"
ARCHIVE="$DEST/Sparkle-2.9.6.tar.xz"
SHA=52bf9e88cdd972fc0c81501377a880e90d47031bd8ca5462488f843e2609e192
mkdir -p "$DEST"
if ! printf '%s  %s\n' "$SHA" "$ARCHIVE" | shasum -a 256 -c - >/dev/null 2>&1; then
  curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 \
    https://github.com/sparkle-project/Sparkle/releases/download/2.9.6/Sparkle-2.9.6.tar.xz -o "$ARCHIVE.tmp"
  printf '%s  %s\n' "$SHA" "$ARCHIVE.tmp" | shasum -a 256 -c - >&2
  mv "$ARCHIVE.tmp" "$ARCHIVE"
fi
# Never execute tools from an unverified, previously extracted directory.
VERIFIED="$(mktemp -d "$DEST/verified.XXXXXX")"
tar -xJf "$ARCHIVE" -C "$VERIFIED"
printf '%s\n' "$VERIFIED"
