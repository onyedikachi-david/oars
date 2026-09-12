#!/usr/bin/env bash
# Allow only this CI executable to create WebKitGTK's sandbox namespaces.
set -euo pipefail

if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || true)" != 1 ]; then
  exit 0
fi

OARS_SMOKE_BINARY="$(readlink -f "$1")"
case "$OARS_SMOKE_BINARY" in
  *\"*|*\\*) echo 'Unsupported executable path for AppArmor' >&2; exit 1 ;;
esac
sudo tee /etc/apparmor.d/oars-package-smoke >/dev/null <<EOF
abi <abi/4.0>,
include <tunables/global>
profile oars-package-smoke "$OARS_SMOKE_BINARY" flags=(unconfined) {
  userns,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/oars-package-smoke
