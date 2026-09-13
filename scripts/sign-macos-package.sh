#!/usr/bin/env bash
set -euo pipefail
APP="$1"
# Optional Developer ID signing; archive authentication always uses Ed25519.
if [ -z "${OARS_SIGNING_IDENTITY:-}" ]; then
  codesign --force --sign - "$APP"
  codesign --verify --deep --strict "$APP"
  echo 'Applied ad-hoc bundle signing for integrity; this package is not Developer ID signed or notarized.'
  exit 0
fi
FRAMEWORK="$APP/Contents/Frameworks/Sparkle.framework/Versions/B"
for TARGET in "$FRAMEWORK/XPCServices/Downloader.xpc" "$FRAMEWORK/XPCServices/Installer.xpc" "$FRAMEWORK/Autoupdate" "$FRAMEWORK/Updater.app" "$APP/Contents/Frameworks/Sparkle.framework" "$APP"; do
  if [ -e "$TARGET" ]; then
    codesign --force --timestamp --options runtime --preserve-metadata=entitlements --sign "$OARS_SIGNING_IDENTITY" "$TARGET"
  fi
done
codesign --verify --deep --strict "$APP"
if [ -n "${OARS_NOTARY_PROFILE:-}" ]; then
  TEMP="$(mktemp -d)"
  trap 'rm -rf "$TEMP"' EXIT
  ditto -c -k --sequesterRsrc --keepParent "$APP" "$TEMP/Oars.zip"
  xcrun notarytool submit "$TEMP/Oars.zip" --keychain-profile "$OARS_NOTARY_PROFILE" --wait --timeout 15m
  xcrun stapler staple "$APP"
fi
