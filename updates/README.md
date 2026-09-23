# Oars application updates

macOS release builds embed Sparkle 2.9.6. Settings → Updates controls automatic checks and background downloads. Oars presents a version-change dialog with release notes from the signed feed. A compact progress notice shows real download progress and allows cancellation before extraction. Sparkle owns archive verification and installation through a custom user driver. “Install and restart” is available when work is idle. “Install when idle” downloads as needed and schedules a restart in the native process, even after the dialog closes. Users can cancel that schedule. Update-triggered restarts wait for sessions, transfers, key operations, access operations, backups, and AI work to finish. A prepared update does not block an ordinary user-requested quit; Sparkle can install it on quit. A failed or canceled installation releases the restart reservation.

Linux builds check for new releases and show a notification. Homebrew installations display the Homebrew upgrade command; archive installations link to the fixed Oars releases page. Oars never rewrites the Linux Homebrew Caskroom or executes commands obtained from a feed. Checks use a bounded asynchronous request and run only while Oars is open.

Versions before this updater was introduced need one normal download or Homebrew upgrade to receive it.

## Signing and publication

`public-key.ed25519` is the public trust key embedded in release bundles. Its private key is stored in the macOS Keychain under account `app.getoars` and in the repository's `SPARKLE_PRIVATE_KEY` Actions secret. Keep a secure backup of the private key. Do not generate a replacement key casually: installed clients trust the existing key. Follow Sparkle's key-rotation procedure if a rotation is needed.

The release workflow builds and tests every package, uploads the archives and checksums, then generates signed feeds. Sparkle verifies the archive before extraction and verifies the feed. The publisher embeds the matching CHANGELOG.md release section as bounded plain text before signing each Mac feed. The UI never renders feed HTML. The publisher updates these files together on the `updates` branch:

- `appcast-macos-arm64.xml`
- `appcast-macos-x86_64.xml`
- `latest.json` (Linux notifications only; it contains no executable URL or command)

A missing signing secret, incomplete release, checksum mismatch, or unsigned generated archive stops feed publication. The application never accepts an update merely because its checksum matches.

Apple Developer ID signing is separate from Ed25519 update signing. Builds without a Developer ID identity receive ad-hoc bundle signing for integrity and remain unnotarized. On a signing machine with the identity and notary profile already in its Keychain, run after embedding Sparkle and before making the release ZIP:

```sh
OARS_SIGNING_IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' \
OARS_NOTARY_PROFILE='oars-notary' \
  bash scripts/sign-macos-package.sh path/to/Oars.app
```

The GitHub-hosted runners currently have no Developer ID identity or notary credentials. Configure those before enabling Developer ID signing there. Do not put certificate files or private update keys in this repository.

## Local build and verification

```sh
SPARKLE_PATH="$(bash scripts/fetch-sparkle.sh)"
zig build package -Dpackage-target=macos -Dsparkle-path="$SPARKLE_PATH" -Dnative-sdk-path=/path/to/native-sdk
python3 scripts/package-updater.py zig-out/package/oars-VERSION-macos-ReleaseFast.app "$SPARKLE_PATH" arm64
bash scripts/sign-macos-package.sh zig-out/package/oars-VERSION-macos-ReleaseFast.app
python3 scripts/test-updater-macos.py "$SPARKLE_PATH"
```

Use `x86_64` when packaging an Intel build. The fetch script verifies the pinned Sparkle archive and extracts a fresh copy before executing its tools. Plain macOS development builds without `-Dsparkle-path` keep the updater unavailable.

The macOS integration test uses temporary application bundles, a temporary signing key, and a loopback feed. It proves that a modified archive is rejected, busy work blocks installation, and a verified update installs and relaunches after the restart gate allows it. The loopback HTTP exception exists only in the temporary test bundles. The test does not use the release private key or modify an installed Oars app.

## UI preview

Run `npm --prefix frontend run dev` and open `/preview.html?updates=available`.
The browser-only fixtures also accept `downloading`, `verifying`, `busy`, and
`scheduled`. These use simulated versions and notes and cannot install anything.
The production app does not import this preview code.
