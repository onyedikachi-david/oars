#!/usr/bin/env bash
set -euo pipefail
# Only the three verified feed files enter this dedicated public branch.
FEEDS="$(cd "$1" && pwd)"
gh auth setup-git --hostname github.com
cd "$FEEDS"
git init --initial-branch=updates
git remote add origin "https://github.com/${GITHUB_REPOSITORY}.git"
if git ls-remote --exit-code origin refs/heads/updates >/dev/null 2>&1; then
  git fetch origin updates
  python3 - <<'PYCODE'
import json, pathlib, subprocess, xml.etree.ElementTree as ET
new = json.loads(pathlib.Path('latest.json').read_text())['version']
old = json.loads(subprocess.check_output(['git', 'show', 'FETCH_HEAD:latest.json']))['version']
version = lambda value: tuple(map(int, value.split('.')))
if version(new) < version(old):
    pathlib.Path('.skip-publication').touch()
    print('A newer update feed is already published; leaving it in place.')
elif new == old:
    for name in ('appcast-macos-arm64.xml', 'appcast-macos-x86_64.xml'):
        before = ET.fromstring(subprocess.check_output(['git', 'show', 'FETCH_HEAD:' + name])).find('./channel/item/enclosure')
        after = ET.parse(name).getroot().find('./channel/item/enclosure')
        key = '{http://www.andymatuschak.org/xml-namespaces/sparkle}edSignature'
        if before is None or after is None or before.get(key) != after.get(key):
            raise SystemExit('Refusing to replace an existing version with different archive bytes.')
PYCODE
  if [ -f .skip-publication ]; then exit 0; fi
  git reset --mixed FETCH_HEAD
fi
git add appcast-macos-arm64.xml appcast-macos-x86_64.xml latest.json
if git diff --cached --quiet; then exit 0; fi
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git commit -m 'chore: publish signed update feeds'
git push origin HEAD:updates
