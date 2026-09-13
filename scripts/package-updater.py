"""Embed Sparkle and its pinned trust configuration before release archiving."""
import base64
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

app, sparkle, arch = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
if arch not in ("arm64", "x86_64"):
    raise SystemExit("Unsupported update architecture")
key = (Path(__file__).resolve().parents[1] / "updates/public-key.ed25519").read_text().strip()
if len(base64.b64decode(key, validate=True)) != 32:
    raise SystemExit("Invalid Sparkle public key")
destination = app / "Contents/Frameworks/Sparkle.framework"
if destination.exists():
    shutil.rmtree(destination)
destination.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(["ditto", str(sparkle / "Sparkle.framework"), str(destination)], check=True)
plist = app / "Contents/Info.plist"
info = plistlib.loads(plist.read_bytes())
info.update({
    "SUFeedURL": f"https://raw.githubusercontent.com/onyedikachi-david/oars/updates/appcast-macos-{arch}.xml",
    "SUPublicEDKey": key,
    "SUEnableAutomaticChecks": True,
    "SUAutomaticallyUpdate": True,
    "SUEnableSystemProfiling": False,
    "SUVerifyUpdateBeforeExtraction": True,
    "SURequireSignedFeed": True,
})
plist.write_bytes(plistlib.dumps(info))
print(f"Embedded Sparkle for {arch} with signed-feed and archive verification.")
