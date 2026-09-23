"""Generate authenticated Sparkle feeds only from complete release artifacts."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET


def assert_signing_key(sparkle, key, expected_public):
    """Derive the key with Sparkle itself, then compare the embedded trust root."""
    decoded = base64.b64decode(key.strip(), validate=True)
    if len(decoded) not in (32, 64):
        raise ValueError("Invalid update signing key")
    account = "app.getoars.sign-check." + uuid.uuid4().hex
    try:
        with tempfile.TemporaryDirectory(prefix="oars-key-check-") as directory:
            private = Path(directory) / "key"
            private.write_text(key)
            private.chmod(0o600)
            subprocess.run([str(sparkle / "bin/generate_keys"), "--account", account, "-f", str(private)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            public = subprocess.check_output([str(sparkle / "bin/generate_keys"), "--account", account, "-p"], text=True).strip()
            if public != expected_public.strip():
                raise ValueError("SPARKLE_PRIVATE_KEY does not match the app's embedded public key")
    finally:
        subprocess.run(["security", "delete-generic-password", "-a", account], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def generate(assets, sparkle, output, version, key):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Expected a stable release version")
    if not key.strip():
        raise ValueError("SPARKLE_PRIVATE_KEY is required to publish updates")
    expected = [f"oars-v{version}-{suffix}" for suffix in ("macos.zip", "macos-x86_64.zip", "linux-x86_64.tar.gz")]
    sums = {}
    for line in (assets / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(None, 1)
        if name in sums:
            raise ValueError("Duplicate release checksum")
        sums[name] = digest
    for name in expected:
        if hashlib.sha256((assets / name).read_bytes()).hexdigest() != sums.get(name):
            raise ValueError(f"Release checksum mismatch: {name}")
    assert_signing_key(sparkle, key, (Path(__file__).resolve().parents[1] / "updates/public-key.ed25519").read_text())
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="oars-appcast-") as directory:
        for arch, name in zip(("arm64", "x86_64"), expected[:2]):
            stage = Path(directory) / arch
            stage.mkdir()
            shutil.copy2(assets / name, stage / name)
            feed = output / f"appcast-macos-{arch}.xml"
            subprocess.run([str(sparkle / "bin/generate_appcast"), "--ed-key-file", "-",
                            "--download-url-prefix", f"https://github.com/onyedikachi-david/oars/releases/download/v{version}/",
                            "-o", str(feed.resolve()), str(stage)], input=key, text=True, check=True)
            root = ET.parse(feed).getroot()
            enclosures = root.findall("./channel/item/enclosure")
            if len(enclosures) != 1 or not enclosures[0].get("{http://www.andymatuschak.org/xml-namespaces/sparkle}edSignature"):
                raise ValueError("Sparkle did not sign the update archive; check the signing key")
            # Verify the signed feed with Sparkle's own tool before publishing it.
            subprocess.run([str(sparkle / "bin/sign_update"), "--verify", "--ed-key-file", "-", str(feed)],
                           input=key, text=True, check=True)
    (output / "latest.json").write_text(json.dumps({"schema_version": 1, "version": version}) + "\n")


if __name__ == "__main__":
    generate(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], os.environ.get("SPARKLE_PRIVATE_KEY", ""))
