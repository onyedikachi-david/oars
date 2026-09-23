import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("feeds", Path(__file__).with_name("generate-update-feeds.py"))
feeds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feeds)

class FeedPublicationTests(unittest.TestCase):
    def test_requires_stable_version_and_signing_key(self):
        with self.assertRaisesRegex(ValueError, "stable"):
            feeds.generate(Path("missing"), Path("missing"), Path("missing"), "0.7.0-beta", "key")
        with self.assertRaisesRegex(ValueError, "SPARKLE_PRIVATE_KEY"):
            feeds.generate(Path("missing"), Path("missing"), Path("missing"), "0.7.0", "")

    def test_checks_every_package_before_generating_any_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ["oars-v0.7.0-" + suffix for suffix in ("macos.zip", "macos-x86_64.zip", "linux-x86_64.tar.gz")]
            digest = hashlib.sha256(b"original").hexdigest()
            for name in names:
                (root / name).write_bytes(b"original")
            (root / names[-1]).write_bytes(b"changed")
            (root / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name in names))
            output = root / "feeds"
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                feeds.generate(root, root, output, "0.7.0", "not-a-real-key")
            self.assertFalse(output.exists())

    def test_rejects_ambiguous_checksum_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SHA256SUMS").write_text("a  app.zip\nb  app.zip\n")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                feeds.generate(root, root, root / "feeds", "0.7.0", "not-a-real-key")

if __name__ == "__main__":
    unittest.main()
