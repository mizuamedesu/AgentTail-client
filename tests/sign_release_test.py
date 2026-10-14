#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify release signing with both PEM line endings and a mismatched key."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/sign-release.py"


class ReleaseSigningTests(unittest.TestCase):
    def test_public_key_pinning_and_signature(self):
        with tempfile.TemporaryDirectory(prefix="agenttail-signing-test-") as directory:
            root = Path(directory)
            trust = root / "internal/distribution/trusted.pub"
            trust.parent.mkdir(parents=True)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "agenttail-linux-amd64").write_bytes(b"public signing test artifact")
            keys = []
            for name in ("matching", "different"):
                key = root / (name + ".key")
                subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                key.chmod(0o600)
                keys.append(key)
            public = subprocess.check_output(["openssl", "pkey", "-in", str(keys[0]), "-pubout"]).replace(b"\r\n", b"\n")
            command = [sys.executable, str(SCRIPT), "--dir", str(artifacts), "--version", "0.0.0-test.1", "--sequence", "1"]
            for newline in (b"\n", b"\r\n"):
                with self.subTest(pem_newline=repr(newline)):
                    trust.write_bytes(public.replace(b"\n", newline))
                    result = subprocess.run(command + ["--key", str(keys[0])], cwd=root, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn(b"\r", (artifacts / "manifest.txt").read_bytes())
                    verified = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(trust), "-signature", str(artifacts / "manifest.sig"), str(artifacts / "manifest.txt")], capture_output=True)
                    self.assertEqual(verified.returncode, 0, "manifest signature did not verify")
                    (artifacts / "manifest.txt").unlink()
                    (artifacts / "manifest.sig").unlink()
            rejected = subprocess.run(command + ["--key", str(keys[1])], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("signing key does not match pinned trust key", rejected.stderr)
            self.assertFalse((artifacts / "manifest.txt").exists())
            self.assertFalse((artifacts / "manifest.sig").exists())


if __name__ == "__main__":
    unittest.main()
