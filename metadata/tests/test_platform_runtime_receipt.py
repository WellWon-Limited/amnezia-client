from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "metadata" / "check_platform_runtime_receipt.py"


class PlatformRuntimeReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"],
            text=True,
        ).strip()

    def make_receipt(
        self, *, zero_digest: bool = False, extra_root_key: bool = False
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
        digest_a = "0" * 64 if zero_digest else "1" * 64
        document: dict[str, object] = {
            "schema": 1,
            "source_commit": self.commit,
            "platforms": {
                "ios": {
                    "awg": {
                        "artifact_matrix": "passed",
                        "exact_lifecycle": "passed",
                        "route_leak_matrix": "passed",
                        "device_receipt_sha256": digest_a,
                    },
                    "xray": {
                        "artifact_matrix": "passed",
                        "exact_lifecycle": "passed",
                        "route_leak_matrix": "passed",
                        "device_receipt_sha256": "2" * 64,
                    },
                }
            },
        }
        if extra_root_key:
            document["unsigned_note"] = "must be rejected"
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "receipt.json"
        raw = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
        path.write_bytes(raw)
        return directory, path, hashlib.sha256(raw).hexdigest()

    def run_checker(
        self, path: Path, digest: str, platform: str = "ios"
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--file",
                str(path),
                "--sha256",
                digest,
                "--platform",
                platform,
                "--source-root",
                str(ROOT),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_accepts_exact_commit_bound_dual_transport_receipt(self) -> None:
        directory, path, digest = self.make_receipt()
        self.addCleanup(directory.cleanup)
        result = self.run_checker(path, digest)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("receipt OK for ios", result.stdout)

    def test_rejects_wrong_hash_and_wrong_platform(self) -> None:
        directory, path, digest = self.make_receipt()
        self.addCleanup(directory.cleanup)
        wrong_hash = ("0" if digest[0] != "0" else "1") + digest[1:]
        result = self.run_checker(path, wrong_hash)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stdout)
        result = self.run_checker(path, digest, "android")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required platform 'android' is absent", result.stdout)

    def test_rejects_placeholder_evidence_digest(self) -> None:
        directory, path, digest = self.make_receipt(zero_digest=True)
        self.addCleanup(directory.cleanup)
        result = self.run_checker(path, digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a real evidence digest", result.stdout)

    def test_rejects_unsigned_extension_fields(self) -> None:
        directory, path, digest = self.make_receipt(extra_root_key=True)
        self.addCleanup(directory.cleanup)
        result = self.run_checker(path, digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root key mismatch", result.stdout)


if __name__ == "__main__":
    unittest.main()
