from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "metadata" / "check_macos_engine_artifact.py"
SPEC = importlib.util.spec_from_file_location("check_macos_engine_artifact", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class MacosEngineArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock = json.loads((ROOT / "metadata" / "engine-lock.json").read_text())

    def manifest(self) -> dict:
        awg = self.lock["engines"]["awg-go"]
        xray = self.lock["engines"]["amnezia-xray-bindings"]
        return {
            "type": "engine_manifest_v1",
            "schema": 1,
            "app": {"version": "5.1.68.97", "build": 97},
            "engines": [
                {
                    "protocol": "awg",
                    "adapter": "awg-go",
                    "adapterVersion": awg["conan_version"],
                    "declaredCoreVersion": awg["conan_version"],
                    "sourceCommit": awg["source_commit"],
                    "abi": awg["abi"],
                    "runtimeCoreVersion": None,
                    "runtimeVersionProbed": False,
                    "versionEvidence": "compile_time_lock_plus_artifact_probe",
                    "capabilities": awg["capabilities"],
                },
                {
                    "protocol": "xray",
                    "adapter": "amnezia-xray-bindings",
                    "adapterVersion": xray["conan_version"],
                    "declaredCoreVersion": xray["embedded_xray_core"],
                    "sourceCommit": xray["source_commit"],
                    "abi": xray["abi"],
                    "runtimeCoreVersion": None,
                    "runtimeVersionProbed": False,
                    "versionEvidence": "compile_time_lock_plus_linked_symbol_probe",
                    "capabilities": xray["capabilities"],
                },
            ],
        }

    def test_exact_manifest_matches_lock_and_staged_version(self) -> None:
        checker.check_manifest(
            self.manifest(), self.lock,
            {"CFBundleShortVersionString": "5.1.68", "CFBundleVersion": "97"},
        )

    def test_extra_key_and_engine_drift_fail_closed(self) -> None:
        extra = self.manifest()
        extra["unexpected"] = True
        with self.assertRaises(SystemExit):
            checker.check_manifest(
                extra, self.lock,
                {"CFBundleShortVersionString": "5.1.68", "CFBundleVersion": "97"},
            )

        drift = self.manifest()
        drift["engines"][1]["declaredCoreVersion"] = "future-unlocked-core"
        with self.assertRaises(SystemExit):
            checker.check_manifest(
                drift, self.lock,
                {"CFBundleShortVersionString": "5.1.68", "CFBundleVersion": "97"},
            )

    def test_duplicate_json_key_fails_closed(self) -> None:
        with self.assertRaises(SystemExit):
            json.loads('{"schema":1,"schema":2}',
                       object_pairs_hook=checker.unique_object_pairs)

    @unittest.skipUnless(sys.platform == "darwin", "macOS sandbox contract")
    def test_sandbox_denies_write_and_network_side_effects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tribe-engine-sandbox-test.") as temporary:
            audit_root = Path(temporary)
            for directory in ("home", "tmp", "cache", "config", "data"):
                (audit_root / directory).mkdir(mode=0o700)
            before = checker.tree_snapshot(audit_root)

            attempted_file = audit_root / "forbidden-write"
            write = checker.run_read_only(
                Path("/bin/sh"), ["-c", f"printf bad > {attempted_file}"], audit_root)
            self.assertNotEqual(write.returncode, 0)
            self.assertFalse(attempted_file.exists())
            self.assertEqual(checker.tree_snapshot(audit_root), before)

            network_probe = (
                "import socket,sys; "
                "s=socket.socket(); "
                "e=s.connect_ex(('127.0.0.1', 9)); "
                "sys.exit(0 if e in (1, 13) else 91)"
            )
            network = checker.run_read_only(
                Path("/usr/bin/python3"), ["-c", network_probe], audit_root)
            self.assertEqual(network.returncode, 0, network.stderr)
            self.assertEqual(checker.tree_snapshot(audit_root), before)


if __name__ == "__main__":
    unittest.main()
