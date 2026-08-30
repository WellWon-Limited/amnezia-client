from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_engine_lock", ROOT / "metadata/check_engine_lock.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EngineLockPatchSyntaxTests(unittest.TestCase):
    def test_accepts_well_formed_patch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tribe-patch-syntax-") as raw:
            patch = Path(raw) / "valid.patch"
            patch.write_text(
                "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            self.assertIsNone(MODULE.patch_parse_error(patch))

    def test_rejects_malformed_hunk_counts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tribe-patch-syntax-") as raw:
            patch = Path(raw) / "malformed.patch"
            patch.write_text(
                "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n-old\n+new\n",
                encoding="utf-8",
            )
            error = MODULE.patch_parse_error(patch)
            self.assertIsNotNone(error)
            self.assertIn("corrupt patch", error or "")


if __name__ == "__main__":
    unittest.main()
