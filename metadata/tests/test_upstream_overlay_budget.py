from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_upstream_overlay_budget.py"
SPEC = importlib.util.spec_from_file_location("check_upstream_overlay_budget", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OverlayConflictParserTests(unittest.TestCase):
    def test_parses_content_submodule_and_modify_delete(self) -> None:
        output = "\n".join([
            "CONFLICT (content): Merge conflict in client/main.cpp",
            "CONFLICT (submodule): Merge conflict in client/3rd/amneziawg-apple",
            "CONFLICT (modify/delete): deploy/data/macos/AmneziaVPN.plist deleted in HEAD "
            "and modified in origin/dev. Version origin/dev left in tree.",
        ])
        self.assertEqual(MODULE._conflict_paths(output), {
            "client/main.cpp",
            "client/3rd/amneziawg-apple",
            "deploy/data/macos/AmneziaVPN.plist",
        })

    def test_rejects_unknown_conflict_message(self) -> None:
        with self.assertRaises(RuntimeError):
            MODULE._conflict_paths("CONFLICT (new-kind): unknown format")


if __name__ == "__main__":
    unittest.main()
