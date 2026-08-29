import pathlib
import re
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
QUARANTINE = ROOT / "deploy/data/macos/pf/tribe.999.quarantine.conf"
CANONICAL_QUARANTINE = re.compile(
    r"^block drop quick all(?: flags any(?: no state)?)?$"
)


@unittest.skipUnless(sys.platform == "darwin", "requires the macOS PF parser")
class MacosPfContractTests(unittest.TestCase):
    def test_terminal_quarantine_dry_run_matches_runtime_readback_contract(self) -> None:
        result = subprocess.run(
            [
                "/sbin/pfctl",
                "-vn",
                "-a",
                "tribe/999.quarantine",
                "-f",
                str(QUARANTINE),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(len(rules), 1, result.stdout)
        self.assertRegex(rules[0], CANONICAL_QUARANTINE)

        runtime_source = (
            ROOT / "client/platforms/macos/daemon/macosfirewall.cpp"
        ).read_text(encoding="utf-8")
        self.assertIn("( flags any( no state)?)?", runtime_source)


if __name__ == "__main__":
    unittest.main()
