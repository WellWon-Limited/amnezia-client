import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PARSER = ROOT / "deploy" / "tribe" / "launchctl-job-field.sh"

# Shape captured from `launchctl print system/<label>` on current macOS. The
# top-level running state coexists with nested coalition/jetsam active states.
RUNNING_JOB = """system/Tribe-service = {
    active count = 1
    path = /Library/LaunchDaemons/Tribe-service.plist
    type = LaunchDaemon
    state = running

    program = /Library/PrivilegedHelperTools/TribeVPN/Tribe-service
    arguments = {
        /Library/PrivilegedHelperTools/TribeVPN/Tribe-service
    }
    pid = 4242
    coalition = {
        ID = 101
        state = active
    }
    jetsam coalition = {
        ID = 102
        state = active
    }
}
"""


class MacosLaunchctlParserTests(unittest.TestCase):
    def parse(self, field: str, text: str = RUNNING_JOB, ok: bool = True) -> str:
        result = subprocess.run(
            ["/bin/bash", str(PARSER), field],
            input=text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result.stdout.strip()

    def test_top_level_fields_ignore_nested_states(self) -> None:
        self.assertEqual(self.parse("state"), "running")
        self.assertEqual(self.parse("pid"), "4242")
        self.assertEqual(
            self.parse("program"),
            "/Library/PrivilegedHelperTools/TribeVPN/Tribe-service",
        )

    def test_native_tab_indentation_is_supported(self) -> None:
        tabbed = RUNNING_JOB.replace("        ", "\t\t").replace("    ", "\t")
        self.assertEqual(self.parse("state", tabbed), "running")
        self.assertEqual(self.parse("pid", tabbed), "4242")

    def test_duplicate_top_level_field_is_rejected(self) -> None:
        duplicated = RUNNING_JOB.replace(
            "    state = running\n", "    state = running\n    state = waiting\n"
        )
        self.parse("state", duplicated, ok=False)

    def test_missing_or_unknown_field_is_rejected(self) -> None:
        self.parse("pid", RUNNING_JOB.replace("    pid = 4242\n", ""), ok=False)
        self.parse("environment", ok=False)


if __name__ == "__main__":
    unittest.main()
