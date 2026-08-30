import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "deploy" / "tribe" / "verify-macos-build-paths.sh"


@unittest.skipUnless(sys.platform == "darwin", "Mach-O privacy fixture requires macOS")
class MacosBuildPathPrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="tribe-path-privacy-test-"))
        self.binary = self.temp / "fixture"
        self.source = self.temp / "fixture.c"
        self.compile_fixture("clean-marker")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp)

    def compile_fixture(self, marker: str) -> None:
        self.source.write_text(
            f'static const char marker[] = "{marker}";\n'
            'int main(void) { return marker[0] == 0; }\n',
            encoding="utf-8",
        )
        subprocess.run(
            ["/usr/bin/clang", str(self.source), "-o", str(self.binary)],
            check=True,
        )

    def run_gate(self, ok: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(
            ["/bin/bash", str(GATE), str(self.temp)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(f"privacy gate failed: {result.stdout}\n{result.stderr}")
        if not ok and result.returncode == 0:
            self.fail("privacy gate accepted a private build path")
        return result

    def test_clean_system_macho_is_accepted(self) -> None:
        result = self.run_gate()
        self.assertIn("privacy gate passed across 1 Mach-O", result.stdout)

    def test_per_user_conan_cache_path_is_rejected(self) -> None:
        self.compile_fixture("/Users/release-builder/.conan2/p/b/private/source.go")
        result = self.run_gate(ok=False)
        self.assertIn("per-user Conan cache path leaked", result.stderr)


if __name__ == "__main__":
    unittest.main()
