import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATOR = ROOT / "deploy" / "tribe" / "migrate-macos-legacy-app.sh"


@unittest.skipUnless(Path("/usr/libexec/PlistBuddy").exists(), "macOS-only migration fixture")
class MacosLegacyMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="tribe-legacy-migration-test-"))
        self.new_app = self.temp / "TribeVPN.app"
        self.legacy_app = self.temp / "Tribe VPN.app"
        self.log = self.temp / "migration.log"
        self.stub = self.temp / "codesign-stub.sh"
        self.stub.write_text(
            "#!/bin/bash\n"
            "set -eu\n"
            "target=\"${!#}\"\n"
            "case \"$target\" in *foreign*) exit 1 ;; esac\n"
            "if [ \"${TRIBE_TEST_FAIL_QUARANTINE:-0}\" = 1 ]; then\n"
            "  case \"$target\" in *.tribe-legacy-quarantine.*/*) exit 1 ;; esac\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        self.stub.chmod(0o755)
        self.make_app(self.new_app, "5.1.68", "97")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp)

    @staticmethod
    def make_app(path: Path, short: str, build: str) -> None:
        contents = path / "Contents"
        contents.mkdir(parents=True)
        with (contents / "Info.plist").open("wb") as stream:
            plistlib.dump(
                {
                    "CFBundleIdentifier": "hk.wellwon.vpn",
                    "CFBundleShortVersionString": short,
                    "CFBundleVersion": build,
                },
                stream,
            )
        (contents / "marker").write_text("signed fixture\n", encoding="utf-8")

    def run_migration(self, ok: bool = True, **environment: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update(environment)
        result = subprocess.run(
            [
                "/bin/bash",
                str(MIGRATOR),
                str(self.new_app),
                str(self.legacy_app),
                str(self.log),
                "5.1.68.97",
                "migrate",
                str(self.stub),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        if ok and result.returncode != 0:
            self.fail(f"migration failed: {result.stdout}\n{result.stderr}")
        if not ok and result.returncode == 0:
            self.fail("migration unexpectedly reported success")
        return result

    def test_absent_legacy_is_successful_noop(self) -> None:
        self.run_migration()
        self.assertTrue(self.new_app.is_dir())
        self.assertIn("no spaced Tribe app", self.log.read_text(encoding="utf-8"))

    def test_valid_older_legacy_is_quarantined_reverified_and_removed(self) -> None:
        self.make_app(self.legacy_app, "5.1.64", "93")
        self.run_migration()
        self.assertFalse(self.legacy_app.exists())
        self.assertFalse(list(self.temp.glob(".tribe-legacy-quarantine.*")))
        self.assertIn("migration complete", self.log.read_text(encoding="utf-8"))

    def test_foreign_legacy_is_preserved(self) -> None:
        foreign = self.temp / "foreign.app"
        self.make_app(foreign, "5.1.64", "93")
        foreign.rename(self.legacy_app)
        # The verifier stub keys off the resolved argument spelling.
        marker = self.legacy_app / "Contents" / "foreign"
        marker.write_text("foreign\n", encoding="utf-8")
        original_stub = self.stub.read_text(encoding="utf-8")
        self.stub.write_text(
            original_stub.replace(
                'case "$target" in *foreign*) exit 1 ;; esac',
                'if [ -e "$target/Contents/foreign" ]; then exit 1; fi',
            ),
            encoding="utf-8",
        )
        self.stub.chmod(0o755)
        self.run_migration()
        self.assertTrue(self.legacy_app.is_dir())

    def test_symlink_legacy_is_preserved_without_touching_target(self) -> None:
        target = self.temp / "foreign-target.app"
        self.make_app(target, "5.1.64", "93")
        self.legacy_app.symlink_to(target, target_is_directory=True)
        self.run_migration()
        self.assertTrue(self.legacy_app.is_symlink())
        self.assertTrue(target.is_dir())

    def test_second_signature_failure_restores_proven_legacy_and_fails(self) -> None:
        self.make_app(self.legacy_app, "5.1.64", "93")
        self.run_migration(ok=False, TRIBE_TEST_FAIL_QUARANTINE="1")
        self.assertTrue(self.legacy_app.is_dir())
        self.assertFalse(list(self.temp.glob(".tribe-legacy-quarantine.*")))

    def test_invalid_canonical_version_fails_and_preserves_legacy(self) -> None:
        shutil.rmtree(self.new_app)
        self.make_app(self.new_app, "5.1.66", "95")
        self.make_app(self.legacy_app, "5.1.64", "93")
        self.run_migration(ok=False)
        self.assertTrue(self.legacy_app.is_dir())

    def test_delete_failure_restores_full_legacy_bundle(self) -> None:
        self.make_app(self.legacy_app, "5.1.64", "93")
        marker = self.legacy_app / "Contents" / "marker"
        original = marker.read_bytes()
        self.run_migration(ok=False, TRIBE_TEST_DELETE_FAIL="1")
        self.assertTrue(self.legacy_app.is_dir())
        self.assertEqual(marker.read_bytes(), original)
        self.assertFalse(list(self.temp.glob(".tribe-legacy-quarantine.*")))

    def test_partial_delete_failure_never_restores_a_damaged_bundle(self) -> None:
        self.make_app(self.legacy_app, "5.1.64", "93")
        self.run_migration(ok=False, TRIBE_TEST_PARTIAL_DELETE_FAIL="1")
        self.assertFalse(self.legacy_app.exists())
        quarantines = list(self.temp.glob(".tribe-legacy-quarantine.*"))
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(quarantines[0].stat().st_mode & 0o777, 0o700)
        self.assertIn(
            "partial quarantine deletion failure",
            self.log.read_text(encoding="utf-8"),
        )

    def test_newer_signed_legacy_is_never_removed_by_older_package(self) -> None:
        self.make_app(self.legacy_app, "5.1.69", "98")
        self.run_migration(ok=False)
        self.assertTrue(self.legacy_app.is_dir())


if __name__ == "__main__":
    unittest.main()
