from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_release_version", ROOT / "metadata/check_release_version.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ReleaseVersionTests(unittest.TestCase):
    def test_current_source_has_exact_rc_version_and_track_pair(self) -> None:
        version = MODULE.parse_source_version(ROOT / "tribe_version.cmake")
        self.assertEqual(version.full, "5.1.68.97")
        self.assertEqual(version.marketing, "5.1.68")
        self.assertEqual(version.apple_build, 97)
        self.assertEqual(version.android_tracks, (2158, 2159))
        MODULE.validate_catalog_release_facts(
            ROOT / "metadata/catalog-release-request-facts.json", version
        )

    def test_catalog_release_facts_reject_android_abi_namespace_or_stale_build(
        self,
    ) -> None:
        version = MODULE.ReleaseVersion("5.1.68.97", "5.1.68", 97, 2158)
        with tempfile.TemporaryDirectory(prefix="tribe-release-facts-") as raw:
            facts = Path(raw) / "facts.json"
            source = (ROOT / "metadata/catalog-release-request-facts.json").read_text(
                encoding="utf-8"
            )
            facts.write_text(
                source.replace('"arm64"', '"arm64-v8a"', 1), encoding="utf-8"
            )
            with self.assertRaisesRegex(MODULE.VersionGateError, "drift"):
                MODULE.validate_catalog_release_facts(facts, version)
            facts.write_text(source.replace("2158", "2156"), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.VersionGateError, "drift"):
                MODULE.validate_catalog_release_facts(facts, version)

    def test_duplicate_or_noncanonical_source_definition_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tribe-version-source-") as raw:
            version_file = Path(raw) / "tribe_version.cmake"
            version_file.write_text(
                "set(TRIBE_VERSION 5.1.68.97)\n"
                "set(TRIBE_VERSION 5.1.69.98)\n"
                "set(TRIBE_ANDROID_VERSION_CODE 2158)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.VersionGateError, "one canonical"):
                MODULE.parse_source_version(version_file)

    def test_matching_annotated_release_tag_is_bound_to_exact_head(self) -> None:
        with self.repository() as repository:
            self.git(repository, "tag", "-a", "ios-v5.1.68.97", "-m", "RC")
            version = MODULE.parse_source_version(repository / "tribe_version.cmake")
            head = MODULE.git_commit(repository, "HEAD^{commit}")
            MODULE.validate_ci_identity(
                repository, version, "refs/tags/ios-v5.1.68.97", head
            )

    def test_tag_version_mismatch_is_rejected(self) -> None:
        with self.repository() as repository:
            self.git(repository, "tag", "-a", "macos-v5.1.67.96", "-m", "stale")
            version = MODULE.parse_source_version(repository / "tribe_version.cmake")
            with self.assertRaisesRegex(MODULE.VersionGateError, "source defines"):
                MODULE.validate_ci_identity(
                    repository, version, "refs/tags/macos-v5.1.67.96", ""
                )

    def test_tag_pointing_to_another_commit_is_rejected(self) -> None:
        with self.repository() as repository:
            self.git(repository, "tag", "-a", "android-v5.1.68.97", "-m", "old")
            (repository / "marker").write_text("new source commit\n", encoding="utf-8")
            self.git(repository, "add", "marker")
            self.git(repository, "commit", "-m", "later")
            version = MODULE.parse_source_version(repository / "tribe_version.cmake")
            with self.assertRaisesRegex(MODULE.VersionGateError, "tag resolves"):
                MODULE.validate_ci_identity(
                    repository, version, "refs/tags/android-v5.1.68.97", ""
                )

    def test_ci_sha_mismatch_or_malformed_release_tag_is_rejected(self) -> None:
        with self.repository() as repository:
            version = MODULE.parse_source_version(repository / "tribe_version.cmake")
            with self.assertRaisesRegex(MODULE.VersionGateError, "does not match CI"):
                MODULE.validate_ci_identity(
                    repository, version, "refs/heads/main", "0" * 40
                )
            with self.assertRaisesRegex(MODULE.VersionGateError, "release tags must"):
                MODULE.validate_ci_identity(
                    repository, version, "refs/tags/release-97", ""
                )

    class repository:
        def __init__(self) -> None:
            self.temporary = tempfile.TemporaryDirectory(prefix="tribe-version-git-")
            self.path = Path(self.temporary.name)

        def __enter__(self) -> Path:
            ReleaseVersionTests.git(self.path, "init", "-q")
            (self.path / "tribe_version.cmake").write_text(
                "set(TRIBE_VERSION 5.1.68.97)\nset(TRIBE_ANDROID_VERSION_CODE 2158)\n",
                encoding="utf-8",
            )
            ReleaseVersionTests.git(self.path, "add", "tribe_version.cmake")
            ReleaseVersionTests.git(self.path, "commit", "-m", "source")
            return self.path

        def __exit__(self, *_: object) -> None:
            self.temporary.cleanup()

    @staticmethod
    def git(repository: Path, *arguments: str) -> str:
        result = subprocess.run(
            [
                "git",
                "-c",
                "user.name=Tribe Version Test",
                "-c",
                "user.email=version-test@example.invalid",
                *arguments,
            ],
            cwd=repository,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"git {' '.join(arguments)} failed:\n{result.stdout}\n{result.stderr}"
            )
        return result.stdout.strip()


if __name__ == "__main__":
    unittest.main()
