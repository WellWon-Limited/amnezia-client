from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_ios_release_artifact", ROOT / "metadata/check_ios_release_artifact.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def info(name: str, *, directory: bool = False, mode: int = 0o644) -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(name + ("/" if directory and not name.endswith("/") else ""))
    entry.create_system = 3
    kind = stat.S_IFDIR if directory else stat.S_IFREG
    entry.external_attr = (kind | mode) << 16
    entry.compress_type = zipfile.ZIP_DEFLATED
    return entry


class IOSReleaseArtifactZipTests(unittest.TestCase):
    @staticmethod
    def archive(*extra: zipfile.ZipInfo) -> zipfile.ZipFile:
        buffer = io.BytesIO()
        base = [
            info("Payload", directory=True, mode=0o755),
            info("Payload/AmneziaVPN.app", directory=True, mode=0o755),
            info("Payload/AmneziaVPN.app/Info.plist"),
            info("Payload/AmneziaVPN.app/AmneziaVPN", mode=0o755),
            info("Payload/AmneziaVPN.app/embedded.mobileprovision"),
            info("Payload/AmneziaVPN.app/PlugIns", directory=True, mode=0o755),
            info("Payload/AmneziaVPN.app/PlugIns/AmneziaVPNNetworkExtension.appex",
                 directory=True, mode=0o755),
            info("Payload/AmneziaVPN.app/PlugIns/AmneziaVPNNetworkExtension.appex/Info.plist"),
            info("Payload/AmneziaVPN.app/PlugIns/AmneziaVPNNetworkExtension.appex/"
                 "embedded.mobileprovision"),
            info("Payload/AmneziaVPN.app/PlugIns/AmneziaVPNNetworkExtension.appex/"
                 "AmneziaVPNNetworkExtension", mode=0o755),
        ]
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buffer, "w") as output:
                for entry in [*base, *extra]:
                    output.writestr(entry, b"fixture")
        return zipfile.ZipFile(io.BytesIO(buffer.getvalue()))

    def test_accepts_exact_app_and_network_extension_layout(self) -> None:
        with self.archive() as archive:
            self.assertEqual(
                MODULE.validate_ipa_zip_layout(archive),
                "Payload/AmneziaVPN.app",
            )

    def test_rejects_duplicate_member_before_name_based_read(self) -> None:
        with self.archive(info("Payload/AmneziaVPN.app/Info.plist")) as archive:
            with self.assertRaisesRegex(MODULE.ArtifactError, "duplicate ZIP member"):
                MODULE.validate_ipa_zip_layout(archive)

    def test_rejects_case_colliding_member(self) -> None:
        with self.archive(info("Payload/AmneziaVPN.app/info.plist")) as archive:
            with self.assertRaisesRegex(MODULE.ArtifactError, "case/Unicode-colliding"):
                MODULE.validate_ipa_zip_layout(archive)

    def test_rejects_traversal_or_symlink_member(self) -> None:
        with self.archive(info("Payload/AmneziaVPN.app/../escape")) as archive:
            with self.assertRaisesRegex(MODULE.ArtifactError, "non-canonical"):
                MODULE.validate_ipa_zip_layout(archive)

        link = info("Payload/AmneziaVPN.app/Frameworks/escape")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.archive(link) as archive:
            with self.assertRaisesRegex(MODULE.ArtifactError, "special/symlink"):
                MODULE.validate_ipa_zip_layout(archive)

    def test_rejects_second_app_or_extension(self) -> None:
        with self.archive(info("Payload/Foreign.app/Info.plist")) as archive:
            with self.assertRaisesRegex(MODULE.ArtifactError, "payload app mismatch"):
                MODULE.validate_ipa_zip_layout(archive)
        with self.archive(info("Payload/AmneziaVPN.app/PlugIns/Foreign.appex/Info.plist")) as archive:
            with self.assertRaisesRegex(MODULE.ArtifactError, "Extension matrix mismatch"):
                MODULE.validate_ipa_zip_layout(archive)

    def test_rejects_unreviewed_symbols_or_swift_support_layout(self) -> None:
        with self.archive(info("Symbols/hidden")) as archive:
            with self.assertRaisesRegex(MODULE.ArtifactError, "unexpected IPA top-level"):
                MODULE.validate_ipa_zip_layout(archive)
        with self.archive(info("SwiftSupport/macos/libswiftCore.dylib")) as archive:
            with self.assertRaisesRegex(MODULE.ArtifactError, "unexpected SwiftSupport"):
                MODULE.validate_ipa_zip_layout(archive)

    def test_swift_support_must_byte_match_embedded_runtime(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tribe-ios-swift-") as raw:
            root = Path(raw)
            app = root / "Payload" / "AmneziaVPN.app"
            frameworks = app / "Frameworks"
            support = root / "SwiftSupport" / "iphoneos"
            frameworks.mkdir(parents=True)
            support.mkdir(parents=True)
            (frameworks / "libswiftCore.dylib").write_bytes(b"reviewed-runtime")
            (support / "libswiftCore.dylib").write_bytes(b"reviewed-runtime")
            MODULE.validate_swift_support(root, app)
            (support / "libswiftCore.dylib").write_bytes(b"substituted-runtime")
            with self.assertRaisesRegex(MODULE.ArtifactError, "byte-match"):
                MODULE.validate_swift_support(root, app)

    def test_source_version_is_split_into_marketing_and_build(self) -> None:
        self.assertEqual(MODULE.source_version(ROOT), ("5.1.68", "97"))


if __name__ == "__main__":
    unittest.main()
