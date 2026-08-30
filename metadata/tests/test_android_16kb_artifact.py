from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "metadata" / "check_android_16kb_artifact.py"


def elf64(load_alignment: int) -> bytes:
    """Return the smallest ELF64 image needed by the artifact validator."""
    image = bytearray(120)
    image[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", image, 32, 64)  # e_phoff
    struct.pack_into("<HH", image, 54, 56, 1)  # e_phentsize/e_phnum
    struct.pack_into("<I", image, 64, 1)  # PT_LOAD
    struct.pack_into("<Q", image, 64 + 48, load_alignment)  # p_align
    return bytes(image)


class Android16KArtifactTests(unittest.TestCase):
    def make_artifact(
        self,
        *,
        suffix: str = ".apk",
        compression: int = zipfile.ZIP_DEFLATED,
        load_alignment: int = 0x4000,
        include_x86_64: bool = True,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        directory = tempfile.TemporaryDirectory()
        artifact = Path(directory.name) / f"release{suffix}"
        prefix = "lib" if suffix == ".apk" else "base/lib"
        with zipfile.ZipFile(artifact, "w", compression=compression) as archive:
            archive.writestr(
                f"{prefix}/arm64-v8a/libtribe.so", elf64(load_alignment)
            )
            if include_x86_64:
                archive.writestr(
                    f"{prefix}/x86_64/libtribe.so", elf64(load_alignment)
                )
            # The 16-KiB Android compatibility requirement is for 64-bit
            # devices. A 32-bit library must not make an otherwise valid
            # artifact fail this gate.
            archive.writestr(
                f"{prefix}/armeabi-v7a/liblegacy.so", elf64(0x1000)
            )
        return directory, artifact

    def run_checker(
        self, artifact: Path, *extra_args: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), str(artifact), *extra_args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_accepts_compressed_apk_and_aab_with_16k_64_bit_elfs(self) -> None:
        for suffix in (".apk", ".aab"):
            with self.subTest(suffix=suffix):
                directory, artifact = self.make_artifact(suffix=suffix)
                self.addCleanup(directory.cleanup)
                result = self.run_checker(artifact)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn("Android 16-KiB artifact OK", result.stdout)

    def test_rejects_4k_64_bit_load_alignment(self) -> None:
        directory, artifact = self.make_artifact(load_alignment=0x1000)
        self.addCleanup(directory.cleanup)
        result = self.run_checker(artifact)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PT_LOAD alignment is not 16-KiB compatible", result.stdout)

    def test_rejects_missing_required_64_bit_abi(self) -> None:
        directory, artifact = self.make_artifact(include_x86_64=False)
        self.addCleanup(directory.cleanup)
        result = self.run_checker(artifact)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("64-bit ABI matrix mismatch", result.stdout)

        arm64_only = self.run_checker(
            artifact, "--required-abi", "arm64-v8a"
        )
        self.assertEqual(arm64_only.returncode, 0, arm64_only.stdout)

    def test_rejects_unaligned_stored_apk_entry(self) -> None:
        directory, artifact = self.make_artifact(compression=zipfile.ZIP_STORED)
        self.addCleanup(directory.cleanup)
        result = self.run_checker(artifact)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ZIP data offset", result.stdout)

    def test_rejects_duplicate_zip_member_before_elf_read(self) -> None:
        directory, artifact = self.make_artifact()
        self.addCleanup(directory.cleanup)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(artifact, "a") as archive:
                archive.writestr(
                    "lib/arm64-v8a/libtribe.so", b"ambiguous replacement"
                )
        result = self.run_checker(artifact)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate ZIP member names", result.stdout)
        self.assertNotIn("not a little-endian ELF", result.stdout)


if __name__ == "__main__":
    unittest.main()
