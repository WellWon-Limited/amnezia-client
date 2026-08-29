from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import unittest
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_android_xray_aar", ROOT / "metadata/check_android_xray_aar.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AndroidXrayZipIdentityTests(unittest.TestCase):
    @staticmethod
    def archive(*names: str) -> zipfile.ZipFile:
        buffer = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buffer, "w") as output:
                for index, name in enumerate(names):
                    output.writestr(name, f"entry-{index}")
        return zipfile.ZipFile(io.BytesIO(buffer.getvalue()))

    def test_unique_member_names_are_preserved(self) -> None:
        with self.archive("classes.jar", "jni/arm64-v8a/libgojni.so") as archive:
            self.assertEqual(
                MODULE.unique_zip_names(archive, "fixture"),
                {"classes.jar", "jni/arm64-v8a/libgojni.so"},
            )

    def test_duplicate_aar_member_is_rejected(self) -> None:
        with self.archive("jni/arm64-v8a/libgojni.so",
                          "jni/arm64-v8a/libgojni.so") as archive:
            with self.assertRaisesRegex(SystemExit, "duplicate ZIP member names"):
                MODULE.unique_zip_names(archive, "AAR")

    def test_duplicate_nested_class_member_is_rejected(self) -> None:
        with self.archive("org/example/Api.class", "org/example/Api.class") as archive:
            with self.assertRaisesRegex(SystemExit, "classes.jar.*duplicate"):
                MODULE.unique_zip_names(archive, "classes.jar")


if __name__ == "__main__":
    unittest.main()
