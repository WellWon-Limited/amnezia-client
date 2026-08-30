from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_ios_appicon", ROOT / "metadata/check_ios_appicon.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IOSAppIconTests(unittest.TestCase):
    def copied_catalog(self, root: Path) -> Path:
        target = root / "AppIcon.appiconset"
        shutil.copytree(MODULE.APPICON, target)
        return target

    def test_reviewed_source_catalog_is_complete_opaque_and_closed(self) -> None:
        report = MODULE.validate_source_catalog()
        self.assertEqual(report["descriptors"], 25)
        self.assertEqual(report["png_files"], 19)
        self.assertEqual(report["marketing_dimensions"], (1024, 1024))

    def test_source_rejects_missing_marketing_or_unreviewed_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tribe-appicon-test-") as raw:
            catalog = self.copied_catalog(Path(raw))
            contents = catalog / "Contents.json"
            root = json.loads(contents.read_text(encoding="utf-8"))
            root["images"] = [
                image for image in root["images"] if image["idiom"] != "ios-marketing"
            ]
            contents.write_text(json.dumps(root), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.AppIconError, "descriptor matrix drifted"):
                MODULE.validate_source_catalog(catalog)

        with tempfile.TemporaryDirectory(prefix="tribe-appicon-test-") as raw:
            catalog = self.copied_catalog(Path(raw))
            shutil.copyfile(catalog / "20.png", catalog / "unreviewed.png")
            with self.assertRaisesRegex(MODULE.AppIconError, "file closure drifted"):
                MODULE.validate_source_catalog(catalog)

    def test_source_rejects_wrong_dimensions_and_transparency(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tribe-appicon-test-") as raw:
            catalog = self.copied_catalog(Path(raw))
            shutil.copyfile(catalog / "180.png", catalog / "1024.png")
            with self.assertRaisesRegex(MODULE.AppIconError, "dimensions do not match"):
                MODULE.validate_source_catalog(catalog)

        with tempfile.TemporaryDirectory(prefix="tribe-appicon-test-") as raw:
            catalog = self.copied_catalog(Path(raw))
            icon = catalog / "1024.png"
            payload = bytearray(icon.read_bytes())
            payload[25] = 6  # IHDR RGBA color type.
            payload[29:33] = struct.pack(">I", zlib.crc32(payload[12:29]) & 0xFFFFFFFF)
            icon.write_bytes(payload)
            with self.assertRaisesRegex(MODULE.AppIconError, "alpha/transparency"):
                MODULE.validate_source_catalog(catalog)

    def test_compiled_catalog_requires_each_rendition_exactly_once(self) -> None:
        records: list[dict[str, object]] = [{"Platform": "ios"}]
        for idiom, scale, pixels in MODULE.expected_compiled_entries():
            records.append({
                "Name": "AppIcon",
                "AssetType": "Icon Image",
                "Opaque": True,
                "Idiom": idiom,
                "Scale": scale,
                "PixelWidth": pixels,
                "PixelHeight": pixels,
            })
        report = MODULE.validate_asset_records(records)
        self.assertEqual(report["required_renditions"], 25)

        marketing = next(
            record for record in records if record.get("Idiom") == "marketing"
        )
        with self.assertRaisesRegex(MODULE.AppIconError, "missing/ambiguous"):
            MODULE.validate_asset_records([*records, dict(marketing)])
        with self.assertRaisesRegex(MODULE.AppIconError, "missing/ambiguous"):
            MODULE.validate_asset_records([record for record in records if record is not marketing])


if __name__ == "__main__":
    unittest.main()
