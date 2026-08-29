#!/usr/bin/env python3
"""Fail-closed source and compiled-artifact gate for Tribe's iOS AppIcon.

The source check is platform-independent.  On Darwin, ``--compile-source``
also asks the selected Xcode ``actool`` to compile the reviewed catalog, and
``--assets-car`` inspects the exact catalog embedded in a shipping app.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
from typing import Any, NoReturn
import zlib


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "client/ios/app/Media.xcassets"
APPICON = CATALOG / "AppIcon.appiconset"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# This is a closed, reviewed matrix.  It retains legacy sizes while requiring
# every modern iPhone/iPad slot and the App Store marketing icon.
SOURCE_ENTRIES = frozenset({
    ("iphone", "20x20", "2x", "40.png"),
    ("iphone", "20x20", "3x", "60.png"),
    ("iphone", "29x29", "1x", "29.png"),
    ("iphone", "29x29", "2x", "58.png"),
    ("iphone", "29x29", "3x", "87.png"),
    ("iphone", "40x40", "2x", "80.png"),
    ("iphone", "40x40", "3x", "120.png"),
    ("iphone", "57x57", "1x", "57.png"),
    ("iphone", "57x57", "2x", "114.png"),
    ("iphone", "60x60", "2x", "120.png"),
    ("iphone", "60x60", "3x", "180.png"),
    ("ipad", "20x20", "1x", "20.png"),
    ("ipad", "20x20", "2x", "40.png"),
    ("ipad", "29x29", "1x", "29.png"),
    ("ipad", "29x29", "2x", "58.png"),
    ("ipad", "40x40", "1x", "40.png"),
    ("ipad", "40x40", "2x", "80.png"),
    ("ipad", "50x50", "1x", "50.png"),
    ("ipad", "50x50", "2x", "100.png"),
    ("ipad", "72x72", "1x", "72.png"),
    ("ipad", "72x72", "2x", "144.png"),
    ("ipad", "76x76", "1x", "76.png"),
    ("ipad", "76x76", "2x", "152.png"),
    ("ipad", "83.5x83.5", "2x", "167.png"),
    ("ios-marketing", "1024x1024", "1x", "1024.png"),
})


class AppIconError(RuntimeError):
    """The source catalog or compiled rendition violated the release contract."""


def reject(message: str) -> NoReturn:
    raise AppIconError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def regular_file(path: Path, label: str) -> os.stat_result:
    try:
        details = path.lstat()
    except FileNotFoundError:
        reject(f"{label} is missing")
    require(stat.S_ISREG(details.st_mode) and not path.is_symlink(),
            f"{label} is not a regular non-symlink file")
    require(details.st_nlink == 1, f"{label} must not be hard-linked")
    return details


def png_properties(path: Path) -> tuple[int, int, bool]:
    regular_file(path, f"icon {path.name}")
    payload = path.read_bytes()
    require(payload.startswith(PNG_SIGNATURE), f"icon {path.name} is not a PNG")
    offset = len(PNG_SIGNATURE)
    chunks: list[bytes] = []
    width = height = color_type = None
    saw_iend = False
    while offset < len(payload):
        require(offset + 12 <= len(payload), f"icon {path.name} has a truncated PNG chunk")
        length = struct.unpack(">I", payload[offset:offset + 4])[0]
        kind = payload[offset + 4:offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        require(data_end + 4 <= len(payload),
                f"icon {path.name} has a truncated {kind!r} PNG chunk")
        expected_crc = struct.unpack(">I", payload[data_end:data_end + 4])[0]
        actual_crc = zlib.crc32(kind)
        actual_crc = zlib.crc32(payload[data_start:data_end], actual_crc) & 0xFFFFFFFF
        require(expected_crc == actual_crc, f"icon {path.name} has an invalid PNG CRC")
        chunks.append(kind)
        if kind == b"IHDR":
            require(len(chunks) == 1 and length == 13 and width is None,
                    f"icon {path.name} has an invalid IHDR")
            width, height = struct.unpack(">II", payload[data_start:data_start + 8])
            color_type = payload[data_start + 9]
            require(width > 0 and height > 0, f"icon {path.name} has invalid dimensions")
        elif kind == b"IEND":
            require(length == 0 and not saw_iend, f"icon {path.name} has an invalid IEND")
            saw_iend = True
            require(data_end + 4 == len(payload),
                    f"icon {path.name} has trailing data after IEND")
        offset = data_end + 4
    require(saw_iend and width is not None and height is not None and color_type is not None,
            f"icon {path.name} is not a complete PNG")
    # PNG color types 4 and 6 carry alpha; tRNS adds transparency to 0/2/3.
    opaque = color_type not in {4, 6} and b"tRNS" not in chunks
    return width, height, opaque


def descriptor_pixels(size: str, scale: str) -> int:
    width, separator, height = size.partition("x")
    require(separator == "x" and width == height, f"invalid square icon size {size!r}")
    require(scale in {"1x", "2x", "3x"}, f"invalid icon scale {scale!r}")
    if width.endswith(".5"):
        integer = width[:-2]
        require(integer.isdigit() and (integer == "0" or not integer.startswith("0")),
                f"non-canonical icon size {size!r}")
        doubled_points = int(integer) * 2 + 1
    else:
        require(width.isdigit() and width != "0" and not width.startswith("0"),
                f"non-canonical icon size {size!r}")
        doubled_points = int(width) * 2
    pixels_twice = doubled_points * int(scale[0])
    require(pixels_twice % 2 == 0, f"icon size {size!r} at {scale} is not integral")
    return pixels_twice // 2


def validate_source_catalog(appicon: Path = APPICON) -> dict[str, Any]:
    try:
        directory = appicon.lstat()
    except FileNotFoundError:
        reject("AppIcon.appiconset is missing")
    require(stat.S_ISDIR(directory.st_mode) and not appicon.is_symlink(),
            "AppIcon.appiconset must be a real directory")
    contents = appicon / "Contents.json"
    regular_file(contents, "AppIcon Contents.json")
    try:
        root = json.loads(contents.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"AppIcon Contents.json is invalid: {error}")
    require(isinstance(root, dict) and set(root) == {"images", "info"},
            "AppIcon Contents.json root schema is not closed")
    require(root["info"] == {"author": "xcode", "version": 1},
            "AppIcon Contents.json metadata drifted")
    require(isinstance(root["images"], list), "AppIcon images must be an array")
    entries: list[tuple[str, str, str, str]] = []
    for index, image in enumerate(root["images"]):
        require(isinstance(image, dict)
                and set(image) == {"idiom", "size", "scale", "filename"},
                f"AppIcon image {index} has an unexpected schema")
        entry = tuple(image[key] for key in ("idiom", "size", "scale", "filename"))
        require(all(isinstance(value, str) for value in entry),
                f"AppIcon image {index} fields must be strings")
        idiom, size, scale, filename = entry
        require(filename == Path(filename).name and filename.endswith(".png")
                and filename not in {".", ".."},
                f"AppIcon image {index} has an unsafe filename")
        descriptor_pixels(size, scale)
        entries.append((idiom, size, scale, filename))
    require(len(entries) == len(set(entries)), "AppIcon descriptor matrix contains a duplicate")
    require(set(entries) == SOURCE_ENTRIES, "AppIcon descriptor matrix drifted")

    referenced = {entry[3] for entry in entries}
    actual_files = {path.name for path in appicon.iterdir() if path.name != "Contents.json"}
    require(actual_files == referenced,
            f"AppIcon file closure drifted: expected={sorted(referenced)}, actual={sorted(actual_files)}")
    dimensions: dict[str, tuple[int, int]] = {}
    for idiom, size, scale, filename in entries:
        pixels = descriptor_pixels(size, scale)
        actual_width, actual_height, opaque = png_properties(appicon / filename)
        require((actual_width, actual_height) == (pixels, pixels),
                f"icon {filename} dimensions do not match {size} at {scale}")
        require(opaque, f"icon {filename} contains alpha/transparency")
        dimensions[filename] = (actual_width, actual_height)
    return {
        "descriptors": len(entries),
        "png_files": len(referenced),
        "marketing_icon": "1024.png",
        "marketing_dimensions": dimensions["1024.png"],
    }


def expected_compiled_entries() -> set[tuple[str, int, int]]:
    idioms = {"iphone": "phone", "ipad": "pad", "ios-marketing": "marketing"}
    return {
        (idioms[idiom], int(scale[0]), descriptor_pixels(size, scale))
        for idiom, size, scale, _filename in SOURCE_ENTRIES
    }


def validate_asset_records(records: Any) -> dict[str, Any]:
    require(isinstance(records, list) and all(isinstance(record, dict) for record in records),
            "assetutil output is not an array of dictionaries")
    headers = [record for record in records if "Platform" in record]
    require(len(headers) == 1 and headers[0].get("Platform") == "ios",
            "Assets.car is not an unambiguous iOS asset catalog")
    named_records = [record for record in records if record.get("Name") == "AppIcon"]
    require(all(record.get("AssetType") in {"Icon Image", "MultiSized Image"}
                for record in named_records),
            "Assets.car contains an unexpected AppIcon record type")
    icons = [record for record in named_records if record.get("AssetType") == "Icon Image"]
    require(icons, "Assets.car has no AppIcon renditions")
    compiled: Counter[tuple[str, int, int]] = Counter()
    for icon in icons:
        require(icon.get("Opaque") is True,
                "Assets.car contains a transparent AppIcon rendition")
        width = icon.get("PixelWidth")
        height = icon.get("PixelHeight")
        scale = icon.get("Scale")
        idiom = icon.get("Idiom")
        require(isinstance(width, int) and width > 0 and height == width,
                "Assets.car contains a non-square AppIcon rendition")
        require(isinstance(scale, int) and scale in {1, 2, 3}
                and idiom in {"phone", "pad", "marketing"},
                "Assets.car contains an invalid AppIcon idiom/scale")
        compiled[(idiom, scale, width)] += 1
    missing_or_ambiguous = {
        entry: compiled[entry] for entry in expected_compiled_entries() if compiled[entry] != 1
    }
    require(not missing_or_ambiguous,
            f"Assets.car required AppIcon matrix is missing/ambiguous: {missing_or_ambiguous}")
    require(compiled[("marketing", 1, 1024)] == 1,
            "Assets.car must contain exactly one opaque 1024px marketing icon")
    return {
        "compiled_renditions": len(icons),
        "required_renditions": len(expected_compiled_entries()),
    }


def validate_assets_car(path: Path) -> dict[str, Any]:
    regular_file(path, "Assets.car")
    result = subprocess.run(
        ["/usr/bin/assetutil", "--info", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(result.returncode == 0,
            f"assetutil rejected Assets.car: {result.stderr.decode('utf-8', 'replace')[:1000]}")
    try:
        records = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"assetutil returned invalid JSON: {error}")
    return validate_asset_records(records)


def validate_primary_icon_info(info: dict[str, Any], *, require_root_name: bool = True) -> None:
    if require_root_name:
        require(info.get("CFBundleIconName") == "AppIcon",
                "application Info.plist primary icon name mismatch")
    for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        section = info.get(key)
        require(isinstance(section, dict), f"application Info.plist lacks {key}")
        primary = section.get("CFBundlePrimaryIcon")
        require(isinstance(primary, dict) and primary.get("CFBundleIconName") == "AppIcon",
                f"application Info.plist {key} does not select AppIcon")


def compile_source_catalog(catalog: Path = CATALOG) -> dict[str, Any]:
    require(sys.platform == "darwin", "--compile-source requires Darwin/Xcode")
    require(Path("/usr/bin/xcrun").is_file() and Path("/usr/bin/assetutil").is_file(),
            "Xcode asset inspection tools are unavailable")
    with tempfile.TemporaryDirectory(prefix="tribe-appicon-actool-") as raw:
        temporary = Path(raw)
        output = temporary / "compiled"
        output.mkdir()
        partial = temporary / "partial.plist"
        result = subprocess.run(
            [
                "/usr/bin/xcrun", "actool", str(catalog),
                "--compile", str(output),
                "--platform", "iphoneos",
                "--minimum-deployment-target", "17.0",
                "--target-device", "iphone",
                "--target-device", "ipad",
                "--app-icon", "AppIcon",
                "--output-partial-info-plist", str(partial),
                "--output-format", "human-readable-text",
                "--warnings", "--errors", "--notices",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        require(result.returncode == 0,
                "actool rejected AppIcon: "
                + (result.stderr or result.stdout).decode("utf-8", "replace")[:2000])
        regular_file(partial, "actool partial Info.plist")
        try:
            with partial.open("rb") as handle:
                info = plistlib.load(handle)
        except plistlib.InvalidFileException as error:
            reject(f"actool partial Info.plist is invalid: {error}")
        require(isinstance(info, dict), "actool partial Info.plist is not a dictionary")
        validate_primary_icon_info(info, require_root_name=False)
        return validate_assets_car(output / "Assets.car")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--compile-source", action="store_true")
    parser.add_argument("--assets-car", type=Path)
    args = parser.parse_args()
    try:
        source_root = args.source_root.resolve(strict=True)
        require(source_root == ROOT.resolve(), "checker must validate its own source root")
        source_report = validate_source_catalog(
            source_root / "client/ios/app/Media.xcassets/AppIcon.appiconset"
        )
        compiled_report = compile_source_catalog(
            source_root / "client/ios/app/Media.xcassets"
        ) if args.compile_source else None
        artifact_report = validate_assets_car(args.assets_car) if args.assets_car else None
        print(
            "iOS AppIcon OK: "
            f"source={source_report['descriptors']} descriptors/"
            f"{source_report['png_files']} PNGs; "
            f"compiled={compiled_report}; artifact={artifact_report}"
        )
        return 0
    except (AppIconError, OSError) as error:
        print(f"iOS AppIcon rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
