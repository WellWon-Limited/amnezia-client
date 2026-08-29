#!/usr/bin/env python3
"""Fail-closed validation for the Conan-produced Tribe amnezia-libxray AAR."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import json
import pathlib
import re
import struct
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "metadata/engine-lock.json").read_text(encoding="utf-8"))
ENGINE = LOCK["engines"]["amnezia-libxray"]
EXPECTED_ABIS = {"armeabi-v7a", "arm64-v8a", "x86", "x86_64"}
EXPECTED_CLASSES = {
    "org/amnezia/vpn/protocol/xray/libXray/LibXray.class",
    "org/amnezia/vpn/protocol/xray/libXray/DialerController.class",
    "org/amnezia/vpn/protocol/xray/libXray/Logger.class",
    "org/amnezia/vpn/protocol/xray/libXray/Tun2SocksConfig.class",
}
MINIMUM_ANDROID_LOAD_ALIGNMENT = 0x4000
REQUIRED_NATIVE_SYMBOLS = {
    b"Java_org_amnezia_vpn_protocol_xray_libXray_LibXray_initXray",
    b"Java_org_amnezia_vpn_protocol_xray_libXray_LibXray_runXray",
    b"Java_org_amnezia_vpn_protocol_xray_libXray_LibXray_stopXray",
    b"Java_org_amnezia_vpn_protocol_xray_libXray_LibXray_startTun2Socks",
    b"Java_org_amnezia_vpn_protocol_xray_libXray_LibXray_stopTun2Socks",
    b"Java_org_amnezia_vpn_protocol_xray_libXray_LibXray_xrayVersion",
}


def load_alignments(binary: bytes, abi: str) -> list[int]:
    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[5] != 1:
        fail(f"{abi} libgojni.so is not a little-endian ELF")
    elf_class = binary[4]
    if elf_class == 1:
        phoff = struct.unpack_from("<I", binary, 28)[0]
        phentsize, phnum = struct.unpack_from("<HH", binary, 42)
        alignment_offset, minimum_entry = 28, 32
        alignment_format = "<I"
    elif elf_class == 2:
        phoff = struct.unpack_from("<Q", binary, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", binary, 54)
        alignment_offset, minimum_entry = 48, 56
        alignment_format = "<Q"
    else:
        fail(f"{abi} libgojni.so has unsupported ELF class {elf_class}")
    if phnum == 0 or phentsize < minimum_entry or phoff + phentsize * phnum > len(binary):
        fail(f"{abi} libgojni.so has malformed program headers")
    values: list[int] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if struct.unpack_from("<I", binary, offset)[0] == 1:  # PT_LOAD
            values.append(struct.unpack_from(alignment_format, binary,
                                             offset + alignment_offset)[0])
    if not values or any(value < MINIMUM_ANDROID_LOAD_ALIGNMENT
                         or value & (value - 1) for value in values):
        fail(f"{abi} PT_LOAD alignment is not 16 KiB compatible: {values}")
    return values


def reject_local_build_paths(binary: bytes, abi: str) -> None:
    """Reject Go module replacements that disclose and hash the build directory.

    gomobile synthesizes a temporary module with an absolute ``replace`` path
    for the bound package.  Go records that path in ``runtime.modinfo`` even
    with ``-trimpath``.  Besides leaking the builder path, this made otherwise
    identical universal AARs differ between Conan package IDs and caused the
    multi-ABI checksum race.  The recipe deliberately clears runtime.modinfo;
    keep the artifact gate fail-closed if that flag ever regresses.
    """
    if (b"/.conan2/" in binary or b"\\.conan2\\" in binary
            or re.search(rb"=>\t(?:/|[A-Za-z]:[\\/])", binary)):
        fail(f"{abi} libgojni.so contains an absolute local Go module replacement path")


def fail(message: str) -> None:
    raise SystemExit(f"libxray AAR validation failed: {message}")


def unique_zip_names(archive: zipfile.ZipFile, label: str) -> set[str]:
    """Reject ambiguous members before any name-based read or set conversion."""
    members = [entry.filename for entry in archive.infolist()]
    duplicates = sorted(name for name, count in Counter(members).items()
                        if count > 1)
    if duplicates:
        fail(f"{label} contains duplicate ZIP member names: {duplicates}")
    return set(members)


def parse_packaged_artifact(value: str) -> tuple[str, pathlib.Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(
            "packaged artifact must be ABI=/absolute/path/libgojni.so")
    abi, raw_path = value.split("=", 1)
    if abi not in EXPECTED_ABIS:
        raise argparse.ArgumentTypeError(f"unsupported ABI {abi!r}")
    path = pathlib.Path(raw_path)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("packaged artifact path must be absolute")
    return abi, path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("aar", type=pathlib.Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--packaged-artifact", action="append", default=[],
                        type=parse_packaged_artifact,
                        help="optional Gradle release-stripped ABI=/absolute/path/libgojni.so")
    parser.add_argument("--write-stamp", type=pathlib.Path)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        fail("expected SHA-256 must be 64 lowercase hex characters")
    if args.aar.is_symlink() or not args.aar.is_file():
        fail("artifact must be a regular non-symlink file")
    actual = hashlib.sha256(args.aar.read_bytes()).hexdigest()
    if actual != args.sha256:
        fail(f"SHA-256 mismatch (expected {args.sha256}, got {actual})")

    try:
        with zipfile.ZipFile(args.aar) as archive:
            names = unique_zip_names(archive, "AAR")
            abis = {
                parts[1]
                for name in names
                if (parts := name.split("/"))[:1] == ["jni"]
                and len(parts) == 3
                and parts[2] == "libgojni.so"
            }
            if abis != EXPECTED_ABIS:
                fail(f"ABI matrix mismatch (expected {sorted(EXPECTED_ABIS)}, got {sorted(abis)})")
            native_binaries = {
                abi: archive.read(f"jni/{abi}/libgojni.so")
                for abi in sorted(abis)
            }
            for abi, binary in native_binaries.items():
                reject_local_build_paths(binary, abi)
            alignments = {
                abi: load_alignments(binary, abi)
                for abi, binary in native_binaries.items()
            }
            if "classes.jar" not in names:
                fail("classes.jar missing")
            with zipfile.ZipFile(io.BytesIO(archive.read("classes.jar"))) as classes:
                class_names = unique_zip_names(classes, "classes.jar")
                missing = EXPECTED_CLASSES - class_names
                if missing:
                    fail(f"required gomobile API classes missing: {sorted(missing)}")
                libxray_class = classes.read(
                    "org/amnezia/vpn/protocol/xray/libXray/LibXray.class")
                for method in (b"registerSocketControllers", b"clearSocketControllers"):
                    if method not in libxray_class:
                        fail(f"required controller-slot gomobile method missing: {method.decode()}")
    except zipfile.BadZipFile as error:
        fail(f"invalid ZIP/JAR: {error}")

    packaged_result: dict[str, object] = {}
    if args.packaged_artifact:
        packaged = dict(args.packaged_artifact)
        if (len(packaged) != len(args.packaged_artifact)
                or set(packaged) != EXPECTED_ABIS):
            fail(f"exact packaged ABI matrix required: {sorted(EXPECTED_ABIS)}")
        for abi, path in sorted(packaged.items()):
            if path.is_symlink() or not path.is_file():
                fail(f"release-packaged {abi} artifact must be a regular non-symlink file")
            binary = path.read_bytes()
            digest = hashlib.sha256(binary).hexdigest()
            expected = ENGINE["android_release_packaged_sha256"][abi]
            if digest != expected:
                fail(f"release-packaged {abi} SHA-256 mismatch "
                     f"(expected {expected}, got {digest})")
            reject_local_build_paths(binary, abi)
            missing_symbols = sorted(
                symbol.decode() for symbol in REQUIRED_NATIVE_SYMBOLS if symbol not in binary)
            if missing_symbols:
                fail(f"release-packaged {abi} JNI symbols missing: {missing_symbols}")
            packaged_result[abi] = {
                "sha256": digest,
                "pt_load_alignments": load_alignments(binary, abi),
            }

    if args.write_stamp:
        args.write_stamp.write_text(
            json.dumps({
                "schema": 1,
                "adapter": "amnezia-libxray",
                "version": ENGINE["conan_version"],
                "core": "1.260728.0",
                "abi": ENGINE["abi"],
                "sha256": actual,
                "android_abis": sorted(abis),
                "minimum_pt_load_alignment": MINIMUM_ANDROID_LOAD_ALIGNMENT,
                "pt_load_alignments": alignments,
                "absolute_module_replacement_paths": False,
                "release_packaged_artifacts": packaged_result,
            }, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    suffix = "; release strip locked" if packaged_result else ""
    print(f"libxray AAR OK: {actual} "
          f"({','.join(sorted(abis))}; PT_LOAD>=0x4000{suffix})")


if __name__ == "__main__":
    main()
