#!/usr/bin/env python3
"""Validate the pinned AWG Android protected-start native ABI matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "metadata/engine-lock.json").read_text(encoding="utf-8"))
ENGINE = LOCK["engines"]["awg-android"]
EXPECTED_ABIS = {"armeabi-v7a", "arm64-v8a", "x86", "x86_64"}
REQUIRED_SYMBOLS = {
    b"Java_org_amnezia_awg_GoBackend_awgPrepareProtected",
    b"Java_org_amnezia_awg_GoBackend_awgResumeProtected",
    b"Java_org_amnezia_awg_GoBackend_awgProtectedTurnOff",
    b"Java_org_amnezia_awg_GoBackend_awgProtectedGetSocketV4",
    b"Java_org_amnezia_awg_GoBackend_awgProtectedGetSocketV6",
    b"Java_org_amnezia_awg_GoBackend_awgProtectedGetConfig",
    b"awgPrepareProtected",
    b"awgResumeProtected",
    b"awgProtectedTurnOff",
}


def fail(message: str) -> None:
    raise SystemExit(f"AWG Android artifact validation failed: {message}")


def load_alignments(binary: bytes, abi: str) -> list[int]:
    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[5] != 1:
        fail(f"{abi}: artifact is not a little-endian ELF")
    elf_class = binary[4]
    if elf_class == 1:
        phoff = struct.unpack_from("<I", binary, 28)[0]
        phentsize, phnum = struct.unpack_from("<HH", binary, 42)
        alignment_offset, minimum_entry, alignment_format = 28, 32, "<I"
    elif elf_class == 2:
        phoff = struct.unpack_from("<Q", binary, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", binary, 54)
        alignment_offset, minimum_entry, alignment_format = 48, 56, "<Q"
    else:
        fail(f"{abi}: unsupported ELF class {elf_class}")
    if phnum == 0 or phentsize < minimum_entry or phoff + phentsize * phnum > len(binary):
        fail(f"{abi}: malformed program headers")
    values: list[int] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if struct.unpack_from("<I", binary, offset)[0] == 1:
            values.append(struct.unpack_from(
                alignment_format, binary, offset + alignment_offset,
            )[0])
    minimum = ENGINE["minimum_pt_load_alignment"]
    if not values or any(value < minimum or value & (value - 1) for value in values):
        fail(f"{abi}: PT_LOAD alignment is not 16-KiB compatible: {values}")
    return values


def parse_artifact(value: str) -> tuple[str, pathlib.Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("artifact must be ABI=/absolute/path/libwg-go.so")
    abi, raw_path = value.split("=", 1)
    if abi not in EXPECTED_ABIS:
        raise argparse.ArgumentTypeError(f"unsupported ABI {abi!r}")
    path = pathlib.Path(raw_path)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("artifact path must be absolute")
    return abi, path


def validate_matrix(artifacts: dict[str, pathlib.Path], hash_field: str,
                    label: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for abi in sorted(artifacts):
        path = artifacts[abi]
        if path.is_symlink() or not path.is_file():
            fail(f"{label} {abi}: artifact must be a regular non-symlink file")
        binary = path.read_bytes()
        digest = hashlib.sha256(binary).hexdigest()
        expected = ENGINE[hash_field][abi]
        if digest != expected:
            fail(f"{label} {abi}: SHA-256 mismatch (expected {expected}, got {digest})")
        missing = sorted(symbol.decode() for symbol in REQUIRED_SYMBOLS if symbol not in binary)
        if missing:
            fail(f"{label} {abi}: protected-start ABI symbols missing: {missing}")
        if b"github.com/amnezia-vpn/amneziawg-go/v3\tv3.1.20260814\t" not in binary:
            fail(f"{label} {abi}: embedded AWG core version evidence missing")
        result[abi] = {
            "sha256": digest,
            "pt_load_alignments": load_alignments(binary, abi),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", action="append", required=True, type=parse_artifact)
    parser.add_argument("--packaged-artifact", action="append", default=[], type=parse_artifact,
                        help="optional Gradle release-stripped ABI=/absolute/path/libwg-go.so")
    parser.add_argument("--write-stamp", type=pathlib.Path)
    args = parser.parse_args()
    artifacts = dict(args.artifact)
    if len(artifacts) != len(args.artifact) or set(artifacts) != EXPECTED_ABIS:
        fail(f"exact ABI matrix required: {sorted(EXPECTED_ABIS)}")
    result = validate_matrix(artifacts, "android_artifact_sha256", "raw")
    packaged_result: dict[str, object] = {}
    if args.packaged_artifact:
        packaged = dict(args.packaged_artifact)
        if (len(packaged) != len(args.packaged_artifact)
                or set(packaged) != EXPECTED_ABIS):
            fail(f"exact packaged ABI matrix required: {sorted(EXPECTED_ABIS)}")
        packaged_result = validate_matrix(
            packaged, "android_release_packaged_sha256", "release-packaged")

    if args.write_stamp:
        args.write_stamp.write_text(json.dumps({
            "schema": 1,
            "adapter": "awg-android",
            "version": ENGINE["conan_version"],
            "core": ENGINE["embedded_awg_go"],
            "abi": ENGINE["abi"],
            "source_commit": ENGINE["source_commit"],
            "artifacts": result,
            "release_packaged_artifacts": packaged_result,
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    suffix = "; release strip locked" if packaged_result else ""
    print(f"AWG Android artifacts OK: protected-start ABI; 4 ABIs; PT_LOAD>=0x4000{suffix}")


if __name__ == "__main__":
    main()
