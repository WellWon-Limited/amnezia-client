#!/usr/bin/env python3
"""Validate every 64-bit native library in a release APK or AAB for 16-KiB pages."""

from __future__ import annotations

import argparse
from collections import Counter
import pathlib
import struct
import zipfile


REQUIRED_64_BIT_ABIS = {"arm64-v8a", "x86_64"}
MINIMUM_LOAD_ALIGNMENT = 0x4000
LOCAL_FILE_HEADER = struct.Struct("<IHHHHHIIIHH")


def fail(message: str) -> None:
    raise SystemExit(f"Android 16-KiB artifact validation failed: {message}")


def load_alignments(binary: bytes, name: str) -> list[int]:
    if len(binary) < 64 or binary[:4] != b"\x7fELF" or binary[5] != 1:
        fail(f"{name} is not a little-endian ELF")
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
        fail(f"{name} has unsupported ELF class {elf_class}")
    if phnum == 0 or phentsize < minimum_entry or phoff + phentsize * phnum > len(binary):
        fail(f"{name} has malformed program headers")
    values = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if struct.unpack_from("<I", binary, offset)[0] == 1:  # PT_LOAD
            values.append(struct.unpack_from(
                alignment_format, binary, offset + alignment_offset)[0])
    if not values or any(value < MINIMUM_LOAD_ALIGNMENT or value & (value - 1)
                         for value in values):
        fail(f"{name} PT_LOAD alignment is not 16-KiB compatible: {values}")
    return values


def apk_data_offset(artifact: pathlib.Path, entry: zipfile.ZipInfo) -> int:
    with artifact.open("rb") as handle:
        handle.seek(entry.header_offset)
        header = handle.read(LOCAL_FILE_HEADER.size)
    if len(header) != LOCAL_FILE_HEADER.size:
        fail(f"truncated local ZIP header for {entry.filename}")
    values = LOCAL_FILE_HEADER.unpack(header)
    if values[0] != 0x04034B50:
        fail(f"invalid local ZIP header for {entry.filename}")
    return entry.header_offset + LOCAL_FILE_HEADER.size + values[-2] + values[-1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=pathlib.Path)
    parser.add_argument(
        "--required-abi",
        action="append",
        choices=sorted(REQUIRED_64_BIT_ABIS),
        help=("64-bit ABI that must be present; repeat for a custom matrix. "
              "Defaults to both Play-required 64-bit ABIs."),
    )
    args = parser.parse_args()
    artifact = args.artifact
    required_abis = set(args.required_abi or REQUIRED_64_BIT_ABIS)
    if artifact.is_symlink() or not artifact.is_file():
        fail("artifact must be a regular non-symlink file")
    if artifact.suffix not in {".apk", ".aab"}:
        fail("artifact must have an .apk or .aab suffix")

    prefix = "lib/" if artifact.suffix == ".apk" else "base/lib/"
    seen_abis: set[str] = set()
    native_count = 0
    load_count = 0
    stored_count = 0
    compressed_count = 0
    try:
        with zipfile.ZipFile(artifact) as archive:
            entries = archive.infolist()
            duplicates = sorted(
                name for name, count in Counter(
                    entry.filename for entry in entries
                ).items() if count > 1
            )
            if duplicates:
                fail(f"artifact contains duplicate ZIP member names: {duplicates}")
            for entry in entries:
                parts = entry.filename.split("/")
                if (len(parts) < 3 or not entry.filename.startswith(prefix)
                        or not entry.filename.endswith(".so")):
                    continue
                abi = parts[1] if artifact.suffix == ".apk" else parts[2]
                if abi not in required_abis:
                    continue
                seen_abis.add(abi)
                native_count += 1
                load_count += len(load_alignments(archive.read(entry), entry.filename))
                if artifact.suffix == ".apk":
                    if entry.compress_type == zipfile.ZIP_STORED:
                        stored_count += 1
                        offset = apk_data_offset(artifact, entry)
                        if offset % MINIMUM_LOAD_ALIGNMENT:
                            fail(f"{entry.filename} ZIP data offset {offset} is not 16-KiB aligned")
                    else:
                        # Compressed libraries are extracted before loading, so only
                        # their ELF PT_LOAD alignment matters. ZIP data alignment is
                        # required solely for libraries loaded directly from the APK.
                        compressed_count += 1
    except zipfile.BadZipFile as error:
        fail(f"invalid ZIP artifact: {error}")

    if seen_abis != required_abis:
        fail(f"64-bit ABI matrix mismatch: expected {sorted(required_abis)}, "
             f"got {sorted(seen_abis)}")
    if native_count == 0:
        fail("no 64-bit native libraries found")
    zip_suffix = (f"; {stored_count} stored ZIP entries aligned, "
                  f"{compressed_count} compressed entries extracted"
                  if artifact.suffix == ".apk" else "")
    print(f"Android 16-KiB artifact OK: {native_count} 64-bit libraries, "
          f"{load_count} PT_LOAD segments{zip_suffix}")


if __name__ == "__main__":
    main()
