#!/usr/bin/env python3
"""Validate the commit-bound device/runtime evidence used by release builds."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn


MAX_RECEIPT_BYTES = 131_072
ALLOWED_PLATFORMS = {"android", "ios", "macos_daemon", "macos_ne"}
TRANSPORTS = {"awg", "xray"}
PASS_FIELDS = {"artifact_matrix", "exact_lifecycle", "route_leak_matrix"}
EVIDENCE_FIELDS = PASS_FIELDS | {"device_receipt_sha256"}
LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}\Z")


def fail(message: str) -> NoReturn:
    raise SystemExit(f"platform runtime receipt rejected: {message}")


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        fail(f"{label} key mismatch (missing={missing}, extra={extra})")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--platform", choices=sorted(ALLOWED_PLATFORMS), required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()

    if not args.file.is_absolute() or not args.file.is_file():
        fail("receipt must be an existing absolute regular file")
    if not LOWER_HEX_64.fullmatch(args.sha256):
        fail("pinned receipt SHA-256 must be 64 lowercase hexadecimal characters")
    raw = args.file.read_bytes()
    if not raw or len(raw) > MAX_RECEIPT_BYTES:
        fail(f"receipt size must be 1..{MAX_RECEIPT_BYTES} bytes")
    actual_digest = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_digest, args.sha256):
        fail("receipt SHA-256 mismatch")

    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid UTF-8 JSON: {error}")
    root = exact_object(document, {"schema", "source_commit", "platforms"}, "root")
    if root["schema"] != 1 or isinstance(root["schema"], bool):
        fail("schema must be integer 1")
    source_commit = root["source_commit"]
    if not isinstance(source_commit, str) or not GIT_SHA1.fullmatch(source_commit):
        fail("source_commit must be a full lowercase Git SHA-1")

    source_root = args.source_root.resolve(strict=True)
    result = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "--verify", "HEAD"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    current_commit = result.stdout.strip()
    if result.returncode != 0 or not GIT_SHA1.fullmatch(current_commit):
        fail("source root has no verifiable full Git commit")
    if not hmac.compare_digest(current_commit, source_commit):
        fail("receipt is not bound to the source commit being built")

    platforms = root["platforms"]
    if not isinstance(platforms, dict) or not platforms:
        fail("platforms must be a non-empty object")
    unknown_platforms = set(platforms) - ALLOWED_PLATFORMS
    if unknown_platforms:
        fail(f"unknown platforms: {sorted(unknown_platforms)}")
    if args.platform not in platforms:
        fail(f"required platform {args.platform!r} is absent")

    for platform_name, platform_value in platforms.items():
        platform = exact_object(platform_value, TRANSPORTS,
                                f"platforms.{platform_name}")
        for transport_name, transport_value in platform.items():
            label = f"platforms.{platform_name}.{transport_name}"
            evidence = exact_object(transport_value, EVIDENCE_FIELDS, label)
            for field in PASS_FIELDS:
                if evidence[field] != "passed":
                    fail(f"{label}.{field} must equal 'passed'")
            evidence_digest = evidence["device_receipt_sha256"]
            if (not isinstance(evidence_digest, str)
                    or not LOWER_HEX_64.fullmatch(evidence_digest)
                    or set(evidence_digest) == {"0"}):
                fail(f"{label}.device_receipt_sha256 is not a real evidence digest")

    print(f"platform runtime receipt OK for {args.platform} at {source_commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
