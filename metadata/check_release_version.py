#!/usr/bin/env python3
"""Validate the source-owned Tribe release version and an optional CI tag.

Store/TestFlight monotonic floors intentionally do not live here: release upload
must compare those external ledgers separately.  This gate prevents a release
tag from naming one version while its exact Git commit builds another one.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys


VERSION_DEFINITION = re.compile(
    r"^set\(TRIBE_VERSION ([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\)$",
    re.MULTILINE,
)
ANDROID_DEFINITION = re.compile(
    r"^set\(TRIBE_ANDROID_VERSION_CODE ([0-9]+)\)$", re.MULTILINE
)
RELEASE_TAG = re.compile(
    r"^refs/tags/(ios|macos|android)-v"
    r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$"
)
FULL_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class VersionGateError(RuntimeError):
    """A release identity is malformed or not bound to the checked-out source."""


@dataclass(frozen=True)
class ReleaseVersion:
    full: str
    marketing: str
    apple_build: int
    android_base: int

    @property
    def android_tracks(self) -> tuple[int, int]:
        return self.android_base, self.android_base + 1


def parse_source_version(version_file: Path) -> ReleaseVersion:
    if not version_file.is_file() or version_file.is_symlink():
        raise VersionGateError("tribe_version.cmake must be a regular source file")
    source = version_file.read_text(encoding="utf-8")
    versions = VERSION_DEFINITION.findall(source)
    android_codes = ANDROID_DEFINITION.findall(source)
    if len(versions) != 1:
        raise VersionGateError(
            "TRIBE_VERSION must have one canonical four-part definition"
        )
    if len(android_codes) != 1:
        raise VersionGateError(
            "TRIBE_ANDROID_VERSION_CODE must have one canonical integer definition"
        )

    major, minor, patch, build = (int(part) for part in versions[0])
    android_base = int(android_codes[0])
    if major < 5 or build <= 0 or android_base <= 0:
        raise VersionGateError(
            "release version/build values are outside the Tribe range"
        )
    full = f"{major}.{minor}.{patch}.{build}"
    marketing = f"{major}.{minor}.{patch}"
    return ReleaseVersion(full, marketing, build, android_base)


def validate_catalog_release_facts(path: Path, version: ReleaseVersion) -> None:
    """Byte-contract the actual shipping app build/Qt-architecture namespaces."""
    if not path.is_file() or path.is_symlink():
        raise VersionGateError(
            "catalog release request facts must be a regular source file"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise VersionGateError(
            f"catalog release request facts are invalid: {error}"
        ) from error
    expected = {
        "marketing_version": version.marketing,
        "release_version": version.full,
        "schema": 1,
        "shipping_flavors": [
            {
                "adapter": "apple_network_extension",
                "app_builds": [version.apple_build],
                "architectures": ["arm64"],
                "platform": "ios",
            },
            {
                "adapter": "android_vpn_service",
                "app_builds": list(version.android_tracks),
                # These are QSysInfo::currentCpuArchitecture() values. Android
                # package ABI aliases (arm64-v8a/armeabi-v7a) are a different
                # namespace and must never reach catalog compatibility rows.
                "architectures": ["arm64", "arm", "x86", "x86_64"],
                "platform": "android",
            },
            {
                "adapter": "macos_daemon_ipc",
                "app_builds": [version.apple_build],
                "architectures": ["arm64"],
                "platform": "macos",
            },
        ],
    }
    if document != expected:
        raise VersionGateError(
            "catalog release request facts drift from source version/platform matrix"
        )


def git_commit(root: Path, revision: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", revision],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    commit = result.stdout.strip()
    if result.returncode != 0 or not FULL_SHA1.fullmatch(commit):
        detail = result.stderr.strip() or "revision did not resolve to one commit"
        raise VersionGateError(f"cannot resolve {revision}: {detail}")
    return commit


def validate_ci_identity(
    root: Path,
    version: ReleaseVersion,
    ref: str,
    expected_head: str,
) -> None:
    head = git_commit(root, "HEAD^{commit}")
    if expected_head:
        if not FULL_SHA1.fullmatch(expected_head):
            raise VersionGateError("expected CI head is not a full lowercase Git SHA-1")
        if head != expected_head:
            raise VersionGateError(
                f"checked-out HEAD {head} does not match CI source commit {expected_head}"
            )

    if not ref.startswith("refs/tags/"):
        return
    match = RELEASE_TAG.fullmatch(ref)
    if match is None:
        raise VersionGateError(
            "release tags must be ios-v, macos-v or android-v plus the exact four-part version"
        )
    tagged_version = match.group(2)
    if tagged_version != version.full:
        raise VersionGateError(
            f"tag names version {tagged_version}, but source defines {version.full}"
        )
    tagged_commit = git_commit(root, f"{ref}^{{commit}}")
    if tagged_commit != head:
        raise VersionGateError(
            f"tag resolves to {tagged_commit}, but checked-out source is {head}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--expected-head", default=os.environ.get("GITHUB_SHA", ""))
    args = parser.parse_args()

    root = args.source_root.resolve()
    try:
        version = parse_source_version(root / "tribe_version.cmake")
        validate_catalog_release_facts(
            root / "metadata/catalog-release-request-facts.json", version
        )
        validate_ci_identity(root, version, args.ref, args.expected_head)
    except (OSError, UnicodeError, VersionGateError) as error:
        print(f"release version gate failed: {error}", file=sys.stderr)
        return 1

    first, second = version.android_tracks
    print(
        "Release version gate passed: "
        f"app={version.full}, marketing={version.marketing}, "
        f"Apple build={version.apple_build}, Android tracks={first}/{second}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
