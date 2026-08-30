#!/usr/bin/env python3
"""Validate a signed Tribe iOS xcarchive or exported IPA, fail closed.

This gate intentionally validates the exported artifact again: a successful
Xcode compile or archive is not evidence that export kept the expected app,
Network Extension, provisioning profiles, entitlements, versions, or engines.
"""

from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import hashlib
import hmac
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
from typing import Any, NoReturn
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_BUNDLE_ID = "hk.wellwon.vpn"
NE_BUNDLE_ID = "hk.wellwon.vpn.network-extension"
APP_NAME = "AmneziaVPN.app"
NE_NAME = "AmneziaVPNNetworkExtension.appex"
APP_EXECUTABLE = "AmneziaVPN"
NE_EXECUTABLE = "AmneziaVPNNetworkExtension"
TEAM_ID = "Q7DVH5MCWF"
APP_GROUP = "group.hk.wellwon.tribe"
KEYCHAIN_GROUPS = {
    f"{TEAM_ID}.hk.wellwon.tribe",
    f"{TEAM_ID}.group.hk.wellwon.zanaves",
}
MINIMUM_IOS = "17.0"
EXPECTED_QT = "6.11.1"
EXPECTED_XCODE_CODE = "2640"
EXPECTED_IOS_SDK = "iphoneos26.4"
MAX_IPA_MEMBERS = 100_000
MAX_IPA_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024
MAX_IPA_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FULL_GIT_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_IPA_TOP_LEVELS = {"Payload", "SwiftSupport"}
ALLOWED_ZIP_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


class ArtifactError(RuntimeError):
    """A release artifact violated the closed shipping contract."""


def reject(message: str) -> NoReturn:
    raise ArtifactError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def command(arguments: list[str], *, label: str) -> bytes:
    result = subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        reject(f"{label} failed: {detail[:1000]}")
    # Apple inspection tools inconsistently write human-readable display data
    # to stderr, while plist/binary payloads go to stdout. Never append stderr
    # to a plist: trailing diagnostics make otherwise valid CMS/entitlements
    # ambiguous. Fall back to stderr only when stdout is genuinely empty.
    return result.stdout if result.stdout else result.stderr


def source_version(source_root: pathlib.Path) -> tuple[str, str]:
    version_file = source_root / "tribe_version.cmake"
    require(version_file.is_file() and not version_file.is_symlink(),
            "tribe_version.cmake is not a regular source file")
    matches = re.findall(
        r"^\s*set\(TRIBE_VERSION\s+([0-9]+\.[0-9]+\.[0-9]+\.([0-9]+))\s*\)\s*$",
        version_file.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    require(len(matches) == 1, "TRIBE_VERSION must have one canonical four-part definition")
    full, build = matches[0]
    marketing = ".".join(full.split(".")[:3])
    require(str(int(build)) == build and int(build) > 0,
            "Apple build number must be a canonical positive integer")
    return marketing, build


def source_commit(source_root: pathlib.Path) -> tuple[str, str]:
    full = command(
        ["git", "-C", str(source_root), "rev-parse", "--verify", "HEAD"],
        label="Git source identity",
    ).decode().strip()
    short = command(
        ["git", "-C", str(source_root), "rev-parse", "--short", "HEAD"],
        label="Git short source identity",
    ).decode().strip()
    require(FULL_GIT_SHA1.fullmatch(full) is not None,
            "source commit is not a full lowercase Git SHA-1")
    require(re.fullmatch(r"[0-9a-f]{7,40}", short) is not None and full.startswith(short),
            "source short commit is not canonical")
    return full, short


def canonical_zip_path(name: str) -> tuple[str, ...]:
    require(name and "\x00" not in name and "\\" not in name,
            f"unsafe IPA member name {name!r}")
    require(not name.startswith("/") and not re.match(r"^[A-Za-z]:", name),
            f"absolute IPA member name {name!r}")
    parts = name.rstrip("/").split("/")
    require(parts and all(part not in {"", ".", ".."} for part in parts),
            f"non-canonical IPA member name {name!r}")
    for part in parts:
        require(unicodedata.normalize("NFC", part) == part,
                f"non-NFC IPA member name {name!r}")
        require(":" not in part and all(ord(character) >= 0x20 for character in part),
                f"ambiguous IPA member name {name!r}")
    return tuple(parts)


def validate_ipa_zip_layout(archive: zipfile.ZipFile) -> str:
    """Validate ZIP identity/layout before any name-based read or extraction."""
    entries = archive.infolist()
    require(0 < len(entries) <= MAX_IPA_MEMBERS,
            f"IPA member count must be 1..{MAX_IPA_MEMBERS}")
    names = [entry.filename for entry in entries]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    require(not duplicates, f"IPA contains duplicate ZIP member names: {duplicates[:10]}")

    normalized: dict[str, str] = {}
    total_size = 0
    payload_apps: set[str] = set()
    appex_paths: set[str] = set()
    provisioning_paths: set[str] = set()
    for entry in entries:
        parts = canonical_zip_path(entry.filename)
        folded = "/".join(parts).casefold()
        previous = normalized.setdefault(folded, entry.filename.rstrip("/"))
        require(previous == entry.filename.rstrip("/"),
                f"case/Unicode-colliding IPA members: {previous!r}, {entry.filename!r}")
        require(parts[0] in ALLOWED_IPA_TOP_LEVELS,
                f"unexpected IPA top-level path {parts[0]!r}")
        require(not (entry.flag_bits & 0x1), f"encrypted IPA member {entry.filename!r}")
        require(entry.compress_type in ALLOWED_ZIP_COMPRESSION,
                f"unsupported compression for IPA member {entry.filename!r}")
        require(0 <= entry.file_size <= MAX_IPA_MEMBER_BYTES,
                f"oversized IPA member {entry.filename!r}")
        total_size += entry.file_size
        require(total_size <= MAX_IPA_UNCOMPRESSED_BYTES,
                "IPA uncompressed size exceeds the release limit")
        if entry.file_size and entry.compress_size:
            require(entry.file_size <= entry.compress_size * 10_000,
                    f"implausible compression ratio for IPA member {entry.filename!r}")

        unix_mode = (entry.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        expected_directory = entry.filename.endswith("/")
        if file_type:
            require(file_type in {stat.S_IFREG, stat.S_IFDIR},
                    f"special/symlink IPA member {entry.filename!r}")
            require((file_type == stat.S_IFDIR) == expected_directory,
                    f"ZIP type/name mismatch for {entry.filename!r}")
        require(not (unix_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)),
                f"special permission bits on IPA member {entry.filename!r}")
        require(not (unix_mode & 0o022),
                f"group/world-writable IPA member {entry.filename!r}")

        if parts[0] == "Payload":
            if parts == ("Payload",) and expected_directory:
                continue
            require(len(parts) >= 2 and parts[1].endswith(".app"),
                    f"loose file outside the payload app: {entry.filename!r}")
            payload_apps.add(parts[1])
            for index, part in enumerate(parts):
                if part.endswith(".app"):
                    require(index == 1,
                            f"unexpected nested application in IPA: {entry.filename!r}")
                if part.endswith(".appex"):
                    appex_paths.add("/".join(parts[: index + 1]))
            if parts[-1] == "embedded.mobileprovision":
                provisioning_paths.add("/".join(parts))
        elif parts[0] == "SwiftSupport":
            if len(parts) == 1:
                require(expected_directory, "SwiftSupport root must be a directory")
            elif len(parts) == 2:
                require(parts[1] == "iphoneos" and expected_directory,
                        f"unexpected SwiftSupport directory {entry.filename!r}")
            else:
                require(len(parts) == 3 and parts[1] == "iphoneos"
                        and parts[2].endswith(".dylib") and not expected_directory,
                        f"unexpected SwiftSupport member {entry.filename!r}")

    require(payload_apps == {APP_NAME},
            f"IPA payload app mismatch: {sorted(payload_apps)}")
    app_prefix = f"Payload/{APP_NAME}"
    require(f"{app_prefix}/Info.plist" in names,
            "IPA payload app Info.plist is missing")
    expected_appex = f"{app_prefix}/PlugIns/{NE_NAME}"
    require(appex_paths == {expected_appex},
            f"IPA Network Extension matrix mismatch: {sorted(appex_paths)}")
    require(f"{expected_appex}/Info.plist" in names,
            "IPA Network Extension Info.plist is missing")
    require(provisioning_paths == {
        f"{app_prefix}/embedded.mobileprovision",
        f"{expected_appex}/embedded.mobileprovision",
    }, f"IPA provisioning profile matrix mismatch: {sorted(provisioning_paths)}")
    return app_prefix


def extract_ipa(artifact: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    try:
        with zipfile.ZipFile(artifact) as archive:
            app_prefix = validate_ipa_zip_layout(archive)
            for entry in archive.infolist():
                parts = canonical_zip_path(entry.filename)
                target = destination.joinpath(*parts)
                unix_mode = (entry.external_attr >> 16) & 0o777
                if entry.is_dir():
                    target.mkdir(mode=unix_mode or 0o755, parents=True, exist_ok=True)
                    os.chmod(target, unix_mode or 0o755)
                    continue
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target, flags, unix_mode or 0o644)
                try:
                    with os.fdopen(descriptor, "wb") as output, archive.open(entry) as source:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                    descriptor = -1
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                os.chmod(target, unix_mode or 0o644)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        reject(f"invalid IPA ZIP: {error}")
    app = destination / app_prefix
    validate_swift_support(destination, app)
    return app


def load_plist(path: pathlib.Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is not a regular file")
    require(path.stat().st_nlink == 1 and path.stat().st_size <= 4 * 1024 * 1024,
            f"{label} has unsafe link count or size")
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        reject(f"{label} is not a valid plist: {error}")
    require(isinstance(value, dict), f"{label} root must be a dictionary")
    return value


def validate_tree(root: pathlib.Path, label: str) -> None:
    require(root.is_dir() and not root.is_symlink(), f"{label} must be a real directory")
    identities: dict[str, str] = {}
    for path in [root, *root.rglob("*")]:
        relative = path.relative_to(root).as_posix() or "."
        folded = unicodedata.normalize("NFC", relative).casefold()
        previous = identities.setdefault(folded, relative)
        require(previous == relative,
                f"case/Unicode-colliding bundle paths: {previous!r}, {relative!r}")
        details = path.lstat()
        require(not stat.S_ISLNK(details.st_mode), f"symlink in {label}: {relative}")
        require(stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode),
                f"special file in {label}: {relative}")
        require(not (details.st_mode & 0o022),
                f"group/world-writable path in {label}: {relative}")
        if stat.S_ISREG(details.st_mode):
            require(details.st_nlink == 1, f"hard-linked file in {label}: {relative}")


def validate_swift_support(extraction_root: pathlib.Path, app: pathlib.Path) -> None:
    support = extraction_root / "SwiftSupport"
    if not support.exists():
        return
    validate_tree(support, "IPA SwiftSupport")
    platform = support / "iphoneos"
    require(platform.is_dir() and not platform.is_symlink()
            and set(support.iterdir()) == {platform},
            "IPA SwiftSupport must contain only iphoneos")
    libraries = sorted(path for path in platform.iterdir()
                       if path.is_file() and not path.is_symlink())
    require(libraries and all(path.suffix == ".dylib" for path in libraries)
            and len(libraries) == len(list(platform.iterdir())),
            "IPA SwiftSupport has an invalid runtime matrix")
    frameworks = app / "Frameworks"
    for library in libraries:
        embedded = frameworks / library.name
        require(embedded.is_file() and not embedded.is_symlink()
                and hmac.compare_digest(digest(library), digest(embedded)),
                f"SwiftSupport runtime does not byte-match the app: {library.name}")


def executable_for(bundle: pathlib.Path, info: dict[str, Any], expected: str,
                   label: str) -> pathlib.Path:
    executable_name = info.get("CFBundleExecutable")
    require(executable_name == expected, f"{label} executable name mismatch")
    require("/" not in executable_name and executable_name not in {".", ".."},
            f"{label} executable name is unsafe")
    executable = bundle / executable_name
    require(executable.is_file() and not executable.is_symlink(),
            f"{label} executable is not a regular file")
    details = executable.stat()
    require(details.st_nlink == 1 and details.st_mode & 0o111,
            f"{label} executable is hard-linked or non-executable")
    return executable


def validate_info(info: dict[str, Any], *, bundle_id: str, package_type: str,
                  marketing: str, build: str, label: str) -> None:
    require(info.get("CFBundleIdentifier") == bundle_id, f"{label} bundle ID mismatch")
    require(info.get("CFBundlePackageType") == package_type,
            f"{label} package type mismatch")
    require(info.get("CFBundleShortVersionString") == marketing,
            f"{label} marketing version mismatch")
    require(info.get("CFBundleVersion") == build, f"{label} build number mismatch")
    require(info.get("CFBundleSupportedPlatforms") == ["iPhoneOS"],
            f"{label} platform matrix is not device-only iPhoneOS")
    require(info.get("MinimumOSVersion") == MINIMUM_IOS,
            f"{label} minimum iOS version mismatch")
    require(info.get("UIDeviceFamily") == [1, 2], f"{label} device family mismatch")
    require(info.get("UIRequiredDeviceCapabilities") == ["arm64"],
            f"{label} must require the arm64 device capability")
    require(info.get("ITSAppUsesNonExemptEncryption") is False,
            f"{label} export-compliance declaration mismatch")
    require(info.get("DTXcode") == EXPECTED_XCODE_CODE,
            f"{label} was not built by shipping Xcode 26.4")
    require(info.get("DTSDKName") == EXPECTED_IOS_SDK,
            f"{label} iOS SDK identity mismatch")


def validate_app_icon(app: pathlib.Path, info: dict[str, Any],
                      source_root: pathlib.Path) -> str:
    require(info.get("CFBundleIconName") == "AppIcon",
            "app Info.plist primary icon name mismatch")
    for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        section = info.get(key)
        require(isinstance(section, dict), f"app Info.plist lacks {key}")
        primary = section.get("CFBundlePrimaryIcon")
        require(isinstance(primary, dict)
                and primary.get("CFBundleIconName") == "AppIcon",
                f"app Info.plist {key} does not select AppIcon")
        files = primary.get("CFBundleIconFiles")
        require(isinstance(files, list) and files
                and all(isinstance(name, str) and name and "/" not in name for name in files),
                f"app Info.plist {key} has an invalid icon-file matrix")
    assets = app / "Assets.car"
    require(assets.is_file() and not assets.is_symlink() and assets.stat().st_nlink == 1,
            "app Assets.car is missing, linked, or not a regular file")
    checker = source_root / "metadata/check_ios_appicon.py"
    require(checker.is_file() and not checker.is_symlink(),
            "iOS AppIcon validator is missing from the reviewed source")
    command(
        [sys.executable, str(checker), "--source-root", str(source_root),
         "--assets-car", str(assets)],
        label="iOS AppIcon source/artifact validation",
    )
    return digest(assets)


def parse_codesign_display(bundle: pathlib.Path, bundle_id: str, label: str) -> dict[str, str]:
    requirement = (
        f'anchor apple generic and identifier "{bundle_id}" '
        f'and certificate leaf[subject.OU] = "{TEAM_ID}"'
    )
    command(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures",
         f"-R={requirement}", str(bundle)],
        label=f"{label} signature verification",
    )
    output = command(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(bundle)],
        label=f"{label} signature display",
    ).decode("utf-8", "replace")

    def exact_field(field: str) -> str:
        values = re.findall(rf"^{re.escape(field)}=(.+)$", output, re.MULTILINE)
        require(len(values) == 1, f"{label} signature has ambiguous {field}")
        return values[0].strip()

    identifier = exact_field("Identifier")
    team = exact_field("TeamIdentifier")
    authorities = re.findall(r"^Authority=(.+)$", output, re.MULTILINE)
    require(identifier == bundle_id and team == TEAM_ID,
            f"{label} signature identity/team mismatch")
    require(len(authorities) >= 2 and authorities[0].startswith("Apple Distribution:"),
            f"{label} is not signed by an Apple Distribution identity")
    require("Signature=adhoc" not in output, f"{label} has an ad-hoc signature")
    return {"identifier": identifier, "team": team, "authority": authorities[0]}


def signed_entitlements(bundle: pathlib.Path, label: str) -> dict[str, Any]:
    output = command(
        ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(bundle)],
        label=f"{label} signed entitlement extraction",
    )
    start = output.find(b"<?xml")
    require(start >= 0, f"{label} signed entitlements are not an XML plist")
    try:
        entitlements = plistlib.loads(output[start:])
    except plistlib.InvalidFileException as error:
        reject(f"{label} signed entitlements are invalid: {error}")
    require(isinstance(entitlements, dict), f"{label} signed entitlements must be a dictionary")
    return entitlements


def validate_entitlements(entitlements: dict[str, Any], *, bundle_id: str,
                          is_app: bool, label: str) -> None:
    allowed = {
        "application-identifier",
        "beta-reports-active",
        "com.apple.developer.networking.networkextension",
        "com.apple.developer.team-identifier",
        "com.apple.security.application-groups",
        "get-task-allow",
        "keychain-access-groups",
    }
    if is_app:
        allowed |= {
            "aps-environment",
            "com.apple.developer.associated-domains",
            "com.apple.security.files.user-selected.read-write",
        }
    extras = sorted(set(entitlements) - allowed)
    require(not extras, f"{label} has unreviewed signed entitlements: {extras}")
    require(entitlements.get("application-identifier") == f"{TEAM_ID}.{bundle_id}",
            f"{label} application identifier entitlement mismatch")
    require(entitlements.get("com.apple.developer.team-identifier") == TEAM_ID,
            f"{label} team entitlement mismatch")
    require(entitlements.get("get-task-allow", False) is False,
            f"{label} distribution artifact permits debugging")
    require(entitlements.get("com.apple.developer.networking.networkextension")
            == ["packet-tunnel-provider"],
            f"{label} packet-tunnel entitlement mismatch")
    require(entitlements.get("com.apple.security.application-groups") == [APP_GROUP],
            f"{label} application-group entitlement mismatch")
    keychain = entitlements.get("keychain-access-groups")
    require(isinstance(keychain, list) and len(keychain) == len(KEYCHAIN_GROUPS)
            and set(keychain) == KEYCHAIN_GROUPS,
            f"{label} keychain access-group matrix mismatch")
    if is_app:
        require(entitlements.get("aps-environment") == "production",
                "app APNs entitlement must be production")
        require(entitlements.get("com.apple.developer.associated-domains")
                == ["applinks:tribevpn.com"],
                "app associated-domain entitlement mismatch")
        require(entitlements.get("com.apple.security.files.user-selected.read-write") is True,
                "app user-selected-file entitlement mismatch")
    else:
        require("aps-environment" not in entitlements
                and "com.apple.developer.associated-domains" not in entitlements
                and "com.apple.security.files.user-selected.read-write" not in entitlements,
                "Network Extension inherited app-only entitlements")


def validate_profile(bundle: pathlib.Path, *, bundle_id: str, label: str,
                     expected_sha256: str, expected_certificate_sha256: str,
                     signed: dict[str, Any]) -> dict[str, str]:
    profile_path = bundle / "embedded.mobileprovision"
    require(profile_path.is_file() and not profile_path.is_symlink(),
            f"{label} embedded provisioning profile is missing")
    require(profile_path.stat().st_nlink == 1 and profile_path.stat().st_size <= 4 * 1024 * 1024,
            f"{label} provisioning profile has unsafe size/link count")
    profile_sha256 = digest(profile_path)
    require(hmac.compare_digest(profile_sha256, expected_sha256),
            f"{label} provisioning profile SHA-256 mismatch")
    decoded = command(
        ["/usr/bin/security", "cms", "-D", "-i", str(profile_path)],
        label=f"{label} provisioning profile decode",
    )
    try:
        profile = plistlib.loads(decoded)
    except plistlib.InvalidFileException as error:
        reject(f"{label} provisioning profile plist is invalid: {error}")
    require(isinstance(profile, dict), f"{label} provisioning profile must be a dictionary")
    uuid = profile.get("UUID")
    require(isinstance(uuid, str)
            and re.fullmatch(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", uuid),
            f"{label} provisioning UUID is invalid")
    teams = profile.get("TeamIdentifier")
    require(teams == [TEAM_ID], f"{label} provisioning team mismatch")
    require(profile.get("ApplicationIdentifierPrefix") == [TEAM_ID],
            f"{label} application identifier prefix mismatch")
    require(profile.get("Platform") == ["iOS"], f"{label} profile is not iOS-only")
    require("ProvisionedDevices" not in profile and profile.get("ProvisionsAllDevices") is not True,
            f"{label} profile is not App Store distribution")
    expiration = profile.get("ExpirationDate")
    require(isinstance(expiration, dt.datetime), f"{label} profile expiration is missing")
    now = dt.datetime.now(tz=expiration.tzinfo) if expiration.tzinfo else dt.datetime.now()
    require(expiration > now + dt.timedelta(days=7),
            f"{label} provisioning profile expires within seven days")
    profile_entitlements = profile.get("Entitlements")
    require(isinstance(profile_entitlements, dict),
            f"{label} profile entitlements are missing")
    require(profile_entitlements.get("application-identifier") == f"{TEAM_ID}.{bundle_id}",
            f"{label} profile application identifier mismatch")
    require(profile_entitlements.get("com.apple.developer.team-identifier") == TEAM_ID,
            f"{label} profile team entitlement mismatch")
    require(profile_entitlements.get("get-task-allow", False) is False,
            f"{label} profile permits debugging")
    certificates = profile.get("DeveloperCertificates")
    require(isinstance(certificates, list) and len(certificates) == 1
            and isinstance(certificates[0], bytes),
            f"{label} profile must authorize exactly one distribution certificate")
    require(hmac.compare_digest(hashlib.sha256(certificates[0]).hexdigest(),
                                expected_certificate_sha256),
            f"{label} profile distribution certificate SHA-256 mismatch")

    # The profile is the authorization envelope for the actual signed
    # entitlements. A keychain wildcard is the only accepted Apple profile
    # expansion; every emitted keychain group is still closed above.
    for key, value in signed.items():
        # App Sandbox's user-selected-file key is directly reviewable in the
        # signed entitlement but is not a managed provisioning capability and
        # is normally absent from an iOS distribution profile envelope.
        if key in {"beta-reports-active", "get-task-allow",
                   "com.apple.security.files.user-selected.read-write"}:
            continue
        authorized = profile_entitlements.get(key)
        if key == "keychain-access-groups" and authorized == [f"{TEAM_ID}.*"]:
            continue
        require(authorized == value,
                f"{label} signed entitlement {key!r} is not authorized by its profile")
    name = profile.get("Name")
    require(isinstance(name, str) and name.strip(), f"{label} profile name is missing")
    return {"uuid": uuid.upper(), "name": name,
            "expiration": expiration.isoformat(), "sha256": profile_sha256}


def certificate_sha256(bundle: pathlib.Path, label: str) -> str:
    with tempfile.TemporaryDirectory(prefix="tribe-ios-cert-") as directory:
        prefix = pathlib.Path(directory) / "certificate"
        command(
            ["/usr/bin/codesign", "--display",
             f"--extract-certificates={prefix}", str(bundle)],
            label=f"{label} certificate extraction",
        )
        leaf = pathlib.Path(f"{prefix}0")
        require(leaf.is_file() and not leaf.is_symlink() and leaf.stat().st_nlink == 1,
                f"{label} signing leaf was not extracted")
        return digest(leaf)


def macho_files(root: pathlib.Path) -> list[pathlib.Path]:
    magics = {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    }
    result = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.stat().st_size < 4:
            continue
        with path.open("rb") as stream:
            if stream.read(4) in magics:
                result.append(path)
    return sorted(result)


def macho_rpaths(executable: pathlib.Path, label: str) -> list[str]:
    output = command(["/usr/bin/otool", "-l", str(executable)],
                     label=f"{label} load-command inspection").decode("utf-8", "replace")
    lines = output.splitlines()
    values: list[str] = []
    for index, line in enumerate(lines):
        if line.strip() != "cmd LC_RPATH":
            continue
        for candidate in lines[index + 1:index + 6]:
            match = re.match(r"\s*path (\S+) \(offset [0-9]+\)\s*$", candidate)
            if match:
                values.append(match.group(1))
                break
        else:
            reject(f"{label} has malformed LC_RPATH")
    require(len(values) == len(set(values)), f"{label} has duplicate LC_RPATH entries")
    return values


def expand_loader_path(value: str, *, loader_dir: pathlib.Path,
                       app_executable_dir: pathlib.Path) -> pathlib.Path | None:
    if value == "@loader_path" or value.startswith("@loader_path/"):
        return loader_dir / value.removeprefix("@loader_path/") if value != "@loader_path" else loader_dir
    if value == "@executable_path" or value.startswith("@executable_path/"):
        return (app_executable_dir / value.removeprefix("@executable_path/")
                if value != "@executable_path" else app_executable_dir)
    return None


def validate_macho_closure(app: pathlib.Path, *, expected_certificate_sha256: str,
                           source_root: pathlib.Path) -> dict[str, Any]:
    files = macho_files(app)
    require(files, "iOS app contains no Mach-O code")
    app_root = app.resolve(strict=True)
    forbidden_bytes = [
        b"/.conan2/", b"\\.conan2\\", b"/private/tmp/", b"/Users/",
        str(source_root).encode(),
    ]
    records: dict[str, Any] = {}
    for executable in files:
        relative = executable.relative_to(app).as_posix()
        label = f"Mach-O {relative}"
        require_arm64(executable, label)
        command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
                 str(executable)], label=f"{label} signature verification")
        display = command(["/usr/bin/codesign", "--display", "--verbose=4", str(executable)],
                          label=f"{label} signature display").decode("utf-8", "replace")
        team_values = re.findall(r"^TeamIdentifier=(.+)$", display, re.MULTILINE)
        authorities = re.findall(r"^Authority=(.+)$", display, re.MULTILINE)
        require(team_values == [TEAM_ID] and authorities
                and authorities[0].startswith("Apple Distribution:"),
                f"{label} does not have the exact distribution team/identity")
        leaf_sha256 = certificate_sha256(executable, label)
        require(hmac.compare_digest(leaf_sha256, expected_certificate_sha256),
                f"{label} signing leaf SHA-256 mismatch")

        binary = executable.read_bytes()
        leaked = [needle.decode("utf-8", "replace") for needle in forbidden_bytes
                  if needle and needle in binary]
        require(not leaked, f"{label} leaks local build paths: {leaked}")
        build = command(["/usr/bin/vtool", "-show-build", str(executable)],
                        label=f"{label} platform inspection").decode("utf-8", "replace")
        platforms = re.findall(r"^\s*platform\s+(\S+)\s*$", build, re.MULTILINE)
        minimums = re.findall(r"^\s*minos\s+(\S+)\s*$", build, re.MULTILINE)
        require(platforms == ["IOS"] and minimums == [MINIMUM_IOS],
                f"{label} platform/minimum mismatch: {platforms}/{minimums}")

        linked = command(["/usr/bin/otool", "-L", str(executable)],
                         label=f"{label} dependency inspection").decode("utf-8", "replace")
        dependencies = []
        for line in linked.splitlines()[1:]:
            stripped = line.strip()
            if not stripped:
                continue
            dependency = stripped.split(" (compatibility version", 1)[0]
            require(dependency and not dependency.startswith(("/Users/", "/private/")),
                    f"{label} links a local absolute dependency: {dependency}")
            dependencies.append(dependency)
        rpaths = macho_rpaths(executable, label)
        for dependency in dependencies:
            if dependency.startswith(("/System/Library/Frameworks/", "/usr/lib/")):
                continue
            candidates: list[pathlib.Path] = []
            if dependency.startswith("@rpath/"):
                suffix = dependency.removeprefix("@rpath/")
                for rpath in rpaths:
                    expanded = expand_loader_path(
                        rpath, loader_dir=executable.parent,
                        app_executable_dir=app,
                    )
                    if expanded is not None:
                        candidates.append(expanded / suffix)
            else:
                expanded = expand_loader_path(
                    dependency, loader_dir=executable.parent,
                    app_executable_dir=app,
                )
                if expanded is not None:
                    candidates.append(expanded)
            require(candidates, f"{label} has unsupported dependency path {dependency!r}")
            resolved = [candidate.resolve(strict=True) for candidate in candidates
                        if candidate.exists() and not candidate.is_symlink()]
            require(any(path == app_root or app_root in path.parents for path in resolved),
                    f"{label} dependency does not resolve inside the signed app: {dependency}")
        records[relative] = {
            "sha256": digest(executable),
            "certificate_sha256": leaf_sha256,
            "dependencies": dependencies,
            "rpaths": rpaths,
        }
    return records


def require_arm64(executable: pathlib.Path, label: str) -> None:
    output = command(["/usr/bin/lipo", "-archs", str(executable)],
                     label=f"{label} architecture inspection").decode().strip().split()
    require(output == ["arm64"], f"{label} architecture matrix mismatch: {output}")


def digest(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def require_binary_needles(path: pathlib.Path, needles: dict[str, str], label: str) -> None:
    data = path.read_bytes()
    missing = [name for name, value in needles.items() if value.encode() not in data]
    require(not missing, f"{label} lacks immutable build evidence: {missing}")


def dsyms_for_archive(archive: pathlib.Path, executables: dict[str, pathlib.Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    dsym_root = archive / "dSYMs"
    require(dsym_root.is_dir() and not dsym_root.is_symlink(), "xcarchive dSYMs directory is missing")
    for name, executable in executables.items():
        suffix = ".app.dSYM" if name == "app" else ".appex.dSYM"
        expected_name = f"{executable.name}{suffix}"
        matches = [path for path in dsym_root.rglob(expected_name)
                   if path.is_dir() and not path.is_symlink()]
        require(len(matches) == 1, f"xcarchive {name} dSYM matrix mismatch")
        dwarf = matches[0] / "Contents" / "Resources" / "DWARF" / executable.name
        require(dwarf.is_file() and not dwarf.is_symlink(), f"xcarchive {name} DWARF is missing")
        executable_uuid = command(["/usr/bin/dwarfdump", "--uuid", str(executable)],
                                  label=f"{name} executable UUID").decode().strip()
        dsym_uuid = command(["/usr/bin/dwarfdump", "--uuid", str(dwarf)],
                            label=f"{name} dSYM UUID").decode().strip()
        pattern = re.compile(r"^UUID: ([0-9A-F-]+) \(arm64\)", re.MULTILINE)
        executable_values = pattern.findall(executable_uuid)
        dsym_values = pattern.findall(dsym_uuid)
        require(len(executable_values) == 1 and executable_values == dsym_values,
                f"xcarchive {name} dSYM UUID does not match its executable")
        result[name] = executable_values[0]
    return result


def validate_receipt(path: pathlib.Path, pinned: str, source_root: pathlib.Path,
                     full_commit: str) -> dict[str, Any]:
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            "runtime receipt must be an absolute regular file")
    require(LOWER_SHA256.fullmatch(pinned) is not None,
            "runtime receipt SHA-256 must be lowercase hexadecimal")
    raw = path.read_bytes()
    require(hmac.compare_digest(hashlib.sha256(raw).hexdigest(), pinned),
            "runtime receipt SHA-256 mismatch")
    command(
        [sys.executable, str(source_root / "metadata/check_platform_runtime_receipt.py"),
         "--file", str(path), "--sha256", pinned, "--platform", "ios",
         "--source-root", str(source_root)],
        label="iOS platform runtime receipt validation",
    )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"runtime receipt is invalid JSON: {error}")
    require(document.get("source_commit") == full_commit,
            "runtime receipt/source commit mismatch")
    return document


def validate_engine_lock(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    require(path.is_file() and not path.is_symlink(), "engine lock must be a regular file")
    raw = path.read_bytes()
    try:
        lock = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"engine lock is invalid JSON: {error}")
    require(isinstance(lock, dict) and isinstance(lock.get("engines"), dict),
            "engine lock root is invalid")
    for name in ("awg-apple", "amnezia-libxray"):
        require(isinstance(lock["engines"].get(name), dict),
                f"engine lock lacks {name}")
    return lock, hashlib.sha256(raw).hexdigest()


def expected_build_manifest(*, full_commit: str, marketing: str, build: str,
                            receipt_sha256: str, lock_sha256: str,
                            lock: dict[str, Any]) -> dict[str, Any]:
    apple = lock["engines"]["awg-apple"]
    xray = lock["engines"]["amnezia-libxray"]
    return {
        "Schema": 1,
        "SourceCommit": full_commit,
        "Version": f"{marketing}.{build}",
        "MarketingVersion": marketing,
        "Build": build,
        "QtVersion": EXPECTED_QT,
        "StoreBuild": True,
        "RuntimeReceiptSHA256": receipt_sha256,
        "EngineLockSHA256": lock_sha256,
        "GuardCapabilities": {"AWG": True, "Xray": True},
        "Engines": {
            "AWG": {
                "Adapter": apple["conan_version"],
                "SourceCommit": apple["source_commit"],
                "Core": apple["embedded_awg_go"],
                "ABI": apple["abi"],
            },
            "Xray": {
                "Adapter": apple["embedded_xray_adapter"],
                "SourceCommit": xray["source_commit"],
                "Core": apple["embedded_xray_core"],
                "ABI": apple["xray_abi"],
            },
        },
    }


def validate_build_manifest(bundle: pathlib.Path, expected: dict[str, Any],
                            label: str) -> dict[str, Any]:
    manifest = load_plist(bundle / "TribeBuildManifest.plist",
                          f"{label} TribeBuildManifest.plist")
    require(manifest == expected, f"{label} signed build manifest mismatch")
    return manifest


def validate_privacy_manifest(bundle: pathlib.Path, source: pathlib.Path,
                              label: str) -> None:
    actual = load_plist(bundle / "PrivacyInfo.xcprivacy", f"{label} privacy manifest")
    reviewed = load_plist(source, f"reviewed {label} privacy manifest")
    require(actual == reviewed, f"{label} privacy manifest differs from reviewed source")


def locate_archive_app(archive: pathlib.Path) -> pathlib.Path:
    require(archive.is_dir() and not archive.is_symlink(),
            "xcarchive must be a real directory")
    products = archive / "Products" / "Applications"
    require(products.is_dir() and not products.is_symlink(),
            "xcarchive Products/Applications is missing")
    apps = [path for path in products.iterdir()
            if path.name.endswith(".app") and path.is_dir() and not path.is_symlink()]
    require(len(apps) == 1 and apps[0].name == APP_NAME,
            f"xcarchive application matrix mismatch: {[path.name for path in apps]}")
    archive_info = load_plist(archive / "Info.plist", "xcarchive Info.plist")
    properties = archive_info.get("ApplicationProperties")
    require(archive_info.get("ArchiveVersion") == 2 and isinstance(properties, dict),
            "xcarchive metadata schema mismatch")
    require(properties.get("ApplicationPath") == f"Applications/{APP_NAME}"
            and properties.get("CFBundleIdentifier") == APP_BUNDLE_ID
            and properties.get("Team") == TEAM_ID,
            "xcarchive application identity metadata mismatch")
    signing_identity = properties.get("SigningIdentity")
    require(isinstance(signing_identity, str)
            and signing_identity.startswith("Apple Distribution:"),
            "xcarchive metadata is not distribution-signed")
    return apps[0]


def validate_bundles(app: pathlib.Path, *, marketing: str, build: str,
                     full_commit: str, short_commit: str, lock: dict[str, Any],
                     lock_digest: str, receipt_sha256: str,
                     certificate_sha256_pin: str, app_profile_sha256: str,
                     ne_profile_sha256: str, source_root: pathlib.Path,
                     archive: pathlib.Path | None) -> dict[str, Any]:
    validate_tree(app, "iOS app")
    app_info = load_plist(app / "Info.plist", "app Info.plist")
    validate_info(app_info, bundle_id=APP_BUNDLE_ID, package_type="APPL",
                  marketing=marketing, build=build, label="app")
    require(app_info.get("com.wireguard.ios.app_group_id") == APP_GROUP,
            "app Info.plist application group mismatch")
    assets_car_sha256 = validate_app_icon(app, app_info, source_root)
    app_executable = executable_for(app, app_info, APP_EXECUTABLE, "app")

    plugins = app / "PlugIns"
    require(plugins.is_dir() and not plugins.is_symlink(), "app PlugIns directory is missing")
    extensions = [path for path in plugins.iterdir()
                  if path.name.endswith(".appex") and path.is_dir() and not path.is_symlink()]
    require(len(extensions) == 1 and extensions[0].name == NE_NAME,
            f"app extension matrix mismatch: {[path.name for path in extensions]}")
    ne = extensions[0]
    ne_info = load_plist(ne / "Info.plist", "Network Extension Info.plist")
    validate_info(ne_info, bundle_id=NE_BUNDLE_ID, package_type="XPC!",
                  marketing=marketing, build=build, label="Network Extension")
    require(ne_info.get("com.wireguard.ios.app_group_id") == APP_GROUP,
            "Network Extension Info.plist application group mismatch")
    extension_point = ne_info.get("NSExtension")
    require(extension_point == {
        "NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel",
        "NSExtensionPrincipalClass": f"{NE_EXECUTABLE}.PacketTunnelProvider",
    }, "Network Extension entry point mismatch")
    ne_executable = executable_for(ne, ne_info, NE_EXECUTABLE, "Network Extension")

    expected_manifest = expected_build_manifest(
        full_commit=full_commit, marketing=marketing, build=build,
        receipt_sha256=receipt_sha256, lock_sha256=lock_digest, lock=lock,
    )
    app_manifest = validate_build_manifest(app, expected_manifest, "app")
    ne_manifest = validate_build_manifest(ne, expected_manifest, "Network Extension")
    require(app_manifest == ne_manifest,
            "app and Network Extension signed build manifests diverge")
    validate_privacy_manifest(app, source_root / "client/ios/app/PrivacyInfo.xcprivacy", "app")
    validate_privacy_manifest(
        ne, source_root / "client/ios/networkextension/PrivacyInfo.xcprivacy",
        "Network Extension",
    )

    require_arm64(app_executable, "app")
    require_arm64(ne_executable, "Network Extension")
    app_signature = parse_codesign_display(app, APP_BUNDLE_ID, "app")
    ne_signature = parse_codesign_display(ne, NE_BUNDLE_ID, "Network Extension")
    app_entitlements = signed_entitlements(app, "app")
    ne_entitlements = signed_entitlements(ne, "Network Extension")
    validate_entitlements(app_entitlements, bundle_id=APP_BUNDLE_ID, is_app=True, label="app")
    validate_entitlements(ne_entitlements, bundle_id=NE_BUNDLE_ID, is_app=False,
                          label="Network Extension")
    app_profile = validate_profile(
        app, bundle_id=APP_BUNDLE_ID, label="app",
        expected_sha256=app_profile_sha256,
        expected_certificate_sha256=certificate_sha256_pin,
        signed=app_entitlements,
    )
    ne_profile = validate_profile(
        ne, bundle_id=NE_BUNDLE_ID, label="Network Extension",
        expected_sha256=ne_profile_sha256,
        expected_certificate_sha256=certificate_sha256_pin,
        signed=ne_entitlements,
    )
    require(app_profile["uuid"] != ne_profile["uuid"],
            "app and Network Extension unexpectedly share one provisioning profile")

    apple = lock["engines"]["awg-apple"]
    xray = lock["engines"]["amnezia-libxray"]
    require_binary_needles(app_executable, {"source Git commit": short_commit}, "app executable")
    require_binary_needles(ne_executable, {
        "AWG adapter": apple["conan_version"],
        "AWG source commit": apple["source_commit"],
        "AWG core": apple["embedded_awg_go"],
        "AWG ABI": apple["abi"],
        "AWG trailers capability": "awg.random_trailers",
        "AWG cookies capability": "awg.disable_cookies",
        "Xray adapter": apple["embedded_xray_adapter"],
        "Xray source commit": xray["source_commit"],
        "Xray core": apple["embedded_xray_core"],
        "Xray ABI": apple["xray_abi"],
        "Xray socket protection result": "xray.socket_protection_result",
        "Xray transport capability": "xray.vless.reality.vision.tcp",
    }, "Network Extension executable")

    closure = validate_macho_closure(
        app, expected_certificate_sha256=certificate_sha256_pin,
        source_root=source_root,
    )
    require(app_executable.relative_to(app).as_posix() in closure
            and ne_executable.relative_to(app).as_posix() in closure,
            "Mach-O signature closure omitted the app or Network Extension executable")

    executables = {"app": app_executable, "network_extension": ne_executable}
    return {
        "app": {
            "bundle_id": APP_BUNDLE_ID,
            "marketing_version": marketing,
            "build": build,
            "executable_sha256": digest(app_executable),
            "assets_car_sha256": assets_car_sha256,
            "signature": app_signature,
            "profile": app_profile,
        },
        "network_extension": {
            "bundle_id": NE_BUNDLE_ID,
            "marketing_version": marketing,
            "build": build,
            "executable_sha256": digest(ne_executable),
            "signature": ne_signature,
            "profile": ne_profile,
        },
        "signed_build_manifest": expected_manifest,
        "macho_closure": closure,
        "dsyms": dsyms_for_archive(archive, executables) if archive else None,
    }


def write_report(path: pathlib.Path, report: dict[str, Any]) -> None:
    require(path.is_absolute() and path.parent.is_dir() and not path.exists(),
            "report path must be a new absolute file in an existing directory")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=pathlib.Path, required=True)
    parser.add_argument("--runtime-receipt", type=pathlib.Path, required=True)
    parser.add_argument("--runtime-receipt-sha256", required=True)
    parser.add_argument("--certificate-sha256", required=True,
                        help="pinned DER SHA-256 of the Apple Distribution leaf")
    parser.add_argument("--app-profile-sha256", required=True)
    parser.add_argument("--ne-profile-sha256", required=True)
    parser.add_argument("--engine-lock", type=pathlib.Path,
                        default=ROOT / "metadata/engine-lock.json")
    parser.add_argument("--source-root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()

    try:
        source_root = args.source_root.resolve(strict=True)
        require(source_root == ROOT.resolve(), "validator must run against its own source root")
        for label, value in (
            ("certificate", args.certificate_sha256),
            ("app profile", args.app_profile_sha256),
            ("Network Extension profile", args.ne_profile_sha256),
        ):
            require(LOWER_SHA256.fullmatch(value) is not None,
                    f"{label} SHA-256 pin must be lowercase hexadecimal")
        marketing, build = source_version(source_root)
        full_commit, short_commit = source_commit(source_root)
        receipt = validate_receipt(args.runtime_receipt, args.runtime_receipt_sha256,
                                   source_root, full_commit)
        lock, lock_digest = validate_engine_lock(args.engine_lock)

        artifact = args.artifact
        archive: pathlib.Path | None = None
        artifact_digest: str | None = None
        if artifact.name.endswith(".xcarchive"):
            archive = artifact
            app = locate_archive_app(archive)
            artifact_kind = "xcarchive"
        elif artifact.suffix == ".ipa":
            require(artifact.is_file() and not artifact.is_symlink(),
                    "IPA must be a regular non-symlink file")
            artifact_digest = digest(artifact)
            temporary = tempfile.TemporaryDirectory(prefix="tribe-ios-ipa-")
            try:
                app = extract_ipa(artifact, pathlib.Path(temporary.name))
                bundle_report = validate_bundles(
                    app, marketing=marketing, build=build, full_commit=full_commit,
                    short_commit=short_commit, lock=lock, lock_digest=lock_digest,
                    receipt_sha256=args.runtime_receipt_sha256,
                    certificate_sha256_pin=args.certificate_sha256,
                    app_profile_sha256=args.app_profile_sha256,
                    ne_profile_sha256=args.ne_profile_sha256,
                    source_root=source_root, archive=None,
                )
            finally:
                temporary.cleanup()
            artifact_kind = "ipa"
        else:
            reject("artifact must be a .xcarchive directory or .ipa file")

        if archive is not None:
            bundle_report = validate_bundles(
                app, marketing=marketing, build=build, full_commit=full_commit,
                short_commit=short_commit, lock=lock, lock_digest=lock_digest,
                receipt_sha256=args.runtime_receipt_sha256,
                certificate_sha256_pin=args.certificate_sha256,
                app_profile_sha256=args.app_profile_sha256,
                ne_profile_sha256=args.ne_profile_sha256,
                source_root=source_root, archive=archive,
            )

        report = {
            "schema": 1,
            "artifact_kind": artifact_kind,
            "artifact_sha256": artifact_digest,
            "source_commit": full_commit,
            "runtime_receipt_sha256": args.runtime_receipt_sha256,
            "runtime_receipt_source_commit": receipt["source_commit"],
            "engine_lock_sha256": lock_digest,
            "certificate_sha256": args.certificate_sha256,
            **bundle_report,
        }
        write_report(args.report, report)
        print(
            f"iOS {artifact_kind} release artifact OK: "
            f"{APP_BUNDLE_ID} {marketing} ({build}); AWG 3.1 + Xray; "
            f"report={args.report}"
        )
        return 0
    except ArtifactError as error:
        print(f"iOS release artifact rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
