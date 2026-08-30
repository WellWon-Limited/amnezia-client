#!/usr/bin/env python3
"""Fail-closed identity and side-effect gate for the staged macOS engines."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "metadata" / "engine-lock.json"
MANIFEST_ARGUMENT = "--tribe-engine-manifest-v1"
SANDBOX_PROFILE = """\
(version 1)
(allow default)
(deny network*)
(deny file-write*)
"""


def fail(message: str) -> NoReturn:
    raise SystemExit(f"macOS engine artifact rejected: {message}")


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    if set(value) != keys:
        fail(f"{label} key set drift: {sorted(value)}")
    return value


def unique_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def tree_snapshot(root: Path) -> tuple[tuple[str, int, int, int, int], ...]:
    records: list[tuple[str, int, int, int, int]] = []
    for path in sorted((root, *root.rglob("*"))):
        info = path.lstat()
        records.append((
            "." if path == root else path.relative_to(root).as_posix(),
            stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode),
            info.st_size,
            info.st_mtime_ns,
            info.st_ino,
        ))
    return tuple(records)


def run_read_only(binary: Path, arguments: list[str], audit_root: Path) -> subprocess.CompletedProcess[str]:
    sandbox = Path("/usr/bin/sandbox-exec")
    if not sandbox.is_file():
        fail("/usr/bin/sandbox-exec is required to deny filesystem/network side effects")
    environment = {
        "HOME": str(audit_root / "home"),
        "TMPDIR": str(audit_root / "tmp"),
        "XDG_CACHE_HOME": str(audit_root / "cache"),
        "XDG_CONFIG_HOME": str(audit_root / "config"),
        "XDG_DATA_HOME": str(audit_root / "data"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for value in environment.values():
        if value.startswith(str(audit_root)):
            Path(value).mkdir(mode=0o700, exist_ok=True)
    try:
        return subprocess.run(
            [str(sandbox), "-p", SANDBOX_PROFILE, str(binary), *arguments],
            cwd=audit_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        fail(f"{binary.name} identity probe timed out: {error}")


def check_manifest(document: Any, lock: dict[str, Any], info: dict[str, Any]) -> None:
    root = exact_object(document, {"type", "schema", "app", "engines"}, "manifest")
    if root["type"] != "engine_manifest_v1" or root["schema"] != 1:
        fail("manifest type/schema drift")

    app = exact_object(root["app"], {"version", "build"}, "manifest.app")
    marketing_version = info.get("CFBundleShortVersionString")
    if not isinstance(marketing_version, str) or not marketing_version:
        fail("staged app has no marketing version")
    try:
        expected_build = int(str(info["CFBundleVersion"]))
    except (KeyError, TypeError, ValueError):
        fail("staged app has no numeric CFBundleVersion")
    if isinstance(app["build"], bool) or app["build"] != expected_build:
        fail("manifest build does not match the staged app")
    if app["version"] != f"{marketing_version}.{expected_build}":
        fail("manifest full release version does not match marketing version plus build")

    engines = root["engines"]
    if not isinstance(engines, list) or len(engines) != 2:
        fail("manifest must contain exactly AWG and Xray")
    by_protocol: dict[str, dict[str, Any]] = {}
    engine_keys = {
        "protocol", "adapter", "adapterVersion", "declaredCoreVersion",
        "sourceCommit", "abi", "runtimeCoreVersion", "runtimeVersionProbed",
        "versionEvidence", "capabilities",
    }
    for index, raw_engine in enumerate(engines):
        engine = exact_object(raw_engine, engine_keys, f"manifest.engines[{index}]")
        protocol = engine.get("protocol")
        if protocol not in {"awg", "xray"} or protocol in by_protocol:
            fail("manifest engine protocol inventory drift")
        if engine["runtimeCoreVersion"] is not None or engine["runtimeVersionProbed"] is not False:
            fail(f"{protocol}: unsupported runtime probe claim")
        by_protocol[protocol] = engine

    locked_engines = lock["engines"]
    awg_lock = locked_engines[lock["runtime_assets"]["macos-awg-runtime"]["engine_ref"]]
    xray_lock = locked_engines[lock["runtime_assets"]["macos-xray-runtime"]["engine_ref"]]
    expected = {
        "awg": {
            "adapter": "awg-go",
            "adapterVersion": awg_lock["conan_version"],
            "declaredCoreVersion": awg_lock["conan_version"],
            "sourceCommit": awg_lock["source_commit"],
            "abi": awg_lock["abi"],
            "versionEvidence": "compile_time_lock_plus_artifact_probe",
            "capabilities": awg_lock["capabilities"],
        },
        "xray": {
            "adapter": "amnezia-xray-bindings",
            "adapterVersion": xray_lock["conan_version"],
            "declaredCoreVersion": xray_lock["embedded_xray_core"],
            "sourceCommit": xray_lock["source_commit"],
            "abi": xray_lock["abi"],
            "versionEvidence": "compile_time_lock_plus_linked_symbol_probe",
            "capabilities": xray_lock["capabilities"],
        },
    }
    for protocol, fields in expected.items():
        engine = by_protocol[protocol]
        for key, value in fields.items():
            if engine[key] != value:
                fail(f"{protocol}: {key} does not match engine-lock.json")


def main() -> int:
    parser = argparse.ArgumentParser()
    artifact = parser.add_mutually_exclusive_group(required=True)
    artifact.add_argument("--app", type=Path)
    artifact.add_argument("--runtime-root", type=Path)
    parser.add_argument(
        "--app-info", type=Path,
        help="required with --runtime-root; staged app Info.plist binding",
    )
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    args = parser.parse_args()

    if sys.platform != "darwin":
        fail("this artifact gate must run on macOS")
    if args.app is not None:
        if args.app_info is not None:
            fail("--app-info is only valid with --runtime-root")
        if args.app.is_symlink() or not args.app.is_dir():
            fail("--app must be a non-symlink app directory")
        app = args.app.resolve(strict=True)
        runtime_root = app / "Contents" / "MacOS"
        relocated_data_root = app / "Contents" / "Resources" / "daemon-runtime"
        if relocated_data_root.exists():
            if relocated_data_root.is_symlink() or not relocated_data_root.is_dir():
                fail("relocated daemon data must be a non-symlink directory")
            if any((runtime_root / name).exists() for name in ("geoip.dat", "geosite.dat", "pf")):
                fail("daemon data exists in both code and resource bundle locations")
            data_root = relocated_data_root
        else:
            # The staging gate runs before the sealed payload relocates data; the final product
            # gate runs after it.  Both states are closed and ambiguity is rejected above.
            data_root = runtime_root
        info_path = app / "Contents" / "Info.plist"
        artifact_root = app
    else:
        if args.runtime_root is None or args.runtime_root.is_symlink() \
                or not args.runtime_root.is_dir():
            fail("--runtime-root must be a non-symlink directory")
        if args.app_info is None or args.app_info.is_symlink() \
                or not args.app_info.is_file():
            fail("--runtime-root requires a non-symlink --app-info file")
        runtime_root = args.runtime_root.resolve(strict=True)
        data_root = runtime_root
        info_path = args.app_info.resolve(strict=True)
        artifact_root = runtime_root
    if args.lock.is_symlink() or not args.lock.is_file():
        fail("--lock must be a non-symlink regular file")
    lock_path = args.lock.resolve(strict=True)
    try:
        lock = json.loads(
            lock_path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read engine lock: {error}")

    service = runtime_root / "Tribe-service"
    awg = runtime_root / "amneziawg-go"
    openvpn = runtime_root / "openvpn"
    tun2socks = runtime_root / "tun2socks"
    geoip = data_root / "geoip.dat"
    geosite = data_root / "geosite.dat"
    for path in (service, awg, openvpn, tun2socks, geoip, geosite, info_path):
        if path.is_symlink() or not path.is_file():
            fail(f"missing non-symlink staged artifact: {path}")
    try:
        with info_path.open("rb") as stream:
            info = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as error:
        fail(f"cannot read staged Info.plist: {error}")

    service_tree_before = tree_snapshot(artifact_root)
    with tempfile.TemporaryDirectory(prefix="tribe-engine-identity.") as temporary:
        audit_root = Path(temporary)
        for directory in ("home", "tmp", "cache", "config", "data"):
            (audit_root / directory).mkdir(mode=0o700)
        audit_before = tree_snapshot(audit_root)
        service_result = run_read_only(service, [MANIFEST_ARGUMENT], audit_root)
        audit_after_service = tree_snapshot(audit_root)
        if service_result.returncode != 0:
            fail(f"service manifest probe rc={service_result.returncode}: {service_result.stderr.strip()}")
        if service_result.stderr:
            fail(f"service manifest probe wrote stderr: {service_result.stderr.strip()}")
        if audit_after_service != audit_before:
            fail("service manifest probe changed its isolated HOME/TMP/XDG tree")
        if tree_snapshot(artifact_root) != service_tree_before:
            fail("service manifest probe changed the staged artifact tree")
        if service_result.stdout.count("\n") != 1 or not service_result.stdout.endswith("\n"):
            fail("service manifest probe must emit exactly one JSON line")
        try:
            manifest = json.loads(
                service_result.stdout,
                object_pairs_hook=unique_object_pairs,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"service manifest probe emitted invalid JSON: {error}")
        check_manifest(manifest, lock, info)

        awg_result = run_read_only(awg, ["--version"], audit_root)
        if awg_result.returncode != 0 or awg_result.stderr:
            fail(f"AWG version probe failed: {awg_result.stderr.strip()}")
        if (tree_snapshot(audit_root) != audit_before
                or tree_snapshot(artifact_root) != service_tree_before):
            fail("AWG version probe had filesystem side effects")
        expected_awg_version = lock["engines"]["awg-go"]["conan_version"]
        first_line = awg_result.stdout.splitlines()[0] if awg_result.stdout else ""
        if first_line != f"amneziawg-go {expected_awg_version}":
            fail("AWG artifact version does not match engine-lock.json")

        openvpn_result = run_read_only(openvpn, ["--version"], audit_root)
        if openvpn_result.returncode != 0 or openvpn_result.stderr:
            fail(f"OpenVPN version probe failed: {openvpn_result.stderr.strip()}")
        openvpn_lines = openvpn_result.stdout.splitlines()
        expected_openvpn = lock["runtime_assets"]["openvpn"]["conan_version"]
        expected_openssl = lock["runtime_assets"]["openssl"]["conan_version"]
        if (not openvpn_lines
                or not openvpn_lines[0].startswith(f"OpenVPN {expected_openvpn} ")
                or len(openvpn_lines) < 2
                or not openvpn_lines[1].startswith(
                    f"library versions: OpenSSL {expected_openssl} ")):
            fail("OpenVPN/OpenSSL runtime versions do not match engine-lock.json")
        if (tree_snapshot(audit_root) != audit_before
                or tree_snapshot(artifact_root) != service_tree_before):
            fail("OpenVPN version probe had filesystem side effects")

        tun_result = run_read_only(tun2socks, ["--version"], audit_root)
        if tun_result.returncode != 0 or tun_result.stderr:
            fail(f"tun2socks version probe failed: {tun_result.stderr.strip()}")
        tun_lines = tun_result.stdout.splitlines()
        tun_lock = lock["runtime_assets"]["tun2socks"]
        if (len(tun_lines) != 2
                or tun_lines[0] != f"tun2socks-{tun_lock['conan_version']}"
                or not tun_lines[1].endswith(f", {tun_lock['source_commit']}")):
            fail("tun2socks runtime version/commit does not match engine-lock.json")
        if (tree_snapshot(audit_root) != audit_before
                or tree_snapshot(artifact_root) != service_tree_before):
            fail("tun2socks version probe had filesystem side effects")

    geo_lock = lock["runtime_assets"]["v2ray-rules-dat"]
    for path, field in ((geoip, "geoip_sha256"), (geosite, "geosite_sha256")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != geo_lock[field]:
            fail(f"{path.name} does not match the pinned desktop geodata")

    nm = subprocess.run(
        ["/usr/bin/nm", "-gU", str(service)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if nm.returncode != 0:
        fail(f"cannot inspect linked Xray symbols: {nm.stderr.strip()}")
    linked_symbols = {
        "_amnezia_xray_configure", "_amnezia_xray_free",
        "_amnezia_xray_setloghandler", "_amnezia_xray_setsockcallback",
        "_amnezia_xray_start", "_amnezia_xray_stop",
    }
    actual_symbols = {
        line.split()[-1] for line in nm.stdout.splitlines() if line.split()
    }
    missing = sorted(linked_symbols - actual_symbols)
    if missing:
        fail(f"Tribe-service is not linked to the closed Xray C ABI: {missing}")

    strings = subprocess.run(
        ["/usr/bin/strings", "-a", str(service)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if strings.returncode != 0:
        fail(f"cannot inspect linked Xray Go modules: {strings.stderr.strip()}")
    lines = strings.stdout.splitlines()
    module_versions: dict[str, set[str]] = {}
    for module, version in zip(lines, lines[1:]):
        if module in {
            "github.com/xtls/xray-core",
            "github.com/amnezia-vpn/amnezia-xray-core",
        }:
            module_versions.setdefault(module, set()).add(version)
    expected_xray_core = f"v{lock['engines']['amnezia-xray-bindings']['embedded_xray_core']}"
    for module in (
        "github.com/xtls/xray-core",
        "github.com/amnezia-vpn/amnezia-xray-core",
    ):
        if module_versions.get(module) != {expected_xray_core}:
            fail(f"linked Xray Go module drift for {module}: {module_versions.get(module)}")

    print("macOS runtime artifact identity OK (AWG/Xray/OpenVPN/OpenSSL/tun2socks/geodata; sandboxed no-write/no-network probes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
