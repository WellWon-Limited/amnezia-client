#!/usr/bin/env python3
"""Static/reproducibility gate for the embedded AWG and Xray engine matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "metadata" / "engine-lock.json"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def contains(path: str, needle: str, errors: list[str]) -> None:
    require(needle in read(path), f"{path}: missing {needle!r}", errors)


def patch_parse_error(path: Path) -> str | None:
    """Return git's parse error for a malformed patch without needing its source tree."""
    result = subprocess.run(
        ["git", "apply", "--numstat", str(path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode == 0:
        return None
    return result.stdout.strip() or f"git apply exited {result.returncode}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apple-source",
        type=Path,
        help="optional clean official awg-apple v3.1.4 tree for git apply --check",
    )
    parser.add_argument(
        "--awg-android-source",
        type=Path,
        help="optional clean official awg-android v3.1.20260814 tree for protected-start patch check",
    )
    parser.add_argument(
        "--libxray-source",
        type=Path,
        help="optional clean official amnezia-libxray v1.0.3 tree for 16-KB patch check",
    )
    parser.add_argument(
        "--hev-source",
        type=Path,
        help="optional clean official hev-socks5-tunnel v2.15.0 tree for lifecycle patch check",
    )
    args = parser.parse_args()
    errors: list[str] = []
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    engines = lock.get("engines", {})
    runtime_assets = lock.get("runtime_assets", {})

    referenced_patches = {
        value
        for engine in engines.values()
        for key, value in engine.items()
        if (key == "patch_file" or key.endswith("_patch_file"))
        and isinstance(value, str)
    }
    for relative_path in sorted(referenced_patches):
        patch_path = ROOT / relative_path
        require(patch_path.is_file(), f"referenced patch is missing: {relative_path}", errors)
        if patch_path.is_file():
            parse_error = patch_parse_error(patch_path)
            require(parse_error is None,
                    f"referenced patch is malformed: {relative_path}: {parse_error}", errors)

    require(lock.get("app_identity") == {
                "release_version": "APP_VERSION (= APP_MAJOR_VERSION.APP_BUILD)",
                "marketing_version": (
                    "APP_MAJOR_VERSION / CFBundleShortVersionString / PackageInfo.versionName"
                ),
                "apple_and_desktop_build": "CMAKE_PROJECT_VERSION_TWEAK",
                "android_build": (
                    "PackageInfo.longVersionCode / TRIBE_ANDROID_VERSION_CODE"
                ),
            }, "application identity contract drift", errors)
    require(set(runtime_assets) == {
                "openvpn", "tun2socks", "openssl", "v2ray-rules-dat",
                "macos-awg-runtime", "macos-xray-runtime",
            }, "runtime asset inventory drift", errors)

    require(lock.get("schema") == 1, "engine-lock schema must be 1", errors)
    require(lock.get("release_ready") is False, "source-only slice must not claim release readiness", errors)
    expected_caps = {
        "awg.random_trailers",
        "awg.disable_cookies",
        "xray.vless.reality.vision.tcp",
    }
    require(set(lock.get("capability_contract", [])) == expected_caps,
            "canonical capability contract drift", errors)

    for name, item in engines.items():
        require(re.fullmatch(r"[0-9a-f]{40}", item.get("source_commit", "")) is not None,
                f"{name}: source_commit must be a full SHA-1", errors)
        require(re.fullmatch(r"[0-9a-f]{64}", item.get("archive_sha256", "")) is not None,
                f"{name}: archive_sha256 must be SHA-256", errors)

    expected_android_abis = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
    for name in ("awg-android", "amnezia-libxray"):
        packaged = engines[name].get("android_release_packaged_sha256") or {}
        if name == "amnezia-libxray":
            artifact_status = engines[name].get("artifact_status")
            if artifact_status == "pending_rebuild_after_controller_slot":
                require(not packaged and engines[name].get("android_artifact_sha256") is None,
                        "amnezia-libxray: pending rebuild must not retain stale artifact hashes",
                        errors)
                continue
            if artifact_status == "rebuilt_reproducible_pending_release_packaging":
                require(not packaged,
                        "amnezia-libxray: pre-packaging lock must not claim Gradle ABI hashes",
                        errors)
                require(re.fullmatch(
                            r"[0-9a-f]{64}",
                            engines[name].get("android_artifact_sha256", ""),
                        ) is not None,
                        "amnezia-libxray: reproducible AAR lock must be SHA-256", errors)
                continue
        require(set(packaged) == expected_android_abis,
                f"{name}: release-packaged Android ABI hash matrix drift", errors)
        for abi, digest in packaged.items():
            require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                    f"{name}: release-packaged {abi} digest must be SHA-256", errors)

    top = read("conanfile.py")
    requirements = {
        "awg-go": "awg-go/3.1.20260814",
        "awg-android": "awg-android/3.1.20260814",
        "awg-apple": "awg-apple/3.1.4-tribe.3",
        "amnezia-libxray": "amnezia-libxray/1.0.3-tribe.1",
        "amnezia-xray-bindings": "amnezia-xray-bindings/1.4.0",
        "hev-socks5-tunnel": "hev-socks5-tunnel/2.15.0",
    }
    for name, requirement in requirements.items():
        require(f'self.requires("{requirement}"' in top,
                f"top-level Conan requirement missing: {requirement}", errors)
        require(requirement.split("/", 1)[1] == engines[name]["conan_version"],
                f"{name}: lock/requirement version drift", errors)

    desktop_geo = runtime_assets.get("v2ray-rules-dat", {})
    require(desktop_geo.get("conan_version") == "202603162227",
            "desktop geodata lock version drift", errors)
    require(desktop_geo.get("source_url") ==
            "https://github.com/Loyalsoldier/v2ray-rules-dat",
            "desktop geodata source drift", errors)
    require(desktop_geo.get("platforms") == ["desktop", "macos"],
            "desktop geodata platform allowlist drift", errors)
    for field in ("geoip_sha256", "geosite_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", desktop_geo.get(field, "")) is not None,
                f"desktop geodata {field} must be SHA-256", errors)
    require('self.requires("v2ray-rules-dat/202603162227"' in top,
            "top-level Conan requirement missing: v2ray-rules-dat/202603162227", errors)

    runtime_recipe_assets = {
        "openvpn": {
            "version": "2.7.0",
            "source_url": "https://github.com/OpenVPN/openvpn",
            "source_commit": "ee1577744fb09af760dc319d57746e6abc55db85",
            "archive_sha256": "1a65d8587f932c13d55b1f175ff2e1d61d795d9092788662e888054854d4ee3d",
            "platforms": ["linux", "macos", "windows"],
            "recipe": "recipes/openvpn/conanfile.py",
        },
        "tun2socks": {
            "version": "2.6.0",
            "source_url": "https://github.com/xjasonlyu/tun2socks",
            "source_commit": "4127937ea7c450a5230b273f406c9410acec2be7",
            "archive_sha256": "a7ef9cec1c30dfe9971af89a8aac767fd3d2a4df833e92b635642c2f0204c701",
            "platforms": ["linux", "macos", "windows"],
            "recipe": "recipes/tun2socks/conanfile.py",
        },
        "openssl": {
            "version": "3.6.2",
            "source_url": "https://github.com/openssl/openssl",
            "source_commit": "fe686e15d84334b284f883118ed92f64b409b3aa",
            "archive_sha256": "aaf51a1fe064384f811daeaeb4ec4dce7340ec8bd893027eee676af31e83a04f",
            "platforms": ["android", "ios", "linux", "macos", "macos-ne", "windows"],
            "recipe": "recipes/openssl/conanfile.py",
        },
    }
    for name, expected in runtime_recipe_assets.items():
        asset = runtime_assets.get(name, {})
        require(set(asset) == {"conan_version", "source_url", "source_commit",
                               "archive_sha256", "platforms"},
                f"{name}: runtime asset key set drift", errors)
        require(asset.get("conan_version") == expected["version"],
                f"{name}: runtime asset version drift", errors)
        require(asset.get("source_url") == expected["source_url"],
                f"{name}: runtime asset source drift", errors)
        require(asset.get("source_commit") == expected["source_commit"]
                and re.fullmatch(r"[0-9a-f]{40}", asset.get("source_commit", "")) is not None,
                f"{name}: runtime asset source commit drift", errors)
        require(asset.get("archive_sha256") == expected["archive_sha256"],
                f"{name}: runtime asset archive SHA-256 drift", errors)
        require(asset.get("platforms") == expected["platforms"],
                f"{name}: runtime asset platform allowlist drift", errors)
        require(f'self.requires("{name}/{expected["version"]}"' in top,
                f"top-level Conan requirement missing: {name}/{expected['version']}", errors)
        recipe = read(expected["recipe"])
        for needle in (
            f'version = "{expected["version"]}"',
            expected["source_url"],
            expected["archive_sha256"],
        ):
            require(needle in recipe,
                    f"{expected['recipe']}: runtime lock binding missing {needle!r}", errors)
        if name == "tun2socks":
            require(expected["source_commit"] in recipe
                    and "BUILD_VERSION=v{self.version}" in recipe
                    and "BUILD_COMMIT={self._source_commit}" in recipe
                    and '"LDFLAGS += -buildid=",' in recipe,
                    "tun2socks recipe must inject the locked archive identity", errors)

    engine_runtime_assets = {
        "macos-awg-runtime": {
            "engine_ref": "awg-go",
            "artifact": "amneziawg-go",
            "identity_probe": "--version",
            "platforms": ["macos"],
        },
        "macos-xray-runtime": {
            "engine_ref": "amnezia-xray-bindings",
            "artifact": "Tribe-service",
            "linkage": "linked",
            "identity_probe": "--tribe-engine-manifest-v1",
            "platforms": ["macos"],
        },
    }
    for name, expected in engine_runtime_assets.items():
        asset = runtime_assets.get(name, {})
        require(asset == expected, f"{name}: engine runtime binding drift", errors)
        engine_ref = asset.get("engine_ref", "")
        require(engine_ref in engines, f"{name}: unknown engine_ref {engine_ref!r}", errors)
        require("conan_version" not in asset and "archive_sha256" not in asset,
                f"{name}: must reference the canonical engine pin, not duplicate it", errors)

    recipe_checks = {
        "recipes/awg-go/conanfile.py": [
            'version = "3.1.20260814"',
            engines["awg-go"]["archive_sha256"],
            engines["awg-go"]["source_commit"],
            'const Version = "{self.version}"',
        ],
        "recipes/awg-android/conanfile.py": [
            'version = "3.1.20260814"',
            engines["awg-android"]["source_commit"],
            "Git(self, folder=self._upstream_root).get_commit()",
            "github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814",
            engines["awg-android"]["patch_sha256"],
            engines["awg-android"]["source_overlay_sha256"],
            engines["awg-android"]["abi"],
        ],
        "recipes/awg-apple/conanfile.py": [
            'version = "3.1.4-tribe.3"',
            '_upstream_version = "3.1.4"',
            engines["awg-apple"]["archive_sha256"],
            engines["awg-apple"]["source_commit"],
            "apply_conandata_patches(self)",
            'copy(self, "*.h", src=os.path.join(self.source_folder, "Sources", "WireGuardKitC")',
            '"AWG_APPLE_SOURCE_DIR"',
            '"miphoneos-version-min"',
            '"mmacosx-version-min"',
            'self.settings.get_safe("os.version")',
            '"WireGuardKitGo/vendor/*"',
        ],
        "recipes/amnezia-libxray/conanfile.py": [
            'version = "1.0.3-tribe.1"',
            engines["amnezia-libxray"]["archive_sha256"],
            engines["amnezia-libxray"]["source_commit"],
            '"1.260728.0"',
            'artifact lock is pending',
            engines["amnezia-libxray"]["geo_data"]["geosite_release"],
            engines["amnezia-libxray"]["geo_data"]["geosite_sha256"],
            engines["amnezia-libxray"]["geo_data"]["geoip_release"],
            engines["amnezia-libxray"]["geo_data"]["geoip_sha256"],
            str(engines["amnezia-libxray"]["geo_data"]["timestamp_epoch"]),
            "download(",
            "apply_conandata_patches(self)",
        ],
        "recipes/amnezia-xray-bindings/conanfile.py": [
            'version = "1.4.0"',
            engines["amnezia-xray-bindings"]["archive_sha256"],
            engines["amnezia-xray-bindings"]["source_commit"],
            '"1.260728.0"',
            '"XRAY_BINDINGS_RUNTIME_VERSION_PROBE": False',
        ],
        "recipes/hev-socks5-tunnel/conanfile.py": [
            'version = "2.15.0"',
            engines["hev-socks5-tunnel"]["archive_sha256"],
            engines["hev-socks5-tunnel"]["source_commit"],
            "_restore_archive_symlinks",
            "link_count != 31",
            "apply_conandata_patches(self)",
        ] + [value
             for item in engines["hev-socks5-tunnel"]["submodules"].values()
             for value in (item["commit"], item["archive_sha256"])],
        "recipes/v2ray-rules-dat/conanfile.py": [
            'version = "202603162227"',
            desktop_geo.get("source_url", ""),
            desktop_geo.get("geoip_sha256", ""),
            desktop_geo.get("geosite_sha256", ""),
        ],
    }
    for path, needles in recipe_checks.items():
        for needle in needles:
            contains(path, needle, errors)

    xray_artifact_status = engines["amnezia-libxray"].get("artifact_status")
    require(xray_artifact_status in {
                "pending_rebuild_after_controller_slot",
                "rebuilt_reproducible_pending_release_packaging",
                "release_packaged_locked",
            }, "amnezia-libxray: unknown artifact lifecycle status", errors)
    if xray_artifact_status == "pending_rebuild_after_controller_slot":
        contains("recipes/amnezia-libxray/conanfile.py",
                 "_android_artifact_sha256 = None", errors)
    else:
        contains("recipes/amnezia-libxray/conanfile.py",
                 engines["amnezia-libxray"]["android_artifact_sha256"], errors)

    apple = engines["awg-apple"]
    patch_path = ROOT / apple["patch_file"]
    apple_sequential_patch_paths = [
        patch_path,
        ROOT / apple["xray_socket_patch_file"],
        ROOT / apple["guarded_settings_patch_file"],
    ]
    require(patch_path.is_file(), "awg-apple Tribe patch is missing", errors)
    if patch_path.is_file():
        patch = patch_path.read_bytes()
        actual = hashlib.sha256(patch).hexdigest()
        require(actual == apple["patch_sha256"], "awg-apple Tribe patch checksum drift", errors)
        patch_text = patch.decode("utf-8")
        for symbol in ("wgSetSplitDns", "rebindListenPort", "wrapTunIfEnabled", "dnsfwd.go"):
            require(symbol in patch_text, f"awg-apple Tribe patch lost {symbol}", errors)
        require("TunnelConfiguration+WgQuickConfig.swift" not in patch_text,
                "old unknown-key parser override must not be rebased", errors)
    for label, field, digest_field in (
        ("Xray socket result", "xray_socket_patch_file", "xray_socket_patch_sha256"),
        ("guarded settings owner", "guarded_settings_patch_file",
         "guarded_settings_patch_sha256"),
        ("Xray core controller", "xray_core_controller_patch_file",
         "xray_core_controller_patch_sha256"),
    ):
        extra_patch = ROOT / apple[field]
        require(extra_patch.is_file(), f"awg-apple {label} patch is missing", errors)
        if extra_patch.is_file():
            require(hashlib.sha256(extra_patch.read_bytes()).hexdigest() == apple[digest_field],
                    f"awg-apple {label} patch checksum drift", errors)
    contains("recipes/awg-apple/conandata.yml", '"3.1.4-tribe.3"', errors)
    contains("recipes/awg-apple/conandata.yml", "0002-xray-socket-protection-result.patch", errors)
    contains("recipes/awg-apple/conandata.yml", "0003-guarded-network-settings-owner.patch", errors)
    guarded_settings_patch = read(apple["guarded_settings_patch_file"])
    for needle in (
        "public final class WireGuardGuardPreparation",
        "prepareGuardedTunnel",
        "resolvedEndpointLiterals",
        "reresolveEndpoints: false",
        "self.managesNetworkSettings = guardPreparation == nil",
        "guard self.guardPreparation == nil",
        'Network settings (start): owned by outer guard',
        'Network settings (update): owned by outer guard',
        'Network settings (resume): owned by outer guard',
    ):
        require(needle in guarded_settings_patch,
                f"awg-apple guarded settings patch lost {needle}", errors)
    native_guard_source = read("client/platforms/ios/PacketTunnelProvider+NativeGuard.swift")
    wireguard_provider_source = read("client/platforms/ios/PacketTunnelProvider+WireGuard.swift")
    xray_provider_source = read("client/platforms/ios/PacketTunnelProvider+Xray.swift")
    for needle in ("prepareGuardedWireguard(configuration)",
                   "preparation.networkSettings",
                   "wireGuardPreparation: material.wireGuard",
                   "guardPreparation: prepared.wireGuardPreparation"):
        require(needle in native_guard_source,
                f"Apple guarded PREPARE/ACTIVATE plumbing lost {needle}", errors)
    for needle in ("WireGuardAdapter.prepareGuardedTunnel",
                   "TribeNativeDispatchPolicy.isPublicEndpointLiteral",
                   "guardPreparation.tunnelConfiguration == decodedTunnel"):
        require(needle in wireguard_provider_source,
                f"Apple guarded AWG endpoint freeze lost {needle}", errors)
    require("if xrayConfig.guardedCatalogV2 == true" in xray_provider_source
            and "launchInner()" in xray_provider_source,
            "Apple guarded Xray must not issue a second NE settings mutation", errors)
    for needle in ("go mod vendor", "0004-xray-core-controller-errors.patch",
                   "TestTribeExternalControllerErrorsArePropagated",
                   '"AWG_APPLE_XRAY_SOCKET_ABI"'):
        contains("recipes/awg-apple/conanfile.py", needle, errors)
    apple_recipe_text = read("recipes/awg-apple/conanfile.py")
    require('prep_env.define("GOFLAGS", "")' in apple_recipe_text,
            "awg-apple must clear inherited GOFLAGS before vendoring", errors)
    require('vendor_env.define("GOFLAGS", "-mod=vendor -trimpath -buildvcs=false")'
            in apple_recipe_text,
            "awg-apple must replace inherited GOFLAGS with its vendor/reproducibility policy",
            errors)
    if "with vendor_env.vars(self).apply():" in apple_recipe_text:
        vendor_scope = apple_recipe_text.index("with vendor_env.vars(self).apply():")
        require(vendor_scope
                < apple_recipe_text.index("TestTribeExternalControllerErrorsArePropagated")
                < apple_recipe_text.index("TestTribeXraySockCallbackSlot")
                < apple_recipe_text.index("autotools.make()"),
                "awg-apple Go tests/final make escaped the forced vendor environment", errors)
    contains("deploy/tribe/conan/awg-apple-tribe/README.md",
             "intentionally retired", errors)
    require(not (ROOT / "deploy/tribe/conan/awg-apple-tribe/conanfile.py").exists(),
            "obsolete external-fork AWG Apple recipe must not re-enter release packaging",
            errors)

    android_awg = engines["awg-android"]
    android_awg_patch = ROOT / android_awg["patch_file"]
    android_awg_overlay = ROOT / android_awg["source_overlay_file"]
    require(android_awg_patch.is_file(), "awg-android protected-start JNI patch is missing", errors)
    require(android_awg_overlay.is_file(), "awg-android protected-start source is missing", errors)
    if android_awg_patch.is_file():
        require(hashlib.sha256(android_awg_patch.read_bytes()).hexdigest()
                == android_awg["patch_sha256"],
                "awg-android protected-start JNI patch checksum drift", errors)
    if android_awg_overlay.is_file():
        require(hashlib.sha256(android_awg_overlay.read_bytes()).hexdigest()
                == android_awg["source_overlay_sha256"],
                "awg-android protected-start source checksum drift", errors)
        overlay_text = android_awg_overlay.read_text(encoding="utf-8")
        for needle in ("bind.ready <- err", "case <-bind.release:",
                       "awgPrepareProtected", "awgResumeProtected",
                       "awgProtectedTurnOff"):
            require(needle in overlay_text,
                    f"awg-android protected-start invariant missing: {needle}", errors)

    if args.awg_android_source:
        source = args.awg_android_source.resolve()
        require(source.is_dir(), f"AWG Android source does not exist: {source}", errors)
        if source.is_dir() and android_awg_patch.is_file():
            result = subprocess.run(
                ["patch", "--dry-run", "-p1", "-d", str(source),
                 "-i", str(android_awg_patch)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            require(result.returncode == 0,
                    "protected-start JNI patch does not apply to clean awg-android "
                    f"v3.1.20260814: {result.stdout.strip()}", errors)

    for engine_name in ("amnezia-libxray", "hev-socks5-tunnel"):
        engine = engines[engine_name]
        engine_patch = ROOT / engine["patch_file"]
        require(engine_patch.is_file(), f"{engine_name}: patch is missing", errors)
        if engine_patch.is_file():
            require(hashlib.sha256(engine_patch.read_bytes()).hexdigest() == engine["patch_sha256"],
                    f"{engine_name}: patch checksum drift", errors)

    xray = engines["amnezia-libxray"]
    xray_patch = ROOT / xray["patch_file"]
    xray_geo_patch = ROOT / xray["geo_patch_file"]
    xray_controller_patch = ROOT / xray["controller_patch_file"]
    xray_core_controller_patch = ROOT / xray["core_controller_patch_file"]
    for label, path, digest in (
        ("controller slot", xray_controller_patch, xray["controller_patch_sha256"]),
        ("core controller propagation", xray_core_controller_patch,
         xray["core_controller_patch_sha256"]),
    ):
        require(path.is_file(), f"amnezia-libxray: {label} patch is missing", errors)
        if path.is_file():
            require(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                    f"amnezia-libxray: {label} patch checksum drift", errors)
    require(xray_geo_patch.is_file(), "amnezia-libxray: pinned geo-data patch is missing", errors)
    if xray_geo_patch.is_file():
        require(hashlib.sha256(xray_geo_patch.read_bytes()).hexdigest()
                == xray["geo_patch_sha256"],
                "amnezia-libxray: pinned geo-data patch checksum drift", errors)
        geo_patch_text = xray_geo_patch.read_text(encoding="utf-8")
        for needle in ("+func validateGeoData", '+\tvalidateGeoData(datDir, "geosite", "domain")',
                       '+\tvalidateGeoData(datDir, "geoip", "ip")'):
            require(needle in geo_patch_text,
                    f"amnezia-libxray: geo-data patch lost {needle!r}", errors)
    if xray_patch.is_file():
        xray_patch_text = xray_patch.read_text(encoding="utf-8")
        for needle in ("-X=runtime.modinfo=", "max-page-size=16384", "-trimpath"):
            require(needle in xray_patch_text,
                    f"amnezia-libxray: reproducible Android build patch lost {needle!r}", errors)
    require(xray.get("reproducible_artifact") is True,
            "amnezia-libxray: artifact must remain reproducibility-locked", errors)
    require(xray.get("runtime_modinfo") == "stripped",
            "amnezia-libxray: runtime.modinfo must remain stripped", errors)
    contains("recipes/amnezia-libxray/conandata.yml", xray["patch_file"].split("/", 2)[-1], errors)
    contains("recipes/amnezia-libxray/conandata.yml", xray["geo_patch_file"].split("/", 2)[-1], errors)
    contains("recipes/amnezia-libxray/conandata.yml", xray["controller_patch_file"].split("/", 2)[-1], errors)
    for needle in ("go mod vendor", "amnezia-xray-core@v1.260728.0",
                   'for module_file in ("go.mod", "go.sum")',
                   "go mod edit ",
                   "-replace=github.com/xtls/xray-core=./vendor/github.com/xtls/xray-core",
                   'gomobile_env.define("GOFLAGS", "-mod=mod -trimpath -buildvcs=false")',
                   "gomobile graph escaped the patched local Xray core",
                   "0004-xray-core-controller-errors.patch",
                   'self.info.settings.rm_safe("arch")',
                   'self.info.settings.rm_safe("compiler")',
                   'self.info.settings.rm_safe("os.api_level")',
                   "TestTribeAndroidControllerSlot", "TestTribeExternalControllerErrorsArePropagated"):
        contains("recipes/amnezia-libxray/conanfile.py", needle, errors)
    android_xray_recipe_text = read("recipes/amnezia-libxray/conanfile.py")
    require('prep_env.define("GOFLAGS", "")' in android_xray_recipe_text,
            "amnezia-libxray must clear inherited GOFLAGS before vendoring", errors)
    require('vendor_env.define("GOFLAGS", "-mod=vendor -trimpath -buildvcs=false")'
            in android_xray_recipe_text,
            "amnezia-libxray must replace inherited GOFLAGS with its vendor policy", errors)
    xray_controller_patch_text = xray_controller_patch.read_text(encoding="utf-8")
    require("GOFLAGS='-mod=mod -trimpath -buildvcs=false' gomobile bind"
            in xray_controller_patch_text
            and "GOFLAGS='-mod=mod -trimpath -buildvcs=false' go run main/main.go"
            in xray_controller_patch_text,
            "amnezia-libxray gomobile patch must use its generated-module-safe policy", errors)
    if ("with vendor_env.vars(self).apply():" in android_xray_recipe_text
            and "with gomobile_env.vars(self).apply():" in android_xray_recipe_text):
        vendor_scope = android_xray_recipe_text.index("with vendor_env.vars(self).apply():")
        local_replace = android_xray_recipe_text.index("go mod edit ")
        gomobile_scope = android_xray_recipe_text.index("with gomobile_env.vars(self).apply():")
        require(vendor_scope
                < android_xray_recipe_text.index("TestTribeAndroidControllerSlot")
                < android_xray_recipe_text.index(
                    "TestTribeExternalControllerErrorsArePropagated")
                < local_replace
                < gomobile_scope
                < android_xray_recipe_text.index('self.run("./build.sh android")'),
                "amnezia-libxray patched-core proof/final gomobile ordering drifted", errors)

    if args.apple_source:
        source = args.apple_source.resolve()
        require(source.is_dir(), f"Apple source does not exist: {source}", errors)
        if source.is_dir() and all(path.is_file() for path in apple_sequential_patch_paths):
            try:
                import patch_ng
            except ImportError as error:
                require(False, f"Conan patch_ng unavailable for exact Apple patch proof: {error}",
                        errors)
            else:
                with tempfile.TemporaryDirectory(prefix="tribe-awg-apple-patch-") as raw:
                    work = Path(raw) / "source"
                    shutil.copytree(source, work, symlinks=True)
                    for patch_file in apple_sequential_patch_paths:
                        patchset = patch_ng.fromfile(str(patch_file))
                        if not patchset or not patchset.apply(root=str(work)):
                            require(False,
                                    "sequential Tribe patch stack does not apply exactly to clean "
                                    f"awg-apple v3.1.4 at {patch_file.name}", errors)
                            break

    if args.libxray_source:
        source = args.libxray_source.resolve()
        require(source.is_dir(), f"libxray source does not exist: {source}", errors)
        require(xray_patch.is_file(), "libxray reproducible-build patch is missing", errors)
        require(xray_geo_patch.is_file(), "libxray pinned geo-data patch is missing", errors)
        if (source.is_dir() and xray_patch.is_file() and xray_geo_patch.is_file()
                and xray_controller_patch.is_file()):
            result = subprocess.run(
                ["git", "-C", str(source), "apply", "--check",
                 str(xray_patch), str(xray_geo_patch), str(xray_controller_patch)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            require(result.returncode == 0,
                    "reproducible-build, pinned geo-data, and controller-slot patches do not apply "
                    f"to clean libxray v1.0.3: {result.stdout.strip()}", errors)

    if args.hev_source:
        source = args.hev_source.resolve()
        hev_patch = ROOT / engines["hev-socks5-tunnel"]["patch_file"]
        require(source.is_dir(), f"HEV source does not exist: {source}", errors)
        require(hev_patch.is_file(), "HEV lifecycle patch is missing", errors)
        if source.is_dir() and hev_patch.is_file():
            result = subprocess.run(
                ["git", "-C", str(source), "apply", "--check", str(hev_patch)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            require(result.returncode == 0,
                    f"lifecycle patch does not apply to clean HEV v2.15.0: {result.stdout.strip()}", errors)

    cmake_paths = [
        "client/cmake/ios.cmake",
        "client/cmake/macos_ne.cmake",
        "client/ios/networkextension/CMakeLists.txt",
        "client/macos/networkextension/CMakeLists.txt",
    ]
    for path in cmake_paths:
        text = read(path)
        require("3rd/amneziawg-apple/Sources" not in text,
                f"{path}: stale submodule source path", errors)
        contains(path, "AWG_APPLE_SOURCE_DIR", errors)
        require(re.search(r"(?<![A-Za-z0-9_])WG_APPLE_SOURCE_DIR\b", text) is None,
                f"{path}: undefined legacy WG_APPLE_SOURCE_DIR", errors)
    for path in ("client/cmake/ios.cmake", "client/cmake/macos_ne.cmake"):
        text = read(path)
        require("AWG_APPLE_INCLUDE_DIRS" in text,
                f"{path}: main-app Apple C headers are not package-derived", errors)
        require(re.search(r"set\(LIBS[^\n]*amnezia::awg-apple", text) is None,
                f"{path}: do not duplicate the Go engine in the containing app", errors)

    release_wrapper_checks = {
        "deploy/build.sh": [
            "--catalog-root-kid",
            "--catalog-root-public-key-hex",
            "--runtime-receipt",
            "--runtime-receipt-sha256",
            "TRIBE_REQUIRED_RUNTIME_PLATFORM",
            "check_platform_runtime_receipt.py",
            "run_tribe_release_gates.sh",
        ],
        "cmake/platform_runtime_receipts.cmake": [
            "TRIBE_REQUIRED_RUNTIME_PLATFORM",
            "release receipt lacks passed",
            "_tribe_receipt_sha256_length EQUAL 64",
            "git status --porcelain=v1 --untracked-files=all",
        ],
        "metadata/run_tribe_release_gates.sh": [
            "check_engine_lock.py",
            "check_platform_runtime.py",
            "unittest discover -s metadata/tests",
            "git status --porcelain=v1 --untracked-files=all",
            "build_catalog_coordinator.sh",
        ],
        "metadata/check_platform_runtime_receipt.py": [
            "ALLOWED_PLATFORMS",
            "device_receipt_sha256",
            "source_commit",
            "hmac.compare_digest",
        ],
        "metadata/check_android_awg_artifacts.py": [
            "awgPrepareProtected",
            "awgResumeProtected",
            "minimum_pt_load_alignment",
            "android_artifact_sha256",
            "android_release_packaged_sha256",
            "--packaged-artifact",
        ],
        "metadata/check_android_xray_aar.py": [
            "absolute local Go module replacement path",
            "absolute_module_replacement_paths",
            "minimum_pt_load_alignment",
            "android_release_packaged_sha256",
            "--packaged-artifact",
        ],
        "metadata/check_android_16kb_artifact.py": [
            "REQUIRED_64_BIT_ABIS",
            "MINIMUM_LOAD_ALIGNMENT",
            "ZIP_STORED",
            "PT_LOAD alignment is not 16-KiB compatible",
            "artifact contains duplicate ZIP member names",
        ],
        "deploy/tribe/macos-service-payload.sh": [
            "PAYLOAD-MANIFEST.sha256",
            "PAYLOAD-SYMLINKS",
            "payload does not match the signed app version anchor",
        ],
        "deploy/tribe/sanitize-macos-app.sh": [
            "libqsqlite.dylib",
            "libqsqlmimer.dylib",
            "verify-macos-runtime.sh",
        ],
        "deploy/tribe/verify-macos-runtime.sh": [
            "non-system absolute dependency",
            "requires macOS",
            "qsqlmimer",
        ],
        "deploy/tribe/prepare-macos-service-payload.sh": [
            "Tribe-service",
            "amneziawg-go",
            "openvpn",
            "tun2socks",
            "geoip.dat",
            "geosite.dat",
            "macos-service-payload.sh",
            "check_macos_engine_artifact.py",
        ],
        "metadata/check_macos_engine_artifact.py": [
            "--tribe-engine-manifest-v1",
            "(deny network*)",
            "(deny file-write*)",
            "macos-awg-runtime",
            "macos-xray-runtime",
            "_amnezia_xray_start",
        ],
        "cmake/sign_binaries.cmake": [
            "prepare-macos-service-payload.sh",
            "check_macos_engine_artifact.py",
            "TribeVPN.app",
            "nested_files",
        ],
        "deploy/data/macos/post_install.sh": [
            "tribe-svc-install.sh",
            "tribe-svc.tar.gz",
            "sealed daemon payload installation failed",
        ],
        "metadata/platform-runtime-receipt.schema.json": [
            "platform-runtime-receipt:1",
            "device_receipt_sha256",
            "macos_daemon",
            "macos_ne",
        ],
        ".github/workflows/tribe-protocol-gates.yml": [
            "run_tribe_release_gates.sh --source-only",
            "actions/checkout@v4",
            "jurplel/install-qt-action@v3",
        ],
        ".github/actions/tribe-prepare-runtime-receipt/action.yml": [
            "base64.b64decode(encoded, validate=True)",
            "check_platform_runtime_receipt.py",
            "TRIBE_RECEIPT_SHA256",
            "GITHUB_OUTPUT",
        ],
        ".github/workflows/deploy.yml": [
            "TRIBE_CATALOG_ROOT_KID",
            "TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX",
            "TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE",
            "TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256",
            "TRIBE_IOS_PLATFORM_RUNTIME_RECEIPT_BASE64",
            "TRIBE_MACOS_DAEMON_PLATFORM_RUNTIME_RECEIPT_BASE64",
            "TRIBE_ANDROID_PLATFORM_RUNTIME_RECEIPT_BASE64",
            "ANDROID_COMPILE_PLATFORM: android-36",
            "testReleaseUnitTest lintRelease",
            "--target macos-ne --compile-only",
        ],
    }
    for path, needles in release_wrapper_checks.items():
        for needle in needles:
            contains(path, needle, errors)
    deploy_workflow = read(".github/workflows/deploy.yml")
    require(
        deploy_workflow.count("uses: ./.github/actions/tribe-prepare-runtime-receipt") == 3,
        "deploy workflow must verify one runtime receipt for each iOS, Android and macOS store job",
        errors,
    )
    for variable in (
        "TRIBE_CATALOG_ROOT_KID:",
        "TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX:",
        "TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE:",
        "TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256:",
    ):
        require(
            deploy_workflow.count(variable) == 3,
            f"deploy workflow must pass {variable[:-1]} to all three store jobs",
            errors,
        )
    for path in ("cmake/platform_runtime_receipts.cmake",
                 "client/cmake/avpn.cmake", "client/cmake/android.cmake"):
        require("{64}" not in read(path),
                f"{path}: CMake regex does not portably support bounded repetition", errors)

    native_checks = {
        "client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/WireguardConfig.kt":
            ["random_trailers", "disable_cookies", "Invalid AWG boolean value"],
        "client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt":
            ["verifyAwg31Uapi", "GoBackend.awgProtectedGetConfig",
             "GoBackend.awgPrepareProtected", "GoBackend.awgResumeProtected"],
        "client/platforms/ios/WGConfig.swift":
            ["RandomTrailers", "DisableCookies", "validateAwg31Booleans"],
        "client/platforms/ios/PacketTunnelProvider+WireGuard.swift":
            ["awg31UapiExpectations", "UAPI capability mismatch"],
        "client/daemon/daemon.cpp":
            ["RandomTrailers", "DisableCookies", "awgBoolToUapi"],
        "client/platforms/macos/daemon/wireguardutilsmacos.cpp":
            ["random_trailers", "disable_cookies", "get=1", "UAPI capability mismatch"],
        "client/platforms/linux/daemon/wireguardutilslinux.cpp":
            ["random_trailers", "disable_cookies", "get=1", "UAPI capability mismatch"],
    }
    for path, needles in native_checks.items():
        for needle in needles:
            contains(path, needle, errors)

    # The in-app self-hosted path is a separate pipeline from the typed
    # catalog.  Verify both new fields survive defaults -> ScriptVars -> the
    # rendered server/client templates, and extraction back into the model.
    self_hosted_checks = {
        "client/core/installers/awgInstaller.cpp": [
            "protocols::awg::awgV3_1",
            "serverConfig.randomTrailers = protocols::awg::defaultRandomTrailers",
            "serverConfig.disableCookies = protocols::awg::defaultDisableCookies",
            "serverConfigMap.value(configKey::randomTrailers)",
            "serverConfigMap.value(configKey::disableCookies)",
        ],
        "client/core/utils/selfhosted/scriptsRegistry.cpp": [
            '"$RANDOM_TRAILERS", AwgProtocolConfig::isToggleEnabled(config.randomTrailers)',
            '"$DISABLE_COOKIES", AwgProtocolConfig::isToggleEnabled(config.disableCookies)',
            "config.hasAwg3Params()",
        ],
        "client/server_scripts/awg/configure_container.sh": [
            "RandomTrailers = $RANDOM_TRAILERS",
            "DisableCookies = $DISABLE_COOKIES",
        ],
        "client/server_scripts/awg/template.conf": [
            "RandomTrailers = $RANDOM_TRAILERS",
            "DisableCookies = $DISABLE_COOKIES",
        ],
    }
    for path, needles in self_hosted_checks.items():
        for needle in needles:
            contains(path, needle, errors)

    for path in ("client/server_scripts/awg/configure_container.sh",
                 "client/server_scripts/awg/template.conf"):
        rendered = read(path).replace("$RANDOM_TRAILERS", "on").replace("$DISABLE_COOKIES", "on")
        require("RandomTrailers = on" in rendered and "DisableCookies = on" in rendered,
                f"{path}: AWG 3.1 self-hosted render round-trip failed", errors)

    contains("client/main.cpp", "QCoreApplication::setApplicationVersion(QStringLiteral(APP_VERSION))", errors)
    root_cmake = read("CMakeLists.txt")
    require("set(APP_BUILD_NUMBER ${APP_ANDROID_VERSION_CODE})" in root_cmake,
            "Android APP_BUILD must use store versionCode", errors)
    require("set(APP_BUILD_NUMBER ${CMAKE_PROJECT_VERSION_TWEAK})" in root_cmake,
            "Apple/desktop APP_BUILD must use bundle build", errors)
    version_header = read("version.h.in")
    require("#define APP_BUILD @APP_BUILD_NUMBER@" in version_header,
            "version.h must expose the platform-selected app build", errors)

    android_engine_manifest = read("client/android/protocolApi/src/main/kotlin/EngineManifest.kt")
    guarded_settings_owner = "tribe.guarded_settings_owner"
    for name in ("awg-android", "amnezia-libxray"):
        require(guarded_settings_owner in engines[name]["capabilities"],
                f"{name}: Android outer-guard settings ownership capability missing", errors)
    require(android_engine_manifest.count(f'"{guarded_settings_owner}"') == 2,
            "both Android compile-time engine manifests must advertise outer-guard settings ownership",
            errors)
    for needle in (
        engines["awg-android"]["conan_version"],
        engines["awg-android"]["source_commit"],
        engines["awg-android"]["embedded_awg_go"],
        engines["awg-android"]["abi"],
        engines["amnezia-libxray"]["conan_version"],
        engines["amnezia-libxray"]["source_commit"],
        engines["amnezia-libxray"]["embedded_xray_core"],
        engines["amnezia-libxray"]["abi"],
    ):
        require(needle in android_engine_manifest,
                f"Android compile-time manifest/lock drift: {needle}", errors)

    android_registry = read("client/android/src/org/amnezia/vpn/EngineManifestRegistry.kt")
    for needle in ("Wireguard.probeEngineManifest", "Xray.probeEngineManifest",
                   "packageInfo.longVersionCode"):
        require(needle in android_registry, f"Android pre-connect manifest missing {needle}", errors)
    android_awg = read("client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt")
    for needle in ("fun probeEngineManifest", "GoBackend.awgVersion()"):
        require(needle in android_awg, f"Android AWG runtime probe missing {needle}", errors)
    protected_order = [
        android_awg.find("GoBackend.awgPrepareProtected"),
        android_awg.find("GoBackend.awgProtectedGetSocketV4"),
        android_awg.find("!protect(socketV4)"),
        android_awg.find("GoBackend.awgResumeProtected"),
        android_awg.find("verifyAwg31Uapi(config)"),
    ]
    require(all(position >= 0 for position in protected_order)
            and protected_order == sorted(protected_order),
            "Android AWG must prepare sockets, protect, resume, then verify UAPI", errors)
    android_awg_jni = read("client/android/wireguard/src/main/kotlin/org/amnezia/awg/GoBackend.kt")
    for symbol in ("awgPrepareProtected", "awgResumeProtected", "awgProtectedTurnOff",
                   "awgProtectedGetSocketV4", "awgProtectedGetSocketV6",
                   "awgProtectedGetConfig"):
        require(f"external fun {symbol}" in android_awg_jni,
                f"Android AWG Kotlin protected-start binding missing {symbol}", errors)
    android_xray = read("client/android/xray/src/main/kotlin/Xray.kt")
    for needle in ("fun probeEngineManifest", "LibXray.xrayVersion()"):
        require(needle in android_xray, f"Android Xray runtime probe missing {needle}", errors)
    android_cpp = read("client/platforms/android/android_controller.cpp")
    require(android_cpp.count(
                f'caps.contains(QStringLiteral("{guarded_settings_owner}"))') == 2,
            "both Android Qt manifest allowlists must require outer-guard settings ownership",
            errors)
    for capability in expected_caps:
        require(capability in android_cpp, f"Android JNI validator missing {capability}", errors)
    require("engines.size() == 2" in android_cpp, "Android JNI must require both engine manifests", errors)
    require('QLatin1String("engine_manifest_v1")' in android_cpp,
            "Android JNI must reject unknown manifest message types", errors)
    require('positiveJsonInteger(app.value(QStringLiteral("build")))' in android_cpp,
            "Android JNI must validate the runtime package build", errors)

    # The Android Xray ABI is an exact cross-language contract, not a version
    # family. A stale Qt allowlist previously rejected the new controller-slot
    # package even though the Kotlin manifest and Conan recipe were current.
    xray_abi = engines["amnezia-libxray"]["abi"]
    xray_recipe = read("recipes/amnezia-libxray/conanfile.py")
    require(f'abi = "{xray_abi}"' in android_engine_manifest,
            "Android Kotlin Xray ABI does not match engine-lock.json", errors)
    require(f'"AMNEZIA_LIBXRAY_ABI": "{xray_abi}"' in xray_recipe,
            "amnezia-libxray recipe export does not match engine-lock.json", errors)
    require(android_cpp.count(f'QLatin1String("{xray_abi}")') == 2,
            "both Android Qt runtime/manifest Xray ABI allowlists must match the lock", errors)
    obsolete_xray_abi = "gomobile-libxray-" + "v1"
    shipping_suffixes = {
        ".c", ".cc", ".cpp", ".h", ".hpp", ".json", ".kt", ".kts",
        ".mm", ".py", ".swift", ".yml", ".yaml",
    }
    obsolete_hits: list[str] = []
    for shipping_root in (ROOT / "client", ROOT / "recipes"):
        for path in shipping_root.rglob("*"):
            if (not path.is_file() or path.suffix not in shipping_suffixes
                    or "tests" in path.parts or "fixtures" in path.parts):
                continue
            if obsolete_xray_abi in path.read_text(encoding="utf-8", errors="ignore"):
                obsolete_hits.append(str(path.relative_to(ROOT)))
    require(not obsolete_hits,
            f"obsolete Android Xray ABI remains in shipping source: {obsolete_hits}", errors)

    apple_manifest = read("client/platforms/ios/TribeEngineManifest.swift.in")
    for capability in expected_caps:
        require(capability in apple_manifest, f"Apple manifest missing {capability}", errors)
    for probe in ("wgVersion()", "LibXrayXrayVersion()"):
        require(probe in apple_manifest, f"Apple runtime manifest missing {probe}", errors)
    require(apple_manifest.count("defer { free") == 2,
            "Apple runtime version probes must free both Go C strings", errors)
    for needle in ('value == declared', 'value == "v\\(declared)"'):
        require(needle in apple_manifest,
                f"Apple manifest lacks exact runtime-version grammar: {needle}", errors)
    for needle in ('raw == declared', 'raw == "v$declared"'):
        require(needle in android_engine_manifest,
                f"Android manifest lacks exact runtime-version grammar: {needle}", errors)
    require('"activeProtocol"' not in apple_manifest and '"upstreamVersion"' not in apple_manifest,
            "Apple manifest must match the closed C++ root/engine schema", errors)
    daemon_ipc = read("client/daemon/daemonlocalserverconnection.cpp")
    service_manifest = read("service/server/main.cpp")
    product_runtime = read("client/core/serviceEngine/CatalogProductRuntime.cpp")
    for name in ("awg-go", "amnezia-xray-bindings"):
        require(guarded_settings_owner in engines[name]["capabilities"],
                f"{name}: macOS daemon settings ownership capability missing", errors)
    macos_lock_start = product_runtime.rfind("#elif defined(Q_OS_MACOS)")
    macos_lock_end = product_runtime.find("#else", macos_lock_start)
    require(macos_lock_start >= 0 and macos_lock_end > macos_lock_start
            and product_runtime[macos_lock_start:macos_lock_end].count(
                f'QStringLiteral("{guarded_settings_owner}")') == 2,
            "macOS ProductRuntime lock must require guarded settings ownership for both engines",
            errors)
    require(daemon_ipc.count(f'"{guarded_settings_owner}"') == 2,
            "macOS daemon IPC manifest must advertise guarded settings ownership twice", errors)
    require(service_manifest.count(
                f'QStringLiteral("{guarded_settings_owner}")') == 2,
            "macOS side-effect-free artifact manifest must advertise guarded settings ownership twice",
            errors)
    require('type == "engine_manifest_v1"' in daemon_ipc, "macOS daemon manifest IPC missing", errors)
    require('xray.insert("runtimeVersionProbed", false)' in daemon_ipc,
            "desktop Xray must not claim an unavailable runtime version probe", errors)
    for needle in ('"declaredCoreVersion"', '"runtimeCoreVersion"',
                   '"compile_time_lock_only"'):
        require(needle in daemon_ipc, f"macOS daemon manifest missing {needle}", errors)
    require('compile_time_conan_lock' not in daemon_ipc and '"coreVersion"' not in daemon_ipc,
            "macOS daemon manifest contains a non-contract evidence/key", errors)
    apple_recipe = read("recipes/awg-apple/conanfile.py")
    require('AWG_APPLE_XRAY_SOURCE_COMMIT' in apple_recipe
            and engines["amnezia-libxray"]["source_commit"] in apple_recipe,
            "Apple pre-connect Xray source evidence is not exported by the package lock", errors)
    ios_controller = read("client/platforms/ios/ios_controller.mm")
    for needle in ("IosController::engineManifest", "TRIBE_APPLE_AWG_SOURCE_COMMIT",
                   "TRIBE_APPLE_XRAY_SOURCE_COMMIT", '"compile_time_lock_only"'):
        require(needle in ios_controller,
                f"Apple app-side pre-connect manifest missing {needle}", errors)

    banned_caps = ("awg31.random_trailers", "awg31.disable_cookies")
    relevant = "\n".join([
        android_engine_manifest,
        android_registry,
        apple_manifest,
        daemon_ipc,
    ])
    for capability in banned_caps:
        require(capability not in relevant, f"non-contract capability leaked: {capability}", errors)

    if errors:
        print("engine lock check FAILED:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print("engine lock check OK (artifacts locked where recorded; device matrix still pending)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
