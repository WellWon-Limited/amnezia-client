#!/bin/bash
# AVPN (Scanner, lane L4): ScanEngineReplayTests.swift - the extension's relay (TribeScanHost.swift) linked with the
# REAL probe engine: awg-apple 3.1.4-tribe.14's libwg-go.a for macOS from the local conan cache (the recipe revision
# of this tree, find_awg_apple_package.py; it must export LibXrayTribeScanMessage). No packet leaves this Mac (see
# the test). AWG_APPLE_MAC_PACKAGE_DIR=<package folder> overrides the lookup; no package = SKIPPED (exit 0).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$IOS_DIR/../../.." && pwd)"
PATH="$HOME/Library/Python/3.13/bin:$PATH"
PKG="${AWG_APPLE_MAC_PACKAGE_DIR:-}"
if [[ -z "$PKG" ]] && command -v conan >/dev/null 2>&1; then
    # The package of THIS tree's recipe (find_awg_apple_package.py), not merely the newest revision.
    PKG="$(python3 -I "$HERE/find_awg_apple_package.py" "$REPO_ROOT" Macos || true)"
    if [[ -n "$PKG" ]] && ! grep -q LibXrayTribeScanMessage "$PKG/include/wireguard.h" 2>/dev/null; then PKG=""; fi
fi
if [[ -z "$PKG" || ! -f "$PKG/lib/libwg-go.a" ]]; then
    echo "scan engine replay: SKIPPED (no macOS awg-apple package with the scan exports in the conan cache)"
    exit 0
fi
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR:?}"' EXIT
echo "real engine: $PKG/lib/libwg-go.a"
xcrun --sdk macosx swiftc -Onone -parse-as-library \
    -import-objc-header "$PKG/include/wireguard.h" \
    -o "$WORK_DIR/scan_engine_replay" \
    "$IOS_DIR/TribeScanHost.swift" \
    "$IOS_DIR/XraySocketCallbackLifecycle.swift" \
    "$HERE/ScanEngineReplayTests.swift" \
    "$PKG/lib/libwg-go.a" \
    -Xlinker -framework -Xlinker CoreFoundation -Xlinker -framework -Xlinker Security -Xlinker -lresolv
"$WORK_DIR/scan_engine_replay" "$REPO_ROOT/client/core/serviceEngine/tests/vectors"
