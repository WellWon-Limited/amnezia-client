#!/bin/sh
# AVPN (patch 0015): typechecks the patched WireGuardKit Swift sources (macOS and iOS SDKs) against
# the package's own C headers, so the backend hook compiles before any app build.
# Usage: typecheck_adapter.sh <awg-apple build folder>
set -eu
b=$1
work=$(mktemp -d "${TMPDIR:-/tmp}/tribe-adapter-typecheck.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp "$b"/Sources/WireGuardKit/*.swift "$work/"
printf '#include "WireGuardKitC.h"\n#include "wireguard.h"\n' > "$work/bridge.h"
for t in "macosx arm64-apple-macos12.0" "iphoneos arm64-apple-ios16.0"; do
    sdk=${t%% *}
    target=${t#* }
    xcrun swiftc -typecheck -sdk "$(xcrun --sdk "$sdk" --show-sdk-path)" -target "$target" \
        -import-objc-header "$work/bridge.h" -Xcc -I"$b/Sources/WireGuardKitC" -Xcc -I"$b/Sources/WireGuardKitGo" \
        "$work"/*.swift
done
echo "typecheck_adapter: OK"
