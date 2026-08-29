#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Apple Swift host suites require macOS" >&2
    exit 2
fi
command -v xcrun >/dev/null 2>&1 || {
    echo "xcrun is required for Apple Swift host suites" >&2
    exit 2
}

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/tribe-swift-host-tests.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
mkdir -p "$TEST_ROOT/swift-module-cache" "$TEST_ROOT/tmp"
export TMPDIR="$TEST_ROOT/tmp"

SDK="$(xcrun --sdk macosx --show-sdk-path)"
ARCH="$(uname -m)"
case "$ARCH" in
    arm64|x86_64) ;;
    *) echo "unsupported Apple host architecture: $ARCH" >&2; exit 2 ;;
esac
TARGET="$ARCH-apple-macos13.0"

run_suite() {
    local name="$1"
    shift
    local binary="$TEST_ROOT/$name"
    xcrun swiftc \
        -parse-as-library \
        -warnings-as-errors \
        -module-cache-path "$TEST_ROOT/swift-module-cache" \
        -sdk "$SDK" \
        -target "$TARGET" \
        "$@" \
        -o "$binary"
    "$binary"
}

typecheck_suite() {
    local name="$1"
    shift
    xcrun swiftc \
        -typecheck \
        -warnings-as-errors \
        -module-cache-path "$TEST_ROOT/swift-module-cache" \
        -sdk "$SDK" \
        -target "$TARGET" \
        "$@"
    printf '%s\n' "$name typecheck passed"
}

run_suite protected-split-policy \
    "$ROOT/client/platforms/ios/TribeProtectedSplitPolicy.swift" \
    "$ROOT/client/platforms/ios/tests/TribeProtectedSplitPolicyTests.swift"

run_suite socks-runtime-lifecycle \
    "$ROOT/client/platforms/ios/Socks5TunnelLifecycle.swift" \
    "$ROOT/client/platforms/ios/TunnelRuntimeStatus.swift" \
    "$ROOT/client/platforms/ios/tests/Socks5TunnelLifecycleTests.swift"

run_suite native-session-guard \
    "$ROOT/client/platforms/ios/TribeNativeSessionGuard.swift" \
    "$ROOT/client/platforms/ios/tests/TribeNativeSessionGuardTests.swift"

run_suite xray-callback-lifecycle \
    "$ROOT/client/platforms/ios/TribeNativeSessionGuard.swift" \
    "$ROOT/client/platforms/ios/XraySocketCallbackLifecycle.swift" \
    "$ROOT/client/platforms/ios/tests/XraySocketCallbackLifecycleTests.swift"

run_suite runtime-authority-lease \
    "$ROOT/client/platforms/ios/NativeDispatchPolicy.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityWatchdog.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityLease.swift" \
    "$ROOT/client/platforms/ios/tests/TribeRuntimeAuthorityLeaseTests.swift"

run_suite runtime-authority-renewal \
    "$ROOT/client/platforms/ios/NativeDispatchPolicy.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityWatchdog.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityLease.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityRenewal.swift" \
    "$ROOT/client/platforms/ios/tests/TribeRuntimeAuthorityRenewalTests.swift"

run_suite runtime-authority-watchdog \
    "$ROOT/client/platforms/ios/NativeDispatchPolicy.swift" \
    "$ROOT/client/platforms/ios/TribeNativeSessionGuard.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityWatchdog.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityLease.swift" \
    "$ROOT/client/platforms/ios/tests/TribeRuntimeAuthorityWatchdogTests.swift"

run_suite native-guard-provider-policy \
    "$ROOT/client/platforms/ios/NativeDispatchPolicy.swift" \
    "$ROOT/client/platforms/ios/TribeProtectedSplitPolicy.swift" \
    "$ROOT/client/platforms/ios/TribeNativeSessionGuard.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityWatchdog.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityLease.swift" \
    "$ROOT/client/platforms/ios/TribeRuntimeAuthorityRenewal.swift" \
    "$ROOT/client/platforms/ios/TunnelRuntimeStatus.swift" \
    "$ROOT/client/platforms/ios/tests/NativeGuardProviderTypecheckStubs.swift" \
    "$ROOT/client/platforms/ios/PacketTunnelProvider+NativeGuard.swift" \
    "$ROOT/client/platforms/ios/tests/NativeGuardRoutePolicyTests.swift"

typecheck_suite xray-provider \
    "$ROOT/client/platforms/ios/NativeDispatchPolicy.swift" \
    "$ROOT/client/platforms/ios/TribeProtectedSplitPolicy.swift" \
    "$ROOT/client/platforms/ios/TribeNativeSessionGuard.swift" \
    "$ROOT/client/platforms/ios/XraySocketCallbackLifecycle.swift" \
    "$ROOT/client/platforms/ios/TunnelRuntimeStatus.swift" \
    "$ROOT/client/platforms/ios/XrayConfig.swift" \
    "$ROOT/client/platforms/ios/tests/XrayProviderTypecheckStubs.swift" \
    "$ROOT/client/platforms/ios/PacketTunnelProvider+Xray.swift"

typecheck_suite wireguard-provider \
    "$ROOT/client/platforms/ios/NativeDispatchPolicy.swift" \
    "$ROOT/client/platforms/ios/TribeProtectedSplitPolicy.swift" \
    "$ROOT/client/platforms/ios/TunnelRuntimeStatus.swift" \
    "$ROOT/client/platforms/ios/WGConfig.swift" \
    "$ROOT/client/platforms/ios/tests/WireGuardProviderTypecheckStubs.swift" \
    "$ROOT/client/platforms/ios/PacketTunnelProvider+WireGuard.swift"

echo "Apple Swift host suites passed (8 executable + 2 provider typechecks)"
