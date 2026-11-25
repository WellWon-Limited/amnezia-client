#!/bin/bash
# AVPN (волна AWG 3.1 + Xray, этап D3): автономная проверка Apple-слоя xray-пути NE.
#
# Шаг 1 (всегда, ~5с, без устройства и без Xcode-проекта): хостовый Swift-тест изолированных
# Foundation-only файлов — TunnelRuntimeStatus.swift (аккумулятор rx/tx, поколения сессии,
# payload runtime status v1) и XraySocketCallbackLifecycle.swift (слот protect-колбэка,
# забор поздних колбэков, точный teardown, gate нативных старт/стоп).
#
# Шаг 2 (опционально, --ne): компиляция реальной цели Network Extension под iphoneos —
# единственный способ проверить PacketTunnelProvider+Xray.swift целиком (libxray, hev,
# NetworkExtension). Требует настроенной папки сборки iOS (по умолчанию deploy/build,
# создаётся обычным configure-циклом iOS). Полный архив НЕ запускается.
#
# Использование:
#   bash client/platforms/ios/tests/run_ios_swift_checks.sh            # только хостовый тест
#   bash client/platforms/ios/tests/run_ios_swift_checks.sh --ne       # + сборка цели NE
#   bash client/platforms/ios/tests/run_ios_swift_checks.sh --ne-typecheck  # + typecheck NE (без проекта)
#   IOS_BUILD_DIR=~/my-ios-build bash .../run_ios_swift_checks.sh --ne
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$IOS_DIR/../../.." && pwd)"
IOS_BUILD_DIR="${IOS_BUILD_DIR:-$REPO_ROOT/deploy/build}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "== 1/2 хостовый Swift-тест (macOS SDK) =="
xcrun --sdk macosx swiftc -Onone -parse-as-library \
    -o "$WORK_DIR/xray_lifecycle_tests" \
    "$IOS_DIR/TunnelRuntimeStatus.swift" \
    "$IOS_DIR/XraySocketCallbackLifecycle.swift" \
    "$IOS_DIR/IPv4RouteSpec.swift" \
    "$IOS_DIR/IPv6RouteSpec.swift" \
    "$SCRIPT_DIR/XraySocketCallbackLifecycleTests.swift"
"$WORK_DIR/xray_lifecycle_tests"

# AVPN (review R43 F3): the order of startTunnel's and stopTunnel's answers (TunnelStartSlot).
echo "== 1-slot хостовый Swift-тест порядка ответов старта и стопа =="
xcrun --sdk macosx swiftc -Onone -parse-as-library \
    -o "$WORK_DIR/tunnel_start_slot_order_tests" \
    "$IOS_DIR/TunnelRuntimeStatus.swift" \
    "$SCRIPT_DIR/TunnelStartSlotOrderTests.swift"
"$WORK_DIR/tunnel_start_slot_order_tests"

# AVPN (floor 19.11): the RU split of an own Xray session as one routing rule of the core (XrayDirectSplit.swift).
echo "== 1a хостовый Swift-тест разделения РФ внутри ядра Xray =="
xcrun --sdk macosx swiftc -Onone -parse-as-library \
    -o "$WORK_DIR/xray_direct_split_tests" \
    "$IOS_DIR/XrayDirectSplit.swift" \
    "$SCRIPT_DIR/XrayDirectSplitTests.swift"
"$WORK_DIR/xray_direct_split_tests"

# AVPN (upstream nodes, lane L3): lease machine twin + renewer + tunables, replaying the shared C++
# vectors (client/core/serviceEngine/tests/vectors).
echo "== 1b хостовый Swift-тест аренды upstream (векторы C++) =="
xcrun --sdk macosx swiftc -Onone -parse-as-library \
    -o "$WORK_DIR/upstream_lease_tests" \
    "$IOS_DIR/UpstreamLeaseMachine.swift" \
    "$IOS_DIR/UpstreamLeaseWire.swift" \
    "$IOS_DIR/UpstreamLeaseRenewer.swift" \
    "$IOS_DIR/UpstreamProxyMeter.swift" \
    "$IOS_DIR/XrayTunables.swift" \
    "$IOS_DIR/XrayConfig.swift" \
    "$SCRIPT_DIR/UpstreamLeaseTests.swift"
"$WORK_DIR/upstream_lease_tests" "$REPO_ROOT/client/core/serviceEngine/tests/vectors"

# AVPN (Scanner, lane L4): the extension's probe host relay (TribeScanHost.swift) against stub engine symbols,
# replaying scan_host_vectors.json byte for byte, + the source gate of its wiring into the provider (nothing
# of the scan host reaches xraySocketProtectionFailed / cancelTunnelWithError; stop-all before every core
# stop, restart and peer change).
echo "== 1b-scan хостовый Swift-тест хоста сканера (векторы C++) + проверка точек вызова =="
xcrun --sdk macosx swiftc -Onone -parse-as-library \
    -o "$WORK_DIR/scan_bridge_tests" \
    "$IOS_DIR/TribeScanHost.swift" \
    "$IOS_DIR/XraySocketCallbackLifecycle.swift" \
    "$SCRIPT_DIR/ScanBridgeTests.swift"
"$WORK_DIR/scan_bridge_tests" "$REPO_ROOT/client/core/serviceEngine/tests/vectors"
bash "$SCRIPT_DIR/check_ios_scan_wiring.sh"
# The same relay linked with the REAL engine (awg-apple's macOS libwg-go.a from the conan cache; SKIPPED without
# it): every request vector, the real caps, one local scan bound to lo0 through freeze, cancel and final.
bash "$SCRIPT_DIR/run_scan_engine_replay.sh"
# The app side's pure parts (IosScanHost.h) against the app's decoder; needs Qt for macOS.
if [[ -d "${QT_ROOT:-$HOME/Qt/6.11.1/macos}" ]]; then
    OUT_DIR="$WORK_DIR/ios-scan-host" bash "$SCRIPT_DIR/build_ios_scan_host_check.sh"
else
    echo "iOS scan host check: SKIPPED (no Qt for macOS; set QT_ROOT)"
fi

# AVPN (upstream nodes): --ne-typecheck = every Swift source of the NE target (list as in
# client/ios/networkextension/CMakeLists.txt) typechecked for iphoneos against the conan packages
# awg-apple 3.1.4-tribe.14 (wireguard.h with LibXrayTribeHTTP), hev-socks5-tunnel 2.15.0-tribe.2 and
# openvpnadapter 1.0.0 from the local cache. No Xcode project, no build, no signing.
if [[ "${1:-}" == "--ne-typecheck" ]]; then
    echo "== 1c typecheck цели NE (iphoneos, пакеты conan) =="
    PATH="$HOME/Library/Python/3.13/bin:$PATH"
    # AVPN (Scanner, L4): the newest recipe revision that HAS a matching binary - a newer revision exported
    # without one (a configure that failed in build()) no longer hides the packages that exist.
    pkg() { # <ref> <python filter on the package settings/options> -> package folder
        local ref="$1" filter="$2" id
        id=$(conan list "$ref#*:*" --format=json 2>/dev/null | python3 -I -c "
import json, sys
d = json.load(sys.stdin)['Local Cache']
for rr in d.values():
    for rid, rev in sorted(rr['revisions'].items(), key=lambda kv: -float(kv[1].get('timestamp', 0))):
        for pid, p in rev.get('packages', {}).items():
            s = p['info'].get('settings', {}); o = p['info'].get('options', {})
            if $filter: print(rid + ':' + pid); sys.exit(0)
")
        [[ -n "$id" ]] || { echo "СТОП: нет пакета $ref для iOS в кеше conan" >&2; exit 1; }
        conan cache path "$ref#$id" 2>/dev/null
    }
    # AVPN (Scanner, L4): the awg-apple package of THIS tree's recipe (find_awg_apple_package.py), not merely the
    # newest revision (re-exporting an older recipe makes it the newest again).
    AWG="${AWG_APPLE_PACKAGE_DIR:-$(python3 -I "$SCRIPT_DIR/find_awg_apple_package.py" "$REPO_ROOT" iOS || true)}"
    [[ -n "$AWG" ]] || AWG="$(pkg awg-apple/3.1.4-tribe.14 "s.get('os') == 'iOS'")"
    HEVP="${HEV_PACKAGE_DIR:-$(pkg hev-socks5-tunnel/2.15.0-tribe.2 "s.get('os') == 'iOS' and o.get('as_framework') == 'True'")}"
    OVPN="${OPENVPNADAPTER_PACKAGE_DIR:-$(pkg openvpnadapter/1.0.0 "s.get('os') == 'iOS'")}"
    WGS="$AWG/src/Sources"
    grep -q LibXrayTribeHTTP "$AWG/include/wireguard.h" || { echo "СТОП: $AWG без LibXrayTribeHTTP" >&2; exit 1; }
    grep -q LibXrayTribeOutboundStats "$AWG/include/wireguard.h" || { echo "СТОП: $AWG без LibXrayTribeOutboundStats" >&2; exit 1; }
    grep -q LibXrayTribeScanMessage "$AWG/include/wireguard.h" || { echo "СТОП: $AWG без LibXrayTribeScanMessage (патч 0013)" >&2; exit 1; }
    # AVPN (Scanner, review F2): WireGuardAdapter conforms to TribeBackendRestartObservable exactly when the package's
    # adapter has the backend-restart callback (otherwise the conformance does not compile, or the callback is left unset).
    CONFORMS=0; grep -q '^extension WireGuardAdapter: TribeBackendRestartObservable' "$IOS_DIR/PacketTunnelProvider+Scan.swift" && CONFORMS=1
    HAS_CB=0; grep -q 'tribeBackendWillRestart' "$AWG/src/Sources/WireGuardKit/WireGuardAdapter.swift" && HAS_CB=1
    if [[ "$CONFORMS" != "$HAS_CB" ]]; then
        echo "СТОП: адаптер пакета tribeBackendWillRestart=$HAS_CB, а conformance в PacketTunnelProvider+Scan.swift=$CONFORMS" >&2
        exit 1
    fi
    echo "backend-restart callback: package=$HAS_CB conformance=$CONFORMS"
    sed 's/@BUILD_IOS_GROUP_IDENTIFIER@/group.typecheck/' "$IOS_DIR/GroupIdentifier.swift.in" > "$WORK_DIR/GroupIdentifier.swift"
    SDK=$(xcrun --sdk iphoneos --show-sdk-path)
    xcrun --sdk iphoneos swiftc -typecheck -target arm64-apple-ios16.0 -sdk "$SDK" -swift-version 5 \
        -import-objc-header "$REPO_ROOT/client/ios/networkextension/WireGuardNetworkExtension-Bridging-Header.h" \
        -I "$AWG/include" -I "$WGS/WireGuardKitC" \
        -I "$HEVP/HevSocks5Tunnel.xcframework/ios-arm64/Headers" -F "$OVPN" -module-name NETypecheck \
        "$WGS/WireGuardKit/WireGuardAdapter.swift" "$WGS/WireGuardKit/TribeRoaming.swift" \
        "$WGS/WireGuardKit/TribeDataWatch.swift" \
        "$WGS/WireGuardKit/PacketTunnelSettingsGenerator.swift" "$WGS/WireGuardKit/DNSResolver.swift" \
        "$WGS/WireGuardNetworkExtension/ErrorNotifier.swift" "$WGS/Shared/Keychain.swift" \
        "$WGS/Shared/Model/TunnelConfiguration+WgQuickConfig.swift" \
        "$WGS/Shared/Model/NETunnelProviderProtocol+Extension.swift" \
        "$WGS/Shared/Model/String+ArrayConversion.swift" "$WGS/WireGuardKit/TunnelConfiguration.swift" \
        "$WGS/WireGuardKit/IPAddressRange.swift" "$WGS/WireGuardKit/Endpoint.swift" \
        "$WGS/WireGuardKit/DNSServer.swift" "$WGS/WireGuardKit/InterfaceConfiguration.swift" \
        "$WGS/WireGuardKit/PeerConfiguration.swift" "$WGS/Shared/FileManager+Extension.swift" \
        "$WGS/WireGuardKit/Array+ConcurrentMap.swift" "$WGS/WireGuardKit/IPAddress+AddrInfo.swift" \
        "$WGS/WireGuardKit/PrivateKey.swift" \
        "$IOS_DIR/HevSocksTunnel.swift" "$IOS_DIR/NELogController.swift" "$IOS_DIR/Log.swift" \
        "$IOS_DIR/TribeSharedState.swift" "$WORK_DIR/GroupIdentifier.swift" "$IOS_DIR/LogRecord.swift" \
        "$IOS_DIR/PacketTunnelProvider.swift" "$IOS_DIR/PacketTunnelProvider+WireGuard.swift" \
        "$IOS_DIR/PacketTunnelProvider+OpenVPN.swift" "$IOS_DIR/PacketTunnelProvider+Xray.swift" \
        "$IOS_DIR/IPv4RouteSpec.swift" "$IOS_DIR/IPv6RouteSpec.swift" "$IOS_DIR/WGConfig.swift" \
        "$IOS_DIR/XrayConfig.swift" "$IOS_DIR/XrayDirectSplit.swift" "$IOS_DIR/TunnelRuntimeStatus.swift" \
        "$IOS_DIR/XraySocketCallbackLifecycle.swift" "$IOS_DIR/UpstreamLeaseMachine.swift" \
        "$IOS_DIR/UpstreamLeaseWire.swift" "$IOS_DIR/UpstreamLeaseRenewer.swift" \
        "$IOS_DIR/UpstreamProxyMeter.swift" \
        "$IOS_DIR/XrayTunables.swift" "$IOS_DIR/PacketTunnelProvider+Upstream.swift" \
        "$IOS_DIR/TribeScanHost.swift" "$IOS_DIR/PacketTunnelProvider+Scan.swift" \
        "$IOS_DIR/TribeWatchPlan.swift" "$IOS_DIR/TribeDataWatchRuntime.swift" "$IOS_DIR/PacketTunnelProvider+DataWatch.swift"
    echo "NE typecheck passed (awg-apple: $AWG)"
    exit 0
fi

if [[ "${1:-}" != "--ne" ]]; then
    echo "== 2/2 сборка цели NE пропущена (запусти с --ne) =="
    exit 0
fi

if [[ ! -f "$IOS_BUILD_DIR/AmneziaVPN.xcodeproj/project.pbxproj" ]]; then
    echo "СТОП: нет настроенной сборки iOS в $IOS_BUILD_DIR — нечего собирать." >&2
    echo "Настрой её обычным configure-циклом iOS или задай IOS_BUILD_DIR." >&2
    exit 1
fi

echo "== 2/2 регенерация xcodeproj + сборка цели networkextension (iphoneos) =="
# Регенерация обязательна: новые .swift из client/ios/networkextension/CMakeLists.txt
# в стейл-проекте отсутствуют и молча не попадают в компиляцию.
(cd "$IOS_BUILD_DIR" && PATH="$HOME/Library/Python/3.13/bin:$PATH" cmake . >/dev/null)
# Битый симлинк .appex от прошлого архива (DerivedData удалена) роняет MkDir цели.
APPEX="$IOS_BUILD_DIR/client/ios/networkextension/Release-iphoneos/AmneziaVPNNetworkExtension.appex"
if [[ -L "$APPEX" && ! -e "$APPEX" ]]; then
    rm -f "$APPEX"
fi
xcodebuild -project "$IOS_BUILD_DIR/AmneziaVPN.xcodeproj" \
    -target networkextension -configuration Release \
    -destination 'generic/platform=iOS' \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
    ENABLE_DEBUG_DYLIB=NO ENABLE_PREVIEWS=NO build
