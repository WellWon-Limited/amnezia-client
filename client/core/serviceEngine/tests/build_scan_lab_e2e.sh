#!/bin/bash
# AVPN Scanner: build the local end-to-end lab program (tests/scan_lab_e2e.cpp). Never part of an ordinary gate:
# it does nothing without TRIBE_SCAN_LAB=1, and the binary needs the lab around it (~/avpn-build/scan-lab: backend,
# redis, edge fronts, Xray servers; see the header of scan_lab_e2e.cpp).
#   TRIBE_SCAN_ENGINE_PKG=<dir with include/amnezia_xray.h + lib/libamnezia_xray.a>  (the lab-built engine archive:
#   the conan package's source with the root-pool test seam set from TRIBE_SCAN_LAB_ROOTS)
#   OUT=<binary path> (default ~/avpn-build/scan-lab/bin/scan_lab_e2e)
set -euo pipefail
if [ "${TRIBE_SCAN_LAB:-}" != "1" ]; then echo "build_scan_lab_e2e.sh: skipped (TRIBE_SCAN_LAB is not 1)"; exit 0; fi
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
ROOT="$(cd "$CLIENT/.." && pwd)"
SVC="$ROOT/service/server"
PKG="${TRIBE_SCAN_ENGINE_PKG:?the engine archive dir (include/ + lib/)}"
OUT="${OUT:-$HOME/avpn-build/scan-lab/bin/scan_lab_e2e}"
GEN="$(mktemp -d "$HOME/avpn-build/scan-lab/build.XXXXXX")"
trap 'rm -rf -- "${GEN:?}"' EXIT

MOCI=(-F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/include"
      -I"$ROOT/ipc" -I"$CLIENT/mozilla/shared")
for kind in source replica; do
  "$QT/libexec/repc" -o $kind "$ROOT/ipc/ipc_scan_interface.rep" "$GEN/rep_ipc_scan_interface_$kind.h"
  "$QT/libexec/repc" -o $kind "$ROOT/ipc/ipc_interface.rep" "$GEN/rep_ipc_interface_$kind.h"
done
for h in rep_ipc_scan_interface_source rep_ipc_scan_interface_replica rep_ipc_interface_source rep_ipc_interface_replica; do
  "$QT/libexec/moc" "${MOCI[@]}" "$GEN/$h.h" -o "$GEN/moc_$h.cpp"
done
for h in TribeScanner ScanApiClient UpstreamLeaseClient; do
  "$QT/libexec/moc" -f"$h.h" "$SE/$h.h" -o "$GEN/moc_$h.cpp"
done

ARCH_FLAGS=()
[ "$(uname -m)" = "arm64" ] && ARCH_FLAGS=(-include arm_acle.h)
CXX=(clang++ -std=c++17 -fPIC ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} -Wall -Wno-unused-parameter -Wno-deprecated-declarations)
INC=(-I"$SE" -I"$CLIENT" -I"$SVC" -I"$SVC/tests" -I"$ROOT/ipc" -I"$CLIENT/mozilla/shared" -I"$GEN" -I"$PKG/include"
     -I"$SSL/include" -F"$QT/lib" -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers"
     -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/lib/QtCore5Compat.framework/Headers")
SRCS=("$HERE/scan_lab_e2e.cpp"
      "$SE/TribeScanner.cpp" "$SE/ScanApiClient.cpp" "$SE/UpstreamLeaseClient.cpp" "$SE/Ed25519Verify.cpp"
      "$SE/DaemonScanHost.cpp" "$SE/SubscriptionParser.cpp" "$SE/XrayConfigBuilder.cpp" "$SE/AwgConfigBuilder.cpp"
      "$SVC/tribe_scan.cpp" "$SVC/tests/tribe_scan_platform_stubs.cpp"
      "$GEN/moc_TribeScanner.cpp" "$GEN/moc_ScanApiClient.cpp" "$GEN/moc_UpstreamLeaseClient.cpp"
      "$GEN/moc_rep_ipc_scan_interface_source.cpp" "$GEN/moc_rep_ipc_scan_interface_replica.cpp"
      "$GEN/moc_rep_ipc_interface_source.cpp" "$GEN/moc_rep_ipc_interface_replica.cpp")
OBJS=()
for s in "${SRCS[@]}"; do
  o="$GEN/$(basename "${s%.cpp}").o"
  "${CXX[@]}" "${INC[@]}" -c "$s" -o "$o" &
  OBJS+=("$o")
done
wait
for o in "${OBJS[@]}"; do [ -f "$o" ] || { echo "build_scan_lab_e2e.sh: compile failed ($o)"; exit 1; }; done
mkdir -p "$(dirname "$OUT")"
clang++ "${OBJS[@]}" "$PKG/lib/libamnezia_xray.a" -framework CoreFoundation -framework Security -lresolv \
  -F"$QT/lib" -framework QtCore -framework QtNetwork -framework QtRemoteObjects -L"$SSL/lib" -lcrypto \
  -Wl,-rpath,"$QT/lib" -o "$OUT"
echo ">>> build ok: $OUT"
