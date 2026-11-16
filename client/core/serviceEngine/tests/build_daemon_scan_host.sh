#!/bin/bash
# AVPN (Scanner): build + run the desktop probe host adapter test (DaemonScanHost.cpp against a fake
# transport). Generates the QtRO replica headers of ipc/ipc_interface.rep (the witness) and
# ipc/ipc_scan_interface.rep with repc, as the client build does (client/CMakeLists.txt, cmake/avpn.cmake).
# The real QtRO round trip with the service side: service/server/tests/build_tribe_scan.sh.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
GEN="$(mktemp -d /tmp/avpn_daemon_scan_host.XXXXXX)"
trap 'rm -rf "${GEN:?}"' EXIT
MOCI=(-F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/include"
      -I"$ROOT/ipc" -I"$ROOT/client/mozilla/shared")
"$QT/libexec/repc" -o replica "$ROOT/ipc/ipc_interface.rep" "$GEN/rep_ipc_interface_replica.h"
"$QT/libexec/repc" -o replica "$ROOT/ipc/ipc_scan_interface.rep" "$GEN/rep_ipc_scan_interface_replica.h"
for h in rep_ipc_interface_replica rep_ipc_scan_interface_replica; do
  "$QT/libexec/moc" "${MOCI[@]}" "$GEN/$h.h" -o "$GEN/moc_$h.cpp"
done
OUT="$GEN/daemon_scan_host_check"
clang++ -std=c++17 -fPIC -Wall -Wno-deprecated-declarations \
  -I"$HERE/.." -I"$ROOT/client" -I"$ROOT/ipc" -I"$ROOT/client/mozilla/shared" -I"$GEN" \
  -F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/lib/QtCore5Compat.framework/Headers" -I"$QT/include" \
  "$HERE/../DaemonScanHost.cpp" "$HERE/daemon_scan_host_check.cpp" \
  "$GEN/moc_rep_ipc_interface_replica.cpp" "$GEN/moc_rep_ipc_scan_interface_replica.cpp" \
  -framework QtCore -framework QtNetwork -framework QtRemoteObjects -Wl,-rpath,"$QT/lib" -o "$OUT"
echo ">>> build ok: daemon_scan_host_check"
"$OUT"
