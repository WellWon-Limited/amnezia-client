#!/bin/bash
# AVPN (review F1, 24.11.2026): build + run xray_protocol_end_check - the REAL client/core/protocols/xrayProtocol.cpp,
# compiled with AddressSanitizer, against a fake service (QtRO sources of ipc/ipc_interface.rep and
# ipc/ipc_process_interface.rep on local sockets in the temp dir). The protocol sources are copied next to the
# test stand-in vpnProtocol.h; xray_protocol_stub/ also replaces the IpcClient URLs (never the installed service),
# the network lookups, the inbound credentials and ipc.h. Nothing is installed, no service or tunnel is touched.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
STUB="$HERE/xray_protocol_stub"
GEN="$(mktemp -d "${TMPDIR:-/tmp}/avpn_xray_protocol_end.XXXXXX")"
trap 'rm -rf "${GEN:?}"' EXIT
mkdir -p "$GEN/proto"
cp "$ROOT/client/core/protocols/xrayProtocol.cpp" "$ROOT/client/core/protocols/xrayProtocol.h" \
   "$ROOT/client/core/protocols/tun2socksOutputReader.h" "$STUB/vpnProtocol.h" "$GEN/proto/"
QTI=(-F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers"
     -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/include")
INC=(-I"$STUB" -I"$GEN/proto" -I"$GEN" -I"$ROOT/client" -I"$ROOT/client/mozilla/shared")
for r in ipc_interface ipc_process_interface; do
  "$QT/libexec/repc" -o source "$ROOT/ipc/$r.rep" "$GEN/rep_${r}_source.h" > /dev/null
  "$QT/libexec/repc" -o replica "$ROOT/ipc/$r.rep" "$GEN/rep_${r}_replica.h" > /dev/null
  for k in source replica; do
    "$QT/libexec/moc" "${QTI[@]}" "${INC[@]}" "$GEN/rep_${r}_$k.h" -o "$GEN/moc_rep_${r}_$k.cpp"
  done
done
MOCS=()
for h in "$GEN/proto/vpnProtocol.h" "$ROOT/client/core/utils/errorCodes.h" "$ROOT/client/core/utils/routeModes.h" \
         "$ROOT/client/core/utils/protocolEnum.h"; do
  m="$GEN/moc_$(basename "$h" .h).cpp"
  "$QT/libexec/moc" "${QTI[@]}" "${INC[@]}" "$h" -o "$m"
  MOCS+=("$m")
done
OUT="$GEN/xray_protocol_end_check"
clang++ -std=c++17 -fPIC -g -fsanitize=address -fno-omit-frame-pointer -Wall -Wno-deprecated-declarations \
  "${INC[@]}" "${QTI[@]}" \
  "$GEN/proto/xrayProtocol.cpp" "$HERE/xray_protocol_end_check.cpp" "${MOCS[@]}" \
  "$GEN"/moc_rep_*.cpp \
  -framework QtCore -framework QtNetwork -framework QtRemoteObjects -Wl,-rpath,"$QT/lib" -o "$OUT"
echo ">>> build ok: xray_protocol_end_check (AddressSanitizer)"
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=0}" "$OUT"
