#!/bin/bash
# AVPN (macOS crash 24.11.2026): build + run the tun2socks stderr reader check (client/core/protocols/
# tun2socksOutputReader.h) against a real QtRO source on a local socket. Generates the source and replica
# headers of ipc/ipc_process_interface.rep with repc, as the client and service builds do. Nothing is
# installed, no service or tunnel is touched; the local socket lives in the temp dir.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
GEN="$(mktemp -d "${TMPDIR:-/tmp}/avpn_tun2socks_reader.XXXXXX")"
trap 'rm -rf "${GEN:?}"' EXIT
MOCI=(-F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/include")
"$QT/libexec/repc" -o source "$ROOT/ipc/ipc_process_interface.rep" "$GEN/rep_ipc_process_interface_source.h"
"$QT/libexec/repc" -o replica "$ROOT/ipc/ipc_process_interface.rep" "$GEN/rep_ipc_process_interface_replica.h"
for h in rep_ipc_process_interface_source rep_ipc_process_interface_replica; do
  "$QT/libexec/moc" "${MOCI[@]}" "$GEN/$h.h" -o "$GEN/moc_$h.cpp"
done
OUT="$GEN/tun2socks_reader_check"
clang++ -std=c++17 -fPIC -Wall -Wno-deprecated-declarations \
  -I"$ROOT/client" -I"$GEN" \
  -F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtRemoteObjects.framework/Headers" -I"$QT/include" \
  "$HERE/tun2socks_reader_check.cpp" \
  "$GEN/moc_rep_ipc_process_interface_source.cpp" "$GEN/moc_rep_ipc_process_interface_replica.cpp" \
  -framework QtCore -framework QtNetwork -framework QtRemoteObjects -Wl,-rpath,"$QT/lib" -o "$OUT"
echo ">>> build ok: tun2socks_reader_check"
"$OUT"
