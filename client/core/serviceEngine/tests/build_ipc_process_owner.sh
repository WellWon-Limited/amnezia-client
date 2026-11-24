#!/bin/bash
# AVPN (macOS orphan tun2socks 24.11.2026): build + run the check of the service's ownership of its privileged
# children (ipc/ipcprocessowner.h) with real child processes (/bin/sleep stands in for tun2socks; every child
# lives at most 30 s and is ended by its handle, never by name). QtCore only. Nothing is installed, no service
# or tunnel is touched.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
GEN="$(mktemp -d "${TMPDIR:-/tmp}/avpn_ipc_process_owner.XXXXXX")"
trap 'rm -rf "${GEN:?}"' EXIT
OUT="$GEN/ipc_process_owner_check"
clang++ -std=c++17 -fPIC -Wall -Wno-deprecated-declarations \
  -I"$ROOT/ipc" \
  -F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/include" \
  "$HERE/ipc_process_owner_check.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT"
echo ">>> build ok: ipc_process_owner_check"
"$OUT"
