#!/bin/bash
set -euo pipefail

QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
OUT="${TMPDIR:-/tmp}/tribe_openvpn_config_security_check"

clang++ -std=c++20 -fPIC -DTRIBE_DNS_SECURITY_TESTING \
  -I"$ROOT/ipc" -I"$ROOT/service/server" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -I"$QT/lib/QtNetwork.framework/Headers" -F"$QT/lib" \
  "$ROOT/ipc/openvpnconfigsecurity.cpp" \
  "$ROOT/service/server/openvpndnssecurity.cpp" \
  "$HERE/openvpn_config_security_harness.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -framework CoreFoundation -framework SystemConfiguration \
  -Wl,-rpath,"$QT/lib" -o "$OUT"

(cd "$ROOT" && "$OUT")
