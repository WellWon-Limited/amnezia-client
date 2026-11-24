#!/bin/bash
# AVPN: build and run the check of the macOS service's Xray core session rule and its diagnostics
# (service/server/xraysession.h). QtCore headers only, no link with the service - the pattern of
# build_xray_traffic.sh.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_xray_session_check
clang++ -std=c++17 -fPIC \
  -I"$QT/include" -I"$QT/include/QtCore" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/xray_session_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> build ok: $OUT"
"$OUT"
