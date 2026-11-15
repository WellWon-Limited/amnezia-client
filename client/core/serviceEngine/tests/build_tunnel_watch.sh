#!/bin/bash
# Standalone build+run of the checks of the app's half of the iOS tunnel-side data watch
# (ConnectTunables.h table, TunnelWatchPlan.h, TunnelWatchStatus.h): pure inline functions, QtCore only.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-/tmp/avpn_tunnel_watch_check}"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra \
  -I"$QT/include" -I"$QT/include/QtCore" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/tunnel_watch_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> build ok: $OUT"
cd "$HERE"
"$OUT"
