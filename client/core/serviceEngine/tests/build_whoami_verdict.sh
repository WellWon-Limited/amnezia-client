#!/bin/bash
# Standalone build+run of the whoami verdict and network memory checks (WhoamiVerdict.h,
# NetworkMemory.h): pure inline functions, no network, QtCore only. Plan v3 step 5.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-/tmp/avpn_whoami_verdict_check}"
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/whoami_verdict_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> build ok: $OUT"
cd "$HERE"
"$OUT"
