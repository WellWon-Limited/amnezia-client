#!/bin/bash
# Автономная сборка+запуск проверки CidrCarve (carve-out IP API из RU-direct сева). Только QtCore+QtNetwork.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_cidr_carve_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/cidr_carve_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
