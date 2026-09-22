#!/bin/bash
# Автономная сборка+запуск проверки нативного ICMP-пробера (RttProbeIcmp): чистая агрегация
# трёх эх на цель (фикс-волна 2026-09-22, B9) + живой замер 127.0.0.1 / TEST-NET. Только QtCore/QtNetwork.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-/tmp/avpn_rtt_icmp_check}"
clang++ -std=c++17 -fPIC \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/../RttProbeIcmp.cpp" "$HERE/rtt_icmp_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
