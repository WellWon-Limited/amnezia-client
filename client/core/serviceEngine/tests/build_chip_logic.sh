#!/bin/bash
# Автономная сборка+запуск проверки чистой логики чипов доступности v2 (ChipLogic.h):
# классификация reachability-голоса, кворум «оба упали = заблокировано», уточнение качества,
# гистерезис ухудшения/восстановления. Без сети, без форка. Только QtCore.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_chip_logic_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/chip_logic_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
cd "$HERE"
"$OUT"
