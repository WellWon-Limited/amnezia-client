#!/bin/bash
# AVPN (macOS self-update v2): автономная сборка+запуск юнита LaunchGuard.h (только QtCore).
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_launch_guard_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/launch_guard_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
# Фасад обязан компилироваться и без macOS-реализации (iOS/NE-ветка = no-op).
"$QT/libexec/moc" "$HERE/../LaunchGuard.h" -o /tmp/avpn_moc_LaunchGuard.cpp
clang++ -std=c++17 -fPIC -include arm_acle.h -DMACOS_NE -fsyntax-only \
  -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -F"$QT/lib" "$HERE/../LaunchGuard.cpp"
echo ">>> LaunchGuard.cpp компилируется под MACOS_NE (no-op ветка)"
