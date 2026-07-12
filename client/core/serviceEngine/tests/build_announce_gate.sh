#!/bin/bash
# Автономная сборка+запуск проверки AnnounceGate (header-only, вне тяжёлой сборки форка). Только QtCore.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_announce_gate_check
clang++ -std=c++17 -fPIC \
  -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" \
  "$HERE/announce_gate_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
