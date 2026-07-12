#!/bin/bash
# Автономная сборка+запуск проверки TribeDiagReport (header-only, вне тяжёлой сборки форка). Только QtCore.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_diag_report_check
clang++ -std=c++17 -fPIC \
  -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" \
  "$HERE/test_diag_report.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
