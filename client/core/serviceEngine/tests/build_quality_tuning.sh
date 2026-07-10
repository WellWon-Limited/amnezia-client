#!/bin/bash
# Автономная сборка+запуск проверки порогов качества/троттлинга (GoodputThresholds::fromTuning,
# SignalQuality::RttBands::fromTuning) — читают TuningStore, header-only, только QtCore.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_quality_tuning_check
clang++ -std=c++17 -fPIC \
  -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" \
  "$HERE/test_quality_tuning.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
