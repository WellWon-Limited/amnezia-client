#!/bin/bash
# Автономная сборка+запуск проверки политики журнала тестирования (JournalPolicy.h).
# Только QtCore. OUT_DIR — куда класть бинарь.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-journal-policy.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$HERE/.." \
  "$HERE/journal_policy_check.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/journal_policy_check"
"$OUT_DIR/journal_policy_check"
