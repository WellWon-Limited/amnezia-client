#!/bin/bash
# Автономная сборка+запуск проверки отправщика журнала тестирования (TribeJournal.cpp) против
# локального HTTP-сервера. QtCore + QtNetwork; logger.h — заглушка из tests/stub.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-journal-upload.XXXXXX)"
trap 'rm -rf -- "$OUT"' EXIT
"$QT/libexec/moc" -f"$HERE/../TribeJournal.h" "$HERE/../TribeJournal.h" -o "$OUT/moc_TribeJournal.cpp"
clang++ -std=c++17 -fPIC \
  -I"$HERE/stub" -I"$HERE/.." -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/journal_upload_check.cpp" "$HERE/../TribeJournal.cpp" "$OUT/moc_TribeJournal.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT/journal_upload_check"
WW_TEST=1 WW_TEST_ID=journal-upload "$OUT/journal_upload_check"
