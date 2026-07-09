#!/bin/bash
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_config_store_check
clang++ -std=c++17 -fPIC -DAVPN_CONFIGSTORE_TEST=1 \
  -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" \
  "$HERE/config_store_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
