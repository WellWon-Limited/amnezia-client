#!/bin/bash
# Standalone build+run of the ApkUpdatePolicy check (header-only, outside the fork build). QtCore only.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_apk_update_policy_check
clang++ -std=c++17 -fPIC \
  -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" \
  "$HERE/apk_update_policy_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> build ok: $OUT"
"$OUT"
