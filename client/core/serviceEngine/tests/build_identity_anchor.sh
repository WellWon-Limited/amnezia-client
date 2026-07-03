#!/bin/bash
# Автономная сборка+запуск проверки чистой логики Keychain-якоря идентичности.
# Только inline-функции IdentityAnchor.h — без QtKeychain/сети. Только QtCore.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_identity_anchor_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -DAVPN_ANCHOR_PURE_ONLY \
  -I"$QT/include" -I"$QT/include/QtCore" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/identity_anchor_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
cd "$HERE"
"$OUT"
