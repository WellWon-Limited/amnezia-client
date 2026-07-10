#!/bin/bash
# Автономная сборка+запуск проверки BypassListLkg (LKG-кеш bypass-списков: сериализация,
# повторная верификация подписи, анти-downgrade). QtCore + libcrypto (Ed25519Verify.cpp).
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_bypass_lkg_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" -I"$SSL/include" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/../Ed25519Verify.cpp" "$HERE/test_bypass_lkg.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -L"$SSL/lib" -lcrypto \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
cd "$HERE"
"$OUT"
