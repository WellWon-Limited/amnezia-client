#!/bin/bash
# Автономная сборка+запуск проверки Ed25519Verify (детачед-подпись серверного конфига). QtCore + libcrypto.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_ed25519_verify_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$SSL/include" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/../Ed25519Verify.cpp" "$HERE/ed25519_verify_check.cpp" \
  -framework QtCore -framework Foundation \
  -L"$SSL/lib" -lcrypto \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
