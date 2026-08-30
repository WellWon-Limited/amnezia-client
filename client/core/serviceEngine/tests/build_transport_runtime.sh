#!/bin/bash
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
OUT=/tmp/tribe_transport_runtime_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$CLIENT" -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$SSL/include" -F"$QT/lib" \
  "$HERE/../CatalogParser.cpp" "$HERE/../Ed25519Verify.cpp" \
  "$HERE/../AwgConfigBuilder.cpp" "$HERE/../NativeProfileCompiler.cpp" \
  "$HERE/../NativeConnectionPolicy.cpp" "$HERE/../NativeDispatchPolicyDigest.cpp" \
  "$CLIENT/core/models/protocols/xrayProtocolConfig.cpp" \
  "$HERE/../ConnectionReducer.cpp" "$HERE/transport_runtime_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -L"$SSL/lib" -lcrypto -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> build ok: $OUT"
"$OUT"
