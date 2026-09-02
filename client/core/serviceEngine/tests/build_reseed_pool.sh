#!/bin/bash
# Автономная сборка+запуск проверки reseed пула на живом приложении (волна awg31-xray-v1, этап D4):
# ServiceEngine::reseedPool — терминал/неизменная текущая нода/pending, ревизии, pin по локации,
# сброс RTT-кэша. Только QtCore/QtNetwork (по образцу build_proto_forward.sh).
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT=/tmp/avpn_reseed_pool_check
SHIM="$(mktemp -d)"
trap 'rm -rf "$SHIM"' EXIT
printf '#pragma once\n#define QKEYCHAIN_EXPORT\n' > "$SHIM/qkeychain_export.h"
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$SHIM" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$CLIENT" -I"$MAIN_CLIENT" \
  -F"$QT/lib" \
  "$HERE/../ServiceEngine.cpp" "$HERE/../SubscriptionParser.cpp" "$HERE/../Prober.cpp" \
  "$HERE/../AwgConfigBuilder.cpp" \
  "$HERE/reseed_pool_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
cd "$HERE"
"$OUT"
