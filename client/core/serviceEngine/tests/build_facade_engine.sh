#!/bin/bash
# Автономная сборка+запуск последовательностей фасада AvpnEngineQml против настоящего ServiceEngine
# (фикс-волна 2026-09-22, зона CL-A, пробелы критика полноты): флаппинг сети не глушит DEAD (GAP-2),
# повтор после дедлайна свитча сохраняет цель и бюджет лечения (GAP-3). По образцу
# build_engine_reliability.sh (QtCore/QtNetwork). OUT — путь бинаря.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT="${OUT:-/tmp/avpn_facade_engine_check}"
SHIM="$(mktemp -d)"
trap 'rm -rf "$SHIM"' EXIT
printf '#pragma once\n#define QKEYCHAIN_EXPORT\n' > "$SHIM/qkeychain_export.h"
SRC="$HERE/.."
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$SHIM" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$CLIENT" -I"$MAIN_CLIENT" \
  -F"$QT/lib" \
  "$SRC/ServiceEngine.cpp" "$SRC/SubscriptionParser.cpp" "$SRC/Prober.cpp" \
  "$SRC/AwgConfigBuilder.cpp" \
  "$HERE/facade_engine_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
