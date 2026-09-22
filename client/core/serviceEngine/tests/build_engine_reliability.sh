#!/bin/bash
# Автономная сборка+запуск регрессий фикс-волны надёжности 2026-09-22 (зона CL-B, контракт K5):
# ServiceEngine/HealthLoop — пустая выдача, ревизии, Unchanged/switchlog-flood, identity, фазы свитча,
# лестница DEAD, итог rebind, roaming grace, RTT-кэш. Только QtCore/QtNetwork (по образцу build_failover.sh).
#
#   build_engine_reliability.sh          — против рабочего дерева (должно быть OK);
#   build_engine_reliability.sh --base   — секции [OLD-API] против движка из git-ревизии BASE_REV
#                                          (по умолчанию HEAD): на базе они ОБЯЗАНЫ падать —
#                                          доказательство, что тест ловит исходные дефекты.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT="${OUT:-/tmp/avpn_engine_reliability_check}"
SHIM="$(mktemp -d)"
trap 'rm -rf "$SHIM"' EXIT
printf '#pragma once\n#define QKEYCHAIN_EXPORT\n' > "$SHIM/qkeychain_export.h"

SRC="$HERE/.."
DEFS=""
if [ "${1:-}" = "--base" ]; then
  BASE="$SHIM/base"
  mkdir -p "$BASE"
  (cd "$CLIENT/.." && git archive "${BASE_REV:-HEAD}" client/core) | tar -x -C "$BASE"
  SRC="$BASE/client/core/serviceEngine"
  cp "$HERE/engine_reliability_check.cpp" "$SRC/tests/engine_reliability_check.cpp"
  DEFS="-DAVPN_ENGINE_OLD_API"
  echo ">>> база: ${BASE_REV:-HEAD} (секции [OLD-API])"
fi

clang++ -std=c++17 -fPIC -include arm_acle.h $DEFS \
  -I"$SHIM" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$CLIENT" -I"$MAIN_CLIENT" \
  -F"$QT/lib" \
  "$SRC/ServiceEngine.cpp" "$SRC/SubscriptionParser.cpp" "$SRC/Prober.cpp" \
  "$SRC/AwgConfigBuilder.cpp" \
  "$SRC/tests/engine_reliability_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
