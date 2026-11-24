#!/bin/bash
# AVPN (owner's Mac 24.11.2026, cause F): standalone build + run of system_sleep_check - the engine's one fact "the
# system is fully awake" and its gate (SystemAwake.h) on the event script of that night, and the real ServiceEngine +
# attempt owner behind it with a fake tunnel (no start, no judgement while asleep; one evaluation on the awake edge).
# The same build as build_facade_engine.sh (QtCore/QtNetwork). OUT - the binary's path.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT="${OUT:-/tmp/avpn_system_sleep_check}"
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
  "$HERE/system_sleep_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> build ok: $OUT"
"$OUT"
