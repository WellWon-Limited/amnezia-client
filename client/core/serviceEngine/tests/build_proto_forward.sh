#!/bin/bash
# Автономная сборка+запуск проверки форвард-совместимости по proto нод (Task 10, backend-first-3):
# xray-нода не роняет парс, остаётся в пуле, но не выбирается никаким путём. Только QtCore/QtNetwork
# (ServiceEngine + туннель-стаб + линк-стабы сетевых функций — по образцу build_failover.sh).
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
# Фолбэк для хедеров 3rd-сабмодулей (qtkeychain): в git-worktree сабмодули могут быть не развёрнуты.
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT=/tmp/avpn_proto_forward_check
# Шим генерируемого qkeychain_export.h (транзитивно через secureQSettings.h; сам keychain не нужен).
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
  "$HERE/proto_forward_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
cd "$HERE"
"$OUT"
