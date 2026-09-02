#!/bin/bash
# Автономная сборка+запуск проверки гардов data-plane (независимое ревью волны awg31-xray-v1):
# кап подряд идущих провалов data-plane (вместо вечной карусели failover), приведение недоступного
# режима «Xray» к «Авто», доказательство трафика ЧЕРЕЗ туннель при верификации xray, единый
# предикат «туннель поднят» (verifying в нём).
# Только QtCore/QtNetwork (ServiceEngine + туннель-стаб + линк-стабы — по образцу build_proto_forward.sh).
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
# Фолбэк для хедеров 3rd-сабмодулей (qtkeychain): в git-worktree сабмодули могут быть не развёрнуты.
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT=/tmp/avpn_dataplane_guard_check
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
  "$HERE/dataplane_guard_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
cd "$HERE"
"$OUT"
