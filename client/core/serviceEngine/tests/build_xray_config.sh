#!/bin/bash
# Автономная сборка+запуск проверки волны «AWG 3.1 + Xray через v1» (этап D1):
# DTO/парсер xray_params + host_id/location/transport_rank/pool_revision, XrayConfigBuilder
# (конверт апстрима protocol=xray + xray_config_data.config = JSON xray-core), фильтр незнакомых
# wg-quick ключей для awg-apple, регресс «старый JSON байт-в-байт». Только QtCore/QtNetwork,
# по образцу build_proto_forward.sh (без ServiceEngine — парсер/билдеры автономны).
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT=/tmp/avpn_xray_config_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$CLIENT" \
  -F"$QT/lib" \
  "$HERE/../SubscriptionParser.cpp" "$HERE/../AwgConfigBuilder.cpp" \
  "$HERE/../XrayConfigBuilder.cpp" "$HERE/../Prober.cpp" \
  "$HERE/xray_config_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
cd "$HERE"
"$OUT"
