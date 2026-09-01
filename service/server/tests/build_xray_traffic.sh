#!/bin/bash
# AVPN: автономная сборка+запуск проверки reset-safe аккумулятора статистики xray-пути демона
# (XrayTrafficAccumulator, service/server/xray.h). Только QtCore-хедеры, без линка с демоном —
# по образцу client/core/serviceEngine/tests/build_proto_forward.sh.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_xray_traffic_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/xray_traffic_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
