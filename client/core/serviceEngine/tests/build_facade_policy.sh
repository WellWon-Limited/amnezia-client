#!/bin/bash
# Автономная сборка+запуск проверки чистых решений фасада AvpnEngineQml (фикс-волна 2026-09-22,
# зона CL-A): латч подтверждения стопа/статуса, адопт новой сессии, пустая выдача/LKG, pin,
# дедлайн/ошибка внутреннего свитча, бюджет подготовки старта, outbox отчётов, кольцо лога.
# Только QtCore (заголовки DebugSnapshot.h / ReportDelivery.h). OUT_DIR — куда класть бинарь.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-facade-policy.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  "$HERE/facade_policy_check.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/facade_policy_check"
"$OUT_DIR/facade_policy_check"
