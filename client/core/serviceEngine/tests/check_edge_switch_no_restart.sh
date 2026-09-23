#!/bin/bash
# AVPN (разбор 2026-09-23): смена API-edge (ConfigService::activeEdgeChanged) НЕ должна
# перезапускать живой туннель. Журнал iPhone владельца: ложные «три отказа подряд» (запросы,
# пережившие заморозку iOS или смену чужого VPN) → смена edge → rebuildApiCarveOut() →
# reapplyBypass() → guardedStop("reconcile_restart"); iOS замораживала приложение до старта →
# VPN выключен до следующего открытия. Вырез API-IP применяется при следующем обычном старте.
# Проверка уровня исходника: в теле rebuildApiCarveOut() и в обработчике activeEdgeChanged нет
# вызовов, которые передёргивают туннель.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../AvpnEngineQml.cpp"
fail=0

body_of() { # $1 — строка-начало функции; печатает тело до строки "}" в первой колонке
    awk -v start="$1" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$SRC"
}

carve="$(body_of 'void AvpnEngineQml::rebuildApiCarveOut()')"
if [ -z "$carve" ]; then
    echo "FAIL: rebuildApiCarveOut() не найдена"; fail=1
elif printf '%s\n' "$carve" | grep -v '^[[:space:]]*//' | grep -Eq 'reapplyBypass\(|m_needsRestart|guardedStop\(|reconcile\('; then
    echo "FAIL: rebuildApiCarveOut() передёргивает туннель:"
    printf '%s\n' "$carve" | grep -n -E 'reapplyBypass\(|m_needsRestart|guardedStop\(|reconcile\('
    fail=1
fi

handler="$(awk '/&avpn::ConfigService::activeEdgeChanged, this,/ { on = 1 } on { print } on && /^[[:space:]]*}\);/ { exit }' "$SRC")"
if [ -z "$handler" ]; then
    echo "FAIL: обработчик activeEdgeChanged не найден"; fail=1
elif printf '%s\n' "$handler" | grep -v '^[[:space:]]*//' | grep -Eq 'reapplyBypass\(|m_needsRestart|guardedStop\(|reconcile\('; then
    echo "FAIL: обработчик activeEdgeChanged передёргивает туннель"; fail=1
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "check_edge_switch_no_restart: ok"
