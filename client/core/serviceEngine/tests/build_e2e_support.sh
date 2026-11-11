#!/bin/bash
# AVPN — сборка+запуск E2E чата поддержки (TribeSupportChat против локального бэкенда).
# Нужны: живой бэкенд ветки feat/support-device-bearer, env TEST_TOKEN (device Bearer),
# AVPN_API_URL (например http://127.0.0.1:48611), E2E_ADMIN_TOKEN.
# Enrollment подменяется стабом (реальный тянет SecureQSettings/Keychain — не для харнесса).
# Без этих env (нет живого бэкенда) скрипт только собирает и линкует харнесс и выходит с SKIP прогона
# (exit 0, как check_neverbypass_sync.sh без чекаута бэкенда); сборка проверяется всегда.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
# Фолбэк для хедеров 3rd-сабмодулей (qtkeychain): в git-worktree сабмодули могут быть не развёрнуты.
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT=/tmp/avpn_e2e_support
MOC="$QT/libexec/moc"
# TribeSupportChat.cpp тянет AvpnEngineQml.h (ради AvpnEngineQml::uiForeground), а тот —
# VpnConnectionTunnelControl.h → "core/utils/containerEnum.h" (путь от корня client/) и
# secureQSettings.h → qkeychain_export.h (генерируемый хедер: шим, сам keychain не нужен — как в
# build_transport_pick.sh).
SHIM="$(mktemp -d)"
trap 'rm -rf "$SHIM"' EXIT
printf '#pragma once\n#define QKEYCHAIN_EXPORT\n' > "$SHIM/qkeychain_export.h"

STUB=/tmp/avpn_e2e_stub_enrollment.cpp
cat > "$STUB" <<'EOF'
// Стаб Enrollment для E2E: токен из env вместо SecureQSettings (Keychain).
#include "Enrollment.h"
namespace avpn {
QString Enrollment::loadToken()
{
    return QString::fromUtf8(qgetenv("TEST_TOKEN"));
}
} // namespace avpn
// Стаб AvpnEngineQml::uiForeground: фасад целиком (QML, VpnConnection) харнессу не нужен; окно чата
// в E2E считаем активным (фоновый опрос бейджа идёт как на открытом экране).
#include "AvpnEngineQml.h"
bool avpn::AvpnEngineQml::uiForeground()
{
    return true;
}
EOF

# -f: включить заголовок по короткому имени (кладём moc-выхлоп вне дерева исходников)
"$MOC" -f "TribeSupportChat.h" "$HERE/../TribeSupportChat.h" -o /tmp/avpn_e2e_moc_support.cpp

clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$SHIM" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" -I"$QT/include/QtGui" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtGui.framework/Headers" \
  -I"$HERE/.." -I"$CLIENT" -I"$MAIN_CLIENT" \
  -F"$QT/lib" \
  "$HERE/../TribeSupportChat.cpp" /tmp/avpn_e2e_moc_support.cpp "$STUB" \
  "$HERE/e2e_support_check.cpp" \
  -framework QtCore -framework QtNetwork -framework QtGui -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"

if [ -z "${AVPN_API_URL:-}" ] || [ -z "${TEST_TOKEN:-}" ] || [ -z "${E2E_ADMIN_TOKEN:-}" ]; then
    echo ">>> SKIP e2e-support: прогону нужен живой бэкенд (env AVPN_API_URL / TEST_TOKEN / E2E_ADMIN_TOKEN) — проверена только сборка"
    exit 0
fi
QT_PLUGIN_PATH="$QT/plugins" "$OUT"
