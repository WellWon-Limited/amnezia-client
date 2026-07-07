#!/bin/bash
# AVPN — сборка+запуск E2E чата поддержки (TribeSupportChat против локального бэкенда).
# Нужны: живой бэкенд ветки feat/support-device-bearer, env TEST_TOKEN (device Bearer),
# AVPN_API_URL (например http://127.0.0.1:48611), E2E_ADMIN_TOKEN.
# Enrollment подменяется стабом (реальный тянет SecureQSettings/Keychain — не для харнесса).
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_e2e_support
MOC="$QT/libexec/moc"

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
EOF

# -f: включить заголовок по короткому имени (кладём moc-выхлоп вне дерева исходников)
"$MOC" -f "TribeSupportChat.h" "$HERE/../TribeSupportChat.h" -o /tmp/avpn_e2e_moc_support.cpp

clang++ -std=c++17 -fPIC \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" -I"$QT/include/QtGui" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtGui.framework/Headers" \
  -I"$HERE/.." \
  -F"$QT/lib" \
  "$HERE/../TribeSupportChat.cpp" /tmp/avpn_e2e_moc_support.cpp "$STUB" \
  "$HERE/e2e_support_check.cpp" \
  -framework QtCore -framework QtNetwork -framework QtGui -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"

QT_PLUGIN_PATH="$QT/plugins" "$OUT"
