#!/bin/bash
# Используется как CPack PREFLIGHT (чистка перед установкой новой версии) И как
# скрипт полного удаления. Делегирует снятие демона в ЕДИНЫЙ tribe-daemon.sh, чтобы
# гарантированно не осталось хвостов от прошлых установок. Официальную Amnezia не трогает.
set -uo pipefail

APP="/Applications/TribeVPN.app"
MGR="$APP/Contents/Resources/tribe-daemon.sh"

# Корректно закрыть GUI, если запущен
if pgrep -x "TribeVPN" > /dev/null 2>&1; then
    osascript -e 'tell application "TribeVPN" to quit' 2>/dev/null || true
    for _ in $(seq 1 10); do pgrep -x "TribeVPN" >/dev/null 2>&1 || break; sleep 1; done
fi

if [ -x "$MGR" ]; then
    bash "$MGR" uninstall || true
else
    # Фолбэк, если менеджер недоступен (старая/битая установка): снять наши артефакты вручную.
    launchctl bootout system /Library/LaunchDaemons/Tribe-service.plist 2>/dev/null \
        || launchctl unload /Library/LaunchDaemons/Tribe-service.plist 2>/dev/null || true
    rm -f /Library/LaunchDaemons/Tribe-service.plist \
          /Library/LaunchDaemons/AntiVPN.plist \
          /Library/LaunchDaemons/com.antivpn.helper.plist
    pkill -x "Tribe-service" 2>/dev/null || true
    pkill -f "PrivilegedHelperTools/.*/amneziawg-go" 2>/dev/null || true
    for anc in $(pfctl -s Anchors 2>/dev/null | awk '/^[[:space:]]*tribe/ {sub(/\*$/,"",$1); print $1}'); do
        pfctl -a "$anc" -F all 2>/dev/null || true
    done
    rm -rf /Library/PrivilegedHelperTools/Tribe \
           /Library/PrivilegedHelperTools/TribeVPN \
           "/Library/Application Support/TribeVPN" \
           "/Library/Application Support/ANTIVPN" \
           /Applications/AntiVPN.app
fi

# Полное удаление: снести и приложение (для PREFLIGHT productbuild это безопасно —
# payload пишется уже после preflight, новая копия встанет следом).
rm -rf "$APP"
exit 0
