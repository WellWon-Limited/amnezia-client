#!/bin/bash
# CPack productbuild POSTFLIGHT — ставит/обновляет root-демон Tribe через ЕДИНЫЙ
# tribe-daemon.sh. Идемпотентно и без накопления: tribe-daemon.sh сам снимает все
# исторические варианты перед установкой свежего. Официальную Amnezia не трогает.
set -uo pipefail

APP="/Applications/TribeVPN.app"
MGR="$APP/Contents/Resources/tribe-daemon.sh"
BIN="$APP/Contents/MacOS/Tribe-service"
PFDIR="$APP/Contents/MacOS/pf"
LOG_DIR="/var/log/TribeVPN"
LOG="$LOG_DIR/post-install.log"

mkdir -p "$LOG_DIR"
echo "$(date) postflight start" >> "$LOG"

VER="$(/usr/bin/defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo unknown)"

if [ -x "$MGR" ] && [ -x "$BIN" ]; then
    # productbuild postflight уже выполняется под root — sudo не нужен
    bash "$MGR" install "$BIN" "$PFDIR" "$VER" >> "$LOG" 2>&1 \
        && echo "$(date) daemon installed (v$VER)" >> "$LOG" \
        || echo "$(date) ERROR: tribe-daemon.sh install завершился с ошибкой" >> "$LOG"
else
    echo "$(date) ERROR: не найдены $MGR или $BIN" >> "$LOG"
fi

# Запустить приложение
open -a "$APP" >> "$LOG" 2>&1 || true
echo "$(date) postflight done" >> "$LOG"
exit 0
