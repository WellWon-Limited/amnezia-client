#!/bin/bash
# install-tribe-service.sh — установка/удаление root-демона Tribe VPN (dev, macOS).
#
# ЖЕЛЕЗНОЕ ПРАВИЛО: скрипт не трогает НИЧЕГО из официальной Amnezia —
# ни AmneziaVPN-service, ни pf-анкор "amn", ни группу amnvpn, ни порт 5959.
# Все наши имена: демон/label Tribe-service, pf-анкор "tribe", группа tribevpn,
# pf-данные /Library/Application Support/TribeVPN/pf, wg-runtime /var/run/tribewg.
#
# Использование:
#   sudo ./install-tribe-service.sh install /путь/к/Tribe-service
#   sudo ./install-tribe-service.sh uninstall
set -euo pipefail

LABEL="Tribe-service"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
GROUP="tribevpn"
PF_ANCHOR="tribe"
PF_DATA_DIR="/Library/Application Support/TribeVPN/pf"
REPO_PF_DIR="$(cd "$(dirname "$0")/../data/macos/pf" && pwd)"

die() { echo "ОШИБКА: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "нужен sudo"

cmd="${1:-}"

uninstall() {
    # Снимаем ТОЛЬКО наш демон и наш pf-анкор.
    launchctl bootout system "$PLIST" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    pkill -x "$LABEL" 2>/dev/null || true
    rm -rf "/Library/PrivilegedHelperTools/TribeVPN"

    # Чистим только анкор "tribe" и под-анкоры — системные правила и "amn" не трогаем.
    for anc in $(pfctl -s Anchors 2>/dev/null | awk '/^'"$PF_ANCHOR"'/ {sub(/\*$/, "", $1); print $1}'); do
        pfctl -a "$anc" -F all 2>/dev/null || true
    done
    if [ -f "$PF_DATA_DIR/pf.token" ]; then
        pfctl -X "$(cat "$PF_DATA_DIR/pf.token")" 2>/dev/null || true
    fi
    rm -rf "/Library/Application Support/TribeVPN"
    echo "Tribe-service удалён. Официальная Amnezia не тронута."
}

install() {
    local src="${1:-}"
    [ -n "$src" ] || die "укажи путь к бинарю: install /путь/к/Tribe-service"
    [ -x "$src" ] || die "бинарь не найден или не исполняемый: $src"
    [ "$(basename "$src")" = "$LABEL" ] || die "ожидаю бинарь с именем $LABEL (isServiceReady ищет процесс по имени)"
    case "$src" in */AmneziaVPN.app/*) die "это бинарь официальной Amnezia — отказ";; esac

    # ⚠️ launchd МОЛЧА не запускает системных демонов из user-writable путей —
    # кладём бинарь в root-овый /Library/PrivilegedHelperTools (см. TRIBE-iOS-DEV §15).
    local destdir="/Library/PrivilegedHelperTools/TribeVPN"
    local bin="$destdir/$LABEL"
    local srcdir="$(cd "$(dirname "$src")" && pwd)"
    mkdir -p "$destdir"
    cp -f "$src" "$bin"

    # amneziawg-go демон запускает из своего же каталога (applicationDirPath) — кладём рядом.
    [ -x "$srcdir/amneziawg-go" ] && cp -f "$srcdir/amneziawg-go" "$destdir/amneziawg-go" \
        || echo "  ⚠️ amneziawg-go не найден рядом с демоном — туннель не поднимется"

    # Вшитый Qt+openssl (bundle-daemon-qt.sh): демон ищет их по rpath @loader_path/Frameworks.
    # Без этого на машине без ~/Qt демон не стартует (dyld). Если каталога нет — демон рассчитывает
    # на dev-Qt в ~/Qt (только для этой машины).
    if [ -d "$srcdir/Frameworks" ]; then
        rm -rf "$destdir/Frameworks"
        cp -aR "$srcdir/Frameworks" "$destdir/Frameworks"
        echo "  + вшитый Qt/openssl скопирован в $destdir/Frameworks"
    else
        echo "  ⚠️ нет $srcdir/Frameworks — демон будет грузить Qt из ~/Qt (не для раздачи!)"
    fi

    # pf-правила демон читает из каталога pf рядом с бинарём (ResourceDir).
    mkdir -p "$destdir/pf"
    cp -f "$REPO_PF_DIR/${PF_ANCHOR}."*.conf "$REPO_PF_DIR/${PF_ANCHOR}.conf" "$destdir/pf/" 2>/dev/null \
        || die "в $REPO_PF_DIR нет ${PF_ANCHOR}.*.conf (пересобери: cmake генерирует tribe.400.allowPIA.conf)"
    # AVPN: маркер версии демона (хэш бинарей) — тот же расчёт, что в make-macos-dist.sh, чтобы
    # приложение не считало ручную dev-установку устаревшей и не показывало лишний промпт.
    cat "$bin" "$destdir/amneziawg-go" 2>/dev/null | shasum -a 256 | cut -c1-16 > "$destdir/VERSION"
    chown -R root:wheel "$destdir"
    chmod 755 "$destdir" "$bin"

    # Группа для xray-фильтрации (своя, не amnvpn).
    if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
        local gid
        gid=$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | sort -n | awk '$1>=500{g=$1} END{print (g?g+1:501)}')
        dscl . -create "/Groups/$GROUP"
        dscl . -create "/Groups/$GROUP" PrimaryGroupID "$gid"
        dscl . -create "/Groups/$GROUP" RealName "Tribe VPN Service Group"
    fi

    # Идемпотентно: сначала снимаем старую копию.
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"

    # Без блока Sockets: демон его не использует, а launchd-листенер на общем
    # порту (5959) конфликтовал с официальной Amnezia (Bootstrap failed: 5).
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${bin}</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>GroupName</key>
    <string>${GROUP}</string>
</dict>
</plist>
EOF
    chown root:wheel "$PLIST"
    chmod 644 "$PLIST"

    launchctl bootstrap system "$PLIST" || die "bootstrap не прошёл — смотри: launchctl print system/${LABEL}"
    launchctl enable "system/${LABEL}" || true
    launchctl kickstart -k "system/${LABEL}" || true
    sleep 1
    launchctl print "system/${LABEL}" | head -5 || true
    echo "OK: ${LABEL} установлен (${bin})."
}

case "$cmd" in
    install)   install "${2:-}";;
    uninstall) uninstall;;
    *)         die "использование: $0 install /путь/к/Tribe-service | uninstall";;
esac
