#!/bin/bash
# tribe-daemon.sh — единый менеджер root-демона Tribe VPN на macOS.
#
# ЦЕЛЬ: ровно ОДИН экземпляр демона, чистая замена при каждом деплое, НОЛЬ накопления
# хвостов от прошлых установок/перезапусков. Любой install сначала вычищает ВСЕ
# исторические варианты наших артефактов и только потом ставит свежую копию —
# поэтому результат не зависит от того, какой мусор остался от прошлой версии.
#
# ЖЕЛЕЗНОЕ ПРАВИЛО: НИКОГДА не трогаем официальную Amnezia —
#   плист AmneziaVPN.plist, демон AmneziaVPN-service, receipt com.yourcompany/org.amnezia,
#   pf-анкор "amn", группу amnvpn. Все НАШИ имена изолированы (см. ниже).
#
# Использование:
#   sudo ./tribe-daemon.sh install <путь-к-Tribe-service> [<pf-каталог>] [<версия>]
#   sudo ./tribe-daemon.sh uninstall
#   sudo ./tribe-daemon.sh status
set -euo pipefail

# ---------- Каноническая личность (ОДНО имя везде) ----------
LABEL="Tribe-service"                              # = SERVICE_NAME (по нему isServiceReady ищет процесс)
PLIST="/Library/LaunchDaemons/${LABEL}.plist"      # имя файла ВСЕГДА = Label
HELPER_DIR="/Library/PrivilegedHelperTools/Tribe"  # бинарь живёт ВНЕ .app → апдейты приложения не трогают демон
BIN="${HELPER_DIR}/${LABEL}"
WG_BIN="${HELPER_DIR}/amneziawg-go"
PF_DIR="${HELPER_DIR}/pf"                           # ResourceDir демона = applicationDirPath()/pf
GROUP="tribevpn"
PF_ANCHOR="tribe"
DATA_DIR="/Library/Application Support/TribeVPN"
VERSION_FILE="${DATA_DIR}/daemon.version"

# ---------- Все исторические варианты НАШИХ артефактов (для purge) ----------
# upstream Amnezia сюда НЕ входит и не трогается.
LEGACY_PLISTS=(
  "/Library/LaunchDaemons/Tribe-service.plist"
  "/Library/LaunchDaemons/AntiVPN.plist"
  "/Library/LaunchDaemons/com.antivpn.helper.plist"
)
LEGACY_LABELS=( "Tribe-service" "com.antivpn.helper" )
LEGACY_DIRS=(
  "/Library/PrivilegedHelperTools/TribeVPN"   # старый каталог хелпера
  "/Library/Application Support/ANTIVPN"       # хелпер удалённого NeVPN
  "/Applications/AntiVPN.app"                  # старое имя приложения
)

die(){ echo "ОШИБКА: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "нужен sudo"

bootout_one(){
  local plist="$1"
  [ -e "$plist" ] || return 0
  launchctl bootout system "$plist" 2>/dev/null || launchctl unload "$plist" 2>/dev/null || true
  rm -f "$plist"
}

flush_anchor(){
  # Снимаем ТОЛЬКО наш анкор "tribe" и его под-анкоры. amn/системные не трогаем.
  local anc
  for anc in $(pfctl -s Anchors 2>/dev/null | awk '/^[[:space:]]*'"$PF_ANCHOR"'/ {sub(/\*$/,"",$1); print $1}'); do
    pfctl -a "$anc" -F all 2>/dev/null || true
  done
  if [ -f "$DATA_DIR/pf/pf.token" ]; then
    pfctl -X "$(cat "$DATA_DIR/pf/pf.token" 2>/dev/null)" 2>/dev/null || true
    rm -f "$DATA_DIR/pf/pf.token"
  fi
}

purge(){
  # 1) снять и удалить ВСЕ наши плисты (любые исторические имена)
  local p l d
  for p in "${LEGACY_PLISTS[@]}"; do bootout_one "$p"; done
  # 2) добить ВСЕ процессы демона (в т.ч. осиротевшие дубли, не отвечающие на bootout)
  #    + наш amneziawg-go (имя уникально: upstream = wireguard-go). SIGTERM, затем SIGKILL.
  for l in "${LEGACY_LABELS[@]}"; do pkill -x "$l" 2>/dev/null || true; done
  pkill -f "PrivilegedHelperTools/.*/amneziawg-go" 2>/dev/null || true
  sleep 1
  for l in "${LEGACY_LABELS[@]}"; do pkill -9 -x "$l" 2>/dev/null || true; done
  pkill -9 -f "PrivilegedHelperTools/.*/amneziawg-go" 2>/dev/null || true
  # 3) снять наш pf-анкор и токен
  flush_anchor
  # 4) удалить старые каталоги бинаря/легаси-приложение
  for d in "${LEGACY_DIRS[@]}"; do rm -rf "$d"; done
}

count_our_plists(){
  local p n=0
  for p in "${LEGACY_PLISTS[@]}"; do [ -f "$p" ] && n=$((n+1)); done
  echo "$n"
}

status(){
  echo "== Tribe daemon status =="
  echo "version: $([ -f "$VERSION_FILE" ] && cat "$VERSION_FILE" || echo '<нет>')"
  echo "plist:   $([ -f "$PLIST" ] && echo "$PLIST" || echo MISSING)"
  echo "binary:  $([ -x "$BIN" ] && echo "$BIN" || echo MISSING)"
  echo "wg-go:   $([ -x "$WG_BIN" ] && echo "$WG_BIN" || echo '<нет (поставится при сборке)>')"
  echo -n "launchd: "; launchctl print "system/${LABEL}" >/dev/null 2>&1 && echo loaded || echo "not loaded"
  local pids; pids="$(pgrep -x "$LABEL" 2>/dev/null | tr '\n' ' ' || true)"
  echo "process: $([ -n "$pids" ] && echo "running (pid ${pids})" || echo 'not running')"
  echo "--- инварианты (накопления быть не должно) ---"
  echo "наших плистов в /Library/LaunchDaemons: $(count_our_plists) (норма: 1)"
  echo "процессов ${LABEL}: $(pgrep -xc "$LABEL" 2>/dev/null || echo 0) (норма: 0–1)"
  echo "--- upstream Amnezia (не трогаем) ---"
  echo "AmneziaVPN.plist: $([ -f /Library/LaunchDaemons/AmneziaVPN.plist ] && echo present || echo absent)"
}

install(){
  local src="${1:-}" pfsrc="${2:-}" ver="${3:-}"
  [ -n "$src" ] || die "укажи путь к бинарю: install <путь-к-${LABEL}> [pf-каталог] [версия]"
  [ -x "$src" ] || die "бинарь не найден/не исполняемый: $src"
  [ "$(basename "$src")" = "$LABEL" ] || die "ожидаю бинарь с именем '${LABEL}' (isServiceReady ищет процесс по имени)"
  case "$src" in */AmneziaVPN.app/*) die "это бинарь официальной Amnezia — отказ";; esac
  [ -n "$pfsrc" ] || pfsrc="$(cd "$(dirname "$0")/../data/macos/pf" 2>/dev/null && pwd || true)"
  [ -d "$pfsrc" ] || die "не найден pf-каталог (нужны ${PF_ANCHOR}.*.conf): $pfsrc"
  ls "$pfsrc/${PF_ANCHOR}."*.conf >/dev/null 2>&1 || die "в $pfsrc нет ${PF_ANCHOR}.*.conf — пересобери (cmake генерит tribe.400.allowPIA.conf)"

  # ── ЧИСТЫЙ СТАРТ: снять всё историческое, гарантируя один экземпляр ──
  purge

  # ── разложить свежую копию ──
  mkdir -p "$HELPER_DIR" "$PF_DIR" "$DATA_DIR"
  cp -f "$src" "$BIN"
  # amneziawg-go кладём рядом, если лежит рядом с исходным бинарём (демон зовёт applicationDirPath()/amneziawg-go)
  if [ -x "$(dirname "$src")/amneziawg-go" ]; then
    cp -f "$(dirname "$src")/amneziawg-go" "$WG_BIN"
  fi
  rm -f "$PF_DIR"/*.conf 2>/dev/null || true
  cp -f "$pfsrc/${PF_ANCHOR}."*.conf "$PF_DIR/"
  [ -f "$pfsrc/${PF_ANCHOR}.conf" ] && cp -f "$pfsrc/${PF_ANCHOR}.conf" "$PF_DIR/" || true
  chown -R root:wheel "$HELPER_DIR"
  chmod -R go-w "$HELPER_DIR"
  chmod 755 "$HELPER_DIR" "$PF_DIR" "$BIN"
  [ -e "$WG_BIN" ] && chmod 755 "$WG_BIN" || true
  # Снять карантин/provenance xattr → macOS не делает повторный скан подписи при первом
  # запуске демоном (иначе amneziawg-go не успевает создать utun за таймаут → туннель падает).
  xattr -cr "$HELPER_DIR" 2>/dev/null || true

  # ── группа для xray-фильтрации (своя, не amnvpn) ──
  if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    local gid
    gid=$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | sort -n | awk '$1>=500{g=$1} END{print (g?g+1:501)}')
    dscl . -create "/Groups/$GROUP"
    dscl . -create "/Groups/$GROUP" PrimaryGroupID "$gid"
    dscl . -create "/Groups/$GROUP" RealName "Tribe VPN Service Group"
  fi

  # ── плист: имя файла = Label; KeepAlive → launchd сам поднимает упавший демон ──
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN}</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>GroupName</key>
    <string>${GROUP}</string>
    <key>StandardErrorPath</key>
    <string>/tmp/tribe-daemon.log</string>
    <key>StandardOutPath</key>
    <string>/tmp/tribe-daemon.log</string>
</dict>
</plist>
EOF
  chown root:wheel "$PLIST"
  chmod 644 "$PLIST"

  # ── версионный штамп (для проверки дрейфа демон↔приложение) ──
  printf '%s\n' "${ver:-unknown}" > "$VERSION_FILE"
  chmod 644 "$VERSION_FILE"

  # ── запуск (bootout уже сделан в purge → чистая загрузка) ──
  launchctl bootstrap system "$PLIST" || die "bootstrap не прошёл — смотри: launchctl print system/${LABEL}"
  launchctl enable "system/${LABEL}" 2>/dev/null || true
  launchctl kickstart -k "system/${LABEL}" 2>/dev/null || true
  sleep 1
  echo "OK: ${LABEL} установлен → ${BIN} (версия ${ver:-unknown})"
  echo
  status
}

uninstall(){
  purge
  rm -rf "$HELPER_DIR" "$DATA_DIR"
  # группу удаляем, только если её не использует ни один пользователь как primary
  if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    local gid users
    gid=$(dscl . -read "/Groups/$GROUP" PrimaryGroupID 2>/dev/null | awk '{print $2}')
    users=""
    [ -n "${gid:-}" ] && users=$(dscl . -list /Users PrimaryGroupID 2>/dev/null | awk -v g="$gid" '$2==g{print $1}')
    [ -z "$users" ] && dscl . -delete "/Groups/$GROUP" 2>/dev/null || true
  fi
  echo "Tribe-service полностью удалён (плисты, бинарь, pf-анкор, данные). Официальная Amnezia не тронута."
}

case "${1:-}" in
  install)   shift; install "$@";;
  uninstall) uninstall;;
  status)    status;;
  *)         die "использование: $0 install <путь-к-${LABEL}> [pf-каталог] [версия] | uninstall | status";;
esac
