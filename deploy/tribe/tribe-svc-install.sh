#!/bin/bash
# tribe-svc-install.sh — ВШИВАЕТСЯ в TribeVPN.app/Contents/Resources/. Запускается приложением
# через osascript «with administrator privileges» (один системный промпт пароля, без терминала).
# Распаковывает payload-tarball (аргумент $1: tribe-svc.tar.gz с Tribe-service + amneziawg-go +
# tun2socks (с 5.1.108, рантайм Xray) + Frameworks(вшитый Qt) + pf, бинари подписаны Developer ID+runtime) в
# /Library/PrivilegedHelperTools/TribeVPN, пишет LaunchDaemon + bootstrap.
# Payload — tarball-РЕСУРС (а не loose-файлы в бандле): не ломает подпись app, нотаризация внутрь
# tar не лезет. НЕ трогает официальную Amnezia (имена: Tribe-service / tribevpn / анкор tribe).
set -uo pipefail
# AuthorizationExecuteWithPrivileges запускает нас с ПУСТЫМ PATH → bare-команды (tar/mktemp/cp/
# chown/launchctl/dscl в /usr/bin,/usr/sbin,/bin) не находятся. Задаём PATH явно. Лог — для диагностики.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
exec > >(tee -a /tmp/tribe-svc-install.log) 2>&1
echo "=== tribe-svc-install $(date) PATH=$PATH ==="

TARBALL="${1:?укажи путь к tribe-svc.tar.gz}"
[ -f "$TARBALL" ] || { echo "нет tarball: $TARBALL"; exit 1; }
SRC="$(mktemp -d)"; trap 'rm -rf "$SRC"' EXIT
tar xzf "$TARBALL" -C "$SRC" || { echo "распаковка не удалась"; exit 1; }

LABEL="Tribe-service"; GROUP="tribevpn"
DEST="/Library/PrivilegedHelperTools/TribeVPN"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

[ -x "$SRC/Tribe-service" ] || { echo "нет Tribe-service в tarball"; exit 1; }
[ -x "$SRC/amneziawg-go" ]  || { echo "нет amneziawg-go в tarball"; exit 1; }
[ -x "$SRC/tun2socks" ]     || { echo "нет tun2socks в tarball"; exit 1; }
[ -d "$SRC/Frameworks" ]    || { echo "нет Frameworks в tarball"; exit 1; }

# AVPN (инцидент 5.1.92, 2026-09-25): замена бинарей поверх РАБОТАЮЩЕГО демона через `cp -f` пишет
# в тот же файл (тот же inode) — ядро держит закэшированную подпись старой версии, и каждый новый
# запуск убивается «SIGKILL (Code Signature Invalid)» до перезагрузки (демон в крэш-лупе, VPN не
# поднимается). Поэтому: 1) сначала останавливаем демон и его amneziawg-go, 2) кладём файлы через
# временное имя + mv (новый inode — ядро читает подпись заново).
launchctl bootout "system/${LABEL}" 2>/dev/null || launchctl bootout system "$PLIST" 2>/dev/null || true
pkill -f "$DEST/amneziawg-go" 2>/dev/null || true
pkill -f "$DEST/tun2socks" 2>/dev/null || true
replace_file() {
  local src="$1" dst="$2" tmp="$2.new.$$"
  cp -p "$src" "$tmp" && mv -f "$tmp" "$dst" || { rm -f "$tmp"; echo "замена $dst не удалась"; exit 1; }
}
mkdir -p "$DEST"
replace_file "$SRC/Tribe-service" "$DEST/Tribe-service"
replace_file "$SRC/amneziawg-go"  "$DEST/amneziawg-go"
replace_file "$SRC/tun2socks"     "$DEST/tun2socks"
rm -rf "$DEST/Frameworks.new"; cp -aR "$SRC/Frameworks" "$DEST/Frameworks.new" \
  && rm -rf "$DEST/Frameworks" && mv "$DEST/Frameworks.new" "$DEST/Frameworks" \
  || { echo "замена Frameworks не удалась"; exit 1; }
mkdir -p "$DEST/pf"; cp -f "$SRC/pf/"*.conf "$DEST/pf/" 2>/dev/null || true
# AVPN: маркер версии демона (хэш бинарей) — приложение сверяет и переустанавливает при отличии
# (иначе апдейт логики демона не доезжал бы до юзеров с уже установленным демоном). Нет файла в
# tarball (старая сборка) → пишем метку "legacy", чтобы след. апдейт всё равно триггернул замену.
[ -f "$SRC/VERSION" ] && cp -f "$SRC/VERSION" "$DEST/VERSION" || echo "legacy" > "$DEST/VERSION"
chown -R root:wheel "$DEST"
chmod 755 "$DEST" "$DEST/Tribe-service" "$DEST/amneziawg-go" "$DEST/tun2socks"
xattr -cr "$DEST" 2>/dev/null || true

# Группа для xray-фильтрации (своя, не amnvpn).
if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
  gid=$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | sort -n | awk '$1>=500{g=$1} END{print (g?g+1:501)}')
  dscl . -create "/Groups/$GROUP"
  dscl . -create "/Groups/$GROUP" PrimaryGroupID "$gid"
  dscl . -create "/Groups/$GROUP" RealName "Tribe VPN Service Group"
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>${DEST}/${LABEL}</string></array>
    <key>KeepAlive</key><true/>
    <key>RunAtLoad</key><true/>
    <key>GroupName</key><string>${GROUP}</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"; chmod 644 "$PLIST"

launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST" || { echo "bootstrap failed"; exit 1; }
launchctl enable "system/${LABEL}" 2>/dev/null || true
# AVPN 5.1.109: bootstrap уже запускает демон (RunAtLoad). Прежний `kickstart -k` УБИВАЛ этот свежий
# экземпляр (SIGTERM через ~16 мс), launchd откладывал повторный запуск на 10 с (throttle), а
# приложение после установщика ждёт демона ~5 с → «Служба VPN установлена, но не запустилась» на
# обновлении службы (системный журнал 2026-11-10 17:21:52 UTC). kickstart без -k запускает службу,
# только если она не запущена. Затем ждём (с потолком 15 с), пока launchd держит службу в state =
# running с тем же pid секундой позже; приложение следом проверяет процесс (macServiceRunning).
launchctl kickstart "system/${LABEL}" 2>/dev/null || true
# pid и state берём у launchd (а не pgrep -x): если bootout вернулся раньше, чем старый процесс
# вышел, pgrep посчитал бы старый экземпляр новым. Секундой позже pid обязан быть тем же.
daemon_pid() {
  launchctl print "system/${LABEL}" 2>/dev/null \
    | awk '$1=="state" && s=="" {s=$3} $1=="pid" && p=="" {p=$3} END {if (s=="running" && p!="") print p}' || true
}
wait_daemon() {
  local deadline=$((SECONDS + 15)) pid
  while [ "$SECONDS" -lt "$deadline" ]; do
    pid="$(daemon_pid)"
    if [ -n "$pid" ]; then
      sleep 1
      [ "$(daemon_pid)" = "$pid" ] && { echo "Tribe-service запущен (pid $pid)."; return 0; }
    else
      sleep 0.5
    fi
  done
  return 1
}
if ! wait_daemon; then
  # Код выхода 0 намеренно: ненулевой `do shell script` приложение показывает как «нет прав
  # администратора»; честную ошибку «установлена, но не запустилась» оно выдаст само по pgrep.
  echo "ОШИБКА: Tribe-service не запустился за 15 с после bootstrap — состояние launchd ниже"
  launchctl print "system/${LABEL}" 2>&1 | head -25
  exit 0
fi
echo "Tribe-service установлен."
exit 0
