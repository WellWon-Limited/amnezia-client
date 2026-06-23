#!/bin/bash
# tribe-svc-install.sh — ВШИВАЕТСЯ в TribeVPN.app/Contents/Resources/. Запускается приложением
# через osascript «with administrator privileges» (один системный промпт пароля, без терминала).
# Распаковывает payload-tarball (аргумент $1: tribe-svc.tar.gz с Tribe-service + amneziawg-go +
# Frameworks(вшитый Qt) + pf, бинари подписаны Developer ID+runtime) в
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
[ -d "$SRC/Frameworks" ]    || { echo "нет Frameworks в tarball"; exit 1; }

mkdir -p "$DEST"
cp -f  "$SRC/Tribe-service" "$DEST/Tribe-service"
cp -f  "$SRC/amneziawg-go"  "$DEST/amneziawg-go"
rm -rf "$DEST/Frameworks"; cp -aR "$SRC/Frameworks" "$DEST/Frameworks"
mkdir -p "$DEST/pf"; cp -f "$SRC/pf/"*.conf "$DEST/pf/" 2>/dev/null || true
chown -R root:wheel "$DEST"
chmod 755 "$DEST" "$DEST/Tribe-service" "$DEST/amneziawg-go"
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
launchctl kickstart -k "system/${LABEL}" 2>/dev/null || true
echo "Tribe-service установлен."
exit 0
