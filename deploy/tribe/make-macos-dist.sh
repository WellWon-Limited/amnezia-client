#!/bin/bash
# make-macos-dist.sh — собрать раздаваемый macOS-дистрибутив Tribe VPN (демон-модель, ноль терминала).
# Предполагает, что app+демон УЖЕ собраны (cmake) в deploy/build-macos-desktop.
# Делает: Qt в app+демон → подпись Developer ID+runtime → daemon.pkg → вшивает pkg в app →
#         подпись app (entitlements) → [нотаризация] → dmg → [нотаризация dmg].
#
# Конечный пользователь: открыл dmg → перетащил в Applications → запустил → Connect →
# ОДИН системный промпт пароля (ставит демон) → подключено. Терминал НЕ нужен.
#
# Использование:
#   make-macos-dist.sh sign           # только подписать app с вшитым pkg (без dmg/нотаризации) — для теста
#   make-macos-dist.sh dmg            # + собрать dmg, без нотаризации
#   make-macos-dist.sh notarize       # + нотаризовать app и dmg (нужен keychain-профиль AC_NOTARY)
set -euo pipefail
STAGE="${1:-sign}"

REPO="$HOME/amnezia-client"
BUILD="$REPO/deploy/build-macos-desktop"
APP="$BUILD/client/TribeVPN.app"
SRV="$BUILD/service/server"
QTBIN="$HOME/Qt/6.10.2/macos/bin"
DEVID="Developer ID Application: WellWon Limited (Q7DVH5MCWF)"
ENTS="$REPO/deploy/tribe/tribe-app.entitlements"
DIST="$HOME/avpn-build/dist"; DMG="$DIST/Tribe VPN.dmg"
SIGN=(codesign --force --options runtime --timestamp --sign "$DEVID")

[ -d "$APP" ] || { echo "нет $APP — сначала cmake build"; exit 1; }

echo "=== 0. Чистка хвостов прошлых сборок (stale pkg/Helpers/tarball) ==="
rm -f  "$APP/Contents/Resources/Tribe-service.pkg"
rm -f  "$APP/Contents/Resources/tribe-svc.tar.gz" "$APP/Contents/Resources/tribe-svc-install.sh"
rm -rf "$APP/Contents/Helpers"

echo "=== 1. Qt в app (macdeployqt) ==="
"$QTBIN/macdeployqt" "$APP" -qmldir="$REPO/client/ui/qml" >/dev/null 2>&1 || true

echo "=== 2. Qt в демон (самодостаточность) ==="
bash "$REPO/deploy/tribe/bundle-daemon-qt.sh" "$SRV" >/dev/null

echo "=== 3. Подпись демона: Developer ID + hardened runtime + timestamp (inside-out) ==="
find "$SRV/Frameworks" -type f \( -name '*.dylib' -o -path '*/Versions/A/Qt*' \) -print0 \
  | while IFS= read -r -d '' f; do "${SIGN[@]}" "$f"; done
"${SIGN[@]}" "$SRV/amneziawg-go"
"${SIGN[@]}" "$SRV/Tribe-service"

echo "=== 4. Payload-tarball (подписанный демон) → Contents/Resources (непрозрачный ресурс) ==="
# Бинари уже подписаны Developer ID+runtime (шаг 3). Tarball codesign пломбирует как ресурс,
# нотаризация внутрь tar НЕ лезет → нет «unsigned nested code». Скрипт на установке распакует в /Library.
ST="$(mktemp -d)"
cp -f  "$SRV/Tribe-service" "$ST/Tribe-service"
cp -f  "$SRV/amneziawg-go"  "$ST/amneziawg-go"
cp -aR "$SRV/Frameworks"    "$ST/Frameworks"
mkdir -p "$ST/pf"; cp -f "$REPO/deploy/data/macos/pf/tribe."*.conf "$REPO/deploy/data/macos/pf/tribe.conf" "$ST/pf/"
( cd "$ST" && COPYFILE_DISABLE=1 tar czf "$APP/Contents/Resources/tribe-svc.tar.gz" Tribe-service amneziawg-go Frameworks pf )
rm -rf "$ST"
cp -f "$REPO/deploy/tribe/tribe-svc-install.sh" "$APP/Contents/Resources/tribe-svc-install.sh"
chmod +x "$APP/Contents/Resources/tribe-svc-install.sh"
echo "  tarball: $(ls -la "$APP/Contents/Resources/tribe-svc.tar.gz" | awk '{print $5}') байт"

echo "=== 5/6. Подпись app: фреймворки/плагины inside-out + app c entitlements ==="
find "$APP/Contents/Frameworks" -type f \( -name '*.dylib' -o -path '*/Versions/*/Qt*' \) -print0 \
  | while IFS= read -r -d '' f; do "${SIGN[@]}" "$f" 2>/dev/null; done
find "$APP/Contents/PlugIns" -type f -name '*.dylib' -print0 \
  | while IFS= read -r -d '' f; do "${SIGN[@]}" "$f" 2>/dev/null; done
codesign --force --options runtime --timestamp --entitlements "$ENTS" --sign "$DEVID" "$APP"
codesign --verify --deep --strict --verbose=1 "$APP" && echo "  ✅ подпись app валидна"

[ "$STAGE" = sign ] && { echo "=== ГОТОВО (sign) — app: $APP ==="; exit 0; }

if [ "$STAGE" = notarize ]; then
  echo "=== 7. Нотаризация app ==="
  ZIP=/tmp/TribeVPN-notarize.zip; rm -f "$ZIP"
  ditto -c -k --keepParent "$APP" "$ZIP"
  xcrun notarytool submit "$ZIP" --keychain-profile AC_NOTARY --wait
  xcrun stapler staple "$APP"
fi

echo "=== 8. dmg (из ЧИСТОГО staging — НЕ create-dmg: он путал наш app со stale в dist/) ==="
mkdir -p "$DIST"; rm -rf "$DMG" "$DIST/Tribe VPN.app"
DMGROOT="$(mktemp -d)/dmg"; mkdir -p "$DMGROOT"
cp -R "$APP" "$DMGROOT/Tribe VPN.app"          # переименовываем копию для красивого drag-install
ln -s /Applications "$DMGROOT/Applications"
hdiutil create -volname "Tribe VPN" -srcfolder "$DMGROOT" -format UDZO -ov "$DMG"
rm -rf "$(dirname "$DMGROOT")"
codesign --force --timestamp --sign "$DEVID" "$DMG"

if [ "$STAGE" = notarize ]; then
  echo "=== 9. Нотаризация dmg ==="
  # КРИТИЧНО: смонтированный dmg ВЕШАЕТ pre-submission checks notarytool намертво
  # (висит на «initiating connection», submission ID не приходит). Перед сабмитом —
  # отмонтировать ВСЕ инстансы образа (Finder/прошлый прогон могли смонтировать).
  for dev in $(hdiutil info | grep -A30 "Tribe VPN.dmg" | grep -oE "/dev/disk[0-9]+" | sort -u); do
    hdiutil detach "$dev" -force 2>/dev/null || true
  done
  xcrun notarytool submit "$DMG" --keychain-profile AC_NOTARY --wait
  xcrun stapler staple "$DMG"
  codesign -v -R=notarized --verbose=1 "$DMG" && echo "  ✅ dmg notarized (codesign -R=notarized exit0)"
  spctl -a -t open --context context:primary-signature -vv "$DMG" || true
fi
echo "=== ГОТОВО: $DMG ==="
ls -la "$DMG"
