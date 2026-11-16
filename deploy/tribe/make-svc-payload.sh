#!/bin/bash
# make-svc-payload.sh — assemble the macOS service payload for the app bundle: tribe-svc.tar.gz,
# the service version marker and the expected geo hashes. Step 4 of make-macos-dist.sh, kept apart
# so it can run on its own (no signing, no notarization): make-macos-dist.sh signs the binaries
# first and then calls this script; a dry run can call it on any build tree or a stub tree.
#
# Usage: make-svc-payload.sh <service dir> <resources dir>
#   <service dir>    deploy/build-macos-desktop/service/server: Tribe-service, amneziawg-go,
#                    tun2socks, Frameworks, geoip.dat, geosite.dat, tribe-xray-geo.sha256
#                    (all copied there by service/server/CMakeLists.txt)
#   <resources dir>  TribeVPN.app/Contents/Resources (or a temp dir for a dry run)
# Writes into <resources dir>: tribe-svc.tar.gz, tribe-svc.version, tribe-svc-geo.sha256,
#   tribe-svc-install.sh.
set -euo pipefail
SRV="${1:?service dir}"
OUT="${2:?resources dir}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
die() { echo "make-svc-payload: $*" >&2; exit 1; }

[ -x "$SRV/tun2socks" ] || die "нет $SRV/tun2socks — служба собрана без conan tun2socks"
for f in Tribe-service amneziawg-go; do [ -x "$SRV/$f" ] || die "нет $SRV/$f"; done
[ -d "$SRV/Frameworks" ] || die "нет $SRV/Frameworks (bundle-daemon-qt.sh)"
# AVPN (upstream nodes): the cut geo pair (recipes/tribe-xray-geo) lives next to Tribe-service; the
# core reads it from the executable directory. Exactly the pinned pair, or no payload.
GEO_SUMS="$SRV/tribe-xray-geo.sha256"
[ -f "$GEO_SUMS" ] || die "нет $GEO_SUMS — служба собрана без tribe-xray-geo"
[ "$(awk '{print $2}' "$GEO_SUMS" | sort | tr '\n' ' ')" = "geoip.dat geosite.dat " ] \
  || die "$GEO_SUMS должен перечислять ровно geoip.dat и geosite.dat"
( cd "$SRV" && shasum -a 256 -c "$GEO_SUMS" >/dev/null ) || die "geoip.dat/geosite.dat в $SRV не совпадают с $GEO_SUMS"
mkdir -p "$OUT"

# Payload tarball (signed daemon) -> Contents/Resources (opaque resource).
# Бинари уже подписаны Developer ID+runtime (make-macos-dist.sh шаг 3). Tarball codesign пломбирует
# как ресурс, нотаризация внутрь tar НЕ лезет → нет «unsigned nested code». Скрипт на установке
# распакует в /Library.
ST="$(mktemp -d)"; HT="$(mktemp -d)"
trap 'rm -rf "${ST:?}" "${HT:?}"' EXIT
cp -f  "$SRV/Tribe-service" "$ST/Tribe-service"
cp -f  "$SRV/amneziawg-go"  "$ST/amneziawg-go"
cp -f  "$SRV/tun2socks"     "$ST/tun2socks"
cp -f  "$SRV/geoip.dat"     "$ST/geoip.dat"
cp -f  "$SRV/geosite.dat"   "$ST/geosite.dat"
cp -f  "$GEO_SUMS"          "$ST/geo.sha256"
cp -aR "$SRV/Frameworks"    "$ST/Frameworks"
mkdir -p "$ST/pf"; cp -f "$REPO/deploy/data/macos/pf/tribe."*.conf "$REPO/deploy/data/macos/pf/tribe.conf" "$ST/pf/"
# AVPN: маркер версии демона = хэш бинарей (меняется ⟺ меняется демон). Кладём В tarball (установщик
# перенесёт в /Library/.../VERSION) И в ресурс app (приложение сверяет с установленным → авто-
# переустановка при апдейте, ноль терминала). См. MacServiceInstaller::macServiceOutdated.
# AVPN 2026-09-04: хэш считаем по бинарям БЕЗ подписи. Подпись (шаг 3) несёт timestamp-токен,
# из-за чего маркер менялся КАЖДУЮ сборку при неизменённом демоне, и каждое обновление приложения
# спрашивало пароль на переустановку службы (MAC-23/24). Снятая подпись даёт одинаковые байты
# и для Developer-ID-, и для ad-hoc-подписанного бинаря (проверено 2026-09-04).
cp -f "$SRV/Tribe-service" "$HT/Tribe-service"; cp -f "$SRV/amneziawg-go" "$HT/amneziawg-go"
cp -f "$SRV/tun2socks" "$HT/tun2socks"
codesign --remove-signature "$HT/Tribe-service"; codesign --remove-signature "$HT/amneziawg-go"
codesign --remove-signature "$HT/tun2socks"
# AVPN (волна-3, 2026-09-28): pf-правила — тоже часть службы (200.allowVPN и др.): правка только pf
# иначе не доезжала до уже установленных пользователей (маркер не менялся).
# 5.1.108: tun2socks входит в маркер — служба с ним ≠ служба без него (одна переустановка с паролем).
# Upstream nodes: the geo pair too — a service without it (or with other data) is outdated, and a
# data-only change reaches installed services.
DVER="$(cat "$HT/Tribe-service" "$HT/amneziawg-go" "$HT/tun2socks" "$ST"/pf/*.conf \
  "$ST/geoip.dat" "$ST/geosite.dat" | shasum -a 256 | cut -c1-16)"
echo "$DVER" > "$ST/VERSION"
echo "$DVER" > "$OUT/tribe-svc.version"
# Expected hashes of the installed pair for the app (MacServiceInstaller::macUpstreamGeoPresent).
cp -f "$GEO_SUMS" "$OUT/tribe-svc-geo.sha256"
echo "  daemon version: $DVER"
( cd "$ST" && COPYFILE_DISABLE=1 tar czf "$OUT/tribe-svc.tar.gz" \
    Tribe-service amneziawg-go tun2socks geoip.dat geosite.dat geo.sha256 Frameworks pf VERSION )
cp -f "$REPO/deploy/tribe/tribe-svc-install.sh" "$OUT/tribe-svc-install.sh"
chmod +x "$OUT/tribe-svc-install.sh"
echo "  tarball: $(ls -la "$OUT/tribe-svc.tar.gz" | awk '{print $5}') байт"
