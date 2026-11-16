#!/bin/bash
# AVPN Scanner: build + run tests/uplink_kind_check.cpp - the physical uplink's kind under the Mac's own VPN
# (UplinkMonitor.h, pure helpers; QtCore only, no SystemConfiguration, no network).
#   --mutate : each rule in MUTATIONS is broken in a copy of UplinkMonitor.h; the check must fail for each.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d /tmp/tribe-uplink-kind.XXXXXX)"
trap 'rm -rf -- "${WORK:?}"' EXIT
ARCH_FLAGS=()
[ "$(uname -m)" = "arm64" ] && ARCH_FLAGS=(-include arm_acle.h)
build() { # $1 = directory searched first for UplinkMonitor.h, $2 = output
  clang++ -std=c++17 ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} -Wall -Wextra -I"$1" -I"$SE" -I"$QT/lib/QtCore.framework/Headers" \
    -F"$QT/lib" "$HERE/uplink_kind_check.cpp" -F"$QT/lib" -framework QtCore -Wl,-rpath,"$QT/lib" -o "$2"
}
if [ "${1:-}" = "--mutate" ]; then
  MUTATIONS=(
    "wifi-wins-over-wired@@        if (i.medium == UplinkIfaceMedium::Ethernet)\n            return i.name;\n    for (const UplinkRouteIface &i : ifaces)\n        if (i.medium == UplinkIfaceMedium::Wifi)@@        if (i.medium == UplinkIfaceMedium::Wifi)\n            return i.name;\n    for (const UplinkRouteIface &i : ifaces)\n        if (i.medium == UplinkIfaceMedium::Ethernet)"
    "unknown-medium-taken@@        if (i.medium == UplinkIfaceMedium::Wifi)\n            return i.name;\n    return QString();@@        if (i.medium == UplinkIfaceMedium::Wifi)\n            return i.name;\n    return ifaces.isEmpty() ? QString() : ifaces.first().name;"
    "kind-always-wifi@@QStringLiteral(\"ethernet\") : QStringLiteral(\"wifi\")@@QStringLiteral(\"wifi\") : QStringLiteral(\"wifi\")"
    "first-route-only@@    for (const UplinkRouteIface &i : ifaces)\n        if (i.medium == UplinkIfaceMedium::Ethernet)\n            return i.name;@@    if (!ifaces.isEmpty() && ifaces.first().medium == UplinkIfaceMedium::Ethernet)\n        return ifaces.first().name;"
  )
  caught=0; missed=0; broken=0
  for m in "${MUTATIONS[@]}"; do
    name="${m%%@@*}"; rest="${m#*@@}"; from="${rest%%@@*}"; to="${rest#*@@}"
    dir="$WORK/m-$name"; mkdir -p "$dir"
    if ! FROM="$from" TO="$to" python3 -I - "$SE/UplinkMonitor.h" "$dir/UplinkMonitor.h" <<'PY'
import os, sys
src = open(sys.argv[1], encoding="utf-8").read()
frm = os.environ["FROM"].replace("\\n", "\n"); to = os.environ["TO"].replace("\\n", "\n")
if src.count(frm) != 1:
    sys.stderr.write("pattern occurs %d times\n" % src.count(frm)); sys.exit(3)
open(sys.argv[2], "w", encoding="utf-8").write(src.replace(frm, to))
PY
    then printf '%-28s %s\n' "$name" "NOT APPLIED"; broken=$((broken + 1)); continue; fi
    if ! build "$dir" "$dir/check" 2>"$dir/build.log"; then printf '%-28s %s\n' "$name" "BUILD FAILED"; broken=$((broken + 1)); continue; fi
    if "$dir/check" >"$dir/run.log" 2>&1; then printf '%-28s %s\n' "$name" "MISSED"; missed=$((missed + 1))
    else printf '%-28s caught\n' "$name"; caught=$((caught + 1)); fi
  done
  echo ">>> mutations: ${#MUTATIONS[@]}, caught $caught, missed $missed, not applied/build $broken"
  [ "$missed" -eq 0 ] && [ "$broken" -eq 0 ]
  exit $?
fi
build "$SE" "$WORK/uplink_kind_check"
"$WORK/uplink_kind_check"
