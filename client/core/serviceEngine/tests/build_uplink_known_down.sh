#!/bin/bash
# Device round of 142 (B2): build + run tests/uplink_known_down_check.cpp - the fact behind the Connect caption
# «Нет сети — VPN продолжит, когда сеть вернётся» (UplinkMonitor.h physicalUplinkKnownDown; QtCore only, no network).
#   --mutate : each rule in MUTATIONS is broken in a copy of UplinkMonitor.h; the check must fail for each.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d /tmp/tribe-uplink-known-down.XXXXXX)"
trap 'rm -rf -- "${WORK:?}"' EXIT
ARCH_FLAGS=()
[ "$(uname -m)" = "arm64" ] && ARCH_FLAGS=(-include arm_acle.h)
build() { # $1 = directory searched first for UplinkMonitor.h, $2 = output
  clang++ -std=c++17 ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} -Wall -Wextra -I"$1" -I"$SE" -I"$QT/lib/QtCore.framework/Headers" \
    -F"$QT/lib" "$HERE/uplink_known_down_check.cpp" -F"$QT/lib" -framework QtCore -Wl,-rpath,"$QT/lib" -o "$2"
}
if [ "${1:-}" = "--mutate" ]; then
  MUTATIONS=(
    "monitor-not-first@@    if (authoritative)\n        return !monitorUp;\n    if (appPath != AppPathFact::None)@@    if (appPath != AppPathFact::None)"
    "app-path-ignored@@    if (appPath != AppPathFact::None)\n        return appPath == AppPathFact::NoPhysical;\n@@"
    "app-path-inverted@@        return appPath == AppPathFact::NoPhysical;@@        return appPath == AppPathFact::Physical;"
    "unknown-is-down@@        return appPath == AppPathFact::NoPhysical;\n    return !monitorUp;@@        return appPath == AppPathFact::NoPhysical;\n    return true;"
    "fallback-never-down@@        return appPath == AppPathFact::NoPhysical;\n    return !monitorUp;@@        return appPath == AppPathFact::NoPhysical;\n    return false;"
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
build "$SE" "$WORK/uplink_known_down_check"
"$WORK/uplink_known_down_check"
