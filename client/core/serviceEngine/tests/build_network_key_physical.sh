#!/bin/bash
# Round mac-B: build + run tests/network_key_physical_check.cpp - the network key names the physical network: our own
# tunnel of every transport and another app's VPN leave it as it is, a real network change moves it (UplinkMonitor.h
# uplinkPhysicalFacts -> path/NetworkKey.h; QtCore only, no SystemConfiguration, no network).
#   --mutate : each rule below is broken in a copy of UplinkMonitor.h - the check must fail for each. "rule-9fb35ab7b"
#              is the rule of build 141 / 9fb35ab7b (the facts from the path's status, interfaces and gateways).
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tribe-netkey-physical.XXXXXX")"
trap 'rm -rf -- "${WORK:?}"' EXIT
ARCH_FLAGS=()
[ "$(uname -m)" = "arm64" ] && ARCH_FLAGS=(-include arm_acle.h)
build() { # $1 = directory searched first for UplinkMonitor.h, $2 = output
  clang++ -std=c++17 ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} -Wall -Wextra -Wno-unused-variable -I"$1" -I"$SE" \
    -I"$QT/lib/QtCore.framework/Headers" -F"$QT/lib" "$HERE/network_key_physical_check.cpp" -F"$QT/lib" \
    -framework QtCore -Wl,-rpath,"$QT/lib" -o "$2"
}
if [ "${1:-}" = "--mutate" ]; then
  caught=0; missed=0; broken=0; total=0
  while IFS= read -r name; do
    total=$((total + 1))
    dir="$WORK/m-$name"; mkdir -p "$dir"
    if ! python3 -I - "$name" "$SE/UplinkMonitor.h" "$dir/UplinkMonitor.h" <<'PY'
import sys
name, src_path, out_path = sys.argv[1:4]
src = open(src_path, encoding="utf-8").read()
NEW_RULE = """    const QString in = f.kind + QLatin1Char('|') + routeIfnames.join(QLatin1Char(',')) + QLatin1Char('|')
                       + routers.join(QLatin1Char(','));
    f.hash = QCryptographicHash::hash(in.toUtf8(), QCryptographicHash::Sha256);
    if (!routers.isEmpty())
        f.gatewayHash = QString::fromLatin1(
            QCryptographicHash::hash(routers.join(QLatin1Char(',')).toUtf8(), QCryptographicHash::Sha256).toHex().left(16));
"""
OLD_RULE = """    // 9fb35ab7b (UplinkMonitor.mm pathFactsOf): the path's status, interfaces and gateways
    const QString routeIf = r.pathKind.isEmpty() ? uplinkPhysicalIfname(r.routeIfaces) : QString();
    const QString in = QString::number(r.pathStatus) + QLatin1Char('|') + r.pathInterfaces.join(QLatin1Char(','))
                       + QLatin1Char('|') + r.pathGateways.join(QLatin1Char(',')) + QLatin1Char('|') + routeIf;
    f.hash = QCryptographicHash::hash(in.toUtf8(), QCryptographicHash::Sha256);
    if (!r.pathGateways.isEmpty())
        f.gatewayHash = QString::fromLatin1(
            QCryptographicHash::hash(r.pathGateways.join(QLatin1Char(',')).toUtf8(), QCryptographicHash::Sha256).toHex().left(16));
"""
M = {
    "rule-9fb35ab7b": (NEW_RULE, OLD_RULE),
    "gateway-from-path": ("            QCryptographicHash::hash(routers.join(QLatin1Char(',')).toUtf8(), QCryptographicHash::Sha256).toHex().left(16));\n",
                          "            QCryptographicHash::hash(r.pathGateways.join(QLatin1Char(',')).toUtf8(), QCryptographicHash::Sha256).toHex().left(16));\n"),
    "status-in-facts": ("    const QString in = f.kind + QLatin1Char('|')", "    const QString in = QString::number(r.pathStatus) + f.kind + QLatin1Char('|')"),
    "path-ifaces-in-facts": ("    const QString in = f.kind + QLatin1Char('|')", "    const QString in = r.pathInterfaces.join(QLatin1Char(',')) + f.kind + QLatin1Char('|')"),
    "route-duplicates-kept": ("        if (!routeIfnames.contains(i.name))\n            routeIfnames << i.name;", "        routeIfnames << i.name;"),
    "virtual-router-kept": ("        if (!uplinkIfnameVirtual(sr.section(QLatin1Char('='), 0, 0)) && !routers.contains(sr))", "        if (!routers.contains(sr))"),
    "kind-from-path-only": ("    f.kind = !r.pathKind.isEmpty() ? r.pathKind : uplinkPhysicalKind(r.routeIfaces);", "    f.kind = r.pathKind;"),
    "no-router-in-facts": ("+ QLatin1Char('|')\n                       + routers.join(QLatin1Char(','));", ";"),
}
if name not in M:
    sys.stderr.write("unknown mutant\n"); sys.exit(3)
frm, to = M[name]
if src.count(frm) != 1:
    sys.stderr.write("pattern occurs %d times\n" % src.count(frm)); sys.exit(3)
open(out_path, "w", encoding="utf-8").write(src.replace(frm, to))
PY
    then printf '%-24s %s\n' "$name" "NOT APPLIED"; broken=$((broken + 1)); continue; fi
    if ! build "$dir" "$dir/check" 2>"$dir/build.log"; then printf '%-24s %s\n' "$name" "BUILD FAILED"; broken=$((broken + 1)); continue; fi
    if "$dir/check" >"$dir/run.log" 2>&1; then printf '%-24s %s\n' "$name" "MISSED"; missed=$((missed + 1))
    else printf '%-24s caught: %s\n' "$name" "$(grep -m1 FAIL "$dir/run.log")"; caught=$((caught + 1)); fi
  done <<'LIST'
rule-9fb35ab7b
gateway-from-path
status-in-facts
path-ifaces-in-facts
route-duplicates-kept
virtual-router-kept
kind-from-path-only
no-router-in-facts
LIST
  echo ">>> mutations: $total, caught $caught, missed $missed, not applied/build $broken"
  [ "$missed" -eq 0 ] && [ "$broken" -eq 0 ]
  exit $?
fi
build "$SE" "$WORK/network_key_physical_check"
"$WORK/network_key_physical_check"
