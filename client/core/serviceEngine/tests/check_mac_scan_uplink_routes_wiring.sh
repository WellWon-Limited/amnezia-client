#!/bin/bash
# AVPN (round mac-C, 25.11.2026, Scanner under AmneziaWG on macOS): the probe sockets of the service are pinned to the
# uplink (IP_BOUND_IF); under an AmneziaWG session (0/1 + 128/1 via its utun) a pinned socket had no route at all
# (`route get -ifscope en0` "not in table", connect ENETUNREACH before pf) and a scan found nothing in 0.3 s. The scan
# host owns the uplink's half routes for the scan's lifetime (service/server/tribe_scan.h). Each line below fails if a
# call site is reverted; the behaviour itself is tested by service/server/tests/build_tribe_scan.sh (uplinkRoutes),
# which this check runs (its real-engine stage skipped: TRIBE_SCAN_ENGINE=0).
#   R1  the production deps of macOS arm, disarm and clear the half routes; other platforms have none;
#   R2  scan_start arms them after the pf exemption and before the engine; needed-but-not-in-force refuses the scan
#       with the no-uplink reply and removes the exemption armed for it;
#   R3  every end of the scan removes them with the exemption (endActive); a move of the uplink removes them at once
#       (sample -> dropRoutes); the service start removes a previous instance's tagged ones;
#   R4  the route listener knows this process (its own half routes are no path fact); the routes are tagged and
#       scoped, and the pinned test is a UDP connect (no packet).
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
SCAN="$ROOT/service/server/tribe_scan.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
at() { printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1 | sed 's/^$/0/'; }

# ---- R1 ------------------------------------------------------------------------------------------------------
deps="$(body "$SCAN" 'TribeScanDeps tribeScanServiceDeps()')"
mac="$(printf '%s\n' "$deps" | awk '/^#ifdef Q_OS_MACOS/ { on = 1; next } on && /^#else/ { exit } on { print }')"
has "$mac" 'd.armRoutes = armUplinkRoutes;' || bad "R1: the macOS service does not arm the uplink's half routes"
has "$mac" 'd.disarmRoutes = disarmUplinkRoutes;' || bad "R1: the macOS service does not disarm them"
has "$mac" 'd.clearLeftoverRoutes = clearLeftoverUplinkRoutes;' || bad "R1: the macOS service does not clear leftovers"
other="$(printf '%s\n' "$deps" | awk '/^#else/ { on = 1; next } on && /^#endif/ { exit } on { print }')"
if has "$other" 'armRoutes'; then bad "R1: a platform other than macOS arms half routes"; fi

# ---- R2 ------------------------------------------------------------------------------------------------------
proc="$(body "$SCAN" 'QByteArray TribeScanHost::process(')"
fw=$(at "$proc" 'const int arm = m_deps.armFirewall ? m_deps.armFirewall(up.name) : 0;')
rt=$(at "$proc" 'm_deps.armRoutes(up)')
keep=$(at "$proc" 'm_active.routes = routes.added;')
eng=$(at "$proc" 'm_deps.message(message, tribeScanHostOptions(gen, &up, &awg, epoch))')
[ "${fw:-0}" -gt 0 ] && [ "${rt:-0}" -gt "${fw:-0}" ] && [ "${keep:-0}" -gt "${rt:-0}" ] && [ "${eng:-0}" -gt "${keep:-0}" ] \
  || bad "R2: scan_start does not arm the half routes after the pf exemption and before the engine"
has "$proc" 'if (routes.result < 0 && arm > 0 && m_deps.disarmFirewall)' \
  || bad "R2: a refused scan keeps the pf exemption armed for it"
has "$proc" 'return QByteArray(kErrNoUplink);' || bad "R2: needed-but-not-in-force does not refuse with the no-uplink reply"
has "$proc" 'm_deps.disarmRoutes(previous);' || bad "R2: a replacing start keeps the replaced scan's routes"

# ---- R3 ------------------------------------------------------------------------------------------------------
end="$(body "$SCAN" 'bool TribeScanHost::endActive(const QString &scanId, const char *why)')"
has "$end" 'routes = m_active.routes;' && has "$end" 'm_deps.disarmRoutes(routes);' \
  || bad "R3: the end of a scan does not remove its half routes"
smp="$(body "$SCAN" 'void TribeScanHost::sample(const TribeScanUplink &up, bool loss)')"
has "$smp" 'moved = m_gen.observe(fp, loss);' && has "$smp" 'dropRoutes("uplink_changed");' \
  || bad "R3: a move of the uplink does not remove the half routes"
ctor="$(body "$SCAN" 'TribeScanHost::TribeScanHost(TribeScanDeps deps, QObject *parent)')"
has "$ctor" 'm_deps.clearLeftoverRoutes();' || bad "R3: the service start does not remove a previous instance's routes"

# ---- R4 ------------------------------------------------------------------------------------------------------
has "$(body "$SCAN" 'void TribeScanHost::readRouteSocket()')" 'tribeScanRouteEvent(buf, qsizetype(n), index, qint64(::getpid()))' \
  || bad "R4: the route listener does not tell its own half routes from path facts"
msg="$(body "$SCAN" 'QByteArray tribeScanHalfRouteMessage(bool add, const TribeScanHalfRoute &r, int seq)')"
has "$msg" 'RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_IFSCOPE | RTF_PROTO3' || bad "R4: the half routes are not scoped and tagged"
pin="$(body "$SCAN" 'bool pinnedRouteExists(int ifindex, quint32 dst)')"
has "$pin" 'SOCK_DGRAM' && has "$pin" 'IP_BOUND_IF' || bad "R4: the pinned-route test is not a pinned UDP connect"

# ---- the behaviour (service host checks, without the real engine stage) ---------------------------------------
if [ "$fail" = "0" ]; then
  if ! TRIBE_SCAN_ENGINE=0 bash "$ROOT/service/server/tests/build_tribe_scan.sh"; then
    bad "service/server/tests/build_tribe_scan.sh failed"
  fi
fi
[ "$fail" = "0" ] && echo "check_mac_scan_uplink_routes_wiring: ok"
exit "$fail"
