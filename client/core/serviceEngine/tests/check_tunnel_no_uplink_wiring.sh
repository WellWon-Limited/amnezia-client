#!/bin/bash
# Device round of 142 (B2, iPhone Air): the VPN connected, airplane mode on - the screen kept «Connected» with the amber
# «Подключено, трафик не проходит». The tunnel is kept through a network loss and the checks pause; the Connect screen
# now says «Нет сети — VPN продолжит, когда сеть вернётся» while the tunnel is up and the device is KNOWN to have no
# network. The fact is pure and tested by behaviour (build_uplink_known_down.sh: physicalUplinkKnownDown). What is
# checked here is where it is wired - each line fails if its call site is reverted:
#   N1  the engine property: tunnelUpNoUplink = tunnel Connected && the cached fact (NOTIFY changed);
#   N2  noteUplinkFact reads the fact from the facts the engine already has: the uplink monitor (authoritative / up)
#       and, on iOS, the app's own path monitor (a path seen; a physical interface on it) - no timer, no probe;
#   N3  it is read on every network notice (scanNotifyNetwork) and first thing on every tick (onTick);
#   N4  a move of the fact voids the live verdict of the old network (liveDead, the streak, bars, RTT) and the live
#       proof (review R50 2: m_liveProof = Voided - neither a live pass nor the connect's "works" shows ONLINE until a
#       live probe passes again) and tells QML (liveQualityChanged, changed); the connect's verdict (m_pathCheck) is kept;
#   N5  the Connect caption: in the connected branch, before «трафик не проходит», the neutral colour; ONLINE waits
#       (Connect card and the server list);
#   N6  the string has finished en and es translations.
# Run by the check sweep (every check_*.sh of this directory).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$HERE/.."
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }        # a file without full-line comments
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

FACADE="$ENGINE/AvpnEngineQml.cpp"
FACADE_H="$ENGINE/AvpnEngineQml.h"
CONNECT="$CLIENT/ui/qml/Tribe/Pages/PageConnectTribe.qml"
SERVERS="$CLIENT/ui/qml/Tribe/Pages/PageServersTribe.qml"
TS_EN="$CLIENT/translations/tribe/tribe_en.ts"
TS_ES="$CLIENT/translations/tribe/tribe_es.ts"
SRC='Нет сети — VPN продолжит, когда сеть вернётся'

# ---- N1 ----
h="$(code "$FACADE_H")"
has "$h" 'Q_PROPERTY(bool tunnelUpNoUplink READ tunnelUpNoUplink NOTIFY changed)' || bad "N1: no Q_PROPERTY tunnelUpNoUplink (NOTIFY changed)"
has "$h" 'bool tunnelUpNoUplink() const { return m_lastTunnelState == Vpn::Connected && m_uplinkKnownDown; }' \
    || bad "N1: tunnelUpNoUplink must be 'tunnel Connected && m_uplinkKnownDown'"

# ---- N2 / N4 ----
note="$(body "$FACADE" 'void AvpnEngineQml::noteUplinkFact()')"
[ -n "$note" ] || bad "N2: AvpnEngineQml::noteUplinkFact() not found"
has "$note" 'avpn::physicalUplinkKnownDown(uplink->authoritative(), uplink->up(), appPath)' \
    || bad "N2: the fact must be physicalUplinkKnownDown of the uplink monitor and the app path"
has "$note" 'IosScanHost::appGeneration(seen)' && has "$note" 'IosScanHost::appBindInterfaceIndex() > 0' \
    || bad "N2: iOS must read the app's own path monitor (a path seen, a physical interface on it)"
printf '%s\n' "$note" | grep -B3 'IosScanHost::appGeneration' | grep -q '#ifdef Q_OS_IOS' || bad "N2: the app path read must be iOS only"
printf '%s\n' "$note" | grep -qE 'QTimer|singleShot|measure|->start\(|probe' && bad "N2: noteUplinkFact must not start a timer or a probe"
has "$note" 'if (down == m_uplinkKnownDown)' || bad "N4: only a move of the fact acts"
for v in 'm_liveDead = false;' 'm_liveFailStreak = 0;' 'm_liveBars = 0;' 'm_liveRtt = -1;' 'm_liveReachable = false;' 'm_signal.reset();' \
         'emit liveQualityChanged();' 'emit changed();'; do
    has "$note" "$v" || bad "N4: a move must void the live verdict and tell QML ($v)"
done
has "$note" 'm_liveProof = avpn::liveProofAfterUplinkMove(m_liveProof);' \
    || bad "N4: a move must void the live proof (an old pass or the connect's works showed ONLINE with no data - review R50 2)"
has "$note" 'm_pathCheck' && bad "N4: the connect's verdict (m_pathCheck) is not the network's verdict - keep it"

# ---- N3 ----
has "$(body "$FACADE" 'void AvpnEngineQml::scanNotifyNetwork()')" 'noteUplinkFact();' || bad "N3: scanNotifyNetwork must read the fact"
tick="$(body "$FACADE" 'void AvpnEngineQml::onTick()')"
[ "$(printf '%s\n' "$tick" | sed -n '3p' | sed 's#//.*##' | tr -d ' ')" = "noteUplinkFact();" ] \
    || bad "N3: onTick must read the fact first (iOS: the app path monitor has no event without the Scanner's hook)"

# ---- N5 ----
c="$(code "$CONNECT")"
has "$c" 'readonly property bool noNetHeld: isOn && hasEngine && TribeEngine.tunnelUpNoUplink === true' \
    || bad "N5: PageConnectTribe needs noNetHeld from TribeEngine.tunnelUpNoUplink"
printf '%s\n' "$c" | grep -A1 -F ": root.isOn ? (root.noNetHeld ? qsTr(\"${SRC}\")" | grep -qF ': root.liveDeadNow ? qsTr("Подключено, трафик не проходит")' \
    || bad "N5: the connected caption must say «${SRC}» before «трафик не проходит»"
printf '%s\n' "$c" | grep -A1 -F 'color: (root.whitelistModeNow || root.nextPathNow || (root.isOn && root.liveDeadNow && !root.noNetHeld))' \
    | grep -qF '? Theme.color.warning : root.slate400' || bad "N5: no amber colour while there is no network"
has "$c" 'readonly property bool dataFlowingNow: isOn && !noNetHeld && hasEngine && TribeEngine.dataFlowing === true' \
    || bad "N5: the Connect card's ONLINE must wait while there is no network"
has "$(code "$SERVERS")" 'TribeEngine.dataFlowing === true && TribeEngine.tunnelUpNoUplink !== true' \
    || bad "N5: the server list's ONLINE must wait while there is no network"

# ---- N6 ----
for ts in "$TS_EN" "$TS_ES"; do
    grep -A1 -F "<source>${SRC}</source>" "$ts" | grep -qE '<translation>[^<]+</translation>' \
        || bad "N6: $(basename "$ts") has no finished translation of «${SRC}»"
done

[ "$fail" -eq 0 ] && echo "check_tunnel_no_uplink_wiring: OK"
exit "$fail"
