#!/bin/bash
# AVPN (review round 20 R1, Android): the uplink fact is about the PHYSICAL network and comes from a source that
# does not see our own tunnel. The rules are pure and tested by behaviour: failedAttemptIntent
# (facade_policy_check r20PhysicalLossDuringConnect), physicalSourceStart (uplink_kind_check), PhysicalUplink
# (client/android/utils src/test PhysicalUplinkTest). What is checked here is where they are wired - each line
# fails if its call site is reverted:
#   U1  no time-coincidence classification of an uplink loss remains (the D2 heuristic of f69c7b3fd);
#   U2  both failed-attempt decisions read the monitor (uplinkUp()) as it is;
#   U3  Android's UplinkMonitor is authoritative from the physical set: it registers the Kotlin event, starts the
#       watch, takes the initial value through physicalSourceStart and applies events on its own thread (queued);
#       QNetworkInformation remains only as the fallback after it;
#   U4  the Kotlin source: the NOT_VPN + INTERNET request, onLost leaves the set, every set change goes through
#       PhysicalUplink and a move is told to C++;
#   U5  the network-change signals that still read QNetworkInformation (the default network: our own VPN on
#       Android) keep their own-tunnel rule;
#   U6  (android2 P5b) the path engine's network observation carries the authoritative uplink (withPhysicalUplink,
#       tested in facade_policy_check p5bOfflineObservation and path_integration_check), the uplink event reaches the
#       engine (scanNotifyNetwork) before the facade's uplink handler, and that handler takes the attempt's result.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$HERE/.."
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }        # a file without full-line comments
count() { code "$1" | grep -cF -- "$2" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

FACADE="$ENGINE/AvpnEngineQml.cpp"
FACADE_H="$ENGINE/AvpnEngineQml.h"
SNAP="$ENGINE/DebugSnapshot.h"
MON="$ENGINE/UplinkMonitor.cpp"
MON_H="$ENGINE/UplinkMonitor.h"
KT="$CLIENT/android/utils/src/main/kotlin/net/NetworkState.kt"

# ---- U1 ----
for f in "$FACADE" "$FACADE_H" "$SNAP"; do
    for token in 'uplinkLossIsOwnTunnel' 'uplinkUpForDecision' 'm_uplinkLossOwnTunnel' 'kMonitorSeesOwnTunnel'; do
        [ "$(count "$f" "$token")" = "0" ] || bad "U1: $(basename "$f") still classifies an uplink loss by time ($token)"
    done
done
[ "$(count "$FACADE" '" own_tunnel"')" = "0" ] || bad "U1: the facade still writes 'uplink down own_tunnel'"

# ---- U2 ----
sync="$(body "$FACADE" 'bool AvpnEngineQml::syncAttempt()')"
[ "$(printf '%s\n' "$sync" | grep -cF 'uplinkUp(), m_engine.attemptAfterLiveLoss())')" = "2" ] \
    || bad "U2: both failed-attempt decisions must read uplinkUp() as it is"
has "$sync" 'm_waitUplink = true;' && has "$sync" 'intent_kept why=attempt_failed_no_uplink' \
    || bad "U2: the Wait branch must keep the request and wait for the uplink"
has "$(body "$FACADE" 'bool AvpnEngineQml::uplinkUp()')" 'return avpn::UplinkMonitor::instance()->up();' \
    || bad "U2: uplinkUp() must be the monitor's answer"

# ---- U3 ----
start="$(body "$MON" 'void UplinkMonitor::start()')"
first="$(printf '%s\n' "$start" | grep -nF 'startPhysical()' | head -1 | cut -d: -f1)"
fallback="$(printf '%s\n' "$start" | grep -nF 'QNetworkInformation::loadDefaultBackend()' | head -1 | cut -d: -f1)"
[ -n "$first" ] && [ -n "$fallback" ] && [ "$first" -lt "$fallback" ] \
    || bad "U3: Android must start the physical source before the QNetworkInformation fallback"
phys="$(body "$MON" 'bool UplinkMonitor::startPhysical()')"
has "$phys" '{"onPhysicalUplink", "(Z)V", reinterpret_cast<void *>(onPhysicalUplink)},' \
    || bad "U3: the Kotlin event onPhysicalUplink is not registered"
has "$phys" '"watchUplink",' || bad "U3: the watch is not started"
has "$phys" 'physicalSourceStart(int(initial))' || bad "U3: the initial value does not go through physicalSourceStart"
has "$phys" 'm_authoritative = true;' || bad "U3: the physical source is not authoritative"
has "$(body "$MON" 'void UplinkMonitor::postPhysicalUp(bool up)')" 'Qt::QueuedConnection' \
    || bad "U3: an event must be applied on the monitor's thread (queued)"
has "$(code "$MON_H")" 'bool physicalUp() const { return m_authoritative ? m_up : m_physicalUp; }' \
    || bad "U3: physicalUp() must follow the authoritative source"
has "$(code "$MON")" 'kPhysicalSourceClass[] = "org/amnezia/vpn/util/net/ScanAppNetwork";' \
    || bad "U3: the source class moved"

# ---- U4 ----
kt="$(code "$KT")"
has "$kt" '.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)' || bad "U4: the source is not the NOT_VPN set"
has "$kt" 'external fun onPhysicalUplink(up: Boolean)' || bad "U4: no Kotlin event to C++"
has "$kt" 'fun watchUplink(context: Context): Int {' || bad "U4: no watch start for C++"
has "$kt" 'if (networks.remove(network) != null) observeLocked()' || bad "U4: onLost must leave the set"
has "$kt" 'if (uplink.onSet(networks.size) && uplinkWatched) {' || bad "U4: a set change must go through PhysicalUplink"
has "$kt" 'runCatching { onPhysicalUplink(up) }' || bad "U4: a move must be told to C++"

# ---- U5 ----
[ "$(count "$FACADE" 'reliabilityEvent(QStringLiteral("network_change_ignored own_tunnel"));')" = "2" ] \
    || bad "U5: the QNetworkInformation change signals must keep their own-tunnel rule"

# ---- U6 ----
obs="$(body "$FACADE" 'avpn::path::NetworkObservation AvpnEngineQml::currentNetworkObservation() const')"
has "$obs" 'return avpn::path::withPhysicalUplink(o, uplink->authoritative(), uplink->up());' \
    || bad "U6: the network observation must carry the authoritative uplink"
notify="$(code "$FACADE" | grep -nF '&avpn::UplinkMonitor::changed, this, [this](bool) { scanNotifyNetwork(); });' | head -1 | cut -d: -f1)"
handler="$(code "$FACADE" | grep -nF '&avpn::UplinkMonitor::changed, this, [this](bool up) {' | head -1 | cut -d: -f1)"
[ -n "$notify" ] && [ -n "$handler" ] && [ "$notify" -lt "$handler" ] \
    || bad "U6: the uplink event must reach the engine before the facade's uplink handler"
code "$FACADE" | sed -n "${handler:-1},$(( ${handler:-1} + 6 ))p" | grep -qF 'if (avpn::UplinkMonitor::instance()->authoritative())' \
    && code "$FACADE" | sed -n "${handler:-1},$(( ${handler:-1} + 6 ))p" | grep -qF '            syncAttempt();' \
    || bad "U6: the uplink handler must take the attempt's result while the uplink is as it says"

[ "$fail" = "0" ] && echo "check_android_uplink_wiring: OK"
exit "$fail"
