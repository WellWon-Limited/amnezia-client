#!/usr/bin/env bash
# Phone 26.11 (Android, split routes): the data check failed fast with routes on - the service says CONNECTED on the
# handshake, Android makes the VPN network usable for this app's sockets only after installing its routes (longer with
# more routes), and a request sent before that was cut and judged "no data" (the node marked dead). Checked here:
#   U1  the app's default network is watched (NetworkState.kt VpnDefaultNetwork, registerDefaultNetworkCallback,
#       TRANSPORT_VPN) and reaches C++ (UplinkMonitor: onVpnDefault registered before watch(), vpnDefaultChanged);
#   U2  on Android the first whoami request waits for that report, bounded by whoamiUsableWaitMs (inside the attempt
#       owner's grace), and the check's window starts then;
#   U3  a try sent before the network was usable is "not yet" (whoamiNext's sentBeforeUsable), and the journal says so.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }

NS="$CLIENT/android/utils/src/main/kotlin/net/NetworkState.kt"
UM="$HERE/../UplinkMonitor.cpp"
FACADE="$HERE/../AvpnEngineQml.cpp"
WV="$HERE/../WhoamiVerdict.h"

# ---- U1 ----
ns="$(code "$NS" | tr -s ' \n' ' ')"
has "$ns" 'object VpnDefaultNetwork {' && has "$ns" 'cm.registerDefaultNetworkCallback(object : NetworkCallback() {' \
    && has "$ns" 'set(caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))' && has "$ns" 'external fun onVpnDefault(vpn: Boolean)' \
    || bad "U1: the app's default network must be watched for TRANSPORT_VPN"
um="$(body "$UM" 'void UplinkMonitor::startVpnDefault()')"
r=$(printf '%s\n' "$um" | grep -nF '{"onVpnDefault", "(Z)V", reinterpret_cast<void *>(onVpnDefault)},' | head -1 | cut -d: -f1)
w=$(printf '%s\n' "$um" | grep -nF '"watch", "(Landroid/content/Context;)I"' | head -1 | cut -d: -f1)
if [ -z "$r" ] || [ -z "$w" ] || [ "$r" -ge "$w" ]; then bad "U1: the native must be registered before the watch starts"; fi
has "$(body "$UM" 'void UplinkMonitor::postVpnDefault(bool vpn)')" 'emit m->vpnDefaultChanged(vpn);' || bad "U1: a change must be told"
has "$(body "$UM" 'void UplinkMonitor::start()')" 'startVpnDefault();' || bad "U1: the watch must start with the monitor"

# ---- U2 ----
sw="$(body "$FACADE" 'void AvpnEngineQml::startWhoamiVerification()')"
swf="$(printf '%s\n' "$sw" | tr -s ' \n' ' ')"
has "$swf" 'const int waitMs = avpn::whoamiUsableWaitMs(m_engine.checkGraceMs());' \
    && has "$swf" 'if ((uplink->vpnDefault() == 0 || uplink->vpnDefault() == -1) && waitMs > 0) {' \
    && has "$swf" 'connect(uplink, &avpn::UplinkMonitor::vpnDefaultChanged, hold, [go](bool vpn) { if (vpn) go("usable"); });' \
    && has "$swf" 'QTimer::singleShot(waitMs, hold, [go]() { go("bound"); });' \
    && has "$swf" 'm_verifyClock.start(); // the check' \
    || bad "U2: the first request must wait for the usable network, bounded inside the owner's grace"
has "$(body "$WV" 'inline int whoamiUsableWaitMs(int checkGraceMs)' | tr -s ' \n' ' ')" 'return std::max(0, checkGraceMs - 300);' \
    || bad "U2: the wait must end inside the owner's grace"

# ---- U3 ----
wa="$(body "$FACADE" 'void AvpnEngineQml::whoamiAttempt(int epoch)')"
waf="$(printf '%s\n' "$wa" | tr -s ' \n' ' ')"
has "$waf" 'sentBeforeUsable = avpn::UplinkMonitor::instance()->vpnDefault() == 0 || avpn::UplinkMonitor::instance()->vpnDefault() == -1;' \
    && has "$waf" 'avpn::whoamiNext(v, o, m_whoamiAnswered, m_verifyAttempts - 1, leftNow, sentBeforeUsable);' \
    && has "$waf" 'usable=%2' \
    || bad "U3: a try sent before the network was usable must be 'not yet', and the journal must say which"
has "$(code "$WV" | tr -s ' \n' ' ')" 'if (whoamiNotYet(o) || (sentBeforeUsable && v != WhoamiVerdict::Works)) {' \
    || bad "U3: whoamiNext must take a pre-usability answer as not yet"

[ "$fail" -eq 0 ] && echo "android check usable wiring: OK"
exit "$fail"
