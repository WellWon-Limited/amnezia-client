#!/bin/bash
# Round mac-B (test Mac 25.11.2026, three crash reports: SIGSEGV at 0x30 in QMetaObject::activate under
# QIODevice::channelReadyRead <- QAbstractSocketPrivate::canReadNotification on the VpnConnection thread). The
# protocol's callback (AmneziaWG: LocalSocketController::readData, the daemon socket's readyRead) reaches
# VpnConnection::setConnectionState -> onConnectionStateChanged, which waited for the service's replies - a nested
# event loop on that thread. The queued disconnectFromVpn / connectToVpn ran inside it and deleted the protocol, its
# controller and the socket that was still emitting. The lifetime rule (macOS): no event loop inside a protocol's
# callback, so the protocol is destroyed only by its own command event. Checked where it is wired - each line fails if
# a wait comes back:
#   L1  onConnectionStateChanged makes no wait of its own (waitForFinished, waitForSource, QEventLoop, exec,
#       processEvents) and reaches the service only through withInterfaceNow / logIpcResult;
#   L2  on macOS logIpcResult only watches the reply (QRemoteObjectPendingCallWatcher) and withInterfaceNow takes the
#       replica as it is through IpcClient::InterfaceIfReady (validity first; review M1: IpcClient::Interface() calls
#       waitForSource - a nested loop - and is never reached from a callback); other desktops keep upstream's waits;
#   L3  the protocol is released only in connectToVpn and disconnectFromVpn (and the Android restore path);
#   L4  the daemon socket's own handlers (readData, parseCommand, errorOccurred, disconnectInternal) wait for nothing;
#   D1  the service side of the same socket (six service crashes in the same round: SIGSEGV in QIODevice::readAll under
#       DaemonLocalServerConnection::readData): the macOS daemon's waits inside a client's command (the UAPI reply,
#       the tunnel's name) dispatch no events - a client that leaves meanwhile is deleted only after its command;
#   D2  (review M3) those blocking waits hold the daemon's only thread: the name <= 2 s and a UAPI command <= 1 s (measured
#       105-109 ms / <= 1 ms on the test Mac), each journalled ("[tunnel wait]").
# The lifetime itself is not host-testable: VpnConnection needs the app's IPC replica, repositories and protocols. It
# is proven on the test Mac (round mac-B: 30 rapid AmneziaWG connect/stop cycles and the leg loop, no crash).
# Run by the check sweep (every check_*.sh of this directory).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
VC="$CLIENT/vpnConnection.cpp"
LSC="$CLIENT/mozilla/localsocketcontroller.cpp"
WGM="$CLIENT/platforms/macos/daemon/wireguardutilsmacos.cpp"
DLSC="$CLIENT/daemon/daemonlocalserverconnection.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
WAITS='waitForFinished|waitForSource|QEventLoop|\.exec\(|processEvents|IpcClient::withInterface'

# ---- L1 ----
occ="$(body "$VC" 'void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)')"
[ -n "$occ" ] || bad "L1: VpnConnection::onConnectionStateChanged not found"
printf '%s\n' "$occ" | grep -nE "$WAITS" | sed 's/^/  /' | grep . && bad "L1: onConnectionStateChanged waits inside the protocol's callback"
has "$occ" 'withInterfaceNow([&](QSharedPointer<IpcInterfaceReplica> iface) {' || bad "L1: the service is not reached through withInterfaceNow"
[ "$(printf '%s\n' "$occ" | grep -c 'logIpcResult(this, iface->')" = 3 ] || bad "L1: the three replies are not logged through logIpcResult"
has "$(body "$VC" 'void VpnConnection::setConnectionState(Vpn::ConnectionState state) {')" 'onConnectionStateChanged(state);' \
    || bad "L1: setConnectionState no longer runs onConnectionStateChanged (the check would look at the wrong place)"

# ---- L2 ----
lr="$(code "$VC" | awk '/^void logIpcResult\(/ { on = 1 } on { print } on && /^}$/ { exit }')"
mac="$(printf '%s\n' "$lr" | awk '/^#ifdef Q_OS_MACOS/ { on = 1; next } /^#else/ { exit } on { print }')"
has "$mac" 'new QRemoteObjectPendingCallWatcher(reply, ctx);' || bad "L2: macOS does not watch the reply"
printf '%s\n' "$mac" | grep -qE "$WAITS" && bad "L2: macOS logIpcResult waits"
wn="$(code "$VC" | awk '/^void withInterfaceNow\(Func func\)/ { on = 1 } on { print } on && /^}$/ { exit }')"
wmac="$(printf '%s\n' "$wn" | awk '/^#ifdef Q_OS_MACOS/ { on = 1; next } /^#else/ { exit } on { print }')"
# review M1: IpcClient::Interface() itself waits (waitForSource) - the callbacks take the non-waiting getter only
has "$wmac" 'IpcClient::InterfaceIfReady();' || bad "L2: macOS does not take the replica through the non-waiting getter"
has "$wmac" 'IpcClient::Interface()' && bad "L2: macOS calls IpcClient::Interface(), which waits for the source (review M1)"
printf '%s\n' "$wmac" | grep -qE "$WAITS" && bad "L2: macOS withInterfaceNow waits for the service"
IPC="$CLIENT/core/utils/ipcClient.cpp"
ready="$(body "$IPC" 'QSharedPointer<IpcInterfaceReplica> IpcClient::InterfaceIfReady()')"
[ -n "$ready" ] || bad "L2: IpcClient::InterfaceIfReady() not found"
has "$ready" 'isReplicaValid()' || bad "L2: InterfaceIfReady does not check validity"
printf '%s\n' "$ready" | grep -qE "$WAITS|Interface\(\)" && bad "L2: InterfaceIfReady waits (or calls the waiting getter)"

# ---- L3 ----
for f in 'void VpnConnection::connectToVpn(' 'void VpnConnection::disconnectFromVpn()'; do
    b="$(body "$VC" "$f")"
    printf '%s\n' "$b" | grep -qE 'm_vpnProtocol\.reset\(|m_vpnProtocol = nullptr' || bad "L3: $f no longer releases the protocol"
done
n="$(code "$VC" | grep -cE 'm_vpnProtocol\.reset\(|m_vpnProtocol = nullptr')"
[ "$n" = 5 ] || bad "L3: the protocol is released at $n places (expected 5: connectToVpn x2, Android x2, disconnectFromVpn)"

# ---- L4 ----
for f in 'void LocalSocketController::readData() {' 'void LocalSocketController::parseCommand(const QByteArray& command) {' \
         'void LocalSocketController::disconnectInternal() {'; do
    b="$(body "$LSC" "$f")"
    [ -n "$b" ] || { bad "L4: $f not found"; continue; }
    printf '%s\n' "$b" | grep -qE "$WAITS" && bad "L4: $f waits"
done
b="$(code "$LSC" | awk '/^void LocalSocketController::errorOccurred\(/ { on = 1 } on { print } on && /^}$/ { exit }')"
[ -n "$b" ] && ! printf '%s\n' "$b" | grep -qE "$WAITS" || bad "L4: errorOccurred waits (or is gone)"

# ---- D1 ----
wg="$(code "$WGM")"
printf '%s\n' "$wg" | grep -nE 'processEvents|QEventLoop' | sed 's/^/  /' | grep . && bad "D1: the macOS daemon dispatches events inside a client's command"
uapi="$(body "$WGM" 'QString WireguardUtilsMacos::uapiCommand(const QString& command) {')"
has "$uapi" 'socket.waitForReadyRead(' && has "$uapi" 'uapiDeadline.hasExpired()' || bad "D1: the UAPI reply is not a blocking wait against a deadline"
name="$(body "$WGM" 'QString WireguardUtilsMacos::waitForTunnelName(const QString& filename) {')"
has "$name" 'm_tunnel.waitForFinished(100)' && has "$name" 'deadline.hasExpired()' || bad "D1: the tunnel name wait is not a blocking wait against a deadline"
printf '%s\n' "$(code "$DLSC")" | grep -qE 'processEvents|QEventLoop|waitForFinished\(\)' && bad "D1: the daemon's client connection waits"
# review M3: the blocking waits hold the daemon's only thread (IPC, the Scanner's host) - bounded by what was measured
has "$name" 'QDeadlineTimer deadline(WG_TUN_NAME_TIMEOUT);' || bad "D2: the tunnel name wait is not bounded by WG_TUN_NAME_TIMEOUT"
grep -qE '^constexpr const int WG_TUN_NAME_TIMEOUT = ([0-9]{1,3}|1[0-9]{3}|2000);' "$WGM" || bad "D2: the tunnel name wait may hold the daemon over 2 s"
grep -qE '^constexpr const int WG_UAPI_TIMEOUT = ([0-9]{1,3}|1000);' "$WGM" || bad "D2: a UAPI command may hold the daemon over 1 s"
[ "$(grep -c '\[tunnel wait\]' "$WGM")" -ge 3 ] || bad "D2: the waits' lengths are not journalled"

[ "$fail" = 0 ] && echo "check_vpn_connection_callback_loop: OK"
exit "$fail"
