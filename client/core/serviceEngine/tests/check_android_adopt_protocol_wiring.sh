#!/usr/bin/env bash
# Round 58 review, finding 3 (Android): VpnConnection drops its protocol at the end of every disconnect and gets it back only
# from the first status snapshot of the process (AndroidController: isWaitingStatus -> initConnectionState ->
# restoreConnection). A session the service started by itself later in the same process (the notification's «Connect»
# after a Stop, the tile) and the app adopted or took over from a STATUS snapshot had no protocol: the engine's stop went
# to disconnectFromVpn, which says "Disconnected" without a protocol and sends nothing - the screen said off, the system
# VPN stayed on, and the service's live states reached nobody. The fix is the restore, not a second stop path:
#   P1  VpnConnection::ensureAndroidProtocol restores the protocol (restoreConnection, as the first snapshot does) only
#       when it is missing, and is callable queued (Q_INVOKABLE);
#   P2  the STATUS adoption and the take-over queue it before anything of theirs that could stop the session;
#   P3  disconnectFromVpn keeps its upstream shape: no second stop path inside its no-protocol branch;
#   P4  (phone 26.11, T1) a live CONNECTED edge without a protocol - the notification's «Подключиться» after a Stop - gets
#       the protocol back in ONE place (VpnConnection's own listener) and goes on as a native Connected, which the facade
#       decides by the attempt owner first (onTunnelConnected) and then the one Adopt rule (tryAdoptObservedTunnel);
#       the stop listener no longer restores on its own.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }

VC="$CLIENT/vpnConnection.cpp"
VH="$CLIENT/vpnConnection.h"
FACADE="$HERE/../AvpnEngineQml.cpp"

# ---- P1 ----
has "$(code "$VH")" 'Q_INVOKABLE void ensureAndroidProtocol();' || bad "P1: ensureAndroidProtocol must be callable queued"
en="$(body "$VC" 'void VpnConnection::ensureAndroidProtocol()')"
has "$(printf '%s\n' "$en" | tr -s ' \n' ' ')" '{ if (m_vpnProtocol.isNull()) restoreConnection(); }' \
    || bad "P1: the protocol is restored only when it is missing, the way the first snapshot does"

# ---- P2 ----
status="$(code "$FACADE" | awk '/&AndroidController::status, this,/{f=1} f{print} f&&/^            Qt::QueuedConnection\);$/{exit}')"
ad="$(printf '%s\n' "$status" | awk '/} else if \(action == AndroidStatusAction::Adopt\) \{/ { on = 1 } on { print } on && /adoptTunnelConnected/ { exit }')"
has "$ad" 'QMetaObject::invokeMethod(m_conn, "ensureAndroidProtocol", Qt::QueuedConnection);' \
    || bad "P2: the STATUS adoption must give the connection its protocol back"
tk="$(printf '%s\n' "$status" | awk '/} else if \(rebuild == AndroidStatusAction::TakeOver\) \{/ { on = 1 } on { print } on && /guardedStop\("takeover_rebuild"\);/ { exit }')"
e=$(printf '%s\n' "$tk" | grep -nF 'QMetaObject::invokeMethod(m_conn, "ensureAndroidProtocol", Qt::QueuedConnection);' | head -1 | cut -d: -f1)
g=$(printf '%s\n' "$tk" | grep -nF 'guardedStop("takeover_rebuild");' | head -1 | cut -d: -f1)
if [ -z "$e" ] || [ -z "$g" ] || [ "$e" -ge "$g" ]; then bad "P2: the take-over must restore the protocol before its stop"; fi

# ---- P3 ----
dis="$(body "$VC" 'void VpnConnection::disconnectFromVpn()')"
nb="$(printf '%s\n' "$dis" | awk '/if \(m_vpnProtocol.isNull\(\)\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
printf '%s\n' "$nb" | grep -qE 'AndroidController::instance\(\)->stop\(\)|callActivityMethod' \
    && bad "P3: a second stop path inside the no-protocol branch"

# ---- P4 ----
ctor="$(body "$VC" 'VpnConnection::VpnConnection(')"
ctf="$(printf '%s\n' "$ctor" | tr -s ' \n' ' ')"
has "$ctf" 'connect(AndroidController::instance(), &AndroidController::vpnStateChanged, this, [this](AndroidController::ConnectionState state) { if (state != AndroidController::ConnectionState::CONNECTED || !m_vpnProtocol.isNull()) return; restoreConnection(); if (m_vpnProtocol) m_vpnProtocol->setConnectionState(Vpn::ConnectionState::Connected); });' \
    || bad "P4: a live CONNECTED without a protocol must get it back and go on as a native Connected"
[ "$(code "$VC" | grep -c 'restoreConnection();')" -eq 2 ] \
    || bad "P4: the protocol is restored in exactly two places (the live edge's listener and ensureAndroidProtocol)"
has "$(body "$FACADE" 'void AvpnEngineQml::applyNativeState(')" 'if (!m_engine.onTunnelConnected() && !m_engine.isVerifying()) tryAdoptObservedTunnel("connected", ourStopPendingBefore);' \
    || has "$(body "$FACADE" 'void AvpnEngineQml::applyNativeState(' | tr -s ' \n' ' ')" 'if (!m_engine.onTunnelConnected() && !m_engine.isVerifying()) tryAdoptObservedTunnel("connected", ourStopPendingBefore);' \
    || bad "P4: the native Connected is the attempt owner's first, else the one Adopt rule"

[ "$fail" -eq 0 ] && echo "android adopt protocol wiring: OK"
exit "$fail"
