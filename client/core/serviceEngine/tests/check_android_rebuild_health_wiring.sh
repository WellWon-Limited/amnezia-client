#!/bin/bash
# AVPN (emulator rounds of 26.11, D2 -> F2, Android): after a network change the VPN service rebuilds the session it holds by
# itself (AmneziaVpnService.reconnect -> RECONNECTING until the rebuilt tunnel's first handshake, no deadline). A rebuild
# that never handshook left «Connecting… / Picking a server…» for 2 min 23 s (round 1) and 3 min 58 s (round 2): nothing
# judged it - the live probe's result is dropped while the platform is not Connected, and an Android AmneziaWG session has
# no handshake statistics for the dead rule (so e475d4553's health-gate input could not fire; it is gone). Now the rebuild
# itself is the end of the live session and the owner's ordinary attempt takes over. The rule is tested by behaviour
# (path_integration_check 2r: ServiceEngine::leaveRebuiltSession). What is checked here is where it is wired - each line
# fails if its call site is reverted:
#   H1  the facade's Reconnecting case, on Android only, hands the live session to the engine (leaveRebuiltSession); the
#       health gate is the plain platform Connected again (no dead input);
#   H2  the engine loses the live session as Inconclusive with a restart (nothing against the node, the owner's attempt);
#   H3  the owner's stop reaches the service in that state: the service's disconnect() refuses only UNKNOWN,
#       DISCONNECTED and DISCONNECTING, and the protocol's stop ends the handshake wait.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }

FACADE="$HERE/../AvpnEngineQml.cpp"
SE="$HERE/../ServiceEngine.cpp"
SVC="$CLIENT/android/src/org/amnezia/vpn/AmneziaVpnService.kt"
WG="$CLIENT/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt"

# ---- H1 ----
ans="$(body "$FACADE" 'void AvpnEngineQml::applyNativeState(')"
[ -n "$ans" ] || bad "H1: applyNativeState not found"
rc="$(printf '%s\n' "$ans" | awk '/    case Vpn::Reconnecting:/ { on = 1 } on { print } on && /^        break;$/ { exit }' | tr -s ' \n' ' ')"
has "$rc" '#if defined(Q_OS_ANDROID) if (m_engine.leaveRebuiltSession()) {' \
    || bad "H1: the Android Reconnecting case must hand the live session to the engine"
has "$rc" '#endif' || bad "H1: the hand-over must stay Android-only"
tick="$(body "$FACADE" 'void AvpnEngineQml::onTick()')"
has "$tick" 'if (!healthTickAllowed(m_latch, m_lastTunnelState == Vpn::Connected, m_paused)) {' \
    || bad "H1: the health gate is the platform's Connected"
grep -rqF --include='*.h' --include='*.cpp' 'healthSessionUp' "$HERE/.." && bad "H1: the dead health-gate input (healthSessionUp) is back"

# ---- H2 ----
lr="$(body "$SE" 'bool ServiceEngine::leaveRebuiltSession()')"
has "$lr" 'if (m_state != EngineState::Connected || m_owner.phase() != path::AttemptPhase::Connected)' \
    || bad "H2: only a live session can be lost"
has "$lr" 'loseLiveSession(path::PathOutcome::Inconclusive, /*tunnelGone=*/false, /*restart=*/true,' \
    || bad "H2: the rebuild is an Inconclusive loss with the owner's restart"

# ---- H3 ----
disc="$(code "$SVC" | awk '/private fun disconnect\(\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$disc" 'if (isUnknown || isDisconnected || protocolState.value == DISCONNECTING) return' \
    || bad "H3: the service's stop must not refuse a RECONNECTING session"
has "$disc" 'connectionJob?.cancelAndJoin()' || bad "H3: the stop must end the rebuild job"
off="$(code "$WG" | awk '/private fun turnOffVpn\(\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$off" 'statusJob?.cancel()' || bad "H3: the protocol's stop must end the handshake wait"

[ "$fail" -eq 0 ] && echo "android rebuild wiring: OK"
exit "$fail"
