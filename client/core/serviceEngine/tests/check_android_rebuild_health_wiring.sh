#!/bin/bash
# AVPN (emulator round 26.11.2026, D2, Android): after a 95 s network loss the VPN service rebuilt the session by itself
# (AmneziaVpnService.reconnect -> RECONNECTING until the first handshake, no deadline); the facade's health gate wanted
# the platform's Connected, so the live probe and the dead rule never ran and «Connecting…» stood for 2 min 23 s. The rule
# is pure and tested by behaviour (DebugSnapshot.h healthSessionUp: facade_policy_check d2AndroidRebuildIsTheLiveSession).
# What is checked here is where it is wired - each line fails if its call site is reverted:
#   H1  onTick's health gate takes its "connected" from healthSessionUp: the platform's Connected, or its Reconnecting
#       while the engine holds the session, the latter only where Reconnecting is the service's rebuild (Android);
#   H2  a dead verdict on such a session goes the ordinary way: the probe result reaches the engine's dead rule
#       (feedProbeResult) and a live loss is the owner's liveLost - no restart flag of the facade is involved (its
#       reconcile waits while the platform is Reconnecting);
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
tick="$(body "$FACADE" 'void AvpnEngineQml::onTick()')"
[ -n "$tick" ] || bad "H1: AvpnEngineQml::onTick not found"
flat="$(printf '%s\n' "$tick" | tr -s ' \n' ' ')"
has "$flat" '#if defined(Q_OS_ANDROID) constexpr bool kReconnectingKeepsSession = true; #else constexpr bool kReconnectingKeepsSession = false; #endif' \
    || bad "H1: the service's rebuild counts as the live session on Android only"
has "$flat" 'avpn::healthSessionUp(m_lastTunnelState == Vpn::Connected, m_lastTunnelState == Vpn::Reconnecting, m_engine.state() == avpn::EngineState::Connected, kReconnectingKeepsSession)' \
    || bad "H1: the gate's input must be healthSessionUp of the platform's and the engine's state"
has "$tick" 'if (!healthTickAllowed(m_latch, liveSessionUp, m_paused)) {' || bad "H1: the health gate must take liveSessionUp"
has "$tick" 'healthTickAllowed(m_latch, m_lastTunnelState == Vpn::Connected' && bad "H1: the gate still wants the platform's Connected only"

# ---- H2 ----
code "$FACADE" | grep -qF 'if (m_engine.feedProbeResult(reachable, m_probe->startedWallMs())) {' \
    || bad "H2: the live probe's result must reach the engine's dead rule"
ll="$(body "$SE" 'void ServiceEngine::loseLiveSession(')"
has "$ll" 'feedOwner(path::AttemptEvent::liveLost(' || bad "H2: a live loss must be the owner's liveLost"

# ---- H3 ----
disc="$(code "$SVC" | awk '/private fun disconnect\(\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$disc" 'if (isUnknown || isDisconnected || protocolState.value == DISCONNECTING) return' \
    || bad "H3: the service's stop must not refuse a RECONNECTING session"
has "$disc" 'connectionJob?.cancelAndJoin()' || bad "H3: the stop must end the rebuild job"
off="$(code "$WG" | awk '/private fun turnOffVpn\(\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$off" 'statusJob?.cancel()' || bad "H3: the protocol's stop must end the handshake wait"

[ "$fail" -eq 0 ] && echo "android rebuild health wiring: OK"
exit "$fail"
