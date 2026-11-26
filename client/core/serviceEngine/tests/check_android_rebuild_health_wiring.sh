#!/bin/bash
# AVPN (emulator rounds of 26.11, D2 -> F2, Android): after a network change the VPN service rebuilds the session it holds in
# place (AmneziaVpnService.reconnect: the new interface first, then the old backend off) and reports Reconnecting until the
# rebuilt tunnel's first handshake, with no deadline. A rebuild that never handshook left «Connecting… / Picking a server…»
# for 2 min 23 s (round 1) and 3 min 58 s (round 2). Nothing judged it: the live probe's result is dropped while the
# platform is not Connected, and an Android AmneziaWG session has no handshake statistics for the dead rule. A rebuild is
# a leg's connect to the same node, so it now gets a leg's bound in the engine (ServiceEngine::noteLiveRebuild /
# judgeLiveRebuild: tested by behaviour in path_integration_check 2r a-g). The immediate hand-over of 897b76eef (every
# rebuild a stop + connect) is gone: a rebuild that comes back in time is invisible. What is checked here is where it is
# wired - each line fails if its call site is reverted:
#   H1  the facade's Reconnecting case, on Android only, starts the bound and hands nothing over; the health gate is the
#       platform's Connected (e475d4553's dead input stays removed);
#   H2  a status snapshot after a return starts the bound on RECONNECTING and ends it on CONNECTED (the activity is
#       unbound while stopped and sees no live edge);
#   H3  the bound is a leg's (local-build limit + the kind's start deadline, no tunable of its own), judged on the attempt
#       tick after the tick's events; past it the live session is lost as NoHandshake with the owner's restart; the
#       rebuild's Connected, a loss and the person's Stop end the wait;
#   H4  the service's in-place rebuild stays as upstream has it, and the owner's stop still reaches a RECONNECTING service;
#   H5  (entry c) a service in an unfinished state (CONNECTING or RECONNECTING) that no attempt of ours owns is taken
#       over - our stop, then the ordinary connect - by the Adopt rule's person's-will test, without asking for the
#       session metadata (host case: facade_policy_check f2cStatusTakesOverARebuild).
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
has "$rc" '#if defined(Q_OS_ANDROID) if (m_engine.noteLiveRebuild(/*newRebuild=*/true))' \
    || bad "H1: the Android Reconnecting edge must start the rebuild's bound afresh (review finding 4)"
has "$rc" '#endif' || bad "H1: the bound's start must stay Android-only"
printf '%s\n' "$rc" | grep -qE 'leaveRebuiltSession|loseLiveSession|requestStop' && bad "H1: the Reconnecting case hands the live session over again"
tick="$(body "$FACADE" 'void AvpnEngineQml::onTick()')"
has "$tick" 'if (!healthTickAllowed(m_latch, m_lastTunnelState == Vpn::Connected, m_paused)) {' \
    || bad "H1: the health gate is the platform's Connected"
grep -rqF --include='*.h' --include='*.cpp' 'healthSessionUp' "$HERE/.." && bad "H1: the dead health-gate input (healthSessionUp) is back"
grep -rqF --include='*.h' --include='*.cpp' 'leaveRebuiltSession' "$HERE/.." && bad "H1: the immediate hand-over (leaveRebuiltSession) is back"

# ---- H2 ----
fac="$(code "$FACADE")"
has "$fac" 'if (serviceUnfinished && m_engine.noteLiveRebuild())' \
    || bad "H2: a snapshot of an unfinished state (RECONNECTING or CONNECTING, review finding 7) must start the bound"
has "$fac" 'else if (st == AndroidController::ConnectionState::CONNECTED)' && has "$fac" 'm_engine.noteLiveSessionUp();' \
    || bad "H2: a CONNECTED snapshot must end the bound"

# ---- H3 ----
nl="$(body "$SE" 'bool ServiceEngine::noteLiveRebuild(bool newRebuild)')"
has "$nl" 'if (m_rebuildDeadline >= 0 && !newRebuild)' || bad "H3: only a new rebuild restarts a running wait"
has "$nl" 'if (m_state != EngineState::Connected || m_owner.phase() != path::AttemptPhase::Connected || m_owner.running())' \
    || bad "H3: only a session the engine holds gets the bound"
has "$nl" 'const qint64 boundMs = qint64(t.localBuildMs) + m_owner.startTimeoutMs(kind);' || bad "H3: the bound is a leg's"
has "$nl" 'm_rebuildDeadline = m_owner.awakeMs() + boundMs;' || bad "H3: the bound counts the owner's awake time"
at="$(body "$SE" 'void ServiceEngine::attemptTick()')"
t1=$(printf '%s\n' "$at" | grep -nF 'feedOwner(path::AttemptEvent::tick(nowMs()));' | head -1 | cut -d: -f1)
t2=$(printf '%s\n' "$at" | grep -nF 'judgeLiveRebuild();' | head -1 | cut -d: -f1)
[ -n "$t1" ] && [ -n "$t2" ] && [ "$t1" -lt "$t2" ] || bad "H3: the bound must be judged on the attempt tick, after its events"
jl="$(body "$SE" 'void ServiceEngine::judgeLiveRebuild()')"
has "$jl" 'loseLiveSession(path::PathOutcome::NoHandshake, /*tunnelGone=*/false, /*restart=*/true,' \
    || bad "H3: past the bound the session is a failed leg (NoHandshake) with the owner's restart"
has "$(body "$SE" 'bool ServiceEngine::onTunnelConnected()')" 'noteLiveSessionUp();' || bad "H3: the rebuild's Connected must end the wait"
has "$(body "$SE" 'void ServiceEngine::loseLiveSession(')" 'endLiveRebuild(' || bad "H3: a loss must end the wait"
has "$(body "$SE" 'void ServiceEngine::requestStop()')" 'endLiveRebuild(' || bad "H3: the person's Stop must end the wait"

# ---- H4 ----
rec="$(code "$SVC" | awk '/private fun reconnect\(\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$rec" 'protocolState.value = RECONNECTING' && has "$rec" 'vpnProto?.protocol?.reconnectVpn(Builder(), ::protect)' \
    || bad "H4: the service's in-place rebuild must stay as upstream has it"
has "$(code "$WG")" 'start(config, vpnBuilder, protect, true)' || bad "H4: the rebuild must stay seamless (stopExistingVpn)"
disc="$(code "$SVC" | awk '/private fun disconnect\(\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$disc" 'if (isUnknown || isDisconnected || protocolState.value == DISCONNECTING) return' \
    || bad "H4: the service's stop must not refuse a RECONNECTING session"
off="$(code "$WG" | awk '/private fun turnOffVpn\(\) \{/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$off" 'statusJob?.cancel()' || bad "H4: the protocol's stop must end the handshake wait"

# ---- H5 (entry c) ---- a service holding an unfinished tunnel (CONNECTING or RECONNECTING) that no attempt of ours
# owns is taken over by the Adopt rule's person's-will test: our stop first (its latch holds every start, a tap is a
# Stop), then the ordinary connect; the will off stops it; the CONNECTED Adopt rule is untouched
status="$(code "$FACADE" | awk '/&AndroidController::status, this,/{f=1} f{print} f&&/^            Qt::QueuedConnection\);$/{exit}')"
flat="$(printf '%s\n' "$status" | tr -s ' \n' ' ')"
has "$flat" 'const bool serviceUnfinished = st == AndroidController::ConnectionState::CONNECTING || st == AndroidController::ConnectionState::RECONNECTING; const AndroidStatusAction rebuild = androidRebuildStatusDecision( serviceUnfinished, thinkConnected, m_engine.attemptRunning(), m_latch.awaitingStopConfirm, m_wantConnected);' \
    || bad "H5: the STATUS entry must decide a CONNECTING or RECONNECTING service by the person's-will rule"
tk="$(printf '%s\n' "$status" | awk '/} else if \(rebuild == AndroidStatusAction::TakeOver\) \{/ { on = 1 } on { print } on && /^                }$/ { exit }')"
w=$(printf '%s\n' "$tk" | grep -nF 'm_wantConnected = true;' | head -1 | cut -d: -f1)
v=$(printf '%s\n' "$tk" | grep -nF 'onConnectionStateChanged(Vpn::Reconnecting);' | head -1 | cut -d: -f1)
g=$(printf '%s\n' "$tk" | grep -nF 'guardedStop("takeover_rebuild");' | head -1 | cut -d: -f1)
if [ -z "$w" ] || [ -z "$v" ] || [ -z "$g" ] || [ "$w" -ge "$v" ] || [ "$v" -ge "$g" ]; then
    bad "H5: the take-over must set the intent, take the service's transition as the view, then send our own stop"
fi
printf '%s\n' "$tk" | grep -qE 'guardedStart|start\(\)|m_engine.connect' && bad "H5: the take-over must not start beside its stop"
printf '%s\n' "$status" | grep -A3 -F '} else if (rebuild == AndroidStatusAction::StopIt) {' | grep -qF 'AndroidController::instance()->stop();' \
    || bad "H5: a rebuilding service the person did not want must be stopped"
dsn="$(code "$HERE/../DebugSnapshot.h")"
dec="$(printf '%s\n' "$dsn" | awk '/inline AndroidStatusAction androidRebuildStatusDecision\(/ { on = 1 } on { print } on && /^}$/ { exit }')"
has "$dec" 'if (!serviceUnfinished || engineConnected || attemptRunning)' \
    && has "$dec" 'adoptObservedTunnel(ourStopPending, wantConnected) == ObservedTunnelAdoption::StopIt' \
    || bad "H5: the rebuild decision must be the Adopt rule's will test, only with nothing held and no attempt"
act="$(printf '%s\n' "$dsn" | awk '/inline AndroidStatusAction androidStatusAction\(/ { on = 1 } on { print } on && /^}$/ { exit }')"
printf '%s\n' "$act" | tr -s ' \n' ' ' | grep -qF 'ObservedTunnel facadeView, bool attemptRunning) { if (serviceConnected && !engineConnected) return AndroidStatusAction::Adopt;' \
    || bad "H5: the Adopt rule for a CONNECTED service must stay as it was"

[ "$fail" -eq 0 ] && echo "android rebuild wiring: OK"
exit "$fail"
