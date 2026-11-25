#!/bin/bash
# One native stop at a time (device round air-D 25.11, iPhone Air, N4 pair 2): a Scanner row tapped while the previous
# row's provider leg waited for its seat ended with "intent_off why=external_loss" and the VPN off - the facade's restart
# sent a second native stop on top of the attempt owner's own stop of the failed leg, the answer to the owner's stop took
# the facade's stop mark, and the answer to the facade's stop then read as an external loss. The rule is pure
# (DebugSnapshot.h facadeStopAction, facade_policy_check) and the sequences run in facade_engine_check against the real
# engine; AvpnEngineQml.cpp has no unit harness, so its use of the rule is checked at source level: guardedStop reads the
# decision before requestStop, sends its own native stop only for IssueStop, and the engine marks the native stop it
# sends itself.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
ENG="$SE/ServiceEngine.cpp"
HDR="$SE/ServiceEngine.h"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
body_of() { awk -v start="$1" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$2"; }

stop="$(body_of 'void AvpnEngineQml::guardedStop(' "$FAC")"
[ -n "$stop" ] || bad "guardedStop() not found"
code="$(printf '%s\n' "$stop" | grep -v '^[[:space:]]*//')"
flat="$(printf '%s\n' "$code" | tr -s ' \n' ' ')"
printf '%s\n' "$flat" | grep -qF 'avpn::facadeStopAction(observedTunnelOf(m_lastTunnelState), m_engine.ownerHoldsNativeLeg(), m_engine.ownerStopInFlight())' \
    || bad "guardedStop must decide its native stop with facadeStopAction(observed, ownerHoldsNativeLeg, ownerStopInFlight)"
decided="$(printf '%s\n' "$code" | grep -n 'facadeStopAction' | head -1 | cut -d: -f1)"
first_request="$(printf '%s\n' "$code" | grep -n 'm_engine.requestStop()' | head -1 | cut -d: -f1)"
[ -n "$decided" ] && [ -n "$first_request" ] && [ "$decided" -lt "$first_request" ] \
    || bad "the decision must be read before requestStop (requestStop makes the owner's stop the facade's)"
printf '%s\n' "$code" | grep -qF 'stopFindsNothingNative' \
    && bad "guardedStop must take the nothing-native case from facadeStopAction, not a second rule"
printf '%s\n' "$flat" | grep -qF 'if (how == avpn::FacadeStop::IssueStop) m_tunnel.down();' \
    || bad "the facade's own native stop (m_tunnel.down) only for FacadeStop::IssueStop"
[ "$(printf '%s\n' "$code" | grep -c 'm_tunnel.down()')" = 1 ] \
    || bad "guardedStop must send at most one native stop, under the decision"

path="$(body_of 'void ServiceEngine::applyOwnerEffects(' "$ENG")"
printf '%s\n' "$path" | tr -s ' \n' ' ' | grep -qF 'm_ownerNativeStop = e.stamp; // ownerStopInFlight: this leg' \
    || bad "the engine must mark the leg whose native stop it sends itself (StopPath)"
grep -qF 'm_ownerNativeStop == m_owner.stoppingLeg()' "$HDR" \
    || bad "ownerStopInFlight must name the leg being stopped, not the facade-stop flag"

[ "$fail" = 0 ] && echo "own stop join wiring: ok"
exit "$fail"
