#!/bin/bash
# AVPN (review of 2af7b3a52, finding 3, round mac-D3): the quit of the macOS / Windows GUI waits for the seat's release
# through the PRODUCTION hook - AvpnEngineQml::endUpstreamSessionOnQuit sets UpstreamQuitHooks::releaseSettled from the
# lease client's releasesSettled() and hands those hooks to runUpstreamQuit; runUpstreamQuit asks releaseSettled before
# it decides there is nothing to do. The host cases (upstream_engine_check) build the hooks by hand, so without this
# check they would still pass with the production wiring removed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
ENG="$ROOT/client/core/serviceEngine/AvpnEngineQml.cpp"
UE="$ROOT/client/core/serviceEngine/UpstreamEngine.h"
fail=0
bad() { echo "FAIL: $*"; fail=1; }
body() { awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }' "$1"; }
q="$(body "$ENG" 'void AvpnEngineQml::endUpstreamSessionOnQuit()')"
[ -n "$q" ] || bad "Q1: endUpstreamSessionOnQuit not found"
printf '%s\n' "$q" | grep -qF 'h.releaseSettled = [this]() { return m_tunnel.upstreamRequestsSettled(); };' || bad "Q1: the quit does not wait through the adapter's settled predicate"
VTC0="$ROOT/client/core/serviceEngine/VpnConnectionTunnelControl.cpp"
rs="$(body "$VTC0" 'bool VpnConnectionTunnelControl::upstreamRequestsSettled() const')"
printf '%s\n' "$rs" | grep -qF 'm_upOwner.requestsOutstanding() == 0' && printf '%s\n' "$rs" | grep -qF 'm_leaseClient->releasesSettled()' \
  || bad "Q1: settled must mean no cancelled acquire pending (the owner) and no release open (the client) - review of f810803d3 (3)"
printf '%s\n' "$q" | grep -qE 'avpn::runUpstreamQuit\(m_appExitKind, avpn::upstreamNodesEnabled\(\), upstreamSession, h\)' \
  || bad "Q2: the quit does not hand these hooks to runUpstreamQuit"
r="$(body "$UE" 'inline bool runUpstreamQuit(')"
first=$(printf '%s\n' "$r" | grep -nE 'upstreamQuitWaitsForRelease\(kind, upstreamNodesOn, h\)' | head -1 | cut -d: -f1)
ret=$(printf '%s\n' "$r" | grep -nF 'return false;' | head -1 | cut -d: -f1)
[ -n "$first" ] && [ -n "$ret" ] && [ "$first" -lt "$ret" ] || bad "Q3: runUpstreamQuit can return before it asks whether a release is pending"
grep -qF 'return kind != AppExitKind::Hide && upstreamNodesOn && h.releaseSettled && !h.releaseSettled();' "$UE" \
  || bad "Q3: the pending-release rule changed"
# Q4 (round mac-D4, review finding 5): once the exit has begun nothing new starts - one latch the facade sets at its
# first aboutToQuit handler, read where attempts start (guardedStart) and passed to the engine's gate (connect, every leg).
be="$(body "$ENG" 'void AvpnEngineQml::beginExit()')"
printf '%s\n' "$be" | grep -qF 'm_exiting = true;' && printf '%s\n' "$be" | grep -qF 'm_engine.setExiting();' || bad "Q4: beginExit does not latch the facade and the engine"
printf '%s\n' "$q" | grep -qF 'beginExit();' || bad "Q4: the quit path does not begin the exit before it pumps the event loop"
fq=$(grep -n 'beginExit(); // round mac-D4: the first aboutToQuit handler' "$ENG" | head -1 | cut -d: -f1)
first=$(grep -n 'QCoreApplication::aboutToQuit, this' "$ENG" | head -1 | cut -d: -f1)
[ -n "$fq" ] && [ -n "$first" ] && [ "$fq" -gt "$first" ] && [ $((fq - first)) -le 2 ] || bad "Q4: the first aboutToQuit handler does not begin the exit"
printf '%s\n' "$(body "$ENG" 'void AvpnEngineQml::guardedStart()')" | sed -n 2,4p | grep -qF 'if (m_exiting)' || bad "Q4: guardedStart does not read the latch first"
SE="$ROOT/client/core/serviceEngine/ServiceEngine.cpp"
printf '%s\n' "$(body "$SE" 'bool ServiceEngine::connect(QString &error)')" | grep -qF 'if (m_exiting) {' || bad "Q4: the engine's connect does not refuse once the exit has begun"
awk '/case path::EffectType::StartPath: \{/ { on = 1; n = 0 } on { n++; if ($0 ~ /if \(m_exiting\)/) found = 1; if (n > 3) on = 0 } END { exit found ? 0 : 1 }' "$SE" \
  || bad "Q4: a leg is raised without asking whether the exit has begun"

# Q5 (round mac-D5): the provider start's asynchronous half - its grant, a re-acquire, a prepared seat - is abandoned by its
# owner when the exit begins: beginExit tells the adapter once, the adapter hands it to the shipped owner's abandonForExit, and
# no seat is taken for a switch after it.
printf '%s\n' "$be" | grep -qF 'm_tunnel.abandonUpstreamStartsForExit();' || bad "Q5: beginExit does not abandon the provider start that is not up"
c1=$(printf '%s\n' "$be" | grep -nE '^[[:space:]]*cancelSeatFirst\(\);' | head -1 | cut -d: -f1)
c2=$(printf '%s\n' "$be" | grep -nE '^[[:space:]]*m_tunnel\.abandonUpstreamStartsForExit\(\);' | head -1 | cut -d: -f1)
[ -n "$c1" ] && [ -n "$c2" ] && [ "$c1" -lt "$c2" ] || bad "Q6: the exit keeps the facade's pending seat-first switch - a late Prepared would stop a tunnel the quit leaves (review of f810803d3 (2))"
printf '%s\n' "$(body "$ENG" 'void AvpnEngineQml::cancelSeatFirst()')" | grep -qF 'm_seatFirst = avpn::UpstreamSeatFirst();' || bad "Q6: cancelSeatFirst does not clear the pending pick"
VTC="$ROOT/client/core/serviceEngine/VpnConnectionTunnelControl.cpp"
printf '%s\n' "$(body "$VTC" 'void VpnConnectionTunnelControl::abandonUpstreamStartsForExit()')" | grep -qF 'applyUpstreamEvents(m_upOwner.abandonForExit(upstreamClockMs()));' \
  || bad "Q5: the adapter does not hand the exit to the lease owner"
grep -qF 'QVector<UpstreamOwnerEvent> abandonForExit(qint64 nowMs)' "$ROOT/client/core/serviceEngine/UpstreamLeaseOwner.h" || bad "Q5: the owner has no exit cancel"
printf '%s\n' "$(body "$VTC" 'void VpnConnectionTunnelControl::abandonUpstreamStartsForExit()')" | grep -qF 'if (!m_upOwner.startNotUp())' \
  || bad "Q5: the adapter's exit cancel is not limited to a start that is not up"
grep -B1 -F '&& avpn::upstreamSeatFirst(intent.needsRestart' "$ENG" | grep -qF 'if (!m_exiting' || bad "Q5: a seat can be taken for a switch after the exit began"

# Q6 (merge of lead/143-names): the API host re-ask that every tunnel transition runs on desktop (the quit's own stop too)
# starts no lookup once the exit has begun - it reads the same latch first.
printf '%s\n' "$(body "$ENG" 'void AvpnEngineQml::resolveApiCarveHostsStillMissing()')" | grep -v '^[[:space:]]*//' | sed -n 2,3p \
  | grep -qF 'if (m_exiting)' || bad "Q6: the API host re-ask starts lookups after the exit began"

[ "$fail" = 0 ] && echo "check_upstream_quit_wiring: ok"
exit "$fail"
