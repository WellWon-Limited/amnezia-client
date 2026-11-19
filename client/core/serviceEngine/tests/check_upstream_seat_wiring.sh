#!/bin/bash
# Provider seats (review round 1 of 17.11, F1-F6, F9): the facade and the tunnel adapter hand the seat-first
# state and the lease I/O through at exactly these places.
#
# The RULES - one acquisition in flight per owner and the seat-identity release (F2, N1), one identity per prepare (F5), no metering of a held
# seat (F6), the release re-sent after each local abort and never reported done without an answer (F3), who releases a seat at the end of a session - are
# UpstreamLeaseMachine.h / UpstreamLeaseOwner.h / UpstreamLeaseWire.h / DebugSnapshot.h and are tested by
# behaviour (upstream_engine_check ownerReviewRound1 / ownerSeatFirst / ownerRefusedBringUp, upstream_lease_check
# releaseResend, facade_policy_check upstreamSeatFirstRule). AvpnEngineQml.cpp, VpnConnectionTunnelControl.cpp and
# UpstreamLeaseClient.cpp have no unit harness, so the forwarding is checked here at source level, and only that:
#   F1  every action on the intent (noteIntentChange) gives a held seat back, and stop() reaches it before its
#       operation guard; a stop with the intent off does too (guardedStop);
#   F5  the prepare's identity goes from prepareUpstream into the pending record and from the adapter's answer
#       (the event's prepareId) through the signal into decideSeatFirstReply;
#   F9  the Scanner's row tap reads the pin BEFORE it changes it and hands that value to pinAndReconnectImpl,
#       which restores it on a refusal;
#   F6  a statistics answer is bound to the tunnel session it was asked on (down() and every connect move it);
#   F3  a release cut locally is sent again; only an HTTP answer reports it confirmed;
#   N1  a release that ended reaches the owner (an acquire of its profile waits for it);
#   and the held seat survives only the old tunnel's down(): up() of the node consumes it, cancel releases it.
# Run by build_check.sh.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
ADP="$SE/VpnConnectionTunnelControl.cpp"
ADH="$SE/VpnConnectionTunnelControl.h"
CLI="$SE/UpstreamLeaseClient.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
body_of() { # $1 file, $2 the first line of a function; prints its body up to a "}" in column one, no comments
    awk -v start="$2" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$1" \
        | grep -v '^[[:space:]]*//' || true
}
has() { printf '%s\n' "$1" | grep -qF -- "$2"; }
first_line() { printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1; }

# F1
nic="$(body_of "$FAC" 'void AvpnEngineQml::noteIntentChange()')"
has "$nic" 'cancelSeatFirst();' || bad "F1: noteIntentChange() must give a held seat back (cancelSeatFirst)"
stop="$(body_of "$FAC" 'void AvpnEngineQml::stop()')"
n1="$(first_line "$stop" 'noteIntentChange();')"
n2="$(first_line "$stop" 'm_op != Op::Stopping')"
{ [ -n "$n1" ] && [ -n "$n2" ] && [ "$n1" -lt "$n2" ]; } \
    || bad "F1: stop() must reach noteIntentChange() before its operation guard (m_op != Op::Stopping)"
gs="$(body_of "$FAC" 'void AvpnEngineQml::guardedStop(')"
has "$gs" 'cancelSeatFirst();' || bad "F1: a stop with the intent off must give a held seat back (guardedStop)"
cs="$(body_of "$FAC" 'void AvpnEngineQml::cancelSeatFirst()')"
has "$cs" 'm_tunnel.cancelUpstreamPrepare();' || bad "F1: cancelSeatFirst() must release through the adapter, pending record or not"

# F5
pin="$(body_of "$FAC" 'void AvpnEngineQml::pinAndReconnectImpl(')"
has "$pin" 'if (const quint64 prepareId = m_tunnel.prepareUpstream(' \
    && has "$pin" 'm_seatFirst = avpn::UpstreamSeatFirst{true, nodeId, prevPin, persist, m_intentSerial, prepareId};' \
    || bad "F5: the pending record must take the identity prepareUpstream returned"
grep -qF 'onUpstreamPrepared(nodeId, prepareId, ok, code);' "$FAC" \
    || bad "F5: the adapter's answer must reach onUpstreamPrepared with its prepareId"
oup="$(body_of "$FAC" 'void AvpnEngineQml::onUpstreamPrepared(')"
has "$oup" 'decideSeatFirstReply(m_seatFirst, nodeId, prepareId, m_intentSerial, ok)' \
    || bad "F5: onUpstreamPrepared must decide with the answer's prepareId"
grep -qF 'void upstreamPrepared(const QString &nodeId, quint64 prepareId, bool ok, const QString &code);' "$ADH" \
    || bad "F5: the adapter's signal must carry the prepareId"
[ "$(grep -cF 'emit upstreamPrepared(' "$ADP")" = "$(grep -cF 'e.prepareId' "$ADP")" ] \
    || bad "F5: every upstreamPrepared the adapter emits must carry the event's prepareId"
prep="$(body_of "$ADP" 'quint64 VpnConnectionTunnelControl::prepareUpstream(')"
has "$prep" 'const quint64 id = m_upOwner.prepareSerial();' && has "$prep" 'return id;' \
    || bad "F5: prepareUpstream must return the owner's prepareSerial of this prepare"

# F9
ctn="$(body_of "$FAC" 'void AvpnEngineQml::connectToNode(')"
p1="$(first_line "$ctn" 'const QString pinBefore = m_engine.pinnedNodeId();')"
p2="$(first_line "$ctn" 'pinServer(nodeId, err)')"
{ [ -n "$p1" ] && [ -n "$p2" ] && [ "$p1" -lt "$p2" ]; } \
    || bad "F9: connectToNode must read the pin BEFORE pinServer"
has "$ctn" ', &pinBefore);' || bad "F9: connectToNode must hand the earlier pin to pinAndReconnectImpl"
has "$pin" 'const QString prevPin = pinBefore ? *pinBefore : m_engine.pinnedNodeId();' \
    || bad "F9: pinAndReconnectImpl must restore the caller's earlier pin"

# F6
poll="$(body_of "$ADP" 'void VpnConnectionTunnelControl::pollXrayRuntimeStatus()')"
has "$poll" 'const quint64 statsSession = m_statsSession;' && has "$poll" 'statsSession != m_statsSession' \
    || bad "F6: a statistics answer must be dropped when the tunnel session changed since it was asked"
has "$(body_of "$ADP" 'void VpnConnectionTunnelControl::down()')" '++m_statsSession;' \
    || bad "F6: down() must end the statistics session"
has "$(body_of "$ADP" 'bool VpnConnectionTunnelControl::invokeConnect(')" '++m_statsSession;' \
    || bad "F6: every connect must start a new statistics session"

# F3 (rounds 1-2) + device round 19.11 (a 502 during a deploy): a release with no answer or a 5xx is sent again on
# the shared spacing (seatReleaseNext, one rule with the probe-batch release); only an HTTP answer reports it
# confirmed, everything else reports "not confirmed" (left to the server's TTL) - never a silent "done".
rel="$(body_of "$CLI" 'void UpstreamLeaseClient::sendRelease(')"
has "$rel" 'const SeatReleaseNext next = seatReleaseNext(status, attempt, spacedMs, releaseRetryBudgetMs);' \
    && has "$rel" 'sendRelease(requestId, leaseId, meter, route, attempt + 1, spacedMs + next.delayMs, key);' \
    || bad "F3: a release with no answer or a 5xx must be sent again on the shared spacing (seatReleaseNext)"
has "$rel" 'onReleaseDone(requestId, true);' && has "$rel" 'onReleaseDone(requestId, false);' \
    || bad "F3: sendRelease must report whether the server answered (onReleaseDone confirmed / not confirmed)"
[ "$(printf '%s\n' "$rel" | grep -cF 'onReleaseDone(requestId, true);')" = "1" ] \
    || bad "F3: only the Answered outcome may report a confirmed release"

# N1 (round 2): a release that ended reaches the owner, so an acquire of its profile that waited goes out
ctor="$(body_of "$ADP" 'VpnConnectionTunnelControl::VpnConnectionTunnelControl(')"
has "$ctor" 'applyUpstreamEvents(m_upOwner.onReleaseDone(id, upstreamClockMs()));' \
    || bad "N1: the lease client's onReleaseDone must reach the owner (m_upOwner.onReleaseDone)"
has "$ctor" 'applyUpstreamEvents(m_upOwner.onAcquireReply(id, r, upstreamClockMs()));' \
    || bad "N1: every acquire answer must reach the owner"

# the held seat: survives down(), consumed by up() of the node, released by cancel
dn="$(body_of "$ADP" 'void VpnConnectionTunnelControl::down()')"
has "$dn" 'if (m_upOwner.active() && !m_upOwner.preparing()) {' || bad "down() must keep a held seat for the up() after it"
upu="$(body_of "$ADP" 'TunnelResult VpnConnectionTunnelControl::upUpstream(')"
has "$upu" 'if (m_upOwner.preparedUsable(node.nodeId, upstreamClockMs())) {' && has "$upu" 'm_upOwner.bringUpPrepared(' \
    || bad "up() of the held node must bring the held seat up"
cup="$(body_of "$ADP" 'void VpnConnectionTunnelControl::cancelUpstreamPrepare()')"
has "$cup" 'applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));' || bad "cancelUpstreamPrepare must release the held seat"

# R1 (decision of 18.11): a seat release never rides the tunnel being abandoned - the adapter stops the core at once
# and holds the release for the confirmed stop (UpstreamLeaseWire.h::upstreamReleaseDue, tested in
# upstream_lease_check releaseAfterStop); the facade tells the adapter that the stop is confirmed; the client
# sends every release over the direct path (upstreamReleaseRoute).
down="$(body_of "$ADP" 'void VpnConnectionTunnelControl::down()')"
p1="$(first_line "$down" 'm_leaseClient->holdReleasesForStop();')"
p2="$(first_line "$down" 'applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));')"
{ [ -n "$p1" ] && [ -n "$p2" ] && [ "$p1" -lt "$p2" ]; } || bad "R1: down() must hold the release for the stop before it ends the lease"
has "$down" 'QMetaObject::invokeMethod(m_conn, "disconnectFromVpn", Qt::QueuedConnection);' && ! has "$down" 'm_stopAfterRelease' \
    || bad "R1: the core stop must not wait for the release"
has "$(body_of "$FAC" 'void AvpnEngineQml::onConnectionStateChanged(Vpn::ConnectionState s)')" 'm_tunnel.upstreamTunnelDown();' \
    || bad "R1: the facade must tell the adapter that the stop is confirmed"
has "$(body_of "$ADP" 'void VpnConnectionTunnelControl::upstreamTunnelDown()')" 'm_leaseClient->tunnelStopped();' \
    || bad "R1: a confirmed stop must send the held releases"
rel="$(body_of "$SE/UpstreamLeaseClient.cpp" 'void UpstreamLeaseClient::release(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter,')"
has "$rel" 'const LeaseRoute direct = upstreamReleaseRoute(route);' && has "$rel" 'sendRelease(requestId, leaseId, meter, direct, /*attempt=*/0);' \
    || bad "R1: a release must go over the direct path"

if [ "$fail" -ne 0 ]; then
    echo "check_upstream_seat_wiring: FAILED"
    exit 1
fi
echo "check_upstream_seat_wiring: OK"
