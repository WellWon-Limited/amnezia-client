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
n2="$(first_line "$stop" 'avpn::stopNeedsGuardedStop(')"
{ [ -n "$n1" ] && [ -n "$n2" ] && [ "$n1" -lt "$n2" ]; } \
    || bad "F1: stop() must reach noteIntentChange() before its operation guard (stopNeedsGuardedStop)"
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
has "$ctn" '&pinBefore, &req);' || bad "F9: connectToNode must hand the earlier pin to pinAndReconnectImpl"
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
has "$rel" 'const SeatReleaseNext next = seatReleaseNext(status, attempt, spacedMs, releaseRetryBudgetMs, fromApi);' \
    && has "$rel" 'sendRelease(requestId, leaseId, meter, route, attempt + 1, spacedMs + next.delayMs, key);' \
    || bad "F3: a release with no answer or a 5xx must be sent again on the shared spacing (seatReleaseNext)"
has "$rel" 'onReleaseDone(requestId, true);' && has "$rel" 'onReleaseDone(requestId, false);' \
    || bad "F3: sendRelease must report whether the server answered (onReleaseDone confirmed / not confirmed)"
[ "$(printf '%s\n' "$rel" | grep -cF 'onReleaseDone(requestId, true);')" = "1" ] \
    || bad "F3: only the Answered outcome may report a confirmed release"

# N1 (round 2): a release that ended reaches the owner, so an acquire of its profile that waited goes out
ctor="$(body_of "$ADP" 'VpnConnectionTunnelControl::VpnConnectionTunnelControl(')"
has "$ctor" 'applyUpstreamEvents(m_upOwner.onReleaseDone(id, upstreamClockMs(), confirmed));' \
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
p1="$(first_line "$down" 'm_leaseClient->holdReleasesForStopIfRunning();')"
p2="$(first_line "$down" 'applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));')"
{ [ -n "$p1" ] && [ -n "$p2" ] && [ "$p1" -lt "$p2" ]; } || bad "R1: down() must hold the release for the stop before it ends the lease"
has "$down" 'QMetaObject::invokeMethod(m_conn, "disconnectFromVpn", Qt::QueuedConnection);' && ! has "$down" 'm_stopAfterRelease' \
    || bad "R1: the core stop must not wait for the release"
has "$(body_of "$FAC" 'void AvpnEngineQml::onConnectionStateChanged(Vpn::ConnectionState s)')" 'm_tunnel.upstreamTunnelDown();' \
    || bad "R1: the facade must tell the adapter that the stop is confirmed"
has "$(body_of "$ADP" 'void VpnConnectionTunnelControl::upstreamTunnelDown(bool endsSession)')" 'm_leaseClient->tunnelStopped();' \
    || bad "R1: a confirmed stop must send the held releases"
rel="$(body_of "$SE/UpstreamLeaseClient.cpp" 'void UpstreamLeaseClient::release(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter,')"
has "$rel" 'const LeaseRoute direct = upstreamReleaseRoute(route);' && has "$rel" 'sendRelease(requestId, leaseId, meter, direct, /*attempt=*/0);' \
    || bad "R1: a release must go over the direct path"

# Lease id ledger (reviews R4, R5 of 19.11 and F3, F4, F9 of round 2; the rule and its transition table are the comment
# block "Lease id ledger" in UpstreamLeaseOwner.h, the behaviour is tested in upstream_engine_check lateGrantOwnership):
# every DELETE is a decision of the owner, so the adapter only forwards.
ctor="$(body_of "$ADP" 'VpnConnectionTunnelControl::VpnConnectionTunnelControl(')"
has "$ctor" 'm_upOwner.lateGrant(profile, lease, route, newerOut, acquireId)' || bad "ledger: a late grant must be decided by the owner (lateGrant)"
has "$ctor" 'm_upOwner.acquireEnded(profile, lease, stillOut, ' || bad "ledger: the end of an acquire must reach the owner (acquireEnded)"
has "$ctor" 'm_leaseClient->tunnelStarted();' || bad "ledger: a native tunnel coming up must tell the client (a stop is waited for only while one runs)"
has "$(grep -F 'm_leaseClient->release(' "$ADP")" 'e.requestId' || bad "R5: the after-stop release must carry the owner's request id"
has "$(grep -F 'holdReleasesForStopIfRunning' "$ADP")" 'holdReleasesForStopIfRunning' || bad "F4: the after-stop release must not wait for a stop that already happened"
! grep -qF 'm_leaseClient->release(0,' "$ADP" || bad "R5: a release with request id 0 bypasses the owner's bookkeeping"
tdn="$(body_of "$ADP" 'void VpnConnectionTunnelControl::upstreamTunnelDown(bool endsSession)')"
has "$tdn" 'm_upOwner.tunnelLost(' || bad "F4: a Disconnected nobody asked for must end the session at once (tunnelLost)"
has "$(body_of "$FAC" 'void AvpnEngineQml::onConnectionStateChanged(Vpn::ConnectionState s)')" 'upstreamTunnelDown(/*endsSession=*/false)' \
    || bad "F4: the stale-event branch must not end the live session"
has "$(body_of "$ADP" 'void VpnConnectionTunnelControl::startRefused()')" 'm_upOwner.abortStart(' \
    || bad "F9: a start that never reached the native service must give its seat back (abortStart)"
has "$(body_of "$SE/ServiceEngine.cpp" 'bool ServiceEngine::onPermissionDenied()')" 'm_tunnel->startRefused();' \
    || bad "F9: the Android permission denial ends the attempt without StopPath - it must tell the tunnel adapter"
lateb="$(body_of "$CLI" 'void UpstreamLeaseClient::reportLateGrant(')"
has "$lateb" 'onLateGrant(' || bad "R4/F3: a late grant must be reported to the owner"
! has "$(body_of "$CLI" 'void UpstreamLeaseClient::acquire(')" 'sendRelease(0' || bad "R4: acquire() must not release a late grant itself"

# G1 of round 3: ONE gate for every acquire. The machine hands the owner SendAcquire actions (direct, standby
# confirmation in tunnelUp(), provisional re-acquire in tick()); the only call that sends one is sendAcquire().
OWN="$SE/UpstreamLeaseOwner.h"
[ "$(grep -v '^[[:space:]]*//' "$OWN" | grep -c 'm_io->acquire(')" = "1" ] || bad "G1: UpstreamLeaseOwner.h must send an acquire from exactly one place (sendAcquire)"
# Round 9 R1: a start never waits for a release, not even one on the wire (a local timeout of a DELETE proves nothing about
# the server; the DELETE carries its grant's token and the server ends the lease only for the current one).
! grep -rn --include='*.cpp' --include='*.h' -E 'releaseOnWireFor|releaseInFlight|m_inFlight\.(insert|remove)|m_gatedAcquires' "$SE/UpstreamLeaseOwner.h" "$SE/UpstreamLeaseClient.h" "$SE/UpstreamLeaseClient.cpp" "$SE/UpstreamLeaseMachine.h" | grep -v '^[^:]*:[0-9]*:[[:space:]]*//' | grep -q . \
    || bad "R1: no release may hold a start (releaseOnWireFor / releaseInFlight / gated acquires are gone)"
sa="$(awk 'index($0, "    void sendAcquire(const LeaseAction &a)") == 1 { on = 1 } on { print } on && /^    }/ { exit }' "$OWN")"
! has "$sa" 'return;' || bad "R1: sendAcquire must always send (no early return = no gate)"
! grep -v '^[[:space:]]*//' "$OWN" | grep -q 'dispatchLeaseIo(' || bad "G1: the owner must not dispatch machine steps around its gate (dispatchLeaseIo)"
! grep -rn --include='*.cpp' --include='*.h' --include='*.mm' -E '(leaseClient|m_leaseClient)(->|\.)acquire\(' "$SE/.." | grep -v '/tests/' | grep -q . \
    || bad "G1: nothing but the owner may ask the lease client for a seat"
# G2 of round 3: a granted seat's lifetime starts at the grant - an attempt that ends before Connected, and a start the
# native side refused or lost, give it back through the owner.
[ "$(grep -c 'm_tunnel->startRefused();' "$SE/ServiceEngine.cpp")" -ge 2 ] \
    || bad "G2: a failed attempt (Finish effect) and a refused permission must both tell the tunnel adapter (startRefused)"
has "$(body_of "$ADP" 'void VpnConnectionTunnelControl::bringUpUpstream(const UpstreamOwnerEvent &e)')" 'm_leaseClient->tunnelStarted();' \
    || bad "G2: asking for the native start must mark the tunnel as running for the release hold"

# S1 (device round 10, contract 1.19.0): a start waits for no release and takes none back - the server gives the new start another
# lease, so an old DELETE can only end the old start's own lease (and may still carry its final report). The client asks before
# every resend and before a held release is sent (the owner answers false only for a chain that a newer request for the same
# lease took over).
! grep -v '^[[:space:]]*//' "$OWN" | grep -qiE 'withdraw|reinstate|reassert|startOrder|tokenNonce|takeOver|startTakingOver' \
    || bad "S1: nothing is withdrawn, reinstated, re-asserted or adopted any more (tenure rule: one nonce, one lease, one token)"
has "$ctor" 'm_upOwner.releaseWanted(id,' || bad "S1: the adapter must give the client the owner's releaseWanted"
[ "$(grep -c 'releaseWanted' "$CLI")" -ge 3 ] || bad "S1: the client must ask releaseWanted before a resend, a timer resend and a held send"

# R1 + R6 (round 9): a session lease is NEVER released without the renew token of the grant being released - one place builds
# the DELETE body (upstreamReleaseBody, field renew_token), the late grant carries ITS token and the request that was
# answered, the iOS extension's own release carries the token of its lease; the pending releases are ONE structure keyed by
# lease id. A probe lease has no token and no route here (the Scanner's batch release is another endpoint).
has "$(body_of "$CLI" 'void UpstreamLeaseClient::sendRelease(')" 'upstreamReleaseBody(meter, route.renewToken)' || bad "R1: sendRelease must put the grant's token into the DELETE body"
! grep -v '^[[:space:]]*//' "$CLI" "$OWN" "$SE/UpstreamLeaseMachine.h" | grep -E 'upstreamReleaseBody\([^,()]*\)' | grep -q . \
    || bad "R1: upstreamReleaseBody must never be called without a token"
has "$(body_of "$CLI" 'void UpstreamLeaseClient::acquire(')" 'LeaseRoute{reply.grant.renewToken, route.apiBase}, requestId' \
    || bad "R1: a late grant must be reported with ITS token and the request id that was answered"
IOSW="$SE/../../platforms/ios"
has "$(cat "$IOSW/UpstreamLeaseRenewer.swift")" 'UpstreamLeaseWire.releaseBody(action.meter, renewToken: action.route.renewToken)' \
    || bad "R1: the extension's release must carry the token of its lease"
! grep -qF 'renew_token' "$SE/ScanApiClient.cpp" || bad "R1: the Scanner's probe-lease release has no token (a probe lease is released as before)"
for gone in m_releasesOut m_withdrawn m_unsent m_deferredSeat; do
    ! grep -qF "$gone" "$OWN" || bad "R6: $gone must not exist - the pending releases are one structure keyed by lease id (m_releases)"
done
has "$(grep -v '^[[:space:]]*//' "$OWN")" 'QHash<QString, PendingRelease> m_releases;' || bad "R6: m_releases (one pending release per lease id and token) is missing"

# R3 (round 9) + R4 (round 10): ANY answer of the API proves its route (only a transport failure does not): the unsent releases
# go out on the route that answered - direct, or the tunnel's base for an answer through the tunnel - not only after a direct
# grant, and it is decided in ONE place: the client calls onRouteProved for every acquire request that got an HTTP answer,
# whichever path it took (in time, after the hedge, a grant or not); the adapter hands it to the owner's routeProved, and the
# owner's answer handlers do not flush on their own.
has "$(grep -v '^[[:space:]]*//' "$CLI")" 'if (upstreamRouteProved(reply) && onRouteProved)' \
    || bad "R4 + round 11 R3: the client must report every acquire answer of the API (it carries the API's mark) as a proved route (onRouteProved), for in-time and late paths alike"
has "$(grep -v '^[[:space:]]*//' "$CLI")" 'seatReleaseNext(status, attempt, spacedMs, releaseRetryBudgetMs, fromApi)' \
    || bad "round 11 R3: a release is finished only by an answer of the API (the mark), the same rule as the route proof"
[ "$(grep -v '^[[:space:]]*//' "$CLI" | grep -c 'onRouteProved(requestId)')" = "1" ] || bad "R4: onRouteProved must be called from exactly one place in the client"
has "$ctor" 'm_upOwner.routeProved(requestId, upstreamClockMs())' || bad "R4: the adapter must hand a proved route to the owner (routeProved)"
oar="$(awk 'index($0, "    QVector<UpstreamOwnerEvent> onAcquireReply(") == 1 { on = 1 } on { print } on && /^    }/ { exit }' "$OWN" | grep -v '^[[:space:]]*//')"
! has "$oar" 'flushUnsent(' || bad "R4: onAcquireReply must not flush on its own (routeProved is the one place)"
! has "$(grep -v '^[[:space:]]*//' "$OWN")" 'r.kind == LeaseReplyKind::Granted && requestId == m_lastAcquireRequest && !m_lastAcquireStandby' \
    || bad "R3: the flush must not wait for a grant of a direct acquire"

# S3: evidence about a path only for something really sent - the engine asks the adapter before it records a provider
# leg's no_handshake, and the adapter answers from the owner's own fact.
has "$(grep -n 'upstreamRequestSent' "$SE/ServiceEngine.cpp")" 'upstreamRequestSent' || bad "S3: the Report effect must check that the provider leg sent something"
has "$(grep 'upstreamRequestSent' "$ADH")" 'm_upOwner.requestSent()' || bad "S3: the adapter must answer upstreamRequestSent from the owner"

# S2: a release that gave up is not abandoned - the adapter tells the owner whether the server answered it.
has "$ctor" 'm_upOwner.onReleaseDone(id, upstreamClockMs(), confirmed)' || bad "S2: the adapter must pass the release's outcome to the owner (onReleaseDone confirmed)"
has "$(body_of "$CLI" 'void UpstreamLeaseClient::releaseVia(')" 'sendRelease(requestId, leaseId, meter, route' || bad "S2: releaseVia must send over the route it is given (no direct-path strip)"

# S4 + round 18 R1: the hedge is a property of ONE moment - the acquire of a start that can still fall back to a provisional start
# (the lease machine is Acquiring). The machine SAYS it on the SendAcquire action (beforeProvisionalStart, set from its phase in
# its one sendAcquire), the owner combines it with its pack entry and hands the client a decided `hedged`; the client applies it and
# infers nothing from the request (before: "a direct request of a profile with a pack entry" also hedged an ACTIVE session's
# re-acquire after its lease ran out - its in-time grant became a late one and the renewals never resumed).
MCH="$SE/UpstreamLeaseMachine.h"
acq="$(body_of "$CLI" 'void UpstreamLeaseClient::acquire(')"
has "$acq" 'const int waitMs = hedged ? upstreamAcquireHedgeMsTuned() : upstreamAcquireTimeoutMsTuned();' \
    || bad "S4: acquire() must wait the hedge exactly when the owner decided it (hedged), the full share otherwise"
! has "$(grep -v '^[[:space:]]*//' "$CLI" "$SE/UpstreamLeaseClient.h" "$ADP")" 'hasStandbyFor' \
    || bad "round 18 R1: the client must not infer the hedge from the profile's pack entry (hasStandbyFor)"
! has "$acq" 'standbyConfigSha256.isEmpty() && route.apiBase.isEmpty()' \
    || bad "round 18 R1: the client must not infer the hedge from the request's parameters (direct request)"
[ "$(grep -v '^[[:space:]]*//' "$MCH" | grep -c 'a.beforeProvisionalStart = ')" = "1" ] \
    && has "$(grep -v '^[[:space:]]*//' "$MCH")" 'a.beforeProvisionalStart = m_phase == LeasePhase::Acquiring;' \
    || bad "round 18 R1: the machine must set beforeProvisionalStart in one place, from its phase (Acquiring)"
has "$(grep -v '^[[:space:]]*//' "$OWN")" 'a.beforeProvisionalStart && provisionalFallback()' \
    || bad "round 18 R1: the owner must hedge only the machine's acquire before a provisional start of a session with a pack entry"
has "$(grep -v '^[[:space:]]*//' "$OWN")" 'if (provisionalFallback() && mayStartProvisional(m_lastAcquire)) {' \
    || bad "round 18 R1: the hedge and the provisional start must rest on the same owner fact (provisionalFallback)"

# Round 12 R2: the server's order floor (min_session_order) is taken from ANY acquire answer of the API in ONE place of the client,
# reaches the owner's counter, and the counter's store is read again before every allocation (a second process may have moved it).
[ "$(grep -v '^[[:space:]]*//' "$CLI" | grep -c 'onSessionOrderFloor(floorOrder)')" = "1" ] \
    && has "$(grep -v '^[[:space:]]*//' "$CLI")" 'upstreamOrderFloorOf(reply)' \
    || bad "round 12 R2: the client must report the order floor of every acquire answer in exactly one place"
has "$(grep -v '^[[:space:]]*//' "$ADP")" 'm_leaseClient->onSessionOrderFloor = [this](qint64 floorOrder) { m_upOwner.raiseOrderFloor(floorOrder); };' \
    || bad "round 12 R2: the order floor must reach the owner's counter (raiseOrderFloor)"
has "$(body_of "$ADP" 'VpnConnectionTunnelControl::VpnConnectionTunnelControl(')" 'st.sync();' \
    || bad "round 12 R2: the order store must be re-read (sync) before every allocation"

# Round 16 F4 + round 17 R3: every proof of the direct route (ConfigService::directRouteProved - an answer of the API itself,
# also when the fact stays Reachable) flushes the kept seat releases on the direct route
proof_handler="$(grep -F 'ConfigService::directRouteProved' "$FAC" | grep -v '^[[:space:]]*//' || true)"
has "$proof_handler" 'm_tunnel.upstreamDirectRouteProved();' \
    || bad "F4/R3: the directRouteProved handler must call m_tunnel.upstreamDirectRouteProved() (kept seat releases would wait for an acquire)"
has "$(grep -v '^[[:space:]]*//' "$SE/ConfigService.cpp")" 'emit directRouteProved();' \
    || bad "R3: ConfigService must announce every direct proof, not only a change of the fact"
has "$(grep -v '^[[:space:]]*//' "$ADH")" 'm_upOwner.directRouteProved(upstreamClockMs());' \
    || bad "F4: the adapter must hand the proof to the owner (directRouteProved)"

# Device round 11 of 20.11 (a seat left taken for ten minutes after a failed start: the lease answer was lost to the app's own API
# reset of a tunnel transition, nobody knew the lease id, nothing was owed). The rule is UpstreamLeaseOwner.h, row "answer lost"
# (upstream_engine_check lostAnswerSeatDebt, ledgerModel, ownerSeatModel); here only the forwarding:
#   the client tells the owner, with the end of every acquire request, which request it was and whether its outcome is unknown;
#   every step of the owner is followed by the look at what it keeps (noteSeatDebts), which asks the control plane for the proof;
#   ConfigService consults the owner before every ask, and the facade connects the two.
acq="$(body_of "$CLI" 'void UpstreamLeaseClient::acquire(')"
has "$acq" 'const bool seatUnknown = upstreamAcquireOutcomeUnknown(reply);' \
    || bad "answer lost: the client must decide the unknown outcome by upstreamAcquireOutcomeUnknown"
[ "$(printf '%s\n' "$acq" | grep -cF 'requestId, seatUnknown);')" = "2" ] \
    || bad "answer lost: both ends of an acquire request (in time, after the wait) must carry the request id and seatUnknown"
has "$ctor" 'applyUpstreamEvents(m_upOwner.acquireEnded(profile, lease, stillOut, acquireId, seatUnknown, upstreamClockMs()));' \
    || bad "answer lost: the end of an acquire request must reach the owner with its id and seatUnknown"
aue="$(body_of "$ADP" 'void VpnConnectionTunnelControl::applyUpstreamEvents(')"
has "$aue" 'noteSeatDebts();' || bad "answer lost: every step of the owner must be followed by noteSeatDebts()"
nsd="$(body_of "$ADP" 'void VpnConnectionTunnelControl::noteSeatDebts()')"
has "$nsd" 'if (upstreamProofOwed())' && has "$nsd" 'emit upstreamRouteProofOwed();' \
    || bad "answer lost: what the owner keeps on an idle device must ask for the proof of the direct route"
has "$(grep -v '^[[:space:]]*//' "$ADH")" 'bool upstreamProofOwed() { return m_upOwner.proofOwed(upstreamClockMs()); }' \
    || bad "answer lost: the adapter must expose the owner's proofOwed()"
fac_nc="$(grep -v '^[[:space:]]*//' "$FAC")"
has "$fac_nc" 'm_configSvc->setProofOwedSource([this]() { return m_tunnel.upstreamProofOwed(); });' \
    && has "$fac_nc" 'connect(&m_tunnel, &avpn::VpnConnectionTunnelControl::upstreamRouteProofOwed, m_configSvc, &avpn::ConfigService::noteProofOwed);' \
    || bad "answer lost: the facade must connect the owner's owed proof to ConfigService (source + noteProofOwed)"
ask="$(body_of "$SE/ConfigService.cpp" 'void ConfigService::askDirectOnce()')"
has "$ask" 'const bool proofOwed = m_proofOwedFn && m_proofOwedFn();' && has "$ask" 'm_askLater.start(int(kAskSpacingMs));' \
    || bad "answer lost: askDirectOnce must consult the owed proof and come back after the spacing while it is owed"

if [ "$fail" -ne 0 ]; then
    echo "check_upstream_seat_wiring: FAILED"
    exit 1
fi
echo "check_upstream_seat_wiring: OK"
