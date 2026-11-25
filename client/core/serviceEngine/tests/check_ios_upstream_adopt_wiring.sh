#!/bin/bash
# iOS: the seat of a provider session adopted after a relaunch (device round 24.11, iPhone Air, case C3). Connect to a provider
# row, force-quit, relaunch: the live tunnel was adopted ("adopt_connected verdict=1 node=up:.."), and the Stop sent no release -
# every other lease of the round got DELETE 204, this one none; the seat stayed held until its 15-minute TTL. The app had no
# owner of the seat after the relaunch (only the macOS GUI owner kept a record).
#
# The RULES - the record (no token) written before the bring-up / with the confirmed seat and cleared at every end, the match
# of a record to THE live session (node + start order), the owner restored handed over (no acquire, no renewal; the release
# after the confirmed stop) - are UpstreamEngine.h / UpstreamLeaseOwner.h / UpstreamLeaseMachine.h and are tested by behaviour
# (upstream_engine_check ownerHandedOverAdoption). VpnConnectionTunnelControl.cpp, AvpnEngineQml.cpp and the iOS bridge have no
# unit harness for this path, so the forwarding is checked here at source level, and only that:
#   R1  the iOS adapter keeps the record (keepRecord) and really writes / removes it (Persist / ClearRecord under Q_OS_IOS);
#   R2  the start's order rides in the session's tribeSessionMetadata of an iOS provider start, before the start is sent;
#   R3  the bridge passes the metadata through (providerMetadata starts from the envelope's, a relaunch reads the whole
#       dictionary back) - read only here, ios_controller.mm is not changed by this rule;
#   R4  adoptUpstreamSession matches the record to the live session's metadata and restores the owner handed over;
#   R5  the facade calls it on every iOS adoption (tryAdoptObservedTunnel) and when an adopted identity resolves late;
#   R6  the end goes the existing way: down() ends an active owner, ReleaseAfterStop holds for the confirmed stop.
# Run by the client gate (gate-and-build.sh: every check_*.sh).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
ADP="$SE/VpnConnectionTunnelControl.cpp"
ADH="$SE/VpnConnectionTunnelControl.h"
IOS="$SE/../../platforms/ios/ios_controller.mm"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
body_of() { # $1 file, $2 the first line of a function; prints its body up to a "}" in column one, no comments
    awk -v start="$2" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$1" \
        | grep -v '^[[:space:]]*//' || true
}
has() { printf '%s\n' "$1" | grep -qF -- "$2"; }
first_line() { printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1; }
# The lines between a `#if <cond>` line (the whole line, exactly) and the next #endif: what is compiled under that condition.
under() { # $1 text, $2 the exact #if line
    printf '%s\n' "$1" | awk -v c="$2" '$0 ~ /^#endif/ && on { on = 0 } on { print } $0 == c { on = 1 }'
}

# R1
ctor="$(body_of "$ADP" 'VpnConnectionTunnelControl::VpnConnectionTunnelControl(')"
has "$(under "$ctor" '#if defined(Q_OS_IOS)')" 'o.keepRecord = true;' \
    || bad "R1: the iOS adapter must keep the session's record (o.keepRecord = true under Q_OS_IOS)"
aue="$(body_of "$ADP" 'void VpnConnectionTunnelControl::applyUpstreamEvents(')"
persist="$(printf '%s\n' "$aue" | awk '/case UpstreamOwnerEventKind::Persist:/ { on = 1 } on { print } on && /break;/ { exit }')"
has "$persist" '#if AVPN_UPSTREAM_GUI_OWNER || defined(Q_OS_IOS)' \
    && has "$persist" 'QSettings().setValue(QLatin1String(kUpstreamLeaseRecordKey), e.record.toJson());' \
    || bad "R1: Persist must write the record on iOS too (#if AVPN_UPSTREAM_GUI_OWNER || defined(Q_OS_IOS))"
clear="$(printf '%s\n' "$aue" | awk '/case UpstreamOwnerEventKind::ClearRecord:/ { on = 1 } on { print } on && /break;/ { exit }')"
has "$clear" '#if AVPN_UPSTREAM_GUI_OWNER || defined(Q_OS_IOS)' \
    && has "$clear" 'QSettings().remove(QLatin1String(kUpstreamLeaseRecordKey));' \
    || bad "R1: ClearRecord must remove the record on iOS too"

# R2
bu="$(body_of "$ADP" 'void VpnConnectionTunnelControl::bringUpUpstream(')"
ord="$(under "$bu" '#if defined(Q_OS_IOS)')"
has "$ord" 'meta.insert(QLatin1String(kUpstreamSessionOrderMetaKey), double(m_upOwner.tunnelOrder()));' \
    && has "$ord" 'xcfg.insert(QStringLiteral("tribeSessionMetadata"), meta);' \
    || bad "R2: an iOS provider start must carry the order its tunnel is brought up with (tunnelOrder, round 44 F3) in tribeSessionMetadata"
o1="$(first_line "$bu" 'meta.insert(QLatin1String(kUpstreamSessionOrderMetaKey)')"
o2="$(first_line "$bu" 'invokeConnect(xcfg, m_upStub.nodeId, DockerContainer::Xray)')"
{ [ -n "$o1" ] && [ -n "$o2" ] && [ "$o1" -lt "$o2" ]; } \
    || bad "R2: the order must be in the envelope before invokeConnect"

# R3 (read only: the bridge is not changed by this rule)
grep -qF 'QJsonObject metadata = m_rawConfig.value(QStringLiteral("tribeSessionMetadata")).toObject();' "$IOS" \
    || bad "R3: providerMetadata must start from the envelope's tribeSessionMetadata (the order passes through)"
grep -qF 'NSDictionary *metadata = proto.providerConfiguration[@"tribeSessionMetadata"];' "$IOS" \
    || bad "R3: a relaunch must read the whole tribeSessionMetadata back from the provider configuration"
grep -qF 'QVariantMap IosController::sessionMetadata() const' "$IOS" \
    || bad "R3: IosController::sessionMetadata() is what adoptUpstreamSession reads"

# R4
ad="$(body_of "$ADP" 'void VpnConnectionTunnelControl::adoptUpstreamSession()')"
[ -n "$ad" ] || bad "R4: VpnConnectionTunnelControl::adoptUpstreamSession() not found"
ios_ad="$(under "$ad" '#if defined(Q_OS_IOS)')"
has "$ios_ad" 'm_upOwner.active()' || bad "R4: a live session of this process is never replaced by an adoption"
has "$ios_ad" 'IosController::Instance()->sessionMetadata()' || bad "R4: the live session's metadata must be the input"
has "$ios_ad" 'upstreamHandedOverRecordMatches(rec, liveNode, upstreamSessionOrderOf(meta), QDateTime::currentMSecsSinceEpoch())' \
    || bad "R4: the record must match the live session (node + start order) before it is adopted"
has "$ios_ad" 'applyUpstreamEvents(m_upOwner.adoptHandedOver(rec, upstreamClockMs()));' \
    || bad "R4: a matching record must restore the owner handed over (adoptHandedOver)"
m1="$(first_line "$ios_ad" 'upstreamHandedOverRecordMatches(')"
m2="$(first_line "$ios_ad" 'm_upOwner.adoptHandedOver(')"
{ [ -n "$m1" ] && [ -n "$m2" ] && [ "$m1" -lt "$m2" ]; } || bad "R4: the match must come before the adoption"
has "$(grep -v '^[[:space:]]*//' "$ADH")" 'void adoptUpstreamSession();' || bad "R4: the adapter must declare adoptUpstreamSession()"

# R5 (+ device round air-D 25.11, S2): on every iOS adoption the seat is owned and the record's stub joins the candidates AFTER the
# adoption verdict and BEFORE the engine adopts by node id (a Scanner row's node is not in the pool after a relaunch); the same when
# the metadata comes late (identifyAdoptedSession) and on the macOS record adoption.
tao="$(body_of "$FAC" 'bool AvpnEngineQml::tryAdoptObservedTunnel(')"
ios_tao="$(printf '%s\n' "$tao" | awk '/^#if defined\(Q_OS_IOS\) \|\| defined\(MACOS_NE\)/ { on = 1; next } /^#else/ && on { exit } on { print }')"
t0="$(first_line "$ios_tao" 'if (verdict == TunnelAdoption::Reject)')"
t1="$(first_line "$ios_tao" 'm_tunnel.adoptUpstreamSession();')"
t2="$(first_line "$ios_tao" 'restoreAdoptedUpstreamNode();')"
t3="$(first_line "$ios_tao" 'm_engine.adoptTunnelConnected(nodeId, proto, endpoint)')"
{ [ -n "$t0" ] && [ -n "$t1" ] && [ -n "$t2" ] && [ -n "$t3" ] && [ "$t0" -lt "$t1" ] && [ "$t1" -lt "$t2" ] && [ "$t2" -lt "$t3" ]; } \
    || bad "R5/S2: tryAdoptObservedTunnel must own the seat, then restore the record's stub, after the verdict and before the engine adopts by node id"
ias="$(body_of "$FAC" 'void AvpnEngineQml::identifyAdoptedSession()')"
i1="$(first_line "$ias" 'm_tunnel.adoptUpstreamSession();')"
i2="$(first_line "$ias" 'restoreAdoptedUpstreamNode();')"
i3="$(first_line "$ias" 'm_engine.adoptTunnelConnected(metadata.value(QStringLiteral("node_id")).toString(), proto, endpoint);')"
{ [ -n "$i1" ] && [ -n "$i2" ] && [ -n "$i3" ] && [ "$i1" -lt "$i2" ] && [ "$i2" -lt "$i3" ]; } \
    || bad "R5/S2: a late identity (identifyAdoptedSession) must own the seat and restore the stub before it adopts by node id"
mac="$(awk '/upstreamSessionAdopted, this,/ { on = 1 } on { print } on && /\}\);/ { exit }' "$FAC" | grep -v '^[[:space:]]*//')"
m1="$(first_line "$mac" 'restoreAdoptedUpstreamNode();')"
m2="$(first_line "$mac" 'm_engine.adoptTunnelConnected(nodeId, QStringLiteral("xray"), QString());')"
{ [ -n "$m1" ] && [ -n "$m2" ] && [ "$m1" -lt "$m2" ]; } || bad "S2: the macOS record adoption must restore the stub before it identifies the node"
ran="$(body_of "$FAC" 'void AvpnEngineQml::restoreAdoptedUpstreamNode()')"
has "$ran" 'const QJsonObject stub = m_tunnel.adoptedUpstreamStub();' && has "$ran" 'm_engine.offerScanNodes(QJsonArray{stub});' \
    && has "$ran" 'syncStandbyCandidates();' || bad "S2: the adopted stub must go through the subscription's parser into the candidates"
dpv="$(body_of "$FAC" 'void AvpnEngineQml::startDataPathVerification()')"
has "$dpv" 'if (m_engine.currentNodeIsUpstream() || unnamedProviderSession()) {' \
    || bad "S2: a provider session the engine cannot name must never be judged by whoami"
ups="$(body_of "$FAC" 'bool AvpnEngineQml::unnamedProviderSession() const')"
has "$ups" 'if (m_engine.currentIdentityKnown())' && has "$ups" 'm_tunnel.upstreamActive() && !m_tunnel.upstreamPreparing()' \
    && has "$ups" 'sessionMetadata().value(QStringLiteral("upstream")).toInt() == 1' \
    || bad "S2: an unnamed provider session = an owned (not prepared) seat or the session's own upstream metadata"

# R6 (the end of an adopted session takes the existing path)
dn="$(body_of "$ADP" 'void VpnConnectionTunnelControl::down()')"
has "$dn" 'if (m_upOwner.active() && !m_upOwner.preparing()) {' && has "$dn" 'applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));' \
    || bad "R6: down() must end an active owner (the adopted one included)"
ras="$(printf '%s\n' "$aue" | awk '/case UpstreamOwnerEventKind::ReleaseAfterStop:/ { on = 1 } on { print } on && /break;/ { exit }')"
has "$ras" 'm_leaseClient->holdReleasesForStopIfRunning();' \
    && has "$ras" 'm_leaseClient->release(e.requestId, e.leaseId, UpstreamMeter{}, e.route);' \
    || bad "R6: ReleaseAfterStop must wait for the confirmed stop and name the event's lease"
utd="$(body_of "$ADP" 'void VpnConnectionTunnelControl::upstreamTunnelDown(')"
has "$utd" 'applyUpstreamEvents(m_upOwner.tunnelLost(upstreamClockMs()));' && has "$utd" 'm_leaseClient->tunnelStopped();' \
    || bad "R6: a Disconnected nobody asked for must end the session and send what was held"

if [ "$fail" -ne 0 ]; then
    echo "check_ios_upstream_adopt_wiring: FAILED"
    exit 1
fi
echo "check_ios_upstream_adopt_wiring: OK"
