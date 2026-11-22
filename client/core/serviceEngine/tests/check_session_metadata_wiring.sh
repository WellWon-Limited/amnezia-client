#!/bin/bash
# Session identity for every transport (release 141, device round air20 R5, D2): the app killed while connected through
# an own Xray node («Германия 1 · Xray Reality», 12:xray) came back with adopt_connected node= (empty) and the card
# «Умный выбор сервера». Only the AmneziaWG start wrote tribeSessionMetadata; the own-Xray envelope had none, so the
# tunnel's provider configuration (iOS / macOS NE) and the Android service had nothing to hand back.
# The builder (NodeRotation.h ownSessionMetadata) and the adoption by it are tested in engine_reliability_check;
# VpnConnectionTunnelControl.cpp and the iOS bridge have no unit harness for this path, so the wiring is checked here.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
CTL="$SE/VpnConnectionTunnelControl.cpp"
FAC="$SE/AvpnEngineQml.cpp"
IOS="$SE/../../platforms/ios/ios_controller.mm"
fail=0
bad() { echo "FAIL: $1"; fail=1; }

# The own-Xray branch: from `if (xrayNode) {` to its invokeConnect - the metadata is in the envelope before it is sent.
xray="$(awk '/^    if \(xrayNode\) \{/ { on = 1 } on { print } on && /invokeConnect\(xcfg, primary.nodeId/ { exit }' "$CTL")"
[ -n "$xray" ] || bad "the own-Xray start branch (if (xrayNode) ... invokeConnect(xcfg, primary.nodeId ...) not found"
printf '%s\n' "$xray" | grep -v '^[[:space:]]*//' | grep -qF 'xcfg.insert(QStringLiteral("tribeSessionMetadata"), ownSessionMetadata(primary));' \
    || bad "an own Xray start must carry tribeSessionMetadata (ownSessionMetadata) before invokeConnect"
grep -v '^[[:space:]]*//' "$CTL" | grep -qF 'cfg.insert(QStringLiteral("tribeSessionMetadata"), ownSessionMetadata(primary));' \
    || bad "the AmneziaWG start must use the same builder (ownSessionMetadata)"
n="$(grep -v '^[[:space:]]*//' "$CTL" | grep -c 'QStringLiteral("schema_version")')"
[ "$n" = 0 ] || bad "a second hand-built session metadata in VpnConnectionTunnelControl.cpp ($n): use ownSessionMetadata"

# iOS / macOS NE bridge: the envelope's metadata goes into the provider configuration of an Xray start, and a
# relaunch reads it back; the facade adopts by node_id / proto / endpoint.
grep -qF 'QJsonObject metadata = m_rawConfig.value(QStringLiteral("tribeSessionMetadata")).toObject();' "$IOS" \
    || bad "providerMetadata must start from the envelope's tribeSessionMetadata"
awk '/^bool IosController::startXray\(/ { on = 1 } on { print } on && /^}/ { exit }' "$IOS" \
    | grep -qF 'provider[@"tribeSessionMetadata"] = providerMetadata();' \
    || bad "startXray must write tribeSessionMetadata into the provider configuration"
awk '/^void IosController::restoreSessionMetadata\(/ { on = 1 } on { print } on && /^}/ { exit }' "$IOS" \
    | grep -qF 'proto.providerConfiguration[@"tribeSessionMetadata"]' \
    || bad "restoreSessionMetadata must read the provider configuration's tribeSessionMetadata"
awk '/^void AvpnEngineQml::identifyAdoptedSession\(/ { on = 1 } on { print } on && /^}/ { exit }' "$FAC" \
    | tr -s ' \n' ' ' | grep -qF 'm_engine.adoptTunnelConnected(metadata.value(QStringLiteral("node_id")).toString(), proto, endpoint);' \
    || bad "identifyAdoptedSession must adopt by the session metadata's node_id / proto / endpoint"

[ "$fail" = 0 ] && echo "session metadata wiring: ok"
exit "$fail"
