#!/bin/bash
# AVPN (android2 "P7 card after UI kill", 21.11, Android): a UI process that comes back to a live tunnel learns the
# node of the session the VPN service runs, and the home card never names the pin as a live session's server. The
# rules are pure and tested by behaviour: TribeSession.metadataOf (client/android/utils src/test TribeSessionTest),
# cardNodeSource (facade_policy_check p7CardNeverNamesThePinForALiveSession). What is checked here is where they are
# wired - each line fails if its call site is reverted:
#   S1  the service keeps the metadata of the start it launches and puts it into STATUS and STATUS_CHANGED;
#   S2  the activity hands it to C++ before the state; the native is registered and emits it;
#   S3  the facade keeps it and the Android adoption passes node_id / proto / endpoint (as iOS does);
#   S4  currentNode() decides through cardNodeSource and looks up the hint for an unknown live session.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$HERE/.."
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
count() { printf '%s\n' "$1" | grep -cF -- "$2" || true; }

FACADE="$ENGINE/AvpnEngineQml.cpp"
SVC="$CLIENT/android/src/org/amnezia/vpn/AmneziaVpnService.kt"
ACT="$CLIENT/android/src/org/amnezia/vpn/AmneziaActivity.kt"
QTC="$CLIENT/android/src/org/amnezia/vpn/qt/QtAndroidController.kt"
JNI="$CLIENT/platforms/android/android_controller.cpp"

# ---- S1 ----
svc="$(code "$SVC")"
has "$svc" 'sessionMetadata = TribeSession.metadataOf(config)' || bad "S1: the service must keep the metadata of the start it launches"
[ "$(printf '%s\n' "$svc" | grep -cE '^[[:space:]]+putSessionMetadata\(\)$' || true)" = "2" ] || bad "S1: STATUS and STATUS_CHANGED must carry the session metadata"
has "$svc" 'sessionMetadata?.let { putString(MSG_SESSION_METADATA, it) }' || bad "S1: the metadata goes under MSG_SESSION_METADATA"

# ---- S2 ----
act="$(code "$ACT")"
[ "$(count "$act" 'msg.data?.let(::handSessionMetadata)')" = "2" ] || bad "S2: both status events must hand the metadata over"
status_meta="$(printf '%s\n' "$act" | grep -nF 'msg.data?.let(::handSessionMetadata)' | sed -n 2p | cut -d: -f1)"
status_state="$(printf '%s\n' "$act" | grep -nF 'msg.data?.getStatus()?.let { QtAndroidController.onStatus(it) }' | head -1 | cut -d: -f1)"
[ -n "$status_meta" ] && [ -n "$status_state" ] && [ "$status_meta" -lt "$status_state" ] \
    || bad "S2: the metadata must reach C++ before the STATUS state"
has "$act" 'QtAndroidController.onSessionMetadata(data.getString(MSG_SESSION_METADATA) ?: "")' || bad "S2: the activity must pass the metadata"
has "$(code "$QTC")" 'external fun onSessionMetadata(json: String)' || bad "S2: no Kotlin native for the metadata"
jni="$(code "$JNI")"
has "$jni" '{"onSessionMetadata", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onSessionMetadata)},' \
    || bad "S2: the metadata native is not registered"
has "$(body "$JNI" 'void AndroidController::onSessionMetadata(')" 'emit AndroidController::instance()->sessionMetadata(' \
    || bad "S2: the native must emit the metadata"

# ---- S3 ----
fac="$(code "$FACADE")"
has "$fac" '[this](const QVariantMap &metadata) { m_serviceSessionMeta = metadata; }, Qt::QueuedConnection);' \
    || bad "S3: the facade must keep the service's session metadata (queued, in order with the status)"
has "$fac" 'm_engine.adoptTunnelConnected(m_serviceSessionMeta.value(QStringLiteral("node_id")).toString(),' \
    || bad "S3: the Android adoption must name the session's node"
[ "$(count "$fac" '                    m_engine.adoptTunnelConnected();')" = "0" ] \
    || bad "S3: the Android adoption must not adopt without the session's identity"

# ---- S4 ----
node="$(body "$FACADE" 'QVariantMap AvpnEngineQml::currentNode() const')"
has "$node" 'const CardNodeSource source = cardNodeSource(' || bad "S4: currentNode() must decide through cardNodeSource"
has "$node" 'else if (source == CardNodeSource::Pin)' || bad "S4: the pin only when cardNodeSource says so"
has "$node" 'if (source == CardNodeSource::Unknown) {' || bad "S4: an unknown live session is shown by its hint"

[ "$fail" = "0" ] && echo "check_android_session_identity_wiring: OK"
exit "$fail"
