#!/bin/bash
# AVPN (android2 V2, 21.11, Android): a build report of the VPN service belongs to ONE engine leg, and a leg is local
# until its own "built". The rules are pure and tested by behaviour: AttemptOwner::setLocalBuildReported
# (path_engine_check scenarioLocalBuildQueued), ServiceEngine::onLocalBuild with the leg (path_integration_check),
# TribeStart.legOf / endState (client/android/utils src/test TribeStartTest). What is checked here is where they are
# wired - each line fails if its call site is reverted:
#   B1  the start config carries the leg (Android only): beginNativeOp keeps it, invokeConnect inserts tribeStartLeg;
#   B2  the service reads the leg of a start, names it in every build report, and reports a start without a tunnel as
#       NOT_STARTED (never "built");
#   B3  the activity and the JNI hand the leg over; the native is registered with it and says the platform reports;
#   B4  the facade passes the report with its leg to the engine and turns the reported mode on (start, adoption).
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$HERE/.."
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
kbody() { code "$1" | awk -v sig="$2" 'index($0, sig) > 0 { on = 1 } on { print } on && /^    }$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
count() { printf '%s\n' "$1" | grep -cF -- "$2" || true; }

TC="$ENGINE/VpnConnectionTunnelControl.cpp"
FACADE="$ENGINE/AvpnEngineQml.cpp"
SVC="$CLIENT/android/src/org/amnezia/vpn/AmneziaVpnService.kt"
ACT="$CLIENT/android/src/org/amnezia/vpn/AmneziaActivity.kt"
QTC="$CLIENT/android/src/org/amnezia/vpn/qt/QtAndroidController.kt"
JNI="$CLIENT/platforms/android/android_controller.cpp"

# ---- B1 ----
has "$(body "$TC" 'void VpnConnectionTunnelControl::beginNativeOp(quint64 leg)')" 'm_startLeg = leg;' \
    || bad "B1: beginNativeOp must keep the leg of the start that follows"
inv="$(body "$TC" 'bool VpnConnectionTunnelControl::invokeConnect(')"
has "$inv" 'withLeg.insert(QStringLiteral("tribeStartLeg"), qint64(m_startLeg));' && has "$inv" 'Q_ARG(QJsonObject, withLeg));' \
    || bad "B1: invokeConnect must send the leg in the start config"
has "$inv" '#if defined(Q_OS_ANDROID)' || bad "B1: the leg goes into the start config on Android only"

# ---- B2 ----
svc="$(code "$SVC")"
has "$svc" 'val leg = TribeStart.legOf(vpnConfig)' || bad "B2: the service must read the leg of the start"
has "$svc" 'putLong(MSG_TUNNEL_BUILD_LEG, leg)' || bad "B2: every build report must name its leg"
has "$svc" 'reportTunnelBuild(TribeStart.endState(started = false), seq, leg)' || bad "B2: a start not launched is NOT_STARTED"
has "$svc" 'mainScope.launch { reportTunnelBuild(TribeStart.endState(started), seq, leg) }' \
    || bad "B2: the end of a launched start must say whether its tunnel started"
[ "$(count "$svc" 'reportTunnelBuild(TUNNEL_BUILT')" = "0" ] || bad "B2: no build end may be reported as built unconditionally"

# ---- B3 ----
has "$(code "$ACT")" 'd.getLong(MSG_TUNNEL_BUILD_LEG))' || bad "B3: the activity must hand the leg to C++"
has "$(code "$QTC")" 'external fun onTunnelBuild(state: Int, seq: Int, leg: Long)' || bad "B3: the Kotlin native must carry the leg"
jni="$(code "$JNI")"
has "$jni" '{"onTunnelBuild", "(IIJ)V", reinterpret_cast<void *>(onTunnelBuild)},' || bad "B3: the native must be registered with the leg"
has "$jni" 's_reportsTunnelBuild.store(true);' || bad "B3: a registered native must say the platform reports its builds"
has "$jni" 'emit AndroidController::instance()->tunnelBuild(int(state), int(seq), quint64(leg));' || bad "B3: the leg must reach the signal"

# ---- B4 ----
fac="$(code "$FACADE")"
has "$fac" '&AndroidController::tunnelBuild, this, [this](int buildState, int seq, quint64 leg) {' \
    || bad "B4: the facade must take the leg of a build report"
has "$fac" ': avpn::ServiceEngine::LocalBuildReport::NotStarted,' || bad "B4: state 2 must be NotStarted"
[ "$(count "$fac" 'm_engine.setLocalBuildReported(AndroidController::reportsTunnelBuild());')" = "2" ] \
    || bad "B4: the reported mode must be set at the attempt start and at the adoption"

[ "$fail" = "0" ] && echo "check_android_build_identity_wiring: OK"
exit "$fail"
