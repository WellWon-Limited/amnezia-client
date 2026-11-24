#!/bin/bash
# AVPN (android3 runs a, f, 21.11, Android): first Connect after an app start, Wi-Fi lost 1.3 s later - the engine's stop
# went out before the VPN service was bound and vanished, the queued start brought a tunnel up behind a «Connect» screen,
# and the engine sat in a state where neither the uplink's return nor a tap did anything. The rules are pure and tested
# by behaviour (ServiceCommandQueue: client/android/utils src/test ServiceCommandQueueTest; the facade's status rule:
# facade_policy_check). What is checked here is where they are wired - each line fails if its call site is reverted:
#   Q1  the activity gives every start/stop messenger command through the queue and flushes it, in order, on the bind;
#       a start behind a waiting command does not overtake it as a second intent;
#   Q2  a running tunnel reported after our stop (the stop did not take) is not lost with the stopped protocol: VpnConnection
#       wires the protocol back (restoreConnection) and reports Connected; the facade adopts it with the session's identity;
#   Q3  a stop the owner gave up leaves no dead view: the engine says so (takeStopGivenUp), the facade asks the service
#       for a status snapshot (AndroidController::requestStatus -> activity requestStatus) and resolves its view by
#       androidStatusAction - ConfirmOwnStop applies Disconnected as the end of our own stop and reconciles;
#   R3  (review R3) a stop of a start intent Android accepted goes as an intent (ACTION_DISCONNECT, handled in
#       onStartCommand), never kept for a bind; the STATUS entry decides by androidStatusDecision (the native entry's
#       adoptObservedTunnel inside) before it touches the intent;
#   G4  (android4 G4) on return the activity always learns the service's truth (ServiceReach.onForeground: rebind a running
#       one, DISCONNECTED at once for one that ended); a stop with no service to give it to is never dropped
#       (ServiceReach.unsentStop); a destroyed service removes its notification.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
count() { printf '%s\n' "$1" | grep -cF -- "$2" || true; }

ACT="$CLIENT/android/src/org/amnezia/vpn/AmneziaActivity.kt"
VC="$CLIENT/vpnConnection.cpp"
FACADE="$HERE/../AvpnEngineQml.cpp"
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }

# ---- Q1 ----
act="$(code "$ACT")"
has "$act" 'serviceCommands.onBound().forEach(::sendServiceCommand)' || bad "Q1: the bind must deliver the waiting commands"
has "$act" 'giveServiceCommand(ServiceCommand.Disconnect)' || bad "Q1: the stop must go through the queue"
has "$act" 'giveServiceCommand(ServiceCommand.Connect(vpnConfig))' || bad "Q1: a bound start must go through the queue"
has "$act" 'if (serviceCommands.startWaits(ServiceCommand.Connect(vpnConfig), bound = false,' \
    && has "$act" 'binding = isInBoundState && !isServiceConnected)) {' \
    || bad "Q1: a start waits behind a kept command only while that bind is in progress (review R1)"
# review R1: the queue belongs to one bind; the bind flags combine; the bound state is bindService's answer
has "$act" 'bindService(it, serviceConnection, BIND_ABOVE_CLIENT or BIND_AUTO_CREATE)' || bad "R1: the bind flags must combine (or)"
has "$act" 'isInBoundState = Intent(this, proto.serviceClass).let {' || bad "R1: the bound state must be bindService's answer"
[ "$(count "$act" 'dropServiceCommands(')" -ge "4" ] || bad "R1: a given-up bind (unbind, service gone, bind refused) must drop what was kept"
has "$act" '        dropServiceCommands("unbind")' || bad "R1: every unbind drops what was kept for that bind"
[ "$(count "$act" 'vpnServiceMessenger.send(Action.DISCONNECT)')" = "1" ] \
    || bad "Q1: DISCONNECT may be sent only by sendServiceCommand"
has "$act" 'serviceCommands.offer(command, bound = isServiceConnected, binding = isInBoundState && !isServiceConnected,' \
    || bad "Q1: the queue must know whether the service is bound or a bind is in progress"

# ---- Q2 ----
dis="$(body "$VC" 'void VpnConnection::disconnectFromVpn()')"
has "$dis" '} else if (state == AndroidController::ConnectionState::CONNECTED && m_vpnProtocol.isNull()) {' \
    || bad "Q2: a CONNECTED after our stop must not be dropped"
cn="$(printf '%s\n' "$dis" | grep -nF 'CONNECTED && m_vpnProtocol.isNull()' | head -1 | cut -d: -f1)"
printf '%s\n' "$dis" | sed -n "${cn:-1},$(( ${cn:-1} + 10 ))p" | grep -qF 'restoreConnection();' \
    && printf '%s\n' "$dis" | sed -n "${cn:-1},$(( ${cn:-1} + 14 ))p" | grep -qF 'm_vpnProtocol->setConnectionState(Vpn::ConnectionState::Connected);' \
    || bad "Q2: the protocol must be wired back and the running tunnel reported through it (review R2: one Connected)"
printf '%s\n' "$dis" | sed -n "${cn:-1},$(( ${cn:-1} + 14 ))p" | grep -qE '^[[:space:]]+setConnectionState\(Vpn::ConnectionState::Connected\);' \
    && bad "R2: VpnConnection must not report the restored Connected itself (the protocol's copy would be a second one)"
has "$(code "$FACADE")" 'tryAdoptObservedTunnel("connected", ourStopPendingBefore);' \
    && has "$(code "$FACADE")" 'ourStopPendingBefore = m_latch.awaitingStopConfirm;' \
    || bad "R2: the native Connected must tell the adoption whether our stop was pending (before the latch clears)"
adopt="$(body "$FACADE" 'bool AvpnEngineQml::tryAdoptObservedTunnel(const char *why, bool ourStopPending)')"
has "$adopt" 'const bool adopted = m_engine.adoptTunnelConnected(m_serviceSessionMeta.value(QStringLiteral("node_id")).toString(),' \
    || bad "Q2: the Android adoption of a native Connected must name the session's node"
has "$adopt" 'if (adoptObservedTunnel(ourStopPending, m_wantConnected) == ObservedTunnelAdoption::StopIt) {' \
    || bad "R2: the non-iOS adoption must not overrule the person's Stop"

# ---- Q3 ----
SE="$HERE/../ServiceEngine.cpp"
JNI="$CLIENT/platforms/android/android_controller.cpp"
fac="$(code "$FACADE")"
has "$(code "$SE")" 'm_stopGivenUp = true;' || bad "Q3: the engine must say it gave a stop up"
has "$fac" 'if (m_engine.takeStopGivenUp()) {' && has "$fac" 'AndroidController::instance()->requestStatus();' \
    || bad "Q3: the facade must ask the service for its status after a given-up stop"
has "$(body "$JNI" 'void AndroidController::requestStatus()')" 'callActivityMethod("requestStatus", "()V");' \
    || bad "Q3: AndroidController::requestStatus must ask the activity"
has "$act" 'fun requestStatus() {' || bad "Q3: the activity must answer requestStatus"
has "$fac" 'const AndroidStatusAction action = androidStatusDecision(' || bad "Q3: the status handler must decide by androidStatusAction (inside androidStatusDecision)"
has "$fac" 'applyNativeState(Vpn::Disconnected, /*confirmsOwnStop=*/true);' || bad "Q3: ConfirmOwnStop must end our own stop"
has "$fac" '|| confirmsOwnStop; // android3: the end of the owner' || bad "Q3: the end of our own stop is not a loss"

# ---- R3 ----
SVC="$CLIENT/android/src/org/amnezia/vpn/AmneziaVpnService.kt"
has "$act" 'afterStartIntent = command is ServiceCommand.Disconnect && startIntentAccepted)) {' \
    && has "$act" 'ServiceCommandQueue.Disposition.AS_INTENT -> sendStopIntent()' \
    || bad "R3: a stop after an accepted start intent must go as an intent"
has "$act" 'ContextCompat.startForegroundService(this, Intent(this, proto.serviceClass).setAction(ACTION_DISCONNECT))' \
    || bad "R3: the stop intent must go to the service the start went to"
has "$act" '                startIntentAccepted = true // review R3' && has "$act" 'startIntentAccepted = false // review R3' \
    || bad "R3: the accepted start intent is known until a bind completes"
has "$(code "$SVC")" 'if (intent?.action == ACTION_DISCONNECT) {' || bad "R3: the service must take the stop intent"
status="$(code "$FACADE" | awk '/&AndroidController::status, this,/{f=1} f{print} f&&/Qt::QueuedConnection\);/{exit}')"
has "$status" 'const AndroidStatusAction action = androidStatusDecision(' && has "$status" 'm_latch.awaitingStopConfirm, m_wantConnected);' \
    || bad "R3: the STATUS entry must decide by the person's-will rule"
stopit="$(printf '%s\n' "$status" | grep -nF 'if (action == AndroidStatusAction::StopIt) {' | head -1 | cut -d: -f1)"
want="$(printf '%s\n' "$status" | grep -nF 'm_wantConnected = true;' | head -1 | cut -d: -f1)"
[ -n "$stopit" ] && [ -n "$want" ] && [ "$stopit" -lt "$want" ] || bad "R3: StopIt must be decided before the intent is touched"
has "$(code "$HERE/../DebugSnapshot.h")" 'if (a == AndroidStatusAction::Adopt && adoptObservedTunnel(ourStopPending, wantConnected) == ObservedTunnelAdoption::StopIt)' \
    || bad "R3: the STATUS rule must be the native entry's rule"

# ---- G4 ----
NOTIF="$CLIENT/android/src/org/amnezia/vpn/ServiceNotification.kt"
has "$act" 'when (ServiceReach.onForeground(knownService = vpnProto != null, running = isServiceRunning(),' \
    && has "$act" 'ServiceReach.OnForeground.GONE -> {' || bad "G4: onStart must learn the service's truth"
[ "$(count "$act" 'QtAndroidController.onVpnStateChanged(ProtocolState.DISCONNECTED.ordinal)')" -ge "3" ] \
    || bad "G4: a gone service and a stop with nothing to stop must tell DISCONNECTED"
has "$act" 'ServiceCommandQueue.Disposition.NO_SERVICE -> giveUnsentCommand(command)' \
    && has "$act" 'when (ServiceReach.unsentStop(running = isServiceRunning())) {' || bad "G4: a stop must never go into the void"
dest="$(code "$SVC" | awk '/override fun onDestroy\(\)/{f=1} f{print} f&&/^    }$/{exit}')"
has "$dest" 'serviceNotification.cancel()' && has "$dest" 'ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)' \
    || bad "G4: a destroyed service must remove its notification"
has "$(code "$NOTIF")" 'notificationManager.cancel(NOTIFICATION_ID)' || bad "G4: the notification must be cancellable"

[ "$fail" = "0" ] && echo "check_android_service_order_wiring: OK"
exit "$fail"
