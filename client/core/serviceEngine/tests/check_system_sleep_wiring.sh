#!/bin/bash
# AVPN (owner's Mac 24.11.2026, cause F: tunnel restarts inside Power Nap dark wakes). The rules are tested by behaviour
# in system_sleep_check.cpp (build_system_sleep.sh: the fact, the gate and the real ServiceEngine) and in
# path_engine_check.cpp (scenarioSystemSleep: the attempt owner); what is checked here is where they are CALLED FROM -
# each line below fails if an automatic mechanism bypasses the gate or the fact loses a source.
#   S1  each automatic mechanism of the facade asks the one gate first, at its own entry: reconcile, the service's
#       wake / network events, the wake-restart retry, the health tick, the live probe, the data check;
#   S2  the primitives those mechanisms run are reached only through them (no second door): guardedStart, the wake
#       probe, the health verdict, the seat renewals, the whoami / provider checks;
#   S3  the wake probe chain carries its epoch (a sleep ends it, its late answer decides nothing);
#   S4  the edges: "will sleep" stops the engine's own steps (the owner, the check, the probe); the awake edge looks at
#       the network first, then lets the owner resume, probes a live session once and reconciles once;
#   S5  the attempt owner reads the same fact in its context at every event (ServiceEngine::ownerContext) and holds its
#       own steps while asleep;
#   S6  the sources: the app's NSWorkspace notifications and a person's input (macOS desktop app only), the service's
#       wakeup as a proof; the gate is a constant false everywhere else;
#   F1  (review of 558d79086) the awake edge resumes a held wake-restart retry once, decided by the edge's evaluation;
#   F2  every entry into the wake probe (the edge, the service's wakeup, networkChanged, a chain's step) goes through
#       the one decision that includes the engine's state - a running data check is never probed beside;
#   F3  only a spontaneous press or key is a person; code speaks for a person through notePersonPresent() only.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
SE="$ROOT/client/core/serviceEngine"
FAC="$SE/AvpnEngineQml.cpp"
FACH="$SE/AvpnEngineQml.h"
ENG="$SE/ServiceEngine.cpp"
OWN="$SE/path/AttemptOwner.h"
MM="$ROOT/client/platforms/macos/AvpnSystemSleep.mm"
CMK="$ROOT/client/cmake/avpn.cmake"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
# The body of a C++ function: from its definition line to the first line that is exactly "}".
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
cnt() { printf '%s\n' "$1" | grep -cF -- "$2" || true; }
# Line number (within $1) of the first line containing fixed string $2; 0 when absent.
at() { local n; n="$(printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1)"; echo "${n:-0}"; }
# The first statement of a body (the line after the opening brace that is not a comment or empty).
first() { printf '%s\n' "$1" | awk 'NR > 2 && $0 !~ /^[[:space:]]*$/ { print; exit }'; }

fac="$(code "$FAC")"
reconcile="$(body "$FAC" 'void AvpnEngineQml::reconcile()')"
wakeEv="$(body "$FAC" 'void AvpnEngineQml::daemonWakeEvent(const char *why)')"
onWakeup="$(body "$FAC" 'void AvpnEngineQml::onDaemonWakeup()')"
probe="$(body "$FAC" 'void AvpnEngineQml::wakeLivenessProbe(int epoch)')"
kick="$(body "$FAC" 'void AvpnEngineQml::wakeKick()')"
tick="$(body "$FAC" 'void AvpnEngineQml::onTick()')"
live="$(body "$FAC" 'void AvpnEngineQml::measureLiveProbe()')"
check="$(body "$FAC" 'void AvpnEngineQml::startDataPathVerification()')"
enter="$(body "$FAC" 'void AvpnEngineQml::enterSystemSleep()')"
leave="$(body "$FAC" 'void AvpnEngineQml::leaveSystemSleep()')"
note="$(body "$FAC" 'bool AvpnEngineQml::noteSleepSignal(avpn::SleepSignal s)')"
held="$(body "$FAC" 'bool AvpnEngineQml::heldBySystemSleep(avpn::SleepHeld what)')"
upv="$(body "$FAC" 'void AvpnEngineQml::upstreamVerifyAttempt(int epoch)')"

# ---- S1 ------------------------------------------------------------------------------------------------
for pair in "reconcile|Reconcile" "wakeEv|TunnelProbe" "kick|WakeRetry" "tick|HealthTick" "live|LiveProbe" "check|DataCheck"; do
    var="${pair%%|*}"; what="${pair##*|}"
    b="${!var}"
    [ -n "$b" ] || { bad "S1: the body of $var is not found"; continue; }
    first "$b" | grep -qF "if (heldBySystemSleep(avpn::SleepHeld::$what))" \
        || bad "S1: $var does not ask the gate (SleepHeld::$what) as its first statement"
done
[ "$(cnt "$fac" 'heldBySystemSleep(avpn::SleepHeld::')" = "6" ] || bad "S1: the gate is asked at another number of places than the six entries"
has "$held" 'return m_systemAwake.hold(what);' || bad "S1: the gate is not the one fact's hold()"
lg=$(at "$wakeEv" 'heldBySystemSleep(avpn::SleepHeld::TunnelProbe)')
lv=$(at "$wakeEv" 'VpnConnection::reconnectToVpn')
[ "$lg" -gt 0 ] && [ "$lv" -gt "$lg" ] || bad "S1: the vanilla reconnect of daemonWakeEvent is reachable before the gate"
lt=$(at "$tick" 'heldBySystemSleep(avpn::SleepHeld::HealthTick)')
for prim in 'm_tunnel.upstreamTick();' 'm_engine.tick(' 'measureLiveProbe();' 'refreshSubscription();' 'maybeRefreshStandby('; do
    lp=$(at "$tick" "$prim")
    [ "$lp" -gt "$lt" ] || bad "S1: onTick runs '$prim' before (or without) the gate"
done

# ---- S2 ------------------------------------------------------------------------------------------------
# guardedStart: only from reconcile (and its own deferral)
[ "$(cnt "$fac" 'guardedStart();')" = "2" ] || bad "S2: guardedStart() is called outside reconcile"
has "$reconcile" 'guardedStart();' || bad "S2: reconcile no longer raises the tunnel itself"
# the wake probe: only from daemonWakeEvent and its own retry
[ "$(cnt "$fac" 'wakeLivenessProbe(epoch);')" = "2" ] || bad "S2: the wake probe is started from another place"
has "$wakeEv" 'wakeLivenessProbe(epoch);' || bad "S2: daemonWakeEvent does not start the probe itself"
# the health verdict and the seat renewals: only the health tick (and the provider check's own poll, inside a check)
[ "$(cnt "$fac" 'm_engine.tick(')" = "1" ] || bad "S2: the health verdict is fed outside onTick"
[ "$(cnt "$fac" 'm_tunnel.upstreamTick();')" = "2" ] || bad "S2: seat renewals are driven from another place"
has "$upv" 'm_tunnel.upstreamTick();' || bad "S2: the second renewal driver is not the provider check's poll"
# the data checks: only through startDataPathVerification
[ "$(cnt "$fac" 'startWhoamiVerification();')" = "1" ] && has "$check" 'startWhoamiVerification();' \
    || bad "S2: the whoami check starts outside startDataPathVerification"
[ "$(cnt "$fac" 'startUpstreamVerification();')" = "1" ] && has "$check" 'startUpstreamVerification();' \
    || bad "S2: the provider check starts outside startDataPathVerification"
# the live probe: only through measureLiveProbe
[ "$(cnt "$fac" 'm_probe->measure()')" = "1" ] && has "$live" 'm_probe->measure();' \
    || bad "S2: the live probe is measured outside measureLiveProbe"

# ---- S3 ------------------------------------------------------------------------------------------------
has "$wakeEv" 'const int epoch = ++m_wakeProbeEpoch;' || bad "S3: the wake probe chain gets no epoch"
first "$probe" | grep -qF 'if (epoch != m_wakeProbeEpoch)' || bad "S3: a probe step of an ended chain still runs"
[ "$(cnt "$probe" 'if (epoch != m_wakeProbeEpoch)')" = "2" ] || bad "S3: the probe's answer is judged without its epoch"
has "$probe" 'QTimer::singleShot(4000, this, [this, epoch]() { wakeLivenessProbe(epoch); });' \
    || bad "S3: the probe's retry loses its epoch"

# ---- S4 ------------------------------------------------------------------------------------------------
has "$enter" 'm_engine.setSystemAwake(false);' || bad "S4: 'will sleep' does not reach the attempt owner"
has "$enter" '++m_verifyEpoch;' || bad "S4: the data check in flight survives 'will sleep'"
has "$enter" '++m_wakeProbeEpoch;' || bad "S4: the wake probe in flight survives 'will sleep'"
has "$enter" 'm_probe->cancel();' || bad "S4: the live probe in flight survives 'will sleep'"
ln=$(at "$leave" 'scanNotifyNetwork();')
la=$(at "$leave" 'm_engine.setSystemAwake(true);')
lp=$(at "$leave" 'daemonWakeEvent("awake");')
lr=$(at "$leave" 'reconcile();')
[ "$ln" -gt 0 ] && [ "$la" -gt "$ln" ] && [ "$lp" -gt "$la" ] && [ "$lr" -gt "$lp" ] \
    || bad "S4: the awake edge is not network -> owner -> one probe -> one reconcile"
[ "$(cnt "$leave" 'daemonWakeEvent(')" = "1" ] && [ "$(cnt "$leave" 'reconcile();')" = "1" ] \
    || bad "S4: the awake edge evaluates more than once"
has "$note" 'case avpn::SleepEdge::Slept:' && has "$note" 'enterSystemSleep();' && has "$note" 'leaveSystemSleep();' \
    || bad "S4: the edges of the fact do not run enterSystemSleep / leaveSystemSleep"
has "$note" 'avpn::TuningStore::flag(QStringLiteral("system_sleep_gate"), true)' || bad "S4: the kill switch is not read"

# ---- S5 ------------------------------------------------------------------------------------------------
octx="$(body "$ENG" 'path::SelectionContext ServiceEngine::ownerContext() const')"
has "$octx" 'c.systemAsleep = !m_systemAwake;' || bad "S5: the owner's context does not carry the fact"
seta="$(body "$ENG" 'void ServiceEngine::setSystemAwake(bool awake)')"
has "$seta" 'feedOwner(path::AttemptEvent::tick(nowMs()));' || bad "S5: the owner does not learn of the edge at once"
own="$(code "$OWN")"
has "$own" 'm_asleep = ctx.systemAsleep;' || bad "S5: the owner does not read the fact from its context"
has "$own" 'if (!m_asleep)' && has "$own" 'checkDeadlines(ctx, out); // asleep: the clock stands' \
    || bad "S5: the owner's deadlines run while asleep"
nb="$(printf '%s\n' "$own" | awk '/void beginNext\(const SelectionContext &ctx, QList<AttemptEffect> &out\)/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$nb" 'm_nextOnWake = true;' || bad "S5: the owner chooses a leg while asleep"

# ---- S6 ------------------------------------------------------------------------------------------------
mm="$(code "$MM")"
for n in NSWorkspaceWillSleepNotification NSWorkspaceDidWakeNotification NSWorkspaceScreensDidWakeNotification; do
    has "$mm" "$n" || bad "S6: the app no longer observes $n"
done
has "$mm" '[[NSWorkspace sharedWorkspace] notificationCenter]' || bad "S6: the notifications are not taken from NSWorkspace's own center"
has "$mm" 'installEventFilter(new PersonInputFilter(app));' || bad "S6: a person's input is not a proof of a full wake"
has "$mm" 'tell(avpn::SleepSignal::PersonInput);' || bad "S6: a person's input is not told to the engine"
ins=$(printf '%s\n' "$fac" | grep -n 'AvpnSystemSleep_install(\[guard' | cut -d: -f1)
[ -n "$ins" ] || bad "S6: the observers are not installed"
if [ -n "$ins" ]; then
    guardline=$(printf '%s\n' "$fac" | head -n "$ins" | grep -n '^#' | tail -1)
    printf '%s\n' "$guardline" | grep -qF '#if defined(Q_OS_MACOS) && !defined(MACOS_NE)' \
        || bad "S6: the observers are installed outside the macOS desktop app"
fi
has "$onWakeup" 'noteSleepSignal(avpn::SleepSignal::ServicePoweredOn)' || bad "S6: the service's wakeup is not a proof of a full wake"
fh="$(code "$FACH")"
has "$fh" 'static constexpr bool heldBySystemSleep(avpn::SleepHeld) { return false; }' \
    || bad "S6: the gate is not a constant false off the macOS desktop app"
grep -B12 'platforms/macos/AvpnSystemSleep.mm' "$CMK" | grep -qF 'if(APPLE AND NOT IOS AND NOT MACOS_NE)' \
    || bad "S6: AvpnSystemSleep.mm is built outside the macOS desktop app"

# ---- F1 ------------------------------------------------------------------------------------------------
sa="$(code "$SE/SystemAwake.h")"
has "$sa" 'e.resumeWakeRestart = wakeRestartPending;' || bad "F1: the edge's evaluation does not decide the held wake restart"
has "$leave" 'wakeProbeEngineLive(), m_wakeProbing, m_wakeRestartPending);' \
    || bad "F1: the awake edge does not give its evaluation the pending wake restart"
lk=$(at "$leave" 'wakeKick();')
lc=$(at "$leave" 'if (e.resumeWakeRestart)')
[ "$lc" -gt 0 ] && [ "$lk" -eq $((lc + 1)) ] || bad "F1: the awake edge does not resume the held wake restart by its evaluation"
[ "$(cnt "$leave" 'wakeKick();')" = "1" ] || bad "F1: the awake edge resumes the wake restart more than once"
[ "$lk" -lt "$lp" ] || bad "F1: the wake restart is resumed after the probe"

# ---- F2 ------------------------------------------------------------------------------------------------
has "$sa" 'e.probe = wakeProbeDecision(intentOn, tunnelUp, engineConnected, probing);' \
    || bad "F2: the edge's probe is not the one probe decision"
has "$wakeEv" 'const avpn::WakeProbe decision = avpn::wakeProbeDecision(m_wantConnected, m_lastTunnelState == Vpn::Connected,' \
    || bad "F2: an entry into the wake probe does not go through the one decision"
has "$wakeEv" 'wakeProbeEngineLive(), m_wakeProbing);' || bad "F2: the probe decision does not see the engine's state"
[ "$(cnt "$wakeEv" 'm_lastTunnelState != Vpn::Connected')" = "0" ] || bad "F2: the probe entry decides on the platform's state alone"
[ "$(cnt "$probe" 'avpn::liveSessionToProbe(m_wantConnected, m_lastTunnelState == Vpn::Connected, wakeProbeEngineLive())')" = "2" ] \
    || bad "F2: a step of the probe chain decides without the engine's state"
[ "$(cnt "$probe" 'm_lastTunnelState != Vpn::Connected')" = "0" ] || bad "F2: a step of the probe chain decides on the platform's state alone"
live2="$(body "$FAC" 'bool AvpnEngineQml::wakeProbeEngineLive() const')"
has "$live2" 'return m_engine.state() == avpn::EngineState::Connected;' || bad "F2: the macOS app does not give the engine's live session"
has "$onWakeup" 'daemonWakeEvent("wakeup");' || bad "F2: a service wakeup while awake no longer reaches the one probe entry"
[ "$(cnt "$fac" 'm_wakeProbing = true;')" = "2" ] || bad "F2: a probe chain is started outside the probe entry and its retry"

# ---- F3 ------------------------------------------------------------------------------------------------
has "$mm" 'if (avpn::personInputProof(event->type(), event->spontaneous()))' \
    || bad "F3: the window's input is taken without its spontaneous flag"
[ "$(cnt "$mm" 'case QEvent::')" = "0" ] || bad "F3: the window's filter decides on the event type alone"
pip="$(printf '%s\n' "$sa" | awk '/inline bool personInputProof\(QEvent::Type type, bool spontaneous\)/ { on = 1 } on { print } on && /^}$/ { exit }')"
first "$pip" | grep -qF 'if (!spontaneous)' || bad "F3: a press the code sent or posted is a person"
npp="$(body "$FAC" 'void AvpnEngineQml::notePersonPresent()')"
has "$npp" 'noteSleepSignal(avpn::SleepSignal::PersonInput);' || bad "F3: notePersonPresent is not the proof of a person"
[ "$(cnt "$fac" 'noteSleepSignal(avpn::SleepSignal::PersonInput)')" = "1" ] || bad "F3: a person is told to the fact outside notePersonPresent"
has "$fac" 'guard->notePersonPresent(); // the one entry for "a person is here"' || bad "F3: the window's input does not use the one entry"
grep -qF 'Not covered by the gate (by decision of the review of' "$FAC" || bad "F2: the gate does not say the vanilla path (wake_restart off) is not covered"

if [ "$fail" -ne 0 ]; then
    echo "check_system_sleep_wiring: FAILED"
    exit 1
fi
echo "check_system_sleep_wiring: OK"
