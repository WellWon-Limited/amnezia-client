#!/bin/bash
# AVPN (device round air-B 24.11, iOS): a start the native parks behind the previous session's teardown is the leg's
# local phase, and a stop answers a start that is still running. The rules are pure and tested by behaviour:
# AttemptOwner "Local build" + report() (path_engine_check scenarioTraceAirB2411 / scenarioIosStopDuringStart),
# ServiceEngine::onLocalBuild on iOS (path_integration_check, the last block), TunnelStartSlot
# (XraySocketCallbackLifecycleTests.swift via run_ios_swift_checks.sh). What is checked here is where they are wired -
# each line fails if its call site is reverted:
#   P1  the controller says when a start is parked and when it goes out (iOS only), and the park is the owner's to
#       bound (the long ceiling while parked, the whole start deadline after it);
#   P2  the facade hands both reports to the engine's local-build entry with the leg the native stream is at;
#   P3  the extension: one answer per startTunnel, and the stop answers a running start after its native stop and
#       before its own answer, writing its duration into the stop record; the app logs that record;
#   P4  the owner never records no_handshake for a leg in its local phase.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
IOS="$(cd "$HERE/.." && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
sbody() { code "$1" | awk -v sig="$2" 'index($0, sig) > 0 { on = 1 } on { print } on && /^    }$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
# first line of $2 before first line of $3 inside text $1
before() {
    local a b
    a=$(printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1)
    b=$(printf '%s\n' "$1" | grep -nF -- "$3" | head -1 | cut -d: -f1)
    [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

CTL="$IOS/ios_controller.mm"
CTLH="$IOS/ios_controller.h"
FACADE="$CLIENT/core/serviceEngine/AvpnEngineQml.cpp"
PTP="$IOS/PacketTunnelProvider.swift"
RTS="$IOS/TunnelRuntimeStatus.swift"
OWNER="$CLIENT/core/serviceEngine/path/AttemptOwner.h"

# ---- P1 ----
has "$(code "$CTLH")" 'void startAwaitsTeardown(bool waiting);' || bad "P1: IosController must declare startAwaitsTeardown"
park="$(body "$CTL" 'void IosController::beginAwaitTeardown(uint64_t operation)')"
has "$park" 'emit startAwaitsTeardown(true);' || bad "P1: a park must be reported"
has "$park" 'armConnectDeadline(operation, avpn_ios::nativeTimings().permissionPromptCapMs);' \
    || bad "P1: while parked the native keeps only the long ceiling (the owner bounds the wait)"
before "$park" '#if defined(Q_OS_IOS)' 'emit startAwaitsTeardown(true);' || bad "P1: the park report is iOS only"
before "$park" 'emit startAwaitsTeardown(true);' 'recheckTeardown(operation);' \
    || bad "P1: parked is reported before the first recheck (which may continue at once)"
cont="$(body "$CTL" 'IosController::TeardownStep IosController::continueConnectAfterTeardown()')"
has "$cont" 'emit startAwaitsTeardown(false);' || bad "P1: the start that goes out after the teardown must be reported"
before "$cont" 'emit startAwaitsTeardown(false);' 'if (!configureSelectedTunnel()) {' \
    || bad "P1: 'goes out' is reported before the start is configured"
before "$cont" 'armConnectDeadline(operation, avpn_ios::nativeTimings().connectDeadlineMs);' 'if (!configureSelectedTunnel()) {' \
    || bad "P1: the start after the park gets its whole connect deadline"

# ---- P2 ----
fac="$(code "$FACADE")"
has "$fac" 'connect(IosController::Instance(), &IosController::startAwaitsTeardown, this, [this](bool waiting) {' \
    || bad "P2: the facade must take the park reports"
blk="$(printf '%s\n' "$fac" | awk 'index($0, "&IosController::startAwaitsTeardown") > 0 { on = 1 } on { print } on && /Qt::QueuedConnection\);/ { exit }')"
has "$blk" 'const quint64 leg = m_tunnel.nativeLegSeen();' || bad "P2: the report belongs to the leg the native stream is at"
has "$blk" 'm_engine.onLocalBuild(waiting ? avpn::ServiceEngine::LocalBuildReport::Building' \
    || bad "P2: parked = the leg's local phase begins (Building)"
has "$blk" ': avpn::ServiceEngine::LocalBuildReport::Built,' || bad "P2: goes out = the local phase ends (Built)"
has "$blk" '}, Qt::QueuedConnection);' || bad "P2: queued, never re-entering the controller"
pre="$(printf '%s\n' "$fac" | grep -n -B3 '&IosController::startAwaitsTeardown' | head -4)"
has "$pre" '#ifdef Q_OS_IOS' || bad "P2: the wiring is iOS only (macOS NE unchanged)"

# ---- P3 ----
start="$(sbody "$PTP" 'override func startTunnel(')"
before "$start" 'let completionHandler = tribeStartSlot.begin(tribeScanReopenOnSuccess(completionHandler))' 'switch protoType' \
    || bad "P3: startTunnel must route every start path through the one-answer slot"
stop="$(sbody "$PTP" 'override func stopTunnel(')"
before "$stop" 'let startPendingAtStop = tribeStartSlot.pending' 'switch protoType' \
    || bad "P3: stopTunnel must note whether a start was unanswered when it came"
wrap="$(printf '%s\n' "$stop" | awk 'index($0, "let completionHandler: () -> Void = {") > 0 { on = 1 } on { print } on && /^        }$/ { exit }')"
before "$wrap" '_ = tribeStartSlot.abortForStop()' 'completionHandler()' \
    || bad "P3: a running start is answered after the native stop, before the stop's own answer"
has "$wrap" 'done["stop_ms"] =' && has "$wrap" 'done["start_pending"] =' \
    && has "$wrap" 'try? TribeSharedState.appGroup?.write(done, "TribeLastStop.json")' \
    || bad "P3: the stop record must carry the stop's duration and the pending start"
before "$wrap" 'TribeLastStop.json' 'completionHandler()' || bad "P3: the stop record is written before the system hears the stop"
before "$stop" 'let completionHandler: () -> Void = {' 'switch protoType' || bad "P3: every protocol's stop goes through the wrapper"
rts="$(code "$RTS")"
has "$rts" 'final class TunnelStartSlot {' && has "$rts" 'func abortForStop() -> Bool {' \
    || bad "P3: TunnelStartSlot must exist in the host-tested runtime file"
rep="$(body "$CTL" 'void IosController::reportDisconnected()')"
has "$rep" 'stop.value(QStringLiteral("stop_ms"), -1)' && has "$rep" 'stop.value(QStringLiteral("start_pending"), -1)' \
    || bad "P3: the app must log the extension's stop duration and pending start"

# ---- P4 ----
own="$(code "$OWNER" | awk 'index($0, "void report(PathOutcome o, int connectMs, int ttfbMs") > 0 { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$own" 'if (o == PathOutcome::NoHandshake && m_leg.buildSince >= 0)' && has "$own" 'o = PathOutcome::Inconclusive;' \
    || bad "P4: report() must never record no_handshake for a leg in its local phase"

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "ios start park wiring: OK (P1 controller, P2 facade, P3 extension + app log, P4 owner)"
