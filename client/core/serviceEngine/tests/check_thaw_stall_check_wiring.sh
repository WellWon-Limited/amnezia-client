#!/bin/bash
# AVPN (owner road 26.11, T1 / journal J1; review C5): the app opened on an AmneziaWG tunnel dead for minutes runs the
# existing data check at once when the FIRST status asked after a real return says the path is stalled past
# awg_probe_dead_stall_s. The rule is pure (DebugSnapshot.h judgeThawStall - facade_policy_check t1ThawStallCheck; with
# the engine - path_integration_check 2a). AvpnEngineQml.cpp has no unit harness, so its wiring is checked here - each
# line fails if reverted:
#   T1  a real return from the background (foregroundIsReturn) arms it; every AmneziaWG status reply is offered to it
#       (IosController::dataStallChanged, queued) - no tick, no timer;
#   T2  its inputs: the reply's stall verdict read as the live probe reads it (freshDataStallSec, inNetworkGrace), the
#       reply's request time, the existing threshold, and "nothing else runs";
#   T3  one judgement per return (disarmed whatever it says), the action is the existing entry
#       (reenterVerifying -> startDataPathVerification);
#   T4  nothing in it reads the data watch's flag or hold;
#   T5  the live probe's corroboration reads the same two engine functions.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
body_of() { code "$2" | awk -v start="$1" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
F="$(code "$FAC")"
ret="$(printf '%s\n' "$F" | awk '/if \(!foregroundIsReturn\(hidden, inactiveFor\)\)/{f=1} f{print} f&&/m_fgTimer.start\(\);/{exit}')"
has "$ret" 'm_thawStallArmedMs = now;' || bad "T1: a real return must arm the judgement (after foregroundIsReturn)"
[ "$(printf '%s\n' "$F" | grep -c 'm_thawStallArmedMs = now;')" = "1" ] || bad "T1: only the real return arms it"
printf '%s\n' "$F" | tr -s ' \n' ' ' | grep -qF 'connect(IosController::Instance(), &IosController::dataStallChanged, this, [this](qint64 seconds, qint64 requestSentMs) { checkStalledTunnelAfterThaw(seconds, requestSentMs); }, Qt::QueuedConnection);' \
    || bad "T1: every status reply must be offered to the judgement"
has "$(body_of 'void AvpnEngineQml::onTick()' "$FAC")" 'checkStalledTunnelAfterThaw' && bad "T1: the judgement must not ride on the tick"
fn="$(body_of 'void AvpnEngineQml::checkStalledTunnelAfterThaw(qint64 stallSec, qint64 requestSentMs)' "$FAC")"
for want in 'in.armedForThawMs = m_thawStallArmedMs;' 'in.stallAtMs = requestSentMs;' 'in.stallSec = m_engine.freshDataStallSec(nowEpoch, reply);' \
            'in.networkGrace = m_engine.inNetworkGrace(nowEpoch);' 'in.thresholdSec = avpn::awgProbeDeadStallSTuned();' \
            'in.intentOn = m_wantConnected;' 'm_op == Op::None' '!m_engine.attemptRunning()' '!m_engine.isVerifying()' \
            '!ownStopping()' '!m_latch.awaitingStopConfirm' '!m_latch.needStatusBeforeStart' '!m_paused' \
            '!m_engine.currentNodeIsXray()' '!m_engine.currentNodeIsUpstream()'; do
    has "$fn" "$want" || bad "T2: the judgement lost its input: $want"
done
wait_at="$(printf '%s\n' "$fn" | grep -nF 'if (j == avpn::ThawStallJudgement::Wait)' | head -1 | cut -d: -f1)"
disarm_at="$(printf '%s\n' "$fn" | grep -nF 'm_thawStallArmedMs = 0;' | head -1 | cut -d: -f1)"
act_at="$(printf '%s\n' "$fn" | grep -nF 'if (j != avpn::ThawStallJudgement::Check || !m_engine.reenterVerifying())' | head -1 | cut -d: -f1)"
[ -n "$wait_at" ] && [ -n "$disarm_at" ] && [ -n "$act_at" ] && [ "$wait_at" -lt "$disarm_at" ] && [ "$disarm_at" -lt "$act_at" ] \
    || bad "T3: the first status after the return must disarm the judgement whatever it says, before any action"
has "$fn" 'const avpn::ThawStallJudgement j = avpn::judgeThawStall(in);' && has "$fn" 'startDataPathVerification();' \
    || bad "T3: the judgement and the existing data check"
printf '%s\n' "$fn" | grep -qE 'watchFlag|ios_tunnel_watch|tunnelWatchFrozen|m_watchResume' && bad "T4: the judgement must not depend on the data watch"
probe="$(body_of 'bool ServiceEngine::feedProbeResult(bool ok)' "$SE/ServiceEngine.cpp")"
has "$probe" 'const qint64 dataStallSec = freshDataStallSec(nowEpoch);' && has "$probe" 'inNetworkGrace(nowEpoch),' \
    || bad "T5: the live probe's corroboration must read the same freshness and grace"
[ "$fail" = "0" ] && echo "check_thaw_stall_check_wiring: OK"
exit "$fail"
