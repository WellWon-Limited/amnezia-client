#!/bin/bash
# AVPN (owner road 26.11, T1 / journal J1): the app opened on an AmneziaWG tunnel dead for minutes runs the existing data
# check at once when the extension's fresh status says the path is stalled past awg_probe_dead_stall_s. The rule is pure
# (DebugSnapshot.h thawStallCheckDue - facade_policy_check t1ThawStallCheck; its verdict path - path_integration_check
# 2a). AvpnEngineQml.cpp has no unit harness, so its wiring is checked here - each line fails if reverted:
#   T1  the facade's tick asks the trigger on iOS, before (and independent of) the data watch's hold;
#   T2  its inputs: the thaw, the status the extension sent after it (data_stall_s and its request time), the existing
#       threshold, and "nothing else runs" (own op, attempt, check, stop, teardown latch, pause);
#   T3  the action is the existing entry (reenterVerifying -> startDataPathVerification), once per thaw;
#   T4  nothing in it reads the data watch's flag or hold.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
body_of() { code "$2" | awk -v start="$1" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

tick="$(body_of 'void AvpnEngineQml::onTick()' "$FAC")"
call="$(printf '%s\n' "$tick" | grep -nF 'checkStalledTunnelAfterThaw();' | head -1 | cut -d: -f1)"
hold="$(printf '%s\n' "$tick" | grep -nF 'tunnelWatchFrozen("health_tick")' | head -1 | cut -d: -f1)"
[ -n "$call" ] && [ -n "$hold" ] && [ "$call" -lt "$hold" ] || bad "T1: the tick must ask the trigger before the data watch's hold"

fn="$(body_of 'void AvpnEngineQml::checkStalledTunnelAfterThaw()' "$FAC")"
for want in 'in.stallSec = st.dataStallSec;' 'in.stallAtMs = st.dataStallAtMs;' 'in.thawMs = m_lastResumeMs;' \
            'in.checkedThawMs = m_thawStallCheckedMs;' 'in.thresholdSec = avpn::awgProbeDeadStallSTuned();' \
            'in.intentOn = m_wantConnected;' 'm_op == Op::None' '!m_engine.attemptRunning()' '!m_engine.isVerifying()' \
            '!ownStopping()' '!m_latch.awaitingStopConfirm' '!m_latch.needStatusBeforeStart' '!m_paused' \
            '!m_engine.currentNodeIsXray()' '!m_engine.currentNodeIsUpstream()'; do
    has "$fn" "$want" || bad "T2: the trigger lost its input: $want"
done
has "$fn" 'if (!avpn::thawStallCheckDue(in) || !m_engine.reenterVerifying())' || bad "T3: the trigger must decide by thawStallCheckDue and enter through reenterVerifying"
has "$fn" 'm_thawStallCheckedMs = m_lastResumeMs;' || bad "T3: one check per thaw"
has "$fn" 'startDataPathVerification();' || bad "T3: the existing data check must run"
printf '%s\n' "$fn" | grep -qE 'watchFlag|ios_tunnel_watch|tunnelWatchFrozen|m_watchResume' && bad "T4: the trigger must not depend on the data watch"
[ "$fail" = "0" ] && echo "check_thaw_stall_check_wiring: OK"
exit "$fail"
