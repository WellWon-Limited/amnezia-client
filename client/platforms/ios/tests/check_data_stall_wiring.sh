#!/bin/bash
# AVPN (awg-apple tribe.18, second review G1): the extension's stall verdict reaches the AmneziaWG probe rule dated by
# the time its status REQUEST was sent (a reply applied after a suspension must not look fresh), and a failed probe
# that spanned a suspension of the app is not fed. Structure check of the wiring (the rules are tested by behaviour in
# engine_reliability_check.cpp). Usage: bash client/platforms/ios/tests/check_data_stall_wiring.sh
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
client="$(cd "$here/../../.." && pwd)"
ctl="$client/platforms/ios/ios_controller.mm"
vctc="$client/core/serviceEngine/VpnConnectionTunnelControl.cpp"
facade="$client/core/serviceEngine/AvpnEngineQml.cpp"
fail=0
bad() { echo "check_data_stall_wiring: $1"; fail=1; }
grep -q 'const qint64 requestSentMs = QDateTime::currentMSecsSinceEpoch();' "$ctl" || bad "the status request's send time is not taken"
grep -q 'sendVpnExtensionMessage(tunnel, message, \[this, gen, request, requestSentMs\]' "$ctl" || bad "the reply handler does not carry the send time"
grep -q 'emit dataStallChanged(dataStallSec >= 0 ? (qint64) dataStallSec : -1, requestSentMs);' "$ctl" || bad "the verdict is not emitted with the send time"
grep -q 'm_stats.dataStallAtMs = measuredAtMs;' "$vctc" || bad "the tunnel control does not keep the measure time"
grep -q 'dataStallAtMs = QDateTime' "$vctc" && bad "the tunnel control dates the verdict by the apply time"
grep -q 'avpn::HealthLoop::probeSpannedSuspension(m_probe->startedWallMs(), QDateTime::currentMSecsSinceEpoch(),' "$facade" \
    || bad "the live probe callback does not drop a failure that spanned a suspension"
[ "$fail" = 0 ] && echo "check_data_stall_wiring: OK"
exit "$fail"
