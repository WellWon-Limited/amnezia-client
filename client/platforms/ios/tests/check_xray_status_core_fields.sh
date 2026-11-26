#!/bin/bash
# AVPN (device round air-I, 25.11): the Xray status reply nests the core's own fields in its "core" object
# (PacketTunnelProvider+Xray.swift handleXrayStatusMessage -> TunnelRuntimeStatus.payload(core:)); the app read them at
# the top level, so the interface name, the socket-protect counters and the start failure were always empty / 0. Checks
# that both sides name the same place: each key the reader takes from "core" is written into `core` by the extension and
# never read at the top level; core_log_tail stays out of the reader on purpose (ios_controller.mm says why).
# Review F3 (25.11): the stored start failure is cleared by the one place that knows a core start succeeded, so a reply
# carries a failure only for the start it belongs to; the app's xrayStartFailed is read by nothing but the log.
# Usage: bash client/platforms/ios/tests/check_xray_status_core_fields.sh
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
client="$(cd "$here/../../.." && pwd)"
ctl="$client/platforms/ios/ios_controller.mm"
ext="$client/platforms/ios/PacketTunnelProvider+Xray.swift"
status="$client/platforms/ios/TunnelRuntimeStatus.swift"
fail=0
bad() { echo "check_xray_status_core_fields: $1"; fail=1; }
grep -qF '"core": core,' "$status" || bad "the runtime status no longer nests the core fields under \"core\""
grep -qF 'var response = xrayRuntimeSession.payload(core: core)' "$ext" || bad "the Xray reply is no longer built from payload(core:)"
grep -qF 'NSDictionary *xrayCore = [response[@"core"] isKindOfClass:[NSDictionary class]] ? response[@"core"] : nil;' "$ctl" \
    || bad "the reader does not take the reply's \"core\" object"
for key in active_interface_name protect_bound protect_unbound protect_rejected; do
    grep -qE "\"$key\": " "$ext" || bad "the extension no longer writes $key into core"
done
grep -qF 'core["last_start_failure"] = failure' "$ext" || bad "the extension no longer writes last_start_failure into core"
for key in active_interface_name last_start_failure; do
    grep -qF "stringFromResponse(xrayCore, @\"$key\")" "$ctl" || bad "the reader does not take $key from core"
    grep -qF "stringFromResponse(response, @\"$key\")" "$ctl" && bad "the reader takes $key from the top level"
done
for key in protect_bound protect_unbound protect_rejected; do
    grep -qF "[xrayCore[@\"$key\"] longLongValue]" "$ctl" || bad "the reader does not take $key from core"
    grep -qF "[response[@\"$key\"] longLongValue]" "$ctl" && bad "the reader takes $key from the top level"
done
grep -qF 'stringFromResponse(xrayCore, @"core_log_tail")' "$ctl" && bad "core_log_tail is read from core - a logging decision of its own"
start="$(awk '/private func setupAndStartXray\(/{f=1} f{print} f&&/^    }$/{exit}' "$ext")"
run_at="$(printf '%s\n' "$start" | grep -nF 'LibXrayRunXray(' | head -1 | cut -d: -f1)"
clear_at="$(printf '%s\n' "$start" | grep -nF 'lastXrayStartFailure = nil' | head -1 | cut -d: -f1)"
ok_at="$(printf '%s\n' "$start" | awk -v from="${run_at:-0}" 'NR > from && /^            return nil$/ { print NR; exit }')"
[ -n "$run_at" ] && [ -n "$clear_at" ] && [ -n "$ok_at" ] && [ "$clear_at" -gt "$run_at" ] && [ "$clear_at" -lt "$ok_at" ] \
    || bad "the core start's success must clear the stored start failure (after LibXrayRunXray, before return nil)"
[ "$(cat "$client"/platforms/ios/*.swift | grep -cF 'lastXrayStartFailure = nil')" = "1" ] \
    || bad "only the core start's success may clear the stored start failure"
vctc="$client/core/serviceEngine/VpnConnectionTunnelControl.cpp"
[ "$(grep -rlF 'xrayStartFailed' "$client" --include=*.cpp --include=*.mm --include=*.h --include=*.qml | grep -v '/tests/' | grep -v '/3rd' | sort | tr '\n' ' ')" \
  = "$client/core/serviceEngine/VpnConnectionTunnelControl.cpp $client/platforms/ios/ios_controller.h $client/platforms/ios/ios_controller.mm " ] \
    || bad "xrayStartFailed has a new reader - check that it decides nothing on a stale failure"
[ "$(grep -cF 'm_lastXrayStartFailure' "$vctc" "$client/core/serviceEngine/VpnConnectionTunnelControl.h" | awk -F: '{ s += $2 } END { print s }')" = "2" ] \
    || bad "VpnConnectionTunnelControl reads the start failure somewhere besides the log line"
[ "$fail" = 0 ] && echo "check_xray_status_core_fields: OK"
exit "$fail"
