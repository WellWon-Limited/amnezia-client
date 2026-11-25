#!/bin/bash
# AVPN (device round air-I, 25.11): the Xray status reply nests the core's own fields in its "core" object
# (PacketTunnelProvider+Xray.swift handleXrayStatusMessage -> TunnelRuntimeStatus.payload(core:)); the app read them at
# the top level, so the interface name, the socket-protect counters and the start failure were always empty / 0. Checks
# that both sides name the same place: each key the reader takes from "core" is written into `core` by the extension and
# never read at the top level; core_log_tail stays out of the reader on purpose (ios_controller.mm says why).
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
[ "$fail" = 0 ] && echo "check_xray_status_core_fields: OK"
exit "$fail"
