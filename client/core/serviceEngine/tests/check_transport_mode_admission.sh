#!/bin/bash
# AVPN 5.1.109 (S4.1; review of d5d739403): the stored transport-mode choice comes into force only
# through ONE path of the facade, and that path asks the pure decisions first. AvpnEngineQml.cpp has
# no unit harness, so the wiring is checked at source level (as check_edge_switch_no_restart.sh):
#   1. ServiceEngine::admitTransportModeChoice() is called from syncTransportModeChoice() only, after
#      planTransportModeSync() said "admit" (at load or while idle - transportModeMayChangeNow);
#   2. the engine's setTransportMode() (choice + in force at once) is called from the tap handler only;
#   3. the macOS runtime gate is written from the constructor and from refreshXrayRuntimeGate() only,
#      and there through xrayRuntimeGateNext() (loss at once, gain only while idle);
#   4. guardedStart() admits nothing itself (the defect: the choice came into force between the tap
#      and connect());
#   5. restorePin() does not wipe a saved pin that the mode refused (a transient pool state).
# The decisions themselves: facade_policy_check; the admission: transport_pick_check §17.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../AvpnEngineQml.cpp"
fail=0

code() { grep -v '^[[:space:]]*//' "$SRC"; } # the source without full-line comments
body_of() { # $1 - the first line of a function; prints its body up to a "}" in column one
    awk -v start="$1" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$SRC" \
        | grep -v '^[[:space:]]*//' || true
}
count() { code | grep -c -- "$1" || true; }

sync_body="$(body_of 'void AvpnEngineQml::syncTransportModeChoice(')"
if [ -z "$sync_body" ]; then
    echo "FAIL: syncTransportModeChoice() not found"; fail=1
else
    if [ "$(count 'admitTransportModeChoice(')" != "1" ] \
        || ! printf '%s\n' "$sync_body" | grep -q 'admitTransportModeChoice('; then
        echo "FAIL: admitTransportModeChoice() must be called once, from syncTransportModeChoice() only"; fail=1
    fi
    plan_line="$(printf '%s\n' "$sync_body" | grep -n 'planTransportModeSync(' | head -1 | cut -d: -f1)"
    gate_line="$(printf '%s\n' "$sync_body" | grep -n 'if (!plan.admit)' | head -1 | cut -d: -f1)"
    admit_line="$(printf '%s\n' "$sync_body" | grep -n 'admitTransportModeChoice(' | head -1 | cut -d: -f1)"
    if [ -z "$plan_line" ] || [ -z "$gate_line" ] || [ -z "$admit_line" ] \
        || [ "$plan_line" -ge "$gate_line" ] || [ "$gate_line" -ge "$admit_line" ]; then
        echo "FAIL: syncTransportModeChoice() must admit only after planTransportModeSync() and 'if (!plan.admit) return'"; fail=1
    fi
    if ! printf '%s\n' "$sync_body" | grep -q 'transportModeIdle()'; then
        echo "FAIL: syncTransportModeChoice() must ask transportModeIdle()"; fail=1
    fi
fi

idle_body="$(body_of 'bool AvpnEngineQml::transportModeIdle(')"
if ! printf '%s\n' "$idle_body" | grep -q 'transportModeMayChangeNow('; then
    echo "FAIL: transportModeIdle() must decide through transportModeMayChangeNow()"; fail=1
fi

tap_body="$(body_of 'void AvpnEngineQml::setTransportMode(')"
if [ "$(count 'm_engine.setTransportMode(')" != "1" ] \
    || ! printf '%s\n' "$tap_body" | grep -q 'm_engine.setTransportMode('; then
    echo "FAIL: m_engine.setTransportMode() must be called once, from the tap handler setTransportMode() only"; fail=1
fi

gate_body="$(body_of 'bool AvpnEngineQml::refreshXrayRuntimeGate(')"
if [ -z "$gate_body" ] || ! printf '%s\n' "$gate_body" | grep -q 'xrayRuntimeGateNext('; then
    echo "FAIL: refreshXrayRuntimeGate() must decide through xrayRuntimeGateNext()"; fail=1
fi
if [ "$(count 'xrayPlatformRuntimeReady().store(')" != "2" ] \
    || ! printf '%s\n' "$gate_body" | grep -q 'xrayPlatformRuntimeReady().store('; then
    echo "FAIL: the runtime gate must be written from the constructor and refreshXrayRuntimeGate() only"; fail=1
fi
if code | grep -q 'xrayPlatformRuntimeReady().exchange('; then
    echo "FAIL: the runtime gate must not be exchanged directly (gain is allowed only while idle)"; fail=1
fi

start_body="$(body_of 'void AvpnEngineQml::guardedStart()')"
if [ -z "$start_body" ]; then
    echo "FAIL: guardedStart() not found"; fail=1
elif printf '%s\n' "$start_body" | grep -Eq 'syncTransportModeChoice\(|admitTransportModeChoice\(|setTransportModeChoice\(|m_engine\.setTransportMode\(|syncTransportAvailabilityWhileIdle\('; then
    echo "FAIL: guardedStart() must not bring a transport mode into force (between the tap and connect()):"
    printf '%s\n' "$start_body" | grep -n -E 'syncTransportModeChoice\(|admitTransportModeChoice\(|setTransportModeChoice\(|m_engine\.setTransportMode\(|syncTransportAvailabilityWhileIdle\('
    fail=1
fi

pin_body="$(body_of 'void AvpnEngineQml::restorePin(const QString &pinBefore)')"
if [ -z "$pin_body" ]; then
    echo "FAIL: restorePin() not found"; fail=1
elif printf '%s\n' "$pin_body" | grep -q 'no_transport\|savedPinRefusedByMode'; then
    echo "FAIL: restorePin() must not wipe a saved pin the mode refused (transient pool state)"; fail=1
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "check_transport_mode_admission: ok"
