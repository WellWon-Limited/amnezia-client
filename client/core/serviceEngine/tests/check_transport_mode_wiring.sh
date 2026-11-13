#!/bin/bash
# AVPN 5.1.109 (S4.1; reviews of d5d739403 and 3dbe0361f): the facade forwards its events to the
# transport-mode gate at exactly these places and applies what comes back.
#
# The RULE - when the stored choice is in force, what happens to the pin, what an adopted session
# keeps, the macOS runtime gate, the legacy value - is TransportModeGate.h and is tested by behaviour:
# transport_mode_gate_check (the gate alone) and transport_pick_check §17 (on a real engine, with the
# pin and the sessions the engine adopts). AvpnEngineQml.cpp has no unit harness, so what is left in
# it - the forwarding - is checked here at source level, and only that:
#   1. the stored choice is loaded once, in the constructor, BEFORE the pin is restored;
#   2. the gate is told "something changed" from one function (syncTransportMode) with the one
#      snapshot (modeActivity), and that function is called on every changed(), when a config is
#      applied, on a return to the screen and when the macOS runtime gate moves;
#   3. the snapshot carries every field the gate judges "nothing is running" by;
#   4. the outcome is applied in one function: journal, stored value, a pin stored cleared;
#   5. the tap goes through the gate; the facade never sets the engine's mode itself;
#   6. the macOS runtime gate is written from the constructor and refreshXrayRuntimeGate() only, and
#      there by the gate's decision; every way the daemon probe ends reports the startup observation;
#   7. guardedStart() brings no mode into force itself;
#   8. restorePin() does not wipe a saved pin the mode refused.
# Run by build_check.sh.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../AvpnEngineQml.cpp"
HDR="$HERE/../AvpnEngineQml.h"
fail=0
bad() { echo "FAIL: $1"; fail=1; }

code() { grep -v '^[[:space:]]*//' "$SRC"; } # the source without full-line comments
body_of() { # $1 - the first line of a function; prints its body up to a "}" in column one
    awk -v start="$1" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$SRC" \
        | grep -v '^[[:space:]]*//' || true
}
count() { code | grep -c -- "$1" || true; }
line_of() { grep -n -- "$1" "$SRC" | grep -v '^[0-9]*:[[:space:]]*//' | head -1 | cut -d: -f1; }
has() { printf '%s\n' "$1" | grep -q -- "$2"; }

# 1. the load, before the pin
load_line="$(line_of 'm_engine.loadTransportModeChoice(')"
saved_line="$(line_of 'm_savedPin = s.value(QStringLiteral("avpn/pinnedNode"))')"
[ "$(count 'm_engine.loadTransportModeChoice(')" = "1" ] || bad "the stored choice must be loaded once (m_engine.loadTransportModeChoice)"
if [ -z "$load_line" ] || [ -z "$saved_line" ] || [ "$load_line" -ge "$saved_line" ]; then
    bad "the stored choice must be loaded BEFORE the saved pin is read and restored (a refused pin stays saved)"
else
    restore_line="$(awk -v from="$saved_line" 'NR > from && /^[[:space:]]*restorePin\(\);/ { print NR; exit }' "$SRC")"
    [ -n "$restore_line" ] && [ "$((restore_line - saved_line))" -le 3 ] \
        || bad "restorePin() must follow the load of the saved pin in the constructor"
fi
ctor_body="$(body_of 'AvpnEngineQml::AvpnEngineQml(')"
has "$ctor_body" 'm_engine.loadTransportModeChoice(' || bad "the stored choice must be loaded in the constructor"
has "$ctor_body" 'avpn/transportModeByChoice' || bad "the constructor must read the marker avpn/transportModeByChoice"

# 2. one forwarding function and its call sites
sync_body="$(body_of 'void AvpnEngineQml::syncTransportMode(')"
[ "$(count 'm_engine.noteModeActivity(')" = "1" ] && has "$sync_body" 'applyModeChange(m_engine.noteModeActivity(modeActivity(), why))' \
    || bad "syncTransportMode() must be the one place that tells the gate: applyModeChange(m_engine.noteModeActivity(modeActivity(), why))"
[ "$(count 'connect(this, &AvpnEngineQml::changed, this, &AvpnEngineQml::syncTransportModeIdle)')" = "1" ] \
    && has "$ctor_body" 'connect(this, &AvpnEngineQml::changed, this, &AvpnEngineQml::syncTransportModeIdle)' \
    || bad "every changed() must reach the gate: connect(changed -> syncTransportModeIdle) in the constructor"
grep -q 'void syncTransportModeIdle() { syncTransportMode(QStringLiteral("idle")); }' "$HDR" \
    || bad "syncTransportModeIdle() must forward to syncTransportMode(\"idle\")"
cfg_line="$(line_of 'syncTransportMode(QStringLiteral("config"))')"
cfg_from="$(line_of 'connect(m_configSvc, &avpn::ConfigService::configApplied')"
cfg_to="$(line_of 'connect(m_configSvc, &avpn::ConfigService::activeEdgeChanged')"
if [ -z "$cfg_line" ] || [ -z "$cfg_from" ] || [ -z "$cfg_to" ] || [ "$cfg_line" -le "$cfg_from" ] || [ "$cfg_line" -ge "$cfg_to" ]; then
    bad "an applied config must reach the gate: syncTransportMode(\"config\") inside the configApplied handler"
fi
[ "$(count 'syncTransportMode(QStringLiteral("config"))')" = "1" ] || bad "syncTransportMode(\"config\") must have one call site"
fg_body="$(body_of 'void AvpnEngineQml::onForegroundDebounced()')"
has "$fg_body" 'syncTransportMode(QStringLiteral("foreground"))' || bad "a return to the screen must reach the gate (onForegroundDebounced)"
has "$fg_body" 'refreshXrayRuntimeGate(QStringLiteral("foreground"))' || bad "a return to the screen must look at the macOS runtime gate"

# 3. the snapshot
act_body="$(body_of 'avpn::ModeActivity AvpnEngineQml::modeActivity() const')"
for field in 'a.wantConnected = m_wantConnected;' 'a.operationInFlight = m_op != Op::None || m_opInFlight;' \
    'a.operationInFlight = a.operationInFlight || m_svcInstallInFlight;' \
    'a.preparingStart = m_preparingStart || m_startPrepared;' 'a.paused = m_paused;' \
    'a.tunnel = modeTunnelOf(observedTunnelOf(m_lastTunnelState), m_latch);'; do
    has "$act_body" "$field" || bad "modeActivity() must carry: $field"
done

# 4. the outcome
apply_body="$(body_of 'void AvpnEngineQml::applyModeChange(')"
has "$apply_body" 'm_engine.takeModeJournal()' && has "$apply_body" 'reliabilityEvent(line)' \
    || bad "applyModeChange() must write the gate's journal lines"
printf '%s\n' "$apply_body" | grep -A1 'if (!c.pinCleared.isEmpty())' | grep -q 'persistPin();' \
    || bad "applyModeChange() must store a pin the gate cleared (and only that one)"
[ "$(printf '%s\n' "$apply_body" | grep -c 'persistPin();')" = "1" ] || bad "applyModeChange() must not store an un-applied pin"
has "$apply_body" 'if (c.storeChoice)' && has "$apply_body" 'avpn/transportModeByChoice' \
    || bad "applyModeChange() must rewrite the stored value with its marker when asked"
has "$apply_body" 'if (c.idleEntered)' || bad "applyModeChange() must look at the macOS runtime gate when nothing is running any more"
has "$apply_body" 'emit changed();' || bad "applyModeChange() must tell the UI"

# 5. the tap
tap_body="$(body_of 'void AvpnEngineQml::setTransportMode(')"
[ "$(count 'm_engine.tapTransportMode(')" = "1" ] && has "$tap_body" 'm_engine.tapTransportMode(m)' \
    || bad "the tap handler must go through the gate (m_engine.tapTransportMode), once"
has "$tap_body" 'if (tap.refused)' && has "$tap_body" 'if (tap.noop)' || bad "the tap handler must honour refused / noop"
has "$tap_body" 'avpn/transportModeByChoice' || bad "the tap handler must store the marker next to the choice"
[ "$(count 'm_engine.setTransportMode(')" = "0" ] || bad "the facade must not set the engine's mode itself"

# 6. the macOS runtime gate and the startup observation
gate_body="$(body_of 'bool AvpnEngineQml::refreshXrayRuntimeGate(')"
[ "$(count 'm_engine.nextXrayRuntimeGate(')" = "1" ] \
    && has "$gate_body" 'm_engine.nextXrayRuntimeGate(readyNow, avpn::macXrayRuntimePresent(), modeActivity())' \
    || bad "refreshXrayRuntimeGate() must decide by the gate with the facade's snapshot"
has "$gate_body" 'syncTransportMode(why)' || bad "refreshXrayRuntimeGate() must tell the gate that availability changed"
[ "$(count 'xrayPlatformRuntimeReady().store(')" = "2" ] && has "$gate_body" 'xrayPlatformRuntimeReady().store(next)' \
    || bad "the runtime gate must be written from the constructor and refreshXrayRuntimeGate() only"
if code | grep -q 'xrayPlatformRuntimeReady().exchange('; then bad "the runtime gate must not be exchanged directly"; fi
grep -q 'void noteStartupTunnelObserved() { applyModeChange(m_engine.noteStartupObserved(modeActivity())); }' "$HDR" \
    || bad "noteStartupTunnelObserved() must forward to the gate"
probe_body="$(body_of 'void AvpnEngineQml::probeDaemonTunnelOnStartup()')"
[ "$(printf '%s\n' "$probe_body" | grep -c 'noteStartupTunnelObserved();')" = "5" ] \
    || bad "every way the daemon probe ends must report the startup observation (2 early returns, the answer, the error, the timeout)"
[ "$(count 'noteStartupTunnelObserved();')" = "6" ] \
    || bad "noteStartupTunnelObserved() call sites: the daemon probe (5) and the m_daemonProbed moment (1)"
code | grep -B2 -A2 'm_daemonProbed = true;' | grep -q 'noteStartupTunnelObserved();' \
    || bad "the m_daemonProbed moment must report the startup observation (the backstop)"

# 7. the start
start_body="$(body_of 'void AvpnEngineQml::guardedStart()')"
if [ -z "$start_body" ]; then
    bad "guardedStart() not found"
elif printf '%s\n' "$start_body" | grep -Eq 'syncTransportMode\(|applyModeChange\(|tapTransportMode\(|noteStartupTunnelObserved\(|loadTransportModeChoice\('; then
    bad "guardedStart() must not bring a transport mode into force itself (between the tap and connect())"
fi

# 8. the pin
pin_body="$(body_of 'void AvpnEngineQml::restorePin(const QString &pinBefore)')"
if [ -z "$pin_body" ]; then
    bad "restorePin() not found"
elif printf '%s\n' "$pin_body" | grep -q 'no_transport\|savedPinRefusedByMode'; then
    bad "restorePin() must not wipe a saved pin the mode refused (transient pool state)"
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "check_transport_mode_wiring: ok"
