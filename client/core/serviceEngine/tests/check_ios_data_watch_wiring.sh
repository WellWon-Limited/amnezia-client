#!/bin/bash
# AVPN build 141 (iOS tunnel-side data watch, design docs/specs/2026-11-14-ios-tunnel-side-data-watch-
# design.md in the backend repository, sections 0 and 0a): the wiring that unit tests cannot reach.
#
# The RULES are pure and tested by behaviour: the verdict (recipes/awg-apple/tribe/TribeDataWatch.swift,
# tests/TribeDataWatchTests.swift, tests/TribeDataWatchLadderTests.swift + the mutation run in
# recipes/awg-apple/replay), the probe (tribeprobe_test.go in patch 0012), the plan and the bypass reply
# (platforms/ios/tests/TribeWatchPlanTests.swift), the provider's runtime with fakes (platforms/ios/tests/
# TribeDataWatchRuntimeTests.swift: the kill switch, the status reply, the probe's outcomes, the state
# file), the app's half (tests/tunnel_watch_check.cpp: the plan write, the hand-over object with the
# freeze, the background hold, the deferred decisions and the re-check; platforms/ios/tests/
# IosDataWatchTests.cpp; the controller harness). What is left is where they are CALLED FROM, and only
# what no test of those reaches: the adapter patch, the provider's call sites, the facade's call sites.
#   extension
#    E1. the adapter feeds the watch from the EXISTING stall tick, before the ladder acts, and the patch
#        adds no timer;
#    E2. with the policy off every hook in the adapter is a no-op;
#    E3. the probe wrapper is the outermost one and is not created unless configured;
#    E4. the provider prepares the runtime before the adapter starts, attaches and detaches it, marks the
#        app alive on a status request and adds the `watch` key only when there is a block;
#    E5. the statistics tick is the runtime's (plan first, with the log on or off); neither the runtime
#        nor the rule has a timer; the bypass request is bound to the physical interface; nothing
#        notifies the user;
#    E6. who may move the tunnel (stage 2): only the rule's arbiter orders, only the adapter executes, in
#        one place, through the tested sequence and the shared budget; a switch that leaves no engine is
#        told and retried on the same tick; the start goes by the start source the app really passes;
#        the engine stop of a switch is announced through the backend hook of patch 0015 (the Scanner's
#        probe sessions end first), and a provider node is never a candidate;
#    E7. the package: tribe.14 = tribe.12 + 0012 (the Go half, in its slot) + 0016 (the adapter half,
#        after 0015), the patches of tribe.12 in between untouched in number and order; both extension
#        targets compile the new sources;
#    E8. the Xray statistics line is written only through the statistics tick;
#   app
#    A1. every new call in the facade is inside a Q_OS_IOS block;
#    A2. the flags are read with the default false;
#    A3. the plan is rewritten at the listed moments, through the one tested write;
#    A4. the `watch` block reaches the facade only for the reply that was applied;
#    A5. the hand-over is consulted before the health verdict and before a data check completes;
#    A6. the new code has no timer, watchdog or user notification;
#    A7. the tunnel-restart guard keeps its own two calls; the arming holds under its own reason and
#        asks the system itself whether the app is on the screen;
#    A8. the effects handed to the hand-over never touch the pin, the intent or the "data proven" marks;
#    A9. the engine's way back to Verifying is called from one place;
#    A10. stage 2 in the app: candidates only with both flags, one entry point for an adopted switch
#        (from any status reply), the way back and the engine-down restart go through the ordinary restart;
#    X1. the numbers the extension reads and their bounds are those of the app's table;
#    X2. the extension's built-in bypass targets are the white-list detector's own defaults.
# Run by build_check.sh.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
ENGINE="$HERE/.."
IOS="$ROOT/client/platforms/ios"
RECIPE="$ROOT/recipes/awg-apple"
# The data watch is two patches of the package (conandata.yml says why): 0012, the Go half, in the slot
# tribe.12 left for it, and 0016, the adapter half, after the Scanner's 0015. The checks below read
# them as one text.
PATCH_GO="$RECIPE/patches/0012-tribe-data-watch.patch"
PATCH_ADAPTER="$RECIPE/patches/0016-tribe-data-watch-adapter.patch"
PATCH="$(mktemp "${TMPDIR:-/tmp}/tribe-data-watch-wiring.XXXXXX")"
trap 'rm -f "${PATCH:?}"' EXIT
cat "$PATCH_GO" "$PATCH_ADAPTER" > "$PATCH"
FACADE="$ENGINE/AvpnEngineQml.cpp"
CONTROLLER="$IOS/ios_controller.mm"
fail=0
bad() { echo "FAIL: $1"; fail=1; }

code() { grep -v '^[[:space:]]*//' "$1" || true; }             # a file without full-line comments
count() { code "$1" | grep -c -- "$2" || true; }
has() { printf '%s\n' "$1" | grep -- "$2" > /dev/null; } # not -q: grep leaving early breaks printf's pipe on a long text
order() { # $1 text, $2 first pattern, $3 second pattern: 0 when both occur and the first comes first
    local a b
    a="$(printf '%s\n' "$1" | grep -n -- "$2" | head -1 | cut -d: -f1)"
    b="$(printf '%s\n' "$1" | grep -n -- "$3" | head -1 | cut -d: -f1)"
    [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}
body_of() { # $1 file, $2 the first line of a function; its body up to a "}" in column one, no comments
    awk -v start="$2" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$1" \
        | grep -v '^[[:space:]]*//' || true
}
swift_func() { # $1 file, $2 text of the func line; the lines up to the next line that closes at the same indent
    awk -v start="$2" '
        !on && index($0, start) { on = 1; match($0, /^[[:space:]]*/); indent = RLENGTH }
        on { print }
        on && NR > first && match($0, /^[[:space:]]*}/) && RLENGTH == indent + 1 { exit }
        on && !first { first = NR }' "$1" | grep -v '^[[:space:]]*//' || true
}
added() { grep '^+' "$PATCH" | grep -v '^+++' || true; }        # what patches 0012 and 0016 add
added_swift() { # the added lines of the adapter only
    awk '/^diff --git/ { on = ($0 ~ /WireGuardAdapter\.swift/) } on && /^\+/ && !/^\+\+\+/ { print substr($0, 2) }' "$PATCH" \
        | grep -v '^[[:space:]]*//' || true
}

# ---- E1: one owner, the existing tick -------------------------------------------------------------
swift_added="$(added_swift)"
[ "$(printf '%s\n' "$swift_added" | grep -c 'self.dataWatchTick(sample, handle: handle')" = "1" ] \
    || bad "E1: the adapter must feed the data watch from exactly one place"
tick_ctx="$(grep -n -A5 'if self.dataWatchTick(sample, handle: handle, settingsGenerator: settingsGenerator) { return }' "$PATCH" | head -6)"
has "$tick_ctx" 'self.recovery.tick(sample, pathSatisfied' \
    || bad "E1: the data watch must be fed on the stall tick, right before the recovery ladder judges the same sample; a tick on which the watch acted is not judged by the ladder as well"
# Second review, R6: one owner of recovery while the arbiter treats or leaves a node - the ladder's own
# steps would spend the shared budget the switch needs (that the property is false with the switch key
# off is tested: TribeDataWatchTests keys_off_the_arbiter_never_owns_recovery).
order "$tick_ctx" 'if self.dataWatch.arbiterOwnsRecovery { return }' 'self.recovery.tick(sample, pathSatisfied' \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'arbiterOwnsRecovery')" = "1" ] \
    || bad "E1: while the arbiter owns the recovery the ladder must not judge the same samples (one place, right before the ladder)"
for token in 'makeTimerSource' 'asyncAfter' 'Timer(' 'scheduledTimer' 'DispatchWorkItem'; do
    has "$swift_added" "$token" && bad "E1: the data watch adds a timer or a delayed block to the adapter ($token)"
done

# ---- E2: off = tribe.12 ------------------------------------------------------------------------------
tick_body="$(printf '%s\n' "$swift_added" | awk '/private func dataWatchTick/ { on = 1 } on { print } on && /^    }$/ { exit }')"
order "$tick_body" 'guard self.dataWatchPolicy.enabled else' 'self.dataWatch.step(' \
    || bad "E2: dataWatchTick must leave before the step when the policy is off"
has "$tick_body" 'self.dataWatchInputs?(handle)' && order "$tick_body" 'guard self.dataWatchPolicy.enabled else' 'self.dataWatchInputs?(handle)' \
    || bad "E2: the provider's inputs must not be asked for while the policy is off"
path_body="$(printf '%s\n' "$swift_added" | awk '/private func dataWatchPathEvent/ { on = 1 } on { print } on && /^    }$/ { exit }')"
order "$path_body" 'guard self.dataWatchPolicy.enabled else { return }' 'self.dataWatch.notePathEvent(' \
    || bad "E2: a path event must not reach a switched-off watch"
# Every note to the watch about a (re)started device is under the policy flag: on the same line or on
# the line above. Two of each: the start and the engine brought back after a failed switch; the ladder's
# in-place restart and the switch that came back to the previous node.
unguarded="$(printf '%s\n' "$swift_added" | awk '
    /self\.dataWatch\.note(DeviceStarted|BackendRestarted)\(/ && !/self\.dataWatchPolicy\.enabled/ && prev !~ /if self\.dataWatchPolicy\.enabled \{$/ { print }
    { prev = $0 }')"
[ -z "$unguarded" ] \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'self.dataWatch.noteDeviceStarted(')" = "2" ] \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'self.dataWatch.noteBackendRestarted(')" = "2" ] \
    || bad "E2: the device-start and backend-restart notes must be under the policy flag"
has "$swift_added" 'private var dataWatchPolicy = TribeDataWatchPolicy.disabled' \
    || bad "E2: the adapter's policy must start disabled"
has "$swift_added" 'dataWatchHealSteps\|healSteps' && bad "E2: the adapter must not count the ladder's steps for the watch (the verdict does not depend on them)"

# ---- E3: the probe wrapper ---------------------------------------------------------------------------
go_added="$(awk '/^diff --git/ { on = ($0 ~ /api-apple\.go/) } on && /^[+ ]/ { print substr($0, 2) }' "$PATCH")"
order "$go_added" 'wrapDirectSplitIfEnabled(tun' 'wrapTribeProbeIfEnabled(tun' \
    || bad "E3: the probe wrapper must wrap the direct-split wrapper (outermost)"
probe_go="$(awk '/^diff --git/ { on = ($0 ~ /tribeprobe\.go/) } on && /^\+/ && !/^\+\+\+/ { print substr($0, 2) }' "$PATCH")"
wrap_body="$(printf '%s\n' "$probe_go" | awk '/^func wrapTribeProbeIfEnabled/ { on = 1 } on { print } on && /^}/ { exit }')"
order "$wrap_body" 'if tribeProbeCfg == nil {' 'return inner' \
    || bad "E3: without a configuration the device must get the inner tun itself"
order "$wrap_body" 'return inner' 'tribeProbeTunDev{' \
    || bad "E3: the wrapper must not be created before the configuration check"

# ---- E4: the provider --------------------------------------------------------------------------------
WG="$IOS/PacketTunnelProvider+WireGuard.swift"
start_body="$(swift_func "$WG" 'func startWireguard(')"
order "$start_body" 'prepareTribeDataWatch(wgConfig)' 'adapter.start(tunnelConfiguration' \
    || bad "E4: the probe must be configured before the adapter starts (the device wraps the tunnel at wgTurnOn)"
order "$start_body" 'tribeDataWatch.attach(adapter: adapter)' 'adapter.start(tunnelConfiguration' \
    || bad "E4: the runtime must be attached before the adapter starts"
[ "$(cat "$IOS"/*.swift | grep -v '^[[:space:]]*//' | grep -c 'wgSetTribeProbe(')" = "1" ] \
    || bad "E4: the probe must be configured from one place"
glue="$(code "$IOS/PacketTunnelProvider+DataWatch.swift")"
has "$glue" 'setProbe: { clientIP, resolver, enabled in wgSetTribeProbe(clientIP, resolver, enabled ? 1 : 0) }' \
    || bad "E4: the runtime's setProbe must be the Go call, with the runtime's own on/off"
has "$glue" 'clientIP: wgConfig.clientIP, resolver: wgConfig.dns1,' \
    || bad "E4: the probe goes from the client's tunnel address to the session's resolver"
order "$(swift_func "$IOS/PacketTunnelProvider+DataWatch.swift" 'func prepareTribeDataWatch(')" 'tribeDataWatch.configure(tribeDataWatchDeps())' 'tribeDataWatch.prepare(' \
    || bad "E4: the runtime must get its dependencies before it prepares a session"
status_body="$(swift_func "$WG" 'func handleWireguardStatusMessage(')"
has "$status_body" 'tribeDataWatch.noteAppStatusRequest()' || bad "E4: a status request must mark the app alive"
has "$status_body" 'if let watch { response\["watch"\] = watch }' \
    || bad "E4: the watch key must be added only when the runtime returned a block"
[ "$(count "$WG" 'response\["watch"\]')" = "1" ] || bad "E4: the watch key must be set in one place"
stop_body="$(swift_func "$WG" 'func stopWireguard(')"
has "$stop_body" 'tribeDataWatch.detach()' || bad "E4: the runtime must be detached on stop"
runtime="$(code "$IOS/TribeDataWatchRuntime.swift")"
block_body="$(swift_func "$IOS/TribeDataWatchRuntime.swift" 'func statusBlock(')"
order "$block_body" 'guard enabled, let live else { completion(nil); return }' 'live.dataWatchSnapshot' \
    || bad "E4: with the watch off the status reply must get no block at all"

# ---- E5: no timer, the bypass, no notifications --------------------------------------------------------
stats_body="$(swift_func "$WG" 'private func logTribeStats(')"
has "$stats_body" 'tribeDataWatch.statsTick(isXray: protoType == .xray, loggingEnabled: Log.isLoggingEnabled,' \
    || bad "E5: the statistics tick must be the runtime's sequence (plan first, with the log on or off - tested there)"
has "$stats_body" 'guard Log.isLoggingEnabled' && bad "E5: the provider must not gate the statistics tick on the file log itself"
[ "$(cat "$IOS"/*.swift | grep -v '^[[:space:]]*//' | grep -c 'statsTick(')" = "2" ] \
    || bad "E5: the statistics tick has exactly one caller besides its definition"
for token in 'makeTimerSource' 'scheduledTimer' 'Timer(' 'DispatchSourceTimer' 'CADisplayLink'; do
    for f in TribeDataWatchRuntime.swift TribeWatchPlan.swift PacketTunnelProvider+DataWatch.swift; do
        has "$(code "$IOS/$f")" "$token" && bad "E5: $f has a timer of its own ($token)"
    done
    has "$(code "$RECIPE/tribe/TribeDataWatch.swift")" "$token" && bad "E5: the pure rule has a timer ($token)"
done
[ "$(printf '%s\n' "$runtime" | grep -c 'asyncAfter')" = "1" ] \
    || bad "E5: the only delayed block of the runtime is the deadline of one bypass request"
has "$runtime" 'parameters.requiredInterface = interface' \
    || bad "E5: the bypass request must be bound to the physical interface"
has "$runtime" 'URLSession' && bad "E5: the bypass request must not use URLSession (it cannot be bound to an interface)"
for f in "$IOS"/TribeDataWatchRuntime.swift "$IOS"/TribeWatchPlan.swift "$IOS/PacketTunnelProvider+DataWatch.swift" \
         "$IOS/PacketTunnelProvider+WireGuard.swift" "$RECIPE/tribe/TribeDataWatch.swift" \
         "$ENGINE/TunnelWatchPlan.h" "$ENGINE/TunnelWatchStatus.h" "$IOS/BackgroundHoldBook.h" "$IOS/IosBackgroundArm.h"; do
    grep -q 'UNUserNotificationCenter\|UserNotifications\|UNMutableNotificationContent\|displayMessage' "$f" \
        && bad "E5/A6: $(basename "$f") notifies the user - the owner's decision is no notifications at all"
done
has "$(added)" 'UNUserNotificationCenter' && bad "E5: the data watch's patches notify the user"

# ---- E6: who may move the tunnel (stage 2) ---------------------------------------------------------------
# Only the rule's arbiter orders, only behind its own key; only the adapter executes, in one place, in
# the tested order; the runtime and the provider glue never touch the tunnel themselves.
rule="$(code "$RECIPE/tribe/TribeDataWatch.swift")"
[ "$(printf '%s\n' "$rule" | grep -c 'if !policy.switchEnabled || policy.maxSwitches == 0 || appAlive {')" = "1" ] \
    || bad "E6: the arbiter must be gated by the switch key, the switch budget and the living app, in one place"
[ "$(printf '%s\n' "$rule" | grep -c 'arbiterCommand(now: now, env: env, policy: policy, canSwitch: canSwitch)')" = "1" ] \
    || bad "E6: the arbiter must be asked from one place"
arb="$(swift_func "$RECIPE/tribe/TribeDataWatch.swift" 'private mutating func arbiterCommand(')"
[ "$(printf '%s\n' "$rule" | grep -c 'return (\.switchPeer(\|return (\.heal(')" = "$(printf '%s\n' "$arb" | grep -c 'return (\.switchPeer(\|return (\.heal(')" ] \
    || bad "E6: a command may be produced only by arbiterCommand"
[ "$(printf '%s\n' "$swift_added" | grep -c 'self.performDataWatchCommand(')" = "1" ] \
    || bad "E6: the adapter must execute a command of the watch from exactly one place"
order "$swift_added" 'if let command = output.command {' 'self.performDataWatchCommand(' \
    || bad "E6: the adapter may act only on a command the rule returned"
[ "$(printf '%s\n' "$swift_added" | grep -c 'self.switchBackend(handle: handle, from: settingsGenerator, to: configuration)')" = "1" ] \
    || bad "E6: the peer may be replaced from exactly one place"
has "$swift_added" 'guard let configuration = self.dataWatchCandidate?(nodeId) else { return .rejected }' \
    || bad "E6: a node the provider has no usable configuration for must be rejected (never asked again while the plan lives)"
# Second review, R6: a switch goes through the shared recovery budget, after the configuration is known
# (a refused budget is 'denied' - asked again; nothing was spent for a node that cannot be raised).
has "$swift_added" 'guard self.recovery.requestPeerSwitch(sample, pathSatisfied: self.lastPathSatisfiable) == .performed else { return .denied }' \
    && order "$swift_added" 'self.dataWatchCandidate?(nodeId)' 'self.recovery.requestPeerSwitch(' \
    && order "$swift_added" 'self.recovery.requestPeerSwitch(' 'return self.switchBackend(handle: handle, from: settingsGenerator, to: configuration)' \
    || bad "E6: a switch must ask the shared recovery budget, after the candidate's configuration and before the tunnel is touched"
has "$(swift_func "$RECIPE/tribe/TribeRoaming.swift" 'mutating func requestPeerSwitch(')" 'if let denial = budget.request(at: sample.at, kind: .softRestart, persistent: true) { return .budget(denial) }' \
    || bad "E6: the switch must be charged to the ladder's own budget as a new device (rolling cap and cooldown)"
# Second review, R5: the order of a switch and every way it can fail are TribeSwitchSequence (pure, tested
# with a fake engine: TribeDataWatchTests switch_sequence_every_way_it_can_fail). Here: the adapter runs
# that sequence once, hands it the real effects in the right slots, and returns ITS verdict.
sw="$(printf '%s\n' "$swift_added" | awk '/private func switchBackend\(/ { on = 1 } on { print } on && /^    }$/ { exit }')"
[ "$(printf '%s\n' "$swift_added" | grep -c 'TribeSwitchSequence.run(')" = "1" ] && has "$sw" 'let outcome = TribeSwitchSequence.run(TribeSwitchSteps(' \
    || bad "E6: the switch must be the tested sequence, run from one place"
order "$sw" 'prepare: {' 'newGenerator = try? self.makeSettingsGenerator(with: tunnelConfiguration)' \
    && order "$sw" 'newGenerator = try? self.makeSettingsGenerator(with: tunnelConfiguration)' 'stopEngine: {' \
    || bad "E6: 'prepare' must resolve the new endpoint (while the old backend still runs)"
order "$sw" 'stopEngine: {' 'wgTurnOff(handle)' && order "$sw" 'wgTurnOff(handle)' 'applySettings: { new in' \
    || bad "E6: 'stopEngine' must turn the old backend off"
order "$sw" 'applySettings: { new in' 'return self.applySettingsConfirmed(generator.generateNetworkSettings())' \
    && order "$sw" 'return self.applySettingsConfirmed(generator.generateNetworkSettings())' 'startEngine: { new in' \
    || bad "E6: 'applySettings' must apply the settings and wait for the system's confirmation"
order "$sw" 'startEngine: { new in' 'self.startBackendForSwitch(generator)' \
    || bad "E6: 'startEngine' must start a backend with the configuration it was asked for"
[ "$(printf '%s\n' "$sw" | grep -c 'guard let generator = new ? newGenerator : oldGenerator')" = "2" ] \
    || bad "E6: both steps must take the configuration the sequence names (new or previous)"
has "$sw" 'self.packetTunnelProvider?.reasserting = true' && has "$sw" 'defer { self.packetTunnelProvider?.reasserting = false }' \
    || bad "E6: the switch must be announced to the system as a reconnect and the mark taken back"
has "$sw" 'return outcome.result' && ! has "$sw" 'return \.performed' && ! has "$sw" 'return \.failed' \
    || bad "E6: the adapter must return the sequence's own verdict (never 'performed' by itself)"
order "$sw" '} else if !outcome.engineUp {' 'self.state = .temporaryShutdown(oldGenerator)' \
    && order "$sw" 'self.state = .temporaryShutdown(oldGenerator)' 'self.dataWatchEngineDown = (oldGenerator, outcome.settingsInForce, TribeEngineRetry(at: now))' \
    && order "$sw" 'self.dataWatchEngineDown = (oldGenerator' 'self.dataWatchEngineHandler?(true)' \
    || bad "E6: a switch that left no engine must say so and arm the retry of the previous configuration"
confirm="$(printf '%s\n' "$swift_added" | awk '/private func applySettingsConfirmed\(/ { on = 1 } on { print } on && /^    }$/ { exit }')"
has "$confirm" 'guard done, systemError == nil else {' && order "$confirm" 'guard done, systemError == nil else {' 'return true' \
    || bad "E6: network settings count as applied only when the system confirmed them without an error (no answer = failure)"
[ "$(printf '%s\n' "$swift_added" | grep -c 'wgTurnOff(')" = "1" ] && [ "$(printf '%s\n' "$swift_added" | grep -c 'setNetworkSettings(')" = "0" ] \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'setTunnelNetworkSettings(')" = "1" ] \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'self.applySettingsConfirmed(')" = "2" ] \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'self.startBackendForSwitch(')" = "2" ] \
    || bad "E6: the data watch stops a backend only inside the switch and applies settings / starts a backend only in the switch and in the retry"
# Merged with the Scanner (tribe.14): that one stop is announced through the adapter's backend hook of
# patch 0015, with the reason the provider acts on (.restart: its probe sessions end first; .rebind
# keeps them). The same line is what tests/check_backend_hook.sh of the package gate requires of the
# fully patched adapter; the order hook -> stop -> settings -> engine is TribeDataWatchLadderTests 14.
[ "$(printf '%s\n' "$sw" | grep -c 'TribeBackendHook.before(.restart, self.tribeBackendWillRestart) { wgTurnOff(handle) }')" = "1" ] \
    && [ "$(printf '%s\n' "$swift_added" | grep 'wgTurnOff(\|wgBumpSockets(\|wgSetConfig(' | grep -vc 'TribeBackendHook.before(.restart, self.tribeBackendWillRestart)')" = "0" ] \
    && order "$sw" 'self.packetTunnelProvider?.reasserting = true' 'TribeBackendHook.before(.restart, self.tribeBackendWillRestart) { wgTurnOff(handle) }' \
    || bad "E6: the engine stop of a switch must run through TribeBackendHook.before(.restart, ...) (the Scanner's probes end before the peer changes)"
# ... and it is the only announcement the data watch makes: one more would end scans for nothing.
[ "$(printf '%s\n' "$swift_added" | grep -c 'TribeBackendHook\|tribeBackendWillRestart')" = "1" ] \
    || bad "E6: the data watch announces a backend restart in one place only (the engine stop of a switch)"
grep -q '"tribe_backend_hook": True' "$RECIPE/conanfile.py" && grep -q '_xray_pins\["3.1.4-tribe.14"\] = _xray_pins\["3.1.4-tribe.12"\]' "$RECIPE/conanfile.py" \
    && grep -q 'check_backend_hook.sh' "$RECIPE/conanfile.py" \
    || bad "E6: the package of the data watch must be gated on the backend-hook structure check (tribe.14 keeps the pins of tribe.12)"
# The tick keeps running in every outcome: with no engine it retries, before anything asks for a handle.
has "$(grep -A1 '     private func stallTick() {' "$PATCH")" '+        if self.dataWatchEngineDown != nil { self.dataWatchRetryEngine(); return }' \
    || bad "E6: with no engine the stall tick must retry first (it must not leave on the missing handle)"
retry="$(printf '%s\n' "$swift_added" | awk '/private func dataWatchRetryEngine\(/ { on = 1 } on { print } on && /^    }$/ { exit }')"
order "$retry" 'guard self.lastPathSatisfiable, down.retry.due(at: now) else { return }' 'self.startBackendForSwitch(down.generator)' \
    || bad "E6: the retry must wait for its back-off and for a network"
order "$retry" 'if !down.settingsInForce {' 'down.settingsInForce = self.applySettingsConfirmed(down.generator.generateNetworkSettings())' \
    && has "$retry" 'if down.settingsInForce, let handle = self.startBackendForSwitch(down.generator) {' \
    || bad "E6: the retry must put the settings in force before it starts an engine on them"
order "$retry" 'down.retry.failed(at: now)' 'self.dataWatchEngineDown = down' \
    || bad "E6: a failed retry must lengthen the back-off and stay armed"
[ "$(printf '%s\n' "$retry" | grep -c 'self.dataWatchEngineHandler?(false)')" = "2" ] \
    || bad "E6: an engine that runs again must be told (brought back by the retry or by the path handler)"
has "$swift_added" 'update(tunnelConfiguration' && bad "E6: the data watch must not call the public update path (its backend keeps running across the settings change)"
for token in 'setTunnelNetworkSettings' 'update(tunnelConfiguration' 'cancelTunnelWithError' 'stopTunnel' 'reasserting' 'wgTurnOff' 'wgTurnOn' 'wgSetConfig'; do
    has "$runtime" "$token" && bad "E6: the runtime must only report and answer ($token)"
    has "$(code "$IOS/PacketTunnelProvider+DataWatch.swift")" "$token" && bad "E6: the provider glue must only report and answer ($token)"
done
wgfile="$(code "$IOS/PacketTunnelProvider+WireGuard.swift")"
[ "$(printf '%s\n' "$wgfile" | grep -c 'adapter.dataWatchCandidate = ')" = "1" ] \
    && has "$wgfile" 'adapter.dataWatchCandidate = { \[weak self\] nodeId in self?.tribeSwitchConfiguration(nodeId) }' \
    || bad "E6: the adapter must get candidate configurations from the provider's one function"
# Second review, R1: who started the tunnel is the tribeStartSource the start options really carry (the
# app and our commands always pass one; iOS passes none) - not the session id iOS hands to every start.
has "$wgfile" 'let startConfiguration = tribeStartConfiguration(profile: tunnelConfiguration, startSource: tribeStartSource)' \
    && has "$wgfile" 'adapter.start(tunnelConfiguration: startConfiguration)' \
    || bad "E6: the start must go through tribeStartConfiguration with the start source of this start"
has "$(code "$IOS/PacketTunnelProvider.swift")" 'tribeStartSource = options?\["tribeStartSource"\] as? String' \
    && [ "$(cat "$IOS"/*.swift | grep -v '^[[:space:]]*//' | grep -c 'tribeStartSource = ')" = "1" ] \
    || bad "E6: the start source must be exactly what the start options carry, set in one place"
has "$glue" 'guard let choice = tribeDataWatch.chooseStart(source: startSource) else { return profile }' \
    || bad "E6: which node a start raises is decided by the runtime's tested choice (a start by the app: the profile's node)"
cat "$IOS"/*.swift "$RECIPE"/tribe/*.swift | grep -v '^[[:space:]]*//' | grep -q 'activationAttemptId != nil\|startedByApp' \
    && bad "E6: nothing may tell an app start from a system start by the activation id (iOS passes one to every start)"
has "$(swift_func "$IOS/TribeWatchPlan.swift" 'static func startedBySystem(')" 'source == nil' \
    || bad "E6: only a start without any start source is a start by the system"
has "$wgfile" 'completionHandler(self.tribeEngineDownReply())' \
    || bad "E6: with no engine the status reply must say so"
has "$runtime" 'adapter.dataWatchEngineHandler = { \[weak self\] down in self?.noteEngine(down: down) }' \
    || bad "E6: the runtime must be told when the engine goes down and comes back"
[ "$(printf '%s\n' "$wgfile" | grep -c 'self.tribeApplySessionOverride(&metadata)')" = "1" ] \
    || bad "E6: the status reply must carry the node the tunnel stands on"
has "$glue" 'guard let made = tribeDataWatch.sessionSwitch() else { return }' \
    || bad "E6: without a switch the status reply's session must stay untouched"
# Second review R7, third review T4: the plan file has two writers - the app (the whole plan) and the
# extension (only to take the spare nodes' keys out). Both hold ONE lock for their write, and the
# extension's "is it still the plan I judged?" is decided under that lock, together with its write
# (TribeWatchPlanFile.replaceIfUnchanged - tested with the reviewer's interleaving). Here: both sides
# really go through it, with the same lock file.
planfile="$(code "$IOS/TribeWatchPlan.swift")"
has "$glue" 'return TribeWatchPlanFile.replaceIfUnchanged(in: directory, expected: expected, with: clean)' \
    && [ "$(printf '%s\n' "$runtime" | grep -c 'deps.replacePlan(')" = "1" ] \
    || bad "E6: the extension may write the plan only through the locked compare-and-replace, from one place"
for f in TribeDataWatchRuntime.swift PacketTunnelProvider+DataWatch.swift PacketTunnelProvider+WireGuard.swift PacketTunnelProvider.swift; do
    code "$IOS/$f" | grep -q 'TribeWatchPlan.fileName).*write\|\.write(to:' && bad "E6: $f writes a file itself (the plan has one extension-side writer: TribeWatchPlanFile)"
done
[ "$(printf '%s\n' "$planfile" | grep -c 'completeFileProtectionUntilFirstUserAuthentication')" = "1" ] \
    && has "$planfile" 'values.isExcludedFromBackup = true' \
    || bad "E6: the extension's rewrite of the plan must keep the file's protection and stay out of backups"
grep -q 'NSURLIsExcludedFromBackupKey' "$CONTROLLER" && grep -q 'NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication' "$CONTROLLER" \
    || bad "E6: the app must write the plan protected and excluded from backups"
has "$planfile" 'static let lockName = "TribeWatchPlan.lock"' && grep -q 'URLByAppendingPathComponent:@"TribeWatchPlan.lock"\]' "$CONTROLLER" \
    || bad "E6: the two writers of the plan must lock the same file"
app_write="$(body_of "$CONTROLLER" 'static bool writeTunnelWatchPlan(')"
order "$app_write" 'locked = flock(lockFd, LOCK_EX | LOCK_NB) == 0;' 'const BOOL written = \[data writeToURL:url options:options error:&error\];' \
    && order "$app_write" 'const BOOL written = \[data writeToURL:url options:options error:&error\];' 'flock(lockFd, LOCK_UN);' \
    || bad "E6: the app must hold the plan's lock across its write"
# A stop by the user: the spare nodes' keys leave the file (before the runtime lets go of its adapter).
order "$stop_body" 'tribeDataWatch.noteStop(userInitiated: reason == .userInitiated)' 'tribeDataWatch.detach()' \
    || bad "E6: a stop must tell the runtime whether the user stopped the tunnel"

# ---- A10: stage 2 in the app is inert (path engine, design 2026-11-17: the attempt owner is the only one that
# chooses a path) - the plan never carries candidates, nothing adopts a switch, there is no way back to take; the
# session plumbing of the hand-over (status replies, Reasserting, engine down) stays as it was --------------------
ctor="$(body_of "$FACADE" 'AvpnEngineQml::AvpnEngineQml(')"
plan_fn="$(body_of "$FACADE" 'void AvpnEngineQml::writeTunnelWatchPlan(')"
has "$plan_fn" 'in.candidates' && bad "A10: the app must write no switch candidate into the plan (one owner of the path)"
has "$(code "$ENGINE/ServiceEngine.h") $(code "$ENGINE/ServiceEngine.cpp")" 'extensionSwitchCandidates' \
    && bad "A10: nothing may produce a switch candidate for the extension (one owner of the path)"
[ -e "$ENGINE/TunnelWatchCandidates.h" ] && bad "A10: the candidate producer is gone (a replaced mechanism does not stay in the tree)"
[ "$(grep -c 'adoptExtensionSwitch' "$FACADE" "$ENGINE/ServiceEngine.cpp" "$ENGINE/ServiceEngine.h" | awk -F: '{s+=$2} END {print s}')" = "0" ] \
    || bad "A10: nothing adopts a switch of the extension any more"
resume_fn="$(body_of "$FACADE" 'void AvpnEngineQml::setupTunnelWatchResume()')"
has "$resume_fn" 'ops.adoptSwitch = \[\](const QString &, const avpn::WatchSwitchStamp &) { return false; };' \
    && has "$resume_fn" 'ops.restartToChoice = \[\] {};' && has "$resume_fn" 'ops.forgetNode = \[\](const QString &) {};' \
    || bad "A10: the hand-over's stage-2 effects must be inert"
meta_ctx="$(code "$FACADE" | grep -A8 '&IosController::sessionMetadataChanged, this,')"
order "$meta_ctx" 'm_watchResume->onSessionMetadata(metadata);' 'adoptNativeIdentity();' \
    || bad "A10: every status reply's session must reach the hand-over before the app's own identity rules"
[ "$(count "$FACADE" 'm_watchResume->onSessionMetadata(')" = "1" ] && [ "$(count "$FACADE" 'm_watchResume->onReasserted()')" = "1" ] \
    || bad "A10: the hand-over hears of a session change and of a Reasserting from one place each"
has "$(code "$FACADE")" 'if (m_watchResume && avpn::sessionReasserted(s == Vpn::Connected, m_lastTunnelState == Vpn::Connecting, engineStateBefore))' \
    || bad "A10: a Reasserting is recognised by the tested rule, with the engine's state before the callback"
order "$(code "$FACADE")" 'm_watchResume->onReasserted();' 'm_lastTunnelState = s; // AVPN' \
    || bad "A10: the Reasserting hook must run while the previous tunnel state is still known"
down_fn="$(body_of "$FACADE" 'void AvpnEngineQml::onTunnelEngineDown()')"
order "$down_fn" 'if (!avpn::decideEngineDownRestart(in))' 'm_needsRestart = true;' && has "$down_fn" 'reconcile();' \
    || bad "A10: an engine-down reply must lead to the ordinary restart, by decideEngineDownRestart"
has "$ctor" '&IosController::tunnelEngineDown' && has "$ctor" '&AvpnEngineQml::onTunnelEngineDown' \
    || bad "A10: the facade must hear that the tunnel has no engine"
down_ctx="$(code "$CONTROLLER" | grep -A3 'if (engineDown) {')"
has "$down_ctx" 'emit tunnelEngineDown();' && has "$down_ctx" 'return;' && [ "$(count "$CONTROLLER" 'emit tunnelEngineDown()')" = "1" ] \
    || bad "A10: a reply without an engine must be told and judged by nothing else"
cfg_start="$(body_of "$ENGINE/ConfigService.cpp" 'void ConfigService::start()')"
order "$cfg_start" '#ifdef Q_OS_IOS' 'freezeCachedFeatures(c.features, /\*ios=\*/true);' \
    && has "$cfg_start" 'freezeCachedFeatures(c.features, /\*ios=\*/false);' \
    || bad "A10: a cached config must not switch the tunnel-side switch on at a cold start (iOS)"
[ "$(grep -c 'freezeCachedFeatures(' "$ENGINE/ConfigService.cpp")" = "2" ] || bad "A10: the freeze is applied in one place"

# ---- E7: the package and the targets ----------------------------------------------------------------------
# tribe.15 (the probe engine's host limits, an engine patch) = tribe.14's package patches byte for byte.
# tribe.16 (one definition of "data is flowing", device round 24.11 B1) = tribe.15's + 0017 last.
# tribe.17 (its review: TribeRoaming.swift only) = tribe.16's patches unchanged.
# tribe.18 (the second review: TribeRoaming.swift only) = tribe.17's patches unchanged.
grep -q 'self.requires("awg-apple/3.1.4-tribe.18")' "$ROOT/conanfile.py" || bad "E7: the root conanfile must require tribe.18"
grep -q '^    version = "3.1.4-tribe.18"' "$RECIPE/conanfile.py" || bad "E7: the recipe version must be tribe.18"
list18="$(awk '/^  "3.1.4-tribe.18":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')"
[ -n "$list18" ] && [ "$list18" = "$(awk '/^  "3.1.4-tribe.17":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')" ] \
    || bad "E7: tribe.18 must carry the package patches of tribe.17 unchanged, in the same order"
list17="$(awk '/^  "3.1.4-tribe.17":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')"
[ -n "$list17" ] && [ "$list17" = "$(awk '/^  "3.1.4-tribe.16":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')" ] \
    || bad "E7: tribe.17 must carry the package patches of tribe.16 unchanged, in the same order"
list16="$(awk '/^  "3.1.4-tribe.16":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')"
[ -n "$list16" ] && [ "$list16" = "$(awk '/^  "3.1.4-tribe.15":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')
patches/0017-tribe-data-quiet-export.patch" ] \
    || bad "E7: tribe.16 must carry the package patches of tribe.15 unchanged, in the same order, and 0017 last"
list15="$(awk '/^  "3.1.4-tribe.15":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')"
list14="$(awk '/^  "3.1.4-tribe.14":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')"
list12="$(awk '/^  "3.1.4-tribe.12":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')"
[ -n "$list15" ] && [ "$list15" = "$(awk '/^  "3.1.4-tribe.14":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')" ] \
    || bad "E7: tribe.15 must carry the package patches of tribe.14 unchanged, in the same order"
# tribe.14 = the list of tribe.12, untouched in number and order, with 0012 right after 0011 and 0016 last.
[ -n "$list12" ] && [ "$(printf '%s\n' "$list14" | grep -v 'tribe-data-watch')" = "$list12" ] \
    || bad "E7: tribe.14 must carry the patches of tribe.12 unchanged, in the same order"
[ "$(printf '%s\n' "$list14" | grep -A1 'patches/0011-' | tail -1)" = "patches/0012-tribe-data-watch.patch" ] \
    && [ "$(printf '%s\n' "$list14" | grep -B1 'patches/0013-' | head -1)" = "patches/0012-tribe-data-watch.patch" ] \
    && [ "$(printf '%s\n' "$list14" | tail -1)" = "patches/0016-tribe-data-watch-adapter.patch" ] \
    && [ "$(printf '%s\n' "$list14" | grep -c 'tribe-data-watch')" = "2" ] \
    || bad "E7: the data watch must be 0012 in its slot (between 0011 and 0013) and 0016 after everything else"
# Why two patches: the recipe's patch tool matches hunks at exact line numbers, and 0015 was recorded on
# an adapter without the data watch. So nothing of the data watch may touch the adapter before 0015, and
# the Go half must not touch it at all.
grep -q '^diff --git a/Sources/WireGuardKit/' "$PATCH_GO" && bad "E7: patch 0012 must not touch the Swift sources (it is applied before 0015)"
[ "$(grep -c '^diff --git ' "$PATCH_ADAPTER")" = "1" ] && grep -q '^diff --git a/Sources/WireGuardKit/WireGuardAdapter.swift ' "$PATCH_ADAPTER" \
    || bad "E7: patch 0016 must be the adapter's changes and nothing else"
for cm in "$ROOT/client/ios/networkextension/CMakeLists.txt" "$ROOT/client/macos/networkextension/CMakeLists.txt"; do
    for src in 'WireGuardKit/TribeDataWatch.swift' 'platforms/ios/TribeWatchPlan.swift' 'platforms/ios/TribeDataWatchRuntime.swift' \
               'platforms/ios/PacketTunnelProvider+DataWatch.swift'; do
        grep -q "$src" "$cm" || bad "E7: $(basename "$(dirname "$cm")")/CMakeLists.txt does not compile $src"
    done
done
grep -q 'run_tribe_data_watch_tests.sh' "$RECIPE/conanfile.py" || bad "E7: the package must be gated on the data-watch unit test"
grep -q 'TribeDataWatchLadderTests.swift' "$RECIPE/conanfile.py" && grep -q 'TribeDataWatchLadderTests' "$RECIPE/tests/run_tribe_data_watch_tests.sh" \
    || bad "E7: the package must be gated on the vectors that couple the rule with the stall ladder"
grep -q "TestTribeProbe" "$RECIPE/conanfile.py" || bad "E7: the package must be gated on the probe's Go test"

# ---- E8: Xray statistics --------------------------------------------------------------------------------
XR="$IOS/PacketTunnelProvider+Xray.swift"
[ "$(count "$XR" 'startTribeStatsTimer()')" = "1" ] && [ "$(count "$XR" 'stopTribeStatsTimer()')" = "1" ] \
    || bad "E8: the Xray path starts and stops the statistics tick once each"
[ "$(cat "$IOS"/*.swift | grep -v '^[[:space:]]*//' | grep -c 'logTribeXrayStats()')" = "2" ] \
    && has "$stats_body" 'logXray: { \[weak self\] in self?.logTribeXrayStats() }' \
    || bad "E8: the Xray statistics line is written only by the statistics tick (which writes it only with the file log on)"

# ---- A1: Q_OS_IOS around every new call in the facade ----------------------------------------------------
outside="$(awk '
    /^[[:space:]]*#if(def)?[[:space:]].*Q_OS_IOS/ && !/!defined|ifndef/ { stack[++depth] = 1; next }
    /^[[:space:]]*#if/ { stack[++depth] = 0; next }
    /^[[:space:]]*#(else|elif)/ { if (depth > 0) stack[depth] = 0; next }
    /^[[:space:]]*#endif/ { if (depth > 0) depth--; next }
    /^[[:space:]]*\/\// { next }
    /^(void|bool) AvpnEngineQml::/ { next }
    /writeTunnelWatchPlan\(|setupTunnelWatchResume\(|tickTunnelWatchFreeze\(|tunnelWatchFrozen\(|deferWhileTunnelWatchFrozen\(|m_watchResume|noteAppBackground\(|reenterVerifying\(|requestStatusSnapshot\(|writeTunnelWatchPlanFile\(|&IosController::tunnelWatchSnapshot|&IosController::onDemandBackgroundEvent/ {
        ios = 0
        for (i = 1; i <= depth; i++) if (stack[i]) ios = 1
        if (!ios) print NR ": " $0
    }' "$FACADE")"
[ -z "$outside" ] || bad "A1: a data-watch call in the facade is outside Q_OS_IOS:
$outside"
[ "$(count "$FACADE" 'writeTunnelWatchPlan(')" -ge 6 ] || bad "A1: the plan writer lost call sites"

# ---- A2: default false -----------------------------------------------------------------------------------
for key in ios_tunnel_watch ios_tunnel_watch_switch ios_on_demand_bg_arm; do
    reads="$(code "$FACADE" | grep -o "featureEnabled(QStringLiteral(\"$key\"), [a-z]*)" || true)"
    [ -n "$reads" ] || bad "A2: features.$key is not read by the facade"
    printf '%s\n' "$reads" | grep -vq ', false)$' && bad "A2: features.$key must be read with the default false"
    grep -rn "\"$key\")[^,]*, *true" "$ENGINE"/*.cpp "$ENGINE"/*.h "$IOS"/*.mm "$IOS"/*.h >/dev/null 2>&1 \
        && bad "A2: features.$key is read somewhere with the default true"
done
grep -q 'features.value("ios_tunnel_watch").toBool()\|"ios_tunnel_watch", true' "$ENGINE/TunnelWatchPlan.h" \
    && bad "A2: the plan builder must not decide the flag itself"

# ---- A3: when the plan is rewritten ----------------------------------------------------------------------
ctor="$(body_of "$FACADE" 'AvpnEngineQml::AvpnEngineQml(')"
has "$ctor" 'writeTunnelWatchPlan("config")' || bad "A3: a fresh config must rewrite the plan"
has "$ctor" 'writeTunnelWatchPlan("foreground")' || bad "A3: a return to the foreground must rewrite the plan"
has "$(body_of "$FACADE" 'void AvpnEngineQml::guardedStart()')" 'writeTunnelWatchPlan("start")' || bad "A3: every start must rewrite the plan"
has "$(body_of "$FACADE" 'void AvpnEngineQml::persistPin()')" 'writeTunnelWatchPlan("pin")' || bad "A3: a pin change must rewrite the plan"
has "$(body_of "$FACADE" 'void AvpnEngineQml::setTransportMode(')" 'writeTunnelWatchPlan("mode")' || bad "A3: a mode change must rewrite the plan"
plan_body="$(body_of "$FACADE" 'void AvpnEngineQml::writeTunnelWatchPlan(')"
has "$plan_body" 'avpn::writeWatchPlan(' && [ "$(count "$FACADE" 'writeTunnelWatchPlanFile(')" = "1" ] \
    && order "$plan_body" 'avpn::writeWatchPlan(' 'writeTunnelWatchPlanFile(' \
    || bad "A3: the file is written only through the tested write (writeWatchPlan decides whether, numbers it and journals it)"
order "$plan_body" 'if (!out.attempted)' 's.setValue(QLatin1String(avpn::kWatchPlanSeqSettingsKey), out.seqAfter);' \
    || bad "A3: the sequence number and the ever-on mark must be persisted after a write"
has "$plan_body" 'avpn::watchPlanSanityTargets(' || bad "A3: the bypass targets must come through watchPlanSanityTargets"
has "$plan_body" 'avpn::ConfigStore::configReceivedAtMs()' || bad "A3: the plan must carry when the config in force was received"
has "$plan_body" 'avpn::watchPlanNumbers(' || bad "A3: the plan's numbers must come through the clamp table"

# ---- A4: the watch block --------------------------------------------------------------------------------
[ "$(count "$CONTROLLER" 'emit tunnelWatchSnapshot(')" = "1" ] || bad "A4: the snapshot must be emitted from one place"
emit_ctx="$(code "$CONTROLLER" | grep -B4 'emit tunnelWatchSnapshot(')"
has "$emit_ctx" 'm_statusRequests.lastAppliedIs(gen, request)' \
    || bad "A4: the snapshot must be emitted only for the reply that was applied"
has "$emit_ctx" 'm_watchSnapshotWanted.store(false);' \
    || bad "A4: the emitted snapshot must consume the request (one request - one snapshot)"
[ "$(count "$CONTROLLER" 'm_watchSnapshotWanted.store(true)')" = "1" ] || bad "A4: only requestStatusSnapshot asks for a snapshot"
[ "$(grep -c 'requestStatusSnapshot()' "$FACADE")" = "1" ] || bad "A4: the facade asks for a snapshot only as the hand-over's effect"
has "$ctor" '&IosController::tunnelWatchSnapshot' && has "$ctor" '&AvpnEngineQml::onTunnelWatchSnapshot' \
    || bad "A4: the facade must receive the snapshot"
snap_body="$(body_of "$CONTROLLER" 'void IosController::requestStatusSnapshot()')"
order "$snap_body" 'm_statusRequests.invalidate();' 'checkStatus();' \
    || bad "A4: a snapshot request must cancel older replies before it asks"
has "$snap_body" 'm_watchSnapshotWanted.store(true);' || bad "A4: a snapshot request must mark the snapshot as wanted"
watch_body="$(body_of "$FACADE" 'void AvpnEngineQml::onTunnelWatchSnapshot(')"
has "$watch_body" 'm_watchResume->onSnapshot(snapshot);' || bad "A4: the snapshot goes to the hand-over object and nowhere else"
for token in 'parseTunnelWatch' 'decideWatchConsume' 'startDataPathVerification' 'reenterVerifying'; do
    has "$watch_body" "$token" && bad "A4: the facade must not judge a snapshot itself ($token)"
done

# ---- A5: the freeze comes first ---------------------------------------------------------------------------
tick="$(body_of "$FACADE" 'void AvpnEngineQml::onTick()')"
order "$tick" 'tunnelWatchFrozen("health_tick")' 'm_engine.tick(' || bad "A5: the freeze must be consulted before the health verdict"
has "$tick" '} else if (m_engine.tick(' || bad "A5: only the health verdict may wait - the rest of the tick must run"
whoami="$(body_of "$FACADE" 'void AvpnEngineQml::whoamiAttempt(')"
order "$whoami" 'deferWhileTunnelWatchFrozen("whoami"' 'avpn::whoamiAttemptGate(' \
    || bad "A5: a late whoami attempt must wait for the snapshot before it is judged"
has "$whoami" 'deferWhileTunnelWatchFrozen("whoami_reply"' || bad "A5: a whoami reply cut by a freeze must wait for the snapshot"
verify="$(body_of "$FACADE" 'void AvpnEngineQml::verifyAttempt(')"
order "$verify" 'deferWhileTunnelWatchFrozen("verify"' 'm_engine.dataCheckMs()' \
    || bad "A5: a late verify attempt must wait for the snapshot before its budget is judged"
has "$verify" 'deferWhileTunnelWatchFrozen("tiebreak_reply"' || bad "A5: a tiebreak reply cut by a freeze must wait for the snapshot"
frozen="$(body_of "$FACADE" 'bool AvpnEngineQml::tunnelWatchFrozen(')"
has "$frozen" 'm_watchResume->held(site, m_lastTransitionTickMs, m_transitionTimer.interval())' \
    || bad "A5: a decision must ask the hand-over object, with the tick it measures a thaw by"
has "$(body_of "$FACADE" 'bool AvpnEngineQml::deferWhileTunnelWatchFrozen(')" 'm_watchResume->defer(site, m_lastTransitionTickMs, m_transitionTimer.interval(), std::move(resume))' \
    || bad "A5: a decision that must wait is kept by the hand-over object"
has "$(body_of "$FACADE" 'void AvpnEngineQml::tickTunnelWatchFreeze(')" 'm_watchResume->onTick(sinceMs, m_transitionTimer.interval());' \
    || bad "A5: the hand-over is driven by the existing transition tick"
has "$ctor" 'tickTunnelWatchFreeze(since)' || bad "A5: the hand-over must be driven by the existing transition tick"
has "$ctor" 'setupTunnelWatchResume();' || bad "A5: the hand-over object must be built"
setup="$(body_of "$FACADE" 'void AvpnEngineQml::setupTunnelWatchResume()')"
has "$setup" 'ops.watchFlag = \[this\] { return featureEnabled(QStringLiteral("ios_tunnel_watch"), false); };' \
    || bad "A5: the hand-over reads features.ios_tunnel_watch, default false"
has "$setup" 'ops.nodeScanFlag = \[this\] { return featureEnabled(QStringLiteral("node_scan"), false); };' \
    || bad "A5: the hand-over reads features.node_scan, default false"
has "$setup" 'return m_hiddenSeen && featureEnabled(QStringLiteral("ios_on_demand_bg_arm"), false) && !m_restartGuard.held();' \
    || bad "A5: the background hold is: in the background, the arming flag on, nothing of ours in flight"
has "$ctor" 'beginTunnelWatchFreeze\|noteAppForeground' && bad "A5: a return to the screen needs no call of its own (a thaw is recognised by the overdue tick)"

# ---- A6: no timers in the new code ---------------------------------------------------------------------------
for f in "$ENGINE/TunnelWatchPlan.h" "$ENGINE/TunnelWatchStatus.h" "$ENGINE/TunnelWatchResume.h" "$IOS/BackgroundHoldBook.h" "$IOS/IosBackgroundArm.h"; do
    grep -q 'QTimer\|startTimer\|dispatch_after\|NSTimer\|std::thread\|sleep(' "$f" && bad "A6: $(basename "$f") must stay pure (no timer, no thread)"
done
for fn in 'void AvpnEngineQml::writeTunnelWatchPlan(' 'void AvpnEngineQml::setupTunnelWatchResume()' 'bool AvpnEngineQml::tunnelWatchFrozen(' \
          'void AvpnEngineQml::tickTunnelWatchFreeze(' 'void AvpnEngineQml::onTunnelWatchSnapshot(' 'bool AvpnEngineQml::deferWhileTunnelWatchFrozen('; do
    b="$(body_of "$FACADE" "$fn")"
    [ -n "$b" ] || bad "A6: $fn not found"
    has "$b" 'QTimer\|startTimer\|new QObject' && bad "A6: $fn must not start a timer"
done
for fn in 'void IosController::noteAppBackground(' 'void IosController::tickBackgroundArmHold()' 'void IosController::endBackgroundArmHold(' \
          'void IosController::requestStatusSnapshot()'; do
    b="$(body_of "$CONTROLLER" "$fn")"
    [ -n "$b" ] || bad "A6: $fn not found"
    has "$b" 'QTimer\|dispatch_after\|NSTimer\|startTimer' && bad "A6: $fn must not start a timer (the hold is judged on the status poll)"
done
status="$(body_of "$CONTROLLER" 'void IosController::checkStatus()')"
has "$status" 'tickBackgroundArmHold();' || bad "A6: the arming hold must be judged on the existing status poll"

# ---- A7: the guard -----------------------------------------------------------------------------------------
[ "$(count "$FACADE" 'AvpnBackgroundGuard_begin(')" = "1" ] && [ "$(count "$FACADE" 'AvpnBackgroundGuard_end()')" = "1" ] \
    || bad "A7: the tunnel-restart guard must keep exactly its two calls in the facade"
has "$(code "$FACADE")" 'AvpnBackgroundGuard_acquire\|AvpnBackgroundGuard_release' && bad "A7: the facade must not hold background time for another reason"
[ "$(count "$CONTROLLER" 'AvpnBackgroundGuard_acquire(avpn_ios::BgReason::OnDemandArm')" = "1" ] \
    && [ "$(count "$CONTROLLER" 'AvpnBackgroundGuard_release(avpn_ios::BgReason::OnDemandArm)')" = "1" ] \
    || bad "A7: the arming must take and give back background time under its own reason, once each"
has "$(code "$CONTROLLER")" 'BgReason::TunnelRestart' && bad "A7: the controller must not touch the restart reason"
bg="$(body_of "$CONTROLLER" 'void IosController::noteAppBackground(')"
order "$bg" 'if (!bgArmFlag)' 'emit onDemandBackgroundEvent(' || bad "A7: with the flag off the background transition must do and journal nothing"
order "$bg" 'avpn_ios::decideBackgroundArm(' 'AvpnBackgroundGuard_acquire(' || bad "A7: the hold must follow decideBackgroundArm"
arm="$(body_of "$CONTROLLER" 'void IosController::armOnDemandForConfirmedSession()')"
has "$arm" 'avpn_ios::decideOnDemandArm(' || bad "A7: the arming must keep its own decision (only a proven session)"
has "$arm" 'endBackgroundArmHold(' || bad "A7: the arming's result must end the hold"
has "$(body_of "$CONTROLLER" 'void IosController::tickBackgroundArmHold()')" 'in.appActive = appIsActive();' \
    || bad "A7: the hold's tick must ask the system itself whether the app is on the screen"
has "$(body_of "$CONTROLLER" 'bool IosController::appIsActive() const')" 'applicationState == UIApplicationStateActive' \
    || bad "A7: on the phone the answer comes from UIKit"

# ---- A8: a reason to re-check, never a sentence ----------------------------------------------------------------
# What the hand-over does with a verdict is tested (tunnel_watch_check: handOver). Here: the effects the
# facade hands to it are what they claim to be and touch nothing else.
# (The two effects of the way back - stage 2, checked in A10 - are the ordinary restart and its facts.)
verdict_effects="$(printf '%s\n' "$setup" | grep -v 'ops.returnFacts = \|ops.restartToChoice = ')"
has "$verdict_effects" 'ops.adoptSwitch = ' && has "$verdict_effects" 'ops.forgetNode = ' \
    || bad "A8: the scan of the verdict's effects lost its subject"
for token in 'm_savedPin' 'clearPin' 'setPinned' 'm_wantConnected' 'verifySucceeded' 'verifyFailed' 'noteDataPlaneFailure' 'rememberNetworkPath' \
             'guardedStop' 'guardedStart' 'm_needsRestart' 'onDead' 'reconcile('; do
    has "$verdict_effects" "$token" && bad "A8: the hand-over's effects must not touch $token (the extension's verdict is a reason to check, not a result)"
done
has "$setup" 'ops.reenterVerifying = \[this\] { return m_engine.reenterVerifying(); };' || bad "A8: the engine's consent is the engine's own answer"
order "$setup" 'ops.startVerification = \[this\] {' 'startDataPathVerification();' || bad "A8: the re-check must be the app's own data check"
has "$setup" 'ops.forgetNode = \[\](const QString &) {};' || bad "A8: the app keeps no per-network memory of its own - the ledger records the re-check's outcome"
resume_h="$(code "$ENGINE/TunnelWatchResume.h")"
order "$resume_h" 'if (watchVerdictForgetsNode(w.verdict))' 'm_ops.forgetNode(nodeId);' \
    || bad "A8: the per-network memory forgets the node only on a verdict the judge confirmed"

# ---- A9: one caller of the way back to Verifying -------------------------------------------------------------------
callers="$(grep -ln 'reenterVerifying()' "$ENGINE"/*.cpp "$ENGINE"/*.h "$IOS"/*.mm 2>/dev/null | xargs -n1 basename | sort | tr '\n' ' ')"
[ "$callers" = "AvpnEngineQml.cpp ServiceEngine.cpp ServiceEngine.h TunnelWatchResume.h " ] || bad "A9: reenterVerifying is referenced from: $callers"
[ "$(count "$ENGINE/TunnelWatchResume.h" 'm_ops.reenterVerifying()')" = "1" ] || bad "A9: the hand-over asks for the engine's consent at one place"
[ "$(count "$FACADE" 'm_engine.reenterVerifying()')" = "1" ] || bad "A9: the facade must call reenterVerifying from one place"

# ---- X1: one registry of numbers, the same bounds on both sides ----------------------------------------------------
# The app clamps a server number (ConnectTunables.h) and the extension clamps it again (fromPlan):
# a bound that differs between the two would make the journal of the app lie about what is in force.
app_rows="$(sed -n 's/^ *{"\(ios_[a-z0-9_]*\)", *[0-9]*, *\([0-9]*\), *\([0-9]*\), *true}.*/\1 \2 \3/p' "$ENGINE/ConnectTunables.h" \
    | grep -v -e '^ios_tw_plan_ttl_h ' -e '^ios_tw_policy_max_age_h ' -e '^ios_tw_switch_lease_min ' | sort)"
ext_rows="$(sed -n 's/.*numbers\["\(ios_[a-z0-9_]*\)"\].*min: *\([0-9_]*\), *max: *\([0-9_]*\)).*/\1 \2 \3/p' "$RECIPE/tribe/TribeDataWatch.swift" \
    | awk '{ gsub("_", "", $2); gsub("_", "", $3); print }' | sort)"
[ -n "$app_rows" ] && [ "$(printf '%s\n' "$app_rows" | wc -l | tr -d ' ')" -ge 20 ] || bad "X1: the app's table of numbers was not found"
[ "$app_rows" = "$ext_rows" ] || bad "X1: the numbers and bounds the extension reads differ from the app's table (ConnectTunables.h vs TribeDataWatch.swift fromPlan)"
# The three terms the app turns into moments of time are carried as such, not as numbers.
plan_h="$(code "$ENGINE/TunnelWatchPlan.h")"
has "$plan_h" '"expires_ms"' && has "$plan_h" '"policy_max_age_ms"' && has "$plan_h" '"switch_lease_until_ms"' \
    || bad "X1: the plan must carry expires_ms, policy_max_age_ms and switch_lease_until_ms"
has "$(code "$IOS/TribeWatchPlan.swift")" '"switch_lease_until_ms"' || bad "X1: the extension must read the switch lease"

# ---- X2: the same hosts as the white-list detector -----------------------------------------------------------------
# The extension's built-in bypass targets must be the detector's compiled defaults (the marketplace tier
# and its first anchor): they are what the plan carries when the server sets its own lists.
detector="$(code "$ENGINE/WhitelistDetector.cpp")"
wl="$(printf '%s\n' "$detector" | awk '/^const QStringList kDefaultWhitelistDomains = \{/ { on = 1; next } on && /^};/ { exit } on { print }' | grep -o '"[^"]*"' | tr -d '"' | tr '\n' ' ')"
anchor="$(printf '%s\n' "$detector" | awk '/^const QStringList kDefaultAnchorDomains = \{/ { on = 1; next } on && /^};/ { exit } on { print }' | grep -o '"[^"]*"' | head -1 | tr -d '"')"
builtin="$(code "$IOS/TribeWatchPlan.swift" | grep 'static let builtIn = ' | grep -o '"https://[^"]*"' | tr -d '"' | sed 's#https://##' | tr '\n' ' ')"
[ -n "$wl" ] && [ -n "$anchor" ] && [ "$builtin" = "${wl}${anchor} " ] \
    || bad "X2: the extension's built-in bypass targets ($builtin) are not the white-list detector's defaults (${wl}${anchor})"

if [ "$fail" -ne 0 ]; then
    echo "check_ios_data_watch_wiring: FAILED"
    exit 1
fi
echo "check_ios_data_watch_wiring: OK"
