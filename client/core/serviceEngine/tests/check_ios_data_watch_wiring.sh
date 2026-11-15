#!/bin/bash
# AVPN build 140 (iOS tunnel-side data watch, design docs/specs/2026-11-14-ios-tunnel-side-data-watch-
# design.md in the backend repository, sections 0 and 0a): the wiring that unit tests cannot reach.
#
# The RULES are pure and tested by behaviour: the verdict (recipes/awg-apple/tribe/TribeDataWatch.swift,
# tests/TribeDataWatchTests.swift + the mutation run in recipes/awg-apple/replay), the probe
# (tribeprobe_test.go in patch 0012), the plan and the bypass reply (platforms/ios/tests/
# TribeWatchPlanTests.swift), the app's half (tests/tunnel_watch_check.cpp, platforms/ios/tests/
# IosDataWatchTests.cpp, the controller harness). What is left is where they are CALLED FROM: the
# adapter patch, the provider, the facade and the controller have no unit harness of their own at these
# places, so the forwarding is checked here at source level, and only that:
#   extension
#    E1. the adapter feeds the watch from the EXISTING stall tick, before the ladder acts, and the patch
#        adds no timer;
#    E2. with the policy off every hook in the adapter is a no-op;
#    E3. the probe wrapper is the outermost one and is not created unless configured;
#    E4. the provider configures the probe before the adapter starts, attaches and detaches the runtime,
#        marks the app alive on a status request and adds the `watch` key only when there is a block;
#    E5. the runtime has no timer of its own (the plan is re-read on the 10 s statistics tick), the
#        bypass request is bound to the physical interface, nothing notifies the user;
#    E6. stage 1 moves nobody: no switching action is produced, no network settings are re-applied;
#    E7. the package: tribe.13 = tribe.11 + 0012, both extension targets compile the new sources;
#    E8. the Xray statistics line is diagnostics only;
#   app
#    A1. every new call in the facade is inside a Q_OS_IOS block;
#    A2. the flags are read with the default false;
#    A3. the plan is rewritten at the listed moments;
#    A4. the `watch` block reaches the facade only for the reply that was applied;
#    A5. the freeze is consulted before the health verdict and before a data check completes;
#    A6. the new code has no timer, watchdog or user notification;
#    A7. the tunnel-restart guard keeps its own two calls; the arming holds under its own reason;
#    A8. a verdict of the extension never touches the pin, the intent or the "data proven" marks;
#    A9. the engine's way back to Verifying is called from one place;
#    X1. the numbers the extension reads and their bounds are those of the app's table.
# Run by build_check.sh.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
ENGINE="$HERE/.."
IOS="$ROOT/client/platforms/ios"
RECIPE="$ROOT/recipes/awg-apple"
PATCH="$RECIPE/patches/0012-tribe-data-watch.patch"
FACADE="$ENGINE/AvpnEngineQml.cpp"
CONTROLLER="$IOS/ios_controller.mm"
fail=0
bad() { echo "FAIL: $1"; fail=1; }

code() { grep -v '^[[:space:]]*//' "$1" || true; }             # a file without full-line comments
count() { code "$1" | grep -c -- "$2" || true; }
has() { printf '%s\n' "$1" | grep -q -- "$2"; }
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
added() { grep '^+' "$PATCH" | grep -v '^+++' || true; }        # what patch 0012 adds
added_swift() { # the added lines of the adapter only
    awk '/^diff --git/ { on = ($0 ~ /WireGuardAdapter\.swift/) } on && /^\+/ && !/^\+\+\+/ { print substr($0, 2) }' "$PATCH" \
        | grep -v '^[[:space:]]*//' || true
}

# ---- E1: one owner, the existing tick -------------------------------------------------------------
swift_added="$(added_swift)"
[ "$(printf '%s\n' "$swift_added" | grep -c 'self.dataWatchTick(sample)')" = "1" ] \
    || bad "E1: the adapter must feed the data watch from exactly one place"
tick_ctx="$(grep -n -A2 'self.dataWatchTick(sample)' "$PATCH" | head -3)"
has "$tick_ctx" 'self.recovery.tick(sample, pathSatisfied' \
    || bad "E1: the data watch must be fed on the stall tick, right before the recovery ladder judges the same sample"
for token in 'makeTimerSource' 'asyncAfter' 'Timer(' 'scheduledTimer' 'DispatchWorkItem'; do
    has "$swift_added" "$token" && bad "E1: patch 0012 adds a timer or a delayed block to the adapter ($token)"
done

# ---- E2: off = tribe.11 ------------------------------------------------------------------------------
tick_body="$(printf '%s\n' "$swift_added" | awk '/private func dataWatchTick/ { on = 1 } on { print } on && /^    }$/ { exit }')"
order "$tick_body" 'guard self.dataWatchPolicy.enabled else' 'self.dataWatch.step(' \
    || bad "E2: dataWatchTick must leave before the step when the policy is off"
has "$tick_body" 'self.dataWatchInputs?()' && order "$tick_body" 'guard self.dataWatchPolicy.enabled else' 'self.dataWatchInputs?()' \
    || bad "E2: the provider's inputs must not be asked for while the policy is off"
path_body="$(printf '%s\n' "$swift_added" | awk '/private func dataWatchPathEvent/ { on = 1 } on { print } on && /^    }$/ { exit }')"
order "$path_body" 'guard self.dataWatchPolicy.enabled else { return }' 'self.dataWatch.notePathEvent(' \
    || bad "E2: a path event must not reach a switched-off watch"
start_note="$(printf '%s\n' "$swift_added" | grep -B1 'self.dataWatch.noteDeviceStarted(' | head -1)"
has "$start_note" 'if self.dataWatchPolicy.enabled {$' \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'self.dataWatch.noteDeviceStarted(')" = "1" ] \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'if self.dataWatchPolicy.enabled { self.dataWatch.noteBackendRestarted() }')" = "1" ] \
    && [ "$(printf '%s\n' "$swift_added" | grep -c 'self.dataWatch.noteBackendRestarted()')" = "1" ] \
    || bad "E2: the device-start and backend-restart notes must be under the policy flag"
has "$swift_added" 'private var dataWatchPolicy = TribeDataWatchPolicy.disabled' \
    || bad "E2: the adapter's policy must start disabled"

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
order "$start_body" 'tribeDataWatch.attach(adapter: adapter, probeConfigured: tribeProbeReady)' 'adapter.start(tunnelConfiguration' \
    || bad "E4: the runtime must be attached before the adapter starts"
[ "$(cat "$IOS"/*.swift | grep -v '^[[:space:]]*//' | grep -c 'wgSetTribeProbe(')" = "1" ] \
    || bad "E4: the probe must be configured from one place"
has "$(code "$IOS/PacketTunnelProvider+DataWatch.swift")" 'wgSetTribeProbe(wgConfig.clientIP, wgConfig.dns1, wanted ? 1 : 0)' \
    || bad "E4: the probe goes from the client's tunnel address to the session's resolver, and is reset when not wanted"
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
has "$stats_body" 'tribeDataWatch.refreshPlan()' || bad "E5: the plan must be re-read on the statistics tick"
[ "$(cat "$IOS"/*.swift | grep -v '^[[:space:]]*//' | grep -c 'refreshPlan()')" = "2" ] \
    || bad "E5: refreshPlan has exactly one caller (the statistics tick) besides its definition"
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
has "$(added)" 'UNUserNotificationCenter' && bad "E5: patch 0012 notifies the user"

# ---- E6: nobody is moved in stage 1 ---------------------------------------------------------------------
rule="$(code "$RECIPE/tribe/TribeDataWatch.swift")"
[ "$(printf '%s\n' "$rule" | grep -c 'switchPeer')" = "1" ] && [ "$(printf '%s\n' "$rule" | grep -c '\.exhausted\|case exhausted')" = "1" ] \
    || bad "E6: the switching actions may only be declared in this version, never produced"
has "$swift_added" 'update(tunnelConfiguration' && bad "E6: patch 0012 must not switch the configuration"
has "$swift_added" 'setTunnelNetworkSettings' && bad "E6: patch 0012 must not re-apply network settings"
for token in 'setTunnelNetworkSettings' 'update(tunnelConfiguration' 'cancelTunnelWithError' 'stopTunnel' 'reasserting'; do
    has "$runtime" "$token" && bad "E6: the runtime must only report ($token)"
    has "$(code "$IOS/PacketTunnelProvider+DataWatch.swift")" "$token" && bad "E6: the provider glue must only report ($token)"
done

# ---- E7: the package and the targets ----------------------------------------------------------------------
grep -q 'self.requires("awg-apple/3.1.4-tribe.13")' "$ROOT/conanfile.py" || bad "E7: the root conanfile must require tribe.13"
grep -q '^    version = "3.1.4-tribe.13"' "$RECIPE/conanfile.py" || bad "E7: the recipe version must be tribe.13"
list13="$(awk '/^  "3.1.4-tribe.13":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')"
list11="$(awk '/^  "3.1.4-tribe.11":/ { on = 1; next } on && /^  "/ { exit } on && /patch_file/ { print $3 }' "$RECIPE/conandata.yml" | tr -d '"')"
[ "$list13" = "$list11
patches/0012-tribe-data-watch.patch" ] || bad "E7: tribe.13 must be the patches of tribe.11 plus 0012, nothing else"
for cm in "$ROOT/client/ios/networkextension/CMakeLists.txt" "$ROOT/client/macos/networkextension/CMakeLists.txt"; do
    for src in 'WireGuardKit/TribeDataWatch.swift' 'platforms/ios/TribeWatchPlan.swift' 'platforms/ios/TribeDataWatchRuntime.swift' \
               'platforms/ios/PacketTunnelProvider+DataWatch.swift'; do
        grep -q "$src" "$cm" || bad "E7: $(basename "$(dirname "$cm")")/CMakeLists.txt does not compile $src"
    done
done
grep -q 'run_tribe_data_watch_tests.sh' "$RECIPE/conanfile.py" || bad "E7: the package must be gated on the data-watch unit test"
grep -q "TestTribeProbe" "$RECIPE/conanfile.py" || bad "E7: the package must be gated on the probe's Go test"

# ---- E8: Xray statistics --------------------------------------------------------------------------------
XR="$IOS/PacketTunnelProvider+Xray.swift"
[ "$(count "$XR" 'startTribeStatsTimer()')" = "1" ] && [ "$(count "$XR" 'stopTribeStatsTimer()')" = "1" ] \
    || bad "E8: the Xray path starts and stops the statistics tick once each"
xstats="$(swift_func "$IOS/PacketTunnelProvider+DataWatch.swift" 'func logTribeXrayStats(')"
order "$xstats" 'guard Log.isLoggingEnabled else { return }' 'xrayLog(' || bad "E8: the Xray statistics line is written only while the file log is on"

# ---- A1: Q_OS_IOS around every new call in the facade ----------------------------------------------------
outside="$(awk '
    /^[[:space:]]*#if(def)?[[:space:]].*Q_OS_IOS/ && !/!defined|ifndef/ { stack[++depth] = 1; next }
    /^[[:space:]]*#if/ { stack[++depth] = 0; next }
    /^[[:space:]]*#(else|elif)/ { if (depth > 0) stack[depth] = 0; next }
    /^[[:space:]]*#endif/ { if (depth > 0) depth--; next }
    /^[[:space:]]*\/\// { next }
    /^(void|bool) AvpnEngineQml::/ { next }
    /writeTunnelWatchPlan\(|beginTunnelWatchFreeze\(|tickTunnelWatchFreeze\(|tunnelWatchFrozen\(|deferWhileTunnelWatchFrozen\(|releaseTunnelWatchFreeze\(|reverifyAfterExtensionVerdict\(|noteAppBackground\(|noteAppForeground\(|reenterVerifying\(|requestStatusSnapshot\(|writeTunnelWatchPlanFile\(|&IosController::tunnelWatchSnapshot|&IosController::onDemandBackgroundEvent/ {
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
order "$plan_body" 'avpn::decideWatchPlanWrite(' 'if (!w.write)' && order "$plan_body" 'if (!w.write)' 'writeTunnelWatchPlanFile(' \
    || bad "A3: the file must not be written until the flag has been on once (decideWatchPlanWrite first)"
has "$plan_body" 'avpn::ConfigStore::configReceivedAtMs()' || bad "A3: the plan must carry when the config in force was received"
has "$plan_body" 'avpn::watchPlanNumbers(' || bad "A3: the plan's numbers must come through the clamp table"

# ---- A4: the watch block --------------------------------------------------------------------------------
[ "$(count "$CONTROLLER" 'emit tunnelWatchSnapshot(')" = "1" ] || bad "A4: the snapshot must be emitted from one place"
emit_ctx="$(code "$CONTROLLER" | grep -B4 'emit tunnelWatchSnapshot(')"
has "$emit_ctx" 'm_statusRequests.lastAppliedIs(gen, request)' \
    || bad "A4: the snapshot must be emitted only for the reply that was applied"
has "$emit_ctx" 'if (m_watchSnapshotWanted.exchange(false))' \
    || bad "A4: the snapshot must be emitted once per request and never without one"
[ "$(count "$CONTROLLER" 'm_watchSnapshotWanted.store(true)')" = "1" ] || bad "A4: only requestStatusSnapshot asks for a snapshot"
[ "$(grep -c 'requestStatusSnapshot()' "$FACADE")" = "2" ] || bad "A4: the facade asks for a snapshot from the freeze only (begin, re-ask)"
has "$ctor" '&IosController::tunnelWatchSnapshot' && has "$ctor" '&AvpnEngineQml::onTunnelWatchSnapshot' \
    || bad "A4: the facade must receive the snapshot"
snap_body="$(body_of "$CONTROLLER" 'void IosController::requestStatusSnapshot()')"
order "$snap_body" 'm_statusRequests.invalidate();' 'checkStatus();' \
    || bad "A4: a snapshot request must cancel older replies before it asks"
has "$snap_body" 'm_watchSnapshotWanted.store(true);' || bad "A4: a snapshot request must mark the snapshot as wanted"
watch_body="$(body_of "$FACADE" 'void AvpnEngineQml::onTunnelWatchSnapshot(')"
order "$watch_body" 'if (!m_watchFreeze.active)' 'avpn::parseTunnelWatch(' \
    || bad "A4: outside a freeze a snapshot changes nothing"
order "$watch_body" 'avpn::decideWatchConsume(' 'reverifyAfterExtensionVerdict(' \
    || bad "A4: the re-check must go through decideWatchConsume"

# ---- A5: the freeze comes first ---------------------------------------------------------------------------
tick="$(body_of "$FACADE" 'void AvpnEngineQml::onTick()')"
order "$tick" 'tunnelWatchFrozen("health_tick")' 'm_engine.tick(' || bad "A5: the freeze must be consulted before the health verdict"
has "$tick" '} else if (m_engine.tick(' || bad "A5: only the health verdict may wait - the rest of the tick must run"
whoami="$(body_of "$FACADE" 'void AvpnEngineQml::whoamiAttempt(')"
order "$whoami" 'deferWhileTunnelWatchFrozen("whoami"' 'avpn::whoamiAttemptGate(' \
    || bad "A5: a late whoami attempt must wait for the snapshot before it is judged"
has "$whoami" 'deferWhileTunnelWatchFrozen("whoami_reply"' || bad "A5: a whoami reply cut by a freeze must wait for the snapshot"
verify="$(body_of "$FACADE" 'void AvpnEngineQml::verifyAttempt(')"
order "$verify" 'deferWhileTunnelWatchFrozen("verify"' 'avpn::xrayVerifyTimeoutMsTuned()' \
    || bad "A5: a late verify attempt must wait for the snapshot before its budget is judged"
has "$verify" 'deferWhileTunnelWatchFrozen("tiebreak_reply"' || bad "A5: a tiebreak reply cut by a freeze must wait for the snapshot"
frozen="$(body_of "$FACADE" 'bool AvpnEngineQml::tunnelWatchFrozen(')"
order "$frozen" 'if (!featureEnabled(QStringLiteral("ios_tunnel_watch"), false))' 'avpn::thawDetected(' \
    || bad "A5: with the flag off nothing is ever frozen (the flag is checked first)"
begin="$(body_of "$FACADE" 'void AvpnEngineQml::beginTunnelWatchFreeze(')"
order "$begin" 'avpn::resumeFreezeBegins(' 'requestStatusSnapshot()' || bad "A5: the freeze must begin by its rule and then ask the extension"
has "$ctor" 'tickTunnelWatchFreeze(since)' || bad "A5: the freeze must be judged on the existing transition tick"

# ---- A6: no timers in the new code ---------------------------------------------------------------------------
for f in "$ENGINE/TunnelWatchPlan.h" "$ENGINE/TunnelWatchStatus.h" "$IOS/BackgroundHoldBook.h" "$IOS/IosBackgroundArm.h"; do
    grep -q 'QTimer\|startTimer\|dispatch_after\|NSTimer\|std::thread\|sleep(' "$f" && bad "A6: $(basename "$f") must stay pure (no timer, no thread)"
done
for fn in 'void AvpnEngineQml::writeTunnelWatchPlan(' 'void AvpnEngineQml::beginTunnelWatchFreeze(' 'bool AvpnEngineQml::tunnelWatchFrozen(' \
          'void AvpnEngineQml::tickTunnelWatchFreeze(' 'void AvpnEngineQml::onTunnelWatchSnapshot(' 'void AvpnEngineQml::releaseTunnelWatchFreeze(' \
          'void AvpnEngineQml::reverifyAfterExtensionVerdict('; do
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

# ---- A8: a reason to re-check, never a sentence ----------------------------------------------------------------
rev="$(body_of "$FACADE" 'void AvpnEngineQml::reverifyAfterExtensionVerdict(')"
for token in 'm_savedPin' 'clearPin' 'setPinned' 'm_wantConnected' 'verifySucceeded' 'verifyFailed' 'noteDataPlaneFailure' 'rememberNetworkPath' \
             'guardedStop' 'm_needsRestart' 'onDead'; do
    has "$rev" "$token" && bad "A8: the re-check must not touch $token (the extension's verdict is a reason to check, not a result)"
done
has "$rev" 'startDataPathVerification()' || bad "A8: the re-check must be the app's own data check"
has "$rev" 'avpn::networkMemoryForgetStored(' || bad "A8: the node must be forgotten in the per-network memory"
has "$rev" 'if (avpn::watchVerdictForgetsNode(snapshot.verdict) && ' || bad "A8: the per-network memory forgets the node only on a verdict the probe confirmed"
has "$rev" 'avpn::watchConsumedJournalLine(' || bad "A8: the consumed verdict must be journaled"

# ---- A9: one caller of the way back to Verifying -------------------------------------------------------------------
callers="$(grep -ln 'reenterVerifying()' "$ENGINE"/*.cpp "$ENGINE"/*.h "$IOS"/*.mm 2>/dev/null | xargs -n1 basename | sort | tr '\n' ' ')"
[ "$callers" = "AvpnEngineQml.cpp ServiceEngine.cpp ServiceEngine.h " ] || bad "A9: reenterVerifying is referenced from: $callers"
[ "$(count "$FACADE" 'm_engine.reenterVerifying()')" = "1" ] || bad "A9: the facade must call reenterVerifying from one place"

# ---- X1: one registry of numbers, the same bounds on both sides ----------------------------------------------------
# The app clamps a server number (ConnectTunables.h) and the extension clamps it again (fromPlan):
# a bound that differs between the two would make the journal of the app lie about what is in force.
app_rows="$(sed -n 's/^ *{"\(ios_[a-z0-9_]*\)", *[0-9]*, *\([0-9]*\), *\([0-9]*\), *true}.*/\1 \2 \3/p' "$ENGINE/ConnectTunables.h" \
    | grep -v -e '^ios_tw_plan_ttl_h ' -e '^ios_tw_policy_max_age_h ' | sort)"
ext_rows="$(sed -n 's/.*numbers\["\(ios_[a-z0-9_]*\)"\].*min: *\([0-9_]*\), *max: *\([0-9_]*\)).*/\1 \2 \3/p' "$RECIPE/tribe/TribeDataWatch.swift" \
    | awk '{ gsub("_", "", $2); gsub("_", "", $3); print }' | sort)"
[ -n "$app_rows" ] && [ "$(printf '%s\n' "$app_rows" | wc -l | tr -d ' ')" -ge 20 ] || bad "X1: the app's table of numbers was not found"
[ "$app_rows" = "$ext_rows" ] || bad "X1: the numbers and bounds the extension reads differ from the app's table (ConnectTunables.h vs TribeDataWatch.swift fromPlan)"
# The two terms the app turns into moments of time are carried as such, not as numbers.
plan_h="$(code "$ENGINE/TunnelWatchPlan.h")"
has "$plan_h" '"expires_ms"' && has "$plan_h" '"policy_max_age_ms"' || bad "X1: the plan must carry expires_ms and policy_max_age_ms"

if [ "$fail" -ne 0 ]; then
    echo "check_ios_data_watch_wiring: FAILED"
    exit 1
fi
echo "check_ios_data_watch_wiring: OK"
