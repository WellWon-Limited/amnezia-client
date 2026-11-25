#!/bin/sh
# AVPN (patch 0015): every place where WireGuardAdapter.swift stops, pauses, replaces or rebinds its
# backend by itself (or on the provider's stop) runs through TribeBackendHook.before; only deinit
# (the object is going away) calls wgTurnOff bare. Usage: check_backend_hook.sh WireGuardAdapter.swift
set -eu
f=$1
fail=0
# wgTurnOff / wgBumpSockets / wgSetConfig outside comments.
code=$(grep -n 'wgTurnOff(\|wgBumpSockets(\|wgSetConfig(' "$f" | grep -v '^[0-9]*: *///\|^[0-9]*: *//')
bare=$(printf '%s\n' "$code" | grep -v 'TribeBackendHook.before(' || true)
# Allowed bare calls: deinit's wgTurnOff and update(tunnelConfiguration:)'s wgSetConfig (the
# provider's own reconfiguration, which its lifecycle gate handles).
deinit_line=$(grep -n 'deinit {' "$f" | head -1 | cut -d: -f1)
printf '%s\n' "$bare" | while IFS= read -r l; do
    [ -z "$l" ] && continue
    n=${l%%:*}
    case "$l" in
    *wgTurnOff\(handle\)*)
        if [ "$n" -lt "$deinit_line" ] || [ "$n" -gt $((deinit_line + 20)) ]; then echo "bare wgTurnOff at line $n"; exit 1; fi ;;
    *'wgSetConfig(handle, wgConfig)'*)
        upd=$(awk -v n="$n" 'NR<=n && /func update\(tunnelConfiguration/ {u=NR} NR<=n && /func scheduleRoamRebind/ {u=0} END {print u+0}' "$f")
        if [ "$upd" -eq 0 ]; then echo "bare wgSetConfig outside update() at line $n"; exit 1; fi ;;
    *) echo "bare backend call at line $n: $l"; exit 1 ;;
    esac
done || fail=1
for reason in pause restart rebind stop; do
    grep -q "TribeBackendHook.before(.$reason, self.tribeBackendWillRestart)" "$f" || { echo "no hook for .$reason"; fail=1; }
done
grep -q 'public var tribeBackendWillRestart: ((TribeBackendRestart) -> Void)?' "$f" || { echo "no tribeBackendWillRestart property"; fail=1; }
# tribe.22 (review R53 2): an in-place restart that leaves no backend is never silent. From patch 0019 on (the
# adapter that knows TribeRestartDriver): the restart runs through the driver, its spent retries reach the
# engine-down owner, and no caller drops the restart's result or answers "performed" for a step without a backend.
if grep -q 'TribeRestartDriver(' "$f"; then
    grep -q 'engineDown: { \[weak self\] in self?.noteNoBackendAfterRestart(settingsGenerator) }' "$f" \
        || { echo "spent retries do not reach noteNoBackendAfterRestart"; fail=1; }
    down=$(awk '/private func noteNoBackendAfterRestart\(/ { on = 1 } on { print } on && /^    }$/ { exit }' "$f")
    printf '%s\n' "$down" | grep -q 'self.dataWatchEngineDown = (settingsGenerator, true, TribeEngineRetry(' \
        && printf '%s\n' "$down" | grep -q 'self.dataWatchEngineHandler?(true)' \
        && printf '%s\n' "$down" | grep -q 'self.startStallWatchdog()' \
        || { echo "noteNoBackendAfterRestart must enter the engine-down state, tell the owner and keep the tick"; fail=1; }
    if grep -n '_ = self.restartBackendInPlace(' "$f" | grep -v '^[0-9]*: *//' > /dev/null; then echo "a restart's result is dropped"; fail=1; fi
    if grep -q 'softRestartRetriesLeft' "$f"; then echo "a second retry counter beside TribeRestartDriver"; fail=1; fi
    rebind=$(awk '/public func rebindListenPortResult\(/ { on = 1 } on { print } on && /^    }$/ { exit }' "$f")
    printf '%s\n' "$rebind" | grep -q 'completionHandler(.failed)' || { echo "a rebind whose new device did not start must answer .failed"; fail=1; }
    grep -q 'socketOps(for: .rebindPort), handle: handle, settingsGenerator: settingsGenerator) ? .performed : .failed' "$f" \
        || { echo "the data watch's fresh-port heal must not be performed without a backend"; fail=1; }
fi
[ "$fail" -eq 0 ] && echo "check_backend_hook: OK"
exit "$fail"
