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
[ "$fail" -eq 0 ] && echo "check_backend_hook: OK"
exit "$fail"
