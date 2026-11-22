#!/bin/bash
# Scanner row chain (release 141, device round air20 R3, D1): a row tapped right after another row failed was marked
# «Не удалось» before its own attempt began - the facade fed the row's chain the engine's Error of the OLDER attempt.
# The rule is pure (DebugSnapshot.h scanRowAttemptObserve, facade_policy_check scannerRowOutcomeBelongsToItsAttempt);
# AvpnEngineQml.cpp has no unit harness, so its inputs are checked at source level: the tap records the intent epoch
# it set, and every observation passes the epoch of the engine's newest attempt (never the facade's current epoch,
# which would make any older attempt's Error the new row's).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
ENG="$SE/ServiceEngine.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
body_of() { awk -v start="$1" 'index($0, start) == 1 { on = 1 } on { print } on && /^}/ { exit }' "$2"; }

tap="$(body_of 'void AvpnEngineQml::connectToNode(' "$FAC")"
[ -n "$tap" ] || bad "connectToNode() not found"
printf '%s\n' "$tap" | grep -qF 'scanRowAttemptBegin(m_scanRow, nodeId, m_intentSerial, m_intentEpoch.epoch)' \
    || bad "a row tap must record the intent epoch its own attempt serves"

sync="$(body_of 'void AvpnEngineQml::scanSyncState()' "$FAC")"
[ -n "$sync" ] || bad "scanSyncState() not found"
printf '%s\n' "$sync" | tr -s ' \n' ' ' | grep -qF 'attemptOver, m_engine.lastAttemptIntentEpoch())' \
    || bad "the row chain must be told which intent the engine's newest attempt serves (lastAttemptIntentEpoch)"
printf '%s\n' "$sync" | grep -v '^[[:space:]]*//' | grep -q 'gaveUp' \
    && bad "scanSyncState must not fold the engine's Error into one give-up flag again"

owner="$(body_of 'void ServiceEngine::feedOwner(' "$ENG")"
printf '%s\n' "$owner" | grep -qF 'm_lastAttemptEpoch = m_intentEpoch;' \
    || bad "every attempt the owner begins must stamp the newest attempt's intent epoch"

[ "$fail" = 0 ] && echo "scan row attempt wiring: ok"
exit "$fail"
