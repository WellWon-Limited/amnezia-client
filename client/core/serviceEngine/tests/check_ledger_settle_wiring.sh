#!/bin/bash
# AVPN (device round R 26.11, finding 3; review of 1ff3cf163): failure evidence of the path ledger expires by its own
# age - one settle rule (PathLedger::settled) applied to the stored entry before a new observation is counted and to a
# copy in every const reader, so every reader sees the same thing at the same moment with no probe needed. Behaviour:
# path_engine_check testFailureSettle, path_integration_check (S6 blocks). Wired here - each line fails if reverted:
#   L1  record() settles the stored entry before the new observation; its probe-pass block reads noDataMarkHolds;
#   L2  view() and tunnelNoDataHere() read a settled copy (after the revision / evidenceTtlMs check);
#   L3  the rule: void once the quarantine is over and the newest failure is failureTtlMs old - the streak, the
#       no-data time, the ended quarantine; the data proof only when the forgotten evidence holds a no-data not
#       older than it (noDataMarkHolds, read before the streak is cleared - review of 863c9d8e8); the failure time
#       is lastFailureMs, falling back to noDataMs, never touchedMs;
#   L4  the no-data mark reads the settled entry only (no age or streak special case of its own);
#   L5  ServiceEngine::failedInTunnelHere asks the ledger's tunnelNoDataHere and keeps no copy of the rule;
#   L6  the default TTL is the quarantine ladder's last step.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
body() { printf '%s\n' "$1" | awk -v start="$2" 'index($0, start){f=1} f{print} f&&/^    }$/{exit}'; }
L="$(code "$SE/path/PathLedger.h")"
rec="$(body "$L" '    bool record(const QString &network, const PathId &path, PathOutcome o')"
pre="$(printf '%s\n' "$rec" | awk '/switch \(o\)/{exit} {print}')"
has "$pre" 'e = settled(e, nowMs, m_t);' || bad "L1: record() must settle the stored entry before the new observation"
has "$rec" 'if (noDataMarkHolds(e))' || bad "L1: the probe-pass block must read noDataMarkHolds on the settled entry"
has "$rec" 'e.noDataMs >= e.dataOkMs' && bad "L1: an inline copy of the no-data rule is back in record()"
view="$(body "$L" '    PathView view(const QString &network, const PathId &path, qint64 nowMs) const')"
has "$view" 'const LedgerEntry e = settled(it.value(), nowMs, m_t);' || bad "L2: view() must read a settled copy"
tnd="$(body "$L" '    bool tunnelNoDataHere(const QString &network, const PathId &path, qint64 nowMs) const')"
has "$tnd" 'if (it->revision != path.revision || nowMs - it->touchedMs > m_t.evidenceTtlMs)' \
    || bad "L2: tunnelNoDataHere must skip another revision and an entry untouched for evidenceTtlMs"
has "$tnd" 'return noDataMarkHolds(settled(it.value(), nowMs, m_t));' || bad "L2: tunnelNoDataHere must read a settled copy"
rule="$(body "$L" '    static LedgerEntry settled(LedgerEntry e, qint64 nowMs, const LedgerTunables &t)')"
has "$rule" 'const qint64 last = lastFailureAt(e);' || bad "L3: the rule must age from the newest failure"
has "$rule" 'if (last <= 0 || nowMs < e.quarantineUntilMs || nowMs - last < t.failureTtlMs)' \
    || bad "L3: void only once the quarantine is over and the newest failure is failureTtlMs old"
for line in 'e.failStreak = 0;' 'e.noDataMs = 0;' 'e.quarantineUntilMs = 0;' 'if (supersededProof) {' 'e.dataOkMs = 0;'; do
    has "$rule" "$line" || bad "L3: the settle must void: $line"
done
printf '%s\n' "$rule" | awk '/const bool supersededProof = noDataMarkHolds\(e\);/{p=NR} /e.failStreak = 0;/{c=NR} END{exit !(p && c && p < c)}' \
    || bad "L3: only a no-data (noDataMarkHolds, read before the streak is cleared) may void the data proof"
has "$rule" 'e.dataOkMs <= last' && bad "L3: a data proof voided by the failure time alone (lost handshakes must keep it)"
has "$rule" 'probeOkMs' && bad "L3: the settle must keep the probe facts"
has "$L" 'static qint64 lastFailureAt(const LedgerEntry &e) { return e.lastFailureMs > 0 ? e.lastFailureMs : e.noDataMs; }' \
    || bad "L3: the failure time is lastFailureMs, then noDataMs"
printf '%s\n' "$rule" | grep -q 'touchedMs' && bad "L3: the rule must not age from the entry's touch"
mark="$(body "$L" '    static bool noDataMarkHolds(const LedgerEntry &e)')"
has "$mark" 'return e.failStreak > 0 && e.noDataMs > 0 && e.noDataMs >= e.dataOkMs;' || bad "L4: the mark reads the settled entry"
printf '%s\n' "$mark" | grep -qE 'nowMs|failStreak >= 2' && bad "L4: the mark keeps an age or streak case of its own"
S="$(code "$SE/ServiceEngine.cpp" | awk '/^bool ServiceEngine::failedInTunnelHere\(const QString &nodeId\) const/{f=1} f{print} f&&/^}$/{exit}')"
has "$S" 'return m_ledger.tunnelNoDataHere(m_net.current().local, path::derivePathId(*n), nowMs());' \
    || bad "L5: failedInTunnelHere must ask the ledger's tunnelNoDataHere"
has "$S" 'noDataMs' && bad "L5: failedInTunnelHere keeps its own copy of the rule"
has "$(code "$SE/path/PathTunables.h")" 'long long failureTtlMs = quarantineMs.back();' \
    || bad "L6: failureTtlMs must default to the quarantine ladder's last step"
[ "$fail" = "0" ] && echo "check_ledger_settle_wiring: OK"
exit "$fail"
