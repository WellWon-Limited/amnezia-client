#!/bin/bash
# AVPN (device round R 26.11, finding 3): a single tunnel "no data" ages from its own moment and expires after
# noDataTtlMs (the top of the quarantine ladder); a probe pass neither clears a live mark nor extends it; two or more
# failures stay the ladder's. Behaviour: path_engine_check testNoDataMarkTtl, path_integration_check (S6 block).
# Wired here - each line fails if reverted:
#   L1  the probe-pass block in PathLedger::record reads the one rule (noDataMarkHolds), no inline copy;
#   L2  tunnelNoDataHere reads the same rule on an entry view() still reads (revision, evidenceTtlMs);
#   L3  the rule ages the mark from noDataMs (not from the entry's touch) and leaves a dead row to the ladder;
#   L4  ServiceEngine::failedInTunnelHere asks the ledger's tunnelNoDataHere and keeps no copy of the rule;
#   L5  the default TTL is the ladder's last step.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
L="$(code "$SE/path/PathLedger.h")"
rec="$(printf '%s\n' "$L" | awk '/    bool record\(const QString &network, const PathId &path, PathOutcome o/{f=1} f{print} f&&/^    }$/{exit}')"
has "$rec" 'if (noDataMarkHolds(e, nowMs, m_t))' || bad "L1: the probe-pass block must read noDataMarkHolds"
has "$rec" 'e.noDataMs >= e.dataOkMs' && bad "L1: an inline copy of the no-data rule is back in record()"
tnd="$(printf '%s\n' "$L" | awk '/    bool tunnelNoDataHere\(const QString &network, const PathId &path, qint64 nowMs\) const/{f=1} f{print} f&&/^    }$/{exit}')"
has "$tnd" 'if (e.revision != path.revision || nowMs - e.touchedMs > m_t.evidenceTtlMs)' \
    || bad "L2: tunnelNoDataHere must skip another revision and an entry untouched for evidenceTtlMs"
has "$tnd" 'return noDataMarkHolds(e, nowMs, m_t);' || bad "L2: tunnelNoDataHere must read noDataMarkHolds"
rule="$(printf '%s\n' "$L" | awk '/    static bool noDataMarkHolds\(const LedgerEntry &e, qint64 nowMs, const LedgerTunables &t\)/{f=1} f{print} f&&/^    }$/{exit}')"
has "$rule" 'if (e.failStreak <= 0 || e.noDataMs <= 0 || e.noDataMs < e.dataOkMs)' || bad "L3: the mark needs a failure, a no-data and no data ok since"
has "$rule" 'return e.failStreak >= 2 || nowMs - e.noDataMs < t.noDataTtlMs;' \
    || bad "L3: a single mark must age from noDataMs on noDataTtlMs, a dead row must stay the ladder's"
has "$rule" 'touchedMs' && bad "L3: the mark must not age from the entry's touch"
S="$(code "$SE/ServiceEngine.cpp" | awk '/^bool ServiceEngine::failedInTunnelHere\(const QString &nodeId\) const/{f=1} f{print} f&&/^}$/{exit}')"
has "$S" 'return m_ledger.tunnelNoDataHere(m_net.current().local, path::derivePathId(*n), nowMs());' \
    || bad "L4: failedInTunnelHere must ask the ledger's tunnelNoDataHere"
has "$S" 'noDataMs' && bad "L4: failedInTunnelHere keeps its own copy of the rule"
has "$(code "$SE/path/PathTunables.h")" 'long long noDataTtlMs = quarantineMs.back();' \
    || bad "L5: noDataTtlMs must default to the quarantine ladder's last step"
[ "$fail" = "0" ] && echo "check_ledger_no_data_ttl_wiring: OK"
exit "$fail"
