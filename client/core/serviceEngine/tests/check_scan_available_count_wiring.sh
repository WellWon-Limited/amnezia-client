#!/bin/bash
# AVPN (owner road 26.11, S4 / journal J8): «N доступно» has one definition - the choice (slotWorks) and the result's
# rings count the same stored result the same way, whether or not its rows are loaded. Behaviour: scanner_facade_check
# caseAvailableCountOneDefinition. Wired here - each line fails if reverted:
#   C1  the ids the coordinator asks the ledger about cover the held rows and every stored result's rows;
#   C2  the coordinator asks for exactly those ids;
#   C3  both counts read one rule (failedHere: the tunnel-no-data set and the tap-failed set - review C6) - slotWorks
#       and the row's verdict (rowViewOf) alike.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
M="$(code "$SE/ScanMachine.h")"
ids="$(printf '%s\n' "$M" | awk '/QStringList tunnelFactIds\(\) const/{f=1} f{print} f&&/^    }$/{exit}')"
has "$ids" 'for (const Row &r : m_rows)' && has "$ids" 'for (const ScanCachedResult &c : m_slots)' \
    || bad "C1: the ledger must be asked about the held rows and every stored result's rows"
sync="$(code "$SE/TribeScanner.cpp" | awk '/^void TribeScanner::syncTunnelFacts\(\)/{f=1} f{print} f&&/^}$/{exit}')"
has "$sync" 'for (const QString &id : m_m.tunnelFactIds())' || bad "C2: the coordinator must ask about tunnelFactIds()"
printf '%s\n' "$M" | grep -q 'rowIds()' && bad "C2: a held-rows-only id list is back"
has "$M" '&& !failedHere(r.id, r.fullProof)) ? 1 : 0;' || bad "C3: slotWorks must read the one rule"
has "$M" 'if (!isCurrent && failedHere(r.id, fullProofOf(r)))' || bad "C3: the row's verdict must read the one rule"
has "$M" 'return (m_tunnelNoData.contains(id) && !fullProof) || m_tapFailed.contains(id);' || bad "C3: the rule must hold both sets"
[ "$fail" = "0" ] && echo "check_scan_available_count_wiring: OK"
exit "$fail"
