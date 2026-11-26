#!/bin/bash
# AVPN (owner road 26.11, S4 / journal J8): «N доступно» has one definition - the choice (slotWorks) and the result's
# rings count the same stored result the same way, whether or not its rows are loaded. Behaviour: scanner_facade_check
# caseAvailableCountOneDefinition. Wired here - each line fails if reverted:
#   C1  the ids the coordinator asks the ledger about cover the held rows and every stored result's rows;
#   C2  the coordinator asks for exactly those ids;
#   C3  both counts read the one set (slotWorks and the row's verdict).
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
has "$M" '&& !(m_tunnelNoData.contains(r.id) && !r.fullProof)) ? 1 : 0;' || bad "C3: slotWorks must read the one set"
has "$M" 'if (!isCurrent && m_tunnelNoData.contains(r.id) && !fullProofOf(r))' || bad "C3: the row's verdict must read the one set"
[ "$fail" = "0" ] && echo "check_scan_available_count_wiring: OK"
exit "$fail"
