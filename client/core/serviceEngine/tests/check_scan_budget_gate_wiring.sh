#!/bin/bash
# AVPN (owner road 26.11, S3 / journal J8): after a relaunch the Scanner's button already knows the mobile hour is spent.
# The rule is ScanBudget.h decideScanStart (behaviour: scan_core_check s3BudgetGateIsTheStartRule, scenario
# budget_blocked_cellular). Wired here - each line fails if reverted:
#   B1  the button's gate (budgetBlocked) is the start rule with no plan known;
#   B2  the start check is the same function with the plan's projection;
#   B3  nothing else in the machine judges the allowance (no second rule, no memory-only projection);
#   B4  the coordinator restores the persisted ledger into the machine.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
M="$(code "$SE/ScanMachine.h")"
gate="$(printf '%s\n' "$M" | awk '/ScanBudgetDecision budgetBlocked\(qint64 now\) const/{f=1} f{print} f&&/^    }$/{exit}')"
has "$gate" 'return decideScanStart(m_ledger, now, m_net.kind, -1, m_manifest.manifest.deviceBytesPerHour, m_t);' \
    || bad "B1: the gate must be the start rule with no plan known"
printf '%s\n' "$M" | tr -s ' \n' ' ' | grep -qF 'decideScanStart(m_ledger, now, m_scanNet.kind, plan.projectedBytes + appWorstCase() + attempts, m_manifest.manifest.deviceBytesPerHour, m_t)' \
    || bad "B2: the start check must be the same rule with the plan's projection"
printf '%s\n' "$M" | grep -q 'decideScanBudget(' && bad "B3: the machine must judge the allowance only through decideScanStart"
printf '%s\n' "$M" | grep -q 'm_lastProjection' && bad "B3: no memory-only projection may feed the gate"
[ "$(printf '%s\n' "$M" | grep -c 'decideScanStart(')" = "2" ] || bad "B3: the gate and the start are the only judges"
has "$(code "$SE/TribeScanner.cpp")" 'restoreBudget(' || bad "B4: the persisted ledger must reach the machine"
[ "$fail" = "0" ] && echo "check_scan_budget_gate_wiring: OK"
exit "$fail"
