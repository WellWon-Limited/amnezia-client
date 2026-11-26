#!/bin/bash
# AVPN (owner road 26.11, S3 / journal J8; review C2): after a relaunch the Scanner's button already knows the mobile hour
# is spent. The rule is ScanBudget.h decideScanStart over ScanMachine::startNeed (behaviour: scan_core_check
# s3BudgetGateIsTheStartRule, scenario budget_blocked_cellular; scanner_facade_check caseBudgetGateAfterRelaunch).
# Wired here - each line fails if reverted:
#   B1  the button's gate is the start rule over the last plan's projection of this network kind;
#   B2  the start stores its plan's projection BEFORE it judges, with the same rule;
#   B3  nothing else in the machine judges the allowance;
#   B4  the coordinator restores the ledger and the projection at construction and writes the projection wherever it
#       writes the ledger;
#   B5  outside a running scan the live probe follows the gate (a blocked hour sends nothing chargeable).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
M="$(code "$SE/ScanMachine.h")"
flat="$(printf '%s\n' "$M" | tr -s ' \n' ' ')"
gate="$(printf '%s\n' "$M" | awk '/ScanBudgetDecision budgetBlocked\(qint64 now\) const/{f=1} f{print} f&&/^    }$/{exit}' | tr -s ' \n' ' ')"
has "$gate" 'return decideScanStart(m_ledger, now, m_net.kind, startNeed(lastProjectionFor(m_net.kind)), m_manifest.manifest.deviceBytesPerHour, m_t);' \
    || bad "B1: the gate must be the start rule over the last projection"
stored="$(printf '%s\n' "$flat" | grep -bo '(m_scanNet.kind == ScanNetKind::Cellular ? m_lastProjectionCell : m_lastProjectionOther) = plan.projectedBytes;' | head -1 | cut -d: -f1)"
judged="$(printf '%s\n' "$flat" | grep -bo 'decideScanStart(m_ledger, now, m_scanNet.kind, startNeed(plan.projectedBytes), m_manifest.manifest.deviceBytesPerHour, m_t)' | head -1 | cut -d: -f1)"
[ -n "$stored" ] && [ -n "$judged" ] && [ "$stored" -lt "$judged" ] || bad "B2: the start must store its projection before it judges, by the same rule"
printf '%s\n' "$M" | grep -q 'decideScanBudget(' && bad "B3: the machine must judge the allowance only through decideScanStart"
[ "$(printf '%s\n' "$M" | grep -c 'decideScanStart(')" = "2" ] || bad "B3: the gate and the start are the only judges"
T="$(code "$SE/TribeScanner.cpp")"
has "$T" 'm_m.restoreBudget(' && has "$T" 'm_m.restoreProjection(QJsonDocument::fromJson(m_store->read(QLatin1String(kScanBudgetProjectionStoreKey))).object());' \
    || bad "B4: the ledger and the projection must be restored at construction"
[ "$(printf '%s\n' "$T" | grep -c 'kScanBudgetStoreKey), compactArray(')" = "$(printf '%s\n' "$T" | grep -c 'kScanBudgetProjectionStoreKey),')" ] \
    || bad "B4: the projection must be written wherever the ledger is"
live="$(printf '%s\n' "$M" | awk '/    void maybeProbeLive\(ScanStep &s\)/{f=1} f{print} f&&/^    }$/{exit}')"
has "$live" 'if (!inScan && budgetBlocked(m_last).hourly) {' || bad "B5: the live probe outside a scan must follow the gate"
[ "$fail" = "0" ] && echo "check_scan_budget_gate_wiring: OK"
exit "$fail"
