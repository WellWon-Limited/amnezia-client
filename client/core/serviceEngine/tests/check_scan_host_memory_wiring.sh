#!/bin/bash
# AVPN (owner road 26.11, S2 / journal J3): a scan start the tunnel's process refuses for memory (connected to a
# provider row) has its own words and leaves no pause. Behaviour: scan_core_check cooldownRule (the refused start
# restores the cooldown, the live probe's bytes stay charged). Wired here - each line fails if reverted:
#   M1  ScanTexts.qml: host_memory has its own title and hint in state 23's layout (not the shared state 23 texts);
#   M2  both shipped translations carry the two sentences (no "unfinished");
#   M3  ScanMachine hostFailed: a start refused for memory restores the cooldown even after the live probe; every
#       other refused start keeps the pause once the live probe went (review C1: their texts say «через минуту»);
#   M4  the host's available / needed MB of the refusal are in the existing "host start error" line.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
CLIENT="$(cd "$HERE/../../.." && pwd)"
TEXTS="$CLIENT/ui/qml/Tribe/ScanTexts.qml"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

# ---- M1 ----
q="$(code "$TEXTS")"
has "$q" 'readonly property string memoryTitle: qsTr("Сейчас проверить нельзя")' \
    && has "$q" 'readonly property string memoryText: qsTr("Подключённому серверу нужна почти вся память VPN. Отключите VPN и запустите проверку снова.")' \
    || bad "M1: the host_memory texts are missing"
mem="$(printf '%s\n' "$q" | awk '/case "host_memory":/{f=1} f{print} f&&/return/{exit}')"
has "$mem" 'title: t.memoryTitle, text: t.memoryText' && has "$mem" 'layout: "blocked"' \
    || bad "M1: host_memory must show its own texts in state 23's layout"
printf '%s\n' "$mem" | grep -qF 'return engine' && bad "M1: host_memory falls back to the shared state 23 texts"

# ---- M2 ----
for l in en es; do
    ts="$CLIENT/translations/tribe/tribe_$l.ts"
    for src in 'Сейчас проверить нельзя' 'Подключённому серверу нужна почти вся память VPN. Отключите VPN и запустите проверку снова.'; do
        grep -A1 -F "<source>$src</source>" "$ts" | grep -q '<translation>[^<]' || bad "M2: $l has no translation of «$src»"
    done
done

# ---- M3 ----
hf="$(code "$SE/ScanMachine.h" | awk '/ScanStep hostFailed\(const QString &scanId, ScanHostError e, qint64 now/{f=1} f{print} f&&/^    }$/{exit}')"
has "$hf" 'if (st == &m_cur && (!m_liveProbeSent || e == ScanHostError::Memory))' && has "$hf" 'm_cooldownUntil = m_cooldownPrev;' \
    || bad "M3: only a memory refusal restores the cooldown after the live probe; the others keep it"

# ---- M4 ----
has "$(code "$SE/TribeScanner.cpp")" 'QStringLiteral("host start error=%1 mem_mb=%2 need_mb=%3")' \
    || bad "M4: the memory refusal's figures must be in the host start error line"

[ "$fail" = "0" ] && echo "check_scan_host_memory_wiring: OK"
exit "$fail"
