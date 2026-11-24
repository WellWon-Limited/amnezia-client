#!/bin/bash
# Scanner one screen (owner 24.11): the page's wiring to the coordinator, checked at source level (the QML has no unit
# harness in the gate; the offscreen screenshot harness drives the same rules with real touches). Rules:
#  - a choice row only SELECTS: its tap and its accessibility action call select(), which never calls the coordinator;
#  - opening the page never scans (show(), or open(false) on an older coordinator);
#  - the one button acts on the selected scope: Scan = chooseCountry(selected) then retry(); «Показать результат» =
#    showSlot(selected), never retry(); «Показать результат» only when no scan can run and the scope has a fresh result;
#  - the button keeps the action of its press (review rounds 36-37): the press records it, a click fires only when it
#    still means the same, a double tap delivers only a Stop;
#  - the rings are the list's first item in every state (no conditional block, no header mark), and the machine shows
#    no «Найдено N …» shade (the rings say the count); «Остановить» keeps what a scan found;
#  - the Scanner's words say «серверы», never «ноды».
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
PAGE="$CLIENT/ui/qml/Tribe/Pages/PageScannerTribe.qml"
BAR="$CLIENT/ui/qml/Tribe/components/TribeScanBar.qml"
TEXTS="$CLIENT/ui/qml/Tribe/ScanTexts.qml"
MACHINE="$CLIENT/core/serviceEngine/ScanMachine.h"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
# the body of a QML / C++ function or handler: from the line that matches $1 to its closing brace
body_of() {
    awk -v pat="$1" 'index($0, pat) && !on { on = 1; depth = 0 }
        on { print; n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m; if (depth <= 0 && (n > 0 || m > 0)) exit }' "$2"
}
# the text of a QML component: from "component <Name>:" to the next "component " line
component_of() { awk -v pat="component $1:" 'index($0, pat) { on = 1; print; next } on && /^    component / { exit } on { print }' "$2"; }

row="$(component_of ScopeRow "$PAGE")"
[ -n "$row" ] || bad "component ScopeRow not found"
printf '%s\n' "$row" | grep -qE '^\s*onClicked: root\.select\(scope\)\s*$' || bad "a choice row's tap must only select (onClicked: root.select(scope))"
printf '%s\n' "$row" | grep -qE 'Accessible\.onPressAction: root\.select\(scope\)' || bad "a choice row's accessibility press must only select"
printf '%s\n' "$row" | grep -q 'TribeScanner\.' && bad "a choice row must not call the coordinator"
sel="$(body_of 'function select(' "$PAGE")"
[ -n "$sel" ] || bad "select() not found"
printf '%s\n' "$sel" | grep -q 'TribeScanner' && bad "select() must not call the coordinator"
printf '%s\n' "$sel" | grep -q 'selected = sc' || bad "select() must set the selected scope"

open="$(body_of 'Component.onCompleted: {' "$PAGE")"
printf '%s\n' "$open" | grep -q 'TribeScanner.show()' || bad "the page must open with show() (no scan)"
printf '%s\n' "$open" | grep -qE 'retry\(|connectAndScan\(|open\(true\)|chooseCountry\(' && bad "opening the page must never scan"
grep -qE '^\s*property string selected: ""' "$PAGE" || bad "the choice must start on «Все страны» (selected: \"\")"

scan="$(body_of 'function scanSelected(' "$PAGE")"
printf '%s\n' "$scan" | awk '/TribeScanner.chooseCountry\(selected\)/ { c = NR } /TribeScanner.retry\(\)/ { r = NR } END { exit !(c && r && c < r) }' \
    || bad "Scan must hand the selected scope (chooseCountry(selected)) before retry()"
show="$(body_of 'function showSelected(' "$PAGE")"
printf '%s\n' "$show" | grep -q 'TribeScanner.showSlot(selected)' || bad "«Показать результат» must open the selected scope's fresh result"
printf '%s\n' "$show" | grep -qE 'retry\(|chooseCountry\(' && bad "«Показать результат» must never scan"
grep -qF ': (scanGated && slotOf(selected) !== null) ? "show" : "scan"' "$PAGE" \
    || bad "«Показать результат» only when no scan can run and the selected scope has a fresh result"
grep -qF 'onScanTapped: root.scanSelected()' "$PAGE" && grep -qF 'onShowTapped: root.showSelected()' "$PAGE" \
    || bad "the bar's Scan / Show must reach scanSelected() / showSelected()"

grep -qF 'onPressed: root.pressAction = root.action()' "$BAR" || bad "the press must record its action"
click="$(body_of 'onClicked: {' "$BAR")"
printf '%s\n' "$click" | grep -qF 'if (a === root.action()) root.fire(a)' || bad "a click must fire only the action it began with"
dbl="$(body_of 'onDoubleClicked: {' "$BAR")"
printf '%s\n' "$dbl" | grep -qF 'if (a === "stop" && root.action() === "stop") root.fire("stop")' || bad "a double tap must deliver only a Stop"
[ "$(printf '%s\n' "$dbl" | grep -c 'root.fire(')" = 1 ] || bad "a double tap must fire nothing but a Stop"

grep -q 'id: ringsBox' "$PAGE" || bad "the rings block is gone"
awk '/id: ringsBox/ { on = 1 } on && /^\s*visible:/ { print; exit } on && /SignalRing \{/ { exit }' "$PAGE" | grep -q . \
    && bad "the rings block must not hide itself (it is the list's first item in every state)"
grep -qE 'compact: true|rightItem: SignalRing' "$PAGE" && bad "no header mark: the rings stay in the list"
grep -q '"scan_found"' "$MACHINE" && bad "the machine must not show the «Найдено N …» shade (the rings say the count)"
stop="$(body_of 'ScanStep stopTapped(qint64 now)' "$MACHINE")"
printf '%s\n' "$stop" | grep -qF 'foundBesidesLive()) {' && printf '%s\n' "$stop" | grep -qF 'stopStage2(now, QStringLiteral("cancel"), s);' \
    || bad "«Остановить» must keep what the scan found (stopStage2 \"cancel\")"

grep -n 'qsTr(' "$TEXTS" | grep -iE 'нод[аыуе]?[^а-я]|нод"' && bad "the Scanner's words say «серверы», not «ноды» (lines above)"

tap="$(body_of 'ScanStep rowTapped(const QString &id, qint64 now)' "$MACHINE")"
printf '%s\n' "$tap" | grep -qF '!m_connectingId.isEmpty() ||' && bad "F6: a second row tap while one connects must not be dropped"
printf '%s\n' "$tap" | grep -qF 'endChain(s, false);' || bad "F6: the superseded row's request must end without a verdict"

[ "$fail" = 0 ] && echo "scanner page wiring: ok"
exit "$fail"
