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
#  - the Scanner's words say «серверы», never «ноды»;
#  review of 24.11: the rings' number is the machine's one count (view.available); the button acts only on a scope
#  shown as selected and taken by the machine (a vanished selection falls back to «Все страны»); «Все страны» counts
#  the white lists too; a stopped result is marked wherever it is shown (view.partial, slots[].partial) and a
#  PersistResults with store false only feeds the evidence; a second row tap while one connects is not dropped.
#  owner 25.11 (143): the title stands right after the back arrow with «Подбор серверов» at the right edge on its
#  baseline (the shared header stays centred by default); the count badge is the server icon and the number, its
#  accessible name the whole phrase; the rings are one size on the choice too (no heroIdle, no size animation).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
PAGE="$CLIENT/ui/qml/Tribe/Pages/PageScannerTribe.qml"
BAR="$CLIENT/ui/qml/Tribe/components/TribeScanBar.qml"
TEXTS="$CLIENT/ui/qml/Tribe/ScanTexts.qml"
MACHINE="$CLIENT/core/serviceEngine/ScanMachine.h"
FACADE="$CLIENT/core/serviceEngine/TribeScanner.cpp"
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
take="$(body_of 'function takeSelected(' "$PAGE")"
printf '%s\n' "$take" | grep -qF 'TribeScanner.chooseCountry(selected)' \
    && printf '%s\n' "$scan" | awk '/takeSelected\(\)/ { c = NR } /TribeScanner.retry\(\)/ { r = NR } END { exit !(c && r && c < r) }' \
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

# review of 24.11
grep -qE '^\s*readonly property int foundCount: Number\(view\.available \|\| 0\)\s*$' "$PAGE" \
    || bad "F1: the number in the rings must be the machine's view.available"
grep -qF 'o.insert(QStringLiteral("available"), v.availableCount);' "$MACHINE" || bad "F1: the view must carry available"
printf '%s\n' "$take" | grep -qF 'if (!listed(selected)) {' && printf '%s\n' "$take" | grep -qF 'return String(barView.scope || "") === selected' \
    || bad "F2: the button acts only on a listed scope the machine took"
printf '%s\n' "$scan" | grep -qF '!takeSelected()' || bad "F2: Scan must go through takeSelected()"
grep -qF 'onSelectedListedChanged: if (!selectedListed) Qt.callLater(dropUnlistedSelection)' "$PAGE" \
    || bad "F2: a selection whose row left the list must fall back to «Все страны»"
retry="$(body_of 'ScanStep retryTapped(qint64 now)' "$MACHINE")"
printf '%s\n' "$retry" | grep -qF '!m_scopeRefused' || bad "F2: retry() after a refused scope choice must not scan"
cnt="$(body_of 'function scopeCount(' "$PAGE")"
printf '%s\n' "$cnt" | grep -qF 'let n = cc === "" ? Math.max(0, poolWhitelist) : 0' || bad "F3: «Все страны» must count the white lists"
grep -qF 'readonly property bool partialResult: view.partial === true' "$PAGE" && grep -qF ': partialResult ? (' "$PAGE" \
    || bad "F5: the rings' line must say a stopped result (view.partial)"
grep -qF 'return slot.partial === true ? ScanTexts.slotStopped' "$PAGE" || bad "F5: a choice row must mark a stopped result"
persist="$(awk '/case ScanActionKind::PersistResults:/ { on = 1 } on { print } on && /break;/ { exit }' "$FACADE")"
printf '%s\n' "$persist" | grep -qF 'if (a.storeResult) {' && printf '%s\n' "$persist" | grep -qF 'onResultsSaved(a.cached);' \
    || bad "F5: PersistResults with store false must only feed the evidence"
tap="$(body_of 'ScanStep rowTapped(const QString &id, qint64 now)' "$MACHINE")"
printf '%s\n' "$tap" | grep -qF '!m_connectingId.isEmpty() ||' && bad "F6: a second row tap while one connects must not be dropped"
printf '%s\n' "$tap" | grep -qF 'endChain(s, false);' || bad "F6: the superseded row's request must end without a verdict"

# device round air-C, D1: one verdict per row - the coordinator never rewrites a row's state after the machine counted
refresh="$(body_of 'void TribeScanner::refreshView()' "$FACADE")"
printf '%s\n' "$refresh" | grep -qE 'insert\(QStringLiteral\("state"\)' && bad "D1: refreshView must not rewrite a row's state (the machine's verdict)"
grep -qF 'dispatch(m_m.tunnelNoDataHere(ids, now()));' "$FACADE" || bad "D1: the ledger's S6 fact must reach the machine (tunnelNoDataHere)"
grep -qF 'readonly property bool available: rowState === "works" || rowState === "slow"' "$CLIENT/ui/qml/Tribe/components/TribeScanRow.qml" \
    || bad "D1: a slow row must read «Доступно» (it is counted)"

# owner 25.11 (143): the header - «Сканер» right after the back arrow, «Подбор серверов» at the right edge
HEADER="$CLIENT/ui/qml/Tribe/components/TribeHeader.qml"
ICONS="$CLIENT/ui/qml/Tribe/components/TribeStrokeIcon.qml"
THEME="$CLIENT/ui/qml/Tribe/Theme.qml"
hdr="$(awk '/^    TribeHeader \{/ { on = 1 } on { print } on && /^    \}/ { exit }' "$PAGE")"
printf '%s\n' "$hdr" | grep -qE '^\s*titleAlignment: Qt\.AlignLeft\s*$' \
    || bad "143: the title must stand right after the back arrow (titleAlignment: Qt.AlignLeft)"
printf '%s\n' "$hdr" | grep -qE '^\s*caption: ScanTexts\.titleCaption\s*$' || bad "143: the header's right caption must be ScanTexts.titleCaption"
grep -qF 'readonly property string titleCaption: qsTr("Подбор серверов")' "$TEXTS" || bad "143: the caption must say «Подбор серверов»"
grep -qE '^\s*property int titleAlignment: Qt\.AlignHCenter\s*$' "$HEADER" || bad "143: the shared header must stay centred by default"
grep -qF 'anchors.baseline: titleText.baseline' "$HEADER" || bad "143: the caption must stand on the title's baseline"
# the count badge: the server icon and the number; the screen reader and the UI driver read the whole phrase
badge="$(awk '/objectName: "scannerCountBadge"/ { on = 1 } on { print } on && /^        \}/ { exit }' "$PAGE")"
printf '%s\n' "$badge" | grep -qE '^\s*icon: "server"\s*$' || bad "143: the count badge must show the server icon"
printf '%s\n' "$badge" | grep -qE '^\s*text: String\(badgesRow\.count\)\s*$' || bad "143: the count badge must show the number only"
printf '%s\n' "$badge" | grep -qE '^\s*Accessible\.name: ScanTexts\.servers\(badgesRow\.count\)\s*$' \
    || bad "143: the count badge's accessible name must be the whole phrase («228 серверов»)"
grep -qE '^\s*"server": "M' "$ICONS" || bad "143: the kit must have the server icon"
# the rings: one size in one place in every state, no animation between the choice and a result
grep -q 'heroIdle' "$PAGE" "$THEME" && bad "143: no small rings on the choice (Theme.scan.heroIdle must be gone)"
grep -qE 'heroFrac|heroAnim' "$PAGE" && bad "143: no size animation between the choice and a result"
rings="$(awk '/id: ringsBox/ { on = 1 } on { print } on && /SignalRing \{/ { exit }' "$PAGE")"
printf '%s\n' "$rings" | grep -qE '^\s*scale:' && bad "143: the rings must never be scaled down"
printf '%s\n' "$rings" | grep -qF 'y: (Theme.scan.hero - height) / 2' || bad "143: the rings must be centred on the full band (Theme.scan.hero)"

[ "$fail" = 0 ] && echo "scanner page wiring: ok"
exit "$fail"
