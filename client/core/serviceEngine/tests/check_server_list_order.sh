#!/bin/bash
# Device round of 142 (A4, iPhone Air): the server list re-sorted between a look and the tap (a latency update) and a
# tap aimed at «Финляндия 1» selected «Эстония 2». Rule: the order the person sees is taken when the page opens (or on
# the person's own change of the transport mode) and kept while the page is on screen; values inside the rows update in
# place; a press and its tap stay on one row.
#   A  the order rule by behaviour: tests/server_list_order_check.qml runs ui/qml/Tribe/ServerListOrder.js headless
#      (Qt's `qml`, offscreen);
#   B  where it is wired in PageServersTribe.qml - each line fails if its call site is reverted:
#      O1 the ListView's model is the order (location keys); a row reads its values from rowsByKey in place;
#      O2 an update keeps the order on screen (keepShownOrder) unless a fresh sort was asked;
#      O3 a fresh sort only when the page opens and when the transport mode changes; the engine's changed() keeps the
#         order; the search only filters it;
#      O4 the values update before the order waits; the order waits while the list moves or a row is pressed;
#      O5 a pressed row holds the order, its tap acts on its own row (row.d); the waiting order follows only after the
#         release was delivered (review R50 5: Qt emits pressedChanged before clicked - a new model array on the release
#         destroyed the delegate whose onClicked was about to run; driven by touches in the offscreen harness);
#      O6 ServerListOrder.js is in qml.qrc (else a blank page in a qrc build).
# Run by the check sweep (every check_*.sh of this directory).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
PAGE="$CLIENT/ui/qml/Tribe/Pages/PageServersTribe.qml"
JS="$CLIENT/ui/qml/Tribe/ServerListOrder.js"
QRC="$CLIENT/ui/qml/qml.qrc"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
# the body of a QML function or handler: from the line that matches $1 to its closing brace
body_of() {
    code "$2" | awk -v pat="$1" 'index($0, pat) && !on { on = 1; depth = 0 }
        on { print; n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m; if (depth <= 0 && (n > 0 || m > 0)) exit }'
}
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

# ---- A ----
if [ ! -f "$JS" ]; then
    bad "A: no $JS"
elif [ ! -x "$QT/bin/qml" ]; then
    bad "A: no Qt qml runner at $QT/bin/qml (set QT_ROOT)"
else
    out="$(QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORM_PLUGIN_PATH="$QT/plugins/platforms" "$QT/bin/qml" "$HERE/server_list_order_check.qml" 2>&1)"
    rc=$?
    printf '%s\n' "$out" | grep -E 'FAIL|server_list_order_check' | sed 's/^qml: //'
    printf '%s\n' "$out" | grep -q 'server_list_order_check: OK' && [ "$rc" -eq 0 ] || bad "A: the order rule failed (exit $rc)"
fi

# ---- B ----
p="$(code "$PAGE")"
has "$p" 'import "../ServerListOrder.js" as ServerListOrder' || bad "O1: the page must use ServerListOrder.js"
has "$p" 'model: root.shownKeys' || bad "O1: the ListView's model must be the order on screen (root.shownKeys)"
has "$p" 'required property string modelData   // the location key' || bad "O1: a delegate is one location key"
has "$p" 'readonly property var d: root.rowsByKey[row.modelData] || root.emptyRow' || bad "O1: a row reads its values from rowsByKey"
has "$p" 'row.modelData.' && bad "O1: a delegate must not read values from its model entry (row.modelData.*)"
has "$p" 'model: root.countries' && bad "O1: the sorted rows must not be the model"

rebuild="$(body_of 'function rebuildCountries(resort)' "$PAGE")"
[ -n "$rebuild" ] || bad "O2: function rebuildCountries(resort) not found"
has "$rebuild" 'const order = root.resortPending ? sortedKeys : ServerListOrder.keepShownOrder(root.orderKeys, sortedKeys)' \
    || bad "O2: an update must keep the order on screen unless a fresh sort was asked"

has "$(body_of 'Component.onCompleted: {' "$PAGE")" 'rebuildCountries(true)' || bad "O3: the page opens with a fresh sort"
has "$p" 'onTransportModeChanged: rebuildCountries(true)' || bad "O3: a transport mode change sorts afresh"
has "$(body_of 'function onChanged()' "$PAGE")" 'root.rebuildCountries(false)' || bad "O3: the engine's changed() must keep the order"
has "$p" 'onQueryChanged: applyQuery()' || bad "O3: the search only filters the order"
[ "$(printf '%s\n' "$p" | grep -c 'rebuildCountries(true)')" = "2" ] || bad "O3: a fresh sort only on open and on a mode change"

vals="$(printf '%s\n' "$rebuild" | grep -n 'root.rowsByKey = byKey' | head -1 | cut -d: -f1)"
wait_="$(printf '%s\n' "$rebuild" | grep -n 'root.orderPending = true' | head -1 | cut -d: -f1)"
[ -n "$vals" ] && [ -n "$wait_" ] && [ "$vals" -lt "$wait_" ] || bad "O4: the values must update in place before the order waits"
has "$p" 'readonly property bool listTouched: list.moving || list.dragging || pressedKey !== ""' \
    || bad "O4: the order waits while the list moves or a row is pressed"
has "$p" 'onListTouchedChanged: if (!listTouched && orderPending) Qt.callLater(root.followWaitingOrder)' \
    || bad "O5: a waiting order follows after the release was delivered (Qt.callLater), never inside pressedChanged"
follow="$(body_of 'function followWaitingOrder() {' "$PAGE")"
has "$follow" 'if (!root.listTouched && root.orderPending)' && has "$follow" 'root.rebuildCountries(false)' \
    || bad "O4: the deferred follow re-checks the touch and keeps the order rule (rebuildCountries(false))"
printf '%s\n' "$p" | grep -E 'onListTouchedChanged:.*rebuildCountries' > /dev/null \
    && bad "O5: the release must not rebuild the model synchronously (the tap of the row is lost)"

ma="$(body_of 'onPressedChanged: {' "$PAGE")"
has "$ma" 'root.pressedKey = row.modelData' || bad "O5: a pressed row must hold the order (pressedKey)"
has "$(code "$PAGE" | awk '/delegate: Rectangle \{/,0')" 'root.pickNode(row.d.nodeId)' || bad "O5: the tap picks its own row (row.d.nodeId)"

grep -qF '<file>Tribe/ServerListOrder.js</file>' "$QRC" || bad "O6: Tribe/ServerListOrder.js is not in qml.qrc"

[ "$fail" -eq 0 ] && echo "check_server_list_order: OK"
exit "$fail"
