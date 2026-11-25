#!/bin/bash
# Device round of 142 (air-C, iPhone Air): «Заменить сервер» on the main screen was pressed with the VPN off and the app
# connected at once to the pinned server (journal: intent wanted=1 with no orb_tap - the button's TribeEngine.start()).
# Rule: the button replaces the server of a live connection (rotateNext, CONNECT-INVARIANTS §11); with nothing to
# replace (off, an attempt that ended) it opens the server choice; busy - nothing; it never starts a connection by
# itself (the orb does). Checked at source level (the offscreen harness drives the same rule with a real touch):
#   R1 the button's press: busy -> nothing; !isOn -> requestServerPicker(); connected -> rotateNext(); no start
#      (round mac-D2: the MouseArea calls the page function onReplaceServerClicked, which holds the decisions - the
#      development builds' test channel presses the same function);
#   R2 the host routes requestServerPicker to the server choice page (PageServersTribe).
# Run by the check sweep (every check_*.sh of this directory).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
PAGE="$CLIENT/ui/qml/Tribe/Pages/PageConnectTribe.qml"
START="$CLIENT/ui/qml/Pages2/PageStart.qml"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
# the MouseArea whose line holds "id: <id>": from that line to the brace that closes the MouseArea
mouse_area() {
    code "$2" | awk -v pat="id: $1;" 'index($0, pat) && !on { on = 1; depth = 1; print; next }
        on { print; n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m; if (depth <= 0) exit }'
}
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

ma="$(mouse_area refreshMa "$PAGE")"
[ -n "$ma" ] || bad "R1: the «Заменить сервер» MouseArea (id: refreshMa) not found"
has "$(code "$PAGE")" 'text: !(root.hasEngine && TribeEngine.busy) ? qsTr("Заменить сервер")' || bad "R1: refreshMa must be the «Заменить сервер» button"
has "$ma" 'onClicked: root.onReplaceServerClicked()' || bad "R1: refreshMa must press the page's onReplaceServerClicked()"
# the page function the press runs: from its line to the brace that closes it
fn="$(code "$PAGE" | awk 'index($0, "function onReplaceServerClicked() {") && !on { on = 1; depth = 1; print; next }
        on { print; n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m; if (depth <= 0) exit }')"
[ -n "$fn" ] || bad "R1: function onReplaceServerClicked() not found"
for call in 'TribeEngine.start(' 'connectButtonClicked' 'orbTap' 'pinAndReconnect' 'switchToNode' 'reconcile'; do
    has "$ma$fn" "$call" && bad "R1: «Заменить сервер» must never start a connection itself ($call)"
done
ma="$fn" # the decisions below are the function's
# the order of the decisions: busy first, then off -> the server choice, then the rotation
busy="$(printf '%s\n' "$ma" | grep -nF 'if (TribeEngine.busy) return' | head -1 | cut -d: -f1)"
off="$(printf '%s\n' "$ma" | grep -nF 'if (!root.isOn) {' | head -1 | cut -d: -f1)"
pick="$(printf '%s\n' "$ma" | grep -nF 'root.requestServerPicker()' | head -1 | cut -d: -f1)"
rot="$(printf '%s\n' "$ma" | grep -nF 'TribeEngine.rotateNext()' | head -1 | cut -d: -f1)"
[ -n "$busy" ] || bad "R1: a press while busy must do nothing"
[ -n "$off" ] && [ -n "$pick" ] && [ "$pick" -eq $((off + 1)) ] || bad "R1: with the VPN off the press must open the server choice"
[ -n "$rot" ] && [ -n "$pick" ] && [ "$rot" -gt "$pick" ] || bad "R1: connected, the press replaces the server (rotateNext) after the off branch returned"
[ -n "$busy" ] && [ -n "$off" ] && [ "$busy" -lt "$off" ] || bad "R1: busy is decided before off"

has "$(code "$START")" 'function onRequestServerPicker() { tabBarStackView.goToTabBarPageUrl("../Tribe/Pages/PageServersTribe.qml") }' \
    || bad "R2: PageStart must open PageServersTribe on requestServerPicker"

[ "$fail" -eq 0 ] && echo "check_replace_server_wiring: OK"
exit "$fail"
