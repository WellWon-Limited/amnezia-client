#!/bin/bash
# AVPN (emulator round 26.11.2026, D4): «Обновлять автоматически» showed in Settings on Android while the update sheet hid
# it there - the condition lived in two copies and only the sheet's had the Android term. It is kept once
# (Tribe/UpdateSwitches.qml autoUpdateShown); each line fails if a reader goes back to its own copy:
#   U1  the singleton holds the silent-install condition: canSelfUpdate and not Android, and is registered (qmldir, qrc);
#   U2  Settings (PageAccountTribe) and the update sheet (TribeUpdateSheet) both read it, and neither keeps its own
#       canSelfUpdate condition for that switch.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
QML="$CLIENT/ui/qml"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

# ---- U1 ----
sw="$(code "$QML/Tribe/UpdateSwitches.qml")"
has "$sw" 'pragma Singleton' || bad "U1: UpdateSwitches.qml must be a singleton"
printf '%s\n' "$sw" | tr -s ' \n' ' ' | grep -F 'autoUpdateShown: hasEngine && TribeEngine.canSelfUpdate === true && Qt.platform.os !== "android"' \
    > /dev/null || bad "U1: autoUpdateShown must be canSelfUpdate and not Android"
grep -qx 'singleton UpdateSwitches 1.0 UpdateSwitches.qml' "$QML/Tribe/qmldir" || bad "U1: UpdateSwitches missing in Tribe/qmldir"
grep -qF '<file>Tribe/UpdateSwitches.qml</file>' "$QML/qml.qrc" || bad "U1: UpdateSwitches.qml missing in qml.qrc"

# ---- U2 ----
for f in "$QML/Tribe/Pages/PageAccountTribe.qml" "$QML/Tribe/components/TribeUpdateSheet.qml"; do
    c="$(code "$f")"
    has "$c" 'visible: UpdateSwitches.autoUpdateShown' || bad "U2: $(basename "$f") must read UpdateSwitches.autoUpdateShown"
done
# neither file carries a private copy of the condition next to the shared one
for f in "$QML/Tribe/Pages/PageAccountTribe.qml" "$QML/Tribe/components/TribeUpdateSheet.qml"; do
    if code "$f" | grep -E 'visible:.*canSelfUpdate === true' | grep -vqF 'UpdateSwitches'; then
        c="$(code "$f" | grep -nE 'visible:.*canSelfUpdate === true' || true)"
        bad "U2: $(basename "$f") keeps its own canSelfUpdate visibility: $c"
    fi
done

[ "$fail" -eq 0 ] && echo "update switch wiring: OK"
exit "$fail"
