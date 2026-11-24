#!/bin/bash
# AVPN (desktop test rig): build + run the test command channel's host test (DevControl.cpp + DevControlApp.cpp over
# a real QLocalServer, against the fakes of dev_control_fakes.h and the QML shape of dev_control_fake.qml; offscreen,
# software scene graph - no window, no app, no service). Also drives the agent's script client/tests/tools/tribe-mac.sh
# in --local mode and a one-shot nc. The release exclusion and the command -> entry point mapping:
# check_dev_control_release.sh, check_dev_control_wiring.sh.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
SE="$HERE/.."
GEN="$(mktemp -d "${TMPDIR:-/tmp}/avpn_devctl.XXXXXX")"
trap 'rm -rf "${GEN:?}"' EXIT
MOCI=(-F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/include" -I"$SE")
"$QT/libexec/moc" "${MOCI[@]}" "$SE/DevControl.h" -o "$GEN/moc_DevControl.cpp"
"$QT/libexec/moc" "${MOCI[@]}" "$SE/DevControlApp.h" -o "$GEN/moc_DevControlApp.cpp"
"$QT/libexec/moc" "${MOCI[@]}" "$SE/DevControlApp.cpp" -o "$GEN/DevControlApp.moc"
"$QT/libexec/moc" "${MOCI[@]}" "$HERE/dev_control_fakes.h" -o "$GEN/moc_dev_control_fakes.cpp"
OUT="$GEN/dev_control_check"
clang++ -std=c++17 -fPIC -Wall -Wextra -Wno-unused-parameter -Werror=return-type \
  -I"$SE" -I"$HERE" -I"$GEN" \
  -F"$QT/lib" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtGui.framework/Headers" \
  -I"$QT/lib/QtNetwork.framework/Headers" -I"$QT/lib/QtQml.framework/Headers" -I"$QT/lib/QtQuick.framework/Headers" \
  -I"$QT/include" \
  "$SE/DevControl.cpp" "$SE/DevControlApp.cpp" "$HERE/dev_control_check.cpp" \
  "$GEN/moc_DevControl.cpp" "$GEN/moc_DevControlApp.cpp" "$GEN/moc_dev_control_fakes.cpp" \
  -framework QtCore -framework QtGui -framework QtNetwork -framework QtQml -framework QtQuick \
  -Wl,-rpath,"$QT/lib" -o "$OUT"
echo ">>> build ok: dev_control_check"
"$OUT" "$HERE/dev_control_fake.qml" "$ROOT/client/tests/tools/tribe-mac.sh"
