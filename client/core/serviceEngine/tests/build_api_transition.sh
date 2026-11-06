#!/bin/bash
# Decision 2026-11-05 + owner test 06.11: tunnel transitions on the shared QNAM (clear + abort of
# requests in flight, NetAwait.h + DebugSnapshot.h) with a real QNetworkAccessManager and a loopback server.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT="$(mktemp -d /tmp/tribe-api-transition.XXXXXX)"
trap 'rm -rf -- "$OUT"' EXIT
"$QT/libexec/moc" "$HERE/api_transition_check.cpp" -o "$OUT/api_transition_check.moc"
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtTest.framework/Headers" -I"$OUT" -I"$CLIENT" -F"$QT/lib" \
  "$HERE/api_transition_check.cpp" \
  -framework QtCore -framework QtNetwork -framework QtTest -framework Foundation \
  -Wl,-rpath,"$QT/lib" -o "$OUT/api_transition_check"
WW_TEST=1 WW_TEST_ID=api-transition "$OUT/api_transition_check"
