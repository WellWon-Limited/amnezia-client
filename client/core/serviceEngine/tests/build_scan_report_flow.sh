#!/bin/bash
# Standalone build + run of the Scanner report check's path through the support report queue (lane L6b):
# reservation / backpressure, schema-5 report as the bench part, per-id acks deciding the card's shade.
# QtCore only, a temp directory, a fake clock.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-scan-report-flow.XXXXXX)"
trap 'rm -rf -- "${OUT:?}"' EXIT
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/lib/QtCore.framework/Headers" -I"$HERE/.." -F"$QT/lib" \
  "$HERE/scan_report_flow_check.cpp" \
  -framework QtCore -framework Foundation -Wl,-rpath,"$QT/lib" -o "$OUT/scan_report_flow_check"
"$OUT/scan_report_flow_check"
