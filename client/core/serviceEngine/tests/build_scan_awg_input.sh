#!/bin/bash
# Standalone build + run of the Scanner's awg_mini input check (lane L6b): the device's own AmneziaWG input of an
# own node (DebugSnapshot.h::awgProbeInputFrom) on a fixture, the contract config it builds, no secret in any log
# line or the redacted journal copy. QtCore only.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT="$(mktemp -d /tmp/tribe-scan-awg-input.XXXXXX)"
trap 'rm -rf -- "${OUT:?}"' EXIT
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." -F"$QT/lib" \
  "$HERE/scan_awg_input_check.cpp" \
  -framework QtCore -framework Foundation -Wl,-rpath,"$QT/lib" -o "$OUT/scan_awg_input_check"
"$OUT/scan_awg_input_check"
