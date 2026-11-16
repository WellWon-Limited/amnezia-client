#!/bin/bash
# Standalone build + run of the Scanner core checks (lane L1 of scanner-client-plan.md): tunables, classes,
# planner, budget, outcomes, host contract, shade queue, the scan machine with the artboard scenarios on a
# fake clock, auto racing, property tests; then the shared-vector replay (tests/vectors/scan_*_vectors.json).
# `--record` rewrites the vector files from the scenario definitions - only after a deliberate behaviour
# change; it refuses to write when any check fails. Headers only, QtCore. No network, no tunnel.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-scan-core.XXXXXX)}"
mkdir -p "$OUT_DIR"
FLAGS=(-std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter
  -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." -F"$QT/lib")
clang++ "${FLAGS[@]}" "$HERE/scan_core_check.cpp" -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/scan_core_check"
clang++ "${FLAGS[@]}" "$HERE/scan_vectors_check.cpp" -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/scan_vectors_check"
cd "$HERE"
if [ "${1:-}" = "--record" ]; then
  "$OUT_DIR/scan_core_check"
  "$OUT_DIR/scan_vectors_check" --record --dir "$HERE/vectors"
else
  "$OUT_DIR/scan_core_check"
  "$OUT_DIR/scan_vectors_check" --dir "$HERE/vectors"
fi
