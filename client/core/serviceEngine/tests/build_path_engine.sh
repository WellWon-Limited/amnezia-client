#!/bin/bash
# Standalone build + run of the path engine core check (design 2026-11-17 "one mechanism to choose a path", stage
# 1): PathId, NetworkKey, PathLedger, PathSelect, AttemptOwner (client/core/serviceEngine/path/) and the network
# scenarios of design §9 in the simulator tests/path_world.h. Headers only, QtCore.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-path-engine.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  -F"$QT/lib" \
  "$HERE/path_engine_check.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/path_engine_check"
"$OUT_DIR/path_engine_check"
