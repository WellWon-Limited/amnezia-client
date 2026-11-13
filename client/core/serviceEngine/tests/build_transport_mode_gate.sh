#!/bin/bash
# Standalone build + run of the transport-mode gate (5.1.109, S4.1): when the user's stored choice of
# the transport mode is in force - load, the startup observation, "nothing is running", a real gain
# against a choice usable since load, sessions this process did not start, the tap, the macOS
# runtime gate. Header only (TransportModeGate.h), QtCore; no engine, no facade, no network.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-transport-mode-gate.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  "$HERE/transport_mode_gate_check.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/transport_mode_gate_check"
"$OUT_DIR/transport_mode_gate_check"
