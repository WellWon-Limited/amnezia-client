#!/bin/bash
# Standalone build + run of the Android upstream status wire check (UpstreamStatusWire.h; release C, lane P1):
# decode, parity with the iOS bridge's rules (IosNativePolicy.h), the macOS owner's object, the engine's
# decision, the hand-over message. QtCore only; no network, no device.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT="$(mktemp -d /tmp/tribe-upstream-status-wire.XXXXXX)"
trap 'rm -rf -- "${OUT:?}"' EXIT
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." -F"$QT/lib" \
  "$HERE/upstream_status_wire_check.cpp" \
  -framework QtCore -framework Foundation -Wl,-rpath,"$QT/lib" -o "$OUT/upstream_status_wire_check"
"$OUT/upstream_status_wire_check"
