#!/bin/bash
# AVPN path engine stage 2: build + run scan_path_prober_model_check.cpp - the random model check of the race prober
# (ScanPathProber) against a hostile model host (late, reordered, repeated replies; scans closed by the host; cancels).
# MODEL_RUNS = number of sequences (default 3000). No network, no device.
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-scan-path-prober-model.XXXXXX)}"
ARCH_FLAGS=()
[ "$(uname -m)" = "arm64" ] && ARCH_FLAGS=(-include arm_acle.h)
clang++ -std=c++17 -fPIC ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} -Wall -Wextra -Wno-unused-parameter \
  -I"$SE" -I"$CLIENT" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" -F"$QT/lib" \
  "$SE/ScanPathProber.cpp" "$HERE/scan_path_prober_model_check.cpp" -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" \
  -o "$OUT_DIR/scan_path_prober_model_check"
"$OUT_DIR/scan_path_prober_model_check"
