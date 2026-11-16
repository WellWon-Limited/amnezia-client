#!/bin/bash
# AVPN (Scanner, lane L4): build + run of ios_scan_host_check.cpp - the pure QtCore parts of the iOS probe host
# (client/core/serviceEngine/IosScanHost.h) against the app's contract decoder (ScanHostContract.h) and the
# shared vectors. macOS Qt only; no device, no network. IosScanHost.mm itself is iOS-only: its syntax check is
# check_ios_scan_compile.sh.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-ios-scan-host.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$CLIENT/core/serviceEngine" -F"$QT/lib" \
  "$HERE/ios_scan_host_check.cpp" -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/ios_scan_host_check"
"$OUT_DIR/ios_scan_host_check" "$CLIENT/core/serviceEngine/tests/vectors"
