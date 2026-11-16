#!/bin/bash
# Standalone build + run of the per-platform Xray gate check (XrayPlatformGate.h, NodeRotation.h; release C,
# lane P1). The same test is built five times: the host's own platform (macOS = Apple) and each platform
# forced with -DAVPN_TEST_XRAY_PLATFORM, so the real callers' decision is run for Android, Windows and the
# rest on this Mac. QtCore only; no network, no tunnel.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-xray-platform-gate.XXXXXX)"
trap 'rm -rf -- "${OUT:?}"' EXIT
build_and_run() {
  local name="$1"; shift
  clang++ -std=c++17 -fPIC -Wall -Wextra "$@" \
    -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/lib/QtCore.framework/Headers" -F"$QT/lib" \
    "$HERE/xray_platform_gate_check.cpp" \
    -framework QtCore -framework Foundation -Wl,-rpath,"$QT/lib" -o "$OUT/$name"
  "$OUT/$name"
}
build_and_run host
build_and_run apple -DAVPN_TEST_XRAY_PLATFORM=Apple
build_and_run android -DAVPN_TEST_XRAY_PLATFORM=Android
build_and_run windows -DAVPN_TEST_XRAY_PLATFORM=Windows
build_and_run other -DAVPN_TEST_XRAY_PLATFORM=Other
