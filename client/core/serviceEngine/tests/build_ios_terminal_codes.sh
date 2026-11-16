#!/bin/bash
# Standalone build + run of the terminal-code parity check: the iOS bridge's list (platforms/ios/IosNativePolicy.h)
# against the engine's (UpstreamStatusWire.h), renew_rejected included (lane L6b fix). QtCore only.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT="$(mktemp -d /tmp/tribe-ios-terminal-codes.XXXXXX)"
trap 'rm -rf -- "${OUT:?}"' EXIT
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." -F"$QT/lib" \
  "$HERE/ios_terminal_codes_check.cpp" \
  -framework QtCore -framework Foundation -Wl,-rpath,"$QT/lib" -o "$OUT/ios_terminal_codes_check"
"$OUT/ios_terminal_codes_check"
