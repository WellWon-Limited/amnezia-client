#!/bin/bash
# Standalone build + run of the own-tunnel process matcher of the macOS warning before connecting (lane L6b):
# the Scanner's `amneziawg-go probe` child is never "our tunnel is up". QtCore only.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-mac-service-match.XXXXXX)"
trap 'rm -rf -- "${OUT:?}"' EXIT
clang++ -std=c++17 -fPIC -Wall -Wextra \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/lib/QtCore.framework/Headers" -I"$HERE/.." -F"$QT/lib" \
  "$HERE/mac_service_match_check.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT/mac_service_match_check"
"$OUT/mac_service_match_check"
