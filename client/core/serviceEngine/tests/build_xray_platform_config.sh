#!/bin/bash
# Standalone build + run of the per-platform cached-config check (the real ConfigService.cpp with the
# platform forced by -DAVPN_TEST_XRAY_PLATFORM; release C, lane P1): Apple, Android, Windows. QtCore +
# QtNetwork (the service type only - no request is made: the service has no network access manager).
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-xray-platform-config.XXXXXX)"
trap 'rm -rf -- "${OUT:?}"' EXIT
"$QT/libexec/moc" -f"$HERE/../ConfigService.h" "$HERE/../ConfigService.h" -o "$OUT/moc_ConfigService.cpp"
for platform in Apple Android Windows; do
  clang++ -std=c++17 -fPIC -include arm_acle.h -DAVPN_TEST_XRAY_PLATFORM="$platform" \
    -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" -I"$OUT" -F"$QT/lib" \
    "$HERE/xray_platform_config_check.cpp" "$OUT/moc_ConfigService.cpp" \
    -framework QtCore -framework QtNetwork -framework Foundation \
    -Wl,-rpath,"$QT/lib" -o "$OUT/xray_platform_config_check_$platform"
  "$OUT/xray_platform_config_check_$platform"
done
