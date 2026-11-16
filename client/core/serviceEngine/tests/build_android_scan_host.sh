#!/bin/bash
# AVPN (Scanner, lane A3): build + run of android_scan_host_check.cpp - the pure QtCore parts of the Android probe
# host (client/core/serviceEngine/AndroidScanHost.h) against the shared vectors. macOS Qt only; no device, no
# network. ANDROID=1 additionally syntax-checks AndroidScanHost.cpp itself with the NDK clang and Qt for Android
# (BUILD_DIR = an Android build tree for the generated headers, default deploy/build-android-a3).
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-android-scan-host.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$CLIENT/core/serviceEngine" -F"$QT/lib" \
  "$HERE/android_scan_host_check.cpp" -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/android_scan_host_check"
"$OUT_DIR/android_scan_host_check" "$CLIENT/core/serviceEngine/tests/vectors"

if [ "${ANDROID:-0}" = "1" ]; then
  NDK="${ANDROID_NDK:-$HOME/Library/Android/sdk/ndk/27.0.11718014}"
  NDK_CXX="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang++"
  QTA="${QT_ANDROID:-$HOME/Qt/6.11.1/android_arm64_v8a}"
  BUILD_DIR="${BUILD_DIR:-$CLIENT/../deploy/build-android-a3}"
  INC="-I$QTA/include -I$QTA/mkspecs/android-clang"
  for m in QtCore QtNetwork QtGui QtQml QtQuick QtCore5Compat QtConcurrent; do INC="$INC -I$QTA/include/$m"; done
  INC="$INC -I$CLIENT -I$CLIENT/core/serviceEngine -I$CLIENT/mozilla -I$CLIENT/mozilla/shared -I$CLIENT/../ipc \
    -I$CLIENT/../common/logger -I$BUILD_DIR/client -I$BUILD_DIR/client/AmneziaVPN_autogen/include"
  # shellcheck disable=SC2086
  "$NDK_CXX" --target=aarch64-linux-android28 -std=gnu++17 -fPIC -DQT_CORE_LIB -DQT_NO_DEBUG $INC \
    -fsyntax-only -Wno-deprecated-declarations "$CLIENT/core/serviceEngine/AndroidScanHost.cpp"
  echo "Android syntax OK: core/serviceEngine/AndroidScanHost.cpp"
fi
