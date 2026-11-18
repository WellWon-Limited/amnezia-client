#!/bin/bash
# Syntax-level compile (no object kept, no link) of the path engine core (client/core/serviceEngine/path/*.h)
# with the toolchains of every platform, before any engine translation unit includes it. The check translation
# unit tests/path_engine_check.cpp includes every header of path/ plus the simulator, so one TU covers them.
# Once ServiceEngine.cpp / AvpnEngineQml.cpp include path/ headers, check_upstream_compile.sh covers them too.
#   macOS:   host clang with Qt for macOS (always)
#   IOS=1:   the iOS SDK (arm64-apple-ios16.0) with Qt for iOS
#   ANDROID=1: the NDK clang (aarch64-linux-android28) with Qt for Android
#   WINDOWS_APPROX=1: zig c++ (x86_64-windows-gnu, mingw headers) with the macOS Qt headers - APPROXIMATE, as in
#     check_upstream_compile.sh: catches C++ errors, not MSVC specifics; the real proof is the CI MSVC build.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
TU="$HERE/path_engine_check.cpp"
ERR="$(mktemp /tmp/path-core-compile.XXXXXX)"
fail=0

QTM="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
if clang++ -std=c++17 -fsyntax-only -Wall -Wextra -Wno-unused-parameter -I"$QTM/lib/QtCore.framework/Headers" \
    -F"$QTM/lib" -I"$CLIENT" "$TU" 2>"$ERR"; then
  echo "macOS syntax OK: path core"
else
  echo "macOS syntax FAIL: path core"; grep -m 12 "error:" "$ERR"; fail=1
fi

if [ "${IOS:-0}" = "1" ]; then
  QTI="${QT_IOS:-$HOME/Qt/6.11.1/ios}"
  SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
  if clang++ -std=gnu++17 -target arm64-apple-ios16.0 -isysroot "$SDK" -fsyntax-only -DQT_CORE_LIB -DQT_NO_DEBUG \
      -isystem "$QTI/include" -isystem "$QTI/include/QtCore" -isystem "$QTI/lib/QtCore.framework/Headers" \
      -isystem "$QTI/mkspecs/macx-ios-clang" -iframework "$QTI/lib" -I"$CLIENT" "$TU" 2>"$ERR"; then
    echo "iOS syntax OK: path core"
  else
    echo "iOS syntax FAIL: path core"; grep -m 12 "error:" "$ERR"; fail=1
  fi
fi

if [ "${ANDROID:-0}" = "1" ]; then
  NDK="${ANDROID_NDK:-$HOME/Library/Android/sdk/ndk/27.0.11718014}"
  NDK_CXX="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang++"
  QTA="${QT_ANDROID:-$HOME/Qt/6.11.1/android_arm64_v8a}"
  if "$NDK_CXX" --target=aarch64-linux-android28 -std=gnu++17 -fPIC -fsyntax-only -DQT_CORE_LIB -DQT_NO_DEBUG \
      -I"$QTA/include" -I"$QTA/include/QtCore" -I"$QTA/mkspecs/android-clang" -I"$CLIENT" "$TU" 2>"$ERR"; then
    echo "Android syntax OK: path core"
  else
    echo "Android syntax FAIL: path core"; grep -m 12 "error" "$ERR"; fail=1
  fi
fi

if [ "${WINDOWS_APPROX:-0}" = "1" ]; then
  SHIM_W="$(mktemp -d /tmp/tribe-path-win.XXXXXX)"
  ln -s "$QTM/lib/QtCore.framework/Headers" "$SHIM_W/QtCore"
  # zig: -fsyntax-only ends with a bogus FileNotFound - the object goes into the temp dir, removed below.
  if zig c++ -target x86_64-windows-gnu -std=gnu++17 -DQT_CORE_LIB -DQT_NO_DEBUG -I"$SHIM_W" -I"$SHIM_W/QtCore" \
      -I"$CLIENT" -c -o "$SHIM_W/out.obj" "$TU" 2>"$ERR"; then
    echo "Windows (approximate, mingw) syntax OK: path core"
  else
    echo "Windows (approximate, mingw) syntax FAIL: path core"; grep -v warning "$ERR" | grep -m 12 "error"; fail=1
  fi
  rm -rf -- "${SHIM_W:?}"
fi
rm -f -- "${ERR:?}"
exit $fail
