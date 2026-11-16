#!/bin/bash
# Syntax-level compile (clang -fsyntax-only: no object, no link, no moc) of the Scanner engine wiring (lane
# L6b): coreController.cpp (the TribeScanner context property and the probe host factory) next to the engine,
# with the include paths and defines of a real macOS desktop build tree, plus an iOS pass (IosScanHost branch)
# and an Android pass (no host). check_upstream_compile.sh covers AvpnEngineQml.cpp, ServiceEngine.cpp and
# the coordinator sources; this one adds the controller that wires them. Nothing is built or installed.
#   BUILD_DIR=<macOS build tree> (default ~/amnezia-client/deploy/build-macos-desktop)
#   IOS=1 / ANDROID=1 add the passes (as in check_upstream_compile.sh).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$HOME/amnezia-client/deploy/build-macos-desktop}"
FLAGS_MAKE="$BUILD_DIR/client/CMakeFiles/AmneziaVPN.dir/flags.make"
[ -f "$FLAGS_MAKE" ] || { echo "no flags.make at $FLAGS_MAKE"; exit 2; }
ORIG_CLIENT="$(grep -E '^CXX_INCLUDES' "$FLAGS_MAKE" | tr ' ' '\n' | grep -E '^-I.*/client$' | grep -vxF -- "-I${BUILD_DIR%/}/client" | grep -v deploy | head -1 | sed 's/^-I//')"
rewrite() { sed "s#${ORIG_CLIENT}#${CLIENT}#g"; }
INCLUDES="$(grep -E '^CXX_INCLUDES' "$FLAGS_MAKE" | sed 's/^CXX_INCLUDES = //' | rewrite)"
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
INCLUDES="$INCLUDES -I$MAIN_CLIENT -I$MAIN_CLIENT/3rd/qtkeychain"
DEFINES="$(grep -E '^CXX_DEFINES' "$FLAGS_MAKE" | sed 's/^CXX_DEFINES = //')"
CXXFLAGS="$(grep -E '^CXX_FLAGS =' "$FLAGS_MAKE" | sed 's/^CXX_FLAGS = //')"
SE="$CLIENT/core/serviceEngine"
# Third-party headers the controller pulls in (libssh for the self-hosted wizard, openssl, zlib): the conan
# packages of the macOS tree - plain headers, reused read-only by the iOS and Android passes.
DEPS_INC=""
for d in $(grep -E '^CXX_INCLUDES' "$FLAGS_MAKE" | tr ' ' '\n' | grep -E '/\.conan2/' | sort -u); do
  DEPS_INC="$DEPS_INC -isystem $d"
done
CC_TU="$CLIENT/core/controllers/coreController.cpp"
ERR="$(mktemp /tmp/scan-engine-compile.XXXXXX)"
fail=0

for tu in "$CC_TU" "$SE/AvpnEngineQml.cpp"; do
  # shellcheck disable=SC2086
  if eval clang++ $CXXFLAGS $DEFINES $INCLUDES -fsyntax-only -Wno-deprecated-declarations "\"$tu\"" 2>"$ERR"; then
    echo "macOS syntax OK: ${tu#$CLIENT/}"
  else
    echo "macOS syntax FAIL: ${tu#$CLIENT/}"; grep -m 20 "error:" "$ERR"; fail=1
  fi
done

if [ "${IOS:-0}" = "1" ]; then
  QTI="${QT_IOS:-$HOME/Qt/6.11.1/ios}"
  SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
  IOS_INC="-isystem $QTI/include -isystem $QTI/include/QtCore -isystem $QTI/include/QtNetwork -isystem $QTI/include/QtGui \
    -isystem $QTI/include/QtQml -isystem $QTI/include/QtQuick -isystem $QTI/include/QtCore5Compat -isystem $QTI/mkspecs/macx-ios-clang \
    -iframework $QTI/lib -isystem $QTI/lib/QtCore.framework/Headers -isystem $QTI/lib/QtNetwork.framework/Headers \
    -isystem $QTI/lib/QtRemoteObjects.framework/Headers -isystem $QTI/lib/QtGui.framework/Headers \
    -isystem $QTI/lib/QtQml.framework/Headers -isystem $QTI/lib/QtQuick.framework/Headers \
    -isystem $QTI/lib/QtCore5Compat.framework/Headers -isystem $QTI/include/QtQmlIntegration \
    -isystem $QTI/lib/QtQuickControls2.framework/Headers -isystem $QTI/include/QtQuickControls2 \
    -isystem $QTI/lib/QtConcurrent.framework/Headers -isystem $QTI/include/QtConcurrent \
    -isystem $QTI/lib/QtSvg.framework/Headers -isystem $QTI/include/QtSvg -isystem $QTI/lib/QtXml.framework/Headers \
    -I$CLIENT -I$CLIENT/mozilla -I$CLIENT/mozilla/shared -I$CLIENT/../ipc -I$CLIENT/../common/logger -I$CLIENT/../common/crypto \
    -I$CLIENT/3rd/qrcodegen -I$MAIN_CLIENT/3rd/qrcodegen -I$CLIENT/3rd/qtkeychain -I$MAIN_CLIENT -I$BUILD_DIR/client/AmneziaVPN_autogen/include -I$BUILD_DIR/client -I$BUILD_DIR/client/3rd/qtkeychain -I$BUILD_DIR/3rd/qtkeychain/qtkeychain"
  IOS_DEF="-DQT_CORE_LIB -DQT_NETWORK_LIB -DQT_REMOTEOBJECTS_LIB -DQT_GUI_LIB -DQT_QML_LIB -DQT_NO_DEBUG -DAVPN_ENGINE_ENABLED=1 \
    -DGROUP_ID=\\\"group.hk.wellwon.tribe\\\" -DVPN_NE_BUNDLEID=\\\"hk.wellwon.vpn.network-extension\\\" -DAPP_TS_PREFIX=\\\"amneziavpn\\\""
  # coreController.cpp includes swiftBridge.h -> the generated AmneziaVPN-Swift.h of an iOS Xcode build:
  # IOS_SWIFT_HDR_DIR, else the newest DerivedSources under ~/avpn-build (read only).
  SWIFT_DIR="${IOS_SWIFT_HDR_DIR:-}"
  if [ -z "$SWIFT_DIR" ]; then
    SWIFT_HDR="$(ls -t "$HOME"/avpn-build/*/build/AmneziaVPN.build/Release-iphoneos/DerivedSources/AmneziaVPN-Swift.h 2>/dev/null | head -1)"
    [ -n "$SWIFT_HDR" ] && SWIFT_DIR="$(dirname "$SWIFT_HDR")"
  fi
  [ -n "$SWIFT_DIR" ] && IOS_INC="$IOS_INC -I$SWIFT_DIR"
  for tu in "$SE/AvpnEngineQml.cpp" "$CC_TU"; do
    if [ "$tu" = "$CC_TU" ] && [ -z "$SWIFT_DIR" ]; then
      echo "iOS syntax SKIP: ${tu#$CLIENT/} (no AmneziaVPN-Swift.h of an iOS build)"; continue
    fi
    # shellcheck disable=SC2086
    if eval clang++ -std=gnu++17 -target arm64-apple-ios16.0 -isysroot "$SDK" $IOS_DEF $IOS_INC $DEPS_INC -fsyntax-only "\"$tu\"" 2>"$ERR"; then
      echo "iOS syntax OK: ${tu#$CLIENT/}"
    else
      echo "iOS syntax FAIL: ${tu#$CLIENT/}"; grep -m 12 "error:" "$ERR"; fail=1
    fi
  done
fi

if [ "${ANDROID:-0}" = "1" ]; then
  NDK="${ANDROID_NDK:-$HOME/Library/Android/sdk/ndk/27.0.11718014}"
  NDK_CXX="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang++"
  QTA="${QT_ANDROID:-$HOME/Qt/6.11.1/android_arm64_v8a}"
  A_INC="-I$QTA/include -I$QTA/mkspecs/android-clang"
  for m in QtCore QtNetwork QtGui QtQml QtQuick QtCore5Compat QtQmlIntegration QtConcurrent QtRemoteObjects QtSvg QtXml QtQuickControls2; do
    A_INC="$A_INC -I$QTA/include/$m"
  done
  CLIENT_INC="-I$CLIENT -I$CLIENT/mozilla -I$CLIENT/mozilla/shared -I$CLIENT/../ipc -I$CLIENT/../common/logger \
    -I$CLIENT/../common/crypto -I$CLIENT/3rd/qrcodegen -I$MAIN_CLIENT/3rd/qrcodegen -I$CLIENT/3rd/qtkeychain \
    -I$MAIN_CLIENT/3rd/qtkeychain -I$MAIN_CLIENT -I$BUILD_DIR/client/AmneziaVPN_autogen/include -I$BUILD_DIR/client \
    -I$BUILD_DIR/client/3rd/qtkeychain -I$BUILD_DIR/3rd/qtkeychain/qtkeychain"
  A_DEF="-DQT_CORE_LIB -DQT_NETWORK_LIB -DQT_GUI_LIB -DQT_QML_LIB -DQT_QUICK_LIB -DQT_NO_DEBUG -DAVPN_ENGINE_ENABLED=1 -D_WINSOCKAPI_ -DAPP_TS_PREFIX=\"amneziavpn\""
  for tu in "$SE/AvpnEngineQml.cpp" "$CC_TU"; do
    # shellcheck disable=SC2086
    if eval "\"$NDK_CXX\"" --target=aarch64-linux-android28 -std=gnu++17 -fPIC $A_DEF $A_INC $CLIENT_INC $DEPS_INC \
        -fsyntax-only -Wno-deprecated-declarations "\"$tu\"" 2>"$ERR"; then
      echo "Android syntax OK: ${tu#$CLIENT/}"
    else
      echo "Android syntax FAIL: ${tu#$CLIENT/}"; grep -m 12 "error" "$ERR"; fail=1
    fi
  done
fi
rm -f -- "${ERR:?}"
exit $fail
