#!/bin/bash
# Syntax-level compile (clang -fsyntax-only, no object, no link, no moc) of the translation units the
# upstream-node wiring touches, with the include paths and defines of a real macOS desktop build tree
# (its flags.make; the generated headers - QtRO replicas, autogen - are read from that tree, the sources
# from THIS checkout). Optional second pass with the iOS SDK + Qt for iOS and the defines of the iOS app
# (Q_OS_IOS paths of the shared engine). Nothing is built, signed or installed.
#   BUILD_DIR=<macOS build tree> (default ~/amnezia-client/deploy/build-macos-desktop)
#   IOS=1 additionally runs the iOS pass.
#   ANDROID=1 (release C) additionally runs an Android pass: the NDK clang (aarch64-linux-android28) with
#     Qt for Android headers - the Q_OS_ANDROID paths of the shared engine and android_controller.cpp.
#     Generated headers still come from the macOS tree (autogen); no moc, no link, no gradle.
#   WINDOWS_APPROX=1 (release C) additionally runs an APPROXIMATE Windows pass: zig c++ (clang, mingw
#     target x86_64-windows-gnu, mingw headers) with the macOS Qt headers. NOT MSVC and NOT the Windows Qt
#     build: it only catches C++ errors inside our Q_OS_WIN branches; the real proof is the CI MSVC build.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$HOME/amnezia-client/deploy/build-macos-desktop}"
FLAGS_MAKE="$BUILD_DIR/client/CMakeFiles/AmneziaVPN.dir/flags.make"
[ -f "$FLAGS_MAKE" ] || { echo "no flags.make at $FLAGS_MAKE"; exit 2; }
ORIG_CLIENT="$(grep -E '^CXX_INCLUDES' "$FLAGS_MAKE" | tr ' ' '\n' | grep -E '^-I.*/client$' | grep -vxF -- "-I${BUILD_DIR%/}/client" | grep -v deploy | head -1 | sed 's/^-I//')"
rewrite() { sed "s#${ORIG_CLIENT}#${CLIENT}#g"; }
INCLUDES="$(grep -E '^CXX_INCLUDES' "$FLAGS_MAKE" | sed 's/^CXX_INCLUDES = //' | rewrite)"
# Fallback for 3rd submodules a git worktree may not have checked out (qtkeychain): the main checkout's
# headers, read only, lowest priority.
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
INCLUDES="$INCLUDES -I$MAIN_CLIENT -I$MAIN_CLIENT/3rd/qtkeychain"
DEFINES="$(grep -E '^CXX_DEFINES' "$FLAGS_MAKE" | sed 's/^CXX_DEFINES = //')"
CXXFLAGS="$(grep -E '^CXX_FLAGS =' "$FLAGS_MAKE" | sed 's/^CXX_FLAGS = //')"
SE="$CLIENT/core/serviceEngine"
TUS=(
  "$SE/ServiceEngine.cpp"
  "$SE/VpnConnectionTunnelControl.cpp"
  "$SE/XrayConfigBuilder.cpp"
  "$SE/UpstreamLeaseClient.cpp"
  "$SE/AvpnEngineQml.cpp"
  "$SE/ConfigService.cpp"
  "$CLIENT/core/protocols/xrayProtocol.cpp"
  "$SE/ScanApiClient.cpp"
  "$SE/TribeScanner.cpp"
)
fail=0
for tu in "${TUS[@]}"; do
  # shellcheck disable=SC2086
  if eval clang++ $CXXFLAGS $DEFINES $INCLUDES -fsyntax-only -Wno-deprecated-declarations "\"$tu\"" 2>/tmp/upstream_compile_err.txt; then
    echo "macOS syntax OK: ${tu#$CLIENT/}"
  else
    echo "macOS syntax FAIL: ${tu#$CLIENT/}"; grep -m 20 "error:" /tmp/upstream_compile_err.txt; fail=1
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
    -I$CLIENT -I$CLIENT/mozilla -I$CLIENT/mozilla/shared -I$CLIENT/../ipc -I$CLIENT/../common/logger -I$CLIENT/../common/crypto \
    -I$CLIENT/3rd/qrcodegen -I${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}/3rd/qrcodegen -I$CLIENT/3rd/qtkeychain -I${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client} -I$BUILD_DIR/client/AmneziaVPN_autogen/include -I$BUILD_DIR/client -I$BUILD_DIR/client/3rd/qtkeychain -I$BUILD_DIR/3rd/qtkeychain/qtkeychain"
  IOS_DEF="-DQT_CORE_LIB -DQT_NETWORK_LIB -DQT_REMOTEOBJECTS_LIB -DQT_GUI_LIB -DQT_QML_LIB -DQT_NO_DEBUG -DAVPN_ENGINE_ENABLED=1 \
    -DGROUP_ID=\\\"group.hk.wellwon.tribe\\\" -DVPN_NE_BUNDLEID=\\\"hk.wellwon.vpn.network-extension\\\""
  for tu in "$SE/ServiceEngine.cpp" "$SE/XrayConfigBuilder.cpp" "$SE/UpstreamLeaseClient.cpp" "$SE/VpnConnectionTunnelControl.cpp" "$SE/AvpnEngineQml.cpp" \
      "$SE/ScanApiClient.cpp" "$SE/TribeScanner.cpp"; do
    # shellcheck disable=SC2086
    if eval clang++ -std=gnu++17 -target arm64-apple-ios16.0 -isysroot "$SDK" $IOS_DEF $IOS_INC -fsyntax-only "\"$tu\"" 2>/tmp/upstream_compile_ios_err.txt; then
      echo "iOS syntax OK: ${tu#$CLIENT/}"
    else
      echo "iOS syntax FAIL: ${tu#$CLIENT/}"; grep -m 12 "error:" /tmp/upstream_compile_ios_err.txt; fail=1
    fi
  done
fi

# Shared by the release C passes: the client's own include dirs and the build tree's generated headers.
CLIENT_INC="-I$CLIENT -I$CLIENT/mozilla -I$CLIENT/mozilla/shared -I$CLIENT/../ipc -I$CLIENT/../common/logger \
  -I$CLIENT/../common/crypto -I$CLIENT/3rd/qrcodegen -I$MAIN_CLIENT/3rd/qrcodegen -I$CLIENT/3rd/qtkeychain \
  -I$MAIN_CLIENT/3rd/qtkeychain -I$MAIN_CLIENT -I$BUILD_DIR/client/AmneziaVPN_autogen/include -I$BUILD_DIR/client \
  -I$BUILD_DIR/client/3rd/qtkeychain -I$BUILD_DIR/3rd/qtkeychain/qtkeychain"
STR_DEF='-DCLIENT_KEYCHAIN_NAME_STR="AVPN-Keychain" -DDEV_AGW_ENDPOINT="" -DDEV_AGW_PUBLIC_KEY="" -DDEV_S3_ENDPOINT="" -DFALLBACK_S3_ENDPOINT="" -DFREE_V2_ENDPOINT="" -DPREM_V1_ENDPOINT="" -DPROD_AGW_PUBLIC_KEY="" -DPROD_S3_ENDPOINT="" -DGIT_COMMIT_HASH="syntax"'
QT_MODULES="QtCore QtNetwork QtGui QtQml QtQuick QtCore5Compat QtQmlIntegration QtConcurrent QtRemoteObjects QtSvg QtXml QtQuickControls2"
RELEASE_C_TUS=(
  "$SE/ServiceEngine.cpp"
  "$SE/VpnConnectionTunnelControl.cpp"
  "$SE/AvpnEngineQml.cpp"
  "$SE/ConfigService.cpp"
  "$SE/ScanApiClient.cpp"
  "$SE/TribeScanner.cpp"
)

if [ "${ANDROID:-0}" = "1" ]; then
  NDK="${ANDROID_NDK:-$HOME/Library/Android/sdk/ndk/27.0.11718014}"
  NDK_CXX="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang++"
  QTA="${QT_ANDROID:-$HOME/Qt/6.11.1/android_arm64_v8a}"
  A_INC="-I$QTA/include -I$QTA/mkspecs/android-clang"
  for m in $QT_MODULES; do A_INC="$A_INC -I$QTA/include/$m"; done
  A_DEF="-DQT_CORE_LIB -DQT_NETWORK_LIB -DQT_GUI_LIB -DQT_QML_LIB -DQT_QUICK_LIB -DQT_NO_DEBUG -DAVPN_ENGINE_ENABLED=1 -D_WINSOCKAPI_"
  for tu in "${RELEASE_C_TUS[@]}" "$CLIENT/platforms/android/android_controller.cpp"; do
    # shellcheck disable=SC2086
    if eval "\"$NDK_CXX\"" --target=aarch64-linux-android28 -std=gnu++17 -fPIC $A_DEF "$STR_DEF" $A_INC $CLIENT_INC \
        -fsyntax-only -Wno-deprecated-declarations "\"$tu\"" 2>/tmp/upstream_compile_android_err.txt; then
      echo "Android syntax OK: ${tu#$CLIENT/}"
    else
      echo "Android syntax FAIL: ${tu#$CLIENT/}"; grep -m 12 "error" /tmp/upstream_compile_android_err.txt; fail=1
    fi
  done
fi

if [ "${WINDOWS_APPROX:-0}" = "1" ]; then
  QTM="${QT_MAC:-$HOME/Qt/6.11.1/macos}"
  SHIM_W="$(mktemp -d /tmp/tribe-win-qt.XXXXXX)"
  for m in $QT_MODULES; do
    if [ -d "$QTM/lib/$m.framework/Headers" ]; then ln -s "$QTM/lib/$m.framework/Headers" "$SHIM_W/$m"
    elif [ -d "$QTM/include/$m" ]; then ln -s "$QTM/include/$m" "$SHIM_W/$m"; fi
  done
  # The macOS Qt install has no Windows-only Qt headers: the one QtGui needs is shimmed with the handle
  # declarations Qt's own qwindowdefs_win.h makes.
  mkdir -p "$SHIM_W/extra/QtGui"
  cat > "$SHIM_W/extra/QtGui/qwindowdefs_win.h" <<'SHIM'
#ifndef QWINDOWDEFS_WIN_H
#define QWINDOWDEFS_WIN_H
#include <QtGui/qtguiglobal.h>
#ifndef STRICT
#define STRICT
#endif
#define Q_DECLARE_HANDLE(name) struct name##__; typedef struct name##__ *name
#ifndef HINSTANCE
Q_DECLARE_HANDLE(HINSTANCE);
#endif
Q_DECLARE_HANDLE(HDC); Q_DECLARE_HANDLE(HWND); Q_DECLARE_HANDLE(HFONT); Q_DECLARE_HANDLE(HPEN);
Q_DECLARE_HANDLE(HBRUSH); Q_DECLARE_HANDLE(HBITMAP); Q_DECLARE_HANDLE(HICON); typedef HICON HCURSOR;
Q_DECLARE_HANDLE(HPALETTE); Q_DECLARE_HANDLE(HRGN); Q_DECLARE_HANDLE(HMONITOR);
#ifndef _HRESULT_DEFINED
typedef long HRESULT;
#endif
typedef struct tagMSG MSG;
#endif
SHIM
  W_INC="-I$SHIM_W/extra -I$SHIM_W"
  for m in $QT_MODULES; do W_INC="$W_INC -I$SHIM_W/$m"; done
  # zig: -fsyntax-only ends with a bogus FileNotFound and -o /dev/null leaves <name>.obj in the current
  # directory - the object goes into the temp dir, removed below.
  W_DEF="-DAMNEZIA_DESKTOP -DQT_CORE_LIB -DQT_NETWORK_LIB -DQT_GUI_LIB -DQT_QML_LIB -DQT_QUICK_LIB -DQT_REMOTEOBJECTS_LIB -DQT_NO_DEBUG -DAVPN_ENGINE_ENABLED=1 -D_WINSOCKAPI_"
  for tu in "${RELEASE_C_TUS[@]}" "$CLIENT/core/protocols/xrayProtocol.cpp"; do
    # shellcheck disable=SC2086
    if eval zig c++ -target x86_64-windows-gnu -std=gnu++17 $W_DEF "$STR_DEF" $W_INC $CLIENT_INC \
        -c -o "\"$SHIM_W/out.obj\"" -Wno-deprecated-declarations "\"$tu\"" 2>/tmp/upstream_compile_windows_err.txt; then
      echo "Windows (approximate, mingw) syntax OK: ${tu#$CLIENT/}"
    else
      echo "Windows (approximate, mingw) syntax FAIL: ${tu#$CLIENT/}"; grep -v warning /tmp/upstream_compile_windows_err.txt | grep -m 12 "error"; fail=1
    fi
  done
  rm -rf -- "${SHIM_W:?}"
fi
exit $fail
