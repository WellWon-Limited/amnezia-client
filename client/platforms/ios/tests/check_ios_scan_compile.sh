#!/bin/bash
# AVPN (Scanner, lane L4): iOS syntax compile (clang -fsyntax-only: no object, no link, no moc) of the app-side
# translation units of the iOS probe host - client/core/serviceEngine/IosScanHost.mm, the in-app host IosAppScanHost.mm
# (with -DAVPN_IOS_APP_SCAN_HOST=1) and
# client/platforms/ios/ios_controller.mm (the scan channel) - with the iPhoneOS SDK, Qt for iOS and the iOS app's
# defines, the way core/serviceEngine/tests/check_upstream_compile.sh does its IOS=1 pass (generated headers from
# a macOS desktop build tree). The files are compiled MRC, like the app target compiles them. Nothing is built,
# signed or installed.
#   BUILD_DIR=<macOS build tree> (default ~/amnezia-client/deploy/build-macos-desktop), QT_IOS=<Qt for iOS>.
#   SWIFT_HEADER_DIR=<dir with AmneziaVPN-Swift.h> (ios_controller.mm includes the app's generated Swift header;
#   default: the newest iOS release build tree that has one, read only). Without it only IosScanHost.mm is checked.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$HOME/amnezia-client/deploy/build-macos-desktop}"
[ -d "$BUILD_DIR/client" ] || { echo "no macOS build tree at $BUILD_DIR"; exit 2; }
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
QTI="${QT_IOS:-$HOME/Qt/6.11.1/ios}"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
IOS_INC="-isystem $QTI/include -isystem $QTI/include/QtCore -isystem $QTI/include/QtNetwork -isystem $QTI/include/QtGui \
  -isystem $QTI/include/QtQml -isystem $QTI/include/QtQuick -isystem $QTI/include/QtCore5Compat -isystem $QTI/mkspecs/macx-ios-clang \
  -iframework $QTI/lib -isystem $QTI/lib/QtCore.framework/Headers -isystem $QTI/lib/QtNetwork.framework/Headers \
  -isystem $QTI/lib/QtRemoteObjects.framework/Headers -isystem $QTI/lib/QtGui.framework/Headers \
  -isystem $QTI/lib/QtQml.framework/Headers -isystem $QTI/lib/QtQuick.framework/Headers \
  -isystem $QTI/lib/QtCore5Compat.framework/Headers -isystem $QTI/include/QtQmlIntegration \
  -I$CLIENT -I$CLIENT/core/serviceEngine -I$CLIENT/platforms/ios -I$CLIENT/mozilla -I$CLIENT/mozilla/shared -I$CLIENT/../ipc \
  -I$CLIENT/../common/logger -I$CLIENT/../common/crypto -I$CLIENT/3rd/qrcodegen -I$MAIN_CLIENT/3rd/qrcodegen \
  -I$CLIENT/3rd/qtkeychain -I$MAIN_CLIENT -I$BUILD_DIR/client/AmneziaVPN_autogen/include -I$BUILD_DIR/client \
  -I$BUILD_DIR/client/3rd/qtkeychain -I$BUILD_DIR/3rd/qtkeychain/qtkeychain"
IOS_DEF="-DQT_CORE_LIB -DQT_NETWORK_LIB -DQT_REMOTEOBJECTS_LIB -DQT_GUI_LIB -DQT_QML_LIB -DQT_NO_DEBUG -DAVPN_ENGINE_ENABLED=1 \
  -DGROUP_ID=\\\"group.hk.wellwon.tribe\\\" -DVPN_NE_BUNDLEID=\\\"hk.wellwon.vpn.network-extension\\\""
if [ -z "${SWIFT_HEADER_DIR:-}" ]; then
  for d in $(ls -d "$HOME"/amnezia-worktrees/ios-release-*/deploy/build/build/AmneziaVPN.build/Release-iphoneos/DerivedSources 2>/dev/null | sort -r); do
    [ -f "$d/AmneziaVPN-Swift.h" ] && { SWIFT_HEADER_DIR="$d"; break; }
  done
fi
TUS=("$CLIENT/core/serviceEngine/IosScanHost.mm" "$CLIENT/core/serviceEngine/IosAppScanHost.mm")
if [ -n "${SWIFT_HEADER_DIR:-}" ] && [ -f "$SWIFT_HEADER_DIR/AmneziaVPN-Swift.h" ]; then
  IOS_INC="$IOS_INC -I$SWIFT_HEADER_DIR"
  TUS+=("$CLIENT/platforms/ios/ios_controller.mm")
  echo "generated Swift header (read only): $SWIFT_HEADER_DIR/AmneziaVPN-Swift.h"
else
  echo "ios_controller.mm: SKIPPED (no AmneziaVPN-Swift.h; set SWIFT_HEADER_DIR)"
fi
fail=0
for tu in "${TUS[@]}"; do
  # The in-app probe host exists only with the CMake option AVPN_IOS_APP_SCAN_HOST (its define).
  TU_DEF=""; case "$tu" in *IosAppScanHost.mm) TU_DEF="-DAVPN_IOS_APP_SCAN_HOST=1";; esac
  # shellcheck disable=SC2086
  if eval xcrun clang++ -x objective-c++ -std=gnu++17 -target arm64-apple-ios16.0 -isysroot "$SDK" -fno-objc-arc \
      -Werror=return-type $IOS_DEF $TU_DEF $IOS_INC -fsyntax-only "\"$tu\"" 2>/tmp/ios_scan_compile_err.txt; then
    echo "iOS syntax OK: ${tu#$CLIENT/} ($(grep -c 'warning:' /tmp/ios_scan_compile_err.txt) warnings)"
  else
    echo "iOS syntax FAIL: ${tu#$CLIENT/}"; grep -m 20 "error:" /tmp/ios_scan_compile_err.txt; fail=1
  fi
done
exit $fail
