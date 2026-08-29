#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "macOS native session guard suite requires macOS" >&2
    exit 2
fi
command -v xcrun >/dev/null 2>&1 || {
    echo "xcrun is required for the macOS native session guard suite" >&2
    exit 2
}

QT_PREFIX="${TRIBE_QT_MACOS_ROOT:-${QT_ROOT:-${QT_ROOT_DIR:-}}}"
if [[ -z "$QT_PREFIX" ]] && command -v qtpaths6 >/dev/null 2>&1; then
    QT_PREFIX="$(qtpaths6 --query QT_INSTALL_PREFIX)"
fi
if [[ -z "$QT_PREFIX" && -x "$HOME/Qt/6.11.1/macos/bin/qtpaths6" ]]; then
    QT_PREFIX="$HOME/Qt/6.11.1/macos"
fi
if [[ ! -x "$QT_PREFIX/bin/qtpaths6" ]]; then
    echo "Qt 6.11.1 macOS prefix is required (set TRIBE_QT_MACOS_ROOT)" >&2
    exit 2
fi
QT_VERSION="$("$QT_PREFIX/bin/qtpaths6" --query QT_VERSION)"
if [[ "$QT_VERSION" != "6.11.1" ]]; then
    echo "Qt 6.11.1 is required; resolved $QT_VERSION at $QT_PREFIX" >&2
    exit 2
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/tribe-macos-guard-tests.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
BINARY="$TEST_ROOT/macos-native-session-guard-tests"

xcrun clang++ \
    -std=c++20 -Wall -Wextra -Werror -fno-omit-frame-pointer \
    -I"$QT_PREFIX/lib/QtCore.framework/Headers" \
    -I"$QT_PREFIX/lib/QtNetwork.framework/Headers" \
    -F"$QT_PREFIX/lib" \
    "$ROOT/client/platforms/macos/daemon/macosnativesessionguard.cpp" \
    "$ROOT/client/platforms/macos/tests/MacosNativeSessionGuardTests.cpp" \
    -framework QtCore -framework QtNetwork \
    -Wl,-rpath,"$QT_PREFIX/lib" \
    -o "$BINARY"

"$BINARY" \
    "$ROOT/client/core/serviceEngine/tests/fixtures/native_dispatch_awg_v1.json" \
    "$ROOT/client/core/serviceEngine/tests/fixtures/native_dispatch_xray_v1.json"
