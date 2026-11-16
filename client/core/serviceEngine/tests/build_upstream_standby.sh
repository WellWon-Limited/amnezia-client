#!/bin/bash
# Standalone build + run of the upstream standby-pack check: parse and refusals, age on the wall clock,
# the stale-entry rule, the "may fall back to the pack" decision. QtCore + libcrypto (keys generated in
# the test). No engine, no network.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-upstream-standby.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$SSL/include" -I"$CLIENT" -I"$HERE/.." \
  -F"$QT/lib" \
  "$HERE/../Ed25519Verify.cpp" "$HERE/upstream_standby_check.cpp" \
  -framework QtCore -L"$SSL/lib" -lcrypto -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/upstream_standby_check"
"$OUT_DIR/upstream_standby_check"
