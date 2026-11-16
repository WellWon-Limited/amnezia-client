#!/bin/bash
# Standalone build + run of the upstream lease check (plan provider-pool v2, D6/D13): the signature with
# a domain-separation context, the lease wire format and the pure lease state machine. QtCore + libcrypto
# (keys are generated in the test). No engine, no network.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-upstream-lease.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$SSL/include" -I"$CLIENT" -I"$HERE/.." \
  -F"$QT/lib" \
  "$HERE/../Ed25519Verify.cpp" "$HERE/upstream_lease_check.cpp" \
  -framework QtCore -L"$SSL/lib" -lcrypto -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/upstream_lease_check"
"$OUT_DIR/upstream_lease_check"
