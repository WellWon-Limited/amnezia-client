#!/bin/bash
# Standalone build + run of the upstream shared-vector replay: tests/vectors/upstream_{lease,wire,signature}
# _vectors.json against the real C++ lease machine, wire classifier and signature input (the spec of the
# Swift twin in the iOS extension). `--record` rewrites the files from the scenario definitions - only
# after a deliberate behaviour change; review the JSON diff. QtCore + libcrypto (test key from a public
# seed, never a real key).
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
SSL="${OPENSSL_ROOT:-$(brew --prefix openssl@3)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-upstream-vectors.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$SSL/include" -I"$CLIENT" -I"$HERE/.." \
  -F"$QT/lib" \
  "$HERE/../Ed25519Verify.cpp" "$HERE/upstream_vectors_check.cpp" \
  -framework QtCore -L"$SSL/lib" -lcrypto -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/upstream_vectors_check"
if [ "${1:-}" = "--record" ]; then
  "$OUT_DIR/upstream_vectors_check" --record --dir "$HERE/vectors"
else
  "$OUT_DIR/upstream_vectors_check" --dir "$HERE/vectors"
fi
