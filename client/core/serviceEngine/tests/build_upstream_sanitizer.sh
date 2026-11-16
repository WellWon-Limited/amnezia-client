#!/bin/bash
# Standalone build + run of the XrayProfileSanitizer check (plan provider-pool v2, D3): every invariant of
# a normalized upstream profile refuses with its own code, the bind matches the backend's
# bind_local_inbound, the rest stays byte-for-byte. Header only; QtCore + QtNetwork (QHostAddress).
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-upstream-sanitizer.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  -F"$QT/lib" \
  "$HERE/upstream_sanitizer_check.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/upstream_sanitizer_check"
"$OUT_DIR/upstream_sanitizer_check"
