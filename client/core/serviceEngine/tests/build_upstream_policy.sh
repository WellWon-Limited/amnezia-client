#!/bin/bash
# Standalone build + run of the upstream policy check (plan provider-pool v2, D7/D9): the data-check
# verdict of an upstream node and the policy-tier rule with seeded property tests. Headers only, QtCore.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-upstream-policy.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  -F"$QT/lib" \
  "$HERE/upstream_policy_check.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/upstream_policy_check"
"$OUT_DIR/upstream_policy_check"
