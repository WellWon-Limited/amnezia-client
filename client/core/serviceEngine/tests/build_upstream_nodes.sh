#!/bin/bash
# Standalone build + run of the upstream-nodes check (plan provider-pool v2, §5.1): DTO, parser, kill
# switch features.upstream_nodes (same input on both settings), gate, identity, clamped tunables, the
# cache freeze helper and the config path's refusal of typed bodies. QtCore/QtNetwork; no engine.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-upstream-nodes.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  -F"$QT/lib" \
  "$HERE/../SubscriptionParser.cpp" "$HERE/upstream_nodes_check.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/upstream_nodes_check"
"$OUT_DIR/upstream_nodes_check"
