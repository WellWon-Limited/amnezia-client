#!/bin/bash
# Standalone build + run of the pure decisions about the cached signed /v1/config (5.1.109, S4.1):
# bounded trust in the cached xray_client=true, the server-tunable bound, config refetch on an API
# success. Header only (ConfigCachePolicy.h), QtCore; no network, no storage.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/tribe-config-cache-policy.XXXXXX)}"
mkdir -p "$OUT_DIR"
clang++ -std=c++17 -fPIC -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$HERE/.." \
  "$HERE/config_cache_policy_check.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT_DIR/config_cache_policy_check"
"$OUT_DIR/config_cache_policy_check"
