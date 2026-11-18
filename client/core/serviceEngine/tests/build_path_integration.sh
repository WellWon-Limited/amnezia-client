#!/bin/bash
# Standalone build + run of the path engine integration check (design 2026-11-17, stage 1): the real ServiceEngine
# with the attempt owner and the ledger, driven as the facade drives it, against a fake tunnel (link stubs for the
# network functions of Enrollment/Identity - no network in the test). QtCore/QtNetwork.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
# Fallback for 3rd submodule headers (qtkeychain): a git worktree may not have them checked out.
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
OUT="${OUT:-/tmp/avpn_path_integration_check}"
# Shim of the generated qkeychain_export.h (only reached through secureQSettings.h).
SHIM="$(mktemp -d)"
trap 'rm -rf "$SHIM"' EXIT
printf '#pragma once\n#define QKEYCHAIN_EXPORT\n' > "$SHIM/qkeychain_export.h"
clang++ -std=c++17 -fPIC -include arm_acle.h -Wall -Wextra -Wno-unused-parameter \
  -I"$SHIM" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$CLIENT" -I"$MAIN_CLIENT" \
  -F"$QT/lib" \
  "$HERE/../ServiceEngine.cpp" "$HERE/../SubscriptionParser.cpp" "$HERE/../Prober.cpp" \
  "$HERE/../AwgConfigBuilder.cpp" \
  "$HERE/path_integration_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
"$OUT"
