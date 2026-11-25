#!/bin/bash
# AVPN (round mac-C, 25.11.2026): build + run mac_daemon_adopt_check - a session the macOS GUI adopts from the root
# daemon is named by the daemon's peer endpoint and a mode tap restarts it like a session the GUI started
# (DaemonAdoptHint.h). QtCore/QtNetwork only, the real ServiceEngine (as build_engine_reliability.sh).
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
MAIN_CLIENT="${AVPN_MAIN_CLIENT:-$HOME/amnezia-client/client}"
GEN="$(mktemp -d /tmp/avpn_mac_daemon_adopt.XXXXXX)"
trap 'rm -rf "${GEN:?}"' EXIT
printf '#pragma once\n#define QKEYCHAIN_EXPORT\n' > "$GEN/qkeychain_export.h"
SRC="$HERE/.."
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$GEN" \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$CLIENT" -I"$MAIN_CLIENT" -F"$QT/lib" \
  "$SRC/ServiceEngine.cpp" "$SRC/SubscriptionParser.cpp" "$SRC/Prober.cpp" "$SRC/AwgConfigBuilder.cpp" \
  "$HERE/mac_daemon_adopt_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -o "$GEN/mac_daemon_adopt_check"
echo ">>> build ok: mac_daemon_adopt_check"
"$GEN/mac_daemon_adopt_check"
