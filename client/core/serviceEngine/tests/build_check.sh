#!/bin/bash
# Автономная сборка+запуск проверки парсера (вне тяжёлой сборки форка). Только QtCore.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_parse_check
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/../SubscriptionParser.cpp" "$HERE/../AwgConfigBuilder.cpp" "$HERE/../Prober.cpp" "$HERE/parse_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" -F"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
cd "$HERE"
"$OUT"

# AVPN H-4: сверка ручных копий never-bypass (клиент vs бэкенд)
"$HERE/check_neverbypass_sync.sh"

# 5.1.109 (S4.1): the facade forwards its events to the transport-mode gate at the expected places
# (source level - AvpnEngineQml.cpp has no unit harness; the rule itself is tested by behaviour).
"$HERE/check_transport_mode_wiring.sh"

# 5.1.111 (141, iOS data watch): the adapter, the provider, the facade and the controller call the
# watch at the expected places and only there (source level; the rules are tested by behaviour).
"$HERE/check_ios_data_watch_wiring.sh"

# Review round 1 of 17.11 (provider seats): the facade, the adapter and the lease client hand the seat-first state
# and the lease I/O through at the expected places (source level; the rules are tested by behaviour).
"$HERE/check_upstream_seat_wiring.sh"

# Build 142 (owner's iPhone, build 140, 16.11): the Scanner cancel, the re-check of an unproven adopted session,
# the AmneziaWG ban and its readers are called at the expected places (source level; the rules are tested by
# behaviour in facade_policy_check, tunnel_watch_check, transport_pick_check, upstream_engine_check, harness).
"$HERE/check_lifecycle_142_wiring.sh"

# Path engine, stage 1 core (design 2026-11-17 "one mechanism to choose a path"): PathId, NetworkKey, PathLedger,
# PathSelect, AttemptOwner and the network scenarios of design §9 in the simulator; then the same headers through
# the platform toolchains (IOS=1 / ANDROID=1 / WINDOWS_APPROX=1 add the passes).
"$HERE/build_path_engine.sh"
"$HERE/check_path_core_compile.sh"
# ... and wired into the engine: the real ServiceEngine driven as the facade drives it (fake tunnel).
"$HERE/build_path_integration.sh"
