#!/bin/bash
# AVPN «Доступ к сайтам РФ» (owner 26.11.2026): the decision table of the switch's effective value (BypassMaster.h) -
# choice / legacy false / platform default (Android API 33+ off) - and the store reading. QtCore only, no network.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT="$(mktemp -d /tmp/tribe-bypass-master.XXXXXX)"
trap 'rm -rf -- "$OUT"' EXIT
clang++ -std=c++17 -fPIC -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  "$HERE/bypass_master_check.cpp" \
  -framework QtCore -Wl,-rpath,"$QT/lib" -o "$OUT/bypass_master_check"
"$OUT/bypass_master_check"
