#!/bin/bash
# AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67): the route budget (RouteBudget.h), the cut of the split list to it
# (RouteReduce.h: lossless merge, then the largest; a subset, never widened) and the Android app layer's list -> config
# mapping (RuApps.h). QtCore + QtNetwork (QHostAddress), no network. `--table`: the coverage table per budget instead.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$HERE/../../.."
OUT="$(mktemp -d /tmp/tribe-route-budget.XXXXXX)"
trap 'rm -rf -- "$OUT"' EXIT
clang++ -std=c++17 -O1 -fPIC -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" -I"$CLIENT" -I"$HERE/.." \
  "$HERE/route_budget_check.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT/route_budget_check"
"$OUT/route_budget_check" "$@"
