#!/bin/bash
# AVPN: build and run the MacUpstreamGeo.h unit check (QtCore only, host); then a syntax-only compile
# of MacServiceInstaller.mm (Objective-C++, no link). GEO_DIR=<tribe-xray-geo package>/geo also checks
# the real artifact against its own SHA256SUMS.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_mac_upstream_geo_check
clang++ -std=c++17 -fPIC \
  -I"$QT/include" -I"$QT/include/QtCore" \
  -I"$QT/lib/QtCore.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/mac_upstream_geo_check.cpp" \
  -framework QtCore -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
clang++ -std=c++17 -x objective-c++ -fsyntax-only \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/lib/QtCore.framework/Headers" -F"$QT/lib" \
  "$HERE/../MacServiceInstaller.mm"
echo ">>> MacServiceInstaller.mm: syntax ok"
