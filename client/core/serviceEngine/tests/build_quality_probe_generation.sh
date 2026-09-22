#!/bin/bash
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-quality-probe.XXXXXX)"
trap 'rm -rf "$OUT"' EXIT
"$QT/libexec/moc" -f"$HERE/../QualityProbe.h" "$HERE/../QualityProbe.h" -o "$OUT/moc_QualityProbe.cpp"
clang++ -std=c++17 -fPIC -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  "$HERE/../QualityProbe.cpp" "$OUT/moc_QualityProbe.cpp" "$HERE/quality_probe_generation_check.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT/check"
"$OUT/check"
