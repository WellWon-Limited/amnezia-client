#!/bin/bash
# ЖИВАЯ проверка goodput-проб (сеть! не для CI): moc ServiceProbe.h → сборка → запуск.
set -e
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT=/tmp/avpn_svcprobe_live
MOC=/tmp/avpn_moc_serviceprobe.cpp
"$QT/libexec/moc" "$HERE/../ServiceProbe.h" -f"$HERE/../ServiceProbe.h" -o "$MOC"
clang++ -std=c++17 -fPIC \
  -I"$QT/include" -I"$QT/include/QtCore" -I"$QT/include/QtNetwork" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -F"$QT/lib" \
  "$HERE/../ServiceProbe.cpp" "$MOC" "$HERE/svcprobe_live_check.cpp" \
  -framework QtCore -framework QtNetwork -framework Foundation \
  -Wl,-rpath,"$QT/lib" \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
