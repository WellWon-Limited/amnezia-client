#!/bin/bash
# ServiceProbe: поздний таймаут-таймер reachability-голоса после finished (краш macOS после сна,
# 5.1.99/129). Без сети; AddressSanitizer ловит запись в освобождённую память.
set -eu
QT="${QT_ROOT:-$HOME/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-svcprobe-late-timer.XXXXXX)"
trap 'rm -rf "$OUT"' EXIT
"$QT/libexec/moc" -f"$HERE/../ServiceProbe.h" "$HERE/../ServiceProbe.h" -o "$OUT/moc_ServiceProbe.cpp"
clang++ -std=c++17 -fPIC -g -fsanitize=address -fno-omit-frame-pointer -F"$QT/lib" \
  -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  "$HERE/../ServiceProbe.cpp" "$OUT/moc_ServiceProbe.cpp" "$HERE/svcprobe_late_timer_check.cpp" \
  -framework QtCore -framework QtNetwork -Wl,-rpath,"$QT/lib" -o "$OUT/check"
ASAN_OPTIONS=detect_leaks=0 "$OUT/check"
