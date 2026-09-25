#!/bin/bash
# Автономная сборка+запуск проверки заслона UIPasteboard (TribePasteMenuFix.mm) под Mac Catalyst —
# UIKit без iPhone и без симулятора. paste_gate_check.mm ОБЯЗАН идти первым: его +load ставит
# заглушки буфера раньше, чем +load заслона их обернёт (порядок +load = порядок линковки).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
OUT=/tmp/avpn_paste_gate_check
clang++ -std=c++17 -target arm64-apple-ios16.0-macabi \
  -isysroot "$SDK" \
  -iframework "$SDK/System/iOSSupport/System/Library/Frameworks" \
  -F"$SDK/System/iOSSupport/System/Library/Frameworks" \
  "$HERE/paste_gate_check.mm" \
  "$HERE/../TribePasteMenuFix.mm" \
  -framework UIKit -framework Foundation -lobjc \
  -o "$OUT"
echo ">>> сборка ок: $OUT"
"$OUT"
