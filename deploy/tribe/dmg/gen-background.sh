#!/bin/bash
# Перегенерация фона DMG из background.html (после правок дизайна).
# Chrome headless → PNG 1x (660x460) + 2x (1320x920) → многодпайный background.tiff.
# background.tiff закоммичен: на сборке Chrome не нужен, скрипт — только для правок дизайна.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
TMP="$(mktemp -d)"

for scale in 1 2; do
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars \
    --window-size=660,460 --force-device-scale-factor="$scale" \
    --screenshot="$TMP/bg${scale}x.png" "file://$DIR/background.html" 2>/dev/null
done
# -cathidpicheck собирает 1x+2x в один tiff с корректными dpi-репрезентациями для Retina
tiffutil -cathidpicheck "$TMP/bg1x.png" "$TMP/bg2x.png" -out "$DIR/background.tiff"
rm -rf "$TMP"
echo "OK: $DIR/background.tiff"; tiffutil -info "$DIR/background.tiff" | head -6
