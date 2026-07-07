#!/bin/bash
# AVPN (i18n): обновить tribe_*.ts из НАШИХ исходников (Tribe-слой + serviceEngine) и
# скомпилировать .qm. Апстримные amneziavpn_*.ts НЕ трогаем (у них свой update_translations).
#
# Схема: исходник строк — РУССКИЙ (qsTr/tr в Tribe-слое написаны по-русски).
#   tribe_en.ts — рус→англ, tribe_es.ts — рус→исп. Для ru транслятор не нужен (исходник).
# .qm КОММИТЯТСЯ (qrc = tribe_translations.qrc, подключается в avpn.cmake) — на сборке
# lupdate/lrelease не гоняются, как и у апстрима. После правки строк: запустить этот скрипт,
# заполнить недостающие переводы в .ts, запустить ЕЩЁ РАЗ (lrelease) и закоммитить .ts+.qm.
set -euo pipefail

QT_BIN="${QT_BIN:-$HOME/Qt/6.11.1/macos/bin}"
HERE="$(cd "$(dirname "$0")" && pwd)"           # client/translations/tribe
CLIENT="$(cd "$HERE/../.." && pwd)"             # client/

SRC=(
  "$CLIENT/ui/qml/Tribe"
  "$CLIENT/ui/qml/Pages2/PageHomeTribe.qml"
  "$CLIENT/core/serviceEngine"
)

"$QT_BIN/lupdate" -locations relative -no-obsolete \
  "${SRC[@]}" -ts "$HERE/tribe_en.ts" "$HERE/tribe_es.ts"

for l in en es; do
  "$QT_BIN/lrelease" "$HERE/tribe_$l.ts" -qm "$HERE/tribe_$l.qm"
done
echo "OK: tribe_{en,es}.{ts,qm} обновлены. Незаполненные переводы показываются русским исходником."
