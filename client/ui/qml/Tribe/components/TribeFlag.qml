import QtQuick
import Qt5Compat.GraphicalEffects as Fx

import ".."  // Theme

// AVPN: КРУГЛЫЙ флаг страны по ISO-3166 alpha-2 (country_code с бэкенда). Берём готовый
// SVG из бандла Amnezia (qrc:/countriesFlags/images/flagKit/<CC>.svg — 249 стран), обрезаем
// «во всю плашку» по кругу (OpacityMask) + тонкое кольцо-обводка. НЕ эмодзи (см. дизайн-систему:
// «Flags = drawn rectangles/SVG, never emoji»). Если кода нет / страны нет в наборе → показываем
// `fallback` (мир-иконка на Connect, точка в списке).
//
// Использование:
//   TribeFlag { width: 52; height: 52; code: node.countryCode
//               fallback: Component { Shape { ... } } }
Item {
    id: root

    // ISO alpha-2 (регистр любой). Пусто/невалид → флаг не рисуем, показываем fallback.
    property string code: ""
    // что показать, когда флага нет (мир-иконка / точка). Рендерится по центру в полном размере.
    property Component fallback: null
    // The white-list scope's flag (owner, 2026-11-19): a white circle with a black globe, same size and ring as a
    // country flag. Wins over `code` and `fallback`; the one place it is drawn (Scanner rows, country menu, home card,
    // server list).
    property bool whitelist: false

    readonly property string cc: code ? code.trim().toUpperCase() : ""
    // Two LETTERS only: a placeholder ("??" - the servers page's key for a node without a country, e.g. a
    // provider profile) is no country - the fallback is shown at once, no qrc request for "??.svg"
    // (owner's iPhone 16.11: a decode error per provider row on every list rebuild).
    readonly property bool valid: /^[A-Z]{2}$/.test(cc)
    readonly property bool ready: !whitelist && valid && flagImg.status === Image.Ready

    // SVG-флаг 21×15 → PreserveAspectCrop в квадрат → круглая маска. sourceSize ×2 — резкость на ретине.
    Image {
        id: flagImg
        anchors.fill: parent
        source: (root.valid && !root.whitelist) ? ("qrc:/countriesFlags/images/flagKit/" + root.cc + ".svg") : ""
        fillMode: Image.PreserveAspectCrop
        sourceSize: Qt.size(Math.round(width * 2), Math.round(height * 2))
        smooth: true
        asynchronous: false      // SVG крошечные — грузим синхронно, без мигания фолбэка
        cache: true
        visible: false           // источник для маски
    }

    // круглая маска — radius = половина → идеальный круг «во всю плашку»
    Rectangle {
        id: circleMask
        anchors.fill: parent
        radius: width / 2
        visible: false
    }

    Fx.OpacityMask {
        anchors.fill: parent
        source: flagImg
        maskSource: circleMask
        visible: root.ready
        cached: true
    }

    // тонкое кольцо-обводка поверх флага (отделяет от тёмной плашки)
    Rectangle {
        anchors.fill: parent
        radius: width / 2
        color: "transparent"
        border.width: 1
        border.color: Qt.rgba(1, 1, 1, 0.14)
        visible: root.ready
    }

    // white-list flag: white disc, black globe, the same hairline ring
    Rectangle {
        anchors.fill: parent
        visible: root.whitelist
        radius: width / 2
        color: Theme.color.flagWhitelist
        border.width: 1
        border.color: Theme.color.border2
        Accessible.ignored: true
        TribeStrokeIcon {
            anchors.centerIn: parent
            width: parent.width * 0.62
            height: parent.height * 0.62
            icon: "globe"
            tint: Theme.color.flagWhitelistGlyph
        }
    }

    // фолбэк (мир-иконка / точка), когда страны нет
    Loader {
        anchors.fill: parent
        active: !root.ready && !root.whitelist
        sourceComponent: root.fallback
    }
}
