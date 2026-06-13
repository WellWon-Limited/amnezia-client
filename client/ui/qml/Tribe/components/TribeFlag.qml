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

    readonly property string cc: code ? code.trim().toUpperCase() : ""
    readonly property bool valid: cc.length === 2
    readonly property bool ready: valid && flagImg.status === Image.Ready

    // SVG-флаг 21×15 → PreserveAspectCrop в квадрат → круглая маска. sourceSize ×2 — резкость на ретине.
    Image {
        id: flagImg
        anchors.fill: parent
        source: root.valid ? ("qrc:/countriesFlags/images/flagKit/" + root.cc + ".svg") : ""
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

    // фолбэк (мир-иконка / точка), когда страны нет
    Loader {
        anchors.fill: parent
        active: !root.ready
        sourceComponent: root.fallback
    }
}
