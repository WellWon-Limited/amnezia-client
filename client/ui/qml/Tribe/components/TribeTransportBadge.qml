import QtQuick

import ".."   // Theme

// AVPN awg31-xray-v1 (спека 2026-09-01 §2.3): бейдж ТРАНСПОРТА — «Amnezia v3.1» / «Xray».
// Показывает ФАКТ (какой транспорт есть у локации / на каком поднят туннель), а НЕ выбранный
// пользователем режим (режим — TribeTransportSelector). Версия приходит из движка
// (NodeDebugRow.protoVersion: "2"/"3"/"3.1"; у xray версии AWG нет).
//
// Палитра: активный — accent (нейтральный акцент, НЕ connected-зелёный: транспорт ≠ статус
// подключения), проверка трафика xray — warning, неподдерживаемый клиентом — приглушённый.
Rectangle {
    id: badge

    property string transport: ""     // "awg" | "xray"
    property string version: ""       // мажор AWG ("2"/"3"/"3.1"); для xray пусто
    property bool active: false       // транспорт, на котором сейчас поднят туннель
    property bool supported: true     // клиент этой версии умеет транспорт
    property bool verifying: false    // xray поднят, идёт проверка трафика через туннель
    property bool compact: false      // плотный вариант (карточка сервера на главной)

    readonly property string label:
        transport === "xray" ? qsTr("Xray")
                             : (version.length > 0 ? qsTr("Amnezia v%1").arg(version)
                                                   : qsTr("Amnezia"))

    readonly property color _fg: !supported ? Theme.color.textDisabled
                                 : (verifying && active ? Theme.color.warning
                                 : (active ? Theme.color.accent : Theme.color.text3))
    readonly property color _bg: !supported ? Theme.color.glass
                                 : (verifying && active ? Theme.color.badgeWarn
                                 : (active ? Theme.color.chipSelected : Theme.color.surface2))

    implicitHeight: compact ? 16 : 17
    implicitWidth: lbl.implicitWidth + 2 * Theme.space.sm
    radius: Theme.radius.pill
    color: _bg
    border.width: active ? 1 : 0
    border.color: active ? _fg : "transparent"
    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }

    Accessible.role: Accessible.StaticText
    Accessible.name: badge.label

    Text {
        id: lbl
        anchors.centerIn: parent
        text: badge.label
        textFormat: Text.PlainText
        color: badge._fg
        font.family: Theme.font.body
        font.pixelSize: Theme.font.caption - 1
        font.weight: Theme.font.wBold
    }
}
