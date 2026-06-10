import QtQuick

import ".."   // Theme

// AVPN: glass card. Translucent surface + hairline border (glass depth without heavy blur).
Rectangle {
    id: card
    property bool elevated: false
    radius: Theme.radius.lg
    color: elevated ? Theme.color.surface2 : Theme.color.surface1
    border.width: 1
    border.color: Theme.color.border
    default property alias content: inner.data
    Item { id: inner; anchors.fill: parent }
}
