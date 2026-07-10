import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Qt5Compat.GraphicalEffects

import ".."   // Tribe/qmldir → Theme singleton

// AVPN: Tribe VPN button. Variants: "primary" (gradient + glow), "glass", "ghost", "icon".
// Tokens only (Theme). UI-DESIGN.md §3.
AbstractButton {
    id: control

    property string variant: "primary"          // primary | glass | ghost | icon
    property string iconSource: ""
    property bool loading: false
    property bool glow: true                    // primary: выключаемый Glow-ореол (рефералка — без засветов)
    readonly property bool isIcon: variant === "icon"

    implicitHeight: isIcon ? 44 : 46
    implicitWidth: isIcon ? 44 : Math.max(120, contentRow.implicitWidth + 2 * Theme.space.xl)
    padding: isIcon ? 0 : Theme.space.md
    opacity: enabled ? 1.0 : 0.45
    hoverEnabled: true

    // Ховер — СВОЙ HoverHandler, не AbstractButton.hovered: тот дребезжал («мерцает,
    // загорается и гаснет», 2026-07-10) — hover-события у него отнимали дети/пере-лейаут.
    // margin 2 гасит субпиксельный джиттер геометрии; handlers получают ховер параллельно
    // и не зависят от acceptHoverEvents-цепочки.
    HoverHandler { id: hv; margin: 2 }
    readonly property bool hover: enabled && hv.hovered

    // AVPN: contentItem растягивается AbstractButton'ом на всю площадь кнопки; RowLayout как прямой
    // contentItem паковал бы детей слева. Оборачиваем в Item и центрируем строку через anchors.centerIn
    // (надёжно для full-width кнопок — текст строго по центру).
    contentItem: Item {
        implicitWidth: contentRow.implicitWidth
        implicitHeight: contentRow.implicitHeight

        RowLayout {
            id: contentRow
            anchors.centerIn: parent
            spacing: Theme.space.sm
            layoutDirection: Qt.LeftToRight

            BusyIndicator {
                visible: control.loading
                running: control.loading
                hoverEnabled: false   // не красть ховер у кнопки
                Layout.alignment: Qt.AlignVCenter
                implicitWidth: 18; implicitHeight: 18
            }
            Image {
                visible: control.iconSource !== "" && !control.loading
                source: control.iconSource
                sourceSize.width: 20; sourceSize.height: 20
                Layout.alignment: Qt.AlignVCenter
            }
            Text {
                visible: control.text !== "" && !control.isIcon && !control.loading
                text: control.text
                Layout.alignment: Qt.AlignVCenter
                horizontalAlignment: Text.AlignHCenter
                font.family: Theme.font.body
                font.pixelSize: 15
                font.weight: Theme.font.wSemibold
                color: control.variant === "primary" ? "white"
                     : control.variant === "ghost" ? Theme.color.text2
                     : Theme.color.text1
            }
        }
    }

    background: Rectangle {
        id: bg
        radius: control.isIcon ? Theme.radius.md : Theme.radius.md
        // primary uses gradient; others flat/glass
        gradient: control.variant === "primary" ? primaryGrad : null
        color: {
            if (control.variant === "primary") return "transparent"
            if (control.variant === "ghost") return control.hover ? Theme.color.glassStrong : "transparent"
            // glass + icon: ховер = surface3. НЕ surface2 — покойная заливка glassStrong (белая
            // 7%) ПОВЕРХ карточки surface1 композитится в ~#242E3F, т.е. СВЕТЛЕЕ surface2 —
            // «ховер» тёмным не читался, заметен был только бордер (жалоба 2026-07-10).
            return control.hover ? Theme.color.surface3 : Theme.color.glassStrong
        }
        border.width: control.variant === "primary" ? 0 : 1
        border.color: control.hover ? Theme.color.border2 : Theme.color.border
        layer.enabled: control.variant === "primary" && control.glow
        layer.effect: Glow {
            color: Theme.color.accentGlow
            radius: 18; samples: 25; spread: 0.2
            transparentBorder: true
        }
        // БЕЗ Behavior/ColorAnimation: любой редкий дребезг ховера анимация растягивает в
        // заметное «загорается-гаснет»; мгновенная смена стабильна глазу.

        Gradient {
            id: primaryGrad
            orientation: Gradient.Vertical
            GradientStop { position: 0.0; color: control.pressed ? Theme.color.accentDeep : Theme.color.gradTop }
            GradientStop { position: 1.0; color: Theme.color.gradBottom }
        }
    }
}
