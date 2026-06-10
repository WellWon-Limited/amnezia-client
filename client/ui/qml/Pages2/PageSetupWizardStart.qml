import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Shapes

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Config"
import "../Controls2/TextTypes"
import "../Components"

PageType {
    id: root
    enableTimer: (SettingsController.isOnTv()) ? false : true

    // Тёмный фон в стиле AntiVPN
    Rectangle {
        anchors.fill: parent
        color: "#0B0C10"
    }

    ColumnLayout {
        id: content

        anchors.fill: parent
        spacing: 0

        Item { Layout.fillHeight: true }

        // Зелёный щит — вектор, прозрачный фон
        Item {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: 184
            Layout.preferredHeight: 184

            Shape {
                anchors.fill: parent
                preferredRendererType: Shape.CurveRenderer
                transform: Scale { xScale: 7.6; yScale: 7.6 }

                ShapePath {
                    strokeColor: "#34D399"
                    fillColor: "transparent"
                    strokeWidth: 1.5
                    capStyle: ShapePath.RoundCap
                    joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }
                }
                ShapePath {
                    strokeColor: "#34D399"
                    fillColor: "transparent"
                    strokeWidth: 1.5
                    capStyle: ShapePath.RoundCap
                    PathSvg { path: "M7.5 7 15.3 15.6" }
                }
            }
        }

        Text {
            Layout.fillWidth: true
            Layout.leftMargin: 28
            Layout.rightMargin: 28
            Layout.topMargin: 30
            text: qsTr("Работает всё — и Рунет, и весь интернет")
            color: "#F2F2F5"
            font.pixelSize: 25
            font.weight: Font.Bold
            font.letterSpacing: -0.3
            lineHeight: 1.15
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
        }

        Text {
            Layout.fillWidth: true
            Layout.leftMargin: 28
            Layout.rightMargin: 28
            Layout.topMargin: 16
            text: qsTr("Зарубежные сайты открываются через VPN, а российские — банки, Госуслуги, маркетплейсы — напрямую. Без блокировок и переключений: всё работает сразу.")
            color: "#9A9DA6"
            font.pixelSize: 14
            lineHeight: 1.5
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
        }

        Item { Layout.fillHeight: true }

        BasicButtonType {
            id: startButton
            Layout.fillWidth: true
            Layout.bottomMargin: 48 + PageController.safeAreaBottomMargin
            Layout.leftMargin: 16
            Layout.rightMargin: 16
            Layout.alignment: Qt.AlignBottom

            text: qsTr("Let's get started")

            defaultColor: "#34D399"
            hoveredColor: "#3FE0AC"
            pressedColor: "#10B981"
            textColor: "#0B0C10"

            Component.onCompleted: {
                buttonTextLabel.font.weight = Font.Bold
                buttonTextLabel.font.pixelSize = 16
            }

            clickedFunc: function() {
                // Бесшовно: восстанавливаем наш пул (.backup с ключами) штатным механизмом Amnezia.
                // ВАЖНО: .backup — это бэкап настроек, его читает SettingsController.restoreAppConfig,
                // а НЕ ImportController.extractConfigFromFile (тот для одиночных vpn-конфигов → ErrorCode 901).
                // restoreAppConfig берёт обычный путь к файлу (без префикса file://).
                // TODO: заменить путь на AutoConfigFetcher → бэкенд-пул (выдаёт 1 конфиг на устройство).
                PageController.showBusyIndicator(true)
                SettingsController.restoreAppConfig("/Users/macbookpro/avpn-build/pool.backup")
            }
        }

        // Бэкап восстановлен (серверы добавлены) → уводим на экран Connect (PageHome)
        Connections {
            target: SettingsController
            function onRestoreBackupFinished() {
                PageController.showBusyIndicator(false)
                PageController.goToPageHome()
            }
            function onErrorOccurred(errorCode) {
                PageController.showBusyIndicator(false)
                PageController.goToPage(PageEnum.PageSetupWizardConfigSource) // фолбэк: ручной импорт
            }
        }
    }

    Timer {
        interval: 250
        running: SettingsController.isOnTv()
        repeat: true
        onTriggered: {
            startButton.forceActiveFocus()
            if (startButton.activeFocus) {
                running = false
            }
        }
    }

    onVisibleChanged: {
        if (visible && SettingsController.isOnTv()) {
            startButton.forceActiveFocus()
        }
    }
}
