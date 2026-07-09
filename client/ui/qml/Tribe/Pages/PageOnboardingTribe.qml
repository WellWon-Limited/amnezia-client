import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects as Fx

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType

// AVPN: онбординг первого запуска (вместо ванильного PageSetupWizardStart), 3 экрана:
// 1 «АнтиVPN» (умный сплит: зарубежные через VPN, российские напрямую, демо-тумблер),
// 2 «Режим одной кнопки» (4 шага, каскадный reveal), 3 «100% приватность» (+ правовая
// декларация App Review 5.4 — ссылки Terms/Privacy до старта сервиса).
// Референс-дизайн: tribe-front/resources/Tribe_onbording.html.
// PageStart по requestStart() помечает онбординг пройденным и уводит на Connect.
PageType {
    id: root

    signal requestStart()

    // iOS: PageController.safeArea* реализован только для Android → берём максимум
    // с SafeArea (Qt 6.9+); окно edge-to-edge (Qt.ExpandedClientAreaHint в main2.qml)
    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    readonly property real safeBottom: Math.max(PageController.safeAreaBottomMargin, SafeArea.margins.bottom)

    readonly property int screen: swiper.currentIndex
    // каскадный reveal экранов 2/3
    property int reveal1: Theme.motion.reduceMotion ? 4 : 0
    property int reveal2: Theme.motion.reduceMotion ? 3 : 0

    function goTo(i) { swiper.setCurrentIndex(Math.max(0, Math.min(2, i))) }

    // «назад» видна только когда страница долистнулась; при любом переходе гаснет сразу
    property bool backReady: false
    Timer {
        id: backReadyTimer
        interval: 500   // длительность пролистывания SwipeView
        onTriggered: root.backReady = true
    }

    onScreenChanged: {
        backReady = false
        if (screen > 0)
            backReadyTimer.restart()
        if (Theme.motion.reduceMotion)
            return
        if (screen === 1) reveal1 = 0
        else if (screen === 2) reveal2 = 0
    }
    Timer {
        interval: 170; repeat: true
        running: !Theme.motion.reduceMotion && root.screen === 1 && root.reveal1 < 4
        onTriggered: root.reveal1++
    }
    Timer {
        interval: 170; repeat: true
        running: !Theme.motion.reduceMotion && root.screen === 2 && root.reveal2 < 3
        onTriggered: root.reveal2++
    }

    // ---------- переиспользуемые блоки ----------

    // марка 5 баров + wordmark (пропорции лого 16/28/36/26/18 → ×31/36)
    component BrandHeader: Row {
        Layout.topMargin: Theme.space.lg   // логотип чуть ниже на всех трёх экранах
        spacing: Theme.space.md
        Row {
            anchors.bottom: parent.bottom
            spacing: 3
            Rectangle { width: 5; height: 14; radius: 2.5; color: Theme.color.text1;  anchors.bottom: parent.bottom }
            Rectangle { width: 5; height: 24; radius: 2.5; color: Theme.color.text1;  anchors.bottom: parent.bottom }
            Rectangle { width: 5; height: 31; radius: 2.5; color: Theme.color.accent; anchors.bottom: parent.bottom }
            Rectangle { width: 5; height: 22; radius: 2.5; color: Theme.color.text1;  anchors.bottom: parent.bottom }
            Rectangle { width: 5; height: 16; radius: 2.5; color: Theme.color.text1;  anchors.bottom: parent.bottom }
        }
        Text {
            // wordmark по нижней границе баров (компенсация descent шрифта)
            anchors.bottom: parent.bottom
            anchors.bottomMargin: -6
            text: "Tribe VPN"
            color: Theme.color.text1
            font.family: Theme.font.display; font.pixelSize: Theme.font.h2
            font.weight: Theme.font.wExtra
            font.letterSpacing: 0.02 * Theme.font.h2
        }
    }

    // штриховая иконка 24-grid (Tabler/lucide)
    component StrokeIcon: Shape {
        property string d
        property color tint: Theme.color.accent
        width: 24; height: 24
        preferredRendererType: Shape.CurveRenderer
        ShapePath {
            strokeColor: tint; fillColor: "transparent"; strokeWidth: 2
            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
            PathSvg { path: d }
        }
    }

    // подпись секции сервисов: точка + caption-капс
    component SectionLabel: Row {
        property string label
        property color tint
        spacing: Theme.space.sm - 2
        Rectangle {
            width: 6; height: 6; radius: 3; color: parent.tint
            anchors.verticalCenter: parent.verticalCenter
        }
        Text {
            anchors.verticalCenter: parent.verticalCenter
            text: parent.label
            color: parent.tint
            font.family: Theme.font.body; font.pixelSize: 10
            font.weight: Theme.font.wBold
            font.capitalization: Font.AllUppercase
            font.letterSpacing: 0.09 * 10
        }
    }

    // плитка сервиса 44×44: SVG-глиф или текстовый знак на брендовом фоне
    component BrandTile: Rectangle {
        property string glyph: ""
        property real glyphRatio: 0.58
        property string mark: ""
        property color markColor: "white"
        property real markSize: Theme.font.bodyM
        width: 44; height: 44; radius: Theme.radius.md
        Image {
            visible: parent.glyph !== ""
            anchors.centerIn: parent
            source: parent.glyph
            width: Math.round(44 * parent.glyphRatio); height: width
            sourceSize: Qt.size(88, 88)
        }
        Text {
            visible: parent.mark !== ""
            anchors.centerIn: parent
            text: parent.mark
            color: parent.markColor
            font.family: Theme.font.display; font.pixelSize: parent.markSize
            font.weight: Theme.font.wExtra
        }
    }

    // карточка шага (экраны 2/3) с reveal-анимацией появления
    component StepCard: Rectangle {
        id: card
        property string iconD
        property string title
        property string sub
        property bool shown: true
        Layout.fillWidth: true
        implicitHeight: cardRow.implicitHeight + 2 * Theme.space.md + 2
        radius: Theme.radius.xl
        color: Theme.color.surface1
        border.width: 1; border.color: Qt.alpha(Theme.color.accent, 0.12)
        opacity: shown ? 1 : 0
        transform: Translate {
            y: card.shown ? 0 : 16
            Behavior on y { NumberAnimation { duration: 550; easing.type: Easing.OutCubic } }
        }
        Behavior on opacity { NumberAnimation { duration: 550 } }
        RowLayout {
            id: cardRow
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left; anchors.right: parent.right
            anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
            spacing: Theme.space.md + 2
            Rectangle {
                Layout.preferredWidth: 42; Layout.preferredHeight: 42
                radius: Theme.radius.md
                color: Qt.alpha(Theme.color.accent, 0.12)
                StrokeIcon { anchors.centerIn: parent; d: card.iconD }
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                Text {
                    Layout.fillWidth: true
                    text: card.title
                    color: Theme.color.text1
                    font.family: Theme.font.display; font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wBold
                    // одна строка: на узких экранах ужимаемся, не переносимся
                    maximumLineCount: 1
                    fontSizeMode: Text.HorizontalFit; minimumPixelSize: 12
                }
                Text {
                    Layout.fillWidth: true
                    text: card.sub
                    color: Theme.color.text2
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS - 1
                    lineHeight: 1.3
                    wrapMode: Text.WordWrap
                }
            }
        }
    }

    // соединительная линия между карточками (по центру иконки)
    component StepLink: Rectangle {
        property bool shown: true
        Layout.preferredWidth: 2; Layout.preferredHeight: 14
        Layout.leftMargin: Theme.space.lg + 20
        color: Theme.color.surface3
        opacity: shown ? 1 : 0
        Behavior on opacity { NumberAnimation { duration: 550 } }
    }

    // ---------- фон ----------

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // звёздное небо (как на Connect, статичное)
    Item {
        id: starField
        anchors.fill: parent
        clip: true
        property var starsData: []
        Component.onCompleted: {
            var arr = []
            for (var i = 0; i < 30; i++)
                arr.push({ tx: Math.random(), ty: Math.random(),
                           s: Math.random() * 1.8 + 1, o: Math.random() * 0.4 + 0.08 })
            starsData = arr
        }
        Repeater {
            model: starField.starsData
            delegate: Rectangle {
                width: modelData.s; height: modelData.s; radius: width / 2; color: "white"
                x: modelData.tx * starField.width; y: modelData.ty * starField.height
                opacity: modelData.o
            }
        }
        Rectangle {
            anchors.fill: parent
            // верхнее «сияние» ночного неба (референс: radial #123055 → bg)
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.rgba(0x1E/255, 0x3A/255, 0x8A/255, 0.30) }
                GradientStop { position: 0.45; color: "transparent" }
                GradientStop { position: 1.0; color: "transparent" }
            }
        }
    }

    // ---------- слайдер экранов ----------

    SwipeView {
        id: swiper
        anchors.top: parent.top
        anchors.left: parent.left; anchors.right: parent.right
        anchors.bottom: footer.top
        clip: true

        // ============ Экран 1 · АнтиVPN ============
        Item {
            ColumnLayout {
                anchors.fill: parent
                anchors.topMargin: root.safeTop + Theme.space.lg
                anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
                spacing: 0

                BrandHeader { Layout.alignment: Qt.AlignHCenter }

                Item { Layout.fillHeight: true }

                Text {
                    Layout.fillWidth: true
                    text: qsTr("Надоело выключать VPN?")
                    color: Theme.color.text1
                    font.family: Theme.font.display; font.pixelSize: Theme.font.h1
                    font.weight: Theme.font.wExtra
                    font.letterSpacing: Theme.font.trackTight * Theme.font.h1
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.maximumWidth: 344   // две строки: «…через VPN.» целиком во второй
                    Layout.topMargin: Theme.space.sm + 2
                    text: qsTr("Умная маршрутизация сама решает, какой трафик нужно направить через VPN.")
                    color: Theme.color.text2
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS + 1
                    lineHeight: 1.4
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                }

                // карточка «АнтиVPN активирован» с демо-тумблером
                Rectangle {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.xl
                    implicitHeight: antiRow.implicitHeight + 2 * Theme.space.lg
                    radius: Theme.radius.xl
                    color: Theme.color.surface1
                    border.width: 1; border.color: Qt.alpha(Theme.color.accent, 0.15)
                    RowLayout {
                        id: antiRow
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.left: parent.left; anchors.right: parent.right
                        anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                        spacing: Theme.space.md + 1
                        // иконка «RU-шар» — 1:1 как AutoVpnIcon на Connect-экране (редизайн 2026-07-02):
                        // круг с диагональным сине-красным градиентом (сценические цвета) + контурное кольцо
                        Item {
                            id: onbRuIcon
                            Layout.preferredWidth: 52; Layout.preferredHeight: 52
                            Rectangle {
                                width: onbRuBall.width; height: onbRuBall.height
                                anchors.centerIn: parent
                                radius: width / 2
                                color: Qt.rgba(0x0F/255, 0x17/255, 0x2A/255, 0.8)
                            }
                            Item {
                                id: onbRuBall
                                // чётная ширина — иначе полупиксельный офсет слоя-маски (см. PageConnectTribe)
                                width: 2 * Math.round(onbRuIcon.width * 0.87 / 2); height: width
                                anchors.centerIn: parent
                                layer.enabled: true
                                layer.effect: Fx.OpacityMask {
                                    maskSource: Rectangle { width: onbRuBall.width; height: onbRuBall.height; radius: width / 2 }
                                }
                                Fx.LinearGradient {
                                    anchors.fill: parent
                                    start: Qt.point(width * 0.85, 0); end: Qt.point(width * 0.15, height)
                                    gradient: Gradient {
                                        GradientStop { position: 0.0;  color: "#4E7FCB" }   // scenic: RU-шар синий
                                        GradientStop { position: 0.45; color: "#4E7FCB" }
                                        GradientStop { position: 1.0;  color: "#C1524E" }   // scenic: RU-шар красный
                                    }
                                }
                                Text {
                                    anchors.centerIn: parent
                                    text: "RU"; color: "white"
                                    font.family: Theme.font.display
                                    font.pixelSize: Math.round(parent.height * 0.42)
                                    font.weight: Theme.font.wBold
                                }
                            }
                            Rectangle {
                                width: onbRuBall.width + 6; height: width
                                anchors.centerIn: parent
                                radius: width / 2
                                color: "transparent"
                                border.width: 1; border.color: Qt.rgba(0x64/255, 0x74/255, 0x8B/255, 0.55)
                            }
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 3
                            Text {
                                Layout.fillWidth: true
                                text: qsTr("Доступ к сайтам РФ включён")
                                color: Theme.color.text1
                                font.family: Theme.font.display; font.pixelSize: Theme.font.bodyM
                                font.weight: Theme.font.wExtra
                                // одна строка: на узких экранах ужимаемся, не переносимся
                                maximumLineCount: 1
                                fontSizeMode: Text.HorizontalFit; minimumPixelSize: 12
                            }
                            Text {
                                Layout.fillWidth: true
                                text: qsTr("Теперь VPN выключать не нужно.")
                                color: Theme.color.text2
                                font.family: Theme.font.body; font.pixelSize: Theme.font.caption + 1
                                wrapMode: Text.WordWrap
                            }
                        }
                    }
                }

                SectionLabel {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: Theme.space.xl - 4
                    label: qsTr("Зарубежные — направляются через VPN")
                    tint: Theme.color.accent
                }
                Row {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: Theme.space.sm
                    spacing: Theme.space.sm + 1
                    // брендовые цвета сервисов — сценическая деталь онбординга
                    BrandTile { color: "#25D366"; glyph: "../images/brand-whatsapp.svg"; glyphRatio: 0.60 }
                    BrandTile { color: "#229ED9"; glyph: "../images/brand-telegram.svg" }
                    BrandTile { color: "#FF0000"; glyph: "../images/brand-youtube.svg"; glyphRatio: 0.56 }
                    BrandTile { color: "#FFFFFF"; glyph: "../images/brand-gemini.svg"; glyphRatio: 0.62 }
                    BrandTile { color: "#D97757"; glyph: "../images/brand-claude.svg" }
                }

                SectionLabel {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: Theme.space.lg + 2
                    label: qsTr("Российские — всегда работают напрямую")
                    tint: Theme.color.text2
                }
                Row {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: Theme.space.sm
                    spacing: Theme.space.sm + 1
                    BrandTile {
                        mark: "WB"; markSize: Theme.font.bodyS
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: "#CB11AB" }
                            GradientStop { position: 1.0; color: "#7A0FB0" }
                        }
                    }
                    BrandTile { color: "#005BFF"; mark: "O"; markSize: Theme.font.h3 + 2 }
                    BrandTile { color: "#FF6600"; glyph: "../images/brand-kinopoisk.svg" }
                    BrandTile { color: "#FFDD2D"; mark: "Т"; markColor: "#0A0A0A"; markSize: Theme.font.h3 + 2 }
                    BrandTile { color: "#FFFFFF"; glyph: "../images/brand-gosuslugi.png"; glyphRatio: 1.0; radius: Theme.radius.md }
                }

                Text {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.maximumWidth: 344
                    Layout.topMargin: Theme.space.xxl + Theme.space.sm   // отступ от иконок на строку ниже
                    text: qsTr("Зарубежные сайты — работают через VPN,\nБанки, кинотеатры, Госуслуги, маркетплейсы продолжают работать без переключений!")
                    color: Theme.color.text2
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                    lineHeight: 1.45
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                }

                Item { Layout.fillHeight: true }
            }
        }

        // ============ Экран 2 · Режим одной кнопки ============
        Item {
            ColumnLayout {
                anchors.fill: parent
                anchors.topMargin: root.safeTop + Theme.space.lg
                anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
                spacing: 0

                BrandHeader { Layout.alignment: Qt.AlignHCenter }

                Item { Layout.fillHeight: true }

                Text {
                    Layout.fillWidth: true
                    text: qsTr("Режим одной кнопки")
                    color: Theme.color.text1
                    font.family: Theme.font.display; font.pixelSize: Theme.font.h1
                    font.weight: Theme.font.wExtra
                    font.letterSpacing: Theme.font.trackTight * Theme.font.h1
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.maximumWidth: 300
                    Layout.topMargin: Theme.space.sm + 2
                    text: qsTr("Никаких настроек, конфигов и инструкций. Одна кнопка — и вы под защитой.")
                    color: Theme.color.text2
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS + 1
                    lineHeight: 1.4
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                }

                Item { Layout.preferredHeight: Theme.space.xl }

                StepCard {
                    shown: root.reveal1 >= 1
                    iconD: "M9 11.5V5a2 2 0 0 1 4 0v5.5 M13 10.5V9a2 2 0 0 1 4 0v3 M17 11.5a2 2 0 0 1 4 .5c0 5-2.5 9-7.5 9H12c-2.6 0-4.3-1.2-5.6-3.3L4 14a1.9 1.9 0 0 1 3-2l2 2.4"
                    title: qsTr("Нажмите кнопку Connect")
                    sub: qsTr("Подключение за пару секунд")
                }
                StepLink { shown: root.reveal1 >= 1 }
                StepCard {
                    shown: root.reveal1 >= 2
                    iconD: "M13 2L4.5 13.5H11L9.5 22 19 10.5h-6.5L13 2z"
                    title: qsTr("Сервер выберется сам")
                    sub: qsTr("Приложение подберёт самый быстрый сервер")
                }
                StepLink { shown: root.reveal1 >= 2 }
                StepCard {
                    shown: root.reveal1 >= 3
                    iconD: "M20 11.5A8 8 0 0 0 6.5 6L3.5 9 M3.5 4.5V9H8 M4 12.5A8 8 0 0 0 17.5 18l3-3 M20.5 19.5V15H16"
                    title: qsTr("Вы можете сменить сервер")
                    sub: qsTr("Если скорость интернета низкая вы можете нажать \"Сменить сервер\"")
                }
                StepLink { shown: root.reveal1 >= 3 }
                StepCard {
                    shown: root.reveal1 >= 4
                    iconD: "M2.5 12a9.5 9.5 0 1 0 19 0a9.5 9.5 0 1 0 -19 0 M2.5 12h19 M12 2.5a14 14 0 0 1 0 19 14 14 0 0 1 0-19z"
                    title: qsTr("Выбирайте любую страну")
                    sub: qsTr("Выберите любую страну из доступного списка серверов, есть даже Россия")
                }

                Item { Layout.fillHeight: true }
            }
        }

        // ============ Экран 3 · Приватность ============
        Item {
            ColumnLayout {
                anchors.fill: parent
                anchors.topMargin: root.safeTop + Theme.space.lg
                anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
                spacing: 0

                BrandHeader { Layout.alignment: Qt.AlignHCenter }

                Item { Layout.fillHeight: true }

                Text {
                    Layout.fillWidth: true
                    text: qsTr("100% приватность")
                    color: Theme.color.text1
                    font.family: Theme.font.display; font.pixelSize: Theme.font.h1
                    font.weight: Theme.font.wExtra
                    font.letterSpacing: Theme.font.trackTight * Theme.font.h1
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.maximumWidth: 300
                    Layout.topMargin: Theme.space.sm + 2
                    text: qsTr("Нам не нужны ваши данные — главное, чтобы всё работало.")
                    color: Theme.color.text2
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS + 1
                    lineHeight: 1.4
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                }

                Item { Layout.preferredHeight: Theme.space.xl }

                StepCard {
                    shown: root.reveal2 >= 1
                    iconD: "M5.5 7.5a3.5 3.5 0 1 0 7 0a3.5 3.5 0 1 0 -7 0 M3.5 20c0-3 2.5-5.5 5.5-5.5s5.5 2.5 5.5 5.5 M16.5 8.5l4.5 4.5 M21 8.5l-4.5 4.5"
                    title: qsTr("Никакой регистрации")
                    sub: qsTr("Мы не собираем email или Telegram аккаунты. Соблюдаем анонимность!")
                }
                StepLink { shown: root.reveal2 >= 1 }
                StepCard {
                    shown: root.reveal2 >= 2
                    iconD: "M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z M9.2 12a2.8 2.8 0 1 0 5.6 0a2.8 2.8 0 1 0 -5.6 0 M4.5 4.5l15 15"
                    title: qsTr("Никаких логов")
                    sub: qsTr("Мы не анализируем ваш трафик и не знаем какие сайты и приложения используете")
                }
                StepLink { shown: root.reveal2 >= 2 }
                StepCard {
                    shown: root.reveal2 >= 3
                    iconD: "M12 2l8 4v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6l8-4z M9 12l2 2 4-4"
                    title: qsTr("Полная анонимность")
                    sub: qsTr("Авторизация происходит только из приложения без ввода личных данных")
                }

                // Декларация о данных ДО первого использования сервиса + правовые ссылки
                // (App Review 5.4: VPN обязан заявить сбор данных до старта; тексты — /legal/*)
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.maximumWidth: 320
                    Layout.topMargin: Theme.space.lg
                    horizontalAlignment: Text.AlignHCenter
                    textFormat: Text.StyledText
                    wrapMode: Text.WordWrap
                    color: Theme.color.text3
                    linkColor: Theme.color.accent
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    lineHeight: 1.4
                    text: qsTr("Мы не логируем трафик и не продаём ваши данные. Нажимая «Приступим», вы принимаете <a href='https://tribevpn.com/legal/terms'>Условия</a> и <a href='https://tribevpn.com/legal/privacy'>Политику конфиденциальности</a>.")
                    // AVPN in-app Legal: юр-ссылки открываются оверлеем ВНУТРИ онбординга
                    // (PageLegalTribe сам выбирает язык); прочие ссылки — наружу как раньше
                    onLinkActivated: (link) => {
                        if (link.indexOf("/legal/") !== -1) {
                            legalSheet.show(link.indexOf("terms") !== -1 ? "terms" : "privacy")
                            return
                        }
                        var lang = (typeof TribeEngine !== "undefined" && TribeEngine.appLang)
                                   ? TribeEngine.appLang : Qt.locale().name.split("_")[0]
                        Qt.openUrlExternally(link + "?lang=" + lang)
                    }
                }

                Item { Layout.fillHeight: true }
            }
        }
    }

    // ---------- кнопка «назад» поверх слайдера ----------

    Rectangle {
        // появляется после того, как страница полностью долистнулась; гаснет в момент перехода
        visible: opacity > 0
        opacity: (root.screen > 0 && root.backReady) ? 1 : 0
        Behavior on opacity { NumberAnimation { duration: Theme.motion.fast } }
        x: Theme.space.xl   // отступ слева = как у контента экранов
        y: root.safeTop + Theme.space.md
        width: 38; height: 38
        radius: Theme.radius.md
        color: Theme.color.glassStrong
        border.width: 1; border.color: Qt.alpha(Theme.color.accent, 0.18)
        StrokeIcon { anchors.centerIn: parent; d: "M15 5l-7 7 7 7"; tint: Theme.color.text2; scale: 18 / 24 }
        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: root.goTo(root.screen - 1)
        }
    }

    // ---------- футер: точки + CTA ----------

    ColumnLayout {
        id: footer
        anchors.left: parent.left; anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
        anchors.bottomMargin: Theme.space.lg + root.safeBottom
        spacing: Theme.space.lg

        Row {
            Layout.alignment: Qt.AlignHCenter
            spacing: 7
            Repeater {
                model: 3
                Rectangle {
                    required property int index
                    width: root.screen === index ? 24 : 8
                    height: 8; radius: Theme.radius.pill
                    color: root.screen === index ? Theme.color.accent : Theme.color.surface3
                    Behavior on width { NumberAnimation { duration: Theme.motion.fast } }
                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                    TapHandler { onTapped: root.goTo(parent.index) }
                }
            }
        }

        TribeButton {
            Layout.fillWidth: true
            Layout.preferredHeight: 52
            variant: "primary"
            text: root.screen < 2 ? qsTr("Далее") : qsTr("Приступим")
            onClicked: root.screen < 2 ? root.goTo(root.screen + 1) : root.requestStart()
        }
    }

    // ── AVPN in-app Legal: юр-ссылки согласия открываются ВНУТРИ онбординга ─────────
    // Оверлей с PageLegalTribe (кэш+qrc-снапшот+fetch) вместо выброса в браузер: флоу
    // согласия не прерывается, а в РФ без VPN сайт может быть недоступен. Back/Escape
    // закрывает ОВЕРЛЕЙ, не онбординг — паттерн дровера (incrementDrawerDepth/
    // closeTopDrawer, как TribeResultSheet); «назад» в шапке страницы = requestSettings.
    Item {
        id: legalSheet
        anchors.fill: parent
        visible: opened
        z: 200

        property bool   opened: false
        property string doc: "privacy"
        property int    depthIndex: 0

        function show(d) {
            doc = d
            opened = true
            depthIndex = PageController.incrementDrawerDepth()
        }
        // viaController=true — по Back/Escape: pageController декрементит depth САМ после emit
        function close(viaController) {
            if (!opened)
                return
            opened = false
            depthIndex = 0
            if (!viaController)
                PageController.decrementDrawerDepth()
        }
        // страница может быть уничтожена с открытым оверлеем — компенсируем depth,
        // иначе Back/Escape ломаются во всём приложении (см. TribeResultSheet)
        Component.onDestruction: {
            if (opened)
                PageController.decrementDrawerDepth()
        }

        Connections {
            target: PageController
            enabled: legalSheet.opened
            function onCloseTopDrawer() {
                if (legalSheet.depthIndex === PageController.getDrawerDepth())
                    legalSheet.close(true)
            }
        }

        MouseArea { anchors.fill: parent }   // глушим клики в онбординг под оверлеем

        Loader {
            anchors.fill: parent
            active: legalSheet.opened        // свежий инстанс на каждое открытие
            sourceComponent: PageLegalTribe {
                docKey: legalSheet.doc
                onRequestSettings: legalSheet.close()
            }
        }
    }
}
