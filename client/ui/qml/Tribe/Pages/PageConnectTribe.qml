import QtQuick
import QtQuick.Controls
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects as Fx

import ".."              // Theme
import "../components" // TribeFlag (круглый флаг по country_code) и др.
import "../../Controls2" // PageType

// AVPN: Connect-экран (звёздное небо + горы во всю ширину + орб-сфера). Горы full-bleed и
// заходят на нижнюю часть круга. Синий = Theme.accent (#7ca2d0, финал). UI: переписан 2026-06.
PageType {
    id: root

    readonly property color blueAccent: Theme.color.accent
    readonly property color blue300: "#93C5FD"
    readonly property color blue400: "#60A5FA"
    readonly property color blue600: "#2563EB"
    readonly property color slate400: Theme.color.text2
    readonly property color slate500: Theme.color.text3
    readonly property color slate900: "#0F172A"

    // previewSim: визуальная симуляция (off→Поиск…→Connected) ТОЛЬКО для превью-демо.
    // false = орб ходит в реальный ConnectionController (прод-поведение). // AVPN
    property bool previewSim: false
    property bool simConnected: false
    property bool simConnecting: false
    readonly property bool isOn:  previewSim ? simConnected  : ConnectionController.isConnected
    readonly property bool isBusy: previewSim ? simConnecting : ConnectionController.isConnectionInProgress

    signal requestTab(int index)
    signal requestSettings()
    signal requestNotifications()
    signal requestAdminServers()  // AVPN: админ-просмотр пула нод (только Dev.adminMode)

    // AVPN: центр уведомлений — счётчик непрочитанных. Реальные пуши (#9) идут через мост
    // AvpnPush (APNs/FCM → C++ → QML). В dev-превью моста нет → фолбэк 2 (mock-бейдж).
    readonly property bool hasPush: (typeof AvpnPush !== "undefined")
    readonly property int unreadCount: hasPush ? Number(AvpnPush.unreadCount) : 2

    // AVPN: бейдж подписки. Реактивные Q_PROPERTY на TribeEngine (NOTIFY changed): trafficUsed/
    // trafficLimit/daysLeft/subActive — читают загруженную Subscription через движок. Гард на
    // undefined-движок (dev-превью) с литеральными фолбэками.
    readonly property bool hasEngine:     (typeof TribeEngine !== "undefined")
    readonly property real trafficUsedB:  hasEngine ? Number(TribeEngine.trafficUsed)  : 0
    readonly property real trafficLimitB: hasEngine ? Number(TribeEngine.trafficLimit) : 0
    readonly property bool subActive:     (hasEngine && TribeEngine.subActive !== undefined) ? TribeEngine.subActive : true
    // AVPN: триал/подписка исчерпаны → монетизационный CTA «Получить ключ» вместо ротации.
    // Исчерпан, если: подписка неактивна, ИЛИ дней не осталось (0), ИЛИ лимит трафика выбран.
    readonly property bool subExpired: root.hasEngine && (!root.subActive
                              || (TribeEngine.daysLeft === 0)
                              || (root.trafficLimitB > 0 && root.trafficUsedB >= root.trafficLimitB))
    // остаток трафика: «∞» при безлимите/неизвестно (limit 0 или NaN), иначе (limit-used) в ГБ
    function fmtTrafficLeft() {
        if (!hasEngine) return "3.2 GB"                // dev-превью: литеральный фолбэк
        if (!(trafficLimitB > 0)) return "∞"           // безлимит / ещё не загружено (0 или NaN)
        var leftB = Math.max(0, trafficLimitB - trafficUsedB)
        if (isNaN(leftB)) return "∞"
        return (leftB / 1e9).toFixed(1) + " GB"
    }
    // daysLeft<0 = бессрочно/неизвестно → «∞»; иначе «N дн.»
    readonly property string daysLeftText: !hasEngine ? qsTr("12 дн.")
                              : (TribeEngine.daysLeft >= 0 ? qsTr("%1 дн.").arg(TribeEngine.daysLeft)
                                                          : qsTr("∞"))

    // AVPN: реальный сервер из подписки (карточка внизу). Гард на undefined currentNode (иначе краш).
    readonly property var curNode: (hasEngine && TribeEngine.currentNode) ? TribeEngine.currentNode
                                             : ({ region: "", ip: "", hasNode: false })

    // iOS/Android/desktop: натив-инсет из pageController (на iOS читает UIKit safeAreaInsets).
    readonly property real safeTop: PageController.safeAreaTopMargin

    // Мобайл: сцена (орб + горы + подпись) опущена на ~20% высоты экрана, но так, чтобы
    // подпись не наезжала на карточку сервера (низ сцены ≥ 24px над bottomBlock).
    // Шапку, бейдж, карточку и кнопку не трогаем (реш. 2026-06-11).
    readonly property bool isMobile: Qt.platform.os === "ios" || Qt.platform.os === "android"
    readonly property real sceneShift: {
        if (!isMobile) return 0
        var orbBase = safeTop + 16 + 40 + 76          // header top+height + базовый отступ орба
        var captionBottom = orbBase + 256 + 30 + 18   // орб + отступ подписи + высота подписи
        var maxShift = bottomBlock.y - captionBottom - 24
        // сцена опущена на ~20% высоты, но приподнята на ~высоту кнопки «Обновить» (52, чуть меньше — 44)
        return Math.max(0, Math.min(Math.round(root.height * 0.20) - 44, maxShift))
    }

    function onOrbClicked() {
        if (previewSim) {
            if (simConnected) { simConnected = false; return }
            simConnecting = true; simTimer.restart()
        } else if (typeof TribeEngine !== "undefined") {
            // сервисная модель: enroll → /v1/subscription → выбор ноды → туннель (E2E №1)
            if (isOn || isBusy) TribeEngine.stop()
            else TribeEngine.start()
        } else if (ServersUiController.getServersCount() === 0) {
            // нет ни движка, ни конфигурации — не уводим в ванильный wizard.
            // Гостевой trial (без аккаунта) подключится вместе с control plane (POST /v1/trial).
            PageController.showNotificationMessage(qsTr("Серверы сервиса запускаются — пробный доступ появится в ближайшем обновлении, аккаунт не нужен"))
        } else {
            ConnectionController.connectButtonClicked()
        }
    }

    // ошибки движка — в стандартный тост
    Connections {
        target: typeof TribeEngine !== "undefined" ? TribeEngine : null
        ignoreUnknownSignals: true
        function onError(message) { PageController.showErrorMessage(message) }
    }

    // AVPN (Task 13): активация после покупки по диплинку → re-fetch подписки (бейдж оживёт).
    Connections {
        target: (typeof AvpnDeepLink !== "undefined") ? AvpnDeepLink : null
        ignoreUnknownSignals: true
        function onActivated(token, accountId) {
            if (typeof TribeEngine !== "undefined" && typeof TribeEngine.bootstrap === "function")
                TribeEngine.bootstrap()
            PageController.showNotificationMessage(qsTr("Доступ активирован на этом устройстве"))
        }
    }

    // AVPN (Task 11): bootstrap НЕ зовём из Component.onCompleted — он делает блокирующий сетевой
    // вызов (вложенный QEventLoop), а во время построения QML это вызывает re-entrancy и краш
    // (QQuickItem::setFocus на недостроенном элементе). Движок сам дефер-вызывает bootstrap из
    // конструктора уже ПОСЛЕ показа окна (QTimer::singleShot) — безопасно, как обычный start().
    Timer { id: simTimer; interval: 1500; onTriggered: { root.simConnecting = false; root.simConnected = true } }
    // AVPN DEV: УБРАТЬ — самоскрин для верификации без TCC (см. tribe-ui-verify-loop)
    Timer { running: true; interval: 2500; repeat: false
        onTriggered: root.grabToImage(function(r){ r.saveToFile("/tmp/avpn-screen.png") }) }

    // ── фон ─────────────────────────────────────────────────────────────
    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // ── звёздное небо (full-bleed, верхняя зона) ────────────────────────
    Item {
        id: starField
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        height: 400; clip: true; z: 0   // выше = звёзды тянутся ниже, ближе к орбу
        property var starsData: []
        Component.onCompleted: {
            var arr = []
            for (var i = 0; i < 32; i++)
                arr.push({ tx: Math.random(), ty: Math.random() * 0.6,
                           s: Math.random() * 1.8 + 1, o: Math.random() * 0.6 + 0.15,
                           d: Math.random() * 2600 })
            starsData = arr
        }
        Repeater {
            model: starField.starsData
            delegate: Rectangle {
                width: modelData.s; height: modelData.s; radius: width / 2; color: "white"
                x: modelData.tx * starField.width; y: modelData.ty * starField.height
                opacity: modelData.o
                SequentialAnimation on opacity {
                    running: !Theme.motion.reduceMotion; loops: Animation.Infinite
                    NumberAnimation { from: modelData.o; to: modelData.o * 0.25; duration: 1400; easing.type: Easing.InOutSine }
                    NumberAnimation { from: modelData.o * 0.25; to: modelData.o; duration: 1400; easing.type: Easing.InOutSine }
                    PauseAnimation { duration: modelData.d }
                }
            }
        }
        Rectangle {
            anchors.fill: parent
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.rgba(0x1E/255, 0x3A/255, 0x8A/255, 0.10) }
                GradientStop { position: 0.55; color: "transparent" }
                GradientStop { position: 1.0; color: Theme.color.bg800 }
            }
        }
    }

    // ── header: бренд-марк + Tribe VPN + бейдж подписки ─────────────────
    Item {
        id: header
        anchors.top: parent.top; anchors.left: parent.left; anchors.right: parent.right
        anchors.topMargin: 16 + root.safeTop
        anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.lg
        height: 40; z: 10

        Item {
            id: brand
            anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter
            width: brandMark.width + 10 + brandText.width
            height: brandText.height

            Row {  // brand-mark: 5 баров сигнала (пропорции лого-SVG 16/28/36/26/18), высота = капсам,
                   // низ баров — на базовой линии wordmark (одна линия с текстом)
                id: brandMark
                anchors.left: parent.left
                anchors.bottom: brandText.baseline
                spacing: 2
                Rectangle { width: 3; height: 7;  radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 12; radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 16; radius: 1.5; color: root.blueAccent;  anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 12; radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
                Rectangle { width: 3; height: 8;  radius: 1.5; color: "#EEF3F9";        anchors.bottom: parent.bottom }
            }
            Text {
                id: brandText
                anchors.left: brandMark.right; anchors.leftMargin: 10
                text: "Tribe VPN"; color: "#EEF3F9"
                font.family: Theme.font.display; font.pixelSize: Theme.font.h2; font.weight: Theme.font.wExtra
                font.letterSpacing: Theme.font.trackTight * Theme.font.h2
            }
        }
        // AVPN: админ-вход в просмотр пула нод (server/stack, vector). Только Dev.adminMode.
        // Маленькая иконка справа от бренда; тап → requestAdminServers() → PageLocationsTribe (админ).
        Rectangle {
            id: adminServersBtn
            visible: Dev.adminMode
            anchors.left: brand.right; anchors.leftMargin: Theme.space.md
            anchors.verticalCenter: parent.verticalCenter
            width: 36; height: 36
            radius: Theme.radius.pill
            color: adminMa.containsMouse ? Theme.color.surface2 : Theme.color.surface1
            border.width: 1; border.color: Theme.color.border
            Behavior on color { ColorAnimation { duration: 160 } }
            // иконка «server/stack» (Tabler "stack", 24-grid → 22px)
            Shape {
                anchors.centerIn: parent
                width: 22; height: 22
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 1.7
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M12 3 L21 8 L12 13 L3 8 Z M3 12 L12 17 L21 12 M3 16 L12 21 L21 16" }
                }
            }
            MouseArea { id: adminMa; anchors.fill: parent; hoverEnabled: true
                cursorShape: Qt.PointingHandCursor; onClicked: root.requestAdminServers() }
        }

        // бейдж подписки + колокол уведомлений (прижаты вправо одной Row); // AVPN
        Row {
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Theme.space.md

            // бейдж подписки (одна строка): остаток трафика (real) + дни (real daysLeft).
            // тап → Профиль (заменяет шестерёнку). subActive гейтит цвет рамки.
            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: statRow.width + 2 * Theme.space.lg
                height: 36
                radius: Theme.radius.pill
                color: statMa.containsMouse ? Theme.color.surface2 : Theme.color.surface1
                border.width: 1
                border.color: root.subActive ? Theme.color.border : Theme.color.warning
                Behavior on color { ColorAnimation { duration: 160 } }
                Row {
                    id: statRow
                    anchors.centerIn: parent
                    spacing: Theme.space.sm
                    Text { text: root.fmtTrafficLeft(); color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: 13; anchors.verticalCenter: parent.verticalCenter }
                    Rectangle { width: 3; height: 3; radius: 1.5; color: root.slate500; anchors.verticalCenter: parent.verticalCenter }
                    Text { text: root.daysLeftText; color: Theme.color.text1; font.family: Theme.font.mono; font.pixelSize: 13; anchors.verticalCenter: parent.verticalCenter }
                }
                MouseArea { id: statMa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: root.requestSettings() }
            }

            // колокол уведомлений (vector Tabler "bell") + бейдж непрочитанных
            Rectangle {
                id: bellBtn
                anchors.verticalCenter: parent.verticalCenter
                width: 36; height: 36
                radius: Theme.radius.pill
                color: bellMa.containsMouse ? Theme.color.surface2 : Theme.color.surface1
                border.width: 1; border.color: Theme.color.border
                Behavior on color { ColorAnimation { duration: 160 } }
                Shape {
                    anchors.centerIn: parent
                    width: 22; height: 22
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath {
                        strokeColor: Theme.color.text1; fillColor: "transparent"; strokeWidth: 1.7
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M6 8 a6 6 0 0 1 12 0 c0 7 3 9 3 9 H3 s3 -2 3 -9z M10.5 21 a2 2 0 0 0 3 0" }
                    }
                }
                // бейдж непрочитанных (красный кружок с числом)
                Rectangle {
                    visible: root.unreadCount > 0
                    width: 16; height: 16; radius: 8
                    color: Theme.color.danger
                    anchors.right: parent.right; anchors.top: parent.top
                    anchors.rightMargin: -2; anchors.topMargin: -2
                    Text {
                        anchors.centerIn: parent
                        text: root.unreadCount > 9 ? "9+" : String(root.unreadCount)
                        color: "#FFFFFF"
                        font.family: Theme.font.body; font.pixelSize: 10; font.weight: Theme.font.wBold
                    }
                }
                MouseArea { id: bellMa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: root.requestNotifications() }
            }
        }
    }

    // ── ОРБ (центрирован, z10) ──────────────────────────────────────────
    Item {
        id: orb
        width: 256; height: 256
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: header.bottom; anchors.topMargin: 76 + root.sceneShift   // сцена опущена (мобайл: ещё ~20% вниз), шапка на месте
        z: 10

        // внешнее свечение (КРУГЛОЕ — задаём радиусы = половине ширины, иначе квадрат)
        Fx.RadialGradient {
            anchors.centerIn: parent
            width: 360; height: 360
            horizontalRadius: width / 2
            verticalRadius: height / 2
            scale: root.isOn ? 1.2 : (root.isBusy ? 1.1 : 1.0)
            Behavior on scale { NumberAnimation { duration: 700; easing.type: Easing.InOutSine } }
            SequentialAnimation on opacity {
                running: root.isBusy && !Theme.motion.reduceMotion; loops: Animation.Infinite
                NumberAnimation { from: 0.6; to: 0.3; duration: 700 }
                NumberAnimation { from: 0.3; to: 0.6; duration: 700 }
            }
            opacity: root.isOn ? 0.5 : (root.isBusy ? 0.6 : 0.22)
            gradient: Gradient {
                GradientStop { position: 0.0;  color: root.isOn ? root.blueAccent : (root.isBusy ? root.blue400 : Qt.rgba(1,1,1,1)) }
                GradientStop { position: 0.42; color: root.isOn ? Qt.rgba(0x3E/255,0x80/255,0xED/255,0.45) : Qt.rgba(1,1,1,0.22) }
                GradientStop { position: 0.72; color: "transparent" }
                GradientStop { position: 1.0;  color: "transparent" }
            }
        }

        // 2 внешних кольца (эталон: -inset-18 → 292, -inset-36 → 328)
        Rectangle { anchors.centerIn: parent; width: 292; height: 292; radius: 146
            color: "transparent"; border.width: 1.5; border.color: Qt.rgba(1,1,1,0.15) }
        Rectangle { anchors.centerIn: parent; width: 328; height: 328; radius: 164
            color: "transparent"; border.width: 1; border.color: Qt.rgba(1,1,1,0.10) }

        // основная сфера (эталон: inset-2 от 256 → 240)
        Rectangle {
            id: sphere
            anchors.centerIn: parent
            width: 240; height: 240; radius: 120
            gradient: Gradient {
                GradientStop { position: 0.0; color: root.isOn ? root.blue300 : "white" }
                GradientStop { position: 1.0; color: root.isOn ? root.blue600 : "#F1F5F9" }
            }
            scale: orbMa.pressed ? 0.97 : 1.0
            Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
            Rectangle { anchors.fill: parent; anchors.margins: 3;  radius: width/2; color: "transparent"; border.width: 1.5; border.color: Qt.rgba(1,1,1,0.40) }
            Rectangle { anchors.fill: parent; anchors.margins: 13; radius: width/2; color: "transparent"; border.width: 1;   border.color: Qt.rgba(1,1,1,0.20) }
            Rectangle { anchors.fill: parent; anchors.margins: 26; radius: width/2; color: "transparent"; border.width: 1;   border.color: Qt.rgba(1,1,1,0.10) }
        }

        Text {
            anchors.centerIn: parent; z: 40
            text: root.isBusy ? "Connecting…" : (root.isOn ? "Connected" : "Connect")
            color: root.isOn ? "white" : root.slate900
            font.family: Theme.font.display; font.pixelSize: 26; font.weight: Theme.font.wBold
        }

        MouseArea { id: orbMa; anchors.fill: sphere; cursorShape: Qt.PointingHandCursor; onClicked: root.onOrbClicked() }
    }

    // ── ГОРЫ (FULL-BLEED, 1:1 с эталонным React-макетом: 3 слоя, каждый —
    //    градиент, растворяющийся в фон #0A111D к нижней кромке) ───────────
    Item {
        id: mtn
        anchors.left: parent.left; anchors.right: parent.right
        anchors.top: orb.top; anchors.topMargin: 88   // top-[120px] макета при орбе на +32
        height: 250; z: 20
        Shape {
            width: 1000; height: 320
            transform: Scale { xScale: mtn.width / 1000; yScale: 250 / 320 }
            preferredRendererType: Shape.CurveRenderer
            // дальний misty-план (farMountainGrad). SVG-градиенты в эталоне привязаны к bbox
            // КАЖДОГО слоя (objectBoundingBox), поэтому y1 = вершина слоя, не 0.
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 130; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x1E/255,0x29/255,0x3B/255,0.35) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,200 L 100,160 L 200,190 L 320,140 L 410,180 L 500,130 L 590,180 L 680,140 L 820,180 L 920,150 L 1000,180 L 1000,320 L 0,320 Z" }
            }
            // средний план (midMountainGrad)
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 150; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x1E/255,0x24/255,0x30/255,0.75) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,240 L 120,190 L 240,230 L 350,165 L 430,200 L 500,150 L 570,200 L 660,160 L 780,210 L 900,170 L 1000,200 L 1000,320 L 0,320 Z" }
            }
            // передний план (frontMountainGrad) — тоже градиент, НЕ сплошной.
            // Левый склон (550,220→640,180) ПАРАЛЛЕЛЕН подъёму среднего (570,200→660,160),
            // отступ 20 — скала «вписана в силуэт тени», грани не пересекаются (эталон 2026-06-10).
            ShapePath {
                strokeWidth: 0; fillColor: "transparent"
                fillGradient: LinearGradient {
                    x1: 0; y1: 170; x2: 0; y2: 320
                    GradientStop { position: 0.0; color: Qt.rgba(0x15/255,0x1B/255,0x28/255,0.90) }
                    GradientStop { position: 1.0; color: "#0A111D" }
                }
                PathSvg { path: "M 0,280 L 150,230 L 280,260 L 380,190 L 450,220 L 500,170 L 550,220 L 640,180 L 750,240 L 880,200 L 1000,240 L 1000,320 L 0,320 Z" }
            }
        }
    }

    // подпись под орбом (поверх гор)
    Text {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: orb.bottom; anchors.topMargin: 30   // чуть ниже орба (просьба 2026-06-11)
        z: 30; horizontalAlignment: Text.AlignHCenter
        text: root.isOn ? qsTr("Защита активна — ваше соединение безопасно")
                        : qsTr("Подключиться — нажмите кнопку выше")
        color: root.slate400
        font.family: Theme.font.body; font.pixelSize: Theme.font.monoData; font.weight: Theme.font.wMedium
    }

    // ── низ: карточка сервера + кнопка обновить (z30 — выше основания гор) ──
    Column {
        id: bottomBlock
        anchors.bottom: parent.bottom; anchors.left: parent.left; anchors.right: parent.right
        anchors.bottomMargin: Theme.space.lg
        anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.lg
        z: 30

        // карточка сервера
        Rectangle {
            width: parent.width; implicitHeight: 84; height: 84
            radius: 24
            color: Qt.rgba(0x1E/255, 0x29/255, 0x3B/255, 0.40)
            border.width: 1; border.color: Qt.rgba(0x33/255, 0x41/255, 0x55/255, 0.5)
            Row {
                anchors.fill: parent; anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                spacing: Theme.space.lg
                // иконка региона: КРУГЛЫЙ флаг по country_code «во всю плашку» (SVG из flagKit,
                // не эмодзи), иначе тёмная плашка с Tabler "world".
                TribeFlag {
                    width: 52; height: 52; anchors.verticalCenter: parent.verticalCenter
                    code: root.curNode.hasNode ? (root.curNode.countryCode || "") : ""
                    fallback: Component {
                        Rectangle {
                            radius: width / 2
                            color: Qt.rgba(0x0F/255,0x17/255,0x2A/255,0.8)
                            border.width: 1; border.color: Qt.rgba(0x33/255,0x41/255,0x55/255,0.5)
                            Shape {
                                anchors.centerIn: parent; width: 26; height: 26
                                preferredRendererType: Shape.CurveRenderer
                                ShapePath {
                                    strokeColor: root.blueAccent; fillColor: "transparent"; strokeWidth: 1.8
                                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                    PathSvg { path: "M13 2 a11 11 0 1 0 0.01 0z M2 13 h22 M13 2 a16 16 0 0 1 0 22 a16 16 0 0 1 0 -22z" }
                                }
                            }
                        }
                    }
                }
                Column {
                    anchors.verticalCenter: parent.verticalCenter; spacing: 2
                    // при выбранном узле справа сигнал+шеврон (30+18); без узла — текст во всю ширину
                    width: parent.width - 52 - Theme.space.lg - (root.curNode.hasNode ? (30 + 18 + 2 * Theme.space.lg) : 0)
                    Text { text: root.curNode.hasNode ? (root.curNode.name || root.curNode.region) : qsTr("Умный выбор сервера")
                        color: "white"; elide: Text.ElideRight; width: parent.width
                        font.family: Theme.font.display; font.pixelSize: Theme.font.h3; font.weight: Theme.font.wBold }
                    Text { text: root.curNode.hasNode ? ("IP: " + root.curNode.ip) : qsTr("Сервис запускает узел")
                        color: root.slate500
                        font.family: Theme.font.mono; font.pixelSize: 10 }
                }
                Row {  // сигнал-бары (только когда узел выбран)
                    visible: root.curNode.hasNode
                    spacing: 2; height: 16; anchors.verticalCenter: parent.verticalCenter
                    Rectangle { width: 4; height: 8;  radius: 2; color: root.blueAccent; anchors.bottom: parent.bottom }
                    Rectangle { width: 4; height: 12; radius: 2; color: root.blueAccent; anchors.bottom: parent.bottom }
                    Rectangle { width: 4; height: 16; radius: 2; color: root.blueAccent; anchors.bottom: parent.bottom }
                }
                Shape {
                    visible: root.curNode.hasNode
                    width: 18; height: 18; anchors.verticalCenter: parent.verticalCenter
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath { strokeColor: root.slate500; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M7 4 L13 9 L7 14" } }
                }
            }
            // карточка-инфо (без перехода): Серверы ушли в админ-панель (#5). // AVPN
        }

        // ── нижний слот: два состояния одной геометрии (52/lg) ──────────────
        // subExpired → ЗОЛОТАЯ кнопка «Получить ключ» (CTA, монетизация).
        // иначе      → кнопка «Обновить подключение» (ротация ноды).
        // ────────────────────────────────────────────────────────────────────

        // ЗОЛОТАЯ CTA «Обновить ключ» — в личный кабинет с JWT-авторизацией (триал исчерпан). // AVPN
        Rectangle {
            id: ctaBtn
            visible: root.subExpired
            width: parent.width; height: 52; radius: Theme.radius.lg
            gradient: Gradient {
                GradientStop { position: 0.0; color: ctaMa.pressed ? Theme.color.ctaDeep : Theme.color.cta }
                GradientStop { position: 1.0; color: Theme.color.ctaDeep }
            }
            scale: ctaMa.pressed ? 0.985 : 1.0
            Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
            Row {
                anchors.centerIn: parent; spacing: 10
                // иконка ключа (lucide "key-round", 24-grid → 20px)
                Shape {
                    width: 20; height: 20; anchors.verticalCenter: parent.verticalCenter
                    transform: Scale { xScale: 20/24; yScale: 20/24 }
                    preferredRendererType: Shape.CurveRenderer
                    ShapePath { strokeColor: Theme.color.bg900; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M2.586 17.414 A2 2 0 0 0 2 18.828 V21 a1 1 0 0 0 1 1 h3 a1 1 0 0 0 1 -1 v-1 a1 1 0 0 1 1 -1 h1 a1 1 0 0 0 1 -1 v-1 a1 1 0 0 1 1 -1 h.172 a2 2 0 0 0 1.414 -.586 l.814 -.814 a6.5 6.5 0 1 0 -4 -4z M15.5 7.5 a.5 .5 0 1 0 .01 0z" } }
                }
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: qsTr("Обновить ключ")
                    color: Theme.color.bg900
                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM; font.weight: Theme.font.wBold
                }
            }
            MouseArea {
                id: ctaMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onClicked: {
                    // Личный кабинет с JWT-авторизацией: токен подписки (если движок его отдаёт) → query.
                    // TODO(AVPN): экспонировать TribeEngine.authToken (JWT) из C++ для сквозной авторизации.
                    var base = "https://tribevpn.com/account"
                    var tok = (root.hasEngine && TribeEngine.authToken !== undefined) ? String(TribeEngine.authToken) : ""
                    Qt.openUrlExternally(tok.length > 0 ? (base + "?token=" + encodeURIComponent(tok)) : base)
                }
            }
        }

        // кнопка «Обновить коннект» → ротация на ДРУГУЮ ноду (TribeEngine.manualSwitch,
        // исключает текущую). Активна только при подключении; на время свитча — busy. // AVPN
        Rectangle {
            id: refreshBtn
            visible: !root.subExpired
            width: parent.width; height: 52; radius: 16
            // ротация осмысленна только когда туннель поднят; иначе приглушаем
            opacity: (root.hasEngine && !root.isOn) ? 0.45 : 1.0
            color: refreshMa.containsMouse ? Qt.rgba(0x1E/255,0x29/255,0x3B/255,0.5) : "transparent"
            border.width: 1
            border.color: refreshMa.containsMouse ? Qt.rgba(0x3E/255,0x80/255,0xED/255,0.5) : Qt.rgba(0x33/255,0x41/255,0x55/255,0.8)
            Behavior on color { ColorAnimation { duration: 160 } }
            Row {
                anchors.centerIn: parent; spacing: 10
                // иконка обновления (Tabler refresh, 24-grid → ровно в 20px, по центру).
                // На время свитча — бесконечное вращение. // AVPN
                Shape {
                    id: refreshIcon
                    width: 20; height: 20; anchors.verticalCenter: parent.verticalCenter
                    transform: Scale { xScale: 20/24; yScale: 20/24 }
                    preferredRendererType: Shape.CurveRenderer
                    RotationAnimation on rotation {
                        running: root.hasEngine && TribeEngine.busy && !Theme.motion.reduceMotion
                        from: 0; to: 360; duration: 900; loops: Animation.Infinite
                    }
                    ShapePath { strokeColor: root.blueAccent; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M20 11 a8.1 8.1 0 0 0 -15.5 -2 M4 5 v4 h4" } }
                    ShapePath { strokeColor: root.blueAccent; fillColor: "transparent"; strokeWidth: 2
                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                        PathSvg { path: "M4 13 a8.1 8.1 0 0 0 15.5 2 M20 19 v-4 h-4" } }
                }
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: (root.hasEngine && TribeEngine.busy) ? qsTr("Подбираем сервер…") : qsTr("Обновить подключение")
                    color: "#DBEAFE"; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wMedium
                }
            }
            MouseArea {
                id: refreshMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onClicked: {
                    if (!root.hasEngine) return
                    if (TribeEngine.busy) return
                    if (!root.isOn) {     // не подключены — обычный старт вместо ротации
                        TribeEngine.start()
                        return
                    }
                    TribeEngine.manualSwitch()   // форс-свитч на другую ноду (исключая текущую)
                }
            }
        }
    }
}
