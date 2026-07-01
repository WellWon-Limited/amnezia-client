import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes
import QtCore                            // Settings (персист состояния обхода)
import Qt5Compat.GraphicalEffects as Fx

import ".."              // Theme
import "../components"
import "../../Controls2" // PageType
import "../data/presets.js" as Presets   // реальный конфиг NeVPN (см. data/presets.js)

// AVPN: «Анти-VPN» (вкладка nav) — обход VPN для РФ-ресурсов (порт функционала NeVPN).
// РАБОЧАЯ схема: пресеты+исключения → site-based split tunneling Amnezia
// (IpSplitTunnelingController: routeMode VpnAllExceptSites + список доменов/CIDR).
// Применяется при следующем подключении туннеля (как и ванильный split tunneling).
PageType {
    id: root

    // ── состояние обхода (персист в QSettings, категория AvpnBypass) ────
    Settings {
        id: store
        category: "AvpnBypass"
        // AVPN: РФ-доступ ВКЛЮЧЁН ПО УМОЛЧАНИЮ (новые установки). Существующим юзерам (у кого уже
        // сохранён false) включаем одноразовой миграцией ниже (defaultOnMigrated). Дальше выбор
        // пользователя уважается. Конфиг сидится тихо при старте → байпас в первом же коннекте,
        // без обрыва VPN и без тоста (см. Component.onCompleted + apply(silent)).
        property bool masterOn: true
        property bool defaultOnMigrated: false   // одноразовый форс-вкл для старых юзеров
        property string disabledServices: "[]"   // JSON: id выключенных сервисов (дефолт — все вкл)
        property string customHosts: "[]"        // JSON: [{host, on}]
    }

    // AVPN: РФ-доступ должен быть включён по умолчанию у ВСЕХ, не только у новых установок.
    // Одноразовая миграция: первый запуск этой версии форсит masterOn=true (даже если был false),
    // затем флаг defaultOnMigrated блокирует повтор. После — ТИХО (silent) сидим конфиг обхода в
    // движок: пока не подключены, reconnectTimer = no-op → ни тоста, ни рестарта; байпас применится
    // в ближайший коннект. На каждом открытии вкладки тихий re-seed безвреден (без reconnect). // AVPN
    Component.onCompleted: {
        if (!store.defaultOnMigrated) {
            store.masterOn = true
            store.defaultOnMigrated = true
        }
        if (store.masterOn)
            root.apply(true /* silent: без reconnectTimer */)
    }
    property var disabledIds: JSON.parse(store.disabledServices)
    property var customHosts: JSON.parse(store.customHosts)
    property int stateRev: 0   // бамп → Repeater'ы пересоздают строки (свежие биндинги тогглов)

    function isServiceOn(id) { return root.disabledIds.indexOf(id) < 0 }

    function setServiceOn(id, on) {
        var d = root.disabledIds.filter(function(x) { return x !== id })
        if (!on) d.push(id)
        root.disabledIds = d
        store.disabledServices = JSON.stringify(d)
        root.apply()
    }

    function categoryAllOn(cat) {
        for (var i = 0; i < cat.services.length; i++)
            if (!isServiceOn(cat.services[i].id)) return false
        return true
    }

    function setCategoryAll(cat, on) {
        var ids = cat.services.map(function(s) { return s.id })
        var d = root.disabledIds.filter(function(x) { return ids.indexOf(x) < 0 })
        if (!on) d = d.concat(ids)
        root.disabledIds = d
        store.disabledServices = JSON.stringify(d)
        root.stateRev++
        root.apply()
    }

    function addCustomHost(host) {
        host = host.trim()
        if (host === "") return
        for (var i = 0; i < root.customHosts.length; i++)
            if (root.customHosts[i].host === host) return
        var list = root.customHosts.slice()
        list.push({ host: host, on: true })
        root.customHosts = list
        store.customHosts = JSON.stringify(list)
        root.apply()
    }

    function setCustomHost(index, on, remove) {
        var list = root.customHosts.slice()
        if (remove) list.splice(index, 1)
        else list[index].on = on
        root.customHosts = list
        store.customHosts = JSON.stringify(list)
        root.apply()
    }

    // авто-переподключение туннеля после изменений (дебаунс): close → дождаться
    // отключения → open. Без него split-tunneling применился бы только при следующем коннекте.
    property bool pendingReconnect: false
    Timer {
        id: reconnectTimer
        interval: 1200
        onTriggered: {
            if (!ConnectionController.isConnected) return
            // AVPN: на iOS NEVPNManager форсит видимый рестарт туннеля при смене конфига → не рвём
            // активное соединение; настройки уже сохранены и применятся при следующем подключении.
            if (Qt.platform.os === "ios") {
                PageController.showNotificationMessage(qsTr("Изменения применятся при следующем подключении"))
                return
            }
            root.pendingReconnect = true
            ConnectionController.closeConnection()
        }
    }
    Connections {
        target: ConnectionController
        function onConnectionStateChanged() {
            if (root.pendingReconnect && !ConnectionController.isConnected
                    && !ConnectionController.isConnectionInProgress) {
                root.pendingReconnect = false
                ConnectionController.openConnection()
            }
        }
    }

    // полная реконсиляция: собрать все активные записи → в split tunneling Amnezia.
    // Корзина routeMode=VpnAllExceptSites своя, ванильные списки юзера не трогаем.
    function apply(silent) {
        // silent=true (старт/дефолт-сид): только пишем конфиг в движок, БЕЗ авто-реконнекта —
        // применится при следующем коннекте. Обычные правки юзера (silent отсутствует) дебаунсят
        // reconnectTimer как раньше. // AVPN
        if (!silent) reconnectTimer.restart()
        if (!store.masterOn) {
            IpSplitTunnelingController.toggleSplitTunneling(false)
            return
        }
        IpSplitTunnelingController.setRouteMode(2 /* RouteMode::VpnAllExceptSites */)
        IpSplitTunnelingController.removeSites()
        var cats = root.presetCategories
        for (var c = 0; c < cats.length; c++)
            for (var s = 0; s < cats[c].services.length; s++) {
                var svc = cats[c].services[s]
                if (!root.isServiceOn(svc.id)) continue
                var entries = (svc.domains || []).concat(svc.prefixes || [])
                for (var e = 0; e < entries.length; e++)
                    IpSplitTunnelingController.addSite(entries[e])
            }
        for (var h = 0; h < root.customHosts.length; h++)
            if (root.customHosts[h].on)
                IpSplitTunnelingController.addSite(root.customHosts[h].host)
        IpSplitTunnelingController.toggleSplitTunneling(true)
    }

    function activeEntryCount() {
        var n = 0
        var cats = root.presetCategories
        for (var c = 0; c < cats.length; c++)
            for (var s = 0; s < cats[c].services.length; s++) {
                var svc = cats[c].services[s]
                if (root.isServiceOn(svc.id))
                    n += (svc.domains || []).length + (svc.prefixes || []).length
            }
        for (var h = 0; h < root.customHosts.length; h++)
            if (root.customHosts[h].on) n++
        return n
    }

    // реальный конфиг пресетов NeVPN (тот же, что тянется с GitHub:
    // wellwon/anti-vpn-config/presets.json). Схема: categories[key,title,services[id,title,domains,prefixes]]
    readonly property var presetCategories: Presets.config.categories
    readonly property int presetsVersion: Presets.config.version
    readonly property int presetsServiceCount: {
        var n = 0
        for (var i = 0; i < Presets.config.categories.length; i++)
            n += Presets.config.categories[i].services.length
        return n
    }

    // иконки категорий по key (24-grid lucide, сабпасы одной строкой)
    readonly property var categoryIcons: ({
        market: "M6 2 L3 6 V20 a2 2 0 0 0 2 2 H19 a2 2 0 0 0 2 -2 V6 L18 2 Z M3 6 H21 M16 10 a4 4 0 0 1 -8 0",
        social: "M9 11 a4 4 0 1 0 0 -8 4 4 0 0 0 0 8 z M17 21 v-2 a4 4 0 0 0 -4 -4 H5 a4 4 0 0 0 -4 4 v2 M16 3.1 a4 4 0 0 1 0 7.8 M23 21 v-2 a4 4 0 0 0 -3 -3.9",
        bank: "M12 3 L3 8.5 H21 Z M5 11 V18 M9.5 11 V18 M14.5 11 V18 M19 11 V18 M3 21 H21",
        media: "M4 7 h16 a2 2 0 0 1 2 2 v9 a2 2 0 0 1 -2 2 H4 a2 2 0 0 1 -2 -2 V9 a2 2 0 0 1 2 -2 Z M8 3 L12 7 L16 3",
        gov: "M4 21 V5 a2 2 0 0 1 2 -2 h12 a2 2 0 0 1 2 2 v16 M9 8 h1 M14 8 h1 M9 12 h1 M14 12 h1 M9 16 h1 M14 16 h1 M3 21 H21",
        ved: "M21 16 V8 a2 2 0 0 0 -1 -1.73 l-7 -4 a2 2 0 0 0 -2 0 l-7 4 A2 2 0 0 0 3 8 v8 a2 2 0 0 0 1 1.73 l7 4 a2 2 0 0 0 2 0 l7 -4 A2 2 0 0 0 21 16 Z M3.3 7 L12 12 L20.7 7 M12 22 V12",
        wechat: "M21 11.5 a8.38 8.38 0 0 1 -.9 3.8 8.5 8.5 0 0 1 -7.6 4.7 8.38 8.38 0 0 1 -3.8 -.9 L3 21 l1.9 -5.7 a8.38 8.38 0 0 1 -.9 -3.8 8.5 8.5 0 0 1 4.7 -7.6 8.38 8.38 0 0 1 3.8 -.9 h.5 a8.48 8.48 0 0 1 8 8 v.5 z"
    })
    readonly property string fallbackIcon: "M12 21 a9 9 0 1 0 -0.01 0 z M3.6 9 H20.4 M3.6 15 H20.4 M12 3 a15 15 0 0 1 0 18 M12 3 a15 15 0 0 0 0 18"

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // подпись секции: «ЗАГОЛОВОК · N» + опц. ссылка справа
    component SectionLabel: RowLayout {
        property string text: ""
        property string linkText: ""
        spacing: Theme.space.md
        Text {
            Layout.fillWidth: true
            text: parent.text
            color: Theme.color.text3
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold; font.letterSpacing: 1.4
        }
        signal linkClicked()
        Text {
            visible: parent.linkText !== ""
            text: parent.linkText
            color: linkMa.containsMouse ? Theme.color.accentBright : Theme.color.accent
            font.family: Theme.font.body; font.pixelSize: Theme.font.caption
            font.weight: Theme.font.wSemibold
            MouseArea {
                id: linkMa; anchors.fill: parent; anchors.margins: -6
                hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                onClicked: parent.parent.linkClicked()
            }
        }
    }

    // иконка-чип (32×32) с вектором внутри (сабпасы — одной SVG-строкой через "M…")
    component IconChip: Rectangle {
        id: chip
        property string path: ""
        width: 32; height: 32; radius: Theme.radius.sm
        color: Theme.color.surface2
        Shape {
            anchors.centerIn: parent
            width: 18; height: 18
            transform: Scale { xScale: 18 / 24; yScale: 18 / 24 }
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                strokeColor: Theme.color.text2; fillColor: "transparent"; strokeWidth: 1.7
                capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                PathSvg { path: chip.path }
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: Theme.space.xl + PageController.safeAreaTopMargin   // iOS: натив-инсет из pageController
        anchors.leftMargin: Theme.space.xl
        anchors.rightMargin: Theme.space.xl
        spacing: Theme.space.md

        Flickable {
            id: flick
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentHeight: content.height + Theme.space.xl
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Column {
                id: content
                width: parent.width
                spacing: Theme.space.md

                // ── мастер-тоггл ───────────────────────────────────────────
                Rectangle {
                    width: parent.width
                    height: 76
                    radius: Theme.radius.lg
                    color: Theme.color.surface1
                    border.width: 1; border.color: Theme.color.border
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space.lg
                        anchors.rightMargin: Theme.space.lg
                        spacing: Theme.space.md
                        // флаг РФ (круглый, как флаги серверов) — триколор заполняет ВЕСЬ круг
                        // (без внутреннего зазора): три полосы во всю плашку + круговая маска. // AVPN
                        Item {
                            Layout.preferredWidth: 44; Layout.preferredHeight: 44
                            Item {
                                anchors.fill: parent
                                layer.enabled: true
                                layer.effect: Fx.OpacityMask { maskSource: Rectangle { width: 44; height: 44; radius: 22 } }
                                Column {
                                    anchors.fill: parent
                                    Rectangle { width: parent.width; height: parent.height / 3; color: "#EEF2F7" }
                                    Rectangle { width: parent.width; height: parent.height / 3; color: "#3A5BA0" }
                                    Rectangle { width: parent.width; height: parent.height / 3; color: "#B8434E" }
                                }
                            }
                            // тонкий борд-ринг поверх — отделяет светлую верхнюю полосу от фона (как TribeFlag)
                            Rectangle {
                                anchors.fill: parent; radius: 22; color: "transparent"
                                border.width: 1; border.color: Qt.rgba(1, 1, 1, 0.14)
                            }
                        }
                        Column {
                            Layout.fillWidth: true
                            spacing: 2
                            Text {
                                text: qsTr("Доступ к сайтам РФ")
                                color: Theme.color.text1
                                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyM
                                font.weight: Theme.font.wSemibold
                            }
                            Text {
                                text: store.masterOn
                                      ? qsTr("%1 сайтов — без VPN").arg(root.activeEntryCount())
                                      : qsTr("напрямую, мимо VPN-туннеля")
                                color: Theme.color.text3
                                font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                            }
                        }
                        TribeToggle {
                            checked: store.masterOn
                            onToggled: { store.masterOn = checked; root.apply() }
                        }
                    }
                }

                // ── свои исключения ────────────────────────────────────────
                SectionLabel { width: parent.width; text: qsTr("СВОИ ИСКЛЮЧЕНИЯ") }

                RowLayout {
                    width: parent.width
                    spacing: Theme.space.sm
                    TribeField {
                        id: hostField
                        Layout.fillWidth: true
                        placeholderText: qsTr("Сайт, IP или подсеть 17.0.0.0/8…")
                        onAccepted: { root.addCustomHost(text); text = "" }
                    }
                    Rectangle {
                        Layout.preferredWidth: 46; Layout.preferredHeight: 46
                        radius: Theme.radius.sm
                        color: addMa.containsMouse ? Theme.color.accentBright : Theme.color.accent
                        Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                        Shape {
                            anchors.centerIn: parent
                            width: 18; height: 18
                            preferredRendererType: Shape.CurveRenderer
                            ShapePath {
                                strokeColor: "white"; fillColor: "transparent"; strokeWidth: 2
                                capStyle: ShapePath.RoundCap
                                PathSvg { path: "M9 2 V16 M2 9 H16" }
                            }
                        }
                        MouseArea {
                            id: addMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                            onClicked: { root.addCustomHost(hostField.text); hostField.text = "" }
                        }
                    }
                }

                // пользовательские записи
                Repeater {
                    model: { root.stateRev; return root.customHosts }
                    Rectangle {
                        required property var modelData
                        required property int index
                        width: content.width
                        height: 56
                        radius: Theme.radius.md
                        color: Theme.color.surface1
                        border.width: 1; border.color: Theme.color.border
                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.space.lg
                            anchors.rightMargin: Theme.space.lg
                            spacing: Theme.space.md
                            Rectangle {
                                Layout.preferredWidth: 7; Layout.preferredHeight: 7; radius: 3.5
                                color: parent.parent.modelData.on ? Theme.color.connected : Theme.color.textDisabled
                            }
                            Rectangle {
                                Layout.preferredWidth: 28; Layout.preferredHeight: 28
                                radius: Theme.radius.sm; color: Theme.color.surface2
                                Text {
                                    anchors.centerIn: parent
                                    text: parent.parent.parent.modelData.host.charAt(0).toUpperCase()
                                    color: Theme.color.text2
                                    font.family: Theme.font.display; font.pixelSize: Theme.font.caption; font.weight: Theme.font.wBold
                                }
                            }
                            Text {
                                Layout.fillWidth: true
                                text: modelData.host
                                color: Theme.color.text1
                                font.family: Theme.font.mono; font.pixelSize: Theme.font.monoData
                                elide: Text.ElideRight
                            }
                            // удалить (lucide trash)
                            Item {
                                Layout.preferredWidth: 28; Layout.preferredHeight: 28
                                Shape {
                                    anchors.centerIn: parent
                                    width: 17; height: 17
                                    transform: Scale { xScale: 17 / 24; yScale: 17 / 24 }
                                    preferredRendererType: Shape.CurveRenderer
                                    ShapePath {
                                        strokeColor: delMa.containsMouse ? Theme.color.danger : Theme.color.text3
                                        fillColor: "transparent"; strokeWidth: 1.7
                                        capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                        PathSvg { path: "M3 6 H21 M19 6 V20 a2 2 0 0 1 -2 2 H7 a2 2 0 0 1 -2 -2 V6 M8 6 V4 a2 2 0 0 1 2 -2 h4 a2 2 0 0 1 2 2 v2 M10 11 v6 M14 11 v6" }
                                    }
                                }
                                MouseArea {
                                    id: delMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor
                                    onClicked: { root.setCustomHost(index, false, true); root.stateRev++ }
                                }
                            }
                            TribeToggle {
                                checked: modelData.on
                                onToggled: root.setCustomHost(index, checked, false)
                            }
                        }
                    }
                }

                // ── пресеты (реальный конфиг, все категории) ───────────────
                Repeater {
                    model: root.presetCategories
                    Column {
                        id: presetSection
                        required property var modelData
                        width: content.width
                        spacing: Theme.space.md
                        SectionLabel {
                            width: parent.width
                            text: presetSection.modelData.title.toUpperCase() + " · " + presetSection.modelData.services.length
                            linkText: { root.stateRev; return root.categoryAllOn(presetSection.modelData) ? qsTr("всё выкл") : qsTr("всё вкл") }
                            onLinkClicked: root.setCategoryAll(presetSection.modelData, !root.categoryAllOn(presetSection.modelData))
                        }
                        Rectangle {
                            width: parent.width
                            height: presetCol.height
                            radius: Theme.radius.lg
                            color: Theme.color.surface1
                            border.width: 1; border.color: Theme.color.border
                            Column {
                                id: presetCol
                                width: parent.width
                                Repeater {
                                    model: { root.stateRev; return presetSection.modelData.services }
                                    Item {
                                        required property var modelData
                                        required property int index
                                        width: presetCol.width; height: 54
                                        Rectangle {
                                            visible: index > 0
                                            anchors.top: parent.top
                                            anchors.left: parent.left; anchors.right: parent.right
                                            anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                                            height: 1; color: Theme.color.border
                                        }
                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: Theme.space.lg
                                            anchors.rightMargin: Theme.space.lg
                                            spacing: Theme.space.md
                                            IconChip { path: root.categoryIcons[presetSection.modelData.key] || root.fallbackIcon }
                                            Column {
                                                Layout.fillWidth: true
                                                spacing: 1
                                                Text {
                                                    text: modelData.title
                                                    color: Theme.color.text1
                                                    font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                                                }
                                                Text {
                                                    text: (modelData.domains ? modelData.domains.length : 0)
                                                          + qsTr(" доменов")
                                                          + (modelData.prefixes && modelData.prefixes.length
                                                             ? " · " + modelData.prefixes.length + qsTr(" подсетей") : "")
                                                    color: Theme.color.text3
                                                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                                                }
                                            }
                                            TribeToggle {
                                                checked: root.isServiceOn(modelData.id)
                                                onToggled: root.setServiceOn(modelData.id, checked)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ── конфигурация ───────────────────────────────────────────
                SectionLabel { width: parent.width; text: qsTr("КОНФИГУРАЦИЯ") }

                Rectangle {
                    width: parent.width
                    height: cfgCol.height
                    radius: Theme.radius.lg
                    color: Theme.color.surface1
                    border.width: 1; border.color: Theme.color.border
                    Column {
                        id: cfgCol
                        width: parent.width

                        // авто-обновление пресетов
                        Item {
                            width: parent.width; height: 62
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                                spacing: Theme.space.md
                                IconChip { path: "M21 15 v4 a2 2 0 0 1 -2 2 H5 a2 2 0 0 1 -2 -2 v-4 M7 10 L12 15 L17 10 M12 15 V3" }
                                Column {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    Text { text: qsTr("Обновлять списки"); color: Theme.color.text1; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wMedium }
                                    Text { text: qsTr("пресеты с GitHub раз в сутки"); color: Theme.color.text3; font.family: Theme.font.body; font.pixelSize: Theme.font.caption }
                                }
                                TribeToggle { checked: true }
                            }
                        }

                        Rectangle { width: parent.width - 2 * Theme.space.lg; height: 1; color: Theme.color.border; anchors.horizontalCenter: parent.horizontalCenter }

                        // конфиг пресетов
                        Item {
                            width: parent.width; height: 62
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.space.lg; anchors.rightMargin: Theme.space.lg
                                spacing: Theme.space.md
                                IconChip { path: "M20 11 a8.1 8.1 0 0 0 -15.5 -2 M4 5 v4 h4 M4 13 a8.1 8.1 0 0 0 15.5 2 M20 19 v-4 h-4" }
                                Column {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    Text { text: qsTr("Конфиг пресетов"); color: Theme.color.text1; font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS; font.weight: Theme.font.wMedium }
                                    Text {
                                        text: qsTr("версия %1 · %2 сервисов").arg(root.presetsVersion).arg(root.presetsServiceCount)
                                        color: Theme.color.text3; font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                                    }
                                }
                                Rectangle {
                                    Layout.preferredWidth: updText.width + 2 * Theme.space.lg
                                    Layout.preferredHeight: 34
                                    radius: Theme.radius.pill
                                    color: updMa.containsMouse ? Theme.color.surface2 : "transparent"
                                    border.width: 1; border.color: Theme.color.border2
                                    Behavior on color { ColorAnimation { duration: Theme.motion.fast } }
                                    Text {
                                        id: updText
                                        anchors.centerIn: parent
                                        text: qsTr("Обновить")
                                        color: Theme.color.text1
                                        font.family: Theme.font.body; font.pixelSize: Theme.font.caption; font.weight: Theme.font.wSemibold
                                    }
                                    MouseArea { id: updMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor }
                                }
                            }
                        }

                    }
                }

                Text {
                    width: parent.width
                    text: qsTr("При изменениях активный туннель переподключается автоматически")
                    color: Theme.color.text3
                    font.family: Theme.font.body; font.pixelSize: Theme.font.caption
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
