pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes

import ".."   // Theme
import "."    // TribeFlag

// AVPN (Доктор v2, активная; спека 2026-07-17-doctor-v1-design.md + правки владельца):
// попап полной диагностики. Хост — ГЛОБАЛЬНО в PageStart (тест переживает смену вкладок).
// Флоу: интро-плашка с ЗОЛОТОЙ «Запустить диагностику» (возвращена реш. владельца
// 2026-07-17 вечер) → панель стадий с серым таймером и «Отменить» → финал НА ТОМ ЖЕ экране.
// Серверная стадия: «Сервер: [флаг] Страна · мс» — флаг МЕЖДУ двоеточием и названием.
// Стадия «Проверяю другие серверы» опциональна (движок запускает её только при проблеме —
// до 2 альтернатив; рабочая найдена → остаёмся на ней). «Отчёт отправлен в поддержку.
// Ожидайте ответа» — ТОЛЬКО когда была проблема и отчёт реально ушёл в тред; «всё ок»
// тред не дёргает (анонимный отчёт на бэк уходит всегда, движок). Менеджеру — ЧИТАЕМОЕ
// резюме текстом (doctorHumanReport) + diag.log вложением.
Item {
    id: root
    anchors.fill: parent
    visible: opened

    property bool opened: false
    // "intro" | "running" | "done" — интро-плашка с золотой кнопкой ВОЗВРАЩЕНА
    // (реш. владельца 2026-07-17 вечер: запуск только по явному «Запустить диагностику»)
    property string mode: "intro"
    property bool sentToSupport: false
    property int elapsedSec: 0

    readonly property bool hasEngine: typeof TribeEngine !== "undefined"
    readonly property bool hasChat: typeof TribeSupport !== "undefined"
    readonly property bool running: hasEngine && TribeEngine.doctorRunning === true

    // ── Интро-шаги (волна UX 07-22): тип сети → оператор (если сотовая) → режим → запуск ────
    // Авто-детект знает тип сети → вопросов нет (кейс владельца: на Wi-Fi спрашивало оператора).
    property string autoNet: ""      // авто-тип на момент открытия ("" = платформа не знает)
    property string netChoice: ""    // ручной выбор шага 1 ("wifi"/"cellular")
    readonly property string effNet: autoNet !== "" ? autoNet : netChoice
    property bool fullMode: false    // false = быстрая (дефолт), true = полная (все серверы)
    property string carrierSel: ""   // выбранный оператор (код из diagOperators)
    property int nodeTab: 0          // активная вкладка финала «по серверам»
    readonly property bool needNet: autoNet === "" && netChoice === ""
    readonly property bool needOp: effNet === "cellular" && hasEngine
                                   && TribeEngine.diagCarrierAuto() === "" && carrierSel === ""
    readonly property bool canRun: !needNet && !needOp

    // Финал: вкладки по проверенным серверам — текущий + все альтернативы обзора (жалоба
    // владельца: «анализировал три ноды — где инфа по всем трём?»). Пусто = обзора не было.
    readonly property var nodeTabs: {
        if (mode !== "done" || !hasEngine) return []
        const arr = TribeEngine.doctorStages || []
        var cur = ({ kind: "current", name: "", cc: "", rtt: -1 })
        var alts = []
        for (var i = 0; i < arr.length; ++i) {
            const s = arr[i]
            if (s.id === "servers") {
                cur.name = s.region || ""
                cur.cc = s.countryCode || ""
                cur.rtt = (s.rttMs !== undefined ? s.rttMs : -1)
            } else if (s.id === "connect") {
                cur.dataFlows = s.dataFlows === true
                cur.tunMs = s.tunnelIcmpMs
                cur.epMs = s.epIcmpMs
                cur.epBig = s.epIcmpBig
            } else if (s.id === "altnodes" && s.details !== undefined) {
                for (var j = 0; j < s.details.length; ++j) alts.push(s.details[j])
            }
        }
        if (alts.length === 0) return []
        var tabs = []
        if (cur.name !== "" || cur.cc !== "") tabs.push(cur)
        return tabs.concat(alts)
    }
    function tabDotColor(d) {
        if (d.kind === "current")
            return d.dataFlows === true ? Theme.color.connected : Theme.color.danger
        return d.verdict === 2 ? Theme.color.connected
             : d.verdict === 1 ? Theme.color.warning : Theme.color.danger
    }
    function tabLines(d) {
        var out = []
        if (d.kind === "current") {
            if (d.rtt !== undefined && d.rtt > 0)
                out.push(qsTr("Отклик: ~%1 мс").arg(d.rtt))
            out.push(d.dataFlows === true ? qsTr("Данные через туннель идут")
                                          : qsTr("Данные через туннель не проходят"))
            if (d.tunMs !== undefined && d.tunMs >= 0)
                out.push(qsTr("Пинг через туннель: ~%1 мс").arg(d.tunMs))
        } else {
            if (d.rtt_ms !== undefined && d.rtt_ms > 0)
                out.push(qsTr("Отклик: ~%1 мс").arg(d.rtt_ms))
            out.push(d.verdict === 2 ? qsTr("Работает стабильно — обе пробы прошли")
                   : d.verdict === 1 ? qsTr("Нестабильно — данные пропадают после подключения")
                                     : qsTr("Не отвечает — данные не проходят"))
            if (d.tunnel_icmp_ms !== undefined && d.tunnel_icmp_ms >= 0)
                out.push(qsTr("Пинг через туннель: ~%1 мс").arg(d.tunnel_icmp_ms))
        }
        var epMs = d.kind === "current" ? d.epMs : d.ep_icmp_ms
        var epBig = d.kind === "current" ? d.epBig : d.ep_icmp_big
        if (epMs !== undefined)
            out.push(epMs >= 0 ? qsTr("Сервер отвечает напрямую: ~%1 мс").arg(epMs)
                               : qsTr("Сервер не отвечает напрямую — возможна блокировка адреса"))
        if (epBig === false)
            out.push(qsTr("Большие пакеты режутся — признак ограничений оператора"))
        return out
    }

    // Фикс-порядок стадий (id движка -> подпись). Статусы доезжают в doctorStages.
    readonly property var stageDefs: [
        { id: "network",  label: qsTr("Проверяю вашу сеть") },
        { id: "connect",  label: qsTr("Подключаюсь к VPN") },
        { id: "servers",  label: qsTr("Проверяю сервер") },
        { id: "services", label: qsTr("Проверяю мессенджеры и видео") },
        { id: "rusplit",  label: qsTr("Проверяю доступ к сайтам РФ"), optional: true },
        { id: "speed",    label: qsTr("Проверяю скорость") },
        { id: "altnodes", label: qsTr("Проверяю другие серверы"), optional: true },
    ]

    property int depthIndex: 0
    function show() {
        if (opened)
            return
        mode = "intro"
        sentToSupport = false
        elapsedSec = 0
        fullMode = false
        netChoice = ""
        nodeTab = 0
        // тип сети замеряем на момент открытия; выбранный ранее оператор — из настроек
        autoNet = hasEngine ? TribeEngine.doctorNetType() : "wifi"
        carrierSel = hasEngine ? TribeEngine.diagCarrier() : ""
        opened = true
        depthIndex = PageController.incrementDrawerDepth()
    }
    function close() {
        if (!opened)
            return
        if (root.running && root.hasEngine)
            TribeEngine.cancelDoctor()
        opened = false
        mode = "intro"
        if (depthIndex > 0) {
            depthIndex = 0
            PageController.decrementDrawerDepth()
        }
    }
    Connections {
        target: PageController
        enabled: root.opened
        // «назад»/Escape: pageController после emit сам декрементит глубину —
        // закрываемся без повторного декремента.
        function onCloseTopDrawer() {
            if (root.depthIndex !== PageController.getDrawerDepth())
                return
            if (root.running && root.hasEngine)
                TribeEngine.cancelDoctor()
            root.opened = false
            root.mode = "intro"
            root.depthIndex = 0
        }
    }
    Component.onDestruction: if (opened && depthIndex > 0) PageController.decrementDrawerDepth()

    // таймер прошедшего времени (правее прогресс-бара, серым)
    Timer {
        interval: 1000; repeat: true
        running: root.opened && root.mode === "running"
        onTriggered: root.elapsedSec += 1
    }
    function fmtElapsed(s) {
        if (s < 60) return s + qsTr(" с")
        var m = Math.floor(s / 60)
        var r = s % 60
        return m + ":" + (r < 10 ? "0" : "") + r
    }

    Connections {
        target: root.hasEngine ? TribeEngine : null
        ignoreUnknownSignals: true
        function onDoctorFinished() {
            if (!root.opened)
                return
            root.mode = "done"
            root.nodeTab = 0
            // в тред поддержки — ТОЛЬКО при реальной проблеме: читаемое резюме текстом
            // (менеджеру) + diag.log вложением (разработчику). «Всё ок» тред не дёргает.
            if (TribeEngine.doctorHasProblem && root.hasChat) {
                TribeSupport.sendText(TribeEngine.doctorHumanReport())
                TribeSupport.sendDiagReport(TribeEngine.doctorDiagText())
                root.sentToSupport = true
            }
        }
    }

    Rectangle { anchors.fill: parent; color: Qt.alpha(Theme.color.bg800, 0.85) }
    MouseArea {
        anchors.fill: parent
        onClicked: if (root.mode === "intro") root.close()   // в тесте/финале — есть кнопки
    }

    Rectangle {
        id: card
        anchors.centerIn: parent
        // шире (реш. владельца 07-21): те же боковые отступы, что у остальных элементов
        // приложения (Theme.space.xl), кап 520 — только чтобы не распластаться на десктопе
        width: Math.min(parent.width - 2 * Theme.space.xl, 520)
        implicitHeight: col.implicitHeight + 2 * Theme.space.xl
        height: implicitHeight
        radius: Theme.radius.xl
        color: Theme.color.surface1
        border.width: 1
        border.color: Theme.color.border2
        MouseArea { anchors.fill: parent }   // клик по карточке не проваливается в фон

        ColumnLayout {
            id: col
            anchors.left: parent.left; anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.space.xl; anchors.rightMargin: Theme.space.xl
            spacing: Theme.space.md

            // Круглая иконка activity — акцентная
            Rectangle {
                Layout.alignment: Qt.AlignHCenter
                implicitWidth: 52; implicitHeight: 52; radius: 26
                color: Qt.alpha(Theme.color.accent, 0.12)
                border.width: 1
                border.color: Qt.alpha(Theme.color.accent, 0.45)
                Item {
                    anchors.centerIn: parent
                    width: 26; height: 26
                    Shape {
                        width: 24; height: 24
                        transform: Scale { xScale: 26 / 24; yScale: 26 / 24 }
                        preferredRendererType: Shape.CurveRenderer
                        ShapePath {
                            strokeColor: Theme.color.accent; fillColor: "transparent"
                            strokeWidth: 1.8
                            capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                            PathSvg { path: "M22 12 L18 12 L15 21 L9 3 L6 12 L2 12" }
                        }
                    }
                }
            }

            Text {
                Layout.fillWidth: true
                text: root.mode === "done" ? qsTr("Диагностика завершена")
                    : root.mode === "running" ? qsTr("Провожу диагностику")
                    : qsTr("Запустить диагностику?")
                color: Theme.color.text1
                font.family: Theme.font.display
                font.pixelSize: Theme.font.h3
                font.weight: Theme.font.wBold
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            // ── ИНТРО: описание + предупреждение (текст по скриншоту владельца) ──────────
            Text {
                visible: root.mode === "intro"
                Layout.fillWidth: true
                text: qsTr("Диагностика запустит процесс проверки состояния подключений, скорости, лучших серверов, наличия ошибок и др. (полностью анонимно)")
                color: Theme.color.text2
                font.family: Theme.font.body
                font.pixelSize: Theme.font.bodyS
                lineHeight: 1.25
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }
            Text {
                visible: root.mode === "intro"
                Layout.fillWidth: true
                text: root.fullMode
                      ? qsTr("Полная проверка переберёт все серверы — займёт 5–10 минут.")
                      : qsTr("Займёт 1–2 минуты — не закрывайте приложение.")
                color: Theme.color.text3
                font.family: Theme.font.body
                font.pixelSize: Theme.font.caption
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            // ── ШАГ 1: тип интернета — ТОЛЬКО когда платформа сама не знает (иначе не спрашиваем;
            // жалоба владельца: на Wi-Fi предлагало выбрать оператора) ────────────────────────
            ColumnLayout {
                visible: root.mode === "intro" && root.autoNet === ""
                Layout.fillWidth: true
                Layout.topMargin: Theme.space.sm
                spacing: Theme.space.xs
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Какой у вас интернет?")
                    color: Theme.color.text2
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                    font.weight: Theme.font.wSemibold
                    horizontalAlignment: Text.AlignHCenter
                }
                RowLayout {
                    Layout.alignment: Qt.AlignHCenter
                    spacing: Theme.space.xs
                    Repeater {
                        model: [ { code: "wifi", name: qsTr("Wi-Fi") },
                                 { code: "cellular", name: qsTr("Мобильный") } ]
                        delegate: Rectangle {
                            id: netChip
                            required property var modelData
                            readonly property bool on: root.netChoice === modelData.code
                            radius: Theme.radius.pill
                            color: on ? Theme.color.accent : Theme.color.surface2
                            border.width: 1
                            border.color: on ? Theme.color.accent : Theme.color.border
                            implicitHeight: 32
                            implicitWidth: netLabel.implicitWidth + Theme.space.md * 2
                            Text {
                                id: netLabel
                                anchors.centerIn: parent
                                text: netChip.modelData.name
                                color: netChip.on ? Theme.color.bg800 : Theme.color.text2
                                font.family: Theme.font.body
                                font.pixelSize: Theme.font.bodyS
                                font.weight: Theme.font.wSemibold
                            }
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    Haptic.play("selection")
                                    root.netChoice = netChip.modelData.code
                                    if (root.hasEngine)
                                        TribeEngine.setDiagNetType(netChip.modelData.code)
                                }
                            }
                        }
                    }
                }
            }

            // ── ШАГ 2: оператор — только на сотовой и только когда авто-код недоступен (iOS 16+
            // закрыл CTCarrier; на Android авто-код есть → блок скрыт). Выбор обязателен для
            // запуска — паттерны «оператор X режет ноду Y» без него слепые; есть «Другой».
            ColumnLayout {
                id: carrierPick
                visible: root.mode === "intro" && root.hasEngine && root.effNet === "cellular"
                         && TribeEngine.diagCarrierAuto() === ""
                Layout.fillWidth: true
                Layout.topMargin: Theme.space.sm
                spacing: Theme.space.xs
                readonly property var ops: root.hasEngine ? TribeEngine.diagOperators() : []

                Text {
                    Layout.fillWidth: true
                    text: qsTr("Выберите вашего мобильного оператора:")
                    color: Theme.color.text2
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                    font.weight: Theme.font.wSemibold
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                }
                Flow {
                    Layout.fillWidth: true
                    spacing: Theme.space.xs
                    Repeater {
                        model: carrierPick.ops
                        delegate: Rectangle {
                            id: opChip
                            required property var modelData
                            readonly property bool on: root.carrierSel === modelData.code
                            radius: Theme.radius.pill
                            color: on ? Theme.color.accent : Theme.color.surface2
                            border.width: 1
                            border.color: on ? Theme.color.accent : Theme.color.border
                            implicitHeight: 32
                            implicitWidth: opLabel.implicitWidth + Theme.space.md * 2
                            Text {
                                id: opLabel
                                anchors.centerIn: parent
                                text: opChip.modelData.name
                                color: opChip.on ? Theme.color.bg800 : Theme.color.text2
                                font.family: Theme.font.body
                                font.pixelSize: Theme.font.bodyS
                                font.weight: Theme.font.wSemibold
                            }
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    Haptic.play("selection")
                                    const code = opChip.on ? "" : opChip.modelData.code
                                    root.carrierSel = code
                                    if (root.hasEngine) TribeEngine.setDiagCarrier(code)
                                }
                            }
                        }
                    }
                }
            }

            // ── ШАГ 3: режим — «Быстрая» (дефолт) / «Полная» (все серверы, кроме РФ) ─────────
            Rectangle {
                visible: root.mode === "intro"
                Layout.fillWidth: true
                Layout.topMargin: Theme.space.sm
                implicitHeight: 36
                radius: Theme.radius.pill
                color: Theme.color.surface2
                border.width: 1
                border.color: Theme.color.border
                RowLayout {
                    anchors.fill: parent
                    anchors.margins: 3
                    spacing: 3
                    Repeater {
                        model: [ { full: false, name: qsTr("Быстрая") },
                                 { full: true,  name: qsTr("Полная") } ]
                        delegate: Rectangle {
                            id: modeSeg
                            required property var modelData
                            readonly property bool on: root.fullMode === modelData.full
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            radius: Theme.radius.pill
                            color: on ? Theme.color.surface3 : "transparent"
                            border.width: on ? 1 : 0
                            border.color: Theme.color.border2
                            Text {
                                anchors.centerIn: parent
                                text: modeSeg.modelData.name
                                color: modeSeg.on ? Theme.color.text1 : Theme.color.text3
                                font.family: Theme.font.body
                                font.pixelSize: Theme.font.bodyS
                                font.weight: Theme.font.wSemibold
                            }
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    Haptic.play("selection")
                                    root.fullMode = modeSeg.modelData.full
                                }
                            }
                        }
                    }
                }
            }

            // ── СТАДИИ (ход теста и финал) ───────────────────────────────────────────────
            ColumnLayout {
                visible: root.mode !== "intro"
                Layout.fillWidth: true
                spacing: Theme.space.sm

                Repeater {
                    model: root.stageDefs
                    delegate: RowLayout {
                        id: stageRow
                        required property var modelData
                        required property int index
                        Layout.fillWidth: true
                        spacing: Theme.space.sm
                        // опциональные стадии (altnodes) видны только когда реально запущены
                        visible: modelData.optional !== true || stageRow.st !== -100 || stageRow.isCurrent

                        readonly property var doneInfo: {
                            if (!root.hasEngine) return undefined
                            const arr = TribeEngine.doctorStages || []
                            for (var i = 0; i < arr.length; ++i)
                                if (arr[i].id === modelData.id) return arr[i]
                            return undefined
                        }
                        readonly property bool isCurrent: root.hasEngine
                                                          && TribeEngine.doctorStage === modelData.id
                        readonly property int st: doneInfo !== undefined ? (doneInfo.status ?? 0) : -100
                        readonly property string cc: doneInfo !== undefined
                                                     ? (doneInfo.countryCode || "") : ""

                        Item {
                            implicitWidth: 20; implicitHeight: 20
                            Rectangle {   // будущая стадия
                                anchors.centerIn: parent
                                width: 8; height: 8; radius: 4
                                visible: !stageRow.isCurrent && stageRow.st === -100
                                color: Theme.color.text3
                                opacity: 0.4
                            }
                            Rectangle {   // активная — пульс
                                anchors.centerIn: parent
                                width: 10; height: 10; radius: 5
                                visible: stageRow.isCurrent
                                color: Theme.color.accent
                                SequentialAnimation on opacity {
                                    running: stageRow.isCurrent && !Theme.motion.reduceMotion
                                    loops: Animation.Infinite
                                    NumberAnimation { from: 1.0; to: 0.35; duration: 600; easing.type: Easing.InOutSine }
                                    NumberAnimation { from: 0.35; to: 1.0; duration: 600; easing.type: Easing.InOutSine }
                                }
                            }
                            Shape {       // Ok — галка
                                anchors.centerIn: parent
                                width: 14; height: 14
                                visible: stageRow.st === 0
                                preferredRendererType: Shape.CurveRenderer
                                ShapePath {
                                    strokeColor: Theme.color.connected; fillColor: "transparent"
                                    strokeWidth: 2
                                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                                    PathSvg { path: "M2 8 L6 12 L13 3" }
                                }
                            }
                            Rectangle {   // Warn/Bad — точка цветом
                                anchors.centerIn: parent
                                width: 10; height: 10; radius: 5
                                visible: stageRow.st === 1 || stageRow.st === 2
                                color: stageRow.st === 2 ? Theme.color.danger : Theme.color.warning
                            }
                            Rectangle {   // Skip — тире
                                anchors.centerIn: parent
                                width: 8; height: 2; radius: 1
                                visible: stageRow.st === -1
                                color: Theme.color.text3
                            }
                        }

                        // серверная стадия: «Сервер: [флаг] Страна · мс» — флаг МЕЖДУ
                        // двоеточием и названием (реш. владельца). Прочие стадии — просто note.
                        Text {
                            visible: stageRow.cc !== ""
                            text: qsTr("Сервер:")
                            color: Theme.color.text2
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyS
                        }
                        TribeFlag {
                            visible: stageRow.cc !== ""
                            Layout.preferredWidth: 16; Layout.preferredHeight: 16
                            code: stageRow.cc
                        }
                        Text {
                            Layout.fillWidth: true
                            text: {
                                if (stageRow.cc !== "" && stageRow.doneInfo !== undefined) {
                                    var s = stageRow.doneInfo.region || ""
                                    var rtt = stageRow.doneInfo.rttMs
                                    if (rtt !== undefined && rtt > 0) s += " · ~" + rtt + qsTr(" мс")
                                    return s
                                }
                                return stageRow.doneInfo !== undefined && (stageRow.doneInfo.note || "") !== ""
                                       ? stageRow.doneInfo.note : stageRow.modelData.label
                            }
                            color: stageRow.isCurrent ? Theme.color.text1
                                 : stageRow.st !== -100 ? Theme.color.text2 : Theme.color.text3
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.bodyS
                            // перенос до 2 строк вместо обрезки («интернет работ…» — жалоба)
                            wrapMode: Text.WordWrap
                            maximumLineCount: 2
                            elide: Text.ElideRight
                        }
                    }
                }

                // прогресс-бар + серый таймер справа над ним (ТОЛЬКО во время теста)
                RowLayout {
                    visible: root.mode === "running"
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.sm
                    spacing: Theme.space.sm
                    Item { Layout.fillWidth: true }
                    Text {
                        text: root.fmtElapsed(root.elapsedSec)
                        color: Theme.color.text3
                        font.family: Theme.font.mono
                        font.pixelSize: Theme.font.caption
                    }
                }
                Rectangle {
                    visible: root.mode === "running"
                    Layout.fillWidth: true
                    height: 6
                    radius: Theme.radius.pill
                    color: Theme.color.surface3
                    Rectangle {
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        radius: Theme.radius.pill
                        width: parent.width * (root.hasEngine ? TribeEngine.doctorPercent : 0) / 100
                        color: Theme.color.accent
                        Behavior on width { NumberAnimation { duration: Theme.motion.normal; easing.type: Easing.OutCubic } }
                    }
                }
                Text {
                    visible: root.mode === "running"
                    Layout.fillWidth: true
                    text: qsTr("Не закрывайте приложение — идёт проверка")
                    color: Theme.color.text3
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.caption
                    horizontalAlignment: Text.AlignHCenter
                }

                // ── ИТОГ (тот же экран): вердикт; про поддержку — только если реально ушло ──
                Rectangle {
                    visible: root.mode === "done"
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.xs
                    height: 1
                    color: Theme.color.border
                }
                Text {
                    visible: root.mode === "done"
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.xs
                    text: root.hasEngine ? TribeEngine.doctorSummary : ""
                    color: Theme.color.text1
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wSemibold
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                }
                // ── ВКЛАДКИ ПО СЕРВЕРАМ (обзор альтернатив был): текущий + каждая проверенная
                // нода; тап по чипу-флагу листает детали («инфа по всем нодам» — реш. владельца)
                Flow {
                    visible: root.mode === "done" && root.nodeTabs.length > 0
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space.xs
                    spacing: Theme.space.xs
                    Repeater {
                        model: root.nodeTabs
                        delegate: Rectangle {
                            id: tabChip
                            required property var modelData
                            required property int index
                            readonly property bool on: root.nodeTab === index
                            radius: Theme.radius.pill
                            color: on ? Qt.alpha(Theme.color.accent, 0.16) : Theme.color.surface2
                            border.width: 1
                            border.color: on ? Theme.color.accent : Theme.color.border
                            implicitHeight: 30
                            implicitWidth: tabRow.implicitWidth + Theme.space.md * 2
                            RowLayout {
                                id: tabRow
                                anchors.centerIn: parent
                                spacing: 5
                                TribeFlag {
                                    visible: (tabChip.modelData.cc || "") !== ""
                                    Layout.preferredWidth: 14; Layout.preferredHeight: 14
                                    code: tabChip.modelData.cc || ""
                                }
                                Text {
                                    text: tabChip.modelData.name || ""
                                    color: tabChip.on ? Theme.color.text1 : Theme.color.text2
                                    font.family: Theme.font.body
                                    font.pixelSize: Theme.font.caption
                                    font.weight: Theme.font.wSemibold
                                }
                                Rectangle {
                                    implicitWidth: 6; implicitHeight: 6; radius: 3
                                    color: root.tabDotColor(tabChip.modelData)
                                }
                            }
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    Haptic.play("selection")
                                    root.nodeTab = tabChip.index
                                }
                            }
                        }
                    }
                }
                ColumnLayout {
                    visible: root.mode === "done" && root.nodeTabs.length > 0
                    Layout.fillWidth: true
                    spacing: 2
                    Repeater {
                        model: root.nodeTab >= 0 && root.nodeTab < root.nodeTabs.length
                               ? root.tabLines(root.nodeTabs[root.nodeTab]) : []
                        delegate: Text {
                            required property var modelData
                            Layout.fillWidth: true
                            text: modelData
                            color: Theme.color.text2
                            font.family: Theme.font.body
                            font.pixelSize: Theme.font.caption
                            wrapMode: Text.WordWrap
                        }
                    }
                }

                Text {
                    visible: root.mode === "done" && root.sentToSupport
                    Layout.fillWidth: true
                    text: qsTr("Отчёт отправлен в тех. поддержку. Ожидайте ответа.")
                    color: Theme.color.text2
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyS
                    lineHeight: 1.25
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                }
            }

            // ── КНОПКА: интро = ЗОЛОТАЯ «Запустить диагностику»; running = серая «Отменить»;
            //    done = серая «Понятно» ────────────────────────────────────────────────────
            Rectangle {
                readonly property bool isIntro: root.mode === "intro"
                Layout.fillWidth: true
                Layout.topMargin: Theme.space.sm
                height: 52
                radius: Theme.radius.lg
                color: isIntro ? "transparent"
                               : (goMa.pressed ? Theme.color.surface3 : Theme.color.surface2)
                border.width: isIntro ? 0 : 1
                border.color: Theme.color.border2
                gradient: isIntro ? goGrad : null
                // гейт шагов: пока не выбраны тип сети/оператор — кнопка приглушена и молчит
                opacity: isIntro && !root.canRun ? 0.45 : 1.0
                scale: goMa.pressed ? 0.985 : 1.0
                Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
                Gradient {
                    id: goGrad
                    GradientStop { position: 0.0; color: goMa.pressed ? Theme.color.ctaDeep : Theme.color.cta }
                    GradientStop { position: 1.0; color: Theme.color.ctaDeep }
                }

                Text {
                    anchors.centerIn: parent
                    text: parent.isIntro ? qsTr("Запустить диагностику")
                        : root.mode === "done" ? qsTr("Понятно") : qsTr("Отменить")
                    color: parent.isIntro ? Theme.color.bg900 : Theme.color.text1
                    font.family: Theme.font.body
                    font.pixelSize: Theme.font.bodyM
                    font.weight: Theme.font.wBold
                }
                MouseArea {
                    id: goMa
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        if (root.mode === "intro" && root.hasEngine) {
                            if (!root.canRun)
                                return // шаги не пройдены (тип сети/оператор)
                            Haptic.play("light")
                            root.mode = "running"
                            root.elapsedSec = 0
                            TribeEngine.startDoctor(root.fullMode)
                        } else {
                            root.close()
                        }
                    }
                }
            }
        }
    }
}
