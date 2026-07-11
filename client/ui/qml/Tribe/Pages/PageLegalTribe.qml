import QtQuick
import QtQuick.Layouts

import ".."              // Theme, Dev
import "../components"
import "../../Controls2" // PageType

// AVPN in-app Legal: Политика конфиденциальности / Условия использования БЕЗ выброса
// на внешний сайт (в РФ он без VPN может быть недоступен). Три слоя контента:
//   1) TribeEngine.legalDocCached() — дисковый кэш прошлого fetch, а при его отсутствии
//      qrc-снапшот Tribe/legal/<doc>.<lang>.md (читает C++: XHR к file:/qrc: в QML
//      по умолчанию запрещён — QML_XHR_ALLOW_FILE_READ);
//   2) тихий fetch tribevpn.com/legal/<doc>.<lang>.md — TribeEngine.legalDocFetch()
//      → onLegalDocReady. Ошибки сети молчаливые: остаёмся на кэше/снапшоте.
//   3) XHR-чтение снапшота с диска — ТОЛЬКО страховка dev-превью без движка
//      (ui-preview.sh выставляет QML_XHR_ALLOW_FILE_READ=1).
// Правка документов = пересборка .md на сайте (tribe-backend scripts/build_legal_md.py),
// БЕЗ перевыпуска приложений. Спека: tribe-front
// docs/superpowers/specs/2026-07-07-in-app-legal-pages-design.md
PageType {
    id: root

    // какой документ показываем; выставляется при открытии (PageStart, extraProps)
    property string docKey: "privacy"   // privacy | terms

    // назад — в настройки (goAvpnTab(3) в PageStart): страница открыта из настроек
    signal requestSettings()

    readonly property real safeTop: Math.max(PageController.safeAreaTopMargin, SafeArea.margins.top)
    readonly property bool hasEngine: (typeof TribeEngine !== "undefined")
    // язык документа: язык приложения (или локаль), нормализованный в ru/en/es
    // (зеркалит LegalDocs::normalizeLang; прочие локали → en)
    readonly property string lang: {
        var l = (root.hasEngine && TribeEngine.appLang) ? TribeEngine.appLang
                                                        : Qt.locale().name
        l = l.substring(0, 2).toLowerCase()
        return (l === "ru" || l === "es") ? l : "en"
    }
    readonly property string title: docKey === "terms" ? qsTr("Условия использования")
                                                       : qsTr("Политика конфиденциальности")

    property string bodyMd: ""   // приоритет: fetch > кэш > qrc-снапшот

    function loadSnapshot() {
        // qrc-снапшот (или файл с диска в dev-превью) — только если слоёв выше ещё нет
        var xhr = new XMLHttpRequest()
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE
                    && xhr.responseText && root.bodyMd === "")
                root.bodyMd = xhr.responseText
        }
        xhr.open("GET", Qt.resolvedUrl("../legal/" + docKey + "." + lang + ".md"))
        xhr.send()
    }

    function reload() {
        // стейл-бинарник движка (dev-превью) может не знать legal-методов — гварды по функции
        var fresh = ""
        if (root.hasEngine && typeof TribeEngine.legalDocCached === "function")
            fresh = TribeEngine.legalDocCached(docKey, lang)
        root.bodyMd = fresh
        if (root.bodyMd === "")
            loadSnapshot()
        if (root.hasEngine && typeof TribeEngine.legalDocFetch === "function")
            TribeEngine.legalDocFetch(docKey, lang)
    }

    property bool _ready: false
    Component.onCompleted: { _ready = true; reload() }
    // язык сменили, пока страница живёт (оверлей поверх онбординга, где есть переключатель
    // языка) — перечитываем документ; для обычного открытия из настроек это no-op
    onLangChanged: if (_ready) reload()
    onDocKeyChanged: if (_ready) reload()

    Connections {
        target: root.hasEngine ? TribeEngine : null
        ignoreUnknownSignals: true
        function onLegalDocReady(doc, lang, text) {
            if (doc === root.docKey && lang === root.lang)
                root.bodyMd = text
        }
    }

    Rectangle { anchors.fill: parent; color: Theme.color.bg800 }

    // свайп слева-направо = «назад» (жалоба 2026-07-11)
    TribeEdgeBack { onTriggered: root.requestSettings() }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: root.safeTop
        spacing: 0

        TribeHeader {
            Layout.fillWidth: true
            title: root.title
            showBack: true
            onBackClicked: root.requestSettings()
        }

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: Theme.space.xl
            Layout.rightMargin: Theme.space.xl
            contentHeight: legalBody.implicitHeight + Theme.space.xxl
            clip: true

            Text {
                id: legalBody
                anchors.left: parent.left; anchors.right: parent.right
                topPadding: Theme.space.md
                text: root.bodyMd
                textFormat: Text.MarkdownText
                wrapMode: Text.WordWrap
                color: Theme.color.text2
                linkColor: Theme.color.accent
                font.family: Theme.font.body; font.pixelSize: Theme.font.bodyS
                onLinkActivated: (link) => Qt.openUrlExternally(link)
            }
        }
    }
}
