import QtQuick

import ".." // Theme

// Human-readable reducer stage. Only typed, redacted reasons cross this boundary.
Text {
    id: root

    property string stage: "idle"
    property string transport: "none"
    property string fallbackFrom: "none"
    property string fallbackTo: "none"
    property string typedReason: ""
    property string awgLabel: qsTr("AWG")
    property string xrayLabel: qsTr("Xray")

    function protocolName(value) {
        return value === "awg" ? awgLabel
             : value === "xray" ? xrayLabel : qsTr("VPN")
    }

    function failureText(reason) {
        if (reason === "no_compatible_candidate" || reason === "no_candidate"
                || reason === "mode_location_pair_unavailable"
                || reason === "catalog_v2_no_connectable_runtime")
            return qsTr("Нет совместимого сервера для выбранного режима")
        if (reason === "no_alternative_candidate" || reason === "reselect_unavailable")
            return qsTr("Другого совместимого сервера сейчас нет")
        if (reason === "location_unavailable")
            return qsTr("Выбранная локация больше недоступна — выберите другую")
        if (reason === "doctor_requires_live_v2_session"
                || reason === "doctor_unavailable"
                || reason === "verification_retry_unavailable"
                || reason === "no live unverified session")
            return qsTr("Сначала подключите VPN, затем запустите диагностику")
        if (reason === "catalog_auth_not_ready" || reason === "signed_out")
            return qsTr("Нет активного доступа")
        if (reason === "catalog_network_unavailable"
                || reason === "catalog_refresh_unavailable"
                || reason === "catalog_refresh_unavailable_or_inflight"
                || reason === "catalog_protocol_error")
            return qsTr("Не удалось обновить список серверов — проверьте интернет и повторите")
        if (reason === "user_intent_preferences_unavailable")
            return qsTr("Не удалось сохранить выбор — освободите место и повторите")
        if (reason === "logout_in_progress")
            return qsTr("Завершаем выход — подождите немного")
        if (reason === "verification_timeout"
                || reason === "post_tunnel_verification_timeout"
                || reason === "post_tunnel_dns_timeout")
            return qsTr("Сервер запустился, но интернет через него не отвечает")
        if (reason === "guard_unavailable" || reason === "guard_lost"
                || reason === "guard_arm_failed"
                || reason === "catalog_v2_platform_guard_unavailable"
                || reason === "native_guard_recovery_required"
                || reason === "legacy_native_teardown_pending")
            return qsTr("Безопасное переключение недоступно на этом устройстве")
        if (reason === "transport_stop_timeout")
            return qsTr("Старое соединение не остановилось — новое заблокировано для безопасности")
        if (reason === "receipt_authority_rejected"
                || reason === "receipt_catalog_stale"
                || reason === "catalog_acceptance_rejected"
                || reason === "catalog_lkg_unusable")
            return qsTr("Доступ обновился — получите новый список серверов")
        if (reason === "receipt_trust_refresh_required"
                || reason === "verification_authority_refresh_required")
            return qsTr("Обновляем доверенные ключи проверки соединения")
        return qsTr("Не удалось установить защищённое соединение")
    }

    function stageText() {
        switch (stage) {
        case "resolving": return qsTr("Получаем доступные серверы…")
        case "preparing": return qsTr("Сервер готовит защищённый доступ…")
        case "renewing": return qsTr("Обновляем защищённый доступ без переподключения…")
        case "selecting": return qsTr("Подбираем рабочий сервер…")
        case "starting": return qsTr("Запускаем %1…").arg(protocolName(transport))
        case "tunnel_ready": return qsTr("Туннель запущен, проверяем интернет…")
        case "dns": return qsTr("Проверяем DNS через VPN…")
        case "traffic": return qsTr("Проверяем передачу трафика…")
        case "fallback": return fallbackTo === "awg" || fallbackTo === "xray"
                                ? qsTr("%1 не передаёт трафик — пробуем %2…")
                                      .arg(protocolName(fallbackFrom)).arg(protocolName(fallbackTo))
                                : qsTr("Подбираем рабочий сервер…")
        case "verified": return qsTr("Защищено")
        case "unknown": return qsTr("Соединение не удалось полностью проверить")
        case "disconnecting": return qsTr("Отключаем защищённое соединение…")
        case "failed": return failureText(typedReason)
        case "idle": return typedReason.length > 0 ? failureText(typedReason) : qsTr("Отключено")
        default: return qsTr("Отключено")
        }
    }

    text: stageText()
    textFormat: Text.PlainText
    color: stage === "verified" ? Theme.color.connected
         : (stage === "failed" ? Theme.color.danger
         : (stage === "unknown" || stage === "fallback" ? Theme.color.warning
                                                           : Theme.color.text2))
    font.family: Theme.font.body
    font.pixelSize: Theme.font.bodyS
    font.weight: stage === "verified" ? Theme.font.wBold : Theme.font.wMedium
    horizontalAlignment: Text.AlignHCenter
    wrapMode: Text.Wrap
    Accessible.role: Accessible.StaticText
    Accessible.name: text
}
