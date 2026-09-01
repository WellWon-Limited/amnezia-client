// AVPN serviceEngine — парсинг подписки (Qt JSON) + валидация контрактных инвариантов (§6.4 плана).
#pragma once

#include "dto/Subscription.h"
#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QStringList>

namespace avpn {

class SubscriptionParser {
public:
    // Парсит тело GET /v1/subscription. true + out заполнен; иначе false + error.
    // AVPN awg31-xray-v1: xray-нода без ВАЛИДНЫХ xray_params отбрасывается молча (ответ не роняется,
    // awg-ноды парсятся как раньше — регресс-гейт tests/build_xray_config.sh).
    static bool parse(const QByteArray &json, Subscription &out, QString &error);

    // AVPN awg31-xray-v1 (§2.2): разбор + нормализация + валидация nodes[].xray_params.
    // true → out заполнен нормализованными значениями (fingerprint пусто → chrome, network пусто/raw
    // → tcp, security пусто → reality); false → why = причина (uuid/short_id/…). Fail-closed:
    // любой неподдерживаемый transport/security/flow/fingerprint = невалидно (до NE не доедет).
    static bool parseXrayParams(const QJsonObject &o, XrayParams &out, QString &why);

    // Не-фатальные проблемы конфигов (пустой список = всё ок). Кодирует грабли §6.4:
    // dns>=1, endpoint = host:port, полный AWG-бандл, address не пуст.
    static QStringList validate(const Subscription &sub);
};

} // namespace avpn
