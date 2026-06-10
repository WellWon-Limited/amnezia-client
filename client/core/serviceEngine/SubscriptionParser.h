// AVPN serviceEngine — парсинг подписки (Qt JSON) + валидация контрактных инвариантов (§6.4 плана).
#pragma once

#include "dto/Subscription.h"
#include <QByteArray>
#include <QString>
#include <QStringList>

namespace avpn {

class SubscriptionParser {
public:
    // Парсит тело GET /v1/subscription. true + out заполнен; иначе false + error.
    static bool parse(const QByteArray &json, Subscription &out, QString &error);

    // Не-фатальные проблемы конфигов (пустой список = всё ок). Кодирует грабли §6.4:
    // dns>=1, endpoint = host:port, полный AWG-бандл, address не пуст.
    static QStringList validate(const Subscription &sub);
};

} // namespace avpn
