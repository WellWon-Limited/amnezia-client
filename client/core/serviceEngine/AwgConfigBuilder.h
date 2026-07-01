// AVPN serviceEngine — построитель конфига: наш DTO подписки → QJsonObject в форме, которую ест
// VpnConnection::connectToVpn (см. разведку: outer protocol + awg_config_data + dns/hostName).
// Ключи — из amnezia configKeys.h (захардкожены строками, чтобы билдер тестировался автономно;
// при сборке в форке сверить outer-ключ протокола с connectionController createConnectionConfiguration).
#pragma once

#include "dto/Subscription.h"
#include <QJsonObject>
#include <QString>

namespace avpn {

struct ClientKeys {
    QString privateKey;   // из Identity (Keychain), на бэкенд не уходит
    QString publicKey;    // = client_id
};

class AwgConfigBuilder {
public:
    // Полный QJsonObject для connectToVpn (proto=awg). address берётся из подписки (стабильный /32).
    // Всегда ОДИН пир full-tunnel; РФ-байпас — split-tunnel (AvpnEngineQml::applyRuBypassSplit), не пир.
    static QJsonObject build(const Subscription &sub, const SubscriptionNode &node, const ClientKeys &keys);

    // Внутренний awg_config_data (отдельно — удобно тестировать/переиспользовать).
    static QJsonObject buildInner(const Subscription &sub, const SubscriptionNode &node, const ClientKeys &keys);

    // Native wg-quick текст (ключ "config") в формате AmneziaWG. TODO(in-fork): сверить с шаблоном форка.
    static QString wgQuick(const Subscription &sub, const SubscriptionNode &node, const ClientKeys &keys);

    // host из "host:port".
    static QString host(const QString &endpoint);
    // port из "host:port" (0 если нет).
    static int port(const QString &endpoint);
};

} // namespace avpn
