// AVPN serviceEngine — построитель конфига: наш DTO подписки → QJsonObject в форме, которую ест
// VpnConnection::connectToVpn (см. разведку: outer protocol + awg_config_data + dns/hostName).
// Ключи — из amnezia configKeys.h (захардкожены строками, чтобы билдер тестировался автономно;
// при сборке в форке сверить outer-ключ протокола с connectionController createConnectionConfiguration).
#pragma once

#include "dto/Subscription.h"
#include <QJsonObject>
#include <QSet>
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

    // AVPN bench v5: санитизированный дамп конфига для отчёта бенча (tunnel.config). Только
    // parity-поля (mtu/dns/port/keepalive/awg-параметры/факты allowed_ips|psk) — НИ ключей,
    // НИ endpoint-хоста, НИ client_ip: отчёт пересылается наружу. mtu/dns — ЭФФЕКТИВНЫЕ
    // (с подставленными дефолтами) — ровно то, что реально уйдёт в туннель.
    static QJsonObject reportSummary(const Subscription &sub, const SubscriptionNode &node);

    // host из "host:port".
    static QString host(const QString &endpoint);
    // port из "host:port" (0 если нет).
    static int port(const QString &endpoint);

    // AVPN awg31-xray-v1 (§2.3, инвариант волны «незнакомый ключ не доезжает до NE»): фильтр
    // wg-quick текста — строки `Key = value`, чей ключ (без регистра) НЕ в allowlist, вырезаются;
    // известные ключи, заголовки секций, комментарии и пустые строки сохраняют исходный порядок.
    // allowlist — ключи в нижнем регистре. Применять ТОЛЬКО под гейтом Apple (awg-apple 3.1.4
    // TunnelConfiguration+WgQuickConfig.swift бросает interfaceHasUnrecognizedKey/
    // peerHasUnrecognizedKey; awg-go/android/windows мягче) — точку вызова добавляет этап интеграции.
    static QString stripUnknownWgQuickKeys(const QString &nativeConfText, const QSet<QString> &allowlist);

    // Ключи wg-quick, известные awg-apple 3.1.4 (interfaceSectionKeys ∪ peerSectionKeys того же
    // файла, нижний регистр). Обновлять вместе с бампом рецепта recipes/awg-apple.
    static const QSet<QString> &awgAppleWgQuickKeys();
};

} // namespace avpn
