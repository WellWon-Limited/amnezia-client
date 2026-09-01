#include "XrayConfigBuilder.h"

#include "../utils/constants/protocolConstants.h"

#include <QJsonArray>
#include <QJsonDocument>

namespace avpn {

// AVPN parity с AwgConfigBuilder: service-путь обходит ConnectionController::createConnectionConfiguration,
// дефолты — обязанность билдера. iOS XrayConfig.swift терпит отсутствие dns1/dns2 (Optional), но NE
// тогда ставит 1.1.1.1 сам; десктопный XrayProtocol читает dns1/dns2 из корня как строки — держим
// одинаково с AWG (upstream secureAppSettingsRepository 1.1.1.1/1.0.0.1).
static QStringList dnsOrDefault(const QStringList &dns)
{
    return dns.isEmpty() ? QStringList{ QStringLiteral("1.1.1.1"), QStringLiteral("1.0.0.1") } : dns;
}

static int portOrDefault(const QString &endpoint)
{
    const int p = AwgConfigBuilder::port(endpoint);
    return p > 0 ? p : QString::fromLatin1(amnezia::protocols::xray::defaultPort).toInt();
}

QJsonObject XrayConfigBuilder::coreConfig(const SubscriptionNode &node)
{
    namespace px = amnezia::protocols::xray;
    if (!node.xray.has_value())
        return {};
    const XrayParams &x = *node.xray;

    // users[0] — per-device VLESS credential. flow — только при непустоте (паттерн апстрима).
    QJsonObject user;
    user.insert(QLatin1String(px::id), x.uuid);
    user.insert(QLatin1String(px::encryption), QStringLiteral("none"));
    if (!x.flow.isEmpty())
        user.insert(QLatin1String(px::flow), x.flow);

    QJsonObject vnextEntry;
    vnextEntry.insert(QLatin1String(px::address), AwgConfigBuilder::host(node.endpoint));
    vnextEntry.insert(QLatin1String(px::port), portOrDefault(node.endpoint));
    vnextEntry.insert(QLatin1String(px::users), QJsonArray{ user });

    QJsonObject outboundSettings;
    outboundSettings.insert(QLatin1String(px::vnext), QJsonArray{ vnextEntry });

    // streamSettings — Reality поверх TCP (парсер уже нормализовал network/security/fingerprint).
    QJsonObject reality;
    reality.insert(QLatin1String(px::fingerprint), x.fingerprint);
    reality.insert(QLatin1String(px::serverName), x.serverName);
    reality.insert(QLatin1String(px::publicKey), x.publicKey);
    reality.insert(QLatin1String(px::shortId), x.shortId);
    reality.insert(QLatin1String(px::spiderX), QString());

    QJsonObject stream;
    stream.insert(QLatin1String(px::network), x.network);
    stream.insert(QLatin1String(px::security), x.security);
    stream.insert(QLatin1String(px::realitySettings), reality);

    QJsonObject outbound;
    outbound.insert(QStringLiteral("protocol"), QStringLiteral("vless"));
    outbound.insert(QLatin1String(px::settings), outboundSettings);
    outbound.insert(QLatin1String(px::streamSettings), stream);

    // inbound socks на loopback: десктоп tun2socks / iOS hev-socks5 / Android ходят сюда; логин-пароль
    // и фактический порт (iOS acquireFreeLocalPort) подставляет EnsureInboundAuth апстрима.
    QJsonObject inbound;
    inbound.insert(QStringLiteral("listen"), QString::fromLatin1(px::defaultLocalListenAddr));
    inbound.insert(QLatin1String(px::port), QString::fromLatin1(px::defaultLocalProxyPort).toInt());
    inbound.insert(QStringLiteral("protocol"), QStringLiteral("socks"));
    inbound.insert(QLatin1String(px::settings), QJsonObject{ { QStringLiteral("udp"), true } });

    QJsonObject core;
    core.insert(QStringLiteral("log"),
                QJsonObject{ { QStringLiteral("loglevel"), QStringLiteral("error") } });
    core.insert(QLatin1String(px::inbounds), QJsonArray{ inbound });
    core.insert(QLatin1String(px::outbounds), QJsonArray{ outbound });
    return core;
}

QString XrayConfigBuilder::coreConfigText(const SubscriptionNode &node)
{
    const QJsonObject core = coreConfig(node);
    if (core.isEmpty())
        return {};
    return QString::fromUtf8(QJsonDocument(core).toJson(QJsonDocument::Compact));
}

QJsonObject XrayConfigBuilder::buildInner(const Subscription &sub, const SubscriptionNode &node,
                                          const ClientKeys &keys)
{
    Q_UNUSED(sub)
    Q_UNUSED(keys)
    const QString text = coreConfigText(node);
    if (text.isEmpty())
        return {};
    QJsonObject o;
    // configKey::config — единственное, что читают XrayProtocol/setupXray/Xray.kt из обёртки.
    o.insert(QStringLiteral("config"), text);
    o.insert(QStringLiteral("hostName"), AwgConfigBuilder::host(node.endpoint));
    o.insert(QStringLiteral("port"), portOrDefault(node.endpoint));
    return o;
}

QJsonObject XrayConfigBuilder::build(const Subscription &sub, const SubscriptionNode &node,
                                     const ClientKeys &keys)
{
    const QJsonObject inner = buildInner(sub, node, keys);
    if (inner.isEmpty())
        return {};
    QJsonObject root;
    root.insert(QStringLiteral("protocol"), QStringLiteral("xray")); // configKey::vpnProto
    root.insert(QStringLiteral("xray_config_data"), inner);          // key_proto_config_data(Proto::Xray)
    root.insert(QStringLiteral("hostName"), AwgConfigBuilder::host(node.endpoint)); // m_remoteAddress
    const QStringList dns = dnsOrDefault(node.dns);
    root.insert(QStringLiteral("dns1"), dns.value(0));
    root.insert(QStringLiteral("dns2"), dns.value(dns.size() > 1 ? 1 : 0));
    // Как у AwgConfigBuilder: дефолт full-tunnel; appendSplitTunnelingConfig в connectToVpn перепишет
    // routeMode из репозитория (RU-байпас сеет адаптер). iOS setupXray читает splitTunnelType из корня.
    root.insert(QStringLiteral("splitTunnelType"), 0);
    root.insert(QStringLiteral("config_version"), 0);
    return root;
}

QJsonObject XrayConfigBuilder::reportSummary(const Subscription &sub, const SubscriptionNode &node)
{
    Q_UNUSED(sub) // sub.address = client_ip — PII, в отчёт не пишем
    QJsonObject o;
    o.insert(QStringLiteral("proto"), node.proto);
    o.insert(QStringLiteral("port"), portOrDefault(node.endpoint));
    QJsonArray dns;
    for (const QString &d : dnsOrDefault(node.dns))
        dns.append(d);
    o.insert(QStringLiteral("dns"), dns);
    o.insert(QStringLiteral("host_id"), node.hostId);
    o.insert(QStringLiteral("transport_rank"), node.transportRank);
    o.insert(QStringLiteral("has_xray_params"), node.xray.has_value());
    if (node.xray) {
        const XrayParams &x = *node.xray;
        // uuid (credential) и publicKey (идентифицирует ноду) — НЕ пишем; short_id — только длина.
        o.insert(QStringLiteral("network"), x.network);
        o.insert(QStringLiteral("security"), x.security);
        o.insert(QStringLiteral("flow"), x.flow);
        o.insert(QStringLiteral("fingerprint"), x.fingerprint);
        o.insert(QStringLiteral("server_name"), x.serverName);
        o.insert(QStringLiteral("short_id_len"), int(x.shortId.size()));
    }
    return o;
}

} // namespace avpn
