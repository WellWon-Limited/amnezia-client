#include "AwgConfigBuilder.h"

#include "../utils/constants/protocolConstants.h"

#include <QJsonArray>

namespace avpn {

// AVPN parity: наш service-путь (VpnConnectionTunnelControl::invokeConnect → connectToVpn напрямую)
// ОБХОДИТ ConnectionController::createConnectionConfiguration, где upstream подставляет дефолты.
// Поэтому дефолты — обязанность билдера: без dns1 iOS WGConfig.swift (dns1/dns2 non-optional String)
// не декодится вовсе (туннель молча не поднимается), без mtu демон берёт 1420 (daemon.cpp) вместо
// awg-дефолта 1376 desktop / 1280 mobile. Значения = upstream (secureAppSettingsRepository 1.1.1.1/
// 1.0.0.1; protocols::awg::defaultMtu).
static QStringList dnsOrDefault(const QStringList &dns)
{
    return dns.isEmpty() ? QStringList{QStringLiteral("1.1.1.1"), QStringLiteral("1.0.0.1")} : dns;
}

static QString mtuOrDefault(int mtu)
{
    return mtu > 0 ? QString::number(mtu) : QLatin1String(amnezia::protocols::awg::defaultMtu);
}

QString AwgConfigBuilder::host(const QString &endpoint)
{
    const int i = endpoint.lastIndexOf(QLatin1Char(':'));
    return i > 0 ? endpoint.left(i) : endpoint;
}

int AwgConfigBuilder::port(const QString &endpoint)
{
    const int i = endpoint.lastIndexOf(QLatin1Char(':'));
    return i > 0 ? endpoint.mid(i + 1).toInt() : 0;
}

// AVPN: [Peer]-блок для wg-quick. Обфускация не здесь — она уровня [Interface]. У нас всегда ОДИН
// пир full-tunnel (allowedIps пустой => 0.0.0.0/0,::/0); РФ-байпас идёт split-tunnel'ом (excludeRoutes),
// а не отдельным пиром (см. AvpnEngineQml::applyRuBypassSplit).
static void appendPeerBlock(QStringList &l, const SubscriptionNode &p)
{
    l << QString();
    l << QStringLiteral("[Peer]");
    l << QStringLiteral("PublicKey = %1").arg(p.serverPubkey);
    if (!p.presharedKey.isEmpty())
        l << QStringLiteral("PresharedKey = %1").arg(p.presharedKey);
    const QStringList aips = p.allowedIps.isEmpty()
        ? QStringList{QStringLiteral("0.0.0.0/0"), QStringLiteral("::/0")}
        : p.allowedIps;
    l << QStringLiteral("AllowedIPs = %1").arg(aips.join(QStringLiteral(", ")));
    l << QStringLiteral("Endpoint = %1").arg(p.endpoint);
    l << QStringLiteral("PersistentKeepalive = %1").arg(p.persistentKeepalive);
}

QString AwgConfigBuilder::wgQuick(const Subscription &sub, const SubscriptionNode &node, const ClientKeys &keys)
{
    QStringList l;
    l << QStringLiteral("[Interface]");
    l << QStringLiteral("PrivateKey = %1").arg(keys.privateKey);
    if (!sub.address.isEmpty())
        l << QStringLiteral("Address = %1").arg(sub.address.join(QStringLiteral(", ")));
    l << QStringLiteral("DNS = %1").arg(dnsOrDefault(node.dns).join(QStringLiteral(", ")));
    l << QStringLiteral("MTU = %1").arg(mtuOrDefault(node.mtu));
    // AmneziaWG-обфускация (бандл обязателен целиком)
    const AwgParams &a = node.awg;
    l << QStringLiteral("Jc = %1").arg(a.Jc);
    l << QStringLiteral("Jmin = %1").arg(a.Jmin);
    l << QStringLiteral("Jmax = %1").arg(a.Jmax);
    l << QStringLiteral("S1 = %1").arg(a.S1);
    l << QStringLiteral("S2 = %1").arg(a.S2);
    if (a.S3) l << QStringLiteral("S3 = %1").arg(*a.S3);
    if (a.S4) l << QStringLiteral("S4 = %1").arg(*a.S4);
    l << QStringLiteral("H1 = %1").arg(a.H1);
    l << QStringLiteral("H2 = %1").arg(a.H2);
    l << QStringLiteral("H3 = %1").arg(a.H3);
    l << QStringLiteral("H4 = %1").arg(a.H4);
    if (!a.I1.isEmpty()) l << QStringLiteral("I1 = %1").arg(a.I1);
    if (!a.I2.isEmpty()) l << QStringLiteral("I2 = %1").arg(a.I2);
    if (!a.I3.isEmpty()) l << QStringLiteral("I3 = %1").arg(a.I3);
    if (!a.I4.isEmpty()) l << QStringLiteral("I4 = %1").arg(a.I4);
    if (!a.I5.isEmpty()) l << QStringLiteral("I5 = %1").arg(a.I5);

    appendPeerBlock(l, node);                 // единственный (загран) пир — full-tunnel
    return l.join(QLatin1Char('\n')) + QLatin1Char('\n');
}

QJsonObject AwgConfigBuilder::reportSummary(const Subscription &sub, const SubscriptionNode &node)
{
    Q_UNUSED(sub) // sub.address = client_ip — в отчёт НЕ пишем (PII); параметр оставлен под будущие факты
    QJsonObject o;
    o.insert(QStringLiteral("proto"), node.proto);
    o.insert(QStringLiteral("mtu"), mtuOrDefault(node.mtu).toInt());
    QJsonArray dns;
    for (const QString &d : dnsOrDefault(node.dns))
        dns.append(d);
    o.insert(QStringLiteral("dns"), dns);
    o.insert(QStringLiteral("port"), port(node.endpoint));
    o.insert(QStringLiteral("keepalive"), node.persistentKeepalive);
    o.insert(QStringLiteral("has_psk"), !node.presharedKey.isEmpty());
    o.insert(QStringLiteral("allowed_ips"),
             node.allowedIps.isEmpty() ? 2 : int(node.allowedIps.size()));
    const AwgParams &a = node.awg;
    QJsonObject awg;
    awg.insert(QStringLiteral("jc"), a.Jc);
    awg.insert(QStringLiteral("jmin"), a.Jmin);
    awg.insert(QStringLiteral("jmax"), a.Jmax);
    awg.insert(QStringLiteral("s1"), a.S1);
    awg.insert(QStringLiteral("s2"), a.S2);
    if (a.S3) awg.insert(QStringLiteral("s3"), *a.S3);
    if (a.S4) awg.insert(QStringLiteral("s4"), *a.S4); // S4≠0 = класс blackhole-бага awg-go 0.2.16
    awg.insert(QStringLiteral("h1"), a.H1);
    awg.insert(QStringLiteral("h2"), a.H2);
    awg.insert(QStringLiteral("h3"), a.H3);
    awg.insert(QStringLiteral("h4"), a.H4);
    // I-пакеты: только факт+размер (контент — серверная обфускация, в отчёте не нужен)
    const int iLens[] = { int(a.I1.size()), int(a.I2.size()), int(a.I3.size()),
                          int(a.I4.size()), int(a.I5.size()) };
    QJsonArray iPkts;
    for (int len : iLens)
        if (len > 0)
            iPkts.append(len);
    if (!iPkts.isEmpty())
        awg.insert(QStringLiteral("i_pkt_lens"), iPkts);
    o.insert(QStringLiteral("awg"), awg);
    return o;
}

QJsonObject AwgConfigBuilder::buildInner(const Subscription &sub, const SubscriptionNode &node, const ClientKeys &keys)
{
    QJsonObject o;
    // ключи — configKeys.h
    o.insert(QStringLiteral("client_ip"), sub.address.value(0));
    o.insert(QStringLiteral("client_priv_key"), keys.privateKey);
    o.insert(QStringLiteral("client_pub_key"), keys.publicKey);
    o.insert(QStringLiteral("client_id"), keys.publicKey);
    o.insert(QStringLiteral("server_pub_key"), node.serverPubkey);
    if (!node.presharedKey.isEmpty())
        o.insert(QStringLiteral("psk_key"), node.presharedKey);
    o.insert(QStringLiteral("hostName"), host(node.endpoint));
    o.insert(QStringLiteral("port"), port(node.endpoint));

    QJsonArray aips;
    const QStringList allowed = node.allowedIps.isEmpty()
        ? QStringList{QStringLiteral("0.0.0.0/0"), QStringLiteral("::/0")}
        : node.allowedIps;
    for (const QString &s : allowed)
        aips.append(s);
    o.insert(QStringLiteral("allowed_ips"), aips);

    o.insert(QStringLiteral("persistent_keep_alive"), QString::number(node.persistentKeepalive));
    o.insert(QStringLiteral("mtu"), mtuOrDefault(node.mtu)); // всегда: демон без mtu берёт 1420 (≠ awg-дефолт)

    // AmneziaWG-параметры. AVPN: ТОЛЬКО строки — форк (awgProtocolConfig.h) и iOS WGConfig.swift
    // объявляют Jc..H4 как QString/String?. Если слать числами, Swift JSONDecoder падает typeMismatch
    // → весь WGConfig не декодится → NE не поднимает туннель (баг «AWG в Настройках, но 0 хендшейков»).
    const AwgParams &a = node.awg;
    o.insert(QStringLiteral("Jc"), QString::number(a.Jc));
    o.insert(QStringLiteral("Jmin"), QString::number(a.Jmin));
    o.insert(QStringLiteral("Jmax"), QString::number(a.Jmax));
    o.insert(QStringLiteral("S1"), QString::number(a.S1));
    o.insert(QStringLiteral("S2"), QString::number(a.S2));
    if (a.S3) o.insert(QStringLiteral("S3"), QString::number(*a.S3));
    if (a.S4) o.insert(QStringLiteral("S4"), QString::number(*a.S4));
    o.insert(QStringLiteral("H1"), QString::number(a.H1));
    o.insert(QStringLiteral("H2"), QString::number(a.H2));
    o.insert(QStringLiteral("H3"), QString::number(a.H3));
    o.insert(QStringLiteral("H4"), QString::number(a.H4));
    if (!a.I1.isEmpty()) o.insert(QStringLiteral("I1"), a.I1);
    if (!a.I2.isEmpty()) o.insert(QStringLiteral("I2"), a.I2);
    if (!a.I3.isEmpty()) o.insert(QStringLiteral("I3"), a.I3);
    if (!a.I4.isEmpty()) o.insert(QStringLiteral("I4"), a.I4);
    if (!a.I5.isEmpty()) o.insert(QStringLiteral("I5"), a.I5);

    o.insert(QStringLiteral("isObfuscationEnabled"), true); // AWG-ноды: иначе Android тихо обычный WG (§6.4)
    o.insert(QStringLiteral("config"), wgQuick(sub, node, keys));
    return o;
}

QJsonObject AwgConfigBuilder::build(const Subscription &sub, const SubscriptionNode &node, const ClientKeys &keys)
{
    QJsonObject root;
    root.insert(QStringLiteral("protocol"), QStringLiteral("awg")); // configKey::vpnProto
    root.insert(QStringLiteral("awg_config_data"), buildInner(sub, node, keys));
    root.insert(QStringLiteral("hostName"), host(node.endpoint));
    const QStringList dns = dnsOrDefault(node.dns); // iOS: dns1 И dns2 обязательны (non-optional в WGConfig.swift)
    root.insert(QStringLiteral("dns1"), dns.value(0));
    root.insert(QStringLiteral("dns2"), dns.value(dns.size() > 1 ? 1 : 0));
    // AVPN: iOS setupAwg читает splitTunnelType из КОРНЯ (m_rawConfig), а WGConfig.swift объявляет его
    // Int (non-optional) → без него декод падает. 0 = full-tunnel (совпадает с allowed_ips 0.0.0.0/0).
    root.insert(QStringLiteral("splitTunnelType"), 0);
    root.insert(QStringLiteral("config_version"), 0);
    return root;
}

} // namespace avpn
