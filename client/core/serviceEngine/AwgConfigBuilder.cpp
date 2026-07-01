#include "AwgConfigBuilder.h"

#include <QJsonArray>

namespace avpn {

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
    if (!node.dns.isEmpty())
        l << QStringLiteral("DNS = %1").arg(node.dns.join(QStringLiteral(", ")));
    if (node.mtu > 0)
        l << QStringLiteral("MTU = %1").arg(node.mtu);
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
    if (node.mtu > 0)
        o.insert(QStringLiteral("mtu"), QString::number(node.mtu));

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
    if (node.dns.size() > 0)
        root.insert(QStringLiteral("dns1"), node.dns.value(0));
    root.insert(QStringLiteral("dns2"), node.dns.value(node.dns.size() > 1 ? 1 : 0)); // iOS: dns2 обязателен
    // AVPN: iOS setupAwg читает splitTunnelType из КОРНЯ (m_rawConfig), а WGConfig.swift объявляет его
    // Int (non-optional) → без него декод падает. 0 = full-tunnel (совпадает с allowed_ips 0.0.0.0/0).
    root.insert(QStringLiteral("splitTunnelType"), 0);
    root.insert(QStringLiteral("config_version"), 0);
    return root;
}

} // namespace avpn
