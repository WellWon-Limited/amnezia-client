#include "SubscriptionParser.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

namespace avpn {

static AwgParams parseAwg(const QJsonObject &o)
{
    AwgParams a;
    a.Jc = o.value("Jc").toInt();
    a.Jmin = o.value("Jmin").toInt();
    a.Jmax = o.value("Jmax").toInt();
    a.S1 = o.value("S1").toInt();
    a.S2 = o.value("S2").toInt();
    if (o.contains("S3") && !o.value("S3").isNull()) a.S3 = o.value("S3").toInt();
    if (o.contains("S4") && !o.value("S4").isNull()) a.S4 = o.value("S4").toInt();
    a.H1 = o.value("H1").toInt();
    a.H2 = o.value("H2").toInt();
    a.H3 = o.value("H3").toInt();
    a.H4 = o.value("H4").toInt();
    a.I1 = o.value("I1").toString();
    a.I2 = o.value("I2").toString();
    a.I3 = o.value("I3").toString();
    a.I4 = o.value("I4").toString();
    a.I5 = o.value("I5").toString();
    return a;
}

bool SubscriptionParser::parse(const QByteArray &json, Subscription &out, QString &error)
{
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
    if (pe.error != QJsonParseError::NoError) {
        error = QStringLiteral("JSON parse error: %1").arg(pe.errorString());
        return false;
    }
    if (!doc.isObject()) {
        error = QStringLiteral("subscription root is not a JSON object");
        return false;
    }
    const QJsonObject root = doc.object();

    out = Subscription{};
    out.version = root.value("version").toInt();
    if (out.version == 0) {
        error = QStringLiteral("missing/invalid 'version'");
        return false;
    }

    for (const QJsonValue &v : root.value("address").toArray())
        out.address << v.toString();

    out.status = (root.value("status").toString(QStringLiteral("active")) == QLatin1String("degraded"))
                     ? SubStatus::Degraded
                     : SubStatus::Active;
    out.expiresAt = root.value("expires_at").toString();

    const QJsonObject tr = root.value("traffic").toObject();
    out.trafficUsed = static_cast<qint64>(tr.value("used").toDouble());
    out.trafficLimit = static_cast<qint64>(tr.value("limit").toDouble());

    for (const QJsonValue &nv : root.value("nodes").toArray()) {
        const QJsonObject no = nv.toObject();
        SubscriptionNode n;
        n.nodeId = no.value("node_id").toString();
        n.region = no.value("region").toString();
        n.endpoint = no.value("endpoint").toString();
        n.serverPubkey = no.value("server_pubkey").toString();
        n.awg = parseAwg(no.value("awg_params").toObject());
        n.proto = no.value("proto").toString(QStringLiteral("awg"));
        n.weight = no.value("weight").toDouble(1.0);

        const QJsonObject h = no.value("health").toObject();
        for (auto it = h.begin(); it != h.end(); ++it)
            n.health.insert(it.key(), it.value().toDouble());

        for (const QJsonValue &a : no.value("allowed_ips").toArray())
            n.allowedIps << a.toString();
        for (const QJsonValue &d : no.value("dns").toArray())
            n.dns << d.toString();

        n.mtu = no.value("mtu").toInt();
        n.persistentKeepalive = no.value("persistent_keepalive").toInt(25);
        n.presharedKey = no.value("preshared_key").toString();
        out.nodes << n;
    }
    return true;
}

QStringList SubscriptionParser::validate(const Subscription &sub)
{
    QStringList issues;
    if (sub.address.isEmpty())
        issues << QStringLiteral("address (stable /32) is empty");

    // Пустой пул легитимен только при degraded (мягкий лимит/истечение).
    if (sub.nodes.isEmpty() && sub.status == SubStatus::Active)
        issues << QStringLiteral("active subscription has no nodes");

    for (const SubscriptionNode &n : sub.nodes) {
        const QString id = n.nodeId.isEmpty() ? QStringLiteral("<no id>") : n.nodeId;
        if (n.endpoint.isEmpty() || !n.endpoint.contains(QLatin1Char(':')))
            issues << QStringLiteral("node %1: endpoint must be host:port").arg(id);
        if (n.serverPubkey.isEmpty())
            issues << QStringLiteral("node %1: missing server_pubkey").arg(id);
        if (n.dns.isEmpty())
            issues << QStringLiteral("node %1: dns is required (>=1)").arg(id);
        if (n.proto == QLatin1String("awg") && !n.awg.hasFullBundle())
            issues << QStringLiteral("node %1: incomplete AWG bundle (Jc..H4 must all be present)").arg(id);
    }
    return issues;
}

} // namespace avpn
