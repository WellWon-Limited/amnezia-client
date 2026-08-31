#include "SubscriptionParser.h"

#include "NodeRotation.h" // AVPN (Task 10): isSupportedProtoNode — awg-контракт неприменим к чужим proto

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

    // AVPN AWG 3.0 (план awg3-migration §3 F7): 7 v3-ключей, имена — канон апстрима (configKeys.h).
    a.headerProtectionKey = o.value("HeaderProtectionKey").toString();
    a.contentPaddingAddition = o.value("ContentPaddingAddition").toString();
    a.rekeyAfterTime = o.value("RekeyAfterTime").toString();
    a.rekeyTimeout = o.value("RekeyTimeout").toString();
    a.rejectAfterTime = o.value("RejectAfterTime").toString();
    a.keepaliveTimeout = o.value("KeepaliveTimeout").toString();
    a.maxHandshakeAttempts = o.value("MaxHandshakeAttempts").toString();

    const auto optionalBool = [&o](const char *key) -> std::optional<bool> {
        const QJsonValue value = o.value(QLatin1String(key));
        if (value.isBool())
            return value.toBool();
        // AVPN AWG 3.1 transitional tolerance for older JSON emitters; DTO/build output is typed
        // and normalized to string 1/0 for native platform parsers.
        if (value.isString()) {
            const QString text = value.toString().trimmed().toLower();
            if (text == QLatin1String("1") || text == QLatin1String("true")
                || text == QLatin1String("on"))
                return true;
            if (text == QLatin1String("0") || text == QLatin1String("false")
                || text == QLatin1String("off"))
                return false;
        }
        return std::nullopt;
    };
    a.randomTrailers = optionalBool("RandomTrailers");
    a.disableCookies = optionalBool("DisableCookies");
    a.awg31ToggleEncodingValid =
        (!o.contains(QStringLiteral("RandomTrailers")) || a.randomTrailers.has_value())
        && (!o.contains(QStringLiteral("DisableCookies")) || a.disableCookies.has_value());

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
    out.graceUntil = root.value("grace_until").toString(); // AVPN: grace (expires_at + 24ч)

    const QJsonObject tr = root.value("traffic").toObject();
    out.trafficUsed = static_cast<qint64>(tr.value("used").toDouble());
    out.trafficLimit = static_cast<qint64>(tr.value("limit").toDouble());

    for (const QJsonValue &nv : root.value("nodes").toArray()) {
        const QJsonObject no = nv.toObject();
        SubscriptionNode n;
        n.nodeId = no.value("node_id").toString();
        n.region = no.value("region").toString();
        n.name = no.value("label").toString(no.value("name").toString()); // AVPN: label (фолбэк name)
        n.countryCode = no.value("country_code").toString(); // AVPN: ISO-3166 → флаг-эмодзи
        n.endpoint = no.value("endpoint").toString();
        n.serverPubkey = no.value("server_pubkey").toString();
        n.awg = parseAwg(no.value("awg_params").toObject());
        n.proto = no.value("proto").toString(QStringLiteral("awg"));
        n.weight = no.value("weight").toDouble(1.0);
        n.manualOnly = no.value("manual_only").toBool(false); // AVPN: только ручной pin (§14.3)

        const QJsonObject h = no.value("health").toObject();
        for (auto it = h.begin(); it != h.end(); ++it)
            n.health.insert(it.key(), it.value().toDouble());

        for (const QJsonValue &a : no.value("allowed_ips").toArray())
            n.allowedIps << a.toString();
        for (const QJsonValue &d : no.value("dns").toArray())
            n.dns << d.toString();

        n.mtu = no.value("mtu").toInt();
        // AVPN (план awg3 §3 F5-K): кламп <=0 → 25. Апстрим-фолбэки keepalive удалены (AWG3-волна),
        // явный 0 из подписки или смена типа поля дали бы «keepalive выключен» молча.
        n.persistentKeepalive = no.value("persistent_keepalive").toInt(25);
        if (n.persistentKeepalive <= 0)
            n.persistentKeepalive = 25;
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
        // AVPN (Task 10, proto-форвард): нода с неизвестным протоколом (xray, ...) НЕ роняет
        // валидацию ответа и НЕ отбрасывается — awg-требования (endpoint host:port, pubkey, dns,
        // AWG-бандл) к ней неприменимы. Она остаётся в пуле для диагностики/будущей эскалации,
        // а из любого выбора её исключает isSupportedProtoNode (Selector/pick*/ротация/pin).
        if (!isSupportedProtoNode(n))
            continue;
        const QString id = n.nodeId.isEmpty() ? QStringLiteral("<no id>") : n.nodeId;
        if (n.endpoint.isEmpty() || !n.endpoint.contains(QLatin1Char(':')))
            issues << QStringLiteral("node %1: endpoint must be host:port").arg(id);
        if (n.serverPubkey.isEmpty())
            issues << QStringLiteral("node %1: missing server_pubkey").arg(id);
        if (n.dns.isEmpty())
            issues << QStringLiteral("node %1: dns is required (>=1)").arg(id);
        if (n.proto == QLatin1String("awg") && !n.awg.hasFullBundle())
            issues << QStringLiteral("node %1: incomplete AWG bundle (Jc..H4 must all be present)").arg(id);
        if (n.awg.randomTrailers.has_value() != n.awg.disableCookies.has_value())
            issues << QStringLiteral("node %1: incomplete AWG 3.1 toggle bundle").arg(id);
        if (!n.awg.awg31ToggleEncodingValid)
            issues << QStringLiteral("node %1: invalid AWG 3.1 toggle value").arg(id);
    }
    return issues;
}

} // namespace avpn
