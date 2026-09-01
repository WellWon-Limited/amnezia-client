#include "SubscriptionParser.h"

#include "NodeRotation.h" // AVPN (Task 10): isSupportedProtoNode — awg-контракт неприменим к чужим proto

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QRegularExpression>

namespace avpn {

// AVPN awg31-xray-v1: строковое поле xray_params — только строка (число/bool/null = отсутствует).
static QString xrayStr(const QJsonObject &o, const char *key)
{
    const QJsonValue v = o.value(QLatin1String(key));
    return v.isString() ? v.toString().trimmed() : QString();
}

bool SubscriptionParser::parseXrayParams(const QJsonObject &o, XrayParams &out, QString &why)
{
    XrayParams p;
    p.uuid = xrayStr(o, "uuid");
    p.publicKey = xrayStr(o, "public_key");
    p.shortId = xrayStr(o, "short_id");
    p.serverName = xrayStr(o, "server_name");
    p.fingerprint = xrayStr(o, "fingerprint").toLower();
    p.flow = xrayStr(o, "flow");
    p.network = xrayStr(o, "network").toLower();
    p.security = xrayStr(o, "security").toLower();

    // uuid — per-device credential VLESS: канонический 8-4-4-4-12 hex (xray-core принимает и
    // «строка → uuid v5», но нам нужен именно серверный UUID из TransportBinding).
    static const QRegularExpression uuidRe(
        QStringLiteral("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"));
    if (!uuidRe.match(p.uuid).hasMatch()) {
        why = QStringLiteral("xray_params.uuid is not a canonical UUID");
        return false;
    }
    // public_key — Reality x25519 (base64/base64url); в конфиг уходит как есть, но пробелы/мусор
    // = кривая выдача → отбросить, а не дать xray-core упасть на старте.
    static const QRegularExpression pubkeyRe(QStringLiteral("^[A-Za-z0-9+/_=-]{32,64}$"));
    if (!pubkeyRe.match(p.publicKey).hasMatch()) {
        why = QStringLiteral("xray_params.public_key is empty or malformed");
        return false;
    }
    // short_id — hex чётной длины 2..16 (Reality: до 8 байт).
    static const QRegularExpression shortIdRe(QStringLiteral("^(?:[0-9a-fA-F]{2}){1,8}$"));
    if (!shortIdRe.match(p.shortId).hasMatch()) {
        why = QStringLiteral("xray_params.short_id must be hex of even length 2..16");
        return false;
    }
    if (p.serverName.isEmpty()) {
        why = QStringLiteral("xray_params.server_name is empty");
        return false;
    }
    // fingerprint — allowlist uTLS xray-core; пусто с бэка → дефолт апстрима "chrome".
    static const QStringList fingerprints{
        QStringLiteral("chrome"), QStringLiteral("firefox"), QStringLiteral("safari"),
        QStringLiteral("ios"), QStringLiteral("android"), QStringLiteral("edge"),
        QStringLiteral("360"), QStringLiteral("qq"), QStringLiteral("random"),
        QStringLiteral("randomized")
    };
    if (p.fingerprint.isEmpty())
        p.fingerprint = QStringLiteral("chrome");
    if (!fingerprints.contains(p.fingerprint)) {
        why = QStringLiteral("xray_params.fingerprint '%1' is not allowed").arg(p.fingerprint);
        return false;
    }
    // flow — только Vision или пусто (без flow VLESS+Reality тоже валиден).
    if (!p.flow.isEmpty() && p.flow != QLatin1String("xtls-rprx-vision")) {
        why = QStringLiteral("xray_params.flow '%1' is not supported").arg(p.flow);
        return false;
    }
    // network — только TCP ("raw" = новое имя того же транспорта в xray-core; апстримный
    // xrayConfigurator пишет "tcp" — нормализуем к нему).
    if (p.network.isEmpty() || p.network == QLatin1String("raw"))
        p.network = QStringLiteral("tcp");
    if (p.network != QLatin1String("tcp")) {
        why = QStringLiteral("xray_params.network '%1' is not supported").arg(p.network);
        return false;
    }
    // security — только Reality (tls/none в этой волне не выдаются и не поддерживаются билдером).
    if (p.security.isEmpty())
        p.security = QStringLiteral("reality");
    if (p.security != QLatin1String("reality")) {
        why = QStringLiteral("xray_params.security '%1' is not supported").arg(p.security);
        return false;
    }
    out = p;
    why.clear();
    return true;
}

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
    // AVPN awg31-xray-v1: pool_revision (число; отсутствует/не число → 0 = «нет ревизии»).
    out.poolRevision = root.value("pool_revision").isDouble()
        ? static_cast<qint64>(root.value("pool_revision").toDouble())
        : 0;

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

        // AVPN awg31-xray-v1 (§2.2): локация/ранг транспорта. host_id/transport_rank — только числа
        // (строка/null → дефолт, НЕ 0: «ранг 0» ставил бы ноду выше всех по опечатке бэка).
        n.hostId = no.value("host_id").isDouble() ? no.value("host_id").toInt() : 0;
        n.location = no.value("location").toString();
        const bool isXray = n.proto == QLatin1String("xray");
        n.transportRank = no.value("transport_rank").isDouble()
            ? no.value("transport_rank").toInt()
            : (isXray ? kTransportRankXray : kTransportRankAwg);

        // xray-нода обязана нести валидные xray_params; иначе она непригодна для коннекта и в пул не
        // попадает — но ответ НЕ роняем (остальные ноды живут; инвариант волны §4.5 «незнакомый
        // proto/ключ не роняет ответ и не доезжает до NE»). awg-ноды этот блок не трогает.
        if (isXray) {
            XrayParams xp;
            QString why;
            if (!parseXrayParams(no.value("xray_params").toObject(), xp, why))
                continue;
            n.xray = xp;
        }
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
        // AVPN awg31-xray-v1: xray-контракт — endpoint host:port + валидные xray_params (парсер
        // гарантирует xray.has_value(); здесь — страховка для DTO, собранных мимо парсера).
        if (n.proto == QLatin1String("xray")) {
            if (n.endpoint.isEmpty() || !n.endpoint.contains(QLatin1Char(':')))
                issues << QStringLiteral("node %1: endpoint must be host:port").arg(id);
            if (!n.xray.has_value())
                issues << QStringLiteral("node %1: xray node without xray_params").arg(id);
            continue;
        }
        // AVPN (Task 10, proto-форвард): нода с неизвестным протоколом НЕ роняет
        // валидацию ответа и НЕ отбрасывается — awg-требования (endpoint host:port, pubkey, dns,
        // AWG-бандл) к ней неприменимы. Она остаётся в пуле для диагностики/будущей эскалации,
        // а из любого выбора её исключает isSupportedProtoNode (Selector/pick*/ротация/pin).
        if (!isSupportedProtoNode(n))
            continue;
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
