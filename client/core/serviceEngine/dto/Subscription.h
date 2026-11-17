// AVPN serviceEngine — DTO подписки. Соответствует контракту api/openapi.yaml (Subscription/SubscriptionNode/AwgParams).
// Overlay-код: НЕ часть апстрима Amnezia. См. core/serviceEngine/README.md.
#pragma once

#include <QString>
#include <QStringList>
#include <QList>
#include <QHash>
#include <optional>

namespace avpn {

// AmneziaWG-параметры обфускации. Бандл Jc..H4 — обязателен целиком (iOS включает AWG только при всех 9).
struct AwgParams {
    int Jc = 0, Jmin = 0, Jmax = 0;
    int S1 = 0, S2 = 0;
    std::optional<int> S3, S4;          // опц.
    int H1 = 0, H2 = 0, H3 = 0, H4 = 0;
    QString I1, I2, I3, I4, I5;          // опц. hex-пакеты (пусто => не слать)

    // AVPN AWG 3.0 (план awg3-migration §3 F7): 7 ключей v3, все строки (канон — диапазоны "a-b",
    // HeaderProtectionKey — base64 32 байта). Пусто => не слать (паттерн апстрима «по непустоте»).
    // Бандл v3-ноды — НАДМНОЖЕСТВО: 2.0-набор выше остаётся обязательным (§2.2 плана).
    QString headerProtectionKey;
    QString contentPaddingAddition;
    QString rekeyAfterTime;
    QString rekeyTimeout;
    QString rejectAfterTime;
    QString keepaliveTimeout;
    QString maxHandshakeAttempts;

    // AVPN Tribe AWG 3.1: exact typed quick-config keys. Presence is distinct from false so a v1
    // fallback response without 3.1 fields remains byte-compatible. The native adapters turn
    // these into UAPI random_trailers/disable_cookies=1|0; they are never routed through extra.
    std::optional<bool> randomTrailers;
    std::optional<bool> disableCookies;
    bool awg31ToggleEncodingValid = true;

    bool hasFullBundle() const { return Jc && Jmin && Jmax && S1 && S2 && H1 && H2 && H3 && H4; }

    // AVPN AWG 3.0: версия протокола обфускации по факту наличия ключей (зеркало апстримного
    // awgVersionOf) — для метки «Amnezia vN» в пикере серверов. Любой v3-ключ ⇒ "3"; иначе
    // S3/S4/I1 (наш флот) ⇒ "2"; иначе "1". Возвращаем мажор строкой (для UI "v"+major).
    QString protocolMajor() const
    {
        if (randomTrailers.has_value() || disableCookies.has_value())
            return QStringLiteral("3.1");
        if (!headerProtectionKey.isEmpty() || !contentPaddingAddition.isEmpty()
            || !rekeyAfterTime.isEmpty() || !rekeyTimeout.isEmpty() || !rejectAfterTime.isEmpty()
            || !keepaliveTimeout.isEmpty() || !maxHandshakeAttempts.isEmpty())
            return QStringLiteral("3");
        if (S3.has_value() || S4.has_value() || !I1.isEmpty())
            return QStringLiteral("2");
        return QStringLiteral("1");
    }
};

// AVPN Xray (волна awg31-xray-v1, спека 2026-09-01 §2.2): VLESS + Reality + xtls-rprx-vision по
// схеме апстримного xrayConfigurator (vnext[]/realitySettings). Заполняется ТОЛЬКО парсером после
// валидации (SubscriptionParser::parseXrayParams): uuid = per-device credential (секрет: в логи/
// отчёты не писать), publicKey/shortId/serverName — Reality-параметры ноды, fingerprint из
// allowlist xray-core (пусто с бэка → "chrome"), flow "xtls-rprx-vision" | "", network "tcp",
// security "reality". Другие transport/security в этой волне не поддерживаются — нода отбрасывается.
struct XrayParams {
    QString uuid;
    QString publicKey;
    QString shortId;
    QString serverName;
    QString fingerprint = QStringLiteral("chrome");
    QString flow;
    QString network = QStringLiteral("tcp");
    QString security = QStringLiteral("reality");
};

// AVPN: дефолтный серверный ранг транспорта внутри локации (transport_rank, меньше = раньше):
// AWG выше Xray — решение владельца 2026-09-01 «по умолчанию Amnezia». Значение с бэка перекрывает.
constexpr int kTransportRankAwg = 10;
constexpr int kTransportRankXray = 20;

// AVPN upstream nodes (plan provider-pool v2, D2): credential-free stub of an upstream profile - a
// complete Xray config built by the backend and handed out only in the signed lease answer
// (POST /v1/upstream/lease). The subscription carries no host, port or credential of it. Filled only by
// the parser after validation (UpstreamNode.h::parseUpstreamStub) and only while the client kill switch
// features.upstream_nodes is on; such a node is proto "xray" without `xray`. Identity of the node =
// profileId + configSha256 (a new sha = the provider rotated its servers; the row stays the same).
enum class UpstreamProbeClass { Single, Composite };

// What a provider profile is (contract 1.10.0, owner 17.11: no row is ever named «Сервер N»). The wire `kind`
// of a stub, a scan manifest entry and a standby entry: country = one exit country («<страна> n», a flag);
// whitelist = a profile for white-list networks («Белые списки n», a neutral icon, no country); auto = the
// provider's own balancer across countries - an Auto candidate only, never a row of the manual list or the
// Scanner. Unspecified = the field did not come (a server before 1.10.0).
enum class UpstreamKind { Unspecified, Country, Whitelist, Auto };

// The wire value: absent / null -> Unspecified; a value this build does not know -> Auto (contract: "An unknown
// value: treat as auto"). Pure.
inline UpstreamKind upstreamKindFromWire(bool present, const QString &value)
{
    if (!present)
        return UpstreamKind::Unspecified;
    if (value == QLatin1String("country"))
        return UpstreamKind::Country;
    if (value == QLatin1String("whitelist"))
        return UpstreamKind::Whitelist;
    return UpstreamKind::Auto;
}

// The kind a profile is SHOWN as. A whitelist profile stays one (no flag, even when a country came); a country
// profile without a country code cannot be a country row; an older server's stub (no `kind`) is a country row
// when it has a country and otherwise the provider's balancer - kept for Auto, hidden from the manual list
// (before 1.10.0 such a stub was the «Сервер N» row the owner rejected). Never Unspecified. Pure.
inline UpstreamKind upstreamRowKind(UpstreamKind wire, const QString &countryCode)
{
    const bool hasCountry = !countryCode.trimmed().isEmpty();
    switch (wire) {
    case UpstreamKind::Whitelist: return UpstreamKind::Whitelist;
    case UpstreamKind::Auto: return UpstreamKind::Auto;
    case UpstreamKind::Country: return hasCountry ? UpstreamKind::Country : UpstreamKind::Auto;
    case UpstreamKind::Unspecified: break;
    }
    return hasCountry ? UpstreamKind::Country : UpstreamKind::Auto;
}

// A row of the manual server list and of the Scanner: every shown kind except the provider's balancer. Hiding
// a row never removes the node from the subscription: Auto keeps it as a candidate.
inline bool upstreamKindListed(UpstreamKind rowKind) { return rowKind != UpstreamKind::Auto; }

inline const char *upstreamKindName(UpstreamKind k)
{
    switch (k) {
    case UpstreamKind::Country: return "country";
    case UpstreamKind::Whitelist: return "whitelist";
    case UpstreamKind::Auto: return "auto";
    case UpstreamKind::Unspecified: break;
    }
    return "";
}

struct UpstreamStub {
    QString profileId;                   // opaque id for the lease request; node_id == "up:" + profileId
    QString configSha256;                // lower-case hex of the normalized config the lease hands out
    UpstreamProbeClass probeClass = UpstreamProbeClass::Composite;
    QStringList protocols;               // normalizer summary ("proto:vless", "net:tcp", ...)
    QStringList requiredGeo;             // "geosite:..."/"geoip:..." tags the profile routes by
    int     sizeBytes = 0;               // size of the normalized config
    int     tier = 1;                    // policy tier (D9), >= 1; 0 is reserved for own nodes
    int     priority = 0;                // order inside the tier, lower first
    // Synthesized by the app from a standby-pack entry because the subscription in force has no stub for
    // that profile (cold start without the API; UpstreamEngine.h::standbyPackCandidates). Such a candidate
    // runs only through the provisional path (direct acquire first; transport failure -> the pack).
    bool    packSourced = false;
    // Display name parts (release A, owner decision 14.11): our stable number of the profile inside its
    // country (>= 1; 0 = not given) and whether the stub's `label` is the admin's own display name (false
    // = a server fallback such as "NL 1", never shown - UpstreamNode.h::upstreamDisplayName).
    int     ordinal = 0;
    bool    labelCustom = false;
    UpstreamKind kind = UpstreamKind::Unspecified; // the wire `kind` (upstreamRowKind decides how it is shown)
};

struct SubscriptionNode {
    QString nodeId;
    QString region;
    QString name;                        // AVPN: label из контракта (фолбэк region) — отображаемое имя
    QString countryCode;                 // AVPN: ISO-3166 alpha-2 (country_code) → флаг-эмодзи; пусто = нет
    QString endpoint;                    // "host:port" — клиент разбивает на host+port
    QString serverPubkey;
    AwgParams awg;
    QString proto = QStringLiteral("awg");
    // AVPN awg31-xray-v1 (§2.2): листенеры одного хоста группируются в «локацию» по host_id
    // (0 = поле не пришло — старый бэк/LKG; тогда локация = сама нода). location — код локации
    // с бэка ("ee"), пусто = нет. transportRank — порядок выбора транспорта внутри локации
    // (Auto): дефолт по proto (awg 10 / xray 20), сервер может перекрыть.
    int     hostId = 0;
    QString location;
    int     transportRank = kTransportRankAwg;
    std::optional<XrayParams> xray;      // AVPN: только у proto=="xray" и только валидные (парсер)
    std::optional<UpstreamStub> upstream; // AVPN upstream nodes: proto "xray" without xray (kill switch upstream_nodes)
    double  weight = 1.0;                 // score = url_rtt / weight
    bool    manualOnly = false;          // AVPN: manual_only (openapi 0.6.1) — только ручной pin, вне авто-выбора
    QHash<QString, double> health;       // target -> [0..1]
    QStringList allowedIps;              // full-tunnel: 0.0.0.0/0, ::/0
    QStringList dns;                     // >=1 (бэкенд шлёт >=2: iOS dns1/dns2)
    int     mtu = 0;                     // 0 => дефолт платформы
    int     persistentKeepalive = 25;
    QString presharedKey;                // опц.
};

enum class SubStatus { Active, Degraded };  // degraded = мягкий лимит/истечение → пул пуст/урезан

// Верхнеуровневая подписка. ВАЖНО: address — ОДИН стабильный /32 на юзера (не per-node), §6.3 плана.
struct Subscription {
    int         version = 0;
    QStringList address;                 // стабильный /32 (Interface Address), маппится в client_ip
    SubStatus   status = SubStatus::Active;
    QString     expiresAt;               // ISO-8601; пусто = бессрочно
    QString     graceUntil;              // AVPN: expires_at + 24ч — не рвать туннель раньше (grace)
    qint64      trafficUsed = 0;
    qint64      trafficLimit = 0;        // 0 = безлимит
    // AVPN awg31-xray-v1 (§2.2/§2.3): pool_revision монотонно растёт при любой смене выдачи —
    // триггер reseed пула на живом приложении (ServiceEngine::reseedPool, kill-switch
    // subscription_reseed_pool). 0 = поле не пришло (старый бэк/LKG) → reseed по ревизии не срабатывает.
    qint64      poolRevision = 0;
    // AVPN upstream nodes: upstream_revision (epoch ms, monotonic) - present only for a device the server
    // admits to upstream nodes. 0 = absent: the parser keeps no upstream node then (contract: "absence =
    // no upstream entries are usable, drop them").
    qint64      upstreamRevision = 0;
    QList<SubscriptionNode> nodes;
};

} // namespace avpn
