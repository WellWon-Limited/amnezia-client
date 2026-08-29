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

    // Legacy-only generic channel. Deprecated for catalog v2: v2 has a strict typed schema and
    // rejects unknown keys because Apple/Windows parsers have version-specific allowlists.
    // Kept here solely so the transitional /v1 AWG response remains backward-compatible.
    // Эмиссия в конфиг туннеля гейтится server-driven allowlist'ом awg_extra_keys_allowed
    // (TuningStore lists, дефолт пуст) — см. AwgConfigBuilder.
    QHash<QString, QString> extra;

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

struct SubscriptionNode {
    QString nodeId;
    QString region;
    QString name;                        // AVPN: label из контракта (фолбэк region) — отображаемое имя
    QString countryCode;                 // AVPN: ISO-3166 alpha-2 (country_code) → флаг-эмодзи; пусто = нет
    QString endpoint;                    // "host:port" — клиент разбивает на host+port
    QString serverPubkey;
    AwgParams awg;
    QString proto = QStringLiteral("awg");
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
    QList<SubscriptionNode> nodes;
};

} // namespace avpn
