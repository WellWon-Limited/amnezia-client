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

    bool hasFullBundle() const { return Jc && Jmin && Jmax && S1 && S2 && H1 && H2 && H3 && H4; }
};

struct SubscriptionNode {
    QString nodeId;
    QString region;
    QString endpoint;                    // "host:port" — клиент разбивает на host+port
    QString serverPubkey;
    AwgParams awg;
    QString proto = QStringLiteral("awg");
    double  weight = 1.0;                 // score = url_rtt / weight
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
    qint64      trafficUsed = 0;
    qint64      trafficLimit = 0;        // 0 = безлимит
    QList<SubscriptionNode> nodes;
};

} // namespace avpn
