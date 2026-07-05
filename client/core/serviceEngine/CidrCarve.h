// AVPN RU-direct: carve-out «свой control plane НИКОГДА не в байпасе».
// api.tribevpn.com хостится на Beget (RU, 159.194.214.36) и накрывается рунет-списком
// ru_prefixes (159.194.208.0/20) → сев уводил запросы движка к API мимо туннеля, где их
// режет оператор (ТСПУ): пустое приложение без подписки/нод (инцидент 2026-07-05).
// Инвариант — расширение урока «серых чипов» (2026-07-03): эндпоинты, критичные для работы
// приложения (пробы, control plane), не должны пересекаться с байпас-CIDR.
// Здесь — чистая логика без Qt-сети (тестируется tests/build_cidr_carve.sh).
#pragma once

#include <QHostAddress>
#include <QMap>
#include <QString>
#include <QStringList>

namespace avpn {

// Разбить v4-CIDR (net/prefix) на под-CIDR, покрывающие всё, КРОМЕ одного ip (/32).
// Классическое дихотомическое исключение: на каждом уровне отдаём «половину без ip»,
// спускаемся в половину с ip. Для /20 это 12 под-CIDR (/21…/32-сосед).
inline QStringList splitCidrExcludingIp(quint32 net, int prefix, quint32 ip)
{
    QStringList out;
    for (int p = prefix + 1; p <= 32; ++p) {
        const quint32 branchBit = 1u << (32 - p);
        // половина, в которой НЕТ ip — целиком в результат
        const quint32 ipHalf = ip & branchBit;
        const quint32 keepNet = (net & ~branchBit) | (ipHalf ^ branchBit);
        out << QStringLiteral("%1/%2").arg(QHostAddress(keepNet).toString()).arg(p);
        net = (net & ~branchBit) | ipHalf; // спускаемся в половину с ip
    }
    return out;
}

// Убрать ip из карты сева (key=value=CIDR, формат applyRuBypassSplit): каждый v4-CIDR,
// накрывающий ip, заменяется своим разбиением без /32. v6 и невалидные ключи не трогаем.
inline void carveOutIpFromSites(QMap<QString, QString> &sites, const QHostAddress &ip)
{
    if (ip.isNull() || ip.protocol() != QAbstractSocket::IPv4Protocol)
        return;
    const quint32 ip4 = ip.toIPv4Address();
    const QStringList keys = sites.keys();
    for (const QString &key : keys) {
        const int slash = key.indexOf(QLatin1Char('/'));
        if (slash <= 0)
            continue;
        const QHostAddress netAddr(key.left(slash));
        if (netAddr.isNull() || netAddr.protocol() != QAbstractSocket::IPv4Protocol)
            continue;
        bool ok = false;
        const int prefix = key.mid(slash + 1).toInt(&ok);
        if (!ok || prefix < 0 || prefix > 32)
            continue;
        const quint32 mask = prefix == 0 ? 0u : ~0u << (32 - prefix);
        if ((netAddr.toIPv4Address() & mask) != (ip4 & mask))
            continue; // не накрывает
        sites.remove(key);
        const QStringList parts = splitCidrExcludingIp(netAddr.toIPv4Address() & mask, prefix, ip4);
        for (const QString &part : parts)
            sites.insert(part, part);
    }
}

} // namespace avpn
