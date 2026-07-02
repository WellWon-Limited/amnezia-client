// AVPN serviceEngine — валидация IPv6-CIDR для split-tunnel. Дополнение к IPv4-only
// NetworkUtilities::checkIpSubnetFormat: тот молча выбрасывал все 2174 IPv6-префикса ru_prefixes.h,
// при том что туннель забирает ::/0 → на dual-stack РФ-операторах (МТС/МегаФон/Билайн) Happy Eyeballs
// уводил рунет-сайты с AAAA В туннель (загран-IP) при включённом «АвтоVPN». iOS-датапас v6-exclude
// умеет (IPAddressRange → NEIPv6Route excludedRoutes), Android — InetNetwork/excludeRoute; блокером
// был только Qt-фильтр. Header-only, покрыт tests/failover_check.cpp (секция cidr).
#pragma once

#include <QHostAddress>
#include <QString>

namespace avpn {

// true для IPv6-адреса или IPv6-CIDR (маска 0–128). IPv4/домены/мусор → false (их путь —
// NetworkUtilities::checkIpSubnetFormat). Только проверка формы, без DNS-резолва.
inline bool isIpv6Cidr(const QString &s)
{
    const int slash = s.indexOf(QLatin1Char('/'));
    const QString addr = (slash < 0) ? s : s.left(slash);
    if (!addr.contains(QLatin1Char(':')))
        return false; // быстрый отсев v4/доменов: валидный текстовый IPv6 всегда содержит ':'
    if (QHostAddress(addr).protocol() != QAbstractSocket::IPv6Protocol)
        return false;
    if (slash < 0)
        return true;
    bool ok = false;
    const int mask = s.mid(slash + 1).toInt(&ok);
    return ok && mask >= 0 && mask <= 128;
}

} // namespace avpn
