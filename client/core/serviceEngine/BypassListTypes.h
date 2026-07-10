// client/core/serviceEngine/BypassListTypes.h
// AVPN server-driven АнтиВПН: типы + форвард-совместимый парсер+валидатор серверного
// /v1/bypass-lists (ru_cidrs/bypass_extra/cn_liauto_cidrs/split_dns, ed25519-подпись
// снаружи — см. Ed25519Verify.h, здесь только тело payload'а).
// Header-only, по стилю ConfigTypes.h::parseConfig: сброс out перед парсингом,
// неизвестные поля игнорируются, битый JSON не оставляет out полу-валидным.
#pragma once

#include <QAbstractSocket>
#include <QByteArray>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QVector>

namespace avpn {

struct BypassLists
{
    int         version = 0;
    QStringList ruCidrs;
    QStringList bypassExtra;
    QStringList cnLiAutoCidrs;
    QStringList splitDnsSuffixes;   // ["ru","su",...]
    QString     splitDnsServer;     // "77.88.8.8"
    QStringList maskDns;            // ["77.88.8.8","77.88.8.1"]
    bool        valid = false;
};

// Never-bypass: диапазоны, которые НИКОГДА не должны попасть в сев мимо туннеля
// (приватные/loopback/CGNAT/Apple push + IPv6-эквиваленты). Дублирует NEVER_BYPASS
// бэкенда (11 диапазонов) — фильтр держим и на клиенте как defense-in-depth на случай
// компрометации/бага сервера-источника списков.
inline const QStringList &neverBypassRanges()
{
    static const QStringList kRanges = {
        QStringLiteral("0.0.0.0/8"),
        QStringLiteral("10.0.0.0/8"),
        QStringLiteral("100.64.0.0/10"),
        QStringLiteral("127.0.0.0/8"),
        QStringLiteral("169.254.0.0/16"),
        QStringLiteral("172.16.0.0/12"),
        QStringLiteral("192.168.0.0/16"),
        QStringLiteral("17.0.0.0/8"),
        QStringLiteral("::1/128"),
        QStringLiteral("fc00::/7"),
        QStringLiteral("fe80::/10"),
    };
    return kRanges;
}

inline const QVector<QPair<QHostAddress, int>> &neverBypassSubnets()
{
    static const QVector<QPair<QHostAddress, int>> kSubnets = [] {
        QVector<QPair<QHostAddress, int>> v;
        for (const QString &r : neverBypassRanges())
            v << QHostAddress::parseSubnet(r);
        return v;
    }();
    return kSubnets;
}

// Двусторонний overlap-тест: (netAddr,prefixLen) — сама запись сева, nb — never-bypass
// диапазон. Проверяем ОБА направления, иначе запись-СУПЕРСЕТЬ never-диапазона (например
// 100.0.0.0/8, которая накрывает CGNAT 100.64.0.0/10 целиком) проходит фильтр: её network-
// адрес (100.0.0.0) сам по себе не лежит внутри более узкого never-диапазона, хотя
// пересечение есть. Направление 1 (netAddr in nb) ловит запись-ПОДСЕТЬ never-диапазона;
// направление 2 (nb.first in {netAddr,prefixLen}) ловит запись-СУПЕРСЕТЬ.
inline bool isNeverBypassAddr(const QHostAddress &netAddr, int prefixLen)
{
    const QPair<QHostAddress, int> entry(netAddr, prefixLen);
    for (const auto &nb : neverBypassSubnets()) {
        if (netAddr.isInSubnet(nb))
            return true;
        if (nb.first.isInSubnet(entry))
            return true;
    }
    return false;
}

// Валидна ли отдельная CIDR-запись сева: парсится, prefixlen >= 8, вне never-bypass
// (в обе стороны — см. isNeverBypassAddr).
inline bool isBypassCidrAllowed(const QString &cidr)
{
    if (cidr.isEmpty())
        return false;
    const QPair<QHostAddress, int> parsed = QHostAddress::parseSubnet(cidr);
    if (parsed.first.isNull() || parsed.second < 0)
        return false; // невалидная запись (мусор, не CIDR)
    if (parsed.second < 8)
        return false; // подозрительно широкий диапазон — потенциальная дыра сева
    if (isNeverBypassAddr(parsed.first, parsed.second))
        return false;
    return true;
}

// Отфильтровать список CIDR-строк, оставив только допустимые (см. isBypassCidrAllowed).
inline QStringList filterBypassCidrs(const QJsonArray &arr)
{
    QStringList out;
    for (const QJsonValue &v : arr) {
        if (!v.isString())
            continue;
        const QString cidr = v.toString();
        if (isBypassCidrAllowed(cidr))
            out << cidr;
    }
    return out;
}

// Минимальный порог валидного ru_cidrs: защита от битого/пустого/урезанного списка
// с сервера — при недоборе клиент обязан остаться на текущем (встроенном/кэшированном)
// севе, а не переключиться на дырявый.
constexpr int kMinValidRuCidrs = 6000;

// Дефолты split_dns из контракта — per-field fallback (см. parseBypassLists): каждое из
// трёх полей откатывается на дефолт НЕЗАВИСИМО, если пришло пустым/битым, а не всё разом.
inline const QStringList &defaultSplitDnsSuffixes()
{
    static const QStringList kDefaults = {
        QStringLiteral("ru"), QStringLiteral("su"), QStringLiteral("xn--p1ai"),
        QStringLiteral("vk.com"), QStringLiteral("userapi.com"),
        QStringLiteral("yandex.net"), QStringLiteral("yastatic.net"),
    };
    return kDefaults;
}

inline QString defaultSplitDnsServer()
{
    return QStringLiteral("77.88.8.8");
}

inline const QStringList &defaultMaskDns()
{
    static const QStringList kDefaults = { QStringLiteral("77.88.8.8"), QStringLiteral("77.88.8.1") };
    return kDefaults;
}

// Валиден ли IP-адрес (v4/v6) в виде строки — используется для split_dns.server/mask_dns.
inline bool isValidIpAddress(const QString &s)
{
    if (s.isEmpty())
        return false;
    return QHostAddress(s).protocol() != QAbstractSocket::UnknownNetworkLayerProtocol;
}

inline bool parseBypassLists(const QByteArray &body, BypassLists &out, QString &err)
{
    // Идемпотентность: сбрасываем out ПЕРЕД парсингом — переиспользуемый struct не должен
    // аккумулировать CIDR между вызовами и не должен остаться полу-валидным после ошибки.
    out = BypassLists();
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        err = pe.errorString();
        if (err.isEmpty())
            err = QStringLiteral("not a JSON object");
        return false;
    }
    const QJsonObject o = doc.object();

    out.version = o.value(QStringLiteral("version")).toInt(0);
    out.ruCidrs = filterBypassCidrs(o.value(QStringLiteral("ru_cidrs")).toArray());
    out.bypassExtra = filterBypassCidrs(o.value(QStringLiteral("bypass_extra")).toArray());
    out.cnLiAutoCidrs = filterBypassCidrs(o.value(QStringLiteral("cn_liauto_cidrs")).toArray());

    const QJsonObject splitDns = o.value(QStringLiteral("split_dns")).toObject();
    const bool haveSplitDns = o.value(QStringLiteral("split_dns")).isObject();

    QStringList suffixesIn;
    QString serverIn;
    QStringList maskDnsIn;
    if (haveSplitDns) {
        const QJsonArray suffixes = splitDns.value(QStringLiteral("suffixes")).toArray();
        for (const QJsonValue &v : suffixes) {
            // M-1: суффикс с запятой/пробелом невалиден — в DNS-суффиксе их не бывает, а
            // downstream join(',') (dnsFwd) расщепил бы "a,b" на два суффикса молча.
            if (v.isString() && !v.toString().isEmpty()
                && !v.toString().contains(QLatin1Char(','))
                && !v.toString().contains(QLatin1Char(' ')))
                suffixesIn << v.toString();
        }
        serverIn = splitDns.value(QStringLiteral("server")).toString();
        const QJsonArray maskDns = splitDns.value(QStringLiteral("mask_dns")).toArray();
        for (const QJsonValue &v : maskDns)
            if (v.isString())
                maskDnsIn << v.toString();
    }

    // Per-field откат на дефолт: пустота/битость ОДНОГО поля не должна гасить остальные
    // два (иначе валидные свежие suffixes/mask_dns пропадают из-за, например, одного
    // битого server). Каждое поле валидируется и откатывается независимо.
    out.splitDnsSuffixes = suffixesIn.isEmpty() ? defaultSplitDnsSuffixes() : suffixesIn;

    out.splitDnsServer = isValidIpAddress(serverIn) ? serverIn : defaultSplitDnsServer();

    bool maskDnsAllValid = !maskDnsIn.isEmpty();
    for (const QString &m : maskDnsIn) {
        if (!isValidIpAddress(m)) {
            maskDnsAllValid = false;
            break;
        }
    }
    out.maskDns = maskDnsAllValid ? maskDnsIn : defaultMaskDns();

    if (out.ruCidrs.size() < kMinValidRuCidrs || out.version <= 0) {
        out.valid = false;
        return false;
    }
    out.valid = true;
    return true;
}

} // namespace avpn
