// client/core/serviceEngine/BypassListTypes.h
// AVPN server-driven АнтиВПН: типы + форвард-совместимый парсер+валидатор серверного
// /v1/bypass-lists (ru_cidrs/bypass_extra/cn_liauto_cidrs/split_dns, ed25519-подпись
// снаружи — см. Ed25519Verify.h, здесь только тело payload'а).
// Header-only, по стилю ConfigTypes.h::parseConfig: сброс out перед парсингом,
// неизвестные поля игнорируются, битый JSON не оставляет out полу-валидным.
#pragma once

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

inline bool isNeverBypassAddr(const QHostAddress &netAddr)
{
    for (const auto &nb : neverBypassSubnets())
        if (netAddr.isInSubnet(nb))
            return true;
    return false;
}

// Валидна ли отдельная CIDR-запись сева: парсится, prefixlen >= 8, вне never-bypass.
inline bool isBypassCidrAllowed(const QString &cidr)
{
    if (cidr.isEmpty())
        return false;
    const QPair<QHostAddress, int> parsed = QHostAddress::parseSubnet(cidr);
    if (parsed.first.isNull() || parsed.second < 0)
        return false; // невалидная запись (мусор, не CIDR)
    if (parsed.second < 8)
        return false; // подозрительно широкий диапазон — потенциальная дыра сева
    if (isNeverBypassAddr(parsed.first))
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
    bool haveSplitDns = o.value(QStringLiteral("split_dns")).isObject();
    if (haveSplitDns) {
        const QJsonArray suffixes = splitDns.value(QStringLiteral("suffixes")).toArray();
        for (const QJsonValue &v : suffixes)
            if (v.isString())
                out.splitDnsSuffixes << v.toString();
        out.splitDnsServer = splitDns.value(QStringLiteral("server")).toString();
        const QJsonArray maskDns = splitDns.value(QStringLiteral("mask_dns")).toArray();
        for (const QJsonValue &v : maskDns)
            if (v.isString())
                out.maskDns << v.toString();
    }
    // Дефолты — если split_dns целиком отсутствует ИЛИ пришёл битым (сервер выдал
    // объект без ожидаемых полей): без этого клиент останется без split-DNS вообще.
    if (out.splitDnsSuffixes.isEmpty() || out.splitDnsServer.isEmpty() || out.maskDns.isEmpty()) {
        out.splitDnsSuffixes = QStringList{
            QStringLiteral("ru"), QStringLiteral("su"), QStringLiteral("xn--p1ai"),
            QStringLiteral("vk.com"), QStringLiteral("userapi.com"),
            QStringLiteral("yandex.net"), QStringLiteral("yastatic.net"),
        };
        out.splitDnsServer = QStringLiteral("77.88.8.8");
        out.maskDns = QStringList{ QStringLiteral("77.88.8.8"), QStringLiteral("77.88.8.1") };
    }

    if (out.ruCidrs.size() < kMinValidRuCidrs || out.version <= 0) {
        out.valid = false;
        return false;
    }
    out.valid = true;
    return true;
}

} // namespace avpn
