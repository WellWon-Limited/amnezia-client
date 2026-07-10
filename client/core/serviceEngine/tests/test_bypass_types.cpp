// client/core/serviceEngine/tests/test_bypass_types.cpp
// AVPN server-driven АнтиВПН: типы+парсер+валидатор /v1/bypass-lists (BypassListTypes.h).
// Сборка/запуск: tests/build_bypass_types.sh (QtCore+QtNetwork, header-only).
#include "../BypassListTypes.h"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

// Строит body с ruCidrs = count валидных /24 в диапазоне 5.0.0.0/8 (без пересечения
// с never-bypass), плюс bypass_extra/cn_liauto_cidrs/split_dns из контракта.
static QByteArray makeBody(int version, int ruCidrCount, const QJsonArray &extraRu = {})
{
    QJsonArray ru;
    int made = 0;
    for (int a = 0; a < 26 && made < ruCidrCount; ++a) {
        for (int b = 0; b < 250 && made < ruCidrCount; ++b) {
            ru << QStringLiteral("5.%1.%2.0/24").arg(a).arg(b);
            ++made;
        }
    }
    for (const QJsonValue &v : extraRu)
        ru << v;

    QJsonObject splitDns;
    splitDns[QStringLiteral("suffixes")] = QJsonArray{ QStringLiteral("ru"), QStringLiteral("su"),
        QStringLiteral("xn--p1ai"), QStringLiteral("vk.com"), QStringLiteral("userapi.com"),
        QStringLiteral("yandex.net"), QStringLiteral("yastatic.net") };
    splitDns[QStringLiteral("server")] = QStringLiteral("77.88.8.8");
    splitDns[QStringLiteral("mask_dns")] = QJsonArray{ QStringLiteral("77.88.8.8"), QStringLiteral("77.88.8.1") };

    QJsonObject o;
    o[QStringLiteral("version")] = version;
    o[QStringLiteral("generated_at")] = QStringLiteral("2026-07-10T00:00:00Z");
    o[QStringLiteral("ru_cidrs")] = ru;
    o[QStringLiteral("bypass_extra")] = QJsonArray{ QStringLiteral("216.239.38.0/24") };
    o[QStringLiteral("cn_liauto_cidrs")] = QJsonArray{ QStringLiteral("120.92.0.0/16") };
    o[QStringLiteral("split_dns")] = splitDns;
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // (а) валидное тело: 6500 CIDR → valid, размеры сходятся.
    {
        avpn::BypassLists out;
        QString err;
        const QByteArray body = makeBody(3, 6500);
        CHECK(avpn::parseBypassLists(body, out, err), "(a) valid body parses");
        CHECK(out.valid, "(a) valid flag set");
        CHECK(out.version == 3, "(a) version");
        CHECK(out.ruCidrs.size() == 6500, "(a) ru_cidrs size == 6500");
        CHECK(out.bypassExtra.size() == 1 && out.bypassExtra[0] == QStringLiteral("216.239.38.0/24"),
              "(a) bypass_extra kept");
        CHECK(out.cnLiAutoCidrs.size() == 1 && out.cnLiAutoCidrs[0] == QStringLiteral("120.92.0.0/16"),
              "(a) cn_liauto_cidrs kept");
        CHECK(out.splitDnsServer == QStringLiteral("77.88.8.8"), "(a) split_dns.server from body");
        CHECK(out.splitDnsSuffixes.size() == 7, "(a) split_dns.suffixes count");
        CHECK(out.maskDns.size() == 2, "(a) mask_dns count");
    }

    // (б) never-bypass + мусор во входе → отфильтрованы, легитимные CIDR остаются.
    {
        avpn::BypassLists out;
        QString err;
        QJsonArray extra = {
            QStringLiteral("10.0.0.0/8"),      // private — never-bypass
            QStringLiteral("17.1.0.0/16"),     // внутри Apple 17.0.0.0/8 — never-bypass
            QStringLiteral("127.0.0.1/32"),    // loopback — never-bypass
            QStringLiteral("169.254.1.0/24"),  // link-local — never-bypass
            QStringLiteral("::1/128"),         // v6 loopback — never-bypass
            QStringLiteral("fe80::/10"),       // v6 link-local — never-bypass
            QStringLiteral("fc00::/7"),        // v6 ULA — never-bypass
            QStringLiteral("1.0.0.0/7"),       // prefixlen < 8 — drop
            QStringLiteral("not-a-cidr"),      // мусор — drop
            QStringLiteral(""),                // пусто — drop
        };
        const QByteArray body = makeBody(1, 50, extra);
        avpn::parseBypassLists(body, out, err);
        CHECK(out.ruCidrs.size() == 50, "(b) only 50 legit ru_cidrs survive filtering");
        for (const QString &bad : { QStringLiteral("10.0.0.0/8"), QStringLiteral("17.1.0.0/16"),
                                     QStringLiteral("127.0.0.1/32"), QStringLiteral("169.254.1.0/24"),
                                     QStringLiteral("::1/128"), QStringLiteral("fe80::/10"),
                                     QStringLiteral("fc00::/7"), QStringLiteral("1.0.0.0/7"),
                                     QStringLiteral("not-a-cidr") })
            CHECK(!out.ruCidrs.contains(bad), qPrintable(QStringLiteral("(b) dropped: %1").arg(bad)));
        CHECK(out.ruCidrs.contains(QStringLiteral("5.0.0.0/24")), "(b) legit entry kept");
    }

    // (в) 100 CIDR (все валидные) → !valid, размер меньше гейта 6000.
    {
        avpn::BypassLists out;
        QString err;
        const QByteArray body = makeBody(1, 100);
        CHECK(!avpn::parseBypassLists(body, out, err), "(c) too few ru_cidrs => false");
        CHECK(!out.valid, "(c) valid flag false");
        CHECK(out.ruCidrs.size() == 100, "(c) filtered ru_cidrs still returned (for diagnostics)");
    }

    // (в-доп) version <= 0 при достаточном числе CIDR тоже гасит valid.
    {
        avpn::BypassLists out;
        QString err;
        const QByteArray body = makeBody(0, 6500);
        CHECK(!avpn::parseBypassLists(body, out, err), "(c2) version<=0 => false");
        CHECK(!out.valid, "(c2) valid flag false despite enough cidrs");
    }

    // (г) нет split_dns → дефолты из контракта.
    {
        avpn::BypassLists out;
        QString err;
        QJsonObject o;
        o[QStringLiteral("version")] = 5;
        QJsonArray ru;
        for (int a = 0; a < 26; ++a)
            for (int b = 0; b < 250; ++b)
                ru << QStringLiteral("5.%1.%2.0/24").arg(a).arg(b);
        o[QStringLiteral("ru_cidrs")] = ru;
        const QByteArray body = QJsonDocument(o).toJson(QJsonDocument::Compact);
        CHECK(avpn::parseBypassLists(body, out, err), "(d) body without split_dns parses");
        CHECK(out.valid, "(d) valid");
        CHECK(out.splitDnsServer == QStringLiteral("77.88.8.8"), "(d) default split_dns.server");
        CHECK(out.splitDnsSuffixes.size() == 7
              && out.splitDnsSuffixes.contains(QStringLiteral("xn--p1ai")), "(d) default suffixes");
        CHECK(out.maskDns.size() == 2
              && out.maskDns.contains(QStringLiteral("77.88.8.1")), "(d) default mask_dns");
    }

    // (д) битый JSON → !valid, out чистый (сброшен), err непустой.
    {
        avpn::BypassLists out;
        QString err;
        CHECK(!avpn::parseBypassLists(QByteArrayLiteral("{not json"), out, err), "(e) broken json => false");
        CHECK(!out.valid, "(e) valid false");
        CHECK(!err.isEmpty(), "(e) err set");
        CHECK(out.ruCidrs.isEmpty() && out.bypassExtra.isEmpty() && out.cnLiAutoCidrs.isEmpty(),
              "(e) out cleared on broken json");
        CHECK(out.version == 0, "(e) version reset to 0");
    }

    // Идемпотентность: переиспользуемый struct не аккумулирует стейл между вызовами.
    {
        avpn::BypassLists out;
        QString err;
        CHECK(avpn::parseBypassLists(makeBody(3, 6500), out, err), "(reuse) first parse ok");
        CHECK(avpn::parseBypassLists(QByteArrayLiteral("{not json"), out, err) == false,
              "(reuse) second (broken) parse false");
        CHECK(out.ruCidrs.isEmpty(), "(reuse) stale ru_cidrs cleared after broken parse");
    }

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
