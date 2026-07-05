// AVPN: проверка CidrCarve.h — carve-out IP control plane из RU-direct сева.
// Регресс-инвариант инцидента 2026-07-05: ни один севаемый CIDR не накрывает IP API.
#include "../CidrCarve.h"
#include "../ru_prefixes.h"

#include <QCoreApplication>
#include <QHostAddress>
#include <cstdio>
#include <cstdlib>

static int g_fail = 0;
#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            printf("OK   %s\n", msg);                                                              \
        } else {                                                                                   \
            printf("FAIL %s\n", msg);                                                              \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static bool cidrCovers(const QString &cidr, quint32 ip4)
{
    const int slash = cidr.indexOf(QLatin1Char('/'));
    if (slash <= 0)
        return false;
    const QHostAddress net(cidr.left(slash));
    if (net.protocol() != QAbstractSocket::IPv4Protocol)
        return false;
    const int prefix = cidr.mid(slash + 1).toInt();
    const quint32 mask = prefix == 0 ? 0u : ~0u << (32 - prefix);
    return (net.toIPv4Address() & mask) == (ip4 & mask);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QHostAddress apiIp(QStringLiteral("159.194.214.36"));
    const quint32 api4 = apiIp.toIPv4Address();

    // 1) разбиение /20 без /32: 12 частей, покрывают всё кроме ip, ip не накрыт
    {
        const QHostAddress net(QStringLiteral("159.194.208.0"));
        const QStringList parts = avpn::splitCidrExcludingIp(net.toIPv4Address(), 20, api4);
        CHECK(parts.size() == 12, "split /20: 12 под-CIDR");
        bool coversApi = false;
        quint64 total = 0;
        for (const QString &p : parts) {
            if (cidrCovers(p, api4))
                coversApi = true;
            total += 1ull << (32 - p.mid(p.indexOf('/') + 1).toInt());
        }
        CHECK(!coversApi, "split /20: IP API не накрыт");
        CHECK(total == (1ull << 12) - 1, "split /20: покрыто 4095 адресов из 4096");
        // сосед /32 остаётся direct
        CHECK(cidrCovers(parts.last(), api4 ^ 1u), "split /20: сосед-/32 остаётся в байпасе");
    }

    // 2) carve по карте сева: реальный ru_prefixes + kBypassExtra-подобный ключ
    {
        QMap<QString, QString> sites;
        for (const QString &cidr : avpn::ruPrefixes())
            sites.insert(cidr, cidr);
        int coveredBefore = 0;
        for (auto it = sites.cbegin(); it != sites.cend(); ++it)
            if (cidrCovers(it.key(), api4))
                ++coveredBefore;
        CHECK(coveredBefore > 0, "ru_prefixes сейчас накрывает IP API (иначе тест неактуален)");

        avpn::carveOutIpFromSites(sites, apiIp);
        int coveredAfter = 0;
        for (auto it = sites.cbegin(); it != sites.cend(); ++it)
            if (cidrCovers(it.key(), api4))
                ++coveredAfter;
        CHECK(coveredAfter == 0, "после carve НИ ОДИН севаемый CIDR не накрывает IP API");
    }

    // 3) не-накрывающие и v6/мусорные ключи не трогаются
    {
        QMap<QString, QString> sites;
        sites.insert(QStringLiteral("8.6.112.0/24"), QStringLiteral("8.6.112.0/24"));
        sites.insert(QStringLiteral("2a00:1450::/32"), QStringLiteral("2a00:1450::/32"));
        sites.insert(QStringLiteral("garbage"), QStringLiteral("garbage"));
        const auto before = sites;
        avpn::carveOutIpFromSites(sites, apiIp);
        CHECK(sites == before, "чужие/v6/мусорные ключи не изменены");
    }

    // 4) null/v6 ip — no-op
    {
        QMap<QString, QString> sites;
        sites.insert(QStringLiteral("159.194.208.0/20"), QStringLiteral("159.194.208.0/20"));
        const auto before = sites;
        avpn::carveOutIpFromSites(sites, QHostAddress());
        avpn::carveOutIpFromSites(sites, QHostAddress(QStringLiteral("::1")));
        CHECK(sites == before, "null/v6 ip — no-op");
    }

    printf(g_fail ? ">>> FAIL: %d\n" : ">>> ALL OK\n", g_fail);
    return g_fail ? EXIT_FAILURE : EXIT_SUCCESS;
}
