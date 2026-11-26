// Device round air-I review F4 (25.11): an address of our API edge is a public unicast address; every user of the
// app's API address list dials it outside the session's core, so the app keeps only those (ApiHostAddress.h).
// Build/run: tests/build_api_host_address.sh
#include "../ApiHostAddress.h"

#include <QHostAddress>
#include <cstdio>

using namespace avpn;

static int g_fail = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                            \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static bool pub(const char *a) { return isPublicUnicastAddress(QHostAddress(QString::fromLatin1(a))); }

// The table, with both edges of every range.
static void table()
{
    // public
    for (const char *a : {"1.1.1.1", "8.8.8.8", "201.34.134.103", "95.217.135.30", "9.255.255.255", "11.0.0.0",
                          "100.63.255.255", "100.128.0.0", "126.255.255.255", "128.0.0.1", "169.253.255.255", "169.255.0.0",
                          "172.15.255.255", "172.32.0.0", "192.0.1.255", "192.0.3.0", "192.167.255.255", "192.169.0.0",
                          "198.17.255.255", "198.20.0.0", "198.51.99.255", "198.51.101.0", "203.0.112.255", "203.0.114.0",
                          "223.255.255.255", "2a01:4f8::1", "2606:4700::1111", "2001:db7:ffff::1", "2001:db9::1",
                          "3fff:ffff::1", "::ffff:8.8.8.8"})
        CHECK(pub(a));
    // not public: every range of the table, its first and last address
    for (const char *a : {"0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255", "100.64.0.0", "100.127.255.255",
                          "100.88.0.5", // our normalizer's FakeDNS pool (inside 100.64/10)
                          "127.0.0.1", "127.255.255.255", "169.254.0.0", "169.254.255.255", "172.16.0.0", "172.31.255.255",
                          "192.0.0.0", "192.0.0.255", "192.0.2.0", "192.0.2.255", "192.168.0.0", "192.168.255.255",
                          "198.18.0.0", "198.19.255.255", // Xray's default FakeDNS pool
                          "198.51.100.0", "198.51.100.255", "203.0.113.0", "203.0.113.255", "224.0.0.1",
                          "239.255.255.255", "240.0.0.0", "255.255.255.255", "::ffff:100.88.0.5", "::ffff:10.0.0.1"})
        CHECK(!pub(a));
    for (const char *a : {"::", "::1", "fc00::1", "fc00::5", "fc00:3fff::1", "fdff:ffff::1", "fe80::1", "fe80::1%en0",
                          "ff02::1", "2001:db8::", "2001:db8:ffff:ffff::1", "1fff:ffff::1", "4000::1", "::8.8.8.8"})
        CHECK(!pub(a));
    CHECK(!isPublicUnicastAddress(QHostAddress()));
    CHECK(publicUnicastOnly({QStringLiteral("100.88.0.5"), QStringLiteral(" 8.8.8.8 "), QStringLiteral("api.tribevpn.com"),
                             QStringLiteral("fc00::5"), QStringLiteral("2a01:4f8::1"), QString()})
          == (QStringList{QStringLiteral("8.8.8.8"), QStringLiteral("2a01:4f8::1")}));
    CHECK(publicUnicastOnly({}).isEmpty());
}

// The recording rule: a lookup inside a provider session (FakeDNS answers) records nothing; what was recorded before is
// kept; public answers are added in order without duplicates; the count of left-out answers is returned.
static void recording()
{
    QList<QHostAddress> all;
    QStringList mine;
    // the app opened inside a provider session: the answer is the session's pool
    CHECK(recordApiHostAnswers(all, mine, {QHostAddress(QStringLiteral("100.88.0.5"))}) == 1);
    CHECK(all.isEmpty() && mine.isEmpty());
    CHECK(recordApiHostAnswers(all, mine, {QHostAddress(QStringLiteral("198.18.0.7")), QHostAddress(QStringLiteral("fc00::7"))}) == 2);
    CHECK(all.isEmpty() && mine.isEmpty());
    // the next lookup outside it: the real address
    CHECK(recordApiHostAnswers(all, mine, {QHostAddress(QStringLiteral("201.34.134.103"))}) == 0);
    CHECK(mine == QStringList{QStringLiteral("201.34.134.103")} && all.size() == 1);
    // recorded before, then another provider session: kept, nothing added
    CHECK(recordApiHostAnswers(all, mine, {QHostAddress(QStringLiteral("100.88.0.9"))}) == 1);
    CHECK(mine == QStringList{QStringLiteral("201.34.134.103")} && all.size() == 1);
    // a mixed answer: public ones in order, no duplicate
    CHECK(recordApiHostAnswers(all, mine, {QHostAddress(QStringLiteral("10.0.0.1")), QHostAddress(QStringLiteral("2a01:4f8::1")),
                                           QHostAddress(QStringLiteral("201.34.134.103"))}) == 1);
    CHECK(mine == (QStringList{QStringLiteral("201.34.134.103"), QStringLiteral("2a01:4f8::1")}) && all.size() == 2);
    // another host's list shares `all` without duplicates
    QStringList other;
    CHECK(recordApiHostAnswers(all, other, {QHostAddress(QStringLiteral("2a01:4f8::1"))}) == 0);
    CHECK(other == QStringList{QStringLiteral("2a01:4f8::1")} && all.size() == 2);
}

int main()
{
    table();
    recording();
    if (g_fail == 0)
        std::printf("api_host_address_check: OK\n");
    return g_fail == 0 ? 0 : 1;
}
