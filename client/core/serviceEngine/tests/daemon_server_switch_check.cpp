// AVPN (awg audit 25.11.2026, round mac-D): the shared desktop daemon (client/daemon/daemon.cpp, macOS/Linux/Windows)
// switches a live tunnel to another server in place only when the interface keeps nothing of the old server.
//
// Daemon::activate on a live tunnel took an in-place switch (switchServer -> WireguardUtils::updatePeer) whenever the
// private key, device addresses and gateways were equal - always true in Tribe (one device key, one /32 per user on
// every node, one gateway). updatePeer sends only the peer; the interface-level settings that addInterface applied
// (AmneziaWG jc/jmin/jmax, s1-s4, h1-h4, i1-i5, the 3.x settings, MTU, DNS, the kill switch session with the old
// peer's host) stayed those of the old node: "connected" with no handshake.
//
// The real Daemon::activate / deactivate / parseConfig against a fake WireguardUtils that records what the interface
// was created with and which peer it carries. Configs come through Daemon::parseConfig from the JSON the client sends.
// Addresses are documentation ranges, keys are fake.
#include "daemon.h"
#include "serverswitchpolicy.h"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>
#include <functional>

#include "../platforms/macos/daemon/splitdnsresolverfiles.h"
#include "logger.h"  // tests/daemon_stub: daemonStubLogLines()

// ---- what daemon.cpp links against in the service, stubbed ---------------------------------------------------------
namespace avpn {
void tribeScanBeforeTunnelChange(const char *) {}
}
namespace SplitDnsResolverFiles {
bool apply(const QStringList &, const QString &, const QString &) { return true; }
void clear() {}
}

namespace {

int g_fail = 0;
int g_checks = 0;
void check(bool ok, const QString &what)
{
    ++g_checks;
    if (!ok) {
        ++g_fail;
        std::printf("FAIL %s\n", qPrintable(what));
    }
}

class FakeWg final : public WireguardUtils {
public:
    FakeWg() : WireguardUtils(nullptr) {}
    bool up = false;
    int addInterfaceCalls = 0;
    int deleteInterfaceCalls = 0;
    int updatePeerCalls = 0;
    InterfaceConfig iface;   // what the live interface was created with (addInterface)
    QString peerKey;         // the peer it carries now (updatePeer / deletePeer)

    bool interfaceExists() override { return up; }
    bool addInterface(const InterfaceConfig &c) override
    {
        ++addInterfaceCalls;
        up = true;
        iface = c;
        return true;
    }
    bool deleteInterface() override
    {
        ++deleteInterfaceCalls;
        up = false;
        peerKey.clear();
        return true;
    }
    bool updatePeer(const InterfaceConfig &c) override
    {
        ++updatePeerCalls;
        peerKey = c.m_serverPublicKey;
        return true;
    }
    bool deletePeer(const InterfaceConfig &c) override
    {
        if (peerKey == c.m_serverPublicKey)
            peerKey.clear();
        return true;
    }
    QList<PeerStatus> getPeerStatus() override { return {}; }
    bool updateRoutePrefix(const IPAddress &) override { return true; }
    bool deleteRoutePrefix(const IPAddress &) override { return true; }
    bool addExclusionRoute(const IPAddress &) override { return true; }
    bool deleteExclusionRoute(const IPAddress &) override { return true; }
    bool excludeLocalNetworks(const QList<IPAddress> &) override { return true; }
};

class FakeDns final : public DnsUtils {
public:
    FakeDns() : DnsUtils(nullptr) {}
    bool updateResolvers(const QString &, const QList<QHostAddress> &) override { return true; }
    bool restoreResolvers() override { return true; }
};

class TestDaemon final : public Daemon {
public:
    TestDaemon() : Daemon(nullptr) {}
    FakeWg wg;
    FakeDns dns;

protected:
    WireguardUtils *wgutils() const override { return const_cast<FakeWg *>(&wg); }
    DnsUtils *dnsutils() override { return &dns; }
};

// The JSON the client sends for one Tribe AmneziaWG node (mozilla/localsocketcontroller.cpp): the same device key,
// device /32 and gateway on every node; the server's host is the first excluded address.
QJsonObject node(const QString &serverKey, const QString &host, bool killSwitch)
{
    QJsonObject o;
    o["privateKey"] = QStringLiteral("ZGV2aWNlLWtleS1mYWtlLWRldmljZS1rZXktZmFrZT0=");
    o["deviceIpv4Address"] = QStringLiteral("10.64.0.17/32");
    o["serverIpv4Gateway"] = QStringLiteral("10.127.255.254");
    o["serverPublicKey"] = serverKey;
    o["serverPskKey"] = QStringLiteral("cHNrLWZha2UtcHNrLWZha2UtcHNrLWZha2UtcHNrLWY=");
    o["serverIpv4AddrIn"] = host;
    o["serverPort"] = 585;
    o["deviceMTU"] = QStringLiteral("1376");
    o["persistentKeepalive"] = QStringLiteral("25");
    o["primaryDnsServer"] = QStringLiteral("10.127.255.254");
    o["secondaryDnsServer"] = QStringLiteral("1.1.1.1");
    o["killSwitchOption"] = killSwitch ? QStringLiteral("true") : QStringLiteral("false");
    QJsonArray allowed;
    allowed.append(QJsonObject{{"address", "0.0.0.0"}, {"range", 0}, {"isIpv6", false}});
    o["allowedIPAddressRanges"] = allowed;
    o["excludedAddresses"] = QJsonArray{host};
    o["vpnDisabledApps"] = QJsonArray{};
    o["allowedDnsServers"] = QJsonArray{};
    o["Jc"] = QStringLiteral("6");
    o["Jmin"] = QStringLiteral("10");
    o["Jmax"] = QStringLiteral("50");
    o["S1"] = QStringLiteral("39");
    o["S2"] = QStringLiteral("47");
    o["S3"] = QStringLiteral("39");
    o["S4"] = QStringLiteral("12");
    o["H1"] = QStringLiteral("1020325451");
    o["H2"] = QStringLiteral("3288052141");
    o["H3"] = QStringLiteral("1766607858");
    o["H4"] = QStringLiteral("2528465083");
    o["I1"] = QStringLiteral("<b 0xc700000001><r 16>");
    o["I2"] = QStringLiteral("<r 32>");
    return o;
}

InterfaceConfig parse(const QJsonObject &o)
{
    InterfaceConfig c;
    const bool ok = Daemon::parseConfig(o, c);
    check(ok, QStringLiteral("parseConfig accepts the test node %1").arg(o.value("serverPublicKey").toString()));
    return c;
}

const QString kKeyA = QStringLiteral("c2VydmVyLWEtZmFrZS1zZXJ2ZXItYS1mYWtlLXNlcnY=");
const QString kKeyB = QStringLiteral("c2VydmVyLWItZmFrZS1zZXJ2ZXItYi1mYWtlLXNlcnY=");
const QString kHostA = QStringLiteral("192.0.2.10");
const QString kHostB = QStringLiteral("198.51.100.20");

bool logged(const QString &needle)
{
    for (const QString &l : daemonStubLogLines())
        if (l.contains(needle))
            return true;
    return false;
}

struct Outcome {
    bool activated = false;
    bool newInterface = false;  // deactivate + activate (addInterface twice, deleteInterface once)
    bool inPlace = false;       // switchServer: one interface, the peer replaced
    InterfaceConfig iface;      // what the live interface carries after the second activate
    QString peerKey;
    bool loggedSupported = false;
    bool loggedNotSupported = false;
};

// activate(first) on a down daemon, then activate(second) on the live tunnel - what the GUI sends when the user picks
// another server while connected.
Outcome switchTo(const QJsonObject &first, const QJsonObject &second)
{
    TestDaemon d;
    const InterfaceConfig a = parse(first);
    const InterfaceConfig b = parse(second);
    const bool firstUp = d.activate(a);
    check(firstUp && d.wg.addInterfaceCalls == 1 && d.wg.peerKey == a.m_serverPublicKey,
          QStringLiteral("the first activate brings the interface up with its peer"));
    daemonStubLogLines().clear();
    Outcome r;
    r.activated = d.activate(b);
    r.newInterface = d.wg.addInterfaceCalls == 2 && d.wg.deleteInterfaceCalls == 1;
    r.inPlace = d.wg.addInterfaceCalls == 1 && d.wg.deleteInterfaceCalls == 0 && d.wg.updatePeerCalls == 2;
    r.iface = d.wg.iface;
    r.peerKey = d.wg.peerKey;
    r.loggedSupported = logged(QStringLiteral("Server switching supported"));
    r.loggedNotSupported = logged(QStringLiteral("Server switching not supported"));
    d.deactivate(false);
    return r;
}

void expectNewInterface(const QString &label, const QJsonObject &first, const QJsonObject &second)
{
    const Outcome r = switchTo(first, second);
    const InterfaceConfig b = parse(second);
    check(r.activated, label + QStringLiteral(": the switch activates"));
    check(r.newInterface, label + QStringLiteral(": deactivate + activate (a new interface), not an in-place switch"));
    check(!r.loggedSupported && r.loggedNotSupported,
          label + QStringLiteral(": the service log says \"Server switching not supported\""));
    // the fake keeps the whole config addInterface got: the new server's = its jc/s/h/i, MTU, DNS, kill switch session
    check(r.iface.m_serverPublicKey == b.m_serverPublicKey && r.iface.m_junkPacketCount == b.m_junkPacketCount
              && r.iface.m_specialJunk == b.m_specialJunk && r.iface.m_excludedAddresses == b.m_excludedAddresses,
          label + QStringLiteral(": the live interface was created from the new server's config"));
    check(r.peerKey == b.m_serverPublicKey, label + QStringLiteral(": the interface carries the new peer"));
}

void expectInPlace(const QString &label, const QJsonObject &first, const QJsonObject &second)
{
    const Outcome r = switchTo(first, second);
    const InterfaceConfig b = parse(second);
    check(r.activated, label + QStringLiteral(": the switch activates"));
    check(r.inPlace, label + QStringLiteral(": an in-place switch (one interface, the peer replaced)"));
    check(r.loggedSupported, label + QStringLiteral(": the service log says \"Server switching supported\""));
    check(r.peerKey == b.m_serverPublicKey, label + QStringLiteral(": the interface carries the new peer"));
}

}  // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // ---- 1. the defect: another Tribe node with other obfuscation, kill switch off ----------------------------------
    {
        QJsonObject b = node(kKeyB, kHostB, false);
        b["Jc"] = QStringLiteral("4");
        b["S1"] = QStringLiteral("72");
        b["H1"] = QStringLiteral("42000111");
        b["I1"] = QStringLiteral("<b 0xc200000001><r 20>");
        expectNewInterface(QStringLiteral("1 other node, other jc/s1/h1/i1"), node(kKeyA, kHostA, false), b);
    }

    // ---- 2. every interface-level setting alone: the switch takes a new interface ------------------------------------
    // (kill switch off, so only the setting itself differs from an in-place-capable pair)
    const QList<QPair<QString, QString>> one = {
        {"Jc", "3"}, {"Jmin", "11"}, {"Jmax", "51"}, {"S1", "40"}, {"S2", "48"}, {"S3", "40"}, {"S4", "13"},
        {"H1", "1"}, {"H2", "2"}, {"H3", "3"}, {"H4", "4"}, {"I1", "<r 17>"}, {"I2", "<r 33>"}, {"I3", "<r 8>"},
        {"I4", "<r 9>"}, {"I5", "<r 10>"}, {"HeaderProtectionKey", "aHBrLWZha2UtaHBrLWZha2UtaHBrLWZha2UtaHBrLWY="},
        {"ContentPaddingAddition", "16"}, {"RekeyAfterTime", "90"}, {"RekeyTimeout", "4"}, {"RejectAfterTime", "170"},
        {"KeepaliveTimeout", "9"}, {"MaxHandshakeAttempts", "15"}, {"RandomTrailers", "on"}, {"DisableCookies", "on"},
        {"deviceMTU", "1280"}, {"primaryDnsServer", "10.127.255.253"}, {"secondaryDnsServer", "9.9.9.9"},
    };
    for (const auto &kv : one) {
        QJsonObject b = node(kKeyB, kHostB, false);
        b[kv.first] = kv.second;
        expectNewInterface(QStringLiteral("2 %1 differs").arg(kv.first), node(kKeyA, kHostA, false), b);
    }
    // a setting the old node had and the new one does not (an older server's config without the 3.x specials)
    {
        QJsonObject b = node(kKeyB, kHostB, false);
        b.remove("I1");
        b.remove("I2");
        expectNewInterface(QStringLiteral("2 i1/i2 absent on the new node"), node(kKeyA, kHostA, false), b);
    }
    // the kill switch turned on between two sessions
    expectNewInterface(QStringLiteral("2 kill switch off -> on"), node(kKeyA, kHostA, false), node(kKeyB, kHostB, true));

    // ---- 3. kill switch on: its session (macOS/Linux addInterface) passes the old peer's host only ------------------
    expectNewInterface(QStringLiteral("3 kill switch on, another host"), node(kKeyA, kHostA, true), node(kKeyB, kHostB, true));
    {
        QJsonObject a = node(kKeyA, kHostA, true);
        QJsonObject b = node(kKeyB, kHostA, true);
        b["allowedIPAddressRanges"] = QJsonArray{QJsonObject{{"address", "10.0.0.0"}, {"range", 8}, {"isIpv6", false}}};
        expectNewInterface(QStringLiteral("3 kill switch on, other allowed ranges"), a, b);
    }
    // Windows: the peer's firewall rules (enablePeerTraffic) are kept on a switch with the SAME peer key - an extra allowed DNS
    // server dropped from the list would stay allowed (review of f37b06b0e)
    {
        QJsonObject a = node(kKeyA, kHostA, true);
        a["allowedDnsServers"] = QJsonArray{QStringLiteral("198.51.100.53"), QStringLiteral("203.0.113.53")};
        QJsonObject b = node(kKeyA, kHostA, true);
        b["allowedDnsServers"] = QJsonArray{QStringLiteral("198.51.100.53")};
        expectNewInterface(QStringLiteral("3 kill switch on, same peer, other allowed DNS servers"), a, b);
    }

    // ---- 4. what stays in place: only the peer differs ---------------------------------------------------------------
    // kill switch off, the same interface settings, another peer and host: switchServer replaces the peer and routes
    expectInPlace(QStringLiteral("4 kill switch off, only the peer differs"), node(kKeyA, kHostA, false), node(kKeyB, kHostB, false));
    // kill switch on, the same host (its session already passes it), another peer key
    expectInPlace(QStringLiteral("4 kill switch on, same host, another peer key"), node(kKeyA, kHostA, true), node(kKeyB, kHostA, true));
    // kill switch off, other allowed ranges: the routes are the switch's own job
    {
        QJsonObject b = node(kKeyB, kHostB, false);
        b["allowedIPAddressRanges"] = QJsonArray{QJsonObject{{"address", "10.0.0.0"}, {"range", 8}, {"isIpv6", false}}};
        expectInPlace(QStringLiteral("4 kill switch off, other allowed ranges"), node(kKeyA, kHostA, false), b);
    }
    // kill switch off, other allowed DNS servers: no firewall applies them
    {
        QJsonObject b = node(kKeyB, kHostB, false);
        b["allowedDnsServers"] = QJsonArray{QStringLiteral("198.51.100.53")};
        expectInPlace(QStringLiteral("4 kill switch off, other allowed DNS servers"), node(kKeyA, kHostA, false), b);
    }

    // ---- 5. the decision names settings, never their values ----------------------------------------------------------
    {
        QJsonObject b = node(kKeyB, kHostB, false);
        b["HeaderProtectionKey"] = QStringLiteral("c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3I=");
        const QStringList names = avpn::interfaceSettingsThatDiffer(parse(node(kKeyA, kHostA, false)), parse(b));
        check(names == QStringList{QStringLiteral("header_protection_key")},
              QStringLiteral("5 the names of the differing settings: ") + names.join(QLatin1Char(',')));
        check(!names.join(QLatin1Char(' ')).contains(QStringLiteral("c2VjcmV0")), QStringLiteral("5 no value in the names"));
    }

    std::printf("daemon_server_switch_check: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
