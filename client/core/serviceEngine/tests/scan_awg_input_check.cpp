// AVPN Scanner (lane L6b, second pass): the awg_mini input of an own AmneziaWG node (DebugSnapshot.h::awgProbeInputFrom
// behind AvpnEngineQml's IScanEngine::awgProbeInput) on a fixture subscription - the device's own key, the tunnel
// address, mtu, the node's peer key / PSK / IP-literal endpoint and the obfuscation lines in the order the live
// tunnel's UAPI carries them (platforms/macos/daemon/wireguardutilsmacos.cpp). The input builds the contract config
// (ScanHostContract.h::scanAwgMiniConfig), and no secret of it reaches any log line or the redacted journal copy.
// Build and run: tests/build_scan_awg_input.sh (QtCore only).
#include "../DebugSnapshot.h"
#include "../ScanHostContract.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QStringList>

#include <cstdio>

using namespace avpn;

static int g_fail = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static QStringList g_log;
static void captureHandler(QtMsgType, const QMessageLogContext &, const QString &m) { g_log << m; }

static const char *kPriv = "aGVsbG8tdGhpcy1pcy1hLXRlc3QtcHJpdmF0ZS1rZXk="; // 32 bytes, base64
static const char *kPeer = "cGVlci1wdWJsaWMta2V5LW9mLXRoZS10ZXN0LW5vZGU="; // 32 bytes, base64
static const char *kPsk = "cHJlLXNoYXJlZC1rZXktb2YtdGhlLXRlc3Qtbm9kZTE="; // 32 bytes, base64
static const char *kHpk = "aGVhZGVyLXByb3RlY3Rpb24ta2V5LWZvci10ZXN0cyE="; // 32 bytes, base64

static SubscriptionNode awgNode()
{
    SubscriptionNode n;
    n.nodeId = QStringLiteral("9");
    n.endpoint = QStringLiteral("38.180.164.134:585");
    n.serverPubkey = QLatin1String(kPeer);
    n.presharedKey = QLatin1String(kPsk);
    n.proto = QStringLiteral("awg");
    n.mtu = 1280;
    AwgParams &a = n.awg;
    a.Jc = 4; a.Jmin = 50; a.Jmax = 1000; a.S1 = 86; a.S2 = 57; a.S3 = 20; a.S4 = 0;
    a.H1 = 101; a.H2 = 202; a.H3 = 303; a.H4 = 404;
    a.I1 = QStringLiteral("<b 0xdeadbeef>");
    a.headerProtectionKey = QLatin1String(kHpk);
    a.rekeyAfterTime = QStringLiteral("100-200");
    a.randomTrailers = true;
    a.disableCookies = false;
    return n;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    Subscription sub;
    sub.address = {QStringLiteral("fd00::5/128"), QStringLiteral("10.7.0.5/32")};
    const SubscriptionNode node = awgNode();

    qInstallMessageHandler(captureHandler);
    ScanAwgMiniInput in;
    CHECK(awgProbeInputFrom(sub, node, QLatin1String(kPriv), 1376, in));
    CHECK(in.privateKey == QLatin1String(kPriv));
    CHECK(in.address == QLatin1String("10.7.0.5/32")); // the IPv4 address first
    CHECK(in.mtu == 1280);
    CHECK(in.peerPublicKey == QLatin1String(kPeer));
    CHECK(in.presharedKey == QLatin1String(kPsk));
    CHECK(in.endpoint == QLatin1String("38.180.164.134:585"));
    CHECK(in.boundIf == -1);
    // The daemon's UAPI order: jc jmin jmax s1 s2 s3 s4 h1..h4, i1, header_protection_key (hex), the 3.0 timers,
    // random_trailers / disable_cookies as 1|0.
    QStringList keys;
    for (const auto &kv : in.obfuscation)
        keys << kv.first;
    CHECK(keys == (QStringList{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1",
                               "header_protection_key", "rekey_after_time", "random_trailers", "disable_cookies"}));
    auto val = [&in](const char *k) {
        for (const auto &kv : in.obfuscation)
            if (kv.first == QLatin1String(k))
                return kv.second;
        return QString();
    };
    CHECK(val("jc") == "4" && val("jmax") == "1000" && val("s4") == "0" && val("h4") == "404");
    CHECK(val("header_protection_key") == QString::fromLatin1(QByteArray::fromBase64(kHpk).toHex()));
    CHECK(val("random_trailers") == "1" && val("disable_cookies") == "0");
    CHECK(val("i1") == "<b 0xdeadbeef>");
    // mtu absent on the node: the platform default the live tunnel gets.
    SubscriptionNode noMtu = node;
    noMtu.mtu = 0;
    ScanAwgMiniInput d;
    CHECK(awgProbeInputFrom(sub, noMtu, QLatin1String(kPriv), 1376, d) && d.mtu == 1376);

    // The coordinator's half: the probe host + IP, then the contract config.
    in.probeHost = QStringLiteral("api.tribevpn.com");
    in.probeIp = QStringLiteral("201.34.134.103");
    in.echoTarget = QStringLiteral("10.7.0.1");
    QString why;
    const QString cfg = scanAwgMiniConfig(in, &why);
    CHECK(!cfg.isEmpty());
    CHECK(why.isEmpty());
    const QString uapi = QJsonDocument::fromJson(cfg.toUtf8()).object().value(QStringLiteral("uapi")).toString();
    CHECK(uapi.contains(QStringLiteral("jc=4\njmin=50\njmax=1000\n")));
    CHECK(uapi.contains(QStringLiteral("endpoint=38.180.164.134:585\n")));
    CHECK(uapi.contains(QStringLiteral("random_trailers=1\n")));

    // Nothing of it in any log line and nothing in the journal's redacted copy of the candidate.
    ScanHostCandidate c;
    c.id = QStringLiteral("9#awg");
    c.kind = ScanProbeKind::AwgMini;
    c.config = cfg;
    const QByteArray redacted = QJsonDocument(scanRedactForLog(scanHostCandidateToJson(c)).toObject()).toJson(QJsonDocument::Compact);
    const QStringList secrets{QLatin1String(kPriv), QLatin1String(kPsk), QLatin1String(kHpk),
                              QString::fromLatin1(QByteArray::fromBase64(kPriv).toHex()),
                              QString::fromLatin1(QByteArray::fromBase64(kPsk).toHex()), val("header_protection_key")};
    qInstallMessageHandler(nullptr);
    for (const QString &sec : secrets) {
        CHECK(!redacted.contains(sec.toUtf8()));
        for (const QString &line : g_log)
            CHECK(!line.contains(sec));
    }
    CHECK(g_log.isEmpty()); // the builder logs nothing at all

    // No config: not an own AWG node, no key, no address.
    ScanAwgMiniInput x;
    SubscriptionNode xray = node;
    xray.proto = QStringLiteral("xray");
    CHECK(!awgProbeInputFrom(sub, xray, QLatin1String(kPriv), 1376, x));
    SubscriptionNode up = node;
    up.upstream = UpstreamStub();
    CHECK(!awgProbeInputFrom(sub, up, QLatin1String(kPriv), 1376, x));
    CHECK(!awgProbeInputFrom(sub, node, QString(), 1376, x));
    Subscription noAddr;
    CHECK(!awgProbeInputFrom(noAddr, node, QLatin1String(kPriv), 1376, x));
    SubscriptionNode noPeer = node;
    noPeer.serverPubkey.clear();
    CHECK(!awgProbeInputFrom(sub, noPeer, QLatin1String(kPriv), 1376, x));
    // A host name endpoint: input given, endpoint empty -> the coordinator refuses awg_no_endpoint (no DNS).
    SubscriptionNode named = node;
    named.endpoint = QStringLiteral("ee1.example.net:585");
    ScanAwgMiniInput y;
    CHECK(awgProbeInputFrom(sub, named, QLatin1String(kPriv), 1376, y) && y.endpoint.isEmpty());
    y.probeHost = in.probeHost;
    y.probeIp = in.probeIp;
    QString why2;
    CHECK(scanAwgMiniConfig(y, &why2).isEmpty() && why2 == QLatin1String("awg_no_endpoint"));
    CHECK(endpointIsIpLiteral(QStringLiteral("[2a01:4f8::1]:585")));
    CHECK(!endpointIsIpLiteral(QStringLiteral("300.1.1.1:585")));
    CHECK(!endpointIsIpLiteral(QStringLiteral("1.2.3.4")));

    if (g_fail) {
        std::printf("scan_awg_input_check: %d FAILED\n", g_fail);
        return 1;
    }
    std::printf("scan_awg_input_check: OK\n");
    return 0;
}
