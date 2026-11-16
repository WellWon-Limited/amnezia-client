// service/server/tests/tribe_scan_ipc_check.cpp
// AVPN: the Scanner's desktop IPC end to end over a real QtRO connection on a local socket: the app's
// DaemonScanHost (client/core/serviceEngine/DaemonScanHost.cpp, production QtRO transport) against the
// service's TribeScanHost (service/server/tribe_scan.cpp) on stub bindings, with a stand-in IpcInterface
// source as the service's existing interface. Request and reply bytes cross unchanged (unicode, 1 MiB,
// overlapping requests), refusals come back as ipc_refused, the generation is pushed, stopAll reaches
// the engine, and an older service (IpcInterface only), no service, or a service that goes away are all
// "unavailable" with their reason - never a call into a missing slot. Run by build_tribe_scan.sh.
#include "tribe_scan.h"
#include "tribe_scan_fakes.h"

#include "core/serviceEngine/DaemonScanHost.h"
#include "core/serviceEngine/ScanHostContract.h"

#include "rep_ipc_interface_source.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QRemoteObjectHost>
#include <QThread>

#include <cstdio>
#include <memory>

using namespace avpn;

static int g_checks = 0;
static int g_failed = 0;
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        if (!(cond)) {                                                                                                 \
            ++g_failed;                                                                                                \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                       \
        }                                                                                                              \
    } while (0)

template <typename P>
static bool waitFor(P pred, int ms = 5000)
{
    QElapsedTimer t;
    t.start();
    while (!pred()) {
        if (t.elapsed() > ms)
            return false;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return true;
}

// The service's existing interface, as far as the witness replica needs it (never called here).
class WitnessSource : public IpcInterfaceSource
{
public:
    int createPrivilegedProcess() override { return -1; }
    int routeAddList(const QString &, const QStringList &) override { return 0; }
    bool clearSavedRoutes() override { return false; }
    bool routeDeleteList(const QString &, const QStringList &) override { return false; }
    bool flushDns() override { return false; }
    void resetIpStack() override {}
    bool checkAndInstallDriver() override { return false; }
    QStringList getTapList() override { return {}; }
    void cleanUp() override {}
    void setLogsEnabled(bool) override {}
    void clearLogs() override {}
    bool createTun(const QString &, const QString &) override { return false; }
    bool deleteTun(const QString &) override { return false; }
    bool StartRoutingIpv6() override { return false; }
    bool StopRoutingIpv6() override { return false; }
    bool disableKillSwitch() override { return false; }
    bool disableAllTraffic() override { return false; }
    bool refreshKillSwitch(bool) override { return false; }
    bool addKillSwitchAllowedRange(const QStringList) override { return false; }
    bool resetKillSwitchAllowedRange(const QStringList) override { return false; }
    bool enablePeerTraffic(const QJsonObject &) override { return false; }
    bool enableKillSwitch(const QJsonObject &, int) override { return false; }
    bool updateResolvers(const QString &, const QList<QHostAddress> &) override { return false; }
    bool restoreResolvers() override { return false; }
    bool xrayStart(const QString &) override { return false; }
    bool xrayStop() override { return false; }
    QJsonObject xrayRuntimeStatus(const QString &) override { return {}; }
    bool startNetworkCheck(const QString &, const QString &) override { return false; }
    bool stopNetworkCheck() override { return false; }
};

static TribeScanDeps testDeps()
{
    TribeScanDeps d = tribeScanServiceDeps();
    d.uplink = []() {
        TribeScanUplink u;
        u.name = QStringLiteral("en7");
        u.index = 7;
        u.gateway = QStringLiteral("192.0.2.1");
        u.up = true;
        return u;
    };
    d.armFirewall = [](const QString &) { return 0; };
    d.disarmFirewall = []() {};
    d.awgProbeBinary = []() { return QString(); };
    d.awgLive = []() {
        TribeScanAwgLive l;
        l.state = 0;
        return l;
    };
    d.killProbeChildren = []() { return TribeScanKillResult(); };
    d.routeMonitor = false;
    return d;
}

static QUrl testUrl(const char *tag)
{
    return QUrl(QStringLiteral("local:%1/tribe-scan-ipc-%2-%3").arg(QDir::tempPath()).arg(QCoreApplication::applicationPid()).arg(QLatin1String(tag)));
}

struct Reply {
    bool got = false;
    QByteArray bytes;
    int calls = 0;
};

static void send(DaemonScanHost &h, const QByteArray &req, Reply &r)
{
    h.sendMessage(req, [&r](const QByteArray &b) {
        r.got = true;
        r.bytes = b;
        ++r.calls;
    });
}

static void fullService()
{
    fake::engine().reset();
    const QUrl url = testUrl("full");
    auto node = std::make_unique<QRemoteObjectHost>(url);
    WitnessSource witness;
    qint64 clock = 1000;
    auto scan = std::make_unique<TribeScanHost>(testDeps());
    scan->setClockForTest([&clock]() { return clock; });
    CHECK(node->enableRemoting(&witness));
    CHECK(node->enableRemoting(scan.get())); // as localserver.cpp does

    DaemonScanHost h(DaemonScanHost::serviceTransport(url));
    int availabilityChanges = 0, generationChanges = 0;
    h.onAvailabilityChanged = [&]() { ++availabilityChanges; };
    h.onGenerationChanged = [&]() { ++generationChanges; };
    CHECK(waitFor([&]() { return h.availability() == ScanHostAvailability::Available; }));
    CHECK(h.unavailableReason().isEmpty() && availabilityChanges >= 1);

    // The generation is known before any scan: the service pushes it as a property.
    ScanNetSource g, want;
    CHECK(h.generation(g));
    CHECK(scanNetSourceFromJson(QJsonDocument::fromJson(scan->scanGeneration().toUtf8()).object(), want) && g == want);
    CHECK(g.source == QStringLiteral("service"));
    const int genBefore = generationChanges;
    scan->notePathEvent(true);
    CHECK(waitFor([&]() {
        ScanNetSource n;
        return h.generation(n) && n.counter == g.counter + 1;
    }));
    CHECK(generationChanges > genBefore);

    // Caps: the engine's bytes, unchanged.
    const QByteArray caps = R"({"type":"scan_caps","version":"tribe-scan-v1","max_full_concurrent":2,"max_leg_concurrent":6,"max_awg_concurrent":0,"can_verify_composite":true,"dns_plan":true,"reach_stage":true,"needs_vpn":false,"kinds":["xray_full","xray_leg"],"mem_mb":8,"platform":"macos"})";
    fake::engine().reply = [&](const QByteArray &, const QByteArray &) { return caps; };
    Reply r;
    send(h, R"({"action":"scan_caps"})", r);
    CHECK(!r.got); // never from inside sendMessage
    CHECK(waitFor([&]() { return r.got; }));
    CHECK(r.bytes == caps && r.calls == 1);
    CHECK(scanDecodeReply(r.bytes).kind == ScanHostReplyKind::Caps);

    // Unicode and a 1 MiB message cross both ways unchanged.
    const QByteArray big = QStringLiteral("{\"action\":\"scan_add\",\"scan_id\":\"Ж✓\",\"candidates\":[],\"pad\":\"%1\"}")
                               .arg(QString(1024 * 1024, QChar(0x0436)))
                               .toUtf8();
    const QByteArray uniReply = QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"Ж✓\",\"accepted\":0,\"mem_mb\":null}").toUtf8();
    fake::engine().reply = [&](const QByteArray &, const QByteArray &) { return uniReply; };
    clock += 2000;
    Reply rb;
    send(h, big, rb);
    CHECK(waitFor([&]() { return rb.got; }, 10000));
    CHECK(rb.bytes == uniReply);
    CHECK(!fake::engine().snapshot().isEmpty() && fake::engine().snapshot().last().message == big);

    // Overlapping requests: each reply finds its own request, whatever the order.
    fake::engine().reply = [](const QByteArray &msg, const QByteArray &) {
        const QString a = QJsonDocument::fromJson(msg).object().value(QLatin1String("action")).toString();
        return QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"%1\",\"accepted\":0,\"mem_mb\":null}").arg(a).toUtf8();
    };
    fake::engine().closeGate();
    clock += 2000;
    Reply ra, rf, rp;
    send(h, R"({"action":"scan_add","scan_id":"o","candidates":[]})", ra);
    send(h, R"({"action":"scan_freeze","scan_id":"o"})", rf);
    send(h, R"({"action":"scan_poll","scan_id":"o","since":0})", rp);
    CHECK(waitFor([&]() { return h.pendingCount() == 3; }, 100));
    fake::engine().openGate();
    CHECK(waitFor([&]() { return ra.got && rf.got && rp.got; }));
    CHECK(QJsonDocument::fromJson(ra.bytes).object().value(QLatin1String("scan_id")).toString() == QStringLiteral("scan_add"));
    CHECK(QJsonDocument::fromJson(rf.bytes).object().value(QLatin1String("scan_id")).toString() == QStringLiteral("scan_freeze"));
    CHECK(QJsonDocument::fromJson(rp.bytes).object().value(QLatin1String("scan_id")).toString() == QStringLiteral("scan_poll"));
    CHECK(h.pendingCount() == 0);

    // The service's own bounds come back as ipc_refused (decoded as an open-set error, never success).
    clock += 10000;
    int refused = 0, answered = 0;
    QList<std::shared_ptr<Reply>> many;
    for (int i = 0; i < kTribeScanRateMax + 5; ++i) {
        auto x = std::make_shared<Reply>();
        many << x;
        h.sendMessage(R"({"action":"scan_poll","scan_id":"o","since":0})", [x](const QByteArray &b) {
            x->got = true;
            x->bytes = b;
        });
    }
    CHECK(waitFor([&]() {
        for (const auto &x : many)
            if (!x->got)
                return false;
        return true;
    }));
    for (const auto &x : many) {
        const ScanHostReply d = scanDecodeReply(x->bytes);
        if (d.kind == ScanHostReplyKind::Error && d.errorCode == QStringLiteral("ipc_refused"))
            ++refused;
        else
            ++answered;
    }
    CHECK(refused >= 5 && answered >= 1);
    CHECK(scanDecodeReply(daemonScanRefusalReply(2)).error == ScanHostError::Other);

    // stopAll reaches the engine once a scan ran (the service only calls it then).
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"type":"scan_ack","scan_id":"s","accepted":0,"mem_mb":null})"); };
    clock += 20000;
    ScanStartRequest sr;
    sr.scanId = QStringLiteral("s");
    sr.deadlineMs = 5000;
    sr.probeBase = QStringLiteral("https://198.51.100.7");
    sr.token = QStringLiteral("tok-0123456789abcdef");
    Reply rs;
    send(h, scanCompact(scanEncodeStart(sr)), rs);
    CHECK(waitFor([&]() { return rs.got; }));
    CHECK(scanDecodeReply(rs.bytes).kind == ScanHostReplyKind::Ack);
    h.stopAll();
    CHECK(waitFor([]() {
        for (const fake::Call &c : fake::engine().snapshot())
            if (c.what == QStringLiteral("stop_all") && c.waitMs == kTribeScanStopForAppMs)
                return true;
        return false;
    }));

    // The service goes away with a request in flight: that reply comes back empty, the host turns
    // unavailable (service_off), and a later message gets no answer at once.
    fake::engine().closeGate();
    clock += 2000;
    Reply rgone;
    send(h, R"({"action":"scan_poll","scan_id":"s","since":0})", rgone);
    CHECK(waitFor([&]() { return h.pendingCount() == 1; }, 100));
    node.reset();
    fake::engine().openGate();
    CHECK(waitFor([&]() { return rgone.got; }, 8000));
    CHECK(rgone.bytes.isEmpty() && rgone.calls == 1);
    CHECK(waitFor([&]() { return h.availability() == ScanHostAvailability::Unavailable; }));
    CHECK(h.unavailableReason() == QStringLiteral("service_off"));
    ScanNetSource none;
    CHECK(!h.generation(none));
    Reply rafter;
    send(h, R"({"action":"scan_caps"})", rafter);
    CHECK(waitFor([&]() { return rafter.got; }));
    CHECK(rafter.bytes.isEmpty() && rafter.calls == 1);
    scan.reset();
}

static void olderService()
{
    fake::engine().reset();
    const QUrl url = testUrl("old");
    QRemoteObjectHost node(url);
    WitnessSource witness;
    CHECK(node.enableRemoting(&witness)); // a service from before the Scanner: no IpcScanInterface
    DaemonScanHost h(DaemonScanHost::serviceTransport(url));
    CHECK(h.availability() == ScanHostAvailability::Unavailable);
    CHECK(waitFor([&]() { return h.unavailableReason() == QStringLiteral("service_old"); }, kDaemonScanOldGraceMs + 3000));
    CHECK(h.availability() == ScanHostAvailability::Unavailable);
    Reply r;
    send(h, R"({"action":"scan_caps"})", r);
    CHECK(waitFor([&]() { return r.got; }));
    CHECK(r.bytes.isEmpty() && r.calls == 1);
    CHECK(fake::engine().snapshot().isEmpty());
}

// The production order (service/server/localserver.cpp:36-44): a plain QLocalServer, the first connection
// is handed to a URL-less QRemoteObjectHost, and only then are both sources enabled.
static void lazyRemotingLikeLocalServer()
{
    fake::engine().reset();
    const QString path = QStringLiteral("%1/tribe-scan-ipc-%2-lazy").arg(QDir::tempPath()).arg(QCoreApplication::applicationPid());
    QLocalServer::removeServer(path);
    QLocalServer server;
    server.setSocketOptions(QLocalServer::WorldAccessOption);
    CHECK(server.listen(path));
    QRemoteObjectHost node;
    WitnessSource witness;
    TribeScanHost scan(testDeps());
    bool enabled = false;
    QObject::connect(&server, &QLocalServer::newConnection, &server, [&]() {
        while (QLocalSocket *sock = server.nextPendingConnection()) {
            node.addHostSideConnection(sock);
            if (!enabled) {
                enabled = true;
                node.enableRemoting(&witness);
                node.enableRemoting(&scan);
            }
        }
    });
    DaemonScanHost h(DaemonScanHost::serviceTransport(QUrl(QStringLiteral("local:") + path)));
    CHECK(waitFor([&]() { return h.availability() == ScanHostAvailability::Available; }));
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"type":"scan_ack","scan_id":"z","accepted":0,"mem_mb":null})"); };
    Reply r;
    send(h, R"({"action":"scan_freeze","scan_id":"z"})", r);
    CHECK(waitFor([&]() { return r.got; }));
    CHECK(r.bytes == QByteArray(R"({"type":"scan_ack","scan_id":"z","accepted":0,"mem_mb":null})"));
    // A second app connection (the app's own IpcClient node is one already) sees the same sources.
    DaemonScanHost h2(DaemonScanHost::serviceTransport(QUrl(QStringLiteral("local:") + path)));
    CHECK(waitFor([&]() { return h2.availability() == ScanHostAvailability::Available; }));
}

static void noService()
{
    DaemonScanHost h(DaemonScanHost::serviceTransport(testUrl("none")));
    CHECK(h.unavailableReason() == QStringLiteral("connecting"));
    CHECK(waitFor([&]() { return h.unavailableReason() == QStringLiteral("service_off"); }, kDaemonScanStartupMs + 2000));
    CHECK(h.availability() == ScanHostAvailability::Unavailable);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    fullService();
    lazyRemotingLikeLocalServer();
    olderService();
    noService();
    std::printf("tribe_scan_ipc_check: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
