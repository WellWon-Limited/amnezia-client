// service/server/tests/tribe_scan_check.cpp
// AVPN: the Scanner's desktop probe host (service/server/tribe_scan.{h,cpp}) on stub bindings
// (fake_bindings/amnezia_xray.h + tribe_scan_fakes.cpp): pure parts, the relay round trip, the shared
// host vectors through the relay byte for byte, the no-uplink refusal, stop-all ordering, the pf
// exemption's lifetime, size / rate / queue bounds, the path generation, no tunnel API from the relay,
// and no secret, host or interface name in the service log. Run by build_tribe_scan.sh.
#include "tribe_scan.h"
#include "tribe_scan_fakes.h"

#include "core/serviceEngine/ScanHostContract.h"

#include <QCoreApplication>
#include <QHash>
#include <QElapsedTimer>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutex>
#include <QTemporaryDir>
#include <QThread>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <cstring>
#include <thread>
#include <unistd.h>
#include <utility>

#ifdef Q_OS_MACOS
    #include <arpa/inet.h>
    #include <csignal>
    #include <libproc.h>
    #include <net/if.h>
    #include <net/route.h>
    #include <netinet/in.h>
    #include <spawn.h>
    #include <sys/wait.h>
extern char **environ;
#endif

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
#define CHECK_EQ(a, b)                                                                                                 \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        if (!((a) == (b))) {                                                                                           \
            ++g_failed;                                                                                                \
            std::fprintf(stderr, "FAIL %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b);                               \
        }                                                                                                              \
    } while (0)

// --- the service log, captured -------------------------------------------------------------------------------------

static QMutex g_logMutex;
static QStringList g_log;
static void captureLog(QtMsgType, const QMessageLogContext &, const QString &msg)
{
    QMutexLocker l(&g_logMutex);
    g_log << msg;
}

template <typename P>
static bool waitFor(P pred, int ms = 3000)
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

static TribeScanUplink phys()
{
    TribeScanUplink u;
    u.name = QStringLiteral("en7");
    u.index = 7;
    u.gateway = QStringLiteral("192.0.2.1");
    u.addresses = {QStringLiteral("192.0.2.10"), QStringLiteral("2001:db8::10")};
    u.up = true;
    return u;
}

static QByteArray compact(const QJsonValue &v)
{
    if (v.isString())
        return v.toString().toUtf8();
    return QJsonDocument(v.toObject()).toJson(QJsonDocument::Compact);
}

static QJsonObject obj(const QByteArray &b)
{
    return QJsonDocument::fromJson(b).object();
}

struct Harness {
    qint64 clock = 100000;
    std::atomic<int> armResult{1};
    std::atomic<int> killKilled{0}; // what the fake belt kill reports
    std::atomic<int> killAlive{0};
    QHash<quint64, QByteArray> replies;
    TribeScanUplink uplink = phys();
    QMutex uplinkMutex;
    QString awgBinary; // guarded by uplinkMutex (read on the worker)
    TribeScanAwgLive awgLive = [] {
        TribeScanAwgLive l;
        l.state = 0;
        return l;
    }();
    std::unique_ptr<TribeScanHost> host;
    quint64 nextId = 1;
    // The uplink's half routes: what armRoutes answers (guarded by uplinkMutex; result 0 = not needed, noted only
    // when it is not 0, so the order lists of the other checks stay as they are), the leftover clears counted.
    TribeScanRouteArm routeArm;
    std::atomic<int> routeClears{0};
    QList<quint32> unrouted; // entry addresses a pinned socket cannot reach (guarded by uplinkMutex)

    Harness()
    {
        TribeScanDeps d = tribeScanServiceDeps(); // the real glue to the (fake) bindings
        d.uplink = [this]() {
            QMutexLocker l(&uplinkMutex);
            return uplink;
        };
        d.armFirewall = [this](const QString &ifname) {
            fake::engine().note(QStringLiteral("arm:") + ifname);
            return armResult.load();
        };
        d.disarmFirewall = []() { fake::engine().note(QStringLiteral("disarm")); };
        d.armRoutes = [this](const TribeScanUplink &u) {
            QMutexLocker l(&uplinkMutex);
            if (routeArm.result != 0)
                fake::engine().note(QStringLiteral("routes:arm:%1").arg(u.index));
            return routeArm;
        };
        d.disarmRoutes = [](const QList<TribeScanHalfRoute> &added) {
            fake::engine().note(QStringLiteral("routes:disarm:%1").arg(added.size()));
        };
        d.clearLeftoverRoutes = [this]() { ++routeClears; };
        d.pinnedRoute = [this](int, quint32 ip) {
            QMutexLocker l(&uplinkMutex);
            return !unrouted.contains(ip);
        };
        d.killProbeChildren = [this]() {
            fake::engine().note(QStringLiteral("kill"));
            TribeScanKillResult k;
            k.killed = killKilled.load();
            k.alive = killAlive.load();
            return k;
        };
        d.awgProbeBinary = [this]() {
            QMutexLocker l(&uplinkMutex);
            return awgBinary;
        };
        d.awgLive = [this]() { return awgLive; }; // main thread, like the daemon
        d.routeMonitor = false;
        host = std::make_unique<TribeScanHost>(d);
        host->setClockForTest([this]() { return clock; });
        QObject::connect(host.get(), &IpcScanInterfaceSource::scanReply, host.get(),
                         [this](quint64 id, const QString &r) { replies.insert(id, r.toUtf8()); });
    }
    void setUplink(const TribeScanUplink &u)
    {
        QMutexLocker l(&uplinkMutex);
        uplink = u;
    }
    void setRouteArm(const TribeScanRouteArm &a)
    {
        QMutexLocker l(&uplinkMutex);
        routeArm = a;
    }
    // Submits and waits for the reply; returns the slot's code, the reply in *out.
    int send(const QByteArray &message, QByteArray *out = nullptr, int waitMs = 3000)
    {
        const quint64 id = nextId++;
        const int code = host->scanSubmit(id, QString::fromUtf8(message));
        if (code != 0)
            return code;
        if (!waitFor([&]() { return replies.contains(id); }, waitMs))
            return -100;
        if (out)
            *out = replies.value(id);
        return 0;
    }
};

static int countOf(const QList<QString> &l, const QString &prefix)
{
    int n = 0;
    for (const QString &s : l)
        n += s.startsWith(prefix) ? 1 : 0;
    return n;
}

static QByteArray startRequest(const QString &scanId, qint64 deadlineMs = 8000)
{
    ScanStartRequest r;
    r.scanId = scanId;
    r.deadlineMs = deadlineMs;
    r.probeBase = QStringLiteral("https://198.51.100.7");
    r.token = QStringLiteral("SECRET-TOKEN-0123456789abcdef");
    ScanHostCandidate c;
    c.id = QStringLiteral("2:xray");
    c.kind = ScanProbeKind::XrayFull;
    c.config = QStringLiteral("{\"SECRET-CONFIG\":\"203.0.113.9\"}");
    c.entryIp = QStringLiteral("203.0.113.9");
    c.entryPort = 443;
    c.reachAtMs = 0;
    c.costBytes = 83456;
    r.candidates << c;
    return scanCompact(scanEncodeStart(r));
}

// --- pure parts --------------------------------------------------------------------------------------------------

static void pureParts()
{
    TribeScanRateWindow w(1000, 3);
    CHECK(w.admit(0) && w.admit(10) && w.admit(999));
    CHECK(!w.admit(999));
    CHECK(w.admit(1000)); // the event at 0 left the window
    CHECK(!w.admit(1001));

    CHECK(tribeScanIsVirtualIfname(QStringLiteral("utun4")) && tribeScanIsVirtualIfname(QStringLiteral("ipsec0"))
          && tribeScanIsVirtualIfname(QStringLiteral("ppp0")) && tribeScanIsVirtualIfname(QStringLiteral("bridge100")));
    CHECK(!tribeScanIsVirtualIfname(QStringLiteral("en0")) && !tribeScanIsVirtualIfname(QStringLiteral("Ethernet 2")));
    TribeScanUplink u = phys();
    CHECK(tribeScanUplinkUsable(u));
    TribeScanUplink v = u;
    v.name = QStringLiteral("utun3");
    CHECK(!tribeScanUplinkUsable(v));
    v = u;
    v.up = false;
    CHECK(!tribeScanUplinkUsable(v));
    v = u;
    v.loopback = true;
    CHECK(!tribeScanUplinkUsable(v));
    v = u;
    v.virtualType = true; // wintun / wireguard-nt
    CHECK(!tribeScanUplinkUsable(v));
    v = u;
    v.index = 0;
    CHECK(!tribeScanUplinkUsable(v));
    CHECK(!tribeScanUplinkUsable(TribeScanUplink()));

    const QByteArray fp = tribeScanUplinkFingerprint(u);
    CHECK(!fp.isEmpty());
    v = u;
    std::reverse(v.addresses.begin(), v.addresses.end());
    CHECK_EQ(tribeScanUplinkFingerprint(v), fp); // a set: order does not matter
    v = u;
    v.gateway = QStringLiteral("192.0.2.254");
    CHECK(tribeScanUplinkFingerprint(v) != fp);
    v = u;
    v.addresses << QStringLiteral("192.0.2.11");
    CHECK(tribeScanUplinkFingerprint(v) != fp);
    v = u;
    v.index = 8;
    CHECK(tribeScanUplinkFingerprint(v) != fp);
    CHECK(tribeScanUplinkFingerprint(TribeScanUplink()).isEmpty());

    TribeScanGeneration g(0x5eed5eed5eed5eedULL);
    CHECK(!g.observe(fp, false)); // baseline
    CHECK_EQ(g.now().counter, qint64(0));
    CHECK(!g.observe(fp, false));
    CHECK(g.observe(fp, true)); // an interruption with the same end state still counts
    CHECK_EQ(g.now().counter, qint64(1));
    CHECK(g.observe(QByteArray(), false)); // the uplink is gone
    CHECK(!g.observe(QByteArray(), false));
    CHECK(g.observe(fp, false)); // and back
    CHECK_EQ(g.now().counter, qint64(3));
    CHECK_EQ(g.now().source, QStringLiteral("service"));
    CHECK_EQ(g.now().epoch, quint64(0x5eed5eed5eed5eedULL));

    const ScanNetSource gen = g.now();
    const QJsonObject gj = obj(tribeScanGenerationJson(gen));
    ScanNetSource back;
    CHECK(scanNetSourceFromJson(gj, back) && back == gen);
    CHECK_EQ(gj.value(QLatin1String("epoch")).toString(), QStringLiteral("5eed5eed5eed5eed"));

    const QJsonObject start = obj(tribeScanHostOptions(gen, &u));
    CHECK_EQ(start.value(QLatin1String("bind_interface_index")).toInt(), 7);
    CHECK_EQ(start.value(QLatin1String("bind_interface")).toString(), QStringLiteral("en7"));
    CHECK(scanNetSourceFromJson(start.value(QLatin1String("gen")), back) && back == gen);
    TribeScanUplink win = u;
    win.name = QStringLiteral("Ethernet 2");
    const QJsonObject startWin = obj(tribeScanHostOptions(gen, &win));
    CHECK(!startWin.contains(QLatin1String("bind_interface")) && startWin.value(QLatin1String("bind_interface_index")).toInt() == 7);
    const QJsonObject other = obj(tribeScanHostOptions(gen));
    CHECK_EQ(other.keys(), QStringList{QStringLiteral("gen")});

    const QStringList six = {"scan_caps", "scan_start", "scan_add", "scan_poll", "scan_freeze", "scan_cancel"};
    for (const QString &a : six)
        CHECK(tribeScanKnownAction(a));
    CHECK(!tribeScanKnownAction(QStringLiteral("status")) && !tribeScanKnownAction(QStringLiteral("scan_teleport"))
          && !tribeScanKnownAction(QString()));

    TribeScanRequestInfo ri = tribeScanInspectRequest(startRequest(QStringLiteral("s9"), 7000));
    CHECK(ri.object && ri.action == QStringLiteral("scan_start") && ri.scanId == QStringLiteral("s9") && ri.deadlineMs == 7000);
    CHECK(!tribeScanInspectRequest("{nope").object && !tribeScanInspectRequest("[1]").object);
    TribeScanReplyInfo pi = tribeScanInspectReply(R"({"type":"scan_progress","scan_id":"s9","final":true})");
    CHECK(pi.type == QStringLiteral("scan_progress") && pi.scanId == QStringLiteral("s9") && pi.finalTotals);
    CHECK(tribeScanInspectReply(R"({"error":"memory"})").error == QStringLiteral("memory"));
    CHECK(tribeScanInspectReply("<html>").type.isEmpty());

#ifdef Q_OS_MACOS
    rt_msghdr rt{};
    rt.rtm_msglen = sizeof(rt);
    rt.rtm_version = RTM_VERSION;
    rt.rtm_type = RTM_ADD;
    rt.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
    rt.rtm_index = 7;
    auto ev = [](const void *m, size_t len, int idx) { return tribeScanRouteEvent(static_cast<const char *>(m), qsizetype(len), idx); };
    TribeScanRouteEvent e = ev(&rt, sizeof(rt), 7);
    CHECK(e.resample && !e.loss);
    rt.rtm_type = RTM_DELETE;
    e = ev(&rt, sizeof(rt), 7);
    CHECK(e.resample && e.loss); // the uplink's gateway route went away
    e = ev(&rt, sizeof(rt), 9);
    CHECK(e.resample && !e.loss); // another interface's
    rt.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_WASCLONED;
    e = ev(&rt, sizeof(rt), 7);
    CHECK(!e.resample && !e.loss); // per-destination clones churn: ignored
    rt.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_HOST;
    e = ev(&rt, sizeof(rt), 7);
    CHECK(!e.resample && !e.loss); // host routes (exclusions, Xray /32s): ignored
    rt.rtm_flags = RTF_UP;
    e = ev(&rt, sizeof(rt), 7);
    CHECK(!e.resample); // on-link routes: ignored
    rt.rtm_flags = RTF_UP | RTF_GATEWAY;
    rt.rtm_version = RTM_VERSION + 1;
    e = ev(&rt, sizeof(rt), 7);
    CHECK(!e.resample && !e.loss);
    rt.rtm_version = RTM_VERSION;
    e = ev(&rt, 3, 7);
    CHECK(!e.resample);
    ifa_msghdr ifa{};
    ifa.ifam_msglen = sizeof(ifa);
    ifa.ifam_version = RTM_VERSION;
    ifa.ifam_type = RTM_NEWADDR;
    ifa.ifam_index = 7;
    e = ev(&ifa, sizeof(ifa), 7);
    CHECK(e.resample && !e.loss);
    ifa.ifam_type = RTM_DELADDR;
    e = ev(&ifa, sizeof(ifa), 7);
    CHECK(e.resample && e.loss);
    if_msghdr ifm{};
    ifm.ifm_msglen = sizeof(ifm);
    ifm.ifm_version = RTM_VERSION;
    ifm.ifm_type = RTM_IFINFO;
    ifm.ifm_index = 7;
    ifm.ifm_flags = IFF_UP | IFF_RUNNING;
    e = ev(&ifm, sizeof(ifm), 7);
    CHECK(e.resample && !e.loss);
    ifm.ifm_flags = IFF_UP;
    e = ev(&ifm, sizeof(ifm), 7);
    CHECK(e.resample && e.loss); // link down
    e = ev(&ifm, sizeof(ifm), 0);
    CHECK(e.resample && !e.loss); // no uplink known yet
#endif
}

// --- relay ------------------------------------------------------------------------------------------------------

static void relayRoundTrip()
{
    fake::engine().reset();
    Harness h;
    const QByteArray capsReply = R"({"type":"scan_caps","version":"tribe-scan-v1","max_full_concurrent":2,"max_leg_concurrent":6,"max_awg_concurrent":0,"can_verify_composite":true,"dns_plan":true,"reach_stage":true,"needs_vpn":false,"kinds":["xray_full","xray_leg"],"mem_mb":8,"platform":"macos"})";
    fake::engine().reply = [&](const QByteArray &, const QByteArray &) { return capsReply; };
    QByteArray r;
    CHECK_EQ(h.send(R"({"action":"scan_caps"})", &r), 0);
    CHECK_EQ(r, capsReply); // caps as the engine said, byte for byte
    const QList<fake::Call> calls = fake::engine().snapshot();
    CHECK(calls.size() == 1 && calls.first().message == QByteArray(R"({"action":"scan_caps"})"));
    // A non-start message carries only the service's generation.
    CHECK(calls.size() == 1
          && obj(calls.first().options).keys() == (QStringList{QStringLiteral("gen"), QStringLiteral("host_epoch")}));

    // Unicode survives the QString hop both ways.
    const QByteArray uni = QStringLiteral("{\"action\":\"scan_poll\",\"scan_id\":\"с-Ж-✓\",\"since\":0}").toUtf8();
    const QByteArray uniReply = QStringLiteral("{\"type\":\"scan_progress\",\"scan_id\":\"с-Ж-✓\",\"note\":\"ü\"}").toUtf8();
    fake::engine().reply = [&](const QByteArray &, const QByteArray &) { return uniReply; };
    CHECK_EQ(h.send(uni, &r), 0);
    CHECK_EQ(r, uniReply);
    CHECK_EQ(fake::engine().snapshot().last().message, uni);
}

static void vectorReplay(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        std::fprintf(stderr, "FAIL: no vectors at %s\n", qPrintable(path));
        ++g_failed;
        return;
    }
    const QJsonObject vf = QJsonDocument::fromJson(f.readAll()).object();
    fake::engine().reset();
    Harness h;
    // A tunnel callback registered the way Xray::startXray registers its own; it must never run for a
    // probe message, and the relay must never touch the tunnel API.
    amnezia_xray_setsockcallback([](uintptr_t, void *) { ++fake::engine().tunnelCallbackInvocations; }, nullptr);
    const QByteArray marker = R"({"type":"scan_ack","scan_id":"vec","accepted":0,"mem_mb":null})";
    fake::engine().reply = [&](const QByteArray &, const QByteArray &) { return marker; };

    int requests = 0;
    for (const QJsonValue &v : vf.value(QLatin1String("requests")).toArray()) {
        const QJsonObject vec = v.toObject();
        const QString name = vec.value(QLatin1String("name")).toString();
        const QByteArray bytes = compact(vec.value(QLatin1String("json")));
        const QJsonObject expect = vec.value(QLatin1String("expect")).toObject();
        const QString err = expect.value(QLatin1String("error")).toString();
        h.clock += 2000; // stays under both rate bounds
        const int before = fake::engine().snapshot().size();
        QByteArray r;
        const int code = h.send(bytes, &r);
        CHECK_EQ(code, 0);
        const QList<fake::Call> calls = fake::engine().snapshot();
        const bool serviceAnswers = err == QLatin1String("unknown_action") || expect.value(QLatin1String("detail")).toString() == QLatin1String("json");
        if (serviceAnswers) {
            // Never reaches the engine; the service's own reply decodes as the vector says.
            CHECK_EQ(calls.size(), before);
            const ScanHostReply d = scanDecodeReply(r);
            CHECK(d.kind == ScanHostReplyKind::Error && QLatin1String(scanHostErrorName(d.error)) == err);
            if (err == QLatin1String("bad_request"))
                CHECK_EQ(d.detail, QStringLiteral("json"));
        } else {
            // Relayed byte for byte (the engine decides bad_request / version itself).
            const bool relayed = calls.size() == before + 1 && calls.last().message == bytes;
            if (!relayed)
                std::fprintf(stderr, "  request vector %s not relayed byte for byte\n", qPrintable(name));
            CHECK(relayed);
            CHECK_EQ(r, marker);
        }
        ++requests;
    }

    int replies = 0;
    for (const QJsonValue &v : vf.value(QLatin1String("replies")).toArray()) {
        const QJsonObject vec = v.toObject();
        const QString name = vec.value(QLatin1String("name")).toString();
        const QByteArray bytes = compact(vec.value(QLatin1String("json")));
        const QString err = vec.value(QLatin1String("expect")).toObject().value(QLatin1String("error")).toString();
        fake::engine().reply = [&](const QByteArray &, const QByteArray &) { return bytes; };
        h.clock += 50;
        QByteArray r = "unset";
        CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"scan-1789000000000-1","since":0})", &r), 0);
        if (r != bytes)
            std::fprintf(stderr, "  reply vector %s changed in the relay\n", qPrintable(name));
        CHECK_EQ(r, bytes);
        const ScanHostReply d = scanDecodeReply(r);
        if (err.isEmpty())
            CHECK(d.kind != ScanHostReplyKind::Error);
        else
            CHECK(d.kind == ScanHostReplyKind::Error && QLatin1String(scanHostErrorName(d.error)) == err);
        ++replies;
    }
    std::printf("vectors: %d requests and %d replies through the relay\n", requests, replies);
    CHECK(requests >= 19 && replies >= 30);

    CHECK_EQ(fake::engine().tunnelCallbackInvocations.load(), 0);
    CHECK_EQ(fake::engine().setSockCallbackCalls.load(), 1); // this test's own registration only
    CHECK_EQ(fake::engine().configureCalls.load(), 0);
    CHECK_EQ(fake::engine().startCalls.load(), 0);
    CHECK_EQ(fake::engine().stopCalls.load(), 0);
    CHECK_EQ(fake::engine().logHandlerCalls.load(), 0);
}

static void startPath()
{
    fake::engine().reset();
    Harness h;
    const auto ackStart = [](const QByteArray &msg, const QByteArray &) -> QByteArray {
        const QJsonObject o = obj(msg);
        if (o.value(QLatin1String("action")).toString() == QLatin1String("scan_start"))
            return QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"%1\",\"accepted\":1,\"mem_mb\":9}")
                .arg(o.value(QLatin1String("scan_id")).toString())
                .toUtf8();
        return R"({"type":"scan_progress","scan_id":"other","seq":0,"phase":"data","items":[],"bytes_spent":0,"done":false})";
    };
    fake::engine().reply = ackStart;

    // No physical uplink: the contract's refusal, without the engine, without an exemption.
    for (const TribeScanUplink &bad : {TribeScanUplink(), [] {
                                           TribeScanUplink u = phys();
                                           u.name = QStringLiteral("utun4"); // a foreign VPN owns the default route
                                           return u;
                                       }(),
                                       [] {
                                           TribeScanUplink u = phys();
                                           u.loopback = true;
                                           return u;
                                       }()}) {
        h.setUplink(bad);
        fake::engine().reset();
        QByteArray r;
        h.clock += 2000;
        CHECK_EQ(h.send(startRequest(QStringLiteral("s-noup")), &r), 0);
        CHECK_EQ(r, QByteArray(R"({"error":"bad_request","detail":"host_options.bind_interface"})"));
        const ScanHostReply d = scanDecodeReply(r);
        CHECK(d.kind == ScanHostReplyKind::Error && d.error == ScanHostError::BadRequest
              && d.detail == QStringLiteral("host_options.bind_interface"));
        CHECK(fake::engine().snapshot().isEmpty());
        CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("arm:")), 0);
    }

    // Before any scan: a tunnel change does not even call the engine.
    fake::engine().reset();
    fake::engine().reply = ackStart;
    h.setUplink(phys());
    h.host->stopAllBeforeTunnelChange("xray_start");
    tribeScanBeforeTunnelChange("awg_activate");
    CHECK(fake::engine().snapshot().isEmpty());

    // A start: exemption first, then the engine with the uplink and the generation.
    QByteArray r;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("s1")), &r), 0);
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Ack);
    QList<fake::Call> calls = fake::engine().snapshot();
    CHECK(calls.size() == 1);
    if (calls.size() == 1) {
        const QJsonObject opts = obj(calls.first().options);
        CHECK_EQ(opts.value(QLatin1String("bind_interface_index")).toInt(), 7);
        CHECK_EQ(opts.value(QLatin1String("bind_interface")).toString(), QStringLiteral("en7"));
        ScanNetSource g;
        CHECK(scanNetSourceFromJson(opts.value(QLatin1String("gen")), g) && g.source == QStringLiteral("service"));
        CHECK_EQ(calls.first().message, startRequest(QStringLiteral("s1")));
    }
    // The daemon's hook (Daemon::activate) ends the scan; the exemption goes after the engine stopped it.
    tribeScanBeforeTunnelChange("awg_activate");
    QList<QString> order = fake::engine().orderSnapshot();
    const QList<QString> want = {QStringLiteral("arm:en7"), QStringLiteral("scan_message:scan_start"),
                                 QStringLiteral("stop_all:2000"), QStringLiteral("disarm")}; // no kill: the engine confirmed
    if (order != want)
        std::fprintf(stderr, "  order: %s\n", qPrintable(order.join(QLatin1Char(' '))));
    CHECK_EQ(order, want);

    // A final progress of the active scan removes its exemption; one of another scan does not.
    fake::engine().reset();
    fake::engine().reply = [&](const QByteArray &msg, const QByteArray &) -> QByteArray {
        const QJsonObject o = obj(msg);
        const QString a = o.value(QLatin1String("action")).toString();
        if (a == QLatin1String("scan_start"))
            return R"({"type":"scan_ack","scan_id":"s2","accepted":1,"mem_mb":9})";
        if (o.value(QLatin1String("scan_id")).toString() == QLatin1String("old"))
            return R"({"type":"scan_progress","scan_id":"old","seq":3,"phase":"done","items":[],"bytes_spent":1,"done":true,"final":true})";
        return R"({"type":"scan_progress","scan_id":"s2","seq":3,"phase":"done","items":[],"bytes_spent":1,"done":true,"final":true})";
    };
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("s2")), &r), 0);
    CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"old","since":0})", &r), 0);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")), 0);
    CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"s2","since":0})", &r), 0);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")), 1);

    // A start the engine refuses keeps no exemption.
    fake::engine().reset();
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"error":"bad_request","detail":"probe.token"})"); };
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("s3")), &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"bad_request","detail":"probe.token"})"));
    order = fake::engine().orderSnapshot();
    CHECK(order == (QList<QString>{QStringLiteral("arm:en7"), QStringLiteral("scan_message:scan_start"), QStringLiteral("disarm")}));

    // The kill switch is ours but its exemption does not load: the scan is refused (fail closed), the
    // engine never sees it; "not needed" (no kill switch of ours) starts normally without an exemption.
    fake::engine().reset();
    fake::engine().reply = ackStart;
    h.armResult = -1;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("s-fw")), &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"internal","detail":"kill_switch_exemption"})"));
    CHECK(scanDecodeReply(r).error == ScanHostError::Internal);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("scan_message:")), 0);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("stop_all:500")), 1); // the older scan ends too
    h.armResult = 0;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("s-nofw")), &r), 0);
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Ack);
    tribeScanBeforeTunnelChange("xray_stop");
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")), 0); // nothing was armed
    h.armResult = 1;

    // A scan the app never closes: the exemption ends at deadline + grace by itself (the timer's arming and
    // firing through the seam - no wall time; the default timer is a precise single shot).
    struct Armed {
        qint64 ms;
        std::function<void()> fire;
    };
    QList<Armed> armed;
    h.host->setDisarmTimerForTest([&](qint64 ms, std::function<void()> fire) { armed << Armed{ms, std::move(fire)}; });
    fake::engine().reset();
    fake::engine().reply = [](const QByteArray &msg, const QByteArray &) {
        return QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"%1\",\"accepted\":1,\"mem_mb\":9}")
            .arg(obj(msg).value(QLatin1String("scan_id")).toString())
            .toUtf8();
    };
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("s4"), 1000), &r), 0);
    CHECK(waitFor([&]() { return armed.size() == 1; }));
    CHECK(armed.size() == 1 && armed.first().ms == 1000 + kTribeScanDisarmGraceMs);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")), 0);
    if (!armed.isEmpty())
        armed.first().fire();
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")), 1);
    // A deadline of an older scan does nothing to the scan that replaced it.
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("s4b"), 120000), &r), 0);
    CHECK(waitFor([&]() { return armed.size() == 2; }));
    CHECK(armed.size() == 2 && armed.last().ms == 120000 + kTribeScanDisarmGraceMs);
    if (!armed.isEmpty())
        armed.first().fire();
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")), 1);
    if (armed.size() == 2)
        armed.last().fire();
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")), 2);
    h.host->setDisarmTimerForTest(nullptr);

    // The app's scanStopAll reaches the engine (worker) and removes the exemption.
    fake::engine().reset();
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"type":"scan_ack","scan_id":"s5","accepted":1,"mem_mb":9})"); };
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("s5")), &r), 0);
    CHECK_EQ(h.host->scanStopAll(), 0);
    CHECK(waitFor([]() { return countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")) == 1; }));
    order = fake::engine().orderSnapshot();
    CHECK(order.size() >= 4 && order.at(2) == QStringLiteral("stop_all:500") && order.at(3) == QStringLiteral("disarm"));

    // scan_start rate: 6 in 10 s, the 7th is the service's refusal and never reaches the engine.
    fake::engine().reset();
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"type":"scan_ack","scan_id":"r","accepted":1,"mem_mb":9})"); };
    h.clock += 20000;
    int acked = 0;
    for (int i = 0; i < kTribeScanStartMax; ++i) {
        h.clock += 100;
        acked += h.send(startRequest(QStringLiteral("r%1").arg(i)), &r) == 0 && scanDecodeReply(r).kind == ScanHostReplyKind::Ack;
    }
    CHECK_EQ(acked, kTribeScanStartMax);
    h.clock += 100;
    CHECK_EQ(h.send(startRequest(QStringLiteral("r-over")), &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"rate_limited","detail":"scan_start"})"));
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("scan_message:scan_start")), kTribeScanStartMax);

    // Shutdown: the engine's stop-all (a scan ran), then nothing more is accepted.
    fake::engine().reset();
    h.host->shutdown();
    CHECK(countOf(fake::engine().orderSnapshot(), QStringLiteral("stop_all:2000")) == 1);
    CHECK_EQ(h.host->scanSubmit(999, QStringLiteral("{\"action\":\"scan_caps\"}")), int(TribeScanSubmit::ShuttingDown));
}

static void bounds()
{
    fake::engine().reset();
    Harness h;
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"type":"scan_ack","scan_id":"b","accepted":0,"mem_mb":null})"); };

    // Size: over the cap = refused at the slot, never queued; exactly at the cap = relayed byte for byte.
    const QByteArray head = R"({"action":"scan_poll","scan_id":"b","since":0,"pad":")";
    const QByteArray tail = R"("})";
    QByteArray atCap = head + QByteArray(kTribeScanMaxMessageBytes - head.size() - tail.size(), 'x') + tail;
    CHECK_EQ(atCap.size(), kTribeScanMaxMessageBytes);
    QByteArray r;
    CHECK_EQ(h.send(atCap, &r, 10000), 0);
    CHECK(fake::engine().snapshot().size() == 1 && fake::engine().snapshot().first().message == atCap);
    QByteArray over = atCap;
    over.insert(head.size(), 'x');
    h.clock += 2000;
    CHECK_EQ(h.host->scanSubmit(1, QString::fromUtf8(over)), int(TribeScanSubmit::TooLarge));
    // Multi-byte characters: the UTF-8 size is what the engine would get.
    QString wide = QString::fromUtf8(head) + QString(kTribeScanMaxMessageBytes / 2, QChar(0x0416)) + QString::fromUtf8(tail);
    CHECK(wide.size() <= kTribeScanMaxMessageBytes && wide.toUtf8().size() > kTribeScanMaxMessageBytes);
    CHECK_EQ(h.host->scanSubmit(2, wide), int(TribeScanSubmit::TooLarge));
    CHECK_EQ(fake::engine().snapshot().size(), 1);

    // Rate: kTribeScanRateMax messages per window, then refused until the window moves.
    h.clock += 10000;
    int ok = 0;
    for (int i = 0; i < kTribeScanRateMax; ++i)
        ok += h.send(R"({"action":"scan_poll","scan_id":"b","since":0})") == 0;
    CHECK_EQ(ok, kTribeScanRateMax);
    CHECK_EQ(h.host->scanSubmit(3, QStringLiteral("{\"action\":\"scan_caps\"}")), int(TribeScanSubmit::RateLimited));
    h.clock += kTribeScanRateWindowMs + 1;
    CHECK_EQ(h.send(R"({"action":"scan_caps"})"), 0);

    // Queue: with the engine stuck, kTribeScanMaxPending messages wait, the next is refused; all queued ones
    // are answered once the engine moves.
    h.clock += 10000;
    fake::engine().closeGate();
    QList<quint64> ids;
    for (int i = 0; i < kTribeScanMaxPending; ++i) {
        const quint64 id = 5000 + quint64(i);
        CHECK_EQ(h.host->scanSubmit(id, QStringLiteral("{\"action\":\"scan_poll\",\"scan_id\":\"b\",\"since\":0}")), 0);
        ids << id;
    }
    CHECK_EQ(h.host->scanSubmit(6000, QStringLiteral("{\"action\":\"scan_caps\"}")), int(TribeScanSubmit::QueueFull));
    fake::engine().openGate();
    CHECK(waitFor([&]() {
        for (quint64 id : ids)
            if (!h.replies.contains(id))
                return false;
        return true;
    }));
}

static void generation()
{
    fake::engine().reset();
    Harness h;
    ScanNetSource g0;
    CHECK(scanNetSourceFromJson(obj(h.host->scanGeneration().toUtf8()), g0));
    CHECK(g0.source == QStringLiteral("service") && g0.counter == 0 && g0.epoch != 0);
    CHECK_EQ(h.host->scanIpcVersion(), 1);
    // Another host instance (a service restart) has another epoch.
    {
        Harness other;
        ScanNetSource g1;
        CHECK(scanNetSourceFromJson(obj(other.host->scanGeneration().toUtf8()), g1) && g1.epoch != g0.epoch);
    }
    int changed = 0;
    QObject::connect(h.host.get(), &IpcScanInterfaceSource::scanGenerationChanged, h.host.get(), [&](const QString &) { ++changed; });
    h.host->notePathEvent(true); // a wake-up
    ScanNetSource g;
    CHECK(scanNetSourceFromJson(obj(h.host->scanGeneration().toUtf8()), g) && g.counter == 1 && g.epoch == g0.epoch);
    CHECK_EQ(changed, 1);
    h.host->notePathEvent(false); // nothing moved
    CHECK_EQ(changed, 1);

    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"type":"scan_ack","scan_id":"g","accepted":0,"mem_mb":null})"); };
    CHECK_EQ(h.send(R"({"action":"scan_freeze","scan_id":"g"})"), 0);
    ScanNetSource sent;
    CHECK(scanNetSourceFromJson(obj(fake::engine().snapshot().last().options).value(QLatin1String("gen")), sent) && sent.counter == 1);
    // A poll samples the path first: a new gateway is a new generation in that very message.
    TribeScanUplink u = phys();
    u.gateway = QStringLiteral("192.0.2.254");
    h.setUplink(u);
    CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"g","since":0})"), 0);
    CHECK(scanNetSourceFromJson(obj(fake::engine().snapshot().last().options).value(QLatin1String("gen")), sent) && sent.counter == 2);
    CHECK(waitFor([&]() { return changed == 2; }));
}

// --- awg_mini host options --------------------------------------------------------------------------------------

static QString script(const QString &dir, const QString &name, const QByteArray &body, bool exec = true)
{
    const QString path = QDir(dir).filePath(name);
    QFile f(path);
    f.open(QIODevice::WriteOnly);
    f.write(body);
    f.close();
    f.setPermissions(exec ? (QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner) : (QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    return path;
}

static void awgParts()
{
    const QString bin = QStringLiteral("/svc/amneziawg-go");
    TribeScanAwgLive none;
    none.state = 0;
    TribeScanAwgLive unknown; // -1: no daemon object
    TribeScanAwgLive up;
    up.state = 1;
    up.publicKey = QStringLiteral("cHVibGljLWtleS1vZi10aGUtbGl2ZS1wZWVyMDEyMzQ=");
    up.endpoint = QStringLiteral("198.51.100.20:51820");
    TribeScanAwgLive upNoPeer;
    upNoPeer.state = 1;
    TribeScanAwgLive upKeyOnly = up;
    upKeyOnly.endpoint.clear();

    TribeScanAwgOptions o = tribeScanAwgDecide(bin, none, false);
    CHECK(o.binary == bin && !o.livePeer);
    o = tribeScanAwgDecide(bin, up, false);
    CHECK(o.binary == bin && o.livePeer && o.livePeerKey == up.publicKey && o.livePeerEndpoint == up.endpoint);
    o = tribeScanAwgDecide(bin, upKeyOnly, false);
    CHECK(o.binary == bin && o.livePeer && o.livePeerEndpoint.isEmpty()); // either field is enough
    CHECK(tribeScanAwgDecide(bin, upNoPeer, false).binary.isEmpty());     // tunnel up, peer unknown: no awg_mini
    CHECK(tribeScanAwgDecide(bin, unknown, false).binary.isEmpty());      // daemon state unknown: no awg_mini
    CHECK(tribeScanAwgDecide(bin, none, true).binary.isEmpty());          // a tunnel change meanwhile
    CHECK(tribeScanAwgDecide(QString(), up, false).binary.isEmpty());

    TribeScanGeneration g(1);
    const TribeScanUplink u = phys();
    const TribeScanAwgOptions withPeer = tribeScanAwgDecide(bin, up, false);
    const QJsonObject start = obj(tribeScanHostOptions(g.now(), &u, &withPeer));
    CHECK(start.value(QLatin1String("awg_probe_binary")).toString() == bin);
    const QJsonObject peer = start.value(QLatin1String("awg_live_peer")).toObject();
    CHECK(peer.value(QLatin1String("public_key")).toString() == up.publicKey && peer.value(QLatin1String("endpoint")).toString() == up.endpoint);
    CHECK(!start.contains(QLatin1String("live_awg_peer")) && !start.contains(QLatin1String("awg_runner")));
    const TribeScanAwgOptions keyOnly = tribeScanAwgDecide(bin, upKeyOnly, false);
    CHECK(obj(tribeScanHostOptions(g.now(), &u, &keyOnly)).value(QLatin1String("awg_live_peer")).toObject().keys()
          == QStringList{QStringLiteral("public_key")});
    const QJsonObject caps = obj(tribeScanHostOptions(g.now(), nullptr, &withPeer)); // scan_caps: the binary only
    CHECK(caps.value(QLatin1String("awg_probe_binary")).toString() == bin && !caps.contains(QLatin1String("awg_live_peer")));
    const TribeScanAwgOptions off = tribeScanAwgDecide(bin, upNoPeer, false);
    const QJsonObject startOff = obj(tribeScanHostOptions(g.now(), &u, &off));
    CHECK(!startOff.contains(QLatin1String("awg_probe_binary")) && !startOff.contains(QLatin1String("awg_live_peer")));

    CHECK(tribeScanAwgDecide(bin, upNoPeer, false).unavailable == QStringLiteral("awg_live_peer_unknown"));
    CHECK(tribeScanAwgDecide(bin, unknown, false).unavailable == QStringLiteral("awg_live_peer_unknown"));
    CHECK(tribeScanAwgDecide(bin, up, false).unavailable.isEmpty() && tribeScanAwgDecide(QString(), upNoPeer, false).unavailable.isEmpty());
    const QByteArray capsRaw = R"({"type":"scan_caps","version":"tribe-scan-v1","max_full_concurrent":2,"kinds":["xray_full"],"can_verify_composite":true,"needs_vpn":false})";
    CHECK(tribeScanAddAwgUnavailable(capsRaw, QString()) == capsRaw); // untouched without a reason
    CHECK(obj(tribeScanAddAwgUnavailable(capsRaw, QStringLiteral("awg_live_peer_unknown"))).value(QLatin1String("awg_unavailable")).toString()
          == QStringLiteral("awg_live_peer_unknown"));
    CHECK(tribeScanAddAwgUnavailable(R"({"error":"internal"})", QStringLiteral("awg_live_peer_unknown")) == QByteArray(R"({"error":"internal"})"));
    CHECK(tribeScanInspectRequest(R"({"action":"scan_add","scan_id":"s","candidates":[{"kind":"xray_leg"},{"kind":"awg_mini"}]})").hasAwgMini);
    CHECK(!tribeScanInspectRequest(R"({"action":"scan_add","scan_id":"s","candidates":[{"kind":"xray_leg"}]})").hasAwgMini);

    // The binary check: only a binary that answers `probe --abi` with the ABI passes.
    QTemporaryDir tmp;
    const QString good = script(tmp.path(), QStringLiteral("good"),
                                "#!/bin/sh\nif [ \"$1\" = probe ] && [ \"$2\" = --abi ]; then echo tribe-awg-probe-v1; exit 0; fi\nexit 3\n");
    const QString old = script(tmp.path(), QStringLiteral("old"), "#!/bin/sh\necho \"Usage: $0 [-f/--foreground] INTERFACE-NAME\"\n");
    const QString badExit = script(tmp.path(), QStringLiteral("badexit"), "#!/bin/sh\necho tribe-awg-probe-v1\nexit 1\n");
    const QString hang = script(tmp.path(), QStringLiteral("hang"), "#!/bin/sh\nsleep 5\necho tribe-awg-probe-v1\n");
    const QString noExec = script(tmp.path(), QStringLiteral("noexec"), "#!/bin/sh\necho tribe-awg-probe-v1\n", false);
    const QString link = QDir(tmp.path()).filePath(QStringLiteral("link"));
    QFile::link(good, link);
    CHECK(tribeScanCheckAwgProbeBinary(good, false) == good);
    CHECK(tribeScanCheckAwgProbeBinary(old, false).isEmpty());
    CHECK(tribeScanCheckAwgProbeBinary(badExit, false).isEmpty());
    // A binary that does not answer within the bound is killed and refused (without the bound it would print
    // the ABI after 5 s and pass, so the result alone proves the bound).
    CHECK(tribeScanCheckAwgProbeBinary(hang, false, 300).isEmpty());
    CHECK(tribeScanCheckAwgProbeBinary(noExec, false).isEmpty());
    CHECK(tribeScanCheckAwgProbeBinary(link, false).isEmpty());
    CHECK(tribeScanCheckAwgProbeBinary(QStringLiteral("relative/amneziawg-go"), false).isEmpty());
    CHECK(tribeScanCheckAwgProbeBinary(QDir(tmp.path()).filePath(QStringLiteral("missing")), false).isEmpty());
    if (::getuid() != 0)
        CHECK(tribeScanCheckAwgProbeBinary(good, true).isEmpty()); // the service runs only a root-owned binary
    // The real binaries from the awg-go packages (build_tribe_scan.sh finds them): the probe-capable one
    // passes, the shipped daemon of today (no tribe_probe) prints its usage and does not.
    const QString realProbe = qEnvironmentVariable("TRIBE_AWG_PROBE_BIN");
    const QString realPlain = qEnvironmentVariable("TRIBE_AWG_PLAIN_BIN");
    if (!realProbe.isEmpty())
        CHECK(tribeScanCheckAwgProbeBinary(realProbe, false) == realProbe);
    if (!realPlain.isEmpty())
        CHECK(tribeScanCheckAwgProbeBinary(realPlain, false).isEmpty());
    std::printf("awg binary check: real probe binary %s, real plain binary %s\n", realProbe.isEmpty() ? "not found" : "checked",
                realPlain.isEmpty() ? "not found" : "checked");
}

static void awgHost()
{
    fake::engine().reset();
    Harness h;
    fake::engine().reply = [](const QByteArray &msg, const QByteArray &) -> QByteArray {
        const QJsonObject o = obj(msg);
        if (o.value(QLatin1String("action")).toString() == QLatin1String("scan_caps"))
            return R"({"type":"scan_caps","version":"tribe-scan-v1","max_full_concurrent":2,"kinds":["xray_full"],"can_verify_composite":true,"needs_vpn":false})";
        return QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"%1\",\"accepted\":1,\"mem_mb\":9}")
            .arg(o.value(QLatin1String("scan_id")).toString())
            .toUtf8();
    };
    auto lastOptions = []() { return obj(fake::engine().snapshot().last().options); };
    const QString bin = QStringLiteral("/svc/amneziawg-go");
    {
        QMutexLocker l(&h.uplinkMutex);
        h.awgBinary = bin;
    }
    // No AmneziaWG tunnel: caps and start name the binary, no live peer.
    QByteArray r;
    CHECK_EQ(h.send(R"({"action":"scan_caps"})", &r), 0);
    CHECK(lastOptions().value(QLatin1String("awg_probe_binary")).toString() == bin);
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("a1")), &r), 0);
    CHECK(lastOptions().value(QLatin1String("awg_probe_binary")).toString() == bin && !lastOptions().contains(QLatin1String("awg_live_peer")));
    // A live tunnel with a known peer: the start carries it, so the engine refuses that node.
    h.awgLive.state = 1;
    h.awgLive.publicKey = QStringLiteral("cHVibGljLWtleS1vZi10aGUtbGl2ZS1wZWVyMDEyMzQ=");
    h.awgLive.endpoint = QStringLiteral("198.51.100.20:51820");
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("a2")), &r), 0);
    const QJsonObject peer = lastOptions().value(QLatin1String("awg_live_peer")).toObject();
    CHECK(lastOptions().value(QLatin1String("awg_probe_binary")).toString() == bin);
    CHECK(peer.value(QLatin1String("public_key")).toString() == h.awgLive.publicKey
          && peer.value(QLatin1String("endpoint")).toString() == h.awgLive.endpoint);
    CHECK_EQ(h.send(R"({"action":"scan_caps"})", &r), 0);
    CHECK(lastOptions().contains(QLatin1String("awg_probe_binary")) && !lastOptions().contains(QLatin1String("awg_live_peer")));
    // A live tunnel whose peer is unknown, or a daemon whose state cannot be told: no binary at all, and the
    // caps say why (host-only "awg_unavailable", the reason the iOS host gives).
    CHECK(!obj(r).contains(QLatin1String("awg_unavailable"))); // peer known above: no reason
    h.awgLive.publicKey.clear();
    h.awgLive.endpoint.clear();
    CHECK_EQ(h.send(R"({"action":"scan_caps"})", &r), 0);
    CHECK(!lastOptions().contains(QLatin1String("awg_probe_binary")));
    CHECK_EQ(obj(r).value(QLatin1String("awg_unavailable")).toString(), QStringLiteral("awg_live_peer_unknown"));
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Caps); // the app's decoder ignores the addition
    // A start or an add carrying awg_mini sessions is refused like on iOS (the coordinator sends it again
    // without them and marks those rows); the engine never sees it.
    QJsonObject awgStart = obj(startRequest(QStringLiteral("a3w")));
    {
        QJsonArray cands = awgStart.value(QLatin1String("candidates")).toArray();
        QJsonObject c0 = cands.at(0).toObject();
        c0.insert(QStringLiteral("kind"), QStringLiteral("awg_mini"));
        cands.append(c0);
        awgStart.insert(QStringLiteral("candidates"), cands);
    }
    const int engineCalls = fake::engine().snapshot().size();
    h.clock += 2000;
    CHECK_EQ(h.send(QJsonDocument(awgStart).toJson(QJsonDocument::Compact), &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"internal","detail":"awg_live_peer_unknown"})"));
    CHECK_EQ(h.send(R"({"action":"scan_add","scan_id":"a2","candidates":[{"id":"9","kind":"awg_mini","config":"{}"}]})", &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"internal","detail":"awg_live_peer_unknown"})"));
    CHECK_EQ(fake::engine().snapshot().size(), engineCalls);
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("a3")), &r), 0);
    CHECK(!lastOptions().contains(QLatin1String("awg_probe_binary")) && !lastOptions().contains(QLatin1String("awg_live_peer")));
    h.awgLive = TribeScanAwgLive(); // state -1
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("a4")), &r), 0);
    CHECK(!lastOptions().contains(QLatin1String("awg_probe_binary")));
    CHECK_EQ(h.send(R"({"action":"scan_caps"})", &r), 0);
    CHECK_EQ(obj(r).value(QLatin1String("awg_unavailable")).toString(), QStringLiteral("awg_live_peer_unknown"));
    // No probe-capable binary: nothing either, whatever the tunnel.
    h.awgLive.state = 0;
    {
        QMutexLocker l(&h.uplinkMutex);
        h.awgBinary.clear();
    }
    CHECK_EQ(h.send(R"({"action":"scan_caps"})", &r), 0);
    CHECK(!lastOptions().contains(QLatin1String("awg_probe_binary")));
    CHECK(!obj(r).contains(QLatin1String("awg_unavailable"))); // no binary: caps simply offer no awg_mini
    {
        QMutexLocker l(&h.uplinkMutex);
        h.awgBinary = bin;
    }

    // F2: a scan_start and a scan_add queued before a tunnel change are dropped (tunnel_changed) and never
    // reach the engine - no probe of them can start during the change; a poll queued with them is still relayed
    // (it starts nothing).
    fake::engine().reset();
    fake::engine().reply = [](const QByteArray &msg, const QByteArray &) {
        return QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"%1\",\"accepted\":1,\"mem_mb\":9}")
            .arg(obj(msg).value(QLatin1String("scan_id")).toString())
            .toUtf8();
    };
    fake::engine().closeGate();
    const quint64 idPoll = 7001, idStart = 7002, idAdd = 7004, idPoll2 = 7005;
    h.clock += 2000;
    CHECK_EQ(h.host->scanSubmit(idPoll, QStringLiteral("{\"action\":\"scan_poll\",\"scan_id\":\"a4\",\"since\":0}")), 0);
    CHECK_EQ(h.host->scanSubmit(idStart, QString::fromUtf8(startRequest(QStringLiteral("a5")))), 0);
    CHECK_EQ(h.host->scanSubmit(idAdd, QStringLiteral("{\"action\":\"scan_add\",\"scan_id\":\"a4\",\"candidates\":[]}")), 0);
    CHECK_EQ(h.host->scanSubmit(idPoll2, QStringLiteral("{\"action\":\"scan_poll\",\"scan_id\":\"a4\",\"since\":0}")), 0);
    CHECK(waitFor([]() { return fake::engine().gateWaiters.load() == 1; }, 10000)); // the worker sits in the first poll
    h.host->stopAllBeforeTunnelChange("awg_activate");
    fake::engine().openGate();
    CHECK(waitFor([&]() { return h.replies.contains(idStart) && h.replies.contains(idAdd) && h.replies.contains(idPoll2); }));
    CHECK_EQ(h.replies.value(idStart), QByteArray(R"({"error":"tunnel_changed"})"));
    CHECK_EQ(h.replies.value(idAdd), QByteArray(R"({"error":"tunnel_changed"})"));
    CHECK(scanDecodeReply(h.replies.value(idStart)).kind == ScanHostReplyKind::Error
          && scanDecodeReply(h.replies.value(idStart)).errorCode == QStringLiteral("tunnel_changed"));
    {
        const QList<QString> o = fake::engine().orderSnapshot();
        CHECK_EQ(countOf(o, QStringLiteral("scan_message:scan_start")), 0);
        CHECK_EQ(countOf(o, QStringLiteral("scan_message:scan_add")), 0);
        CHECK_EQ(countOf(o, QStringLiteral("scan_message:scan_poll")), 2);
        CHECK_EQ(countOf(o, QStringLiteral("arm:")), 0); // no exemption for a dropped start
    }
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("a6")), &r), 0); // a message after the change has a fresh view
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Ack);
    CHECK(lastOptions().value(QLatin1String("awg_probe_binary")).toString() == bin);

    // A scan_start inside the engine and a tunnel change: the change waits for the start (so the new scan
    // exists when every scan is stopped), then stops it.
    fake::engine().reset();
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"type":"scan_ack","scan_id":"a7","accepted":1,"mem_mb":9})"); };
    fake::engine().closeGate();
    const quint64 idA7 = 7003;
    h.clock += 2000;
    CHECK_EQ(h.host->scanSubmit(idA7, QString::fromUtf8(startRequest(QStringLiteral("a7")))), 0);
    CHECK(waitFor([]() { return fake::engine().gateWaiters.load() == 1; }, 10000)); // the worker is inside the engine call
    std::thread opener([]() {
        QThread::msleep(300);
        fake::engine().openGate();
    });
    h.host->stopAllBeforeTunnelChange("awg_activate");
    opener.join();
    // The proof is the order, not a duration: the start is recorded only once the gate opens, so a stop-all
    // that did not wait for it would come first.
    const QList<QString> order = fake::engine().orderSnapshot();
    const int iStart = order.indexOf(QStringLiteral("scan_message:scan_start"));
    const int iStop = order.indexOf(QStringLiteral("stop_all:2000"));
    if (!(iStart >= 0 && iStop > iStart))
        std::fprintf(stderr, "  order: %s\n", qPrintable(order.join(QLatin1Char(' '))));
    CHECK(iStart >= 0 && iStop > iStart);
    CHECK(waitFor([&]() { return h.replies.contains(idA7); }));
}

// --- F1 / F4: the teardown before a tunnel change, the app's stop-all, host_epoch ------------------------------

static void teardownTests()
{
    fake::engine().reset();
    Harness h;
    const auto ack = [](const QByteArray &msg, const QByteArray &) {
        return QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"%1\",\"accepted\":1,\"mem_mb\":9}")
            .arg(obj(msg).value(QLatin1String("scan_id")).toString())
            .toUtf8();
    };
    fake::engine().reply = ack;
    QByteArray r;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("t1")), &r), 0);
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Ack);

    // host_epoch: every message carries the tunnel-change count it belongs to; a tunnel change moves it.
    CHECK_EQ(h.send(R"({"action":"scan_caps"})", &r), 0);
    const double epoch0 = obj(fake::engine().snapshot().last().options).value(QLatin1String("host_epoch")).toDouble(-1);
    CHECK(epoch0 >= 0);

    // F1: the engine does not confirm the stop - the probe children are killed, the exemption goes, and the
    // tunnel change proceeds (the hook returns); new scans and adds are refused until the engine confirms.
    fake::engine().reset();
    fake::engine().reply = ack;
    fake::engine().stopAllResult = false;
    {
        QMutexLocker l(&g_logMutex);
        g_log.clear();
    }
    h.killKilled = 2;
    fake::engine().stopAllReply = R"({"stopped":false,"instances":1,"jobs":2})"; // an engine that reports counts
    h.host->stopAllBeforeTunnelChange("xray_start");
    fake::engine().stopAllReply.clear();
    h.killKilled = 0;
    CHECK_EQ(fake::engine().orderSnapshot(),
             (QList<QString>{QStringLiteral("stop_all:2000"), QStringLiteral("kill"), QStringLiteral("disarm")}));
    {
        // One line with what was left: the engine's live counts as it reports them, children killed / still
        // alive, whether an exemption was removed.
        QMutexLocker l(&g_logMutex);
        QStringList journal;
        for (const QString &line : std::as_const(g_log))
            if (line.contains(QStringLiteral("stopped=false")))
                journal << line;
        CHECK_EQ(journal.size(), 1);
        const QString j = journal.value(0);
        CHECK(j.contains(QStringLiteral("reason=xray_start")) && j.contains(QStringLiteral("engine_live=instances=1,jobs=2"))
              && j.contains(QStringLiteral("probe_children_killed=2")) && j.contains(QStringLiteral("probe_children_alive=0"))
              && j.contains(QStringLiteral("exemption_removed=yes")) && j.contains(QStringLiteral("new scans refused")));
        if (journal.size() == 1)
            std::printf("journal: %s\n", qPrintable(j));
    }
    CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"t1","since":0})", &r), 0);
    CHECK(obj(fake::engine().snapshot().last().options).value(QLatin1String("host_epoch")).toDouble() == epoch0 + 1);
    fake::engine().reset();
    fake::engine().reply = ack;
    fake::engine().stopAllResult = false;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("t2")), &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"teardown_pending"})"));
    CHECK_EQ(h.send(R"({"action":"scan_add","scan_id":"t1","candidates":[]})", &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"teardown_pending"})"));
    CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"t1","since":0})", &r), 0); // a poll still answers
    {
        const QList<QString> o = fake::engine().orderSnapshot();
        CHECK_EQ(countOf(o, QStringLiteral("stop_all:0")), 2); // each refused start / add asked the engine
        CHECK_EQ(countOf(o, QStringLiteral("scan_message:scan_start")), 0);
        CHECK_EQ(countOf(o, QStringLiteral("scan_message:scan_add")), 0);
        CHECK_EQ(countOf(o, QStringLiteral("arm:")), 0);
    }
    fake::engine().reset();
    fake::engine().reply = ack;
    fake::engine().stopAllResult = true; // the engine confirms now
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("t3")), &r), 0);
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Ack);
    CHECK_EQ(fake::engine().orderSnapshot(),
             (QList<QString>{QStringLiteral("stop_all:0"), QStringLiteral("arm:en7"), QStringLiteral("scan_message:scan_start")}));
    // The stop carries the epoch of the change (the engine refuses older starts as stale_epoch), and the
    // zero-wait check that cleared the refusal carried the same epoch.
    {
        double stopEpoch = -1, zeroEpoch = -1;
        for (const fake::Call &c : fake::engine().snapshot())
            if (c.what == QStringLiteral("stop_all") && c.waitMs == 0)
                zeroEpoch = double(c.epoch);
        CHECK(zeroEpoch == epoch0 + 1);
        fake::engine().reset();
        fake::engine().reply = ack;
        h.host->stopAllBeforeTunnelChange("xray_stop");
        for (const fake::Call &c : fake::engine().snapshot())
            if (c.what == QStringLiteral("stop_all"))
                stopEpoch = double(c.epoch);
        CHECK(stopEpoch == epoch0 + 2);
        CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("kill")), 0); // confirmed: no belt
    }
    // A stop the engine does not confirm and a child that is still not dead after the whole wait (cannot
    // normally happen after SIGKILL): journaled with its count, the hook still returns, new scans refused.
    fake::engine().reset();
    fake::engine().reply = ack;
    h.killKilled = 1;
    h.killAlive = 1;
    fake::engine().stopAllResult = false;
    {
        QMutexLocker l(&g_logMutex);
        g_log.clear();
    }
    h.host->stopAllBeforeTunnelChange("awg_deactivate");
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("kill")), 1);
    {
        QMutexLocker l(&g_logMutex);
        int n = 0;
        for (const QString &line : std::as_const(g_log))
            n += line.contains(QStringLiteral("probe_children_alive=1")) && line.contains(QStringLiteral("engine_live=not_reported"))
                         && line.contains(QStringLiteral("exemption_removed=none_armed"))
                     ? 1
                     : 0;
        CHECK_EQ(n, 1);
    }
    h.killKilled = 0;
    h.killAlive = 0;
    fake::engine().stopAllResult = false;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("t4")), &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"teardown_pending"})"));
    fake::engine().stopAllResult = true;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("t5")), &r), 0);
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Ack);

    // F4: the app's stop-all is bounded - repeated calls coalesce into one pending stop, the rate bound applies.
    fake::engine().reset();
    fake::engine().reply = ack;
    h.clock += 20000;
    int accepted = 0;
    for (int i = 0; i < 30; ++i)
        accepted += h.host->scanStopAll() == 0 ? 1 : 0;
    CHECK_EQ(accepted, 30);
    CHECK(waitFor([]() { return countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")) >= 1; }));
    QCoreApplication::processEvents();
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("stop_all:500")), 1); // one stop for 30 calls
    CHECK_EQ(h.host->scanStopAll(), 0); // the next call after it ran is a new stop
    CHECK(waitFor([]() { return countOf(fake::engine().orderSnapshot(), QStringLiteral("stop_all:500")) == 2; }));
    h.clock += 20000;
    int admitted = 0;
    for (int i = 0; i < kTribeScanRateMax; ++i)
        admitted += h.host->scanStopAll() == 0 ? 1 : 0;
    CHECK_EQ(admitted, kTribeScanRateMax);
    CHECK_EQ(h.host->scanStopAll(), int(TribeScanSubmit::RateLimited));
    CHECK_EQ(h.host->scanSubmit(9001, QStringLiteral("{\"action\":\"scan_caps\"}")), int(TribeScanSubmit::RateLimited)); // one budget
}

#ifdef Q_OS_MACOS
static pid_t spawnChild(const QString &path, const QStringList &args)
{
    QList<QByteArray> store;
    store << path.toLocal8Bit();
    for (const QString &a : args)
        store << a.toLocal8Bit();
    std::vector<char *> argv;
    for (QByteArray &b : store)
        argv.push_back(b.data());
    argv.push_back(nullptr);
    pid_t pid = -1;
    if (posix_spawn(&pid, store.first().constData(), nullptr, nullptr, argv.data(), environ) != 0)
        return -1;
    // Wait until the exec is done (before it the child still shows this test's path).
    const QString canon = QFileInfo(path).canonicalFilePath();
    waitFor([&]() {
        char p[PROC_PIDPATHINFO_MAXSIZE];
        return proc_pidpath(pid, p, sizeof(p)) > 0 && QFileInfo(QString::fromUtf8(p)).canonicalFilePath() == canon;
    });
    return pid;
}

static bool aliveNotZombie(pid_t pid)
{
    int st = 0;
    return ::kill(pid, 0) == 0 && ::waitpid(pid, &st, WNOHANG) == 0;
}
#endif

static void childKill()
{
    // The death wait after SIGKILL, on a given clock (no wall time): a child dead at 1500 ms is waited for
    // (the bound is 2000 ms, not 500); one never dead is given up at exactly the bound and counted.
    {
        qint64 now = 0;
        const auto clock = [&now]() { return now; };
        const auto pause = [&now]() { now += 10; };
        const auto deadAt = [&now](qint64 pid) { return pid == 1 ? now >= 1500 : pid == 2 ? now >= 0 : false; };
        CHECK_EQ(kTribeScanChildDeathMs, 2000);
        CHECK_EQ(tribeScanAwaitDeath({1, 2}, kTribeScanChildDeathMs, deadAt, clock, pause), 0);
        CHECK(now >= 1500 && now < 2000);
        now = 0;
        CHECK_EQ(tribeScanAwaitDeath({1, 3}, kTribeScanChildDeathMs, deadAt, clock, pause), 1); // pid 3 never dies
        CHECK(now == kTribeScanChildDeathMs); // given up at the bound, not before
        now = 0;
        CHECK_EQ(tribeScanAwaitDeath({}, kTribeScanChildDeathMs, deadAt, clock, pause), 0);
        CHECK(now == 0); // nothing to wait for
        CHECK_EQ(kTribeScanTunnelHookCapMs, 4000);
    }
    {
        const TribeScanStopResult a = tribeScanParseStopReply(R"({"stopped":true})");
        CHECK(a.stopped && a.live.isEmpty());
        const TribeScanStopResult b = tribeScanParseStopReply(R"({"stopped":false,"jobs":2,"instances":1,"note":"x"})");
        CHECK(!b.stopped && b.live == QStringLiteral("instances=1 jobs=2")); // numbers only, sorted
        CHECK(!tribeScanParseStopReply("garbage").stopped);
        // The engine's real "not stopped" shape (amnezia-libxray 0012 StopAllJSON): flat top-level counts.
        const TribeScanStopResult c = tribeScanParseStopReply(
            R"({"stopped":false,"instances":1,"jobs":2,"closers":1,"attempts":3,"awg":4,"children":5})");
        CHECK(!c.stopped && c.live == QStringLiteral("attempts=3 awg=4 children=5 closers=1 instances=1 jobs=2"));
    }
    // argv of a KERN_PROCARGS2 buffer, and which children are probe children.
    QByteArray buf;
    const int argc = 2;
    buf.append(reinterpret_cast<const char *>(&argc), sizeof(argc));
    buf.append("/x/amneziawg-go", 15);
    buf.append(QByteArray(5, '\0'));
    buf.append("/x/amneziawg-go\0probe\0ENV=1\0", 28);
    CHECK_EQ(tribeScanParseProcArgs(buf), (QStringList{QStringLiteral("/x/amneziawg-go"), QStringLiteral("probe")}));
    CHECK(tribeScanParseProcArgs(buf.left(int(sizeof(int)) + 22)).isEmpty()); // truncated
    QByteArray huge = buf;
    const int many = 1 << 20;
    std::memcpy(huge.data(), &many, sizeof(many));
    CHECK(tribeScanParseProcArgs(huge).isEmpty());
    const QString b = QStringLiteral("/x/amneziawg-go");
    CHECK(tribeScanIsProbeChild(b, {b, QStringLiteral("probe")}, b));
    CHECK(!tribeScanIsProbeChild(b, {b, QStringLiteral("-f"), QStringLiteral("utun")}, b)); // the live tunnel
    CHECK(!tribeScanIsProbeChild(b, {b, QStringLiteral("probe"), QStringLiteral("x")}, b));
    CHECK(!tribeScanIsProbeChild(QStringLiteral("/y/amneziawg-go"), {b, QStringLiteral("probe")}, b));
    CHECK(!tribeScanIsProbeChild(b, {b, QStringLiteral("probe")}, QString()));
#ifdef Q_OS_MACOS
    // Real children of this process: only `<bin> probe` dies; the tunnel's `<bin> -f utun`, `<bin> probe x` and
    // another binary's `probe` stay.
    const QString sleeper = qEnvironmentVariable("TRIBE_SCAN_SLEEPER");
    CHECK(!sleeper.isEmpty());
    if (sleeper.isEmpty())
        return;
    QTemporaryDir tmp;
    const QString bin = QDir(tmp.path()).filePath(QStringLiteral("amneziawg-go"));
    const QString other = QDir(tmp.path()).filePath(QStringLiteral("other-go"));
    CHECK(QFile::copy(sleeper, bin) && QFile::copy(sleeper, other));
    QFile::setPermissions(bin, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    QFile::setPermissions(other, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    const pid_t probe = spawnChild(bin, {QStringLiteral("probe")});
    const pid_t probe2 = spawnChild(bin, {QStringLiteral("probe")});
    const pid_t tunnel = spawnChild(bin, {QStringLiteral("-f"), QStringLiteral("utun")});
    const pid_t extra = spawnChild(bin, {QStringLiteral("probe"), QStringLiteral("x")});
    const pid_t otherProbe = spawnChild(other, {QStringLiteral("probe")});
    CHECK(probe > 0 && probe2 > 0 && tunnel > 0 && extra > 0 && otherProbe > 0);
    const TribeScanKillResult kr = tribeScanKillProbeChildren(bin);
    CHECK(kr.killed == 2 && kr.alive == 0);
    for (pid_t p : {probe, probe2}) {
        int st = 0;
        CHECK(::waitpid(p, &st, 0) == p && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL); // its spawner reaps it
    }
    CHECK(aliveNotZombie(tunnel) && aliveNotZombie(extra) && aliveNotZombie(otherProbe));
    CHECK(tribeScanKillProbeChildren(bin).killed == 0);
    CHECK(tribeScanKillProbeChildren(QString()).killed == 0);
    for (pid_t p : {tunnel, extra, otherProbe}) {
        ::kill(p, SIGKILL);
        int st = 0;
        ::waitpid(p, &st, 0);
    }
#endif
}

static void logInjection()
{
    fake::engine().reset();
    Harness h;
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"error":"bad\nrequest"})"); };
    {
        QMutexLocker l(&g_logMutex);
        g_log.clear();
    }
    h.clock += 2000;
    QByteArray r;
    CHECK_EQ(h.send(startRequest(QStringLiteral("evil\n[tribescan] forged line")), &r), 0);
    QMutexLocker l(&g_logMutex);
    bool sawStart = false;
    for (const QString &line : std::as_const(g_log)) {
        CHECK(!line.contains(QLatin1Char('\n')) && !line.contains(QStringLiteral("forged")));
        sawStart = sawStart || line.contains(QStringLiteral("scan_start scan=?"));
    }
    CHECK(sawStart);
}

static void logPrivacy(const QString &vectorsPath)
{
    QStringList secrets = {QStringLiteral("SECRET-TOKEN"), QStringLiteral("SECRET-CONFIG"), QStringLiteral("203.0.113.9"),
                           QStringLiteral("198.51.100.7"), QStringLiteral("192.0.2."), QStringLiteral("en7"),
                           QStringLiteral("utun4"), QStringLiteral("2001:db8")};
    QFile f(vectorsPath);
    if (f.open(QIODevice::ReadOnly)) {
        const QJsonObject vf = QJsonDocument::fromJson(f.readAll()).object();
        for (const QJsonValue &v : vf.value(QLatin1String("requests")).toArray()) {
            const QJsonObject j = v.toObject().value(QLatin1String("json")).toObject();
            const QString tok = j.value(QLatin1String("probe")).toObject().value(QLatin1String("token")).toString();
            if (tok.size() >= 8)
                secrets << tok;
            for (const QJsonValue &c : j.value(QLatin1String("candidates")).toArray()) {
                const QJsonObject co = c.toObject();
                if (co.value(QLatin1String("config")).toString().size() >= 8)
                    secrets << co.value(QLatin1String("config")).toString();
                const QString ip = co.value(QLatin1String("entry")).toObject().value(QLatin1String("ip")).toString();
                if (!ip.isEmpty())
                    secrets << ip;
            }
        }
    }
    QMutexLocker l(&g_logMutex);
    int lines = 0;
    for (const QString &line : std::as_const(g_log)) {
        ++lines;
        for (const QString &s : std::as_const(secrets)) {
            if (line.contains(s)) {
                std::fprintf(stderr, "FAIL log line carries a secret, host or interface: %s\n", qPrintable(line));
                ++g_failed;
            }
        }
    }
    ++g_checks;
    std::printf("log: %d service lines checked against %lld markers\n", lines, qlonglong(secrets.size()));
}

// --- the uplink's half routes for pinned probe sockets (round mac-C: under AmneziaWG every pinned probe had no route) ---

#ifdef Q_OS_MACOS
// One AF_INET route-table entry as NET_RT_DUMP writes it: rt_msghdr, then DST, GATEWAY, NETMASK (each rounded to 4).
// maskLen = the trimmed netmask sockaddr's length (0 = a /0 mask, 5 = a /1 mask as the kernel keeps it), -1 = none.
static QByteArray dumpEntry(int flags, int index, quint32 dst, bool gwInet, quint32 gw, int maskLen, quint8 maskByte = 0x80)
{
    const auto inet = [](quint32 a) {
        sockaddr_in s{};
        s.sin_len = sizeof(s);
        s.sin_family = AF_INET;
        s.sin_addr.s_addr = htonl(a);
        return QByteArray(reinterpret_cast<const char *>(&s), sizeof(s));
    };
    QByteArray body = inet(dst);
    int addrs = RTA_DST | RTA_GATEWAY;
    if (gwInet) {
        body += inet(gw);
    } else {
        QByteArray link(20, '\0'); // a sockaddr_dl (the tunnel's link): AF_LINK
        link[0] = char(20);
        link[1] = char(AF_LINK);
        body += link;
    }
    if (maskLen >= 0) {
        addrs |= RTA_NETMASK;
        QByteArray mask(maskLen > 0 ? 8 : 4, '\0');
        mask[0] = char(maskLen);
        if (maskLen >= 5)
            mask[4] = char(maskByte);
        body += mask;
    }
    rt_msghdr h{};
    h.rtm_version = RTM_VERSION;
    h.rtm_type = RTM_GET;
    h.rtm_flags = flags;
    h.rtm_index = u_short(index);
    h.rtm_addrs = addrs;
    h.rtm_msglen = u_short(sizeof(h) + size_t(body.size()));
    return QByteArray(reinterpret_cast<const char *>(&h), sizeof(h)) + body;
}

static quint32 saAt(const QByteArray &m, qsizetype off)
{
    sockaddr_in s{};
    std::memcpy(&s, m.constData() + off, sizeof(s));
    return ntohl(s.sin_addr.s_addr);
}
#endif

#ifdef Q_OS_MACOS
// The kernel and the disk as the half routes see them (review N2, N3): a route table (dumped as NET_RT_DUMP writes it),
// pinned lookups judged from it the way the kernel did on the test Mac (an unscoped route of another interface hides the
// primary default for its addresses unless a route scoped to the pinned interface covers them), the ownership record on
// a disk, and a kill switch of the process: after `budget` mutations (route writes, record writes) the process is dead
// - nothing it does changes the kernel or the disk any more.
struct FakeKernel {
    struct Route {
        quint32 dst = 0;
        int prefix = 0;   // 32 = host
        int flags = 0;
        int ifindex = 0;
        quint32 gw = 0;   // 0 = a link gateway
    };
    QList<Route> routes;
    QByteArray disk;
    bool diskFails = false;
    QHash<quint32, int> addError;    // dst -> errno of an add (EEXIST: someone else's route arrives just then)
    QHash<quint32, int> deleteError; // dst -> errno of a delete
    int budget = -1;                 // mutations left before the process dies; -1 = never
    QStringList writes;
    static constexpr int kUp = 7;
    static constexpr quint32 kRouter = 0xC0000201u;

    bool alive() { return budget != 0; }
    void spend() { if (budget > 0) --budget; }
    static quint32 maskOf(int prefix) { return prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix); }
    void add(quint32 dst, int prefix, int flags, int ifindex, quint32 gw = 0)
    {
        routes << Route{dst, prefix, flags | RTF_UP | (prefix == 32 ? RTF_HOST : 0), ifindex, gw};
    }
    void defaultOff()   // the VPN off: the primary default, loopback, link-local, multicast, the LAN
    {
        add(0, 0, RTF_GATEWAY | RTF_STATIC, kUp, kRouter);
        add(0x7F000000u, 8, RTF_STATIC, 1);
        add(0xA9FE0000u, 16, RTF_STATIC, kUp);
        add(0xE0000000u, 4, RTF_STATIC, kUp);
        add(0xC0000200u, 24, 0, kUp);
    }
    void awgTunnel(int utun = 20)
    {
        add(0x00000000u, 1, RTF_STATIC, utun);
        add(0x80000000u, 1, RTF_STATIC, utun);
    }
    bool hasHalf(quint32 dst, int ifindex, quint32 gw) const
    {
        for (const Route &r : routes)
            if (r.dst == dst && r.prefix == 1 && (r.flags & RTF_IFSCOPE) && r.ifindex == ifindex && r.gw == gw)
                return true;
        return false;
    }
    int halves() const // scoped half routes on the uplink
    {
        int n = 0;
        for (const Route &r : routes)
            n += (r.prefix == 1 && (r.flags & RTF_IFSCOPE) && r.ifindex == kUp) ? 1 : 0;
        return n;
    }
    QByteArray dump() const
    {
        QByteArray out;
        for (const Route &r : routes) {
            const int maskLen = r.prefix == 32 ? -1 : (r.prefix == 0 ? 0 : 5 + (r.prefix > 8) + (r.prefix > 16) + (r.prefix > 24));
            QByteArray e = dumpEntry(r.flags | (r.gw ? RTF_GATEWAY : 0), r.ifindex, r.dst, r.gw != 0, r.gw, qMin(maskLen, 5),
                                     quint8(maskOf(r.prefix) >> 24));
            out += e;
        }
        return out;
    }
    bool pinned(int ifindex, quint32 dst) const
    {
        int best = -1;
        bool bestOk = false;
        for (const Route &r : routes) {
            const bool mine = (r.flags & RTF_IFSCOPE) && r.ifindex == ifindex;
            if ((dst & maskOf(r.prefix)) != r.dst || r.prefix < best || (r.prefix == best && !mine))
                continue; // the longest match; at an equal length a route scoped to the pinned interface wins
            if (r.flags & RTF_IFSCOPE) {
                if (r.ifindex != ifindex)
                    continue;
                best = r.prefix;
                bestOk = true;
            } else if (r.prefix == 0 || r.ifindex == ifindex) {
                best = r.prefix;
                bestOk = r.ifindex == ifindex;
            } else {
                best = r.prefix;
                bestOk = false; // another interface's route hides the primary default
            }
        }
        return bestOk;
    }
    TribeScanRouteOps ops()
    {
        TribeScanRouteOps o;
        o.pinned = [this](int ifindex, quint32 dst) { return pinned(ifindex, dst); };
        o.table = [this]() { return dump(); };
        o.recordRead = [this]() { return disk; };
        o.recordWrite = [this](const QByteArray &b) {
            if (!alive())
                return true; // a dead process believes nothing
            spend();
            if (diskFails)
                return false;
            disk = b;
            return true;
        };
        o.write = [this](bool add, const TribeScanHalfRoute &r) {
            if (!alive())
                return 0;
            spend();
            writes << QStringLiteral("%1:%2").arg(add ? QStringLiteral("add") : QStringLiteral("del")).arg(r.dst == 0 ? 0 : 128);
            if (add) {
                const int e = addError.value(r.dst, 0);
                if (e == EEXIST || hasHalf(r.dst, r.ifindex, r.gateway) || hasHalf(r.dst, r.ifindex, 0)) {
                    if (!hasHalf(r.dst, r.ifindex, r.gateway))
                        routes << Route{r.dst, 1, RTF_UP | RTF_IFSCOPE | RTF_STATIC | RTF_GATEWAY, r.ifindex, r.gateway};
                    return EEXIST;
                }
                if (e != 0)
                    return e;
                routes << Route{r.dst, 1, RTF_UP | RTF_IFSCOPE | RTF_STATIC | RTF_GATEWAY, r.ifindex, r.gateway};
                return 0;
            }
            if (const int e = deleteError.value(r.dst, 0))
                return e;
            for (int i = 0; i < routes.size(); ++i)
                if (routes.at(i).dst == r.dst && routes.at(i).prefix == 1 && (routes.at(i).flags & RTF_IFSCOPE)
                    && routes.at(i).ifindex == r.ifindex) {
                    routes.removeAt(i);
                    return 0;
                }
            return ESRCH;
        };
        return o;
    }
};
#endif

static void uplinkRoutes()
{
#ifdef Q_OS_MACOS
    // The message the service writes: RTM_ADD / RTM_DELETE of one half, scoped to the uplink.
    TribeScanHalfRoute hi;
    hi.dst = kTribeScanHalfHigh;
    hi.gateway = 0xC0000201u; // 192.0.2.1
    hi.ifindex = 7;
    for (const bool add : {true, false}) {
        const QByteArray m = tribeScanHalfRouteMessage(add, hi, 42);
        rt_msghdr h{};
        CHECK(m.size() == qsizetype(sizeof(h) + 3 * sizeof(sockaddr_in)));
        if (m.size() < qsizetype(sizeof(h) + 3 * sizeof(sockaddr_in)))
            continue;
        std::memcpy(&h, m.constData(), sizeof(h));
        CHECK_EQ(int(h.rtm_msglen), int(m.size()));
        CHECK_EQ(int(h.rtm_version), RTM_VERSION);
        CHECK_EQ(int(h.rtm_type), add ? RTM_ADD : RTM_DELETE);
        CHECK_EQ(int(h.rtm_index), 7);
        CHECK_EQ(h.rtm_seq, 42);
        CHECK_EQ(h.rtm_addrs, RTA_DST | RTA_GATEWAY | RTA_NETMASK);
        CHECK_EQ(h.rtm_flags, RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_IFSCOPE);
        CHECK_EQ(saAt(m, sizeof(h)), kTribeScanHalfHigh);
        CHECK_EQ(saAt(m, sizeof(h) + sizeof(sockaddr_in)), 0xC0000201u);
        CHECK_EQ(saAt(m, sizeof(h) + 2 * sizeof(sockaddr_in)), 0x80000000u); // a /1 mask
    }

    // The route table: the default's IPv4 router per interface (the uplink's router when getGatewayAndIface
    // hands an IPv6 gateway).
    const int scoped = RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_IFSCOPE;
    const QByteArray dump = dumpEntry(RTF_UP | RTF_GATEWAY | RTF_STATIC, 7, 0, true, 0xC0000201u, 0)   // primary default en7
                            + dumpEntry(scoped, 9, 0, true, 0xC6336401u, 0)                          // scoped default en9
                            + dumpEntry(RTF_UP | RTF_STATIC, 20, 0, false, 0, 5)                     // the tunnel's 0/1
                            + dumpEntry(scoped, 7, kTribeScanHalfLow, true, 0xC0000201u, 5)          // a half route
                            + dumpEntry(scoped, 11, 0x0A000000u, true, 0xC0000201u, 5, 0xFF);        // 10/8 on en11
    CHECK_EQ(tribeScanDefaultRouter(dump, 7), 0xC0000201u);
    CHECK_EQ(tribeScanDefaultRouter(dump, 9), 0xC6336401u); // a scoped default when there is no primary one
    CHECK_EQ(tribeScanDefaultRouter(dump, 20), 0u);         // the tunnel has no IPv4 router
    CHECK_EQ(tribeScanDefaultRouter(dump, 11), 0u);         // a /8 is no default
    CHECK_EQ(tribeScanDefaultRouter(dump.left(dump.size() - 3), 7), 0xC0000201u); // a cut dump: no read past its end
    CHECK_EQ(tribeScanDefaultRouter(QByteArray(), 7), 0u);

    // The scoped half routes this process writes are no path fact - the kernel's delete report of one (as the test Mac
    // showed it: GATEWAY, STATIC, PRCLONING, IFSCOPE, CONDEMNED, the /1 mask trimmed to 5 bytes) read as a loss of the
    // uplink and moved the generation after every scan; anyone else's still counts, and so does any other route.
    const auto report = [](int type, int pid, int flags, quint32 dst, int maskLen, quint8 maskByte) {
        QByteArray m = dumpEntry(flags, 7, dst, true, 0xC0000201u, maskLen, maskByte);
        rt_msghdr h{};
        std::memcpy(&h, m.constData(), sizeof(h));
        h.rtm_type = u_char(type);
        h.rtm_pid = pid;
        std::memcpy(m.data(), &h, sizeof(h));
        return m;
    };
    const int deleted = RTF_GATEWAY | RTF_DONE | RTF_STATIC | RTF_PRCLONING | RTF_IFSCOPE | RTF_CONDEMNED;
    const auto ev = [](const QByteArray &m, qint64 pid) { return tribeScanRouteEvent(m.constData(), m.size(), 7, pid); };
    for (const quint32 half : {kTribeScanHalfLow, kTribeScanHalfHigh}) {
        TribeScanRouteEvent e = ev(report(RTM_DELETE, 4242, deleted, half, 5, 0x80), 4242);
        CHECK(!e.resample && !e.loss);
        e = ev(report(RTM_ADD, 4242, RTF_UP | RTF_GATEWAY | RTF_DONE | RTF_STATIC | RTF_IFSCOPE, half, 5, 0x80), 4242);
        CHECK(!e.resample && !e.loss);
        e = ev(report(RTM_DELETE, 4243, deleted, half, 5, 0x80), 4242); // another process's
        CHECK(e.resample && e.loss);
    }
    TribeScanRouteEvent e = ev(report(RTM_DELETE, 4242, RTF_GATEWAY | RTF_DONE | RTF_STATIC, kTribeScanHalfLow, 5, 0x80), 4242);
    CHECK(e.resample && e.loss); // not scoped: not one of these
    e = ev(report(RTM_DELETE, 4242, deleted, 0, 0, 0), 4242);
    CHECK(e.resample && e.loss); // a scoped default of the uplink: a path fact
    e = ev(report(RTM_DELETE, 4242, deleted, 0x0A000000u, 5, 0xFF), 4242);
    CHECK(e.resample && e.loss); // a scoped /8: not a half
    e = ev(report(RTM_DELETE, 4242, deleted, kTribeScanHalfHigh, 5, 0x80), -1);
    CHECK(e.resample && e.loss); // no pid given (the tests above): as before
#endif

    // The record of what was added: written as it was, read back as it was; anything else in it is dropped.
    {
        TribeScanHalfRoute lo;
        lo.dst = kTribeScanHalfLow;
        lo.gateway = 0xC0000201u;
        lo.ifindex = 11;
        TribeScanHalfRoute up = lo;
        up.dst = kTribeScanHalfHigh;
        const QByteArray rec = tribeScanHalfRoutesRecord({lo, up});
        CHECK_EQ(rec, QByteArray("half 0 c0000201 11\nhalf 80000000 c0000201 11\n"));
        CHECK(tribeScanParseHalfRoutesRecord(rec) == (QList<TribeScanHalfRoute>{lo, up}));
        CHECK(tribeScanHalfRoutesRecord({}).isEmpty());
        CHECK(tribeScanParseHalfRoutesRecord("half a000000 c0000201 11\n"        // not a half
                                             "half 0 0 11\n"                     // no gateway
                                             "half 0 c0000201 0\n"               // no interface
                                             "full 0 c0000201 11\n"              // not a record line
                                             "half 0 c0000201 11 extra\n"
                                             "half 0 c0000201 11\nhalf 0 c0000201 11\n") // a duplicate
              == (QList<TribeScanHalfRoute>{lo}));
        CHECK(tribeScanParseHalfRoutesRecord(QByteArray(5000, 'x')).isEmpty());
    }

#ifdef Q_OS_MACOS
    // Review N2: the need is read from the table, half by half - never from one sample address.
    {
        FakeKernel k;
        k.defaultOff();
        TribeScanHalfNeed n = tribeScanHalvesNeeded(k.dump(), FakeKernel::kUp);
        CHECK(!n.low && !n.high); // the VPN off: loopback, link-local, multicast and the LAN hide nothing
        k.awgTunnel();
        n = tribeScanHalvesNeeded(k.dump(), FakeKernel::kUp);
        CHECK(n.low && n.high); // AmneziaWG
        k.add(0x01010101u, 32, RTF_STATIC | RTF_GATEWAY, FakeKernel::kUp, FakeKernel::kRouter); // an exclusion 1.1.1.1/32
        n = tribeScanHalvesNeeded(k.dump(), FakeKernel::kUp);
        CHECK(n.low && n.high);                       // the exclusion does not unhide the rest of the low half
        CHECK(k.pinned(FakeKernel::kUp, kTribeScanTestLow)); // ... though the old sample address now routes
        CHECK(!k.pinned(FakeKernel::kUp, 0x05050505u));      // ... and its neighbours do not
        FakeKernel x;
        x.defaultOff();
        for (int p = 1; p <= 7; ++p) // an Xray tun's split 1/8 .. 64/2, 128/1
            x.add(p == 1 ? 0x80000000u : (0x80000000u >> (p - 1)), p == 1 ? 1 : p, RTF_STATIC, 22);
        n = tribeScanHalvesNeeded(x.dump(), FakeKernel::kUp);
        CHECK(n.low && n.high); // a finer split hides both halves too
        x.routes << FakeKernel::Route{kTribeScanHalfLow, 1, RTF_UP | RTF_IFSCOPE | RTF_STATIC | RTF_GATEWAY, FakeKernel::kUp, FakeKernel::kRouter};
        x.routes << FakeKernel::Route{kTribeScanHalfHigh, 1, RTF_UP | RTF_IFSCOPE | RTF_STATIC | RTF_GATEWAY, FakeKernel::kUp, FakeKernel::kRouter};
        n = tribeScanHalvesNeeded(x.dump(), FakeKernel::kUp);
        CHECK(!n.low && !n.high); // ... and the Xray session's own scoped pair serves them
        FakeKernel h;
        h.defaultOff();
        h.add(0x08080808u, 32, RTF_STATIC | RTF_GATEWAY, 20, 0x0A000001u); // a host route into a tunnel
        h.add(0xC6336402u, 32, RTF_WASCLONED | RTF_GATEWAY, 20, 0x0A000001u); // a clone: churn, ignored
        n = tribeScanHalvesNeeded(h.dump(), FakeKernel::kUp);
        CHECK(n.low && !n.high);
        FakeKernel sd;
        sd.defaultOff();
        sd.awgTunnel();
        sd.add(0, 0, RTF_STATIC | RTF_GATEWAY | RTF_IFSCOPE, FakeKernel::kUp, FakeKernel::kRouter); // a scoped default
        n = tribeScanHalvesNeeded(sd.dump(), FakeKernel::kUp);
        CHECK(!n.low && !n.high);
    }

    // The arm: nothing when the table serves pinned sockets; both halves under AmneziaWG (with an exclusion too).
    TribeScanUplink u = phys();
    {
        FakeKernel k; // the VPN off
        k.defaultOff();
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        CHECK(a.result == 0 && a.added.isEmpty() && k.writes.isEmpty() && k.disk.isEmpty());
    }
    {
        FakeKernel k; // AmneziaWG + an exclusion 1.1.1.1/32 via the uplink: the old sample test added only the high half
        k.defaultOff();
        k.awgTunnel();
        k.add(0x01010101u, 32, RTF_STATIC | RTF_GATEWAY, FakeKernel::kUp, FakeKernel::kRouter);
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        CHECK_EQ(a.result, 1);
        CHECK_EQ(k.writes, (QStringList{QStringLiteral("add:0"), QStringLiteral("add:128")}));
        CHECK(a.added.size() == 2 && k.halves() == 2);
        CHECK(k.pinned(FakeKernel::kUp, 0x05050505u) && k.pinned(FakeKernel::kUp, 0xC6336401u));
        CHECK(tribeScanParseHalfRoutesRecord(k.disk) == a.added); // recorded: exactly what was added
        CHECK(tribeScanRemoveHalfRoutes(a.added, k.ops()).isEmpty());
        CHECK(k.halves() == 0 && k.disk.isEmpty());
    }
    {
        FakeKernel k; // someone's low half arrives between the table read and our add: never ours
        k.defaultOff();
        k.awgTunnel();
        k.addError.insert(kTribeScanHalfLow, EEXIST);
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        CHECK(a.result == 1 && a.added.size() == 1 && a.added.first().dst == kTribeScanHalfHigh);
        CHECK(tribeScanParseHalfRoutesRecord(k.disk) == a.added);
        tribeScanRemoveHalfRoutes(a.added, k.ops());
        CHECK(k.halves() == 1 && k.disk.isEmpty()); // someone's stays
    }
    {
        FakeKernel k; // the second add fails: the first goes again, nothing recorded, fail closed
        k.defaultOff();
        k.awgTunnel();
        k.addError.insert(kTribeScanHalfHigh, EPERM);
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        CHECK(a.result == -1 && a.added.isEmpty() && k.halves() == 0 && k.disk.isEmpty());
        CHECK_EQ(k.writes, (QStringList{QStringLiteral("add:0"), QStringLiteral("add:128"), QStringLiteral("del:0")}));
    }
    {
        FakeKernel k; // the intent cannot be made durable: nothing is added
        k.defaultOff();
        k.awgTunnel();
        k.diskFails = true;
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        CHECK(a.result == -1 && k.writes.isEmpty() && k.halves() == 0);
    }
    {
        FakeKernel k; // needed, no IPv4 router anywhere: nothing written, fail closed
        k.awgTunnel();
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, 0, k.ops());
        CHECK(a.result == -1 && k.writes.isEmpty() && k.disk.isEmpty());
    }
    {
        FakeKernel k; // the router from the table when the uplink's gateway is not IPv4
        k.defaultOff();
        k.awgTunnel();
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, 0, k.ops());
        CHECK(a.result == 1 && a.added.size() == 2 && a.added.first().gateway == FakeKernel::kRouter);
    }
    {
        FakeKernel k;
        TribeScanUplink bad = u;
        bad.name = QStringLiteral("utun4");
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(bad, FakeKernel::kRouter, k.ops());
        CHECK(a.result == 0 && k.writes.isEmpty());
    }

    // Review N3: the record is an intent log. A kill between ANY two mutations of an arm or a removal leaves nothing of
    // ours behind once the next service start recovers - and a route of someone else is never touched.
    for (int kill = 0; kill <= 4; ++kill) {
        FakeKernel k;
        k.defaultOff();
        k.awgTunnel();
        k.budget = kill; // dies after `kill` mutations of the arm (intent, add, add, ...)
        tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        k.budget = -1; // the next service instance
        tribeScanRecoverHalfRoutes(k.ops());
        if (k.halves() != 0 || !k.disk.isEmpty())
            std::fprintf(stderr, "  kill after %d mutations of an arm: halves %d record '%s'\n", kill, k.halves(), k.disk.constData());
        CHECK(k.halves() == 0 && k.disk.isEmpty());
    }
    for (int kill = 0; kill <= 3; ++kill) {
        FakeKernel k;
        k.defaultOff();
        k.awgTunnel();
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        CHECK(a.result == 1);
        k.budget = kill; // dies inside the removal (del, del, record)
        tribeScanRemoveHalfRoutes(a.added, k.ops());
        k.budget = -1;
        tribeScanRecoverHalfRoutes(k.ops());
        CHECK(k.halves() == 0 && k.disk.isEmpty());
    }
    {
        FakeKernel k; // an Xray session's pair (not recorded) is never removed by a recovery or by our removal
        k.defaultOff();
        k.awgTunnel();
        k.routes << FakeKernel::Route{kTribeScanHalfLow, 1, RTF_UP | RTF_IFSCOPE | RTF_STATIC | RTF_GATEWAY, FakeKernel::kUp, FakeKernel::kRouter};
        k.routes << FakeKernel::Route{kTribeScanHalfHigh, 1, RTF_UP | RTF_IFSCOPE | RTF_STATIC | RTF_GATEWAY, FakeKernel::kUp, FakeKernel::kRouter};
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        CHECK(a.result == 0 && k.writes.isEmpty() && k.disk.isEmpty()); // served: nothing recorded
        tribeScanRecoverHalfRoutes(k.ops());
        CHECK(k.halves() == 2);
    }
    {
        FakeKernel k; // the record names a route that someone has since replaced (another gateway): forgotten, kept
        k.defaultOff();
        TribeScanHalfRoute rec;
        rec.dst = kTribeScanHalfLow;
        rec.gateway = FakeKernel::kRouter;
        rec.ifindex = FakeKernel::kUp;
        k.disk = tribeScanHalfRoutesRecord({rec});
        k.routes << FakeKernel::Route{kTribeScanHalfLow, 1, RTF_UP | RTF_IFSCOPE | RTF_STATIC | RTF_GATEWAY, FakeKernel::kUp, 0xC00002FEu};
        CHECK_EQ(tribeScanRecoverHalfRoutes(k.ops()), 0);
        CHECK(k.halves() == 1 && k.disk.isEmpty() && k.writes.isEmpty());
        k.disk = tribeScanHalfRoutesRecord({rec}); // ... or gone (a reboot): forgotten
        k.routes.clear();
        CHECK_EQ(tribeScanRecoverHalfRoutes(k.ops()), 0);
        CHECK(k.disk.isEmpty());
        k.disk = "garbage\n"; // an unreadable record: nothing of it can be told ours
        CHECK_EQ(tribeScanRecoverHalfRoutes(k.ops()), 0);
        CHECK(k.disk.isEmpty());
    }
    {
        FakeKernel k; // a delete that fails stays recorded and is retried by the next recovery
        k.defaultOff();
        k.awgTunnel();
        const TribeScanRouteArm a = tribeScanArmHalfRoutes(u, FakeKernel::kRouter, k.ops());
        k.deleteError.insert(kTribeScanHalfLow, EPERM);
        const QList<TribeScanHalfRoute> left = tribeScanRemoveHalfRoutes(a.added, k.ops());
        CHECK(left.size() == 1 && left.first().dst == kTribeScanHalfLow);
        CHECK(tribeScanParseHalfRoutesRecord(k.disk) == left && k.halves() == 1);
        k.deleteError.clear();
        CHECK_EQ(tribeScanRecoverHalfRoutes(k.ops()), 1);
        CHECK(k.halves() == 0 && k.disk.isEmpty());
    }
#endif

    // The host: the routes live exactly as long as the scan's pf exemption, and go first when the uplink moves.
    fake::engine().reset();
    Harness h;
    CHECK_EQ(h.routeClears.load(), 1); // crash recovery at start: the routes a previous instance recorded
    const auto progress = [](const QByteArray &msg, const QByteArray &) -> QByteArray {
        const QJsonObject o = obj(msg);
        const QString id = o.value(QLatin1String("scan_id")).toString();
        if (o.value(QLatin1String("action")).toString() == QLatin1String("scan_start"))
            return QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"%1\",\"accepted\":1,\"mem_mb\":9}").arg(id).toUtf8();
        return QStringLiteral("{\"type\":\"scan_progress\",\"scan_id\":\"%1\",\"seq\":3,\"phase\":\"done\",\"items\":[],"
                              "\"bytes_spent\":1,\"done\":true,\"final\":true}")
            .arg(id)
            .toUtf8();
    };
    fake::engine().reply = progress;
    QByteArray r;
    // Not needed (the VPN off, an Xray session): no route is written or deleted.
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt0")), &r), 0);
    CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"rt0","since":0})", &r), 0);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("routes:")), 0);

    TribeScanRouteArm need;
    need.result = 1;
    TribeScanHalfRoute lo;
    lo.dst = kTribeScanHalfLow;
    lo.gateway = 0xC0000201u;
    lo.ifindex = 7;
    TribeScanHalfRoute hiR = lo;
    hiR.dst = kTribeScanHalfHigh;
    need.added = {lo, hiR};
    h.setRouteArm(need);
    // Needed (AmneziaWG up): pf first, then the routes, then the engine; the final reply removes both.
    fake::engine().reset();
    fake::engine().reply = progress;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt1")), &r), 0);
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Ack);
    CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"rt1","since":0})", &r), 0);
    QList<QString> order = fake::engine().orderSnapshot();
    const QList<QString> want1 = {QStringLiteral("arm:en7"), QStringLiteral("routes:arm:7"), QStringLiteral("scan_message:scan_start"),
                                  QStringLiteral("scan_message:scan_poll"), QStringLiteral("routes:disarm:2"), QStringLiteral("disarm")};
    if (order != want1)
        std::fprintf(stderr, "  routes order: %s\n", qPrintable(order.join(QLatin1Char(' '))));
    CHECK_EQ(order, want1);

    // A tunnel change ends the scan: the engine stops, then its routes and its exemption go.
    fake::engine().reset();
    fake::engine().reply = progress;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt2")), &r), 0);
    tribeScanBeforeTunnelChange("awg_deactivate");
    order = fake::engine().orderSnapshot();
    const QList<QString> want2 = {QStringLiteral("arm:en7"), QStringLiteral("routes:arm:7"), QStringLiteral("scan_message:scan_start"),
                                  QStringLiteral("stop_all:2000"), QStringLiteral("routes:disarm:2"), QStringLiteral("disarm")};
    if (order != want2)
        std::fprintf(stderr, "  routes order: %s\n", qPrintable(order.join(QLatin1Char(' '))));
    CHECK_EQ(order, want2);

    // The uplink moves under a scan: its routes lead to a router it may no longer have - they go at once, once.
    fake::engine().reset();
    fake::engine().reply = progress;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt3")), &r), 0);
    TribeScanUplink moved = phys();
    moved.gateway = QStringLiteral("192.0.2.254");
    h.setUplink(moved);
    h.host->notePathEvent(false);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("routes:disarm:2")), 1);
    h.host->notePathEvent(false); // nothing moved since
    CHECK_EQ(h.send(R"({"action":"scan_poll","scan_id":"rt3","since":0})", &r), 0);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("routes:disarm:")), 1);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("disarm")), 1); // the exemption at the final
    h.setUplink(phys());

    // A scan replaced by the next start: the old routes go before the new arm.
    fake::engine().reset();
    fake::engine().reply = [](const QByteArray &msg, const QByteArray &) {
        return QStringLiteral("{\"type\":\"scan_ack\",\"scan_id\":\"%1\",\"accepted\":1,\"mem_mb\":9}")
            .arg(obj(msg).value(QLatin1String("scan_id")).toString())
            .toUtf8();
    };
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt4a")), &r), 0);
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt4b")), &r), 0);
    order = fake::engine().orderSnapshot();
    const QList<QString> want4 = {QStringLiteral("arm:en7"), QStringLiteral("routes:arm:7"), QStringLiteral("scan_message:scan_start"),
                                  QStringLiteral("arm:en7"), QStringLiteral("routes:disarm:2"), QStringLiteral("routes:arm:7"),
                                  QStringLiteral("scan_message:scan_start")};
    if (order != want4)
        std::fprintf(stderr, "  routes order: %s\n", qPrintable(order.join(QLatin1Char(' '))));
    CHECK_EQ(order, want4);
    tribeScanBeforeTunnelChange("xray_stop"); // rt4b ends
    // ... and a scan the app never closes loses them at its deadline with its exemption.
    QList<std::function<void()>> fires;
    h.host->setDisarmTimerForTest([&](qint64, std::function<void()> fire) { fires << std::move(fire); });
    fake::engine().reset();
    fake::engine().reply = [](const QByteArray &, const QByteArray &) { return QByteArray(R"({"type":"scan_ack","scan_id":"rt5","accepted":1,"mem_mb":9})"); };
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt5"), 1000), &r), 0);
    CHECK(waitFor([&]() { return fires.size() == 1; }));
    if (!fires.isEmpty())
        fires.last()();
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("routes:disarm:2")), 1);
    h.host->setDisarmTimerForTest(nullptr);

    // Needed but not in force: the no-uplink refusal, the engine never asked, the exemption armed for it removed.
    TribeScanRouteArm fail;
    fail.result = -1;
    h.setRouteArm(fail);
    fake::engine().reset();
    fake::engine().reply = progress;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt6")), &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"bad_request","detail":"host_options.bind_interface"})"));
    order = fake::engine().orderSnapshot();
    CHECK_EQ(countOf(order, QStringLiteral("scan_message:")), 0);
    CHECK(order.size() >= 3 && order.at(0) == QStringLiteral("arm:en7") && order.at(1) == QStringLiteral("routes:arm:7")
          && order.at(2) == QStringLiteral("disarm"));

    // Review N2: a target without a pinned route - the scan never runs (nothing could be stored as "not working");
    // what was armed for it goes. Same for an add of the running scan.
    h.setRouteArm(need);
    {
        QMutexLocker l(&h.uplinkMutex);
        h.unrouted = {0xCB007109u}; // 203.0.113.9: the request's entry
    }
    fake::engine().reset();
    fake::engine().reply = progress;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt6b")), &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"bad_request","detail":"host_options.bind_interface"})"));
    order = fake::engine().orderSnapshot();
    CHECK_EQ(countOf(order, QStringLiteral("scan_message:")), 0);
    CHECK(order.size() >= 4 && order.at(0) == QStringLiteral("arm:en7") && order.at(1) == QStringLiteral("routes:arm:7")
          && order.at(2) == QStringLiteral("routes:disarm:2") && order.at(3) == QStringLiteral("disarm"));
    {
        QMutexLocker l(&h.uplinkMutex);
        h.unrouted.clear();
    }
    fake::engine().reset();
    fake::engine().reply = progress;
    h.clock += 2000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt6c")), &r), 0); // routed: runs
    CHECK(scanDecodeReply(r).kind == ScanHostReplyKind::Ack);
    {
        QMutexLocker l(&h.uplinkMutex);
        h.unrouted = {0xC6336414u}; // an added provider's entry 198.51.100.20
    }
    const QByteArray addMsg =
        R"({"action":"scan_add","scan_id":"rt6c","candidates":[{"id":"p1","kind":"xray_full","entry":{"ip":"198.51.100.20","port":443}}]})";
    CHECK_EQ(h.send(addMsg, &r), 0);
    CHECK_EQ(r, QByteArray(R"({"error":"bad_request","detail":"host_options.bind_interface"})"));
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("scan_message:scan_add")), 0);
    {
        QMutexLocker l(&h.uplinkMutex);
        h.unrouted.clear();
    }
    CHECK_EQ(h.send(addMsg, &r), 0);
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("scan_message:scan_add")), 1);
    tribeScanBeforeTunnelChange("awg_deactivate");
    CHECK(tribeScanInspectRequest(addMsg).entryIps == (QList<quint32>{0xC6336414u}));
    CHECK(tribeScanInspectRequest(startRequest(QStringLiteral("x"))).entryIps == (QList<quint32>{0xCB007109u}));

    // Shutdown with a scan's routes in place: they go.
    h.setRouteArm(need);
    fake::engine().reset();
    fake::engine().reply = progress;
    h.clock += 20000;
    CHECK_EQ(h.send(startRequest(QStringLiteral("rt7")), &r), 0);
    h.host->shutdown();
    CHECK_EQ(countOf(fake::engine().orderSnapshot(), QStringLiteral("routes:disarm:2")), 1);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    qInstallMessageHandler(captureLog);
    const QString vectors = argc > 1 ? QString::fromLocal8Bit(argv[1])
                                     : qEnvironmentVariable("TRIBE_SCAN_VECTORS");
    pureParts();
    awgParts();
    relayRoundTrip();
    vectorReplay(vectors);
    startPath();
    bounds();
    generation();
    awgHost();
    teardownTests();
    uplinkRoutes();
    childKill();
    logInjection();
    logPrivacy(vectors);
    qInstallMessageHandler(nullptr);
    std::printf("tribe_scan_check: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
