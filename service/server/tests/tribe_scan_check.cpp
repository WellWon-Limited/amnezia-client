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
#include <cstdio>
#include <memory>
#include <cstring>
#include <thread>
#include <unistd.h>
#include <utility>

#ifdef Q_OS_MACOS
    #include <csignal>
    #include <libproc.h>
    #include <net/if.h>
    #include <net/route.h>
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
    childKill();
    logInjection();
    logPrivacy(vectors);
    qInstallMessageHandler(nullptr);
    std::printf("tribe_scan_check: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
