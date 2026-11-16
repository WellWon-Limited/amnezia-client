// service/server/tests/tribe_scan_engine_check.cpp
// AVPN: the Scanner's service host against the REAL bindings archive (libamnezia_xray.a with the
// tribe-scan exports): the production glue of tribe_scan.cpp (engineMessage / engineStopAll / host
// options) talks to the Go engine, and a tunnel socket callback registered the way Xray::startXray does
// (amnezia_xray_setsockcallback) is never invoked for any probe socket - the reach dial, the probe
// instances' outbound dials and the direct access attempts all go to closed loopback ports on a socket
// bound to lo0, so nothing leaves the machine. Every reply decodes with the app's ScanHostContract.h.
// Run by build_tribe_scan.sh when a bindings package with the exports is found.
#include "tribe_scan.h"

#include "core/serviceEngine/DaemonScanHost.h"
#include "core/serviceEngine/ScanHostContract.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QThread>

#include <amnezia_xray.h>

#include <arpa/inet.h>
#include <atomic>
#include <csignal>
#include <libproc.h>
#include <spawn.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <vector>
extern char **environ;
#include <cstdio>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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

static std::atomic<int> g_tunnelCallback{0};

static int closedLoopbackPort()
{
    const int s = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    ::bind(s, reinterpret_cast<sockaddr *>(&a), sizeof(a));
    socklen_t len = sizeof(a);
    ::getsockname(s, reinterpret_cast<sockaddr *>(&a), &len);
    ::close(s); // nothing listens there now: every dial is refused at once
    return ntohs(a.sin_port);
}

static QJsonObject vless(const QString &tag, int port)
{
    return QJsonObject{{"tag", tag},
                       {"protocol", "vless"},
                       {"settings",
                        QJsonObject{{"vnext", QJsonArray{QJsonObject{{"address", "127.0.0.1"},
                                                                     {"port", port},
                                                                     {"users", QJsonArray{QJsonObject{{"id", "6b0e6e1c-0f5b-4e1e-9d1a-2a3b4c5d6e7f"},
                                                                                                      {"encryption", "none"}}}}}}}}}};
}

template <typename P>
static bool waitUntil(P pred, int ms)
{
    QElapsedTimer t;
    t.start();
    while (!pred()) {
        if (t.elapsed() > ms)
            return false;
        QThread::msleep(5);
    }
    return true;
}

// This process's AF_INET / AF_INET6 sockets (the probe instances live in it).
static int inetSockets()
{
    const int bytes = proc_pidinfo(::getpid(), PROC_PIDLISTFDS, 0, nullptr, 0);
    if (bytes <= 0)
        return -1;
    std::vector<proc_fdinfo> fds(size_t(bytes) / sizeof(proc_fdinfo) + 32);
    const int got = proc_pidinfo(::getpid(), PROC_PIDLISTFDS, 0, fds.data(), int(fds.size() * sizeof(proc_fdinfo)));
    int n = 0;
    for (int i = 0; i < got / int(sizeof(proc_fdinfo)); ++i) {
        if (fds[size_t(i)].proc_fdtype != PROX_FDTYPE_SOCKET)
            continue;
        socket_fdinfo si;
        if (proc_pidfdinfo(::getpid(), fds[size_t(i)].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si)) == int(sizeof(si))
            && (si.psi.soi_family == AF_INET || si.psi.soi_family == AF_INET6))
            ++n;
    }
    return n;
}

// Every child of this process, alive or not yet reaped.
static int children()
{
    pid_t pids[256];
    return proc_listchildpids(::getpid(), pids, sizeof(pids));
}

static pid_t spawnHelper(const QString &path, const QStringList &args)
{
    QList<QByteArray> store{path.toLocal8Bit()};
    for (const QString &a : args)
        store << a.toLocal8Bit();
    std::vector<char *> argv;
    for (QByteArray &b : store)
        argv.push_back(b.data());
    argv.push_back(nullptr);
    pid_t pid = -1;
    return posix_spawn(&pid, store.first().constData(), nullptr, nullptr, argv.data(), environ) == 0 ? pid : -1;
}

static QString awgCandidateConfig(int ifIndex, int udpPort, int tcpPort)
{
    const QString uapi = QStringLiteral("private_key=%1\nlisten_port=0\nreplace_peers=true\npublic_key=%2\nendpoint=127.0.0.1:%3\n"
                                        "replace_allowed_ips=true\nallowed_ip=127.0.0.1/32\n")
                             .arg(QString(QStringLiteral("11")).repeated(32), QString(QStringLiteral("22")).repeated(32))
                             .arg(udpPort);
    return QString::fromUtf8(QJsonDocument(QJsonObject{{"uapi", uapi},
                                                       {"address", "10.8.0.2/32"},
                                                       {"mtu", 1280},
                                                       {"bound_if", ifIndex},
                                                       {"prime_echo_target", QJsonValue::Null},
                                                       {"probe", QJsonObject{{"host", "example.com"}, {"ip", "127.0.0.1"}, {"port", tcpPort}}}})
                                 .toJson(QJsonDocument::Compact));
}

// A scan stopped through the service's own stop (the epoch message) while one probe is in flight: when the
// stop answers true, no probe child of this process and no probe socket is left; with a hung child the
// stop still answers within its bound.
static void stopProofs(const TribeScanDeps &deps, const ScanNetSource &gen, const TribeScanUplink &lo, qint64 &epoch)
{
    const QString helper = qEnvironmentVariable("TRIBE_SCAN_SLEEPER");
    const QString probeBin = qEnvironmentVariable("TRIBE_AWG_PROBE_BIN");
    CHECK(!helper.isEmpty() && !probeBin.isEmpty());
    if (helper.isEmpty() || probeBin.isEmpty())
        return;
    CHECK(children() == 0);
    const auto startScan = [&](const QString &id, const ScanHostCandidate &c, const QString &awgBinary) {
        ScanStartRequest r;
        r.scanId = id;
        r.deadlineMs = 60000;
        r.probeBase = QStringLiteral("https://127.0.0.1:%1").arg(closedLoopbackPort());
        r.token = QStringLiteral("stop-proof-token-0123456789");
        r.limits.concurrency = c.kind == ScanProbeKind::XrayFull ? 1 : 0;
        r.limits.legConcurrency = c.kind == ScanProbeKind::XrayLeg ? 1 : 0;
        r.limits.awgConcurrency = c.kind == ScanProbeKind::AwgMini ? 1 : 0;
        r.limits.ttfbMs = 15000;
        r.limits.totalMs = 30000;
        r.limits.stallMs = 10000;
        r.limits.awgHandshakeMs = 5000; // the contract maximum: the child waits that long
        r.limits.entryIpSpacingMs = 0;
        r.limits.stage1StaggerMs = 0;
        r.candidates = {c};
        TribeScanAwgOptions awg;
        awg.binary = awgBinary;
        const QByteArray raw = deps.message(scanCompact(scanEncodeStart(r)), tribeScanHostOptions(gen, &lo, &awg, epoch));
        const ScanHostReply a = scanDecodeReply(raw);
        if (a.kind != ScanHostReplyKind::Ack)
            std::fprintf(stderr, "  start %s refused: %s\n", qPrintable(id), raw.left(200).constData());
        return a.kind == ScanHostReplyKind::Ack;
    };
    const auto stopNow = [&](int waitMs, qint64 *elapsed) {
        ++epoch; // a tunnel change
        QElapsedTimer t;
        t.start();
        const bool ok = deps.stopAll(waitMs, epoch).stopped;
        *elapsed = t.elapsed();
        return ok;
    };
    qint64 took = 0;

    // 1. An Xray leg stalled on a path that accepts and never answers.
    const int holdPort = closedLoopbackPort();
    const pid_t holder = spawnHelper(helper, {QStringLiteral("--hold"), QString::number(holdPort)});
    CHECK(holder > 0);
    CHECK(waitUntil([&]() {
        const int s = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(quint16(holdPort));
        const bool up = ::connect(s, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0;
        ::close(s);
        return up;
    }, 5000));
    const int base = inetSockets();
    ScanHostCandidate leg;
    leg.id = QStringLiteral("leg-stall");
    leg.kind = ScanProbeKind::XrayLeg;
    leg.config = QString::fromUtf8(QJsonDocument(QJsonObject{{"outbound", vless("leg", holdPort)}, {"dns", QJsonArray()}}).toJson(QJsonDocument::Compact));
    leg.costBytes = 83456;
    CHECK(startScan(QStringLiteral("stop-leg"), leg, QString()));
    CHECK(waitUntil([&]() { return inetSockets() > base; }, 5000)); // the leg's connection is open
    CHECK(stopNow(3000, &took));
    const int afterLeg = inetSockets();
    std::printf("stop during an Xray leg: true after %lld ms, sockets %d -> %d (baseline %d)\n", qlonglong(took), base + 1, afterLeg, base);
    CHECK(afterLeg == base);
    ::kill(holder, SIGKILL);
    int st = 0;
    ::waitpid(holder, &st, 0);
    // A start of the epoch before that stop is refused by the engine itself (the service drops it earlier).
    const ScanHostReply stale = scanDecodeReply(deps.message(R"({"action":"scan_add","scan_id":"stop-leg","candidates":[]})",
                                                             tribeScanHostOptions(gen, nullptr, nullptr, epoch - 1)));
    CHECK(stale.kind == ScanHostReplyKind::Error && stale.errorCode == QStringLiteral("stale_epoch"));

    // 2. A real AmneziaWG probe child waiting for a handshake that never comes.
    CHECK(children() == 0);
    ScanHostCandidate awgc;
    awgc.id = QStringLiteral("awg-wait");
    awgc.kind = ScanProbeKind::AwgMini;
    awgc.config = awgCandidateConfig(lo.index, closedLoopbackPort(), closedLoopbackPort());
    awgc.costBytes = 90000;
    CHECK(startScan(QStringLiteral("stop-awg"), awgc, probeBin));
    CHECK(waitUntil([&]() { return tribeScanProbeChildPids(probeBin).size() == 1; }, 5000));
    CHECK(stopNow(3000, &took));
    const int kidsAfterAwg = children();
    std::printf("stop during an AmneziaWG probe child: true after %lld ms, children %d, sockets %d (baseline %d)\n",
                qlonglong(took), kidsAfterAwg, inetSockets(), base);
    CHECK(kidsAfterAwg == 0); // killed AND reaped by the engine
    CHECK(inetSockets() == base);

    // 3. A hung child (reads its job, never answers): the stop still answers within its bound.
    QTemporaryDir tmp;
    const QString hung = QDir(tmp.path()).filePath(QStringLiteral("amneziawg-go"));
    CHECK(QFile::copy(helper, hung));
    QFile::setPermissions(hung, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    CHECK(startScan(QStringLiteral("stop-hung"), awgc, hung));
    CHECK(waitUntil([&]() { return tribeScanProbeChildPids(hung).size() == 1; }, 5000));
    const bool hungStopped = stopNow(2000, &took);
    std::printf("stop with a hung probe child: %s after %lld ms (bound 2000 ms), children %d\n", hungStopped ? "true" : "false",
                qlonglong(took), children());
    CHECK(hungStopped);
    CHECK(took <= 2000 + 1500); // the bound, with room for a loaded machine (an upper bound only)
    CHECK(children() == 0);
    CHECK(inetSockets() == base);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    char *err = amnezia_xray_setsockcallback([](uintptr_t, void *) { ++g_tunnelCallback; }, nullptr);
    CHECK(err == nullptr);
    if (err)
        amnezia_xray_free(err);

    const TribeScanDeps deps = tribeScanServiceDeps(); // the production glue to the real engine
    ScanNetSource gen;
    gen.source = QStringLiteral("service");
    gen.epoch = 0x1234abcd5678ef90ULL;
    gen.counter = 3;

    // Caps: the engine's own answer through the glue decodes as the desktop host the app expects.
    const ScanHostReply caps = scanDecodeReply(deps.message(R"({"action":"scan_caps"})", tribeScanHostOptions(gen)));
    CHECK(caps.kind == ScanHostReplyKind::Caps);
    CHECK(caps.caps.maxFullConcurrent == 2 && caps.caps.maxLegConcurrent == 6 && caps.caps.canVerifyComposite
          && !caps.caps.needsVpn && caps.caps.maxAwgConcurrent == 0);
    CHECK(caps.caps.platform == QStringLiteral("macos"));
    // DaemonScanHost::compiledCaps() is the service's real answer for the default configuration of the macOS
    // payload: the probe-capable amneziawg-go next to the service, no live tunnel.
    const QString probeBin = qEnvironmentVariable("TRIBE_AWG_PROBE_BIN");
    if (!probeBin.isEmpty()) {
        TribeScanAwgLive none;
        none.state = 0;
        const TribeScanAwgOptions awg = tribeScanAwgDecide(tribeScanCheckAwgProbeBinary(probeBin, false), none, false);
        CHECK(awg.binary == probeBin);
        const ScanHostReply real = scanDecodeReply(deps.message(R"({"action":"scan_caps"})", tribeScanHostOptions(gen, nullptr, &awg)));
        const ScanHostCaps cc = DaemonScanHost::compiledCaps();
        CHECK(real.kind == ScanHostReplyKind::Caps && real.kinds.contains(QStringLiteral("awg_mini")));
        CHECK(real.caps.maxFullConcurrent == cc.maxFullConcurrent && real.caps.canVerifyComposite == cc.canVerifyComposite
              && real.caps.maxLegConcurrent == cc.maxLegConcurrent && real.caps.dnsPlan == cc.dnsPlan
              && real.caps.maxAwgConcurrent == cc.maxAwgConcurrent && real.caps.reachStage == cc.reachStage
              && real.caps.needsVpn == cc.needsVpn && real.caps.platform == cc.platform);
        std::printf("compiledCaps == engine caps with the probe binary: full=%d legs=%d awg=%d composite=%d dns=%d needs_vpn=%d\n",
                    real.caps.maxFullConcurrent, real.caps.maxLegConcurrent, real.caps.maxAwgConcurrent,
                    int(real.caps.canVerifyComposite), int(real.caps.dnsPlan), int(real.caps.needsVpn));
    } else {
        std::printf("compiledCaps comparison SKIPPED: no probe-capable amneziawg-go (TRIBE_AWG_PROBE_BIN)\n");
    }

    // The shared host vectors through the real engine, without host options (nothing can start: a
    // request that passes the engine's validation reaches the macOS interface refusal instead of a scan).
    QFile vfile(qEnvironmentVariable("TRIBE_SCAN_VECTORS"));
    int replayed = 0;
    if (vfile.open(QIODevice::ReadOnly)) {
        const QJsonObject vf = QJsonDocument::fromJson(vfile.readAll()).object();
        for (const QJsonValue &v : vf.value(QLatin1String("requests")).toArray()) {
            const QJsonObject vec = v.toObject();
            const QJsonValue j = vec.value(QLatin1String("json"));
            const QByteArray bytes = j.isString() ? j.toString().toUtf8() : QJsonDocument(j.toObject()).toJson(QJsonDocument::Compact);
            const QJsonObject expect = vec.value(QLatin1String("expect")).toObject();
            const QString err = expect.value(QLatin1String("error")).toString();
            const QString detail = expect.value(QLatin1String("detail")).toString();
            const QString action = j.toObject().value(QLatin1String("action")).toString();
            const ScanHostReply d = scanDecodeReply(deps.message(bytes, QByteArray()));
            bool ok = false;
            if (!err.isEmpty())
                ok = d.kind == ScanHostReplyKind::Error && d.errorCode == err && (detail.isEmpty() || d.detail == detail);
            else if (action == QLatin1String("scan_start"))
                ok = d.kind == ScanHostReplyKind::Error && d.errorCode == QStringLiteral("bad_request")
                     && d.detail == QStringLiteral("host_options.bind_interface");
            else if (action == QLatin1String("scan_caps"))
                ok = d.kind == ScanHostReplyKind::Caps;
            else
                ok = !(d.kind == ScanHostReplyKind::Error
                       && (d.errorCode == QStringLiteral("bad_request") || d.errorCode == QStringLiteral("version")
                           || d.errorCode == QStringLiteral("unknown_action")));
            const QString name = vec.value(QLatin1String("name")).toString();
            if (!ok)
                std::fprintf(stderr, "  engine vector %s: got %s/%s\n", qPrintable(name), qPrintable(d.errorCode), qPrintable(d.detail));
            CHECK(ok);
            ++replayed;
        }
    }
    std::printf("engine: %d request vectors replayed\n", replayed);
    CHECK(replayed >= 24);

    // The engine itself refuses a macOS scan_start without an interface (the service never sends one).
    const int vlessPort = closedLoopbackPort();
    const int probePort = closedLoopbackPort();
    ScanStartRequest req;
    req.scanId = QStringLiteral("smoke-1");
    req.deadlineMs = 6000;
    req.probeBase = QStringLiteral("https://127.0.0.1:%1").arg(probePort);
    req.token = QStringLiteral("smoke-token-0123456789abcdef");
    req.limits.concurrency = 1;
    req.limits.legConcurrency = 1;
    req.limits.entryIpSpacingMs = 0;
    req.limits.stage1StaggerMs = 0;
    ScanHostCandidate full;
    full.id = QStringLiteral("full-1");
    full.kind = ScanProbeKind::XrayFull;
    full.config = QString::fromUtf8(QJsonDocument(QJsonObject{
                                                      {"log", QJsonObject{{"loglevel", "warning"}}},
                                                      {"inbounds", QJsonArray{QJsonObject{{"tag", "socks-in"},
                                                                                          {"listen", "127.0.0.1"},
                                                                                          {"port", closedLoopbackPort()},
                                                                                          {"protocol", "socks"}}}},
                                                      {"outbounds", QJsonArray{QJsonObject{{"tag", "block"}, {"protocol", "blackhole"}},
                                                                               vless("proxy", vlessPort)}},
                                                      {"routing", QJsonObject{{"rules", QJsonArray{QJsonObject{{"type", "field"},
                                                                                                             {"inboundTag", QJsonArray{"socks-in"}},
                                                                                                             {"outboundTag", "proxy"}}}}}}})
                                        .toJson(QJsonDocument::Compact));
    full.entryIp = QStringLiteral("127.0.0.1");
    full.entryPort = vlessPort;
    full.reachAtMs = -1; // no reach stage: the data probe itself dials through the instance
    full.costBytes = 83456;
    ScanHostCandidate reach = full;
    reach.id = QStringLiteral("reach-1");
    reach.reachAtMs = 0; // the reach dial (refused: final, no data probe)
    ScanHostCandidate leg;
    leg.id = QStringLiteral("leg-1");
    leg.kind = ScanProbeKind::XrayLeg;
    leg.config = QString::fromUtf8(QJsonDocument(QJsonObject{{"outbound", vless("leg", vlessPort)}, {"dns", QJsonArray()}})
                                       .toJson(QJsonDocument::Compact));
    leg.costBytes = 83456;
    req.candidates = {full, reach, leg};
    const QByteArray start = scanCompact(scanEncodeStart(req));
    const ScanHostReply noBind = scanDecodeReply(deps.message(start, tribeScanHostOptions(gen)));
    CHECK(noBind.kind == ScanHostReplyKind::Error && noBind.error == ScanHostError::BadRequest
          && noBind.detail == QStringLiteral("host_options.bind_interface"));

    // A real scan bound to lo0.
    TribeScanUplink lo;
    lo.name = QStringLiteral("lo0");
    lo.index = int(if_nametoindex("lo0"));
    const ScanHostReply ack = scanDecodeReply(deps.message(start, tribeScanHostOptions(gen, &lo)));
    CHECK(ack.kind == ScanHostReplyKind::Ack && ack.accepted == 3);
    QElapsedTimer t;
    t.start();
    ScanHostProgress last;
    bool final = false;
    int malformed = 0;
    QHash<QString, ScanProbeFacts> items;
    qint64 since = 0;
    while (t.elapsed() < 15000 && !final) {
        QThread::msleep(100);
        gen.counter = 3; // unchanged path
        const QByteArray raw = deps.message(scanCompact(scanEncodePoll(req.scanId, since)), tribeScanHostOptions(gen));
        const ScanHostReply p = scanDecodeReply(raw);
        if (p.kind != ScanHostReplyKind::Progress) {
            ++malformed;
            std::fprintf(stderr, "poll reply did not decode as progress: %s\n", raw.left(300).constData());
            break;
        }
        last = p.progress;
        for (const ScanProbeFacts &f : p.progress.items) {
            items.insert(f.id + QLatin1Char('/') + QString::number(int(f.stage)), f);
            since = qMax(since, f.seq);
        }
        final = p.progress.finalTotals;
        if (p.progress.done && !final) {
            // complete = the queue drained; the scan stays open for scan_add: the app's stop closes it.
            const ScanHostReply fz = scanDecodeReply(deps.message(scanCompact(scanEncodeFreeze(req.scanId)), tribeScanHostOptions(gen)));
            CHECK(fz.kind == ScanHostReplyKind::FreezeAck);
            const ScanHostReply cc = scanDecodeReply(deps.message(scanCompact(scanEncodeCancel(req.scanId)), tribeScanHostOptions(gen)));
            CHECK(cc.kind == ScanHostReplyKind::Ack);
            if (cc.finalTotals)
                final = true;
        }
    }
    CHECK(malformed == 0);
    CHECK(final);
    std::printf("engine scan: %lld items, reason=%s, bytes_spent=%lld, access attempted=%d answered=%d, gen=%d\n",
                qlonglong(items.size()), qPrintable(last.reason), qlonglong(last.bytesSpent), int(last.access.attempted),
                int(last.access.httpAnswered), int(last.hasGen));
    CHECK(items.size() >= 3); // every candidate produced its final item: sockets were really opened
    CHECK(last.hasGen && last.gen == gen); // the service's generation passed through host_options.gen
    CHECK(last.access.attempted && !last.access.httpAnswered); // the direct attempt failed at the network level
    CHECK(last.access.hasGen && last.access.gen == gen);
    // The point of it all: no probe socket reached the tunnel's callback.
    CHECK(g_tunnelCallback.load() == 0);

    char *stop = amnezia_xray_scan_stop_all(1000);
    CHECK(stop && QJsonDocument::fromJson(QByteArray(stop)).object().value(QLatin1String("stopped")).toBool());
    if (stop)
        amnezia_xray_free(stop);
    qint64 epoch = 1;
    CHECK(deps.stopAll(500, epoch).stopped);
    stopProofs(deps, gen, lo, epoch);
    CHECK(g_tunnelCallback.load() == 0);
    std::printf("tribe_scan_engine_check: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
