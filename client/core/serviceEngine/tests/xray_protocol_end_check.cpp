// client/core/serviceEngine/tests/xray_protocol_end_check.cpp
// AVPN (review F1 of 24.11.2026): how the REAL XrayProtocol (client/core/protocols/xrayProtocol.cpp, built with
// AddressSanitizer) ends a session, against a fake service: the IpcInterface and IpcProcessInterface sources of
// ipc/*.rep on local sockets in the temp dir (test stand-ins in xray_protocol_stub/ replace VpnProtocol, the
// IpcClient URLs and the network lookups - nothing reaches the installed service).
//   E1-E3  the protocol is destroyed inside a wait of its own teardown (the quit's disconnectFromVpn delivered
//          by the nested event loop) in each failure path - the routing setup failed, the resource-busy retry
//          could not create tun2socks, tun2socks exited - and nothing touches it afterwards (ASan stops the
//          run on a use after free);
//   E4     the same failure with the protocol alive: the teardown runs once, tun2socks is ended, the error
//          is reported (Error state, the error code);
//   E5     the destructor ends a connected session (teardown, tun2socks ended) without emitting a signal;
//   E6     (round mac-D2) the service gone under a connected session (killed or crashed): the tun2socks replica loses its
//          source - the session ends with an error (the engine reconnects), it never stays Connected. Before the fix the
//          state stayed Connected (device: traffic left the Mac directly for 40+ s, a provider seat was kept); the ended
//          session sends no teardown to a service (the first call waited 30 s on the dead connection).
// The previous code (stop(); setLastError(...) at the three call sites, stop() from the destructor) fails E1-E3
// under ASan and E5. Run by build_xray_protocol_end.sh.
#include "xrayProtocol.h"

#include "core/utils/constants/configKeys.h"
#include "rep_ipc_interface_source.h"
#include "rep_ipc_process_interface_source.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRemoteObjectHost>
#include <QThread>
#include <QTimer>

#include <cstdio>
#include <functional>
#include <memory>
#include <vector>

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

static void pump(int ms)
{
    waitFor([]() { return false; }, ms);
}

class FakeProcess : public IpcProcessInterfaceSource
{
public:
    QByteArray err, out;
    bool started = false;
    int terminates = 0, kills = 0, closes = 0;

    void writeErr(const QByteArray &bytes)
    {
        err += bytes;
        emit readyReadStandardError();
    }
    void exit(int code, QProcess::ExitStatus status) { emit finished(code, status); }

    void start() override { started = true; }
    void terminate() override { ++terminates; }
    void kill() override { ++kills; }
    void close() override { ++closes; }
    void setArguments(const QStringList &) override {}
    void setInputChannelMode(QProcess::InputChannelMode) override {}
    void setNativeArguments(const QString &) override {}
    void setProcessChannelMode(QProcess::ProcessChannelMode) override {}
    void setProgram(int) override {}
    void setWorkingDirectory(const QString &) override {}
    QByteArray readAll() override { return {}; }
    QByteArray readAllStandardError() override { return std::exchange(err, QByteArray()); }
    QByteArray readAllStandardOutput() override { return std::exchange(out, QByteArray()); }
    bool waitForFinished() override { return true; }
    bool waitForFinished(int) override { return true; }
    bool waitForStarted() override { return true; }
    bool waitForStarted(int) override { return true; }
};

class FakeService : public IpcInterfaceSource
{
public:
    bool createTunOk = true;
    bool failCreateProcess = false;
    QStringList calls;
    std::function<void(const QString &)> onCall;
    std::vector<std::unique_ptr<FakeProcess>> processes;
    std::vector<std::unique_ptr<QRemoteObjectHost>> hosts;

    int count(const QString &slot) const { return int(calls.count(slot)); }
    FakeProcess *last() { return processes.empty() ? nullptr : processes.back().get(); }

    int createPrivilegedProcess() override
    {
        note("createPrivilegedProcess");
        if (failCreateProcess)
            return -1;
        const int pid = int(processes.size()) + 1;
        processes.push_back(std::make_unique<FakeProcess>());
        hosts.push_back(std::make_unique<QRemoteObjectHost>(QUrl(avpn_test::processUrl(pid))));
        hosts.back()->enableRemoting(processes.back().get());
        return pid;
    }
    int routeAddList(const QString &, const QStringList &ips) override { return note("routeAddList"), int(ips.size()); }
    bool clearSavedRoutes() override { return note("clearSavedRoutes"); }
    bool routeDeleteList(const QString &, const QStringList &) override { return note("routeDeleteList"); }
    bool flushDns() override { return note("flushDns"); }
    void resetIpStack() override { note("resetIpStack"); }
    bool checkAndInstallDriver() override { return note("checkAndInstallDriver"); }
    QStringList getTapList() override { return {}; }
    void cleanUp() override {}
    void setLogsEnabled(bool) override {}
    void clearLogs() override {}
    bool createTun(const QString &, const QString &) override { return note("createTun") && createTunOk; }
    bool deleteTun(const QString &) override { return note("deleteTun"); }
    bool StartRoutingIpv6() override { return note("StartRoutingIpv6"); }
    bool StopRoutingIpv6() override { return note("StopRoutingIpv6"); }
    bool disableKillSwitch() override { return note("disableKillSwitch"); }
    bool disableAllTraffic() override { return note("disableAllTraffic"); }
    bool refreshKillSwitch(bool) override { return note("refreshKillSwitch"); }
    bool addKillSwitchAllowedRange(const QStringList) override { return note("addKillSwitchAllowedRange"); }
    bool resetKillSwitchAllowedRange(const QStringList) override { return note("resetKillSwitchAllowedRange"); }
    bool enablePeerTraffic(const QJsonObject &) override { return note("enablePeerTraffic"); }
    bool enableKillSwitch(const QJsonObject &, int) override { return note("enableKillSwitch"); }
    bool updateResolvers(const QString &, const QList<QHostAddress> &) override { return note("updateResolvers"); }
    bool restoreResolvers() override { return note("restoreResolvers"); }
    bool xrayStart(const QString &) override { return note("xrayStart"); }
    bool xrayStop() override { return note("xrayStop"); }
    QJsonObject xrayRuntimeStatus(const QString &) override { return {}; }
    bool startNetworkCheck(const QString &, const QString &) override { return true; }
    bool stopNetworkCheck() override { return true; }

private:
    bool note(const char *slot)
    {
        calls << QString::fromLatin1(slot);
        if (const auto hook = onCall) // a copy: the hook may clear onCall while it runs
            hook(QString::fromLatin1(slot));
        return true;
    }
};

static QJsonObject protocolConfig()
{
    const QJsonObject xray{ { QStringLiteral("inbounds"), QJsonArray() }, { QStringLiteral("outbounds"), QJsonArray() } };
    QJsonObject wrapper;
    wrapper.insert(amnezia::configKey::config, QString::fromUtf8(QJsonDocument(xray).toJson(QJsonDocument::Compact)));
    QJsonObject cfg;
    cfg.insert(QStringLiteral("xray_config_data"), wrapper);
    cfg.insert(amnezia::configKey::hostName, QStringLiteral("192.0.2.10"));
    cfg.insert(amnezia::configKey::dns1, QStringLiteral("1.1.1.1"));
    cfg.insert(amnezia::configKey::dns2, QStringLiteral("1.0.0.1"));
    return cfg;
}

static const QByteArray kStackLine = "{\"msg\":\"[STACK] tun://utun22 <-> socks5://test:test@127.0.0.1:10808\"}\n";

// Starts a protocol until its tun2socks runs; null on failure.
static FakeProcess *startTun(FakeService &svc, XrayProtocol *proto)
{
    const size_t before = svc.processes.size();
    if (proto->start() != ErrorCode::NoError)
        return nullptr;
    if (!waitFor([&]() { return svc.processes.size() > before && svc.last()->started; }))
        return nullptr;
    return svc.last();
}

// The quit path's disconnectFromVpn, delivered by a nested event loop of the teardown: the first teardown call
// arms a zero-time deletion, so the protocol goes while stop() still waits on the service.
static void destroyInsideTeardown(FakeService &svc, XrayProtocol *&proto, bool &destroyed)
{
    svc.onCall = [&](const QString &slot) {
        if (slot != QLatin1String("disableKillSwitch"))
            return;
        svc.onCall = nullptr;
        QTimer::singleShot(0, [&]() {
            delete proto;
            proto = nullptr;
            destroyed = true;
        });
    };
}

static void destroyedInFailurePath(FakeService &svc, const char *name, const std::function<void(FakeProcess *)> &fail,
                                   bool failRouting = false, bool failRetry = false)
{
    svc.createTunOk = true;
    svc.failCreateProcess = false;
    auto *proto = new XrayProtocol(protocolConfig());
    FakeProcess *tun = startTun(svc, proto);
    CHECK(tun != nullptr);
    if (!tun)
        return;
    const int teardownsBefore = svc.count(QStringLiteral("xrayStop"));
    bool destroyed = false;
    destroyInsideTeardown(svc, proto, destroyed);
    svc.createTunOk = !failRouting;
    svc.failCreateProcess = failRetry;
    fail(tun);
    CHECK(waitFor([&]() { return destroyed; }, 5000));
    pump(300); // whatever would still run on the destroyed protocol runs now (and ASan reports it)
    CHECK(proto == nullptr);
    CHECK(svc.count(QStringLiteral("xrayStop")) == teardownsBefore + 1); // the teardown went on to its end
    std::fprintf(stderr, "%s: destroyed inside the teardown, nothing touched it afterwards\n", name);
}

static void failureAlive(FakeService &svc)
{
    svc.createTunOk = true;
    svc.failCreateProcess = false;
    auto proto = std::make_unique<XrayProtocol>(protocolConfig());
    FakeProcess *tun = startTun(svc, proto.get());
    CHECK(tun != nullptr);
    if (!tun)
        return;
    tun->writeErr(kStackLine);
    CHECK(waitFor([&]() { return proto->connectionState() == Vpn::ConnectionState::Connected; }));
    const int stopsBefore = svc.count(QStringLiteral("xrayStop"));
    tun->exit(1, QProcess::CrashExit);
    CHECK(waitFor([&]() { return proto->connectionState() == Vpn::ConnectionState::Error; }));
    pump(200);
    CHECK(proto->lastError() == ErrorCode::Tun2SockExecutableCrashed);
    CHECK(svc.count(QStringLiteral("xrayStop")) == stopsBefore + 1);
    CHECK(tun->terminates == 1 && tun->closes == 1);
    proto->stop(); // VpnConnection's stop after the error: no second teardown
    CHECK(svc.count(QStringLiteral("xrayStop")) == stopsBefore + 1);
    CHECK(proto->connectionState() == Vpn::ConnectionState::Disconnected);
}

static void destructorQuiet(FakeService &svc)
{
    svc.createTunOk = true;
    svc.failCreateProcess = false;
    auto *proto = new XrayProtocol(protocolConfig());
    FakeProcess *tun = startTun(svc, proto);
    CHECK(tun != nullptr);
    if (!tun)
        return;
    tun->writeErr(kStackLine);
    CHECK(waitFor([&]() { return proto->connectionState() == Vpn::ConnectionState::Connected; }));
    int emitted = 0;
    QObject::connect(proto, &VpnProtocol::connectionStateChanged, [&emitted](Vpn::ConnectionState) { ++emitted; });
    const int stopsBefore = svc.count(QStringLiteral("xrayStop"));
    delete proto;
    pump(200);
    CHECK(emitted == 0);
    CHECK(svc.count(QStringLiteral("xrayStop")) == stopsBefore + 1); // the session still ends with the object
    CHECK(tun->terminates == 1 && tun->closes == 1);
    std::fprintf(stderr, "E5 destructor: %d signals emitted, teardown %d, tun2socks terminate %d close %d\n", emitted,
                 svc.count(QStringLiteral("xrayStop")) - stopsBefore, tun->terminates, tun->closes);
}

static void serviceGone(FakeService &svc)
{
    svc.createTunOk = true;
    svc.failCreateProcess = false;
    auto proto = std::make_unique<XrayProtocol>(protocolConfig());
    FakeProcess *tun = startTun(svc, proto.get());
    CHECK(tun != nullptr);
    if (!tun)
        return;
    tun->writeErr(kStackLine);
    CHECK(waitFor([&]() { return proto->connectionState() == Vpn::ConnectionState::Connected; }));
    const int teardownsBefore = svc.count(QStringLiteral("disableKillSwitch")) + svc.count(QStringLiteral("xrayStop"));
    QElapsedTimer endClock;
    endClock.start();
    svc.hosts.back().reset(); // the host of the session's process object goes away, as with the service
    const bool ended = waitFor([&]() { return proto->connectionState() == Vpn::ConnectionState::Error; }, 5000);
    CHECK(ended);
    CHECK(endClock.elapsed() < 2000); // at once - no wait on the dead connection
    CHECK(proto->lastError() == ErrorCode::AmneziaServiceConnectionFailed);
    // the gone service's session is not torn down in another service (it holds nothing of it; on the device the first
    // teardown call waited 30 s on the dead connection while Connected stayed on screen)
    CHECK(svc.count(QStringLiteral("disableKillSwitch")) + svc.count(QStringLiteral("xrayStop")) == teardownsBefore);
    std::fprintf(stderr, "E6 service gone: session ended=%d state=%d error=%d\n", int(ended), int(proto->connectionState()),
                 int(proto->lastError()));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    FakeService svc;
    QRemoteObjectHost host{ QUrl(avpn_test::serviceUrl()) };
    CHECK(host.enableRemoting(&svc));

    destroyedInFailurePath(svc, "E1 routing setup failed", [](FakeProcess *tun) { tun->writeErr(kStackLine); }, true);
    destroyedInFailurePath(
            svc, "E2 retry could not create tun2socks",
            [](FakeProcess *tun) {
                tun->out = "open /dev/utun22: resource busy";
                tun->exit(1, QProcess::NormalExit);
            },
            false, true);
    destroyedInFailurePath(svc, "E3 tun2socks exited", [](FakeProcess *tun) { tun->exit(1, QProcess::NormalExit); });
    failureAlive(svc);
    destructorQuiet(svc);
    serviceGone(svc);

    if (g_failed) {
        std::fprintf(stderr, "xray_protocol_end_check: %d of %d checks FAILED\n", g_failed, g_checks);
        return 1;
    }
    std::printf("xray_protocol_end_check: all %d checks passed\n", g_checks);
    return 0;
}
