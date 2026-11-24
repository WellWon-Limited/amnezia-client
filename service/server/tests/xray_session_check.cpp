// AVPN service/server - the macOS service's Xray core session rule and its diagnostics (xraysession.h).
// The bindings keep one process-wide core instance: configure overwrites it without closing it, stop
// closes it and never clears it, and a second close of the same instance fails ("app/proxyman/inbound:
// failed to close all resources"). FakeBindings below copies that behaviour; the driver copies how
// service/server/xray.cpp calls the rule (its call sites: check_mac_xray_session_wiring.sh).
// Build and run: service/server/tests/build_xray_session.sh
#include "../xraysession.h"

#include <cstdio>

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                       \
        }                                                                                           \
    } while (0)

namespace {

// amnezia-xray-bindings main.go: `server` = the last configured instance; stop closes it, never clears it.
struct FakeBindings
{
    struct Instance { bool closed = false; };
    Instance *server = nullptr;
    Instance pool[8];
    int created = 0;
    int closeCalls = 0;
    int closeErrors = 0;

    void configure() { server = &pool[created++]; }
    bool stop() // true = no error
    {
        if (!server)
            return true;
        ++closeCalls;
        if (server->closed) {
            ++closeErrors; // every worker hub closed a second time
            return false;
        }
        server->closed = true;
        return true;
    }
    int openInstances() const
    {
        int n = 0;
        for (int i = 0; i < created; ++i)
            n += pool[i].closed ? 0 : 1;
        return n;
    }
};

// Xray::startXray / Xray::stopXray as they use the rule; guarded=false is the code before the rule.
struct Driver
{
    FakeBindings core;
    avpn::XrayCoreSession session;
    bool guarded = true;
    int maxOpen = 0;

    bool stop()
    {
        const bool close = !guarded || session.beforeStop() == avpn::XrayCoreSession::StopStep::Close;
        bool ok = true;
        if (close) {
            ok = core.stop();
            session.onClosed();
        }
        return ok;
    }
    void start(bool configureOk = true)
    {
        if (guarded && session.beforeStart() == avpn::XrayCoreSession::StartStep::CloseOpenFirst)
            stop();
        if (!configureOk)
            return;
        core.configure();
        session.onConfigured();
        if (core.openInstances() > maxOpen)
            maxOpen = core.openInstances();
    }
};

} // namespace

int main()
{
    // 1. A fresh service: a start needs nothing first, a stop has nothing to close.
    {
        avpn::XrayCoreSession s;
        CHECK(s.beforeStart() == avpn::XrayCoreSession::StartStep::Fresh);
        CHECK(s.beforeStop() == avpn::XrayCoreSession::StopStep::NothingOpen);
        s.onConfigured();
        CHECK(s.beforeStart() == avpn::XrayCoreSession::StartStep::CloseOpenFirst);
        CHECK(s.beforeStop() == avpn::XrayCoreSession::StopStep::Close);
        s.onClosed();
        CHECK(s.beforeStop() == avpn::XrayCoreSession::StopStep::NothingOpen);
    }

    // 2. The owner's log 23.11 21:02:58 / 21:11:37: start, the failover stop, the destructor's stop.
    //    Before the rule the second stop closed the closed instance again -> the core's error.
    {
        Driver before;
        before.guarded = false;
        before.start();
        CHECK(before.stop());
        CHECK(!before.stop());
        CHECK(before.core.closeErrors == 1);

        Driver d;
        d.start();
        CHECK(d.stop());
        CHECK(d.stop()); // nothing open: the core is not touched
        CHECK(d.core.closeCalls == 1);
        CHECK(d.core.closeErrors == 0);
        CHECK(d.core.openInstances() == 0);
    }

    // 3. A start while the previous instance is still open (no stop in between): it is closed first,
    //    never two live instances; before the rule the first one kept running.
    {
        Driver before;
        before.guarded = false;
        before.start();
        before.start();
        CHECK(before.maxOpen == 2);
        CHECK(before.core.openInstances() == 2);

        Driver d;
        d.start();
        d.start();
        CHECK(d.maxOpen == 1);
        CHECK(d.core.openInstances() == 1);
        CHECK(d.core.closeErrors == 0);
        CHECK(d.stop());
        CHECK(d.core.openInstances() == 0);
    }

    // 4. A configure that failed created nothing to close: the next stop leaves the core alone.
    {
        Driver d;
        d.start(false);
        CHECK(d.stop());
        CHECK(d.core.closeCalls == 0);
    }

    // 5. Repeated sessions on one service process (wake, AWG between them): every close succeeds.
    {
        Driver d;
        for (int i = 0; i < 6; ++i) {
            d.start();
            CHECK(d.stop());
            CHECK(d.stop());
        }
        CHECK(d.core.closeCalls == 6);
        CHECK(d.core.closeErrors == 0);
    }

    // 6. Diagnostics: the core log level goes to "info" only with the service log on and only up.
    {
        const QString own = QStringLiteral(R"({"log":{"loglevel":"error","access":"none"},"outbounds":[]})");
        const avpn::XrayDiagConfig off = avpn::xrayDiagConfig(own, false);
        CHECK(off.config == own);
        CHECK(!off.raised);
        CHECK(off.level == QStringLiteral("error"));

        const avpn::XrayDiagConfig on = avpn::xrayDiagConfig(own, true);
        CHECK(on.raised);
        CHECK(on.level == QStringLiteral("info"));
        const QJsonObject log = QJsonDocument::fromJson(on.config.toUtf8()).object().value(QStringLiteral("log")).toObject();
        CHECK(log.value(QStringLiteral("loglevel")).toString() == QStringLiteral("info"));
        CHECK(log.value(QStringLiteral("access")).toString() == QStringLiteral("none")); // other keys stay

        const avpn::XrayDiagConfig noLog = avpn::xrayDiagConfig(QStringLiteral(R"({"outbounds":[]})"), true);
        CHECK(noLog.raised); // the core's default is "warning": below info

        const QString debug = QStringLiteral(R"({"log":{"loglevel":"debug"}})");
        CHECK(!avpn::xrayDiagConfig(debug, true).raised);
        CHECK(avpn::xrayDiagConfig(debug, true).config == debug);
        CHECK(!avpn::xrayDiagConfig(QStringLiteral(R"({"log":{"loglevel":"Info"}})"), true).raised);

        const QString broken = QStringLiteral("{not json");
        CHECK(avpn::xrayDiagConfig(broken, true).config == broken);
        CHECK(!avpn::xrayDiagConfig(broken, true).raised);
    }

    // 7. Only the Info lines that report a failure pass when we raised the level.
    {
        const QString access = QStringLiteral("from udp:127.0.0.1:57438 accepted udp:1.1.1.1:53");
        const QString tunneling = QStringLiteral("[Info] [123] proxy/vless/outbound: tunneling request to tcp:a:443 via b:443");
        const QString dialFail = QStringLiteral(
            "[Info] [123] app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: "
            "failed to find an available destination > dial tcp b:443: i/o timeout");
        const QString warning = QStringLiteral("[Warning] core: Xray 26.11.1 started");
        CHECK(avpn::xrayKeepCoreLine(access, true));
        CHECK(!avpn::xrayKeepCoreLine(tunneling, true));
        CHECK(avpn::xrayKeepCoreLine(dialFail, true));
        CHECK(avpn::xrayKeepCoreLine(QStringLiteral("[Info] [7] app/dns: DNS query timed out"), true));
        CHECK(avpn::xrayKeepCoreLine(warning, true));
        CHECK(avpn::xrayKeepCoreLine(tunneling, false)); // level not raised: nothing filtered
    }

    // 8. The config line names the address kind, never the address.
    {
        const QString ip = QStringLiteral(
            R"({"log":{"loglevel":"info"},"inbounds":[{}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.7","port":443}]},"streamSettings":{"network":"tcp","security":"reality"}}]})");
        const QString line = avpn::xrayConfigSummary(ip, QStringLiteral("info"));
        CHECK(line == QStringLiteral("outbounds=vless/tcp/reality address=ip inbounds=1 dns_section=no loglevel=info"));
        CHECK(!line.contains(QStringLiteral("203.0.113.7")));

        const QString domain = QStringLiteral(
            R"({"dns":{},"outbounds":[{"protocol":"freedom"},{"protocol":"trojan","settings":{"servers":[{"address":"edge.example.net"}]}}]})");
        CHECK(avpn::xrayConfigSummary(domain, QString())
              == QStringLiteral("outbounds=freedom,trojan address=domain inbounds=0 dns_section=yes loglevel=default"));
    }

    fprintf(stderr, "xray_session_check: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
