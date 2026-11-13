// Real ConfigService + loopback HTTP server. Storage and signature verification are
// isolated fixtures; Ed25519 itself has a separate regression suite.
#define AVPN_CONFIGSTORE_TEST
#include <QByteArray>
#include <QStringList>
namespace avpn {
static QByteArray cachedConfig;
static qint64 cachedConfigAtMs = 0; // 5.1.109: when the cached signed body was received (0 = unknown)
static int savedConfigs = 0;
static QString storedActiveEdge;   // 5.1.108: the persisted active edge of an earlier run
static int savedEdges = 0;
static int activeEdgeWrites = 0;
class ConfigStore {
public:
    static QByteArray loadConfig() { return cachedConfig; }
    static void saveConfig(const QByteArray &body, qint64 receivedAtMs)
    {
        cachedConfig = body;
        cachedConfigAtMs = receivedAtMs;
        ++savedConfigs;
    }
    static qint64 configReceivedAtMs() { return cachedConfigAtMs; }
    static QStringList loadEdges() { return {}; }
    static void saveEdges(const QStringList &) { ++savedEdges; }
    static QString activeEdge(const QString &value) { return storedActiveEdge.isEmpty() ? value : storedActiveEdge; }
    static void setActiveEdge(const QString &value) { storedActiveEdge = value; ++activeEdgeWrites; }
};
bool verifyDetached(const QString &, const QByteArray &, const QByteArray &sig)
{
    return sig == "fixture-signature";
}
}
#include "../ConfigService.cpp"
#include <QTcpServer>
#include <QTcpSocket>
#include <QSignalSpy>
#include <QTest>
#include <functional>

// No test in this file may reach a real host: every request goes to a loopback fixture. A request
// to anything else (a regression of the pinned edge, a walk to a compiled-in prod edge) aborts the
// run instead of touching a server.
class LoopbackOnlyNam : public QNetworkAccessManager {
protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &request, QIODevice *outgoingData = nullptr) override
    {
        const QString host = request.url().host();
        if (host != QLatin1String("127.0.0.1"))
            qFatal("config_refresh_check: a test tried to reach %s", qPrintable(host));
        return QNetworkAccessManager::createRequest(op, request, outgoingData);
    }
};

// 5.1.109 tests: a loopback server (127.0.0.1 only - no test here reaches a real host) that answers
// the n-th GET /v1/config by a script; an empty answer = the request stays in flight. Everything
// else (/v1/edges) gets an unsigned "{}".
static QByteArray httpAnswer(const char *status, const QByteArray &body, const char *sig = "fixture-signature")
{
    return QByteArray("HTTP/1.1 ") + status + "\r\nConnection: close\r\nX-Tribe-Sig: " + sig
           + "\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n\r\n" + body;
}
class ConfigServer : public QObject {
public:
    explicit ConfigServer(std::function<QByteArray(int)> script) : m_script(std::move(script))
    {
        m_server.listen(QHostAddress::LocalHost);
        connect(&m_server, &QTcpServer::newConnection, this, [this]() {
            while (auto *socket = m_server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
                    const bool config = socket->readAll().startsWith("GET /v1/config ");
                    const QByteArray answer = config ? m_script(++configRequests) : httpAnswer("200 OK", "{}", "none");
                    if (answer.isEmpty())
                        return; // in flight
                    socket->write(answer);
                    socket->disconnectFromHost();
                });
            }
        });
    }
    bool listening() const { return m_server.isListening(); }
    QString base() const { return QString("http://127.0.0.1:%1").arg(m_server.serverPort()); }
    int configRequests = 0;

private:
    QTcpServer m_server;
    std::function<QByteArray(int)> m_script;
};

static const qint64 kTestNowMs = 1794500000000LL; // a fixed "now" for the injected clock
static const qint64 kHourMs = 3600LL * 1000;

class ConfigRefreshTest : public QObject {
    Q_OBJECT
private slots:
    void init()
    {
        avpn::cachedConfig.clear();
        avpn::cachedConfigAtMs = 0;
        avpn::savedConfigs = 0;
        avpn::storedActiveEdge.clear();
        avpn::savedEdges = 0;
        avpn::activeEdgeWrites = 0;
    }
    // 5.1.108: AVPN_API_URL pins the control plane. Before, the stored active edge of an earlier run
    // won over the env var, the edge walk moved the dev session to the compiled-in prod edges, and the
    // dev backend's edge list was stored into the prod cache.
    void pinnedEdgeIgnoresStoredEdgeAndNeverWalks()
    {
        const QString other = "http://127.0.0.1:11";
        avpn::storedActiveEdge = other;
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        int configs = 0, edges = 0;
        connect(&server, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [&, socket]() {
                    const QByteArray request = socket->readAll();
                    if (request.startsWith("GET /v1/config "))
                        ++configs;
                    if (request.startsWith("GET /v1/edges "))
                        ++edges;
                    const QByteArray body = R"({"edges":["http://127.0.0.1:12"],"recommended_version":{"macos":"dev"}})";
                    socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nX-Tribe-Sig: fixture-signature\r\nContent-Length: "
                                  + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
        LoopbackOnlyNam network;
        const QString base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        {
            // Unpinned (prod): the stored edge of the earlier run is taken - unchanged behaviour.
            avpn::ConfigService prod(&network, base, "fixture-key", {base, other});
            QCOMPARE(prod.activeBaseUrl(), other);
        }
        avpn::ConfigService service(&network, base, "fixture-key", {"https://api.tribevpn.com", other},
                                    nullptr, /*pinned=*/true);
        QVERIFY(service.isPinned());
        QCOMPARE(service.activeBaseUrl(), base);
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        service.start();
        QTRY_COMPARE(service.config().recommendedVersion.value("macos"), QString("dev"));
        QTRY_COMPARE(edges, 1);
        QTest::qWait(50);
        QCOMPARE(avpn::savedEdges, 0);                               // neither /v1/edges nor config edges stored
        QVERIFY(!service.reportSubscriptionOutcome(base, true));
        QVERIFY(!service.reportSubscriptionOutcome(base, true));     // 2 in a row: unpinned would switch
        for (int i = 0; i < 5; ++i)
            service.reportNetworkFailure();                          // threshold 3: unpinned would walk
        QCOMPARE(switched.count(), 0);
        QCOMPARE(service.activeBaseUrl(), base);
        QCOMPARE(avpn::activeEdgeWrites, 0);
        QCOMPARE(configs, 1);                                        // no re-fetch on a "new" edge
    }
    // 5.1.109: this is the cache of a build before 139 (no receive time stored) - frozen as on 138.
    // A copy with a receive time inside the bound is trusted: the S4.1 tests below.
    void cachedXrayDoesNotThawUntilFreshSignedResponse()
    {
        const QByteArray cached = R"({"features":{"xray_client":true,"node_scan":true}})";
        avpn::cachedConfig = cached;
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        connect(&server, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [socket]() {
                    socket->readAll();
                    const QByteArray body = R"({"features":{"xray_client":true,"node_scan":true},"recommended_version":{"macos":"fresh"}})";
                    socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nX-Tribe-Sig: fixture-signature\r\nContent-Length: "
                                  + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
        LoopbackOnlyNam network;
        const QString base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        avpn::ConfigService service(&network, base, "fixture-key", {base});
        service.start();
        QVERIFY(!service.config().features.value("xray_client", true));
        QVERIFY(!service.config().features.value("node_scan", true)); // 5.1.108: frozen like xray_client
        QCOMPARE(avpn::cachedConfig, cached); // no forged write of the modified signed LKG.
        QCOMPARE(avpn::savedConfigs, 0);
        QTRY_COMPARE(service.config().recommendedVersion.value("macos"), QString("fresh"));
        QVERIFY(service.config().features.value("xray_client", false));
        QVERIFY(service.config().features.value("node_scan", false));   // fresh signed answer authorizes it
        QCOMPARE(avpn::savedConfigs, 1);
    }
    // Owner test of 5.1.102 (2026-11-05): a cold start with the tunnel off - the engine's abort of
    // in-flight requests on Disconnected cancelled the startup /v1/config, nothing re-issued it, and
    // the LKG freeze (xray_client=false) hid the Amnezia/Xray switch for the whole run.
    void cachedXrayThawsAfterOwnAbortOfStartupFetch()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        int requests = 0;
        bool answer = false;
        connect(&server, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [&, socket]() {
                    const bool config = socket->readAll().startsWith("GET /v1/config ");
                    if (config) {
                        ++requests;
                        if (!answer)
                            return; // in flight until the abort
                    }
                    const QByteArray body = config ? QByteArray(R"({"features":{"xray_client":true}})") : QByteArray("{}");
                    socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nX-Tribe-Sig: fixture-signature\r\nContent-Length: "
                                  + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
        LoopbackOnlyNam network;
        const QString base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        avpn::ConfigService service(&network, base, "fixture-key", {base});
        service.start();
        QVERIFY(!service.config().features.value("xray_client", true)); // frozen LKG
        QTRY_COMPARE(requests, 1);
        answer = true;
        // AvpnEngineQml::onConnectionStateChanged(Disconnected): abort every running request.
        for (QNetworkReply *r : network.findChildren<QNetworkReply *>(QString(), Qt::FindDirectChildrenOnly))
            if (r->isRunning())
                r->abort();
        QTRY_VERIFY(service.config().features.value("xray_client", false));
        QCOMPARE(requests, 2);
        QVERIFY(service.isFresh());
    }
    // Decision 2026-11-05: small calls succeed on the edge (they reset the edge walk), but two
    // /v1/subscription transport failures in a row on it switch the active edge; a delivered
    // subscription in between resets that streak.
    void subscriptionStreakSwitchesEdgeDespiteSmallSuccesses()
    {
        // Both edges are loopback fixtures that answer /v1/config with 503, and every step waits for
        // the outcome of what it started. Review of d5d739403: this test used unreachable ports and
        // asserted before the failure of a config refetch could land - it passed whatever the
        // refetch did to the edge walk.
        ConfigServer edgeA([](int) { return httpAnswer("503 Service Unavailable", "{}"); });
        ConfigServer edgeB([](int) { return httpAnswer("503 Service Unavailable", "{}"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });          // the streak does not decay while we wait
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        // Not started: no config request of the usual kind has failed, nothing is owed.
        QVERIFY(!service.reportNetworkSuccess());                    // /v1/account OK - no config refetch
        QTest::qWait(150);
        QCOMPARE(edgeA.configRequests, 0);                           // d5d739403: 1, and its failure voted
        service.reportNetworkFailure();                              // two unrelated API failures:
        service.reportNetworkFailure();                              // below the threshold of 3
        QCOMPARE(switched.count(), 0);                               // d5d739403: [success, fail, fail] switched
        service.reportNetworkSuccess();
        QVERIFY(!service.reportSubscriptionOutcome(a, true));        // subscription timeout #1
        service.reportNetworkSuccess();                              // /v1/support/unread OK
        QVERIFY(!service.reportSubscriptionOutcome(a, false));       // delivered -> streak reset
        QVERIFY(!service.reportSubscriptionOutcome(a, true));        // #1 again
        QCOMPARE(switched.count(), 0);
        service.reportNetworkSuccess();
        QTest::qWait(150);
        QCOMPARE(edgeA.configRequests, 0);
        QVERIFY(service.reportSubscriptionOutcome(a, true));         // #2 in a row -> next edge
        QCOMPARE(switched.count(), 1);
        QCOMPARE(switched.at(0).at(0).toString(), b);
        QCOMPARE(service.activeBaseUrl(), b);
        QTRY_COMPARE(edgeB.configRequests, 1);                       // the new edge is asked at once
        QTest::qWait(100);
        QVERIFY(!service.reportSubscriptionOutcome(a, true));        // late failure from the old edge
        QCOMPARE(service.activeBaseUrl(), b);
        QCOMPARE(switched.count(), 1);
    }
    // Owner test 06.11: a failed /v1/config while the process is still on the cached copy (Xray
    // frozen) must not throttle the next foreground refresh - it retries and thaws.
    void failedFetchOnCacheDoesNotThrottleForegroundRefresh()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        int requests = 0;
        connect(&server, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [&, socket]() {
                    const bool config = socket->readAll().startsWith("GET /v1/config ");
                    const bool fail = config && ++requests == 1;
                    const QByteArray body = config && !fail ? QByteArray(R"({"features":{"xray_client":true}})") : QByteArray("{}");
                    socket->write(QByteArray(fail ? "HTTP/1.1 503 Service Unavailable" : "HTTP/1.1 200 OK")
                                  + "\r\nConnection: close\r\nX-Tribe-Sig: fixture-signature\r\nContent-Length: "
                                  + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
        LoopbackOnlyNam network;
        const QString base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        avpn::ConfigService service(&network, base, "fixture-key", {base});
        service.start();
        QTRY_COMPARE(requests, 1);
        QTest::qWait(100);
        QVERIFY(!service.config().features.value("xray_client", true)); // still frozen
        service.refreshIfStale(15 * 60 * 1000);                          // foreground return
        QTRY_VERIFY(service.config().features.value("xray_client", false));
        QCOMPARE(requests, 2);
    }
    // ---- 5.1.109 (plan step S4.1). Defect of 12.11.2026 on 138: after every cold start Xray was gone
    // until the API answered - the cached config forced xray_client=false. Now the last SIGNED "true"
    // is honoured for a bounded time since it was received (ConfigCachePolicy.h). ----

    // Cold start, the API does not answer: Xray is there at once from the copy received an hour ago.
    void cachedXrayTrustedInsideBoundBeforeAnyAnswer()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true,"node_scan":true}})";
        const QByteArray cached = avpn::cachedConfig;
        avpn::cachedConfigAtMs = kTestNowMs - kHourMs;
        ConfigServer srv([](int) { return QByteArray(); }); // every /v1/config stays in flight
        QVERIFY(srv.listening());
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        service.setNowMsForTest([] { return kTestNowMs; });
        int applied = 0;
        connect(&service, &avpn::ConfigService::configApplied, this, [&applied]() { ++applied; });
        service.start();
        QCOMPARE(applied, 1);
        QVERIFY(service.config().features.value("xray_client", false));  // 138: false until the API answers
        QVERIFY(!service.config().features.value("node_scan", true));    // node_scan is NOT covered
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::CacheTrusted);
        QCOMPARE(service.cachedConfigAgeMin(), qint64(60));
        QVERIFY(!service.isFresh());                                     // fresh-only gates stay shut
        QCOMPARE(avpn::cachedConfig, cached);                            // the signed copy is not rewritten
        QCOMPARE(avpn::savedConfigs, 0);
        QTRY_COMPARE(srv.configRequests, 1);                             // the fresh one is asked for as before
        QTest::qWait(50);
        QCOMPARE(applied, 1);
    }
    // The copy is older than the bound: frozen exactly as on 138, until a fresh signed answer.
    void cachedXrayPastBoundIsFrozenUntilFreshAnswer()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        avpn::cachedConfigAtMs = kTestNowMs - 73 * kHourMs;
        ConfigServer srv([](int) { return httpAnswer("200 OK", R"({"features":{"xray_client":true}})"); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        service.setNowMsForTest([] { return kTestNowMs; });
        service.start();
        QVERIFY(!service.config().features.value("xray_client", true));
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::CacheExpired);
        QTRY_VERIFY(service.isFresh());
        QVERIFY(service.config().features.value("xray_client", false));
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::FreshOn);
        QCOMPARE(service.cachedConfigAgeMin(), qint64(-1));
        QCOMPARE(avpn::cachedConfigAtMs, kTestNowMs); // the receive time is stored with the fresh body
    }
    // The server switched Xray off: the fresh answer wins over a trusted cache at once, and the next
    // cold start on that (now "off") copy is off however fresh the copy is.
    void freshOffWinsOverTrustedCacheAtOnce()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        avpn::cachedConfigAtMs = kTestNowMs - kHourMs;
        ConfigServer srv([](int) { return httpAnswer("200 OK", R"({"features":{"xray_client":false}})"); });
        LoopbackOnlyNam network;
        {
            avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
            service.setNowMsForTest([] { return kTestNowMs; });
            service.start();
            QVERIFY(service.config().features.value("xray_client", false)); // trusted until the answer
            QTRY_VERIFY(service.isFresh());
            QVERIFY(!service.config().features.value("xray_client", true));
            QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::FreshOff);
        }
        QCOMPARE(avpn::cachedConfigAtMs, kTestNowMs);
        avpn::ConfigService next(nullptr, srv.base(), "fixture-key", {srv.base()}); // no network at all
        next.setNowMsForTest([] { return kTestNowMs + 60000; });
        next.start();
        QVERIFY(!next.config().features.value("xray_client", true));
        QCOMPARE(next.xrayPolicy(), avpn::XrayPolicy::CacheOff);
    }
    // The bound travels with the signed copy (numbers.xray_client_cache_max_age_h): default 72 h,
    // 0 = the trust is off (the behaviour of 138), ceiling 7 days. Also: no receive time (a cache
    // written by 138) and a clock behind the receive time read as frozen.
    void boundComesWithTheSignedCopy()
    {
        struct Case { const char *numbers; qint64 ageMin; bool allowed; avpn::XrayPolicy why; };
        const Case cases[] = {
            {"", 71 * 60, true, avpn::XrayPolicy::CacheTrusted},
            {"", 72 * 60, false, avpn::XrayPolicy::CacheExpired},
            {R"("xray_client_cache_max_age_h":1)", 30, true, avpn::XrayPolicy::CacheTrusted},
            {R"("xray_client_cache_max_age_h":1)", 61, false, avpn::XrayPolicy::CacheExpired},
            {R"("xray_client_cache_max_age_h":0)", 1, false, avpn::XrayPolicy::CacheTrustOff},
            {R"("xray_client_cache_max_age_h":-3)", 1, false, avpn::XrayPolicy::CacheTrustOff},
            {R"("xray_client_cache_max_age_h":1000)", 167 * 60, true, avpn::XrayPolicy::CacheTrusted},
            {R"("xray_client_cache_max_age_h":1000)", 169 * 60, false, avpn::XrayPolicy::CacheExpired},
            {"", -60, false, avpn::XrayPolicy::CacheClockBack}, // received "in an hour": the clock went back
        };
        for (const Case &c : cases) {
            avpn::cachedConfig = QByteArray(R"({"features":{"xray_client":true},"numbers":{)") + c.numbers + "}}";
            avpn::cachedConfigAtMs = kTestNowMs - c.ageMin * 60000;
            avpn::ConfigService service(nullptr, "http://127.0.0.1:9", "fixture-key", {}); // no network
            service.setNowMsForTest([] { return kTestNowMs; });
            service.start();
            QCOMPARE(service.config().features.value("xray_client", !c.allowed), c.allowed);
            QCOMPARE(service.xrayPolicy(), c.why);
        }
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        avpn::cachedConfigAtMs = 0;                                      // written by a build before 139
        avpn::ConfigService old(nullptr, "http://127.0.0.1:9", "fixture-key", {});
        old.setNowMsForTest([] { return kTestNowMs; });
        QCOMPARE(old.xrayPolicy(), avpn::XrayPolicy::NoConfig);
        old.start();
        QVERIFY(!old.config().features.value("xray_client", true));
        QCOMPARE(old.xrayPolicy(), avpn::XrayPolicy::CacheNoStamp);
        QCOMPARE(old.cachedConfigAgeMin(), qint64(-1));
    }
    // A process that stays on the cached copy (the API answers 503 for days): the trust is judged
    // again before every config request and runs out at the bound - announced like any config.
    void trustRunsOutWhileTheProcessStaysOnTheCache()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true,"node_scan":true}})";
        avpn::cachedConfigAtMs = kTestNowMs - 71 * kHourMs;
        bool up = false;
        ConfigServer srv([&up](int) {
            return up ? httpAnswer("200 OK", R"({"features":{"xray_client":true}})")
                      : httpAnswer("503 Service Unavailable", "{}");
        });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        qint64 now = kTestNowMs;
        service.setNowMsForTest([&now] { return now; });
        int applied = 0;
        connect(&service, &avpn::ConfigService::configApplied, this, [&applied]() { ++applied; });
        service.start();
        QVERIFY(service.config().features.value("xray_client", false));
        QTRY_COMPARE(srv.configRequests, 1);
        QTest::qWait(100);
        QVERIFY(service.config().features.value("xray_client", false)); // a failed request freezes nothing
        now += kHourMs / 2;                                              // 71.5 h: still inside the bound
        service.refreshIfStale(15 * 60 * 1000);                          // a return to the screen
        QTRY_COMPARE(srv.configRequests, 2);
        QTest::qWait(100);
        QVERIFY(service.config().features.value("xray_client", false));
        QCOMPARE(applied, 1);
        now += kHourMs / 2 + 60000;                                      // 72 h 01 min: past the bound
        service.refreshIfStale(15 * 60 * 1000);
        QVERIFY(!service.config().features.value("xray_client", true));
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::CacheExpired);
        QTRY_COMPARE(applied, 2);                                        // announced from the event loop
        QVERIFY(!service.config().features.value("node_scan", true));
        QTRY_COMPARE(srv.configRequests, 3);
        QTest::qWait(100);
        QCOMPARE(applied, 2);                                            // and only once
        up = true;                                                       // the API is back
        service.refreshIfStale(15 * 60 * 1000);
        QTRY_VERIFY(service.isFresh());
        QVERIFY(service.config().features.value("xray_client", false));
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::FreshOn);
    }
    // 138 on iOS: after a failed startup /v1/config the config was asked for again only on a return
    // to the screen or an edge switch. Now the first API request that succeeds (bootstrap retry,
    // subscription, account) asks for it - while it is owed, one request at a time. iOS and macOS.
    void apiSuccessAsksForTheConfigOwedAfterTransportFailure()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})"; // no receive time: frozen
        ConfigServer srv([](int n) {
            return n == 1 ? httpAnswer("503 Service Unavailable", "{}")
                          : httpAnswer("200 OK", R"({"features":{"xray_client":true}})");
        });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        service.start();
        QTRY_COMPARE(srv.configRequests, 1);
        QTest::qWait(100);
        QVERIFY(!service.isFresh());
        QVERIFY(!service.config().features.value("xray_client", true));
        QVERIFY(service.reportNetworkSuccess());   // /v1/subscription answered: the config is asked for now
        QVERIFY(!service.reportNetworkSuccess());  // already in flight: not twice
        QTRY_VERIFY(service.isFresh());
        QCOMPARE(srv.configRequests, 2);
        QVERIFY(service.config().features.value("xray_client", false));
        QVERIFY(!service.reportNetworkSuccess());  // a fresh config is in force: API successes do not ask
        QTest::qWait(50);
        QCOMPARE(srv.configRequests, 2);
    }
    // An attempt the edge ANSWERED (404, a body with a bad signature) is not repeated on every API
    // success, and the config's own answer never re-triggers itself: one request, no loop.
    void answeredConfigIsNotAskedAgainOnApiSuccess()
    {
        const QByteArray answers[] = {
            httpAnswer("404 Not Found", "{}"),
            httpAnswer("200 OK", R"({"features":{"xray_client":true}})", "forged-signature"),
        };
        for (const QByteArray &answer : answers) {
            avpn::cachedConfig = R"({"features":{"xray_client":true}})";
            ConfigServer srv([answer](int) { return answer; });
            LoopbackOnlyNam network;
            avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
            service.start();
            QTRY_COMPARE(srv.configRequests, 1);
            QTest::qWait(100);
            QVERIFY(!service.isFresh());
            QVERIFY(!service.reportNetworkSuccess());
            QTest::qWait(50);
            QCOMPARE(srv.configRequests, 1);
            QVERIFY(!service.config().features.value("xray_client", true)); // a forged "true" changes nothing
        }
    }
    // ---- 5.1.109, review of d5d739403 (finding 3): the refetch on an API success. ----

    // /v1/config keeps failing while other API requests succeed (about every 20 s under a live
    // session). d5d739403 asked for the config on EVERY success; now once per owed episode - a
    // failed refetch does not arm the next one, only the next usual request that fails does - and
    // not closer than the refresh throttle (15 min) to the previous refetch.
    void oneRefetchPerOwedEpisodeWithSpacing()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        ConfigServer srv([](int) { return httpAnswer("503 Service Unavailable", "{}"); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        qint64 now = kTestNowMs;
        service.setNowMsForTest([&now] { return now; });
        service.start();
        QTRY_COMPARE(srv.configRequests, 1);
        QTest::qWait(100);                                           // the start request failed: owed
        QVERIFY(service.reportNetworkSuccess());                     // the one refetch of this episode
        QTRY_COMPARE(srv.configRequests, 2);
        QTest::qWait(100);                                           // ... and it failed too
        for (int i = 0; i < 6; ++i) {                                // two minutes of API successes
            now += 20 * 1000;
            QVERIFY(!service.reportNetworkSuccess());                // d5d739403: true, every time
        }
        QTest::qWait(100);
        QCOMPARE(srv.configRequests, 2);                             // d5d739403: 8
        now += 20 * 60 * 1000;                                       // long past the throttle, and still
        QVERIFY(!service.reportNetworkSuccess());                    // nothing: a failed refetch arms nothing
        QTest::qWait(50);
        QCOMPARE(srv.configRequests, 2);
        service.refreshIfStale(15 * 60 * 1000);                      // a return to the screen: a usual request
        QTRY_COMPARE(srv.configRequests, 3);
        QTest::qWait(100);                                           // failed: owed again - a new episode
        QVERIFY(service.reportNetworkSuccess());                     // its refetch (22 minutes after the first)
        QTRY_COMPARE(srv.configRequests, 4);
        QTest::qWait(100);
        service.refreshIfStale(15 * 60 * 1000);                      // the user comes back again a minute later
        now += 60 * 1000;
        QTRY_COMPARE(srv.configRequests, 5);
        QTest::qWait(100);                                           // failed: owed, a third episode
        QVERIFY(!service.reportNetworkSuccess());                    // but the last refetch was a minute ago
        now += 13 * 60 * 1000;
        QVERIFY(!service.reportNetworkSuccess());                    // 14 minutes
        now += 60 * 1000;
        QVERIFY(service.reportNetworkSuccess());                     // 15 minutes: the refetch of this episode
        QTRY_COMPARE(srv.configRequests, 6);
        QTest::qWait(100);
        QVERIFY(!service.reportNetworkSuccess());
        QCOMPARE(srv.configRequests, 6);
    }
    // The failure of a refetch does not vote in the edge walk: [success, fail, fail] must not switch
    // the API edge (it did on d5d739403: the refetch's own failure was the third vote). A config
    // request of the usual kind still votes.
    void refetchFailureDoesNotVoteInTheEdgeWalk()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        ConfigServer edgeA([](int) { return httpAnswer("503 Service Unavailable", "{}"); });
        ConfigServer edgeB([](int) { return httpAnswer("200 OK", R"({"features":{"xray_client":true}})"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });          // the streak does not decay
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        int failedSignals = 0;
        connect(&service, &avpn::ConfigService::transportFailed, this, [&failedSignals]() { ++failedSignals; });
        service.start();
        QTRY_COMPARE(edgeA.configRequests, 1);
        QTest::qWait(100);                                           // the usual request failed: vote 1
        QVERIFY(service.reportNetworkSuccess());                     // success: streak 0, the refetch goes out
        QTRY_COMPARE(edgeA.configRequests, 2);
        QTest::qWait(100);                                           // the refetch failed: NOT a vote
        service.reportNetworkFailure();                              // fail
        service.reportNetworkFailure();                              // fail - two votes, the threshold is 3
        QTest::qWait(50);
        QCOMPARE(switched.count(), 0);                               // d5d739403: switched to b here
        QCOMPARE(service.activeBaseUrl(), a);
        QCOMPARE(edgeB.configRequests, 0);
        QCOMPARE(failedSignals, 0);                                  // 503 is an answer: nothing for the detector
        service.reportNetworkFailure();                              // the third vote: the walk itself works
        QCOMPARE(switched.count(), 1);
        QCOMPARE(service.activeBaseUrl(), b);
        QTRY_VERIFY(service.isFresh());                              // and the new edge delivers the config
        QCOMPARE(edgeB.configRequests, 1);
    }
    // A refetch that WE aborted (a tunnel transition aborts the requests in flight) is re-issued at
    // once, as every config request on the cached copy - and keeps its origin: the re-issued request
    // must not come back as one whose failure votes.
    void abortedRefetchIsReissuedAndStillDoesNotVote()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        bool hold = false;
        ConfigServer edgeA([&hold](int) {
            return hold ? QByteArray() : httpAnswer("503 Service Unavailable", "{}");
        });
        ConfigServer edgeB([](int) { return httpAnswer("200 OK", R"({"features":{"xray_client":true}})"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        service.start();
        QTRY_COMPARE(edgeA.configRequests, 1);
        QTest::qWait(100);                                           // the usual request failed: vote 1, owed
        hold = true;
        QVERIFY(service.reportNetworkSuccess());                     // streak 0; the refetch is in flight
        QTRY_COMPARE(edgeA.configRequests, 2);
        hold = false;
        // AvpnEngineQml::onConnectionStateChanged: our own abort of the requests in flight
        for (QNetworkReply *r : network.findChildren<QNetworkReply *>(QString(), Qt::FindDirectChildrenOnly))
            if (r->isRunning() && r->url().path() == QLatin1String("/v1/config"))
                r->abort();
        QTRY_COMPARE(edgeA.configRequests, 3);                       // re-issued at once
        QTest::qWait(100);                                           // ... and it failed: still not a vote
        service.reportNetworkFailure();
        service.reportNetworkFailure();
        QCOMPARE(switched.count(), 0);                               // two votes only
        QVERIFY(!service.reportNetworkSuccess());                    // and nothing is owed: one refetch per episode
        QCOMPARE(edgeB.configRequests, 0);
    }
    // The active edge is switched while a config request is in flight to the old one. Before: the
    // in-flight guard swallowed the immediate request to the new edge (nothing was asked until the old
    // request ended, up to its 15 s timeout) and the old edge's failure was then counted against the
    // new one. Now the old request is dropped and the new edge is asked at once.
    void edgeSwitchDropsTheRequestInFlightAndAsksTheNewEdge()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        ConfigServer edgeA([](int) { return QByteArray(); });        // /v1/config stays in flight
        bool bUp = false;
        ConfigServer edgeB([&bUp](int) {
            return bUp ? httpAnswer("200 OK", R"({"features":{"xray_client":true}})")
                       : httpAnswer("503 Service Unavailable", "{}");
        });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        service.start();
        QTRY_COMPARE(edgeA.configRequests, 1);                       // in flight on a
        QVERIFY(!service.reportSubscriptionOutcome(a, true));
        QVERIFY(service.reportSubscriptionOutcome(a, true));         // the subscription streak switches to b
        QCOMPARE(service.activeBaseUrl(), b);
        QTRY_COMPARE_WITH_TIMEOUT(edgeB.configRequests, 1, 2000);    // asked at once (before: after a's 15 s)
        QTest::qWait(150);                                           // b answered 503: ONE vote, b's own
        service.reportNetworkFailure();                              // vote 2
        QCOMPARE(switched.count(), 1);                               // the dropped request on a added nothing
        QCOMPARE(service.activeBaseUrl(), b);
        QVERIFY(!service.isFresh());
        bUp = true;
        service.refreshIfStale(15 * 60 * 1000);
        QTRY_VERIFY(service.isFresh());
        QCOMPARE(edgeA.configRequests, 1);
    }

    // ---- review of d5d739403 (finding 5): the cached trust is judged on more paths and is one-way. ----

    // The trust runs out while the foreground refresh is throttled (the edge ANSWERED the last
    // request, so the next one is 15 minutes away) and while no config request is made at all.
    void trustIsJudgedOnTheThrottledForegroundPathAndOnApiOutcomes()
    {
        const QByteArray cached = R"({"features":{"xray_client":true}})";
        for (const int path : {0, 1, 2}) {
            avpn::cachedConfig = cached;
            avpn::cachedConfigAtMs = kTestNowMs - 72 * kHourMs + 5 * 60 * 1000; // 5 minutes of trust left
            ConfigServer srv([](int) { return httpAnswer("404 Not Found", "{}"); });
            LoopbackOnlyNam network;
            avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
            qint64 now = kTestNowMs;
            service.setNowMsForTest([&now] { return now; });
            int applied = 0;
            connect(&service, &avpn::ConfigService::configApplied, this, [&applied]() { ++applied; });
            service.start();
            QVERIFY(service.config().features.value("xray_client", false));
            QTRY_COMPARE(srv.configRequests, 1);
            QTest::qWait(100);                                       // answered: the refresh is throttled
            now += 6 * 60 * 1000;                                    // the bound has passed
            if (path == 0)
                service.refreshIfStale(15 * 60 * 1000);              // a return to the screen, throttled
            else if (path == 1)
                service.reportNetworkSuccess();                      // any API outcome
            else
                service.reportNetworkFailure();
            QVERIFY(!service.config().features.value("xray_client", true)); // d5d739403: still true
            QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::CacheExpired);
            QTRY_COMPARE(applied, 2);                                // announced like any config
            QTest::qWait(50);
            QCOMPARE(srv.configRequests, 1);                         // no config request was needed for it
        }
    }
    // Once the cached trust has ended in a run it stays ended: setting the clock back inside the
    // bound (not before the receive time) does not revive it. Only a fresh signed answer does.
    void endedTrustIsNotRevivedByAClockChange()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        avpn::cachedConfigAtMs = kTestNowMs - 71 * kHourMs;
        bool up = false;
        ConfigServer srv([&up](int) {
            return up ? httpAnswer("200 OK", R"({"features":{"xray_client":true}})")
                      : httpAnswer("503 Service Unavailable", "{}");
        });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        qint64 now = kTestNowMs;
        service.setNowMsForTest([&now] { return now; });
        service.start();
        QVERIFY(service.config().features.value("xray_client", false));
        QTRY_COMPARE(srv.configRequests, 1);
        QTest::qWait(100);
        now += 2 * kHourMs;                                          // 73 h: expired
        service.refreshIfStale(15 * 60 * 1000);
        QVERIFY(!service.config().features.value("xray_client", true));
        QTRY_COMPARE(srv.configRequests, 2);
        QTest::qWait(100);
        now -= 3 * kHourMs;                                          // the clock is set back: "70 h"
        service.refreshIfStale(15 * 60 * 1000);
        QVERIFY(!service.config().features.value("xray_client", true)); // d5d739403: true again
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::CacheExpired);
        QTRY_COMPARE(srv.configRequests, 3);
        QTest::qWait(100);
        up = true;                                                   // only a fresh signed answer revives it
        service.refreshIfStale(15 * 60 * 1000);
        QTRY_VERIFY(service.isFresh());
        QVERIFY(service.config().features.value("xray_client", false));
    }

    // ---- review of d5d739403 (finding 6): the facade's existing classification of API outcomes
    // applies to the config request too. ----
    void configFailureIgnoredByTheFacadeDoesNotVote()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        ConfigServer edgeA([](int) { return QByteArray(); });        // no answer: the test ends each request itself
        ConfigServer edgeB([](int) { return httpAnswer("200 OK", R"({"features":{"xray_client":true}})"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        bool frozen = true;                                          // "the request outlived a freeze of the process"
        service.setFailureIgnoredFn([&frozen](QNetworkReply *) { return frozen; });
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        int failedSignals = 0;
        connect(&service, &avpn::ConfigService::transportFailed, this, [&failedSignals]() { ++failedSignals; });
        // armTimeout's own expiry: a transport failure with no HTTP status, as after a freeze.
        const auto timeOutRequestInFlight = [&network]() {
            for (QNetworkReply *r : network.findChildren<QNetworkReply *>(QString(), Qt::FindDirectChildrenOnly))
                if (r->isRunning() && r->url().path() == QLatin1String("/v1/config")) {
                    r->setProperty("avpn_timed_out", true);
                    r->abort();
                }
        };
        service.start();
        for (int n = 1; n <= 4; ++n) {                               // four requests die in a freeze
            QTRY_COMPARE(edgeA.configRequests, n);
            timeOutRequestInFlight();
            QTest::qWait(30);
            if (n < 4)
                service.refreshIfStale(15 * 60 * 1000);              // the return to the screen asks again
        }
        QCOMPARE(switched.count(), 0);                               // before: three such failures switched the edge
        QCOMPARE(failedSignals, 0);                                  // and fed the white-list detector
        QVERIFY(service.reportNetworkSuccess());                     // the config is still owed
        QTRY_COMPARE(edgeA.configRequests, 5);
        frozen = false;                                              // honest timeouts from now on
        timeOutRequestInFlight();                                    // a refetch: no vote either
        QTest::qWait(30);
        QCOMPARE(failedSignals, 0);
        for (int n = 6; n <= 8; ++n) {                               // three usual requests time out
            service.refreshIfStale(15 * 60 * 1000);
            QTRY_COMPARE(edgeA.configRequests, n);
            timeOutRequestInFlight();
            QTest::qWait(30);
        }
        QCOMPARE(failedSignals, 3);
        QCOMPARE(switched.count(), 1);                               // the third vote switched the edge
        QTRY_VERIFY(service.isFresh());
    }
    void refreshesWithoutApplicationRestart()
    {
        runScenario(false);
    }
    void doesNotOverlapSlowRequests()
    {
        runScenario(true);
    }
private:
    void runScenario(bool hold)
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        int requests = 0;
        QString version = "5.1.82";
        connect(&server, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [&, socket]() {
                    const QByteArray request = socket->readAll();
                    const bool config = request.startsWith("GET /v1/config ");
                    if (config) {
                        ++requests;
                        if (hold)
                            return;
                    }
                    const QByteArray body = config
                        ? QString("{\"recommended_version\":{\"macos\":\"%1\"}}").arg(version).toUtf8()
                        : QByteArray("{}");
                    socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nX-Tribe-Sig: fixture-signature\r\nContent-Length: "
                                  + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
        LoopbackOnlyNam network;
        const QString base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        avpn::ConfigService service(&network, base, "fixture-key", {base});
        service.start();
        auto *timer = service.findChild<QTimer *>("macosConfigRefresh");
        QVERIFY(timer);
        QCOMPARE(timer->interval(), 15 * 60 * 1000);
        QVERIFY(timer->isActive());
        QTRY_COMPARE(requests, 1);
        if (hold) {
            timer->setInterval(20);
            QTest::qWait(100);
            QCOMPARE(requests, 1);
        } else {
            QTRY_COMPARE(service.config().recommendedVersion.value("macos"), QString("5.1.82"));
            version = "5.1.83";
            timer->setInterval(20);
            QTRY_COMPARE(service.config().recommendedVersion.value("macos"), version);
            QVERIFY(requests >= 2);
        }
    }
};
QTEST_GUILESS_MAIN(ConfigRefreshTest)
#include "config_refresh_check.moc"
