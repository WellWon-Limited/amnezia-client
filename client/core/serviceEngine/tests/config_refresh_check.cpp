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
#include <QList>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSignalSpy>
#include <QElapsedTimer>
#include <QTest>
#include <functional>
#include <utility>

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
// the n-th GET /v1/config by a script; an empty answer = the request stays in flight until
// answerHeld(). Everything else (/v1/edges) gets an unsigned "{}".
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
                    if (answer.isEmpty()) {
                        m_held << socket; // in flight
                        return;
                    }
                    socket->write(answer);
                    socket->disconnectFromHost();
                });
            }
        });
    }
    // The requests left in flight get their answer now (a late answer of this edge).
    void answerHeld(const QByteArray &answer)
    {
        for (const QPointer<QTcpSocket> &socket : std::exchange(m_held, {}))
            if (socket) {
                socket->write(answer);
                socket->disconnectFromHost();
            }
    }
    bool listening() const { return m_server.isListening(); }
    QString base() const { return QString("http://127.0.0.1:%1").arg(m_server.serverPort()); }
    int configRequests = 0;

private:
    QTcpServer m_server;
    std::function<QByteArray(int)> m_script;
    QList<QPointer<QTcpSocket>> m_held;
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
            // Unpinned (prod), R1a of device round 4: the walk of an earlier run is NOT restored - every run starts at
            // the Russian entry (a sticky foreign edge froze every large answer from Russia).
            avpn::ConfigService prod(&network, base, "fixture-key", {base, other});
            QCOMPARE(prod.activeBaseUrl(), base);
            QCOMPARE(prod.directBaseUrl(), base);
            // a session edge (a tunnel carries requests) never becomes the direct edge, and it ends with the session
            prod.setSessionEdge(other);
            QCOMPARE(prod.activeBaseUrl(), other);
            QCOMPARE(prod.directBaseUrl(), base);
            prod.setSessionEdge(QString());
            QCOMPARE(prod.activeBaseUrl(), base);
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
        const QByteArray cached = R"({"features":{"xray_client":true,"node_scan":true,"upstream_nodes":true}})";
        avpn::cachedConfig = cached;
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        connect(&server, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [socket]() {
                    socket->readAll();
                    const QByteArray body = R"({"features":{"xray_client":true,"node_scan":true,"upstream_nodes":true},"recommended_version":{"macos":"fresh"}})";
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
        QVERIFY(!service.config().features.value("upstream_nodes", true)); // upstream nodes: no receive time = outside the bounded trust
        QCOMPARE(avpn::cachedConfig, cached); // no forged write of the modified signed LKG.
        QCOMPARE(avpn::savedConfigs, 0);
        QTRY_COMPARE(service.config().recommendedVersion.value("macos"), QString("fresh"));
        QVERIFY(service.config().features.value("xray_client", false));
        QVERIFY(service.config().features.value("node_scan", false));   // fresh signed answer authorizes it
        QVERIFY(service.config().features.value("upstream_nodes", false)); // and upstream nodes with it
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
    // Fast failover (device round 4): a direct edge that stays silent on its first try in this run is left after
    // ~2.5 s - not after three 15 s failures; the next edge is asked at once.
    void silentEdgeOnFirstTryFailsOverFast()
    {
        QTcpServer silent; // accepts and never answers (the frozen route of round 4)
        QVERIFY(silent.listen(QHostAddress::LocalHost));
        QList<QTcpSocket *> held;
        connect(&silent, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = silent.nextPendingConnection())
                held << socket;
        });
        ConfigServer edgeB([](int) { return httpAnswer("503 Service Unavailable", "{}"); });
        LoopbackOnlyNam network;
        const QString a = QString("http://127.0.0.1:%1").arg(silent.serverPort()), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        QElapsedTimer t;
        t.start();
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(switched.count(), 1, 6000);
        QVERIFY(t.elapsed() < 4500);
        QCOMPARE(service.activeBaseUrl(), b);
        QCOMPARE(service.directBaseUrl(), b);
        QTRY_COMPARE(edgeB.configRequests, 1);
        qDeleteAll(held);
    }
    // R9 (review of 141): with two edges and a network that drops every connection, the quick 2.5 s try walked the
    // edges for ever. One full unsuccessful round now backs off (EdgeWalk.h::edgeRoundPauseMs); inside a round every
    // edge still gets one quick try. Time is scaled: first try 50 ms, pause 100 ms doubling to 400 ms (the real
    // defaults are 2500 ms and 10 s doubling to 120 s).
    void allEdgesSilentBackOffAfterEachRound()
    {
        QStringList order;
        ConfigServer edgeA([&](int) { order << "a"; return QByteArray(); });
        ConfigServer edgeB([&](int) { order << "b"; return QByteArray(); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        service.setEdgeWalkTimingForTest(50, 100, 400);
        service.start();
        QTest::qWait(3000);
        const int total = edgeA.configRequests + edgeB.configRequests;
        // Without the back-off: ~3000 / 50 = 60 requests. With it: rounds at 0, 200, 500, 1000, 1500, 2100, 2600 ms.
        QVERIFY2(total <= 16, qPrintable(QString::number(total)));
        QVERIFY2(total >= 6, qPrintable(QString::number(total))); // the walk still runs round after round
        // No edge twice in a row: each round tries every edge once (two edges, so the order alternates).
        for (int i = 1; i < order.size(); ++i)
            QVERIFY2(order.at(i) != order.at(i - 1), qPrintable(order.join(',')));
    }
    // One edge answers in round N: the walk stops there (the round counter and the pause are reset on any answer).
    void edgeAnswerInLaterRoundStopsWalkAndResetsPause()
    {
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int n) { return n < 3 ? QByteArray() : httpAnswer("503 Service Unavailable", "{}"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        service.setEdgeWalkTimingForTest(50, 100, 400);
        service.start();
        QTRY_VERIFY_WITH_TIMEOUT(edgeB.configRequests >= 3, 4000); // rounds 1 and 2 silent, round 3 answered
        const int ra = edgeA.configRequests;
        QTest::qWait(1200);
        QCOMPARE(edgeA.configRequests, ra); // the walk stopped: nothing more is asked
        QCOMPARE(edgeB.configRequests, 3);
    }
    // A network change (or the foreground) during a long pause ends it: a new round starts at once.
    void networkChangeDuringPauseStartsNewRound()
    {
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int) { return QByteArray(); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        service.setEdgeWalkTimingForTest(50, 5000, 5000);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(edgeA.configRequests + edgeB.configRequests, 2, 2000); // round 1
        QTest::qWait(400);
        QCOMPARE(edgeA.configRequests + edgeB.configRequests, 2); // paused for 5 s
        service.resumeEdgeWalk();
        QTRY_COMPARE_WITH_TIMEOUT(edgeA.configRequests + edgeB.configRequests, 4, 1000); // round 2 at once
        QTest::qWait(400);
        QCOMPARE(edgeA.configRequests + edgeB.configRequests, 4); // and a pause again, from the base
        service.resumeEdgeWalk();                                  // while no pause is running: harmless
        QCOMPARE(edgeA.configRequests + edgeB.configRequests, 4);
    }
    // F7: a pause must never end with "nothing owed, nothing sent". All edges silent -> pause; then another request
    // succeeds / the network changes / the app returns: a config request goes out at once and its answer is applied.
    // Edge B answers its second config request (the first of round 1 is silent).
    void pauseExitsSendTheConfigAtOnceAndApplyIt_data()
    {
        QTest::addColumn<int>("exit");
        QTest::newRow("another request succeeded") << 0;
        QTest::newRow("network change") << 1;
        QTest::newRow("foreground") << 2;
        QTest::newRow("two exits coincide") << 3;
    }
    void pauseExitsSendTheConfigAtOnceAndApplyIt()
    {
        QFETCH(int, exit);
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int n) {
            return n < 2 ? QByteArray() : httpAnswer("200 OK", R"({"features":{"xray_client":true}})");
        });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        service.setEdgeWalkTimingForTest(50, 5000, 5000);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(edgeA.configRequests + edgeB.configRequests, 2, 2000); // round 1, then the pause
        QTest::qWait(300);
        QCOMPARE(edgeA.configRequests + edgeB.configRequests, 2);
        service.refreshIfStale(0); // a config request of another trigger, held back by the pause: no request, no queue
        QCOMPARE(edgeA.configRequests + edgeB.configRequests, 2);
        QVERIFY(!service.isFresh());
        if (exit == 0 || exit == 3)
            service.reportNetworkSuccess();
        if (exit == 1 || exit == 2 || exit == 3)
            service.resumeEdgeWalk();
        QTRY_VERIFY_WITH_TIMEOUT(service.isFresh(), 1000); // at once (the pause was 5 s), and applied
        QVERIFY(service.config().features.value("xray_client", false));
        QTest::qWait(300);
        QCOMPARE(edgeA.configRequests, 1);
        QCOMPARE(edgeB.configRequests, 2); // exactly one request went out: no duplicate from the second exit
    }
    // Lane C: the one fact "can the direct control plane be reached on this network" (ApiReach.h): Unreachable after one
    // full round of silent edges, Reachable at the first direct answer, forgotten (Unknown) on a network change; an
    // answer through a tunnel (session edge) proves nothing about the direct route.
    void directApiReachFollowsTheWalkPerNetworkGeneration()
    {
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int n) { return n < 2 ? QByteArray() : httpAnswer("200 OK", R"({"features":{}})"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        quint64 generation = 1;
        service.setNetworkGenerationSource([&generation] { return generation; });
        service.setNowMsForTest([] { return kTestNowMs; });
        service.setEdgeWalkTimingForTest(50, 5000, 5000);
        QSignalSpy flips(&service, &avpn::ConfigService::directApiReachChanged);
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Unknown);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Unreachable, 2000); // a full round, both silent
        QCOMPARE(edgeA.configRequests + edgeB.configRequests, 2);
        generation = 2; // another network: the fact is not about it
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Unknown);
        service.setSessionEdge(b);
        service.reportNetworkSuccess(); // an answer through a tunnel: nothing about the direct route
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Unknown);
        service.setSessionEdge(QString());
        service.noteNetworkChanged(); // the new network is asked at once (the pause is over)
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 1000);
        QCOMPARE(flips.count(), 2); // Unreachable, Reachable
        generation = 3;
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Unknown);
    }
    // A network change while the walk is not paused still asks the new network (an edge that answered on the old one
    // proves nothing): the fact converges without waiting for the next refresh.
    void networkChangeAsksTheNewNetworkAndFlipsTheFact()
    {
        ConfigServer edgeA([](int) { return httpAnswer("200 OK", R"({"features":{}})"); });
        ConfigServer edgeB([](int) { return httpAnswer("200 OK", R"({"features":{}})"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        quint64 generation = 1;
        service.setNetworkGenerationSource([&generation] { return generation; });
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 2000);
        const int before = edgeA.configRequests;
        generation = 2;
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Unknown);
        service.noteNetworkChanged();
        QTRY_COMPARE_WITH_TIMEOUT(edgeA.configRequests, before + 1, 2000);
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 2000);
    }
    // Lane C review: what a request teaches about the DIRECT route is decided by how it was SENT. An answer to a
    // request sent while a tunnel of ours was up (the app's API requests ride it) says nothing about the direct route.
    void answerThroughOwnTunnelDoesNotSetReachable()
    {
        ConfigServer edge([](int) { return httpAnswer("200 OK", R"({"features":{}})"); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, edge.base(), "fixture-key", {edge.base(), edge.base() + "/"});
        bool tunnel = true;
        service.setTunnelUpSource([&tunnel] { return tunnel; });
        service.setNetworkGenerationSource([] { return quint64(1); });
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(edge.configRequests, 1, 2000);
        QTRY_VERIFY_WITH_TIMEOUT(service.isFresh(), 2000);
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Unknown); // answered through the tunnel
        service.reportNetworkSuccess(/*directRoute=*/false);         // the facade: sent with a tunnel up
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Unknown);
        tunnel = false;
        service.reportNetworkSuccess(/*directRoute=*/true);          // a direct request answered
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Reachable);
    }
    // A request sent on the previous network generation that goes silent after the change is not a silent edge of the
    // new one (with a single edge that alone used to flip the fact).
    void timeoutOfRequestSentOnPreviousGenerationDoesNotCount()
    {
        for (const bool changed : { true, false }) {
            ConfigServer silent([](int) { return QByteArray(); });
            LoopbackOnlyNam network;
            avpn::ConfigService service(&network, silent.base(), "fixture-key", {silent.base()});
            quint64 generation = 1;
            service.setNetworkGenerationSource([&generation] { return generation; });
            service.setEdgeWalkTimingForTest(150, 5000, 5000);
            service.start();
            QTRY_COMPARE_WITH_TIMEOUT(silent.configRequests, 1, 2000);
            if (changed)
                generation = 2; // the network changed while the request was in flight
            QTest::qWait(500);  // its quick timeout has fired
            QCOMPARE(service.directApiReach(), changed ? avpn::ApiReach::Unknown : avpn::ApiReach::Unreachable);
        }
    }
    // Our tunnel went down: nothing learned through it applies; the direct route is asked once.
    void tunnelDownAsksTheDirectRouteOnce()
    {
        ConfigServer edge([](int) { return QByteArray(); }); // silent: the request stays in flight, the fact stays Unknown
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, edge.base(), "fixture-key", {edge.base()});
        bool tunnel = true;
        service.setTunnelUpSource([&tunnel] { return tunnel; });
        service.setNetworkGenerationSource([] { return quint64(1); });
        service.noteTunnelDown(); // still "up" (the facade records the state after): no ask
        QTest::qWait(100);
        QCOMPARE(edge.configRequests, 0);
        tunnel = false;
        service.noteTunnelDown();
        QTRY_COMPARE_WITH_TIMEOUT(edge.configRequests, 1, 1000);
        service.noteTunnelDown(); // once per generation
        service.noteNetworkChanged();
        QTest::qWait(200);
        QCOMPARE(edge.configRequests, 1);
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Unknown);
    }
    // Network changes under a tunnel of ours ask nothing; without a tunnel a flapping network asks once per generation
    // at most and not closer than the spacing.
    void networkChangesAreBoundedAsks()
    {
        ConfigServer edge([](int) { return QByteArray(); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, edge.base(), "fixture-key", {edge.base()});
        bool tunnel = true;
        quint64 generation = 1;
        service.setTunnelUpSource([&tunnel] { return tunnel; });
        service.setNetworkGenerationSource([&generation] { return generation; });
        for (int i = 0; i < 10; ++i) {
            ++generation;
            service.noteNetworkChanged();
        }
        QTest::qWait(200);
        QCOMPARE(edge.configRequests, 0); // ten network changes under a tunnel: zero asks
        tunnel = false;
        for (int i = 0; i < 10; ++i) {
            ++generation;
            service.noteNetworkChanged();
            QTest::qWait(20);
        }
        QTest::qWait(200);
        QCOMPARE(edge.configRequests, 1); // ten changes in a row without a tunnel: one ask (the rest wait the spacing)
    }
    // Round 9, R4: "every edge silent on THIS network" is a set of edges tried and silent under the current generation,
    // not a counter a stale timeout can advance. A request to A sent on the old network times out after the change;
    // the new request to B times out too - A was never tried on the new network, so the fact is not Unreachable.
    void staleTimeoutDoesNotCompleteTheSilentSet()
    {
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int) { return QByteArray(); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        quint64 generation = 1;
        service.setNetworkGenerationSource([&generation] { return generation; });
        service.setEdgeWalkTimingForTest(300, 5000, 5000);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(edgeA.configRequests, 1, 1000); // sent on generation 1
        generation = 2;                                           // the network changed while it is in flight
        service.noteNetworkChanged();
        QTRY_COMPARE_WITH_TIMEOUT(edgeB.configRequests, 1, 2000); // the old request timed out, B asked on generation 2
        QTest::qWait(600);                                        // B's quick timeout has fired too
        QVERIFY(service.directApiReach() != avpn::ApiReach::Unreachable);
    }
    // Second consolidated review, R4: an HTTP answer that is not the API's (a block page instead of the signed config)
    // proves no route: the fact never becomes Reachable from it; with a single edge it is Unreachable.
    void foreignAnswerDoesNotProveTheRoute()
    {
        ConfigServer blocked([](int) { return httpAnswer("403 Forbidden", "<html>blocked</html>", "none"); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, blocked.base(), "fixture-key", {blocked.base()});
        service.setNetworkGenerationSource([] { return quint64(1); });
        QSignalSpy proved(&service, &avpn::ConfigService::directRouteProved);
        service.setEdgeWalkTimingForTest(2000, 5000, 5000);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(blocked.configRequests, 1, 2000);
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Unreachable, 2000);
        QCOMPARE(proved.count(), 0);
        // the same for a 200 whose body is not signed by the API
        ConfigServer unsignedPage([](int) { return httpAnswer("200 OK", "<html>portal</html>", "none"); });
        avpn::ConfigService other(&network, unsignedPage.base(), "fixture-key", {unsignedPage.base()});
        other.setNetworkGenerationSource([] { return quint64(1); });
        other.setEdgeWalkTimingForTest(2000, 5000, 5000);
        other.start();
        QTRY_COMPARE_WITH_TIMEOUT(unsignedPage.configRequests, 1, 2000);
        QTRY_COMPARE_WITH_TIMEOUT(other.directApiReach(), avpn::ApiReach::Unreachable, 2000);
    }
    // Second consolidated review, R3: a proof of the direct route is announced every time, also when the fact was
    // Reachable already (a kept seat release waits for the event, not for a change).
    void everyDirectProofIsAnnounced()
    {
        ConfigServer edge([](int) { return httpAnswer("200 OK", R"({"features":{}})"); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, edge.base(), "fixture-key", {edge.base()});
        service.setNetworkGenerationSource([] { return quint64(1); });
        QSignalSpy proved(&service, &avpn::ConfigService::directRouteProved);
        QSignalSpy changed(&service, &avpn::ConfigService::directApiReachChanged);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 2000);
        const int provedOnce = proved.count(), changedOnce = changed.count();
        QVERIFY(provedOnce >= 1);
        service.reportNetworkSuccess(true); // another direct answer: the fact does not change, the proof is announced
        QCOMPARE(changed.count(), changedOnce);
        QCOMPARE(proved.count(), provedOnce + 1);
        service.reportNetworkSuccess(false); // an answer through a tunnel proves nothing about the direct route
        QCOMPARE(proved.count(), provedOnce + 1);
    }
    // Device round 11 of 20.11: a kept seat release (or a seat owed after a lost lease answer) waits for the EVENT
    // directRouteProved on a phone where nothing runs - nobody asked the API, so the event never came and the seat stayed
    // taken until its lease expired. While the owner says a proof is owed (setProofOwedSource) the direct route is asked
    // although this network was asked already and its fact is known; not closer than the spacing; never under a tunnel;
    // and no more once the owner says it is not owed.
    void aProofThatIsOwedIsAskedFor()
    {
        ConfigServer edge([](int) { return httpAnswer("200 OK", R"({"features":{}})"); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, edge.base(), "fixture-key", {edge.base()});
        qint64 now = kTestNowMs;
        bool owed = false, tunnel = false;
        service.setNowMsForTest([&now] { return now; });
        service.setNetworkGenerationSource([] { return quint64(1); });
        service.setTunnelUpSource([&tunnel] { return tunnel; });
        service.setProofOwedSource([&owed] { return owed; });
        QSignalSpy proved(&service, &avpn::ConfigService::directRouteProved);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 2000);
        QCOMPARE(edge.configRequests, 1);
        const int provedAtStart = proved.count();
        service.noteProofOwed(); // nothing is owed: the fact is known, nothing is asked
        QTest::qWait(150);
        QCOMPARE(edge.configRequests, 1);
        owed = true; // the lease owner keeps a release and nothing runs
        tunnel = true;
        service.noteProofOwed(); // never while a tunnel of ours is up (nothing direct can be learned)
        QTest::qWait(150);
        QCOMPARE(edge.configRequests, 1);
        tunnel = false;
        service.noteProofOwed(); // asked now, although the fact is Reachable and this network was asked
        QTRY_COMPARE_WITH_TIMEOUT(edge.configRequests, 2, 2000);
        QTRY_COMPARE_WITH_TIMEOUT(proved.count(), provedAtStart + 1, 2000); // the event the release waits for
        service.noteProofOwed(); // still owed (the release went out and failed): not closer than the spacing
        service.noteProofOwed();
        QTest::qWait(200);
        QCOMPARE(edge.configRequests, 2);
        now += 30001; // the spacing has passed
        service.noteProofOwed();
        QTRY_COMPARE_WITH_TIMEOUT(edge.configRequests, 3, 2000);
        QTRY_COMPARE_WITH_TIMEOUT(proved.count(), provedAtStart + 2, 2000);
        owed = false; // delivered (or the lease's lifetime passed): the asks end
        now += 30001;
        service.noteProofOwed();
        QTest::qWait(200);
        QCOMPARE(edge.configRequests, 3);
    }
    // Review of the seat-debt lane (F1): a proof is owed AND the network changed. The ask is then the new network's own
    // first ask - the walk starts over with the quick first try (the edge that answered on the old network proves
    // nothing here). The owed-proof branch kept "this edge answered" across the change, so a silent edge got the full
    // request timeout instead of the quick try and a Connect tapped meanwhile went to the dead edge.
    void owedProofOnANewNetworkStartsTheWalkOver()
    {
        bool silentA = false;
        ConfigServer edgeA([&silentA](int) { return silentA ? QByteArray() : httpAnswer("200 OK", R"({"features":{}})"); });
        ConfigServer edgeB([](int) { return httpAnswer("200 OK", R"({"features":{}})"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setEdgeWalkTimingForTest(300, 100, 400);
        qint64 now = kTestNowMs;
        quint64 generation = 1;
        bool owed = false;
        service.setNowMsForTest([&now] { return now; });
        service.setNetworkGenerationSource([&generation] { return generation; });
        service.setProofOwedSource([&owed] { return owed; });
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 2000); // edge A answered
        owed = true;       // a failed start left a seat owed
        now += 30001;      // the spacing has passed
        generation = 2;    // Wi-Fi -> cellular: edge A is silent there, edge B answers
        silentA = true;
        QElapsedTimer t;
        t.start();
        service.noteNetworkChanged();
        QTRY_COMPARE_WITH_TIMEOUT(switched.count(), 1, 3000); // the quick first try, not the 15 s request timeout
        QVERIFY2(t.elapsed() < 2000, qPrintable(QString::number(t.elapsed())));
        QCOMPARE(service.activeBaseUrl(), b);
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 2000);
    }
    // Final review, F5: the network changes while a request of the previous network is in flight. Its answer cannot speak
    // for the new network; the ask the new network is owed must still be sent (it was marked done with nothing sent).
    void askOwedWhileOldRequestInFlight()
    {
        quint64 generation = 1;
        avpn::ConfigService *svc = nullptr;
        ConfigServer edge([&](int n) {
            if (n == 1 && svc) { // request 1 has reached the server: the network changes before its answer is read
                generation = 2;
                svc->noteNetworkChanged();
            }
            return httpAnswer("200 OK", R"({"features":{}})");
        });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, edge.base(), "fixture-key", {edge.base()});
        svc = &service;
        service.setNetworkGenerationSource([&generation] { return generation; });
        service.setEdgeWalkTimingForTest(2000, 5000, 5000);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(edge.configRequests, 1, 2000);
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 4000); // asked and answered on generation 2
        QVERIFY(edge.configRequests >= 2);
    }
    // Round 10, R5: edge A was silent on its quick try; while B is being tried another direct request is answered
    // (reportNetworkSuccess(true)). That answer refutes A's silence: B's timeout must not complete the set.
    void directAnswerRefutesEarlierSilence()
    {
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int) { return QByteArray(); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNetworkGenerationSource([] { return quint64(1); });
        service.setEdgeWalkTimingForTest(300, 5000, 5000);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(edgeB.configRequests, 1, 2000); // A stayed silent, B is being tried
        service.reportNetworkSuccess(true);                       // another direct request got an answer meanwhile
        QCOMPARE(service.directApiReach(), avpn::ApiReach::Reachable);
        QTest::qWait(400);                                        // B's quick timeout has fired; A's next try has not ended
        QVERIFY(service.directApiReach() != avpn::ApiReach::Unreachable); // B alone does not cover {A, B} any more
    }
    // Round 9, R5a: a negative fact learned before a tunnel of ours was up is stale when it goes down: Unknown at once
    // and the direct route is asked again (the walk had stopped on an answer through the tunnel).
    void negativeFactBeforeTunnelIsForgottenWhenItGoesDown()
    {
        ConfigServer edge([](int n) { return n < 2 ? QByteArray() : httpAnswer("200 OK", R"({"features":{}})"); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, edge.base(), "fixture-key", {edge.base()});
        bool tunnel = false;
        service.setTunnelUpSource([&tunnel] { return tunnel; });
        service.setNetworkGenerationSource([] { return quint64(1); });
        service.setEdgeWalkTimingForTest(100, 5000, 5000);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Unreachable, 2000);
        tunnel = true;  // a tunnel of ours came up (the walk stopped on an answer through it)
        tunnel = false; // Stop; the direct route has recovered meanwhile (the fixture answers from now on)
        service.noteTunnelDown();
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 2000);
        QCOMPARE(edge.configRequests, 2);
    }
    // Round 9, R5a: while no tunnel is up the walk's own rounds keep re-testing an Unreachable fact: the pause ends by
    // itself and a direct answer flips it back, with no other trigger.
    void backOffRoundsKeepRetestingUnreachable()
    {
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int n) { return n < 3 ? QByteArray() : httpAnswer("200 OK", R"({"features":{}})"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNetworkGenerationSource([] { return quint64(1); });
        service.setEdgeWalkTimingForTest(50, 100, 200);
        service.start();
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Unreachable, 2000);
        QTRY_COMPARE_WITH_TIMEOUT(service.directApiReach(), avpn::ApiReach::Reachable, 4000); // round 3 reaches B
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
    // Upstream nodes: the cached signed upstream_nodes=true is trusted for its own bound (default 72 h,
    // numbers.upstream_nodes_cache_max_age_h of the same copy), fail-closed beyond it; a cached false is
    // never upgraded; node_scan stays frozen. The cold-start-in-a-whitelist-window case.
    void cachedUpstreamBoundedTrust()
    {
        struct Case { const char *body; qint64 ageMs; bool expect; };
        const Case cases[] = {
            {R"({"features":{"xray_client":true,"upstream_nodes":true,"node_scan":true}})", kHourMs, true},
            {R"({"features":{"xray_client":true,"upstream_nodes":true}})", 71 * kHourMs, true},
            {R"({"features":{"xray_client":true,"upstream_nodes":true}})", 72 * kHourMs, false},
            {R"({"features":{"xray_client":true,"upstream_nodes":false}})", kHourMs, false},
            {R"({"features":{"xray_client":true}})", kHourMs, false},
            {R"({"features":{"upstream_nodes":true},"numbers":{"upstream_nodes_cache_max_age_h":2}})", 3 * kHourMs, false},
            {R"({"features":{"upstream_nodes":true},"numbers":{"upstream_nodes_cache_max_age_h":200}})", 100 * kHourMs, true},
            {R"({"features":{"upstream_nodes":true},"numbers":{"upstream_nodes_cache_max_age_h":0}})", 30 * 60 * 1000, true}, // floor 1 h
            {R"({"features":{"upstream_nodes":true},"numbers":{"upstream_nodes_cache_max_age_h":9999}})", 337 * kHourMs, false}, // ceil 336 h
        };
        for (const Case &c : cases) {
            avpn::cachedConfig = c.body;
            avpn::cachedConfigAtMs = kTestNowMs - c.ageMs;
            ConfigServer srv([](int) { return QByteArray(); }); // the API never answers
            LoopbackOnlyNam network;
            avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
            service.setNowMsForTest([] { return kTestNowMs; });
            service.start();
            QCOMPARE(service.config().features.value("upstream_nodes", !c.expect), c.expect);
            QVERIFY(!service.config().features.value("node_scan", true));
            QCOMPARE(avpn::savedConfigs, 0); // the signed copy is not rewritten
        }
        // No receive time (a cache of a build before 139): off.
        avpn::cachedConfig = R"({"features":{"upstream_nodes":true}})";
        avpn::cachedConfigAtMs = 0;
        ConfigServer srv([](int) { return QByteArray(); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        service.setNowMsForTest([] { return kTestNowMs; });
        service.start();
        QVERIFY(!service.config().features.value("upstream_nodes", true));
    }
    // The trust runs out while the process stays on the cache: off, and a clock moved back does not revive it.
    void cachedUpstreamTrustRunsOutOneWay()
    {
        avpn::cachedConfig = R"({"features":{"upstream_nodes":true}})";
        avpn::cachedConfigAtMs = kTestNowMs - 71 * kHourMs;
        ConfigServer srv([](int) { return QByteArray(); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        qint64 now = kTestNowMs;
        service.setNowMsForTest([&now] { return now; });
        service.start();
        QVERIFY(service.config().features.value("upstream_nodes", false));
        now = kTestNowMs + 2 * kHourMs;
        service.reportNetworkSuccess(); // a rejudge point
        QTRY_VERIFY(!service.config().features.value("upstream_nodes", true));
        now = kTestNowMs;
        service.reportNetworkSuccess();
        QTest::qWait(20);
        QVERIFY(!service.config().features.value("upstream_nodes", true));
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
    // ---- 5.1.109, reviews of d5d739403 (finding 3) and 3dbe0361f (G): the refetch on an API success. ----

    // /v1/config keeps failing while other API requests succeed (about every 20 s under a live
    // session). d5d739403 asked for the config on EVERY success. 3dbe0361f asked once per episode: the
    // startup request fails, the one refetch fails, then 180 successes in an hour brought no config.
    // Now: at once, then every 15 minutes (the refresh throttle) while it is still owed - and the
    // first refetch after the path really returns delivers the config.
    void failedRefetchIsRepeatedAfterTheSpacing()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        bool up = false;
        ConfigServer srv([&up](int) {
            return up ? httpAnswer("200 OK", R"({"features":{"xray_client":true}})")
                      : httpAnswer("503 Service Unavailable", "{}");
        });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        qint64 now = kTestNowMs;
        service.setNowMsForTest([&now] { return now; });
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        service.start();
        QTRY_COMPARE(srv.configRequests, 1);
        QTest::qWait(100);                                           // the start request failed: owed
        QVERIFY(service.reportNetworkSuccess());                     // the first API success asks at once
        QTRY_COMPARE(srv.configRequests, 2);
        QTest::qWait(100);                                           // ... and that refetch failed too
        QList<qint64> askedAtMin;                                    // minutes after the first refetch
        for (int i = 1; i <= 180; ++i) {                             // an hour of API successes, every 20 s
            now += 20 * 1000;
            if (!service.reportNetworkSuccess())
                continue;
            askedAtMin << (now - kTestNowMs) / 60000;
            QTRY_COMPARE(srv.configRequests, 2 + int(askedAtMin.size()));
            QTest::qWait(100);                                       // it failed again
        }
        QCOMPARE(askedAtMin, (QList<qint64>{15, 30, 45, 60}));       // 3dbe0361f: none; d5d739403: 180
        QCOMPARE(srv.configRequests, 6);
        QCOMPARE(switched.count(), 0);                               // and none of those failures voted
        // A usual request that fails in between does not shorten the spacing.
        now += 60 * 1000;
        service.refreshIfStale(15 * 60 * 1000);                      // a return to the screen
        QTRY_COMPARE(srv.configRequests, 7);
        QTest::qWait(100);
        QVERIFY(!service.reportNetworkSuccess());                    // 1 minute after the last refetch
        now += 13 * 60 * 1000;
        QVERIFY(!service.reportNetworkSuccess());                    // 14 minutes
        up = true;                                                   // the path to /v1/config is back
        now += 60 * 1000;
        QVERIFY(service.reportNetworkSuccess());                     // 15 minutes: asked, and answered
        QTRY_VERIFY(service.isFresh());
        QCOMPARE(srv.configRequests, 8);
        QVERIFY(service.config().features.value("xray_client", false));
        now += 60 * 60 * 1000;
        QVERIFY(!service.reportNetworkSuccess());                    // fresh: API successes do not ask
        QTest::qWait(50);
        QCOMPARE(srv.configRequests, 8);
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
        QVERIFY(!service.reportNetworkSuccess());                    // owed, but inside the spacing: not asked again
        QTest::qWait(50);
        QCOMPARE(edgeA.configRequests, 3);
        QCOMPARE(edgeB.configRequests, 0);
    }
    // The active edge is switched while a config request is in flight to the old one. Before 139: the
    // in-flight guard swallowed the immediate request to the new edge (nothing was asked until the old
    // request ended, up to its 15 s timeout) and the old edge's failure was then counted against the
    // new one. Now the new edge is asked at once and the old request is left to finish: its FAILURE
    // is ignored ...
    void edgeSwitchAsksTheNewEdgeAtOnceAndIgnoresTheOldEdgesFailure()
    {
        for (const bool timesOut : {false, true}) {
            avpn::cachedConfig = R"({"features":{"xray_client":true}})";
            avpn::storedActiveEdge.clear();                          // the previous pass stored its edge b
            ConfigServer edgeA([](int) { return QByteArray(); });    // /v1/config stays in flight
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
            int failedSignals = 0;
            connect(&service, &avpn::ConfigService::transportFailed, this, [&failedSignals]() { ++failedSignals; });
            service.start();
            QTRY_COMPARE(edgeA.configRequests, 1);                   // in flight on a
            QVERIFY(!service.reportSubscriptionOutcome(a, true));
            QVERIFY(service.reportSubscriptionOutcome(a, true));     // the subscription streak switches to b
            QCOMPARE(service.activeBaseUrl(), b);
            QTRY_COMPARE_WITH_TIMEOUT(edgeB.configRequests, 1, 2000); // asked at once (before: after a's 15 s)
            QTest::qWait(150);                                       // b answered 503: ONE vote, b's own
            if (timesOut) {                                          // the old request ends by its timeout
                for (QNetworkReply *r : network.findChildren<QNetworkReply *>(QString(), Qt::FindDirectChildrenOnly))
                    if (r->isRunning() && r->url().port() == QUrl(a).port() && r->url().path() == QLatin1String("/v1/config")) {
                        r->setProperty("avpn_timed_out", true);
                        r->abort();
                    }
            } else {
                edgeA.answerHeld(httpAnswer("503 Service Unavailable", "{}")); // ... or by a late 503 of a
            }
            QTest::qWait(150);
            QCOMPARE(failedSignals, 0);                              // the old edge's failure is nobody's vote
            service.reportNetworkFailure();                          // vote 2 against b
            QCOMPARE(switched.count(), 1);                           // before: this was the third - a switch
            QCOMPARE(service.activeBaseUrl(), b);
            QVERIFY(!service.isFresh());
            bUp = true;
            service.refreshIfStale(15 * 60 * 1000);
            QTRY_VERIFY(service.isFresh());
            QCOMPARE(edgeA.configRequests, 1);
        }
    }
    // ... a forged answer of the old edge changes nothing (the signature is checked as always) ...
    void edgeSwitchDoesNotApplyAForgedAnswerOfTheOldEdge()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})"; // no receive time: frozen
        ConfigServer edgeA([](int) { return QByteArray(); });        // /v1/config stays in flight
        ConfigServer edgeB([](int) { return httpAnswer("503 Service Unavailable", "{}"); }); // the new edge is down
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        int applied = 0;
        connect(&service, &avpn::ConfigService::configApplied, this, [&applied]() { ++applied; });
        service.start();
        QCOMPARE(applied, 1);                                        // the cached copy
        QVERIFY(!service.config().features.value("xray_client", true));
        QTRY_COMPARE(edgeA.configRequests, 1);                       // in flight on a
        QVERIFY(!service.reportSubscriptionOutcome(a, true));
        QVERIFY(service.reportSubscriptionOutcome(a, true));         // switched to b
        QTRY_COMPARE_WITH_TIMEOUT(edgeB.configRequests, 1, 2000);
        QTest::qWait(150);                                           // b answered 503
        QVERIFY(!service.isFresh());
        edgeA.answerHeld(httpAnswer("200 OK", R"({"features":{"xray_client":true}})", "forged-signature"));
        QTest::qWait(150);
        QVERIFY(!service.isFresh());
        QCOMPARE(applied, 1);
        QCOMPARE(switched.count(), 1);
    }
    // ... and its signed ANSWER is applied: the body does not depend on the edge that carried it.
    // 138 applied it; 3dbe0361f dropped the request on the switch - a good answer already on its way
    // was lost and the device stayed on the cached copy (Xray frozen) until the new edge answered.
    void edgeSwitchAppliesTheSignedAnswerOfTheOldEdge()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int) { return httpAnswer("503 Service Unavailable", "{}"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        service.start();
        QTRY_COMPARE(edgeA.configRequests, 1);
        QVERIFY(!service.reportSubscriptionOutcome(a, true));
        QVERIFY(service.reportSubscriptionOutcome(a, true));
        QTRY_COMPARE_WITH_TIMEOUT(edgeB.configRequests, 1, 2000);
        QTest::qWait(150);
        QVERIFY(!service.isFresh());
        edgeA.answerHeld(httpAnswer("200 OK", R"({"features":{"xray_client":true},"recommended_version":{"macos":"late"}})"));
        QTRY_VERIFY(service.isFresh());                              // 3dbe0361f: never (the request was dropped)
        QVERIFY(service.config().features.value("xray_client", false));
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::FreshOn);
        QCOMPARE(service.config().recommendedVersion.value("macos"), QString("late"));
        QCOMPARE(avpn::savedConfigs, 1);                             // and stored for the next cold start
        QCOMPARE(service.activeBaseUrl(), b);                        // the edge in use is not touched by it
        QCOMPARE(switched.count(), 1);
        QVERIFY(!service.reportNetworkSuccess());                    // fresh: nothing is owed any more
    }

    // Review of df7f49db8: after an edge switch two requests are in flight, and the body carries no
    // version - the answers are ordered by when their requests were STARTED. The new edge answers
    // first with the newer config (the operator switched Xray off); the old edge's answer, produced
    // before that, lands later: it must not overwrite the newer one (it did: applied as fresh, stored
    // and re-stamped - the next cold start offline trusted "true").
    void lateAnswerOfTheOldEdgeDoesNotOverwriteANewerConfig()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        const QByteArray off = R"({"features":{"xray_client":false},"recommended_version":{"macos":"new"}})";
        ConfigServer edgeA([](int) { return QByteArray(); });        // /v1/config stays in flight
        ConfigServer edgeB([off](int) { return httpAnswer("200 OK", off); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        qint64 now = kTestNowMs;
        service.setNowMsForTest([&now] { return now; });
        int applied = 0;
        connect(&service, &avpn::ConfigService::configApplied, this, [&applied]() { ++applied; });
        service.start();
        QCOMPARE(applied, 1);                                        // the cached copy
        QTRY_COMPARE(edgeA.configRequests, 1);                       // request 1, in flight on a
        QVERIFY(!service.reportSubscriptionOutcome(a, true));
        QVERIFY(service.reportSubscriptionOutcome(a, true));         // switched to b: request 2
        QTRY_VERIFY(service.isFresh());                              // b answered: Xray is off
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::FreshOff);
        QCOMPARE(avpn::savedConfigs, 1);
        QCOMPARE(avpn::cachedConfigAtMs, kTestNowMs);
        now += 5000;
        edgeA.answerHeld(httpAnswer("200 OK", R"({"features":{"xray_client":true},"recommended_version":{"macos":"old"}})"));
        QTest::qWait(200);                                           // the older answer lands, signed and valid
        QVERIFY(!service.config().features.value("xray_client", true)); // df7f49db8: true again
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::FreshOff);
        QCOMPARE(service.config().recommendedVersion.value("macos"), QString("new"));
        QCOMPARE(applied, 2);
        QCOMPARE(avpn::savedConfigs, 1);                             // not stored ...
        QCOMPARE(avpn::cachedConfig, off);
        QCOMPARE(avpn::cachedConfigAtMs, kTestNowMs);                // ... and not re-stamped
    }
    // The other order: the old edge's answer comes first and is applied (finding D of the review of
    // 3dbe0361f stays closed); the answer of the request started later then replaces it.
    void answersAfterAnEdgeSwitchAreAppliedInTheOrderTheRequestsWereStarted()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        ConfigServer edgeA([](int) { return QByteArray(); });
        ConfigServer edgeB([](int) { return QByteArray(); });        // both stay in flight
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        service.start();
        QTRY_COMPARE(edgeA.configRequests, 1);
        QVERIFY(!service.reportSubscriptionOutcome(a, true));
        QVERIFY(service.reportSubscriptionOutcome(a, true));
        QTRY_COMPARE_WITH_TIMEOUT(edgeB.configRequests, 1, 2000);
        edgeA.answerHeld(httpAnswer("200 OK", R"({"features":{"xray_client":true},"recommended_version":{"macos":"old"}})"));
        QTRY_VERIFY(service.isFresh());                              // the earlier request, first to answer: applied
        QVERIFY(service.config().features.value("xray_client", false));
        QCOMPARE(service.config().recommendedVersion.value("macos"), QString("old"));
        edgeB.answerHeld(httpAnswer("200 OK", R"({"features":{"xray_client":false},"recommended_version":{"macos":"new"}})"));
        QTRY_COMPARE(service.config().recommendedVersion.value("macos"), QString("new")); // the later request wins
        QVERIFY(!service.config().features.value("xray_client", true));
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::FreshOff);
        QCOMPARE(avpn::savedConfigs, 2);
        service.refreshIfStale(0);                                   // and an ordinary later request applies as always
        QTRY_COMPARE_WITH_TIMEOUT(edgeB.configRequests, 2, 2000);
        edgeB.answerHeld(httpAnswer("200 OK", R"({"features":{"xray_client":true},"recommended_version":{"macos":"newest"}})"));
        QTRY_COMPARE(service.config().recommendedVersion.value("macos"), QString("newest"));
        QCOMPARE(avpn::savedConfigs, 3);
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
    // Review of 3dbe0361f (F): a clock behind the receive time is a passing state, not the end of the
    // trust - when the time is corrected a one-hour-old cached "true" is trusted again without a
    // restart and without a config request (3dbe0361f: off until the app restarted).
    void clockBehindTheStampIsNotStickyForTheRun()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        avpn::cachedConfigAtMs = kTestNowMs;                         // received "now" by the right clock
        ConfigServer srv([](int) { return httpAnswer("404 Not Found", "{}"); });
        LoopbackOnlyNam network;
        avpn::ConfigService service(&network, srv.base(), "fixture-key", {srv.base()});
        qint64 now = kTestNowMs - 5 * kHourMs;                       // the device clock is 5 hours behind
        service.setNowMsForTest([&now] { return now; });
        int applied = 0;
        connect(&service, &avpn::ConfigService::configApplied, this, [&applied]() { ++applied; });
        service.start();
        QVERIFY(!service.config().features.value("xray_client", true));
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::CacheClockBack);
        QTRY_COMPARE(srv.configRequests, 1);
        QTest::qWait(100);                                           // answered 404: still on the cached copy
        now = kTestNowMs + kHourMs;                                  // the time is corrected: received an hour ago
        service.refreshIfStale(15 * 60 * 1000);                      // a return to the screen (throttled)
        QVERIFY(service.config().features.value("xray_client", false)); // 3dbe0361f: still false
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::CacheTrusted);
        QCOMPARE(service.cachedConfigAgeMin(), qint64(60));
        QTRY_COMPARE(applied, 2);                                    // announced like any config
        QVERIFY(!service.config().features.value("node_scan", true)); // node_scan stays frozen on the cache
        now += 72 * kHourMs;                                         // ... and the bound still applies
        service.reportNetworkFailure();
        QVERIFY(!service.config().features.value("xray_client", true));
        QCOMPARE(service.xrayPolicy(), avpn::XrayPolicy::CacheExpired);
    }
    // Once the cached trust has EXPIRED in a run it stays expired: setting the clock back inside the
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

    // ---- reviews of d5d739403 (finding 6) and 3dbe0361f (E): a config request that outlived a freeze
    // of the process (its timer fired late) is no evidence about the edge. The rule lives in
    // ConfigService itself (ConfigCachePolicy.h::configRequestOutlivedFreeze) - nothing has to be
    // wired by the facade for it. ----
    void configRequestThatOutlivedAFreezeDoesNotVote()
    {
        avpn::cachedConfig = R"({"features":{"xray_client":true}})";
        ConfigServer edgeA([](int) { return QByteArray(); });        // no answer: the test ends each request itself
        ConfigServer edgeB([](int) { return httpAnswer("200 OK", R"({"features":{"xray_client":true}})"); });
        LoopbackOnlyNam network;
        const QString a = edgeA.base(), b = edgeB.base();
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        service.setNowMsForTest([] { return kTestNowMs; });
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        int failedSignals = 0;
        connect(&service, &avpn::ConfigService::transportFailed, this, [&failedSignals]() { ++failedSignals; });
        // armTimeout's own expiry: a transport failure with no HTTP status. frozen - the request was
        // started (armTimeout's stamp) long before its 15 s timer could fire: the process was
        // suspended in between and the timer ran on return.
        const auto timeOutRequestInFlight = [&network](bool frozen) {
            for (QNetworkReply *r : network.findChildren<QNetworkReply *>(QString(), Qt::FindDirectChildrenOnly))
                if (r->isRunning() && r->url().path() == QLatin1String("/v1/config")) {
                    QVERIFY(r->property("avpn_t0").toLongLong() > 0);
                    if (frozen)
                        r->setProperty("avpn_t0", QDateTime::currentMSecsSinceEpoch() - 10 * 60 * 1000);
                    r->setProperty("avpn_timed_out", true);
                    r->abort();
                }
        };
        service.start();
        for (int n = 1; n <= 4; ++n) {                               // four requests die in a freeze
            QTRY_COMPARE(edgeA.configRequests, n);
            timeOutRequestInFlight(/*frozen=*/true);
            QTest::qWait(30);
            if (n < 4)
                service.refreshIfStale(15 * 60 * 1000);              // the return to the screen asks again
        }
        QCOMPARE(switched.count(), 0);                               // 138: three such failures switched the edge
        QCOMPARE(failedSignals, 0);                                  // and fed the white-list detector
        QVERIFY(service.reportNetworkSuccess());                     // the config is still owed
        QTRY_COMPARE(edgeA.configRequests, 5);
        timeOutRequestInFlight(/*frozen=*/false);                    // an honest timeout of a refetch: no vote either
        QTest::qWait(30);
        QCOMPARE(failedSignals, 0);
        for (int n = 6; n <= 8; ++n) {                               // three usual requests time out honestly
            service.refreshIfStale(15 * 60 * 1000);
            QTRY_COMPARE(edgeA.configRequests, n);
            timeOutRequestInFlight(/*frozen=*/false);
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
