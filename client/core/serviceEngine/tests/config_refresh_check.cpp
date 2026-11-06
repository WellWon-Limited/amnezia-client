// Real ConfigService + loopback HTTP server. Storage and signature verification are
// isolated fixtures; Ed25519 itself has a separate regression suite.
#define AVPN_CONFIGSTORE_TEST
#include <QByteArray>
#include <QStringList>
namespace avpn {
static QByteArray cachedConfig;
static int savedConfigs = 0;
class ConfigStore {
public:
    static QByteArray loadConfig() { return cachedConfig; }
    static void saveConfig(const QByteArray &body) { cachedConfig = body; ++savedConfigs; }
    static QStringList loadEdges() { return {}; }
    static void saveEdges(const QStringList &) {}
    static QString activeEdge(const QString &value) { return value; }
    static void setActiveEdge(const QString &) {}
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

class ConfigRefreshTest : public QObject {
    Q_OBJECT
private slots:
    void init() { avpn::cachedConfig.clear(); avpn::savedConfigs = 0; }
    void cachedXrayDoesNotThawUntilFreshSignedResponse()
    {
        const QByteArray cached = R"({"features":{"xray_client":true}})";
        avpn::cachedConfig = cached;
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        connect(&server, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [socket]() {
                    socket->readAll();
                    const QByteArray body = R"({"features":{"xray_client":true},"recommended_version":{"macos":"fresh"}})";
                    socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nX-Tribe-Sig: fixture-signature\r\nContent-Length: "
                                  + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
        QNetworkAccessManager network;
        const QString base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        avpn::ConfigService service(&network, base, "fixture-key", {base});
        service.start();
        QVERIFY(!service.config().features.value("xray_client", true));
        QCOMPARE(avpn::cachedConfig, cached); // no forged write of the modified signed LKG.
        QCOMPARE(avpn::savedConfigs, 0);
        QTRY_COMPARE(service.config().recommendedVersion.value("macos"), QString("fresh"));
        QVERIFY(service.config().features.value("xray_client", false));
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
        QNetworkAccessManager network;
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
        QNetworkAccessManager network; // no server: the switch re-fetches /v1/config, which just fails
        const QString a = "http://127.0.0.1:9", b = "http://127.0.0.1:10";
        avpn::ConfigService service(&network, a, "fixture-key", {a, b});
        QSignalSpy switched(&service, &avpn::ConfigService::activeEdgeChanged);
        service.reportNetworkSuccess();                              // /v1/account OK
        QVERIFY(!service.reportSubscriptionOutcome(a, true));        // subscription timeout #1
        service.reportNetworkSuccess();                              // /v1/support/unread OK
        QVERIFY(!service.reportSubscriptionOutcome(a, false));       // delivered -> streak reset
        QVERIFY(!service.reportSubscriptionOutcome(a, true));        // #1 again
        QCOMPARE(switched.count(), 0);
        service.reportNetworkSuccess();
        QVERIFY(service.reportSubscriptionOutcome(a, true));         // #2 in a row -> next edge
        QCOMPARE(switched.count(), 1);
        QCOMPARE(switched.at(0).at(0).toString(), b);
        QCOMPARE(service.activeBaseUrl(), b);
        QVERIFY(!service.reportSubscriptionOutcome(a, true));        // late failure from the old edge
        QCOMPARE(service.activeBaseUrl(), b);
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
        QNetworkAccessManager network;
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
        QNetworkAccessManager network;
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
