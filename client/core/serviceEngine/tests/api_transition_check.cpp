// Tunnel transitions on the shared QNetworkAccessManager (decision 2026-11-05, owner test 06.11):
// clearConnectionCache() strands a request in flight (Qt destroys its HTTP thread; only our 15 s
// armTimeout would end it). The engine clears only on a real transition and aborts the requests in
// flight whenever the cache was cleared (by us, or by upstream ConnectionUiController on every
// Connected) so their owners re-issue them. Real QNAM + loopback HTTP server that answers after
// 500 ms. Build/run: tests/build_api_transition.sh
#include "../DebugSnapshot.h"
#include "../NetAwait.h"

#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>

using namespace avpn;

class ApiTransitionTest : public QObject {
    Q_OBJECT
    QTcpServer server;
    int requests = 0;
    QString base;

    // The engine's step (AvpnEngineQml::onConnectionStateChanged).
    static void onTransition(QNetworkAccessManager *nam, ObservedTunnel previous, ObservedTunnel now)
    {
        const TransitionNetAction a = transitionNetAction(previous, now);
        if (a.clearCache || a.abortInFlight)
            resetApiConnections(nam, a.clearCache, a.abortInFlight);
    }

    // An API call with the 15 s deadline every call has and the owner's re-issue after our abort
    // (refreshSubscription / ConfigService); counts completed answers.
    void fetch(QNetworkAccessManager *nam, int *completed, int *reissued)
    {
        QNetworkReply *r = nam->get(QNetworkRequest(QUrl(base + "/v1/subscription")));
        armTimeout(r);
        connect(r, &QNetworkReply::finished, this, [=]() {
            r->deleteLater();
            if (reissueAfterOwnAbort(r->error() == QNetworkReply::OperationCanceledError,
                                     r->property("avpn_timed_out").toBool())) {
                ++*reissued;
                QTimer::singleShot(0, this, [=]() { fetch(nam, completed, reissued); });
                return;
            }
            if (r->error() == QNetworkReply::NoError)
                ++*completed;
        });
    }

private slots:
    void init()
    {
        requests = 0;
        QVERIFY(server.isListening() || server.listen(QHostAddress::LocalHost));
        base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        disconnect(&server, nullptr, this, nullptr);
        connect(&server, &QTcpServer::newConnection, this, [this]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
                    socket->readAll();
                    ++requests;
                    QTimer::singleShot(500, socket, [socket]() {
                        socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}");
                        socket->disconnectFromHost();
                    });
                });
            }
        });
    }

    // The Qt behaviour the engine depends on: the server answers, the reply never finishes.
    void qtClearConnectionCacheStrandsInFlight()
    {
        QNetworkAccessManager nam;
        QNetworkReply *r = nam.get(QNetworkRequest(QUrl(base + "/v1/config")));
        QTRY_COMPARE(requests, 1);
        nam.clearConnectionCache();
        QTest::qWait(1500); // the answer came at 500 ms
        QVERIFY(r->isRunning());
        r->abort();          // only an abort (or our 15 s timeout) ends it
        QVERIFY(r->isFinished());
        delete r;
    }

    // Owner 06.11 10:31:21: the app starts while the tunnel is up. Upstream clears the cache on that
    // first Connected; the engine aborts what was in flight and it is re-issued - seconds, not 15 s.
    void adoptionAfterUpstreamClearIsReissued()
    {
        QNetworkAccessManager nam;
        int completed = 0, reissued = 0;
        fetch(&nam, &completed, &reissued);
        QTRY_COMPARE(requests, 1);
        QElapsedTimer t;
        t.start();
        nam.clearConnectionCache(); // upstream ConnectionUiController on Connected
        onTransition(&nam, ObservedTunnel::Unknown, ObservedTunnel::Connected);
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 4000);
        QCOMPARE(reissued, 1);
        QVERIFY(t.elapsed() < 4000);
    }

    // Cold start with the tunnel off (Unknown -> Disconnected): nobody clears, nothing is aborted,
    // the startup call completes on its own (133/134 cleared here and stranded /v1/config).
    void coldStartTunnelOffLeavesStartupCallsAlone()
    {
        QNetworkAccessManager nam;
        int completed = 0, reissued = 0;
        fetch(&nam, &completed, &reissued);
        QTRY_COMPARE(requests, 1);
        onTransition(&nam, ObservedTunnel::Unknown, ObservedTunnel::Disconnected);
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 4000);
        QCOMPARE(reissued, 0);
    }

    // A real tunnel-up: our clear + abort; a call in flight (sent over the physical path) is re-issued.
    void realConnectedClearsAndReissues()
    {
        QNetworkAccessManager nam;
        int completed = 0, reissued = 0;
        fetch(&nam, &completed, &reissued);
        QTRY_COMPARE(requests, 1);
        onTransition(&nam, ObservedTunnel::Transitional, ObservedTunnel::Connected);
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 4000);
        QCOMPARE(reissued, 1);
        QCOMPARE(requests, 2);
    }

    // The snapshot: a call started after the transition is not aborted.
    void callStartedAfterTheTransitionIsKept()
    {
        QNetworkAccessManager nam;
        onTransition(&nam, ObservedTunnel::Transitional, ObservedTunnel::Connected); // nothing in flight
        int completed = 0, reissued = 0;
        fetch(&nam, &completed, &reissued);
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 4000);
        QCOMPARE(reissued, 0);
    }
};

QTEST_GUILESS_MAIN(ApiTransitionTest)
#include "api_transition_check.moc"
