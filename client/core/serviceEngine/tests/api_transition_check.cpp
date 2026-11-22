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

// android5 H1/H3 (21.11): after a return from the background with requests in flight, the app's main thread stood ~5 s
// right after the native state (native_state=1 ... nothing ... control_plane_edge 5.0 s later; the requests ended
// net_error=5 at ~5.2 s; even "Application resumed" was 5.5 s late). The tunnel transition's clearConnectionCache()
// runs QNetworkAccessManagerPrivate::destroyThread on the CALLER's thread: the HTTP thread is told to quit and waited
// for, up to 5 s, while it still serves the requests. The state handler that calls resetApiConnections must never wait.
class ApiTransitionNoWaitTest : public QObject {
    Q_OBJECT
    QTcpServer silent; // accepts, reads, never answers (a server behind a path that is gone)

private slots:
    void initTestCase() { QVERIFY(silent.listen(QHostAddress::LocalHost)); }

    void theTransitionNeverWaitsForTheHttpThread()
    {
        QList<QTcpSocket *> held;
        connect(&silent, &QTcpServer::newConnection, this, [&]() {
            while (auto *s = silent.nextPendingConnection()) {
                held << s;
                connect(s, &QTcpSocket::readyRead, s, [s]() { s->readAll(); });
            }
        });
        QNetworkAccessManager nam;
        const QString base = QString("http://127.0.0.1:%1").arg(silent.serverPort());
        QList<QNetworkReply *> replies;
        for (const char *path : { "/v1/support/unread", "/v1/announcements", "/v1/journal" })
            replies << nam.get(QNetworkRequest(QUrl(base + QLatin1String(path))));
        QTRY_COMPARE(held.size(), 3);
        QTest::qWait(200);
        QElapsedTimer t;
        t.start();
        const TransitionNetAction a = transitionNetAction(ObservedTunnel::Connected, ObservedTunnel::Disconnected);
        resetApiConnections(&nam, a.clearCache, a.abortInFlight);
        const qint64 inHandler = t.elapsed();
        qInfo("resetApiConnections returned after %lld ms", inHandler);
        QVERIFY2(inHandler < 300, "the state handler waited for the network");
        // nothing ran inside the handler: the requests are still running, the drop waits for a later turn
        QVERIFY(std::all_of(replies.cbegin(), replies.cend(), [](QNetworkReply *r) { return r->isRunning(); }));
        QCOMPARE(nam.property("avpnCacheClearPending").toBool(), true);
        // the requests that were in flight end at once (their owners re-issue them), not by a timeout
        QTRY_VERIFY_WITH_TIMEOUT(std::all_of(replies.cbegin(), replies.cend(), [](QNetworkReply *r) { return r->isFinished(); }), 1000);
        for (QNetworkReply *r : replies)
            QCOMPARE(r->error(), QNetworkReply::OperationCanceledError);
        // and the dead keep-alive connections are dropped once nothing runs
        QTRY_VERIFY_WITH_TIMEOUT(nam.property("avpnCacheClearPending").isValid()
                                     && !nam.property("avpnCacheClearPending").toBool(), 6000);
        qDeleteAll(replies);
        qDeleteAll(held);
    }

    // A request started after the transition, while the drop still waits, is never stranded: the drop comes after it.
    void aRequestStartedMeanwhileIsNotStranded()
    {
        QTcpServer slow;
        QVERIFY(slow.listen(QHostAddress::LocalHost));
        connect(&slow, &QTcpServer::newConnection, this, [&]() {
            while (auto *s = slow.nextPendingConnection()) {
                connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
                connect(s, &QTcpSocket::readyRead, s, [s]() {
                    s->readAll();
                    QTimer::singleShot(400, s, [s]() {
                        s->write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}");
                        s->disconnectFromHost();
                    });
                });
            }
        });
        QNetworkAccessManager nam;
        const QString base = QString("http://127.0.0.1:%1").arg(slow.serverPort());
        QNetworkReply *before = nam.get(QNetworkRequest(QUrl(base + "/v1/config")));
        QTest::qWait(100);
        resetApiConnections(&nam, /*clearCache=*/true, /*abortInFlight=*/false); // someone else's transition
        QNetworkReply *after = nam.get(QNetworkRequest(QUrl(base + "/v1/edges")));
        QTRY_VERIFY_WITH_TIMEOUT(before->isFinished() && after->isFinished(), 3000);
        QCOMPARE(before->error(), QNetworkReply::NoError);
        QCOMPARE(after->error(), QNetworkReply::NoError);
        QTRY_COMPARE_WITH_TIMEOUT(nam.property("avpnCacheClearPending").toBool(), false, 3000);
        delete before;
        delete after;
    }
};

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    ApiTransitionTest a;
    ApiTransitionNoWaitTest b;
    return QTest::qExec(&a, argc, argv) | QTest::qExec(&b, argc, argv);
}

// QTEST_GUILESS_MAIN(ApiTransitionTest)
#include "api_transition_check.moc"
