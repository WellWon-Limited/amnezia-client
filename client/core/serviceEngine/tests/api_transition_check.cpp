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
#include <algorithm>
#include <atomic>
#include <QThread>
#include <QFile>
#include <QSslConfiguration>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslServer>

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

// android5 H1/H3 (21.11): the GUI thread stood 5 s after a tunnel transition with requests in flight. Qt 6.11.1:
// clearConnectionCache() quits Qt's HTTP thread and waits for it on the caller's thread (up to 5 s), while that thread
// may be waiting for the GUI (encrypted() is a BlockingQueuedConnection). The design (NetAwait.h): no clear at all - a
// per-generation connection key on every request (TribeNetworkAccessManager) and no idle pooled connection.
class ApiTransitionNoWaitTest : public QObject {
    Q_OBJECT

    // a loopback HTTP/1.1 server: /fast answers at once with keep-alive, anything else is held (never answered);
    // records which socket served each path
    struct Server {
        QTcpServer tcp;
        QHash<QString, QTcpSocket *> servedBy;
        QList<QTcpSocket *> sockets;
        int disconnects = 0;
        void start(QObject *ctx)
        {
            QVERIFY(tcp.listen(QHostAddress::LocalHost));
            QObject::connect(&tcp, &QTcpServer::newConnection, ctx, [this]() {
                while (auto *s = tcp.nextPendingConnection()) {
                    sockets << s;
                    QObject::connect(s, &QTcpSocket::disconnected, s, [this]() { ++disconnects; });
                    QObject::connect(s, &QTcpSocket::readyRead, s, [this, s]() {
                        const QByteArray req = s->readAll();
                        const QString path = QString::fromLatin1(req.split(' ').value(1));
                        servedBy.insert(path, s);
                        if (path.startsWith(QLatin1String("/fast")))
                            s->write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                    });
                }
            });
        }
        QString base() const { return QString("http://127.0.0.1:%1").arg(tcp.serverPort()); }
    };

private slots:
    // The policy of one request: no idle pooled connection; the generation's parity in the connection key (the URL's own
    // host as the verify name, so the TLS check and SNI do not change); what the caller set stays.
    void connectionPolicyOfARequest()
    {
        const QNetworkRequest even = withConnectionPolicy(QNetworkRequest(QUrl("https://api.example.com/v1/config")), 2);
        QCOMPARE(even.attribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute).toInt(), 0);
        QVERIFY(even.peerVerifyName().isEmpty());
        const QNetworkRequest odd = withConnectionPolicy(QNetworkRequest(QUrl("https://api.example.com/v1/config")), 3);
        QCOMPARE(odd.peerVerifyName(), QStringLiteral("api.example.com"));
        QNetworkRequest own(QUrl("https://10.0.0.1/v1/config"));
        own.setPeerVerifyName(QStringLiteral("edge.example.com"));
        own.setAttribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute, 30);
        const QNetworkRequest kept = withConnectionPolicy(own, 5);
        QCOMPARE(kept.peerVerifyName(), QStringLiteral("edge.example.com"));
        QCOMPARE(kept.attribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute).toInt(), 30);
    }

    // The transition itself: returns at once, starts the next generation synchronously, aborts what ran on a later turn.
    void theTransitionNeverWaits()
    {
        Server srv;
        srv.start(this);
        TribeNetworkAccessManager nam;
        QList<QNetworkReply *> replies;
        for (const char *path : { "/held/support", "/held/announcements", "/held/journal" })
            replies << nam.get(QNetworkRequest(QUrl(srv.base() + QLatin1String(path))));
        QTRY_COMPARE(srv.servedBy.size(), 3);
        const quint64 gen = nam.property(kConnGeneration).toULongLong();
        QElapsedTimer t;
        t.start();
        const TransitionNetAction a = transitionNetAction(ObservedTunnel::Connected, ObservedTunnel::Disconnected);
        resetApiConnections(&nam, a.clearCache, a.abortInFlight);
        QVERIFY2(t.elapsed() < 100, "the state handler waited for the network");
        QCOMPARE(nam.property(kConnGeneration).toULongLong(), gen + 1); // the next generation begins now
        QVERIFY(std::all_of(replies.cbegin(), replies.cend(), [](QNetworkReply *r) { return r->isRunning(); }));
        QTRY_VERIFY_WITH_TIMEOUT(std::all_of(replies.cbegin(), replies.cend(), [](QNetworkReply *r) { return r->isFinished(); }), 1000);
        for (QNetworkReply *r : replies)
            QCOMPARE(r->error(), QNetworkReply::OperationCanceledError);
        QTRY_COMPARE_WITH_TIMEOUT(srv.disconnects, 3, 2000); // the aborted requests closed their sockets
        qDeleteAll(replies);
    }

    // The guarantee clearing gave: a request of the new generation never goes over a socket of the old one - even when
    // the old connection is still in use (a held request) and has an idle keep-alive channel (a finished one), which the
    // request would take with the same key.
    void aRequestAfterTheTransitionNeverTakesAnOldSocket()
    {
        Server srv;
        srv.start(this);
        TribeNetworkAccessManager nam;
        QNetworkReply *held = nam.get(QNetworkRequest(QUrl(srv.base() + "/held/a")));
        QNetworkReply *fast = nam.get(QNetworkRequest(QUrl(srv.base() + "/fast/a")));
        QTRY_VERIFY(fast->isFinished());
        QCOMPARE(fast->error(), QNetworkReply::NoError);
        QVERIFY(held->isRunning());
        resetApiConnections(&nam, /*clearCache=*/true, /*abortInFlight=*/true);
        QNetworkReply *after = nam.get(QNetworkRequest(QUrl(srv.base() + "/fast/b")));
        QTRY_VERIFY_WITH_TIMEOUT(after->isFinished(), 2000);
        QCOMPARE(after->error(), QNetworkReply::NoError);
        QVERIFY(srv.servedBy.value("/fast/b") != srv.servedBy.value("/fast/a"));
        QVERIFY(srv.servedBy.value("/fast/b") != srv.servedBy.value("/held/a"));
        delete held;
        delete fast;
        delete after;
    }

    // No idle pooled connection: a socket is closed by the app once its last request is done.
    void aConnectionClosesWithItsLastRequest()
    {
        Server srv;
        srv.start(this);
        TribeNetworkAccessManager nam;
        QNetworkReply *r = nam.get(QNetworkRequest(QUrl(srv.base() + "/fast/one")));
        QTRY_VERIFY(r->isFinished());
        QTRY_COMPARE_WITH_TIMEOUT(srv.disconnects, 1, 2000);
        delete r;
    }

    // The hazard itself (TLS): the HTTP thread reports the finished handshake with a BlockingQueuedConnection and waits
    // for the GUI; clearConnectionCache() on the GUI waits for the HTTP thread - 5 s. A transition at that moment must
    // return at once (it no longer clears).
    void aTransitionMidHandshakeDoesNotWait()
    {
        const QByteArray certPath = qgetenv("AVPN_TEST_TLS_CERT"), keyPath = qgetenv("AVPN_TEST_TLS_KEY");
        if (!QSslSocket::supportsSsl() || certPath.isEmpty())
            QSKIP("no TLS backend or no test certificate");
        QFile cf(QString::fromLocal8Bit(certPath)), kf(QString::fromLocal8Bit(keyPath));
        QVERIFY(cf.open(QIODevice::ReadOnly) && kf.open(QIODevice::ReadOnly));
        QSslConfiguration conf = QSslConfiguration::defaultConfiguration();
        conf.setLocalCertificate(QSslCertificate(cf.readAll(), QSsl::Pem));
        conf.setPrivateKey(QSslKey(kf.readAll(), QSsl::Rsa, QSsl::Pem));
        // the server on its own thread: it completes handshakes while the GUI thread is busy
        std::atomic<int> handshakes{0};
        std::atomic<quint16> port{0};
        QThread serverThread;
        QSslServer *tls = new QSslServer;
        tls->setSslConfiguration(conf);
        tls->moveToThread(&serverThread);
        connect(&serverThread, &QThread::started, tls, [&, tls]() {
            if (!tls->listen(QHostAddress::LocalHost))
                return;
            QObject::connect(tls, &QSslServer::pendingConnectionAvailable, tls, [&, tls]() {
                while (auto *sock = tls->nextPendingConnection()) {
                    ++handshakes;
                    QObject::connect(sock, &QTcpSocket::readyRead, sock, [sock]() { sock->readAll(); }); // never answers
                }
            });
            port = tls->serverPort();
        });
        connect(&serverThread, &QThread::finished, tls, &QObject::deleteLater);
        serverThread.start();
        QTest::qWaitFor([&]() { return port.load() != 0; }, 2000);
        if (port.load() == 0) {
            serverThread.quit();
            serverThread.wait();
            QSKIP("the TLS backend cannot serve");
        }
        const auto measure = [&](bool oldWay) -> qint64 {
            TribeNetworkAccessManager nam;
            QNetworkRequest req(QUrl(QString("https://127.0.0.1:%1/v1/config").arg(port.load())));
            QNetworkReply *r = nam.get(req);
            r->ignoreSslErrors(); // the loopback certificate is self-signed
            // the GUI is busy while the HTTP thread completes the handshake and blocks in encrypted()
            const int before = handshakes.load();
            QTest::qWaitFor([&]() { return handshakes.load() > before || r->isFinished(); }, 3000);
            QThread::msleep(800); // the GUI is busy: encrypted() waits for it in the HTTP thread
            QElapsedTimer t;
            t.start();
            if (oldWay)
                nam.clearConnectionCache();
            else
                resetApiConnections(&nam, true, true);
            const qint64 ms = t.elapsed();
            r->abort();
            delete r;
            return ms;
        };
        const qint64 old = measure(/*oldWay=*/true);
        const qint64 now = measure(/*oldWay=*/false);
        serverThread.quit();
        serverThread.wait();
        qInfo("mid-handshake: clearConnectionCache() %lld ms, resetApiConnections %lld ms", old, now);
        QVERIFY2(old >= 4000, "the Qt behaviour the design avoids (clearConnectionCache waits for the HTTP thread) changed");
        QVERIFY2(now < 100, "the transition waited for the HTTP thread");
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
