// Tunnel transitions on the app's shared API manager (decision 2026-11-05, owner test 06.11, android5 H1/H3 21.11,
// reviews of 0e31a2571 and 5c354b603). NetAwait.h TribeNetworkAccessManager: one plain QNetworkAccessManager per tunnel
// generation behind one facade; a transition starts a new generation (no connection of the old path can be taken by a
// later request), aborts the requests in flight on the next turn (their owners re-issue them), and retires the old
// generation on a retirement thread once its last reply is gone - the GUI thread never waits for Qt's HTTP thread.
// DebugSnapshot.h newApiGeneration: the one owner's decision. Real QNAMs, loopback HTTP and TLS servers.
// Build/run: tests/build_api_transition.sh
#include "../DebugSnapshot.h"
#include "../NetAwait.h"

#include <QElapsedTimer>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslServer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>
#include <QThread>
#include <algorithm>
#include <atomic>
#include <cstdio>

using namespace avpn;

namespace {

// The one owner's step (AvpnEngineQml::applyNativeState).
void onTransition(QNetworkAccessManager *nam, ObservedTunnel previous, ObservedTunnel now)
{
    if (newApiGeneration(previous, now))
        resetApiConnections(nam);
}

QByteArray readEnvFile(const char *var)
{
    QFile f(QString::fromLocal8Bit(qgetenv(var)));
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

// Watches where (and whether) a generation's manager is destroyed - the reply's parent is its generation.
struct RetireWatch {
    std::atomic<bool> destroyed{false};
    std::atomic<bool> onGuiThread{false};
    void watch(QObject *generation)
    {
        QThread *gui = QThread::currentThread();
        QObject::connect(generation, &QObject::destroyed, generation, [this, gui]() {
            onGuiThread = QThread::currentThread() == gui;
            destroyed = true;
        }, Qt::DirectConnection);
    }
};

// A TLS server on its own thread that completes handshakes and never answers - the HTTP thread then reports the
// handshake to the reply's thread with a BlockingQueuedConnection (qnetworkreplyhttpimpl.cpp:996-997).
struct TlsHoldServer {
    QThread thread;
    std::atomic<int> handshakes{0};
    std::atomic<quint16> port{0};
    bool start()
    {
        const QByteArray cert = readEnvFile("AVPN_TEST_TLS_CERT"), key = readEnvFile("AVPN_TEST_TLS_KEY");
        if (!QSslSocket::supportsSsl() || cert.isEmpty() || key.isEmpty())
            return false;
        QSslConfiguration conf = QSslConfiguration::defaultConfiguration();
        conf.setLocalCertificate(QSslCertificate(cert, QSsl::Pem));
        conf.setPrivateKey(QSslKey(key, QSsl::Rsa, QSsl::Pem));
        auto *tls = new QSslServer;
        tls->setSslConfiguration(conf);
        tls->moveToThread(&thread);
        QObject::connect(&thread, &QThread::started, tls, [this, tls]() {
            if (!tls->listen(QHostAddress::LocalHost))
                return;
            QObject::connect(tls, &QSslServer::pendingConnectionAvailable, tls, [this, tls]() {
                while (auto *sock = tls->nextPendingConnection()) {
                    ++handshakes;
                    QObject::connect(sock, &QTcpSocket::readyRead, sock, [sock]() { sock->readAll(); }); // never answers
                }
            });
            port = tls->serverPort();
        });
        QObject::connect(&thread, &QThread::finished, tls, &QObject::deleteLater);
        thread.start();
        return QTest::qWaitFor([this]() { return port.load() != 0; }, 2000);
    }
    ~TlsHoldServer()
    {
        thread.quit();
        thread.wait();
    }
    // A request whose handshake is done while this (GUI) thread is busy: the HTTP thread waits in encrypted().
    QNetworkReply *requestMidHandshake(QNetworkAccessManager *nam)
    {
        QNetworkReply *r = nam->get(QNetworkRequest(QUrl(QString("https://127.0.0.1:%1/v1/config").arg(port.load()))));
        r->ignoreSslErrors(); // the loopback certificate is not trusted here
        const int before = handshakes.load();
        (void)QTest::qWaitFor([&]() { return handshakes.load() > before || r->isFinished(); }, 3000);
        QThread::msleep(800); // the GUI is busy: encrypted() waits for it in the HTTP thread
        return r;
    }
};

} // namespace

class ApiTransitionTest : public QObject {
    Q_OBJECT
    QTcpServer server;
    int requests = 0;
    QString base;

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

    // The one owner's decision: a new API generation on a real transition and on every Connected (where upstream
    // cleared), never on a first non-Connected status, a repeated Disconnected or a transitional state.
    void decisionTable()
    {
        QVERIFY(newApiGeneration(ObservedTunnel::Transitional, ObservedTunnel::Connected));
        QVERIFY(newApiGeneration(ObservedTunnel::Disconnected, ObservedTunnel::Connected));
        QVERIFY(newApiGeneration(ObservedTunnel::Connected, ObservedTunnel::Disconnected));
        QVERIFY(newApiGeneration(ObservedTunnel::Transitional, ObservedTunnel::Disconnected));
        QVERIFY(newApiGeneration(ObservedTunnel::Unknown, ObservedTunnel::Connected));   // adoption
        QVERIFY(newApiGeneration(ObservedTunnel::Connected, ObservedTunnel::Connected)); // repeat
        QVERIFY(!newApiGeneration(ObservedTunnel::Unknown, ObservedTunnel::Disconnected)); // cold start, tunnel off
        QVERIFY(!newApiGeneration(ObservedTunnel::Connected, ObservedTunnel::Transitional));
        QVERIFY(!newApiGeneration(ObservedTunnel::Disconnected, ObservedTunnel::Disconnected));
    }

    // The Qt behaviour the design never relies on: after clearConnectionCache() the server answers, the reply never
    // finishes (Qt destroyed its HTTP thread).
    void qtClearConnectionCacheStrandsInFlight()
    {
        QNetworkAccessManager nam;
        QNetworkReply *r = nam.get(QNetworkRequest(QUrl(base + "/v1/config")));
        QTRY_COMPARE(requests, 1);
        nam.clearConnectionCache();
        QTest::qWait(1500); // the answer came at 500 ms
        QVERIFY(r->isRunning());
        r->abort();
        QVERIFY(r->isFinished());
        delete r;
    }

    // Owner 06.11 10:31:21: the app starts while the tunnel is up. Adoption starts a new generation; what was in flight
    // is aborted and re-issued - seconds, not 15 s.
    void adoptionStartsANewGenerationAndReissues()
    {
        TribeNetworkAccessManager nam;
        int completed = 0, reissued = 0;
        fetch(&nam, &completed, &reissued);
        QTRY_COMPARE(requests, 1);
        QElapsedTimer t;
        t.start();
        onTransition(&nam, ObservedTunnel::Unknown, ObservedTunnel::Connected);
        QCOMPARE(nam.generation(), quint64(1));
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 4000);
        QCOMPARE(reissued, 1);
        QVERIFY(t.elapsed() < 4000);
    }

    // Cold start with the tunnel off (Unknown -> Disconnected): nothing renewed, nothing aborted.
    void coldStartTunnelOffLeavesStartupCallsAlone()
    {
        TribeNetworkAccessManager nam;
        int completed = 0, reissued = 0;
        fetch(&nam, &completed, &reissued);
        QTRY_COMPARE(requests, 1);
        onTransition(&nam, ObservedTunnel::Unknown, ObservedTunnel::Disconnected);
        QCOMPARE(nam.generation(), quint64(0));
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 4000);
        QCOMPARE(reissued, 0);
    }

    // A real tunnel-up: a call in flight (sent over the physical path) is re-issued on the new generation.
    void realConnectedReissues()
    {
        TribeNetworkAccessManager nam;
        int completed = 0, reissued = 0;
        fetch(&nam, &completed, &reissued);
        QTRY_COMPARE(requests, 1);
        onTransition(&nam, ObservedTunnel::Transitional, ObservedTunnel::Connected);
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 4000);
        QCOMPARE(reissued, 1);
        QCOMPARE(requests, 2);
    }

    // A call started after the transition is not aborted.
    void callStartedAfterTheTransitionIsKept()
    {
        TribeNetworkAccessManager nam;
        onTransition(&nam, ObservedTunnel::Transitional, ObservedTunnel::Connected); // nothing in flight
        int completed = 0, reissued = 0;
        fetch(&nam, &completed, &reissued);
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 4000);
        QCOMPARE(reissued, 0);
    }
};

class ApiTransitionNoWaitTest : public QObject {
    Q_OBJECT

    // a loopback HTTP/1.1 server: /fast answers at once with keep-alive, anything else is held (never answered);
    // records which socket served each path and the request line
    struct Server {
        QTcpServer tcp;
        QHash<QString, QTcpSocket *> servedBy;
        QHash<QString, QByteArray> head;
        int disconnects = 0;
        void start(QObject *ctx)
        {
            QVERIFY(tcp.listen(QHostAddress::LocalHost));
            QObject::connect(&tcp, &QTcpServer::newConnection, ctx, [this]() {
                while (auto *s = tcp.nextPendingConnection()) {
                    QObject::connect(s, &QTcpSocket::disconnected, s, [this]() { ++disconnects; });
                    QObject::connect(s, &QTcpSocket::readyRead, s, [this, s]() {
                        const QByteArray req = s->readAll();
                        const QString path = QString::fromLatin1(req.split(' ').value(1));
                        servedBy.insert(path, s);
                        head.insert(path, req);
                        if (path.startsWith(QLatin1String("/fast")))
                            s->write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                    });
                }
            });
        }
        QString base() const { return QString("http://127.0.0.1:%1").arg(tcp.serverPort()); }
    };

private slots:
    // The transition itself: returns at once, the next generation begins synchronously, what ran is aborted on a later turn.
    void theTransitionNeverWaits()
    {
        Server srv;
        srv.start(this);
        TribeNetworkAccessManager nam;
        QList<QNetworkReply *> replies;
        for (const char *path : { "/held/support", "/held/announcements", "/held/journal" })
            replies << nam.get(QNetworkRequest(QUrl(srv.base() + QLatin1String(path))));
        QTRY_COMPARE(srv.servedBy.size(), 3);
        QElapsedTimer t;
        t.start();
        onTransition(&nam, ObservedTunnel::Connected, ObservedTunnel::Disconnected);
        QVERIFY2(t.elapsed() < 100, "the state handler waited for the network");
        QCOMPARE(nam.generation(), quint64(1));
        QVERIFY(std::all_of(replies.cbegin(), replies.cend(), [](QNetworkReply *r) { return r->isRunning(); }));
        QTRY_VERIFY_WITH_TIMEOUT(std::all_of(replies.cbegin(), replies.cend(), [](QNetworkReply *r) { return r->isFinished(); }), 1000);
        for (QNetworkReply *r : replies)
            QCOMPARE(r->error(), QNetworkReply::OperationCanceledError);
        QTRY_COMPARE_WITH_TIMEOUT(srv.disconnects, 3, 2000); // the aborted requests closed their sockets
        qDeleteAll(replies);
    }

    // Review R1: one ordinary Connected may reach the reset more than once. Whatever the number of resets, a request
    // after them never joins a connection opened before - even one still in use (a held request) with an idle
    // keep-alive channel (a finished one), which the same key would give it (qnetworkaccesscache.cpp:225-228).
    void anyNumberOfResetsNeverReusesAnOldConnection()
    {
        for (int resets = 1; resets <= 3; ++resets) {
            Server srv;
            srv.start(this);
            TribeNetworkAccessManager nam;
            QNetworkReply *held = nam.get(QNetworkRequest(QUrl(srv.base() + "/held/a")));
            QNetworkReply *fast = nam.get(QNetworkRequest(QUrl(srv.base() + "/fast/a")));
            QTRY_VERIFY(fast->isFinished());
            QCOMPARE(fast->error(), QNetworkReply::NoError);
            QVERIFY(held->isRunning());
            for (int i = 0; i < resets; ++i)
                resetApiConnections(&nam);
            QNetworkReply *after = nam.get(QNetworkRequest(QUrl(srv.base() + "/fast/b")));
            QTRY_VERIFY_WITH_TIMEOUT(after->isFinished(), 2000);
            QCOMPARE(after->error(), QNetworkReply::NoError);
            QVERIFY2(srv.servedBy.value("/fast/b") != srv.servedBy.value("/fast/a"),
                     qPrintable(QString("after %1 reset(s) the request took the old idle channel").arg(resets)));
            QVERIFY(srv.servedBy.value("/fast/b") != srv.servedBy.value("/held/a"));
            delete held;
            delete fast;
            delete after;
        }
    }

    // P6: within a generation Qt's own keep-alive stays - sequential calls share one connection; a transition ends it.
    void keepAliveWithinAGeneration()
    {
        Server srv;
        srv.start(this);
        TribeNetworkAccessManager nam;
        QNetworkReply *one = nam.get(QNetworkRequest(QUrl(srv.base() + "/fast/1")));
        QTRY_VERIFY(one->isFinished());
        QNetworkReply *two = nam.get(QNetworkRequest(QUrl(srv.base() + "/fast/2")));
        QTRY_VERIFY(two->isFinished());
        QCOMPARE(srv.servedBy.value("/fast/2"), srv.servedBy.value("/fast/1"));
        QCOMPARE(srv.disconnects, 0);
        resetApiConnections(&nam);
        QNetworkReply *three = nam.get(QNetworkRequest(QUrl(srv.base() + "/fast/3")));
        QTRY_VERIFY(three->isFinished());
        QVERIFY(srv.servedBy.value("/fast/3") != srv.servedBy.value("/fast/1"));
        delete one;
        delete two;
        delete three;
    }

    // P3 and the manager contract: a request reaches the wire as the caller made it on every generation (no peer name,
    // no pool attribute); reply->manager() and finished() are the facade's; custom verbs and bodies pass through.
    void theFacadeKeepsRequestsAndTheManagerContract()
    {
        Server srv;
        srv.start(this);
        TribeNetworkAccessManager nam;
        int finished = 0;
        connect(&nam, &QNetworkAccessManager::finished, this, [&finished]() { ++finished; });
        for (int gen = 0; gen < 3; ++gen) {
            const QString path = QString("/fast/g%1").arg(gen);
            QNetworkReply *r = nam.get(QNetworkRequest(QUrl(srv.base() + path)));
            QCOMPARE(r->manager(), static_cast<QNetworkAccessManager *>(&nam));
            QVERIFY(r->parent() != &nam); // it belongs to the generation
            QVERIFY(r->request().peerVerifyName().isEmpty());
            QVERIFY(!r->request().attribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute).isValid());
            QTRY_VERIFY(r->isFinished());
            QCOMPARE(r->error(), QNetworkReply::NoError);
            delete r;
            resetApiConnections(&nam);
        }
        QCOMPARE(finished, 3);
        QNetworkReply *custom = nam.sendCustomRequest(QNetworkRequest(QUrl(srv.base() + "/fast/custom")), "PATCH", QByteArray("{\"a\":1}"));
        QTRY_VERIFY(custom->isFinished());
        QVERIFY(srv.head.value("/fast/custom").startsWith("PATCH /fast/custom"));
        QVERIFY(srv.head.value("/fast/custom").endsWith("{\"a\":1}"));
        QNetworkRequest postReq(QUrl(srv.base() + "/fast/post"));
        postReq.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        QNetworkReply *post = nam.post(postReq, QByteArray("{\"b\":2}"));
        QTRY_VERIFY(post->isFinished());
        QVERIFY(srv.head.value("/fast/post").startsWith("POST /fast/post"));
        QVERIFY(srv.head.value("/fast/post").endsWith("{\"b\":2}"));
        delete custom;
        delete post;
    }

    // Review R3: an automatic HTTPS redirect to another host with its own certificate succeeds on every generation -
    // the TLS identity is the URL's, as in stock Qt (qnetworkreplyhttpimpl.cpp:1188-1190 copies the request).
    void httpsRedirectToAnotherHostOnEveryGeneration()
    {
        const QByteArray ca = readEnvFile("AVPN_TEST_TLS_CA");
        const QByteArray certA = readEnvFile("AVPN_TEST_TLS_CERT"), keyA = readEnvFile("AVPN_TEST_TLS_KEY");
        const QByteArray certB = readEnvFile("AVPN_TEST_TLS_CERT_B"), keyB = readEnvFile("AVPN_TEST_TLS_KEY_B");
        if (!QSslSocket::supportsSsl() || ca.isEmpty() || certB.isEmpty())
            QSKIP("no TLS backend or no test certificates");
        const auto serve = [](QSslServer &srv, const QByteArray &cert, const QByteArray &key) {
            QSslConfiguration c = QSslConfiguration::defaultConfiguration();
            c.setLocalCertificate(QSslCertificate(cert, QSsl::Pem));
            c.setPrivateKey(QSslKey(key, QSsl::Rsa, QSsl::Pem));
            srv.setSslConfiguration(c);
            return srv.listen(QHostAddress::LocalHost);
        };
        QSslServer a, b; // a: https://127.0.0.1 (IP certificate), b: https://localhost (DNS certificate)
        QVERIFY(serve(a, certA, keyA) && serve(b, certB, keyB));
        const QByteArray target = QString("https://localhost:%1/v1/target").arg(b.serverPort()).toLatin1();
        connect(&a, &QSslServer::pendingConnectionAvailable, this, [&a, target]() {
            while (auto *s = a.nextPendingConnection())
                connect(s, &QIODevice::readyRead, s, [s, target]() {
                    s->readAll();
                    s->write("HTTP/1.1 302 Found\r\nLocation: " + target + "\r\nContent-Length: 0\r\n\r\n");
                });
        });
        connect(&b, &QSslServer::pendingConnectionAvailable, this, [&b]() {
            while (auto *s = b.nextPendingConnection())
                connect(s, &QIODevice::readyRead, s, [s]() {
                    s->readAll();
                    s->write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                });
        });
        TribeNetworkAccessManager nam;
        for (int gen = 0; gen < 4; ++gen) {
            QNetworkRequest req(QUrl(QString("https://127.0.0.1:%1/v1/start").arg(a.serverPort())));
            QSslConfiguration c = QSslConfiguration::defaultConfiguration();
            c.addCaCertificates(QSslCertificate::fromData(ca, QSsl::Pem)); // trust, not ignoreSslErrors: the name is checked
            req.setSslConfiguration(c);
            QNetworkReply *r = nam.get(req);
            QList<QSslError> errors;
            connect(r, &QNetworkReply::sslErrors, this, [&errors](const QList<QSslError> &e) { errors = e; });
            QTRY_VERIFY_WITH_TIMEOUT(r->isFinished(), 5000);
            QVERIFY2(r->error() == QNetworkReply::NoError,
                     qPrintable(QString("generation %1: %2").arg(gen).arg(r->errorString())));
            QVERIFY(errors.isEmpty());
            QCOMPARE(r->url().host(), QStringLiteral("localhost"));
            delete r;
            resetApiConnections(&nam);
        }
    }

    // A generation is retired only after its last reply is destroyed, and then off the GUI thread.
    void aGenerationRetiresAfterItsLastReplyOffTheGuiThread()
    {
        Server srv;
        srv.start(this);
        TribeNetworkAccessManager nam;
        QNetworkReply *held = nam.get(QNetworkRequest(QUrl(srv.base() + "/held/r")));
        QTRY_VERIFY(srv.servedBy.contains("/held/r"));
        RetireWatch w;
        w.watch(held->parent());
        resetApiConnections(&nam);
        QTRY_VERIFY(held->isFinished()); // aborted on the next turn
        QTest::qWait(300);
        QVERIFY2(!w.destroyed, "a generation was retired while its reply was alive");
        QCOMPARE(nam.retiringGenerations(), 1);
        delete held;
        QTRY_VERIFY_WITH_TIMEOUT(w.destroyed.load(), 7000);
        QVERIFY2(!w.onGuiThread, "a generation was destroyed on the GUI thread");
        QCOMPARE(nam.retiringGenerations(), 0);
    }

    // The hazard itself (TLS): the HTTP thread reports the finished handshake with a BlockingQueuedConnection and waits
    // for the GUI; clearConnectionCache() on the GUI waits for the HTTP thread - 5 s. A transition at that moment
    // returns at once, and the old generation is destroyed later, off the GUI thread.
    void aTransitionMidHandshakeDoesNotWait()
    {
        TlsHoldServer tls;
        if (!tls.start())
            QSKIP("no TLS backend or no test certificate");
        qint64 old = 0;
        {
            QNetworkAccessManager plain;
            QNetworkReply *r = tls.requestMidHandshake(&plain);
            QElapsedTimer t;
            t.start();
            plain.clearConnectionCache();
            old = t.elapsed();
            r->abort();
            delete r;
        }
        TribeNetworkAccessManager nam;
        QNetworkReply *r = tls.requestMidHandshake(&nam);
        RetireWatch w;
        w.watch(r->parent());
        QElapsedTimer t;
        t.start();
        onTransition(&nam, ObservedTunnel::Transitional, ObservedTunnel::Connected);
        const qint64 now = t.elapsed();
        QTRY_VERIFY_WITH_TIMEOUT(r->isFinished(), 1000);
        QCOMPARE(r->error(), QNetworkReply::OperationCanceledError);
        t.restart();
        delete r; // its owner's deleteLater
        const qint64 deleteMs = t.elapsed();
        QTRY_VERIFY_WITH_TIMEOUT(w.destroyed.load(), 7000);
        qInfo("mid-handshake: clearConnectionCache() %lld ms; transition %lld ms, reply delete %lld ms", old, now, deleteMs);
        QVERIFY2(old >= 4000, "the Qt behaviour the design avoids (clearConnectionCache waits for the HTTP thread) changed");
        QVERIFY2(now < 100, "the transition waited for the HTTP thread");
        QVERIFY2(deleteMs < 100, "deleting the reply waited");
        QVERIFY2(!w.onGuiThread, "the old generation was destroyed on the GUI thread");
    }

    // The facade destroyed while the application still runs, with a request mid-handshake: no wait on the GUI thread,
    // every generation is destroyed off it. (The real exit order, after ~QCoreApplication: exitAfterApplication below.)
    void destroyingTheFacadeDoesNotWait()
    {
        TlsHoldServer tls;
        if (!tls.start())
            QSKIP("no TLS backend or no test certificate");
        qint64 plainMs = 0;
        {
            auto *plain = new QNetworkAccessManager;
            tls.requestMidHandshake(plain);
            QElapsedTimer t;
            t.start();
            delete plain; // what upstream's exit does
            plainMs = t.elapsed();
        }
        auto *nam = new TribeNetworkAccessManager;
        QNetworkReply *older = nam->get(QNetworkRequest(QUrl(QString("https://127.0.0.1:%1/v1/a").arg(tls.port.load()))));
        RetireWatch wOld, wCur;
        wOld.watch(older->parent());
        resetApiConnections(nam);           // an older generation still holding its reply at exit
        QNetworkReply *r = tls.requestMidHandshake(nam);
        wCur.watch(r->parent());
        QPointer<QNetworkReply> rp(r), op(older);
        QElapsedTimer t;
        t.start();
        delete nam;
        const qint64 exitMs = t.elapsed();
        qInfo("exit mid-handshake: deleting a plain QNetworkAccessManager %lld ms, the facade %lld ms", plainMs, exitMs);
        QVERIFY2(exitMs < 100, "app exit waited for Qt's HTTP thread");
        QVERIFY(rp.isNull() && op.isNull()); // the replies went first, as with ~QNetworkAccessManager
        QTRY_VERIFY_WITH_TIMEOUT(wCur.destroyed.load() && wOld.destroyed.load(), 7000);
        QVERIFY(!wCur.onGuiThread && !wOld.onGuiThread);
    }
};

// The app's real exit order: the shared manager is a child of the application object, so it is destroyed in ~QObject
// after ~QCoreApplication has run - no thread delivers posted events any more. With a request in flight, destroying the
// application waits for no HTTP thread, nothing is destroyed on the main thread, and the process ends cleanly after.
static int exitAfterApplication(QCoreApplication *app)
{
    QTcpServer silent; // accepts (the kernel backlog) and never answers
    if (!silent.listen(QHostAddress::LocalHost))
        return 1;
    auto *nam = new TribeNetworkAccessManager(app);
    QNetworkReply *r = nam->get(QNetworkRequest(QUrl(QString("http://127.0.0.1:%1/v1/config").arg(silent.serverPort()))));
    RetireWatch w;
    w.watch(r->parent());
    (void)QTest::qWaitFor([&silent]() { return silent.hasPendingConnections(); }, 2000);
    QElapsedTimer t;
    t.start();
    delete app;
    const qint64 ms = t.elapsed();
    QThread::msleep(500);
    const bool ok = ms < 1000 && !(w.destroyed && w.onGuiThread);
    std::printf("%s: exit after the application: delete %lld ms, generation destroyed on the main thread=%d\n",
                ok ? "PASS" : "FAIL", ms, int(w.destroyed && w.onGuiThread));
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    auto *app = new QCoreApplication(argc, argv);
    int rc = 0;
    {
        ApiTransitionTest a;
        ApiTransitionNoWaitTest b;
        rc = QTest::qExec(&a, argc, argv) | QTest::qExec(&b, argc, argv);
    }
    return rc | exitAfterApplication(app);
}

#include "api_transition_check.moc"
