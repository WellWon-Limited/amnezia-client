// Decision 2026-11-05 (owner test of 5.1.102): an API request in flight when the tunnel comes up
// is aborted (snapshot + deferred abort, NetAwait.h) and re-issued by its owner over the new path,
// instead of hanging for the 15 s timeout; tunnel probes (verification/whoami) are kept; the first
// status a process observes aborts nothing. Real QNetworkAccessManager + loopback HTTP server.
// Build/run: tests/build_api_transition.sh
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
    int subscriptionRequests = 0;
    int probeRequests = 0;
    QString base;

private slots:
    void init()
    {
        subscriptionRequests = probeRequests = 0;
        QVERIFY(server.isListening() || server.listen(QHostAddress::LocalHost));
        base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        disconnect(&server, nullptr, this, nullptr);
        connect(&server, &QTcpServer::newConnection, this, [this]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
                    const QByteArray request = socket->readAll();
                    if (request.startsWith("GET /v1/whoami")) {
                        ++probeRequests;
                        return; // the probe stays in flight (the tunnel answers later)
                    }
                    if (!request.startsWith("GET /v1/subscription"))
                        return;
                    if (++subscriptionRequests == 1)
                        return; // sent over the physical path before the tunnel came up: hangs
                    const QByteArray body = "{}";
                    socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                                  + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
    }

    // A subscription in flight when Connected arrives: aborted, re-issued, done - not left for 15 s.
    void subscriptionInFlightOnConnectedIsAbortedAndReissued()
    {
        QNetworkAccessManager nam;
        int completed = 0, reissued = 0;
        std::function<void()> fetch = [&]() {
            QNetworkReply *r = nam.get(QNetworkRequest(QUrl(base + "/v1/subscription")));
            armTimeout(r); // the 15 s deadline every API call has
            connect(r, &QNetworkReply::finished, this, [&, r]() {
                r->deleteLater();
                if (reissueAfterOwnAbort(r->error() == QNetworkReply::OperationCanceledError,
                                         r->property("avpn_timed_out").toBool())) {
                    ++reissued;
                    QTimer::singleShot(0, this, fetch);
                    return;
                }
                if (r->error() == QNetworkReply::NoError)
                    ++completed;
            });
        };
        QNetworkReply *probe = nam.get(QNetworkRequest(QUrl(base + "/v1/whoami?nonce=x")));
        markTunnelProbe(probe);
        fetch();
        QTRY_COMPARE(subscriptionRequests, 1);
        QTRY_COMPARE(probeRequests, 1);
        QElapsedTimer t;
        t.start();
        // AvpnEngineQml::onConnectionStateChanged(Connected) after Connecting.
        QVERIFY(abortInFlightApiOnTransition(ObservedTunnel::Transitional, ObservedTunnel::Connected));
        abortRunningRepliesDeferred(&nam, /*keepTunnelProbes=*/true);
        QTRY_COMPARE_WITH_TIMEOUT(completed, 1, 3000);
        QCOMPARE(reissued, 1);
        QCOMPARE(subscriptionRequests, 2);
        QVERIFY(t.elapsed() < 3000);  // not the 15 s timeout
        QVERIFY(probe->isRunning());  // the verification probe is kept on Connected
        // On Disconnected the probe goes too (the tunnel it ran over is gone).
        QVERIFY(abortInFlightApiOnTransition(ObservedTunnel::Connected, ObservedTunnel::Disconnected));
        abortRunningRepliesDeferred(&nam, /*keepTunnelProbes=*/false);
        QTRY_VERIFY(probe->isFinished());
        QCOMPARE(probe->error(), QNetworkReply::OperationCanceledError);
        delete probe;
    }

    // The snapshot: a request started after the transition in the same event is not aborted.
    void requestStartedAfterTheTransitionIsKept()
    {
        QNetworkAccessManager nam;
        abortRunningRepliesDeferred(&nam, true); // nothing running yet: no-op
        QNetworkReply *r = nam.get(QNetworkRequest(QUrl(base + "/v1/subscription")));
        QTRY_COMPARE(subscriptionRequests, 1);
        QTest::qWait(50);
        QVERIFY(r->isRunning());
        r->abort();
        delete r;
    }

    // Cold start (Unknown -> Disconnected) and adoption (Unknown -> Connected) abort nothing.
    void firstObservedStatusAbortsNothing()
    {
        QVERIFY(!abortInFlightApiOnTransition(ObservedTunnel::Unknown, ObservedTunnel::Disconnected));
        QVERIFY(!abortInFlightApiOnTransition(ObservedTunnel::Unknown, ObservedTunnel::Connected));
    }
};

QTEST_GUILESS_MAIN(ApiTransitionTest)
#include "api_transition_check.moc"
