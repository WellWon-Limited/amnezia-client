#include "Prober.h"
#include "AwgConfigBuilder.h" // host()/port()

#include <QElapsedTimer>
#include <QEventLoop>
#include <QTcpSocket>
#include <QTimer>
#include <QVector>

namespace avpn {

int Prober::tcpPing(const QString &host, int port, int timeoutMs)
{
    if (host.isEmpty() || port <= 0)
        return -1;
    QTcpSocket sock;
    QElapsedTimer t;
    t.start();
    sock.connectToHost(host, static_cast<quint16>(port));
    if (!sock.waitForConnected(timeoutMs)) {
        sock.abort();
        return -1;
    }
    const int rtt = static_cast<int>(t.elapsed());
    sock.abort();
    return rtt;
}

QList<PingResult> Prober::tcpPingAll(const QList<SubscriptionNode> &nodes, int timeoutMs)
{
    const int n = nodes.size();
    QList<PingResult> res;
    res.reserve(n);
    for (const SubscriptionNode &node : nodes)
        res.append(PingResult{node.nodeId, -1, false});
    if (n == 0)
        return res;

    QList<QTcpSocket *> socks;
    QVector<QElapsedTimer> timers(n);
    QVector<bool> done(n, false);
    QEventLoop loop;
    int remaining = n;

    auto finish = [&](int i, bool ok, int rtt) {
        if (done[i])
            return;
        done[i] = true;
        res[i].ok = ok;
        res[i].rttMs = ok ? rtt : -1;
        if (--remaining == 0)
            loop.quit();
    };

    for (int i = 0; i < n; ++i) {
        auto *s = new QTcpSocket();
        socks.append(s);
        const QString host = AwgConfigBuilder::host(nodes[i].endpoint);
        const int port = AwgConfigBuilder::port(nodes[i].endpoint);
        if (host.isEmpty() || port <= 0) {
            finish(i, false, -1);
            continue;
        }
        timers[i].start();
        QObject::connect(s, &QTcpSocket::connected, &loop, [&, i]() {
            finish(i, true, static_cast<int>(timers[i].elapsed()));
        });
        QObject::connect(s, &QAbstractSocket::errorOccurred, &loop,
                         [&, i](QAbstractSocket::SocketError) { finish(i, false, -1); });
        s->connectToHost(host, static_cast<quint16>(port));
    }

    if (remaining > 0) {
        QTimer::singleShot(timeoutMs, &loop, [&]() { loop.quit(); });
        loop.exec();
    }

    for (QTcpSocket *s : socks) {
        s->abort();
        s->deleteLater();
    }
    return res;
}

} // namespace avpn
