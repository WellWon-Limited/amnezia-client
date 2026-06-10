// AVPN serviceEngine — пробер: TCP-connect ping нод (время до SYN-ACK на host:port).
// Дёшево, годится для скрининга всего пула. Параллельно, с общим таймаутом.
// При первом коннекте туннеля ещё нет → обычный connect = «мимо туннеля». Off-tunnel при поднятом
// full-tunnel (для proactive-скоринга в connected) — спайк §9.3, делается позже.
// [IN-FORK / QtNetwork]
#pragma once

#include "dto/Subscription.h"
#include <QList>
#include <QString>

namespace avpn {

struct PingResult {
    QString nodeId;
    int     rttMs = -1;   // -1 = недостижимо/таймаут
    bool    ok = false;
};

class Prober {
public:
    // Параллельный TCP-ping всех нод. Общий таймаут timeoutMs (~3с). Возвращает результат на каждую ноду.
    static QList<PingResult> tcpPingAll(const QList<SubscriptionNode> &nodes, int timeoutMs = 3000);

    // Один TCP-ping host:port → rtt мс или -1.
    static int tcpPing(const QString &host, int port, int timeoutMs = 3000);
};

} // namespace avpn
