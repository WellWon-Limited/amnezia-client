// AVPN serviceEngine — реестр нод текущей подписки + их score/health. [СКАФФОЛД: заглушка]
#pragma once

#include "dto/Subscription.h"
#include <QList>

namespace avpn {

struct ScoredNode {
    SubscriptionNode node;
    double scoreMs = 0.0;     // url_rtt / weight (меньше = лучше); 0 = не измерено
    bool   reachable = true;
};

class NodePool {
public:
    void setSubscription(const Subscription &sub) { m_sub = sub; }
    const Subscription &subscription() const { return m_sub; }
    const QList<SubscriptionNode> &nodes() const { return m_sub.nodes; }

    // AVPN (#35 живой трафик): узкое обновление ТОЛЬКО счётчиков подписки из свежего GET /v1/account —
    // ноды/ключи не трогаем (они из /v1/subscription). Инертно к туннелю (up() читает эти поля лишь
    // для отображения/cap, не реконнектит). expiresAt="" не затираем — бессрочную подписку не портим.
    void updateTraffic(qint64 used, qint64 limit, const QString &expiresAt)
    {
        m_sub.trafficUsed = used;
        m_sub.trafficLimit = limit;
        if (!expiresAt.isEmpty())
            m_sub.expiresAt = expiresAt;
    }

    // TODO(C-4): хранить измеренные score, отдавать отсортированный список кандидатов.

private:
    Subscription m_sub;
};

} // namespace avpn
