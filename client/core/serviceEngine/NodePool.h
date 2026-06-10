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

    // TODO(C-4): хранить измеренные score, отдавать отсортированный список кандидатов.

private:
    Subscription m_sub;
};

} // namespace avpn
