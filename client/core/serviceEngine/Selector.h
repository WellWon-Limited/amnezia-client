// AVPN serviceEngine — выбор лучшей ноды (CLIENT §4): score = rtt/weight + гистерезис + джиттер.
// Чистые score()/choose() — inline, детерминированно тестируемы. pick() — I/O через Prober.
#pragma once

#include "NodePool.h"
#include "Prober.h"

#include <QList>
#include <algorithm>
#include <optional>

namespace avpn {

struct ScoredNodeS {
    SubscriptionNode node;
    int    rttMs = -1;
    double score = 0.0;   // rtt/weight (меньше = лучше)
};

class Selector {
public:
    // score = rtt / weight (вес с бэкенда: ёмкость/нагрузка). weight<=0 → 1.
    static double score(int rttMs, double weight) { return rttMs / (weight > 0.0 ? weight : 1.0); }

    // Выбор из уже измеренных кандидатов. Чистая функция:
    //  - отбрасывает недостижимые (rtt<0);
    //  - сортирует по score;
    //  - ГИСТЕРЕЗИС: если текущая нода достижима и лучшая быстрее неё не более чем на toleranceMs (rtt) —
    //    остаёмся на текущей (анти-дребезг);
    //  - ДЖИТТЕР: среди near-best (rtt в пределах toleranceMs от лучшей) выбираем по jitterSeed
    //    (против thundering herd; seed=0 → детерминированно первый).
    static std::optional<SubscriptionNode> choose(QList<ScoredNodeS> scored, const QString &currentNodeId,
                                                  int toleranceMs, quint32 jitterSeed,
                                                  const QString &excludeNodeId = QString())
    {
        scored.erase(std::remove_if(scored.begin(), scored.end(),
                                    [&](const ScoredNodeS &s) {
                                        return s.rttMs < 0
                                               || (!excludeNodeId.isEmpty() && s.node.nodeId == excludeNodeId);
                                    }),
                     scored.end());
        if (scored.isEmpty())
            return std::nullopt;

        // AVPN (RU-нода): исключить российские ноды (countryCode==RU) из АВТО-выбора — на них работают
        // только РФ-сайты. Fallback: если после исключения не осталось НИ ОДНОЙ — оставляем как есть
        // (не рвём коннект/failover). Ручной форс RU идёт мимо Selector (pin в connect()).
        {
            QList<ScoredNodeS> nonRu;
            for (const ScoredNodeS &s : scored)
                if (s.node.countryCode.compare(QStringLiteral("RU"), Qt::CaseInsensitive) != 0)
                    nonRu.append(s);
            if (!nonRu.isEmpty())
                scored = nonRu;
        }

        std::sort(scored.begin(), scored.end(),
                  [](const ScoredNodeS &a, const ScoredNodeS &b) { return a.score < b.score; });
        const ScoredNodeS best = scored.first();

        // гистерезис vs текущая
        if (!currentNodeId.isEmpty()) {
            for (const ScoredNodeS &s : scored) {
                if (s.node.nodeId == currentNodeId) {
                    if ((s.rttMs - best.rttMs) <= toleranceMs)
                        return s.node; // остаёмся
                    break;
                }
            }
        }

        // near-best группа (rtt в пределах toleranceMs от лучшей) → джиттер
        QList<ScoredNodeS> group;
        for (const ScoredNodeS &s : scored)
            if ((s.rttMs - best.rttMs) <= toleranceMs)
                group.append(s);

        const int idx = (jitterSeed == 0 || group.size() <= 1)
                            ? 0
                            : static_cast<int>(jitterSeed % static_cast<quint32>(group.size()));
        return group.at(idx).node;
    }

    // Полный выбор: TCP-ping пула → score → choose. (I/O)
    std::optional<SubscriptionNode> pick(const NodePool &pool, const QString &currentNodeId,
                                         int toleranceMs = 75, quint32 jitterSeed = 0,
                                         int timeoutMs = 3000, const QString &excludeNodeId = QString()) const
    {
        const QList<SubscriptionNode> &nodes = pool.nodes();
        if (nodes.isEmpty())
            return std::nullopt;
        const QList<PingResult> pings = Prober::tcpPingAll(nodes, timeoutMs);
        QList<ScoredNodeS> scored;
        for (int i = 0; i < nodes.size(); ++i) {
            ScoredNodeS s;
            s.node = nodes[i];
            s.rttMs = pings[i].rttMs;
            s.score = pings[i].ok ? score(pings[i].rttMs, nodes[i].weight) : 0.0;
            scored.append(s);
        }
        return choose(scored, currentNodeId, toleranceMs, jitterSeed, excludeNodeId);
    }
};

} // namespace avpn
