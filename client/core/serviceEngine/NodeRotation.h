// AVPN (live-node picker): чистая логика ротации «Сменить сервер» (nextLiveNodeId) + общие хелперы
// живости/RU-ноды. Вынесено из ServiceEngine.cpp по паттерну NodeRanking.h — тестируется автономно
// (tests/node_rotation_check.cpp, только QtCore), ServiceEngine делегирует сюда.
#pragma once

#include "dto/Subscription.h"

#include <QList>
#include <QString>
#include <QStringList>

#include <algorithm>

namespace avpn {

// Агрегат backend-health узла в [0..1]. Пустой health = 1.0 (живой) — бэкенд провижинит узлы
// /v1/subscription уже живыми, отсутствие телеметрии не значит «мёртв». Среднее по всем target'ам.
inline double healthAggregate(const SubscriptionNode &n)
{
    if (n.health.isEmpty())
        return 1.0;
    double sum = 0.0;
    for (auto it = n.health.constBegin(); it != n.health.constEnd(); ++it)
        sum += it.value();
    return sum / static_cast<double>(n.health.size());
}

// RU-нода (countryCode==RU) обслуживает ТОЛЬКО РФ-сайты (full-tunnel через РФ) — в общем VPN на ней
// не работает ничего. Исключается из ЛЮБОГО авто-выбора (pick*/Selector/ротация); достижима только
// ручным pin из шторки (сценарий «за границей зайти на РФ-сайт»). CONNECT-INVARIANTS §14.3.
inline bool isRuNode(const SubscriptionNode &n)
{
    return n.countryCode.compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0;
}

// Следующая живая нода после текущей — round-robin для кнопки «Сменить сервер» (rotateNext).
// RU-ноды в кольцо НЕ входят (§14.3: только ручной pin); с запиненной RU ротация уводит на лучшую
// не-RU. Сортировка стабильная: weight desc → health desc → nodeId. Пусто = ротировать некуда.
inline QString nextLiveNodeId(const QList<SubscriptionNode> &nodes, const QString &currentNodeId)
{
    QList<SubscriptionNode> live;
    for (const SubscriptionNode &n : nodes)
        if (!isRuNode(n) && healthAggregate(n) > 0.0)
            live.append(n);
    if (live.isEmpty())
        return QString();
    std::sort(live.begin(), live.end(), [](const SubscriptionNode &a, const SubscriptionNode &b) {
        if (a.weight != b.weight)
            return a.weight > b.weight;
        const double ha = healthAggregate(a), hb = healthAggregate(b);
        if (ha != hb)
            return ha > hb;
        return a.nodeId < b.nodeId;
    });
    int cur = -1;
    for (int i = 0; i < live.size(); ++i)
        if (live.at(i).nodeId == currentNodeId) { cur = i; break; }
    // Текущая в кольце (не-RU) и одна → ротировать некуда; текущая ВНЕ кольца (RU-pin/новый коннект) —
    // единственной не-RU достаточно (уходим на неё).
    if (cur >= 0 && live.size() < 2)
        return QString();
    const int next = (cur < 0) ? 0 : (cur + 1) % live.size();
    return live.at(next).nodeId;
}

} // namespace avpn
