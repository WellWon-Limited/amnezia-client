// AVPN: автономная проверка NodeRotation.h — ротация «Сменить сервер» НЕ должна брать RU-ноду
// (CONNECT-INVARIANTS §14.3: RU только через ручной pin). Только QtCore, без сборки форка.
#include "../NodeRotation.h"

#include <QString>
#include <cstdio>

using namespace avpn;

static int g_fail = 0;

static void check(bool ok, const char *what)
{
    std::printf("%s %s\n", ok ? "OK  " : "FAIL", what);
    if (!ok)
        ++g_fail;
}

static SubscriptionNode mk(const char *id, const char *cc, double weight, double health = 1.0)
{
    SubscriptionNode n;
    n.nodeId = QString::fromLatin1(id);
    n.countryCode = QString::fromLatin1(cc);
    n.weight = weight;
    if (health != 1.0)
        n.health.insert(QStringLiteral("telegram"), health); // health<=0 => мёртв
    return n;
}

int main()
{
    // Пул: RU-нода живая и с МАКСИМАЛЬНЫМ weight (worst case — раньше ротация брала её первой).
    const QList<SubscriptionNode> pool = {
        mk("ru-1", "RU", 10.0),
        mk("fi-1", "FI", 5.0),
        mk("pl-1", "PL", 3.0),
    };

    // 1. Ротация с не-RU ноды НИКОГДА не возвращает RU (раньше: после fi-1 шла ru-1? — порядок
    //    сортировки ru-1(10) > fi-1(5) > pl-1(3); current=fi-1 → next=pl-1, current=pl-1 → wrap
    //    должен дать fi-1, НЕ ru-1).
    check(nextLiveNodeId(pool, QStringLiteral("fi-1")) == QLatin1String("pl-1"),
          "rotate fi-1 -> pl-1 (skip nothing, RU not in ring)");
    check(nextLiveNodeId(pool, QStringLiteral("pl-1")) == QLatin1String("fi-1"),
          "rotate pl-1 wraps to fi-1, NOT ru-1");

    // 2. Текущая нода — RU (ручной pin): ротация уводит на ЛУЧШУЮ не-RU ноду.
    check(nextLiveNodeId(pool, QStringLiteral("ru-1")) == QLatin1String("fi-1"),
          "rotate from pinned RU -> best non-RU (fi-1)");

    // 3. Кроме RU жива всего ОДНА не-RU нода, current=RU → ротация на неё разрешена
    //    (старый гард live.size()<2 не должен резать этот случай).
    const QList<SubscriptionNode> ruPlusOne = { mk("ru-1", "RU", 10.0), mk("fi-1", "FI", 5.0) };
    check(nextLiveNodeId(ruPlusOne, QStringLiteral("ru-1")) == QLatin1String("fi-1"),
          "current=RU + single non-RU -> rotate to it");

    // 4. Только RU-ноды живы → ротировать некуда (пусто; UI покажет «недостаточно серверов»).
    const QList<SubscriptionNode> ruOnly = { mk("ru-1", "RU", 10.0), mk("ru-2", "RU", 9.0) };
    check(nextLiveNodeId(ruOnly, QStringLiteral("ru-1")).isEmpty(),
          "RU-only pool -> no rotation target");

    // 5. Одна не-RU нода и она текущая → некуда (не возвращаем её же).
    const QList<SubscriptionNode> single = { mk("fi-1", "FI", 5.0), mk("ru-1", "RU", 10.0) };
    check(nextLiveNodeId(single, QStringLiteral("fi-1")).isEmpty(),
          "current is the only non-RU -> empty");

    // 6. Мёртвая не-RU нода (health 0) выпадает из кольца.
    const QList<SubscriptionNode> withDead = {
        mk("fi-1", "FI", 5.0), mk("pl-1", "PL", 3.0, 0.0), mk("nl-1", "NL", 2.0),
    };
    check(nextLiveNodeId(withDead, QStringLiteral("fi-1")) == QLatin1String("nl-1"),
          "dead pl-1 skipped -> nl-1");

    // 7. currentNodeId не в пуле (свежий коннект) → первая (лучшая) не-RU нода.
    check(nextLiveNodeId(pool, QStringLiteral("gone")) == QLatin1String("fi-1"),
          "unknown current -> best non-RU first");

    std::printf(g_fail ? ">>> node_rotation_check: %d FAILED\n" : ">>> node_rotation_check: all passed\n",
                g_fail);
    return g_fail ? 1 : 0;
}
