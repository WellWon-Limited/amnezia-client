// AVPN serviceEngine — регрессии фикс-волны надёжности 2026-09-22 (зона CL-B, контракт K5):
//  B1 loadSubscription не отвергает по ревизии и не затирает пул пустым телом;
//  B2 reseedPool: меньшая ревизия допустима, Unchanged без записи в switchLog (харнесс switchlog-flood);
//  B3 tick/DEAD без identity адоптированного туннеля, reseed при неизвестной identity + опознание;
//  B4 часы свитча по фазам (бюджет фазы up >= сторожа коннекта), истечение → interruptedSwitch;
//  B5 Error во внутреннем свитче — цель не теряется молча;
//  B6 лестница DEAD: rebind → переподъём той же ноды → другая нода (та же локация раньше);
//  B7 onRebindResult(false) — следующий DEAD сразу на шаг 2/3;
//  B8 noteNetworkChange — окно grace без DEAD-вердикта (роуминг);
//  B9 кэш RTT: «нет ответа» не затирает свежий замер; failover — по последнему известному RTT.
// Раунд ревью CL-B (REV-n): бюджет лечения возвращается после здорового отрезка (REV-1); переподъём,
// прерванный в фазе down, сохраняет цель, повтор ранжирует по последнему известному RTT (REV-2);
// пустое тело ДРУГОГО аккаунта не держит чужой пул (REV-3); ensureSubscription не затирает LKG с
// нодами пустым телом (REV-4); флаппинг сети не глушит DEAD навсегда (REV-5); провал подъёма
// переподъёма в окне grace не записывает ноду в провалы (REV-6).
// Пробелы полноты (GAP-n): отложенный reseed со сменой порта текущей ноды применяется между рантаймами
// свитча — переподъём идёт по НОВОМУ конфигу (GAP-1); отказ NE rebind с reason "offline" не тратит шаг
// лечения (GAP-2); строки switchLog со штампом UTC и дублем в Qt-лог "[avpn switch]" (GAP-3).
// Закрытие пробелов (GAPFIX-n): новый конфиг текущей ноды (reseed сменил порт после потраченного шага 2)
// получает свой переподъём, а не провал ноды и уход EE→US (GAPFIX-1); отсрочки rebind "offline"
// возвращаются вместе с бюджетом лечения после здорового отрезка (GAPFIX-2).
// Секции, помеченные OLD-API, собираются и против базы (без новых методов) — на базе они ПАДАЮТ
// (доказательство регрессии): tests/build_engine_reliability.sh --base. Флот как в проде: EE + US.
#include "../HealthLoop.h"
#include "../ServiceEngine.h"
#include "../SubscriptionParser.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QTimeZone>
#include <QThread>
#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

// Настраиваемые линк-стабы Enrollment (REV-4: ensureSubscription/bootstrap без сети).
static bool g_enrollOk = false;
static bool g_fetchOk = false;
static QByteArray g_fetchBody;
static QByteArray g_diskLkg;
static int g_lkgSaves = 0;

// GAP-3: перехват Qt-лога (строки "[avpn switch] …" из appendSwitchLog).
static QStringList g_qtLog;
[[maybe_unused]] static void captureQtLog(QtMsgType, const QMessageLogContext &, const QString &msg)
{
    g_qtLog << msg;
}

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                       \
        }                                                                                           \
    } while (0)

struct FakeTunnel : ITunnelControl {
    QString lastUpNodeId;
    QString lastUpEndpoint; // GAP-1: по какому конфигу реально поднят рантайм
    QStringList ups;
    int upCalls = 0;
    int downCalls = 0;
    bool rebindCapable = false;
    int rebindCalls = 0;
    TunnelStats st;
    TunnelResult up(const Subscription &, const SubscriptionNode &node) override
    {
        ++upCalls;
        lastUpNodeId = node.nodeId;
        lastUpEndpoint = node.endpoint;
        ups << node.nodeId;
        return TunnelResult::success();
    }
    TunnelResult applyPeer(const Subscription &, const SubscriptionNode &node) override
    {
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelStats readStats() override { return st; }
    bool rebindSocket() override { ++rebindCalls; return rebindCapable; }
    void down() override { ++downCalls; }
};

static TunnelStats mkStats(qint64 hs, qint64 rx, qint64 tx)
{
    TunnelStats s; s.latestHandshakeEpoch = hs; s.rxBytes = rx; s.txBytes = tx; s.valid = true; return s;
}

static QByteArray awgNodeJson(const char *id, int hostId, const char *cc, const char *endpoint,
                              const char *extra = "")
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "endpoint": ")" + endpoint + R"(", "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": 1.0, "country_code": ")" + cc + R"(", )" + extra + R"(
        "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57,
                        "H1": 1, "H2": 2, "H3": 3, "H4": 4 } })";
}

static QByteArray subJson(const QList<QByteArray> &nodes, int rev, const char *status = "active",
                          int used = 5)
{
    QByteArray joined;
    for (int i = 0; i < nodes.size(); ++i) {
        if (i) joined += ",";
        joined += nodes[i];
    }
    QByteArray revPart = rev >= 0 ? (QByteArray(R"("pool_revision": )") + QByteArray::number(rev) + ",") : QByteArray();
    return QByteArray(R"({ "version": 1, "address": ["10.7.0.5/32"], "status": ")") + status + R"(",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": )" + QByteArray::number(used) + R"(, "limit": 0 },
        )" + revPart + R"(
        "nodes": [)" + joined + "] }";
}

static Subscription parse(const QByteArray &json)
{
    Subscription sub;
    QString err;
    if (!SubscriptionParser::parse(json, sub, err))
        fprintf(stderr, "parse error: %s\n", err.toUtf8().constData());
    return sub;
}

static int countContaining(const QStringList &log, const char *needle)
{
    int n = 0;
    for (const QString &l : log)
        if (l.contains(QLatin1String(needle)))
            ++n;
    return n;
}

// Три тика: посев prev + 2 плохих цикла (tx растёт, rx стоит, handshake неизвестен) → DEAD.
static bool feedDead(ServiceEngine &eng, FakeTunnel &tun, qint64 now, qint64 txBase)
{
    tun.st = mkStats(0, 100, txBase + 100);
    eng.tick(now);
    tun.st = mkStats(0, 100, txBase + 200);
    eng.tick(now + 4);
    tun.st = mkStats(0, 100, txBase + 300);
    return eng.tick(now + 8);
}

static const QByteArray EE = awgNodeJson("9", 9, "EE", "38.180.164.134:585");
static const QByteArray US = awgNodeJson("10", 10, "US", "149.33.7.203:585");

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});

    // --- B1 [OLD-API]: пустая выдача при рабочем пуле — пул цел, аккаунтные поля свежие ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 5), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        CHECK(eng.loadSubscription(subJson({}, 6, "degraded", 77), err));
        CHECK(eng.hasSubscription());                              // пул НЕ затёрт
        CHECK(eng.debugSnapshot().pool.size() == 2);
        CHECK(eng.pinnedNodeId() == QLatin1String("9"));           // pin цел
        CHECK(eng.measuredRtt().value(QStringLiteral("9"), -1) == 40);
        CHECK(eng.debugSnapshot().trafficUsed == 77);              // traffic из свежего тела
        CHECK(eng.debugSnapshot().subStatus == QLatin1String("degraded")); // статус из свежего тела
        CHECK(eng.connect(err));                                   // можно подключиться по сохранённому пулу
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
    }
    // --- B1 [OLD-API]: пустое тело без пула — как раньше (degraded применяется) ---
    {
        ServiceEngine eng;
        QString err;
        CHECK(eng.loadSubscription(subJson({}, 3, "degraded"), err));
        CHECK(!eng.hasSubscription());
        CHECK(eng.debugSnapshot().subStatus == QLatin1String("degraded"));
    }
    // --- B1 [OLD-API]: меньшая ревизия НЕ отвергается (delete_node опускает max) ---
    {
        ServiceEngine eng;
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 20), err));
        CHECK(eng.loadSubscription(subJson({ EE }, 12), err));    // нода US удалена, ревизия упала
        CHECK(eng.debugSnapshot().pool.size() == 1);
        CHECK(eng.poolRevision() == 12);
        CHECK(eng.loadSubscription(subJson({ EE, US }, 13), err)); // следующая выдача тоже принята
        CHECK(eng.debugSnapshot().pool.size() == 2);
    }

    // --- B2 [OLD-API]: switchlog-flood (scratchpad/hunt-ios-engine/switchlog_flood.cpp) ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(eng.notifyConnectionLost());                         // реальный failover → запись «switch …»
        CHECK(eng.onTunnelConnected());
        const int reseedLinesBefore = countContaining(eng.switchLog(), "reseed");
        int applied = 0;
        for (int i = 0; i < 25; ++i)                               // ~8 мин traffic-sync по 20 с
            if (eng.reseedPool(parse(subJson({ EE, US }, 7, "active", 5 + i))) == ReseedResult::Applied)
                ++applied;
        const QStringList log = eng.switchLog();
        CHECK(applied == 0);
        CHECK(countContaining(log, "reseed") == reseedLinesBefore); // равная выдача не пишет в switchLog
        CHECK(countContaining(log, "switch ") >= 1);               // запись о failover пережила 25 рефрешей
        CHECK(eng.debugSnapshot().trafficUsed == 29);              // traffic при этом свежий
        // меньшая ревизия с другим составом применяется (живая нода не изменилась)
        CHECK(eng.reseedPool(parse(subJson({ EE, US, awgNodeJson("11", 11, "FI", "10.0.0.11:585") }, 3)))
              == ReseedResult::Applied);
        CHECK(eng.poolRevision() == 3);
    }
#ifndef AVPN_ENGINE_OLD_API
    // --- B2: Unchanged и снятие устаревшего pending; health-изменение применяется тихо ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.reseedPool(parse(subJson({ EE, US }, 7))) == ReseedResult::Unchanged);
        CHECK(eng.reseedPool(parse(subJson({ EE, US }, 9))) == ReseedResult::Unchanged); // то же содержимое
        CHECK(eng.poolRevision() == 9);
        const int logBefore = eng.switchLog().size();
        const QByteArray usSick = awgNodeJson("10", 10, "US", "149.33.7.203:585", R"("health": {"t": 0.5},)");
        CHECK(eng.reseedPool(parse(subJson({ EE, usSick }, 9))) == ReseedResult::Applied); // метаданные
        CHECK(eng.switchLog().size() == logBefore);                // без смены состава/ревизии — без лога
        CHECK(eng.reseedPool(parse(subJson({ EE }, 10))) == ReseedResult::Applied);
        CHECK(eng.switchLog().size() == logBefore + 1);            // смена состава — одна запись
    }
#endif

    // --- B3 [OLD-API]: DEAD-детект работает для адоптированного туннеля без identity ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.adoptTunnelConnected());                         // identity неизвестна
        CHECK(eng.state() == EngineState::Connected);
        CHECK(eng.currentNodeId().isEmpty());
        CHECK(feedDead(eng, tun, 1000, 0));                        // DEAD → failover на авто-выбор
        CHECK(eng.state() == EngineState::Switching);
        CHECK(tun.downCalls == 1);
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9") || tun.lastUpNodeId == QLatin1String("10"));
    }
    // --- B3 [OLD-API]: reseed применим при Connected с неизвестной identity ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.adoptTunnelConnected());
        CHECK(eng.reseedPool(parse(subJson({ EE }, 8))) == ReseedResult::Applied);
        CHECK(eng.state() == EngineState::Connected);              // живой туннель не тронут
        CHECK(tun.downCalls == 0);
    }
#ifndef AVPN_ENGINE_OLD_API
    // --- A5/B3: нода сессии не в пуле → адопт с неизвестной identity; опознание после reseed ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ US }, 7), err));      // LKG без EE
        CHECK(eng.adoptTunnelConnected(QStringLiteral("9"), QStringLiteral("awg"),
                                       QStringLiteral("38.180.164.134:585")));
        CHECK(eng.state() == EngineState::Connected);
        CHECK(!eng.currentIdentityKnown());
        CHECK(eng.reseedPool(parse(subJson({ EE, US }, 8))) == ReseedResult::Applied);
        CHECK(eng.currentNodeId() == QLatin1String("9"));          // опознана по endpoint
        CHECK(countContaining(eng.switchLog(), "identity resolved") == 1);
        // та же нода, но id сменился (перевыпуск) — опознание по уникальному endpoint
        ServiceEngine eng2;
        eng2.setTunnel(&tun);
        CHECK(eng2.loadSubscription(subJson({ US }, 7), err));
        CHECK(eng2.adoptTunnelConnected(QStringLiteral("old9"), QStringLiteral("awg"),
                                        QStringLiteral("38.180.164.134:585")));
        CHECK(eng2.reseedPool(parse(subJson({ EE, US }, 8))) == ReseedResult::Applied);
        CHECK(eng2.currentNodeId() == QLatin1String("9"));
    }
#endif

    // --- B4 [OLD-API]: часы свитча по фазам — фаза up получает свой бюджет ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false},
                              {QStringLiteral("dead_reup_same_node"), false}}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 1000, 0));                        // DEAD → свитч, фаза down
        CHECK(eng.state() == EngineState::Switching);
        QThread::msleep(150);                                      // медленный Disconnected
        CHECK(eng.onTunnelDisconnected());                         // фаза up: up(US)
        QThread::msleep(100);
        // 250 мс от начала свитча > 200 мс, но фаза up только началась (и её бюджет >= сторожа)
        CHECK(!eng.expireSwitch(200));
        CHECK(eng.state() == EngineState::Switching);
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
#ifndef AVPN_ENGINE_OLD_API
    // --- B4/B5: истечение фазы down/up и Error во внутреннем свитче → interruptedSwitch ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false},
                              {QStringLiteral("dead_reup_same_node"), false}}, {}, {});
        qint64 now = 1'000'000;
        const auto bringUp = [&](ServiceEngine &eng, FakeTunnel &tun) {
            QString err;
            eng.setNowMsForTest([&now]() { return now; });
            eng.setTunnel(&tun);
            eng.loadSubscription(subJson({ EE, US }, 7), err);
            eng.setPinnedNode(QStringLiteral("9"), err);
            eng.connect(err);
            eng.onTunnelConnected();
        };
        {   // дедлайн фазы down: цель сохраняется, повтор connect() идёт на неё (не на мёртвый pin)
            ServiceEngine eng;
            FakeTunnel tun;
            bringUp(eng, tun);
            CHECK(feedDead(eng, tun, 1000, 0));
            CHECK(!eng.switchInUpPhase());
            now += 14'000;
            CHECK(!eng.expireSwitch(15000));
            now += 2'000;
            CHECK(eng.expireSwitch(15000));
            CHECK(eng.state() == EngineState::Error);
            CHECK(eng.hasInterruptedSwitch());
            CHECK(eng.interruptedSwitchCause() == QLatin1String("deadline_down"));
            CHECK(eng.interruptedSwitchTarget() == QLatin1String("10"));
            QString err;
            CHECK(eng.connect(err));                               // фасад A8: повтор старта
            CHECK(tun.lastUpNodeId == QLatin1String("10"));        // цель failover, не мёртвый pin EE
            CHECK(!eng.hasInterruptedSwitch());                    // одноразово
        }
        {   // фаза up: часы перезапущены, бюджет >= reconcileWatchdogMsTuned
            ServiceEngine eng;
            FakeTunnel tun;
            bringUp(eng, tun);
            CHECK(feedDead(eng, tun, 1000, 0));
            now += 10'000;
            CHECK(eng.onTunnelDisconnected());
            CHECK(eng.switchInUpPhase());
            now += 10'000;                                         // 20 с от начала свитча
            CHECK(!eng.expireSwitch(15000));                       // раньше: истекало (часы на обе фазы)
            now += 6'000;
            CHECK(eng.expireSwitch(15000));
            CHECK(eng.interruptedSwitchCause() == QLatin1String("deadline_up"));
            CHECK(eng.interruptedSwitchTarget().isEmpty());        // цель провалила подъём
            CHECK(eng.currentNodeId() == QLatin1String("10"));
            QString err;
            CHECK(eng.connect(err));
            CHECK(tun.lastUpNodeId == QLatin1String("9"));         // повтор мимо провалившейся цели
        }
        {   // Error в фазе down внутреннего failover: цель не потеряна (B5)
            ServiceEngine eng;
            FakeTunnel tun;
            bringUp(eng, tun);
            CHECK(feedDead(eng, tun, 1000, 0));
            CHECK(eng.onTunnelError());
            CHECK(eng.state() == EngineState::Error);
            CHECK(eng.hasInterruptedSwitch());
            CHECK(eng.interruptedSwitchCause() == QLatin1String("error_down"));
            CHECK(eng.interruptedSwitchTarget() == QLatin1String("10"));
            // явный стоп пользователя снимает запись
            eng.requestStop();
            CHECK(!eng.hasInterruptedSwitch());
        }
        {   // Error вне свитча — не внутренний свитч
            ServiceEngine eng;
            FakeTunnel tun;
            bringUp(eng, tun);
            CHECK(eng.onTunnelError());
            CHECK(!eng.hasInterruptedSwitch());
        }
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
#endif

    // --- B6 [OLD-API]: DEAD без rebind → переподъём ТОЙ ЖЕ ноды, не уход EE→US ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 1000, 0));
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));             // шаг 2: та же нода
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 2000, 1000));                     // умерла и после переподъёма
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("10"));            // шаг 3: другая нода
    }
    // --- B6 [OLD-API]: шаг 3 предпочитает ту же локацию (другой листенер того же хоста) ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        const QByteArray EE2 = awgNodeJson("9b", 9, "EE", "38.180.164.134:586");
        CHECK(eng.loadSubscription(subJson({ EE, EE2, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 30}});
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 1000, 0));
        CHECK(eng.onTunnelDisconnected());                         // переподъём 9
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 2000, 1000));
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9b"));            // та же локация раньше соседней US
    }
    // --- GAP-1 [OLD-API]: отложенный reseed сменил порт текущей ноды (EE:585 → EE:586) — переподъём
    // «той же ноды» идёт по НОВОМУ конфигу (раньше up() получал старый :585, поднимался мёртвым → US) ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(tun.lastUpEndpoint == QLatin1String("38.180.164.134:585"));
        CHECK(eng.onTunnelConnected());
        const QByteArray EE586 = awgNodeJson("9", 9, "EE", "38.180.164.134:586");
        CHECK(eng.reseedPool(parse(subJson({ EE586, US }, 8))) == ReseedResult::Deferred);
        CHECK(eng.hasPendingReseed());
        CHECK(feedDead(eng, tun, 1000, 0));                        // rebind выкл → шаг 2 (переподъём)
        CHECK(tun.downCalls == 1);
        CHECK(eng.onTunnelDisconnected());                         // старый рантайм опущен → up()
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(tun.lastUpEndpoint == QLatin1String("38.180.164.134:586")); // на HEAD — :585
        CHECK(!eng.hasPendingReseed());
        CHECK(eng.poolRevision() == 8);
        CHECK(eng.onTunnelConnected());
        CHECK(eng.debugSnapshot().state == QLatin1String("connected"));
    }
    // --- GAP-1 [OLD-API]: новый пул убрал текущую ноду (листенер 9 → 9b того же хоста) — цель
    // переподъёма исчезла → шаг 3 с той же локацией (9b), а не соседняя US с меньшим RTT ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 30}});
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        const QByteArray EE2 = awgNodeJson("9b", 9, "EE", "38.180.164.134:586");
        CHECK(eng.reseedPool(parse(subJson({ EE2, US }, 8))) == ReseedResult::Deferred);
        CHECK(feedDead(eng, tun, 1000, 0));
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9b"));
        CHECK(tun.lastUpEndpoint == QLatin1String("38.180.164.134:586"));
        CHECK(!eng.hasPendingReseed());
    }
    // --- GAP-1 [OLD-API]: reseed пришёл уже в фазе down свитча (Switching, цель сменила порт) —
    // применяется в continuePendingSwitch до up() ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 1000, 0));                        // переподъём 9: Switching, ждём down
        const QByteArray EE586 = awgNodeJson("9", 9, "EE", "38.180.164.134:586");
        CHECK(eng.reseedPool(parse(subJson({ EE586, US }, 8))) == ReseedResult::Deferred);
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(tun.lastUpEndpoint == QLatin1String("38.180.164.134:586"));
        CHECK(!eng.hasPendingReseed());
    }
    // --- GAPFIX-1 [OLD-API]: шаг 2 уже потрачен на СТАРОМ конфиге (:585), затем reseed сменил порт
    // текущей ноды (:586, Deferred) и пришёл следующий DEAD — новый конфиг той же ноды ещё не пробовали:
    // переподъём EE по :586, а не провал ноды 9 и уход на US (жалоба 1; ревью probe2). Только после
    // провала и НОВОГО конфига — честный шаг 3 ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 1000, 0));                        // rebind выкл → шаг 2 на :585
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(tun.lastUpEndpoint == QLatin1String("38.180.164.134:585"));
        CHECK(eng.onTunnelConnected());
        const QByteArray EE586 = awgNodeJson("9", 9, "EE", "38.180.164.134:586");
        CHECK(eng.reseedPool(parse(subJson({ EE586, US }, 8))) == ReseedResult::Deferred);
        CHECK(feedDead(eng, tun, 2000, 10000));                    // DEAD старого конфига
        CHECK(tun.downCalls == 2);
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));             // на HEAD — 10 (US)
        CHECK(tun.lastUpEndpoint == QLatin1String("38.180.164.134:586"));
        const auto toUs = [&eng] {
            int n = 0;
            for (const QString &l : eng.switchLog())
                if (l.contains(QString::fromUtf8("switch 9→10: dead (failover)")))
                    ++n;
            return n;
        };
        CHECK(toUs() == 0);
        CHECK(countContaining(eng.switchLog(), "re-up same node 9") == 2);
        CHECK(eng.poolRevision() == 8);
        CHECK(eng.onTunnelConnected());
        CHECK(eng.debugSnapshot().state == QLatin1String("connected"));
        CHECK(feedDead(eng, tun, 3000, 20000));                    // и новый конфиг мёртв → шаг 3
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("10"));
        CHECK(toUs() == 1);
        CHECK(tun.upCalls == 4);
    }
#ifndef AVPN_ENGINE_OLD_API
    // --- GAP-1: с rebind — rebind×N (NE: performed) по-прежнему на живом рантайме, затем переподъём
    // по новому конфигу; фасад узнаёт о применении через takeReseedAppliedInSwitch() ---
    {
        TuningStore::set({}, {}, {}, {});                          // rebind_heal по умолчанию ВКЛ
        ServiceEngine eng;
        FakeTunnel tun;
        tun.rebindCapable = true;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        const QByteArray EE586 = awgNodeJson("9", 9, "EE", "38.180.164.134:586");
        CHECK(eng.reseedPool(parse(subJson({ EE586, US }, 8))) == ReseedResult::Deferred);
        int cycles = 0;
        for (qint64 t = 1000; tun.downCalls == 0 && cycles < 6; t += 100, ++cycles) {
            feedDead(eng, tun, t, t);
            if (eng.rebindAwaitingResult()) {
                CHECK(eng.hasPendingReseed());                     // rebind живого рантайма пул не трогает
                CHECK(eng.onRebindResult(true));
            }
        }
        CHECK(tun.rebindCalls == 2);                               // кап rebind_heal_max_tries (деф. 2)
        CHECK(tun.downCalls == 1);                                 // затем переподъём
        CHECK(eng.takeReseedAppliedInSwitch());
        CHECK(!eng.takeReseedAppliedInSwitch());                   // флаг одноразовый
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpEndpoint == QLatin1String("38.180.164.134:586"));
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
#endif
#ifndef AVPN_ENGINE_OLD_API
    // --- B6/B7: rebind → отказ NE → следующий DEAD сразу переподъём; поздний ответ игнорируется ---
    {
        TuningStore::set({}, {}, {}, {});                          // rebind_heal по умолчанию ВКЛ
        ServiceEngine eng;
        FakeTunnel tun;
        tun.rebindCapable = true;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(!feedDead(eng, tun, 1000, 0));                       // шаг 1: rebind
        CHECK(tun.rebindCalls == 1);
        CHECK(eng.rebindAwaitingResult());
        CHECK(eng.onRebindResult(false));                          // NE: denied (budget)
        CHECK(!eng.onRebindResult(false));                         // повтор/поздний — не наш
        const int downs = tun.downCalls;
        CHECK(feedDead(eng, tun, 2000, 1000));                     // сразу шаг 2 (без 2-го rebind)
        CHECK(tun.rebindCalls == 1);
        CHECK(tun.downCalls == downs + 1);
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(countContaining(eng.switchLog(), "denied") == 1);
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
    // --- B8: смена сети — окно grace без DEAD, после окна детект снова работает ---
    {
        HealthLoop h;
        h.noteNetworkChange(1000, 20);
        CHECK(h.inNetworkGrace(1019));
        CHECK(!h.feed(mkStats(0, 100, 100), 1001));
        CHECK(!h.feed(mkStats(0, 100, 200), 1005));
        CHECK(!h.feed(mkStats(0, 100, 300), 1009));
        CHECK(!h.feed(mkStats(0, 100, 400), 1013));                // 4 «плохих» цикла в окне — не DEAD
        CHECK(h.badCycles() == 0);
        CHECK(!h.feed(mkStats(0, 100, 500), 1021));                // первый плохой после окна
        CHECK(h.feed(mkStats(0, 100, 600), 1025));                 // второй → DEAD
        h.reset();
        CHECK(h.networkGraceUntil() == 1020);                      // reset окно не снимает
        // серверный тюнинг health_network_grace_s (клампован 0..120)
        TuningStore::set({{QStringLiteral("health_network_grace_s"), 5000}}, {}, {}, {});
        HealthLoop h2;
        h2.noteNetworkChange(0);
        CHECK(h2.networkGraceUntil() == 120);
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        // движок: noteNetworkChange глушит ложный DEAD при роуминге (EE не меняется на US)
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        eng.noteNetworkChange(1000);
        CHECK(!feedDead(eng, tun, 1001, 0));
        CHECK(eng.state() == EngineState::Connected);
        CHECK(tun.downCalls == 0);
    }
#endif

    // --- B9 [OLD-API]: «нет ответа в этом раунде» не выкидывает ноду с прошлым замером ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        eng.setMeasuredRtt({{QStringLiteral("9"), -1}, {QStringLiteral("10"), 150}}); // потерян пакет EE
        CHECK(eng.measuredRtt().value(QStringLiteral("9"), -1) == 40);
        for (int i = 0; i < 20; ++i) {                             // без замера EE был бы US всегда
            CHECK(eng.connect(err));
            CHECK(tun.lastUpNodeId == QLatin1String("9"));
            eng.requestStop();
        }
    }
#ifndef AVPN_ENGINE_OLD_API
    // --- B9: merge дополняет кэш; failover после TTL — по последнему известному RTT (с возрастом) ---
    {
        qint64 now = 5'000'000;
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setNowMsForTest([&now]() { return now; });
        eng.setTunnel(&tun);
        QString err;
        const QByteArray FI = awgNodeJson("11", 11, "FI", "10.0.0.11:585");
        CHECK(eng.loadSubscription(subJson({ FI, EE, US }, 7), err));
        eng.mergeMeasuredRtt({{QStringLiteral("9"), 40}});
        eng.mergeMeasuredRtt({{QStringLiteral("10"), 150}, {QStringLiteral("9"), -1}});
        CHECK(eng.measuredRtt().size() == 2);
        CHECK(eng.measuredRtt().value(QStringLiteral("9")) == 40);
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false},
                              {QStringLiteral("dead_reup_same_node"), false}}, {}, {});
        CHECK(eng.setPinnedNode(QStringLiteral("11"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        now += 200'000;                                            // 200 с в connected: замеров нет
        CHECK(eng.measuredRtt().isEmpty());                        // TTL свежего кэша истёк
        CHECK(eng.lastKnownRtt().value(QStringLiteral("9")) == 40);
        CHECK(eng.lastKnownRttAgeMs(QStringLiteral("9")) == 200'000);
        CHECK(feedDead(eng, tun, 1000, 0));
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));             // EE по последнему RTT, не монета
        CHECK(countContaining(eng.switchLog(), "rtt_age=200s") == 1);
        // исчезнувшая нода теряет и последний известный RTT
        eng.requestStop();
        CHECK(eng.reseedPool(parse(subJson({ FI, US }, 8))) == ReseedResult::Applied);
        CHECK(!eng.lastKnownRtt().contains(QStringLiteral("9")));
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
#endif

    // --- REV-3 [OLD-API]: пустое тело ДРУГОГО аккаунта (redeem/transfer, окно readiness) — чужой
    // пул и /32 не сохраняются (connect не поднимает туннель на ключах прошлого аккаунта) ---
    {
        struct AddrTunnel : FakeTunnel {
            QString addr;
            TunnelResult up(const Subscription &s, const SubscriptionNode &n) override
            {
                addr = s.address.join(QStringLiteral(","));
                return FakeTunnel::up(s, n);
            }
        };
        ServiceEngine eng;
        AddrTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        QByteArray other = subJson({}, 8, "active");
        other.replace("10.7.0.5/32", "10.7.9.9/32");
        CHECK(eng.loadSubscription(other, err));
        CHECK(!eng.hasSubscription());
        CHECK(!eng.connect(err));
        CHECK(tun.upCalls == 0);
        // тот же аккаунт (тот же address) — пул по-прежнему цел (B1 не сломан)
        ServiceEngine eng2;
        FakeTunnel tun2;
        eng2.setTunnel(&tun2);
        CHECK(eng2.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng2.loadSubscription(subJson({}, 8, "degraded"), err));
        CHECK(eng2.hasSubscription());
        CHECK(eng2.debugSnapshot().subStatus == QLatin1String("degraded"));
    }
    // --- REV-4 [OLD-API]: ensureSubscription (bootstrap после redeem/transfer, startFlow) не
    // затирает дисковый LKG с нодами пустым телом того же аккаунта (жалоба 4 после перезапуска) ---
    {
        g_enrollOk = true;
        g_fetchOk = true;
        g_diskLkg = subJson({ EE, US }, 7);
        g_lkgSaves = 0;
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscriptionFromLkg(g_diskLkg, err));
        g_fetchBody = subJson({}, 8, "degraded");
        CHECK(eng.bootstrap(nullptr, QStringLiteral("http://stub"), nullptr, err));
        CHECK(eng.hasSubscription());                              // пул цел
        CHECK(g_lkgSaves == 0);                                    // LKG с нодами не перезаписан
        Subscription disk = parse(g_diskLkg);
        CHECK(disk.nodes.size() == 2);
        // тело с нодами — пишется как раньше
        g_fetchBody = subJson({ EE }, 9);
        CHECK(eng.bootstrap(nullptr, QStringLiteral("http://stub"), nullptr, err));
        CHECK(g_lkgSaves == 1);
        g_enrollOk = false;
        g_fetchOk = false;
        g_diskLkg.clear();
        g_fetchBody.clear();
    }
    // --- REV-1 [OLD-API]: бюджет лечения возвращается после долгого здорового отрезка — второй DEAD
    // через 3 ч на EE снова переподъём EE, а не EE→US (жалобы 1 и 3) ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 1000, 0));                        // шаг 2: переподъём EE
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(eng.onTunnelConnected());
        qint64 rx = 10000, tx = 10000;
        for (qint64 t = 1100; t < 1100 + 3 * 3600; t += 4) {       // 3 ч здорового трафика на EE
            rx += 100; tx += 100;
            tun.st = mkStats(t, rx, tx);
            eng.tick(t);
        }
        CHECK(feedDead(eng, tun, 20000, tx));
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));             // снова переподъём EE, не US
        CHECK(eng.currentNodeId() == QLatin1String("9"));
    }
#ifndef AVPN_ENGINE_OLD_API
    // --- REV-1: бюджет возвращается только после heal_budget_restore_s ЗДОРОВЬЯ; раньше — кап эпизода
    // держится (без тесной петли); rebind тоже возвращается; журнал фиксирует восстановление ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 1000, 0));                        // переподъём EE
        CHECK(eng.onTunnelDisconnected());
        CHECK(eng.onTunnelConnected());
        qint64 rx = 10000, tx = 10000;
        for (qint64 t = 1100; t < 1130; t += 4) {                  // всего 30 с здоровья
            rx += 100; tx += 100;
            tun.st = mkStats(t, rx, tx);
            eng.tick(t);
        }
        CHECK(countContaining(eng.switchLog(), "heal budget restored") == 0);
        CHECK(feedDead(eng, tun, 1200, tx));                       // кап эпизода исчерпан → другая нода
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("10"));
        // простой (ни rx, ни handshake) бюджет не возвращает
        ServiceEngine idle;
        FakeTunnel itun;
        idle.setTunnel(&itun);
        CHECK(idle.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(idle.setPinnedNode(QStringLiteral("9"), err));
        CHECK(idle.connect(err));
        CHECK(idle.onTunnelConnected());
        CHECK(feedDead(idle, itun, 1000, 0));
        CHECK(idle.onTunnelDisconnected());
        CHECK(idle.onTunnelConnected());
        for (qint64 t = 1100; t < 1100 + 1800; t += 4) {
            itun.st = mkStats(0, 5, 5);
            idle.tick(t);
        }
        CHECK(countContaining(idle.switchLog(), "heal budget restored") == 0);
        // серверный кламп heal_budget_restore_s: 10 → 60, 99999 → 3600
        TuningStore::set({{QStringLiteral("heal_budget_restore_s"), 10}}, {}, {}, {});
        CHECK(healBudgetRestoreSTuned() == 60);
        TuningStore::set({{QStringLiteral("heal_budget_restore_s"), 99999}}, {}, {}, {});
        CHECK(healBudgetRestoreSTuned() == 3600);
        // rebind_heal ВКЛ: лестница rebind×2 → переподъём; после 3 ч здоровья — снова rebind
        TuningStore::set({}, {}, {}, {});
        ServiceEngine rb;
        FakeTunnel rtun;
        rtun.rebindCapable = true;
        rb.setTunnel(&rtun);
        CHECK(rb.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(rb.setPinnedNode(QStringLiteral("9"), err));
        CHECK(rb.connect(err));
        CHECK(rb.onTunnelConnected());
        CHECK(!feedDead(rb, rtun, 1000, 0));                       // rebind 1
        CHECK(!feedDead(rb, rtun, 1100, 1000));                    // rebind 2
        CHECK(feedDead(rb, rtun, 1200, 2000));                     // переподъём EE
        CHECK(rtun.rebindCalls == 2);
        CHECK(rb.onTunnelDisconnected());
        CHECK(rtun.lastUpNodeId == QLatin1String("9"));
        CHECK(rb.onTunnelConnected());
        rx = 10000; tx = 10000;
        for (qint64 t = 1300; t < 1300 + 3 * 3600; t += 4) {
            rx += 100; tx += 100;
            rtun.st = mkStats(t, rx, tx);
            rb.tick(t);
        }
        CHECK(countContaining(rb.switchLog(), "heal budget restored on 9") == 1);
        CHECK(rb.rebindHealTries() == 0);
        const int downs = rtun.downCalls;
        CHECK(!feedDead(rb, rtun, 20000, tx));                     // снова шаг 1 (rebind), без свитча
        CHECK(rtun.rebindCalls == 3);
        CHECK(rtun.downCalls == downs);
        CHECK(rb.state() == EngineState::Connected);
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
    // --- REV-2: переподъём EE прерван Error/дедлайном в фазе DOWN → цель EE сохраняется; повтор
    // после 5 мин connected (свежий RTT-кэш пуст) идёт на EE, а не монетой на US ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        int us = 0, targetKept = 0;
        for (int i = 0; i < 20; ++i) {
            qint64 clk = 1'000'000;
            ServiceEngine eng;
            FakeTunnel tun;
            eng.setTunnel(&tun);
            eng.setNowMsForTest([&clk]() { return clk; });
            QString err;
            eng.loadSubscription(subJson({ EE, US }, 7), err);
            eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
            eng.connect(err);
            eng.onTunnelConnected();
            clk += 300'000;                                        // 5 мин connected: TTL свежего кэша истёк
            feedDead(eng, tun, 1000, 0);                           // шаг 2: переподъём EE, down() отправлен
            if (i % 2 == 0) {
                eng.onTunnelError();                               // транзиентный Error в фазе down
            } else {
                clk += 16'000;
                eng.expireSwitch(15000);                           // дедлайн фазы down
            }
            if (eng.hasInterruptedSwitch() && eng.interruptedSwitchTarget() == QLatin1String("9"))
                ++targetKept;
            eng.connect(err);                                      // повтор фасада (A8/A9)
            if (tun.lastUpNodeId == QLatin1String("10"))
                ++us;
        }
        CHECK(targetKept == 20);
        CHECK(us == 0);
        // повтор с пустой целью (провал фазы up у failover-цели) ранжирует по последнему известному RTT
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false},
                              {QStringLiteral("dead_reup_same_node"), false}}, {}, {});
        int ee = 0;
        for (int i = 0; i < 20; ++i) {
            qint64 clk = 1'000'000;
            ServiceEngine eng;
            FakeTunnel tun;
            eng.setTunnel(&tun);
            eng.setNowMsForTest([&clk]() { return clk; });
            QString err;
            eng.loadSubscription(subJson({ EE, US }, 7), err);
            eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
            eng.connect(err);
            eng.onTunnelConnected();
            clk += 300'000;
            feedDead(eng, tun, 1000, 0);                           // шаг 3: EE→US
            eng.onTunnelDisconnected();                            // фаза up на US
            eng.onTunnelError();                                   // US провалил подъём
            if (!(eng.hasInterruptedSwitch() && eng.interruptedSwitchTarget().isEmpty()))
                continue;
            eng.connect(err);                                      // обе в провалах → без исключений
            if (tun.lastUpNodeId == QLatin1String("9"))
                ++ee;
        }
        CHECK(ee == 20);
        // повтор прерванного переподъёма на ту же ноду бюджет лечения не возвращает
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 1000, 0));                        // переподъём EE
        eng.onTunnelError();                                       // прерван в фазе down
        CHECK(eng.connect(err));
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(eng.onTunnelConnected());
        CHECK(feedDead(eng, tun, 2000, 1000));                     // кап эпизода не вернулся → US
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("10"));
    }
    // --- REV-5: флаппинг сети (смена каждые 12 с / 3 с) не глушит DEAD навсегда при мёртвом data-plane ---
    {
        for (const int period : { 12, 3 }) {
            HealthLoop h;
            qint64 tx = 0, deadAt = -1;
            for (qint64 t = 1000; t < 1000 + 600; t += 4) {
                if ((t - 1000) % period < 4)
                    h.noteNetworkChange(t, 20);
                tx += 100;
                if (h.feed(mkStats(0, 100, tx), t)) { deadAt = t; break; }
            }
            CHECK(deadAt >= 0);
            CHECK(deadAt - 1000 <= 60);                            // ≤ 2×grace + пара циклов
        }
        // одиночная смена по-прежнему даёт полное окно grace; остывание не продлевает окно
        HealthLoop h;
        CHECK(h.noteNetworkChange(1000, 20));
        CHECK(h.networkGraceUntil() == 1020);
        CHECK(h.noteNetworkChange(1030, 20));                      // та же серия: продление до капа
        CHECK(h.networkGraceUntil() == 1040);                      // кап серии = 1000 + 2×20
        CHECK(!h.noteNetworkChange(1045, 20));                     // остывание: окно не открывается
        CHECK(!h.inNetworkGrace(1046));
        CHECK(h.noteNetworkChange(1061, 20));                      // после остывания — новая серия
        CHECK(h.networkGraceUntil() == 1081);
        // движок: смена каждые 12 с 10 минут против мёртвого data-plane → DEAD/свитч случается
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        bool dead = false;
        qint64 tx = 0;
        for (qint64 t = 1000; t < 1000 + 600; t += 4) {
            if ((t - 1000) % 12 == 0)
                eng.noteNetworkChange(t);
            tx += 100;
            tun.st = mkStats(0, 100, tx);
            if (eng.tick(t) || eng.state() != EngineState::Connected) { dead = true; break; }
        }
        CHECK(dead);
        CHECK(tun.downCalls == 1);
    }
    // --- REV-6: провал фазы up у переподъёма в окне grace смены сети — нода не виновата: цель та же,
    // в провалы не пишется; вне окна — как раньше (провал, повтор мимо неё) ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        for (const bool inGrace : { true, false }) {
            qint64 clk = 1000 * 1000;
            ServiceEngine eng;
            FakeTunnel tun;
            eng.setTunnel(&tun);
            eng.setNowMsForTest([&clk]() { return clk; });
            QString err;
            CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
            CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
            CHECK(eng.connect(err));
            CHECK(eng.onTunnelConnected());
            CHECK(feedDead(eng, tun, 1000, 0));                    // переподъём EE
            CHECK(eng.onTunnelDisconnected());                     // фаза up на EE
            clk = 1010 * 1000;
            if (inGrace)
                eng.noteNetworkChange(1010);                       // роуминг посреди подъёма
            CHECK(eng.onTunnelError());
            CHECK(eng.hasInterruptedSwitch());
            CHECK(eng.interruptedSwitchCause() == QLatin1String("error_up"));
            CHECK(eng.interruptedSwitchTarget() == (inGrace ? QLatin1String("9") : QLatin1String("")));
            CHECK(countContaining(eng.switchLog(), "network grace") == (inGrace ? 1 : 0));
            eng.clearPin();
            CHECK(eng.connect(err));
            CHECK(tun.lastUpNodeId == (inGrace ? QLatin1String("9") : QLatin1String("10")));
        }
    }
    // --- GAP-2: отказ NE rebind с reason "offline" (путь NE unsatisfied, телефон без сети) — не провал
    // шага: попытка не тратится, следующий DEAD снова rebind (не переподъём/failover); "budget" — провал ---
    {
        TuningStore::set({}, {}, {}, {});                          // rebind_heal по умолчанию ВКЛ
        ServiceEngine eng;
        FakeTunnel tun;
        tun.rebindCapable = true;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(!feedDead(eng, tun, 1000, 0));                       // шаг 1: rebind #1
        CHECK(tun.rebindCalls == 1);
        CHECK(eng.onRebindResult(false, QStringLiteral("offline")));
        CHECK(eng.rebindHealTries() == 0);                         // попытка не потрачена
        CHECK(countContaining(eng.switchLog(), "path offline") == 1);
        CHECK(countContaining(eng.switchLog(), "denied") == 0);
        // окно grace (как noteNetworkChange): «плохие» тики сразу после отказа DEAD не дают
        CHECK(!feedDead(eng, tun, 1010, 500));
        CHECK(tun.rebindCalls == 1);
        CHECK(!feedDead(eng, tun, 1100, 1000));                    // после окна: DEAD → снова rebind
        CHECK(tun.rebindCalls == 2);
        CHECK(tun.downCalls == 0);                                 // ни переподъёма, ни failover
        CHECK(eng.onRebindResult(false, QStringLiteral("budget"))); // бюджет NE — провал шага 1
        CHECK(countContaining(eng.switchLog(), "denied by tunnel on 9 (budget)") == 1);
        feedDead(eng, tun, 1200, 2000);                            // сразу шаг 2 (DEAD уже на 2-м тике)
        CHECK(tun.rebindCalls == 2);
        CHECK(tun.downCalls == 1);
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
    // --- GAP-2: кап отсрочек "offline" на сессию лечения (ложный offline не держит мёртвую ноду вечно) ---
    {
        TuningStore::set({}, {}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        tun.rebindCapable = true;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        int cycles = 0;
        for (qint64 t = 1000; tun.downCalls == 0 && cycles < 40; t += 100, ++cycles) {
            feedDead(eng, tun, t, t * 10);
            if (eng.rebindAwaitingResult())
                CHECK(eng.onRebindResult(false, QStringLiteral("offline")));
        }
        // kRebindOfflineDeferMax отсрочек + одна засчитанная как отказ, затем переподъём той же ноды
        CHECK(tun.rebindCalls == ServiceEngine::kRebindOfflineDeferMax + 1);
        CHECK(tun.downCalls == 1);
        CHECK(countContaining(eng.switchLog(), "re-up same node 9") == 1);
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
    // --- GAPFIX-2: отсрочки "offline" — часть сессии лечения: после heal_budget_restore_s здорового
    // туннеля бюджет (и счётчик отсрочек) возвращается. Раньше счётчик копился всю сессию на ноде:
    // (kRebindOfflineDeferMax+1)-й эпизод засчитывался отказом → переподъём/failover (ревью probe) ---
    {
        TuningStore::set({}, {}, {}, {});                          // rebind_heal ВКЛ, restore 300 с
        ServiceEngine eng;
        FakeTunnel tun;
        tun.rebindCapable = true;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        qint64 t = 1000, tx = 0, rx = 1000;
        const int episodes = ServiceEngine::kRebindOfflineDeferMax + 2;
        int deferredFirst = 0, restored = 0;
        for (int ep = 0; ep < episodes; ++ep) {
            for (int k = 0; k < 10 && !eng.rebindAwaitingResult() && tun.downCalls == 0; ++k) {
                tun.st = mkStats(0, rx, tx += 100);                // tx растёт, rx стоит → DEAD
                eng.tick(t += 4);
            }
            CHECK(eng.rebindAwaitingResult());
            if (!eng.rebindAwaitingResult())
                break;
            CHECK(eng.onRebindResult(false, QStringLiteral("offline")));
            if (eng.switchLog().last().contains(QLatin1String("(not counted, 1/")))
                ++deferredFirst;
            for (int k = 0; k < 100; ++k) {                         // 400 с здорового трафика
                rx += 500; tx += 100;
                tun.st = mkStats(t, rx, tx);
                eng.tick(t += 4);
            }
            if (eng.switchLog().last().contains(QLatin1String("heal budget restored on 9")))
                ++restored;
        }
        CHECK(deferredFirst == episodes);                          // каждая отсрочка — 1/10, не 11-я
        CHECK(restored == episodes);
        CHECK(countContaining(eng.switchLog(), "denied") == 0);
        CHECK(tun.downCalls == 0);                                 // ни переподъёма, ни failover
        CHECK(tun.rebindCalls == episodes);
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
    }
    // --- GAP-3: строки switchLog начинаются с ISO-метки UTC (часы движка) и дублируются в Qt-лог
    // с префиксом "[avpn switch]" (причины свитчей видны в лог-файле и хвосте лога краш-отчёта) ---
    {
        const qint64 stampMs =
            QDateTime(QDate(2026, 9, 22), QTime(21, 5, 7, 123), QTimeZone::UTC).toMSecsSinceEpoch();
        qint64 clk = stampMs;
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        eng.setNowMsForTest([&clk]() { return clk; });
        QString err;
        g_qtLog.clear();
        const QtMessageHandler prev = qInstallMessageHandler(captureQtLog);
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        clk = stampMs + 60000;
        CHECK(feedDead(eng, tun, 1000, 0));                        // переподъём 9 → строки лога
        qInstallMessageHandler(prev);
        const QStringList log = eng.switchLog();
        CHECK(log.size() >= 2);
        for (const QString &l : log)
            CHECK(l.startsWith(QLatin1String("2026-09-22T21:0")) && l.contains(QLatin1String(".123Z ")));
        CHECK(countContaining(log, "re-up same node 9") == 1);
        bool stamped = false;
        for (const QString &l : log)
            if (l.contains(QLatin1String("re-up same node 9")))
                stamped = l.startsWith(QLatin1String("2026-09-22T21:06:07.123Z re-up same node 9"));
        CHECK(stamped);
        int seen = 0;
        for (const QString &m : g_qtLog)
            if (m.startsWith(QLatin1String("[avpn switch] 2026-09-22T21:06:07.123Z "))
                && m.contains(QLatin1String("re-up same node 9")))
                ++seen;
        CHECK(seen == 1);
        CHECK(countContaining(g_qtLog, "[avpn switch]") == log.size()); // каждая строка кольца — в Qt-лог
    }
#endif

    if (g_failed) {
        fprintf(stderr, "engine_reliability_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("engine_reliability_check: OK (%d checks — K5: пустая выдача, ревизии, Unchanged, identity, "
           "фазы свитча, лестница DEAD, rebind-итог, roaming grace, RTT-кэш)\n", g_total);
    return 0;
}

// --- линк-стабы (как failover_check) ---
namespace avpn {

bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &,
                        SecureAppSettingsRepository *, TrialResponse &tr, QString &error,
                        FetchOutcome *)
{
    if (g_enrollOk) {
        tr.subscriptionToken = QStringLiteral("stub-token");
        return true;
    }
    error = QStringLiteral("stub");
    return false;
}

bool Enrollment::fetchSubscription(QNetworkAccessManager *, const QString &, const QString &,
                                   QByteArray &body, QString &error, FetchOutcome *outcome)
{
    if (g_fetchOk) {
        body = g_fetchBody;
        if (outcome)
            *outcome = FetchOutcome::Ok;
        return true;
    }
    error = QStringLiteral("stub");
    return false;
}

void Enrollment::saveLkgSubscription(const QByteArray &body)
{
    g_diskLkg = body;
    ++g_lkgSaves;
}

QByteArray Enrollment::loadLkgSubscription()
{
    return g_diskLkg;
}

QString Enrollment::loadToken()
{
    return {};
}

void Enrollment::clearToken() { }

bool Identity::ensureKeys(SecureAppSettingsRepository *, QString &)
{
    return true;
}

} // namespace avpn
