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
#include "../DebugSnapshot.h"
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
    TunnelStats readStats() override { return st; }
    bool rebindSocket() override { ++rebindCalls; return rebindCapable; }
    void down() override { ++downCalls; }
};

static TunnelStats mkStats(qint64 hs, qint64 rx, qint64 tx)
{
    TunnelStats s; s.latestHandshakeEpoch = hs; s.rxBytes = rx; s.txBytes = tx; s.valid = true; return s;
}

// Path engine: EE ("9") carries the higher server weight - the owner's prior starts on it, as the pin / RTT did here.
static QByteArray awgNodeJson(const char *id, int hostId, const char *cc, const char *endpoint,
                              const char *extra = "")
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "endpoint": ")" + endpoint + R"(", "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": )" + (QByteArray(id) == "9" ? "2.0" : "1.0") + R"(, "country_code": ")" + cc + R"(", )" + extra + R"(
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

// Path engine (design 2026-11-17): a leg is Connected only after its data check through the tunnel.
static bool upConnected(ServiceEngine &eng)
{
    const bool up = eng.onTunnelConnected();
    return eng.isVerifying() ? eng.verifySucceeded() : up;
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
// 5.1.109 (R7e): an Xray listener on the US host (location h:10).
static const QByteArray XRAY_US = QByteArray(R"({ "node_id": "10x", "region": "eu", "host_id": 10,
    "endpoint": "149.33.7.203:443", "proto": "xray", "weight": 1.0, "country_code": "US",
    "xray_params": { "uuid": "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f",
                     "public_key": "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE",
                     "short_id": "a1b2c3d4", "server_name": "vision.example.com",
                     "fingerprint": "chrome", "flow": "xtls-rprx-vision",
                     "network": "tcp", "security": "reality" } })");
static void setXray(bool on)
{
    TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("dead_reup_same_node"), false},
                          {QStringLiteral("xray_client"), on}}, {}, {});
}

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
        CHECK(upConnected(eng));
        CHECK(eng.notifyConnectionLost());                         // реальный failover → запись «switch …»
        CHECK(upConnected(eng));
        const int reseedLinesBefore = countContaining(eng.switchLog(), "reseed");
        int applied = 0;
        for (int i = 0; i < 25; ++i)                               // ~8 мин traffic-sync по 20 с
            if (eng.reseedPool(parse(subJson({ EE, US }, 7, "active", 5 + i))) == ReseedResult::Applied)
                ++applied;
        const QStringList log = eng.switchLog();
        CHECK(applied == 0);
        CHECK(countContaining(log, "reseed") == reseedLinesBefore); // равная выдача не пишет в switchLog
        CHECK(countContaining(log, "attempt_leg") >= 1);           // запись о failover пережила 25 рефрешей
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
        CHECK(eng.isVerifying() && eng.verifySucceeded());         // path engine: one data check, then Connected
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
        CHECK(eng.verifySucceeded());
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
        CHECK(eng.verifySucceeded() && eng.state() == EngineState::Connected);
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
        CHECK(eng2.verifySucceeded());
        CHECK(eng2.reseedPool(parse(subJson({ EE, US }, 8))) == ReseedResult::Applied);
        CHECK(eng2.currentNodeId() == QLatin1String("9"));
    }
#endif

#ifndef AVPN_ENGINE_OLD_API
    // --- D2 (release 141, device round air20 R5): an own Xray session carries its node like an AmneziaWG one ---
    // The app was killed while connected through «Германия 1 · Xray Reality» (12:xray) and opened again: adoption
    // logged node= (empty) and the card said «Умный выбор сервера». The start envelope of an own Xray node had no
    // tribeSessionMetadata at all (only AmneziaWG starts wrote it), so the platform had nothing to hand back.
    {
        setXray(true);
        const Subscription sub = parse(subJson({ EE, US, XRAY_US }, 7));
        const SubscriptionNode *xr = nullptr, *awg = nullptr;
        for (const SubscriptionNode &n : sub.nodes) {
            if (n.nodeId == QLatin1String("10x")) xr = &n;
            if (n.nodeId == QLatin1String("10")) awg = &n;
        }
        CHECK(xr && awg);
        if (xr && awg) {
            // the metadata every start writes, whatever the transport
            for (const SubscriptionNode *n : { xr, awg }) {
                const QJsonObject md = ownSessionMetadata(*n);
                CHECK(md.value(QStringLiteral("schema_version")).toInt() == 1); // the adoption path requires it
                CHECK(md.value(QStringLiteral("node_id")).toString() == n->nodeId);
                CHECK(md.value(QStringLiteral("proto")).toString() == protoOf(*n));
                CHECK(md.value(QStringLiteral("endpoint")).toString() == n->endpoint);
                CHECK(!md.contains(QStringLiteral("upstream"))); // an own node is never an upstream session
            }
            // a relaunched app adopts the live Xray session by that metadata: the node is known at once
            const QJsonObject md = ownSessionMetadata(*xr);
            ServiceEngine eng;
            FakeTunnel tun;
            eng.setTunnel(&tun);
            QString err;
            CHECK(eng.loadSubscription(subJson({ EE, US, XRAY_US }, 7), err));
            CHECK(eng.adoptTunnelConnected(md.value(QStringLiteral("node_id")).toString(),
                                           md.value(QStringLiteral("proto")).toString(),
                                           md.value(QStringLiteral("endpoint")).toString()));
            CHECK(eng.currentNodeId() == QLatin1String("10x")); // not its AmneziaWG sibling on the same host
            CHECK(eng.verifySucceeded() && eng.state() == EngineState::Connected);
            // the node id changed in a pool refresh (reissue): the endpoint + proto hint still names it
            ServiceEngine eng2;
            eng2.setTunnel(&tun);
            CHECK(eng2.loadSubscription(subJson({ EE, US, XRAY_US }, 7), err));
            CHECK(eng2.adoptTunnelConnected(QStringLiteral("old10x"), md.value(QStringLiteral("proto")).toString(),
                                            md.value(QStringLiteral("endpoint")).toString()));
            CHECK(eng2.verifySucceeded());
            CHECK(eng2.tryIdentifyCurrentNode()); // the facade asks on every tick (identifyAdoptedSession)
            CHECK(eng2.currentNodeId() == QLatin1String("10x"));
        }
        setXray(false);
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
        CHECK(upConnected(eng));
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
        // The live probe's part of the AmneziaWG DEAD rule (device round 19.11, review H1/H2).
        using avpn::HealthLoop;
        CHECK(HealthLoop::probeDeadCorroborated(4, 4, false, 1000, 1000 + 140, 135));   // probe dead + rekeys failing
        CHECK(!HealthLoop::probeDeadCorroborated(4, 4, false, 1000, 1000 + 60, 135));   // H1: the tunnel rekeys - healthy
        CHECK(!HealthLoop::probeDeadCorroborated(9, 4, false, 1000, 1000 + 20, 135));   // probe addresses down for long
        CHECK(!HealthLoop::probeDeadCorroborated(4, 4, true, 1000, 1000 + 140, 135));   // H2: a network change is healing
        CHECK(!HealthLoop::probeDeadCorroborated(3, 4, false, 1000, 1000 + 140, 135));  // not enough failures yet
        CHECK(!HealthLoop::probeDeadCorroborated(4, 4, false, 0, 1000 + 140, 135));     // handshake time unknown
        CHECK(!HealthLoop::probeDeadCorroborated(9, 0, false, 1000, 1000 + 999, 135));  // switched off
        // Device round 24.11 (B1, awg-apple tribe.17): handshakes complete, no data comes back. The extension's stall
        // verdict (`data_stall_s`) corroborates the failing probe; the grace still vetoes.
        CHECK(HealthLoop::probeDeadCorroborated(4, 4, false, 1000, 1000 + 10, 135, 45, 45));    // fresh hs, stalled 45 s
        CHECK(!HealthLoop::probeDeadCorroborated(4, 4, false, 1000, 1000 + 10, 135, 44, 45));   // not long enough
        CHECK(!HealthLoop::probeDeadCorroborated(4, 4, false, 1000, 1000 + 10, 135, 0, 45));    // not stalled now
        CHECK(!HealthLoop::probeDeadCorroborated(4, 4, true, 1000, 1000 + 10, 135, 600, 45));   // network change: grace
        CHECK(!HealthLoop::probeDeadCorroborated(3, 4, false, 1000, 1000 + 10, 135, 600, 45));  // 3 of 4 failures
        CHECK(!HealthLoop::probeDeadCorroborated(4, 4, false, 1000, 1000 + 10, 135, 600, 0));   // switched off: 141
        CHECK(HealthLoop::probeDeadCorroborated(4, 4, false, 0, 1000, 135, 50, 45));           // no hs time, stalled
        // Unchanged where the field is unknown (-1: Android, desktop, an extension before tribe.16): the rule of 141.
        {
            const auto rule141 = [](int fail, int cycles, bool grace, qint64 hs, qint64 now, int age) {
                if (cycles <= 0 || fail < cycles || grace || hs <= 0)
                    return false;
                return now - hs > age;
            };
            int same = 0, total = 0;
            for (int fail = 0; fail <= 6; ++fail)
                for (int cycles = 0; cycles <= 5; ++cycles)
                    for (int grace = 0; grace <= 1; ++grace)
                        for (qint64 hs : {qint64(0), qint64(-5), qint64(1000)})
                            for (qint64 age = 0; age <= 400; age += 20)
                                for (int minQuiet : {0, 20, 45, 600}) {
                                    ++total;
                                    same += HealthLoop::probeDeadCorroborated(fail, cycles, grace, hs, 1000 + age, 135, -1,
                                                                              minQuiet)
                                         == rule141(fail, cycles, grace, hs, 1000 + age, 135);
                                }
            CHECK(same == total);
        }
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
        CHECK(upConnected(eng));
        eng.noteNetworkChange(1000);
        CHECK(!feedDead(eng, tun, 1001, 0));
        CHECK(eng.state() == EngineState::Connected);
        CHECK(tun.downCalls == 0);
    }
    // --- Device round 24.11 (B1) and the review of its fix (awg-apple tribe.17): the AmneziaWG probe failover through the
    // engine. The roam is at R (noteNetworkChange, 60 s ago: its grace is over), the in-tunnel probe fails, handshakes
    // stay fresh, and the extension's stall verdict (`data_stall_s`) is what its replay reports at each probe.
    // 141: never (the handshake never ages). Now: the first failure with 4 in a row, outside the grace window, with a
    // FRESH verdict of 45 s or more. Data coming in (the extension reports 0), an old extension (-1), a stale reading
    // and the grace window: nothing.
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        struct Run { bool failedOver = false; qint64 at = -1; };
        // probes: (seconds after R, the verdict the extension reports then); staleMs: how old the reading is
        const auto run = [&](const QList<QPair<qint64, qint64>> &probes, qint64 staleMs = 0, bool grace = false) {
            ServiceEngine eng;
            FakeTunnel tun;
            eng.setTunnel(&tun);
            QString err;
            CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
            CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
            CHECK(eng.connect(err));
            CHECK(upConnected(eng));
            Run r;
            const qint64 now = QDateTime::currentSecsSinceEpoch();
            eng.noteNetworkChange(grace ? now : now - 60);
            for (const auto &p : probes) {
                if (r.failedOver)
                    break;
                tun.st = mkStats(now - 5, 1000, 5000 + p.first * 1500); // a fresh handshake
                tun.st.dataStallSec = p.second;
                tun.st.dataStallAtMs = QDateTime::currentMSecsSinceEpoch() - staleMs;
                if (eng.feedProbeResult(false)) { r.failedOver = true; r.at = p.first; }
            }
            return r;
        };
        QList<QPair<qint64, qint64>> noData, oldExt, review;
        for (qint64 t = 4; t <= 60; t += 4) {
            noData << qMakePair(t, t);   // B1 with no data at all: stalled since R
            oldExt << qMakePair(t, qint64(-1));
        }
        // The review's F3 sequence (TribeRoamingTests "F3 recovered inside the echo window": 12, 24, 36, then 0 at 48:
        // the data has returned at 45 s, inside the stage-3 fresh port's echo window).
        review << qMakePair(qint64(12), qint64(12)) << qMakePair(qint64(24), qint64(24)) << qMakePair(qint64(36), qint64(36))
               << qMakePair(qint64(48), qint64(0)) << qMakePair(qint64(60), qint64(0));
        const Run b1 = run(noData);
        CHECK(b1.failedOver && b1.at == 48);       // verdict 48 s >= 45 at the 12th failed probe (4 in a row at 16 s)
        CHECK(!run(oldExt).failedOver);           // an extension before tribe.17: the rule of 141 (fresh handshake)
        CHECK(!run(review).failedOver);           // F3: the path recovered at 45 s - never failed over
        CHECK(!run(noData, 10000).failedOver);    // Q6: a verdict applied 10 s ago is stale - not corroboration
        CHECK(run(noData, 3000).failedOver);      // ... 3 s ago is fresh (the status poll answers every second)
        CHECK(!run(noData, 0, true).failedOver);  // during the grace window of a network change: no failover
        const qint64 nowMs = 1'800'000'000'000;
        CHECK(HealthLoop::freshDataStall(50, nowMs - 5000, nowMs) == 50 && HealthLoop::freshDataStall(50, nowMs - 5001, nowMs) == -1);
        CHECK(HealthLoop::freshDataStall(50, nowMs + 1000, nowMs) == -1 && HealthLoop::freshDataStall(50, 0, nowMs) == -1);
        CHECK(HealthLoop::freshDataStall(-1, nowMs, nowMs) == -1);
        // Second review, G1 (its sequence): failed probes at R+12/24/36 with fresh verdicts 12/24/36; the reply carrying
        // 46 belongs to a request sent at R+46, the app is suspended at R+46.06 and the reply is applied at R+100, when
        // the overdue 4th probe fails. 2e641743d dated the reading when it was applied (fresh: failover of a tunnel that
        // carries data since R+47); tribe.18 dates it by its request (54 s old: no corroboration).
        const auto g1 = [&](bool datedByRequest) {
            ServiceEngine eng;
            FakeTunnel tun;
            eng.setTunnel(&tun);
            QString err;
            CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
            CHECK(eng.setPinnedNode(QStringLiteral("9"), err));
            CHECK(eng.connect(err));
            CHECK(upConnected(eng));
            const qint64 now = QDateTime::currentSecsSinceEpoch();
            const qint64 nowMsG1 = QDateTime::currentMSecsSinceEpoch();
            eng.noteNetworkChange(now - 160);
            bool failedOver = false;
            for (qint64 verdict : {12, 24, 36}) {
                tun.st = mkStats(now - 5, 1000, 5000 + verdict * 2000);
                tun.st.dataStallSec = verdict;
                tun.st.dataStallAtMs = nowMsG1;
                failedOver = failedOver || eng.feedProbeResult(false);
            }
            tun.st.dataStallSec = 46;
            tun.st.dataStallAtMs = datedByRequest ? nowMsG1 - 54'000 : nowMsG1;
            failedOver = failedOver || eng.feedProbeResult(false);
            return failedOver;
        };
        CHECK(g1(/*datedByRequest=*/false));  // the rule of 2e641743d: fails over a recovered tunnel
        CHECK(!g1(/*datedByRequest=*/true));  // tribe.18: a reply to a request sent before the suspension is stale
        // ... and the 4th probe itself (started at R+40, failed at R+100.002, budget 2 x 4 s) spanned the suspension.
        CHECK(HealthLoop::probeSpannedSuspension(40'000, 100'002, 8'000));
        CHECK(!HealthLoop::probeSpannedSuspension(40'000, 50'000, 8'000) && HealthLoop::probeSpannedSuspension(40'000, 50'001, 8'000));
        CHECK(HealthLoop::probeSpannedSuspension(40'000, 39'000, 8'000) && !HealthLoop::probeSpannedSuspension(0, 100'000, 8'000));
    }
#endif

    // --- B9 [OLD-API]: «нет ответа в этом раунде» не выкидывает ноду с прошлым замером (the RTT cache is the
    // bars' only input now - path engine: it ranks nothing) ---
    {
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ EE, US }, 7), err));
        eng.setMeasuredRtt({{QStringLiteral("9"), 40}, {QStringLiteral("10"), 150}});
        eng.setMeasuredRtt({{QStringLiteral("9"), -1}, {QStringLiteral("10"), 150}}); // потерян пакет EE
        CHECK(eng.measuredRtt().value(QStringLiteral("9"), -1) == 40);
    }
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
        CHECK(upConnected(eng));
        CHECK(feedDead(eng, tun, 1000, 0));                        // шаг 2: переподъём EE
        CHECK(eng.onTunnelDisconnected());
        CHECK(tun.lastUpNodeId == QLatin1String("9"));
        CHECK(upConnected(eng));
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
        CHECK(upConnected(eng));
        CHECK(feedDead(eng, tun, 1000, 0));                        // переподъём EE
        CHECK(eng.onTunnelDisconnected());
        CHECK(upConnected(eng));
        qint64 rx = 10000, tx = 10000;
        for (qint64 t = 1100; t < 1130; t += 4) {                  // всего 30 с здоровья
            rx += 100; tx += 100;
            tun.st = mkStats(t, rx, tx);
            eng.tick(t);
        }
        CHECK(countContaining(eng.switchLog(), "heal budget restored") == 0);
        CHECK(feedDead(eng, tun, 1200, tx));                       // кап эпизода исчерпан → другая нода
        CHECK(eng.onTunnelDisconnected());
        // path engine: the pinned server of the list is a preference - its own paths are spent, the failover attempt
        // goes on to the best available server (the facade tells the person, the preference is kept)
        CHECK(tun.lastUpNodeId == QLatin1String("10"));
        // простой (ни rx, ни handshake) бюджет не возвращает
        ServiceEngine idle;
        FakeTunnel itun;
        idle.setTunnel(&itun);
        CHECK(idle.loadSubscription(subJson({ EE, US }, 7), err));
        CHECK(idle.setPinnedNode(QStringLiteral("9"), err));
        CHECK(idle.connect(err));
        CHECK(upConnected(idle));
        CHECK(feedDead(idle, itun, 1000, 0));
        CHECK(idle.onTunnelDisconnected());
        CHECK(upConnected(idle));
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
        CHECK(upConnected(rb));
        CHECK(!feedDead(rb, rtun, 1000, 0));                       // rebind 1
        CHECK(!feedDead(rb, rtun, 1100, 1000));                    // rebind 2
        CHECK(feedDead(rb, rtun, 1200, 2000));                     // переподъём EE
        CHECK(rtun.rebindCalls == 2);
        CHECK(rb.onTunnelDisconnected());
        CHECK(rtun.lastUpNodeId == QLatin1String("9"));
        CHECK(upConnected(rb));
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
        CHECK(upConnected(eng));
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
        CHECK(upConnected(eng));
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
        CHECK(upConnected(eng));
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
        CHECK(upConnected(eng));
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
        CHECK(upConnected(eng));
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
