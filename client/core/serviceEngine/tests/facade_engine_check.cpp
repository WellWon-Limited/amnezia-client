// AVPN (фикс-волна 2026-09-22, зона CL-A, пробелы критика полноты): последовательности вызовов
// ФАСАДА (AvpnEngineQml) против настоящего ServiceEngine/HealthLoop. Фасад зовёт движок через
// DebugSnapshot.h::facadeNoteNetworkChange — здесь та же функция.
//  GAP-2 (жалоба 3): смена сети каждые 6 с 5 минут при мёртвом data-plane — DEAD наступает
//        (раньше фасад перед noteNetworkChange звал resetHealthSampling() и DEAD не наступал никогда);
//  Scanner rows (path engine): a row is one exact path - raised as it is, never a fallback to another row.
// Каждый блок содержит и «контроль старого поведения»: прежняя последовательность фасада на том же
// движке воспроизводит дефект (иначе тест ничего бы не доказывал).
#include "../DebugSnapshot.h"
#include "../HealthLoop.h"
#include "../ServiceEngine.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <cstdio>
#include <functional>
#include <memory>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

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
    int upCalls = 0;
    int downCalls = 0;
    TunnelStats st;
    TunnelResult up(const Subscription &, const SubscriptionNode &node) override
    {
        ++upCalls;
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelStats readStats() override { return st; }
    bool rebindSocket() override { return false; }
    void down() override { ++downCalls; }
};

static TunnelStats mkStats(qint64 hs, qint64 rx, qint64 tx)
{
    TunnelStats s; s.latestHandshakeEpoch = hs; s.rxBytes = rx; s.txBytes = tx; s.valid = true; return s;
}

static QByteArray awgNodeJson(const char *id, int hostId, const char *cc, const char *endpoint)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )" + QByteArray::number(hostId)
        + R"(, "endpoint": ")" + endpoint + R"(", "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": 1.0, "country_code": ")" + cc + R"(",
        "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57,
                        "H1": 1, "H2": 2, "H3": 3, "H4": 4 } })";
}

static QByteArray subJson(int rev)
{
    return QByteArray(R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 5, "limit": 0 },
        "pool_revision": )") + QByteArray::number(rev) + R"(,
        "nodes": [)" + awgNodeJson("9", 9, "EE", "38.180.164.134:585") + ","
        + awgNodeJson("10", 10, "US", "149.33.7.203:585") + "] }";
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

// Мёртвый data-plane (tx растёт, rx стоит, handshake >180 с) + смена сети каждые 6 с 5 минут,
// тик health каждые 4 с. legacyReset — прежняя последовательность фасада (resetHealthSampling()
// перед noteNetworkChange). Возвращает секунды от первой смены до DEAD/свитча, -1 — не наступил.
static qint64 flappingDeadAfter(bool legacyReset)
{
    ServiceEngine eng;
    FakeTunnel tun;
    eng.setTunnel(&tun);
    QString err;
    CHECK(eng.loadSubscription(subJson(7), err));
    CHECK(eng.connect(err));
    CHECK(eng.onTunnelConnected() && eng.verifySucceeded()); // path engine: Connected after the data check
    const qint64 start = 100000;
    const qint64 staleHs = start - 600; // handshake старше 180 с
    qint64 tx = 0;
    qint64 nextChange = start;
    for (qint64 t = start; t < start + 300; t += 4) {
        while (nextChange <= t) {
            if (legacyReset)
                eng.resetHealthSampling();
            facadeNoteNetworkChange(eng, nextChange);
            nextChange += 6;
        }
        tx += 100;
        tun.st = mkStats(staleHs, 100, tx);
        if (eng.tick(t) || eng.state() != EngineState::Connected)
            return t - start;
    }
    return -1;
}

// AVPN Scanner (lane L6b): three locations, EE close, FI medium, US far.
static QByteArray subJson3(int rev)
{
    return QByteArray(R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 5, "limit": 0 },
        "pool_revision": )") + QByteArray::number(rev) + R"(,
        "nodes": [)" + awgNodeJson("9", 9, "EE", "38.180.164.134:585") + ","
        + awgNodeJson("10", 10, "US", "149.33.7.203:585") + ","
        + awgNodeJson("11", 11, "FI", "203.0.113.11:585") + "] }";
}

// The facade's row tap on the engine (AvpnEngineQml::connectToNode): the pin of the row and its one exact path (a
// Scanner row never falls back - path engine, design 2026-11-17 §3); then reconcile raises it when the intent is on
// (a live tunnel: the facade's stop, confirmed, then the start). Returns whether connect() ran.
static bool rowTap(ServiceEngine &eng, const QString &node, bool tunnelUp, bool force)
{
    QString err;
    CHECK(eng.setPinnedNode(node, err));
    eng.setUserChoice(path::UserChoice::exactPath(node));
    const PinReconnectIntent in = pinReconnectIntent(tunnelUp, force);
    if (!in.wantConnected)
        return false;
    if (in.needsRestart) { // reconcile: guardedStop -> requestStop -> Disconnected -> start
        eng.requestStop();
        eng.onTunnelDisconnected();
    }
    return eng.connect(err);
}

// ---- One native stop at a time (device round air-D 25.11, iPhone Air, N4 pair 2) ------------------------------------
// The facade's stop bookkeeping as AvpnEngineQml has it - guardedStart, guardedStop, reconcile, applyNativeState and the
// result part of syncAttempt - step for step where it decides, with the same pure functions (DebugSnapshot.h), against
// the real ServiceEngine and a native double. The double answers like the platform: iOS - every stop is echoed
// Disconnecting by VpnConnection::disconnectFromVpn and a stop of a session that is down gets a Disconnected at once
// (IosController::disconnectVpn, expected_app_stop); a live session's stops get its one real Disconnected when it goes
// down. Desktop/Android - a stop with no protocol gets a Disconnected at once (no echo); Error proves the teardown. The
// native events wait in `pending` in the order the platform produced them, with the leg markers of
// ITunnelControl::beginNativeOp among them; the test hands them to the facade in the order of the device journal.
// legacy = guardedStop before the fix: it always sent its own native stop.
// The numbers of Vpn::ConnectionState, so the journal lines read as the device's ("native_state=7" is the Error).
enum class Nat { Unknown = 0, Disconnected = 1, Connecting = 3, Connected = 4, Disconnecting = 5, Error = 7, Marker = 99 };

static ObservedTunnel observedOf(Nat s)
{
    switch (s) {
    case Nat::Connected: return ObservedTunnel::Connected;
    case Nat::Disconnected: return ObservedTunnel::Disconnected;
    case Nat::Error: return ObservedTunnel::Error;
    case Nat::Unknown: return ObservedTunnel::Unknown;
    default: return ObservedTunnel::Transitional;
    }
}

struct NativeDouble : ITunnelControl {
    struct Ev { Nat s; quint64 leg; };
    bool ios = true;
    bool sessionUp = false; // a native session runs: its stops are answered by its own Disconnected
    QStringList ups;
    int downs = 0;
    QList<Ev> pending;
    TunnelResult up(const Subscription &, const SubscriptionNode &node) override
    {
        ups << node.nodeId;
        return TunnelResult::success(); // a provider leg waits for its seat: nothing native yet
    }
    TunnelStats readStats() override { return {}; }
    void down() override
    {
        ++downs;
        if (!ios && !sessionUp) { // VpnConnection::disconnectFromVpn with no protocol
            pending << Ev{Nat::Disconnected, 0};
            return;
        }
        pending << Ev{Nat::Disconnecting, 0};
        if (!sessionUp)
            pending << Ev{Nat::Disconnected, 0}; // nothing to stop: answered at once
    }
    void beginNativeOp(quint64 leg) override { pending << Ev{Nat::Marker, leg}; }
    void emitState(Nat s) // what the platform reports by itself (a start going out, a session going down)
    {
        if (s == Nat::Connecting || s == Nat::Connected)
            sessionUp = true;
        if (s == Nat::Disconnected)
            sessionUp = false;
        pending << Ev{s, 0};
    }
    void seeMarker(quint64 leg) { noteNativeLegSeen(leg); }
};

struct FacadeSim {
    enum class Op { None, Starting, Stopping };
    ServiceEngine eng;
    NativeDouble nat;
    bool legacy = false;
    qint64 now = 1'800'000'000'000LL;
    bool want = false;
    bool needsRestart = false;
    Op op = Op::None;
    bool opInFlight = false;
    TeardownLatch latch;
    Nat last = Nat::Unknown;
    quint64 epoch = 1;
    QList<std::function<void()>> q; // the GUI event loop: deferred reconciles and adapter callbacks
    QStringList journal;

    FacadeSim(const QByteArray &sub, bool legacyStop, bool iosNative)
    {
        legacy = legacyStop;
        nat.ios = iosNative;
        eng.setTunnel(&nat);
        eng.setNowMsForTest([this] { return now; });
        eng.setAttemptTimingsForTest(path::AttemptTimings{});
        QString err;
        CHECK(eng.loadSubscription(sub, err));
        path::NetworkObservation home;
        home.medium = path::NetMedium::Wifi;
        home.gateway = QStringLiteral("192.168.1.1");
        home.subnet = QStringLiteral("192.168.1.0/24");
        eng.observeNetwork(home);
        eng.setIntentEpoch(epoch);
    }
    bool errorProvesTeardown() const { return !nat.ios; }
    void post(std::function<void()> f) { q << std::move(f); }
    void drain()
    {
        while (!q.isEmpty())
            q.takeFirst()();
    }
    void pass(qint64 ms) // the facade's attempt tick
    {
        for (qint64 t = 0; t < ms; t += 500) {
            now += 500;
            eng.attemptTick();
            syncAttempt();
        }
        drain();
    }
    void log(const QString &l) { journal << l; }
    void settle(const char *why)
    {
        if (op != Op::None || opInFlight)
            log(QStringLiteral("op_settled op=%1 why=%2").arg(int(op)).arg(QLatin1String(why)));
        op = Op::None;
        opInFlight = false;
    }
    // syncAttempt: the journal lines and the result (G3: a result of an older intent is superseded).
    void syncAttempt()
    {
        journal << eng.takeAttemptJournal();
        const std::optional<path::AttemptResult> r = eng.takeAttemptResult();
        if (!r)
            return;
        if (r->connected || r->reason != path::FailReason::StoppedByUser)
            settle(r->connected ? "attempt_connected" : "attempt_failed");
        if (r->intentEpoch < epoch) {
            log(QStringLiteral("attempt_result_superseded attempt=%1").arg(r->attempt));
            if (want)
                post([this] { reconcile(); });
            return;
        }
        if (!r->connected && r->reason != path::FailReason::StoppedByUser) {
            want = false;
            log(QStringLiteral("intent_off why=attempt_failed reason=%1").arg(QLatin1String(path::failReasonName(r->reason))));
        }
    }
    void guardedStart()
    {
        op = Op::Starting;
        opInFlight = true;
        needsRestart = false;
        log(QStringLiteral("attempt_start choice=%1").arg(eng.userChoice().pathIds.join(QLatin1Char(','))));
        QString err;
        if (!eng.connect(err)) {
            settle("attempt_not_started");
            syncAttempt();
            return;
        }
        syncAttempt();
    }
    void guardedStop(const char *why)
    {
        log(QStringLiteral("guarded_stop why=%1").arg(QLatin1String(why)));
        const FacadeStop how = legacy ? (stopFindsNothingNative(observedOf(last), eng.ownerHoldsNativeLeg())
                                             ? FacadeStop::ConfirmedAtOnce : FacadeStop::IssueStop)
                                      : facadeStopAction(observedOf(last), eng.ownerHoldsNativeLeg(), eng.ownerStopInFlight());
        if (how == FacadeStop::ConfirmedAtOnce) {
            eng.requestStop();
            latch.awaitingStopConfirm = false;
            settle("stop_nothing_native");
            return;
        }
        latch.awaitingStopConfirm = true;
        op = Op::Stopping;
        opInFlight = true;
        eng.requestStop();
        if (how == FacadeStop::IssueStop)
            nat.down();
        else
            log(QStringLiteral("stop_joined_owner_stop why=%1").arg(QLatin1String(why)));
    }
    void reconcile()
    {
        if (opInFlight)
            return;
        if (eng.attemptRunning() || eng.state() == EngineState::Switching) {
            if ((!want || needsRestart) && op != Op::Stopping) {
                const bool restart = needsRestart;
                needsRestart = false;
                guardedStop(restart ? "attempt_restart" : "attempt_intent_off");
            }
            return;
        }
        const ObservedTunnel observed = observedOf(last);
        if (reconcileGate(latch, observed, want, /*statusBudgetLeft=*/true) != ReconcileGate::Proceed) {
            log(QStringLiteral("reconcile_awaits_status"));
            return;
        }
        const bool connected = last == Nat::Connected;
        if (!connected && !reconcileActionable(observed, latch))
            return;
        if (want) {
            if (connected) {
                if (needsRestart) {
                    needsRestart = false;
                    guardedStop("reconcile_restart:pin");
                }
            } else {
                guardedStart();
            }
        } else if (connected) {
            guardedStop("reconcile_intent_off");
        }
    }
    // applyNativeState: staleness, the latch, the engine callback, the loss class, the settle, the deferred reconcile.
    void applyNative(Nat s)
    {
        if (eng.nativeEventStale(nat.nativeLegSeen())) {
            log(QStringLiteral("native_event_stale state=%1").arg(int(s)));
            return;
        }
        log(QStringLiteral("native_state=%1 intent_on=%2 engine=%3").arg(int(s)).arg(int(want)).arg(eng.debugSnapshot().state));
        const QString engineStateBefore = eng.debugSnapshot().state;
        observeTunnelState(latch, observedOf(last), observedOf(s), errorProvesTeardown());
        last = s;
        if (s == Nat::Connected)
            eng.onTunnelConnected();
        else if (s == Nat::Error)
            eng.onTunnelError(/*tunnelGone=*/errorProvesTeardown());
        else if (s == Nat::Disconnected)
            eng.onTunnelDisconnected();
        if (s == Nat::Disconnected || s == Nat::Error) {
            const QString est = eng.debugSnapshot().state;
            const bool weAreOperating = op != Op::None;
            const bool engineStillSwitching = s == Nat::Disconnected && engineOwnTransitionState(est);
            const LossClass loss = classifyLoss(weAreOperating, engineStillSwitching ? est : engineStateBefore,
                                                eng.attemptRunning(), false, true);
            if (loss == LossClass::External) {
                want = false;
                log(QStringLiteral("intent_off why=external_loss"));
            }
        }
        if (s == Nat::Connected || s == Nat::Disconnected || s == Nat::Error)
            settle("native_terminal");
        syncAttempt();
        post([this] { reconcile(); });
    }
    // The next native event the facade receives (leg markers pass through on the way).
    void deliver()
    {
        while (!nat.pending.isEmpty() && nat.pending.first().s == Nat::Marker)
            nat.seeMarker(nat.pending.takeFirst().leg);
        if (nat.pending.isEmpty())
            return;
        applyNative(nat.pending.takeFirst().s);
    }
    // Every native event the platform has produced so far is already in the GUI queue ahead of the reconciles the
    // first of them posts (VpnConnection emits a stop's echo as it takes the stop): all of them, then the reconciles.
    void deliverQueued()
    {
        for (int guard = 0; guard < 64 && !nat.pending.isEmpty(); ++guard)
            deliver();
        drain();
    }
    void deliverAll()
    {
        for (int guard = 0; guard < 64 && !nat.pending.isEmpty(); ++guard) {
            deliver();
            drain();
        }
    }
    // A row tap (connectToNode -> pinAndReconnectImpl): the exact row, the intent on, a restart when the tunnel is up or
    // coming, a new intent epoch; then reconcile.
    void tapRow(const QString &node)
    {
        eng.setUserChoice(path::UserChoice::exactPath(node));
        const PinReconnectIntent in = pinReconnectIntent(isTunnelUpStateName(eng.debugSnapshot().state), /*force=*/true);
        want = in.wantConnected;
        needsRestart = in.needsRestart;
        eng.setIntentEpoch(++epoch);
        log(QStringLiteral("scan_connect node=%1 restart=%2").arg(node).arg(int(needsRestart)));
        reconcile();
        drain();
    }
    // The person's Stop (stop()): the owner is told first, then the facade's own stop.
    void userStop()
    {
        eng.requestStop();
        want = false;
        needsRestart = false;
        if (stopNeedsGuardedStop(last != Nat::Disconnected, op == Op::Stopping, opInFlight, observedOf(last),
                                 eng.ownerHoldsNativeLeg()))
            guardedStop("user");
        else
            reconcile();
        drain();
    }
    // The seat request of a provider leg fails (VpnConnectionTunnelControl::failUpstreamStart): the engine is told first
    // (deferred), then the adapter's Error goes into the native stream.
    void seatFails(const QString &node)
    {
        nat.pending << NativeDouble::Ev{Nat::Error, 0};
        post([this, node] {
            eng.noteStartRefused(node, QStringLiteral("transport"));
            syncAttempt();
        });
        drain();
    }
    // The seat is granted: the provider leg's native start goes out and comes up; its one data check passes.
    void comesUp()
    {
        nat.emitState(Nat::Connecting);
        nat.emitState(Nat::Connected);
        deliverAll();
        if (eng.isVerifying()) {
            eng.verifySucceeded(120);
            syncAttempt();
            drain();
        }
    }
    bool has(const char *needle) const
    {
        for (const QString &l : journal)
            if (l.contains(QLatin1String(needle)))
                return true;
        return false;
    }
    int count(const char *needle) const
    {
        int n = 0;
        for (const QString &l : journal)
            n += l.contains(QLatin1String(needle)) ? 1 : 0;
        return n;
    }
    bool connectedOn(const QString &node) const
    {
        return eng.state() == EngineState::Connected && eng.currentNodeId() == node && want;
    }
    void dumpIfAsked(const char *title) const // AVPN_DUMP=1: every scenario's journal
    {
        if (qEnvironmentVariableIsSet("AVPN_DUMP"))
            dump(title);
    }
    void dump(const char *title) const
    {
        fprintf(stderr, "--- %s (%s) ---\n", title, legacy ? "legacy guardedStop" : "fixed guardedStop");
        for (const QString &l : journal)
            fprintf(stderr, "  %s\n", l.toUtf8().constData());
    }
};

static QByteArray providerPoolJson()
{
    // the own servers stay out of the way: exact rows of the Scanner are provider profiles here
    return QByteArray(R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2027-09-01T00:00:00Z", "traffic": { "used": 5, "limit": 0 }, "pool_revision": 7,
        "nodes": [)") + awgNodeJson("9", 9, "EE", "38.180.164.134:585") + ","
        + awgNodeJson("10", 10, "US", "149.33.7.203:585") + "] }";
}

static SubscriptionNode providerStub(const char *id)
{
    SubscriptionNode n;
    n.nodeId = QString::fromLatin1(id);
    n.region = QStringLiteral("upstream");
    n.proto = QStringLiteral("xray");
    n.countryCode = QStringLiteral("DE");
    UpstreamStub u;
    u.profileId = n.nodeId.mid(3);
    u.kind = UpstreamKind::Auto;
    n.upstream = u;
    return n;
}

// A connected session on `node` (own AmneziaWG): tap, native up, the data check passes.
static void connectOwn(FacadeSim &f, const char *node)
{
    f.tapRow(QString::fromLatin1(node));
    f.nat.emitState(Nat::Connecting);
    f.nat.emitState(Nat::Connected);
    f.deliverAll();
    CHECK(f.eng.isVerifying() && f.eng.verifySucceeded(80));
    f.syncAttempt();
    f.drain();
    CHECK(f.connectedOn(QString::fromLatin1(node)));
    f.journal.clear();
}

static void ownStopJoinScenarios()
{
    TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}, {QStringLiteral("xray_client"), true},
                          {QStringLiteral("upstream_nodes"), true}}, {}, {});
    avpn::upstreamPlatformRuntimeReady().store(true);
    const QString A = QStringLiteral("up:3ab9"), B = QStringLiteral("up:7a28");
    const auto rig = [&](bool legacy, bool ios) {
        auto *f = new FacadeSim(providerPoolJson(), legacy, ios);
        f->eng.setStandbyCandidates({providerStub("up:3ab9"), providerStub("up:7a28")});
        return std::unique_ptr<FacadeSim>(f);
    };

    // P1 - the journal replay (00:11:10.028 tap A, 00:11:10.726 tap B, 00:11:16.743 A's seat request fails). Native order
    // as seen: Error 16.749, Disconnecting 16.757, guarded_stop attempt_restart 16.765, Disconnected 16.772,
    // [old only: Disconnecting 16.785, Disconnected 16.799, intent_off why=external_loss 16.801].
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, /*ios=*/true);
        f->tapRow(A);
        CHECK(f->nat.ups == QStringList{A} && f->eng.attemptRunning() && f->opInFlight); // A's leg waits for its seat
        f->pass(500);
        f->now += 200;
        f->tapRow(B);                               // 0.7 s later: the newest pick; the start of A is still in flight
        CHECK(f->needsRestart && f->nat.downs == 0);
        f->pass(6000);                              // the seat request hangs (no deadline: provider leg 12 s)
        CHECK(f->eng.attemptRunning() && f->nat.downs == 0);
        f->seatFails(A);                            // the owner stops A's leg itself
        CHECK(f->nat.downs == 1 && f->eng.ownerStopInFlight());
        f->deliver();                               // Error (the adapter's)
        f->deliver();                               // Disconnecting (the echo of the owner's stop)
        f->drain();                                 // reconcile: guarded_stop why=attempt_restart
        CHECK(f->has("guarded_stop why=attempt_restart"));
        CHECK(f->nat.downs == (legacy ? 2 : 1));
        CHECK(legacy || f->has("stop_joined_owner_stop why=attempt_restart"));
        f->deliver();                               // Disconnected (the answer to the owner's stop)
        if (legacy) {
            f->deliver();                           // Disconnecting (the echo of the facade's own second stop)
            f->drain();
            f->deliver();                           // Disconnected (its answer) - no stop of ours pending any more
            f->drain();
            CHECK(f->has("intent_off why=external_loss"));
            CHECK(!f->want && f->nat.ups == QStringList{A}); // B never started, the VPN ends off
            CHECK(f->count("attempt_start") == 1);
            f->dump("P1 replay, before the fix");
        } else {
            f->drain();                             // reconcile: B's attempt starts at once
            CHECK(!f->has("external_loss") && f->want);
            CHECK(f->nat.ups == (QStringList{A, B}) && f->count("attempt_start") == 2);
            CHECK(f->nat.pending.size() == 1 && f->nat.pending.first().s == Nat::Marker); // nothing of A's left
            f->comesUp();
            CHECK(f->connectedOn(B));
            CHECK(f->nat.downs == 1);
            f->dump("P1 replay, after the fix");
        }
    }

    // P1 on the desktop / Android (Error proves the teardown, a stop with no protocol is answered at once): the owner's
    // stop is confirmed by the Error itself, the facade's restart never meets it - the same course with or without the fix.
    {
        QStringList runs[2];
        for (const bool legacy : {true, false}) {
            auto f = rig(legacy, /*ios=*/false);
            f->tapRow(A);
            f->pass(500);
            f->now += 200;
            f->tapRow(B);
            f->pass(6000);
            f->seatFails(A);
            f->deliverAll();
            CHECK(!f->has("external_loss") && f->nat.ups == (QStringList{A, B}) && !f->has("stop_joined_owner_stop"));
            CHECK(f->has("native_event_stale state=1")); // the late answer to A's stop never reaches B's leg
            f->comesUp();
            CHECK(f->connectedOn(B));
            runs[legacy ? 0 : 1] = f->journal;
        }
        CHECK(runs[0] == runs[1]); // byte-identical journal: the fix does not touch this course
    }

    // P1b - waiting for a seat, the seat granted late: A comes up, the restart stops it (the facade's one stop), B starts.
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        f->tapRow(A);
        f->pass(700);
        f->tapRow(B);
        f->pass(3000);
        f->nat.emitState(Nat::Connecting);
        f->nat.emitState(Nat::Connected);
        f->deliverAll();                            // Connected settles A's start; reconcile: restart over A's check
        CHECK(f->nat.downs == 1 && f->op == FacadeSim::Op::Stopping && !f->has("stop_joined"));
        f->nat.emitState(Nat::Disconnected);        // A's session goes down: the one answer
        f->deliverAll();
        CHECK(!f->has("external_loss") && f->nat.ups == (QStringList{A, B}));
        f->comesUp();
        CHECK(f->connectedOn(B) && f->nat.downs == 1);
        f->dumpIfAsked("P1b seat granted late");
    }

    // P2 - a start parked behind a teardown (iOS startAwaitsTeardown: the leg's local phase). The pick waits for the start's
    // terminal; the parked start goes out and comes up; the restart is the facade's one stop.
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        connectOwn(*f, "9");
        f->tapRow(QStringLiteral("10"));            // restart of 9: the facade's stop
        CHECK(f->nat.downs == 1);
        f->nat.emitState(Nat::Disconnected);
        f->deliverAll();                            // 10's start goes out (the native parks it: building)
        f->eng.onLocalBuild(ServiceEngine::LocalBuildReport::Building, f->eng.attemptLeg());
        f->syncAttempt();
        CHECK(f->has("leg_build begin"));
        f->tapRow(B);                               // the newest pick while 10's start is parked
        CHECK(f->nat.downs == 1);
        f->eng.onLocalBuild(ServiceEngine::LocalBuildReport::Built, f->eng.attemptLeg());
        f->nat.emitState(Nat::Connecting);
        f->nat.emitState(Nat::Connected);
        f->deliverAll();                            // the parked start came up; reconcile: restart, the facade's stop
        CHECK(f->nat.downs == 2 && !f->has("stop_joined"));
        f->nat.emitState(Nat::Disconnected);
        f->deliverAll();
        CHECK(!f->has("external_loss"));
        CHECK(f->nat.ups.last() == B);
        f->comesUp();
        CHECK(f->connectedOn(B));
        f->dumpIfAsked("P2 start parked behind a teardown");
    }

    // P3 - starting (native Connecting): the start fails with an Error (iOS: the session may still run), the owner stops its
    // leg itself; the session goes down before the facade's restart is sent. Old: the facade's second stop reaches a
    // session that is already down - answered at once - and that answer reads as an external loss.
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        f->tapRow(QStringLiteral("9"));
        f->nat.emitState(Nat::Connecting);
        f->deliverAll();
        f->tapRow(B);                               // waits for the start's terminal
        f->nat.emitState(Nat::Error);
        f->deliver();                               // Error: the owner stops 9's leg (its own stop)
        CHECK(f->nat.downs == 1 && f->eng.ownerStopInFlight());
        f->deliver();                               // Disconnecting (echo)
        f->nat.emitState(Nat::Disconnected);        // the session is down (the answer to the owner's stop)
        f->drain();                                 // reconcile: the restart for B
        CHECK(f->nat.downs == (legacy ? 2 : 1));
        f->deliverQueued();
        CHECK(f->has("intent_off why=external_loss") == legacy);
        CHECK((f->nat.ups.last() == B) == !legacy);
        if (!legacy) {
            f->comesUp();
            CHECK(f->connectedOn(B));
        }
        f->dumpIfAsked("P3 starting, Error");
    }

    // P4a - checking, the pick during the data check: the facade's one stop (the owner sends none).
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        f->tapRow(QStringLiteral("9"));
        f->nat.emitState(Nat::Connecting);
        f->nat.emitState(Nat::Connected);
        f->deliverAll();
        CHECK(f->eng.isVerifying());
        f->tapRow(B);
        CHECK(f->nat.downs == 1 && !f->eng.ownerStopInFlight() && !f->has("stop_joined"));
        f->nat.emitState(Nat::Disconnected);
        f->deliverAll();
        CHECK(!f->has("external_loss") && f->nat.ups.last() == B);
        f->comesUp();
        CHECK(f->connectedOn(B));
        f->dumpIfAsked("P4a checking, pick during the check");
    }

    // P4b - checking, the data check failed just before the pick: the owner's stop is in flight, the session is down
    // before the facade's restart goes out.
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        f->tapRow(QStringLiteral("9"));
        f->nat.emitState(Nat::Connecting);
        f->nat.emitState(Nat::Connected);
        f->deliverAll();
        CHECK(f->eng.verifyFailed(QStringLiteral("no data")));
        f->syncAttempt();
        CHECK(f->nat.downs == 1 && f->eng.ownerStopInFlight());
        f->deliver();                               // Disconnecting (echo)
        f->nat.emitState(Nat::Disconnected);        // down, not yet seen by the facade
        f->tapRow(B);
        CHECK(f->nat.downs == (legacy ? 2 : 1));
        f->deliverQueued();
        CHECK(f->has("intent_off why=external_loss") == legacy);
        if (!legacy) {
            CHECK(f->nat.ups.last() == B);
            f->comesUp();
            CHECK(f->connectedOn(B));
        }
        f->dumpIfAsked("P4b checking, check failed before the pick");
    }

    // P5 - connected: the restart is the facade's one stop.
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        connectOwn(*f, "9");
        f->tapRow(B);
        CHECK(f->has("guarded_stop why=reconcile_restart:pin") && f->nat.downs == 1 && !f->has("stop_joined"));
        f->nat.emitState(Nat::Disconnected);
        f->deliverAll();
        CHECK(!f->has("external_loss") && f->nat.ups.last() == B);
        f->comesUp();
        CHECK(f->connectedOn(B));
        f->dumpIfAsked("P5 connected");
    }

    // P6a - stopping, the facade's own stop in flight (a pick C a moment before): the newest pick B waits for that stop's
    // answer and starts; one native stop.
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        connectOwn(*f, "9");
        f->tapRow(QStringLiteral("10"));
        f->tapRow(B);
        CHECK(f->nat.downs == 1);
        f->nat.emitState(Nat::Disconnected);
        f->deliverAll();
        CHECK(!f->has("external_loss") && f->nat.ups.last() == B && f->count("attempt_start") == 1);
        f->comesUp();
        CHECK(f->connectedOn(B));
        f->dumpIfAsked("P6a stopping, the facade's stop in flight");
    }

    // P6b - stopping, the owner's own stop in flight with no facade operation (the live session lost its data: the failover
    // attempt stops it first); the session is down before the facade's restart goes out.
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        connectOwn(*f, "9");
        CHECK(f->eng.reenterVerifying() && f->eng.verifyFailed(QStringLiteral("no data")));
        f->syncAttempt();
        CHECK(f->eng.ownerStopInFlight() && f->nat.downs == 1 && f->op == FacadeSim::Op::None);
        f->deliver();                               // Disconnecting (echo)
        f->nat.emitState(Nat::Disconnected);
        f->tapRow(B);
        CHECK(f->nat.downs == (legacy ? 2 : 1));
        f->deliverQueued();
        CHECK(f->has("intent_off why=external_loss") == legacy);
        if (!legacy) {
            CHECK(f->nat.ups.last() == B);
            f->comesUp();
            CHECK(f->connectedOn(B));
        }
        f->dumpIfAsked("P6b stopping, the owner's stop in flight");
    }

    // The person's Stop while the owner's own stop is in flight (stop() tells the owner first): still one native stop -
    // the mark of the engine's own stop survives requestStop; its answer is ours, not an external loss.
    for (const bool legacy : {true, false}) {
        auto f = rig(legacy, true);
        connectOwn(*f, "9");
        CHECK(f->eng.reenterVerifying() && f->eng.verifyFailed(QStringLiteral("no data")));
        f->syncAttempt();
        f->deliver();
        f->nat.emitState(Nat::Disconnected);
        f->userStop();
        CHECK(f->nat.downs == (legacy ? 2 : 1));
        f->deliverQueued();
        CHECK(!f->want && f->has("intent_off why=external_loss") == legacy && f->nat.ups.size() == 1);
        f->dumpIfAsked("user Stop during the owner's stop");
    }

    // External (§13, unchanged): connected, the person switches the VPN off in iOS Settings - intent off, no reconnect.
    {
        QStringList runs[2];
        for (const bool legacy : {true, false}) {
            auto f = rig(legacy, true);
            connectOwn(*f, "9");
            f->nat.emitState(Nat::Disconnecting);
            f->nat.emitState(Nat::Disconnected);
            f->deliverAll();
            CHECK(f->has("intent_off why=external_loss") && !f->want);
            CHECK(f->nat.downs == 0 && f->nat.ups.size() == 1 && f->eng.state() == EngineState::Disconnected);
            f->pass(5000);
            CHECK(f->nat.ups.size() == 1 && !f->eng.attemptRunning());
            f->dumpIfAsked("external: VPN off in iOS Settings");
            runs[legacy ? 0 : 1] = f->journal;
        }
        CHECK(runs[0] == runs[1]);
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    ownStopJoinScenarios();

    // --- AVPN Scanner, review F4: VPN off -> row tap -> connect() on the tapped node ---
    {
        TuningStore::set({}, {}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        // The Scanner's row: forced, so the VPN-off tap really connects - on the far node it named.
        CHECK(rowTap(eng, QStringLiteral("10"), /*tunnelUp=*/false, scannerRowConnect(false).forceConnect));
        CHECK(tun.upCalls == 1);
        CHECK(tun.lastUpNodeId == QLatin1String("10"));
        CHECK(eng.currentNodeId() == QLatin1String("10"));
        // Control: the picker's tap with the VPN off only stores the target (F4: no connect at all).
        ServiceEngine eng2;
        FakeTunnel tun2;
        eng2.setTunnel(&tun2);
        CHECK(eng2.loadSubscription(subJson3(7), err));
        CHECK(!rowTap(eng2, QStringLiteral("10"), false, /*force=*/false));
        CHECK(tun2.upCalls == 0);
    }

    // --- AVPN Scanner: VPN on -> row tap -> the ordinary move (stop -> Disconnected -> start) on the row ---
    {
        TuningStore::set({}, {}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected() && eng.verifySucceeded());
        const QString first = tun.lastUpNodeId;
        CHECK(!scannerRowConnect(true).userStartBookkeeping);
        const QString row = first == QLatin1String("11") ? QStringLiteral("9") : QStringLiteral("11");
        CHECK(rowTap(eng, row, /*tunnelUp=*/true, true));
        CHECK(tun.lastUpNodeId == row && tun.upCalls == 2);
    }

    // --- AVPN Scanner: a row is one exact path - its failure ends the attempt, no other row is raised ---
    {
        TuningStore::set({}, {}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        qint64 now = 1'800'000'000'000LL;
        eng.setNowMsForTest([&now] { return now; });
        eng.setAttemptTimingsForTest(path::AttemptTimings{});
        QString err;
        CHECK(eng.loadSubscription(subJson3(7), err));
        CHECK(rowTap(eng, QStringLiteral("10"), false, true));
        for (int i = 0; i < 12; ++i) { // the start deadline passes: no handshake
            now += 500;
            eng.attemptTick();
        }
        CHECK(eng.onTunnelDisconnected()); // the stop of the row's leg confirmed
        const std::optional<path::AttemptResult> r = eng.takeAttemptResult();
        CHECK(r && r->reason == path::FailReason::ExactNodeFailed && tun.upCalls == 1);
    }

    // --- GAP-2: флаппинг сети не глушит DEAD мёртвого туннеля ---
    {
        TuningStore::set({}, {{QStringLiteral("rebind_heal"), false}}, {}, {});
        const int grace = healthNetworkGraceSTuned();
        const int cycles = HealthThresholds::fromTuning().cyclesToDead;
        const qint64 deadAfter = flappingDeadAfter(/*legacyReset=*/false);
        CHECK(deadAfter >= 0);
        CHECK(deadAfter <= 2 * grace + (cycles + 1) * 4); // ≤ 2×grace + cyclesToDead тиков
        fprintf(stderr, "GAP-2: dead after %lld s (grace %d, cycles %d)\n",
                (long long) deadAfter, grace, cycles);
        // контроль: прежняя последовательность фасада — DEAD не наступает за 5 минут никогда
        CHECK(flappingDeadAfter(/*legacyReset=*/true) == -1);
    }

    if (g_failed) {
        fprintf(stderr, "facade_engine_check: %d/%d FAILED\n", g_failed, g_total);
        return 1;
    }
    printf("facade_engine_check: OK (%d checks)\n", g_total);
    return 0;
}

// --- линк-стабы (как engine_reliability_check / failover_check): сеть и хранилище не нужны ---
namespace avpn {

bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &,
                        SecureAppSettingsRepository *, TrialResponse &, QString &error,
                        FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}

bool Enrollment::fetchSubscription(QNetworkAccessManager *, const QString &, const QString &,
                                   QByteArray &, QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}

void Enrollment::saveLkgSubscription(const QByteArray &) { }

QByteArray Enrollment::loadLkgSubscription()
{
    return {};
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
