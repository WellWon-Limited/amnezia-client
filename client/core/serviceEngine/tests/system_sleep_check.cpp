// AVPN (owner's Mac 24.11.2026, cause F of the Mac diagnosis): the engine's one fact "the system is fully awake" and
// its gate (SystemAwake.h), and the real ServiceEngine + attempt owner behind it with a fake tunnel
// (ServiceEngine::setSystemAwake, AttemptOwner.h "System asleep"). Build/run: build_system_sleep.sh.
//
// The event script is the night of 24.11 from the service and app logs (UTC): "will sleep" 08:29:21.268; dark wakes
// 08:39:16 (BSSID change -> networkChanged x2 at 08:39:16.761 and 08:39:41.440), 08:41:45 (networkChanged
// 08:41:46.264), 08:58:42; the lid-open wake: the service's power callback "has powered on" 15:38:14.261. The facade's
// automatic mechanisms are played in the order the app ran them that night: every one asks the gate at its entry
// (the wiring is checked by check_system_sleep_wiring.sh); before the fix each of them acted.
#include "../DebugSnapshot.h"
#include "../ServiceEngine.h"
#include "../SystemAwake.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QTimeZone>
#include <cstdio>

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

static qint64 utc(const char *hms)
{
    return QDateTime::fromString(QStringLiteral("2026-11-24T") + QLatin1String(hms) + QStringLiteral("Z"), Qt::ISODateWithMs)
        .toMSecsSinceEpoch();
}

// --- the facade's automatic mechanisms, as the app runs them, each behind the one gate --------------------------
// What each would have done counts in `acted`; the awake edge's one evaluation counts in `evaluations`/`probes`.
struct FacadeModel {
    SystemAwake fact;
    int acted = 0;       // an automatic action that ran (a probe, a restart, a start, a renewal, a check)
    int evaluations = 0; // awake edges (leaveSystemSleep)
    int probes = 0;      // liveness probes of the live session (§18)
    bool intentOn = true, tunnelUp = true, engineConnected = true;
    bool gateEnabled = true;

    // AvpnEngineQml::noteSleepSignal
    bool signal(SleepSignal s, qint64 now)
    {
        if (fact.awake() && s != SleepSignal::WillSleep)
            return false;
        switch (fact.note(s, now, gateEnabled)) {
        case SleepEdge::Woke: {
            ++evaluations;
            const WakeEvaluation e = wakeEvaluation(intentOn, tunnelUp, engineConnected);
            if (e.probeTunnel)
                ++probes;
            return true;
        }
        case SleepEdge::Slept:
        case SleepEdge::None: break;
        }
        return false;
    }
    // every automatic mechanism's entry: AvpnEngineQml::heldBySystemSleep(what), then its own work
    void automatic(SleepHeld what)
    {
        if (fact.hold(what))
            return;
        ++acted;
    }
    // the service's networkChanged / wakeup (onDaemonNetworkChanged / onDaemonWakeup)
    void networkChanged() { automatic(SleepHeld::TunnelProbe); }
    void wakeup(qint64 now)
    {
        if (signal(SleepSignal::ServicePoweredOn, now))
            return; // the edge's evaluation probes itself
        automatic(SleepHeld::TunnelProbe);
    }
};

static void factAndGateOn24Nov()
{
    FacadeModel f;
    CHECK(f.fact.awake()); // the app was launched by a person: awake

    // 08:29:21 the lid closes
    CHECK(!f.signal(SleepSignal::WillSleep, utc("08:29:21.268")));
    CHECK(!f.fact.awake() && f.fact.sleeps() == 1);

    // 08:39:16 dark wake (19 s): the service's networkChanged x2, the health tick (4 s), the uplink and Wi-Fi state
    // flapping (the wake restart's retry), reconcile of a held start, the live probe, a data check
    f.networkChanged();
    for (int i = 0; i < 5; ++i)
        f.automatic(SleepHeld::HealthTick);
    f.automatic(SleepHeld::WakeRetry);
    f.automatic(SleepHeld::Reconcile);
    f.automatic(SleepHeld::LiveProbe);
    f.networkChanged();
    // 08:41:45 dark wake (11 s): networkChanged, the uplink goes down, a data check of a start that never began
    f.networkChanged();
    f.automatic(SleepHeld::DataCheck);
    f.automatic(SleepHeld::Reconcile);
    // 08:58:42 dark wake (2 s): one health tick
    f.automatic(SleepHeld::HealthTick);
    CHECK(f.acted == 0);            // no probe, no restart, no start, no renewal, no check before the awake edge
    CHECK(f.evaluations == 0 && f.probes == 0);
    CHECK(f.fact.heldCount() == 14);
    CHECK(sleepHeldNames(f.fact.heldMask())
          == QLatin1String("reconcile,tunnel_probe,wake_retry,health_tick,live_probe,data_check"));
    // a second "will sleep" of the same night (going back to sleep from a dark wake) changes nothing
    CHECK(!f.signal(SleepSignal::WillSleep, utc("08:41:56.000")) && !f.fact.awake() && f.fact.heldCount() == 14);

    // 15:38:14 the lid opens: the service's "has powered on" is the awake edge - one evaluation, one probe
    f.wakeup(utc("15:38:14.261"));
    CHECK(f.fact.awake() && f.evaluations == 1 && f.probes == 1 && f.acted == 0);
    CHECK(f.fact.wokeBy() == SleepSignal::ServicePoweredOn);
    CHECK(f.fact.lastAsleepMs() == utc("15:38:14.261") - utc("08:29:21.268"));
    // the other proofs of the same wake (NSWorkspace did wake, screens did wake, the person's first click) and the
    // BSSID change of the real wake: no second evaluation; the network change probes as before the gate (awake)
    CHECK(!f.signal(SleepSignal::DidWake, utc("15:38:14.300")));
    CHECK(!f.signal(SleepSignal::ScreensDidWake, utc("15:38:14.400")));
    CHECK(!f.signal(SleepSignal::PersonInput, utc("15:43:40.000")));
    f.networkChanged();
    CHECK(f.evaluations == 1 && f.probes == 1 && f.acted == 1);
    // awake: every mechanism acts again
    f.automatic(SleepHeld::HealthTick);
    f.automatic(SleepHeld::Reconcile);
    CHECK(f.acted == 3);
}

// The order at the real wake can be the other way round: the BSSID change of the full wake arrives before "has powered
// on" - it is held (still asleep), and the edge that follows evaluates once.
static void networkChangeBeforePoweredOn()
{
    FacadeModel f;
    f.signal(SleepSignal::WillSleep, 0);
    f.networkChanged();
    f.wakeup(1000);
    CHECK(f.acted == 0 && f.evaluations == 1 && f.probes == 1);
}

// The gate must not freeze automation if one notification is missed: "has powered on" and NSWorkspace "did wake" both
// missed - the person's first press in the window heals it (and the tap that follows works); each other proof alone
// heals it as well. No timer is involved.
static void missedPoweredOnHeals()
{
    for (const SleepSignal proof : { SleepSignal::PersonInput, SleepSignal::DidWake, SleepSignal::ScreensDidWake,
                                     SleepSignal::ServicePoweredOn }) {
        FacadeModel f;
        f.signal(SleepSignal::WillSleep, 0);
        f.automatic(SleepHeld::Reconcile);
        CHECK(!f.fact.awake() && f.acted == 0);
        CHECK(f.signal(proof, 3'600'000));
        CHECK(f.fact.awake() && f.evaluations == 1 && f.fact.wokeBy() == proof);
        f.automatic(SleepHeld::Reconcile); // the person's tap: reconcile runs
        CHECK(f.acted == 1);
    }
    // no proof at all: the gate stays shut - it never opens on time alone (a dark wake can last any time)
    FacadeModel f;
    f.signal(SleepSignal::WillSleep, 0);
    for (int h = 1; h <= 48; ++h)
        f.automatic(SleepHeld::HealthTick);
    CHECK(!f.fact.awake() && f.acted == 0 && f.evaluations == 0);
}

// The fact is the app's own: a launch is awake, and nothing the service connection does changes it - a reconnect to the
// service while asleep (the replica re-initialised after a service restart) brings no input; the service's wakeup is a
// proof only for a full wake (it is not delivered for a dark wake).
static void appOwnsTheFact()
{
    SystemAwake launched;
    CHECK(launched.awake() && !launched.hold(SleepHeld::Reconcile));
    CHECK(launched.note(SleepSignal::ServicePoweredOn, 0) == SleepEdge::None); // a proof of what is true
    SystemAwake asleep;
    asleep.note(SleepSignal::WillSleep, 0);
    CHECK(!asleep.awake() && asleep.hold(SleepHeld::TunnelProbe));
}

// features.system_sleep_gate = false: "will sleep" is not taken (the behaviour before the gate); switched off while
// asleep, the next observation ends the sleep.
static void killSwitch()
{
    FacadeModel f;
    f.gateEnabled = false;
    CHECK(!f.signal(SleepSignal::WillSleep, 0) && f.fact.awake());
    f.networkChanged();
    CHECK(f.acted == 1);
    FacadeModel g;
    g.signal(SleepSignal::WillSleep, 0);
    g.gateEnabled = false;
    CHECK(!g.fact.awake());
    CHECK(g.signal(SleepSignal::WillSleep, 1000) && g.fact.awake() && g.evaluations == 1);
}

// The evaluation probes only a live session the person wants; an attempt in flight is resumed by the owner itself.
static void wakeEvaluationRule()
{
    CHECK(wakeEvaluation(true, true, true).probeTunnel);
    CHECK(!wakeEvaluation(false, true, true).probeTunnel);  // the person turned it off
    CHECK(!wakeEvaluation(true, false, false).probeTunnel); // down: reconcile starts it
    CHECK(!wakeEvaluation(true, true, false).probeTunnel);  // checking: the owner runs the check again
    const WakeEvaluation e = wakeEvaluation(true, false, false);
    CHECK(e.observeNetwork && e.resumeOwner && e.reconcile);
}

// --- the real engine behind the gate -------------------------------------------------------------------------

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

static QByteArray subJson()
{
    return QByteArray(R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2027-09-01T00:00:00Z", "traffic": { "used": 5, "limit": 0 },
        "pool_revision": 7,
        "nodes": [)") + awgNodeJson("9", 9, "EE", "198.51.100.9:585") + ","
        + awgNodeJson("10", 10, "FI", "198.51.100.10:585") + "] }";
}

static path::NetworkObservation wifi(const char *gw)
{
    path::NetworkObservation o;
    o.medium = path::NetMedium::Wifi;
    o.gateway = QString::fromLatin1(gw);
    o.subnet = QStringLiteral("192.168.1.0/24");
    return o;
}

struct Rig {
    ServiceEngine eng;
    FakeTunnel tun;
    qint64 now = utc("08:41:56.771");
    explicit Rig()
    {
        TuningStore::set({}, {}, {}, {});
        eng.setTunnel(&tun);
        eng.setNowMsForTest([this] { return now; });
        eng.setAttemptTimingsForTest(path::AttemptTimings{});
        QString err;
        CHECK(eng.loadSubscription(subJson(), err));
        eng.observeNetwork(wifi("aa"));
    }
    // the facade's 500 ms transition timer over `ms` of time (a dark wake), and nothing else
    void ticks(qint64 ms)
    {
        for (qint64 t = 0; t < ms; t += 500) {
            now += 500;
            eng.attemptTick();
        }
    }
};

// 08:41:56.771: the restart issued in the second the Mac slept. The start is in flight when the system sleeps; in
// the dark wake that follows the tunnel comes up and the check's answer (no data - nothing passes) arrives; the
// attempt owner neither judges nor starts anything; on the awake edge the check runs again and the leg connects.
static void engineSleepMidStart()
{
    Rig r;
    QString err;
    CHECK(r.eng.connect(err));
    CHECK(r.tun.upCalls == 1 && r.eng.attemptRunning());
    r.now += 50;
    r.eng.setSystemAwake(false); // the facade's enterSystemSleep (WillSleep)
    CHECK(!r.eng.systemAwake());
    r.now += 1'004'000;          // deep sleep until the 08:58:42 dark wake
    CHECK(r.eng.onTunnelConnected()); // the daemon reports the tunnel up in the dark wake
    CHECK(r.eng.isVerifying());       // the facade's check is held (startDataPathVerification)
    r.ticks(2000);
    CHECK(r.eng.verifyFailed(QStringLiteral("whoami no data (dark wake)"))); // an answer that came anyway: void
    r.ticks(20'000); // far past the start, check and attempt deadlines in awake time - if the clock ran
    CHECK(r.tun.upCalls == 1 && r.tun.downCalls == 0 && r.eng.attemptRunning() && r.eng.isVerifying());
    CHECK(!r.eng.takeAttemptResult().has_value() && r.eng.pathsFailedHere().isEmpty());
    CHECK(!r.eng.takeCheckRerun());
    r.now += 23'000'000; // until 15:38:14
    r.eng.setSystemAwake(true); // the awake edge
    CHECK(r.eng.takeCheckRerun()); // exactly one evaluation of the leg: its check, again, on the same tunnel
    CHECK(r.eng.verifySucceeded());
    CHECK(r.eng.state() == EngineState::Connected && r.tun.upCalls == 1 && r.tun.downCalls == 0);
    const auto res = r.eng.takeAttemptResult();
    CHECK(res.has_value() && res->connected && res->elapsedMs < 10'000);
}

// A live session (the night of 24.11: Connected at 08:29) lost while asleep - the tunnel reports itself gone in a dark
// wake: no failover start in the dark wake; on the awake edge the failover attempt starts once.
static void engineLiveLossWhileAsleep()
{
    Rig r;
    QString err;
    CHECK(r.eng.connect(err) && r.eng.onTunnelConnected() && r.eng.verifySucceeded());
    CHECK(r.eng.state() == EngineState::Connected && r.tun.upCalls == 1);
    (void)r.eng.takeAttemptResult();
    r.eng.setSystemAwake(false);
    r.now += 595'000;
    CHECK(r.eng.notifyConnectionLost()); // onDead(tunnel gone) -> a lost live session, failover asked
    r.ticks(19'000);
    r.eng.observeNetwork(wifi("bb")); // the BSSID of the dark wake
    r.ticks(11'000);
    CHECK(r.tun.upCalls == 1 && r.tun.downCalls == 0);
    r.now += 25'000'000;
    r.eng.observeNetwork(wifi("cc")); // the facade's evaluation: the network as it is now, first
    r.eng.setSystemAwake(true);
    CHECK(r.tun.upCalls == 2); // the failover's first leg, once, after the edge
    r.ticks(1000);
    CHECK(r.tun.upCalls == 2);
}

// The person stops while the system sleeps: the stop goes at once (it is never held).
static void engineStopWhileAsleep()
{
    Rig r;
    QString err;
    CHECK(r.eng.connect(err) && r.eng.onTunnelConnected() && r.eng.verifySucceeded());
    r.eng.setSystemAwake(false);
    r.eng.requestStop();
    CHECK(r.eng.state() == EngineState::Disconnected);
    r.ticks(5000);
    CHECK(r.tun.upCalls == 1);
}

// Never asleep (every platform but the macOS app): the same calls give the same engine as before - the start deadline
// runs out and the next leg starts.
static void engineNeverAsleepUnchanged()
{
    Rig r;
    QString err;
    CHECK(r.eng.connect(err) && r.tun.upCalls == 1);
    r.ticks(6000); // past the AmneziaWG start deadline (4.5 s): no handshake -> the next candidate
    CHECK(r.tun.downCalls == 1);
    r.eng.onTunnelDisconnected(); // the stop confirmed
    CHECK(r.tun.upCalls == 2);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    factAndGateOn24Nov();
    networkChangeBeforePoweredOn();
    missedPoweredOnHeals();
    appOwnsTheFact();
    killSwitch();
    wakeEvaluationRule();
    engineSleepMidStart();
    engineLiveLossWhileAsleep();
    engineStopWhileAsleep();
    engineNeverAsleepUnchanged();
    std::printf("system_sleep_check: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed ? 1 : 0;
}

// --- link stubs (as in facade_engine_check / engine_reliability_check): no network or store is needed ---
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
