// 5.1.109 (S4.1): TransportModeGate - when the user's stored transport-mode choice is in force.
// The gate is a plain reducer: every input is passed in (is Xray usable now, what the facade is doing),
// so each rule is driven here directly, without the engine or the facade. The engine's side (the pin,
// sessions it adopts, the pick paths) is transport_pick_check §17.
#include "../TransportModeGate.h"

#include <cstdio>

using namespace avpn;

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

using Pin = TransportModeGate::Pin;
static const TransportMode Auto = TransportMode::Auto, Awg = TransportMode::Awg, Xray = TransportMode::Xray;
static const QString kXray = QStringLiteral("xray"), kAwg = QStringLiteral("awg"), kAuto = QStringLiteral("auto");
static const QString kIdleWhy = QStringLiteral("idle"), kConfig = QStringLiteral("config");

// Nothing is running, the tunnel is observed down.
static ModeActivity idleDown()
{
    ModeActivity a;
    a.tunnel = ModeTunnel::Down;
    return a;
}
// A live session of this process: the intent is set, the engine is connected, the tunnel is up.
static ModeActivity liveSession()
{
    ModeActivity a;
    a.wantConnected = true;
    a.engineBusy = true;
    a.tunnel = ModeTunnel::Up;
    return a;
}
// Between the tap on Connect and connect(): the intent is set, the start is being prepared.
static ModeActivity startInFlight()
{
    ModeActivity a;
    a.wantConnected = true;
    a.preparingStart = true;
    a.tunnel = ModeTunnel::Down;
    return a;
}
// A cold start before the first tunnel status.
static ModeActivity notObserved()
{
    return ModeActivity();
}
static bool changed(const TransportModeGate::Outcome &o, TransportMode from, TransportMode to)
{
    return o.modeChanged && o.from == from && o.to == to;
}
static bool has(const QStringList &journal, const char *line)
{
    return journal.contains(QLatin1String(line));
}

// The stored value at load: a "xray" written by 138 or earlier may be stale and is dropped once.
static void storedValue()
{
    StoredModeChoice c = storedTransportChoice(kXray, /*byChoiceBuild=*/false);
    CHECK(c.mode == Auto && c.legacyReset);
    c = storedTransportChoice(kXray, true);
    CHECK(c.mode == Xray && !c.legacyReset);
    c = storedTransportChoice(kAwg, false); // "awg" was never rewritten by availability
    CHECK(c.mode == Awg && !c.legacyReset);
    c = storedTransportChoice(kAwg, true);
    CHECK(c.mode == Awg && !c.legacyReset);
    c = storedTransportChoice(kAuto, false);
    CHECK(c.mode == Auto && !c.legacyReset);
    c = storedTransportChoice(QString(), false); // first launch
    CHECK(c.mode == Auto && !c.legacyReset);
    c = storedTransportChoice(QStringLiteral("vless"), true);
    CHECK(c.mode == Auto && !c.legacyReset);

    TransportModeGate legacy;
    TransportModeGate::Outcome o = legacy.load(kXray, /*byChoiceBuild=*/false, /*xrayUsable=*/true);
    CHECK(o.storeChoice && o.storedMode == Auto);             // rewritten as "auto" with the marker
    CHECK(legacy.choice() == Auto && legacy.inForce() == Auto);
    CHECK(has(legacy.takeJournal(), "transport_mode_legacy_reset stored=xray"));
    o = legacy.observe(idleDown(), true, kIdleWhy);           // nothing comes back by itself
    CHECK(!o.modeChanged && legacy.inForce() == Auto && !legacy.choicePending(true));

    TransportModeGate chosen;                                 // chosen on 139 or later: honoured
    o = chosen.load(kXray, true, true);
    CHECK(!o.storeChoice && chosen.choice() == Xray);
    CHECK(chosen.takeJournal().isEmpty());
}

// "Auto" and "Amnezia" need nothing to be usable: in force from load, before the pin is restored
// (a pin the mode cannot serve is then refused by the engine and stays saved - nothing is asked here).
static void autoAndAmneziaAreInForceFromLoad()
{
    TransportModeGate awg;
    TransportModeGate::Outcome o = awg.load(kAwg, false, /*xrayUsable=*/false);
    CHECK(changed(o, Auto, Awg) && o.pin == Pin::Keep && !o.storeChoice);
    CHECK(awg.inForce() == Awg && awg.choice() == Awg && !awg.choicePending(false));
    CHECK(awg.takeJournal().isEmpty());                       // as before 139: no journal line
    o = awg.observe(notObserved(), true, kIdleWhy);           // no startup observation is waited for
    CHECK(!o.modeChanged && awg.inForce() == Awg);
    o = awg.observe(liveSession(), true, kConfig);            // Xray becoming usable changes nothing
    CHECK(!o.modeChanged && awg.inForce() == Awg && !awg.choicePending(true));

    TransportModeGate au;
    o = au.load(kAuto, false, true);
    CHECK(!o.modeChanged && o.pin == Pin::Keep && au.inForce() == Auto);
    o = au.observe(idleDown(), true, kIdleWhy);
    CHECK(!o.modeChanged && au.takeJournal().isEmpty());
}

// "Xray" at load waits for the startup observation: until then nobody knows whether a session of an
// earlier process is alive (review of 3dbe0361f: the choice was admitted in the constructor and by a
// config that arrived before the first status - under a live session, with the pin cleared).
static void xrayWaitsForTheStartupObservation()
{
    {   // iOS: the first status is the observation
        TransportModeGate g;
        TransportModeGate::Outcome o = g.load(kXray, true, /*xrayUsable=*/true);
        CHECK(!o.modeChanged && g.inForce() == Auto && g.choice() == Xray); // not in force by loading
        CHECK(g.choicePending(true));
        o = g.observe(notObserved(), true, kConfig);          // a fresh config before the first status
        CHECK(!o.modeChanged && o.pin == Pin::Keep && g.inForce() == Auto);
        CHECK(has(g.takeJournal(), "transport_mode_pending choice=xray in_force=auto why=config"));
        o = g.observe(notObserved(), true, kConfig);
        CHECK(!o.modeChanged && g.takeJournal().isEmpty());   // one line per wait
        o = g.observe(idleDown(), true, kIdleWhy);            // the first status: Disconnected
        CHECK(changed(o, Auto, Xray));
        CHECK(o.pin == Pin::Unapply);                         // a load admission never CLEARS a pin
        CHECK(g.inForce() == Xray && !g.choicePending(true));
        CHECK(has(g.takeJournal(), "transport_mode_effective from=auto to=xray why=start"));
        o = g.observe(idleDown(), true, kIdleWhy);
        CHECK(!o.modeChanged && o.pin == Pin::Keep && g.takeJournal().isEmpty());
    }
    {   // the macOS service reports no state while down: the end of the daemon probe is the observation
        TransportModeGate g;
        g.load(kXray, true, true);
        TransportModeGate::Outcome o = g.observe(notObserved(), true, kIdleWhy);
        CHECK(!o.modeChanged && !g.idle(notObserved()));      // Unknown is NOT idle before the probe
        o = g.startupObserved(notObserved(), true);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Unapply);
        CHECK(g.idle(notObserved()));                         // after it "no state" means down
        CHECK(has(g.takeJournal(), "transport_mode_effective from=auto to=xray why=start"));
    }
    {   // the user tapped Connect before the observation: the session runs under Auto, the choice is
        // admitted when that session ends - still a load admission (the pin is not cleared)
        TransportModeGate g;
        g.load(kXray, true, true);
        TransportModeGate::Outcome o = g.observe(startInFlight(), true, kIdleWhy);
        CHECK(!o.modeChanged);
        g.sessionStartedByUs();
        o = g.startupObserved(liveSession(), true);
        CHECK(!o.modeChanged && g.inForce() == Auto);
        o = g.observe(liveSession(), true, kIdleWhy);
        CHECK(!o.modeChanged && g.inForce() == Auto);
        o = g.observe(idleDown(), true, kIdleWhy);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Unapply);
        CHECK(has(g.takeJournal(), "transport_mode_effective from=auto to=xray why=start"));
    }
    {   // Xray is not usable at load and does not become usable: nothing waits, nothing is journalled
        TransportModeGate g;
        g.load(kXray, true, /*xrayUsable=*/false);
        CHECK(!g.choicePending(false));
        TransportModeGate::Outcome o = g.observe(idleDown(), false, kIdleWhy);
        CHECK(!o.modeChanged && g.inForce() == Auto && g.choice() == Xray);
        CHECK(g.takeJournal().isEmpty());
    }
}

// "Nothing is running": every one of these holds the admission back (finding 1 of the review of
// d5d739403 - between the tap and connect(); finding 2 - under a live session).
static void admissionOnlyWhileNothingIsRunning()
{
    struct Case { const char *what; ModeActivity a; };
    ModeActivity intent = idleDown();              intent.wantConnected = true;     // backoff / restart between runtimes
    ModeActivity op = idleDown();                  op.operationInFlight = true;     // our stop in flight, service install
    ModeActivity prep = idleDown();                prep.preparingStart = true;
    ModeActivity paused = idleDown();              paused.paused = true;            // pause-for-shopping
    ModeActivity engine = idleDown();              engine.engineBusy = true;        // the engine's own switch
    ModeActivity up = idleDown();                  up.tunnel = ModeTunnel::Up;
    ModeActivity moving = idleDown();              moving.tunnel = ModeTunnel::Moving;
    const Case busy[] = {
        {"the intent is set", intent}, {"an operation is in flight", op}, {"a start is being prepared", prep},
        {"paused", paused}, {"the engine is busy", engine}, {"the tunnel is up", up},
        {"the tunnel is moving", moving}, {"a start in flight", startInFlight()}, {"a live session", liveSession()},
    };
    for (const Case &c : busy) {
        TransportModeGate g;
        g.load(kXray, true, /*xrayUsable=*/false);            // Xray frozen at load ...
        g.observe(idleDown(), false, kIdleWhy);               // (the startup observation is done)
        CHECK(!g.idle(c.a));
        TransportModeGate::Outcome o = g.observe(c.a, /*xrayUsable=*/true, kConfig); // ... allowed again now
        if (o.modeChanged || g.inForce() != Auto || o.pin != Pin::Keep) {
            std::printf("FAIL admission while %s\n", c.what);
            ++g_fail;
        }
        ++g_total;
        CHECK(g.choicePending(true));
        CHECK(has(g.takeJournal(), "transport_mode_pending choice=xray in_force=auto why=config"));
        o = g.observe(c.a, true, kConfig);
        CHECK(!o.modeChanged && g.takeJournal().isEmpty());   // one line per wait
        o = g.observe(idleDown(), true, kIdleWhy);            // ... and it comes when everything stopped
        CHECK(changed(o, Auto, Xray));
        CHECK(o.pin == Pin::Clear);                           // after a real gain the pin rule of a mode change
        CHECK(has(g.takeJournal(), "transport_mode_effective from=auto to=xray why=idle"));
    }
    TransportModeGate g;
    CHECK(!g.idle(notObserved()));                            // not observed yet: not idle
    CHECK(g.idle(idleDown()));
}

// A real gain (Xray became usable during the run) against a choice that was usable since load: only
// the first clears the pin and has it stored cleared. Review of 3dbe0361f, finding A: every cold start
// ran the pin rule against the stored pool and erased the pin on a transient pool state.
static void pinIsClearedOnlyAfterARealGain()
{
    {   // usable since load -> Unapply, whatever delayed the admission
        TransportModeGate g;
        g.load(kXray, true, true);
        TransportModeGate::Outcome o = g.observe(idleDown(), true, kIdleWhy);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Unapply);
    }
    {   // not usable at load, a fresh config allows it while idle -> Clear, why=config
        TransportModeGate g;
        g.load(kXray, true, false);
        g.observe(idleDown(), false, kIdleWhy);
        TransportModeGate::Outcome o = g.observe(idleDown(), true, kConfig);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Clear);
        CHECK(has(g.takeJournal(), "transport_mode_effective from=auto to=xray why=config"));
    }
    {   // the gain arrives BEFORE the startup observation: it waits, and is still a gain afterwards
        TransportModeGate g;
        g.load(kXray, true, false);
        TransportModeGate::Outcome o = g.observe(notObserved(), true, kConfig);
        CHECK(!o.modeChanged && g.inForce() == Auto);
        o = g.startupObserved(notObserved(), true);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Clear);
        CHECK(has(g.takeJournal(), "transport_mode_effective from=auto to=xray why=idle")); // not "start": a gain
    }
    {   // a gain that is lost again before the admission is no gain
        TransportModeGate g;
        g.load(kXray, true, false);
        g.observe(idleDown(), false, kIdleWhy);
        g.observe(liveSession(), true, kConfig);              // allowed under a session: waits
        TransportModeGate::Outcome o = g.observe(liveSession(), false, kConfig); // and forbidden again
        CHECK(!o.modeChanged && !g.choicePending(false));
        o = g.observe(idleDown(), false, kIdleWhy);
        CHECK(!o.modeChanged && g.inForce() == Auto);
        o = g.observe(idleDown(), true, kConfig);             // a new gain, while idle
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Clear);
    }
    {   // Auto is admitted after a suspension: Auto never touches a pin beyond Unapply
        TransportModeGate g;
        g.load(kAwg, false, true);
        g.observe(idleDown(), true, kIdleWhy);
        g.sessionAdopted(kXray, true);                        // a live Xray session of the OS: Amnezia -> Auto
        CHECK(g.inForce() == Auto && g.choicePending(true));
        TransportModeGate::Outcome o = g.observe(idleDown(), true, kIdleWhy);
        CHECK(changed(o, Auto, Awg) && o.pin == Pin::Unapply); // back, the saved pin is not erased
    }
}

// Xray stops being usable: at once, whatever is running - the server switch must act on the next pick.
static void lossIsImmediateAndStaysForTheSession()
{
    TransportModeGate g;
    g.load(kXray, true, true);
    g.observe(idleDown(), true, kIdleWhy);
    CHECK(g.inForce() == Xray);
    g.takeJournal();
    g.sessionStartedByUs();
    TransportModeGate::Outcome o = g.observe(liveSession(), /*xrayUsable=*/false, kConfig);
    CHECK(changed(o, Xray, Auto) && o.pin == Pin::Keep);      // under the live session, at once
    CHECK(g.choice() == Xray);                                // the choice is kept (138: lost)
    CHECK(has(g.takeJournal(), "transport_mode_effective from=xray to=auto why=config"));
    o = g.observe(liveSession(), true, kConfig);              // allowed again under the same session
    CHECK(!o.modeChanged && g.inForce() == Auto);             // no return under it
    CHECK(has(g.takeJournal(), "transport_mode_pending choice=xray in_force=auto why=config"));
    o = g.observe(idleDown(), true, kIdleWhy);
    CHECK(changed(o, Auto, Xray) && o.pin == Pin::Clear);     // a real gain

    TransportModeGate pick;                                   // the engine notices the loss at a pick
    pick.set(Xray, true);
    pick.writeDownLoss(true);
    CHECK(pick.inForce() == Xray && pick.takeJournal().isEmpty());
    pick.writeDownLoss(false);
    CHECK(pick.inForce() == Auto && pick.choice() == Xray);
    CHECK(has(pick.takeJournal(), "transport_mode_effective from=xray to=auto why=pick"));
    pick.writeDownLoss(false);
    CHECK(pick.takeJournal().isEmpty());
    o = pick.observe(liveSession(), true, kConfig);           // usable again under the session
    CHECK(!o.modeChanged && pick.inForce() == Auto);
    o = pick.observe(idleDown(), true, kIdleWhy);
    CHECK(changed(o, Auto, Xray) && o.pin == Pin::Clear);
    TransportModeGate awg;                                    // Amnezia does not depend on Xray
    awg.set(Awg, true);
    awg.writeDownLoss(false);
    CHECK(awg.inForce() == Awg);
}

// A tap on the selector.
static void tap()
{
    TransportModeGate g;
    g.load(kAuto, false, false);
    TransportModeGate::Tap t = g.tap(Xray, /*xrayUsable=*/false);
    CHECK(t.refused && !t.noop && g.choice() == Auto && g.inForce() == Auto); // nothing changed
    t = g.tap(Auto, false);
    CHECK(t.noop && !t.refused);
    t = g.tap(Xray, true);
    CHECK(!t.refused && !t.noop && g.choice() == Xray && g.inForce() == Xray); // at once
    t = g.tap(Xray, true);
    CHECK(t.noop);
    t = g.tap(Awg, true);
    CHECK(!t.noop && g.choice() == Awg && g.inForce() == Awg);

    TransportModeGate waiting;                                // the choice waits under a live session
    waiting.load(kXray, true, false);
    waiting.observe(idleDown(), false, kIdleWhy);
    waiting.observe(liveSession(), true, kConfig);
    CHECK(waiting.inForce() == Auto && waiting.choicePending(true));
    t = waiting.tap(Xray, true);                              // the user taps it: in force now
    CHECK(!t.noop && !t.refused && waiting.inForce() == Xray && !waiting.choicePending(true));

    TransportModeGate dormant;                                // "Auto" tapped while the chosen Xray sleeps
    dormant.load(kXray, true, false);
    dormant.observe(idleDown(), false, kIdleWhy);
    t = dormant.tap(Auto, false);
    CHECK(!t.noop && dormant.choice() == Auto);               // a new choice, stored by the facade
    TransportModeGate::Outcome o = dormant.observe(idleDown(), true, kConfig);
    CHECK(!o.modeChanged && dormant.inForce() == Auto);       // and Xray does not come back
}

// macOS service: tun2socks next to the service. Loss at once, gain only while nothing is running -
// a service updated inside Connect must not add Xray between the tap and connect().
static void runtimeGate()
{
    TransportModeGate g;
    g.load(kAuto, false, false);
    g.observe(idleDown(), false, kIdleWhy);
    CHECK(g.nextRuntimeGate(/*readyNow=*/true, /*present=*/true, liveSession()));
    CHECK(!g.nextRuntimeGate(true, false, liveSession()));    // lost under a session: off at once
    CHECK(!g.nextRuntimeGate(true, false, startInFlight()));
    CHECK(!g.nextRuntimeGate(true, false, idleDown()));
    CHECK(!g.nextRuntimeGate(false, true, startInFlight()));  // the service got it inside Connect
    CHECK(!g.nextRuntimeGate(false, true, liveSession()));
    ModeActivity install = idleDown();
    install.wantConnected = true;
    install.operationInFlight = true;                         // the service is being installed
    CHECK(!g.nextRuntimeGate(false, true, install));
    CHECK(g.nextRuntimeGate(false, true, idleDown()));        // ... Xray is back for the next start
    CHECK(!g.nextRuntimeGate(false, false, idleDown()));
    TransportModeGate cold;                                   // before the startup observation: no gain
    CHECK(!cold.nextRuntimeGate(false, true, notObserved()));
    CHECK(cold.nextRuntimeGate(true, true, notObserved()));
}

// A live session this process did not start (the GUI restarted and the tunnel lived on; the OS started
// it). Review of 3dbe0361f, findings B and C.
static void sessionsThisProcessDidNotStart()
{
    {   // found at startup, transport unknown (an Xray session carries no hint): it takes the choice
        TransportModeGate g;
        g.load(kXray, true, true);
        TransportModeGate::Outcome o = g.sessionAdopted(QString(), true);
        CHECK(changed(o, Auto, Xray));
        CHECK(o.pin == Pin::Unapply);                         // finding C: the pin is never cleared here
        CHECK(has(g.takeJournal(), "transport_mode_effective from=auto to=xray why=adopted_session"));
        // finding B: its identity is resolved later (a pool refresh) and it is an AmneziaWG session
        o = g.sessionTransportKnown(kAwg, true);
        CHECK(changed(o, Xray, Auto) && o.pin == Pin::Keep);
        CHECK(g.choice() == Xray);
        CHECK(has(g.takeJournal(), "transport_mode_effective from=xray to=auto why=adopted_session"));
        o = g.sessionTransportKnown(kAwg, true);              // idempotent
        CHECK(!o.modeChanged && g.inForce() == Auto && g.takeJournal().isEmpty());
        o = g.observe(liveSession(), true, kIdleWhy);         // nothing under the session
        CHECK(!o.modeChanged && g.inForce() == Auto);
        o = g.observe(idleDown(), true, kIdleWhy);            // the session ended: the choice returns
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Unapply);
    }
    {   // found at startup with a known transport
        TransportModeGate xr;
        xr.load(kXray, true, true);
        TransportModeGate::Outcome o = xr.sessionAdopted(kXray, true);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Unapply);
        TransportModeGate aw;                                 // an AmneziaWG session, Xray chosen: Auto
        aw.load(kXray, true, true);
        o = aw.sessionAdopted(kAwg, true);
        CHECK(!o.modeChanged && o.pin == Pin::Keep && aw.inForce() == Auto);
        CHECK(aw.takeJournal().isEmpty());
        o = aw.observe(liveSession(), true, kIdleWhy);
        CHECK(!o.modeChanged && aw.inForce() == Auto);        // not under the session
        o = aw.observe(idleDown(), true, kIdleWhy);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Unapply);
        CHECK(has(aw.takeJournal(), "transport_mode_pending choice=xray in_force=auto why=idle"));
    }
    {   // "Amnezia" in force from load, the adopted session runs on Xray: Auto for the session
        TransportModeGate g;
        g.load(kAwg, false, true);
        TransportModeGate::Outcome o = g.sessionAdopted(kXray, true);
        CHECK(changed(o, Awg, Auto) && o.pin == Pin::Keep && g.choice() == Awg);
        TransportModeGate fits;
        fits.load(kAwg, false, true);
        o = fits.sessionAdopted(kAwg, true);
        CHECK(!o.modeChanged && fits.inForce() == Awg);
        TransportModeGate unknown;
        unknown.load(kAwg, false, true);
        o = unknown.sessionAdopted(QString(), true);
        CHECK(!o.modeChanged && unknown.inForce() == Awg);    // unknown is not judged
    }
    {   // the choice was NOT usable when this run began: the adopted session does not take it
        TransportModeGate g;
        g.load(kXray, true, false);
        g.observe(notObserved(), true, kConfig);              // a real gain before the observation
        TransportModeGate::Outcome o = g.sessionAdopted(QString(), true);
        CHECK(!o.modeChanged && g.inForce() == Auto);
        o = g.observe(idleDown(), true, kIdleWhy);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Clear);
    }
    {   // a session this process started is never re-judged (a tap changed the mode, the restart is on its way)
        TransportModeGate g;
        g.load(kAuto, false, true);
        g.observe(idleDown(), true, kIdleWhy);
        g.sessionStartedByUs();
        g.tap(Xray, true);
        TransportModeGate::Outcome o = g.sessionTransportKnown(kAwg, true);
        CHECK(!o.modeChanged && g.inForce() == Xray);
    }
    {   // this process has already started a session: a later adoption does not admit a waiting choice
        TransportModeGate g;
        g.load(kXray, true, true);
        g.sessionStartedByUs();                               // Connect tapped before the observation
        g.observe(liveSession(), true, kIdleWhy);
        TransportModeGate::Outcome o = g.sessionAdopted(QString(), true); // re-adopted after an Error
        CHECK(!o.modeChanged && g.inForce() == Auto);
        o = g.observe(idleDown(), true, kIdleWhy);
        CHECK(changed(o, Auto, Xray) && o.pin == Pin::Unapply);
    }
    {   // an adoption is a startup observation: afterwards "no state" means down
        TransportModeGate g;
        g.load(kXray, true, true);
        CHECK(!g.idle(notObserved()));
        g.sessionAdopted(kAwg, true);
        CHECK(g.idle(notObserved()));
    }
    {   // Xray is lost while a foreign Xray session is up
        TransportModeGate g;
        g.load(kXray, true, true);
        g.sessionAdopted(kXray, true);
        TransportModeGate::Outcome o = g.sessionTransportKnown(kXray, /*xrayUsable=*/false);
        CHECK(changed(o, Xray, Auto));
    }
    CHECK(sessionFitsMode(Auto, kAwg) && sessionFitsMode(Auto, kXray) && sessionFitsMode(Auto, QString()));
    CHECK(sessionFitsMode(Xray, kXray) && !sessionFitsMode(Xray, kAwg) && sessionFitsMode(Xray, QString()));
    CHECK(sessionFitsMode(Awg, kAwg) && !sessionFitsMode(Awg, kXray) && sessionFitsMode(Awg, QString()));
}

// "Nothing is running any more" is reported once per entry (the macOS facade looks at tun2socks then).
static void idleEntry()
{
    TransportModeGate g;
    g.load(kAuto, false, false);
    TransportModeGate::Outcome o = g.observe(notObserved(), false, kIdleWhy);
    CHECK(!o.idleEntered);
    o = g.observe(idleDown(), false, kIdleWhy);
    CHECK(o.idleEntered);
    o = g.observe(idleDown(), false, kIdleWhy);
    CHECK(!o.idleEntered);
    o = g.observe(liveSession(), false, kIdleWhy);
    CHECK(!o.idleEntered);
    o = g.observe(idleDown(), false, kIdleWhy);
    CHECK(o.idleEntered);
}

// Before load nothing is admitted (the cached config is applied earlier in the facade's constructor).
static void nothingBeforeLoad()
{
    TransportModeGate g;
    TransportModeGate::Outcome o = g.observe(idleDown(), true, kConfig);
    CHECK(!o.modeChanged && g.inForce() == Auto && g.takeJournal().isEmpty());
    o = g.load(kXray, true, true);                            // usable at load: not a gain
    o = g.observe(idleDown(), true, kIdleWhy);
    CHECK(changed(o, Auto, Xray) && o.pin == Pin::Unapply);
}

int main()
{
    storedValue();
    autoAndAmneziaAreInForceFromLoad();
    xrayWaitsForTheStartupObservation();
    admissionOnlyWhileNothingIsRunning();
    pinIsClearedOnlyAfterARealGain();
    lossIsImmediateAndStaysForTheSession();
    tap();
    runtimeGate();
    sessionsThisProcessDidNotStart();
    idleEntry();
    nothingBeforeLoad();
    if (g_fail) {
        std::printf("transport_mode_gate_check: %d FAILED of %d\n", g_fail, g_total);
        return 1;
    }
    std::printf("transport_mode_gate_check: OK (%d checks)\n", g_total);
    return 0;
}
