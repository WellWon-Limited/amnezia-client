// client/core/serviceEngine/SystemAwake.h
// AVPN (owner's Mac 24.11.2026, cause F of the Mac diagnosis): the engine's one fact "the system is fully awake" and
// the one gate of the engine's own automation. [header-only, QtCore; pure: no timers, no I/O]
//
// What happened: with the lid closed the Mac makes a Power Nap dark wake every ~15 min. Wi-Fi associates for a few
// seconds, the root service reports a BSSID change (networkChanged), and the engine probed the tunnel, found it dead
// (nothing passes in a dark wake) and restarted it - at 08:39 and again at 08:41; the second start was issued in the
// second the Mac went back to sleep, the core came up without an uplink, and its data check stayed "checking" for
// 1004 s, until the next dark wake. The root service's wakeup (kIOMessageSystemHasPoweredOn) is not delivered for a
// dark wake (service log 24.11: no power callback between "will sleep" 08:29:21 and the lid-open wake 15:38:13,
// across six dark wakes), so nothing told the engine that the system was not awake.
//
// The fact: asleep from the platform's "will sleep" until a proof of a FULL wake. Any one proof heals it:
//  - NSWorkspaceDidWakeNotification in the app (a dark wake does not post it: DTS, developer forums thread 770517 -
//    "basically means exactly what you're asking for - the system is 'fully awake' and apps should operate normally");
//  - NSWorkspaceScreensDidWakeNotification in the app (a dark wake has no screen on);
//  - the root service's wakeup signal (IOMessage.h, kIOMessageSystemHasPoweredOn: "Announces that the system and its
//    devices have woken up"; per DTS not delivered for a dark wake, "Dark Wake isn't considered 'On'");
//  - a person's press or key in the app's window (nobody can press anything in a dark wake).
// No timer ends the sleep: a missed notification is healed by the next proof of any kind, never by a guess. The
// macOS SDK has no public call to read "fully awake" on demand (IOPMLib.h: none; DTS: "we don't have any API for
// detecting DarkWake"), so the fact can only follow these events.
// Owner of the fact: the app process (the only one that acts on it). It observes the system itself from its launch -
// a person launches it, so it starts awake - and needs nothing from the service to know the value after reconnecting
// to it; an older service changes nothing. Every platform without a "will sleep" source (iOS, Android, Windows, Linux,
// the macOS Network Extension build) never leaves "awake".
//
// The gate (hold): while asleep the engine does nothing on its own - no start, no restart, no probe, no failover, no
// data check, no seat renewal. One call per mechanism, at its own entry (the facade: reconcile, the service's wake
// and network events, the wake-restart retry, the health tick, the live probe, the data check), and the attempt
// owner reads the same fact in its context at every event (path/AttemptOwner.h "System asleep"). A person's action
// is not held: a press in the window (from the window system - personInputProof) is itself a proof of a full wake and
// comes before the action. A call made by code is not a person: a programmatic start() while asleep is held like any
// automatic start (reconcile) and runs on the awake edge; stop() stops at once (it is never held). Code that speaks
// for a person (a test command channel) says so through AvpnEngineQml::notePersonPresent() first.
// The awake edge: exactly one evaluation (wakeEvaluation): the network as it is now (the path engine's generation
// decides whether it is another one), the attempt owner's held step, a held wake-restart retry once, one liveness
// probe of a live session (wakeProbeDecision - the same decision as every other entry into the probe), the intent
// once (reconcile). What was held is only journalled - a networkChanged of a dark wake is never lost, because the
// evaluation always looks at the network and the tunnel as they are at the full wake.
#pragma once

#include <QEvent>
#include <QString>
#include <QStringList>
#include <QtGlobal>

namespace avpn {

// One observation of the system's sleep state.
enum class SleepSignal : quint8 {
    WillSleep,        // the system is going to sleep (NSWorkspaceWillSleepNotification)
    DidWake,          // fully awake (NSWorkspaceDidWakeNotification)
    ScreensDidWake,   // a screen woke (NSWorkspaceScreensDidWakeNotification)
    ServicePoweredOn, // the root service's wakeup (kIOMessageSystemHasPoweredOn)
    PersonInput,      // a press or key in the app's window
};

inline const char *sleepSignalName(SleepSignal s)
{
    switch (s) {
    case SleepSignal::WillSleep: return "will_sleep";
    case SleepSignal::DidWake: return "did_wake";
    case SleepSignal::ScreensDidWake: return "screens_did_wake";
    case SleepSignal::ServicePoweredOn: return "service_powered_on";
    case SleepSignal::PersonInput: return "person_input";
    }
    return "";
}

// The mechanisms the gate holds - named in the journal line of the awake edge.
enum class SleepHeld : unsigned {
    Reconcile = 1u << 0,   // a start, restart or stop of the tunnel (reconcile)
    TunnelProbe = 1u << 1, // the service's wakeup / networkChanged: the liveness probe (and its restart)
    WakeRetry = 1u << 2,   // the wake restart's retry when the network returns
    HealthTick = 1u << 3,  // health (failover), seat renewals, standby pack, traffic refresh
    LiveProbe = 1u << 4,   // the live probe through the tunnel (bars, the Xray DEAD criterion)
    DataCheck = 1u << 5,   // the data check of a raised path
};

inline QString sleepHeldNames(unsigned mask)
{
    static const struct { SleepHeld bit; const char *name; } kNames[] = {
        { SleepHeld::Reconcile, "reconcile" },     { SleepHeld::TunnelProbe, "tunnel_probe" },
        { SleepHeld::WakeRetry, "wake_retry" },    { SleepHeld::HealthTick, "health_tick" },
        { SleepHeld::LiveProbe, "live_probe" },    { SleepHeld::DataCheck, "data_check" },
    };
    QStringList out;
    for (const auto &n : kNames)
        if (mask & unsigned(n.bit))
            out << QLatin1String(n.name);
    return out.isEmpty() ? QStringLiteral("-") : out.join(QLatin1Char(','));
}

enum class SleepEdge : quint8 { None, Slept, Woke };

// The one decision of the wake liveness probe (CONNECT-INVARIANTS §18), for EVERY entry into it: the awake edge's
// evaluation, the service's wakeup, the service's networkChanged - and for every step of a chain in flight. Only a
// live session the person wants is probed: intentOn (the person wants the VPN), tunnelUp (the platform reports the
// tunnel connected) and engineConnected (the engine holds it as a live session - an attempt in flight, its data check
// included, is judged by its own check, never by this probe: review F2 of 558d79086, a probe started beside a running
// check could restart a VPN whose check then passed). probing: a chain is already running - joined, never a second.
//
// The service's wakeup (kIOMessageSystemHasPoweredOn) when the fact is ALREADY awake - a full wake whose edge another
// proof made a moment earlier (NSWorkspace did wake comes first), or one the app never saw go to sleep (a missed
// "will sleep") - means what it meant before the gate: a reason to check a live session, through this decision like
// every other entry. It is never a second evaluation of the edge and never resumes a wake restart (the edge did, once).
enum class WakeProbe : quint8 { None, Start, Joined };

inline bool liveSessionToProbe(bool intentOn, bool tunnelUp, bool engineConnected)
{
    return intentOn && tunnelUp && engineConnected;
}

inline WakeProbe wakeProbeDecision(bool intentOn, bool tunnelUp, bool engineConnected, bool probing)
{
    if (!liveSessionToProbe(intentOn, tunnelUp, engineConnected))
        return WakeProbe::None;
    return probing ? WakeProbe::Joined : WakeProbe::Start;
}

// What the one evaluation of the awake edge does (the facade carries it out, in this order).
struct WakeEvaluation {
    bool observeNetwork = true;     // the platform network as it is now, once: the path engine first, then the Scanner
    bool resumeOwner = true;        // the attempt owner takes the step it held (a next leg, the check again, a lost session)
    bool resumeWakeRestart = false; // a wake restart that waits for the network goes on, once (its retry was held)
    WakeProbe probe = WakeProbe::None; // the liveness probe of a live session (wakeProbeDecision)
    bool probeTunnel = false;       // probe == Start
    bool reconcile = true;          // the intent once (a start or a restart that was held)
};

// intentOn / tunnelUp / engineConnected / probing: as in wakeProbeDecision. wakeRestartPending: our own wake restart
// failed before the sleep and waits for the network to return (its retry, the wake restart's wakeKick, may have been
// held in a dark wake - review F1 of 558d79086: the edge only reconciled, and with the intent dropped by the failed
// attempt the VPN stayed off until a tap). The retry itself decides its tries and a tunnel already up (wakeKick);
// the edge resumes it exactly once - the edge is one per sleep.
inline WakeEvaluation wakeEvaluation(bool intentOn, bool tunnelUp, bool engineConnected, bool probing,
                                     bool wakeRestartPending)
{
    WakeEvaluation e;
    e.resumeWakeRestart = wakeRestartPending;
    e.probe = wakeProbeDecision(intentOn, tunnelUp, engineConnected, probing);
    e.probeTunnel = e.probe == WakeProbe::Start;
    return e;
}

// A person's input as a proof of a full wake (AvpnSystemSleep.mm): a press or a key that came from the window system.
// Qt (qevent.html, QEvent::spontaneous): "Returns true if the event originated outside the application (a system
// event); otherwise returns false" - and "it is also possible to manually send events using
// QCoreApplication::sendEvent() and QCoreApplication::postEvent() (spontaneous() returns false)". An event the code
// sent or posted proves nothing about a person (review F3 of 558d79086). A test channel that must count as "the person
// is here" calls AvpnEngineQml::notePersonPresent() - it never fakes input events.
inline bool personInputProof(QEvent::Type type, bool spontaneous)
{
    if (!spontaneous)
        return false;
    switch (type) {
    case QEvent::MouseButtonPress:
    case QEvent::KeyPress:
    case QEvent::TouchBegin:
    case QEvent::TabletPress:
        return true;
    default:
        return false;
    }
}

class SystemAwake
{
public:
    bool awake() const { return m_awake; }

    // One observation at nowMs. gateEnabled = the kill switch features.system_sleep_gate: off, "will sleep" is not
    // taken (always awake, the behaviour before the gate), and a sleep already taken ends at the next observation.
    SleepEdge note(SleepSignal s, qint64 nowMs, bool gateEnabled = true)
    {
        if (!gateEnabled) {
            if (m_awake)
                return SleepEdge::None;
            return wake(s, nowMs);
        }
        if (s == SleepSignal::WillSleep) {
            if (!m_awake)
                return SleepEdge::None; // already asleep (a second "will sleep" of the same night)
            m_awake = false;
            m_asleepSinceMs = nowMs;
            m_held = 0;
            m_heldCount = 0;
            ++m_sleeps;
            return SleepEdge::Slept;
        }
        if (m_awake)
            return SleepEdge::None; // another proof of what is already true
        return wake(s, nowMs);
    }

    // The gate: true = the caller must not act now (the system is not fully awake). What was held is remembered for
    // the journal of the awake edge; it is not replayed (the edge evaluates the present once).
    bool hold(SleepHeld what)
    {
        if (m_awake)
            return false;
        m_held |= unsigned(what);
        ++m_heldCount;
        return true;
    }

    unsigned heldMask() const { return m_held; }       // since the last "will sleep"
    int heldCount() const { return m_heldCount; }
    qint64 asleepSinceMs() const { return m_asleepSinceMs; }
    qint64 lastAsleepMs() const { return m_lastAsleepMs; } // the length of the last sleep (at its awake edge)
    SleepSignal wokeBy() const { return m_wokeBy; }
    int sleeps() const { return m_sleeps; }

private:
    SleepEdge wake(SleepSignal s, qint64 nowMs)
    {
        m_awake = true;
        m_wokeBy = s;
        m_lastAsleepMs = m_asleepSinceMs >= 0 && nowMs >= m_asleepSinceMs ? nowMs - m_asleepSinceMs : -1;
        m_asleepSinceMs = -1;
        return SleepEdge::Woke;
    }

    bool m_awake = true; // the app starts awake: a person launched it
    unsigned m_held = 0;
    int m_heldCount = 0;
    qint64 m_asleepSinceMs = -1;
    qint64 m_lastAsleepMs = -1;
    SleepSignal m_wokeBy = SleepSignal::DidWake;
    int m_sleeps = 0;
};

} // namespace avpn
