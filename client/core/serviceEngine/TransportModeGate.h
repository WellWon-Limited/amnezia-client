// client/core/serviceEngine/TransportModeGate.h
// AVPN serviceEngine - when the user's stored transport-mode choice is IN FORCE. [header-only, QtCore values]
//
// 5.1.109 (plan step S4.1; defect of 12.11.2026 on 138; reviews of d5d739403, 3dbe0361f+66dc21bb1, df7f49db8).
// On 138 the engine had one value, the mode in force: a stored "Xray" read while the cached config froze
// Xray (every cold start) became Auto for the whole run and never came back. The fix keeps the CHOICE
// apart from the mode IN FORCE; this class is the whole rule of how the mode in force follows the
// choice. It is a plain reducer: events in, the new mode in force and what to do with the pin out. It
// reads nothing global - whether Xray is usable right now, and what the facade is doing, are passed in
// with every event - so it is tested exhaustively without the engine or the facade
// (tests/transport_mode_gate_check.cpp). The engine owns one instance (ServiceEngine::m_modeGate) and
// feeds the session events itself; the facade only forwards its own events and applies the outcome.
//
// The mode in force changes in these ways only:
//  1. a tap on the selector - at once, whatever is running (tap);
//  2. Xray stops being usable (the server switch, the trust in the cached config ran out, the macOS
//     service lost tun2socks) - at once: it reads as Auto and stays Auto for what is running;
//  3. the choice is ADMITTED - the only way a usable "Xray" comes (back) into force:
//      - "Auto" and "Amnezia" need nothing to be usable: in force from load, as before 139;
//      - "Xray" at load waits for the STARTUP OBSERVATION (the first tunnel status on iOS, the end of
//        the daemon probe on the macOS service): until then nobody knows whether a session of an
//        earlier process is alive. No session - admitted. A live session that this process did not
//        start takes the choice unless its transport is KNOWN and the choice excludes it;
//      - later, only while NOTHING IS RUNNING (idle): no intent to be connected - a start in flight,
//        a live session, an app-side restart and the backoff between attempts all hold the intent -
//        no operation, no start being prepared, no pause-for-shopping, the engine in a terminal
//        phase, the tunnel observed down. Never between the tap and connect(), never under a session.
//  4. a session this process did not start turns out to run on a transport the mode in force
//     excludes - it keeps Auto; the choice is admitted when the engine is idle again.
//
// The pin (a country the admitted mode cannot serve - ServiceEngine::pinLacksTransport): an admission
// only UN-APPLIES it - the engine drops it, the SAVED pin stays, exactly what the order "mode first,
// then restorePin" gave before 139 (a refused pin stays saved) - and it comes back when the pool or
// the mode can serve it again. No admission ever erases the saved pin: only the user's tap on a mode
// does (as on 138). Review of df7f49db8: an admission after a gain used to store the pin cleared, so
// whether the pin survived depended on the age of the cached config, not on anything the user did.
//
// Upstream Amnezia has no counterpart (no server kill-switch, no transport mode).
#pragma once

#include "NodeRotation.h" // TransportMode and its names only - nothing in this file reads TuningStore

#include <QString>
#include <QStringList>
#include <utility>

namespace avpn {

// How the tunnel looks to the facade.
enum class ModeTunnel {
    NotObserved, // no status seen in this run yet
    Down,        // observed down, a start may act from it
    Up,          // connected
    Moving,      // connecting, disconnecting, our stop not confirmed, an error that needs a status first
};

// What the facade is doing - one snapshot taken by one function of the facade
// (AvpnEngineQml::modeActivity); engineBusy is filled in by the engine itself.
struct ModeActivity {
    bool wantConnected = false;     // the intent to be connected
    bool operationInFlight = false; // start or stop in flight, the macOS service being installed
    bool preparingStart = false;
    bool paused = false;            // pause-for-shopping: the session comes back by itself
    bool engineBusy = false;        // the engine is not in Disconnected / Error
    ModeTunnel tunnel = ModeTunnel::NotObserved;
};

// The stored value of avpn/transportMode at load. byChoiceBuild - the marker avpn/transportModeByChoice
// written next to it by every build that stores the user's CHOICE (>= 139). A "xray" without the marker
// was written by 138 or earlier and may be stale: there a tap on "Auto" while the engine already read
// Auto (Xray frozen after a cold start) returned before storing, and the selector was hidden in that
// state - the user could not take the choice back. Such a value reads as Auto once and is rewritten;
// the user selects Xray again. "awg" was never rewritten by availability and is honoured as it is.
struct StoredModeChoice {
    TransportMode mode = TransportMode::Auto;
    bool legacyReset = false;
};
inline StoredModeChoice storedTransportChoice(const QString &stored, bool byChoiceBuild)
{
    StoredModeChoice c;
    if (stored == QLatin1String("awg")) {
        c.mode = TransportMode::Awg;
    } else if (stored == QLatin1String("xray")) {
        if (byChoiceBuild)
            c.mode = TransportMode::Xray;
        else
            c.legacyReset = true;
    }
    return c;
}

// A session whose transport is known ("awg" | "xray"; empty = unknown) under a mode: an unknown
// transport is not judged (an adopted Xray session usually carries no hint, the macOS service none).
inline bool sessionFitsMode(TransportMode mode, const QString &sessionProto)
{
    if (mode == TransportMode::Auto || sessionProto.isEmpty())
        return true;
    const bool xraySession = sessionProto == QLatin1String("xray");
    return mode == TransportMode::Xray ? xraySession : !xraySession;
}

class TransportModeGate
{
public:
    enum class Pin {
        Keep,    // nothing to do
        Unapply, // drop a pin the mode cannot serve from the engine, the saved pin stays
    };
    struct Outcome {
        bool modeChanged = false;
        TransportMode from = TransportMode::Auto;
        TransportMode to = TransportMode::Auto;
        Pin pin = Pin::Keep;
        bool storeChoice = false; // write avpn/transportMode = storedMode with the marker
        TransportMode storedMode = TransportMode::Auto;
        bool idleEntered = false; // nothing is running any more (macOS: the runtime gate may open now)
    };
    struct Tap {
        bool refused = false; // "Xray" is not usable now: nothing changed
        bool noop = false;    // already the choice and in force
    };

    TransportMode choice() const { return m_choice; }
    TransportMode inForce() const { return m_inForce; } // readers apply effectiveTransportMode on top
    bool choicePending(bool xrayUsable) const
    {
        return effective(m_choice, xrayUsable) != effective(m_inForce, xrayUsable);
    }
    QStringList takeJournal() { return std::exchange(m_journal, QStringList()); }
    void note(const QString &line) { m_journal << line; }

    // Nothing is running and nothing is about to run.
    bool idle(const ModeActivity &a) const
    {
        if (a.wantConnected || a.operationInFlight || a.preparingStart || a.paused || a.engineBusy)
            return false;
        // NotObserved after the startup observation = a desktop that reports no state while down.
        return a.tunnel == ModeTunnel::Down || (a.tunnel == ModeTunnel::NotObserved && m_startupObserved);
    }

    // --- events of the facade -------------------------------------------------------------------

    // The stored choice at load. "Auto" / "Amnezia" are in force at once (the facade restores the pin
    // AFTER this call: a pin the mode cannot serve is refused by the engine and stays saved).
    Outcome load(const QString &stored, bool byChoiceBuild, bool xrayUsable)
    {
        Outcome o;
        const StoredModeChoice c = storedTransportChoice(stored, byChoiceBuild);
        if (c.legacyReset) {
            o.storeChoice = true;
            o.storedMode = TransportMode::Auto;
            m_journal << QStringLiteral("transport_mode_legacy_reset stored=xray");
        }
        m_choice = c.mode;
        m_loaded = true;
        m_xrayUsable = xrayUsable;
        m_gain = false;
        m_loadAdmitted = false;
        m_pendingJournaled = false;
        if (m_choice != TransportMode::Xray) {
            const TransportMode from = m_inForce;
            m_inForce = m_choice;
            m_loadAdmitted = true;
            o.modeChanged = from != m_inForce;
            o.from = from;
            o.to = m_inForce;
        }
        return o;
    }

    // Anything changed for the facade (it forwards every changed()), a config was applied, the
    // runtime gate moved. why - for the journal: idle | config | start (the runtime gate looked at
    // inside a start) | foreground.
    Outcome observe(const ModeActivity &a, bool xrayUsable, const QString &why)
    {
        Outcome o;
        if (a.tunnel != ModeTunnel::NotObserved)
            m_startupObserved = true;
        const bool idleNow = idle(a);
        o.idleEntered = idleNow && !m_wasIdle;
        m_wasIdle = idleNow;
        noteAvailability(xrayUsable, o, why);
        tryAdmit(idleNow, xrayUsable, why, o);
        return o;
    }

    // The startup observation is done and no state will be reported while the tunnel is down (the
    // macOS service: the end of the daemon probe). iOS needs no call: its first status is the
    // observation. In the journal a load admission reads why=start whatever event carried it; a
    // gain that waited for this observation reads why=idle.
    Outcome startupObserved(const ModeActivity &a, bool xrayUsable)
    {
        m_startupObserved = true;
        return observe(a, xrayUsable, QStringLiteral("idle"));
    }

    // A tap on the selector.
    Tap tap(TransportMode mode, bool xrayUsable)
    {
        Tap t;
        if (mode == TransportMode::Xray && !xrayUsable) {
            t.refused = true;
            return t;
        }
        if (mode == m_choice && mode == effective(m_inForce, xrayUsable)) {
            t.noop = true;
            return t;
        }
        set(mode, xrayUsable);
        return t;
    }

    // The choice and the mode in force at once: the tap after its checks; tests.
    void set(TransportMode mode, bool xrayUsable)
    {
        m_choice = mode;
        m_inForce = effective(mode, xrayUsable);
        m_loaded = true;
        m_loadAdmitted = true;
        m_pendingJournaled = false;
        m_xrayUsable = xrayUsable;
    }

    // macOS service: Xray needs tun2socks next to the installed service. LOSING it takes effect at
    // once - a start must not pick a transport the service cannot raise. GAINING it while the choice
    // is "Xray" takes effect only while nothing is running: a service updated inside Connect must not
    // bring "Xray" into force between the tap and connect(). With "Auto" or "Amnezia" chosen no mode
    // is waiting for the gate, so it opens at once, as before 139 (review of df7f49db8: an Auto user
    // whose service got tun2socks inside Connect had no Xray until the first disconnect).
    bool nextRuntimeGate(bool readyNow, bool present, const ModeActivity &a) const
    {
        return present && (readyNow || idle(a) || m_choice != TransportMode::Xray);
    }

    // --- events of the engine -------------------------------------------------------------------

    // A pick is about to read the mode: a lost Xray is written down as Auto (as before 139).
    void writeDownLoss(bool xrayUsable)
    {
        if (xrayUsable || m_inForce != TransportMode::Xray)
            return;
        m_inForce = TransportMode::Auto;
        m_xrayUsable = false;
        m_journal << effectiveLine(TransportMode::Xray, TransportMode::Auto, QStringLiteral("pick"));
    }

    // connect(): a session this process starts runs under the mode in force and is never re-judged.
    void sessionStartedByUs()
    {
        m_ownStartEver = true;
        m_sessionOwn = true;
    }

    // A live session this process did not start (the GUI restarted and the tunnel lived on, the OS
    // started it). sessionProto - its transport if known. Also the startup observation.
    Outcome sessionAdopted(const QString &sessionProto, bool xrayUsable)
    {
        m_startupObserved = true;
        m_sessionOwn = false;
        return judgeForeignSession(sessionProto, xrayUsable);
    }

    // The transport of the current session became known (its identity was resolved - at adoption or
    // later, in a pool refresh). Nothing for a session this process started.
    Outcome sessionTransportKnown(const QString &sessionProto, bool xrayUsable)
    {
        if (m_sessionOwn)
            return Outcome();
        return judgeForeignSession(sessionProto, xrayUsable);
    }

private:
    static TransportMode effective(TransportMode m, bool xrayUsable)
    {
        return (m == TransportMode::Xray && !xrayUsable) ? TransportMode::Auto : m;
    }
    static QString effectiveLine(TransportMode from, TransportMode to, const QString &why)
    {
        return QStringLiteral("transport_mode_effective from=%1 to=%2 why=%3")
            .arg(transportModeToString(from), transportModeToString(to), why);
    }
    void setInForce(TransportMode to, Outcome &o, const QString &why)
    {
        const TransportMode from = m_inForce;
        if (from == to)
            return;
        m_inForce = to;
        o.modeChanged = true;
        o.from = from;
        o.to = to;
        m_journal << effectiveLine(from, to, why);
    }
    // Xray usable or not, as told with every event: a gain during the run is remembered (the choice
    // was not usable since load - see m_gain), a loss takes effect at once.
    void noteAvailability(bool xrayUsable, Outcome &o, const QString &why)
    {
        if (xrayUsable && !m_xrayUsable && m_loaded)
            m_gain = true;
        m_xrayUsable = xrayUsable;
        if (!xrayUsable && m_inForce == TransportMode::Xray)
            setInForce(TransportMode::Auto, o, why);
    }
    void admit(TransportMode target, const QString &why, Outcome &o)
    {
        setInForce(target, o, why);
        o.pin = Pin::Unapply; // never more: the saved pin is the user's (see the header)
        m_loadAdmitted = true;
        m_pendingJournaled = false;
    }
    void tryAdmit(bool idleNow, bool xrayUsable, const QString &why, Outcome &o)
    {
        const TransportMode target = effective(m_choice, xrayUsable);
        if (!m_loaded || target == m_inForce) {
            m_pendingJournaled = false;
            return;
        }
        if (!idleNow) {
            if (!m_pendingJournaled) {
                m_pendingJournaled = true;
                m_journal << QStringLiteral("transport_mode_pending choice=%1 in_force=%2 why=%3")
                                 .arg(transportModeToString(m_choice), transportModeToString(m_inForce), why);
            }
            return;
        }
        // The first admission of a choice that was usable since load is the load admission ("start"):
        // it only waited for the startup observation.
        const bool loadAdmission = !m_loadAdmitted && !m_gain;
        admit(target, loadAdmission ? QStringLiteral("start") : why, o);
    }
    Outcome judgeForeignSession(const QString &sessionProto, bool xrayUsable)
    {
        Outcome o;
        const QString why = QStringLiteral("adopted_session");
        noteAvailability(xrayUsable, o, why);
        if (!sessionFitsMode(m_inForce, sessionProto)) {
            // It was started while the mode in force was another one: the session keeps Auto.
            setInForce(TransportMode::Auto, o, why);
            return o;
        }
        // The load admission is still due and this is the session found at startup: it takes the
        // choice unless its known transport contradicts it. Not after a real gain (the choice was not
        // usable when this run began), not once this process has started a session itself.
        const TransportMode target = effective(m_choice, xrayUsable);
        if (m_loaded && !m_loadAdmitted && !m_gain && !m_ownStartEver && target != m_inForce
            && sessionFitsMode(target, sessionProto))
            admit(target, why, o);
        return o;
    }

    TransportMode m_choice = TransportMode::Auto;
    TransportMode m_inForce = TransportMode::Auto;
    bool m_loaded = false;          // load() was called: before it nothing is admitted
    bool m_startupObserved = false; // the tunnel of an earlier process was looked for
    bool m_loadAdmitted = false;    // the choice has been in force at least once in this run
    bool m_gain = false;            // Xray became usable during this run: the choice was not usable since load.
                                    // Read only before the first admission: the session found at startup does
                                    // not take such a choice, and its admission is journalled by its own reason.
    bool m_xrayUsable = false;      // as told by the last event
    bool m_ownStartEver = false;    // this process has started a session
    bool m_sessionOwn = false;      // the current session was started by this process
    bool m_wasIdle = false;
    bool m_pendingJournaled = false;
    QStringList m_journal;
};

} // namespace avpn
