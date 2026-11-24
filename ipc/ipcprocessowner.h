#ifndef IPCPROCESSOWNER_H
#define IPCPROCESSOWNER_H

// AVPN (macOS orphan tun2socks 24.11.2026): the privileged children the service starts for its clients
// (IpcServerProcess, ipc/ipc_process_interface.rep), owned by handle.
//
// Before: IpcServerProcess::start() ran Utils::killProcessByName(<full path>) = `pkill <full path>` on macOS
// and Linux. pkill matches the process NAME, so a full path matched nothing (on the owner's Mac:
// pgrep "<full path>" -> 0 matches, pgrep -x tun2socks -> 1) and the previous instance kept the TUN device.
// Matching by name could not be made safe either: another user's session or another product's service (the
// upstream AmneziaVPN service ships its own tun2socks) runs a process of the same name. And a child whose
// client went away (the app quit or crashed) stayed running with nobody able to control it.
//
// Now: the service ends only processes it started itself, by their QProcess handle - the previous instance of
// the same program before a start, and a child whose last controlling connection closed. A child of an
// earlier service instance needs no search: launchd (no AbandonProcessGroup in the plist) and systemd (control
// group) end the whole job with the service.
//
// Pure parts and the ending itself are tested with real child processes by
// client/core/serviceEngine/tests/ipc_process_owner_check.cpp (build_ipc_process_owner.sh); call sites -
// check_xray_quit_wiring.sh. Windows keeps its own path (IpcServerProcess::start, killProcessByName).

#include <QHash>
#include <QPointer>
#include <QProcess>
#include <QTimer>

namespace avpn {

// What the service does when a controlling connection of a child closes.
enum class ControllerLoss {
    Keep,      // another controller is still connected, or the child does not run
    End,       // the last controller is gone; it had asked to end the child (terminate/kill/close)
    Abandoned, // the last controller is gone and never asked: the child would run on with nobody to stop it
};

struct ChildControl
{
    int controllers = 0;
    bool endRequested = false; // terminate(), kill() or close() came from a controller

    void onControllerConnected() { ++controllers; }
    void onEndRequested() { endRequested = true; }
    void onStarted() { endRequested = false; }

    ControllerLoss onControllerLost(bool childRunning)
    {
        if (controllers > 0)
            --controllers;
        if (controllers > 0 || !childRunning)
            return ControllerLoss::Keep;
        return endRequested ? ControllerLoss::End : ControllerLoss::Abandoned;
    }
};

// AVPN (review F2): the service's Xray session by identity. Every xrayStart opens a new generation, every
// xrayStop closes the current one with a new generation too; a tun2socks child carries the generation it was
// started in. Shared state - the core, kill switch, resolvers, routes, the TUN device - belongs to the open
// generation, so a lost client's child may end that state only when it was started in it: a newer client's
// xrayStart that the service handled before the lost client's disconnect makes the child an older one.
// All of it lives on the service's main thread: QtRO slots (xrayStart/xrayStop, the child's start) and the
// sockets' disconnected signals are delivered there one at a time. The teardown that ends a session runs no
// event loop (Router/KillSwitch/Xray block on QProcess::waitForFinished or call the core directly), so no
// xrayStart can land inside it - one that comes later sees a closed generation and starts a fresh one. (The
// AmneziaWG daemon's UAPI waits do pump events, so a handler may run nested inside one; each still runs to its
// end without pumping, and the generation is read when it runs.)
struct XraySessionLedger
{
    quint64 generation = 0;
    bool open = false;

    static XraySessionLedger &service()
    {
        static XraySessionLedger ledger;
        return ledger;
    }

    void onCoreStart()
    {
        ++generation;
        open = true;
    }
    void onCoreStop()
    {
        ++generation;
        open = false;
    }
    bool isCurrentOpen(quint64 childGeneration) const { return open && childGeneration == generation; }
};

// What the service does when a controlling connection of a child closes.
enum class LostControllerStep {
    Nothing,          // the child is still controlled, or not running
    EndChild,         // end the child only (its end was requested, or its session is not the open one)
    EndSessionThenChild, // a tun2socks of the open session lost its client: end that session, then the child
};

inline LostControllerStep decideLostController(ControllerLoss loss, bool isTun2Socks, quint64 childGeneration,
                                               const XraySessionLedger &ledger)
{
    if (loss == ControllerLoss::Keep)
        return LostControllerStep::Nothing;
    if (loss == ControllerLoss::Abandoned && isTun2Socks && ledger.isCurrentOpen(childGeneration))
        return LostControllerStep::EndSessionThenChild;
    return LostControllerStep::EndChild;
}

inline constexpr int kChildTermGraceMs = 1000; // SIGTERM first; SIGKILL if it still runs after this
inline constexpr int kChildKillWaitMs = 1000;

// Ends one child without blocking the event loop: SIGTERM now, SIGKILL after graceMs if it still runs.
inline void endChildLater(QProcess *child, int graceMs = kChildTermGraceMs)
{
    if (!child || child->state() == QProcess::NotRunning)
        return;
    child->terminate();
    QTimer::singleShot(graceMs, child, [child]() {
        if (child->state() != QProcess::NotRunning)
            child->kill();
    });
}

// Ends one child before the caller goes on (the next instance needs its device): SIGTERM, SIGKILL after
// graceMs, then waits for the reap. Bounded: graceMs + killWaitMs at most. True when it is gone.
inline bool endChildNow(QProcess *child, int graceMs = kChildTermGraceMs / 2, int killWaitMs = kChildKillWaitMs)
{
    if (!child || child->state() == QProcess::NotRunning)
        return true;
    child->terminate();
    if (child->waitForFinished(graceMs))
        return true;
    child->kill();
    return child->waitForFinished(killWaitMs) || child->state() == QProcess::NotRunning;
}

// The children of one service, by handle and program id (amnezia::PermittedProcess).
class OwnedChildren
{
public:
    static OwnedChildren &service()
    {
        static OwnedChildren registry;
        return registry;
    }

    void add(QProcess *child, int program) { m_children.insert(child, program); }
    void setProgram(QProcess *child, int program)
    {
        if (m_children.contains(child))
            m_children.insert(child, program);
    }
    void remove(QProcess *child) { m_children.remove(child); }

    // Ends every running child of `program` except `self` (a previous instance) and waits until each is gone.
    // Returns how many were running.
    int endOthersOf(int program, const QProcess *self)
    {
        QList<QPointer<QProcess>> others;
        for (auto it = m_children.cbegin(); it != m_children.cend(); ++it) {
            if (it.key() != self && it.value() == program && it.key()->state() != QProcess::NotRunning)
                others.append(QPointer<QProcess>(it.key()));
        }
        for (const QPointer<QProcess> &child : others) {
            if (child)
                endChildNow(child.data());
        }
        return int(others.size());
    }

private:
    QHash<QProcess *, int> m_children;
};

} // namespace avpn

#endif // IPCPROCESSOWNER_H
