// client/core/serviceEngine/tests/ipc_process_owner_check.cpp
// AVPN (macOS orphan tun2socks 24.11.2026): the service's ownership of its privileged children
// (ipc/ipcprocessowner.h), with real child processes (/bin/sleep stands in for tun2socks).
//   P1  before a start, the previous running instance of the same program is ended and reaped - by its handle;
//       a process of the same executable that the service did not start (another user's or another product's
//       tun2socks) and a child of another program are untouched;
//   P2  a previous instance that ignores SIGTERM is killed after the grace; the call is bounded;
//   P3  endChildLater never blocks: SIGTERM at once, SIGKILL after the grace when SIGTERM is ignored;
//   P4  the controller rule: the last controller gone while the child runs ends it - Abandoned when no
//       controller asked for the end; another controller left, or the child not running -> Keep.
// The old start (pkill <full path>, which matched nothing) fails P1. Run by build_ipc_process_owner.sh.
#include "ipcprocessowner.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QThread>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <memory>

using namespace avpn;

static int g_checks = 0;
static int g_failed = 0;
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        if (!(cond)) {                                                                                                 \
            ++g_failed;                                                                                                \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                       \
        }                                                                                                              \
    } while (0)

enum Program { OpenVpn = 1, Tun2Socks = 3 };

// Every child of this test, ended by handle at exit whatever happened (never by name).
static QList<QProcess *> g_spawned;

static QProcess *spawn(bool ignoreTerm = false)
{
    auto *p = new QProcess;
    if (ignoreTerm)
        p->start(QStringLiteral("/bin/sh"), { QStringLiteral("-c"), QStringLiteral("trap '' TERM; exec /bin/sleep 30") });
    else
        p->start(QStringLiteral("/bin/sleep"), { QStringLiteral("30") });
    p->waitForStarted(3000);
    g_spawned.append(p);
    return p;
}

static bool pidAlive(qint64 pid) { return pid > 0 && (::kill(pid_t(pid), 0) == 0 || errno == EPERM); }

static void pump(int ms)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
}

static void previousInstanceEnded()
{
    OwnedChildren reg;
    QProcess *previous = spawn();
    QProcess *otherProgram = spawn();
    QProcess *notOurs = spawn(); // same executable, not started by the service: never registered
    auto *next = new QProcess;   // the instance about to start
    g_spawned.append(next);
    reg.add(previous, 0); // registered at construction, the program comes with setProgram
    reg.setProgram(previous, Tun2Socks);
    reg.add(otherProgram, OpenVpn);
    reg.add(next, Tun2Socks);
    const qint64 previousPid = previous->processId();
    QElapsedTimer t;
    t.start();
    const int ended = reg.endOthersOf(Tun2Socks, next);
    const qint64 ms = t.elapsed();
    CHECK(ended == 1);
    CHECK(previous->state() == QProcess::NotRunning);
    CHECK(!pidAlive(previousPid)); // reaped, the device it held is free
    CHECK(otherProgram->state() == QProcess::Running);
    CHECK(notOurs->state() == QProcess::Running);
    CHECK(ms < 1000);
    CHECK(reg.endOthersOf(Tun2Socks, next) == 0); // nothing left to end
    reg.remove(previous);
    std::fprintf(stderr, "P1 endOthersOf: %d ended in %lld ms; running after it: previous=%d other-program=%d foreign=%d\n",
                 ended, static_cast<long long>(ms), int(previous->state() != QProcess::NotRunning),
                 int(otherProgram->state() != QProcess::NotRunning), int(notOurs->state() != QProcess::NotRunning));
}

static void stubbornPreviousKilled()
{
    OwnedChildren reg;
    QProcess *stubborn = spawn(true);
    pump(100); // let the shell install its trap before exec
    auto *next = new QProcess;
    g_spawned.append(next);
    reg.add(stubborn, Tun2Socks);
    reg.add(next, Tun2Socks);
    QElapsedTimer t;
    t.start();
    CHECK(reg.endOthersOf(Tun2Socks, next) == 1);
    const qint64 ms = t.elapsed();
    CHECK(stubborn->state() == QProcess::NotRunning);
    CHECK(stubborn->exitStatus() == QProcess::CrashExit); // SIGKILL, not its own exit
    CHECK(ms >= kChildTermGraceMs / 2 - 50 && ms < kChildTermGraceMs / 2 + kChildKillWaitMs); // bounded
    std::fprintf(stderr, "P2 SIGTERM-ignoring previous instance: call took %lld ms, running after it=%d\n",
                 static_cast<long long>(ms), int(stubborn->state() != QProcess::NotRunning));
}

static void endLaterNeverBlocks()
{
    QProcess *plain = spawn();
    QProcess *stubborn = spawn(true);
    QProcess *notOurs = spawn();
    pump(100);
    QElapsedTimer t;
    t.start();
    endChildLater(plain);
    endChildLater(stubborn);
    CHECK(t.elapsed() < 100);
    CHECK(stubborn->state() == QProcess::Running); // SIGTERM ignored, SIGKILL not yet due
    pump(kChildTermGraceMs / 2);
    CHECK(plain->state() == QProcess::NotRunning);
    CHECK(plain->exitStatus() == QProcess::CrashExit); // ended by SIGTERM
    CHECK(stubborn->state() == QProcess::Running);
    QElapsedTimer w;
    w.start();
    while (stubborn->state() != QProcess::NotRunning && w.elapsed() < 3000)
        pump(20);
    CHECK(stubborn->state() == QProcess::NotRunning);
    CHECK(notOurs->state() == QProcess::Running);
    endChildLater(nullptr); // no child, no crash
}

static void controllerRule()
{
    ChildControl c;
    c.onStarted();
    c.onControllerConnected();
    CHECK(c.onControllerLost(true) == ControllerLoss::Abandoned); // the client crashed or quit without a stop

    ChildControl asked;
    asked.onControllerConnected();
    asked.onEndRequested();
    CHECK(asked.onControllerLost(true) == ControllerLoss::End);

    ChildControl gone;
    gone.onControllerConnected();
    CHECK(gone.onControllerLost(false) == ControllerLoss::Keep); // the child had ended already

    ChildControl two;
    two.onControllerConnected();
    two.onControllerConnected();
    CHECK(two.onControllerLost(true) == ControllerLoss::Keep); // one controller is still there
    CHECK(two.onControllerLost(true) == ControllerLoss::Abandoned);
    CHECK(two.onControllerLost(true) == ControllerLoss::Abandoned); // no underflow: still nobody

    ChildControl restarted;
    restarted.onControllerConnected();
    restarted.onEndRequested();
    restarted.onStarted(); // a new start of the same object: the old request does not cover it
    CHECK(restarted.onControllerLost(true) == ControllerLoss::Abandoned);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    controllerRule();
    previousInstanceEnded();
    stubbornPreviousKilled();
    endLaterNeverBlocks();
    for (QProcess *p : std::as_const(g_spawned)) { // by handle only
        if (p->state() != QProcess::NotRunning) {
            p->kill();
            p->waitForFinished(2000);
        }
        delete p;
    }
    if (g_failed) {
        std::fprintf(stderr, "ipc_process_owner_check: %d of %d checks FAILED\n", g_failed, g_checks);
        return 1;
    }
    std::printf("ipc_process_owner_check: all %d checks passed\n", g_checks);
    return 0;
}
