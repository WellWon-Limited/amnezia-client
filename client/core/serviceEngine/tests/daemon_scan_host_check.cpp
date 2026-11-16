// client/core/serviceEngine/tests/daemon_scan_host_check.cpp
// AVPN: DaemonScanHost (the Scanner's desktop IScanHost) against a fake transport - the IScanHost
// obligations of the API note (a): one reply per message, always queued, never from inside
// sendMessage, bytes unchanged, own bound, refusals as ipc_refused, no answer while the service is not
// there, pending replies answered when it goes away; the state table of the two replicas (service off /
// connecting / older service / another build / ready); generation only while ready; knownCaps of the
// desktop engine. The real QtRO round trip is service/server/tests/tribe_scan_ipc_check.cpp.
// Run by build_daemon_scan_host.sh.
#include "DaemonScanHost.h"
#include "ScanHostContract.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QThread>
#include <QTimer>

#include <cstdio>

using namespace avpn;
using RS = QRemoteObjectReplica::State;
using TS = DaemonScanTransport::State;

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

template <typename P>
static bool waitFor(P pred, int ms = 3000)
{
    QElapsedTimer t;
    t.start();
    while (!pred()) {
        if (t.elapsed() > ms)
            return false;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return true;
}

class FakeTransport : public DaemonScanTransport
{
public:
    State st = State::Connecting;
    QString gen;
    struct Sub {
        quint64 id;
        QString message;
        std::function<void(int)> accepted;
    };
    QList<Sub> subs;
    int stops = 0;
    int answerCode = 0; // what the slot answers (async)

    State state() const override { return st; }
    QString generationJson() const override { return gen; }
    void submit(quint64 id, const QString &message, std::function<void(int)> accepted) override
    {
        subs << Sub{id, message, accepted};
        const int code = answerCode;
        QTimer::singleShot(0, [accepted, code]() { accepted(code); });
    }
    void stopAll() override { ++stops; }
    void set(State s)
    {
        st = s;
        if (onStateChanged)
            onStateChanged();
    }
};

struct Got {
    int calls = 0;
    QByteArray bytes;
};

static ScanStartRequest sr()
{
    ScanStartRequest r;
    r.scanId = QStringLiteral("s");
    r.deadlineMs = 5000;
    r.probeBase = QStringLiteral("https://x.example");
    r.token = QStringLiteral("t");
    return r;
}

static void pure()
{
    // The two replicas -> the transport state.
    CHECK(daemonScanTransportState(RS::Valid, RS::Valid, 1, true, false) == TS::Ready);
    CHECK(daemonScanTransportState(RS::Uninitialized, RS::Valid, 1, false, false) == TS::Ready);
    CHECK(daemonScanTransportState(RS::Valid, RS::Valid, 0, true, true) == TS::ServiceOld); // no known version
    CHECK(daemonScanTransportState(RS::Valid, RS::SignatureMismatch, 1, true, false) == TS::ServiceOld);
    CHECK(daemonScanTransportState(RS::Valid, RS::Uninitialized, 1, true, false) == TS::Connecting); // grace
    CHECK(daemonScanTransportState(RS::Valid, RS::Uninitialized, 1, true, true) == TS::ServiceOld);
    CHECK(daemonScanTransportState(RS::SignatureMismatch, RS::Uninitialized, 1, true, true) == TS::ServiceMismatch);
    CHECK(daemonScanTransportState(RS::Uninitialized, RS::Uninitialized, 1, false, false) == TS::Connecting);
    CHECK(daemonScanTransportState(RS::Uninitialized, RS::Uninitialized, 1, true, false) == TS::ServiceOff);
    CHECK(daemonScanTransportState(RS::Suspect, RS::Suspect, 1, true, false) == TS::ServiceOff);
    CHECK(daemonScanTransportState(RS::Default, RS::Default, 1, true, false) == TS::ServiceOff);
    CHECK(daemonScanUnavailableReason(TS::Ready).isEmpty());
    CHECK(daemonScanUnavailableReason(TS::ServiceOff) == QStringLiteral("service_off"));
    CHECK(daemonScanUnavailableReason(TS::ServiceOld) == QStringLiteral("service_old"));
    CHECK(daemonScanUnavailableReason(TS::ServiceMismatch) == QStringLiteral("service_mismatch"));
    CHECK(daemonScanUnavailableReason(TS::Connecting) == QStringLiteral("connecting"));

    // Bounds: a scan_start (the contract's encoder puts "action" first) waits longer.
    ScanStartRequest sr;
    sr.scanId = QStringLiteral("s");
    sr.deadlineMs = 5000;
    sr.probeBase = QStringLiteral("https://x.example");
    sr.token = QStringLiteral("t");
    CHECK(daemonScanReplyBoundMs(scanCompact(scanEncodeStart(sr))) == kDaemonScanStartReplyMs);
    CHECK(daemonScanReplyBoundMs(scanCompact(scanEncodePoll(QStringLiteral("s"), 0))) == kDaemonScanReplyMs);
    CHECK(daemonScanReplyBoundMs(scanCompact(scanEncodeCancel(QStringLiteral("s")))) == kDaemonScanReplyMs);
    CHECK(kDaemonScanStartReplyMs > 3000 + kDaemonScanReplyMs / 2); // a replacing start waits up to 3 s
    CHECK(kDaemonScanMaxMessageBytes == 8 * 1024 * 1024);

    // Refusal replies decode as an open-set error, never as success; 0 and -1 have none.
    for (int code = 1; code <= 4; ++code) {
        const ScanHostReply r = scanDecodeReply(daemonScanRefusalReply(code));
        CHECK(r.kind == ScanHostReplyKind::Error && r.error == ScanHostError::Other && r.errorCode == QStringLiteral("ipc_refused"));
    }
    CHECK(scanDecodeReply(daemonScanRefusalReply(2)).detail == QStringLiteral("rate_limited"));
    CHECK(daemonScanRefusalReply(0).isEmpty() && daemonScanRefusalReply(-1).isEmpty());
}

static void host()
{
    auto ft = std::make_unique<FakeTransport>();
    FakeTransport *t = ft.get();
    DaemonScanHost h(std::move(ft));
    int avail = 0, gens = 0;
    h.onAvailabilityChanged = [&]() { ++avail; };
    h.onGenerationChanged = [&]() { ++gens; };

    const ScanHostCaps c = h.knownCaps();
    CHECK(c.maxFullConcurrent == 2 && c.canVerifyComposite && c.maxLegConcurrent == 6 && c.dnsPlan && c.maxAwgConcurrent == 4
          && c.reachStage && !c.needsVpn && c.platform == QStringLiteral("macos"));
    const ScanHostCaps cc = DaemonScanHost::compiledCaps(); // the same, before any instance exists
    CHECK(cc.maxFullConcurrent == c.maxFullConcurrent && cc.maxLegConcurrent == c.maxLegConcurrent
          && cc.maxAwgConcurrent == c.maxAwgConcurrent && cc.needsVpn == c.needsVpn && cc.platform == c.platform);

    // Not there yet: no answer, still exactly once and never inside sendMessage; nothing reaches the IPC.
    CHECK(h.availability() == ScanHostAvailability::Unavailable && h.unavailableReason() == QStringLiteral("connecting"));
    Got g0;
    bool inside = true;
    h.sendMessage(R"({"action":"scan_caps"})", [&](const QByteArray &b) {
        ++g0.calls;
        g0.bytes = b;
        CHECK(!inside);
    });
    inside = false;
    CHECK(g0.calls == 0);
    CHECK(waitFor([&]() { return g0.calls == 1; }));
    CHECK(g0.bytes.isEmpty() && t->subs.isEmpty());
    ScanNetSource gen;
    t->gen = QStringLiteral(R"({"source":"service","epoch":"0123456789abcdef","counter":4})");
    CHECK(!h.generation(gen)); // only while ready

    t->set(TS::ServiceOff);
    CHECK(avail == 1 && h.unavailableReason() == QStringLiteral("service_off"));
    t->set(TS::ServiceOld);
    CHECK(avail == 2 && h.unavailableReason() == QStringLiteral("service_old") && h.availability() == ScanHostAvailability::Unavailable);
    Got gOld;
    h.sendMessage(R"({"action":"scan_caps"})", [&](const QByteArray &b) {
        ++gOld.calls;
        gOld.bytes = b;
    });
    CHECK(waitFor([&]() { return gOld.calls == 1; }) && gOld.bytes.isEmpty() && t->subs.isEmpty()); // no missing slot is called
    h.stopAll();
    CHECK(t->stops == 0);

    // Ready.
    t->set(TS::Ready);
    CHECK(h.availability() == ScanHostAvailability::Available && h.unavailableReason().isEmpty() && avail == 3 && gens >= 1);
    CHECK(h.generation(gen) && gen.source == QStringLiteral("service") && gen.epoch == 0x0123456789abcdefULL && gen.counter == 4);
    t->gen = QStringLiteral("{not json");
    CHECK(!h.generation(gen));
    t->gen = QStringLiteral(R"({"source":"service","epoch":12,"counter":4})"); // epoch must be 16 hex
    CHECK(!h.generation(gen));

    // Relay: the bytes go out as given and come back as given, once.
    const QByteArray req = QStringLiteral("{\"action\":\"scan_poll\",\"scan_id\":\"Ж\",\"since\":3}").toUtf8();
    Got g1;
    h.sendMessage(req, [&](const QByteArray &b) {
        ++g1.calls;
        g1.bytes = b;
    });
    CHECK(t->subs.size() == 1 && t->subs.first().message.toUtf8() == req);
    const quint64 id1 = t->subs.first().id;
    const QByteArray rep = QStringLiteral("{\"type\":\"scan_progress\",\"scan_id\":\"Ж\"}").toUtf8();
    QCoreApplication::processEvents(); // the slot's 0 arrives
    t->onReply(id1, QString::fromUtf8(rep));
    CHECK(g1.calls == 0); // queued
    CHECK(waitFor([&]() { return g1.calls == 1; }));
    CHECK(g1.bytes == rep);
    t->onReply(id1, QStringLiteral("{\"late\":true}")); // a second reply for the same id is dropped
    QCoreApplication::processEvents();
    QThread::msleep(5);
    QCoreApplication::processEvents();
    CHECK(g1.calls == 1 && h.pendingCount() == 0);

    // Overlapping requests, answered out of order.
    Got ga, gb, gc;
    h.sendMessage("{\"action\":\"scan_add\"}", [&](const QByteArray &b) { ++ga.calls, ga.bytes = b; });
    h.sendMessage("{\"action\":\"scan_freeze\"}", [&](const QByteArray &b) { ++gb.calls, gb.bytes = b; });
    h.sendMessage("{\"action\":\"scan_poll\"}", [&](const QByteArray &b) { ++gc.calls, gc.bytes = b; });
    CHECK(t->subs.size() == 4 && h.pendingCount() == 3);
    const quint64 ia = t->subs.at(1).id, ib = t->subs.at(2).id, ic = t->subs.at(3).id;
    CHECK(ia != ib && ib != ic && ia != ic);
    t->onReply(ic, QStringLiteral("C"));
    t->onReply(ia, QStringLiteral("A"));
    t->onReply(ib, QStringLiteral("B"));
    CHECK(waitFor([&]() { return ga.calls && gb.calls && gc.calls; }));
    CHECK(ga.bytes == "A" && gb.bytes == "B" && gc.bytes == "C" && ga.calls == 1 && gb.calls == 1 && gc.calls == 1);

    // The service's refusal codes, and a failed call.
    t->answerCode = 2;
    Got gr;
    h.sendMessage(R"({"action":"scan_poll"})", [&](const QByteArray &b) { ++gr.calls, gr.bytes = b; });
    CHECK(waitFor([&]() { return gr.calls == 1; }));
    CHECK(gr.bytes == daemonScanRefusalReply(2));
    t->answerCode = -1;
    Got gf;
    h.sendMessage(R"({"action":"scan_poll"})", [&](const QByteArray &b) { ++gf.calls, gf.bytes = b; });
    CHECK(waitFor([&]() { return gf.calls == 1; }));
    CHECK(gf.bytes.isEmpty());
    t->answerCode = 0;

    // Too large: refused here, never sent.
    const int before = t->subs.size();
    Got gl;
    h.sendMessage(QByteArray(kDaemonScanMaxMessageBytes + 1, 'x'), [&](const QByteArray &b) { ++gl.calls, gl.bytes = b; });
    CHECK(waitFor([&]() { return gl.calls == 1; }));
    CHECK(gl.bytes == daemonScanRefusalReply(1) && t->subs.size() == before);

    // The own bound, without wall time: the adapter arms it through the seam with the action's bound; when it
    // expires, the message gets its empty reply once, and a reply arriving after that is dropped.
    struct Armed {
        int ms;
        std::function<void()> expire;
    };
    QList<Armed> armed;
    h.setBoundTimerForTest([&](int ms, std::function<void()> expire) -> QObject * {
        armed << Armed{ms, std::move(expire)};
        return new QObject;
    });
    Got gt;
    h.sendMessage(R"({"action":"scan_poll"})", [&](const QByteArray &b) { ++gt.calls, gt.bytes = b; });
    CHECK(armed.size() == 1 && armed.last().ms == kDaemonScanReplyMs);
    QCoreApplication::processEvents();
    CHECK(gt.calls == 0); // nothing until it expires or the service answers
    armed.last().expire();
    CHECK(waitFor([&]() { return gt.calls == 1; }));
    CHECK(gt.bytes.isEmpty());
    t->onReply(t->subs.last().id, QStringLiteral("late")); // after the bound: dropped
    armed.last().expire();                                 // a second expiry: nothing either
    QCoreApplication::processEvents();
    QCoreApplication::processEvents();
    CHECK(gt.calls == 1 && h.pendingCount() == 0);
    Got gs;
    h.sendMessage(scanCompact(scanEncodeStart(sr())), [&](const QByteArray &b) { ++gs.calls, gs.bytes = b; });
    CHECK(armed.size() == 2 && armed.last().ms == kDaemonScanStartReplyMs); // a scan_start waits longer
    t->onReply(t->subs.last().id, QStringLiteral("S"));
    CHECK(waitFor([&]() { return gs.calls == 1; }));
    armed.last().expire(); // answered already: the expiry does nothing
    QCoreApplication::processEvents();
    CHECK(gs.calls == 1 && gs.bytes == "S");
    h.setBoundTimerForTest(nullptr);

    // stopAll while ready reaches the transport.
    h.stopAll();
    CHECK(t->stops == 1);

    // The service goes away with requests in flight: each gets its empty reply, availability changes.
    Got gx, gy;
    h.sendMessage(R"({"action":"scan_poll"})", [&](const QByteArray &b) { ++gx.calls, gx.bytes = b; });
    h.sendMessage(R"({"action":"scan_freeze"})", [&](const QByteArray &b) { ++gy.calls, gy.bytes = b; });
    CHECK(h.pendingCount() == 2);
    const int availBefore = avail;
    t->set(TS::ServiceOff);
    CHECK(h.pendingCount() == 0 && avail == availBefore + 1 && h.availability() == ScanHostAvailability::Unavailable);
    CHECK(waitFor([&]() { return gx.calls == 1 && gy.calls == 1; }));
    CHECK(gx.bytes.isEmpty() && gy.bytes.isEmpty());
    CHECK(!h.generation(gen));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    pure();
    host();
    std::printf("daemon_scan_host_check: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
