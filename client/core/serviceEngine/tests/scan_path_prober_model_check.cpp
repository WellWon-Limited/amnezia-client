// AVPN path engine stage 2: a MODEL CHECK of the race's probe host adapter (ScanPathProber).
//
// The real ScanPathProber is driven with random sequences against a model host that keeps the ground truth (which part
// ran in which scan, how many bytes it really sent) and that is hostile in the ways a real transport is: requests are
// processed late (the host can close a scan before an add it was sent is processed), replies arrive late, out of order
// and twice, a scan is closed by the host at a random moment, scan_start / scan_add are refused at random, a cancel
// ack carries the final byte total or not, a probe is cancelled at a random moment, the race ends.
//
// Invariants (checked after every step and at the end):
//   I1 every probe ends EXACTLY once (a result) or is cancelled (then never a result); nothing waits for ever
//   I2 a probe is proven only if every part id it sent reported data in a delivered poll answer
//   I3 no part runs at the host twice at the same time (accepted into a second scan while the first one is live),
//      and a part is never accepted twice into one scan
//   I4 a cancelled probe is not running at the host when the dust settles (its scan was cancelled)
//   I5 a probe the host never accepted anything of ends with NEGATIVE bytes (nothing was sent: nothing is charged), and
//      a probe the host accepted a part of never does (its bytes would be refunded to the race cap)
//   I6 bytes: what the prober charged (results + the ledger charges) is never more than the host really sent, and never
//      less except for the stated, bounded exception: scans whose cancel ack carried no final total (their bytes are
//      unknown to the app) - the shortfall is at most those scans' totals
//   I7 liveness: a probe whose parts all succeed at the host ends proven (when the host refused nothing)
//
// Host contract the model follows (quoted from the real host, recipes/amnezia-libxray/patches/0012-tribe-scan-engine.patch,
// scan engine loop): "The queue drained: done, "complete", NOT final - the scan stays open for scan_add until the deadline
// or the app's freeze + cancel." and `closed bool // past the deadline or stopped: scan_add accepts nothing`; the
// ScanHostContract.h text says the same ("complete" = the host's queue is drained; it stays open for scan_add until its
// deadline). So a poll may report done=true / final=false while an add is in flight and the add is still accepted; and
// a poll answer carrying a part's result may arrive BEFORE the ack of the scan_add that carried the part (replies are
// delivered in any order here). The final byte total of a scan (data + the host's opening and closing /netinfo) comes
// with the cancel ack or the final poll.
//
// Built and run by build_scan_path_prober_model.sh. Env MODEL_RUNS (default 3000) sets the number of sequences.
#define main prober_check_main
#include "scan_path_prober_check.cpp"
#undef main

#include <QSet>

#include <random>

namespace {

struct MPart {
    QString id;
    qint64 bytes = 5000;
    bool ok = true;
    bool finished = false;
    qint64 itemSeq = 0; // the host's sequence number of this part's item (set when it finishes)
    qint64 spent = 0; // fixed once the scan ends
};

struct MScan {
    QString id;
    bool open = true;
    bool cancelled = false;
    bool ended = false;
    QList<MPart> parts;
    bool finalDelivered = false; // a cancel ack with the final total was delivered
    bool noFinal = false;
    bool cancelAsked = false;
    static constexpr qint64 kAccessBytes = 4096; // the host's opening + closing /netinfo, in every scan's total
    qint64 total() const
    {
        qint64 t = kAccessBytes;
        for (const MPart &p : parts)
            t += p.finished ? p.bytes : p.spent;
        return t;
    }
};

struct Inbox {
    QByteArray req;
    IScanHost::ReplyFn reply;
};

struct Outbox {
    IScanHost::ReplyFn reply;
    QByteArray bytes;
    QString scanId;
    bool isCancelAck = false;
    bool final = false;
};

struct ModelHost : IScanHost {
    std::mt19937 *rng = nullptr;
    QJsonObject caps{{"type", "scan_caps"}, {"version", "tribe-scan-v1"}, {"max_full_concurrent", 4}, {"max_leg_concurrent", 6},
                     {"max_awg_concurrent", 2}, {"can_verify_composite", true}, {"dns_plan", true}, {"reach_stage", true},
                     {"needs_vpn", false}, {"kinds", QJsonArray{"xray_full", "xray_leg", "awg_mini"}}, {"platform", "ios-app"}};
    QList<Inbox> inbox;
    QList<Outbox> outbox;
    QList<MScan> scans;
    bool refuseStarts = false;
    int refuseAddPercent = 0;
    int finalAckPercent = 70;
    qint64 seq = 0;
    QStringList violations;
    QHash<quint64, QStringList> partsOfProbe; // probe key -> every part id it ever sent
    QSet<quint64> acceptedProbes;             // probes the host accepted a part of
    QHash<QString, int> deliveredItems;       // part id -> delivered ok items (poll answers the prober could use)
    int newestStart = 0;                      // the highest scan number a start was ever processed for (refused or not)
    QHash<QString, int> currentItems;         // part id -> items delivered from the scan that was the app's current one

    ScanHostCaps knownCaps() const override { return ScanHostCaps(); }
    ScanHostAvailability availability() const override { return ScanHostAvailability::Available; }
    QString unavailableReason() const override { return QString(); }
    bool generation(ScanNetSource &) const override { return false; }
    void stopAll() override {}

    int roll(int n) { return int((*rng)() % unsigned(n)); }
    static quint64 probeOf(const QString &id)
    {
        const QString base = id.section(QLatin1Char('.'), 0, 0);
        return base.mid(base.lastIndexOf(QLatin1Char('-')) + 1).toULongLong();
    }
    MScan *scanById(const QString &id)
    {
        for (MScan &s : scans)
            if (s.id == id)
                return &s;
        return nullptr;
    }
    bool partLive(const QString &id, const QString &exceptScan) const
    {
        for (const MScan &s : scans)
            if (s.id != exceptScan && !s.cancelled && !s.ended)
                for (const MPart &p : s.parts)
                    if (p.id == id)
                        return true;
        return false;
    }

    void sendMessage(const QByteArray &request, ReplyFn reply) override { inbox << Inbox{request, reply}; }

    void endScan(MScan &s, bool cancel)
    {
        if (s.ended)
            return;
        for (MPart &p : s.parts)
            if (!p.finished) {
                if (cancel)
                    p.spent = qint64(roll(int(p.bytes)));
                else {
                    p.finished = true; // the engine closes the scan: its jobs run out
                    p.itemSeq = ++seq;
                }
            }
        s.ended = true;
        s.open = false;
        s.cancelled = cancel;
    }

    void accept(MScan &s, const QJsonArray &cands)
    {
        for (const QJsonValue &v : cands) {
            const QString id = v.toObject().value("id").toString();
            MPart p;
            p.id = id;
            p.bytes = v.toObject().value("kind").toString() == "awg_mini" ? 8000 : 5000;
            p.ok = (id.size() * 31 + int(probeOf(id)) * 7) % 9 != 0; // a part's fate (about one in nine fails)
            for (const MPart &q : s.parts)
                if (q.id == id)
                    violations << QStringLiteral("I3 part %1 accepted twice into %2").arg(id, s.id);
            if (partLive(id, s.id))
                violations << QStringLiteral("I3 part %1 runs in two scans at once (%2)").arg(id, s.id);
            s.parts << p;
            acceptedProbes.insert(probeOf(id));
        }
    }

    void learn(const QJsonArray &cands)
    {
        for (const QJsonValue &v : cands) {
            const QString id = v.toObject().value("id").toString();
            QStringList &l = partsOfProbe[probeOf(id)];
            if (!l.contains(id))
                l << id;
        }
    }

    // The host processes its oldest request now.
    bool processOne()
    {
        if (inbox.isEmpty())
            return false;
        const Inbox in = inbox.takeFirst();
        const QJsonObject o = QJsonDocument::fromJson(in.req).object();
        const QString a = o.value("action").toString();
        const QString id = o.value("scan_id").toString();
        QJsonObject r;
        Outbox ob;
        ob.reply = in.reply;
        ob.scanId = id;
        if (a == "scan_caps") {
            r = caps;
        } else if (a == "scan_start") {
            learn(o.value("candidates").toArray());
            newestStart = qMax(newestStart, id.mid(id.lastIndexOf(QLatin1Char('-')) + 1).toInt());
            if (refuseStarts && roll(100) < 35) {
                r = QJsonObject{{"error", "internal"}, {"scan_id", id}};
            } else {
                MScan s;
                s.id = id;
                // a new start ends the host's other open scans (one scan at a time per engine process)
                for (MScan &other : scans)
                    if (!other.ended)
                        endScan(other, true);
                scans << s;
                accept(scans.last(), o.value("candidates").toArray());
                r = QJsonObject{{"type", "scan_ack"}, {"scan_id", id}, {"accepted", o.value("candidates").toArray().size()}, {"mem_mb", 40}};
            }
        } else if (a == "scan_add") {
            learn(o.value("candidates").toArray());
            MScan *s = scanById(id);
            const bool ok = s && s->open && roll(100) >= refuseAddPercent;
            if (ok)
                accept(*s, o.value("candidates").toArray());
            r = QJsonObject{{"type", "scan_ack"}, {"scan_id", id}, {"accepted", ok ? o.value("candidates").toArray().size() : 0}, {"mem_mb", 40}};
        } else if (a == "scan_poll") {
            MScan *s = scanById(id);
            if (!s) {
                r = QJsonObject{{"error", "unknown_scan"}, {"scan_id", id}};
            } else {
                const qint64 since = qint64(o.value("since").toDouble());
                QJsonArray items;
                bool allFinished = true;
                for (MPart &p : s->parts) {
                    const bool dup = p.finished && p.itemSeq <= since && roll(100) < 10; // a repeated item
                    if (p.finished && (p.itemSeq > since || dup))
                        items << QJsonObject{{"id", p.id}, {"stage", "data"}, {"seq", double(p.itemSeq)}, {"error", p.ok ? "" : "dial"},
                                             {"http_status", p.ok ? 200 : 0}, {"sha_ok", p.ok}, {"bytes", p.ok ? 4096 : 0},
                                             {"bytes_requested", 4096}, {"duration_ms", 600}, {"ttfb1_ms", 300}, {"rtt_ms", 40},
                                             {"t64_ms", 100}, {"spent_bytes", double(p.bytes)}, {"retries", 0}, {"start_ms", 10},
                                             {"end_ms", 610}, {"egress_class", QJsonValue::Null}, {"egress_node", QJsonValue::Null},
                                             {"egress_asn", QJsonValue::Null}, {"net_token", QJsonValue::Null}};
                    allFinished = allFinished && p.finished;
                }
                const bool done = allFinished;           // the queue drained (the scan may stay open for scan_add)
                const bool fin = s->ended && allFinished; // the host scan is over: the total is final
                r = QJsonObject{{"type", "scan_progress"}, {"scan_id", id}, {"seq", double(seq)}, {"phase", done ? "done" : "data"},
                                {"items", items}, {"bytes_spent", fin ? double(s->total()) : 0.0}, {"bytes_reserved", 0}, {"mem_mb", 41},
                                {"done", done}, {"reason", done ? "complete" : ""}, {"access", QJsonValue::Null},
                                {"access_close", QJsonValue::Null}, {"gen", QJsonValue::Null}};
                if (fin)
                    r.insert("final", true);
                ob.final = false;
            }
        } else if (a == "scan_cancel") {
            MScan *s = scanById(id);
            if (s) {
                s->cancelAsked = true;
                endScan(*s, true);
                ob.isCancelAck = true;
                s->noFinal = roll(100) >= finalAckPercent;
                r = s->noFinal ? scanEncodeAck(id, 0, 40) : scanEncodeCancelAck(id, s->total(), 40);
                ob.final = !s->noFinal;
            } else {
                r = QJsonObject{{"error", "unknown_scan"}, {"scan_id", id}};
            }
        } else {
            r = QJsonObject{{"error", "unknown_action"}};
        }
        ob.bytes = QJsonDocument(r).toJson(QJsonDocument::Compact);
        outbox << ob;
        return true;
    }

    // One reply reaches the app (any, in any order; sometimes it stays to arrive again).
    bool deliverOne()
    {
        if (outbox.isEmpty())
            return false;
        const int i = roll(int(outbox.size()));
        const Outbox ob = outbox.at(i);
        const bool again = roll(100) < 12;
        if (!again)
            outbox.removeAt(i);
        if (ob.isCancelAck && ob.final) {
            if (MScan *s = scanById(ob.scanId))
                s->finalDelivered = true;
        }
        const QJsonObject o = QJsonDocument::fromJson(ob.bytes).object();
        if (o.value("type").toString() == "scan_progress") {
            // the app's current scan = the newest scan id it has sent a start for (it sends it at once)
            const auto num = [](const QString &sid) { return sid.mid(sid.lastIndexOf(QLatin1Char('-')) + 1).toInt(); };
            int newest = newestStart;
            for (const MScan &s : scans)
                newest = qMax(newest, num(s.id));
            for (const Inbox &in : inbox)
                newest = qMax(newest, num(QJsonDocument::fromJson(in.req).object().value("scan_id").toString()));
            for (const QJsonValue &v : o.value("items").toArray()) {
                const QJsonObject it = v.toObject();
                if (it.value("sha_ok").toBool())
                    deliveredItems[it.value("id").toString()] += 1;
                if (num(ob.scanId) == newest)
                    currentItems[it.value("id").toString()] += 1;
            }
        }
        ob.reply(ob.bytes);
        return true;
    }

    void finishSome()
    {
        for (MScan &s : scans)
            if (!s.ended)
                for (MPart &p : s.parts)
                    if (!p.finished && roll(100) < 40) {
                        p.finished = true;
                        p.itemSeq = ++seq;
                    }
    }
    void closeOne()
    {
        QList<int> open;
        for (int i = 0; i < scans.size(); ++i)
            if (!scans.at(i).ended)
                open << i;
        if (!open.isEmpty())
            endScan(scans[open.at(roll(int(open.size())))], false);
    }
};

struct MResult {
    path::ProbeStamp stamp;
    path::PathOutcome outcome;
    qint64 bytes;
};

} // namespace

static int runModel(unsigned seed, QStringList &broke)
{
    std::mt19937 rng(seed);
    ModelHost host;
    host.rng = &rng;
    FakeApi api;
    FakeEngine engine;
    api.providerConfig = providerProfile();
    ScanPathProber prober(&host, &engine, &api);
    prober.pollIntervalMs = 0;
    QStringList trace; // the prober's own journal of this sequence, shown for the first broken ones (MODEL_VERBOSE)
    prober.log = [&trace](const QString &l) { trace << l; };
    QList<MResult> results;
    qint64 charged = 0; // the ledger charges (everything but the session fetch)
    prober.warmUp();
    for (int i = 0; i < 8; ++i) {
        host.processOne();
        host.deliverOne();
        QCoreApplication::processEvents(QEventLoop::AllEvents, 1);
    }
    prober.chargeApiBytes = [&charged](qint64 b) { charged += b; };

    host.refuseStarts = rng() % 4 == 0;
    host.refuseAddPercent = rng() % 3 == 0 ? 40 : 0;
    host.finalAckPercent = rng() % 4 == 0 ? 0 : 70;
    const bool refuses = host.refuseStarts;

    QHash<quint64, path::ProbeStamp> stamps;
    QSet<quint64> cancelled, ended;
    prober.onResult = [&](const path::ProbeStamp &s, path::PathOutcome o, qint64 b) {
        if (cancelled.contains(s.probe)) // checked AT the result: a cancelled probe never reports
            broke << QStringLiteral("I1 probe %1 reported a result after its cancel").arg(s.probe);
        results << MResult{s, o, b};
    };
    quint64 nextProbe = 1;
    const int steps = 20 + int(rng() % 60);
    const auto fail = [&](const QString &what) { broke << what; };
    const auto checkResults = [&]() {
        QSet<quint64> seen;
        for (const MResult &r : results) {
            if (seen.contains(r.stamp.probe))
                fail(QStringLiteral("I1 probe %1 ended twice").arg(r.stamp.probe));
            seen.insert(r.stamp.probe);
        }
    };

    const auto record = [&]() {
        for (const MResult &r : results)
            ended.insert(r.stamp.probe);
    };

    for (int step = 0; step < steps; ++step) {
        const int a = int(rng() % 100);
        if (a < 14 && nextProbe <= 7) {
            const int kind = int(rng() % 3);
            prober.xrayBurst = kind == 2 ? 4 : 1;
            path::PathCandidate c;
            c.id.id = kind == 0 ? QStringLiteral("16") : (rng() % 2 ? QStringLiteral("11:xray") : QStringLiteral("12:xray"));
            c.kind = kind == 0 ? path::PathKind::OwnAwg : path::PathKind::OwnXray;
            const path::ProbeStamp s{1, 1, nextProbe++};
            stamps.insert(s.probe, s);
            prober.start(s, c, 4000);
        } else if (a < 40) {
            host.processOne();
        } else if (a < 62) {
            host.deliverOne();
        } else if (a < 70) {
            host.finishSome();
        } else if (a < 76) {
            host.closeOne();
        } else if (a < 86) {
            QList<quint64> live;
            for (auto it = stamps.constBegin(); it != stamps.constEnd(); ++it)
                if (!ended.contains(it.key()) && !cancelled.contains(it.key()))
                    live << it.key();
            if (!live.isEmpty()) {
                const quint64 k = live.at(int(rng() % unsigned(live.size())));
                cancelled.insert(k);
                prober.cancel(stamps.value(k));
            }
        } else {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 1);
        }
        record();
        checkResults();
        for (const QString &v : host.violations)
            fail(v);
        host.violations.clear();
    }

    // The race ends: everything still wanted is cancelled; then the dust settles (bounded).
    for (auto it = stamps.constBegin(); it != stamps.constEnd(); ++it)
        if (!ended.contains(it.key()) && !cancelled.contains(it.key())) {
            // a probe the race still waits for at its end is left to finish by itself first (liveness), bounded below
        }
    int idle = 0;
    for (int i = 0; i < 4000 && idle < 40; ++i) {
        bool did = false;
        did = host.processOne() || did;
        host.finishSome();
        did = host.deliverOne() || did;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 1);
        record();
        idle = did ? 0 : idle + 1;
        if (idle == 20) {
            // quiescence: every probe has ended or been cancelled, so no scan may still be open at the host (a scan nobody
            // wants any more must have been cancelled: its AmneziaWG sessions would run beside the tunnel)
            for (const MScan &s : host.scans)
                if (!s.ended)
                    fail(QStringLiteral("I4 scan %1 is still open at the host with no probe wanting it").arg(s.id));
            host.closeOne(); // the host's deadline: whatever still runs ends
        }
    }
    // what is still live now has waited for ever
    QSet<quint64> stuck;
    for (auto it = stamps.constBegin(); it != stamps.constEnd(); ++it)
        if (!ended.contains(it.key()) && !cancelled.contains(it.key()))
            stuck.insert(it.key());
    for (quint64 k : stuck)
        fail(QStringLiteral("I1 probe %1 waits for ever").arg(k));
    // the race over: cancel the stuck ones (the owner would) so the host side can settle for the byte checks
    for (quint64 k : stuck) {
        cancelled.insert(k);
        prober.cancel(stamps.value(k));
    }
    // every other probe was cancelled mid-run or already ended: the host must have no live scan of this race
    for (int i = 0; i < 400; ++i) {
        host.processOne();
        host.deliverOne();
        QCoreApplication::processEvents(QEventLoop::AllEvents, 1);
    }
    record();
    checkResults();

    // I2, I5, I7
    for (const MResult &r : results) {
        const QStringList parts = host.partsOfProbe.value(r.stamp.probe);
        if (r.outcome == path::PathOutcome::ProbeOk)
            for (const QString &id : parts)
                if (host.deliveredItems.value(id) < 1)
                    fail(QStringLiteral("I2 probe %1 proven without a delivered result of part %2").arg(r.stamp.probe).arg(id));
        bool itemDelivered = false; // the app was TOLD (a delivered poll item) that the host ran a part of this probe
        for (const QString &id : parts)
            itemDelivered = itemDelivered || host.currentItems.value(id) > 0;
        if (itemDelivered && r.bytes < 0)
            fail(QStringLiteral("I5 probe %1: the host reported its parts' spend but the result says no byte was sent (refunded)").arg(r.stamp.probe));
        if (!host.acceptedProbes.contains(r.stamp.probe) && r.bytes >= 0)
            fail(QStringLiteral("I5 probe %1 never reached the host but reports %2 bytes (charged as if sent)").arg(r.stamp.probe).arg(r.bytes));
        if (!refuses && host.refuseAddPercent == 0 && !cancelled.contains(r.stamp.probe) && r.outcome != path::PathOutcome::ProbeOk
            && !parts.isEmpty()) {
            bool allOk = true;
            for (const QString &id : parts)
                for (const MScan &s : host.scans)
                    for (const MPart &p : s.parts)
                        if (p.id == id && !p.ok)
                            allOk = false;
            if (allOk)
                fail(QStringLiteral("I7 probe %1 had every part succeed at the host but ended unproven").arg(r.stamp.probe));
        }
    }
    // I4: a cancelled probe does not run at the host
    for (const MScan &s : host.scans)
        if (!s.cancelled && !s.ended)
            for (const MPart &p : s.parts)
                if (cancelled.contains(ModelHost::probeOf(p.id)))
                    fail(QStringLiteral("I4 part %1 of a cancelled probe still runs in %2").arg(p.id, s.id));
    // I6: bytes
    qint64 sent = 0, unknown = 0;
    for (const MScan &s : host.scans) {
        sent += s.total();
        if (s.cancelAsked && !s.finalDelivered)
            unknown += s.total(); // the only scans whose total the app may never learn (a cancel ack without a final total)
    }
    qint64 paid = charged;
    for (const MResult &r : results)
        if (r.bytes > 0)
            paid += r.bytes;
    if (std::getenv("MODEL_TRACE")) {
        for (const MScan &s : host.scans)
            std::fprintf(stderr, "  [host] %s total=%lld final=%d cancelled=%d parts=%d\n", qPrintable(s.id), (long long)s.total(), int(s.finalDelivered), int(s.cancelled), int(s.parts.size()));
        for (const MResult &r : results)
            std::fprintf(stderr, "  [result] probe=%llu bytes=%lld\n", (unsigned long long)r.stamp.probe, (long long)r.bytes);
        std::fprintf(stderr, "  [charged] %lld\n", (long long)charged);
    }
    if (paid > sent)
        fail(QStringLiteral("I6 charged %1 bytes, the host sent only %2 (never more)").arg(paid).arg(sent));
    if (paid < sent - unknown)
        fail(QStringLiteral("I6 charged %1 bytes, the host sent %2 (%3 of it in scans without a final total): bytes vanished")
                 .arg(paid).arg(sent).arg(unknown));
    if (!broke.isEmpty() && std::getenv("MODEL_VERBOSE")) {
        static int shown = 0;
        if (shown++ < 3) {
            std::fprintf(stderr, "--- trace of seed %u\n", seed);
            for (const QString &l : trace)
                std::fprintf(stderr, "  %s\n", qPrintable(l));
            for (const MScan &s : host.scans)
                std::fprintf(stderr, "  [host] %s total=%lld final=%d cancelled=%d ended=%d parts=%d\n", qPrintable(s.id), (long long)s.total(), int(s.finalDelivered), int(s.cancelled), int(s.ended), int(s.parts.size()));
            for (const MResult &r : results)
                std::fprintf(stderr, "  [result] probe=%llu bytes=%lld outcome=%s\n", (unsigned long long)r.stamp.probe, (long long)r.bytes, path::pathOutcomeName(r.outcome));
        }
    }
    return broke.isEmpty() ? 0 : 1;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (qEnvironmentVariableIntValue("MODEL_SEED") > 0) {
        const int n = qMax(1, qEnvironmentVariableIntValue("MODEL_COUNT"));
        for (int k = 0; k < n; ++k) {
            QStringList broke;
            runModel(unsigned(qEnvironmentVariableIntValue("MODEL_SEED") + k), broke);
            for (const QString &b : broke)
                std::printf("seed %d: %s\n", qEnvironmentVariableIntValue("MODEL_SEED") + k, qPrintable(b));
        }
        return 0;
    }
    const int runs = qEnvironmentVariableIntValue("MODEL_RUNS") > 0 ? qEnvironmentVariableIntValue("MODEL_RUNS") : 3000;
    QHash<QString, int> kinds;
    QString firstOfKind;
    int badRuns = 0;
    for (int i = 0; i < runs; ++i) {
        QStringList broke;
        runModel(unsigned(1000 + i), broke);
        if (!broke.isEmpty())
            ++badRuns;
        QSet<QString> seen;
        for (const QString &b : broke) {
            const QString kind = b.left(b.indexOf(QLatin1Char(' ')));
            if (seen.contains(kind))
                continue;
            seen.insert(kind);
            if (!kinds.contains(kind) && std::getenv("MODEL_VERBOSE"))
                std::fprintf(stderr, "seed %u: %s\n", unsigned(1000 + i), qPrintable(b));
            kinds[kind] += 1;
        }
    }
    std::printf("prober model: %d sequences, %d broke an invariant\n", runs, badRuns);
    QStringList names = kinds.keys();
    names.sort();
    for (const QString &k : names)
        std::printf("  %s: %d sequences\n", qPrintable(k), kinds.value(k));
    return badRuns == 0 ? 0 : 1;
}
