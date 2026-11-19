// AVPN path engine stage 2: a MODEL CHECK of the race's probe host adapter (ScanPathProber).
//
// The real ScanPathProber is driven with random sequences against a model host that keeps the ground truth (which part
// ran in which scan, how many bytes it really sent) and that is hostile in the ways a real transport is: requests are
// processed late (the host can close a scan before an add it was sent is processed), replies arrive late, out of order
// and twice, a scan is closed by the host at a random moment, scan_start / scan_add are refused at random, a cancel
// ack carries the final byte total or not, a probe is cancelled at a random moment, the race ends.
//
// Invariants (checked after every step and at the end):
//   I1 every probe ends EXACTLY once (a result) or is cancelled / dropped by the race's end (then never a result); nothing
//      waits for ever
//   I2 a probe is proven only if every part id it sent reported data in a delivered poll answer
//   I3 no part runs at the host twice at the same time (accepted into a second scan while the first one is live),
//      and a part is never accepted twice into one scan
//   I4 once the race has ended no scan of it is open at the host (its AmneziaWG sessions would run beside the tunnel)
//   I5 nothing leaks: once the dust settles the prober follows no scan except one whose final total never came
//   I6 bytes, EXACT: the prober charged, for every scan, the host's own cumulative total as the replies showed it - the
//      scan's FINAL total where a final reply was delivered (the opening and closing /netinfo and a stopped probe's bytes
//      included), the last total shown otherwise. Never more than the host sent. The only shortfall is a scan whose final
//      never arrived (the host replaced it, or its final never came): counted and printed (MODEL_STATS)
//   I8 settling: a cancelled probe is settled (its hold on the race's cap may end) at most once, and - once no scan is followed
//      any more - every probe cancelled by the race has been settled (never earlier than its cancel)
//   I7 liveness: a probe whose parts all succeed at the host ends proven (when the host refused nothing)
//
// Host contract the model follows (quoted from the real host, recipes/amnezia-libxray/patches/0012-tribe-scan-engine.patch,
// scan engine loop): "The queue drained: done, "complete", NOT final - the scan stays open for scan_add until the deadline
// or the app's freeze + cancel." and `closed bool // past the deadline or stopped: scan_add accepts nothing`; the
// ScanHostContract.h text says the same ("complete" = the host's queue is drained; it stays open for scan_add until its
// deadline). So a poll may report done=true / final=false while an add is in flight and the add is still accepted; and
// a poll answer carrying a part's result may arrive BEFORE the ack of the scan_add that carried the part (replies are
// delivered in any order here).
// The cancel (scan_cancel handler of the same patch): "Step 2, answered at once: every probe ends, then the closing access
// attempt, then the final scan_progress (done, final, bytes_spent, access_close). The ack carries the final total only when
// the scan is already over." - so the ack of a running scan has NO final, and the closing /netinfo and the stopped probes'
// bytes show up in LATER polls (every scan_progress carries the scan's cumulative `bytes_spent`: Progress{BytesSpent:
// s.gate.Spent(), ..., Final: s.final}); the model keeps a cancelled scan "closing" for a random number of polls. And scan_start
// (start()): "teardownLocked(old, ReasonCancelled)" then `current.scan = s` - the old scan is no longer the current one and
// its polls answer unknown_scan: a scan replaced by a newer start has no final total for the app (its closing /netinfo is
// not attempted: "a teardown cancelled it").
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
    bool replaced = false;       // a newer scan_start took the host's one scan: polls answer unknown_scan, no closing, no final
    bool closingDone = false;    // the closing /netinfo ran and the scan is final
    bool neverFinal = false;     // a host whose final never comes (the bound of the app's polling ends it)
    int closeAfterPolls = 0;     // polls answered "closing" after a cancel before the final
    int pollsSinceCancel = 0;
    bool cancelAsked = false;
    bool finalDelivered = false; // a reply with final=true was delivered to the app (a poll or a cancel ack)
    qint64 lastDelivered = 0;    // the largest bytes_spent any delivered reply of this scan showed
    static constexpr qint64 kOpening = 2048; // the host's opening /netinfo, in the total from the start
    static constexpr qint64 kClosing = 2048; // the closing /netinfo, in the total at the final
    qint64 total() const
    {
        qint64 t = kOpening + (closingDone ? kClosing : 0);
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

    void endScan(MScan &s, bool cancel, bool bySuccessor = false)
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
        if (bySuccessor)
            s.replaced = true;      // torn down by the next scan_start: no closing /netinfo, no final, unknown_scan from now on
        else if (!cancel)
            s.closingDone = true;   // the host's own end (deadline): the closing check ran, the scan is final
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
                    if (!other.replaced && !other.closingDone) {
                        if (other.ended)
                            other.replaced = true; // a cancelled scan still closing is cut off
                        else
                            endScan(other, true, true);
                    }
                s.closeAfterPolls = roll(4);
                s.neverFinal = roll(100) < 4;
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
            if (!s || s->replaced) {
                r = QJsonObject{{"error", "unknown_scan"}, {"scan_id", id}};
            } else {
                if (s->cancelled && !s->closingDone && !s->neverFinal && s->pollsSinceCancel++ >= s->closeAfterPolls)
                    s->closingDone = true; // the closing /netinfo ran: its bytes are in the total from now on
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
                const bool done = allFinished || s->ended; // the queue drained (the scan may stay open for scan_add)
                const bool fin = s->closingDone;           // nothing in flight, closing check done: the total is final
                r = QJsonObject{{"type", "scan_progress"}, {"scan_id", id}, {"seq", double(seq)}, {"phase", done ? "done" : "data"},
                                {"items", items}, {"bytes_spent", double(s->total())}, {"bytes_reserved", 0}, {"mem_mb", 41},
                                {"done", done}, {"reason", done ? (s->cancelled ? "cancelled" : "complete") : ""}, {"access", QJsonValue::Null},
                                {"access_close", QJsonValue::Null}, {"gen", QJsonValue::Null}};
                if (fin)
                    r.insert("final", true);
                ob.final = fin;
            }
        } else if (a == "scan_cancel") {
            MScan *s = scanById(id);
            if (s && !s->replaced) {
                s->cancelAsked = true;
                endScan(*s, true);
                ob.isCancelAck = true;
                // answered at once: the final total only when the scan is already over
                r = s->closingDone ? scanEncodeCancelAck(id, s->total(), 40) : scanEncodeAck(id, 0, 40);
                ob.final = s->closingDone;
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
        const QJsonObject o = QJsonDocument::fromJson(ob.bytes).object();
        if (MScan *s = scanById(ob.scanId)) { // what this reply shows the app of the scan's cumulative counter
            if (o.value("type").toString() == "scan_progress") {
                s->lastDelivered = qMax(s->lastDelivered, qint64(o.value("bytes_spent").toDouble()));
                s->finalDelivered = s->finalDelivered || o.value("final").toBool();
            } else if (ob.isCancelAck && ob.final) {
                s->lastDelivered = qMax(s->lastDelivered, qint64(o.value("bytes_spent").toDouble()));
                s->finalDelivered = true;
            }
        }
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

static long g_modelReplaced = 0, g_modelNeverFinal = 0, g_modelOther = 0;
static long g_modelNoFinal = 0, g_modelScans = 0, g_modelMissing = 0, g_modelSent = 0;

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
    QSet<quint64> cancelledByCall, settledProbes;
    prober.onSpent = [&charged](quint64 race, qint64 b) { charged += (race == 1 ? b : 0); }; // one race: any other tag is a leak
    prober.onSettled = [&](const path::ProbeStamp &st) {
        if (settledProbes.contains(st.probe))
            broke << QStringLiteral("I8 probe %1 settled twice").arg(st.probe);
        if (!cancelledByCall.contains(st.probe))
            broke << QStringLiteral("I8 probe %1 settled without being cancelled").arg(st.probe);
        settledProbes.insert(st.probe);
    };

    host.refuseStarts = rng() % 4 == 0;
    host.refuseAddPercent = rng() % 3 == 0 ? 40 : 0;
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
                cancelledByCall.insert(k);
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

    // The race ends. Mode A (even seeds): nothing is forced - the dust settles, then the engine's end of race (raceEnded) must
    // leave no scan open at the host (I4). Mode B (odd seeds): the host's deadline ends whatever runs, for liveness (I1).
    const bool endByRace = seed % 2 == 0;
    QSet<quint64> stuck;
    int idle = 0;
    for (int i = 0; i < 4000 && idle < 40; ++i) {
        bool did = false;
        did = host.processOne() || did;
        host.finishSome();
        did = host.deliverOne() || did;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 1);
        record();
        idle = did ? 0 : idle + 1;
        if (idle == 20 && !endByRace)
            host.closeOne(); // the host's deadline: whatever still runs ends
    }
    if (!endByRace) {
        for (auto it = stamps.constBegin(); it != stamps.constEnd(); ++it)
            if (!ended.contains(it.key()) && !cancelled.contains(it.key()))
                stuck.insert(it.key());
        for (quint64 k : stuck)
            fail(QStringLiteral("I1 probe %1 waits for ever").arg(k)); // what is still live now has waited for ever
    }
    // the race is over: the engine tells the prober (the probes it still held are cancelled with it)
    for (auto it = stamps.constBegin(); it != stamps.constEnd(); ++it)
        if (!ended.contains(it.key()) && !cancelled.contains(it.key()))
            cancelled.insert(it.key()); // dropped by the race's end: never a result afterwards
    prober.raceEnded(1);
    for (int i = 0; i < 600; ++i) { // the host settles: the cancel, the closing /netinfo, the finals
        host.processOne();
        host.deliverOne();
        QCoreApplication::processEvents(QEventLoop::AllEvents, 1);
    }
    record();
    checkResults();
    if (endByRace)
        for (const MScan &s : host.scans)
            if (!s.ended)
                fail(QStringLiteral("I4 scan %1 is still open at the host after the race ended").arg(s.id));
    if (prober.liveProbes() != 0)
        fail(QStringLiteral("I1 the prober still holds %1 probes after the race ended").arg(prober.liveProbes()));

    // I2, I7
    for (const MResult &r : results) {
        const QStringList parts = host.partsOfProbe.value(r.stamp.probe);
        if (r.outcome == path::PathOutcome::ProbeOk)
            for (const QString &id : parts)
                if (host.deliveredItems.value(id) < 1)
                    fail(QStringLiteral("I2 probe %1 proven without a delivered result of part %2").arg(r.stamp.probe).arg(id));
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
                if (cancelled.contains(ModelHost::probeOf(p.id)) && endByRace)
                    fail(QStringLiteral("I4 part %1 of a cancelled probe still runs in %2").arg(p.id, s.id));
    // I6: bytes - exact against the host's counter (see the header)
    qint64 sent = 0, expected = 0, missing = 0;
    int noFinal = 0, followedAtEnd = 0;
    for (const MScan &s : host.scans) {
        sent += s.total();
        if (s.finalDelivered) {
            expected += s.total();
        } else {
            expected += s.lastDelivered; // the last total the replies showed
            ++noFinal;
            missing += s.total() - s.lastDelivered;
            if (s.replaced)
                ++g_modelReplaced;       // cut off by the next scan_start (the host's own rule): no final exists to read
            else if (s.neverFinal && s.cancelled)
                ++g_modelNeverFinal;     // a host whose final never comes: the bound ends the polling
            else {
                ++g_modelOther;          // the host would have said final: the prober stopped asking too early
                if (std::getenv("MODEL_TRACE"))
                    std::fprintf(stderr, "  [other] %s total=%lld shown=%lld cancelled=%d ended=%d closing=%d\n", qPrintable(s.id), (long long)s.total(), (long long)s.lastDelivered, int(s.cancelled), int(s.ended), int(s.closingDone));
            }
        }
    }
    followedAtEnd = prober.scansFollowed();
    g_modelNoFinal += noFinal;
    g_modelScans += int(host.scans.size());
    g_modelMissing += missing;
    g_modelSent += sent;
    if (std::getenv("MODEL_TRACE")) {
        for (const MScan &s : host.scans)
            std::fprintf(stderr, "  [host] %s total=%lld shown=%lld final=%d cancelled=%d replaced=%d neverFinal=%d parts=%d\n", qPrintable(s.id), (long long)s.total(), (long long)s.lastDelivered, int(s.finalDelivered), int(s.cancelled), int(s.replaced), int(s.neverFinal), int(s.parts.size()));
        std::fprintf(stderr, "  [charged] %lld expected %lld\n", (long long)charged, (long long)expected);
    }
    if (charged > sent)
        fail(QStringLiteral("I6 charged %1 bytes, the host sent only %2 (never more)").arg(charged).arg(sent));
    if (charged != expected)
        fail(QStringLiteral("I6 charged %1 bytes, the host's counters showed %2 (the host sent %3, %4 of it in %5 scans whose final never came)")
                 .arg(charged).arg(expected).arg(sent).arg(missing).arg(noFinal));
    // I8: once nothing is followed, every probe cancelled by call is settled
    if (prober.scansFollowed() == 0)
        for (quint64 k : cancelledByCall)
            if (!settledProbes.contains(k))
                fail(QStringLiteral("I8 probe %1 was cancelled but never settled").arg(k));
    // I5: nothing leaks - what the prober still follows is only a scan whose final never came
    int neverFinalScans = 0;
    for (const MScan &s : host.scans)
        if (!s.finalDelivered && !s.replaced && s.cancelled)
            ++neverFinalScans;
    if (followedAtEnd > neverFinalScans + 1) // (+1: a scan the host left open and the prober still polls)
        fail(QStringLiteral("I5 the prober still follows %1 scans (%2 can have no final)").arg(followedAtEnd).arg(neverFinalScans));
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
    std::printf("  scans %ld; without a final total at the app %ld (%.1f%%): cut off by a newer scan_start %ld, final never sent by the host %ld, other %ld\n",
                g_modelScans, g_modelNoFinal, g_modelScans ? 100.0 * g_modelNoFinal / g_modelScans : 0.0, g_modelReplaced, g_modelNeverFinal, g_modelOther);
    std::printf("  bytes the host sent %ld, never shown to the app %ld (%.2f%%)\n", g_modelSent, g_modelMissing,
                g_modelSent ? 100.0 * g_modelMissing / g_modelSent : 0.0);
    QStringList names = kinds.keys();
    names.sort();
    for (const QString &k : names)
        std::printf("  %s: %d sequences\n", qPrintable(k), kinds.value(k));
    return badRuns == 0 ? 0 : 1;
}
