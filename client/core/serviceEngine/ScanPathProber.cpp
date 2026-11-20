// client/core/serviceEngine/ScanPathProber.cpp - see ScanPathProber.h.
#include "ScanPathProber.h"

#include "ScanBudget.h"
#include "ScanPlan.h"
#include "XrayProfileSanitizer.h"

#include <QDateTime>
#include <QUrl>

namespace avpn {

ScanPathProber::ScanPathProber(IScanHost *host, IScanEngine *engine, IRaceScanApi *api, QObject *parent)
    : QObject(parent), m_host(host), m_engine(engine), m_api(api)
{
    m_clock.start();
    m_pollTimer.setSingleShot(true);
    QObject::connect(&m_pollTimer, &QTimer::timeout, this, [this]() { poll(); });
}

ScanPathProber::~ScanPathProber()
{
    *m_alive = false; // the probes' seats go with m_probes (their owners)
}

qint64 ScanPathProber::now() const { return wallNow ? wallNow() : QDateTime::currentMSecsSinceEpoch(); }

QString ScanPathProber::networkKey() const
{
    const QString k = m_engine ? m_engine->network().reportingKey : QString();
    return k.isEmpty() ? QStringLiteral("unknown") : k;
}

ScanTunables ScanPathProber::tunables() const
{
    return m_session.numbers.isEmpty() ? ScanTunables() : ScanTunables::fromNumbers(m_session.numbers);
}

bool ScanPathProber::sessionReady() const { return scanPathSessionFresh(m_session, networkKey(), now(), m_sessionAtMs); }

path::ProberCaps ScanPathProber::caps() const
{
    const bool usable = m_host && m_api && m_api->configured() && m_capsKnown
                        && m_host->availability() == ScanHostAvailability::Available && !(hostBusy && hostBusy());
    path::ProberCaps c = scanPathProberCaps(m_caps, usable);
    c.ready = sessionReady(); // the race starts probes only when they can really leave (ServiceEngine::beginRaceForTap)
    c.preparing = m_sessionFetching;
    return c;
}

path::PathRace::Costs ScanPathProber::raceCosts(const ScanTunables &t, int xrayBurst)
{
    const qint64 body = qMin<qint64>(t.stage2Bytes, kRaceProbeBytes);       // openScan: req.bytes
    const qint64 data = qint64(t.warmBytes) + body + 2 * kScanTlsOverheadBytes; // one data connection
    const qint64 access = t.costApiBytes;                                     // the host's /netinfo of a scan: one opening
    // UPPER BOUNDS for admission only (PathRace: spent so far + what the probes in flight hold + its own bound <= cap);
    // nothing is charged by them. Each bound includes one access check (a scan's opening; the closing and a reopen come
    // later, as real bytes) - an over-estimate for every probe but the first of a scan, which is safe. Device 19.11:
    // proven AmneziaWG probe 36 338 B (bound 54 572), proven provider probe 36 214 B (its host part; bound 117 760 with
    // the seat batch, config and release), a failed Xray burst part 2 048 B (part bound 21 504), own Xray with its burst
    // 92 723 B (bound 116 736).
    //
    // WHERE EVERY BYTE OF A RACE IS COUNTED. One stream, ScanPathProber::onSpent(bytes), each byte once; the engine puts
    // it on the race's cap (PathRace::spent) and on the Scanner's hour ledger (raceCharge) - nothing else charges either.
    //   traffic                              spent by                         reaches onSpent
    //   host: probe data, bursts, AWG,       the host's cumulative            the DELTA of every reply that shows a larger
    //     provider probe, the scan's          bytes_spent of each scan         total than the last seen for that scan
    //     opening and closing /netinfo                                        (poll replies, a final cancel ack); a cancelled
    //                                                                          scan is polled until `final` (or a bound)
    //   session fetch (manifest + token)     ScanApiClient (real bytes)       sessionArrived(): once per fetch; counted on the
    //                                                                          cap only if a race runs then (a fetch before
    //                                                                          the tap is already out of the hour's bytesLeft)
    //   provider seat batch with config      ScanSeatBatch (real bytes)       probeSeat callback: once per ask (also an answer
    //                                                                          that comes after its probe ended)
    //   provider seat release                ScanSeatBatch (real bytes)       the release owner's releaseBytes: once per release
    // A probe's own result carries no byte number for accounting; a probe that never left the app (refused locally, no
    // session) spends nothing and holds its bound only while it is "in flight".
    path::PathRace::Costs c;
    c.xray = data + qint64(qBound(1, xrayBurst, 6) - 1) * scanXrayBurstPartCostBytes(t) + access;
    c.awg = kScanAwgHandshakeBytes + qint64(t.awgPrimeEchoes) * kScanAwgEchoBytes + data + access;
    c.providerTail = qint64(kScanSeatReleaseSends) * t.costApiBytes; // the release chain: what a finished provider probe can still spend
    c.provider = data + qint64(t.costBatchBytes) + t.costConfigBytes + c.providerTail + access;
    return c;
}

void ScanPathProber::warmUp()
{
    if (m_host && m_host->availability() == ScanHostAvailability::Available && !m_capsAsked) {
        m_capsAsked = true;
        const std::weak_ptr<bool> alive = m_alive;
        m_host->sendMessage(scanCompact(scanEncodeCaps()), [this, alive](const QByteArray &reply) {
            if (!alive.lock())
                return;
            m_capsAsked = false;
            const ScanHostReply r = scanDecodeReply(reply);
            if (r.kind == ScanHostReplyKind::Caps) {
                m_caps = r.caps;
                m_capsKnown = true;
                say(QStringLiteral("race_prober caps full=%1 legs=%2 awg=%3 composite=%4")
                        .arg(m_caps.maxFullConcurrent).arg(m_caps.maxLegConcurrent).arg(m_caps.maxAwgConcurrent)
                        .arg(m_caps.canVerifyComposite));
            }
        });
    }
    if (!sessionReady())
        fetchSession(0);
}

void ScanPathProber::fetchSession(quint64 race)
{
    if (m_sessionFetching || !m_api || !m_api->configured())
        return;
    m_sessionFetching = true;
    m_fetchRace = race; // the race whose probe asked for it (a warm-up: none)
    const QString key = networkKey();
    const std::weak_ptr<bool> alive = m_alive;
    m_api->session(key, [this, alive](const RaceScanSession &s) {
        if (alive.lock())
            sessionArrived(s);
    });
}

void ScanPathProber::sessionArrived(const RaceScanSession &s)
{
    m_sessionFetching = false;
    spend(m_fetchRace, s.bytes);
    const QSet<quint64> watchers = m_sessionWatchers; // the fetch they asked for is over
    m_sessionWatchers.clear();
    for (quint64 k : watchers)
        settleOne(k);
    if (s.ok) {
        m_session = s;
        m_sessionAtMs = now();
    }
    say(QStringLiteral("race_prober session ok=%1 reason=%2 awg_nodes=%3 base_ips=%4 bytes=%5")
            .arg(s.ok).arg(s.reason).arg(s.awgNodes.size()).arg(s.baseIps.size()).arg(s.bytes));
    const QList<quint64> waiting = m_probes.keys();
    for (quint64 key : waiting) {
        auto it = m_probes.find(key);
        if (it == m_probes.end() || !it->waitingSession)
            continue;
        it->waitingSession = false;
        if (!sessionReady())
            finish(key, path::PathOutcome::Inconclusive, "no_session");
        else
            launch(key);
    }
}

void ScanPathProber::start(const path::ProbeStamp &stamp, const path::PathCandidate &path, int timeoutMs)
{
    Q_UNUSED(timeoutMs) // the race bounds the probe itself; the host bounds each job by its limits
    Probe p;
    p.stamp = stamp;
    p.path = path;
    const quint64 key = stamp.probe;
    m_probes.insert(key, p);
    if (!m_host || !m_api || !m_engine) {
        finishLater(key, "no_host");
        return;
    }
    if (!sessionReady()) {
        m_probes[key].waitingSession = true;
        fetchSession(stamp.race);
        if (!m_sessionFetching) // not configured: nothing will come
            finishLater(key, "no_session");
        return;
    }
    // Launched from the next turn of the event loop: a result never comes from inside start().
    const std::weak_ptr<bool> alive = m_alive;
    QTimer::singleShot(0, this, [this, alive, key]() {
        if (alive.lock() && m_probes.contains(key))
            launch(key);
    });
}

void ScanPathProber::launch(quint64 key)
{
    auto it = m_probes.find(key);
    if (it == m_probes.end())
        return;
    const path::PathCandidate &pc = it->path;
    const ScanTunables t = tunables();
    ScanHostCandidate c;
    c.id = QStringLiteral("race%1-%2").arg(it->stamp.race).arg(key);
    c.reachAtMs = -1; // no reach stage: the race bounds the probe itself
    switch (pc.kind) {
    case path::PathKind::OwnXray: {
        ScanCandidate sc;
        sc.id = pc.id.id;
        sc.origin = ScanOrigin::Own;
        sc.kind = m_caps.maxLegConcurrent > 0 ? ScanProbeKind::XrayLeg : ScanProbeKind::XrayFull;
        c.kind = sc.kind;
        c.config = m_engine->ownProbeConfig(sc);
        if (c.config.isEmpty()) {
            finish(key, path::PathOutcome::Inconclusive, "no_config");
            return;
        }
        c.costBytes = qint64(t.warmBytes) + kRaceProbeBytes + 2 * kScanTlsOverheadBytes;
        const QList<ScanHostCandidate> parts = scanXrayBurstOf(c, qBound(1, xrayBurst, 6), t);
        it->parts = int(parts.size());
        for (const ScanHostCandidate &part : parts)
            sendCandidate(key, part);
        return;
    }
    case path::PathKind::OwnAwg: {
        const auto mark = m_session.awgNodes.constFind(pc.id.id);
        ScanAwgNodeInput n;
        if (m_caps.maxAwgConcurrent <= 0 || t.awgConcurrency <= 0 || mark == m_session.awgNodes.constEnd()
            || m_session.baseIps.isEmpty() || !m_engine->awgProbeInput(pc.id.id, n)) {
            finish(key, path::PathOutcome::Inconclusive, m_caps.maxAwgConcurrent <= 0 ? "awg_no_host"
                   : t.awgConcurrency <= 0                 ? "awg_off"
                   : mark == m_session.awgNodes.constEnd() ? "awg_no_peer"
                   : m_session.baseIps.isEmpty()            ? "awg_no_api_ip"
                                                            : "awg_no_input");
            return;
        }
        ScanAwgMiniInput in;
        in.privateKey = n.privateKey;
        in.address = n.address;
        in.mtu = n.mtu;
        in.peerPublicKey = n.peerPublicKey;
        in.presharedKey = n.presharedKey;
        in.endpoint = n.endpoint;
        in.obfuscation = n.obfuscation;
        in.boundIf = n.boundIf;
        const QUrl base(m_session.probeBase);
        in.probeHost = base.host();
        in.probeIp = m_session.baseIps.first();
        in.probePort = base.port(443);
        in.echoTarget = mark.value();
        c.kind = ScanProbeKind::AwgMini;
        c.config = scanAwgMiniConfig(in);
        if (c.config.isEmpty()) {
            finish(key, path::PathOutcome::Inconclusive, "awg_config");
            return;
        }
        break;
    }
    case path::PathKind::Provider: {
        if (m_caps.maxFullConcurrent <= 0) {
            finish(key, path::PathOutcome::Inconclusive, "no_full_pool");
            return;
        }
        const QString profileId = pc.id.id.startsWith(QLatin1String("up:")) ? pc.id.id.mid(3) : pc.id.id;
        it->waitingSeat = true;
        const std::weak_ptr<bool> alive = m_alive;
        const QString nodeId = pc.id.id;
        const quint64 race = it->stamp.race; // the seat batch and its release are this race's bytes
        const auto charge = [this, alive, race](qint64 bytes) {
            if (alive.lock())
                spend(race, bytes);
        };
        // The cut is the price the race paid for this probe (raceCosts: the batch with its config).
        const std::shared_ptr<IRaceSeat> owner = m_api->probeSeat(profileId, qint64(t.costBatchBytes) + t.costConfigBytes,
                                                                  [this, alive, key, profileId, nodeId, charge](const IRaceScanApi::Seat &seat) {
            if (!alive.lock())
                return;
            charge(seat.bytes);
            auto p = m_probes.find(key);
            if (p == m_probes.end())
                return; // the probe went away while the seat was asked: its owner released the seat
            p->waitingSeat = false;
            if (!seat.ok || seat.leaseId.isEmpty() || seat.config.isEmpty()) {
                finish(key, path::PathOutcome::Inconclusive, seat.code == QLatin1String("lease_gone") ? "seat_gone" : "no_seat");
                return;
            }
            const SanitizedProfile chk = upstreamProfileCheck(seat.config.toUtf8(), seat.configSha256,
                                                              m_engine->upstreamProtocolTags(nodeId));
            if (!chk.ok()) {
                finish(key, path::PathOutcome::Inconclusive, "profile_refused");
                return;
            }
            ScanHostCandidate hc;
            hc.id = QStringLiteral("race%1-%2").arg(p->stamp.race).arg(key);
            hc.kind = ScanProbeKind::XrayFull;
            hc.config = seat.config;
            hc.profileId = profileId;
            hc.earlyRetry = true;
            hc.reachAtMs = -1;
            hc.costBytes = scanProbeCostBytes(ScanProbeKind::XrayFull, false, tunables());
            sendCandidate(key, hc);
        }, charge);
        const auto p = m_probes.find(key);
        if (p != m_probes.end())
            p->seat = owner;
        return;
    }
    }
    c.costBytes = scanProbeCostBytes(c.kind, false, t);
    sendCandidate(key, c);
}

void ScanPathProber::sendCandidate(quint64 key, const ScanHostCandidate &c)
{
    auto it = m_probes.find(key);
    if (it == m_probes.end())
        return;
    if (it->hostId.isEmpty() || !c.id.contains(QLatin1Char('.')))
        it->hostId = c.id;
    bool known = false;
    for (const ScanHostCandidate &s : it->sent)
        known = known || s.id == c.id;
    if (!known)
        it->sent << c; // a re-send of a refused add keeps one entry per part
    const quint64 race = it->stamp.race;
    if (m_scan.closed || m_scan.race != race) {
        openScan(race, {c});
        return;
    }
    it->scanId = m_scan.id;
    it->partScan.insert(c.id, m_scan.id);
    if (!m_scan.acked) {
        m_scan.queued << c; // joins once the start is acked
        return;
    }
    const QString scanId = m_scan.id;
    const std::weak_ptr<bool> alive = m_alive;
    const QList<ScanHostCandidate> cands{c};
    m_host->sendMessage(scanCompact(scanEncodeAdd(scanId, cands)), [this, alive, scanId, cands](const QByteArray &reply) {
        if (alive.lock())
            onAddReply(scanId, cands, reply);
    });
}

void ScanPathProber::openScan(quint64 race, const QList<ScanHostCandidate> &cands)
{
    if (!m_scan.closed && m_scan.startSent)
        endHostScan(); // never two open scans: the old one is cancelled (and polled to its final) before a new one opens
    m_scan = HostScan();
    m_scan.id = QStringLiteral("race-%1-%2").arg(race).arg(++m_scanSeq);
    ScanBook book;
    book.race = race;
    m_books.insert(m_scan.id, book); // its host counter is followed until `final` (or unknown_scan, or the bound)
    m_scan.race = race;
    m_scan.closed = false;
    m_scan.startSent = true;
    for (const ScanHostCandidate &c : cands) {
        const quint64 key = keyOfHostId(c.id);
        if (m_probes.contains(key)) {
            Probe &p = m_probes[key]; // the one place a probe is bound to a scan: first open and every reopen alike
            p.scanId = m_scan.id;
            p.acceptedParts.clear();
            for (const ScanHostCandidate &pc : cands)
                if (keyOfHostId(pc.id) == key)
                    p.partScan.insert(pc.id, m_scan.id);
            // what already reported (doneParts, bytes, allOk) is the probe's own and stays
        }
    }
    const ScanTunables t = tunables();
    ScanStartRequest req;
    req.scanId = m_scan.id;
    req.deadlineMs = 20000; // above the race's own budget (8 s) and one probe's bound
    req.maxBytes = -1;      // the race pays every probe from the Scanner's ledger before it starts it
    req.limits = scanHostLimitsFrom(t, m_caps.maxFullConcurrent, m_caps.maxLegConcurrent,
                                    qMin(m_caps.maxAwgConcurrent, qMax(0, t.awgConcurrency)));
    req.probeBase = m_session.probeBase;
    req.token = m_session.token;
    req.warmBytes = t.warmBytes;
    req.bytes = qMin<int>(t.stage2Bytes, kRaceProbeBytes); // a race proves data, it does not rank speed: a smaller body
    req.probeBaseIps = m_session.baseIps;
    req.candidates = cands;
    const QString scanId = m_scan.id;
    const std::weak_ptr<bool> alive = m_alive;
    say(QStringLiteral("race_prober scan_start scan=%1 candidates=%2").arg(scanId).arg(cands.size()));
    m_host->sendMessage(scanCompact(scanEncodeStart(req)), [this, alive, scanId, cands](const QByteArray &reply) {
        if (alive.lock())
            onStartReply(scanId, cands, reply);
    });
}

void ScanPathProber::onStartReply(const QString &scanId, const QList<ScanHostCandidate> &cands, const QByteArray &reply)
{
    const ScanHostReply r = scanDecodeReply(reply);
    if (scanId != m_scan.id) { // a newer scan replaced it: a probe moved there is the new scan's, the rest is over
        for (const ScanHostCandidate &c : cands) {
            const quint64 key = keyOfHostId(c.id);
            const auto p = m_probes.constFind(key);
            if (p != m_probes.constEnd() && p->scanId == scanId)
                finish(key, path::PathOutcome::Inconclusive, "scan_replaced");
        }
        return;
    }
    if (r.kind != ScanHostReplyKind::Ack) {
        say(QStringLiteral("race_prober scan_start refused scan=%1 error=%2 %3").arg(scanId, r.errorCode, r.detail));
        m_scan.closed = true;
        dropBook(scanId); // the host never held this scan
        for (const ScanHostCandidate &c : cands + m_scan.queued)
            finish(keyOfHostId(c.id), path::PathOutcome::Inconclusive, "start_refused");
        m_scan.queued.clear();
        return;
    }
    m_scan.acked = true;
    for (const ScanHostCandidate &c : cands) {
        const auto p = m_probes.find(keyOfHostId(c.id));
        if (p != m_probes.end()) {
            p->acceptedParts.insert(c.id);
        }
    }
    const QList<ScanHostCandidate> queued = m_scan.queued;
    m_scan.queued.clear();
    if (!queued.isEmpty()) {
        const std::weak_ptr<bool> alive = m_alive;
        m_host->sendMessage(scanCompact(scanEncodeAdd(scanId, queued)), [this, alive, scanId, queued](const QByteArray &rep) {
            if (alive.lock())
                onAddReply(scanId, queued, rep);
        });
    }
    armPoll();
}

void ScanPathProber::onAddReply(const QString &scanId, const QList<ScanHostCandidate> &cands, const QByteArray &reply)
{
    if (scanId == m_scan.id) {
        const ScanHostReply r = scanDecodeReply(reply);
        if (r.kind == ScanHostReplyKind::Ack && r.accepted == cands.size()) {
            for (const ScanHostCandidate &c : cands) {
                const auto p = m_probes.find(keyOfHostId(c.id));
                if (p != m_probes.end())
                    p->acceptedParts.insert(c.id);
            }
            armPoll();
            return;
        }
        // The engine closed that scan (every candidate final, its deadline, a Scanner start replaced it): a part it had
        // already accepted gets no further answer either, so the whole scan is retired and every part that has not
        // reported goes into a new one.
        retireScan();
        return;
    }
    // An older scan's answer, or the refusal of the current one: each named part is resolved from its probe's own state.
    placeParts(scanId, cands);
}

void ScanPathProber::placeParts(const QString &fromScan, const QList<ScanHostCandidate> &cands)
{
    QList<ScanHostCandidate> again;
    for (const ScanHostCandidate &c : cands) {
        const auto p = m_probes.constFind(keyOfHostId(c.id));
        if (p == m_probes.constEnd() || p->doneParts.contains(c.id))
            continue; // gone, or already reported: nothing to run
        if (p->partScan.value(c.id) != fromScan)
            continue; // already named in another scan: that scan's own answer decides it
        again << c;
    }
    if (again.isEmpty())
        return;
    const quint64 race = m_probes.value(keyOfHostId(again.first().id)).stamp.race;
    if (m_scan.closed || m_scan.race != race) {
        openScan(race, again);
        return;
    }
    for (const ScanHostCandidate &c : again)
        sendCandidate(keyOfHostId(c.id), c);
}

// The scans the prober still follows: the current one while it is open, and every cancelled or closed one until the host
// said `final` (its last total), unknown_scan, or the bound passed - a scan is dropped for nothing else.
bool ScanPathProber::pollable(const QString &id, const ScanBook &b) const
{
    return b.forgetAtMs > 0 || (id == m_scan.id && m_scan.acked && !m_scan.closed);
}

void ScanPathProber::armPoll()
{
    if (m_pollTimer.isActive())
        return;
    for (auto it = m_books.constBegin(); it != m_books.constEnd(); ++it)
        if (pollable(it.key(), it.value())) {
            m_pollTimer.start(pollIntervalMs);
            return;
        }
}

void ScanPathProber::poll()
{
    const qint64 t = mono();
    const QStringList ids = m_books.keys();
    for (const QString &id : ids) {
        auto it = m_books.find(id);
        if (it == m_books.end())
            continue;
        if (it->forgetAtMs > 0 && t >= it->forgetAtMs) { // the bound: no final came (the host forgot it, a reply was lost)
            say(QStringLiteral("race_prober scan_forgot scan=%1 seen=%2").arg(id).arg(it->seen));
            ++m_withoutFinal;
            dropBook(id);
            continue;
        }
        if (!pollable(id, it.value()) || (it->pollSentAtMs >= 0 && t - it->pollSentAtMs < kPollStaleMs))
            continue; // a poll of it is still out
        it->pollSentAtMs = t;
        const qint64 since = it->lastSeq;
        const std::weak_ptr<bool> alive = m_alive;
        m_host->sendMessage(scanCompact(scanEncodePoll(id, since)), [this, alive, id](const QByteArray &reply) {
            if (alive.lock())
                onPollReply(id, reply);
        });
    }
    armPoll();
}

// The one entry point of the host's spend: a reply that shows a larger cumulative total than the last seen for that scan
// charges the difference, once. A smaller or equal total (a repeat, an older reply that came late) charges nothing.
void ScanPathProber::noteTotal(const QString &scanId, qint64 total)
{
    const auto it = m_books.find(scanId);
    if (it == m_books.end() || total <= it->seen)
        return;
    const qint64 delta = total - it->seen;
    it->seen = total;
    spend(it->race, delta);
}

void ScanPathProber::spend(quint64 race, qint64 bytes)
{
    if (bytes > 0 && onSpent)
        onSpent(race, bytes);
}

void ScanPathProber::dropBook(const QString &scanId)
{
    m_books.remove(scanId);
    const QList<path::ProbeStamp> settle = m_unsettled.take(scanId);
    for (const path::ProbeStamp &s : settle)
        settleOne(s.probe);
}

void ScanPathProber::settleOne(quint64 key)
{
    const auto it = m_settling.find(key);
    if (it == m_settling.end() || --it->open > 0)
        return;
    const path::ProbeStamp stamp = it->stamp;
    m_settling.erase(it);
    if (onSettled)
        onSettled(stamp);
}

void ScanPathProber::onPollReply(const QString &scanId, const QByteArray &reply)
{
    auto book = m_books.find(scanId);
    if (book == m_books.end())
        return; // forgotten, or its final came already: a late repeat
    book->pollSentAtMs = -1;
    const ScanHostReply r = scanDecodeReply(reply);
    if (r.kind == ScanHostReplyKind::Error) {
        if (reply.isEmpty()) // no answer this time (the host's bound): the timer asks again
            return;
        // unknown_scan: the host no longer has it (a newer scan replaced it, a Scanner start, the engine process went away)
        say(QStringLiteral("race_prober scan_unknown scan=%1 seen=%2").arg(scanId).arg(book->seen));
        ++m_withoutFinal; // a scan that ended without its final total reaching us
        dropBook(scanId);
        closeScan(scanId);
        return;
    }
    if (r.kind != ScanHostReplyKind::Progress)
        return;
    if (r.progress.bytesSpent >= 0)
        noteTotal(scanId, r.progress.bytesSpent);
    if (r.progress.finalTotals) { // the scan's last total: nothing more will come from it
        say(QStringLiteral("race_prober scan_final scan=%1 spent=%2").arg(scanId).arg(r.progress.bytesSpent));
        dropBook(scanId);
    }
    if (scanId != m_scan.id)
        return; // a scan that is no longer the current one: only its bytes matter
    book = m_books.find(scanId);
    if (book != m_books.end())
        book->lastSeq = qMax(book->lastSeq, r.progress.seq);
    for (const ScanProbeFacts &f : r.progress.items) {
        if (f.stage != ScanStage::Data)
            continue;
        const quint64 key = keyOfHostId(f.id);
        auto it = m_probes.find(key);
        if (it == m_probes.end())
            continue;
        if (it->doneParts.contains(f.id))
            continue; // a repeat of a part that already reported: never counted twice
        bool expected = false;
        for (const ScanHostCandidate &sc : it->sent)
            expected = expected || sc.id == f.id;
        if (!expected)
            continue; // not a part of this probe
        it->doneParts.insert(f.id);
        it->acceptedParts.insert(f.id); // a result proves the host took the part, whatever order its ack comes in
        it->bytes += f.spentBytes;      // the journal's figure only; no byte is charged by it
        const bool ok = scanPathOutcomeOf(f) == path::PathOutcome::ProbeOk;
        it->allOk = it->allOk && ok;
        if (it->doneParts.size() >= it->parts)
            finish(key, it->allOk ? path::PathOutcome::ProbeOk : path::PathOutcome::Inconclusive, it->allOk ? "proven" : (it->parts > 1 ? "burst_part_failed" : scanProbeErrorName(f.error)));
    }
    // "The queue drained: done, "complete", NOT final - the scan stays open for scan_add until the deadline or the app's
    // freeze + cancel" (the host's scan engine): only a final answer, or a done with another reason, ends the scan.
    if (r.progress.done && (r.progress.finalTotals || r.progress.reason != QLatin1String("complete")))
        closeScan(scanId);
}

// The scan takes no more adds and no probe runs in it. Its counter is still followed to `final` (bounded).
void ScanPathProber::closeScan(const QString &scanId)
{
    if (scanId != m_scan.id)
        return;
    m_scan.closed = true;
    const auto book = m_books.find(scanId);
    if (book != m_books.end() && book->forgetAtMs == 0)
        book->forgetAtMs = mono() + kScanFinalWaitMs;
    armPoll();
    const QList<quint64> keys = m_probes.keys();
    for (quint64 key : keys) {
        const Probe &p = m_probes.value(key);
        if (p.scanId != scanId || p.hostId.isEmpty())
            continue;
        // The host ended the scan: a part it acknowledged and never reported is lost with it. A part whose add is still
        // unanswered is not: its answer (a refusal) places it in a new scan.
        bool allAccepted = true;
        for (const ScanHostCandidate &sc : p.sent)
            allAccepted = allAccepted && (p.doneParts.contains(sc.id) || p.acceptedParts.contains(sc.id));
        if (allAccepted)
            finish(key, path::PathOutcome::Inconclusive, "scan_ended");
    }
}

void ScanPathProber::cancel(const path::ProbeStamp &stamp)
{
    auto it = m_probes.find(stamp.probe);
    if (it == m_probes.end() || !(it->stamp == stamp))
        return;
    const bool atHost = !it->sent.isEmpty() && it->scanId == m_scan.id && !m_scan.closed;
    // Its spend is final when nothing that can still spend for it is outstanding (see Settling): the race keeps its hold until
    // then. The count starts at 1 (this function) so a spender that finishes at once cannot settle it half way.
    const quint64 key = stamp.probe;
    Settling &st = m_settling[key];
    st.stamp = stamp;
    st.open = 1;
    if (!it->sent.isEmpty() && m_books.contains(it->scanId)) { // the host scan it ran in (its stopped parts are still counted)
        m_unsettled[it->scanId] << stamp;
        ++st.open;
    }
    if (it->waitingSession && m_sessionFetching) { // the session fetch it asked for goes on and spends this race's bytes
        m_sessionWatchers.insert(key);
        ++st.open;
    }
    const std::shared_ptr<IRaceSeat> seat = it->seat;
    m_probes.erase(it);
    if (seat) { // the seat: the batch request still runs (dropping the owner does not cancel it), a release may follow
        ++m_settling[key].open;
        const std::weak_ptr<bool> alive = m_alive;
        seat->retire([this, alive, key]() {
            if (alive.lock())
                settleOne(key);
        });
    }
    settleOne(key); // the count's own 1
    if (!atHost)
        return; // nothing of it runs at the host: no scan is touched
    // The host stops per scan only: end the scan (the cancelled probe, an AmneziaWG session included, ends with it)
    // and re-open the probes that are still wanted in a new scan.
    retireScan();
}

// The race is over: its probes are gone and its host scan ends - once. (The engine applies this before the race's own
// cancels, which then find nothing.)
void ScanPathProber::raceEnded(quint64 race)
{
    const QList<quint64> keys = m_probes.keys();
    for (quint64 key : keys)
        if (m_probes.value(key).stamp.race == race)
            m_probes.remove(key); // its seat goes with it
    if (!m_scan.closed && m_scan.race == race && m_scan.startSent)
        endHostScan();
}

void ScanPathProber::retireScan()
{
    const quint64 race = m_scan.race;
    QList<ScanHostCandidate> again;
    for (const Probe &p : m_probes)
        if (p.scanId == m_scan.id)
            for (const ScanHostCandidate &sc : p.sent)
                if (!p.doneParts.contains(sc.id))
                    again << sc; // accepted or not: a part that has not reported runs again, never twice at the host
    if (!m_scan.closed)
        endHostScan(); // a scan the host already ended needs no cancel
    if (!again.isEmpty())
        openScan(race, again);
}

// Cancel the current scan at the host. Nothing is charged here: the scan's counter keeps being polled until `final` (the
// cancel ack comes at once, without a final total, while the closing /netinfo and the stopped probes still spend).
void ScanPathProber::endHostScan()
{
    const QString scanId = m_scan.id;
    m_scan.closed = true;
    if (m_scan.startSent) {
        const auto book = m_books.find(scanId);
        if (book != m_books.end())
            book->forgetAtMs = mono() + kScanFinalWaitMs;
        const std::weak_ptr<bool> alive = m_alive;
        m_host->sendMessage(scanCompact(scanEncodeCancel(scanId)), [this, alive, scanId](const QByteArray &reply) {
            if (alive.lock())
                onCancelReply(scanId, reply);
        });
        armPoll();
    }
    say(QStringLiteral("race_prober scan_cancel scan=%1").arg(scanId));
}

// The cancel ack: with `final` it carries the scan's last total (the scan was already over); without it the scan is still
// closing - the poll goes on to its final, the bound runs from now.
void ScanPathProber::onCancelReply(const QString &scanId, const QByteArray &reply)
{
    auto book = m_books.find(scanId);
    if (book == m_books.end())
        return; // its final came already (a poll was faster), or it was forgotten: a repeated ack
    const ScanHostReply r = scanDecodeReply(reply);
    if (r.kind == ScanHostReplyKind::Ack && r.bytesSpent >= 0)
        noteTotal(scanId, r.bytesSpent);
    if (r.kind == ScanHostReplyKind::Ack && r.finalTotals) {
        say(QStringLiteral("race_prober scan_final scan=%1 spent=%2 via=cancel").arg(scanId).arg(r.bytesSpent));
        dropBook(scanId);
        return;
    }
    book->forgetAtMs = qMax(book->forgetAtMs, mono() + kScanFinalWaitMs);
}

void ScanPathProber::finishLater(quint64 key, const char *why)
{
    const std::weak_ptr<bool> alive = m_alive;
    const QString reason = QLatin1String(why);
    QTimer::singleShot(0, this, [this, alive, key, reason]() {
        if (alive.lock())
            finish(key, path::PathOutcome::Inconclusive, reason.toLatin1().constData());
    });
}

void ScanPathProber::finish(quint64 key, path::PathOutcome outcome, const char *why)
{
    auto it = m_probes.find(key);
    if (it == m_probes.end())
        return;
    const Probe p = it.value(); // its seat is released as the last copy goes, after the result below
    m_probes.erase(it);
    // bytes: what the probe's host items showed - the journal only. The scan stays open for the race's next probe (the host
    // keeps a drained scan open for scan_add); it is cancelled when the race ends or a cancelled probe has to be stopped.
    say(QStringLiteral("race_prober result race=%1 probe=%2 node=%3 outcome=%4 bytes_seen=%5 why=%6")
            .arg(p.stamp.race).arg(p.stamp.probe).arg(p.path.id.id, QLatin1String(path::pathOutcomeName(outcome)))
            .arg(p.bytes).arg(QLatin1String(why)));
    if (onResult)
        onResult(p.stamp, outcome, p.bytes);
    // A provider probe's seat release starts when its owner is given up (below) and its bytes are counted when the chain ends: the
    // race holds the release budget on its cap until then (PathRace::probeDone), so the probe is settled by the same count as a
    // cancelled one - the seat (request, release) is the one spender left, the count's own 1 covers a seat that is idle at once. Own
    // probes spend nothing more: their bytes are in the host's counter shown with the result (no hold, nothing to settle).
    if (p.path.kind != path::PathKind::Provider)
        return;
    const quint64 settleKey = p.stamp.probe;
    Settling &st = m_settling[settleKey];
    st.stamp = p.stamp;
    st.open = 1;
    if (p.seat) {
        ++st.open;
        const std::weak_ptr<bool> alive = m_alive;
        p.seat->retire([this, alive, settleKey]() {
            if (alive.lock())
                settleOne(settleKey);
        });
    }
    settleOne(settleKey);
}

quint64 ScanPathProber::keyOfHostId(const QString &hostId) const
{
    // "race<r>-<probe>" or a burst part "race<r>-<probe>.<n>"
    const QString dataId = scanXrayBurstBaseOf(hostId);
    const int dash = dataId.lastIndexOf(QLatin1Char('-'));
    return dash < 0 ? 0 : dataId.mid(dash + 1).toULongLong();
}

} // namespace avpn
