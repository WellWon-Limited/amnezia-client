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
    return scanPathProberCaps(m_caps, usable);
}

path::PathRace::Costs ScanPathProber::raceCosts(const ScanTunables &t, int xrayBurst)
{
    const qint64 body = qMin<qint64>(t.stage2Bytes, kRaceProbeBytes);       // openScan: req.bytes
    const qint64 data = qint64(t.warmBytes) + body + 2 * kScanTlsOverheadBytes; // one data connection
    const qint64 access = t.costApiBytes;                                     // a scan opened for this probe
    path::PathRace::Costs c;
    c.xray = data + qint64(qBound(1, xrayBurst, 6) - 1) * scanXrayBurstPartCostBytes(t) + access;
    c.awg = kScanAwgHandshakeBytes + qint64(t.awgPrimeEchoes) * kScanAwgEchoBytes + data + access;
    c.provider = data + qint64(t.costBatchBytes) + t.costConfigBytes + t.costApiBytes /* release */ + access;
    // what of each projection is spent outside the host (PathRace charges it on top of the host's count)
    c.awgFixed = access;
    c.xrayFixed = access;
    c.providerFixed = qint64(t.costBatchBytes) + t.costConfigBytes + t.costApiBytes + access;
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
        fetchSession();
}

void ScanPathProber::fetchSession()
{
    if (m_sessionFetching || !m_api || !m_api->configured())
        return;
    m_sessionFetching = true;
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
    if (chargeApiBytes && s.bytes > 0)
        chargeApiBytes(s.bytes);
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
            finish(key, path::PathOutcome::Inconclusive, 0, "no_session");
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
        fetchSession();
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
            finish(key, path::PathOutcome::Inconclusive, 0, "no_config");
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
            finish(key, path::PathOutcome::Inconclusive, 0,
                   m_caps.maxAwgConcurrent <= 0 ? "awg_no_host"
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
            finish(key, path::PathOutcome::Inconclusive, 0, "awg_config");
            return;
        }
        break;
    }
    case path::PathKind::Provider: {
        if (m_caps.maxFullConcurrent <= 0) {
            finish(key, path::PathOutcome::Inconclusive, 0, "no_full_pool");
            return;
        }
        const QString profileId = pc.id.id.startsWith(QLatin1String("up:")) ? pc.id.id.mid(3) : pc.id.id;
        it->waitingSeat = true;
        const std::weak_ptr<bool> alive = m_alive;
        const QString nodeId = pc.id.id;
        const auto charge = [this, alive](qint64 bytes) {
            if (alive.lock() && chargeApiBytes && bytes > 0)
                chargeApiBytes(bytes);
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
                finish(key, path::PathOutcome::Inconclusive, 0, seat.code == QLatin1String("lease_gone") ? "seat_gone" : "no_seat");
                return;
            }
            const SanitizedProfile chk = upstreamProfileCheck(seat.config.toUtf8(), seat.configSha256,
                                                              m_engine->upstreamProtocolTags(nodeId));
            if (!chk.ok()) {
                finish(key, path::PathOutcome::Inconclusive, 0, "profile_refused");
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
    m_scan = HostScan();
    m_scan.id = QStringLiteral("race-%1-%2").arg(race).arg(++m_scanSeq);
    m_scan.race = race;
    m_scan.closed = false;
    m_scan.startSent = true;
    for (const ScanHostCandidate &c : cands) {
        const quint64 key = keyOfHostId(c.id);
        if (m_probes.contains(key)) {
            Probe &p = m_probes[key]; // the one place a probe is bound to a scan: first open and every reopen alike
            p.scanId = m_scan.id; // what already reported (doneParts, bytes, allOk) is the probe's own and stays
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
                finish(key, path::PathOutcome::Inconclusive, 0, "scan_replaced");
        }
        return;
    }
    if (r.kind != ScanHostReplyKind::Ack) {
        say(QStringLiteral("race_prober scan_start refused scan=%1 error=%2 %3").arg(scanId, r.errorCode, r.detail));
        m_scan.closed = true;
        for (const ScanHostCandidate &c : cands + m_scan.queued)
            finish(keyOfHostId(c.id), path::PathOutcome::Inconclusive, 0, "start_refused");
        m_scan.queued.clear();
        return;
    }
    m_scan.acked = true;
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
    if (scanId != m_scan.id)
        return; // an answer of an older scan: its probes were re-opened in the current one (openScan), nothing to resend
    const ScanHostReply r = scanDecodeReply(reply);
    const bool taken = r.kind == ScanHostReplyKind::Ack && r.accepted == cands.size();
    if (taken) {
        armPoll();
        return;
    }
    // The engine closed that scan (every candidate final, its deadline, a Scanner start replaced it): a new scan.
    QList<ScanHostCandidate> again;
    for (const ScanHostCandidate &c : cands) {
        const quint64 key = keyOfHostId(c.id);
        if (!m_probes.contains(key))
            continue;
        again << c;
    }
    if (scanId == m_scan.id)
        m_scan.closed = true;
    if (again.isEmpty())
        return;
    const quint64 race = m_probes.value(keyOfHostId(again.first().id)).stamp.race;
    if (!m_scan.closed && m_scan.race == race && m_scan.id != scanId) {
        for (const ScanHostCandidate &c : again)
            sendCandidate(keyOfHostId(c.id), c);
        return;
    }
    openScan(race, again);
}

void ScanPathProber::armPoll()
{
    if (!m_scan.closed && !m_pollTimer.isActive())
        m_pollTimer.start(pollIntervalMs);
}

void ScanPathProber::poll()
{
    if (m_scan.closed || !m_scan.acked)
        return;
    const QString scanId = m_scan.id;
    const std::weak_ptr<bool> alive = m_alive;
    m_host->sendMessage(scanCompact(scanEncodePoll(scanId, m_scan.lastSeq)), [this, alive, scanId](const QByteArray &reply) {
        if (alive.lock())
            onPollReply(scanId, reply);
    });
}

void ScanPathProber::onPollReply(const QString &scanId, const QByteArray &reply)
{
    if (scanId != m_scan.id)
        return;
    const ScanHostReply r = scanDecodeReply(reply);
    if (r.kind == ScanHostReplyKind::Error) {
        if (reply.isEmpty()) { // no answer this time (the host's bound): ask again
            armPoll();
            return;
        }
        closeScan(scanId); // unknown_scan: a Scanner start replaced it, or the engine process went away
        return;
    }
    if (r.kind != ScanHostReplyKind::Progress) {
        armPoll();
        return;
    }
    m_scan.lastSeq = qMax(m_scan.lastSeq, r.progress.seq);
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
        it->bytes += f.spentBytes;
        const bool ok = scanPathOutcomeOf(f) == path::PathOutcome::ProbeOk;
        it->allOk = it->allOk && ok;
        if (it->doneParts.size() >= it->parts)
            finish(key, it->allOk ? path::PathOutcome::ProbeOk : path::PathOutcome::Inconclusive, it->bytes,
                   it->allOk ? "proven" : (it->parts > 1 ? "burst_part_failed" : scanProbeErrorName(f.error)));
    }
    if (r.progress.done) {
        closeScan(scanId);
        return;
    }
    armPoll();
}

void ScanPathProber::closeScan(const QString &scanId)
{
    if (scanId != m_scan.id)
        return;
    m_scan.closed = true;
    m_pollTimer.stop();
    const QList<quint64> keys = m_probes.keys();
    for (quint64 key : keys) {
        const Probe &p = m_probes.value(key);
        if (p.scanId == scanId && !p.hostId.isEmpty())
            finish(key, path::PathOutcome::Inconclusive, 0, "scan_ended");
    }
}

void ScanPathProber::cancel(const path::ProbeStamp &stamp)
{
    auto it = m_probes.find(stamp.probe);
    if (it == m_probes.end() || !(it->stamp == stamp))
        return;
    const bool atHost = !it->sent.isEmpty() && it->scanId == m_scan.id && !m_scan.closed;
    m_probes.erase(it); // its seat goes with it (a seat still asked: released by its operation id once the ask ends)
    if (!atHost) {
        cancelScanIfIdle();
        return;
    }
    // The host stops per scan only: end the scan (the cancelled probe, an AmneziaWG session included, ends with it)
    // and re-open the probes that are still wanted in a new scan.
    const quint64 race = m_scan.race;
    QList<ScanHostCandidate> again;
    for (const Probe &p : m_probes)
        if (p.scanId == m_scan.id)
            for (const ScanHostCandidate &sc : p.sent)
                if (!p.doneParts.contains(sc.id))
                    again << sc; // only the parts that have not reported: a reported part is never run (or counted) twice
    endHostScan();
    if (!again.isEmpty())
        openScan(race, again);
}

void ScanPathProber::endHostScan()
{
    const QString scanId = m_scan.id;
    m_scan.closed = true;
    m_pollTimer.stop();
    if (m_scan.startSent)
        m_host->sendMessage(scanCompact(scanEncodeCancel(scanId)), [](const QByteArray &) {});
    say(QStringLiteral("race_prober scan_cancel scan=%1").arg(scanId));
}

void ScanPathProber::cancelScanIfIdle()
{
    if (m_scan.closed)
        return;
    for (const Probe &p : m_probes)
        if (p.scanId == m_scan.id)
            return;
    // nothing of the scan is wanted any more: end it (its AmneziaWG sessions too) before the owner raises a tunnel
    endHostScan();
}

void ScanPathProber::finishLater(quint64 key, const char *why)
{
    const std::weak_ptr<bool> alive = m_alive;
    const QString reason = QLatin1String(why);
    QTimer::singleShot(0, this, [this, alive, key, reason]() {
        if (alive.lock())
            finish(key, path::PathOutcome::Inconclusive, 0, reason.toLatin1().constData());
    });
}

void ScanPathProber::finish(quint64 key, path::PathOutcome outcome, qint64 bytes, const char *why)
{
    auto it = m_probes.find(key);
    if (it == m_probes.end())
        return;
    const Probe p = it.value(); // its seat is released as the last copy goes, after the result below
    m_probes.erase(it);
    say(QStringLiteral("race_prober result race=%1 probe=%2 node=%3 outcome=%4 bytes=%5 why=%6")
            .arg(p.stamp.race).arg(p.stamp.probe).arg(p.path.id.id, QLatin1String(path::pathOutcomeName(outcome)))
            .arg(bytes).arg(QLatin1String(why)));
    if (onResult)
        onResult(p.stamp, outcome, bytes);
    // A finished probe leaves the scan open: the race may add its next probe at once (the engine closes a scan whose
    // candidates are all final by itself; only cancel() ends it early).
}

quint64 ScanPathProber::keyOfHostId(const QString &hostId) const
{
    // "race<r>-<probe>" or a burst part "race<r>-<probe>.<n>"
    const QString dataId = scanXrayBurstBaseOf(hostId);
    const int dash = dataId.lastIndexOf(QLatin1Char('-'));
    return dash < 0 ? 0 : dataId.mid(dash + 1).toULongLong();
}

} // namespace avpn
