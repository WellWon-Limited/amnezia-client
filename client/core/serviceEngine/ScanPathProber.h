// client/core/serviceEngine/ScanPathProber.h
// AVPN serviceEngine - the path race's probe host (path/PathProber.h IPathProber) over the Scanner's own pipeline,
// headless: the signed scan manifest + scan token of the current network, probe seats for provider profiles through
// the batch API, the tribe-scan-v1 probe host of the platform (IScanHost: iOS the in-app host IosHybridScanHost when
// built with AVPN_IOS_APP_SCAN_HOST, macOS / Windows the service's host) and the Scanner's byte ledger. No UI, no
// Scanner screen state, nothing that touches the tunnel.
//
// How one race maps onto the host (one host scan at a time per engine process):
//  - ONE host scan serves a whole race: the first StartProbe opens it (scan_start), the next ones join (scan_add); a scan
//    whose queue drained stays open for scan_add (the host's contract), so sequential probes never reopen it. It is
//    cancelled once: when the race ends (raceEnded) or when cancelling a probe requires stopping the host (below). A scan the
//    host closed itself (its deadline) is replaced by a new scan_start.
//  - Bytes: the host's own cumulative bytes_spent per scan is the only source of host spend. The prober keeps the last
//    total seen per scan and emits each increase once through onSpent; a cancelled scan keeps being polled until the host
//    says `final` (the cancel ack comes without it while the closing /netinfo runs), unknown_scan, or kScanFinalWaitMs.
//    API-side bytes (session, seat batch, release) are emitted by their callbacks. See raceCosts() for the table.
//  - Probe kinds as the Scanner uses them, no reach stage (the race has its own bound): own AmneziaWG -> awg_mini
//    (the device's own key, 64 KB body through the node's NAT; only for a node the signed manifest marks awg_probe
//    and with the API's IP known), own Xray -> xray_leg when the host has legs (the node's one outbound) else
//    xray_full, provider -> xray_full with the probe seat's config (checked by the connect's own profile rule,
//    XrayProfileSanitizer.h). A candidate that cannot be built is answered "not proven" at once.
//  - Results: a data item of the probe -> ProbeOk only with a verified digest of the sized body (sha_ok, no error);
//    anything else, the scan's end without an item, an unknown scan -> Inconclusive (never recorded by the race).
//    A result's bytes are the journal's figure only. Every result goes to onResult once, on the GUI thread,
//    never from inside start().
//  - cancel(): the probe's result is dropped and the probe is gone, and it is stopped AT THE HOST: the host has only
//    a per-scan cancel, so when other probes still share the scan it is cancelled and the others are re-opened in a
//    new scan (only the parts not yet reported run again; a probe's own AmneziaWG session never outlives its cancel - connect
//    invariant: the leg's node is never probed beside the tunnel with the device's key).
//  - Provider seats: one batch call per provider probe (the race starts at most providerPerRace of them); never a
//    session seat. The probe owns its seat (IRaceSeat, production: ScanSeatBatch with its operation id): the seat
//    goes with the probe - its result, its cancel, the prober's end - also a seat whose answer a tunnel transition
//    cut (released by the operation id). A refusal `lease_gone` (a resent operation whose seat already ended) is
//    "no seat": the candidate is skipped, not proven.
//
// Session cache (the cost rule): the session (token, probe base, its IPs, the manifest's awg_probe nodes and
// numbers) is kept in memory per network reporting key until 60 s before the token expires (server scan_token_ttl_s,
// 600 s). warmUp() fetches it ahead (app start, then every 30 s while the app is in front if it is missing or stale -
// a new network has a new key) so a race at the tap never waits for it; without
// one the first probe waits for the fetch (a stored manifest is revalidated with its ETag: 304 + token, two small
// requests). No session (scanner off, offline) = every probe "not proven" at once: the owner walks (stage 1).
// Own Xray needs only the token and the probe base; AmneziaWG also needs the manifest's awg_probe mark (the server
// says the device's peer is on that node) and the API's IP literal.
//
// Availability (caps().available): a host that answers now, its scan_caps known, the Scanner not scanning (it owns
// the host's one scan while its screen runs), a session source configured.
//
// Upstream Amnezia has no counterpart. Tests: tests/scan_path_prober_check.cpp (build_scan_path_prober.sh).
#pragma once

#include "IScanHost.h"
#include "ScanHostContract.h"
#include "ScanPlan.h" // the Xray burst
#include "ScanTunables.h"
#include "ScanTypes.h"
#include "TribeScanner.h" // IScanEngine
#include "path/PathProber.h"

#include <QElapsedTimer>
#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <functional>
#include <memory>

namespace avpn {

// What a race needs from the Scanner's server side for one network.
struct RaceScanSession {
    bool ok = false;
    QString reason;              // !ok: the manifest client's reason (scanner_off, manifest_unavailable, ...)
    QString networkKey;          // the reporting key it was fetched for
    QString token;               // SECRET
    QString probeBase;           // tunnel_api_base
    QStringList baseIps;         // IP literals of the probe base's host ({} = unknown: no AmneziaWG probe)
    QHash<QString, QString> awgNodes; // node id -> echo target ("" = none) of the nodes the manifest marks awg_probe
    QMap<QString, double> numbers;    // the manifest's numbers (ScanTunables::fromNumbers)
    qint64 expiresAtMs = 0;      // wall clock of the token's expiry (0 = unknown: treated as 10 min after fetch)
    qint64 bytes = 0;            // what the fetch transferred
};

// The owner of one provider probe seat: destroying it releases the seat, also one whose answer never came.
class IRaceSeat
{
public:
    virtual ~IRaceSeat() = default;
};

// The server calls of the race (production: ScanApiClient, ScanPathProberApi.cpp; tests: a fake).
class IRaceScanApi
{
public:
    virtual ~IRaceScanApi() = default;
    virtual bool configured() const = 0;
    virtual void session(const QString &networkKey, std::function<void(const RaceScanSession &)> done) = 0;
    struct Seat {
        bool ok = false;
        QString leaseId;      // SECRET
        QString config;       // SECRET
        QString configSha256;
        QString code;         // refused: no_seat | rate_limited | lease_gone | ...
        qint64 bytes = 0;
    };
    // One seat with its config; costBytes cuts the request (resends included). `done` once, never from inside the
    // call; the returned owner releases the seat when it goes (releaseBytes: what that release transferred).
    virtual std::shared_ptr<IRaceSeat> probeSeat(const QString &profileId, qint64 costBytes, std::function<void(const Seat &)> done,
                                                 std::function<void(qint64)> releaseBytes) = 0;
};

// Pure: the race caps of a host's scan_caps (inFlight = the total the race may keep in flight).
inline path::ProberCaps scanPathProberCaps(const ScanHostCaps &c, bool usable)
{
    path::ProberCaps p;
    p.available = usable && (c.maxLegConcurrent > 0 || c.maxFullConcurrent > 0 || c.maxAwgConcurrent > 0);
    p.inFlight = qMax(qMax(c.maxLegConcurrent, c.maxFullConcurrent), 1);
    p.providerAtOnce = qMax(0, c.maxFullConcurrent);
    p.awgAtOnce = qMax(0, c.maxAwgConcurrent);
    return p;
}

// Pure: the race outcome of one data item.
inline path::PathOutcome scanPathOutcomeOf(const ScanProbeFacts &f)
{
    return (f.stage == ScanStage::Data && f.error == ScanProbeError::None && f.shaOk && f.httpStatus == 200)
               ? path::PathOutcome::ProbeOk
               : path::PathOutcome::Inconclusive;
}

// Pure: is a cached session good for a race starting now on this network?
inline bool scanPathSessionFresh(const RaceScanSession &s, const QString &networkKey, qint64 wallNowMs, qint64 fetchedAtMs)
{
    if (!s.ok || s.networkKey != networkKey || s.token.isEmpty() || s.probeBase.isEmpty())
        return false;
    const qint64 expires = s.expiresAtMs > 0 ? s.expiresAtMs : fetchedAtMs + 10 * 60 * 1000;
    return wallNowMs < expires - 60 * 1000;
}

class ScanPathProber final : public QObject, public path::IPathProber
{
public:
    ScanPathProber(IScanHost *host, IScanEngine *engine, IRaceScanApi *api, QObject *parent = nullptr);
    ~ScanPathProber() override;
    // The production wiring hands its server side over (the prober deletes it with itself).
    void adoptApi(std::unique_ptr<IRaceScanApi> api)
    {
        m_ownedApi = std::move(api);
        m_api = m_ownedApi.get();
    }

    // Wiring (all optional). onResult: ServiceEngine::onProbeResult (the third number is the journal's only - what the
    // probe's host items showed; nothing is charged by it). hostBusy: the Scanner's own scan runs (it owns the host).
    // onSpent: THE byte stream - every real byte of the race's traffic, once (the host's counters as deltas, the session,
    // seat and release calls' bytes); the engine sets it through setSpendSink and puts it on the race's cap and the hour
    // ledger (see raceCosts for the table). wallNow: wall clock (token expiry).
    std::function<void(const path::ProbeStamp &, path::PathOutcome, qint64)> onResult;
    std::function<bool()> hostBusy;
    std::function<void(quint64 race, qint64 bytes)> onSpent; // race 0 = outside any race (warm-up): the hour ledger only
    void setSpendSink(std::function<void(quint64, qint64)> sink) override { onSpent = std::move(sink); }
    // A cancelled probe's spend is final: the scan it ran in reached its final total, or went unknown, or its polling bound ended
    // (a probe that never reached the host settles at once). The race holds the probe's bound on its cap until then.
    std::function<void(const path::ProbeStamp &)> onSettled;
    bool holdsAfterCancel() const override { return true; }
    void setSettleSink(std::function<void(const path::ProbeStamp &)> sink) override { onSettled = std::move(sink); }
    void raceEnded(quint64 race) override;
    std::function<qint64()> wallNow;
    std::function<void(const QString &)> log; // ids, kinds, codes, counts only

    path::ProberCaps caps() const override;
    // What one race probe costs at most, as launch() builds it: the race's body (kRaceProbeBytes), every part of an
    // own Xray burst, the AmneziaWG handshake and echoes, a provider's seat batch with its config and its release,
    // and the host's access check of a scan opened for the probe. Device round 19.11: the race charged the Scanner's
    // single-connection price (82 944 B for an own Xray probe that sent four connections, 92 723 B measured).
    path::PathRace::Costs costs() const override { return raceCosts(tunables(), xrayBurst); }
    static path::PathRace::Costs raceCosts(const ScanTunables &t, int xrayBurst);
    void start(const path::ProbeStamp &stamp, const path::PathCandidate &path, int timeoutMs) override;
    void cancel(const path::ProbeStamp &stamp) override;

    // Ask the host's caps and fetch the session of the current network ahead of a tap. Idempotent; a fresh session is
    // kept. Called through prepare() by the engine (attach, a network change, every tap before a race) - no timer (a
    // network change gives a new reporting key: the next warm-up fetches its session; nothing in the background).
    void warmUp();
    void prepare(const path::NetworkKey &net) override
    {
        Q_UNUSED(net)
        warmUp();
    }
    bool sessionReady() const;
    int liveProbes() const { return int(m_probes.size()); }
    QString openScanId() const { return m_scan.id; }
    // Scans still followed for their last total, and scans that ended without it (unknown_scan, the bound): the model's numbers.
    int scansFollowed() const { return int(m_books.size()); }
    int scansWithoutFinal() const { return m_withoutFinal; }
    int pollIntervalMs = 200;
    // Own Xray is probed the way a tunnel opens it (ScanPlan.h scanXrayBurstOf, shared with the Scanner): the data
    // probe plus xrayBurst-1 small parallel ones; proven only if every one of them carried its body. 1 = a single
    // connection (tests only).
    int xrayBurst = kScanXrayBurstParts;
    // The race's data body (device 18.11: 190 KB - 1.4 MB per race with the Scanner's 64 KB body, the cellular hour
    // ran out within a few connects): 24 KB still proves data through the path (a 15-20 KB flow freeze cuts it).
    static constexpr int kRaceProbeBytes = 24576;
    // How long a cancelled or closed scan is polled for its `final` (the host's closing /netinfo takes up to the reach
    // timeout, 1.5 s; its replace wait is 3 s). A scan is dropped from the book only on `final`, unknown_scan or this bound.
    static constexpr qint64 kScanFinalWaitMs = 3000;

private:
    struct Probe {
        path::ProbeStamp stamp;
        path::PathCandidate path;
        QString hostId;        // the candidate id in the host scan ("" = not sent yet)
        QString scanId;        // the host scan it joined
        std::shared_ptr<IRaceSeat> seat; // provider: its probe seat (released with the probe)
        bool waitingSession = false;
        bool waitingSeat = false;
        int parts = 1;          // host candidates of this probe (own Xray: the burst, see xrayBurst)
        QSet<QString> doneParts; // host ids of the parts that reported data, in whatever scan (a repeat is ignored)
        bool allOk = true;
        qint64 bytes = 0;        // what this probe's host items showed (the journal only; no byte is charged by it)
        QSet<QString> acceptedParts; // part ids the CURRENT scan's host acknowledged (cleared when a probe is bound to a new scan)
        QHash<QString, QString> partScan; // part host id -> the scan its last message named (pending or accepted)
        QList<ScanHostCandidate> sent; // the probe's host candidates (all its parts), kept for the probe's life; a reopen sends those not in doneParts
    };
    // What the prober follows of one host scan: the last cumulative bytes_spent seen (the only thing it charges from).
    struct ScanBook {
        quint64 race = 0;         // the race the scan was opened for: its spend is that race's
        qint64 seen = 0;
        qint64 lastSeq = 0;
        qint64 forgetAtMs = 0;    // 0 = the scan is open (no bound); else the time this entry is dropped if `final` never came
        qint64 pollSentAtMs = -1; // a poll of it is out since then (-1 = none)
    };
    struct HostScan {
        QString id;
        quint64 race = 0;
        bool startSent = false;
        bool acked = false;
        bool closed = true;
        QList<ScanHostCandidate> queued; // to add once the start is acked
    };

    qint64 now() const;
    QString networkKey() const;
    void sessionArrived(const RaceScanSession &s);
    void launch(quint64 key);
    void sendCandidate(quint64 key, const ScanHostCandidate &c);
    void openScan(quint64 race, const QList<ScanHostCandidate> &cands);
    void onStartReply(const QString &scanId, const QList<ScanHostCandidate> &cands, const QByteArray &reply);
    void onAddReply(const QString &scanId, const QList<ScanHostCandidate> &cands, const QByteArray &reply);
    void poll();
    void onPollReply(const QString &scanId, const QByteArray &reply);
    void closeScan(const QString &scanId);
    void endHostScan();
    void onCancelReply(const QString &scanId, const QByteArray &reply);
    // End the current scan at the host and open a new one with every part of its probes that has not reported: the
    // one function behind a cancelled neighbour and the refusal of an add (the engine closed the scan).
    void retireScan();
    // Host spend: one counter per scan, the last total seen; only a larger total charges, the difference, once.
    void noteTotal(const QString &scanId, qint64 total);
    void spend(quint64 race, qint64 bytes);
    // The one place a scan leaves the book (its final came, it went unknown, the bound passed, the host never held it): the
    // probes cancelled while it ran are settled with it.
    void dropBook(const QString &scanId);
    QHash<QString, QList<path::ProbeStamp>> m_unsettled; // scan id -> cancelled probes whose spend that scan may still show
    void fetchSession(quint64 race);
    quint64 m_fetchRace = 0;
    bool pollable(const QString &id, const ScanBook &b) const;
    qint64 mono() const { return m_clock.elapsed(); }
    static constexpr qint64 kPollStaleMs = 1000; // an unanswered poll is asked again after this
    QHash<QString, ScanBook> m_books;
    int m_withoutFinal = 0;
    QElapsedTimer m_clock;
    // One owner of what an answer of a scan that is no longer the current one (or a refusal of the current one) means:
    // every named part that is neither reported nor already named in another scan goes into the current scan.
    void placeParts(const QString &fromScan, const QList<ScanHostCandidate> &cands);
    // Every end of a probe - proven, refused, timed out, ended with its scan - reports once.
    void finish(quint64 key, path::PathOutcome outcome, const char *why);
    void finishLater(quint64 key, const char *why);
    void armPoll();
    ScanTunables tunables() const;
    quint64 keyOfHostId(const QString &hostId) const;
    void say(const QString &line) const
    {
        if (log)
            log(line);
    }

    IScanHost *m_host = nullptr;
    IScanEngine *m_engine = nullptr;
    IRaceScanApi *m_api = nullptr;
    std::unique_ptr<IRaceScanApi> m_ownedApi;
    ScanHostCaps m_caps;
    bool m_capsKnown = false;
    bool m_capsAsked = false;
    RaceScanSession m_session;
    qint64 m_sessionAtMs = 0;
    bool m_sessionFetching = false;
    QHash<quint64, Probe> m_probes; // key = stamp.probe (unique per engine process: the race numbers them)
    HostScan m_scan;
    quint64 m_scanSeq = 0;
    QTimer m_pollTimer;
    std::shared_ptr<bool> m_alive = std::make_shared<bool>(true);
};

} // namespace avpn
