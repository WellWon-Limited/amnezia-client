// client/core/serviceEngine/ScanPathProber.h
// AVPN serviceEngine - the path race's probe host (path/PathProber.h IPathProber) over the Scanner's own pipeline,
// headless: the signed scan manifest + scan token of the current network, probe seats for provider profiles through
// the batch API, the tribe-scan-v1 probe host of the platform (IScanHost: iOS the in-app host IosHybridScanHost when
// built with AVPN_IOS_APP_SCAN_HOST, macOS / Windows the service's host) and the Scanner's byte ledger. No UI, no
// Scanner screen state, nothing that touches the tunnel.
//
// How one race maps onto the host (one host scan at a time per engine process):
//  - The first StartProbe of a race opens a host scan (scan_start); the next ones join it (scan_add). A scan the
//    engine already closed (every queued candidate final, or its deadline) is replaced by a new scan_start.
//  - Probe kinds as the Scanner uses them, no reach stage (the race has its own bound): own AmneziaWG -> awg_mini
//    (the device's own key, 64 KB body through the node's NAT; only for a node the signed manifest marks awg_probe
//    and with the API's IP known), own Xray -> xray_leg when the host has legs (the node's one outbound) else
//    xray_full, provider -> xray_full with the probe seat's config (checked by the connect's own profile rule,
//    XrayProfileSanitizer.h). A candidate that cannot be built is answered "not proven" at once.
//  - Results: a data item of the probe -> ProbeOk only with a verified digest of the sized body (sha_ok, no error);
//    anything else, the scan's end without an item, an unknown scan -> Inconclusive (never recorded by the race).
//    Bytes = the item's spent bytes (the host's own count). Every result goes to onResult once, on the GUI thread,
//    never from inside start().
//  - cancel(): the probe's result is dropped; its seat is released; when nothing of the scan is live any more the
//    host scan is cancelled (its AmneziaWG sessions end before the owner raises a tunnel).
//  - Provider seats: one batch call per provider probe (the race starts at most providerPerRace of them), released
//    when the result comes or the probe is cancelled; never a session seat.
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
#include "ScanTunables.h"
#include "ScanTypes.h"
#include "TribeScanner.h" // IScanEngine
#include "path/PathProber.h"

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
        QString code;         // refused: no_seat | rate_limited | ...
        qint64 bytes = 0;
    };
    virtual void probeSeat(const QString &profileId, std::function<void(const Seat &)> done) = 0;
    virtual void releaseSeats(const QStringList &leaseIds) = 0;
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

    // Wiring (all optional). onResult: ServiceEngine::onProbeResult. hostBusy: the Scanner's own scan runs (it owns
    // the host). chargeApiBytes: the manifest / token / seat requests' real bytes into the Scanner's ledger (the
    // probes' bytes go back with each result and the engine charges them). wallNow: wall clock (token expiry).
    std::function<void(const path::ProbeStamp &, path::PathOutcome, qint64)> onResult;
    std::function<bool()> hostBusy;
    std::function<void(qint64)> chargeApiBytes;
    std::function<qint64()> wallNow;
    std::function<void(const QString &)> log; // ids, kinds, codes, counts only

    path::ProberCaps caps() const override;
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
    int pollIntervalMs = 200;
    // Own Xray is probed the way a tunnel opens it (device 18.11, the Estonia capture: the real tunnel opened ~9
    // connections within a second and the network cut most of them, while a single probe connection passed): the
    // data probe plus xrayBurst-1 small parallel ones (4 KB bodies) through the same listener; proven only if every
    // one of them carried its body. 1 = the single connection of before.
    int xrayBurst = 4;
    static constexpr int kXrayBurstBytes = 4096;
    // The race's data body (device 18.11: 190 KB - 1.4 MB per race with the Scanner's 64 KB body, the cellular hour
    // ran out within a few connects): 24 KB still proves data through the path (a 15-20 KB flow freeze cuts it).
    static constexpr int kRaceProbeBytes = 24576;

private:
    struct Probe {
        path::ProbeStamp stamp;
        path::PathCandidate path;
        QString hostId;        // the candidate id in the host scan ("" = not sent yet)
        QString scanId;        // the host scan it joined
        QString leaseId;       // provider: its probe seat
        bool cancelled = false;
        bool waitingSession = false;
        bool waitingSeat = false;
        int parts = 1;          // host candidates of this probe (own Xray: the burst, see xrayBurst)
        int partsDone = 0;
        bool allOk = true;
        qint64 bytes = 0;
    };
    struct HostScan {
        QString id;
        quint64 race = 0;
        bool startSent = false;
        bool acked = false;
        bool closed = true;
        qint64 lastSeq = 0;
        QList<ScanHostCandidate> queued; // to add once the start is acked
    };

    qint64 now() const;
    QString networkKey() const;
    void fetchSession();
    void sessionArrived(const RaceScanSession &s);
    void launch(quint64 key);
    void sendCandidate(quint64 key, const ScanHostCandidate &c);
    void openScan(quint64 race, const QList<ScanHostCandidate> &cands);
    void onStartReply(const QString &scanId, const QList<ScanHostCandidate> &cands, const QByteArray &reply);
    void onAddReply(const QString &scanId, const QList<ScanHostCandidate> &cands, const QByteArray &reply);
    void poll();
    void onPollReply(const QString &scanId, const QByteArray &reply);
    void closeScan(const QString &scanId);
    void cancelScanIfIdle();
    void finish(quint64 key, path::PathOutcome outcome, qint64 bytes, const char *why);
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
