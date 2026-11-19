// client/core/serviceEngine/ScanApiClient.h
// AVPN serviceEngine - the Scanner's server calls (lane L6a): the signed scan manifest with ETag
// revalidation, the scan token, the probe-batch seats and their release, the outcome batch, /v1/netinfo and
// the sized data probe through the LIVE tunnel (UpstreamLeaseClient::runProbe, review F2). Every decision
// lives in the pure core (ScanMachine.h and friends); this class sends, measures, verifies signatures and
// hands back what came. [IN-FORK BUILD: QtNetwork]
//
// Plan scanner-client-plan.md §2.2b (one allowance: every request here carries the worst case the machine
// reserved for it, and its transfer is CUT at that cost), §2.7 (live-tunnel probe), §2.10 (probe-batch),
// §2.11 (manifest, token, outcomes); contract api/openapi.yaml 1.5.0 (/v1/scan/manifest, /v1/scan/token,
// /v1/upstream/lease/probe-batch[/release], /v1/netinfo, /v1/probe, /v1/telemetry/path-outcomes).
// Rules:
//  - Asynchronous only (no nested event loop); every request has a bound (the HTTP layer's timeout) and a
//    byte cut (`maxBytes` = what the machine reserved). A cut answer is a transport failure.
//  - The device token goes only into Authorization; the scan token only into Authorization of /v1/probe and
//    /v1/netinfo. Nothing here logs a token, a lease id, a config, a URL or a host (journal lines carry
//    statuses, counts and byte totals only).
//  - Manifest: stored raw + signature + ETag per network key (IScanStore), re-verified with the /v1/config key
//    and context "tribe-scan-manifest-v1" on EVERY load; revalidated with the exact stored ETag while the copy
//    is unexpired; 304 -> POST /v1/scan/token; a token grant with a newer upstream_revision refetches without
//    If-None-Match; after expires_at fetched without If-None-Match. An answer whose signature fails is never
//    stored and never used.
//  - Probe-batch: signed with the lease context, `type: upstream_probe_batch`; only a verified answer grants
//    anything; every requested profile gets an answer item (missing = refused "lease_failed").
//  - Probe-batch operation (contract 1.15.0): every batch carries an `operation_id` made before its first send; a
//    send our own transition cut is sent again with the SAME id (the server answers the same seats); only an answer
//    echoing that id is used; the seats belong to a ScanSeatBatch owner that releases them by that id when it goes
//    (also seats whose answer never came). A new batch = a new owner = a new id.
//  - Byte counts are wire bytes: the HTTP layer asks gzip itself and inflates the answer (QNAM's own decoding
//    hides the compressed size: its counts are the inflated body, review 19.11).
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanOutcomes.h"
#include "ScanTypes.h"
#include "UpstreamEngine.h"
#include "UpstreamLeaseClient.h"

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QPair>
#include <QPointer>
#include <QString>
#include <QStringList>

#include <functional>
#include <memory>

class QNetworkAccessManager;

namespace avpn {

// --- the HTTP layer (QNAM in the app, a fake in tests) ------------------------------------------------------

class IScanHttp
{
public:
    struct Request {
        QByteArray method = QByteArrayLiteral("GET");
        QString url;
        QList<QPair<QByteArray, QByteArray>> headers;
        QByteArray body;
        qint64 maxBytes = -1;   // hard cut of everything this request may transfer (counted as below); -1 none
        int timeoutMs = 15000;
    };
    struct Response {
        int status = 0;                       // 0 = no complete HTTP answer (transport, timeout, cut)
        QHash<QByteArray, QByteArray> headers; // lower-case names
        QByteArray body;
        qint64 bytes = 0;                     // counted: TLS estimate + request + answer headers + body
        bool cut = false;                     // aborted at maxBytes
        bool canceled = false;                // aborted from outside (our own tunnel transition aborts requests)
        QByteArray header(const char *name) const { return headers.value(QByteArray(name).toLower()); }
    };
    using DoneFn = std::function<void(const Response &)>;
    virtual ~IScanHttp() = default;
    // `done` exactly once, on the GUI thread, never from inside send().
    virtual void send(const Request &r, DoneFn done) = 0;
};

// A manifest / token request our own tunnel switch cancelled (no HTTP answer, canceled from outside - not a timeout)
// is sent again after kScanCanceledRetryDelayMs, at most kScanCanceledRetries times; anything else ends as before.
inline constexpr int kScanCanceledRetries = 3;
inline constexpr int kScanCanceledRetryDelayMs = 1500;
inline bool scanRetryCanceledRequest(int status, bool canceled, int retriesDone)
{
    return status == 0 && canceled && retriesDone < kScanCanceledRetries;
}

// The bytes a request counts before any answer (plan §2.2b: worst cases include one TLS handshake).
qint64 scanHttpRequestBytes(const IScanHttp::Request &r);

// Inflates a gzip body (RFC 1952, one member) into *out; false for anything else or for more than maxOut bytes.
inline constexpr qint64 kScanInflateMaxBytes = 8 * 1024 * 1024; // above 12 configs of the 256 KiB profile cap
bool scanGunzip(const QByteArray &in, qint64 maxOut, QByteArray *out);

// The production layer: the app's QNAM (its edge / connection-cache handling covers these requests), the
// request bound by armTimeout, the answer counted as it arrives and aborted the moment the count would pass
// maxBytes. It sends `Accept-Encoding: gzip` itself, so QNAM hands the body over as it came: the count and the cut
// are wire bytes (an answer QNAM inflated would count 4-7x its transfer: a provider config of 7.5 KB on the wire
// is 30-53 KB inflated), and the body is inflated here (bounded by kScanInflateMaxBytes; a body that does not
// inflate is a transport failure).
class ScanQnamHttp : public QObject, public IScanHttp
{
    Q_OBJECT
public:
    explicit ScanQnamHttp(QNetworkAccessManager *nam, QObject *parent = nullptr);
    void send(const Request &r, DoneFn done) override;

private:
    QPointer<QNetworkAccessManager> m_nam;
};

// --- key-value storage (QSettings / files in the app; memory in tests) --------------------------------------

class IScanStore
{
public:
    virtual ~IScanStore() = default;
    virtual QByteArray read(const QString &key) const = 0;
    virtual bool write(const QString &key, const QByteArray &value) = 0;
    virtual void remove(const QString &key) = 0;
};

// QSettings for small values; keys under "scan-manifests/" are files in the app data directory (QSaveFile).
class ScanSettingsStore : public IScanStore
{
public:
    QByteArray read(const QString &key) const override;
    bool write(const QString &key, const QByteArray &value) override;
    void remove(const QString &key) override;
};

inline constexpr char kScanManifestSigContext[] = "tribe-scan-manifest-v1";
inline constexpr char kScanCandidatesSigContext[] = "tribe-scan-candidates-v1"; // POST /v1/scan/candidates (1.14.0)
inline constexpr char kScanManifestStorePrefix[] = "scan-manifests/";

// The store key of a network's manifest (16 hex of sha256 of the network key: no network key in a file name).
QString scanManifestStoreKey(const QString &networkKey);
// An ETag the contract allows: "sm1.<22 base64url>" with the quotes.
bool scanManifestEtagValid(const QByteArray &etag);
// The provider leg config of `tribe-scan-v1` (ScanHostContract.h CAND config for xray_leg) from the signed
// manifest's projection of that profile: {"outbound": legs[0].outbound, "dns": [{address, tag, transport}]}.
// "" = no single-leg projection. SECRET.
QString scanProviderLegConfig(const QJsonObject &manifestBody, const QString &profileId);
// A fresh probe nonce: 24 chars of [A-Za-z0-9] (the contract allows 8-64 of [A-Za-z0-9._-]).
QByteArray scanProbeNonce();
// A fresh probe-batch operation id: 32 hex chars of a random UUID (the contract: ^[A-Za-z0-9_-]{16,64}$).
QString scanOperationId();
bool scanOperationIdValid(const QString &id);

class ScanApiClient;

// The owner of one probe-seat batch (contract 1.15.0). ScanApiClient::probeBatch makes it with the batch's
// operation id; whoever keeps it owns the batch's seats. The seats are released by the operation id (with the lease
// ids the answer granted) when they may be held and nobody will release them one by one:
//  - at once when the batch request ends without an answer that can be used (no HTTP answer after the resends, a
//    signature that fails, another operation's answer): the server may have granted seats the app never saw;
//  - when the owner is destroyed while granted seats are still held (forget() takes the ones released one by one
//    by lease id) - a request still in flight then sends no resend; its seats are released once it ends.
// A release our own transition cut is sent again (ScanApiClient::sendRelease). Destroying the owner never cancels
// the request: `done` of probeBatch is called exactly once whatever happened.
class ScanSeatBatch
{
public:
    ~ScanSeatBatch();
    ScanSeatBatch(const ScanSeatBatch &) = delete;
    ScanSeatBatch &operator=(const ScanSeatBatch &) = delete;
    QString operationId() const;
    // These lease ids were released by their owner one by one: not released again.
    void forget(const QStringList &leaseIds);
    // The owner gives the batch up for good (what the destructor does) and `idle` is called ONCE when nothing of the batch can
    // spend any more: no request in flight and no release outstanding (at once if that is so already). The state outlives the
    // owner, so the callback comes after the object is gone.
    void retire(std::function<void()> idle);

    struct State;

private:
    friend class ScanApiClient;
    explicit ScanSeatBatch(std::shared_ptr<State> s) : m_s(std::move(s)) {}
    std::shared_ptr<State> m_s;
};

class ScanApiClient : public QObject
{
    Q_OBJECT
public:
    explicit ScanApiClient(IScanHttp *http, IScanStore *store, QObject *parent = nullptr);
    void setHttp(IScanHttp *http) { m_http = http; }

    // apiBase = the app's active API base at the moment of each call (the edge path the upstream client uses);
    // pubKeyHex = the /v1/config key; deviceToken = the subscription token at the moment of the call.
    void configure(std::function<QString()> apiBase, std::function<QString()> pubKeyHex,
                   std::function<QString()> deviceToken);
    bool configured() const;

    // The live-tunnel probe runner: UpstreamLeaseClient::runProbe in the app (set by setNetworkManager), a
    // fake in tests.
    using ProbeRunner = std::function<void(const UpstreamLeaseClient::ProbeRequest &, std::function<void(const UpstreamProbeFacts &)>)>;
    void setProbeRunner(ProbeRunner runner) { m_probe = std::move(runner); }
    // Production wiring: an UpstreamLeaseClient on the app's QNAM provides runProbe.
    void setNetworkManager(QNetworkAccessManager *nam);

    // --- manifest + token ----------------------------------------------------------------------------------
    struct Manifest {
        bool ok = false;
        QString reason;            // !ok: scanner_off (404: the server switch) | not_entitled | over_quota | manifest_invalid | manifest_unavailable
        QJsonObject body;          // the verified signed body
        ScanManifestView view;
        QString scanToken;         // SECRET: this scan's token
        QString tunnelApiBase;     // where /v1/probe goes through a tunnel
        QString directApiBase;     // where /v1/netinfo goes directly
        qint64 bytes = 0;          // what the manifest + token requests really transferred
        int statusManifest = 0;    // 200, 304, ... (0 = none / stored copy used offline)
        bool fromStore = false;    // the stored copy was used (304, or offline with an unexpired token)
        qint64 tokenExpiresAtMs = 0; // wall clock; 0 = unknown
    };
    // costBytes = the machine's reservation for the manifest + token pair (the cut of BOTH requests together).
    void fetchManifest(const QString &networkKey, qint64 costBytes, qint64 nowMs, std::function<void(const Manifest &)> done);
    // POST /v1/scan/token alone (the Doctor's speed sample without a scan): token "" = refused / failed.
    void fetchToken(qint64 costBytes, qint64 nowMs, std::function<void(const QString &token, qint64 expiresAtMs, qint64 bytes)> done);
    // The tunnel_api_base of the stored manifest of a network key ("" = none / not verified).
    QString storedTunnelBase(const QString &networkKey) const;
    // Stored copies older than a newer upstream_revision of a subscription / renewal answer are dropped.
    void dropManifestsBelowRevision(qint64 revision);

    // --- the whole pool (contract 1.14.0) ----------------------------------------------------------------------
    // GET /v1/scan/pool: counts per country / function. ok false: reason scanner_off (404) | not_entitled |
    // over_quota | rate_limited | unsupported (an older server: 404 is read as the switch, so the caller keeps its
    // local menu) | transport | invalid.
    struct Pool {
        bool ok = false;
        QString reason;
        ScanPoolView view;
        qint64 bytes = 0;
        int status = 0;
    };
    void fetchPool(qint64 costBytes, std::function<void(const Pool &)> done);
    // POST /v1/scan/candidates: one signed batch of a scope's rows not in `seen` (scope "default" | "country" |
    // "whitelist"; country with "country" only; limit 1..24). ok false: the same reasons (+ invalid for a bad answer
    // or a signature that fails: nothing of it is used).
    struct Candidates {
        bool ok = false;
        QString reason;
        ScanCandidatesView view;
        QJsonObject body;          // the verified body (SECRET: the provider rows' projections - their leg configs)
        qint64 bytes = 0;
        int status = 0;
    };
    void fetchCandidates(const QString &networkKey, const QString &scope, const QString &country, const QStringList &seen,
                         int limit, qint64 costBytes, std::function<void(const Candidates &)> done);

    // --- probe-batch -----------------------------------------------------------------------------------------
    struct BatchItem {
        QString profileId;
        bool granted = false;
        QString leaseId;   // SECRET
        QString config;    // SECRET (include_config only)
        // refused: no_seat | disabled | rate_limited | not_entitled | over_quota | upstream_unavailable | lease_failed |
        // lease_gone (a resend of the operation: this profile's seat already ended - the candidate has no seat)
        QString code;
        QString configSha256; // with config: its sha256 (the device-side profile check needs it, as at connect)
    };
    struct Batch {
        bool ok = false;          // a verified answer of this operation (items below), else failCode for every profile
        QString failCode;         // transport | not_entitled | over_quota | disabled | rate_limited | invalid
        QList<BatchItem> items;   // one per requested profile, request order
        qint64 bytes = 0;         // every send of the batch together
        int status = 0;
        int resends = 0;          // sends again after a cut by our own transition (same operation id)
    };
    // POST /v1/upstream/lease/probe-batch with a new operation id; costBytes cuts every send of it together. The
    // returned owner holds the seats (see ScanSeatBatch); releaseBytes gets what its own releases transferred.
    std::unique_ptr<ScanSeatBatch> probeBatch(const QStringList &profileIds, bool includeConfig, qint64 costBytes,
                                              std::function<void(const Batch &)> done,
                                              std::function<void(qint64 bytes)> releaseBytes = {});
    // POST .../probe-batch/release by lease ids and / or an operation id (at least one). A try with no HTTP answer or a
    // 5xx is sent again on the shared spacing (UpstreamLeaseWire.h::seatReleaseNext, the session DELETE's rule too).
    void releaseLeases(const QStringList &leaseIds, qint64 costBytes, std::function<void(qint64 bytes)> done,
                       const QString &operationId = QString());

    // --- outcomes, netinfo -----------------------------------------------------------------------------------
    void sendOutcomes(const QString &networkKey, const QList<ScanOutcomeItem> &items, qint64 costBytes,
                      std::function<void(int status, qint64 bytes)> done);
    // GET {directApiBase}/v1/netinfo with the scan token (plan §2.2c; the coordinator does not feed it as
    // access evidence - the host's own attempt is the only source, §2.11).
    void netinfo(const QString &directApiBase, const QString &scanToken, qint64 costBytes,
                 std::function<void(const ScanAccessAttempt &, qint64 bytes)> done);

    // --- the sized probe through the LIVE tunnel (F2) --------------------------------------------------------
    // Two GETs on one connection (warm, then the data body) via runProbe; the digest is computed here
    // (tribeProbeExpectedSha256Hex), never taken from a header. The answer is a data ITEM of the contract
    // (ScanProbeFacts) whatever happened: no base / token / runner = error "config" (no verdict).
    void liveProbe(const QString &base, const QString &scanToken, const QString &profileId, int warmBytes, int bytes,
                   qint64 costBytes, int timeoutMs, std::function<void(const ScanProbeFacts &)> done);
    // ONE sized GET /v1/probe through the live tunnel (the Doctor's speed sample): the digest computed here.
    struct SpeedFacts {
        int httpStatus = 0;
        qint64 bytes = 0;      // body bytes received (0 unless 200)
        qint64 ms = -1;        // first request byte -> last body byte
        bool digestOk = false; // the full body with the digest the nonce defines
        qint64 wireBytes = 0;  // headers + body as read (the ledger's real bytes)
    };
    void speedProbe(const QString &base, const QString &scanToken, const QString &profileId, qint64 bytes, int timeoutMs,
                    std::function<void(const SpeedFacts &)> done);

    // Journal sink (statuses, counts, byte totals; never secrets or hosts). Default qInfo.
    std::function<void(const QString &)> log;
    // The spacing budget of a seat release's resends (seatReleaseNext; tests shorten it).
    qint64 releaseRetryBudgetMs = kSeatReleaseRetryBudgetMs;

private:
    // One try of a probe-seat release; a try with no HTTP answer or a 5xx is sent again (seatReleaseNext).
    void sendRelease(const IScanHttp::Request &rq, int leases, int attempt, qint64 spent, qint64 spacedMs,
                     std::function<void(qint64)> done, quint64 bgKey = 0);
    // One send of a probe-seat batch; a send our own transition cut is sent again with the same body (operation id).
    void sendBatch(std::shared_ptr<ScanSeatBatch::State> st, IScanHttp::Request rq, int attempt);
    void finishBatch(std::shared_ptr<ScanSeatBatch::State> st, const IScanHttp::Response &r);
    friend class ScanSeatBatch;
    static void releaseBatch(const std::shared_ptr<ScanSeatBatch::State> &st);
    struct Stored {
        bool ok = false;
        QByteArray body;
        QByteArray sig;
        QByteArray etag;
        QJsonObject obj;
        qint64 expiresAtMs = 0;
        qint64 tokenExpiresAtMs = 0;
        qint64 revision = 0;
    };
    Stored loadStored(const QString &networkKey) const;
    void saveStored(const QString &networkKey, const QByteArray &body, const QByteArray &sig, const QByteArray &etag);
    void removeStored(const QString &networkKey);
    bool verifyAndParse(const QByteArray &body, const QByteArray &sig, Stored &out) const;
    QString base() const;
    void emitLog(const QString &line) const;

    struct ManifestRun;
    void manifestGet(std::shared_ptr<ManifestRun> run, bool conditional);
    void manifestToken(std::shared_ptr<ManifestRun> run);
    void manifestFinish(std::shared_ptr<ManifestRun> run);
    // A request our own tunnel switch cancelled (net_error 5, not a timeout, not our byte cap) is sent again once
    // the tunnel had time to come up, instead of ending the scan with manifest_unavailable (coordinator 18.11).
    bool retryCanceled(std::shared_ptr<ManifestRun> run, const IScanHttp::Response &r, std::function<void()> again);

    IScanHttp *m_http = nullptr;
    IScanStore *m_store = nullptr;
    std::function<QString()> m_apiBase;
    std::function<QString()> m_pubKeyHex;
    std::function<QString()> m_deviceToken;
    ProbeRunner m_probe;
    UpstreamLeaseClient *m_lease = nullptr; // runProbe provider in the app
};

// The store key of the list of network keys with a stored manifest (for revision drops).
inline constexpr char kScanManifestIndexKey[] = "avpn/scanManifestIndex";

} // namespace avpn
