// client/core/serviceEngine/TribeScanner.h
// AVPN serviceEngine - the Scanner («Сканер») coordinator (lane L6a): the QObject facade that drives the
// pure ScanMachine. It delivers every event (screen, engine, network, host replies, server answers, time),
// executes every action through injected interfaces, and exposes the view and the shade queue to QML.
// [IN-FORK BUILD: QtCore + QtNetwork]
//
// Plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md §0, §2.2-§2.2c, §2.7-§2.12, §5.1 (L6a); API
// note ~/avpn-build/plans/provider-pool/scanner-api-note.md (what the QML, engine and host lanes rely on).
// Rules (each one a test in tests/scanner_facade_check.cpp):
//  - CONNECT-INVARIANTS §32: the coordinator NEVER touches the tunnel itself. The machine's three tunnel
//    actions go to IScanEngine unchanged: UserConnectForScan -> userConnectForScan() (the ordinary start()),
//    CancelPendingConnect -> cancelPendingConnect() (the ordinary stop() of THAT connect), ConnectRow ->
//    connectRow(node, order, ttl, userOrigin, forceConnect) exactly as the machine set them. No other path.
//  - ONE scheduler timer (IScanTimer) whose due time is the earliest of: the machine's wakeAtMs (tick), the
//    view's nextChangeAtMs (re-read), the host poll (scan_poll_ms, only while the host scan runs or the
//    machine is draining()) and the shade queue's wake. No other timer, no watchdog, no retry loop; nothing
//    here acts on the tunnel when it fires.
//  - Secrets join only through scanBuildStartRequest / scanBuildHostCandidates (ScanMachine.h); the scan
//    token, lease ids and configs live here and in ScanApiClient only; no journal line carries a token, a
//    lease id, a config, a URL, an entry address or a provider host (counts, kinds, statuses, byte totals).
//  - Host failures: hostFailed(..., startAccepted = false) ONLY for the error reply to scan_start itself or a
//    start that never reached a host (no host / not available) - settled at once with host charge 0; every
//    other failure (a poll error, the running scan unknown to the host, the host gone mid-scan) keeps the
//    default: the machine's bounded draining rule.
//  - An Unavailable host never gets a start: NoScan "service_off" («Служба Tribe VPN не запущена»),
//    "service_old" or "service_mismatch" (the service differs from the app: update it); "connecting" holds the manifest
//    in Preparing until onAvailabilityChanged, at most scan_stop_ms. A scan_start refused with
//    internal/kill_switch_exemption shows "host_kill_switch" (the core's hostFailed detail). A poll refused by the service's IPC bounds
//    (ipc_refused too_large / rate_limited / queue_full, rate_limited) is a skipped round; ipc_refused
//    shutting_down and every other error are host failures.
//  - A 404 of /v1/scan/manifest or /v1/scan/token = the server's switch is off: NoScan "scanner_off" (never
//    the desktop service's text), and open / retry / connect-and-scan request nothing until refreshSwitches()
//    sees the switches change.
//  - Every asynchronous reply fed into the machine is bound to the scan that asked (scan id + scan token +
//    network generation at request time): a stale live-probe result or light fact is dropped (its bytes still
//    accounted); a stale probe-batch reply never touches the current scan - its grants are released at once.
//  - A transient "not now" of the host (tunnel_changed, stale_epoch; internal/stop_pending = internal/stopping =
//    teardown_pending) to scan_start or
//    scan_add is not a failure: sent ONCE more by the coordinator after the tunnel settled (tunnel_changed and stale_epoch: the
//    next vpnState, at most scan_drain_ms; the others: after scan_drain_ms); a second refusal ends the start as
//    refused (startAccepted = false, no host charge) with NoScan host_busy, an add's candidates «Не проверено».
//  - Host replies (review R1-R3), two invariants held by structure:
//    1. Capture at SEND time: every host message (start, add, their retries, freeze, cancel, poll) goes out through
//       sendFor() with a HostAsk captured then (host scan id, the scan binding, its probes and lease ids); its reply
//       handler, the held-retry entry and the retry timer read only that. A reply of a scan that is no longer
//       current may account bytes of ITS host scan, release ITS seats or cancel ITS host scan - never refuse,
//       grant or fail anything of another scan.
//    2. Exactly-once settlement per host scan id (HostRecord, created when its scan_start is sent): the machine's
//       draining path owns the host charge, except that the machine's share is settled at zero ONLY through
//       machineStartNotTaken() - and a start that may have been taken (its answer not in) is then handed to the
//       coordinator, which charges it once through settleRecord() (its final total, else the whole grant; a second
//       final adjusts to the maximum, never adds). The record is forgotten when every message sent for it is
//       answered, at the latest scan_stop_ms after it settled.
//  - Bytes (plan §2.2b): every app-side action is executed with its costBytes as the hard cut, and its real
//    bytes go back with appRequestDone for EVERY request id - an abandoned manifest (superseded by a network
//    change) included; light checks report their worst case when their facts are in.
//  - Access evidence: only the host's attempts of the CURRENT host scan, started with THIS scan's token, reach
//    the machine; ScanManifestInput.access stays empty; progress of an older host scan is delivered for its
//    byte settlement with access / access_close stripped.
//  - Network: the strict tuple = the engine's app source(s) + the host's element, which joins at open()
//    from IScanHost::generation() or the "gen" of the host's last scan_caps reply; afterwards a change of it (generation() or scan_progress.gen) or its
//    disappearance is a networkChanged. A host element seen only inside scan_progress never joins (the
//    machine's own host-gen guard covers that scan; joining later would break the S6 cooldown). Only the
//    CURRENT scan's progress (binding captured when its start was sent) moves the element, and it only moves
//    forward: an older counter of the same monitor start, or a start already left, is a late reply's past.
//  - Persistence (IScanStore): ledger "avpn/scanBudget" (restored at construction), cached results per
//    network key + weak fingerprint under "avpn/scanCache/<16 hex>" (index "avpn/scanCacheIndex", <= 8), the
//    stored manifests (ScanApiClient).
// Upstream Amnezia has no counterpart.
#pragma once

#include "IScanHost.h"
#include "ScanApiClient.h"
#include "ScanMachine.h"
#include "ShadeQueue.h"

#include <QHash>
#include <QJsonObject>
#include <QObject>
#include <QPair>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <functional>
#include <QJsonArray>
#include <memory>

class QNetworkAccessManager;
class QTimer;

namespace avpn {

// The device's network now (plan §2.11, §2.11a), from the engine lane.
struct ScanNetFacts {
    ScanNetKind kind = ScanNetKind::Unknown;
    QString reportingKey = QStringLiteral("unknown"); // upstreamNetworkKey(...): the only key that leaves the device
    QString gatewayHash;                               // optional local hash of gateway / subnet ("" = none)
    QList<ScanNetSource> appSources;                   // the app process's path monitor element(s)
    QString radio;                                     // cellular radio generation: "5g" | "lte" | "3g" | "2g" | ""
                                                       // (the engine's own network observation; display only)
};

// The AmneziaWG mini-session input of ONE own AWG node, from the engine (plan awg-probe-plan.md §3): the
// DEVICE'S OWN key and config for that node, exactly as the live tunnel would get them (AwgConfigBuilder, the
// node's peer data). SECRET: never logged, never stored. The coordinator adds the probe host / IP / port and
// the echo target and hands it to ScanHostContract.h::scanAwgMiniConfig (which refuses a bad one).
struct ScanAwgNodeInput {
    QString privateKey;                          // the device's own private key (base64 or 64 hex)
    QString address;                             // REQUIRED: the device's tunnel address on that node, "ip" or "ip/prefix"
    int mtu = 0;                                 // 0 = absent
    QString peerPublicKey;                       // the node's public key
    QString presharedKey;                        // optional
    QString endpoint;                            // the node's "ip:port" / "[v6]:port" (an IP literal: no DNS)
    QList<QPair<QString, QString>> obfuscation;  // AmneziaWG UAPI lines key -> value in order (jc, jmin, jmax, s1, s2,
                                                 // h1..h4, i1.. as the live UAPI carries them)
    int boundIf = -1;                            // the physical interface index where known, -1 = unknown
};

// What the engine lane (L6b) provides. Plain C++, GUI thread only.
class IScanEngine
{
public:
    virtual ~IScanEngine() = default;
    virtual ScanCurrent current() const = 0;
    virtual ScanNetFacts network() const = 0;
    // Everything of ScanManifestInput except manifest, access, apiBytes, awgMiniEnabled, strictUnverifiable
    // (the coordinator's): ownNodes, freshFailures, lastKnownGood, upstreamNames, restrictCountry,
    // awgProbeIpKnown, ruSplitOn.
    virtual void fillManifestInput(ScanManifestInput &in) const = 0;
    // SECRET: the exact probe config of an OWN candidate per kind ("" = none).
    virtual QString ownProbeConfig(const ScanCandidate &c) const = 0;
    // Where the live-tunnel probe goes for this connection ("" = the manifest's tunnel_api_base).
    virtual QString liveProbeBase(const ScanCurrent &c) const = 0;
    virtual bool appInFront() const = 0;
    virtual bool reportQueueFull() const = 0;
    // The app's UI language ("ru", "en", "es", ...: AvpnEngineQml::appLang()) for the country menu's names.
    virtual QString uiLanguage() const = 0;
    // R7 (device round 4): the one naming function of the server list for a row id (a node id, "up:<profile>"), so
    // the Scanner never shows «Serbia 1» where the list shows «Сербия 1» (cached rows included). "" = not in the
    // pool now: the row keeps its own label.
    virtual QString rowDisplayName(const QString &rowId) const
    {
        Q_UNUSED(rowId)
        return QString();
    }
    // The AWG mini-session input of an own AWG node (nodeId as in the manifest, e.g. "9"); false = the engine has
    // no config for that node (it is then «Не проверено»). The default (no AWG input: every AWG row «Не
    // проверено» awg_no_address) keeps an engine that does not implement it yet building; L6b overrides it.
    virtual bool awgProbeInput(const QString &nodeId, ScanAwgNodeInput &out) const
    {
        Q_UNUSED(nodeId);
        Q_UNUSED(out);
        return false;
    }
    // IP literals the engine already holds for exactly this host (the probe base's host; e.g. the resolved
    // address of the active API base); {} = none known - the coordinator then resolves it once per scan (the
    // default: always resolve).
    virtual QStringList knownHostIps(const QString &host) const
    {
        Q_UNUSED(host);
        return {};
    }
    // The `upstream.protocols` tags of a provider stub (engine node id "up:<profile>"): the input of the one profile
    // rule the connect applies (XrayProfileSanitizer.h::upstreamProfileOptions). {} = unknown: the backend default.
    virtual QStringList upstreamProtocolTags(const QString &nodeId) const
    {
        Q_UNUSED(nodeId);
        return {};
    }
    // Contract 1.14.0: the stub nodes of a /v1/scan/candidates batch's provider rows (each the exact SubscriptionNode
    // the subscription would carry: no config, a lease grants its seat). The engine adds them to its pool the way it
    // adds standby-pack entries, BEFORE any row of the batch can be tapped, so a tap pins and connects a profile that is
    // not one of the device's 24 stubs. Called on the GUI thread when the batch arrives; the default (an engine
    // without the hook) adds nothing - such a row then fails its connect as an unknown node.
    virtual void offerScanNodes(const QJsonArray &subscriptionNodes)
    {
        Q_UNUSED(subscriptionNodes);
    }
    // The ONLY three ways to the tunnel (CONNECT-INVARIANTS §32).
    virtual void userConnectForScan() = 0;
    virtual void cancelPendingConnect() = 0;
    virtual void connectRow(const QString &nodeId, const QStringList &attemptOrder, qint64 hintTtlMs, bool userOrigin,
                            bool forceConnect) = 0;
    virtual void startLightChecks(const QString &nodeId) = 0;
    // The same with an ask id the engine hands back with each fact (TribeScanner::lightFactFor): binds a fact to
    // exactly the check that asked (review F1). The default forwards to startLightChecks (facts then come
    // through lightFact and are bound by scan, network and live node only).
    virtual void startLightChecksFor(const QString &nodeId, quint64 askId)
    {
        Q_UNUSED(askId);
        startLightChecks(nodeId);
    }
    virtual void startReportCheck(const QString &reportId, const QJsonObject &report, bool withConnection) = 0;
};

// Wall-clock milliseconds as the core expects (ScanMachine.h "Clock"). The app's clock pairs the wall clock
// with a monotonic one: in-process time advances monotonically; a forward wall jump (sleep, NTP) is taken,
// a backward one is not (the machine reads an earlier value as the last one anyway).
class IScanClock
{
public:
    virtual ~IScanClock() = default;
    virtual qint64 nowMs() = 0;
};

// Name resolution of the probe base's host (QHostInfo in the app): once per scan, bounded by the caller; an
// empty list = failure. Never on the tunnel's decision path.
class IScanResolver
{
public:
    virtual ~IScanResolver() = default;
    virtual void lookup(const QString &host, std::function<void(const QStringList &ips)> done) = 0;
};

// The Doctor's speed sample (TribeScanner::sampleSpeed).
struct ScanSpeedSample {
    bool ok = false;        // a 200 came back
    qint64 bytes = 0;       // body bytes received
    qint64 ms = -1;         // request -> last body byte
    bool digestOk = false;  // the full body, the digest verified on the device
    QString error;          // !ok: no_tunnel | budget | no_token | no_base | transport | busy
};

// The one scheduler timer.
class IScanTimer
{
public:
    virtual ~IScanTimer() = default;
    virtual void arm(qint64 delayMs) = 0; // replaces any armed shot
    virtual void cancel() = 0;
    std::function<void()> onFire;
};

inline constexpr char kScannerFlag[] = "scanner";
inline constexpr char kDoctorLegacyFlag[] = "doctor_legacy";
inline constexpr char kScannerReturnHomeFlag[] = "scanner_return_home";
// The scan_caps field (host-only, desktop service, feat/scan-mac-host 49d708502) saying AmneziaWG probes are not
// offered for this scan, its value the reason: "awg_unavailable":"awg_live_peer_unknown" (the probe binary
// exists, the live peer cannot be determined; the kind awg_mini is then absent). The AWG rows end «Не проверено»
// with that reason - the same one the iOS refusal gives.
inline constexpr char kScanCapsAwgWithheldField[] = "awg_unavailable";
inline constexpr char kScanBudgetStoreKey[] = "avpn/scanBudget";
inline constexpr char kScanCacheStorePrefix[] = "avpn/scanCache/";
inline constexpr char kScanCacheIndexKey[] = "avpn/scanCacheIndex";
inline constexpr int kScanCacheMaxNetworks = 8;

// Store key of a network's cached result (network key + weak fingerprint, hashed: nothing readable on disk).
QString scanCacheStoreKey(const QString &networkKey, const QString &fingerprint);

class TribeScanner : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool enabled READ enabled NOTIFY switchesChanged)
    Q_PROPERTY(bool doctorLegacy READ doctorLegacy NOTIFY switchesChanged)
    Q_PROPERTY(bool connectOnOpen READ connectOnOpen NOTIFY switchesChanged)
    Q_PROPERTY(bool returnHome READ returnHome NOTIFY switchesChanged)
    Q_PROPERTY(QVariantMap view READ view NOTIFY viewChanged)
    Q_PROPERTY(bool screenOpen READ screenOpen NOTIFY viewChanged)
    Q_PROPERTY(QVariantMap shade READ shade NOTIFY shadeChanged)
public:
    struct Deps {
        IScanEngine *engine = nullptr;
        IScanHost *host = nullptr;
        IScanHttp *http = nullptr;    // null = ScanQnamHttp over the QNAM of configureApi
        IScanStore *store = nullptr;  // null = ScanSettingsStore
        IScanClock *clock = nullptr;  // null = the system clock pair
        IScanTimer *timer = nullptr;  // null = one QTimer
        IScanResolver *resolver = nullptr; // null = QHostInfo
        bool fetchPoolOnOpen = true;  // GET /v1/scan/pool when the screen opens (contract 1.14.0; off in byte-exact tests)
    };
    explicit TribeScanner(const Deps &deps, QObject *parent = nullptr);
    ~TribeScanner() override;

    // The app's API client: QNAM + active base + /v1/config key + device token (as UpstreamLeaseClient).
    void configureApi(QNetworkAccessManager *nam, std::function<QString()> apiBase, std::function<QString()> pubKeyHex,
                      std::function<QString()> deviceToken);
    ScanApiClient *api() const { return m_api; }

    // --- QML ----------------------------------------------------------------------------------------------------
    bool enabled() const { return m_enabled; }
    bool doctorLegacy() const { return m_doctorLegacy; }
    bool connectOnOpen() const { return m_connectOnOpen; }
    bool returnHome() const { return m_returnHome; }
    QVariantMap view() const { return m_viewMap; }
    bool screenOpen() const { return m_m.screenOpen(); }
    QVariantMap shade() const { return m_shadeMap; }
    // The server list's figures (owner 17.11, provider rows): engine node id -> ms of the latest Scanner result of
    // the network the device is on now, while the Scanner itself would still show it (ScanTypes.h::scanListFigures,
    // scan_cache_works_ttl_s). Reads the persisted result; never measures, never touches the tunnel.
    QHash<QString, int> listFigures() const;

    Q_INVOKABLE void open(bool withCheck = false);
    Q_INVOKABLE void close();
    Q_INVOKABLE void stop();
    Q_INVOKABLE void retry();
    Q_INVOKABLE void connectAndScan();
    Q_INVOKABLE void gotIt();
    Q_INVOKABLE void chooseCountry(const QString &cc);
    // «Найти ещё»: the next batch of this network's candidates not judged yet (country "" = the whole pool, else a
    // scan of that country over the whole pool). The view says more_available / batch / more_country
    // (ScanMachine::moreTapped).
    Q_INVOKABLE void findMore(const QString &country = QString());
    Q_INVOKABLE void tapRow(const QString &id);
    Q_INVOKABLE void tapCheck();
    // Support's «Проверить подключение и отправить отчёт» (variant B, 18.11): the same check without the Scanner
    // screen (ScanMachine::supportCheckTapped); its progress is view.support_check {running, progress}.
    Q_INVOKABLE void checkFromSupport();
    Q_INVOKABLE void tapReportLink();
    Q_INVOKABLE void tapShade();
    Q_INVOKABLE void showShade(const QString &tone, const QString &textKey, const QStringList &args = {},
                               const QString &key = QString());

    // --- the engine lane calls these (GUI thread) ----------------------------------------------------------
    void engineStateChanged();
    void networkChanged();
    void appForeground();
    void lightFact(const ScanLightFact &f);
    // A light fact of the check startLightChecksFor(node, askId) asked for: dropped unless it is the latest ask
    // and its scan, network and live node are still current.
    void lightFactFor(quint64 askId, const ScanLightFact &f);
    // A card fact of the button's FULL check (StartReportCheck): delivered only while that report is the
    // machine's current check AND no new scan started (nor the network changed) since it began.
    void lightFactForReport(const QString &reportId, const ScanLightFact &f);
    void reportCheckStarted();
    void reportCheckProgress(int step, int total);
    void reportCheckDone(bool sent, const QString &reportId);
    // The engine could not start or submit the full check (queue full in a race, another diagnostic running):
    // reason "queue_full" | "busy" | ... - a notice, no «sent» text, the card restored.
    void reportCheckRefused(const QString &reportId, const QString &reason);
    // The Doctor's speed stage: one sized GET /v1/probe of `bytes` (scan_check_speed_bytes) through the LIVE
    // tunnel with this scan's token (POST /v1/scan/token first when there is none), cut at its cost, charged
    // to the cellular / device hour at its worst case like any request outside a scan, refused when that hour
    // cannot cover it. `done` exactly once.
    void sampleSpeed(qint64 bytes, int timeoutMs, std::function<void(const ScanSpeedSample &)> done);
    void connectFailed(const QString &nodeId);
    void attemptEnded();
    // The engine refused a ConnectRow before touching the tunnel (the pin failed, the row's node is gone): the row
    // returns to its normal state and the list takes taps again. Safe to call from inside connectRow (queued).
    void connectRefused(const QString &nodeId);
    void reportQueueChanged();
    void refreshSwitches();
    void noteUpstreamRevision(qint64 revision);

    // --- introspection (tests, journal) --------------------------------------------------------------------
    const ScanMachine &machine() const { return m_m; }
    ScanNetwork lastNetwork() const { return m_lastNet; }
    int pollsActive() const;
    // Settlement records still kept (invariant 2): 0 once every host scan is settled and every message for it answered.
    int hostRecords() const { return int(m_records.size()); }

    // The path race's share of the Scanner (ScanPathProber.h): one byte ledger and one host scan at a time.
    // raceBytesLeft: what may still be spent now (-1 = no cap: no cellular cap applies and no device budget);
    // raceCharge: real bytes of the race's probes and server calls into the same ledger; hostScanRunning: the
    // Scanner's own scan holds the probe host (a race waits).
    // The cellular radio generation for view.net_radio ("5g" | "lte" | "3g" | "2g" | ""): the same platform source the
    // engine reports (TribeNetInfo.h avpn::cellularGeneration), set by the app wiring; unset = none. Used only when
    // the engine's own ScanNetFacts.radio is empty and the network is cellular.
    void setRadioSource(std::function<QString()> radio) { m_radio = std::move(radio); }
    qint64 raceBytesLeft();
    void raceCharge(qint64 bytes);
    bool hostScanRunning() const;
    // Journal sink: one line per event / action kind (never secrets or hosts). Default qInfo "[scanner]".
    std::function<void(const QString &)> log;
    // Taps (tests): every machine event a host reply or a held host message caused, with the scan it acts on (its
    // scan id argument; the current scan for an event keyed by candidate); every byte charge of a host scan made
    // here outside the machine (settleRecord), keyed by host scan id.
    std::function<void(const char *event, const QString &scanId)> onHostEvent;
    std::function<void(const QString &hostScanId, qint64 bytes)> onHostCharge;

    // The timer fired (the IScanTimer's onFire; public for the tests' fake timer).
    void timerFired();

    // Stage 2 of the path engine: the results of a finished scan, as saved (the engine writes them into its ledger
    // at "probe ok" strength - one fact, and Auto reads it from there). Called on the GUI thread.
    std::function<void(const ScanCachedResult &)> onResultsSaved;

signals:
    void viewChanged();
    void shadeChanged();
    void openScreenRequested();
    void closeScreenRequested();
    void switchesChanged();
    void serverSwitchedOff(); // a scan endpoint answered 404 (scanner_off): the engine refreshes /v1/config at once

private:
    // The scan an asynchronous reply belongs to (review F1/F5): captured at request time, compared at reply time.
    struct ScanBinding {
        QString scanId;
        QString token;      // SECRET
        QString generation; // the strict tuple's hash
    };
    ScanBinding bindingNow() const;
    bool bindingCurrent(const ScanBinding &b) const;
    void releaseStaleLeases(const QStringList &leaseIds);
    ScanBinding m_lightAsked;
    QString m_lightNode;
    quint64 m_lightAskId = 0;
    QString m_checkReportId;    // the full check the machine started last (StartReportCheck)
    ScanBinding m_checkAsked;   // the scan / network it started in

    struct HostScan {         // the machine's live tracking of a host scan it owns (polled for the machine)
        QString token;        // SECRET: the token its scan_start carried
        qint64 since = 0;     // the last item seq seen
        bool finalSeen = false;
        bool pollInFlight = false;
    };
    struct Lease {
        QString leaseId; // SECRET
        QString config;  // SECRET
        QString configSha256;
    };
    struct Active {         // what the last delivered manifest gave the current scan
        QString requestId;
        QString token;      // SECRET
        QString tunnelBase;
        QString directBase;
        QJsonObject body;   // the verified manifest (provider projections)
        QStringList baseIps; // IP literals of the probe base's host (probe.base_ips, the AWG session's API IP)
        qint64 tokenExpiresAtMs = 0;
    };
    struct PendingManifest {
        QString requestId;
        bool manifestDone = false;
        bool capsDone = false;
        ScanApiClient::Manifest result;
    };

    qint64 now();
    void dispatch(const ScanStep &s);
    void execute(const ScanAction &a);
    void afterStep();
    void reschedule();
    void refreshView();
    void emitLog(const QString &line) const;

    ScanNetwork buildNetwork() const;
    ScanCachedResult cachedFor(const ScanNetwork &n) const;
    void persistCache(const ScanCachedResult &c);
    void notifyNetwork();
    void foldHostGen(const ScanNetSource &g, bool fromProgress);
    bool hostGenStale(const ScanNetSource &g) const; // older than the joined element: a late reply's past
    void setHostGen(const ScanNetSource &g);
    void hostAvailabilityChanged();
    void hostGenerationChanged();
    bool hostGenerationNow(ScanNetSource &out) const; // IScanHost::generation(), else the last scan_caps "gen"
    void queryCaps(std::function<void()> then);

    void doRequestManifest(const ScanAction &a);
    void manifestComplete(const QString &requestId);
    void deliverManifest(const QString &requestId, const ScanApiClient::Manifest &r, const QStringList &baseIps);
    void continueManifest(const QString &requestId, const ScanApiClient::Manifest &r, const QStringList &baseIps);
    void finishResolve(const QStringList &ips);
    ScanAwgMiniInput awgInputOf(const ScanCandidate &c) const;
    bool admitOutsideScan(qint64 cost, bool *cellularOut);
    void chargeOutsideScan(qint64 bytes, bool cellular);
    void resolveHeld(bool force);
    QString configOf(const ScanCandidate &c) const;
    void doStartHost(const ScanAction &a);
    void doAddHost(const ScanAction &a);
    ScanAction withoutWithheldAwg(const ScanAction &a, QList<QPair<QString, QString>> *refused) const;
    bool m_awgWithheld = false; // the last scan_caps reply withheld AWG probes for this scan
    QString m_awgWithheldReason; // its reason (the field's value)

    // --- host exchanges (TribeScanner.h rules "Host replies", review R1-R3) ---------------------------------------
    // Invariant 1: the context of ONE host message, captured when it is SENT. Its reply handler, a held retry and
    // the retry timer read only this to decide whose state the reply may touch.
    struct HostAsk {
        QString hostScanId;             // the scan id on the wire
        ScanBinding binding;            // the scan that sent it: scan id + scan token + network generation
        QStringList probeIds;           // start / add: the probes it carries
        QHash<QString, QString> leases; // add: candidate id -> its probe lease id when sent (SECRET)
        bool afterStartReply = false;   // sent after its host scan's scan_start was answered: an unknown_scan to it
                                        // can no longer have overtaken that start
    };
    enum class HostAttempt { First, WithoutAwg, NotNowRetry };
    // Invariant 2: what is known about ONE host scan id - created when its scan_start is sent, forgotten when every
    // message sent for it is answered (IScanHost: exactly one reply each), at the latest scan_stop_ms after it is
    // done (settled here, or no longer tracked by the machine).
    enum class HostStart {
        InFlight,   // a scan_start for it is out, not answered: possibly taken
        Held,       // refused with a transient "not now", the one retry not sent yet: not taken
        Accepted,   // acknowledged, or the host answered a freeze / cancel / poll for it
        Unanswered, // its scan_start got no answer: possibly taken (the polls tell)
        Refused,    // the host refused its last scan_start and nothing else is out: not taken
    };
    enum class HostCharge { Final, NotTaken, Conservative };
    struct HostRecord {
        HostAsk start;              // the start's context
        qint64 grant = -1;          // its max_bytes: the whole host grant (-1 = no cap)
        bool cellular = false;      // the network it went out on: where its bytes are charged
        HostStart state = HostStart::InFlight;
        bool ours = false;          // the coordinator charges it (the machine's share was settled at zero while the
                                    // start was possibly taken); else the machine's draining path does
        bool laterStart = false;    // another scan_start went out after it: the engine may have replaced its scan, so
                                    // an unknown_scan no longer proves it never ran
        bool settled = false;       // ours: charged, or proven never taken
        qint64 charged = -1;        // ours: what the ledger got for it here (-1 = nothing yet)
        int pending = 0;            // messages for it sent and not answered yet
        bool cancelInFlight = false;
        bool cancelAcked = false;
        bool cancelAfterReply = false; // ours: a cancel went out after its start was answered
        bool pollInFlight = false;
        qint64 since = 0;
        qint64 lastSpent = 0;
        qint64 lastReserved = 0;
        qint64 deadline = -1;       // ours, not settled: the whole grant is charged then
        qint64 nextPollAt = -1;
        qint64 dropAt = -1;         // done: forgotten at the latest here
    };
    QHash<QString, HostRecord> m_records; // host scan id -> its record
    struct HeldRetry {
        HostAsk ask;                   // the context of the refused message (captured when it was sent)
        bool isStart = true;
        ScanStartRequest start;        // SECRET (token, configs): never logged
        QList<ScanHostCandidate> add;  // SECRET
        bool waitVpn = false;          // tunnel_changed: on the next vpnState event (bounded by dueAt)
        qint64 dueAt = -1;
    };
    QHash<QString, HeldRetry> m_notNow; // a start (key = host scan id) or an add refused with a transient "not now"
    quint64 m_notNowSerial = 0;
    HostAsk askNow(const QString &hostScanId) const;
    HostAsk askOf(const QString &hostScanId) const;
    void sendFor(const HostAsk &ask, const QByteArray &request, std::function<void(const HostAsk &, const QByteArray &)> handler);
    void hostEvent(const char *what, const QString &target, const ScanStep &step);
    bool scanRunning(const ScanBinding &b) const;
    void sendStart(const HostAsk &ask, const ScanStartRequest &req, HostAttempt attempt);
    void onStartReply(const HostAsk &ask, const ScanStartRequest &req, HostAttempt attempt, const QByteArray &reply);
    void retryStartWithoutAwg(const HostAsk &ask, const ScanStartRequest &req);
    void sendAdd(const HostAsk &ask, const QList<ScanHostCandidate> &cands, HostAttempt attempt);
    void onAddReply(const HostAsk &ask, const QList<ScanHostCandidate> &cands, HostAttempt attempt, const QByteArray &reply);
    void refuseAdd(const HostAsk &ask, const QString &reason);
    void holdStart(const HostAsk &ask, const ScanStartRequest &req, const ScanHostReply &r);
    void holdAdd(const HostAsk &ask, const QList<ScanHostCandidate> &cands, const ScanHostReply &r);
    void fireNotNow(bool byVpn);
    void finishHeldStart(const QString &hostScanId, const ScanHostReply *second);
    void machineStartNotTaken(const QString &hostScanId, ScanHostError e, const QString &detail);
    bool startUnanswered(const QString &hostScanId) const;
    void noteTaken(const QString &hostScanId);
    void settleRecord(const QString &hostScanId, HostCharge kind, qint64 bytes = 0);
    void recordUnknown(const HostAsk &ask);
    void sendRecordCancel(const QString &hostScanId);
    void onRecordCancelReply(const HostAsk &ask, const QByteArray &reply);
    void sendRecordPoll(const QString &hostScanId);
    void onRecordPollReply(const HostAsk &ask, const QByteArray &reply);
    void driveRecords();
    void doFreeze(const ScanAction &a);
    void doCancel(const ScanAction &a);
    void doProbeBatch(const ScanAction &a);
    void doRelease(const ScanAction &a);
    void doOutcomes(const ScanAction &a);
    void doLiveProbe(const ScanAction &a);
    void doCandidates(const ScanAction &a);
    void fetchPoolIfStale();
    void doLight(const ScanAction &a);
    void doShade(const ShadeRequest &r);
    void applyShadeStep(const ShadeStep &s);
    void pollHost();
    void onPollReply(const HostAsk &ask, const QByteArray &reply);
    void deliverProgress(ScanHostProgress p, const HostAsk &ask, const QString &startToken);
    void sendHost(const QByteArray &request, IScanHost::ReplyFn reply);
    ScanHostError hostUnavailableError() const;

    IScanEngine *m_engine = nullptr;
    IScanHost *m_host = nullptr;
    IScanHttp *m_http = nullptr;
    IScanStore *m_store = nullptr;
    IScanClock *m_clock = nullptr;
    IScanTimer *m_timer = nullptr;
    std::unique_ptr<IScanHttp> m_ownHttp;
    std::unique_ptr<IScanStore> m_ownStore;
    std::unique_ptr<IScanClock> m_ownClock;
    std::unique_ptr<IScanTimer> m_ownTimer;
    ScanApiClient *m_api = nullptr;

    ScanMachine m_m;
    ShadeQueue m_shade;
    QList<ScanAction> m_queue;
    bool m_dispatching = false;
    qint64 m_machineWake = -1;
    qint64 m_viewWake = -1;
    qint64 m_shadeWake = -1;
    qint64 m_nextPollAt = -1;
    QJsonObject m_viewJson;
    QVariantMap m_viewMap;
    QVariantMap m_shadeMap;

    bool m_enabled = false;
    bool m_doctorLegacy = false;
    bool m_connectOnOpen = true;
    bool m_returnHome = false;
    bool m_serverOff = false;   // a scan endpoint answered 404 (the server's switch): nothing requested until the switches change

    ScanNetwork m_lastNet;
    qint64 m_poolAt = -1;            // when /v1/scan/pool last answered (or was asked); the server allows 60 per hour
    bool m_poolUnsupported = false;  // an older server: no pool endpoint
    bool m_fetchPoolOnOpen = true;
    bool m_hostGenFolded = false;
    ScanNetSource m_hostGen;
    QList<ScanNetSource> m_hostGenLeft; // monitor starts (source + epoch) the host element moved away from (<= 8)
    bool m_capsGenKnown = false;   // the "gen" of the host's last scan_caps reply (iOS: its element outside a scan)
    ScanNetSource m_capsGen;
    bool m_capsInFlight = false;
    QList<std::function<void()>> m_capsWaiters;

    QString m_manifestReqId;                 // the machine's current RequestManifest
    QHash<QString, PendingManifest> m_manifests;
    Active m_active;
    PendingManifest m_held;                  // a manifest waiting for a "connecting" host (desktop)
    QStringList m_heldIps;
    qint64 m_heldUntil = -1;
    struct Resolving {
        QString requestId;
        ScanApiClient::Manifest result;
        quint64 serial = 0;
    };
    Resolving m_resolving;                   // a manifest waiting for its probe base's addresses
    qint64 m_resolveUntil = -1;
    quint64 m_resolveSerial = 0;
    IScanResolver *m_resolver = nullptr;
    std::unique_ptr<IScanResolver> m_ownResolver;
    bool m_speedBusy = false;
    QString m_speedToken;                    // SECRET: a token fetched for the speed sample alone
    qint64 m_speedTokenExpiresAtMs = 0;
    std::function<QString()> m_radio;
    QHash<QString, HostScan> m_hostScans;    // host scan id -> its state
    QHash<QString, Lease> m_leases;          // candidate id -> its probe lease
    QString m_lightReqId;
};

} // namespace avpn
