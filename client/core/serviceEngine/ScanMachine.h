// client/core/serviceEngine/ScanMachine.h
// AVPN serviceEngine - the Scanner («Сканер») as a pure state machine: events in, actions out, plus the
// whole view state the screen binds. [header-only, QtCore values; no timers, no I/O, no globals]
//
// ==== CONNECT-INVARIANTS §32 (owner decision 15.11.2026) ====================================================
// THE SCAN RUNS BESIDE THE TUNNEL AND NEVER SWITCHES IT. The only path from the Scanner to the tunnel is the
// user's tap on a row: ConnectRow = the existing pinAndReconnect of the servers screen plus a one-attempt
// order hint (the visible order after the country filter, starting after the tapped row) that the existing
// ladder (ServiceEngine::nextCandidate) consumes for that attempt only. The machine never connects,
// disconnects or moves the tunnel on its own (REQ S3). Exactly three actions touch the tunnel
// (scanActionTouchesTunnel), each a test in tests/scan_core_check.cpp:
//   ConnectRow           - only from rowTapped (the user's tap); carries userOrigin + forceConnect, so a row
//                          tapped with the VPN off connects through the ordinary user connect (review F4);
//   UserConnectForScan   - REQ S3 (b), the owner's exception: the user opens the Scanner or presses its scan
//                          button with the VPN off on a host whose probes need the tunnel process
//                          (scan_caps.needs_vpn: iPhone, Android) and the client switch
//                          features.scanner_connect_on_open is on (compiled default true): the ordinary user
//                          connect («Подключаемся…»). With the switch off the screen shows the last results and
//                          an explicit «Подключиться и проверить» button (connectAndScanTapped) and nothing
//                          is emitted until it is pressed. A host that probes with the VPN off (macOS,
//                          Windows) never gets it. After the connect the VPN stays on like after any user
//                          connect - whether the scan finishes, is stopped or the screen is closed;
//   CancelPendingConnect - the ordinary user cancel of THAT connect: «Остановить» or leaving the screen while
//                          it has not reached «Подключено» (phase Connecting). Never after the data passed,
//                          never for a tunnel this machine did not start (a fresh machine after an app
//                          relaunch never cancels anything), never on completion. The machine has no other
//                          way to turn the VPN off.
// The scan's own deadline and the light-check bound are wake-ups of this machine (wakeAtMs); they stop
// probes and fill the screen, they never act on the tunnel. An AmneziaWG mini-session (the device's own key)
// is never planned for, and leaves the scan the moment it becomes, the live tunnel's node or the target of a
// connect attempt in progress (awg-probe-plan.md §5: the same key there would move the live endpoint).
// =============================================================================================================
//
// Plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md §1 (states S0-S11, timers, filters, the reality
// table 1.4), §2.1, §2.5-§2.10, §4.4; artboard vpn-scanner.js (demo logic). Behaviour, each a test:
//  - Open (S0): a cached result of this network shows at once (rows marked fromCache, caption «Проверено
//    N мин назад»; only rows of the same weak fingerprint, never counted as verified; up to kScanCacheShowMaxMs
//    old while the fresh scan runs, within scan_cache_works_ttl_s as the result when no scan can run;
//    dropped when the scan finishes unless re-verified). Inside the cooldown after a COMPLETED
//    scan of the same network: the last result and no new scan (S6). A scan that was stopped or interrupted
//    leaves no result: the next open scans.
//  - Cooldown scan_manual_cooldown_s from the scan START, held by this machine (lives in the coordinator,
//    survives leaving the page), whether that scan completed or was left (review F8: reopening a left scan
//    inside the cooldown shows NoScan "cooldown", never a new scan) - armed only by a scan that reached a host
//    (its start was not refused) or sent the live-tunnel probe. A scan that ended before (host unavailable,
//    no_vpn, a refused start, manifest unavailable / invalid / not entitled / over quota, budget) arms none:
//    «Повторить» is enabled at once; such retries still cost a manifest request each - bounded by the
//    cellular hour (ScanBudget.h) and by kScanManifestBackoffMs between the buttons' requests.
//  - Local network identity (F10, ScanNetworkGeneration.h): the strict generation tuple decides what is
//    CURRENT (fresh rows, access facts, the live proof, the exclusion bracket - stamped with its hash); the weak
//    fingerprint keys CACHED rows only (they survive a relaunch, are drawn as cache with their age and never
//    count); the operator key is only for reports. Any change of the tuple cancels the running scan and allows
//    one rescan without the cooldown; fresh rows of another tuple become cache rows of their fingerprint.
//  - Access evidence (F5) - the ASN / net token the D7 path rules compare against - belongs to this tuple and
//    this scan token: cleared at every scan start and network change; set from this scan's manifest input or
//    the host's OPENING access attempt (which replaces it: facts when it answered 200, nothing otherwise);
//    cleared when the host reports another state of its path monitor than at that attempt. Without it a
//    provider path stays «Не проверено» - unless proven by exclusion (ScanClass.h rule 4a: the opening and
//    the closing attempt both failed at the network level around the probe; off with
//    features.upstream_unverifiable_strict). An exclusion row counts as works (reason / stats "exclusion";
//    the outcome and the Doctor row carry evidence "exclusion", contract 1.7.0).
//  - The live connection (F2) is a row «Подключено» at once, but «works» (counted, cached, in the summary)
//    only after ProbeLiveTunnel - the sized, digest-checked /v1/probe through the live tunnel - says so, once
//    per scan; the light checks (S8) also run again with every scan (F9).
//  - Bytes (plan §2.2b, F6/F7): ONE allowance per scan A = min(scan_budget_scan_bytes, the rolling cellular
//    hour) on cellular, the server device budget where named, else unlimited. The app side is reserved FIRST
//    at its worst cases (scan_cost_*: manifest + token before the host; then probe-batch (+ configs on Wi-Fi),
//    one batch release, the live-tunnel probe, the light checks, the outcome batch); every app request is
//    admitted against that slice with the atomic rule and its reservation is replaced by the real bytes
//    (appRequestDone). The host gets the rest as max_bytes; below the cheapest probe the host is not started
//    (app side only, shade "scan_budget"). Stop: FreezeHostScan, then StopHostScan after the freeze ack; the
//    host share is the final total (final progress or cancel ack), else the ack's spent + reserved after
//    scan_drain_ms, else the whole grant after scan_freeze_ack_ms. The ledger gets app actual + host charge
//    once, when both are known (PersistBudget).
//  - Cellular budget (ScanBudget.h): a scan starts only when the rolling hour covers its projection; the
//    button becomes «Повторить через N мин» (hint «Лимит сканов в мобильной сети на этот час»).
//  - Flow: Preparing (manifest requested) -> [Connecting (S1, VPN-required host, VPN off)] -> Reach (S2) ->
//    Data (S3: from the first data item or the host's phase) -> Self (S4: the light checks of «Ваше
//    подключение», only with a live connection, bounded by scan_light_timeout_ms) -> Done (S5) | Empty (S7).
//    NoScan = a scan could not run (scanner switched off / manifest unavailable, budget, host error,
//    network changed while showing results): cached rows within scan_cache_works_ttl_s are the result.
//  - Stop at scan_stop_works working rows (works + slow, the live connection included) or scan_stop_ms
//    after the host start (S1 not counted).
//  - Seats (plan §2.10, lead decision 2): ONE `POST /v1/upstream/lease/probe-batch` per scan
//    (RequestProbeBatch) sized to the first provider wave: at most the slots of the pools the providers use
//    (leg pool, full pool), never above kScanProbeBatchMax = 12, and only what fits the host grant together
//    with the own candidates; the rest is «Не проверено» (batch_cap / budget), never a second batch.
//    `include_config` decided up front, Wi-Fi only: true when a candidate may need a full probe on this host
//    (a full-kind provider, or a leg whose DNS plan is not through the leg while the host can run full
//    probes), so a follow-up reuses the grant; on cellular never (a provider full probe there is «Не
//    проверено» config_cellular). A granted candidate enters the host only when its pool has a slot (own
//    candidates queued in the pool count as busy; free slots warm lower tiers up, D9), never for a tier whose
//    lower tiers already have scan_list_target_works working rows, never past the byte cap; its seat is
//    released right after its last probe (ReleaseProbeLeases, at most 12 per call), on every stop and at once
//    when a grant comes after the stop; a release the allowance cannot admit waits for the final release of
//    the scan, which has its reservation. Refused: no_seat / rate_limited / transport -> «Не проверено»
//    (never «Не работает»); disabled / not_entitled / over_quota / lease_gone -> dropped. Seats asked go to
//    the Doctor summary (seats_requested, contract 1.7.0) and lastStats().
//  - Rows: at most scan_list_target_works verified rows (the live connection, the connecting row and rows
//    whose connect failed always kept; the rest admitted by tier first, fresh before cached, then speed),
//    shown by speed class (fast, medium, slow), then ms, then tier, rank, id - a total order, so a row moves
//    only when its own facts change; the live connection sits where its live ms puts it (artboard). Then
//    at most scan_unverified_rows_max «Не проверено» rows, only while fewer than the cap are verified.
//  - Country filter after the scan (the menu is disabled while scanning, hidden with one country), reset
//    by a new scan; the attempt order hint follows the filtered order.
//  - Tap (S8): during a scan the scan stops at once and keeps its fresh rows. Connecting -> «Подключение…»;
//    the engine's live data (vpnState dataFlowing) -> «Подключено», the screen STAYS (owner 15.11), the card
//    refills for the new node; connectFailed -> «Не удалось» + warning shade «… подключаем следующую» while
//    the hint has a candidate left, else «… проверьте снова через минуту».
//  - Card «Ваше подключение»: Off without a live data path; Filling / Filled from the light facts; Checking
//    while the button's check runs («Проверяем…»); Checked after the report: shade success (sent) or info
//    (queued offline, «Отчёт уйдёт, когда появится связь»). The report is always sent (the coordinator).
//  - Empty (S7): «Понял, подключусь к Wi‑Fi» (cellular) arms the Wi-Fi intent for scan_wifi_rescan_window_s:
//    a Wi-Fi network delivered while the app is in front (networkChanged with appInFront, or appForeground)
//    opens the Scanner and scans once (A5).
//  - Network change during a scan: the scan is cancelled (its finished results still reported under the old
//    key) and restarted on the new network; while the open screen shows a finished result: a new scan by itself
//    (artboard; scanRescanOnNetworkChange - cooldown cleared, the cellular hour still applies, never starting the
//    VPN), otherwise the new network's cached rows (NoScan network_changed).
//  - Outcomes (ScanOutcomes.h): one batch per scan (also for a cancelled one: what was measured is true),
//    one per tap's connect chain. Budget actuals go to the ledger at every scan end (PersistBudget).
//  - Doctor summary (lab seam S4, 16.11): every planned candidate ends in exactly one bucket - works, slow, a
//    failure class, or not_verified with its reason (order-only, no_seat, budget, ..., and "cancelled" for a
//    probe the stop cut in flight, "lease_pending" / "not_started" for one the scan never reached) - so the
//    counts sum to `candidates` (+1 for the live row) and the reasons to counts.not_verified. Those without a
//    verdict are «Не проверено» rows under scan_unverified_rows_max; never an outcome (unknown is not a failure).
//
// Clock: `now` = wall-clock milliseconds (QDateTime::currentMSecsSinceEpoch) - the cached results and the
// budget ledger are persisted across launches. A value earlier than the last one is read as the last one.
// The coordinator calls tick(now) at or after wakeAtMs from a timer it already has (the poll timer of the
// host, 300 ms, runs anyway while the screen is open); view(now) may be re-read at nextChangeAtMs.
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanBudget.h"
#include "ScanClass.h"
#include "ScanHostContract.h"
#include "ScanOutcomes.h"
#include "ScanPlan.h"
#include "ScanTunables.h"
#include "ScanTypes.h"
#include "ShadeQueue.h"

#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVector>

#include <algorithm>
#include <climits>

namespace avpn {


// --- phases --------------------------------------------------------------------------------------------------

enum class ScanPhase { Idle, Preparing, Connecting, Reach, Data, Self, Done, Empty, NoScan };

inline const char *scanPhaseName(ScanPhase p)
{
    switch (p) {
    case ScanPhase::Idle: return "idle";
    case ScanPhase::Preparing: return "preparing";
    case ScanPhase::Connecting: return "connecting";
    case ScanPhase::Reach: return "reach";
    case ScanPhase::Data: return "data";
    case ScanPhase::Self: return "self";
    case ScanPhase::Done: return "done";
    case ScanPhase::Empty: return "empty";
    case ScanPhase::NoScan: break;
    }
    return "no_scan";
}

inline bool scanPhaseScanning(ScanPhase p)
{
    return p == ScanPhase::Preparing || p == ScanPhase::Connecting || p == ScanPhase::Reach || p == ScanPhase::Data
           || p == ScanPhase::Self;
}

// A network change while the open screen shows a finished result (artboard, «Сеть сменилась после скана»: the
// shade «Сеть сменилась — проверяем заново» and a new scan by itself, instead of the old result and «Повторить»).
// Only from a result the person is looking at - Done, Empty, or NoScan for the pause, the cellular hour or an
// earlier network change (the new network clears the pause, §32 п. 9; the hour is checked again by beginScan,
// which shows frame 22 when it is still used up). Never by starting the VPN: a host that needs the VPN (iPhone,
// Android) with no tunnel working, up or coming keeps «Повторить» - only opening the Scanner or its button starts
// the user's connect (§32 п. 2б). Every other NoScan (service, host, server switch, vpn_off, manifest) keeps
// «Повторить» as before. No new timer and no new limit: the scan runs under the existing budget and cooldown. Pure.
inline bool scanRescanOnNetworkChange(bool screenOpen, ScanPhase phase, const QString &noScanReason, bool hostNeedsVpn,
                                      bool tunnelUpOrComing)
{
    if (!screenOpen || (hostNeedsVpn && !tunnelUpOrComing))
        return false;
    if (phase == ScanPhase::Done || phase == ScanPhase::Empty)
        return true;
    return phase == ScanPhase::NoScan
           && (noScanReason == QLatin1String("cooldown") || noScanReason == QLatin1String("budget")
               || noScanReason == QLatin1String("network_changed"));
}

// --- actions -------------------------------------------------------------------------------------------------

enum class ScanActionKind {
    RequestManifest,    // networkKey: answer with manifestReady / manifestUnavailable
    StartHostScan,      // scanId, candidates (no secrets), limits, deadlineMs, maxBytes, warmBytes, bytes
    AddHostCandidates,  // scanId, candidates (provider candidates whose probe lease arrived)
    FreezeHostScan,     // scanId: scan_freeze (stop admitting probes), answer with hostFreezeAck
    StopHostScan,       // scanId: scan_cancel (after the freeze ack, or when it did not come)
    RequestProbeBatch,  // ids + candidates (profile ids), includeConfig: POST /v1/upstream/lease/probe-batch (once per scan)
    ReleaseProbeLeases, // ids (<= 12): POST /v1/upstream/lease/probe-batch/release with their lease ids
    StartLightChecks,   // nodeId: server + chips state + RU sites, answer with lightFact events
    StartReportCheck,   // withConnection: the full check + report (sent ALWAYS)
    ShowShade,          // shade: enqueue in the app's ShadeQueue
    SendOutcomes,       // networkKey, outcomes: POST /v1/telemetry/path-outcomes (ScanOutcomeCollector batches)
    PersistResults,     // cached: store per network key
    PersistBudget,      // ledger: QSettings avpn/scanBudget
    CloseScreen,        // leave the Scanner page
    OpenScreen,         // open the Scanner page (the Wi-Fi intent fired)
    ProbeLiveTunnel,    // nodeId, warmBytes, bytes: the sized /v1/probe through the LIVE tunnel (review F2), answer
                        // with liveProbeResult - the connected row is «works» only after it
    RequestCandidates,  // networkKey, scopeCountry ("" | cc | "whitelist"), ids = seen, batch = limit: POST
                        // /v1/scan/candidates (1.14.0), answer with candidatesReady / candidatesUnavailable
    // The only three that touch the tunnel (§32 above):
    UserConnectForScan,   // VPN-required host, VPN off, the user opened / pressed scan: the ordinary user connect
    CancelPendingConnect, // Stop / leave while that connect has not reached «Подключено»: the ordinary user cancel
    ConnectRow,           // the user's tap: pinAndReconnect(nodeId, userOrigin, forceConnect) + attempt order hint
};

inline const char *scanActionName(ScanActionKind k)
{
    switch (k) {
    case ScanActionKind::RequestManifest: return "request_manifest";
    case ScanActionKind::StartHostScan: return "start_host_scan";
    case ScanActionKind::AddHostCandidates: return "add_host_candidates";
    case ScanActionKind::FreezeHostScan: return "freeze_host_scan";
    case ScanActionKind::StopHostScan: return "stop_host_scan";
    case ScanActionKind::RequestProbeBatch: return "request_probe_batch";
    case ScanActionKind::ReleaseProbeLeases: return "release_probe_leases";
    case ScanActionKind::StartLightChecks: return "start_light_checks";
    case ScanActionKind::StartReportCheck: return "start_report_check";
    case ScanActionKind::ShowShade: return "show_shade";
    case ScanActionKind::SendOutcomes: return "send_outcomes";
    case ScanActionKind::PersistResults: return "persist_results";
    case ScanActionKind::PersistBudget: return "persist_budget";
    case ScanActionKind::CloseScreen: return "close_screen";
    case ScanActionKind::OpenScreen: return "open_screen";
    case ScanActionKind::ProbeLiveTunnel: return "probe_live_tunnel";
    case ScanActionKind::RequestCandidates: return "request_candidates";
    case ScanActionKind::UserConnectForScan: return "user_connect_for_scan";
    case ScanActionKind::CancelPendingConnect: return "cancel_pending_connect";
    case ScanActionKind::ConnectRow: break;
    }
    return "connect_row";
}

inline bool scanActionTouchesTunnel(ScanActionKind k)
{
    return k == ScanActionKind::UserConnectForScan || k == ScanActionKind::CancelPendingConnect || k == ScanActionKind::ConnectRow;
}

struct ScanAction {
    QString scopeCountry;      // RequestManifest: the scan's country scope ("" = all; the server contract to come)
    int batch = 0;             // RequestManifest: 1 = first scan of a series, 2.. = «Найти ещё» batches
    ScanActionKind kind = ScanActionKind::RequestManifest;
    QString scanId;
    QString networkKey;
    QString nodeId;
    QString profileId;
    bool includeConfig = false;       // RequestProbeBatch: ask the configs (a full probe may follow)
    QString requestId;                // app-side requests: the id appRequestDone reports with its real bytes
    qint64 costBytes = 0;             // app-side requests: the worst case reserved in the scan's allowance
    QStringList ids;                  // ConnectRow: the attempt order; RequestProbeBatch / ReleaseProbeLeases: candidate ids
    QStringList baseIps;              // StartHostScan: probe.base_ips (IP literals, <= 8; empty = the host resolves)
    qint64 hintTtlMs = 0;
    QList<ScanCandidate> candidates;  // StartHostScan / AddHostCandidates
    ScanHostLimits limits;
    qint64 deadlineMs = 0;
    qint64 maxBytes = -1;
    int warmBytes = 0;
    int bytes = 0;
    ShadeRequest shade;
    QList<ScanOutcomeItem> outcomes;
    ScanCachedResult cached;
    QJsonArray ledger;
    bool withConnection = false;
    bool userOrigin = false;          // ConnectRow: always true (a user tap)
    bool forceConnect = false;        // ConnectRow: always true (connect even when the VPN is off)
    QString reportId;                 // StartReportCheck: the immutable report's id (the support queue acks it)
    QJsonObject report;               // StartReportCheck: {id, created_at_ms, with_connection, network_key, scan}
    QString reason;
};

struct ScanStep {
    QVector<ScanAction> actions;
    qint64 wakeAtMs = -1;

    const ScanAction *find(ScanActionKind k) const
    {
        for (const ScanAction &a : actions)
            if (a.kind == k)
                return &a;
        return nullptr;
    }
    bool has(ScanActionKind k) const { return find(k) != nullptr; }
    int count(ScanActionKind k) const
    {
        int n = 0;
        for (const ScanAction &a : actions)
            n += a.kind == k ? 1 : 0;
        return n;
    }
};

// Server cap of one probe-batch and one batch release (UPSTREAM_PROBE_BATCH_MAX, default 12).
inline constexpr int kScanProbeBatchMax = 12;
// Two manifest requests from the scan buttons («Повторить», «Подключиться и проверить») at least this far
// apart: a press inside it does nothing (no countdown is shown; the button stays enabled). Compiled, not a
// server number. It only matters for scans that armed no cooldown (they never reached a host).
inline constexpr qint64 kScanManifestBackoffMs = 1000;
// R7 (device round 4): a past result is shown beside a fresh scan only while it can still say something about the
// network now - at most 30 min old («Проверено 114 мин назад» opened the screen with stale rows); older -> the screen
// shows the fresh scan only. Without a running scan the rule is scan_cache_works_ttl_s (10 min).
inline constexpr qint64 kScanCacheShowMaxMs = 30LL * 60 * 1000;

// --- inputs ----------------------------------------------------------------------------------------------------

struct ScanOpen {
    ScanNetwork network;
    ScanCurrent current;
    ScanCachedResult cached;   // the persisted result of this network key (may be absent)
    bool withCheck = false;    // chat run_diag: scan, then run the button's check
    bool connectOnOpen = true; // features.scanner_connect_on_open (scanConnectOnOpenFlag), compiled default true
};

inline constexpr char kScannerConnectOnOpenFlag[] = "scanner_connect_on_open";

// REQ S3 (b) kill switch: the scan-initiated user connect on open; compiled default ON.
inline bool scanConnectOnOpenFlag() { return TuningStore::flag(QLatin1String(kScannerConnectOnOpenFlag), true); }

struct ScanManifestInput {
    ScanManifestView manifest;
    QList<ScanOwnNode> ownNodes;
    QSet<QString> freshFailures;          // engine node ids (network memory), joined with the cached failures
    QString lastKnownGood;                // engine node id of network memory: first inside its tier
    QMap<QString, QString> upstreamNames; // profile_id -> display name
    ScanAccess access;                    // /v1/netinfo before connect, or the NE's netinfo_direct
    QString restrictCountry;
    bool awgMiniEnabled = false;          // features.scanner_awg_mini (ScanPlan.h::scanAwgMiniFlag), default off
    bool awgProbeIpKnown = false;         // the API's IP is known (awg_mini dials it without DNS)
    bool awgAddressKnown = true;          // the device's own tunnel address is known (awg_mini's source)
    QStringList probeBaseIps;             // IP literals of the probe base's host (scan_start probe.base_ips)
    bool strictUnverifiable = false;      // features.upstream_unverifiable_strict: true = no proof by exclusion
    qint64 apiBytes = -1;                 // what the manifest / token requests really transferred (-1 unknown)
    bool ruSplitOn = true;                // the RU split is on: the light checks open RU sites (else they cost 0)
};

enum class ScanFactKind { Server, Services, Sites, Speed };
enum class ScanFactState { Pending, Running, Done, Unknown, Off };

inline const char *scanFactStateName(ScanFactState s)
{
    switch (s) {
    case ScanFactState::Pending: return "pending";
    case ScanFactState::Running: return "running";
    case ScanFactState::Done: return "done";
    case ScanFactState::Unknown: return "unknown";
    case ScanFactState::Off: break;
    }
    return "off";
}

inline bool scanFactFinal(ScanFactState s)
{
    return s == ScanFactState::Done || s == ScanFactState::Unknown || s == ScanFactState::Off;
}

struct ScanLightFact {
    ScanFactKind kind = ScanFactKind::Sites;
    ScanFactState state = ScanFactState::Done;
    QList<int> chips;        // Services: TribeServiceChips states (Telegram, YouTube, Instagram, WhatsApp), -1 unknown
    bool ok = false;         // Sites: «работают» / «не открываются»
    int bars = 0;            // Speed: LoadBars level
    QString word;            // Speed: "comfortable" | "slow"
    bool needsButton = false; // Services: chips did not run in this connection («?», «проверим по кнопке»)
};

enum class ScanReportDelivery { Sent, Queued };

// --- view --------------------------------------------------------------------------------------------------------

enum class ScanStageKey { None, Preparing, Connecting, Reach, Data, Self };
enum class ScanWaitKey { None, RowsAppearHere, SearchingMore };
enum class ScanRowState { Works, Slow, NotVerified, Connecting, Connected, Failed };
enum class ScanCardMode { Hidden, Off, Filling, Filled, Checking, Checked };
enum class ScanCardButton { Hidden, Ready, Disabled, Busy };
enum class ScanBarButton { Stop, Retry, RetryInSeconds, RetryInMinutes, ConnectAndScan };
enum class ScanHint { None, CellularBudgetHour };
enum class ScanEmptyVariant { None, Cellular, Wifi, NoScan };

inline const char *scanStageKeyName(ScanStageKey k)
{
    switch (k) {
    case ScanStageKey::Preparing: return "preparing";
    case ScanStageKey::Connecting: return "connecting";
    case ScanStageKey::Reach: return "reach";
    case ScanStageKey::Data: return "data";
    case ScanStageKey::Self: return "self";
    case ScanStageKey::None: break;
    }
    return "none";
}

inline const char *scanRowStateName(ScanRowState s)
{
    switch (s) {
    case ScanRowState::Works: return "works";
    case ScanRowState::Slow: return "slow";
    case ScanRowState::NotVerified: return "not_verified";
    case ScanRowState::Connecting: return "connecting";
    case ScanRowState::Connected: return "connected";
    case ScanRowState::Failed: break;
    }
    return "failed";
}

inline const char *scanCardModeName(ScanCardMode m)
{
    switch (m) {
    case ScanCardMode::Hidden: return "hidden";
    case ScanCardMode::Off: return "off";
    case ScanCardMode::Filling: return "filling";
    case ScanCardMode::Filled: return "filled";
    case ScanCardMode::Checking: return "checking";
    case ScanCardMode::Checked: break;
    }
    return "checked";
}

inline const char *scanCardButtonName(ScanCardButton b)
{
    switch (b) {
    case ScanCardButton::Hidden: return "hidden";
    case ScanCardButton::Ready: return "ready";
    case ScanCardButton::Disabled: return "disabled";
    case ScanCardButton::Busy: break;
    }
    return "busy";
}

inline const char *scanBarButtonName(ScanBarButton b)
{
    switch (b) {
    case ScanBarButton::Stop: return "stop";
    case ScanBarButton::Retry: return "retry";
    case ScanBarButton::RetryInSeconds: return "retry_in_s";
    case ScanBarButton::ConnectAndScan: return "connect_and_scan";
    case ScanBarButton::RetryInMinutes: break;
    }
    return "retry_in_min";
}

inline const char *scanHintName(ScanHint h)
{
    switch (h) {
    case ScanHint::CellularBudgetHour: return "cellular_budget_hour";
    case ScanHint::None: break;
    }
    return "none";
}

inline const char *scanEmptyVariantName(ScanEmptyVariant v)
{
    switch (v) {
    case ScanEmptyVariant::Cellular: return "cellular";
    case ScanEmptyVariant::Wifi: return "wifi";
    case ScanEmptyVariant::NoScan: return "no_scan";
    case ScanEmptyVariant::None: break;
    }
    return "none";
}

struct ScanRowView {
    QString id;
    ScanOrigin origin = ScanOrigin::Own;
    QString label;
    QString countryCode;
    ScanTransport transport = ScanTransport::Xray;
    QString transportVersion;
    ScanRowState state = ScanRowState::Works;
    ScanSpeed speed = ScanSpeed::None;  // word under the transport badge: fast «быстро», medium «средне»
    int bars = 0;                       // 5 / 3 / 2 / 0 (LoadBars level; failed rows: LoadBars `failed`)
    int ms = -1;                        // -1 = no figure («~N мс» never invented)
    bool fromCache = false;
    bool dimmed = false;                // «Не удалось»
    bool tappable = true;
    bool verifying = false;             // transport badge yellow while connecting
    bool current = false;
    bool verified = true;               // false = a «Не проверено» row
    bool crowdWorks = false;            // «работает у других в вашей сети» (a mark: never order, never verdict)
    quint64 arrival = 0;                // grows with every new fresh row (arrive animation once)
    QString notVerifiedReason;
};

struct ScanFactView {
    ScanFactState state = ScanFactState::Pending;
    QList<int> chips;
    bool ok = false;
    int bars = 0;
    QString word;
    bool needsButton = false;
};

struct ScanCardView {
    ScanCardMode mode = ScanCardMode::Hidden;
    ScanCardButton button = ScanCardButton::Hidden;
    double progress = -1;            // Checking: 0..1
    QString serverLabel;
    QString serverCountry;
    int serverMs = -1;
    ScanFactView server, services, sites, speed;
    bool speedVisible = false;       // the fourth row appears with the button's check only
    bool reportQueueFull = false;    // the support queue is full: the button shows the backpressure notice (F12)
};

struct ScanCountryView {
    QString countryCode;
    int count = 0;
};

struct ScanBarView {
    bool menuVisible = true;
    bool menuEnabled = false;
    QString selected;                // "" = «Все страны»
    QList<ScanCountryView> countries;
    int total = 0;
    ScanBarButton button = ScanBarButton::Stop;
    bool buttonEnabled = true;
    int buttonValue = 0;             // seconds / minutes of the countdown
    ScanHint hint = ScanHint::None;
    QList<ScanCountryView> scopeCountries; // the pool's countries (own nodes + provider profiles), most paths first
    int scopeWhitelist = -1;         // the pool's white-list rows (/v1/scan/pool; -1 = unknown)
    QString scannedScope;            // the country the shown result covers ("" = all)
    QString scope;                   // the scope of the next scan ("" = all)
};

struct ScanEmptyView {
    ScanEmptyVariant variant = ScanEmptyVariant::None;
    QString reason;                  // NoScan: the coordinator's manifest reasons (service_off, service_old,
                                     // service_mismatch, ...), budget, cooldown, vpn_off, network_changed,
                                     // host_<error|detail> (host_no_vpn, host_memory, host_kill_switch, ...);
                                     // Empty: connect_failed (the scan's own connect failed) or ""
    bool reportSending = false;      // «Отправляем отчёт…»
    bool reportLink = false;         // «Отправить отчёт в поддержку» is offered (reportLinkTapped acts): Empty, NoScan,
                                     // and Done with no live connection - no card button then (lab seam S7)
    QString scopeCc;                 // an Empty result of a country scope: that country
};

struct ScanView {
    ScanPhase phase = ScanPhase::Idle;
    bool scanning = false;
    bool hero = false;               // the rings (upper part); false = the compact header indicator
    ScanStageKey stage = ScanStageKey::None;
    int stageCount = 0;
    int stageTotal = 0;
    double progress = 0;             // -1 indeterminate
    ScanWaitKey wait = ScanWaitKey::None;
    int waitSeconds = 0;
    int checkedAgoMin = -1;          // caption «Проверено N мин назад» (0 = «только что»); -1 none
    QList<ScanRowView> rows;         // display order, filter applied
    int verifiedCount = 0;           // fresh verified rows, before the filter (cached rows never count)
    int unverifiedCount = 0;
    ScanCardView card;
    ScanBarView bar;
    ScanEmptyView empty;
    ScanNetKind net = ScanNetKind::Unknown;
    qint64 nextChangeAtMs = -1;      // re-read view() then (countdowns, progress)
    // «Найти ещё» (ScanMachine::moreTapped): a finished scan left candidates of this network without a verdict;
    // false after a batch that found nothing left = «nothing more». batch = 1 for the first scan of a series.
    bool moreAvailable = false;
    int batch = 0;
    QString moreCountry;             // the country of the running / last continuation ("" = whole pool)
    QString moreState;               // view.more.state: available | running | exhausted ("" = none yet)
    QString netRadio;                // view.net_radio: the cellular radio generation ("" = unknown / not cellular)
};

// PathOutcomeItem.probe / DoctorScanRow.probe of a probe kind.
inline const char *scanOutcomeProbeName(ScanProbeKind k)
{
    switch (k) {
    case ScanProbeKind::XrayLeg: return "leg";
    case ScanProbeKind::AwgMini: return "awg_mini";
    case ScanProbeKind::XrayFull: return "full";
    case ScanProbeKind::None: break;
    }
    return "tunnel";
}

// A reason as a summary key: `^[a-z][a-z0-9_]{0,31}$`.
inline QString scanReasonKey(const QString &reason)
{
    QString k;
    for (const QChar c : reason.toLower()) {
        if (k.size() >= 32)
            break;
        if ((c >= QLatin1Char('a') && c <= QLatin1Char('z')) || (!k.isEmpty() && ((c >= QLatin1Char('0') && c <= QLatin1Char('9')) || c == QLatin1Char('_'))))
            k += c;
        else if (!k.isEmpty())
            k += QLatin1Char('_');
    }
    return k.isEmpty() ? QStringLiteral("other") : k;
}

// The reason a probe host's failure gives the screen (NoScan) and the Doctor summary (stop_reason):
// host_<detail> when the host named a cause in its error's "detail" (the desktop service's
// "kill_switch_exemption" -> host_kill_switch), else host_<error>. At most 32 characters.
inline constexpr char kScanHostDetailKillSwitch[] = "kill_switch_exemption";

inline QString scanHostFailureReason(ScanHostError e, const QString &detail = QString())
{
    if (detail == QLatin1String(kScanHostDetailKillSwitch) || detail == QLatin1String("kill_switch"))
        return QStringLiteral("host_kill_switch");
    if (!detail.trimmed().isEmpty())
        return (QStringLiteral("host_") + scanReasonKey(detail)).left(32);
    return QStringLiteral("host_") + QLatin1String(scanHostErrorName(e));
}

// The coordinator reads an app reply in chunks of this size and stops at the first chunk that passes the
// request's reservation (costBytes), so a reported real size is at most the reservation + one chunk + the
// response headers (kScanAppOvershootMaxBytes). The core charges the real size whatever it is.
inline constexpr qint64 kScanAppChunkBytes = 16384;
inline constexpr qint64 kScanAppOvershootMaxBytes = kScanAppChunkBytes + 4096;

// The app's ONE allowance per scan (plan §2.2b, F6): admission is atomic like the host's gate (spent +
// reserved + cost <= max), but a finished request is charged what REALLY went - also above its reservation
// (a reply cut on the wire one chunk late): the excess comes out of the remainder, then out of the hour (the
// ledger gets spent), never dropped; the remainder is never negative.
class ScanAllowance
{
public:
    explicit ScanAllowance(qint64 maxBytes = -1) : m_max(maxBytes) {}

    bool admit(const QString &id, qint64 costBytes)
    {
        const qint64 cost = qMax<qint64>(0, costBytes);
        if (m_open.contains(id))
            return false;
        if (m_max >= 0 && m_spent + m_reserved + cost > m_max)
            return false;
        m_open.insert(id, cost);
        m_reserved += cost;
        return true;
    }

    // The reservation is replaced by the real bytes (>= 0, not clamped to the reservation).
    void finish(const QString &id, qint64 usedBytes)
    {
        const auto it = m_open.constFind(id);
        if (it == m_open.constEnd())
            return;
        m_reserved -= it.value();
        m_open.remove(id);
        m_spent += qMax<qint64>(0, usedBytes);
    }

    void setMaxBytes(qint64 maxBytes) { m_max = maxBytes; }
    qint64 spent() const { return m_spent; }
    qint64 reserved() const { return m_reserved; }
    qint64 maxBytes() const { return m_max; }
    // What is still free (-1 = no cap); 0 once real bytes passed the allowance.
    qint64 left() const { return m_max < 0 ? -1 : qMax<qint64>(0, m_max - m_spent - m_reserved); }
    // Real bytes beyond the allowance (recorded, never dropped).
    qint64 overshoot() const { return m_max < 0 ? 0 : qMax<qint64>(0, m_spent + m_reserved - m_max); }

private:
    qint64 m_max = -1;
    qint64 m_spent = 0;
    qint64 m_reserved = 0;
    QHash<QString, qint64> m_open;
};

// «Найти ещё»: candidates one batch probes (the next untried ones, mixed across tiers; UI spec 18.11).
inline constexpr int kScanMoreBatch = 10;
// The first batch of a scope scan (a country, the white lists): the server's default page.
inline constexpr int kScanScopeFirstBatch = 12;
// The white-list scope (no country): chooseCountry("whitelist"), scanned_scope "whitelist".
inline constexpr char kScanScopeWhitelist[] = "whitelist";

// A scope as the machine keeps it: "" (all), an upper-case country code, or "whitelist".
inline QString scanScopeOf(const QString &raw)
{
    const QString t = raw.trimmed();
    if (t.compare(QLatin1String(kScanScopeWhitelist), Qt::CaseInsensitive) == 0)
        return QLatin1String(kScanScopeWhitelist);
    return t.toUpper();
}

// --- the machine -----------------------------------------------------------------------------------------------

class ScanMachine
{
public:
    explicit ScanMachine(const ScanHostCaps &caps, const ScanTunables &t = ScanTunables()) : m_caps(caps), m_t(t) {}

    void restoreBudget(const QJsonArray &ledger) { m_ledger = ScanBudgetLedger::fromJson(ledger); }
    void setCaps(const ScanHostCaps &caps) { m_caps = caps; }

    // --- screen -----------------------------------------------------------------------------------------------
    ScanStep opened(const ScanOpen &o, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        m_screenOpen = true;
        m_connectOnOpen = o.connectOnOpen;
        m_net.radio = o.network.radio; // display only, never part of the identity
        if (o.network != m_net || m_rowsKey != o.network.key) {
            if (scanPhaseScanning(m_phase))
                applyNetworkChange(o.network, o.cached, now, s); // reopened on another network mid-scan
            else
                adoptNetwork(o.network, o.cached, now);
        }
        setCurrent(o.current, now, s);
        if (o.withCheck)
            m_checkAfterScan = true;
        if (scanPhaseScanning(m_phase)) {
            finishStep(s, now);
            return s;
        }
        // The manual cooldown holds from the last scan START, whether that scan completed or was left (F8).
        if (now < m_cooldownUntil && m_rowsKey == m_net.key) {
            if (m_completed) {
                if (m_checkAfterScan)
                    startReportCheck(s);
            } else {
                if (m_rows.isEmpty())
                    loadCached(o.cached, now);
                toNoScan(QStringLiteral("cooldown"), now, s);
            }
            finishStep(s, now);
            return s;
        }
        beginScan(now, s);
        finishStep(s, now);
        return s;
    }

    ScanStep closed(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (scanPhaseScanning(m_phase))
            cancelScan(now, s);
        m_screenOpen = false;
        finishStep(s, now);
        return s;
    }

    ScanStep stopTapped(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (scanPhaseScanning(m_phase)) {
            cancelScan(now, s);
            m_screenOpen = false;
            s.actions << act(ScanActionKind::CloseScreen);
        }
        finishStep(s, now);
        return s;
    }

    ScanStep retryTapped(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!scanPhaseScanning(m_phase) && now >= m_cooldownUntil && now >= m_lastManifestAt + kScanManifestBackoffMs
            && !budgetBlocked(now).hourly)
            beginScan(now, s);
        finishStep(s, now);
        return s;
    }

    // «Подключиться и проверить» (switch scanner_connect_on_open off): the user's explicit connect-and-scan.
    ScanStep connectAndScanTapped(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!scanPhaseScanning(m_phase) && m_caps.needsVpn && !m_current.working() && now >= m_cooldownUntil
            && now >= m_lastManifestAt + kScanManifestBackoffMs && !budgetBlocked(now).hourly)
            beginScan(now, s, true);
        finishStep(s, now);
        return s;
    }

    ScanStep gotItTapped(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        // The empty result, and «no scan: budget» (the cellular hour is used up) behave the same: close, and
        // on cellular arm the Wi-Fi intent.
        if (m_phase == ScanPhase::Empty || (m_phase == ScanPhase::NoScan && m_noScanReason == QLatin1String("budget"))) {
            if (m_net.kind == ScanNetKind::Cellular) {
                m_wifiIntentUntil = now + qint64(m_t.wifiRescanWindowS) * 1000;
                s.actions << shade(ShadeTone::Info, QStringLiteral("wifi_intent"));
            }
            m_screenOpen = false;
            s.actions << act(ScanActionKind::CloseScreen);
        }
        finishStep(s, now);
        return s;
    }

    // «Найти ещё» (the continuation): the next batch over the whole pool on this network - every candidate this
    // network has not judged yet (a row with a verdict, a failure; «Не проверено» rows are tried again), restricted
    // to one country when `country` is given (a country scan). Rows already found stay fresh; the batch stops at
    // scan_stop_works NEW working rows, scan_stop_ms or the byte budget (unchanged). The manual cooldown does not
    // apply (other candidates). A network that changed since the last scan, or no finished scan yet, runs an
    // ordinary scan (restricted to the country when given). Nothing left: the scan ends at once,
    // nothing_to_probe, and moreAvailable stays false - the «nothing more» signal of the view.
    ScanStep moreTapped(const QString &country, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (scanPhaseScanning(m_phase)) {
            finishStep(s, now);
            return s;
        }
        // The normal rules apply (UI spec 18.11): the manual cooldown and the budget (beginScan) hold a batch too.
        if (now < m_cooldownUntil) {
            finishStep(s, now);
            return s;
        }
        const bool sameNet = m_completed && m_scanNet.key == m_net.key && m_scanNet.generation() == m_net.generation();
        m_continuation = true;
        m_moreKeepRows = sameNet;
        m_moreCountry = country.trimmed().isEmpty() ? m_scope : scanScopeOf(country);
        m_worksBase = sameNet ? freshWorkingCount() : 0;
        if (!sameNet)
            m_shownNet.clear();
        beginScan(now, s);
        finishStep(s, now);
        return s;
    }

    ScanStep filterChosen(const QString &cc, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!scanPhaseScanning(m_phase)) {
            bool present = cc.isEmpty();
            for (const ScanRowView &r : displayRows(now))
                present = present || r.countryCode == cc;
            if (present)
                m_filter = cc;
            // The country is also the SCOPE of the next scan over the whole pool (UI spec 18.11): «Сканировать» /
            // retry() and «Найти ещё» then probe only that country's paths. "" = every country.
            const QString scope = scanScopeOf(cc);
            bool inPool = scope.isEmpty() || (scope == QLatin1String(kScanScopeWhitelist) && m_poolWhitelist > 0);
            for (const ScanCountryView &c : scopeList())
                inPool = inPool || c.countryCode == scope;
            if (inPool || present)
                m_scope = scope;
        }
        finishStep(s, now);
        return s;
    }

    // --- environment ------------------------------------------------------------------------------------------
    ScanStep networkChanged(const ScanNetwork &n, const ScanCachedResult &cached, bool appInFront, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (n != m_net)
            applyNetworkChange(n, cached, now, s);
        m_net.radio = n.radio;
        if (appInFront)
            maybeFireWifiIntent(now, s);
        finishStep(s, now);
        return s;
    }

    ScanStep appForeground(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        maybeFireWifiIntent(now, s);
        finishStep(s, now);
        return s;
    }

    ScanStep vpnState(const ScanCurrent &c, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        setCurrent(c, now, s);
        finishStep(s, now);
        return s;
    }

private:
    // Another strict tuple, kind or key: before anything was measured the scan just targets it; a running
    // scan is cancelled and restarted there; shown results become cache rows of their fingerprint.
    void applyNetworkChange(const ScanNetwork &n, const ScanCachedResult &cached, qint64 now, ScanStep &s)
    {
        if (m_phase == ScanPhase::Connecting || m_phase == ScanPhase::Preparing) {
            // Nothing measured yet: the scan simply targets the new network.
            m_net = n;
            m_scanNet = n;
            m_rowsKey = n.key;
            loadCached(cached, now);
            m_outcomes.begin(n.key);
            m_cur.cellular = n.kind == ScanNetKind::Cellular;
            // A new request inside the same allowance; the old one's real bytes still come back
            // (appRequestDone), else it is charged at its worst case.
            ScanAction mr = act(ScanActionKind::RequestManifest, n.key);
            if (sendApp(QStringLiteral("manifest"), qint64(m_t.costManifestBytes) + m_t.costApiBytes, now, s, mr)) {
                m_manifestReqId = mr.requestId;
                m_lastManifestAt = now;
                s.actions << mr;
            } else {
                m_startedVpn = false;
                toNoScan(QStringLiteral("budget"), now, s);
            }
        } else if (scanPhaseScanning(m_phase)) {
            cancelScan(now, s);
            adoptNetwork(n, cached, now);
            materializeCurrent();
            if (m_screenOpen)
                beginScan(now, s);
        } else {
            const bool rescan = scanRescanOnNetworkChange(m_screenOpen, m_phase, m_noScanReason, m_caps.needsVpn,
                                                          m_current.working() || m_current.live || m_current.connecting);
            adoptNetwork(n, cached, now);
            materializeCurrent();
            if (rescan)
                beginScan(now, s); // its own budget / VPN rules decide (NoScan "budget" = the artboard's frame 22)
            else if (m_screenOpen && m_phase != ScanPhase::Idle)
                toNoScan(QStringLiteral("network_changed"), now, s);
        }
    }

public:
    // --- manifest -----------------------------------------------------------------------------------------------
    ScanStep manifestReady(const ScanManifestInput &m, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        m_manifest = m;
        m_haveManifest = true;
        m_t = ScanTunables::fromNumbers(m.manifest.numbers);
        // Access evidence belongs to this network AND this scan token (net tokens are salted per token, F5):
        // the manifest's facts replace the old ones, also when there are none.
        if (!m_manifestReqId.isEmpty()) {
            const QString id = m_manifestReqId;
            m_manifestReqId.clear();
            const ScanStep d = appRequestDone(id, m.apiBytes, now);
            s.actions << d.actions;
        }
        if (m_phase == ScanPhase::Preparing || m_phase == ScanPhase::Connecting) {
            m_access = m.access;
            m_accessStamp = currentStamp();
        }
        if (m_phase == ScanPhase::Preparing || m_phase == ScanPhase::Connecting)
            m_haveManifestForScan = true;
        if (m_phase == ScanPhase::Preparing) {
            if (wantServerBatch())
                requestCandidates(now, s); // a scope or «Найти ещё»: the server's batch first (1.14.0)
            else
                startHost(now, s);
        }
        finishStep(s, now);
        return s;
    }

    // --- the server's pool and batches (contract 1.14.0) ------------------------------------------------------
    // GET /v1/scan/pool (asked by the coordinator when the screen opens): the scope menu's countries and the
    // white-list rows' count over the whole pool, not only what this device's manifest delivered.
    ScanStep poolReady(const ScanPoolView &p, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        m_poolCountries.clear();
        for (const ScanPoolView::Country &c : p.countries)
            if (c.own + c.provider > 0)
                m_poolCountries << ScanCountryView{c.countryCode, c.own + c.provider};
        std::stable_sort(m_poolCountries.begin(), m_poolCountries.end(),
                         [](const ScanCountryView &a, const ScanCountryView &b) { return a.count > b.count; });
        m_poolWhitelist = p.whitelist;
        finishStep(s, now);
        return s;
    }

    // The batch of POST /v1/scan/candidates: only its rows are probed (the server's order: crowd score first across
    // tiers, then tier and rank), `exhausted` ends «Найти ещё». A stale answer only settles its bytes.
    ScanStep candidatesReady(const QString &requestId, const ScanCandidatesView &c, qint64 apiBytes, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        const bool current = requestId == m_candReqId && m_phase == ScanPhase::Preparing;
        if (requestId == m_candReqId)
            m_candReqId.clear();
        s.actions << appRequestDone(requestId, apiBytes, now).actions;
        if (current) {
            m_serverBatch = ServerBatch::Yes;
            m_fromServer = true;
            m_serverExhausted = c.exhausted;
            m_manifest.manifest.nodes = c.nodes;
            m_manifest.manifest.upstream = c.upstream;
            startHost(now, s);
        }
        finishStep(s, now);
        return s;
    }

    // No batch (an older server: 404 / invalid answer -> this session falls back for good; transport, rate limit ->
    // only this scan): the scan runs over the device's own candidates (the local continuation / scope).
    ScanStep candidatesUnavailable(const QString &requestId, const QString &reason, qint64 apiBytes, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        const bool current = requestId == m_candReqId && m_phase == ScanPhase::Preparing;
        if (requestId == m_candReqId)
            m_candReqId.clear();
        s.actions << appRequestDone(requestId, apiBytes, now).actions;
        if (reason == QLatin1String("scanner_off") || reason == QLatin1String("invalid") || reason == QLatin1String("unsupported"))
            m_serverBatch = ServerBatch::No;
        if (current)
            startHost(now, s);
        finishStep(s, now);
        return s;
    }

    // apiBytes = what the manifest / token requests really transferred when known (e.g. the manifest came,
    // but the desktop host cannot take a scan): replaces their reservation; -1 = unknown (worst case).
    // No host was started: no cooldown is armed - «Повторить» is enabled at once.
    ScanStep manifestUnavailable(const QString &reason, qint64 now, qint64 apiBytes = -1)
    {
        now = clock(now);
        ScanStep s;
        if (m_phase == ScanPhase::Preparing || m_phase == ScanPhase::Connecting) {
            m_startedVpn = false; // the connect (if any) goes on: the VPN stays on
            if (!m_manifestReqId.isEmpty() && apiBytes >= 0) {
                const ScanStep d = appRequestDone(m_manifestReqId, apiBytes, now);
                s.actions << d.actions;
            }
            m_manifestReqId.clear(); // unreported: charged at its worst case when the allowance closes
            toNoScan(reason.isEmpty() ? QStringLiteral("service_off") : reason, now, s);
        }
        finishStep(s, now);
        return s;
    }

    // --- probe host ---------------------------------------------------------------------------------------------
    // The host failed (an error reply, or no host / a broken channel). startAccepted = false ONLY when the
    // host never took the start: the error IS the reply to scan_start, or the start never reached a host -
    // nothing was admitted, the host's charge is 0 and the scan settles at once. Otherwise (default, and
    // whenever this scan's host already answered a poll, a freeze or a cancel) bytes may have moved
    // unreported: the draining rule of the stop applies - the freeze, then the freeze ack's or the final's
    // numbers, else the whole grant after scan_freeze_ack_ms - bounded, with a wake. Either way the ledger
    // entry is written when the scan settles. A scan with nothing measured ends in NoScan host_<error> (any
    // cached rows stay); one with fresh results keeps them (Done).
    // detail = the host error's "detail" when it names a cause (scanHostFailureReason): the screen and the
    // Doctor summary say host_<detail> (host_kill_switch), else host_<error>.
    ScanStep hostFailed(const QString &scanId, ScanHostError e, qint64 now, bool startAccepted = true,
                        const QString &detail = QString())
    {
        now = clock(now);
        ScanStep s;
        const QString why = scanHostFailureReason(e, detail);
        if (Settle *st = settleOf(scanId)) {
            const bool accepted = startAccepted || st->hostSeen;
            if (st->hostStarted && st->stage != HostStage::Settled) {
                if (!accepted) {
                    settleHost(*st, 0, now, s); // the start was refused: nothing was admitted
                    if (st == &m_cur && !m_liveProbeSent)
                        m_cooldownUntil = m_cooldownPrev; // nothing was probed: no cooldown (retry at once)
                }
                else if (st->stage == HostStage::Running)
                    freezeHost(*st, now, s);    // bytes may have moved: the draining rule
            }
        }
        if (scanId == m_scanId && (m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data)) {
            m_hostDone = true;
            if (freshWorkingCount() == 0) { // nothing proven: the host's failure is the result, not «nothing works»
                releaseLeases(s);
                settleUnjudged(false);
                m_stopReason = why;
                recordSummary(displayRows(now), now); // the report says why this scan had no result
                recordScanEnd(now, s);
                toNoScan(why, now, s);
            } else {
                stopStage2(now, why, s);
            }
        }
        finishStep(s, now);
        return s;
    }

    // The coordinator could not build this probe's host config (scanBuildHostCandidates refused it, e.g. an
    // awg_mini session without the device's tunnel address): it never reached the host. «Не проверено» with
    // the builder's reason, its seat goes back, the scan goes on.
    ScanStep candidateRefused(const QString &probeId, const QString &reason, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        bool isFollowUp = false;
        const int i = candIndexForProbe(probeId, &isFollowUp);
        if (i >= 0 && !m_cands.at(i).finalDone && (m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data)) {
            Cand &c = m_cands[i];
            c.inHost = false;
            c.probeDone = true;
            if (c.followUp != FollowUp::None)
                c.followUp = FollowUp::Done;
            if (c.lease == Lease::Granted) {
                releaseIds({c.c.id}, s);
                c.lease = Lease::Done;
            }
            c.finalDone = true;
            const QString r = reason.isEmpty() ? QStringLiteral("config") : reason;
            addUnverified(c.c, r);
            judge(c.c.id, ScanClass::NotVerified, r);
            pumpProviders(now, s);
            if (allFinal() && !hasLeasePending())
                stopStage2(now, QStringLiteral("complete"), s);
        }
        finishStep(s, now);
        return s;
    }

    ScanStep hostProgress(const ScanHostProgress &p, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (Settle *st = settleOf(p.scanId)) {
            st->hostSeen = true;
            st->lastSpent = qMax(st->lastSpent, p.bytesSpent);
            st->lastReserved = qMax<qint64>(0, p.bytesReserved);
            if (st == &m_cur)
                noteAttempts(p, now, s);
            // "final": the host scan is over - nothing in flight, nothing reserved; bytes_spent is its total.
            if (p.finalTotals)
                settleHost(*st, p.bytesSpent, now, s);
            if (st == &m_prev) {
                finishStep(s, now);
                return s;
            }
        }
        if (p.scanId != m_scanId || (m_phase != ScanPhase::Reach && m_phase != ScanPhase::Data)) {
            finishStep(s, now);
            return s;
        }
        m_spent = qMax(m_spent, p.bytesSpent);
        QList<ScanProbeFacts> items = p.items;
        std::stable_sort(items.begin(), items.end(), [](const ScanProbeFacts &a, const ScanProbeFacts &b) { return a.seq < b.seq; });
        bool data = p.phase == QLatin1String("data") || p.phase == QLatin1String("done");
        for (const ScanProbeFacts &f : items) {
            if (f.seq <= m_lastSeq)
                continue;
            m_lastSeq = f.seq;
            bool isFollowUp = false;
            const int i = candIndexForProbe(f.id, &isFollowUp);
            if (i < 0 || m_cands.at(i).finalDone || !m_cands.at(i).inHost)
                continue;
            if (isFollowUp ? m_cands.at(i).followUp != FollowUp::Active : m_cands.at(i).probeDone)
                continue;
            Cand &c = m_cands[i];
            if (f.stage == ScanStage::Reach) {
                if (isFollowUp)
                    continue; // a follow-up has no reach stage
                c.reachDone = true;
                c.reachOk = f.reachOk;
                if (!f.reachOk) {
                    ScanClassifyInput in = classifyInput(c, false);
                    in.reachFailed = true;
                    in.reachError = f.error;
                    onFinal(i, scanClassify(in, m_t), f, ScanOutcomeStage::Reach, false, now, s);
                }
            } else {
                data = true;
                ScanClassifyInput in = classifyInput(c, isFollowUp);
                in.data = f;
                onFinal(i, scanClassify(in, m_t), f, ScanOutcomeStage::Data, isFollowUp, now, s);
            }
        }
        if (data && m_phase == ScanPhase::Reach)
            m_phase = ScanPhase::Data;
        // "complete" = the host's queue is drained; it stays open for scan_add until its deadline, so only
        // the other reasons end the host's side of the scan.
        const bool hostEnded = p.done && !p.reason.isEmpty() && p.reason != QLatin1String("complete");
        if (hostEnded) {
            stopStage2(now, p.reason, s); // freezes a host that ended without its final totals
        } else {
            pumpProviders(now, s);
            checkStop(now, s);
            if (allFinal() && !hasLeasePending())
                stopStage2(now, QStringLiteral("complete"), s);
        }
        finishStep(s, now);
        return s;
    }

    // The acknowledgement of scan_cancel with the scan's final byte total (F7).
    ScanStep hostCancelAck(const QString &scanId, qint64 bytesSpent, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (Settle *st = settleOf(scanId)) {
            st->hostSeen = true;
            if (st->stage == HostStage::AwaitFinal || st->stage == HostStage::AwaitFreeze)
                settleHost(*st, bytesSpent, now, s); // the final total after every probe stopped
        }
        finishStep(s, now);
        return s;
    }

    // The freeze ack (F7): from now on no probe starts; spent + reserved bound what is still to come.
    ScanStep hostFreezeAck(const QString &scanId, qint64 bytesSpent, qint64 bytesReserved, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        Settle *st = settleOf(scanId);
        if (st)
            st->hostSeen = true;
        if (st && st->stage == HostStage::AwaitFreeze) {
            st->freezeSpent = qMax<qint64>(0, bytesSpent);
            st->freezeReserved = qMax<qint64>(0, bytesReserved);
            st->stage = HostStage::AwaitFinal;
            st->deadline = now + m_t.drainMs;
            ScanAction c = act(ScanActionKind::StopHostScan);
            c.scanId = scanId;
            s.actions << c;
        }
        finishStep(s, now);
        return s;
    }

    // The real bytes of an app-side request: they replace its reservation - also when they are MORE (the
    // coordinator cuts a reply on the wire one transport chunk late at most): the ledger records what really
    // went. Reported after its scan's ledger entry (or for a request charged at once outside a scan), only
    // the excess over what was charged is added to the hour; less is never refunded.
    ScanStep appRequestDone(const QString &requestId, qint64 bytes, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        const QString scanId = requestId.section(QLatin1Char('/'), 0, 0);
        Settle *st = settleOf(scanId);
        const auto it = st ? st->app.constFind(requestId) : QHash<QString, qint64>::const_iterator();
        if (st && it != st->app.constEnd()) { // until the ledger entry is written
            st->gate.finish(requestId, bytes < 0 ? it.value() : bytes);
            st->app.remove(requestId);
            st->emitted.remove(requestId);
        } else if (m_charged.contains(requestId)) {
            const Charged c = m_charged.take(requestId);
            if (bytes > c.bytes)
                commitBytes(now, bytes - c.bytes, c.cellular, s);
        }
        finishStep(s, now);
        return s;
    }

    // The support report queue says whether it can take another report (F12): when full no new full check
    // starts; a backpressure notice shows instead; light checks and the scan go on.
    ScanStep reportQueueState(bool full, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        m_reportQueueFull = full;
        finishStep(s, now);
        return s;
    }

    // The answer of ProbeLiveTunnel (F2): the sized /v1/probe through the live tunnel, judged by the same rules
    // as every other row (digest computed on the device, egress class and node / D7 path).
    ScanStep liveProbeResult(const QString &nodeId, const ScanProbeFacts &f, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        const int i = rowIndex(nodeId);
        if (nodeId.isEmpty() || nodeId != m_liveProbeNode || m_liveProbeDone || i < 0 || !m_rows.at(i).fromLive) {
            finishStep(s, now);
            return s;
        }
        m_liveProbeDone = true;
        Row &r = m_rows[i];
        ScanClassifyInput in;
        in.origin = r.origin;
        in.kind = ScanProbeKind::XrayFull;
        in.candidateId = nodeId;
        in.hasReach = true;
        in.data = f;
        in.access = currentAccess();
        const ScanVerdict v = scanClassify(in, m_t);
        if (scanClassWorking(v.cls)) {
            r.liveVerified = true;
            r.base = v.cls;
            r.speed = v.cls == ScanClass::Slow ? ScanSpeed::Slow : v.speed;
            m_liveReasons.remove(nodeId);
        } else {
            m_liveReasons.insert(nodeId, scanReasonKey(QStringLiteral("live_") + v.reason));
        }
        ScanOutcomeItem o;
        const bool up = nodeId.startsWith(QLatin1String("up:"));
        o.kind = up ? QStringLiteral("upstream") : QStringLiteral("node");
        o.id = up ? nodeId.mid(3) : nodeId;
        o.outcome = v.cls;
        o.stage = ScanOutcomeStage::Data;
        o.probe = QStringLiteral("tunnel");
        o.ttfbMs = f.ttfb1Ms;
        o.bytes = f.bytesReceived;
        o.durationMs = f.durationMs;
        o.rttMs = v.ms;
        if (!m_liveReqId.isEmpty()) {
            const ScanStep d = appRequestDone(m_liveReqId, f.spentBytes > 0 ? f.spentBytes : -1, now);
            s.actions << d.actions;
            m_liveReqId.clear();
        }
        if (m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data || m_phase == ScanPhase::Self) {
            m_outcomes.add(o);
            checkStop(now, s);
        } else {
            ScanOutcomeCollector one;
            one.begin(m_net.key);
            if (one.add(o)) {
                ScanAction a = act(ScanActionKind::SendOutcomes, one.networkKey());
                a.outcomes = one.items();
                if (sendApp(QStringLiteral("outcomes"), m_t.costOutcomesBytes, now, s, a))
                    s.actions << a;
            }
        }
        finishStep(s, now);
        return s;
    }

    // One answer item of the scan's probe-batch (the coordinator verifies the signed batch and reports each
    // profile): a grant (its lease id and config stay with the coordinator) or a refusal code. The grant's own
    // `probe` access facts are NOT evidence here (plan §2.11): they belong to a lease-bound token, whose net
    // tokens are salted differently from this scan token's - `access` is accepted and ignored.
    ScanStep probeLeaseGranted(const QString &id, const ScanAccess &access, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        const int i = candIndex(id);
        const bool live = m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data;
        if (i < 0 || !live || m_cands.at(i).lease != Lease::Requested || m_cands.at(i).finalDone) {
            releaseIds({id}, s, !live); // a late or unknown grant: the seat goes back at once
            if (i >= 0 && m_cands.at(i).lease == Lease::Requested)
                m_cands[i].lease = Lease::Done;
        } else {
            Q_UNUSED(access);
            m_cands[i].lease = Lease::Granted;
            pumpProviders(now, s);
        }
        finishStep(s, now);
        return s;
    }

    ScanStep probeLeaseRefused(const QString &id, const QString &code, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        const int i = candIndex(id);
        if (i >= 0 && m_cands.at(i).lease == Lease::Requested) {
            Cand &c = m_cands[i];
            c.lease = Lease::Done;
            c.finalDone = true;
            c.probeDone = true;
            const bool terminal = code == QLatin1String("disabled") || code == QLatin1String("not_entitled")
                                  || code == QLatin1String("over_quota") || code == QLatin1String("lease_gone");
            const QString reason = code.isEmpty() ? QStringLiteral("lease_failed") : code;
            if (terminal) {
                c.dropped = true; // no row; still one candidate of the summary (not verified, its code)
                removeUnverified(c.c.id);
            } else {
                addUnverified(c.c, reason);
            }
            judge(c.c.id, ScanClass::NotVerified, reason);
            if (m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data) {
                pumpProviders(now, s);
                if (allFinal() && !hasLeasePending())
                    stopStage2(now, QStringLiteral("complete"), s);
            }
        }
        finishStep(s, now);
        return s;
    }

    // --- «Ваше подключение» -----------------------------------------------------------------------------------
    ScanStep lightFact(const ScanLightFact &f, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (m_lightActive || m_checking) {
            Fact &x = m_facts[int(f.kind)];
            x.state = f.state;
            x.chips = f.chips;
            x.ok = f.ok;
            x.bars = f.bars;
            x.word = f.word;
            x.needsButton = f.needsButton;
            if (lightFinal())
                m_lightDeadline = -1;
            if (m_phase == ScanPhase::Self && lightFinal())
                finish(now, s);
        }
        finishStep(s, now);
        return s;
    }

    ScanStep checkTapped(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        const ScanCardMode mode = cardMode();
        if ((mode == ScanCardMode::Filled || mode == ScanCardMode::Checked) && m_connectingId.isEmpty())
            startReportCheck(s);
        finishStep(s, now);
        return s;
    }

    // Support's «Проверить подключение и отправить отчёт» (owner 18.11, variant B: the card and its button left the
    // Scanner): the card's full check and report, started from the Support screen - no scan and no Scanner screen
    // needed. With a live connection the stages check it (the view's card turns Checking, its progress is the
    // coordinator's support_check); without one the report goes with the last scan's summary, like the empty
    // state's link. A check or a report already running answers «Проверка уже идёт»; a row's connect in flight -
    // nothing (the attempt decides first). The queue's backpressure is startReportCheck's (report_queue_full).
    ScanStep supportCheckTapped(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!m_connectingId.isEmpty()) {
            // the tapped row's attempt runs: its result first
        } else if (m_checking || m_reportSending) {
            s.actions << shade(ShadeTone::Info, QStringLiteral("report_check_busy"));
        } else {
            startReportCheck(s);
        }
        finishStep(s, now);
        return s;
    }

    // The link «Отправить отчёт в поддержку» (reportLinkOffered): the scan's summary goes to support through the
    // same report flow as the card's button (StartReportCheck without a connection; the queue's reservation and
    // backpressure apply) - also after a scan WITH rows when there is no live connection, so no card button
    // (desktop with the VPN off, lab seam S7: scan results can always reach support).
    ScanStep reportLinkTapped(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!reportLinkOffered()) {
            // nothing: the card's button is the way (a live connection), or a scan runs
        } else if (m_reportQueueFull && !m_reportSending && !m_checking) {
            s.actions << shade(ShadeTone::Warning, QStringLiteral("report_queue_full"));
        } else if (!m_reportSending && !m_checking) {
            m_reportSending = true;
            ScanAction a = act(ScanActionKind::StartReportCheck);
            a.withConnection = false;
            stampReport(a, now);
            s.actions << a;
        }
        finishStep(s, now);
        return s;
    }

    // A check the coordinator started by itself (support chat while the screen shows): mirror it.
    ScanStep reportCheckStarted(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!m_checking && !m_reportSending) {
            if (m_current.working())
                beginChecking();
            else
                m_reportSending = true;
        }
        finishStep(s, now);
        return s;
    }

    ScanStep reportCheckProgress(int step, int total, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (m_checking) {
            m_checkTotal = qMax(1, total);
            m_checkStep = qBound(0, step, m_checkTotal);
        }
        finishStep(s, now);
        return s;
    }

    // The engine could not start or submit the full check (the queue filled up in a race, another diagnostic
    // runs): no report exists, so no «sent» / «will be sent» text - a notice instead (reason "queue_full" or
    // empty: report_queue_full; otherwise report_check_<reason>, e.g. report_check_busy); the card goes back
    // to what it showed before the check; the queue state (reportQueueState) is not touched.
    ScanStep reportCheckRefused(const QString &reportId, const QString &reason, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if ((m_checking || m_reportSending) && (reportId.isEmpty() || reportId == m_reportId)) {
            if (m_checking) {
                m_checking = false;
                for (int k = 0; k < 4; ++k)
                    m_facts[k] = m_factsBeforeCheck[k];
                m_checked = m_checkedBeforeCheck;
            }
            m_reportSending = false;
            const bool full = reason.isEmpty() || reason == QLatin1String("queue_full");
            s.actions << shade(ShadeTone::Warning, full ? QStringLiteral("report_queue_full")
                                                        : QStringLiteral("report_check_") + scanReasonKey(reason).left(18));
        }
        finishStep(s, now);
        return s;
    }

    // reportId = the id of the StartReportCheck's report object (the support queue acked it); empty = the
    // running one.
    ScanStep reportCheckDone(ScanReportDelivery d, qint64 now, const QString &reportId = QString())
    {
        now = clock(now);
        ScanStep s;
        if ((m_checking || m_reportSending) && (reportId.isEmpty() || reportId == m_reportId)) {
            if (m_checking) {
                m_checking = false;
                m_checked = true;
                for (Fact &f : m_facts)
                    if (f.state == ScanFactState::Running || f.state == ScanFactState::Pending)
                        f.state = ScanFactState::Unknown;
            }
            m_reportSending = false;
            if (d == ScanReportDelivery::Sent)
                s.actions << shade(ShadeTone::Success, QStringLiteral("report_sent"));
            else
                s.actions << shade(ShadeTone::Info, QStringLiteral("report_queued"));
        }
        finishStep(s, now);
        return s;
    }

    // --- connect from a row ---------------------------------------------------------------------------------
    ScanStep rowTapped(const QString &id, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        bool found = false;
        for (const ScanRowView &r : displayRows(now))
            if (r.id == id && (m_filter.isEmpty() || r.countryCode == m_filter))
                found = true;
        const bool currentRow = m_current.working() && m_current.nodeId == id;
        if (!found || !m_connectingId.isEmpty() || currentRow || m_tapFailed.contains(id)) {
            finishStep(s, now);
            return s;
        }
        m_connectingId = id; // before the finish below: the tapped row is kept whatever its age
        if (scanPhaseScanning(m_phase)) {
            // The tap stops the scan at once and keeps what it found (artboard `connect`).
            if (m_phase == ScanPhase::Connecting)
                m_startedVpn = false; // the user's tap owns the tunnel now
            if (m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data) {
                freezeHost(now, s);
                m_hostDone = true;
                releaseLeases(s);
            }
            m_lightActive = false;
            m_lightDeadline = -1;
            finishKeeping(now, id, s);
        }
        // The attempt order: the visible rows after the filter, after the tapped one, wrapping.
        const QList<ScanRowView> rows = filteredRows(now);
        int at = -1;
        for (int i = 0; i < rows.size(); ++i)
            if (rows.at(i).id == id)
                at = i;
        QStringList order;
        for (int k = 1; k < rows.size(); ++k) {
            const ScanRowView &r = rows.at((at + k) % rows.size());
            if (r.id == id || m_tapFailed.contains(r.id) || (m_current.working() && r.id == m_current.nodeId))
                continue;
            order << r.id;
        }
        m_connectingId = id;
        m_chainOrder = order;
        m_chainLaterShown = false;
        m_chain.begin(m_net.key);
        ScanAction a = act(ScanActionKind::ConnectRow);
        a.nodeId = id;
        a.ids = order;
        a.hintTtlMs = qint64(m_t.attemptHintTtlS) * 1000;
        a.userOrigin = true;
        a.forceConnect = true;
        s.actions << a;
        finishStep(s, now);
        return s;
    }

    ScanStep connectFailed(const QString &nodeId, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!m_connectingId.isEmpty()) {
            m_tapFailed.insert(nodeId);
            addChainOutcome(nodeId, ScanClass::NoData);
            QString next;
            for (const QString &id : m_chainOrder)
                if (!m_tapFailed.contains(id) && !(m_current.working() && id == m_current.nodeId)) {
                    next = id;
                    break;
                }
            if (!next.isEmpty()) {
                m_connectingId = next;
                s.actions << shade(ShadeTone::Warning, QStringLiteral("connect_failed_next"));
            } else {
                endChain(s, true);
            }
        }
        finishStep(s, now);
        return s;
    }

    // The engine refused the tapped row before it touched the tunnel (device test of 142: the pin failed - the node
    // left the subscription). Nothing was attempted, so nothing is marked failed and no outcome is sent: the row
    // goes back to what it showed and the list takes taps again (before: m_connectingId stayed set, the row read
    // «Подключение…» after reopening and rowTapped ignored every later tap).
    ScanStep connectRefused(const QString &nodeId, qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!m_connectingId.isEmpty() && (nodeId.isEmpty() || nodeId == m_connectingId)) {
            m_connectingId.clear();
            m_chainOrder.clear();
            m_chainLaterShown = false;
            m_chain.begin(m_net.key);
        }
        finishStep(s, now);
        return s;
    }

    // The engine's attempt ended in an error (engine Error) while a tap's chain ran.
    ScanStep attemptEnded(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if (!m_connectingId.isEmpty()) {
            m_tapFailed.insert(m_connectingId);
            addChainOutcome(m_connectingId, ScanClass::NoData);
            endChain(s, true);
        }
        finishStep(s, now);
        return s;
    }

    // --- time -------------------------------------------------------------------------------------------------
    ScanStep tick(qint64 now)
    {
        now = clock(now);
        ScanStep s;
        if ((m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data) && m_deadline >= 0 && now >= m_deadline)
            stopStage2(now, QStringLiteral("deadline"), s);
        for (Settle *st : {&m_cur, &m_prev})
            if (st->open && st->deadline >= 0 && now >= st->deadline)
                settleOnTimeout(*st, now, s);
        if (m_lightDeadline >= 0 && now >= m_lightDeadline) {
            for (int k = 0; k < 3; ++k)
                if (!scanFactFinal(m_facts[k].state))
                    m_facts[k].state = ScanFactState::Unknown;
            m_lightDeadline = -1;
            if (m_phase == ScanPhase::Self)
                finish(now, s);
        }
        finishStep(s, now);
        return s;
    }

    // --- view -------------------------------------------------------------------------------------------------
    ScanView view(qint64 now) const
    {
        now = qMax(now, m_last);
        ScanView v;
        v.phase = m_phase;
        v.scanning = scanPhaseScanning(m_phase);
        v.hero = v.scanning;
        v.net = m_net.kind;
        v.moreAvailable = !v.scanning && m_completed && m_moreAvailable;
        v.batch = m_batch;
        v.moreCountry = m_moreCountry;
        v.moreState = v.scanning ? (m_continuation && m_batch > 1 ? QStringLiteral("running") : QString())
                      : !m_completed  ? QString()
                      : m_moreAvailable ? QStringLiteral("available")
                                        : QStringLiteral("exhausted");
        v.netRadio = m_net.kind == ScanNetKind::Cellular ? m_net.radio : QString();
        v.bar.scopeCountries = scopeList();
        v.bar.scopeWhitelist = m_poolWhitelist;
        v.bar.scannedScope = m_completed || scanPhaseScanning(m_phase) ? m_scannedScope : QString();
        v.bar.scope = m_scope;
        if (m_phase == ScanPhase::Empty)
            v.empty.scopeCc = m_scannedScope;
        const QList<ScanRowView> all = displayRows(now);
        for (const ScanRowView &r : all) {
            if (r.verified && !r.fromCache)
                ++v.verifiedCount; // a cached row is never counted (plan §2.11a)
            else if (!r.verified && !r.current)
                ++v.unverifiedCount; // the unproven live row is neither (F2)
        }
        const QString filter = effectiveFilter(all);
        for (const ScanRowView &r : all)
            if (filter.isEmpty() || r.countryCode == filter)
                v.rows << r;
        // Stage line.
        switch (m_phase) {
        case ScanPhase::Preparing:
            v.stage = ScanStageKey::Preparing;
            break;
        case ScanPhase::Connecting:
            v.stage = ScanStageKey::Connecting;
            v.progress = -1;
            break;
        case ScanPhase::Reach:
            v.stage = ScanStageKey::Reach;
            v.stageTotal = m_cands.size();
            v.stageCount = reachedCount();
            v.progress = v.stageTotal > 0 ? double(v.stageCount) / v.stageTotal : 0;
            break;
        case ScanPhase::Data: {
            v.stage = ScanStageKey::Data;
            v.stageTotal = m_t.stopWorks;
            v.stageCount = qMin(freshWorkingCount(), m_t.stopWorks);
            const double byWorks = double(v.stageCount) / qMax(1, m_t.stopWorks);
            const double byTime = m_s2Start >= 0 ? double(now - m_s2Start) / qMax(1, m_t.stopMs) : 0;
            v.progress = qMin(0.92, qMax(byWorks, byTime));
            break;
        }
        case ScanPhase::Self: {
            v.stage = ScanStageKey::Self;
            int done = 0;
            for (int k = 0; k < 3; ++k)
                done += scanFactFinal(m_facts[k].state) ? 1 : 0;
            v.progress = 0.92 + 0.02 * done;
            break;
        }
        default:
            v.progress = 0;
            break;
        }
        v.card = cardView(now);
        if (v.scanning) {
            if (all.isEmpty() && v.card.mode == ScanCardMode::Hidden)
                v.wait = ScanWaitKey::RowsAppearHere;
            else if (m_phase == ScanPhase::Data && m_deadline >= 0) {
                const int left = int((m_deadline - now + 999) / 1000);
                if (left > 0) {
                    v.wait = ScanWaitKey::SearchingMore;
                    v.waitSeconds = left;
                }
            }
        }
        // Caption.
        qint64 cachedAt = -1;
        for (const Row &r : m_rows)
            if (r.cached && rowShown(r, now))
                cachedAt = qMax(cachedAt, r.cachedAt);
        if (v.scanning)
            v.checkedAgoMin = cachedAt > 0 ? int(qMax<qint64>(0, now - cachedAt) / 60000) : -1;
        else if (m_phase == ScanPhase::Done || m_phase == ScanPhase::Empty)
            v.checkedAgoMin = int(qMax<qint64>(0, now - m_finishedAt) / 60000);
        else if (m_phase == ScanPhase::NoScan && cachedAt > 0)
            v.checkedAgoMin = int(qMax<qint64>(0, now - cachedAt) / 60000);
        // Bottom bar.
        for (const ScanRowView &r : all) {
            bool hit = false;
            for (ScanCountryView &c : v.bar.countries)
                if (c.countryCode == r.countryCode) {
                    ++c.count;
                    hit = true;
                }
            if (!hit)
                v.bar.countries << ScanCountryView{r.countryCode, 1};
        }
        v.bar.total = all.size();
        v.bar.selected = filter;
        const bool cellular = m_net.kind == ScanNetKind::Cellular;
        if (v.scanning) {
            v.bar.menuVisible = true;
            v.bar.menuEnabled = false;
            v.bar.button = ScanBarButton::Stop;
            v.bar.buttonEnabled = true;
        } else {
            v.bar.menuVisible = v.bar.countries.size() >= 2;
            v.bar.menuEnabled = true;
            const ScanBudgetDecision b = budgetBlocked(now);
            if (b.hourly) {
                v.bar.button = ScanBarButton::RetryInMinutes;
                v.bar.buttonEnabled = false;
                v.bar.buttonValue = scanRetryMinutes(b.retryInMs);
                v.bar.hint = ScanHint::CellularBudgetHour;
            } else if (m_phase == ScanPhase::NoScan && m_noScanReason == QLatin1String("vpn_off") && m_caps.needsVpn
                       && !m_current.working() && now >= m_cooldownUntil) {
                v.bar.button = ScanBarButton::ConnectAndScan; // REQ S3 (b) with the switch off
                v.bar.buttonEnabled = true;
            } else if (now < m_cooldownUntil) {
                v.bar.button = ScanBarButton::RetryInSeconds;
                v.bar.buttonEnabled = false;
                v.bar.buttonValue = int((m_cooldownUntil - now + 999) / 1000);
            } else {
                v.bar.button = ScanBarButton::Retry;
                v.bar.buttonEnabled = true;
            }
        }
        // Empty state.
        if (m_phase == ScanPhase::Empty)
            v.empty.variant = cellular ? ScanEmptyVariant::Cellular : ScanEmptyVariant::Wifi;
        else if (m_phase == ScanPhase::NoScan && all.isEmpty())
            v.empty.variant = ScanEmptyVariant::NoScan;
        v.empty.reason = m_phase == ScanPhase::NoScan ? m_noScanReason : m_emptyReason;
        v.empty.reportSending = m_reportSending;
        v.empty.reportLink = reportLinkOffered();
        v.nextChangeAtMs = nextChange(now, v);
        return v;
    }

    // --- introspection (tests, vectors, journal) ----------------------------------------------------------
    ScanPhase phase() const { return m_phase; }
    const ScanHostCaps &caps() const { return m_caps; }
    bool draining() const { return (m_cur.open && m_cur.hostStarted && m_cur.stage != HostStage::Settled) || m_prev.open; }
    qint64 allowanceBytes() const { return m_cur.gate.maxBytes(); }
    qint64 allowanceUsed() const { return m_cur.gate.spent() + m_cur.gate.reserved(); }
    // Real bytes past the allowance (a reply cut one chunk late): recorded in the ledger, never dropped.
    qint64 allowanceOvershoot() const { return m_cur.gate.overshoot(); }
    qint64 hostGrant() const { return m_cur.hostGrant; }
    // Not part of DoctorScanSummary (its schema is closed): seats asked, rows proven by exclusion, the
    // allowance split of the last finished scan.
    QJsonObject lastStats() const { return m_stats; }
    const ScanTunables &tunables() const { return m_t; }
    const QString &scanId() const { return m_scanId; }
    qint64 spentBytes() const { return m_spent; }
    qint64 capBytes() const { return m_cap; }
    qint64 cooldownUntil() const { return m_cooldownUntil; }
    qint64 deadline() const { return m_deadline; }
    bool startedVpn() const { return m_startedVpn; }
    bool screenOpen() const { return m_screenOpen; }
    // The full check / report in flight (Support's action and the card's button share it): running, and the
    // share of the check's stages done (0..1; -1 = a report without a connection, no stages to count).
    bool reportCheckRunning() const { return m_checking || m_reportSending; }
    double reportCheckProgress() const { return m_checking ? double(m_checkStep) / qMax(1, m_checkTotal) : -1.0; }
    qint64 wifiIntentUntil() const { return m_wifiIntentUntil; }
    QString connectingId() const { return m_connectingId; }
    const ScanBudgetLedger &ledger() const { return m_ledger; }
    int outstandingLeases() const
    {
        int n = 0;
        for (const Cand &c : m_cands)
            n += (c.lease == Lease::Requested || c.lease == Lease::Granted) ? 1 : 0;
        return n;
    }
    // Bytes of provider probes handed to the host and still open (what the byte cap is checked against when
    // the next one is added).
    qint64 leaseReservedBytes() const
    {
        qint64 r = 0;
        for (const Cand &c : m_cands)
            if (c.c.needsLease && !c.finalDone && c.busy())
                r += c.followUp == FollowUp::None ? c.c.costBytes : c.fu.costBytes;
        return r;
    }
    int probeBatchesThisScan() const { return m_batches; }
    QStringList scheduledIds() const
    {
        QStringList ids;
        for (const Cand &c : m_cands)
            ids << c.c.id;
        return ids;
    }
    // DoctorScanSummary (openapi 1.7.0) of the last finished scan: the `scan` object of the connection check
    // report. Empty before any finished scan. Checked by the app's own validator (DoctorReport.h scanSummaryValid)
    // in tests/scan_summary_contract_check.cpp.
    QJsonObject lastSummary() const { return m_summary; }

    // Working rows that could be shown now (before the cap): id, tier, cached, forced (live / connecting / failed).
    struct DebugRow {
        QString id;
        int tier = 0;
        bool cached = false;
        bool forced = false;
    };
    QList<DebugRow> debugWorkingRows(qint64 now) const
    {
        QList<DebugRow> out;
        for (const Row &r : m_rows)
            if (scanClassWorking(r.base) && rowShown(r, now))
                out << DebugRow{r.id, r.tier, r.cached,
                                (m_current.working() && r.id == m_current.nodeId) || r.id == m_connectingId || m_tapFailed.contains(r.id)};
        return out;
    }

private:
    enum class Lease { None, Requested, Granted, Done };

    enum class FollowUp { None, Waiting, Active, Done };
    enum class HostStage { Running, AwaitFreeze, AwaitFinal, Settled };

    // ONE allowance for everything a scan transfers (review v2.1 F6): app-side requests are reserved in the
    // gate at their stated worst case before they are sent, the host gets only the rest (its grant, reserved
    // as "host"); every reservation is replaced by what really went when it ends. Nothing is accounted after
    // the fact. The host's share settles through the freeze protocol (F7).
    struct Settle {
        bool open = false;
        QString scanId;
        bool cellular = false;
        ScanAllowance gate;
        QHash<QString, qint64> app;  // app request id -> reserved worst case, until it is done
        QSet<QString> emitted;       // of those, the ones really sent
        bool hostStarted = false;
        qint64 hostGrant = -1;       // -1 = no cap
        HostStage stage = HostStage::Running;
        qint64 deadline = -1;
        qint64 lastSpent = 0;
        qint64 lastReserved = 0;
        qint64 freezeSpent = 0;
        qint64 freezeReserved = 0;
        qint64 hostCharge = 0;
        bool scanEnded = false;
        bool hostSeen = false;       // the host answered for this scan (a poll, a freeze, a cancel): it took the start
    };

    struct Cand {
        ScanCandidate c;          // the scheduled probe (leg, full or awg_mini)
        bool reachDone = false;
        bool reachOk = false;
        bool probeDone = false;   // the scheduled probe has its result
        bool finalDone = false;   // the candidate has its verdict (or was given up)
        bool inHost = false;      // the current probe was handed to the host
        bool dropped = false;
        Lease lease = Lease::None;
        FollowUp followUp = FollowUp::None;
        ScanCandidate fu;         // the full-profile follow-up of a provider leg (D8)
        bool exclusionPending = false; // Unverifiable for lack of access facts: may be proven by exclusion
        ScanVerdict pendingVerdict;
        ScanProbeFacts pendingFacts;

        // The pool the candidate occupies right now.
        ScanProbeKind pool() const { return followUp == FollowUp::None ? c.kind : ScanProbeKind::XrayFull; }
        bool busy() const
        {
            if (followUp == FollowUp::Active)
                return true;
            if (followUp != FollowUp::None)
                return false;
            return !probeDone && inHost;
        }
    };

    struct Row {
        QString id;
        ScanOrigin origin = ScanOrigin::Own;
        QString profileId;
        QString label;
        QString countryCode;
        ScanTransport transport = ScanTransport::Xray;
        QString transportVersion;
        int tier = 0;
        int rank = 0;
        ScanClass base = ScanClass::Works;
        ScanSpeed speed = ScanSpeed::None;
        int sortMs = -1;
        int liveMs = -1;
        bool cached = false;
        qint64 cachedAt = 0;
        bool fromLive = false;
        bool liveVerified = false; // fromLive: the sized download through the live tunnel proved it (F2)
        bool crowdWorks = false;
        QString generation;        // strict local generation of a FRESH row (current evidence, F10)
        QString fingerprint;       // weak local fingerprint of a CACHED row's network
        QString evidence;          // "exclusion" when proven by exclusion (plan v2.2)
        quint64 arrival = 0;
    };

    bool rowVerified(const Row &r) const { return !r.fromLive || r.liveVerified; }

    struct Unverified {
        ScanCandidate c;
        QString reason;
    };

    struct Fact {
        ScanFactState state = ScanFactState::Pending;
        QList<int> chips;
        bool ok = false;
        int bars = 0;
        QString word;
        bool needsButton = false;
    };

    // --- helpers ----------------------------------------------------------------------------------------------
    qint64 clock(qint64 now)
    {
        if (now < m_last)
            now = m_last;
        m_last = now;
        return now;
    }

    ScanAction act(ScanActionKind k, const QString &networkKey = QString()) const
    {
        ScanAction a;
        a.kind = k;
        a.networkKey = networkKey;
        return a;
    }

    ScanAction shade(ShadeTone tone, const QString &key, const QStringList &args = {}) const
    {
        ScanAction a = act(ScanActionKind::ShowShade);
        a.shade.tone = tone;
        a.shade.textKey = key;
        a.shade.args = args;
        return a;
    }



    int candIndex(const QString &id) const
    {
        for (int i = 0; i < m_cands.size(); ++i)
            if (m_cands.at(i).c.id == id)
                return i;
        return -1;
    }

    // A host item id is a probe id: the candidate id, or "<id>#full" for a follow-up.
    int candIndexForProbe(const QString &probeId, bool *followUp) const
    {
        *followUp = probeId.endsWith(QLatin1String("#full"));
        return candIndex(*followUp ? probeId.left(probeId.size() - 5) : probeId);
    }

    int rowIndex(const QString &id) const
    {
        for (int i = 0; i < m_rows.size(); ++i)
            if (m_rows.at(i).id == id)
                return i;
        return -1;
    }

    void finishStep(ScanStep &s, qint64 now) const
    {
        qint64 w = -1;
        const auto take = [&w](qint64 t) {
            if (t >= 0 && (w < 0 || t < w))
                w = t;
        };
        if (m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data)
            take(m_deadline);
        take(m_lightDeadline);
        if (m_cur.open)
            take(m_cur.deadline);
        if (m_prev.open)
            take(m_prev.deadline);
        Q_UNUSED(now);
        s.wakeAtMs = w;
    }

    bool rowShown(const Row &r, qint64 now) const
    {
        if (r.id == m_connectingId || (m_current.working() && r.id == m_current.nodeId))
            return true;
        if (!r.cached)
            return r.generation == m_net.generation(); // current evidence only on its own generation (F10)
        return cachedVisible(r, now);
    }

    // The app side of one scan at its worst cases (plan §2.2b table): manifest + token, probe-batch (without
    // configs) + one release, the live-tunnel probe, the light checks, the outcome batch.
    qint64 appWorstCase() const
    {
        return qint64(m_t.costManifestBytes) + m_t.costApiBytes + m_t.costBatchBytes + m_t.costApiBytes
               + m_t.costTunnelProbeBytes + lightCost() + m_t.costOutcomesBytes;
    }

    qint64 lightCost() const { return m_manifest.ruSplitOn ? m_t.costLightBytes : 0; }

    // The stamp of CURRENT evidence: the strict generation tuple's hash and this scan's token (the scan id).
    QString currentStamp() const { return m_net.generation() + QLatin1Char('|') + m_scanId; }

    ScanBudgetDecision budgetBlocked(qint64 now) const
    {
        if (m_net.kind != ScanNetKind::Cellular && m_manifest.manifest.deviceBytesPerHour <= 0) {
            ScanBudgetDecision d;
            return d;
        }
        const qint64 projection = (m_lastProjection > 0 ? m_lastProjection : 0) + appWorstCase();
        return decideScanBudget(m_ledger, now, m_net.kind, projection, m_manifest.manifest.deviceBytesPerHour, m_t);
    }

    void adoptNetwork(const ScanNetwork &n, const ScanCachedResult &cached, qint64 now)
    {
        m_net = n;
        // Fresh rows of the old generation are no longer current evidence: they stay only as cache rows of
        // their own fingerprint (shown with their age if it matches); unproven live rows go.
        for (int i = m_rows.size() - 1; i >= 0; --i) {
            Row &r = m_rows[i];
            if (r.fromLive && !r.liveVerified) {
                m_rows.removeAt(i);
                continue;
            }
            if (!r.cached) {
                r.cached = true;
                r.cachedAt = m_finishedAt > 0 ? m_finishedAt : now;
                r.fromLive = false;
            }
        }
        m_unverified.clear();
        m_tapFailed.clear();
        m_filter.clear();
        m_completed = false;
        m_cooldownUntil = 0;
        m_rowsKey = n.key;
        m_access = ScanAccess(); // evidence of the old network is never compared again (F5)
        m_cachedFailures = ScanCachedResult();
        loadCached(cached, now);
    }

    void loadCached(const ScanCachedResult &cached, qint64 now)
    {
        Q_UNUSED(now);
        if (!cached.present() || cached.networkKey != m_net.key)
            return;
        m_cachedFailures = cached;
        for (const ScanCachedRow &cr : cached.rows) {
            if (rowIndex(cr.id) >= 0)
                continue;
            Row r;
            r.id = cr.id;
            r.origin = cr.origin;
            r.profileId = cr.profileId;
            r.label = cr.label;
            r.countryCode = cr.countryCode;
            r.transport = cr.transport;
            r.transportVersion = cr.transportVersion;
            r.tier = cr.tier;
            r.rank = cr.rank;
            r.base = cr.cls;
            r.speed = cr.speed;
            r.sortMs = cr.ms;
            r.cached = true;
            r.cachedAt = cached.savedAtMs;
            r.crowdWorks = cr.crowdWorks;
            r.fingerprint = cached.fingerprint;
            m_rows << r;
        }
    }

    // The live connection: its row (materialized from the live tunnel), the connect chain, S1, the card.
    void setCurrent(const ScanCurrent &c, qint64 now, ScanStep &s)
    {
        const ScanCurrent prev = m_current;
        m_current = c;
        materializeCurrent();
        setCurrentRest(prev, c, now, s);
    }

    // The live connection's row: created from the live tunnel (never probed), its ms follows the live ms.
    void materializeCurrent()
    {
        const ScanCurrent &c = m_current;
        if (c.working()) {
            const int i = rowIndex(c.nodeId);
            if (i < 0) {
                Row r;
                r.id = c.nodeId;
                r.origin = c.origin;
                r.profileId = c.origin == ScanOrigin::Upstream && c.nodeId.startsWith(QLatin1String("up:")) ? c.nodeId.mid(3) : QString();
                r.label = c.label;
                r.countryCode = c.countryCode;
                r.transport = c.transport;
                r.transportVersion = c.transportVersion;
                r.tier = c.tier;
                r.base = ScanClass::Works;
                r.speed = scanSpeedOfLive(c.liveRttMs, m_t);
                r.sortMs = c.liveRttMs;
                r.liveMs = c.liveRttMs;
                r.fromLive = true;
                r.liveVerified = false;
                r.generation = m_net.generation();
                r.fingerprint = m_net.fingerprint;
                r.arrival = ++m_arrival;
                for (const Cand &x : m_cands)
                    if (x.c.id == c.nodeId)
                        r.crowdWorks = x.c.crowdWorks;
                m_rows << r;
            } else {
                Row &r = m_rows[i];
                r.liveMs = c.liveRttMs;
                if (r.cached) {
                    r.cached = false;
                    r.fromLive = true;
                    r.liveVerified = false; // a cached verdict is not current evidence
                    r.arrival = ++m_arrival;
                }
                r.generation = m_net.generation();
                r.fingerprint = m_net.fingerprint;
                if (r.fromLive) {
                    if (!r.liveVerified)
                        r.speed = scanSpeedOfLive(c.liveRttMs, m_t);
                    r.sortMs = c.liveRttMs;
                    if (!r.liveVerified)
                        r.base = ScanClass::Works;
                }
            }
        }
    }

    void setCurrentRest(const ScanCurrent &prev, const ScanCurrent &c, qint64 now, ScanStep &s)
    {
        // An AmneziaWG session must never run on the live tunnel's node or a connect attempt's target (the
        // same key there moves the live endpoint): such a candidate leaves the scan at once - the host
        // cancels its sessions before any tunnel change - and is judged by the live tunnel (or stays «Не
        // проверено» without a row). Its late items are ignored.
        for (Cand &x : m_cands)
            if (x.c.kind == ScanProbeKind::AwgMini && !x.finalDone && !x.c.id.isEmpty()
                && (x.c.id == c.nodeId || x.c.id == c.attemptNodeId)) {
                x.finalDone = true;
                x.probeDone = true;
                x.inHost = false;
                judge(x.c.id, ScanClass::NotVerified, QStringLiteral("awg_live"));
            }
        // The tap's chain: the engine moved to another node of the hint.
        if (!m_connectingId.isEmpty()) {
            if (c.connecting && c.nodeId != m_connectingId && m_chainOrder.contains(c.nodeId) && !m_tapFailed.contains(c.nodeId))
                m_connectingId = c.nodeId;
            if (c.working() && c.nodeId == m_connectingId) {
                addChainOutcome(c.nodeId, ScanClass::Works);
                m_connectingId.clear();
                endChain(s, false);
            }
        }
        // S1: the pre-connect of a VPN-required host.
        if (m_phase == ScanPhase::Connecting) {
            if (c.working()) {
                m_startedVpn = false; // data passed: from now on the VPN stays on
                if (m_haveManifestForScan)
                    startHost(now, s);
                else
                    m_phase = ScanPhase::Preparing;
            } else if (c.failed && !c.connecting && !c.live) {
                m_startedVpn = false;
                m_emptyReason = QStringLiteral("connect_failed");
                finish(now, s);
            }
        } else if ((m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data) && m_caps.needsVpn && !c.live) {
            // The host lives in the tunnel: it is gone, maybe with bytes it never reported - the draining
            // rule (the freeze goes unanswered: the whole grant after scan_freeze_ack_ms).
            stopStage2(now, QStringLiteral("tunnel_stopped"), s);
        }
        // The card follows the live connection.
        if (!c.working()) {
            if (prev.working()) {
                m_lightActive = false;
                m_lightDeadline = -1;
                m_lightNode.clear();
                if (m_phase == ScanPhase::Self)
                    finish(now, s);
            }
        } else if (c.nodeId != m_lightNode && !m_checking
                   && (m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data || m_phase == ScanPhase::Self
                       || m_phase == ScanPhase::Done || m_phase == ScanPhase::Empty || m_phase == ScanPhase::NoScan)) {
            startLight(now, s);
        }
        if (c.working() && m_phase != ScanPhase::Idle && m_phase != ScanPhase::Preparing && m_phase != ScanPhase::Connecting)
            maybeProbeLive(s);
    }

    // The connected row is «works» only after a sized, digest-checked download through the live tunnel (F2):
    // once per scan and per node, only for a row no scan probe of this scan already proved.
    void maybeProbeLive(ScanStep &s)
    {
        if (!m_current.working())
            return;
        const int i = rowIndex(m_current.nodeId);
        if (i < 0 || !m_rows.at(i).fromLive || m_rows.at(i).liveVerified)
            return;
        if (m_liveProbeNode == m_current.nodeId)
            return;
        m_liveProbeNode = m_current.nodeId;
        m_liveProbeDone = false;
        ScanAction a = act(ScanActionKind::ProbeLiveTunnel);
        a.nodeId = m_current.nodeId;
        a.warmBytes = m_t.warmBytes;
        a.bytes = m_t.stage2Bytes;
        if (!sendApp(QStringLiteral("live"), m_t.costTunnelProbeBytes, m_last, s, a)) {
            m_liveProbeDone = true; // no room in the allowance: the row stays «Подключено», unproven
            m_liveReasons.insert(m_current.nodeId, QStringLiteral("live_budget"));
            return;
        }
        m_liveReqId = a.requestId;
        s.actions << a;
        m_liveProbeSent = true;
        armCooldown(); // probe bytes through the live tunnel
    }

    // The manual cooldown runs scan_manual_cooldown_s from this scan's START (plan §1.2), armed only by a scan
    // that reached a host (StartHostScan; a refused start disarms it) or sent the live-tunnel probe.
    void armCooldown()
    {
        m_cooldownUntil = qMax(m_cooldownUntil, m_scanStartAt + qint64(m_t.manualCooldownS) * 1000);
    }

    // The report the support queue gets: an immutable object with its own id (review F12).
    void stampReport(ScanAction &a, qint64 now)
    {
        m_reportId = QStringLiteral("report-%1-%2").arg(now).arg(++m_reportSerial);
        a.reportId = m_reportId;
        a.report = QJsonObject{{QStringLiteral("id"), m_reportId},
                               {QStringLiteral("created_at_ms"), double(now)},
                               {QStringLiteral("with_connection"), a.withConnection},
                               {QStringLiteral("network_key"), scanNetworkKeyValid(m_net.key) ? m_net.key : QStringLiteral("unknown")},
                               {QStringLiteral("scan"), m_summary.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(m_summary)},
                               {QStringLiteral("scan_stats"), m_stats.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(m_stats)}};
    }

    void startLight(qint64 now, ScanStep &s)
    {
        if (!m_current.working())
            return;
        m_lightNode = m_current.nodeId;
        m_lightActive = true;
        m_checked = false;
        for (Fact &f : m_facts)
            f = Fact();
        m_facts[int(ScanFactKind::Server)].state = ScanFactState::Done; // name + live ms: known at once
        m_facts[int(ScanFactKind::Services)].state = ScanFactState::Running;
        m_facts[int(ScanFactKind::Sites)].state = ScanFactState::Running;
        m_lightDeadline = now + m_t.lightTimeoutMs;
        ScanAction a = act(ScanActionKind::StartLightChecks);
        a.nodeId = m_current.nodeId;
        if (!sendApp(QStringLiteral("light"), lightCost(), now, s, a)) {
            // No room in the allowance: the light facts are unknown («проверим по кнопке»).
            m_facts[int(ScanFactKind::Services)].state = ScanFactState::Unknown;
            m_facts[int(ScanFactKind::Services)].needsButton = true;
            m_facts[int(ScanFactKind::Sites)].state = ScanFactState::Unknown;
            m_lightDeadline = -1;
            return;
        }
        s.actions << a;
    }

    bool lightFinal() const
    {
        for (int k = 0; k < 3; ++k)
            if (!scanFactFinal(m_facts[k].state))
                return false;
        return true;
    }

    void beginChecking()
    {
        for (int k = 0; k < 4; ++k)
            m_factsBeforeCheck[k] = m_facts[k];
        m_checkedBeforeCheck = m_checked;
        m_checking = true;
        m_checked = false;
        m_checkStep = 0;
        m_checkTotal = 4;
        for (int k = 0; k < 4; ++k) {
            m_facts[k].state = ScanFactState::Running;
            m_facts[k].needsButton = false;
        }
    }

    void startReportCheck(ScanStep &s)
    {
        m_checkAfterScan = false;
        if (m_reportQueueFull) {
            // F12: the queue never drops a report; when it is full no new full check starts.
            s.actions << shade(ShadeTone::Warning, QStringLiteral("report_queue_full"));
            return;
        }
        ScanAction a = act(ScanActionKind::StartReportCheck);
        a.withConnection = m_current.working();
        if (a.withConnection) {
            if (m_checking)
                return;
            beginChecking();
        } else {
            if (m_reportSending)
                return;
            m_reportSending = true;
        }
        stampReport(a, m_last);
        s.actions << a;
    }

    void beginScan(qint64 now, ScanStep &s, bool userPressedConnect = false)
    {
        // Budget pre-check with the last projection (no manifest fetch on a blocked cellular hour).
        const ScanBudgetDecision pre = budgetBlocked(now);
        if (pre.hourly) {
            toNoScan(QStringLiteral("budget"), now, s);
            return;
        }
        // REQ S3 (b): with the switch off a VPN-required host waits for «Подключиться и проверить».
        if (m_caps.needsVpn && !m_current.working() && !m_current.live && !m_current.connecting && !m_connectOnOpen
            && !userPressedConnect) {
            toNoScan(QStringLiteral("vpn_off"), now, s);
            return;
        }
        // The previous scan's allowance: still settling -> it moves aside (an older one is forced now).
        if (m_prev.open) {
            m_prev.scanEnded = true;
            settleOnTimeout(m_prev, now, s);
            tryCommit(m_prev, now, s);
            m_prev = Settle();
        }
        if (m_cur.open) {
            closeScanBudget(now, s);
            tryCommit(m_cur, now, s);
            if (m_cur.open)
                m_prev = m_cur;
        }
        ++m_serial;
        m_scanId = QStringLiteral("scan-%1-%2").arg(now).arg(m_serial);
        m_cur = Settle();
        m_cur.open = true;
        m_cur.scanId = m_scanId;
        m_cur.cellular = m_net.kind == ScanNetKind::Cellular;
        m_cur.gate = ScanAllowance(pre.capBytes); // the scan's ONE allowance (F6)
        m_opening = ScanAccessAttempt();
        m_openingStamp.clear();
        m_accessStamp.clear();
        m_exclusionDone = false;
        m_exclusionWhy.clear();
        m_seatsRequested = 0;
        m_exclusionRows = 0;
        // The manual cooldown is armed only once this scan reaches a host or sends the live probe
        // (armCooldown); a scan that ends before (no host, refused start, manifest unavailable, budget)
        // leaves «Повторить» enabled at once.
        m_cooldownPrev = m_cooldownUntil;
        m_liveProbeSent = false;
        m_access = ScanAccess();     // fresh evidence per scan token (F5)
        m_releaseDeferred.clear();
        m_appSideOnly = false;
        m_liveProbeNode.clear();
        m_liveProbeDone = false;
        // Light checks run again with every scan, also on the same connection (S8, F9).
        m_lightActive = false;
        m_lightNode.clear();
        m_lightDeadline = -1;
        if (!m_checking) {
            m_checked = false;
            for (Fact &f : m_facts)
                f = Fact();
        }
        m_scanNet = m_net;
        m_completed = false;
        // «Найти ещё» (moreTapped): a continuation keeps this network's rows fresh and its judged set; any other
        // scan starts a new series.
        const bool keepRows = m_continuation && m_moreKeepRows;
        if (!m_continuation) {
            m_shownNet.clear();
            m_batch = 0;
            m_moreCountry.clear();
            m_worksBase = 0;
        }
        ++m_batch;
        m_moreAvailable = false;
        m_cands.clear();
        m_unverified.clear();
        m_tapFailed.clear();
        m_scannedScope = m_continuation ? m_moreCountry : m_scope;
        m_fromServer = false;
        m_serverExhausted = false;
        m_candReqId.clear();
        m_filter = m_scannedScope;
        m_planRemaining = 0;
        m_lastSeq = 0;
        m_spent = 0;
        m_cap = -1;
        m_hostStarted = false;
        m_hostDone = false;
        m_haveManifestForScan = false;
        m_s2Start = -1;
        m_deadline = -1;
        m_emptyReason.clear();
        m_noScanReason.clear();
        if (!keepRows)
            m_failuresThisScan.clear();
        m_verdicts.clear();
        m_nvReasonOf.clear();
        m_liveReasons.clear();
        m_batches = 0;
        m_batchConfig = false;
        m_planCandidates = 0;
        m_scanStartAt = now;
        m_outcomes.begin(m_net.key);
        // Rows of the previous result become cached rows of this network (a continuation keeps them fresh: same
        // network, same generation - the rows of the batches before stay this series' evidence).
        for (int i = keepRows ? -1 : m_rows.size() - 1; i >= 0; --i) {
            Row &r = m_rows[i];
            if (m_current.working() && r.id == m_current.nodeId) {
                // The live connection is live evidence, never a cached row; its proof is redone per scan (F2).
                r.cached = false;
                r.fromLive = true;
                r.liveVerified = false;
                r.base = ScanClass::Works;
                r.speed = scanSpeedOfLive(m_current.liveRttMs, m_t);
                r.sortMs = m_current.liveRttMs;
                continue;
            }
            if (!r.cached) {
                r.cached = true;
                r.cachedAt = m_finishedAt > 0 ? m_finishedAt : now;
            }
            if (!rowShownAt(r, now))
                m_rows.removeAt(i);
        }
        if (m_caps.needsVpn && !m_current.working()) {
            m_phase = ScanPhase::Connecting;
            if (!m_current.live && !m_current.connecting) {
                m_startedVpn = true;
                s.actions << act(ScanActionKind::UserConnectForScan);
            } else {
                m_startedVpn = false;
            }
        } else {
            m_phase = ScanPhase::Preparing;
        }
        // Manifest + scan token: reserved at their worst case (a full manifest and one small request); the real
        // bytes come back with manifestReady, before the host's grant is cut (plan §2.2b step 2a).
        ScanAction mr = act(ScanActionKind::RequestManifest, m_net.key);
        // The server's side of the scope and the continuation (being designed: manifest?country=XX beyond the 24/12
        // caps, a continuation batch with an exhausted flag): carried with the request so the manifest client can
        // pass them once the contract lands; today the batch runs over what the device already has.
        mr.scopeCountry = m_scannedScope;
        mr.batch = m_batch;
        if (!sendApp(QStringLiteral("manifest"), qint64(m_t.costManifestBytes) + m_t.costApiBytes, now, s, mr)) {
            m_startedVpn = false;
            toNoScan(QStringLiteral("budget"), now, s);
            return;
        }
        m_manifestReqId = mr.requestId;
        m_lastManifestAt = now;
        s.actions << mr;
        m_haveManifestForScan = false;
    }

    bool rowShownAt(const Row &r, qint64 now) const
    {
        const qint64 age = now - r.cachedAt;
        return !r.fingerprint.isEmpty() && r.fingerprint == m_net.fingerprint && age >= -60000 && age <= kScanCacheShowMaxMs;
    }

    // A cached row (always drawn as cache with its age, never counted as verified): only on the same weak
    // fingerprint; while a scan runs up to kScanCacheShowMaxMs old (the history under «Подключаемся…», fig.
    // 18), otherwise - the result when no scan can run - within scan_cache_works_ttl_s.
    bool cachedVisible(const Row &r, qint64 now) const
    {
        if (!rowShownAt(r, now))
            return false;
        return scanPhaseScanning(m_phase) || now - r.cachedAt <= qint64(m_t.cacheWorksTtlS) * 1000;
    }

    void startHost(qint64 now, ScanStep &s)
    {
        ScanPlanInput in;
        in.manifest = m_manifest.manifest;
        in.ownNodes = m_manifest.ownNodes;
        in.current = m_current;
        in.caps = m_caps;
        in.net = m_scanNet.kind;
        in.tunables = m_t;
        in.freshFailures = m_manifest.freshFailures + scanFreshFailures(m_cachedFailures, now, m_t.cacheFailTtlS);
        // the pool's countries (the scope menu): every country a scan here could probe, before any restriction
        {
            ScanPlanInput all = in;
            all.restrictCountry.clear();
            m_scopeCountries.clear();
            const ScanPlan whole = buildScanPlan(all);
            for (const QList<ScanCandidate> *list : {&whole.probe, &whole.orderOnly})
                for (const ScanCandidate &c : *list) {
                    if (c.countryCode.isEmpty())
                        continue;
                    bool hit = false;
                    for (ScanCountryView &x : m_scopeCountries)
                        if (x.countryCode == c.countryCode) {
                            ++x.count;
                            hit = true;
                        }
                    if (!hit)
                        m_scopeCountries << ScanCountryView{c.countryCode, 1};
                }
            std::stable_sort(m_scopeCountries.begin(), m_scopeCountries.end(),
                             [](const ScanCountryView &a, const ScanCountryView &b) { return a.count > b.count; });
        }
        const bool whitelistScope = m_scannedScope == QLatin1String(kScanScopeWhitelist);
        in.restrictCountry = whitelistScope ? QString() : !m_scannedScope.isEmpty() ? m_scannedScope : m_manifest.restrictCountry;
        in.onlyWhitelist = whitelistScope;
        if (m_continuation && m_moreKeepRows)
            in.skip = m_shownNet;
        if (m_fromServer) {
            in.scoreOrder = true; // the server's batch: its order, all its rows (the server sized it)
        } else if (m_continuation) {
            in.maxProbe = kScanMoreBatch; // the next 10 untried, mixed across tiers (UI spec 18.11)
            in.interleave = true;
        }
        in.upstreamNames = m_manifest.upstreamNames;
        in.lastKnownGood = m_manifest.lastKnownGood;
        in.awgMiniEnabled = m_manifest.awgMiniEnabled;
        in.awgProbeIpKnown = m_manifest.awgProbeIpKnown;
        in.awgAddressKnown = m_manifest.awgAddressKnown;
        const ScanPlan plan = buildScanPlan(in);
        m_planRemaining = m_fromServer ? (m_serverExhausted ? 0 : 1) : plan.remaining;
        m_planCandidates = plan.probe.size() + plan.orderOnly.size();
        m_manifestRevision = m_manifest.manifest.upstreamRevision;
        m_lastProjection = plan.projectedBytes;
        const qint64 attempts = 2 * qint64(m_t.costNetinfoBytes); // the host's opening + closing access attempts
        const ScanBudgetDecision b = decideScanBudget(m_ledger, now, m_scanNet.kind, plan.projectedBytes + appWorstCase() + attempts,
                                                      m_manifest.manifest.deviceBytesPerHour, m_t);
        if (!b.allowed) {
            m_startedVpn = false;
            toNoScan(QStringLiteral("budget"), now, s);
            return;
        }
        // The allowance with the manifest's numbers (plan §2.2b step 1): A = min(scan_budget_scan_bytes, the
        // rolling hour) on cellular, the device budget where named, else none.
        m_cur.gate.setMaxBytes(b.capBytes);
        m_cap = -1;
        m_fullConc = plan.fullConcurrency;
        m_legConc = plan.legConcurrency;
        m_awgConc = plan.awgConcurrency;
        for (const ScanCandidate &c : plan.probe) {
            Cand x;
            x.c = c;
            m_cands << x;
        }
        for (const ScanCandidate &c : plan.orderOnly)
            addUnverified(c, c.notVerifiedReason);
        // F6 (plan §2.2b step 2b): the app side of this scan is reserved at its worst case BEFORE the host's
        // grant is cut - the live-tunnel probe, the light checks, the outcome batch, then the probe-batch
        // (configs only on Wi-Fi) and one release (no room: the providers stay «Не проверено»). The host gets
        // the rest.
        if (m_current.working()) {
            reserveApp(QStringLiteral("live"), m_t.costTunnelProbeBytes);
            reserveApp(QStringLiteral("light"), lightCost());
        }
        reserveApp(QStringLiteral("outcomes"), m_t.costOutcomesBytes);
        const BatchPick pick = pickBatch();
        bool batchReserved = false;
        if (pick.seats > 0) {
            batchReserved = reserveApp(QStringLiteral("batch"), pick.costBytes);
            if (!batchReserved && pick.includeConfig) {
                // No room for the configs: ask without them (full-kind providers cannot be probed then).
                dropFromBatch([](const Cand &c) { return c.c.kind == ScanProbeKind::XrayFull; }, "budget");
                m_batchConfig = false;
                batchReserved = reserveApp(QStringLiteral("batch"), m_t.costBatchBytes);
            }
            if (batchReserved && !reserveApp(QStringLiteral("release"), m_t.costApiBytes)) {
                unreserveApp(QStringLiteral("batch"));
                batchReserved = false;
            }
            if (!batchReserved)
                dropFromBatch([](const Cand &) { return true; }, "budget");
        }
        qint64 grant = hostGrantNow();
        if (grant >= 0 && grant < cheapestCost(true) && batchReserved) {
            // The batch's reservation leaves the host less than one probe: the own candidates go first.
            unreserveApp(QStringLiteral("batch"));
            unreserveApp(QStringLiteral("release"));
            batchReserved = false;
            dropFromBatch([](const Cand &) { return true; }, "budget");
            grant = hostGrantNow();
        }
        const qint64 cheapest = cheapestCost(false);
        m_appSideOnly = grant >= 0 && cheapest >= 0 && grant < cheapest;
        m_cap = grant;
        if (m_appSideOnly) {
            // The host's share cannot carry one probe: the scan runs app side only (plan §2.2b step 3, S11).
            for (Cand &c : m_cands)
                if (!c.finalDone) {
                    markNotVerified(c, "budget");
                    c.lease = Lease::None;
                }
            unreserveApp(QStringLiteral("batch"));
            unreserveApp(QStringLiteral("release"));
            batchReserved = false;
            s.actions << shade(ShadeTone::Warning, QStringLiteral("scan_budget"));
        } else if (batchReserved) {
            cutBatchByGrant(grant);
        }
        m_s2Start = now;
        m_deadline = now + m_t.stopMs;
        m_phase = ScanPhase::Reach;
        if (m_current.working() && m_lightNode != m_current.nodeId)
            startLight(now, s);
        maybeProbeLive(s);
        bool anyHost = false;
        for (const Cand &c : m_cands)
            anyHost = anyHost || (!c.finalDone && (!c.c.needsLease || c.lease == Lease::Requested));
        if (!anyHost) {
            m_hostDone = true;
            stopStage2(now, m_appSideOnly ? QStringLiteral("budget") : QStringLiteral("nothing_to_probe"), s);
            return;
        }
        ScanAction a = act(ScanActionKind::StartHostScan);
        a.scanId = m_scanId;
        for (Cand &c : m_cands)
            if (!c.c.needsLease && !c.finalDone) {
                c.inHost = true;
                a.candidates << c.c;
            }
        a.limits = scanHostLimitsFrom(m_t, m_fullConc, m_legConc, m_awgConc);
        a.deadlineMs = m_t.stopMs + kScanHostDeadlineGraceMs;
        if (grant >= 0)
            m_cur.gate.admit(QStringLiteral("host"), grant);
        m_cur.hostStarted = true;
        m_cur.hostGrant = grant;
        a.maxBytes = grant;
        for (const QString &ip : m_manifest.probeBaseIps)
            if (scanIsIpLiteral(ip) && !a.baseIps.contains(ip) && a.baseIps.size() < kScanProbeBaseIpsMax)
                a.baseIps << ip;
        a.warmBytes = m_t.warmBytes;
        a.bytes = int(qMin<qint64>(m_t.stage2Bytes, m_manifest.manifest.probeMaxBytes > 0 ? m_manifest.manifest.probeMaxBytes : m_t.stage2Bytes));
        s.actions << a;
        m_hostStarted = true;
        armCooldown(); // the host got a start
        if (batchReserved)
            emitBatch(s);
        checkStop(now, s);
    }

    // What the host may still get: the allowance minus everything the app side spent or holds (-1 = no cap).
    qint64 hostGrantNow() const
    {
        return m_cur.gate.left();
    }

    // The cheapest probe the host could run (own candidates only, or every candidate still in the scan).
    qint64 cheapestCost(bool ownOnly) const
    {
        qint64 cheapest = -1;
        for (const Cand &c : m_cands) {
            if (c.finalDone || (ownOnly && c.c.needsLease))
                continue;
            if (c.c.needsLease && c.lease != Lease::Requested)
                continue;
            if (cheapest < 0 || c.c.costBytes < cheapest)
                cheapest = c.c.costBytes;
        }
        return cheapest;
    }

    void markNotVerified(Cand &c, const char *why)
    {
        c.finalDone = c.probeDone = true;
        addUnverified(c.c, QLatin1String(why));
        judge(c.c.id, ScanClass::NotVerified, QLatin1String(why));
    }

    // The candidate's bucket in the Doctor summary (the last word wins: a follow-up, a proof by exclusion).
    void judge(const QString &id, ScanClass cls, const QString &reason = QString())
    {
        m_verdicts.insert(id, cls);
        if (cls == ScanClass::NotVerified)
            m_nvReasonOf.insert(id, scanReasonKey(reason));
        else
            m_nvReasonOf.remove(id);
    }

    // Lab seam S4 (16.11): when the probing of a scan ends (its stop, its finish, a host failure), EVERY planned
    // candidate is in exactly one bucket of the summary, so its counts always sum to its candidates. One without
    // a verdict yet: its «Не проверено» reason when it has one (order-only, a leg waiting for its follow-up, a
    // probe the budget held back); a probe the stop cut in the host "cancelled"; a seat still being asked
    // "lease_pending"; one never handed to the host "not_started" - each eligible for a «Не проверено» row under
    // scan_unverified_rows_max (asRows; not when the scan ends in NoScan: a host that failed before proving
    // anything shows the last result, not the candidates it never judged). No outcome for any of them: unknown is
    // not a failure. Their late host items are ignored (finalDone).
    void settleUnjudged(bool asRows = true)
    {
        for (const Unverified &u : m_unverified)
            if (!m_verdicts.contains(u.c.id))
                judge(u.c.id, ScanClass::NotVerified, u.reason);
        for (Cand &c : m_cands) {
            if (m_verdicts.contains(c.c.id))
                continue;
            const char *why = c.busy() ? "cancelled" : c.lease == Lease::Requested ? "lease_pending" : "not_started";
            c.finalDone = true;
            c.inHost = false;
            if (asRows)
                addUnverified(c.c, QLatin1String(why));
            judge(c.c.id, ScanClass::NotVerified, QLatin1String(why));
        }
    }

    struct BatchPick {
        int seats = 0;          // provider candidates asked for
        bool includeConfig = false;
        qint64 costBytes = 0;   // the worst case of the answer
    };

    // The scan's one probe-batch (plan §2.10, lead decision 2): provider candidates in schedule order, as many
    // as the first provider wave can probe - the slots of the pools they use - never above
    // kScanProbeBatchMax. include_config only on Wi-Fi, when a candidate may need a full probe here; on
    // cellular a full-kind provider is «Не проверено» (config_cellular): its config alone would pass the
    // scan's allowance. The rest is «Не проверено» (batch_cap), never a second batch.
    BatchPick pickBatch()
    {
        BatchPick p;
        const bool cellular = m_scanNet.kind == ScanNetKind::Cellular;
        const bool fullHere = m_fullConc > 0 && m_caps.fullProbe();
        for (Cand &c : m_cands)
            if (c.c.needsLease && cellular && c.c.kind == ScanProbeKind::XrayFull)
                markNotVerified(c, "config_cellular");
        bool anyLeg = false, anyFull = false;
        for (const Cand &c : m_cands) {
            if (!c.c.needsLease || c.finalDone)
                continue;
            anyLeg = anyLeg || c.c.kind == ScanProbeKind::XrayLeg;
            anyFull = anyFull || c.c.kind == ScanProbeKind::XrayFull;
        }
        // A server batch (1.14.0) was sized by the server: every row gets its seat (device 18.11: 10 offered, 6 seated,
        // 4 left «Не проверено»); otherwise the seats follow what can run at once.
        int wanted = 0;
        for (const Cand &c : m_cands)
            wanted += (c.c.needsLease && !c.finalDone) ? 1 : 0;
        const int seats = qMin(kScanProbeBatchMax, m_fromServer ? wanted : (anyLeg ? m_legConc : 0) + (anyFull ? m_fullConc : 0));
        for (Cand &c : m_cands) {
            if (!c.c.needsLease || c.finalDone)
                continue;
            if (p.seats >= seats) {
                markNotVerified(c, "batch_cap");
                continue;
            }
            c.lease = Lease::Requested;
            ++p.seats;
            if (!cellular && (c.c.kind == ScanProbeKind::XrayFull || (c.c.kind == ScanProbeKind::XrayLeg && !c.c.dnsThroughLeg && fullHere)))
                p.includeConfig = true;
        }
        m_batchConfig = p.includeConfig;
        p.costBytes = qint64(m_t.costBatchBytes) + (p.includeConfig ? qint64(p.seats) * m_t.costConfigBytes : 0);
        return p;
    }

    template <typename Pred>
    void dropFromBatch(Pred pred, const char *why)
    {
        for (Cand &c : m_cands)
            if (c.lease == Lease::Requested && pred(c)) {
                c.lease = Lease::None;
                markNotVerified(c, why);
            }
    }

    // Providers asked for must fit the host's grant together with the own candidates' projection.
    void cutBatchByGrant(qint64 grant)
    {
        if (grant < 0)
            return;
        qint64 committed = 0;
        for (const Cand &c : m_cands)
            if (!c.c.needsLease && !c.finalDone)
                committed += c.c.costBytes;
        for (Cand &c : m_cands) {
            if (c.lease != Lease::Requested)
                continue;
            if (committed + c.c.costBytes > grant) {
                c.lease = Lease::None;
                markNotVerified(c, "budget");
                continue;
            }
            committed += c.c.costBytes;
        }
    }

    ScanClassifyInput classifyInput(const Cand &c, bool followUp) const
    {
        const ScanCandidate &x = followUp ? c.fu : c.c;
        ScanClassifyInput in;
        in.origin = x.origin;
        in.kind = x.kind;
        in.candidateId = x.id;
        in.hasReach = x.hasReach();
        in.composite = x.composite;
        in.trimmed = x.trimmed;
        in.dnsThroughLeg = x.dnsThroughLeg;
        in.dnsResolvers = x.dnsResolvers;
        in.access = currentAccess();
        return in;
    }

    // Access facts only when they belong to this generation AND this scan's token (F5/F10).
    ScanAccess currentAccess() const
    {
        return m_accessStamp == currentStamp() && m_scanNet.generation() == m_net.generation() ? m_access : ScanAccess();
    }

    void removeUnverified(const QString &id)
    {
        for (int i = m_unverified.size() - 1; i >= 0; --i)
            if (m_unverified.at(i).c.id == id)
                m_unverified.removeAt(i);
    }

    void addUnverified(const ScanCandidate &c, const QString &reason)
    {
        for (const Unverified &u : m_unverified)
            if (u.c.id == c.id)
                return;
        m_unverified << Unverified{c, reason};
        std::stable_sort(m_unverified.begin(), m_unverified.end(),
                         [](const Unverified &a, const Unverified &b) { return scanCandidateLess(a.c, b.c); });
    }

    void onFinal(int i, const ScanVerdict &v, const ScanProbeFacts &f, ScanOutcomeStage stage, bool isFollowUp,
                 qint64 now, ScanStep &s)
    {
        Cand &c = m_cands[i];
        c.inHost = false;
        if (!isFollowUp) {
            c.probeDone = true;
            // A provider leg that carried the data but whose DNS plan is unproven: a full-profile follow-up
            // decides (D8) when the host can run one and the batch carried the config; it reuses the grant.
            // Until then the row is «Не проверено».
            const bool legUnproven = c.c.kind == ScanProbeKind::XrayLeg && c.c.origin == ScanOrigin::Upstream
                                     && v.cls == ScanClass::NotVerified && v.reason.startsWith(QLatin1String("leg_"));
            if (legUnproven) {
                addUnverified(c.c, v.reason);
                if (m_batchConfig && c.lease == Lease::Granted && m_fullConc > 0 && m_caps.fullProbe()
                    && (!c.c.composite || m_caps.canVerifyComposite)) {
                    c.followUp = FollowUp::Waiting;
                    c.fu = scanFollowUpOf(c.c, m_t);
                    pumpProviders(now, s);
                    return;
                }
            }
        } else {
            c.followUp = FollowUp::Done;
        }
        if (c.lease == Lease::Granted) {
            releaseIds({c.c.id}, s);
            c.lease = Lease::Done;
        }
        c.finalDone = true;
        if (scanClassWorking(v.cls) || scanClassFailure(v.cls))
            removeUnverified(c.c.id);
        if (scanClassWorking(v.cls)) {
            const int ri = rowIndex(c.c.id);
            Row r;
            if (ri >= 0)
                r = m_rows.at(ri);
            r.id = c.c.id;
            r.origin = c.c.origin;
            r.profileId = c.c.profileId;
            r.label = c.c.label;
            r.countryCode = c.c.countryCode;
            r.transport = c.c.transport;
            r.transportVersion = c.c.transportVersion;
            r.tier = c.c.tier;
            r.rank = c.c.rank;
            r.base = v.cls;
            r.speed = v.speed;
            r.sortMs = v.ms;
            r.fromLive = false;
            r.liveVerified = false;
            r.crowdWorks = c.c.crowdWorks;
            r.generation = m_scanNet.generation();
            r.fingerprint = m_scanNet.fingerprint;
            if (r.cached || ri < 0)
                r.arrival = ++m_arrival;
            r.cached = false;
            if (ri >= 0)
                m_rows[ri] = r;
            else
                m_rows << r;
        } else if (scanClassFailure(v.cls)) {
            const int ri = rowIndex(c.c.id);
            if (ri >= 0 && m_rows.at(ri).cached && c.c.id != m_connectingId)
                m_rows.removeAt(ri);
            m_failuresThisScan << ScanCachedFailure{c.c.id, v.cls, m_last};
        } else if (v.exclusionCandidate) {
            // Data proven, path not comparable: «Не проверено» unless the exclusion proof holds at the end.
            c.exclusionPending = true;
            c.pendingVerdict = v;
            c.pendingFacts = f;
            addUnverified(isFollowUp ? c.fu : c.c, QStringLiteral("unverifiable"));
        } else if (f.error == ScanProbeError::Memory || f.error == ScanProbeError::Budget || f.error == ScanProbeError::BindFailed
                   || f.error == ScanProbeError::Cancelled || f.error == ScanProbeError::Deadline) {
            // the host could not run the probe (memory, budget, its own socket binding) or cut it before its
            // verdict (cancelled, deadline): «Не проверено» (unknown is not a failure: no outcome is sent)
            addUnverified(c.c, QLatin1String(scanProbeErrorName(f.error)));
        }
        judge(c.c.id, v.cls, v.reason);
        ScanOutcomeItem o;
        o.kind = c.c.outcomeKind();
        o.id = c.c.outcomeId();
        o.outcome = v.cls;
        o.stage = stage;
        o.probe = QLatin1String(scanOutcomeProbeName(isFollowUp ? ScanProbeKind::XrayFull : c.c.kind));
        if (stage == ScanOutcomeStage::Data) {
            o.ttfbMs = f.ttfb1Ms;
            o.bytes = f.bytesReceived;
            o.durationMs = f.durationMs;
            o.rttMs = v.ms;
        } else {
            o.durationMs = f.reachMs;
        }
        m_outcomes.add(o);
    }

    int freshWorkingCount() const
    {
        int n = 0;
        for (const Row &r : m_rows)
            if (!r.cached && scanClassWorking(r.base) && rowVerified(r))
                ++n;
        return n;
    }

    int reachedCount() const
    {
        int n = 0;
        for (const Cand &c : m_cands)
            n += (c.reachDone || c.probeDone || c.finalDone) ? 1 : 0;
        return n;
    }

    bool allFinal() const
    {
        for (const Cand &c : m_cands)
            if (!c.finalDone)
                return false;
        return true;
    }

    bool hasLeasePending() const
    {
        for (const Cand &c : m_cands)
            if (c.lease == Lease::Requested || c.lease == Lease::Granted)
                return true;
        return false;
    }

    // Stop at scan_stop_works working rows (a continuation counts only its own new ones). The rows are admitted by
    // what the scan itself measured, across tiers (contract 1.14.0 / owner 18.11: tiers order Auto only) - an open
    // candidate of a lower tier no longer holds the stop: the first screen shows what proved fastest now.
    void checkStop(qint64 now, ScanStep &s)
    {
        if ((m_phase != ScanPhase::Reach && m_phase != ScanPhase::Data) || freshWorkingCount() - m_worksBase < m_t.stopWorks)
            return;
        stopStage2(now, QStringLiteral("limit"), s);
    }

    int tierOfRow(const QString &id) const
    {
        const int i = rowIndex(id);
        return i >= 0 ? m_rows.at(i).tier : 0;
    }

    // Working rows per tier among fresh rows (for the list-target rule of lower tiers).
    int workingBelowTier(int tier) const
    {
        int n = 0;
        for (const Row &r : m_rows)
            if (!r.cached && scanClassWorking(r.base) && rowVerified(r) && r.tier < tier)
                ++n;
        return n;
    }

    int poolUse(ScanProbeKind pool) const
    {
        int n = 0;
        for (const Cand &c : m_cands)
            if (!c.finalDone && c.busy() && c.pool() == pool)
                ++n;
        return n;
    }

    int poolConc(ScanProbeKind pool) const
    {
        return pool == ScanProbeKind::XrayLeg ? m_legConc : pool == ScanProbeKind::AwgMini ? m_awgConc : m_fullConc;
    }

    bool anythingInFlight() const
    {
        for (const Cand &c : m_cands)
            if (!c.finalDone && c.busy())
                return true;
        return false;
    }

    // Send the scan's one probe-batch with the candidates pickBatch() kept (its reservation is in place).
    void emitBatch(ScanStep &s)
    {
        ScanAction a = act(ScanActionKind::RequestProbeBatch);
        a.scanId = m_scanId;
        a.includeConfig = m_batchConfig;
        for (const Cand &c : m_cands)
            if (c.lease == Lease::Requested) {
                a.ids << c.c.id;
                a.candidates << c.c;
            }
        if (a.ids.isEmpty()) {
            unreserveApp(QStringLiteral("batch"));
            unreserveApp(QStringLiteral("release"));
            return;
        }
        if (!sendApp(QStringLiteral("batch"), m_t.costBatchBytes, m_last, s, a)) {
            dropFromBatch([](const Cand &) { return true; }, "budget"); // not reached: reserved before
            return;
        }
        ++m_batches;
        m_seatsRequested += a.ids.size();
        s.actions << a;
    }

    // Seats go back as soon as they are not needed (POST .../probe-batch/release, <= 12 ids, one small API
    // request each). A release during the scan is admitted against the allowance; one it cannot admit waits for
    // the scan's FINAL release (finalRelease = true: on every stop), which has its own reservation.
    void releaseIds(const QStringList &ids, ScanStep &s, bool finalRelease = false)
    {
        QStringList all = ids;
        if (finalRelease) {
            all = m_releaseDeferred + ids;
            m_releaseDeferred.clear();
        }
        for (int k = 0; k < all.size(); k += kScanProbeBatchMax) {
            ScanAction r = act(ScanActionKind::ReleaseProbeLeases);
            r.ids = all.mid(k, kScanProbeBatchMax);
            const QString what = finalRelease && k == 0 ? QStringLiteral("release") : QStringLiteral("release_mid");
            if (!sendApp(what, m_t.costApiBytes, m_last, s, r)) {
                if (!finalRelease)
                    m_releaseDeferred << r.ids;
                continue; // after the final one: the seat lapses with its 60 s lease
            }
            s.actions << r;
        }
    }

    // Granted provider probes enter the host when their pool has a slot - own candidates queued in the same
    // pool count as busy, free slots warm lower tiers up (D9); a tier whose lower tiers already fill the list
    // is not probed (its seat goes back); the byte cap is never committed past; a full follow-up reuses the
    // grant while the scan has time for it.
    void pumpProviders(qint64 now, ScanStep &s)
    {
        if (m_phase != ScanPhase::Reach && m_phase != ScanPhase::Data)
            return;
        qint64 reserved = leaseReservedBytes();
        QStringList release;
        ScanAction add = act(ScanActionKind::AddHostCandidates);
        add.scanId = m_scanId;
        for (Cand &c : m_cands) {
            if (c.dropped || c.finalDone || c.lease != Lease::Granted)
                continue;
            const bool initial = !c.inHost && !c.probeDone && c.followUp == FollowUp::None;
            const bool follow = c.followUp == FollowUp::Waiting;
            if (!initial && !follow)
                continue;
            const auto giveUp = [&](bool keepUnverified) {
                c.finalDone = true;
                c.lease = Lease::Done;
                if (c.followUp == FollowUp::Waiting)
                    c.followUp = FollowUp::Done;
                if (!keepUnverified) {
                    removeUnverified(c.c.id);
                    judge(c.c.id, ScanClass::NotVerified, QStringLiteral("list_full")); // no row; one of the summary
                }
                release << c.c.id;
            };
            if (follow && m_deadline >= 0 && m_deadline - now < m_t.followUpMinLeftMs) {
                giveUp(true); // no time left: the leg stays «Не проверено»
                continue;
            }
            if (workingBelowTier(c.c.tier) >= m_t.listTargetWorks) {
                giveUp(false); // could not enter the list (D9)
                continue;
            }
            const ScanProbeKind pool = initial ? c.c.kind : ScanProbeKind::XrayFull;
            const qint64 cost = initial ? c.c.costBytes : c.fu.costBytes;
            if (poolUse(pool) >= poolConc(pool))
                continue;
            if (m_cap >= 0 && m_spent + reserved + cost > m_cap) {
                if (!anythingInFlight()) {
                    if (initial)
                        addUnverified(c.c, QStringLiteral("budget"));
                    giveUp(true);
                }
                continue;
            }
            c.inHost = true;
            if (initial) {
                add.candidates << c.c;
            } else {
                c.followUp = FollowUp::Active;
                add.candidates << c.fu;
            }
            reserved += cost;
        }
        if (!add.candidates.isEmpty())
            s.actions << add;
        releaseIds(release, s);
    }

    void releaseLeases(ScanStep &s)
    {
        QStringList ids;
        for (Cand &c : m_cands)
            if (c.lease == Lease::Granted) {
                ids << c.c.id;
                c.lease = Lease::Done;
            }
        // Requested: a grant that arrives later is released at once (probeLeaseGranted outside a live scan).
        releaseIds(ids, s, true);
    }

    void stopStage2(qint64 now, const QString &reason, ScanStep &s)
    {
        if (m_phase != ScanPhase::Reach && m_phase != ScanPhase::Data)
            return;
        freezeHost(now, s);
        m_hostDone = true;
        releaseLeases(s);
        settleUnjudged(); // what the stop cut in flight is «Не проверено» (cancelled), never a failure
        m_stopReason = reason;
        if (m_current.working() && (!m_lightActive || m_lightNode != m_current.nodeId))
            startLight(now, s);
        if (m_current.working() && !lightFinal()) {
            m_phase = ScanPhase::Self;
            if (m_lightDeadline < 0)
                m_lightDeadline = now + m_t.lightTimeoutMs;
            return;
        }
        finish(now, s);
    }

    // The end of a scan: its outcomes go at once (against their reservation); the app side of the allowance
    // closes; the ledger gets the scan's bytes once the host's share settled too (F6/F7).
    void recordScanEnd(qint64 now, ScanStep &s)
    {
        if (!m_outcomes.empty()) {
            ScanAction o = act(ScanActionKind::SendOutcomes, m_outcomes.networkKey());
            o.outcomes = m_outcomes.items();
            if (sendApp(QStringLiteral("outcomes"), m_t.costOutcomesBytes, now, s, o))
                s.actions << o;
            m_outcomes.begin(m_net.key);
        }
        closeScanBudget(now, s);
        m_spent = 0;
    }

    // The scan is over for the app side: reservations never sent go back; the ones sent wait for their real
    // bytes until the ledger entry is written (tryCommit charges an unreported one at its worst case).
    void closeScanBudget(qint64 now, ScanStep &s)
    {
        if (!m_cur.open || m_cur.scanEnded)
            return;
        for (auto it = m_cur.app.begin(); it != m_cur.app.end();) {
            if (m_cur.emitted.contains(it.key())) {
                ++it;
                continue;
            }
            m_cur.gate.finish(it.key(), 0);
            it = m_cur.app.erase(it);
        }
        m_cur.scanEnded = true;
        tryCommit(m_cur, now, s);
    }

    void commitBytes(qint64 now, qint64 bytes, bool cellular, ScanStep &s)
    {
        if (bytes <= 0)
            return;
        m_ledger.add(now, bytes, cellular);
        m_ledger.prune(now);
        ScanAction b = act(ScanActionKind::PersistBudget);
        b.ledger = m_ledger.toJson();
        s.actions << b;
    }

    // The ledger gets a scan's allowance use when its app side closed and its host share settled.
    void tryCommit(Settle &st, qint64 now, ScanStep &s)
    {
        if (!st.open || !st.scanEnded || (st.hostStarted && st.stage != HostStage::Settled))
            return;
        for (auto it = st.app.constBegin(); it != st.app.constEnd(); ++it) {
            st.gate.finish(it.key(), it.value()); // sent, never reported: its worst case for now
            remember(it.key(), it.value(), st.cellular); // a later report of more adds the excess
        }
        st.app.clear();
        st.emitted.clear();
        qint64 total = 0;
        if (st.gate.maxBytes() >= 0) {
            if (st.hostStarted)
                st.gate.finish(QStringLiteral("host"), st.hostCharge); // the host's charge as settled
            total = st.gate.spent();
        } else {
            total = st.gate.spent() + (st.hostStarted ? st.hostCharge : 0);
        }
        st.open = false;
        commitBytes(now, total, st.cellular, s);
    }

    void settleHost(Settle &st, qint64 charge, qint64 now, ScanStep &s)
    {
        if (!st.hostStarted || st.stage == HostStage::Settled)
            return;
        st.stage = HostStage::Settled;
        st.hostCharge = qMax<qint64>(0, charge);
        st.deadline = -1;
        tryCommit(st, now, s);
    }

    // Stop admitting host probes (F7): the freeze first, the cancel after its ack.
    // Idempotent: only a started host still Running is frozen; every path that ends the host's part of a scan
    // calls it, so no scan stays in Running without a wake (draining always terminates).
    void freezeHost(qint64 now, ScanStep &s) { freezeHost(m_cur, now, s); }

    void freezeHost(Settle &st, qint64 now, ScanStep &s)
    {
        if (!st.open || !st.hostStarted || st.stage != HostStage::Running)
            return;
        st.stage = HostStage::AwaitFreeze;
        st.deadline = now + m_t.freezeAckMs;
        ScanAction a = act(ScanActionKind::FreezeHostScan);
        a.scanId = st.scanId;
        s.actions << a;
    }

    // The timeout rules of F7, also used when a newer scan forces the old one to settle.
    void settleOnTimeout(Settle &st, qint64 now, ScanStep &s)
    {
        if (st.stage == HostStage::AwaitFreeze) {
            ScanAction c = act(ScanActionKind::StopHostScan);
            c.scanId = st.scanId;
            s.actions << c;
            // No freeze ack: the whole host grant (without a cap: the last seen spent + reserved).
            settleHost(st, st.hostGrant >= 0 ? st.hostGrant : st.lastSpent + st.lastReserved, now, s);
        } else if (st.stage == HostStage::AwaitFinal) {
            settleHost(st, st.freezeSpent + st.freezeReserved, now, s);
        } else if (st.stage == HostStage::Running && st.hostStarted) {
            settleHost(st, st.hostGrant >= 0 ? st.hostGrant : st.lastSpent + st.lastReserved, now, s);
        }
    }

    Settle *settleOf(const QString &scanId)
    {
        if (m_cur.open && m_cur.scanId == scanId)
            return &m_cur;
        if (m_prev.open && m_prev.scanId == scanId)
            return &m_prev;
        return nullptr;
    }

    // An app-side request of this scan: sent only inside the allowance (a reservation made before, or one
    // admitted now); after the scan, against the rolling hour, charged at its worst case at once.
    bool sendApp(const QString &what, qint64 cost, qint64 now, ScanStep &s, ScanAction &a)
    {
        if (m_cur.open && !m_cur.scanEnded && m_cur.scanId == m_scanId) {
            QString id = m_scanId + QLatin1Char('/') + what;
            if (!m_cur.app.contains(id) || m_cur.emitted.contains(id)) {
                if (m_cur.app.contains(id))
                    id += QLatin1Char('#') + QString::number(++m_appSerial);
                if (!m_cur.gate.admit(id, cost))
                    return false;
                m_cur.app.insert(id, cost);
            }
            m_cur.emitted.insert(id);
            a.requestId = id;
            a.costBytes = m_cur.app.value(id); // the reservation is the request's hard limit
            return true;
        }
        const bool cellular = m_net.kind == ScanNetKind::Cellular;
        if (cellular && m_ledger.leftInHour(now, m_t.budgetCellularBytesPerHour, true) < cost)
            return false;
        if (m_manifest.manifest.deviceBytesPerHour > 0 && m_ledger.leftInHour(now, m_manifest.manifest.deviceBytesPerHour, false) < cost)
            return false;
        commitBytes(now, cost, cellular, s);
        a.requestId = QStringLiteral("post/") + QString::number(++m_appSerial);
        a.costBytes = cost;
        remember(a.requestId, cost, cellular); // a later report of more adds the excess
        return true;
    }

    // What the ledger already got for a request that may still report its real size (bounded: the oldest go).
    void remember(const QString &id, qint64 bytes, bool cellular)
    {
        if (!m_charged.contains(id))
            m_chargedOrder << id;
        m_charged.insert(id, Charged{bytes, cellular});
        while (m_chargedOrder.size() > 256)
            m_charged.remove(m_chargedOrder.takeFirst());
    }

    // Reserve (not send yet) a request this scan will make, before the host's grant is cut.
    bool reserveApp(const QString &what, qint64 cost)
    {
        const QString id = m_scanId + QLatin1Char('/') + what;
        if (!m_cur.open || m_cur.scanEnded || m_cur.app.contains(id) || !m_cur.gate.admit(id, cost))
            return false;
        m_cur.app.insert(id, cost);
        return true;
    }

    // Give back a reservation that was never sent.
    void unreserveApp(const QString &what)
    {
        const QString id = m_scanId + QLatin1Char('/') + what;
        if (m_cur.app.contains(id) && !m_cur.emitted.contains(id)) {
            m_cur.gate.finish(id, 0);
            m_cur.app.remove(id);
        }
    }

    void dropCachedRowsExcept(const QString &keep)
    {
        for (int i = m_rows.size() - 1; i >= 0; --i)
            if (m_rows.at(i).cached && m_rows.at(i).id != keep && !(m_current.working() && m_rows.at(i).id == m_current.nodeId))
                m_rows.removeAt(i);
    }

    void finish(qint64 now, ScanStep &s) { finishImpl(now, QString(), s); }
    void finishKeeping(qint64 now, const QString &keep, ScanStep &s) { finishImpl(now, keep, s); }

    void finishImpl(qint64 now, const QString &keep, ScanStep &s)
    {
        if (!scanPhaseScanning(m_phase))
            return;
        m_lightDeadline = lightFinal() ? -1 : m_lightDeadline;
        const bool connectStep = m_phase == ScanPhase::Connecting || m_phase == ScanPhase::Preparing;
        dropCachedRowsExcept(keep);
        if (connectStep && keep.isEmpty() && m_emptyReason.isEmpty() && !m_current.working())
            m_emptyReason = QStringLiteral("connect_failed");
        m_finishedAt = now;
        m_completed = true;
        m_startedVpn = false;
        // «Найти ещё»: this network's judged ids grow; more is available while a planned candidate has no verdict
        // (the stop came first or it stayed «Не проверено»).
        for (const Row &r : m_rows)
            if (!r.cached && (scanClassWorking(r.base) || scanClassFailure(r.base)))
                m_shownNet.insert(r.id);
        for (const ScanCachedFailure &f : m_failuresThisScan)
            m_shownNet.insert(f.id);
        m_moreAvailable = m_planRemaining > 0;
        for (const Cand &c : m_cands)
            m_moreAvailable = m_moreAvailable || !m_shownNet.contains(c.c.id);
        m_continuation = false;
        m_moreKeepRows = false;
        freezeHost(now, s);
        m_hostDone = true;
        settleUnjudged(); // a tap's stop, a failed connect: every candidate in its bucket before the rows are read
        const QList<ScanRowView> rows = displayRows(now);
        m_phase = rows.isEmpty() ? ScanPhase::Empty : ScanPhase::Done;
        int working = 0;
        ScanCachedResult cache;
        cache.networkKey = m_scanNet.key;
        cache.fingerprint = m_scanNet.fingerprint;
        cache.savedAtMs = now;
        for (const ScanRowView &r : rows)
            if (r.verified) {
                ++working;
                const int ri = rowIndex(r.id);
                if (ri < 0 || m_rows.at(ri).cached)
                    continue;
                const Row &x = m_rows.at(ri);
                ScanCachedRow cr;
                cr.id = x.id;
                cr.origin = x.origin;
                cr.profileId = x.profileId;
                cr.label = x.label;
                cr.countryCode = x.countryCode;
                cr.transport = x.transport;
                cr.transportVersion = x.transportVersion;
                cr.tier = x.tier;
                cr.rank = x.rank;
                cr.cls = x.base;
                cr.speed = x.speed;
                cr.ms = x.sortMs;
                cr.crowdWorks = x.crowdWorks;
                cache.rows << cr;
            }
        cache.failures = m_failuresThisScan;
        if (!connectStep)
            recordSummary(rows, now);
        if (!connectStep) {
            ScanAction p = act(ScanActionKind::PersistResults, cache.networkKey);
            p.cached = cache;
            s.actions << p;
        }
        recordScanEnd(now, s);
        if (m_phase == ScanPhase::Done && working > 0)
            s.actions << shade(ShadeTone::Info, QStringLiteral("scan_found"), {QString::number(working)});
        if (m_checkAfterScan)
            startReportCheck(s);
    }

    // The Doctor summary and the report's scan_stats of the scan that just ended (Done / Empty, or NoScan
    // after a host failure).
    void recordSummary(const QList<ScanRowView> &rows, qint64 now)
    {
        m_summary = buildSummary(rows, now);
        m_stats = QJsonObject{{QStringLiteral("seats_requested"), m_seatsRequested},
                              {QStringLiteral("exclusion_rows"), m_exclusionRows},
                              {QStringLiteral("allowance_bytes"), double(m_cur.gate.maxBytes())},
                              {QStringLiteral("host_grant_bytes"), double(m_cur.hostGrant)},
                              {QStringLiteral("app_worst_case_bytes"), double(appWorstCase())},
                              {QStringLiteral("app_side_only"), m_appSideOnly}};
        if (!m_exclusionWhy.isEmpty())
            m_stats.insert(QStringLiteral("exclusion_why"), m_exclusionWhy);
    }

    // openapi DoctorScanSummary: aggregates only - candidate ids, classes, ms, probe kinds; never an address,
    // a leg, a token or a net token; the FULL network key (a bare class is refused by the server).
    // One bucket per candidate (settleUnjudged): the counts sum to `candidates`, the reasons to counts.not_verified.
    // `candidates` = the planned ones + the live connection when it is a row of its own (it is never planned - the
    // live tunnel judges it - but it is one of the rows the counts describe).
    QJsonObject buildSummary(const QList<ScanRowView> &rows, qint64 now) const
    {
        QJsonObject o;
        o.insert(QStringLiteral("schema"), 1);
        o.insert(QStringLiteral("network_key"), scanNetworkKeyValid(m_scanNet.key) ? m_scanNet.key : QStringLiteral("unknown"));
        o.insert(QStringLiteral("manifest_revision"), double(qMax<qint64>(0, m_manifestRevision)));
        int candidates = m_planCandidates;
        QMap<QString, int> counts;
        QMap<QString, int> nvReasons;
        for (auto it = m_verdicts.constBegin(); it != m_verdicts.constEnd(); ++it) {
            counts[QLatin1String(scanClassName(it.value()))] += 1;
            if (it.value() == ScanClass::NotVerified)
                nvReasons[m_nvReasonOf.value(it.key(), QStringLiteral("other"))] += 1;
        }
        for (const Unverified &u : m_unverified) // not settled yet (never at a scan's end): as it is shown
            if (!m_verdicts.contains(u.c.id)) {
                counts[QStringLiteral("not_verified")] += 1;
                nvReasons[scanReasonKey(u.reason)] += 1;
            }
        if (m_current.working() && !m_verdicts.contains(m_current.nodeId)) {
            ++candidates;
            const int ci = rowIndex(m_current.nodeId);
            if (ci >= 0 && rowVerified(m_rows.at(ci))) {
                counts[m_rows.at(ci).base == ScanClass::Slow ? QStringLiteral("slow") : QStringLiteral("works")] += 1;
            } else {
                counts[QStringLiteral("not_verified")] += 1;
                nvReasons[m_liveReasons.value(m_current.nodeId, QStringLiteral("live_pending"))] += 1;
            }
        }
        o.insert(QStringLiteral("candidates"), qMin(1024, candidates));
        QJsonObject c;
        for (auto it = counts.constBegin(); it != counts.constEnd(); ++it)
            c.insert(it.key(), qMin(1024, it.value()));
        o.insert(QStringLiteral("counts"), c);
        QJsonArray top;
        for (const ScanRowView &r : rows) {
            if (top.size() >= 20)
                break;
            const bool up = r.id.startsWith(QLatin1String("up:"));
            QJsonObject t{{QStringLiteral("kind"), up ? QStringLiteral("upstream") : QStringLiteral("node")},
                          {QStringLiteral("id"), up ? r.id.mid(3) : r.id},
                          {QStringLiteral("class"), QLatin1String(!r.verified ? "not_verified" : r.state == ScanRowState::Slow ? "slow" : "works")}};
            if (r.ms >= 0)
                t.insert(QStringLiteral("ms"), qMin(r.ms, 600000));
            const int ci = candIndex(r.id);
            if (r.current)
                t.insert(QStringLiteral("probe"), QStringLiteral("tunnel"));
            else if (ci >= 0 && r.verified)
                t.insert(QStringLiteral("probe"), QLatin1String(scanOutcomeProbeName(
                    m_cands.at(ci).followUp == FollowUp::Done ? ScanProbeKind::XrayFull : m_cands.at(ci).c.kind)));
            const int ri = rowIndex(r.id);
            if (kScanOutcomeEvidenceAccepted && r.verified && !r.fromCache && ri >= 0)
                t.insert(QStringLiteral("evidence"), m_rows.at(ri).evidence == QLatin1String("exclusion") ? m_rows.at(ri).evidence
                                                                                                           : QStringLiteral("direct"));
            top << t;
        }
        o.insert(QStringLiteral("top"), top);
        // At most 16 keys (the schema): past that the smallest reasons merge into "other", so the sum stays.
        if (nvReasons.size() > 16) {
            QList<QPair<int, QString>> byCount;
            for (auto it = nvReasons.constBegin(); it != nvReasons.constEnd(); ++it)
                if (it.key() != QLatin1String("other"))
                    byCount << qMakePair(-it.value(), it.key());
            std::sort(byCount.begin(), byCount.end());
            int other = nvReasons.value(QStringLiteral("other"));
            nvReasons.clear();
            for (int i = 0; i < byCount.size(); ++i) {
                if (i < 15)
                    nvReasons.insert(byCount.at(i).second, -byCount.at(i).first);
                else
                    other += -byCount.at(i).first;
            }
            nvReasons.insert(QStringLiteral("other"), other);
        }
        QJsonObject reasons;
        for (auto it = nvReasons.constBegin(); it != nvReasons.constEnd(); ++it)
            reasons.insert(it.key(), qMin(1024, it.value()));
        o.insert(QStringLiteral("not_verified_reasons"), reasons);
        o.insert(QStringLiteral("stop_reason"), scanReasonKey(m_stopReason.isEmpty() ? QStringLiteral("works") : m_stopReason));
        o.insert(QStringLiteral("duration_ms"), double(qBound(qint64(0), now - m_scanStartAt, qint64(600000))));
        o.insert(QStringLiteral("bytes_spent"), double(qBound(qint64(0), m_spent, qint64(1073741824))));
        o.insert(QStringLiteral("seats_requested"), qBound(0, m_seatsRequested, 48)); // contract 1.7.0
        o.insert(QStringLiteral("caps"), QJsonObject{{QStringLiteral("leg_probe"), m_caps.legProbe()},
                                                    {QStringLiteral("full_profile"), m_caps.fullProbe()},
                                                    {QStringLiteral("full_profile_parallel"), m_caps.maxFullConcurrent > 1},
                                                    {QStringLiteral("awg_mini"), m_caps.awgMini()},
                                                    {QStringLiteral("probe_with_vpn_off"), !m_caps.needsVpn}});
        return o;
    }

    // The host's access attempts of this scan (plan §2.2c): the OPENING one becomes the access evidence (its
    // facts when it answered 200, nothing otherwise) and opens the exclusion bracket; the host's path monitor
    // moving after it voids both; the CLOSING one decides the exclusion proof.
    void noteAttempts(const ScanHostProgress &p, qint64 now, ScanStep &s)
    {
        if (p.access.attempted && !m_opening.attempted) {
            m_opening = p.access;
            m_openingStamp = currentStamp();
            m_access = p.access.hasFacts() ? p.access.facts : ScanAccess();
            m_accessStamp = m_openingStamp;
        }
        if (m_opening.attempted && m_opening.hasGen && p.hasGen && p.gen != m_opening.gen) {
            m_access = ScanAccess(); // the host's path changed: those facts describe another path
            m_accessStamp.clear();
            m_openingStamp.clear();
        }
        if (p.accessClose.attempted && !m_exclusionDone)
            evaluateExclusion(p.accessClose, now, s);
    }

    // Proof by exclusion (plan §2.8; the rule is ScanClass.h::scanExclusionWhy): the host's direct access
    // check failed at the network level before the probe AND after it, on one path state, this tuple and this
    // scan token: the access network could not reach the probe host at all, so a probe that came back with a
    // device-verified digest in between did not leave through it. Off with features.upstream_unverifiable_strict.
    void evaluateExclusion(const ScanAccessAttempt &closing, qint64 now, ScanStep &s)
    {
        if (m_exclusionDone)
            return;
        m_exclusionDone = true;
        const QString stamp = currentStamp();
        const bool sameNet = m_scanNet.generation() == m_net.generation();
        ScanOutcomeCollector late;
        late.begin(m_scanNet.key);
        const bool scanning = m_phase == ScanPhase::Reach || m_phase == ScanPhase::Data || m_phase == ScanPhase::Self;
        for (Cand &c : m_cands) {
            if (!c.exclusionPending)
                continue;
            c.exclusionPending = false;
            const QString why = sameNet ? scanExclusionWhy(m_manifest.strictUnverifiable, m_opening, m_openingStamp, closing, stamp, stamp,
                                                           m_net.sources, c.pendingFacts.startMs, c.pendingFacts.endMs)
                                        : QStringLiteral("generation");
            if (!why.isEmpty()) {
                m_exclusionWhy = why;
                continue; // stays «Не проверено» (unverifiable)
            }
            const ScanVerdict &v = c.pendingVerdict;
            const int ri = rowIndex(c.c.id);
            Row r;
            if (ri >= 0)
                r = m_rows.at(ri);
            r.id = c.c.id;
            r.origin = c.c.origin;
            r.profileId = c.c.profileId;
            r.label = c.c.label;
            r.countryCode = c.c.countryCode;
            r.transport = c.c.transport;
            r.tier = c.c.tier;
            r.rank = c.c.rank;
            r.base = v.exclusionClass;
            r.speed = v.speed;
            r.sortMs = v.ms;
            r.fromLive = false;
            r.cached = false;
            r.crowdWorks = c.c.crowdWorks;
            r.generation = m_scanNet.generation();
            r.fingerprint = m_scanNet.fingerprint;
            r.evidence = QStringLiteral("exclusion");
            r.arrival = ++m_arrival;
            if (ri >= 0)
                m_rows[ri] = r;
            else
                m_rows << r;
            removeUnverified(c.c.id);
            judge(c.c.id, v.exclusionClass); // counted under works, not under not_verified_reasons (plan §2.8)
            ++m_exclusionRows;
            ScanOutcomeItem o;
            o.kind = c.c.outcomeKind();
            o.id = c.c.outcomeId();
            o.outcome = v.exclusionClass;
            o.stage = ScanOutcomeStage::Data;
            o.probe = QLatin1String(scanOutcomeProbeName(c.followUp == FollowUp::Done ? ScanProbeKind::XrayFull : c.c.kind));
            o.ttfbMs = c.pendingFacts.ttfb1Ms;
            o.bytes = c.pendingFacts.bytesReceived;
            o.durationMs = c.pendingFacts.durationMs;
            o.rttMs = v.ms;
            o.evidence = QStringLiteral("exclusion");
            if (scanning)
                m_outcomes.add(o);
            else
                late.add(o);
        }
        m_stats.insert(QStringLiteral("exclusion_rows"), m_exclusionRows);
        if (!m_exclusionWhy.isEmpty())
            m_stats.insert(QStringLiteral("exclusion_why"), m_exclusionWhy);
        if (!late.empty()) {
            ScanAction a = act(ScanActionKind::SendOutcomes, late.networkKey());
            a.outcomes = late.items();
            if (sendApp(QStringLiteral("outcomes"), m_t.costOutcomesBytes, now, s, a))
                s.actions << a;
        }
        if (scanning) {
            checkStop(now, s);
        } else if (m_phase == ScanPhase::Done || m_phase == ScanPhase::Empty) {
            if (m_phase == ScanPhase::Empty && !displayRows(now).isEmpty())
                m_phase = ScanPhase::Done;
            ScanAction p = act(ScanActionKind::PersistResults, m_scanNet.key);
            p.cached = buildCache(displayRows(now), now);
            s.actions << p;
            // The summary of the finished scan gets the proven rows (its other figures stay as they were).
            if (!m_summary.isEmpty() && m_exclusionRows > 0) {
                const QJsonObject fresh = buildSummary(displayRows(now), m_finishedAt);
                for (const char *k : {"candidates", "counts", "top", "not_verified_reasons"}) // one bucket per candidate
                    m_summary.insert(QLatin1String(k), fresh.value(QLatin1String(k)));
            }
        }
    }

    ScanCachedResult buildCache(const QList<ScanRowView> &rows, qint64 now) const
    {
        ScanCachedResult cache;
        cache.networkKey = m_scanNet.key;
        cache.fingerprint = m_scanNet.fingerprint;
        cache.savedAtMs = now;
        for (const ScanRowView &r : rows) {
            if (!r.verified)
                continue;
            const int ri = rowIndex(r.id);
            if (ri < 0 || m_rows.at(ri).cached)
                continue;
            const Row &x = m_rows.at(ri);
            ScanCachedRow cr;
            cr.id = x.id;
            cr.origin = x.origin;
            cr.profileId = x.profileId;
            cr.label = x.label;
            cr.countryCode = x.countryCode;
            cr.transport = x.transport;
            cr.transportVersion = x.transportVersion;
            cr.tier = x.tier;
            cr.rank = x.rank;
            cr.cls = x.base;
            cr.speed = x.speed;
            cr.ms = x.sortMs;
            cr.crowdWorks = x.crowdWorks;
            cache.rows << cr;
        }
        cache.failures = m_failuresThisScan;
        return cache;
    }

    void cancelScan(qint64 now, ScanStep &s)
    {
        freezeHost(now, s);
        m_hostDone = true;
        releaseLeases(s);
        if (m_phase == ScanPhase::Connecting && m_startedVpn)
            s.actions << act(ScanActionKind::CancelPendingConnect); // the user's cancel of that connect only
        m_startedVpn = false;
        recordScanEnd(now, s);
        // Partial rows are dropped (artboard leaveScanner); the live connection stays.
        for (int i = m_rows.size() - 1; i >= 0; --i)
            if (!(m_current.working() && m_rows.at(i).id == m_current.nodeId))
                m_rows.removeAt(i);
        m_unverified.clear();
        m_cands.clear();
        m_completed = false;
        m_phase = ScanPhase::Idle;
        m_deadline = -1;
        if (!lightFinal()) {
            m_lightActive = false;
            m_lightDeadline = -1;
            m_lightNode.clear();
        }
        m_checkAfterScan = false;
    }

    void toNoScan(const QString &reason, qint64 now, ScanStep &s)
    {
        freezeHost(now, s);
        if (m_cur.open && !m_cur.scanEnded && m_cur.scanId == m_scanId)
            closeScanBudget(now, s);
        m_phase = ScanPhase::NoScan;
        m_noScanReason = reason;
        m_completed = false;
        m_cands.clear();
        m_deadline = -1;
        ensureLight(now, s);
    }

    // The card always has its light facts for the live connection once the scan is over.
    void ensureLight(qint64 now, ScanStep &s)
    {
        if (m_current.working() && !m_checking && (!m_lightActive || m_lightNode != m_current.nodeId))
            startLight(now, s);
    }

    void maybeFireWifiIntent(qint64 now, ScanStep &s)
    {
        if (m_wifiIntentUntil <= 0 || m_net.kind != ScanNetKind::Wifi)
            return;
        const bool valid = now < m_wifiIntentUntil;
        m_wifiIntentUntil = 0;
        if (!valid || scanPhaseScanning(m_phase))
            return;
        m_screenOpen = true;
        s.actions << act(ScanActionKind::OpenScreen);
        beginScan(now, s);
    }

    void addChainOutcome(const QString &nodeId, ScanClass cls)
    {
        ScanOutcomeItem o;
        const bool up = nodeId.startsWith(QLatin1String("up:"));
        o.kind = up ? QStringLiteral("upstream") : QStringLiteral("node");
        o.id = up ? nodeId.mid(3) : nodeId;
        o.outcome = cls;
        o.stage = ScanOutcomeStage::Connect;
        o.probe = QStringLiteral("tunnel");
        if (cls == ScanClass::Works && m_current.working() && m_current.nodeId == nodeId)
            o.rttMs = m_current.liveRttMs;
        m_chain.add(o);
    }

    void endChain(ScanStep &s, bool failedLast)
    {
        if (failedLast && !m_chainLaterShown) {
            m_chainLaterShown = true;
            s.actions << shade(ShadeTone::Warning, QStringLiteral("connect_failed_later"));
        }
        m_connectingId.clear();
        m_chainOrder.clear();
        if (!m_chain.empty()) {
            ScanAction o = act(ScanActionKind::SendOutcomes, m_chain.networkKey());
            o.outcomes = m_chain.items();
            if (sendApp(QStringLiteral("outcomes"), m_t.costOutcomesBytes, m_last, s, o))
                s.actions << o;
        }
        m_chain.begin(m_net.key);
    }

    // --- rows -------------------------------------------------------------------------------------------------
    static bool displayLess(const ScanRowView &a, int aTier, int aRank, const ScanRowView &b, int bTier, int bRank,
                            int aSort, int bSort)
    {
        const int ra = scanSpeedRank(a.speed), rb = scanSpeedRank(b.speed);
        if (ra != rb)
            return ra < rb;
        const int ma = aSort < 0 ? INT_MAX : aSort, mb = bSort < 0 ? INT_MAX : bSort;
        if (ma != mb)
            return ma < mb;
        if (aTier != bTier)
            return aTier < bTier;
        if (aRank != bRank)
            return aRank < bRank;
        return a.id < b.id;
    }

    QList<ScanRowView> displayRows(qint64 now) const
    {
        struct Item {
            ScanRowView v;
            int tier;
            int rank;
            int sort;
            bool forced;
            bool cached;
        };
        QList<Item> verified;
        for (const Row &r : m_rows) {
            if (!scanClassWorking(r.base) || !rowShown(r, now))
                continue;
            const bool liveUnproven = !rowVerified(r);
            if (liveUnproven && !(m_current.working() && r.id == m_current.nodeId))
                continue; // a live connection that is gone and was never proven: no row
            Item it;
            ScanRowView &v = it.v;
            v.id = r.id;
            v.origin = r.origin;
            v.label = r.label;
            v.countryCode = r.countryCode;
            v.transport = r.transport;
            v.transportVersion = r.transportVersion;
            v.speed = r.base == ScanClass::Slow ? ScanSpeed::Slow : r.speed;
            v.bars = scanSpeedBars(v.speed);
            v.ms = r.sortMs;
            v.fromCache = r.cached;
            v.arrival = r.arrival;
            v.crowdWorks = r.crowdWorks;
            v.state = r.base == ScanClass::Slow ? ScanRowState::Slow : ScanRowState::Works;
            const bool isCurrent = m_current.working() && r.id == m_current.nodeId;
            if (isCurrent) {
                v.state = ScanRowState::Connected;
                v.current = true;
                v.ms = m_current.liveRttMs;
            }
            if (liveUnproven) {
                // Connected, but not counted as verified until the sized check through the tunnel (F2).
                v.verified = false;
                v.notVerifiedReason = QStringLiteral("live_unverified");
                v.bars = scanSpeedBars(v.speed);
            }
            if (m_tapFailed.contains(r.id)) {
                v.state = ScanRowState::Failed;
                v.dimmed = true;
                v.tappable = false;
            }
            if (!m_connectingId.isEmpty() && r.id == m_connectingId) {
                v.state = ScanRowState::Connecting;
                v.verifying = true;
            }
            if (isCurrent)
                v.tappable = false;
            it.tier = r.tier;
            it.rank = r.rank;
            it.sort = r.sortMs;
            it.forced = isCurrent || r.id == m_connectingId || m_tapFailed.contains(r.id);
            it.cached = r.cached;
            verified << it;
        }
        // Admission: forced rows, then tier first, fresh before cached, speed, ms.
        std::stable_sort(verified.begin(), verified.end(), [](const Item &a, const Item &b) {
            if (a.forced != b.forced)
                return a.forced;
            if (a.tier != b.tier)
                return a.tier < b.tier;
            if (a.cached != b.cached)
                return !a.cached;
            return displayLess(a.v, a.tier, a.rank, b.v, b.tier, b.rank, a.sort, b.sort);
        });
        const int cap = qMax(1, m_t.listTargetWorks);
        while (verified.size() > cap)
            verified.removeLast();
        std::stable_sort(verified.begin(), verified.end(), [](const Item &a, const Item &b) {
            return displayLess(a.v, a.tier, a.rank, b.v, b.tier, b.rank, a.sort, b.sort);
        });
        QList<ScanRowView> out;
        QSet<QString> ids;
        for (const Item &it : verified) {
            out << it.v;
            ids.insert(it.v.id);
        }
        if (out.size() < cap) {
            int n = 0;
            for (const Unverified &u : m_unverified) {
                if (n >= m_t.unverifiedRowsMax)
                    break;
                if (ids.contains(u.c.id) || (m_current.working() && u.c.id == m_current.nodeId))
                    continue;
                ScanRowView v;
                v.id = u.c.id;
                v.origin = u.c.origin;
                v.label = u.c.label;
                v.countryCode = u.c.countryCode;
                v.transport = u.c.transport;
                v.transportVersion = u.c.transportVersion;
                v.state = ScanRowState::NotVerified;
                v.verified = false;
                v.crowdWorks = u.c.crowdWorks;
                v.speed = ScanSpeed::None;
                v.bars = 0;
                v.ms = -1;
                v.notVerifiedReason = u.reason;
                if (m_tapFailed.contains(u.c.id)) {
                    v.state = ScanRowState::Failed;
                    v.dimmed = true;
                    v.tappable = false;
                }
                if (!m_connectingId.isEmpty() && u.c.id == m_connectingId) {
                    v.state = ScanRowState::Connecting;
                    v.verifying = true;
                }
                out << v;
                ids.insert(v.id);
                ++n;
            }
        }
        return out;
    }

    QString effectiveFilter(const QList<ScanRowView> &all) const
    {
        if (m_filter.isEmpty() || scanPhaseScanning(m_phase))
            return QString();
        for (const ScanRowView &r : all)
            if (r.countryCode == m_filter)
                return m_filter;
        return QString();
    }

    QList<ScanRowView> filteredRows(qint64 now) const
    {
        const QList<ScanRowView> all = displayRows(now);
        const QString f = effectiveFilter(all);
        QList<ScanRowView> out;
        for (const ScanRowView &r : all)
            if (f.isEmpty() || r.countryCode == f)
                out << r;
        return out;
    }

    // Where «Отправить отчёт в поддержку» is offered: the empty result, «скан невозможен», and a finished scan with
    // rows but no live connection (its card is «VPN не подключён», no button; desktop scans with the VPN off).
    bool reportLinkOffered() const
    {
        return m_phase == ScanPhase::Empty || m_phase == ScanPhase::NoScan
               || (m_phase == ScanPhase::Done && !m_current.working());
    }

    ScanCardMode cardMode() const
    {
        if (!m_current.working())
            return (m_phase == ScanPhase::Idle || m_phase == ScanPhase::Empty) ? ScanCardMode::Hidden : ScanCardMode::Off;
        if (m_checking)
            return ScanCardMode::Checking;
        if (m_phase == ScanPhase::Preparing || m_phase == ScanPhase::Connecting || m_phase == ScanPhase::Reach
            || m_phase == ScanPhase::Data || m_phase == ScanPhase::Idle)
            return ScanCardMode::Hidden;
        if (!m_lightActive || !lightFinal())
            return ScanCardMode::Filling;
        return m_checked ? ScanCardMode::Checked : ScanCardMode::Filled;
    }

    ScanCardView cardView(qint64 now) const
    {
        Q_UNUSED(now);
        ScanCardView c;
        c.mode = cardMode();
        c.reportQueueFull = m_reportQueueFull;
        if (c.mode == ScanCardMode::Hidden || c.mode == ScanCardMode::Off)
            return c;
        c.serverLabel = m_current.label;
        c.serverCountry = m_current.countryCode;
        c.serverMs = m_current.liveRttMs;
        const auto fv = [this](ScanFactKind k) {
            const Fact &f = m_facts[int(k)];
            ScanFactView v;
            v.state = f.state;
            v.chips = f.chips;
            v.ok = f.ok;
            v.bars = f.bars;
            v.word = f.word;
            v.needsButton = f.needsButton;
            return v;
        };
        c.server = fv(ScanFactKind::Server);
        c.services = fv(ScanFactKind::Services);
        c.sites = fv(ScanFactKind::Sites);
        c.speed = fv(ScanFactKind::Speed);
        c.speedVisible = c.mode == ScanCardMode::Checking || c.mode == ScanCardMode::Checked;
        if (c.mode == ScanCardMode::Checking) {
            c.button = ScanCardButton::Busy;
            c.progress = double(m_checkStep) / qMax(1, m_checkTotal);
        } else if (c.mode == ScanCardMode::Filling) {
            c.button = ScanCardButton::Hidden;
        } else {
            c.button = m_connectingId.isEmpty() ? ScanCardButton::Ready : ScanCardButton::Disabled;
        }
        return c;
    }

    qint64 nextChange(qint64 now, const ScanView &v) const
    {
        qint64 w = -1;
        const auto take = [&w](qint64 t) {
            if (t >= 0 && (w < 0 || t < w))
                w = t;
        };
        if (v.scanning && (m_phase == ScanPhase::Data || m_phase == ScanPhase::Reach))
            take(now + 250);
        if (m_phase == ScanPhase::Data && m_deadline > now)
            take(now + ((m_deadline - now) % 1000 == 0 ? 1000 : (m_deadline - now) % 1000));
        if (!v.scanning && now < m_cooldownUntil)
            take(now + ((m_cooldownUntil - now) % 1000 == 0 ? 1000 : (m_cooldownUntil - now) % 1000));
        if (v.checkedAgoMin >= 0) {
            const qint64 base = v.scanning ? -1 : m_finishedAt;
            if (base > 0)
                take(base + (qint64(v.checkedAgoMin) + 1) * 60000);
        }
        if (v.bar.button == ScanBarButton::RetryInMinutes)
            take(now + 60000);
        return w;
    }

    // --- state ------------------------------------------------------------------------------------------------
    ScanHostCaps m_caps;
    ScanTunables m_t;
    ScanBudgetLedger m_ledger;
    ScanPhase m_phase = ScanPhase::Idle;
    ScanNetwork m_net;
    ScanNetwork m_scanNet;
    QString m_rowsKey;
    ScanCurrent m_current;
    ScanManifestInput m_manifest;
    bool m_haveManifest = false;
    bool m_haveManifestForScan = false;
    ScanAccess m_access;
    ScanCachedResult m_cachedFailures;
    QList<Cand> m_cands;
    QList<Row> m_rows;
    QList<Unverified> m_unverified;
    QList<ScanCachedFailure> m_failuresThisScan;
    QSet<QString> m_tapFailed;
    QString m_filter;
    QString m_scanId;
    quint64 m_serial = 0;
    quint64 m_arrival = 0;
    qint64 m_lastSeq = 0;
    qint64 m_spent = 0;
    qint64 m_cap = -1;
    qint64 m_lastProjection = 0;
    QHash<QString, ScanClass> m_verdicts;     // per candidate of this scan (the Doctor summary): every planned one ends here
    QHash<QString, QString> m_nvReasonOf;     // candidate id -> reason key of its NotVerified verdict
    QHash<QString, QString> m_liveReasons;    // node id -> why the live row stayed unproven (live_budget, live_<reason>)
    int m_planCandidates = 0;
    qint64 m_manifestRevision = 0;
    QJsonObject m_summary;                    // the last finished scan (lastSummary)
    qint64 m_scanStartAt = 0;
    bool m_batchConfig = false;
    int m_batches = 0;
    bool m_connectOnOpen = true;
    Settle m_cur;              // this scan's allowance
    Settle m_prev;             // the previous scan, still settling its host bytes
    quint64 m_appSerial = 0;
    QString m_manifestReqId;
    ScanAccessAttempt m_opening;
    QString m_openingStamp;    // generation | scan id of the opening attempt
    QString m_accessStamp;     // generation | scan id the access facts belong to
    bool m_exclusionDone = false;
    QString m_exclusionWhy;    // why the last exclusion check failed for a candidate ("" = none failed)
    QStringList m_releaseDeferred; // seats whose release waits for the scan's final release
    bool m_appSideOnly = false;
    int m_seatsRequested = 0;
    int m_exclusionRows = 0;
    bool m_reportQueueFull = false;
    QJsonObject m_stats;
    QString m_liveProbeNode;
    QString m_liveReqId;
    bool m_liveProbeDone = false;
    QString m_reportId;
    quint64 m_reportSerial = 0;
    int m_fullConc = 0;
    int m_legConc = 0;
    int m_awgConc = 0;
    bool m_hostStarted = false;
    bool m_hostDone = false;
    qint64 m_s2Start = -1;
    qint64 m_deadline = -1;
    struct Charged {
        qint64 bytes = 0;
        bool cellular = false;
    };
    QHash<QString, Charged> m_charged; // request id -> what the ledger got for it (until its real size comes)
    QStringList m_chargedOrder;
    qint64 m_cooldownUntil = 0;
    qint64 m_cooldownPrev = 0;        // the cooldown before this scan armed its own (a refused start restores it)
    bool m_liveProbeSent = false;     // this scan sent the live-tunnel probe (bytes moved: the cooldown holds)
    qint64 m_lastManifestAt = LLONG_MIN / 2; // the last manifest request (the buttons' back-off)
    qint64 m_finishedAt = 0;
    // «Найти ещё» (moreTapped)
    bool m_continuation = false;     // the scan being begun is a continuation
    bool m_moreKeepRows = false;     // ... on the same network: rows stay fresh, judged ids skipped
    QString m_moreCountry;
    QSet<QString> m_shownNet;        // ids judged on this network in this series
    int m_worksBase = 0;             // fresh working rows before the continuation (its stop counts the new ones)
    int m_batch = 0;
    bool m_moreAvailable = false;
    int m_planRemaining = 0;         // probed candidates the batch cap left for the next one
    QString m_scope;                 // the chosen country: the scope of the next scan ("" = all)
    QString m_scannedScope;          // the scope of the running / last scan
    QList<ScanCountryView> m_scopeCountries; // the pool's countries of the last manifest
    QList<ScanCountryView> m_poolCountries;  // the server's pool (/v1/scan/pool), preferred when known
    int m_poolWhitelist = -1;
    enum class ServerBatch { Unknown, Yes, No };
    ServerBatch m_serverBatch = ServerBatch::Unknown; // /v1/scan/candidates answered / refused this session
    QString m_candReqId;
    bool m_fromServer = false;       // this scan probes the server's batch
    bool m_serverExhausted = false;

    QList<ScanCountryView> scopeList() const { return m_poolCountries.isEmpty() ? m_scopeCountries : m_poolCountries; }

    // A scope (a country, the white lists) or «Найти ещё» asks the server for its batch while it may answer.
    bool wantServerBatch() const
    {
        return m_serverBatch != ServerBatch::No && (!m_scannedScope.isEmpty() || (m_continuation && m_moreKeepRows));
    }

    void requestCandidates(qint64 now, ScanStep &s)
    {
        ScanAction a = act(ScanActionKind::RequestCandidates, m_net.key);
        a.scopeCountry = m_scannedScope;
        a.batch = m_continuation ? kScanMoreBatch : kScanScopeFirstBatch;
        QStringList seen = QStringList(m_shownNet.begin(), m_shownNet.end());
        seen.sort();
        a.ids = seen.mid(0, 512);
        if (!sendApp(QStringLiteral("candidates"), qint64(m_t.costManifestBytes), now, s, a)) {
            startHost(now, s); // no room for the request: the device's own candidates
            return;
        }
        m_candReqId = a.requestId;
        s.actions << a;
    }
    bool m_completed = false;
    bool m_screenOpen = false;
    bool m_startedVpn = false;
    bool m_checkAfterScan = false;
    QString m_stopReason;
    QString m_emptyReason;
    QString m_noScanReason;
    qint64 m_wifiIntentUntil = 0;
    ScanOutcomeCollector m_outcomes;
    ScanOutcomeCollector m_chain;
    QString m_connectingId;
    QStringList m_chainOrder;
    bool m_chainLaterShown = false;
    // card
    Fact m_facts[4];
    Fact m_factsBeforeCheck[4];       // restored when the engine refuses the check
    bool m_checkedBeforeCheck = false;
    bool m_lightActive = false;
    QString m_lightNode;
    qint64 m_lightDeadline = -1;
    bool m_checking = false;
    bool m_checked = false;
    int m_checkStep = 0;
    int m_checkTotal = 4;
    bool m_reportSending = false;
    qint64 m_last = 0;
};

// --- JSON views (vectors, journals, the QML lane's mocks). No secrets ever live in actions or views. -------

inline QJsonObject scanCandidateToJson(const ScanCandidate &c)
{
    QJsonObject o;
    o.insert(QStringLiteral("id"), c.id);
    o.insert(QStringLiteral("probe_id"), scanProbeIdOf(c));
    o.insert(QStringLiteral("origin"), c.origin == ScanOrigin::Upstream ? QStringLiteral("upstream") : QStringLiteral("own"));
    o.insert(QStringLiteral("kind"), QLatin1String(scanProbeKindName(c.kind)));
    o.insert(QStringLiteral("tier"), c.tier);
    o.insert(QStringLiteral("rank"), c.rank);
    if (!c.profileId.isEmpty())
        o.insert(QStringLiteral("profile_id"), c.profileId);
    if (!c.entryIp.isEmpty())
        o.insert(QStringLiteral("entry"), c.entryIp + QLatin1Char(':') + QString::number(c.entryPort));
    o.insert(QStringLiteral("reach_at_ms"), double(c.reachAtMs));
    o.insert(QStringLiteral("cost_bytes"), double(c.costBytes));
    if (c.needsLease)
        o.insert(QStringLiteral("needs_lease"), true);
    if (c.dnsThroughLeg)
        o.insert(QStringLiteral("dns_through_leg"), true);
    if (c.lastKnownGood)
        o.insert(QStringLiteral("lkg"), true);
    if (c.crowdWorks)
        o.insert(QStringLiteral("crowd_works"), true);
    if (!c.awgEchoTarget.isEmpty())
        o.insert(QStringLiteral("awg_echo_target"), c.awgEchoTarget);
    if (!c.notVerifiedReason.isEmpty())
        o.insert(QStringLiteral("not_verified_reason"), c.notVerifiedReason);
    return o;
}

inline QJsonObject scanActionToJson(const ScanAction &a)
{
    QJsonObject o;
    o.insert(QStringLiteral("kind"), QLatin1String(scanActionName(a.kind)));
    if (!a.requestId.isEmpty()) {
        o.insert(QStringLiteral("request_id"), a.requestId);
        o.insert(QStringLiteral("cost_bytes"), double(a.costBytes));
    }
    switch (a.kind) {
    case ScanActionKind::RequestManifest:
        o.insert(QStringLiteral("network_key"), a.networkKey);
        break;
    case ScanActionKind::StartHostScan:
    case ScanActionKind::AddHostCandidates: {
        o.insert(QStringLiteral("scan_id"), a.scanId);
        QJsonArray cs;
        for (const ScanCandidate &c : a.candidates)
            cs << scanCandidateToJson(c);
        o.insert(QStringLiteral("candidates"), cs);
        if (a.kind == ScanActionKind::StartHostScan) {
            o.insert(QStringLiteral("limits"), scanHostLimitsToJson(a.limits));
            o.insert(QStringLiteral("deadline_ms"), double(a.deadlineMs));
            o.insert(QStringLiteral("max_bytes"), double(a.maxBytes));
            o.insert(QStringLiteral("warm_bytes"), a.warmBytes);
            o.insert(QStringLiteral("bytes"), a.bytes);
            if (!a.baseIps.isEmpty()) {
                QJsonArray ips;
                for (const QString &ip : a.baseIps)
                    ips << ip;
                o.insert(QStringLiteral("base_ips"), ips);
            }
        }
        break;
    }
    case ScanActionKind::FreezeHostScan:
    case ScanActionKind::StopHostScan:
        o.insert(QStringLiteral("scan_id"), a.scanId);
        break;
    case ScanActionKind::RequestProbeBatch: {
        o.insert(QStringLiteral("scan_id"), a.scanId);
        QJsonArray ids, pids;
        for (const ScanCandidate &c : a.candidates) {
            ids << c.id;
            pids << c.profileId;
        }
        o.insert(QStringLiteral("ids"), ids);
        o.insert(QStringLiteral("profile_ids"), pids);
        o.insert(QStringLiteral("include_config"), a.includeConfig);
        break;
    }
    case ScanActionKind::ReleaseProbeLeases: {
        QJsonArray ids;
        for (const QString &x : a.ids)
            ids << x;
        o.insert(QStringLiteral("ids"), ids);
        break;
    }
    case ScanActionKind::StartLightChecks:
        o.insert(QStringLiteral("node_id"), a.nodeId);
        break;
    case ScanActionKind::StartReportCheck:
        o.insert(QStringLiteral("with_connection"), a.withConnection);
        o.insert(QStringLiteral("report_id"), a.reportId);
        o.insert(QStringLiteral("report"), a.report);
        break;
    case ScanActionKind::ShowShade: {
        o.insert(QStringLiteral("tone"), QLatin1String(shadeToneName(a.shade.tone)));
        o.insert(QStringLiteral("text_key"), a.shade.textKey);
        QJsonArray args;
        for (const QString &x : a.shade.args)
            args << x;
        o.insert(QStringLiteral("args"), args);
        break;
    }
    case ScanActionKind::SendOutcomes: {
        QJsonArray items;
        for (const ScanOutcomeItem &it : a.outcomes)
            items << it.toJson(a.networkKey);
        o.insert(QStringLiteral("network_key"), a.networkKey);
        o.insert(QStringLiteral("items"), items);
        break;
    }
    case ScanActionKind::PersistResults:
        o.insert(QStringLiteral("cached"), scanCachedResultToJson(a.cached));
        break;
    case ScanActionKind::PersistBudget:
        o.insert(QStringLiteral("ledger"), a.ledger);
        break;
    case ScanActionKind::ConnectRow: {
        o.insert(QStringLiteral("node_id"), a.nodeId);
        QJsonArray ids;
        for (const QString &x : a.ids)
            ids << x;
        o.insert(QStringLiteral("attempt_order"), ids);
        o.insert(QStringLiteral("hint_ttl_ms"), double(a.hintTtlMs));
        o.insert(QStringLiteral("user_origin"), a.userOrigin);
        o.insert(QStringLiteral("force_connect"), a.forceConnect);
        break;
    }
    case ScanActionKind::ProbeLiveTunnel:
        o.insert(QStringLiteral("node_id"), a.nodeId);
        o.insert(QStringLiteral("warm_bytes"), a.warmBytes);
        o.insert(QStringLiteral("bytes"), a.bytes);
        break;
    case ScanActionKind::CloseScreen:
    case ScanActionKind::OpenScreen:
    case ScanActionKind::UserConnectForScan:
    case ScanActionKind::CancelPendingConnect:
        break;
    }
    return o;
}

inline QJsonObject scanFactViewToJson(const ScanFactView &f)
{
    QJsonObject o;
    o.insert(QStringLiteral("state"), QLatin1String(scanFactStateName(f.state)));
    if (!f.chips.isEmpty()) {
        QJsonArray c;
        for (int x : f.chips)
            c << x;
        o.insert(QStringLiteral("chips"), c);
    }
    if (f.ok)
        o.insert(QStringLiteral("ok"), true);
    if (f.bars)
        o.insert(QStringLiteral("bars"), f.bars);
    if (!f.word.isEmpty())
        o.insert(QStringLiteral("word"), f.word);
    if (f.needsButton)
        o.insert(QStringLiteral("needs_button"), true);
    return o;
}

inline QJsonObject scanRowViewToJson(const ScanRowView &r)
{
    QJsonObject o;
    o.insert(QStringLiteral("id"), r.id);
    o.insert(QStringLiteral("label"), r.label);
    o.insert(QStringLiteral("cc"), r.countryCode);
    o.insert(QStringLiteral("transport"), QLatin1String(scanTransportName(r.transport)));
    o.insert(QStringLiteral("state"), QLatin1String(scanRowStateName(r.state)));
    o.insert(QStringLiteral("speed"), QLatin1String(scanSpeedName(r.speed)));
    o.insert(QStringLiteral("bars"), r.bars);
    o.insert(QStringLiteral("ms"), r.ms);
    QJsonArray flags;
    if (r.fromCache) flags << QStringLiteral("cache");
    if (r.dimmed) flags << QStringLiteral("dimmed");
    if (!r.tappable) flags << QStringLiteral("not_tappable");
    if (r.verifying) flags << QStringLiteral("verifying");
    if (r.current) flags << QStringLiteral("current");
    if (!r.verified) flags << (r.current ? QStringLiteral("live_unverified") : QStringLiteral("unverified"));
    if (r.crowdWorks) flags << QStringLiteral("crowd");
    o.insert(QStringLiteral("flags"), flags);
    return o;
}

inline QJsonObject scanViewToJson(const ScanView &v)
{
    QJsonObject o;
    o.insert(QStringLiteral("phase"), QLatin1String(scanPhaseName(v.phase)));
    o.insert(QStringLiteral("hero"), v.hero);
    o.insert(QStringLiteral("stage"), QLatin1String(scanStageKeyName(v.stage)));
    o.insert(QStringLiteral("stage_count"), v.stageCount);
    o.insert(QStringLiteral("stage_total"), v.stageTotal);
    o.insert(QStringLiteral("progress"), qRound(v.progress * 100) / 100.0);
    o.insert(QStringLiteral("wait"), v.wait == ScanWaitKey::RowsAppearHere ? QStringLiteral("rows_appear_here")
                                     : v.wait == ScanWaitKey::SearchingMore ? QStringLiteral("searching_more")
                                                                            : QStringLiteral("none"));
    o.insert(QStringLiteral("wait_s"), v.waitSeconds);
    o.insert(QStringLiteral("checked_ago_min"), v.checkedAgoMin);
    QJsonArray rows;
    for (const ScanRowView &r : v.rows)
        rows << scanRowViewToJson(r);
    o.insert(QStringLiteral("rows"), rows);
    o.insert(QStringLiteral("verified"), v.verifiedCount);
    o.insert(QStringLiteral("unverified"), v.unverifiedCount);
    o.insert(QStringLiteral("more_available"), v.moreAvailable);
    o.insert(QStringLiteral("batch"), v.batch);
    o.insert(QStringLiteral("more_country"), v.moreCountry);
    if (!v.moreState.isEmpty())
        o.insert(QStringLiteral("more"), QJsonObject{{QStringLiteral("state"), v.moreState}, {QStringLiteral("batch"), v.batch},
                                                     {QStringLiteral("country"), v.moreCountry}});
    if (!v.netRadio.isEmpty())
        o.insert(QStringLiteral("net_radio"), v.netRadio);
    QJsonObject card;
    card.insert(QStringLiteral("mode"), QLatin1String(scanCardModeName(v.card.mode)));
    card.insert(QStringLiteral("button"), QLatin1String(scanCardButtonName(v.card.button)));
    if (v.card.reportQueueFull)
        card.insert(QStringLiteral("report_queue_full"), true);
    if (v.card.mode != ScanCardMode::Hidden && v.card.mode != ScanCardMode::Off) {
        card.insert(QStringLiteral("server"), scanFactViewToJson(v.card.server));
        card.insert(QStringLiteral("server_ms"), v.card.serverMs);
        card.insert(QStringLiteral("services"), scanFactViewToJson(v.card.services));
        card.insert(QStringLiteral("sites"), scanFactViewToJson(v.card.sites));
        if (v.card.speedVisible)
            card.insert(QStringLiteral("speed"), scanFactViewToJson(v.card.speed));
        if (v.card.progress >= 0)
            card.insert(QStringLiteral("progress"), qRound(v.card.progress * 100) / 100.0);
    }
    o.insert(QStringLiteral("card"), card);
    QJsonObject bar;
    bar.insert(QStringLiteral("menu_visible"), v.bar.menuVisible);
    bar.insert(QStringLiteral("menu_enabled"), v.bar.menuEnabled);
    bar.insert(QStringLiteral("selected"), v.bar.selected);
    QJsonArray countries;
    for (const ScanCountryView &c : v.bar.countries)
        countries << QJsonObject{{QStringLiteral("cc"), c.countryCode}, {QStringLiteral("count"), c.count}};
    bar.insert(QStringLiteral("countries"), countries);
    if (!v.bar.scopeCountries.isEmpty()) {
        QJsonArray scope;
        for (const ScanCountryView &c : v.bar.scopeCountries)
            scope << QJsonObject{{QStringLiteral("cc"), c.countryCode}, {QStringLiteral("count"), c.count}};
        bar.insert(QStringLiteral("scope_countries"), scope);
        bar.insert(QStringLiteral("scanned_scope"), v.bar.scannedScope);
    }
    if (v.bar.scopeWhitelist >= 0)
        bar.insert(QStringLiteral("scope_whitelist"), v.bar.scopeWhitelist);
    bar.insert(QStringLiteral("total"), v.bar.total);
    bar.insert(QStringLiteral("button"), QLatin1String(scanBarButtonName(v.bar.button)));
    bar.insert(QStringLiteral("button_enabled"), v.bar.buttonEnabled);
    bar.insert(QStringLiteral("button_value"), v.bar.buttonValue);
    bar.insert(QStringLiteral("hint"), QLatin1String(scanHintName(v.bar.hint)));
    o.insert(QStringLiteral("bar"), bar);
    QJsonObject empty;
    empty.insert(QStringLiteral("variant"), QLatin1String(scanEmptyVariantName(v.empty.variant)));
    if (!v.empty.reason.isEmpty())
        empty.insert(QStringLiteral("reason"), v.empty.reason);
    if (!v.empty.scopeCc.isEmpty())
        empty.insert(QStringLiteral("scope_cc"), v.empty.scopeCc);
    if (v.empty.reportSending)
        empty.insert(QStringLiteral("report_sending"), true);
    if (v.empty.reportLink)
        empty.insert(QStringLiteral("report_link"), true);
    o.insert(QStringLiteral("empty"), empty);
    o.insert(QStringLiteral("net"), QLatin1String(scanNetKindName(v.net)));
    return o;
}

// --- the coordinator's encoding of the host actions (secrets join here, never inside the machine) ---------

// configOf(candidate) = the exact config of an Xray probe (own Xray: XrayConfigBuilder::coreConfig, or its
// single outbound for a leg; provider full: the probe lease's sanitized config; provider leg: the
// projection's leg outbound + DNS plan); token = the manifest's scan token; probeBase = tunnel_api_base. Host
// ids are probe ids (scanProbeIdOf: "<id>#full" for a follow-up).
inline ScanHostCandidate scanHostCandidateOf(const ScanCandidate &c, const QString &config)
{
    ScanHostCandidate h;
    h.id = scanProbeIdOf(c);
    h.kind = c.kind;
    h.config = config;
    h.entryIp = c.entryIp;
    h.entryPort = c.entryPort;
    h.reachAtMs = c.hasReach() ? c.reachAtMs : -1;
    h.profileId = c.profileId;
    h.earlyRetry = c.origin == ScanOrigin::Upstream;
    h.dnsPlan = c.kind == ScanProbeKind::XrayLeg && c.origin == ScanOrigin::Upstream && c.dnsThroughLeg
                && c.dnsResolvers > 0;
    h.costBytes = c.costBytes;
    return h;
}

// Every candidate's config from configOf as given (the form of 3c1f55a5e; an awg_mini config is passed
// through unchecked - use the typed overload below for AmneziaWG sessions).
template <typename ConfigOf>
inline QList<ScanHostCandidate> scanBuildHostCandidates(const QList<ScanCandidate> &cands, ConfigOf configOf)
{
    QList<ScanHostCandidate> out;
    for (const ScanCandidate &c : cands)
        out << scanHostCandidateOf(c, configOf(c));
    return out;
}

// The typed form: Xray probes from configOf; an awg_mini session from awgOf(candidate) -> ScanAwgMiniInput
// through scanAwgMiniConfig (the contract's exact config; the candidate's echo target fills an empty one).
// A candidate whose config cannot be built (an awg_mini without the device's address, a bad key, an empty
// Xray config) is NOT emitted: its probe id and reason go to *refused - report each with
// ScanMachine::candidateRefused so the row ends «Не проверено».
template <typename ConfigOf, typename AwgOf>
inline QList<ScanHostCandidate> scanBuildHostCandidates(const QList<ScanCandidate> &cands, ConfigOf configOf, AwgOf awgOf,
                                                        QList<QPair<QString, QString>> *refused)
{
    QList<ScanHostCandidate> out;
    for (const ScanCandidate &c : cands) {
        QString config;
        QString why = QStringLiteral("config");
        if (c.kind == ScanProbeKind::AwgMini) {
            ScanAwgMiniInput in = awgOf(c);
            if (in.echoTarget.isEmpty())
                in.echoTarget = c.awgEchoTarget;
            config = scanAwgMiniConfig(in, &why);
        } else {
            config = configOf(c);
        }
        if (config.isEmpty()) {
            if (refused)
                *refused << qMakePair(scanProbeIdOf(c), why);
            continue;
        }
        out << scanHostCandidateOf(c, config);
    }
    return out;
}

inline ScanStartRequest scanStartRequestOf(const ScanAction &a, const QString &token, const QString &probeBase, const ScanAccess &access,
                                           const QList<ScanHostCandidate> &cands)
{
    ScanStartRequest r;
    r.scanId = a.scanId;
    r.deadlineMs = a.deadlineMs;
    r.maxBytes = a.maxBytes;
    r.limits = a.limits;
    r.probeBase = probeBase;
    r.token = token;
    r.warmBytes = a.warmBytes;
    r.bytes = a.bytes;
    r.access = access;
    r.probeBaseIps = a.baseIps;
    r.candidates = cands;
    return r;
}

template <typename ConfigOf>
inline ScanStartRequest scanBuildStartRequest(const ScanAction &a, const QString &token, const QString &probeBase,
                                              const ScanAccess &access, ConfigOf configOf)
{
    return scanStartRequestOf(a, token, probeBase, access, scanBuildHostCandidates(a.candidates, configOf));
}

template <typename ConfigOf, typename AwgOf>
inline ScanStartRequest scanBuildStartRequest(const ScanAction &a, const QString &token, const QString &probeBase,
                                              const ScanAccess &access, ConfigOf configOf, AwgOf awgOf,
                                              QList<QPair<QString, QString>> *refused)
{
    return scanStartRequestOf(a, token, probeBase, access, scanBuildHostCandidates(a.candidates, configOf, awgOf, refused));
}

} // namespace avpn
