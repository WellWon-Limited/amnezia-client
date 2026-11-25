// service/server/tribe_scan.h
// AVPN (Scanner) - the desktop probe host inside the root service (macOS first; the same code serves
// Windows). Plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md §2.2-§2.2c, §2.4, §2.6, §2.11a,
// risk R6; contract client/core/serviceEngine/ScanHostContract.h (tribe-scan-v1).
//
// What it does:
//  - Relays the six tribe-scan-v1 actions (scan_caps, scan_start, scan_add, scan_poll, scan_freeze,
//    scan_cancel) to the Go engine of the bindings (amnezia_xray_scan_message, ABI
//    libxray-tribe-scan-v1, recipes/amnezia-xray-bindings/README.md) on ONE worker thread: the QtRO slot
//    only queues (ipc/ipc_scan_interface.rep scanSubmit), the reply goes back through the scanReply
//    signal. Request bytes reach the engine unchanged and reply bytes come back unchanged (caps, items,
//    byte totals and the final flag included); the service answers by itself only what never reaches
//    the engine: a message that is not a JSON object (bad_request/json), an action outside the six
//    (unknown_action), a scan_start over its rate (rate_limited) or without a physical uplink.
//  - Passes the physical uplink in host_options (bind_interface_index + bind_interface): every probe
//    socket is bound in Go to that interface and never passes the tunnel's socket callback
//    (amnezia_xray_setsockcallback, service/server/xray.cpp) - this file never calls it. No physical
//    uplink (none, or a virtual interface such as a foreign VPN's utun owns the default route) = the
//    contract's refusal {"error":"bad_request","detail":"host_options.bind_interface"} without asking
//    the engine.
//  - Owns the service's element of the Scanner's strict generation tuple (ScanNetworkGeneration.h,
//    source "service"): a random 64-bit epoch per service start and a counter bumped when the physical
//    uplink changes (index, name, default gateway, address set - a local hash, never logged or sent) or
//    is interrupted. Fed by a read-only PF_ROUTE listener on macOS, by the service's NetworkWatcher and
//    by a fresh sample at every scan_start / scan_poll (both platforms). Published as the QtRO property
//    scanGeneration, and passed to the engine as host_options.gen with EVERY message: the engine stamps
//    it into the progress "gen" and into each access attempt's "gen" (README of the bindings), so the
//    reply bytes stay the engine's own.
//  - Ends every scan (amnezia_xray_scan_stop_all, reason tunnel_stopped) before any tunnel start / stop /
//    kill-switch change the service performs (ipc/ipcserver.cpp, client/daemon/daemon.cpp through
//    tribeScanBeforeTunnelChange) and on service shutdown.
//  - macOS kill switch (R6): while a scan runs and the service's pf root anchor is loaded, a
//    group-scoped pass for the service's own sockets on the uplink (MacOSFirewall::scanExemptionRules,
//    anchor tribe/160.allowScan): user applications never match it (they do not run with the service's
//    group). Removed when the scan ends (final reply, stop-all, deadline + grace, shutdown) and at service
//    start (crash recovery). Fail-closed: when the kill switch is ours but the exemption cannot be
//    loaded, scan_start is refused ({"error":"internal","detail":"kill_switch_exemption"}).
//  - macOS routes of the pinned sockets (round mac-C, 25.11.2026): a socket pinned to the uplink (IP_BOUND_IF) is
//    routed only by routes scoped to that interface, or by the primary default when no more specific route of
//    another interface covers the destination. An AmneziaWG session's 0/1 + 128/1 via its utun cover all of IPv4,
//    so every pinned probe failed at once with ENETUNREACH, before pf ever saw a packet (`route get -ifscope en0`
//    "not in table"; the scan ended in 0.3 s with nothing found). An Xray session never had this: it installs the
//    same pair scoped to the uplink for its own pinned core sockets (RouterMac::routeAddXray, upstream #2479), and
//    with the VPN off nothing hides the primary default. So the host adds that pair - 0/1 and 128/1 via the
//    uplink's IPv4 router, scoped to the uplink - for the scan's lifetime, only when a socket pinned to the uplink
//    has no route through the table (tribeScanHalvesNeeded), and deletes exactly what it added: with the pf
//    exemption (every end of a scan), when the uplink changes under it, and at service start (crash recovery).
//    Ownership is an intent log in a root-owned file next to the pf token (kTribeScanRoutesRecord; the kernel keeps
//    no mark of who added a route - RTF_PROTO3 is not stored): written durably before an add, trimmed after a
//    delete (protocol at tribeScanArmHalfRoutes). A route it found (an Xray session's) is never touched. Then every
//    candidate's entry address must have a pinned route: a scan never probes a target it cannot reach, which the
//    app would store as "not working" (review N2). Needed but not in force = the no-uplink refusal
//    (host_options.bind_interface). Scoped routes serve pinned lookups only; under the kill switch a user's pinned
//    socket still meets pf on the uplink, which passes DNS only through the tunnel (macospfanchors.h dnsSessionRules).
//
// What it never does: start, stop or reconfigure a tunnel; register a socket callback; log a request, a
// reply, a config, a token, a host, an address or an interface name (only ids, codes and sizes); retry.
//
// Security (no new capability): the IPC socket and its peer policy are the existing ones
// (service/server/localserver.cpp: world-accessible, no peer validation - exactly like xrayStart, which
// already runs any Xray JSON as root). A scan message cannot give a local process a data path (probe
// instances have no inbound) and is bounded: size, rate, queue, known actions only.
//
// AmneziaWG mini-probes (awg_mini): the engine spawns `<service dir>/amneziawg-go probe` per session
// (protocol tribe-awg-probe-v1) when host_options name the binary (awg_probe_binary, read by scan_caps
// and scan_start). The service names it only when (1) the file next to the service is a regular,
// root-owned, not group/world-writable executable and answers `probe --abi` with tribe-awg-probe-v1, and
// (2) the live AmneziaWG tunnel's peer is known: with a tunnel up its peer goes along as awg_live_peer
// {public_key, endpoint} so the engine refuses that node; a tunnel up with an unknown peer, an unknown
// daemon state, or a tunnel change between the app's message and the engine call = no binary (no
// awg_mini rather than a probe that might hit the live node). The child inherits the service's group,
// so the pf exemption covers its UDP too.
//
// Upstream Amnezia has no counterpart. Tests: service/server/tests/build_tribe_scan.sh.
#pragma once

#include <QByteArray>
#include <QList>
#include <QMutex>
#include <QString>
#include <QStringList>

#include <atomic>
#include <functional>

#include "core/serviceEngine/ScanNetworkGeneration.h"
#include "rep_ipc_scan_interface_source.h"

class QObject;
class QSocketNotifier;
class QThread;

namespace avpn {

// --- limits -------------------------------------------------------------------------------------------------

inline constexpr int kTribeScanIpcVersion = 1;
// One message: a scan_start with every own node (tens of KiB each) or a scan_add with up to 12 provider
// profiles (<= 256 KiB each, spec D3) stays far below this.
inline constexpr qsizetype kTribeScanMaxMessageBytes = 8 * 1024 * 1024;
inline constexpr int kTribeScanMaxPending = 16;           // queued + in the engine
inline constexpr qint64 kTribeScanRateWindowMs = 1000;    // every message (poll period >= 100 ms)
inline constexpr int kTribeScanRateMax = 40;
inline constexpr qint64 kTribeScanStartWindowMs = 10000;  // scan_start (each builds new probe cores)
inline constexpr int kTribeScanStartMax = 6;
// Before a tunnel change: the engine's stop gets this long, then every probe child still alive is killed
// and waited for (kTribeScanChildDeathMs); the hook's own bound is their sum (kTribeScanTunnelHookCapMs) plus a
// pf flush, and at most one in-flight scan_start in front of it (a replacing start waits up to 3 s).
inline constexpr int kTribeScanStopBeforeTunnelMs = 2000;
inline constexpr int kTribeScanChildDeathMs = 2000; // after SIGKILL, per teardown (all children together)
inline constexpr int kTribeScanTunnelHookCapMs = kTribeScanStopBeforeTunnelMs + kTribeScanChildDeathMs; // 4 s
inline constexpr int kTribeScanStopOnQuitMs = 2000;
inline constexpr int kTribeScanStopForAppMs = 500;        // scanStopAll from the app
inline constexpr qint64 kTribeScanDisarmGraceMs = 5000;   // pf exemption outlives deadline_ms by this

// IPC answers of scanSubmit (ipc_scan_interface.rep).
enum class TribeScanSubmit : int { Accepted = 0, TooLarge = 1, RateLimited = 2, QueueFull = 3, ShuttingDown = 4 };

// --- pure parts (unit-tested) ---------------------------------------------------------------------------------

// Sliding window over a monotonic clock in ms: admit() records the event when it is admitted.
class TribeScanRateWindow
{
public:
    TribeScanRateWindow(qint64 windowMs, int max) : m_windowMs(windowMs), m_max(max) {}
    bool admit(qint64 nowMs);

private:
    qint64 m_windowMs;
    int m_max;
    QList<qint64> m_events;
};

// The default-route interface as the service sees it now.
struct TribeScanUplink {
    QString name;
    int index = 0;
    QString gateway;
    QStringList addresses; // the interface's IP addresses
    bool up = false;       // IsUp and IsRunning
    bool loopback = false;
    bool virtualType = false; // QNetworkInterface::Virtual (wintun, wireguard-nt, utun where Qt says so)
    bool unreadable = false;  // the route table could not be read: the uplink is unknown - never a path fact
};

// utun / ipsec / ppp / gif / stf / bridge / awdl / llw (the list of macosroutemonitor.cpp isVirtualIfname).
bool tribeScanIsVirtualIfname(const QString &name);
// A physical uplink probes may bind to.
bool tribeScanUplinkUsable(const TribeScanUplink &u);
// Local hash of the path facts (index, name, gateway, sorted addresses); "" when not usable.
QByteArray tribeScanUplinkFingerprint(const TribeScanUplink &u);
// The element as the wire carries it (the scanGeneration property; host_options.gen).
QByteArray tribeScanGenerationJson(const ScanNetSource &g);

inline constexpr char kTribeAwgProbeAbi[] = "tribe-awg-probe-v1";
inline constexpr int kTribeAwgProbeCheckMs = 2000;

// The live AmneziaWG tunnel of the service's daemon, as seen on the main thread when the app's message
// arrived. state: -1 = cannot be told (no daemon object), 0 = no tunnel, 1 = a tunnel is up.
struct TribeScanAwgLive {
    int state = -1;
    QString publicKey; // base64 or hex
    QString endpoint;  // "ip:port"
};

// What a message may carry for awg_mini: the binary and, with a live tunnel, its peer. `binary` = the
// checked probe binary ("" = none); `stale` = a tunnel change happened after `live` was taken.
struct TribeScanAwgOptions {
    QString binary;      // "" = no awg_probe_binary
    QString livePeerKey; // with a live tunnel: at least one of the two
    QString livePeerEndpoint;
    bool livePeer = false;
    // Why awg_mini is not offered although the probe binary is there: "awg_live_peer_unknown" (a tunnel is
    // up and its peer cannot be told, or the daemon's state cannot be read); "" otherwise.
    QString unavailable;
};
inline constexpr char kTribeAwgLivePeerUnknown[] = "awg_live_peer_unknown";

// The one host-only addition the service makes to an engine reply: "awg_unavailable": <reason> in a
// scan_caps reply (ignored by decoders that do not know it). Returns the reply untouched when `reason` is
// empty or the reply is not scan_caps.
QByteArray tribeScanAddAwgUnavailable(const QByteArray &capsReply, const QString &reason);
TribeScanAwgOptions tribeScanAwgDecide(const QString &binary, const TribeScanAwgLive &live, bool stale);

// The probe binary check: `path` is a regular executable file (not a symlink), owned by root and not
// writable by group or others when `requireRootOwned`, and `path probe --abi` prints
// tribe-awg-probe-v1 within `timeoutMs`. Returns `path`, or "" (an older binary prints its usage).
QString tribeScanCheckAwgProbeBinary(const QString &path, bool requireRootOwned, int timeoutMs = kTribeAwgProbeCheckMs);

// host_options of one message: "gen" always; for scan_start also the uplink to bind to,
// {"bind_interface_index":n} plus "bind_interface" when the name is a plain BSD name
// ([A-Za-z0-9]{1,15}; a Windows friendly name is not - the index alone is used there); for scan_caps and
// scan_start the awg_mini options (`awg`, may be null): "awg_probe_binary", and on scan_start
// "awg_live_peer" {"public_key", "endpoint"} (present fields only).
// "host_epoch" (>= 0): the service's tunnel-change count the message belongs to (the engine refuses a start
// older than its last stop as stale_epoch).
QByteArray tribeScanHostOptions(const ScanNetSource &gen, const TribeScanUplink *bindTo = nullptr,
                                const TribeScanAwgOptions *awg = nullptr, qint64 hostEpoch = -1);

// The service's element of the strict generation tuple.
class TribeScanGeneration
{
public:
    explicit TribeScanGeneration(quint64 epoch) : m_epoch(epoch) {}
    // One sample of the uplink fingerprint ("" = no usable uplink, itself a path state). The first
    // sample sets the baseline; later the counter grows when the fingerprint differs or `loss` is set
    // (the monitor saw the path interrupted). true = the counter moved.
    bool observe(const QByteArray &fingerprint, bool loss);
    ScanNetSource now() const;

private:
    quint64 m_epoch;
    qint64 m_counter = 0;
    bool m_haveBaseline = false;
    QByteArray m_fingerprint;
};

// The few request facts the service acts on (it never trusts more than this).
struct TribeScanRequestInfo {
    bool object = false; // a JSON object
    QString action;
    QString scanId;
    qint64 deadlineMs = -1;
    bool hasAwgMini = false; // a candidate of kind awg_mini (scan_start / scan_add)
    QList<quint32> entryIps; // the IPv4 entry addresses of the candidates (host order; others are not listed)
};
TribeScanRequestInfo tribeScanInspectRequest(const QByteArray &message);
bool tribeScanKnownAction(const QString &action);

struct TribeScanReplyInfo {
    QString type;  // scan_caps | scan_ack | scan_progress | scan_freeze_ack | "" (error or not JSON)
    QString error; // the error code of an error reply
    QString scanId;
    bool finalTotals = false; // "final": true
};
TribeScanReplyInfo tribeScanInspectReply(const QByteArray &reply);

// One PF_ROUTE message (macOS): `resample` = worth a fresh uplink sample; `loss` = the current uplink
// (index) lost its default route, an address or its link. Cloned and host routes are ignored, and so are the
// scoped half routes this process writes itself (ownPid: the scan's, an Xray session's routeAddXray): its own
// plumbing is no path fact - the delete at a scan's end read as a loss and moved the generation twice after every
// scan under AmneziaWG (test Mac 25.11: the rows just found turned stale).
struct TribeScanRouteEvent {
    bool resample = false;
    bool loss = false;
};
TribeScanRouteEvent tribeScanRouteEvent(const char *msg, qsizetype len, int uplinkIndex, qint64 ownPid = -1);

// --- the uplink's half routes for pinned probe sockets (macOS; see the header comment) ---------------------------

// One of the pair: dst 0.0.0.0/1 or 128.0.0.0/1 via `gateway`, scoped to `ifindex`. Addresses in host order.
struct TribeScanHalfRoute {
    quint32 dst = 0;
    quint32 gateway = 0;
    int ifindex = 0;
    bool operator==(const TribeScanHalfRoute &o) const { return dst == o.dst && gateway == o.gateway && ifindex == o.ifindex; }
};
inline constexpr quint32 kTribeScanHalfLow = 0x00000000u;  // 0.0.0.0/1
inline constexpr quint32 kTribeScanHalfHigh = 0x80000000u; // 128.0.0.0/1
// A destination in each half the kernel is asked about after an arm (a pinned UDP connect: no packet is sent).
inline constexpr quint32 kTribeScanTestLow = 0x01010101u;  // 1.1.1.1
inline constexpr quint32 kTribeScanTestHigh = 0xC0000201u; // 192.0.2.1 (TEST-NET-1)

// Which half a socket pinned to the uplink cannot reach through the routing table (review N2, round mac-C: one sample
// address per half decided for the whole half, and an AmneziaWG exclusion such as 1.1.1.1/32 via the uplink made the
// low half look routed while every other address of it stayed hidden). Read from the table itself: a half is NEEDED
// when an unscoped route of ANOTHER interface lies in it (an AmneziaWG 0/1 via its utun, a VPN's finer split, a static
// host route into a tunnel) - such a route hides the primary default from pinned lookups for its addresses - and no
// route scoped to the uplink covers the whole half (0/1 or 128/1 with RTF_IFSCOPE on the uplink: an Xray session's
// pair, or ours). Ignored: defaults, cloned and link-layer entries, and the special ranges a probe never dials
// (127/8, 169.254/16, 224/4 and above).
struct TribeScanHalfNeed {
    bool low = false;
    bool high = false;
    bool any() const { return low || high; }
};
TribeScanHalfNeed tribeScanHalvesNeeded(const QByteArray &dump, int uplinkIndex);
// From the same dump: the scoped half routes on any interface (dst 0/1 or 128/1, RTF_IFSCOPE, an IPv4 gateway).
QList<TribeScanHalfRoute> tribeScanScopedHalfRoutes(const QByteArray &dump);
// From the same dump: the IPv4 router of the default route on `ifindex` (0 = none).
quint32 tribeScanDefaultRouter(const QByteArray &dump, int ifindex);
// From the same dump: the primary IPv4 default route (dst 0, mask 0, an IPv4 gateway, not scoped) - the uplink the
// probes bind to; a scoped default only when there is no primary one; ifindex 0 = none. A /1 is no default.
struct TribeScanDefaultRoute {
    int ifindex = 0;
    quint32 gateway = 0;
};
TribeScanDefaultRoute tribeScanPrimaryDefault(const QByteArray &dump);

struct TribeScanRouteArm {
    int result = 0;                  // 1 = added, 0 = not needed (pinned sockets route through the table), -1 = needed, not in force
    QList<TribeScanHalfRoute> added; // what this arm added, never a route it found
};
// The kernel and the disk as the half routes see them. pinned(ifindex, dst) = a socket pinned to ifindex has a route to
// dst; write(add, route) = 0 on success, else errno (EEXIST on add: a route is there - never ours; ESRCH on delete: it
// is gone); table() = the AF_INET route table (NET_RT_DUMP); recordRead / recordWrite = the ownership record
// (recordWrite("") removes it; true only once the bytes are durable).
struct TribeScanRouteOps {
    std::function<bool(int ifindex, quint32 dst)> pinned;
    std::function<int(bool add, const TribeScanHalfRoute &r)> write;
    std::function<QByteArray()> table;
    std::function<QByteArray()> recordRead;
    std::function<bool(const QByteArray &bytes)> recordWrite;
};
// The ownership record is an intent log (review N3): it names every half route this host has added or is about to
// add, and nothing else. Protocol:
//   arm     - recover first (below); read the table; nothing needed -> nothing written. Else record += the routes to
//             add (durable BEFORE the first RTM_ADD - no record, no add), add each (EEXIST: someone else's -> record -=
//             it), check the table and a pinned lookup per half; any failure removes what was added and answers -1;
//   remove  - delete each route; record -= the ones deleted or already gone (ESRCH); a failed delete stays recorded
//             and is retried by the next recover;
//   recover - at service start and before each arm: for each recorded route, the live table decides - absent: gone
//             (a reboot, a removal) -> forgotten; present scoped to the same interface but via another gateway:
//             someone else's now -> forgotten, never deleted; present as recorded: ours -> deleted.
// A kill between any two steps leaves the record a superset of what is ours in the kernel, and recover removes it.
// Residual: a route someone else adds in the instant between our table read and our RTM_ADD gets EEXIST and is
// dropped from the record - but if the service dies inside that same instant the record still names it, and a later
// recover could delete it while its gateway is unchanged.
TribeScanRouteArm tribeScanArmHalfRoutes(const TribeScanUplink &u, quint32 router, const TribeScanRouteOps &ops);
// Returns the routes that could not be deleted (they stay in the record).
QList<TribeScanHalfRoute> tribeScanRemoveHalfRoutes(const QList<TribeScanHalfRoute> &routes, const TribeScanRouteOps &ops);
// Returns how many recorded routes were deleted.
int tribeScanRecoverHalfRoutes(const TribeScanRouteOps &ops);
// The routing-socket message of an RTM_ADD (add) or RTM_DELETE of one half route: RTA_DST, RTA_GATEWAY, RTA_NETMASK,
// RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_IFSCOPE, rtm_index = the scope. "" outside macOS.
QByteArray tribeScanHalfRouteMessage(bool add, const TribeScanHalfRoute &r, int seq);
// The record (one line each, "half <dst> <gateway> <ifindex>" in hex/decimal); parse keeps only well-formed half routes.
inline constexpr char kTribeScanRoutesRecord[] = "/Library/Application Support/TribeVPN/scan/uplink-routes";
QByteArray tribeScanHalfRoutesRecord(const QList<TribeScanHalfRoute> &routes);
QList<TribeScanHalfRoute> tribeScanParseHalfRoutesRecord(const QByteArray &record);

// The probe children of this process (macOS; the engine spawns `<binary> probe` per AmneziaWG session):
//  - tribeScanParseProcArgs: argv from a KERN_PROCARGS2 buffer (argc, exec path, padding, argv...);
//  - tribeScanIsProbeChild: exactly `<binaryPath> probe` - never the live tunnel's `<binary> -f utun`;
//  - tribeScanKillProbeChildren: SIGKILL every such direct child and wait up to `deathWaitMs` until each one
//    is dead (gone, or a zombie: no fd, no packet). The engine that spawned it reaps it (its exec.Cmd waits);
//    reaping it here could free the pid while the engine still holds it, and a later kill from the engine
//    could then hit an unrelated process. Returns the number killed; -1 = some did not die in time.
QStringList tribeScanParseProcArgs(const QByteArray &procargs2);
bool tribeScanIsProbeChild(const QString &exePath, const QStringList &argv, const QString &binaryPath);
QList<qint64> tribeScanProbeChildPids(const QString &binaryPath); // alive or zombie: `<binaryPath> probe` children
struct TribeScanKillResult {
    int killed = 0; // SIGKILL sent
    int alive = 0;  // of those, not dead (gone or zombie) when the wait ended - cannot normally happen
};
TribeScanKillResult tribeScanKillProbeChildren(const QString &binaryPath, int deathWaitMs = kTribeScanChildDeathMs);
// The wait of tribeScanKillProbeChildren (pure: the clock, the death test and the pause are given): returns
// how many of `pids` are still not dead once all are or `waitMs` passed on `clockMs`.
int tribeScanAwaitDeath(const QList<qint64> &pids, int waitMs, const std::function<bool(qint64 pid)> &dead,
                        const std::function<qint64()> &clockMs, const std::function<void()> &pause);

// The engine's answer to the epoch stop: stopped, and what it reports still live (every numeric field of the
// reply besides "stopped", "k=v ..." sorted; "" = it reports none). The engine answers {"stopped":true} exactly, or
// {"stopped":false,"instances":n,"jobs":n,"closers":n,"attempts":n,"awg":n,"children":n} - flat top-level
// numbers, no nested object (amnezia-libxray 0012 StopAllJSON).
struct TribeScanStopResult {
    bool stopped = false;
    QString live;
};
TribeScanStopResult tribeScanParseStopReply(const QByteArray &reply);

// --- what the host runs on ---------------------------------------------------------------------------------------

struct TribeScanDeps {
    // The engine (amnezia_xray_scan_message in production). stopAll = the host-only message
    // {"action":"scan_stop_all","wait_ms":n} with {"host_epoch":E}: true = nothing of any scan is alive
    // (instances, jobs, probe children killed and reaped, access attempts); the engine refuses starts / adds
    // with a lower host_epoch afterwards (stale_epoch).
    std::function<QByteArray(const QByteArray &message, const QByteArray &hostOptions)> message;
    std::function<TribeScanStopResult(int waitMs, qint64 hostEpoch)> stopAll;
    std::function<TribeScanUplink()> uplink;
    // The scan-lifetime kill-switch exemption (macOS pf; no-ops elsewhere). arm: 1 = armed, 0 = not
    // needed (no kill switch of ours), -1 = needed but failed - the scan is then refused, because probes
    // into a blocking kill switch would read as unreachable nodes and, for the direct access attempts, as
    // "the access network cannot reach the probe host" (false exclusion evidence, plan §2.2c, §2.8).
    std::function<int(const QString &ifname)> armFirewall;
    std::function<void()> disarmFirewall;
    // The uplink's half routes for the pinned probe sockets (macOS; nothing elsewhere): armRoutes adds them where a
    // socket pinned to the uplink has no route and tells what it added; disarmRoutes deletes exactly those;
    // clearLeftoverRoutes deletes the recorded ones a previous service instance left (it died mid-scan). Any thread.
    std::function<TribeScanRouteArm(const TribeScanUplink &u)> armRoutes;
    std::function<void(const QList<TribeScanHalfRoute> &added)> disarmRoutes;
    std::function<void()> clearLeftoverRoutes;
    // A socket pinned to the uplink has a route to this IPv4 target (review N2: checked for every candidate's entry
    // before the engine gets the scan - a target the scan cannot route to would be stored as "not working").
    std::function<bool(int ifindex, quint32 dst)> pinnedRoute;
    // awg_mini: the checked probe binary ("" = none; worker thread) and the live AmneziaWG tunnel (main
    // thread, at the arrival of each message).
    std::function<QString()> awgProbeBinary;
    std::function<TribeScanAwgLive()> awgLive;
    // The belt after a stop the engine did not confirm: kills the engine's probe children
    // (tribeScanKillProbeChildren on the service's amneziawg-go) and waits for their death. Never called after
    // a confirmed stop (the engine killed and reaped them itself). Any thread.
    std::function<TribeScanKillResult()> killProbeChildren;
    bool routeMonitor = true; // the macOS PF_ROUTE listener
};

// The daemon's live tunnel (client/daemon/daemon.cpp): -1 = no daemon object, 0 = no tunnel, 1 = up.
int tribeScanDaemonLivePeer(QString *publicKey, QString *endpoint);

// Production dependencies: the bindings, NetworkUtilities::getGatewayAndIface, MacOSFirewall.
TribeScanDeps tribeScanServiceDeps();

// The QtRO source of IpcScanInterface; lives on the service's main thread.
class TribeScanHost : public IpcScanInterfaceSimpleSource
{
public:
    explicit TribeScanHost(TribeScanDeps deps, QObject *parent = nullptr);
    ~TribeScanHost() override;

    int scanSubmit(quint64 requestId, const QString &message) override;
    int scanStopAll() override;

    // Decision (coordinator, 16.11): connecting has priority - a tunnel change is never held by the Scanner
    // beyond this hook's bound. Within the bound the engine's epoch stop gets kTribeScanStopBeforeTunnelMs; if
    // it does not confirm, the AmneziaWG probe children (the only thing that talks to a node's AWG peer) are
    // SIGKILLed and the hook waits until each one is confirmed dead (gone or zombie, kTribeScanChildDeathMs).
    // On return - confirmed or not - the probe children are dead (a child still alive after SIGKILL and the
    // whole wait cannot normally happen: it is journaled and the hook still returns), the pf exemption is gone,
    // and the engine refuses new starts (internal/stopping while its teardown runs, stale_epoch for anything
    // queued before). What may remain for milliseconds are closing in-process Xray probe instances: separate
    // core instances bound to the physical uplink, sharing nothing with the tunnel core, never passing its
    // socket callback. A timed-out stop leaves one journal line with what was left (engine live counts as far
    // as the engine reports them, children killed / alive, exemption removed) and refuses new scans
    // (teardown_pending) until the engine confirms. Hard cap: kTribeScanTunnelHookCapMs (4 s) plus a pf flush,
    // after at most one in-flight scan_start (a replacing start waits up to 3 s).
    //
    // Ends every scan before the service changes a tunnel, and returns only when nothing of it can send:
    // under the start mutex (no scan_start / scan_add in between) the tunnel-change count moves - so every
    // start or add queued before is answered tunnel_changed and never reaches the engine - the engine stops
    // (kTribeScanStopBeforeTunnelMs), every probe child is killed and dead, the pf exemption is gone. A stop the
    // engine does not confirm refuses new scans (teardown_pending) until it does. Instant when no scan ever
    // ran; bounded otherwise (kTribeScanTunnelHookCapMs + a pf flush, after an in-flight start). Main thread.
    void stopAllBeforeTunnelChange(const char *reason);
    // aboutToQuit: no more messages, stop-all, exemption removed, worker joined.
    void shutdown();

    // A path event from outside (the service's NetworkWatcher: networkChanged, or wakeup = `loss`: the
    // path was down during the sleep).
    void notePathEvent(bool loss);

    // Test seam: the ms clock (monotonic in production).
    void setClockForTest(std::function<qint64()> clock) { m_clock = std::move(clock); }
    // Test seam: how the exemption's deadline is armed (default: a precise single-shot timer on the main
    // thread); `fire` removes that scan's exemption if it is still the active one. Main thread.
    using DisarmTimer = std::function<void(qint64 afterMs, std::function<void()> fire)>;
    void setDisarmTimerForTest(DisarmTimer t) { m_disarmTimer = std::move(t); }

private:
    struct Active {
        QString scanId;
        quint64 serial = 0;
        bool armed = false;
        QList<TribeScanHalfRoute> routes; // the half routes this scan added
        int uplinkIndex = 0;              // the uplink its probes are pinned to
    };

    // worker thread; `live` / `tunnelChanges` as they were when the message arrived (main thread)
    QByteArray process(const QByteArray &message, const TribeScanAwgLive &live, quint64 tunnelChanges);
    void sample(const TribeScanUplink &up, bool loss);             // any thread
    void publishGeneration(const ScanNetSource &g);                // any thread -> main
    // The active scan ends ("" = whichever is active); its exemption and its half routes are removed. Any thread.
    bool endActive(const QString &scanId, const char *why); // true = an exemption was removed
    // The uplink moved: the active scan's half routes lead to a router it may no longer have - they go now (the
    // scan itself is ended by the app, its generation moved too). Any thread.
    void dropRoutes(const char *why);
    // How many of the request's entry addresses a socket pinned to `uplinkIndex` cannot reach (review N2). Any thread.
    int unroutedTargets(const TribeScanRequestInfo &req, int uplinkIndex) const;
    void scheduleDisarm(quint64 serial, qint64 afterMs);           // any thread -> main
    void readRouteSocket();                                        // main thread (macOS)
    // The engine stops (waitMs), probe children die, the exemption goes; a stop the engine does not confirm
    // sets m_teardownPending. The caller holds m_startMutex. Any thread.
    bool teardown(const char *reason, int waitMs);
    qint64 nowMs() const;

    TribeScanDeps m_deps;
    std::function<qint64()> m_clock;
    DisarmTimer m_disarmTimer; // main thread
    QThread *m_thread = nullptr;
    QObject *m_workerContext = nullptr; // lives in m_thread
    std::atomic<int> m_pending{0};
    std::atomic<bool> m_shuttingDown{false};
    std::atomic<bool> m_everStarted{false};
    // Tunnel changes seen by stopAllBeforeTunnelChange; m_startMutex makes "no change since the message
    // arrived" and the engine's scan_start one step against a concurrent change.
    QMutex m_startMutex;
    std::atomic<quint64> m_tunnelChanges{0};
    bool m_teardownPending = false;          // guarded by m_startMutex
    std::atomic<bool> m_stopAllQueued{false}; // one pending app stop-all covers repeated calls
    TribeScanRateWindow m_rate{kTribeScanRateWindowMs, kTribeScanRateMax};             // main thread
    TribeScanRateWindow m_startRate{kTribeScanStartWindowMs, kTribeScanStartMax};      // worker thread

    // m_fwMutex serializes every exemption change with the active-scan record it belongs to (taken
    // before m_mutex); m_mutex guards m_gen, m_active, m_serial, m_lastUplinkIndex, m_published.
    QMutex m_fwMutex;
    mutable QMutex m_mutex;
    TribeScanGeneration m_gen;
    Active m_active;
    quint64 m_serial = 0;
    int m_lastUplinkIndex = 0;
    ScanNetSource m_published;
    bool m_havePublished = false;

    int m_routeSocket = -1;
    QSocketNotifier *m_routeNotifier = nullptr;
};

// For code outside the IPC server that changes a tunnel (client/daemon/daemon.cpp): ends every scan of
// the service's host, if one exists. Main thread.
void tribeScanBeforeTunnelChange(const char *reason);

} // namespace avpn
