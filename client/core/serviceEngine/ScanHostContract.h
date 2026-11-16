// client/core/serviceEngine/ScanHostContract.h
// AVPN serviceEngine - the probe host contract `tribe-scan-v1`: one JSON schema for the iOS tunnel
// extension (messages on the existing {"action": ...} channel) and the macOS root service (QtRO slots
// scanStart/scanPoll/scanCancel carrying the same JSON). C++ encode/decode of every message.
// [header-only, QtCore; pure]
//
// Plan scanner-client-plan.md §2.2-§2.4. The host only EXECUTES probes and reports facts; every decision
// (which candidates, when to stop, the class of a result, budgets, leases) stays in the app process
// (ScanPlan.h, ScanClass.h, ScanMachine.h). Shared vectors: tests/vectors/scan_host_vectors.json (the Go
// probe engine and the Swift bridge replay them; tests/scan_vectors_check.cpp keeps them equal to this
// code).
//
// ---- requests (app -> host); each is one JSON object -------------------------------------------------
//  {"action":"scan_caps"}
//  {"action":"scan_start", "version":"tribe-scan-v1", "scan_id":S, "deadline_ms":int, "max_bytes":int|null,
//   "limits":{"stage1_sockets", "stage1_stagger_ms", "per_entry_ip", "entry_ip_spacing_ms", "stage1_timeout_ms",
//             "concurrency" (xray_full), "leg_concurrency" (xray_leg), "awg_concurrency" (awg_mini),
//             "ttfb_ms", "stall_ms", "stall_after_bytes", "total_ms", "awg_handshake_ms", "awg_prime_echoes",
//             "awg_spacing_ms", "netinfo_cost_bytes"} (all int; a pool the host does not have gets 0),
//   "probe":{"base":url, "path":"/v1/probe", "netinfo_path":"/v1/netinfo", "token":SECRET, "warm_bytes":int,
//            "bytes":int, "access_asn":int|null, "access_net_token":str|null,
//            "base_ips":[ip] (optional, 1..8 IP literals of the base's host: dialled in order with the host name
//            as TLS name and Host, so the host needs no DNS; absent = the host resolves the name, and a DNS
//            failure of an access attempt is "not attempted")},
//   "candidates":[CAND]}                                          (candidates may be empty: scan_add follows)
//  {"action":"scan_add", "scan_id":S, "candidates":[CAND]}        (provider candidates once their probe lease
//                                                                 arrived, full follow-ups; appended to the queue)
//  {"action":"scan_poll", "scan_id":S, "since":int}               (items with seq > since)
//  {"action":"scan_freeze", "scan_id":S}                          (stop ADMITTING probes; answered at once)
//  {"action":"scan_cancel", "scan_id":S}                          (stop every probe; sent after the freeze ack)
//  CAND = {"id":str<=64 (probe id, opaque to the host), "kind":"xray_full"|"xray_leg"|"awg_mini",
//          "config":SECRET str, "entry":{"ip","port"}|null, "reach_at_ms":int (-1 = no reach stage),
//          "profile_id":hex16|null, "early_retry":bool, "dns_plan":bool, "cost_bytes":int,
//          "bytes":int (optional, 1024..4194304: this job's sized body instead of probe.bytes, e.g. a small
//          race probe), "total_ms":int (optional, 1000..30000: this job's limit instead of limits.total_ms)}
//   config per kind: xray_full = the whole sanitized Xray JSON (its socks inbound removed by the host);
//     xray_leg = {"outbound": <the leg's outbound as dialled>, "dns": [{"address","tag","transport"}]}: the
//     host builds ONE shared instance with every leg's outbound (forced tag, core.Dial) and, when dns_plan is
//     true, sends one query per listed resolver through that leg (dns_exercised = all answered);
//     awg_mini (awg-probe-plan.md §3, §6.3; built ONLY by scanAwgMiniConfig below from ScanAwgMiniInput) =
//     {"uapi": SECRET (AmneziaWG UAPI set lines, no "set=1": private_key=<hex of the DEVICE'S OWN key>,
//      listen_port=0, the node's obfuscation lines in order (jc, jmin, jmax, s1..s4, h1..h4, i1..i5, ...),
//      replace_peers=true, public_key=<hex>, [preshared_key=<hex>], endpoint=<ip:port>,
//      replace_allowed_ips=true, allowed_ip=<probe ip>/32|128, [allowed_ip=<echo target>/32|128]; no
//      persistent keepalive), "address": the device's tunnel address "ip/prefix" (REQUIRED: the node drops
//      packets from any other source; a candidate without it is never emitted), "mtu": int (optional,
//      576..1500; absent = the runner's 1280), "probe": {"host": the active API host (TLS name and Host),
//      "ip": its IP literal, "port": int}, "prime_echo_target": ip|null (manifest awg_echo_target of the
//      node, else of the manifest; ScanCandidate::awgEchoTarget), "bound_if": int|null (the physical
//      interface index)}. The handshake wait and the prime echoes are scan-wide (limits.awg_handshake_ms,
//      limits.awg_prime_echoes). No separate probe identity.
// Secrets travel only in `probe.token` and `candidates[].config`; the host never logs, echoes or stores
// them (scanRedactForLog masks both for any journal line on the app side). Nothing in the schema is
// platform specific: iOS (Swift, tunnel extension), macOS (root service) and Android (Kotlin) read the
// same objects; what a host can do is stated by its scan_caps answer only.
//
// ---- replies (host -> app) ---------------------------------------------------------------------------
//  {"type":"scan_caps", "version":"tribe-scan-v1", "max_full_concurrent":int, "max_leg_concurrent":int,
//   "max_awg_concurrent":int, "can_verify_composite":bool, "dns_plan":bool, "reach_stage":bool,
//   "needs_vpn":bool, "kinds":[str], "mem_mb":int|null, "platform":str|null (informational)}
//   (absent fields = 0 / false, reach_stage absent = true: a minimal host that only sends the first fields stays valid)
//  {"type":"scan_ack", "scan_id":S, "accepted":int, "mem_mb":int|null}        (start, add)
//  {"type":"scan_freeze_ack", "scan_id":S, "spent":int, "reserved":int}
//                                                                 (the answer to scan_freeze, at once: from it on
//                                                                 no probe or attempt is admitted; spent + reserved
//                                                                 bound everything this scan can still transfer -
//                                                                 plan §2.2b step 5)
//  {"type":"scan_ack", "scan_id":S, "accepted":0, "mem_mb":int|null}          (cancel; a host with nothing in
//                                                                 flight at that moment MAY add "final":true,
//                                                                 "bytes_spent":int - the same totals as the final
//                                                                 progress)
//  {"type":"scan_progress", "scan_id":S, "seq":int, "phase":"reach"|"data"|"done", "items":[ITEM],
//   "bytes_spent":int, "bytes_reserved":int (absent = 0), "mem_mb":int|null, "done":bool, "final":bool (absent =
//   false), "reason":str, "access":ATTEMPT|null, "access_close":ATTEMPT|null, "gen":GEN|null}
//   final = the host scan is OVER: nothing in flight, nothing reserved, nothing admitted any more; bytes_spent
//   is then the scan's final total. Sent after a cancel (also after a freeze + cancel), and when the host ends
//   by itself (deadline, budget, memory, tunnel stop). "complete" (queue drained) is NOT final: the scan stays
//   open for scan_add until deadline_ms.
//  ATTEMPT = {"attempted":bool, "http_answered":bool, "asn":int|null, "net_token":str|null, "at_ms":int|null,
//   "gen":GEN|null} - one direct access check of the host (plan §2.2c): GET probe.base + probe.netinfo_path
//   with probe.token on a socket bound to the physical interface. "access" = the OPENING attempt (made before
//   the first probe; repeated in every progress once made, null before), "access_close" = the CLOSING attempt
//   (made after the last probe ended, during the stop, before the final totals; in the final progress).
//   http_answered false = no HTTP answer at all (DNS, TCP or TLS failure, timeout); any HTTP status, an error
//   status too, = true. asn / net_token = the netinfo facts of a 200. at_ms = the attempt's START, ms after the
//   host received scan_start (monotonic; the base of the items' start_ms / end_ms). Both attempts are admitted
//   by the byte gate like probes (netinfo_cost_bytes each).
//  GEN = {"source":str<=16, "epoch":hex16, "counter":int} - the host's own path monitor (ScanNetworkGeneration.h):
//   "gen" of the progress = its state now (the coordinator folds it into the strict tuple), ATTEMPT.gen = its
//   state when that attempt started.
//  ITEM reach = {"seq":int>=1, "id":str, "stage":"reach", "ok":bool, "ms":int|null, "error":str}
//  ITEM data  = {"seq", "id", "stage":"data", "http_status":int, "ttfb1_ms", "rtt_ms", "t64_ms",
//                "duration_ms" (int|null each), "bytes_requested":int, "bytes":int, "sha_ok":bool,
//                "egress_class":str|null, "egress_asn":int|null, "net_token":str|null, "error":str,
//                "spent_bytes":int, "retries":int, "dns_exercised":bool (legs; absent = false),
//                "egress_node":str|null (X-Tribe-Egress-Node: our host node id, sent with class tribe-node),
//                "start_ms":int|null, "end_ms":int|null (the probe's first dial and last byte, the at_ms base),
//                "dns":[{...}] (optional, legs with dns_plan: per-resolver diagnostic detail - address,
//                transport, ok, ms, rcode, answers, error; journal only, the app reads dns_exercised),
//                awg_mini also: "handshake_ok":bool, "handshake_ms":int|null, "echo_sent":int,
//                "echo_replies":int (the prime echoes: diagnostic only; the data fields are the
//                normal ones of the sized download through the node)}
//  reason: "" while running | "complete" (queue drained; the scan stays open for scan_add until
//          deadline_ms) | "deadline" | "cancelled" | "budget" | "memory" | "tunnel_stopped" | "internal"
//  item error: "" | reach_timeout | reach_refused | dial | tls | ttfb_timeout | stalled | total_timeout | http |
//          short | digest | memory | budget | cancelled | deadline | config | internal | bind_failed (the
//          probe's own socket protection failed: that probe only, no verdict - «Не проверено» - never a
//          tunnel event); any other code decodes as internal
//  Errors: {"error":"unknown_action"} (any action this host does not know - it MUST answer, R5),
//          {"error":"bad_request","detail":str}, {"error":"version","supported":[str]},
//          {"error":"unknown_scan","scan_id":S}, {"error":"memory","mem_mb":int,"need_mb":int} (memory guard
//          refused the start), {"error":"no_vpn"} (the host needs a running tunnel), {"error":"internal"} (a
//          "detail" names the cause, e.g. "kill_switch_exemption": the desktop service cannot open its kill
//          switch for probes - the screen says host_kill_switch), {"error":"bind_failed"} (the host's probe
//          sockets cannot be bound to the physical interface).
//  Error codes are an open set: an unknown one decodes as ScanHostError::Other, never as success.
//
// ---- host behaviour (every platform) -------------------------------------------------------------------
//  - One scan at a time: a new scan_start ends the running one (as scan_cancel) and starts the new one.
//    scan_start/add/cancel are answered at once (scan_ack); results are only ever polled.
//  - Reach: a candidate with an entry and reach_at_ms >= 0 gets one TCP connect to entry ip:port, not before
//    reach_at_ms after the start, at most stage1_sockets at once, at most per_entry_ip at once to one IP,
//    opens to one IP at least entry_ip_spacing_ms apart, timeout stage1_timeout_ms -> one reach item. A
//    failed reach is final (no data probe).
//  - Data: queue order = start list, then scan_add lists in arrival order; each kind has its own pool
//    (concurrency / leg_concurrency / awg_concurrency); a candidate starts when its pool has a slot, in
//    queue order; the same per-IP spacing for the path's connection; the shared byte cap (review F6) below
//    decides every launch, else a data item with error "budget"; the host's memory guard refuses a
//    launch with error "memory" (e.g. iOS os_proc_available_memory() >= 12 MB before, >= 8 MB during). No
//    launch after deadline_ms; at deadline_ms the scan ends (reason "deadline"); probes in flight end with
//    "deadline".
//  - One Xray data probe (full or leg): ONE TLS connection through the path to probe.base; GET
//    path?bytes=warm_bytes&nonce=a (ttfb1_ms = its first byte, all handshakes included), then GET
//    path?bytes=<bytes>&nonce=b on the same connection (rtt_ms = its first byte, t64_ms = first -> last
//    byte); `profile_id` added when present; headers X-Tribe-Access-Net-Token / X-Tribe-Access-Asn from
//    probe.access when known; digest of the second body computed locally by tribe-probe-v1 (sha_ok), never
//    from X-Tribe-Probe-Sha256; limits ttfb_ms per request, stall_ms after stall_after_bytes, total_ms for
//    the probe; early_retry = the first refusals are retried after 300/600/1200/2000 ms while >= 1 s of
//    total_ms is left (lab D3).
//  - One awg_mini session (awg-probe-plan.md §3): a userspace AmneziaWG device on an in-memory netstack with
//    its own registry and logger and a socket bound to bound_if; handshake within awg_handshake_ms (none ->
//    the item says handshake_ok false); then awg_prime_echoes ICMP echoes to prime_echo_target (the first
//    packet after the handshake is lost with S4 obfuscation), 150 ms each; then the data probe above over TLS
//    to probe.ip:port with probe.host as the TLS name and Host - no DNS inside the session; the device is
//    closed in every path (done, cancel, deadline, memory, tunnel change). At most one session per node in a
//    scan, initiations at least awg_spacing_ms apart; the host refuses a peer equal to the live tunnel's
//    peer (defence in depth: the planner never schedules the live node or an attempt's target), and any
//    tunnel start / peer swap / restart / stop first cancels every session under the scan's lifecycle gate
//    (their items end with error "cancelled").
//  - Probe nonces: 8-64 characters of [A-Za-z0-9._-], fresh per request (the server refuses others).
//  - bytes_spent = bodies + 8192 per TLS connection + 512 per reach socket + echo bytes both ways
//    (cumulative, never decreases).
//  - Shared byte cap (review F6; ScanHostByteGate below is the reference the Go host replays from
//    scan_host_vectors.json "byte_gate"): ONE gate for every pool (full, leg, awg_mini) and every retry of a
//    probe. A probe is admitted ATOMICALLY only if spent + reserved + cost_bytes <= max_bytes (null = no cap);
//    admission reserves its cost_bytes until the probe's final item, then the reservation is replaced by the
//    bytes it really used. cost_bytes is the probe's hard limit: the host cuts a probe (error "budget") before
//    it passes it, so spent + reserved <= max_bytes holds at every moment. bytes_reserved in each
//    scan_progress = the reservations still open.
//  - Stop (plan §2.2b step 5, review v2.1 F7): the app first sends scan_freeze; under the gate's lock the host
//    sets `frozen` (no admission after it) and answers scan_freeze_ack {spent, reserved} at once. Then the app
//    sends scan_cancel: probes in flight end, the host makes its closing access attempt (reserved before the
//    freeze, see below) and its last scan_progress carries done: true, final: true, bytes_spent, access_close.
//    The app charges its one allowance with that final total; with the freeze ack but no final within
//    scan_drain_ms: the ack's spent + reserved; with no freeze ack within scan_freeze_ack_ms: the WHOLE host
//    grant (max_bytes). A poll of a finished scan answers the same final progress.
//  - Access attempts (plan §2.2c): the opening attempt is admitted first, before any probe; the host keeps a
//    reservation of netinfo_cost_bytes for the closing attempt from the start (it is released into spent by the
//    attempt), so a frozen scan can still make it. An attempt that could not LEAVE the physical interface is
//    NOT an attempt (null / attempted false, released from the gate at 0 bytes): budget (the grant cannot
//    cover it), dns (the base's name did not resolve - give probe.base_ips), bind (the socket protection
//    failed), no_route (ENETUNREACH / EHOSTUNREACH / EADDRNOTAVAIL / ENETDOWN on the bound interface). Only a
//    failure AFTER packets left (refused, reset, timeout, TLS or HTTP failure) is attempted with
//    http_answered false - the only kind the exclusion proof accepts.
//  - Proof by exclusion (plan §2.8): the two attempts bracket the probes; when both failed at the network
//    level on one host path state (same gen), the access network could not reach the probe host at all, so a
//    probe that started after the opening and ended before the closing with a verified digest did not leave
//    through it (ScanClass.h::scanExclusionHolds decides on the app side).
//  - seq starts at 1 and grows by 1 per item; items stay pollable until the next scan_start or scan_cancel.
//  - done = every queued candidate has a final item (reason "complete"), or deadline/cancel/budget/memory/
//    tunnel stop.
//
// Decoding is strict: wrong types or ranges -> ScanHostError::Malformed (never a crash, never a partial
// success); unknown fields are ignored.
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanTunables.h"
#include "ScanTypes.h"

#include <QByteArray>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>

#include <cmath>

namespace avpn {

inline constexpr char kScanHostVersion[] = "tribe-scan-v1";
inline constexpr int kScanHostMaxItems = 512;
inline constexpr int kScanHostMaxCandidates = 128;
inline constexpr qint64 kScanHostDeadlineGraceMs = 1000;
// probe.base_ips at most (IP literals of the probe base's host).
inline constexpr int kScanProbeBaseIpsMax = 8;
// Two AmneziaWG initiations of one identity closer than this lose handshakes (awg-probe-plan.md §1.2:
// 10 of 20 without spacing, 0 of 20 with 50 ms).
inline constexpr int kScanAwgSpacingMs = 50;

struct ScanHostLimits {
    int stage1Sockets = 16;
    int stage1StaggerMs = 50;
    int perEntryIp = 2;
    int entryIpSpacingMs = 300;
    int stage1TimeoutMs = 1500;
    int concurrency = 1;       // xray_full pool
    int legConcurrency = 0;    // xray_leg pool (one shared instance)
    int awgConcurrency = 0;    // awg_mini pool
    int ttfbMs = 3000;
    int stallMs = 1500;
    int stallAfterBytes = 4096;  // ScanTunables scan_stage2_stall_after_bytes (always sent: a struct default only)
    int totalMs = 5000;
    int awgHandshakeMs = 1500;
    int awgPrimeEchoes = 1;
    int awgSpacingMs = 50;
    int netinfoCostBytes = 10240; // one direct access attempt, admitted by the byte gate like a probe

    bool operator==(const ScanHostLimits &o) const
    {
        return stage1Sockets == o.stage1Sockets && stage1StaggerMs == o.stage1StaggerMs && perEntryIp == o.perEntryIp
               && entryIpSpacingMs == o.entryIpSpacingMs && stage1TimeoutMs == o.stage1TimeoutMs
               && concurrency == o.concurrency && legConcurrency == o.legConcurrency
               && awgConcurrency == o.awgConcurrency && ttfbMs == o.ttfbMs && stallMs == o.stallMs
               && stallAfterBytes == o.stallAfterBytes && totalMs == o.totalMs && awgHandshakeMs == o.awgHandshakeMs
               && awgPrimeEchoes == o.awgPrimeEchoes && awgSpacingMs == o.awgSpacingMs
               && netinfoCostBytes == o.netinfoCostBytes;
    }
};

inline ScanHostLimits scanHostLimitsFrom(const ScanTunables &t, int concurrency, int legConcurrency = 0,
                                         int awgConcurrency = 0)
{
    ScanHostLimits l;
    l.stage1Sockets = t.stage1Sockets;
    l.stage1StaggerMs = t.stage1StaggerMs;
    l.perEntryIp = t.stage1PerEntryIp;
    l.entryIpSpacingMs = t.entryIpSpacingMs;
    l.stage1TimeoutMs = t.stage1TimeoutMs;
    l.concurrency = qMax(0, concurrency);
    l.legConcurrency = qMax(0, legConcurrency);
    l.awgConcurrency = qMax(0, awgConcurrency);
    l.awgHandshakeMs = t.awgHandshakeMs;
    l.awgPrimeEchoes = t.awgPrimeEchoes;
    l.awgSpacingMs = kScanAwgSpacingMs;
    l.ttfbMs = t.stage2TtfbMs;
    l.stallMs = t.stage2StallMs;
    l.stallAfterBytes = t.stage2StallAfterBytes;
    l.totalMs = t.stage2TotalMs;
    l.netinfoCostBytes = t.costNetinfoBytes;
    return l;
}

struct ScanHostCandidate {
    QString id;
    ScanProbeKind kind = ScanProbeKind::XrayFull;
    QString config;            // SECRET
    QString entryIp;
    int entryPort = 0;
    qint64 reachAtMs = -1;
    QString profileId;
    bool earlyRetry = false;
    bool dnsPlan = false;      // xray_leg: exercise the config's DNS plan through the leg
    qint64 costBytes = 0;
    int bytes = 0;             // optional per-job body size (0 = probe.bytes)
    int totalMs = 0;           // optional per-job limit (0 = limits.total_ms)
};

struct ScanStartRequest {
    QString scanId;
    qint64 deadlineMs = 0;
    qint64 maxBytes = -1;      // -1 = no cap (null on the wire)
    ScanHostLimits limits;
    QString probeBase;
    QString probePath = QStringLiteral("/v1/probe");
    QString netinfoPath = QStringLiteral("/v1/netinfo");
    QString token;             // SECRET
    int warmBytes = 1024;
    int bytes = 65536;
    ScanAccess access;
    QStringList probeBaseIps;  // optional IP literals of the base's host (sent only when not empty)
    QList<ScanHostCandidate> candidates;
};

enum class ScanHostAction { Caps, Start, Add, Poll, Freeze, Cancel };

struct ScanHostRequest {
    ScanHostAction action = ScanHostAction::Caps;
    ScanStartRequest start;                 // Start (scanId also for Add/Poll/Cancel)
    QList<ScanHostCandidate> candidates;    // Add
    qint64 since = 0;                       // Poll
};

struct ScanHostProgress {
    QString scanId;
    qint64 seq = 0;
    QString phase;             // reach | data | done
    QList<ScanProbeFacts> items;
    qint64 bytesSpent = 0;
    qint64 bytesReserved = 0;  // admitted probes not final yet (the shared byte gate)
    int memMb = -1;
    bool done = false;
    bool finalTotals = false;  // "final": the host scan is over; bytesSpent is its final total
    QString reason;
    ScanAccessAttempt access;      // the opening attempt (attempted false = none yet)
    ScanAccessAttempt accessClose; // the closing attempt
    bool hasGen = false;           // the host's path monitor now
    ScanNetSource gen;
};

enum class ScanHostError { None, Malformed, UnknownAction, BadRequest, Version, UnknownScan, Memory, NoVpn, Internal, Other, BindFailed };

inline const char *scanHostErrorName(ScanHostError e)
{
    switch (e) {
    case ScanHostError::None: return "";
    case ScanHostError::Malformed: return "malformed";
    case ScanHostError::UnknownAction: return "unknown_action";
    case ScanHostError::BadRequest: return "bad_request";
    case ScanHostError::Version: return "version";
    case ScanHostError::UnknownScan: return "unknown_scan";
    case ScanHostError::Memory: return "memory";
    case ScanHostError::NoVpn: return "no_vpn";
    case ScanHostError::Internal: return "internal";
    case ScanHostError::BindFailed: return "bind_failed";
    case ScanHostError::Other: break;
    }
    return "other";
}

inline ScanHostError scanHostErrorFrom(const QString &s)
{
    if (s == QLatin1String("unknown_action")) return ScanHostError::UnknownAction;
    if (s == QLatin1String("bad_request")) return ScanHostError::BadRequest;
    if (s == QLatin1String("version")) return ScanHostError::Version;
    if (s == QLatin1String("unknown_scan")) return ScanHostError::UnknownScan;
    if (s == QLatin1String("memory")) return ScanHostError::Memory;
    if (s == QLatin1String("no_vpn")) return ScanHostError::NoVpn;
    if (s == QLatin1String("internal")) return ScanHostError::Internal;
    if (s == QLatin1String("bind_failed")) return ScanHostError::BindFailed;
    return ScanHostError::Other;
}

enum class ScanHostReplyKind { Caps, Ack, Progress, FreezeAck, Error };

struct ScanHostReply {
    ScanHostReplyKind kind = ScanHostReplyKind::Error;
    // Caps
    ScanHostCaps caps;
    QStringList kinds;
    // Ack
    QString scanId;
    int accepted = 0;
    int memMb = -1;
    bool finalTotals = false;  // the cancel ack: bytesSpent is the scan's final total
    qint64 bytesSpent = -1;    // the cancel ack's final total; the freeze ack's "spent"
    qint64 bytesReserved = -1; // the freeze ack's "reserved"
    // Progress
    ScanHostProgress progress;
    // Error
    ScanHostError error = ScanHostError::Malformed;
    QString errorCode;         // the wire code as sent ("" for Malformed)
    QString detail;
    int needMb = -1;
};

// --- JSON helpers -----------------------------------------------------------------------------------------

namespace scanwire {

// Integer field. Absent: ok when !required (value = def). Present: must be an integral number in [lo, hi];
// null is accepted as absent only when nullable.
inline bool intField(const QJsonObject &o, const char *key, qint64 lo, qint64 hi, qint64 def, bool required,
                     bool nullable, qint64 &out)
{
    const QJsonValue v = o.value(QLatin1String(key));
    if (v.isUndefined() || (nullable && v.isNull())) {
        out = def;
        return !required || (nullable && v.isNull());
    }
    if (!v.isDouble())
        return false;
    const double d = v.toDouble();
    if (!std::isfinite(d) || d != std::floor(d) || d < double(lo) || d > double(hi))
        return false;
    out = qint64(d);
    return true;
}

inline bool strField(const QJsonObject &o, const char *key, int maxLen, bool required, bool nullable, QString &out)
{
    const QJsonValue v = o.value(QLatin1String(key));
    if (v.isUndefined() || (nullable && v.isNull())) {
        out.clear();
        return !required || (nullable && v.isNull());
    }
    if (!v.isString())
        return false;
    out = v.toString();
    return out.size() <= maxLen;
}

inline bool boolField(const QJsonObject &o, const char *key, bool def, bool required, bool &out)
{
    const QJsonValue v = o.value(QLatin1String(key));
    if (v.isUndefined()) {
        out = def;
        return !required;
    }
    if (!v.isBool())
        return false;
    out = v.toBool();
    return true;
}

inline QJsonValue intOrNull(qint64 v) { return v < 0 ? QJsonValue(QJsonValue::Null) : QJsonValue(double(v)); }
inline QJsonValue strOrNull(const QString &s) { return s.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(s); }

inline bool hex16(const QString &s)
{
    if (s.size() != 16)
        return false;
    for (const QChar c : s)
        if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9')) || (c >= QLatin1Char('a') && c <= QLatin1Char('f'))))
            return false;
    return true;
}

} // namespace scanwire

// --- encode requests --------------------------------------------------------------------------------------

inline QJsonObject scanHostCandidateToJson(const ScanHostCandidate &c)
{
    QJsonObject o;
    o.insert(QStringLiteral("id"), c.id);
    o.insert(QStringLiteral("kind"), QLatin1String(scanProbeKindName(c.kind)));
    o.insert(QStringLiteral("config"), c.config);
    if (!c.entryIp.isEmpty() && c.entryPort > 0)
        o.insert(QStringLiteral("entry"), QJsonObject{{QStringLiteral("ip"), c.entryIp}, {QStringLiteral("port"), c.entryPort}});
    else
        o.insert(QStringLiteral("entry"), QJsonValue(QJsonValue::Null));
    o.insert(QStringLiteral("reach_at_ms"), double(c.reachAtMs < 0 ? -1 : c.reachAtMs));
    o.insert(QStringLiteral("profile_id"), scanwire::strOrNull(c.profileId));
    o.insert(QStringLiteral("early_retry"), c.earlyRetry);
    o.insert(QStringLiteral("dns_plan"), c.dnsPlan);
    o.insert(QStringLiteral("cost_bytes"), double(qMax<qint64>(0, c.costBytes)));
    if (c.bytes > 0)
        o.insert(QStringLiteral("bytes"), c.bytes);
    if (c.totalMs > 0)
        o.insert(QStringLiteral("total_ms"), c.totalMs);
    return o;
}

inline QJsonObject scanHostLimitsToJson(const ScanHostLimits &l)
{
    QJsonObject o;
    o.insert(QStringLiteral("stage1_sockets"), l.stage1Sockets);
    o.insert(QStringLiteral("stage1_stagger_ms"), l.stage1StaggerMs);
    o.insert(QStringLiteral("per_entry_ip"), l.perEntryIp);
    o.insert(QStringLiteral("entry_ip_spacing_ms"), l.entryIpSpacingMs);
    o.insert(QStringLiteral("stage1_timeout_ms"), l.stage1TimeoutMs);
    o.insert(QStringLiteral("concurrency"), l.concurrency);
    o.insert(QStringLiteral("leg_concurrency"), l.legConcurrency);
    o.insert(QStringLiteral("awg_concurrency"), l.awgConcurrency);
    o.insert(QStringLiteral("ttfb_ms"), l.ttfbMs);
    o.insert(QStringLiteral("stall_ms"), l.stallMs);
    o.insert(QStringLiteral("stall_after_bytes"), l.stallAfterBytes);
    o.insert(QStringLiteral("total_ms"), l.totalMs);
    o.insert(QStringLiteral("awg_handshake_ms"), l.awgHandshakeMs);
    o.insert(QStringLiteral("awg_prime_echoes"), l.awgPrimeEchoes);
    o.insert(QStringLiteral("awg_spacing_ms"), l.awgSpacingMs);
    o.insert(QStringLiteral("netinfo_cost_bytes"), l.netinfoCostBytes);
    return o;
}

inline QJsonObject scanEncodeStart(const ScanStartRequest &r)
{
    QJsonObject o;
    o.insert(QStringLiteral("action"), QStringLiteral("scan_start"));
    o.insert(QStringLiteral("version"), QLatin1String(kScanHostVersion));
    o.insert(QStringLiteral("scan_id"), r.scanId);
    o.insert(QStringLiteral("deadline_ms"), double(r.deadlineMs));
    o.insert(QStringLiteral("max_bytes"), scanwire::intOrNull(r.maxBytes));
    o.insert(QStringLiteral("limits"), scanHostLimitsToJson(r.limits));
    QJsonObject p;
    p.insert(QStringLiteral("base"), r.probeBase);
    p.insert(QStringLiteral("path"), r.probePath);
    p.insert(QStringLiteral("netinfo_path"), r.netinfoPath);
    p.insert(QStringLiteral("token"), r.token);
    p.insert(QStringLiteral("warm_bytes"), r.warmBytes);
    p.insert(QStringLiteral("bytes"), r.bytes);
    p.insert(QStringLiteral("access_asn"), r.access.asn > 0 ? QJsonValue(double(r.access.asn)) : QJsonValue(QJsonValue::Null));
    p.insert(QStringLiteral("access_net_token"), scanwire::strOrNull(r.access.netToken));
    if (!r.probeBaseIps.isEmpty()) {
        QJsonArray ips;
        for (const QString &ip : r.probeBaseIps)
            ips << ip;
        p.insert(QStringLiteral("base_ips"), ips);
    }
    o.insert(QStringLiteral("probe"), p);
    QJsonArray cs;
    for (const ScanHostCandidate &c : r.candidates)
        cs << scanHostCandidateToJson(c);
    o.insert(QStringLiteral("candidates"), cs);
    return o;
}

inline QJsonObject scanEncodeAdd(const QString &scanId, const QList<ScanHostCandidate> &cands)
{
    QJsonArray cs;
    for (const ScanHostCandidate &c : cands)
        cs << scanHostCandidateToJson(c);
    return QJsonObject{{QStringLiteral("action"), QStringLiteral("scan_add")},
                       {QStringLiteral("scan_id"), scanId},
                       {QStringLiteral("candidates"), cs}};
}

inline QJsonObject scanEncodePoll(const QString &scanId, qint64 since)
{
    return QJsonObject{{QStringLiteral("action"), QStringLiteral("scan_poll")},
                       {QStringLiteral("scan_id"), scanId},
                       {QStringLiteral("since"), double(qMax<qint64>(0, since))}};
}

inline QJsonObject scanEncodeFreeze(const QString &scanId)
{
    return QJsonObject{{QStringLiteral("action"), QStringLiteral("scan_freeze")}, {QStringLiteral("scan_id"), scanId}};
}

inline QJsonObject scanEncodeFreezeAck(const QString &scanId, qint64 spent, qint64 reserved)
{
    return QJsonObject{{QStringLiteral("type"), QStringLiteral("scan_freeze_ack")}, {QStringLiteral("scan_id"), scanId},
                       {QStringLiteral("spent"), double(qMax<qint64>(0, spent))},
                       {QStringLiteral("reserved"), double(qMax<qint64>(0, reserved))}};
}

inline QJsonObject scanEncodeCancel(const QString &scanId)
{
    return QJsonObject{{QStringLiteral("action"), QStringLiteral("scan_cancel")}, {QStringLiteral("scan_id"), scanId}};
}

inline QJsonObject scanEncodeCaps() { return QJsonObject{{QStringLiteral("action"), QStringLiteral("scan_caps")}}; }

inline QByteArray scanCompact(const QJsonObject &o) { return QJsonDocument(o).toJson(QJsonDocument::Compact); }

// A copy safe for a journal line: every "token" and "config" value replaced by "<redacted>".
inline QJsonValue scanRedactForLog(const QJsonValue &v)
{
    if (v.isObject()) {
        QJsonObject o = v.toObject();
        for (auto it = o.begin(); it != o.end(); ++it) {
            if (it.key() == QLatin1String("token") || it.key() == QLatin1String("config")
                || it.key() == QLatin1String("access_net_token") || it.key() == QLatin1String("net_token")
                || it.key() == QLatin1String("uapi") || it.key() == QLatin1String("address")
                || it.key() == QLatin1String("private_key") || it.key() == QLatin1String("preshared_key"))
                it.value() = it.value().isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue(QStringLiteral("<redacted>"));
            else
                it.value() = scanRedactForLog(it.value());
        }
        return o;
    }
    if (v.isArray()) {
        QJsonArray a = v.toArray();
        for (int i = 0; i < a.size(); ++i)
            a[i] = scanRedactForLog(a.at(i));
        return a;
    }
    return v;
}

// --- the awg_mini candidate config (the coordinator joins the secrets here, nowhere else) ------------------

// What the coordinator knows for one AmneziaWG mini-session. Keys as the subscription carries them (base64)
// or as 64 hex characters; obfuscation = the node's AmneziaWG UAPI lines, in order, with values exactly as
// the UAPI wants them (jc, jmin, jmax, s1..s4, h1..h4, i1..i5, j1..j3, itime, header_protection_key as hex,
// ...). Never logged; the built config is a SECRET string like every candidate config.
struct ScanAwgMiniInput {
    QString privateKey;                          // SECRET: the DEVICE'S OWN key (no separate probe identity)
    QString address;                             // REQUIRED: the device's tunnel address, "ip" or "ip/prefix"
    int mtu = 0;                                 // 0 = absent (the runner's 1280)
    QString peerPublicKey;                       // the node's public key
    QString presharedKey;                        // SECRET, optional
    QString endpoint;                            // the node's "ip:port" / "[v6]:port"
    QList<QPair<QString, QString>> obfuscation;  // UAPI key -> value, in order
    QString probeHost;                           // the active API host: TLS name and Host
    QString probeIp;                             // its IP literal (the session dials it without DNS)
    int probePort = 443;
    QString echoTarget;                          // prime echo target (ScanCandidate::awgEchoTarget), "" = none
    int boundIf = -1;                            // the physical interface index, -1 = unknown (null)
};

namespace scanwire {

// A WireGuard key (32 bytes) as base64 or 64 hex characters -> lowercase hex; "" when it is neither.
inline QString wgKeyHex(const QString &key)
{
    const QString k = key.trimmed();
    if (k.size() == 64) {
        bool hex = true;
        for (const QChar c : k)
            hex = hex && ((c >= QLatin1Char('0') && c <= QLatin1Char('9')) || (c.toLower() >= QLatin1Char('a') && c.toLower() <= QLatin1Char('f')));
        if (hex)
            return k.toLower();
    }
    const auto r = QByteArray::fromBase64Encoding(k.toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    if (!r || r.decoded.size() != 32)
        return QString();
    return QString::fromLatin1(r.decoded.toHex());
}

inline bool isV6(const QString &ip) { return ip.contains(QLatin1Char(':')); }

// "ip" or "ip/prefix" -> "ip/prefix" (a bare ip gets /32 or /128); "" when invalid.
inline QString cidrOf(const QString &address)
{
    const QString a = address.trimmed();
    const int slash = a.indexOf(QLatin1Char('/'));
    const QString ip = slash < 0 ? a : a.left(slash);
    if (!scanIsIpLiteral(ip))
        return QString();
    const int max = isV6(ip) ? 128 : 32;
    if (slash < 0)
        return ip + QLatin1Char('/') + QString::number(max);
    bool ok = false;
    const int prefix = a.mid(slash + 1).toInt(&ok);
    if (!ok || prefix < 0 || prefix > max)
        return QString();
    return ip + QLatin1Char('/') + QString::number(prefix);
}

// "ip:port" / "[v6]:port" with an IP literal and a port 1..65535.
inline bool endpointOk(const QString &e)
{
    QString host;
    QString port;
    if (e.startsWith(QLatin1Char('['))) {
        const int close = e.indexOf(QStringLiteral("]:"));
        if (close < 0)
            return false;
        host = e.mid(1, close - 1);
        port = e.mid(close + 2);
    } else {
        const int colon = e.lastIndexOf(QLatin1Char(':'));
        if (colon <= 0 || e.count(QLatin1Char(':')) != 1)
            return false;
        host = e.left(colon);
        port = e.mid(colon + 1);
    }
    bool ok = false;
    const int p = port.toInt(&ok);
    return scanIsIpLiteral(host) && ok && p >= 1 && p <= 65535;
}

} // namespace scanwire

// The awg_mini candidate config of the contract (header above) from the typed input; "" and *why set when
// the input cannot make a session: awg_no_address, awg_no_key, awg_no_peer_key, awg_no_endpoint,
// awg_no_api_ip, awg_bad_param, awg_bad_mtu. A candidate whose config is "" is never emitted.
inline QString scanAwgMiniConfig(const ScanAwgMiniInput &in, QString *why = nullptr)
{
    using namespace scanwire;
    const auto refuse = [why](const char *r) {
        if (why)
            *why = QLatin1String(r);
        return QString();
    };
    const QString address = cidrOf(in.address);
    if (address.isEmpty())
        return refuse("awg_no_address");
    const QString priv = wgKeyHex(in.privateKey);
    if (priv.isEmpty())
        return refuse("awg_no_key");
    const QString peer = wgKeyHex(in.peerPublicKey);
    if (peer.isEmpty())
        return refuse("awg_no_peer_key");
    const QString psk = in.presharedKey.isEmpty() ? QString() : wgKeyHex(in.presharedKey);
    if (!in.presharedKey.isEmpty() && psk.isEmpty())
        return refuse("awg_no_peer_key");
    if (!endpointOk(in.endpoint))
        return refuse("awg_no_endpoint");
    if (!scanIsIpLiteral(in.probeIp) || in.probeHost.isEmpty() || in.probeHost.size() > 253 || in.probePort < 1 || in.probePort > 65535)
        return refuse("awg_no_api_ip");
    if (!in.echoTarget.isEmpty() && !scanIsIpLiteral(in.echoTarget))
        return refuse("awg_bad_param");
    if (in.mtu != 0 && (in.mtu < 576 || in.mtu > 1500))
        return refuse("awg_bad_mtu");
    static const QStringList structural = {QStringLiteral("private_key"), QStringLiteral("listen_port"), QStringLiteral("fwmark"),
                                           QStringLiteral("replace_peers"), QStringLiteral("public_key"), QStringLiteral("preshared_key"),
                                           QStringLiteral("endpoint"), QStringLiteral("persistent_keepalive_interval"),
                                           QStringLiteral("replace_allowed_ips"), QStringLiteral("allowed_ip"),
                                           QStringLiteral("protocol_version"), QStringLiteral("remove")};
    QString uapi;
    uapi += QStringLiteral("private_key=") + priv + QLatin1Char('\n');
    uapi += QStringLiteral("listen_port=0\n");
    for (const auto &kv : in.obfuscation) {
        const QString k = kv.first.trimmed().toLower();
        bool keyOk = !k.isEmpty() && k.size() <= 32 && k.at(0) >= QLatin1Char('a') && k.at(0) <= QLatin1Char('z');
        for (const QChar c : k)
            keyOk = keyOk && ((c >= QLatin1Char('a') && c <= QLatin1Char('z')) || (c >= QLatin1Char('0') && c <= QLatin1Char('9')) || c == QLatin1Char('_'));
        const QString v = kv.second.trimmed();
        if (!keyOk || structural.contains(k) || v.isEmpty() || v.size() > 4096 || v.contains(QLatin1Char('\n'))
            || v.contains(QLatin1Char('\r')) || v.contains(QLatin1Char('=')))
            return refuse("awg_bad_param");
        uapi += k + QLatin1Char('=') + v + QLatin1Char('\n');
    }
    uapi += QStringLiteral("replace_peers=true\n");
    uapi += QStringLiteral("public_key=") + peer + QLatin1Char('\n');
    if (!psk.isEmpty())
        uapi += QStringLiteral("preshared_key=") + psk + QLatin1Char('\n');
    uapi += QStringLiteral("endpoint=") + in.endpoint.trimmed() + QLatin1Char('\n');
    uapi += QStringLiteral("replace_allowed_ips=true\n");
    uapi += QStringLiteral("allowed_ip=") + cidrOf(in.probeIp) + QLatin1Char('\n');
    if (!in.echoTarget.isEmpty())
        uapi += QStringLiteral("allowed_ip=") + cidrOf(in.echoTarget) + QLatin1Char('\n');
    QJsonObject o;
    o.insert(QStringLiteral("uapi"), uapi);
    o.insert(QStringLiteral("address"), address);
    if (in.mtu > 0)
        o.insert(QStringLiteral("mtu"), in.mtu);
    o.insert(QStringLiteral("probe"), QJsonObject{{QStringLiteral("host"), in.probeHost}, {QStringLiteral("ip"), in.probeIp},
                                                  {QStringLiteral("port"), in.probePort}});
    o.insert(QStringLiteral("prime_echo_target"), strOrNull(in.echoTarget));
    o.insert(QStringLiteral("bound_if"), in.boundIf < 0 ? QJsonValue(QJsonValue::Null) : QJsonValue(in.boundIf));
    return QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact));
}

// --- decode requests (the host side; also used to prove the round trip) -----------------------------------

inline bool scanDecodeCandidate(const QJsonValue &v, ScanHostCandidate &c)
{
    using namespace scanwire;
    if (!v.isObject())
        return false;
    const QJsonObject o = v.toObject();
    c = ScanHostCandidate();
    QString kind;
    qint64 reach = -1, cost = 0;
    if (!strField(o, "id", 64, true, false, c.id) || c.id.isEmpty())
        return false;
    if (!strField(o, "kind", 16, true, false, kind))
        return false;
    c.kind = scanProbeKindFrom(kind);
    if (c.kind == ScanProbeKind::None)
        return false;
    if (!strField(o, "config", 4 * 1024 * 1024, true, false, c.config) || c.config.isEmpty())
        return false;
    const QJsonValue e = o.value(QLatin1String("entry"));
    if (e.isObject()) {
        qint64 port = 0;
        if (!strField(e.toObject(), "ip", 64, true, false, c.entryIp) || c.entryIp.isEmpty())
            return false;
        if (!intField(e.toObject(), "port", 1, 65535, 0, true, false, port))
            return false;
        c.entryPort = int(port);
    } else if (!e.isNull() && !e.isUndefined()) {
        return false;
    }
    if (!intField(o, "reach_at_ms", -1, 600000, -1, false, false, reach))
        return false;
    c.reachAtMs = reach;
    if (!strField(o, "profile_id", 16, false, true, c.profileId) || (!c.profileId.isEmpty() && !hex16(c.profileId)))
        return false;
    if (!boolField(o, "early_retry", false, false, c.earlyRetry))
        return false;
    if (!boolField(o, "dns_plan", false, false, c.dnsPlan))
        return false;
    if (!intField(o, "cost_bytes", 0, qint64(1) << 32, 0, false, false, cost))
        return false;
    c.costBytes = cost;
    qint64 jobBytes = 0, jobMs = 0;
    if (!intField(o, "bytes", 1024, 4 * 1024 * 1024, 0, false, false, jobBytes)
        || !intField(o, "total_ms", 1000, 30000, 0, false, false, jobMs))
        return false;
    c.bytes = int(jobBytes);
    c.totalMs = int(jobMs);
    return true;
}

inline bool scanDecodeCandidates(const QJsonObject &o, QList<ScanHostCandidate> &out)
{
    const QJsonValue v = o.value(QLatin1String("candidates"));
    if (!v.isArray() || v.toArray().size() > kScanHostMaxCandidates)
        return false;
    out.clear();
    for (const QJsonValue &cv : v.toArray()) {
        ScanHostCandidate c;
        if (!scanDecodeCandidate(cv, c))
            return false;
        out << c;
    }
    return true;
}

// Returns ScanHostError::None on success; UnknownAction, Version or BadRequest (detail = the field).
inline ScanHostError scanDecodeRequest(const QByteArray &bytes, ScanHostRequest &out, QString *detail = nullptr)
{
    using namespace scanwire;
    const auto bad = [detail](const char *f) {
        if (detail)
            *detail = QLatin1String(f);
        return ScanHostError::BadRequest;
    };
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(bytes, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject())
        return bad("json");
    const QJsonObject o = doc.object();
    const QString action = o.value(QLatin1String("action")).toString();
    out = ScanHostRequest();
    if (action == QLatin1String("scan_caps")) {
        out.action = ScanHostAction::Caps;
        return ScanHostError::None;
    }
    QString scanId;
    const bool known = action == QLatin1String("scan_start") || action == QLatin1String("scan_add")
                       || action == QLatin1String("scan_poll") || action == QLatin1String("scan_cancel")
                       || action == QLatin1String("scan_freeze");
    if (!known)
        return ScanHostError::UnknownAction;
    if (!strField(o, "scan_id", 64, true, false, scanId) || scanId.isEmpty())
        return bad("scan_id");
    out.start.scanId = scanId;
    if (action == QLatin1String("scan_cancel")) {
        out.action = ScanHostAction::Cancel;
        return ScanHostError::None;
    }
    if (action == QLatin1String("scan_freeze")) {
        out.action = ScanHostAction::Freeze;
        return ScanHostError::None;
    }
    if (action == QLatin1String("scan_poll")) {
        out.action = ScanHostAction::Poll;
        if (!intField(o, "since", 0, qint64(1) << 40, 0, false, false, out.since))
            return bad("since");
        return ScanHostError::None;
    }
    if (action == QLatin1String("scan_add")) {
        out.action = ScanHostAction::Add;
        if (!scanDecodeCandidates(o, out.candidates))
            return bad("candidates");
        return ScanHostError::None;
    }
    out.action = ScanHostAction::Start;
    if (o.value(QLatin1String("version")).toString() != QLatin1String(kScanHostVersion))
        return ScanHostError::Version;
    ScanStartRequest &r = out.start;
    if (!intField(o, "deadline_ms", 1000, 120000, 0, true, false, r.deadlineMs))
        return bad("deadline_ms");
    if (!intField(o, "max_bytes", 0, qint64(1) << 36, -1, false, true, r.maxBytes))
        return bad("max_bytes");
    const QJsonObject l = o.value(QLatin1String("limits")).toObject();
    struct LimitField {
        const char *key;
        int ScanHostLimits::*f;
        qint64 lo, hi;
    };
    static const LimitField lf[] = {
        {"stage1_sockets", &ScanHostLimits::stage1Sockets, 1, 64},
        {"stage1_stagger_ms", &ScanHostLimits::stage1StaggerMs, 0, 1000},
        {"per_entry_ip", &ScanHostLimits::perEntryIp, 1, 16},
        {"entry_ip_spacing_ms", &ScanHostLimits::entryIpSpacingMs, 0, 2000},
        {"stage1_timeout_ms", &ScanHostLimits::stage1TimeoutMs, 200, 10000},
        {"concurrency", &ScanHostLimits::concurrency, 0, 32},
        {"ttfb_ms", &ScanHostLimits::ttfbMs, 500, 15000},
        {"stall_ms", &ScanHostLimits::stallMs, 200, 10000},
        {"stall_after_bytes", &ScanHostLimits::stallAfterBytes, 1024, 262144},
        {"total_ms", &ScanHostLimits::totalMs, 1000, 30000},
    };
    for (const LimitField &f : lf) {
        qint64 v = 0;
        if (!intField(l, f.key, f.lo, f.hi, 0, true, false, v))
            return bad(f.key);
        r.limits.*(f.f) = int(v);
    }
    // Pools and echo sizes of later hosts: optional (absent = 0 / the defaults).
    static const LimitField optional[] = {
        {"leg_concurrency", &ScanHostLimits::legConcurrency, 0, 32},
        {"awg_concurrency", &ScanHostLimits::awgConcurrency, 0, 32},
        {"awg_handshake_ms", &ScanHostLimits::awgHandshakeMs, 300, 5000},
        {"awg_prime_echoes", &ScanHostLimits::awgPrimeEchoes, 0, 3},
        {"awg_spacing_ms", &ScanHostLimits::awgSpacingMs, 50, 1000},
        {"netinfo_cost_bytes", &ScanHostLimits::netinfoCostBytes, 1024, 1048576},
    };
    for (const LimitField &f : optional) {
        qint64 v = 0;
        if (!intField(l, f.key, f.lo, f.hi, r.limits.*(f.f), false, false, v))
            return bad(f.key);
        r.limits.*(f.f) = int(v);
    }
    const QJsonObject p = o.value(QLatin1String("probe")).toObject();
    qint64 warm = 0, body = 0, asn = 0;
    if (!strField(p, "base", 512, true, false, r.probeBase) || !r.probeBase.startsWith(QLatin1String("https://")))
        return bad("probe.base");
    if (!strField(p, "path", 128, true, false, r.probePath) || !r.probePath.startsWith(QLatin1Char('/')))
        return bad("probe.path");
    if (!strField(p, "netinfo_path", 128, false, false, r.netinfoPath))
        return bad("probe.netinfo_path");
    if (r.netinfoPath.isEmpty())
        r.netinfoPath = QStringLiteral("/v1/netinfo");
    else if (!r.netinfoPath.startsWith(QLatin1Char('/')))
        return bad("probe.netinfo_path");
    if (!strField(p, "token", 4096, true, false, r.token) || r.token.isEmpty())
        return bad("probe.token");
    if (!intField(p, "warm_bytes", 1024, 65536, 0, true, false, warm))
        return bad("probe.warm_bytes");
    if (!intField(p, "bytes", 1024, 4 * 1024 * 1024, 0, true, false, body))
        return bad("probe.bytes");
    if (!intField(p, "access_asn", 1, 4294967295LL, 0, false, true, asn))
        return bad("probe.access_asn");
    if (!strField(p, "access_net_token", 64, false, true, r.access.netToken))
        return bad("probe.access_net_token");
    r.warmBytes = int(warm);
    r.bytes = int(body);
    r.access.asn = asn;
    const QJsonValue ips = p.value(QLatin1String("base_ips"));
    if (!ips.isUndefined() && !ips.isNull()) {
        if (!ips.isArray() || ips.toArray().isEmpty() || ips.toArray().size() > kScanProbeBaseIpsMax)
            return bad("probe.base_ips");
        for (const QJsonValue &ip : ips.toArray()) {
            if (!ip.isString() || !scanIsIpLiteral(ip.toString()))
                return bad("probe.base_ips");
            r.probeBaseIps << ip.toString();
        }
    }
    if (!scanDecodeCandidates(o, r.candidates))
        return bad("candidates");
    return ScanHostError::None;
}

// --- encode replies (the host side; the vectors pin them) -------------------------------------------------

inline QJsonObject scanProbeFactsToJson(const ScanProbeFacts &f)
{
    using namespace scanwire;
    QJsonObject o;
    o.insert(QStringLiteral("seq"), double(f.seq));
    o.insert(QStringLiteral("id"), f.id);
    if (f.stage == ScanStage::Reach) {
        o.insert(QStringLiteral("stage"), QStringLiteral("reach"));
        o.insert(QStringLiteral("ok"), f.reachOk);
        o.insert(QStringLiteral("ms"), intOrNull(f.reachMs));
        o.insert(QStringLiteral("error"), QLatin1String(scanProbeErrorName(f.error)));
        return o;
    }
    o.insert(QStringLiteral("stage"), QStringLiteral("data"));
    o.insert(QStringLiteral("http_status"), f.httpStatus);
    o.insert(QStringLiteral("ttfb1_ms"), intOrNull(f.ttfb1Ms));
    o.insert(QStringLiteral("rtt_ms"), intOrNull(f.rttMs));
    o.insert(QStringLiteral("t64_ms"), intOrNull(f.t64Ms));
    o.insert(QStringLiteral("duration_ms"), intOrNull(f.durationMs));
    o.insert(QStringLiteral("bytes_requested"), double(f.bytesRequested));
    o.insert(QStringLiteral("bytes"), double(f.bytesReceived));
    o.insert(QStringLiteral("sha_ok"), f.shaOk);
    o.insert(QStringLiteral("egress_class"), strOrNull(f.egressClass));
    o.insert(QStringLiteral("egress_node"), strOrNull(f.egressNode));
    o.insert(QStringLiteral("egress_asn"), f.egressAsn > 0 ? QJsonValue(double(f.egressAsn)) : QJsonValue(QJsonValue::Null));
    o.insert(QStringLiteral("net_token"), strOrNull(f.egressNetToken));
    o.insert(QStringLiteral("error"), QLatin1String(scanProbeErrorName(f.error)));
    o.insert(QStringLiteral("spent_bytes"), double(f.spentBytes));
    o.insert(QStringLiteral("retries"), f.retries);
    if (f.dnsExercised)
        o.insert(QStringLiteral("dns_exercised"), true);
    o.insert(QStringLiteral("start_ms"), intOrNull(f.startMs));
    o.insert(QStringLiteral("end_ms"), intOrNull(f.endMs));
    if (f.handshakeOk || f.echoSent > 0 || f.handshakeMs >= 0) {
        o.insert(QStringLiteral("handshake_ok"), f.handshakeOk);
        o.insert(QStringLiteral("handshake_ms"), intOrNull(f.handshakeMs));
        o.insert(QStringLiteral("echo_sent"), f.echoSent);
        o.insert(QStringLiteral("echo_replies"), f.echoReplies);
    }
    return o;
}

// An attempt that was not made is null on the wire.
inline QJsonValue scanAccessAttemptToJson(const ScanAccessAttempt &a)
{
    using namespace scanwire;
    if (!a.attempted)
        return QJsonValue(QJsonValue::Null);
    return QJsonObject{{QStringLiteral("attempted"), true},
                       {QStringLiteral("http_answered"), a.httpAnswered},
                       {QStringLiteral("asn"), a.facts.asn > 0 ? QJsonValue(double(a.facts.asn)) : QJsonValue(QJsonValue::Null)},
                       {QStringLiteral("net_token"), strOrNull(a.facts.netToken)},
                       {QStringLiteral("at_ms"), intOrNull(a.atMs)},
                       {QStringLiteral("gen"), a.hasGen ? QJsonValue(scanNetSourceToJson(a.gen)) : QJsonValue(QJsonValue::Null)}};
}

inline QJsonObject scanEncodeProgress(const ScanHostProgress &p)
{
    QJsonObject o;
    o.insert(QStringLiteral("type"), QStringLiteral("scan_progress"));
    o.insert(QStringLiteral("scan_id"), p.scanId);
    o.insert(QStringLiteral("seq"), double(p.seq));
    o.insert(QStringLiteral("phase"), p.phase);
    QJsonArray items;
    for (const ScanProbeFacts &f : p.items)
        items << scanProbeFactsToJson(f);
    o.insert(QStringLiteral("items"), items);
    o.insert(QStringLiteral("bytes_spent"), double(p.bytesSpent));
    o.insert(QStringLiteral("bytes_reserved"), double(qMax<qint64>(0, p.bytesReserved)));
    o.insert(QStringLiteral("mem_mb"), scanwire::intOrNull(p.memMb));
    o.insert(QStringLiteral("done"), p.done);
    if (p.finalTotals)
        o.insert(QStringLiteral("final"), true);
    o.insert(QStringLiteral("reason"), p.reason);
    o.insert(QStringLiteral("access"), scanAccessAttemptToJson(p.access));
    o.insert(QStringLiteral("access_close"), scanAccessAttemptToJson(p.accessClose));
    o.insert(QStringLiteral("gen"), p.hasGen ? QJsonValue(scanNetSourceToJson(p.gen)) : QJsonValue(QJsonValue::Null));
    return o;
}

inline QJsonObject scanEncodeCapsReply(const ScanHostCaps &c, const QStringList &kinds)
{
    QJsonArray k;
    for (const QString &s : kinds)
        k << s;
    return QJsonObject{{QStringLiteral("type"), QStringLiteral("scan_caps")},
                       {QStringLiteral("version"), QLatin1String(kScanHostVersion)},
                       {QStringLiteral("max_full_concurrent"), c.maxFullConcurrent},
                       {QStringLiteral("max_leg_concurrent"), c.maxLegConcurrent},
                       {QStringLiteral("max_awg_concurrent"), c.maxAwgConcurrent},
                       {QStringLiteral("can_verify_composite"), c.canVerifyComposite},
                       {QStringLiteral("dns_plan"), c.dnsPlan},
                       {QStringLiteral("reach_stage"), c.reachStage},
                       {QStringLiteral("needs_vpn"), c.needsVpn},
                       {QStringLiteral("kinds"), k},
                       {QStringLiteral("mem_mb"), scanwire::intOrNull(c.memMb)},
                       {QStringLiteral("platform"), scanwire::strOrNull(c.platform)}};
}

inline QJsonObject scanEncodeAck(const QString &scanId, int accepted, int memMb)
{
    return QJsonObject{{QStringLiteral("type"), QStringLiteral("scan_ack")},
                       {QStringLiteral("scan_id"), scanId},
                       {QStringLiteral("accepted"), accepted},
                       {QStringLiteral("mem_mb"), scanwire::intOrNull(memMb)}};
}

// The acknowledgement of scan_cancel: the scan's final byte total.
inline QJsonObject scanEncodeCancelAck(const QString &scanId, qint64 bytesSpent, int memMb)
{
    QJsonObject o = scanEncodeAck(scanId, 0, memMb);
    o.insert(QStringLiteral("final"), true);
    o.insert(QStringLiteral("bytes_spent"), double(qMax<qint64>(0, bytesSpent)));
    return o;
}

// Reference of the host's shared byte gate (review F6) - one per scan, every pool and retry. Pure; the Go,
// Swift and Kotlin hosts replay its vectors.
class ScanHostByteGate
{
public:
    explicit ScanHostByteGate(qint64 maxBytes = -1) : m_max(maxBytes) {}

    // Atomic admission: true and the cost reserved, or false and nothing changes. Nothing is admitted after
    // freeze().
    bool admit(const QString &probeId, qint64 costBytes)
    {
        const qint64 cost = qMax<qint64>(0, costBytes);
        if (m_frozen || m_open.contains(probeId))
            return false; // frozen, or one reservation per probe
        if (m_max >= 0 && m_spent + m_reserved + cost > m_max)
            return false;
        m_open.insert(probeId, cost);
        m_reserved += cost;
        return true;
    }

    // The probe's final item: its reservation is replaced by what it really used (never more than its cost:
    // the host cuts a probe at cost_bytes). Unknown ids change nothing; bytes outside a probe (a reach
    // socket) are charged with charge().
    void finish(const QString &probeId, qint64 usedBytes)
    {
        const auto it = m_open.constFind(probeId);
        if (it == m_open.constEnd())
            return;
        const qint64 cost = it.value();
        m_open.remove(probeId);
        m_reserved -= cost;
        m_spent += qBound<qint64>(0, usedBytes, cost);
    }

    // Bytes outside a reservation (e.g. a reach socket): charged only if they fit and the gate is not frozen;
    // false = refused.
    bool charge(qint64 bytes)
    {
        const qint64 b = qMax<qint64>(0, bytes);
        if (m_frozen || (m_max >= 0 && m_spent + m_reserved + b > m_max))
            return false;
        m_spent += b;
        return true;
    }

    // scan_freeze (plan §2.2b step 5): from now on nothing is admitted; open reservations still finish, so
    // spent + reserved at this moment bound everything the scan can still transfer (the freeze ack's numbers).
    void freeze() { m_frozen = true; }
    bool frozen() const { return m_frozen; }

    // The app's allowance is cut again when the manifest's numbers arrive (scan_budget_scan_bytes); what was
    // already spent or reserved stays (a smaller cap only blocks what comes next).
    void setMaxBytes(qint64 maxBytes) { m_max = maxBytes; }

    qint64 spent() const { return m_spent; }
    qint64 reserved() const { return m_reserved; }
    qint64 maxBytes() const { return m_max; }
    int open() const { return m_open.size(); }

private:
    qint64 m_max = -1;
    qint64 m_spent = 0;
    qint64 m_reserved = 0;
    bool m_frozen = false;
    QHash<QString, qint64> m_open;
};

// --- decode replies (the app side) ------------------------------------------------------------------------

inline bool scanDecodeItem(const QJsonValue &v, ScanProbeFacts &f)
{
    using namespace scanwire;
    if (!v.isObject())
        return false;
    const QJsonObject o = v.toObject();
    f = ScanProbeFacts();
    QString stage, err;
    qint64 n = 0;
    if (!intField(o, "seq", 1, qint64(1) << 40, 0, true, false, f.seq))
        return false;
    if (!strField(o, "id", 64, true, false, f.id) || f.id.isEmpty())
        return false;
    if (!strField(o, "stage", 8, true, false, stage))
        return false;
    if (!strField(o, "error", 32, false, true, err))
        return false;
    f.error = scanProbeErrorFrom(err);
    if (stage == QLatin1String("reach")) {
        f.stage = ScanStage::Reach;
        if (!boolField(o, "ok", false, true, f.reachOk))
            return false;
        if (!intField(o, "ms", 0, 600000, -1, false, true, n))
            return false;
        f.reachMs = int(n);
        return true;
    }
    if (stage != QLatin1String("data"))
        return false;
    f.stage = ScanStage::Data;
    if (!intField(o, "http_status", 0, 999, 0, true, false, n))
        return false;
    f.httpStatus = int(n);
    struct T {
        const char *key;
        int ScanProbeFacts::*field;
    };
    static const T timings[] = {{"ttfb1_ms", &ScanProbeFacts::ttfb1Ms},
                                {"rtt_ms", &ScanProbeFacts::rttMs},
                                {"t64_ms", &ScanProbeFacts::t64Ms},
                                {"duration_ms", &ScanProbeFacts::durationMs}};
    for (const T &t : timings) {
        if (!intField(o, t.key, 0, 600000, -1, false, true, n))
            return false;
        f.*(t.field) = int(n);
    }
    if (!intField(o, "bytes_requested", 0, 64 * 1024 * 1024, 0, true, false, f.bytesRequested))
        return false;
    if (!intField(o, "bytes", 0, 64 * 1024 * 1024, 0, true, false, f.bytesReceived))
        return false;
    if (!boolField(o, "sha_ok", false, true, f.shaOk))
        return false;
    if (!strField(o, "egress_class", 32, false, true, f.egressClass))
        return false;
    if (!strField(o, "egress_node", 32, false, true, f.egressNode))
        return false;
    if (!intField(o, "egress_asn", 0, 4294967295LL, 0, false, true, f.egressAsn))
        return false;
    if (!strField(o, "net_token", 64, false, true, f.egressNetToken))
        return false;
    if (!intField(o, "spent_bytes", 0, qint64(1) << 36, 0, false, false, f.spentBytes))
        return false;
    if (!intField(o, "retries", 0, 100, 0, false, false, n))
        return false;
    f.retries = int(n);
    if (!boolField(o, "dns_exercised", false, false, f.dnsExercised))
        return false;
    if (!boolField(o, "handshake_ok", false, false, f.handshakeOk))
        return false;
    if (!intField(o, "handshake_ms", 0, 600000, -1, false, true, n))
        return false;
    f.handshakeMs = int(n);
    if (!intField(o, "echo_sent", 0, 100000, 0, false, false, n))
        return false;
    f.echoSent = int(n);
    if (!intField(o, "echo_replies", 0, 100000, 0, false, false, n) || n > f.echoSent)
        return false;
    f.echoReplies = int(n);
    if (!intField(o, "start_ms", 0, 600000, -1, false, true, f.startMs)
        || !intField(o, "end_ms", 0, 600000, -1, false, true, f.endMs))
        return false;
    if (f.startMs >= 0 && f.endMs >= 0 && f.endMs < f.startMs)
        return false;
    return true;
}

// ATTEMPT of a scan_progress: null / absent = not made; an object needs "attempted"; the rest is optional.
inline bool scanDecodeAccessAttempt(const QJsonValue &v, ScanAccessAttempt &a)
{
    using namespace scanwire;
    a = ScanAccessAttempt();
    if (v.isNull() || v.isUndefined())
        return true;
    if (!v.isObject())
        return false;
    const QJsonObject o = v.toObject();
    qint64 asn = 0;
    if (!boolField(o, "attempted", false, true, a.attempted) || !boolField(o, "http_answered", false, a.attempted, a.httpAnswered)
        || !intField(o, "asn", 1, 4294967295LL, 0, false, true, asn) || !strField(o, "net_token", 64, false, true, a.facts.netToken)
        || !intField(o, "at_ms", 0, 600000, -1, false, true, a.atMs))
        return false;
    a.facts.asn = asn;
    const QJsonValue g = o.value(QLatin1String("gen"));
    if (!g.isNull() && !g.isUndefined()) {
        if (!scanNetSourceFromJson(g, a.gen))
            return false;
        a.hasGen = true;
    }
    if (!a.attempted) {
        a = ScanAccessAttempt(); // "not made" carries nothing
    } else if (!a.httpAnswered) {
        a.facts = ScanAccess(); // no HTTP answer: no facts, whatever was sent
    }
    return true;
}

inline ScanHostReply scanDecodeReply(const QByteArray &bytes)
{
    using namespace scanwire;
    ScanHostReply r;
    const auto malformed = [&r](const char *why) {
        r = ScanHostReply();
        r.kind = ScanHostReplyKind::Error;
        r.error = ScanHostError::Malformed;
        r.detail = QLatin1String(why);
        return r;
    };
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(bytes, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject())
        return malformed("json");
    const QJsonObject o = doc.object();
    qint64 n = 0;
    if (o.contains(QLatin1String("error"))) {
        if (!o.value(QLatin1String("error")).isString() || o.value(QLatin1String("error")).toString().isEmpty())
            return malformed("error");
        r.kind = ScanHostReplyKind::Error;
        r.errorCode = o.value(QLatin1String("error")).toString().left(64);
        r.error = scanHostErrorFrom(r.errorCode);
        r.detail = o.value(QLatin1String("detail")).toString().left(128);
        r.scanId = o.value(QLatin1String("scan_id")).toString().left(64);
        if (intField(o, "mem_mb", 0, 1 << 20, -1, false, true, n))
            r.memMb = int(n);
        if (intField(o, "need_mb", 0, 1 << 20, -1, false, true, n))
            r.needMb = int(n);
        return r;
    }
    const QString type = o.value(QLatin1String("type")).toString();
    if (type == QLatin1String("scan_caps")) {
        if (o.value(QLatin1String("version")).toString() != QLatin1String(kScanHostVersion)) {
            r.kind = ScanHostReplyKind::Error;
            r.error = ScanHostError::Version;
            r.errorCode = QStringLiteral("version");
            return r;
        }
        r.kind = ScanHostReplyKind::Caps;
        if (!intField(o, "max_full_concurrent", 0, 64, 0, true, false, n))
            return malformed("max_full_concurrent");
        r.caps.maxFullConcurrent = int(qMin<qint64>(n, 8));
        if (!intField(o, "max_leg_concurrent", 0, 64, 0, false, false, n))
            return malformed("max_leg_concurrent");
        r.caps.maxLegConcurrent = int(qMin<qint64>(n, 32));
        if (!intField(o, "max_awg_concurrent", 0, 64, 0, false, false, n))
            return malformed("max_awg_concurrent");
        r.caps.maxAwgConcurrent = int(qMin<qint64>(n, 16));
        if (!boolField(o, "can_verify_composite", false, true, r.caps.canVerifyComposite)
            || !boolField(o, "needs_vpn", false, true, r.caps.needsVpn)
            || !boolField(o, "dns_plan", false, false, r.caps.dnsPlan)
            || !boolField(o, "reach_stage", true, false, r.caps.reachStage))
            return malformed("caps");
        if (!strField(o, "platform", 32, false, true, r.caps.platform))
            return malformed("platform");
        const QJsonValue kv = o.value(QLatin1String("kinds"));
        if (!kv.isArray())
            return malformed("kinds");
        for (const QJsonValue &k : kv.toArray()) {
            if (!k.isString())
                return malformed("kinds");
            r.kinds << k.toString();
        }
        // A pool without its kind in `kinds` does not exist (the list is the host's promise).
        if (!r.kinds.contains(QStringLiteral("xray_full")))
            r.caps.maxFullConcurrent = 0;
        if (!r.kinds.contains(QStringLiteral("xray_leg")))
            r.caps.maxLegConcurrent = 0;
        if (!r.kinds.contains(QStringLiteral("awg_mini")))
            r.caps.maxAwgConcurrent = 0;
        if (r.caps.maxFullConcurrent == 0)
            r.caps.canVerifyComposite = false;
        if (r.caps.maxLegConcurrent == 0)
            r.caps.dnsPlan = false;
        if (!intField(o, "mem_mb", 0, 1 << 20, -1, false, true, n))
            return malformed("mem_mb");
        r.caps.memMb = int(n);
        return r;
    }
    if (type == QLatin1String("scan_ack")) {
        r.kind = ScanHostReplyKind::Ack;
        if (!strField(o, "scan_id", 64, true, false, r.scanId) || r.scanId.isEmpty())
            return malformed("scan_id");
        if (!intField(o, "accepted", 0, kScanHostMaxCandidates, 0, false, false, n))
            return malformed("accepted");
        r.accepted = int(n);
        if (!intField(o, "mem_mb", 0, 1 << 20, -1, false, true, n))
            return malformed("mem_mb");
        r.memMb = int(n);
        if (!boolField(o, "final", false, false, r.finalTotals))
            return malformed("final");
        if (!intField(o, "bytes_spent", 0, qint64(1) << 36, -1, r.finalTotals, false, r.bytesSpent))
            return malformed("bytes_spent"); // required with final
        return r;
    }
    if (type == QLatin1String("scan_freeze_ack")) {
        r.kind = ScanHostReplyKind::FreezeAck;
        if (!strField(o, "scan_id", 64, true, false, r.scanId) || r.scanId.isEmpty())
            return malformed("scan_id");
        if (!intField(o, "spent", 0, qint64(1) << 36, 0, true, false, r.bytesSpent)
            || !intField(o, "reserved", 0, qint64(1) << 36, 0, true, false, r.bytesReserved))
            return malformed("freeze_totals"); // both required
        return r;
    }
    if (type == QLatin1String("scan_progress")) {
        r.kind = ScanHostReplyKind::Progress;
        ScanHostProgress &p = r.progress;
        if (!strField(o, "scan_id", 64, true, false, p.scanId) || p.scanId.isEmpty())
            return malformed("scan_id");
        if (!intField(o, "seq", 0, qint64(1) << 40, 0, true, false, p.seq))
            return malformed("seq");
        if (!strField(o, "phase", 8, true, false, p.phase)
            || (p.phase != QLatin1String("reach") && p.phase != QLatin1String("data") && p.phase != QLatin1String("done")))
            return malformed("phase");
        const QJsonValue iv = o.value(QLatin1String("items"));
        if (!iv.isArray() || iv.toArray().size() > kScanHostMaxItems)
            return malformed("items");
        for (const QJsonValue &v : iv.toArray()) {
            ScanProbeFacts f;
            if (!scanDecodeItem(v, f))
                return malformed("item");
            p.items << f;
        }
        if (!intField(o, "bytes_spent", 0, qint64(1) << 36, 0, true, false, p.bytesSpent))
            return malformed("bytes_spent");
        if (!intField(o, "bytes_reserved", 0, qint64(1) << 36, 0, false, false, p.bytesReserved))
            return malformed("bytes_reserved");
        if (!intField(o, "mem_mb", 0, 1 << 20, -1, false, true, n))
            return malformed("mem_mb");
        p.memMb = int(n);
        if (!boolField(o, "done", false, true, p.done))
            return malformed("done");
        if (!boolField(o, "final", false, false, p.finalTotals) || (p.finalTotals && !p.done))
            return malformed("final"); // final implies done
        if (!strField(o, "reason", 32, false, true, p.reason))
            return malformed("reason");
        if (!scanDecodeAccessAttempt(o.value(QLatin1String("access")), p.access))
            return malformed("access");
        if (!scanDecodeAccessAttempt(o.value(QLatin1String("access_close")), p.accessClose))
            return malformed("access_close");
        const QJsonValue g = o.value(QLatin1String("gen"));
        if (!g.isNull() && !g.isUndefined()) {
            if (!scanNetSourceFromJson(g, p.gen))
                return malformed("gen");
            p.hasGen = true;
        }
        return r;
    }
    return malformed("type");
}

} // namespace avpn
