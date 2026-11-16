// AVPN Scanner: shared test vectors for the other implementations of the contract (the Go probe engine, the
// Swift bridge of the iOS extension, the Kotlin side on Android - none of them links Qt) and for later lanes
// that drive the C++ machine (coordinator, QML mocks). This program REPLAYS tests/vectors/scan_*_vectors.json
// against the real C++ code (default), so the files can never drift from it, and re-records them from the
// definitions below (--record; only after a deliberate behaviour change; the JSON diff is part of the review).
// --record REFUSES TO WRITE when any self-check fails (scenario expectations, per-step invariants, the
// expected outcome of every host vector).
//
// ---- scan_host_vectors.json (ScanHostContract.h, `tribe-scan-v1`) ---------------------------------------
// { "schema": 1, "version": "tribe-scan-v1",
//   "requests": [ { "name", "json": <request object exactly as sent>, "expect": { "error": "" | "unknown_action" |
//                   "version" | "bad_request", "detail": str (bad_request only), "decoded": SUMMARY | null } } ],
//   "replies":  [ { "name", "json": <reply object or a string = raw bytes that are not an object>,
//                   "expect": { "kind": "caps" | "ack" | "progress" | "error", "error": str, "decoded": SUMMARY } } ],
//   "byte_gate": [ { "name", "max_bytes": int (-1 = no cap), "ops": [ { "op": "admit" | "finish" | "charge", "id", "bytes",
//                    "expect": { "ok": bool, "spent": int, "reserved": int } } ] } ] }
//   byte_gate = the shared byte cap of every pool and retry (ScanHostByteGate, review F6): a host replays each op
//   on a fresh gate per case and must answer exactly (finish/charge "ok" = false only for a refused charge).
// A host implementation (Go, Swift, Kotlin): every request vector must be accepted or refused exactly as
// stated (same error code; bad_request detail = the first offending field) and a refusal must be answered as
// {"error": code}; every reply vector is a reply the app accepts as stated - a host's own encoder must produce
// replies that decode to the same SUMMARY. SUMMARY = the decoded fields in a canonical object (see
// requestSummary / replySummary below); secrets appear only as their length ("token_len", "config_len").
//
// ---- scan_machine_vectors.json (ScanMachine.h) ------------------------------------------------------------
// { "schema": 1, "clock": "wall-clock ms; a fake origin",
//   "scenarios": [ { "name", "rules": [str], "caps": CAPS, "ledger": [...],
//                    "steps": [ { "event": EVENT (scan_world.h: {event, now_ms, args}),
//                                 "expect": { "actions": [ACTION (scanActionToJson)], "wake_at_ms": int,
//                                             "view": VIEW (scanViewToJson) | null (= unchanged) } } ] } ] }
// A scenario starts with a NEW machine built from CAPS, the ledger restored. Actions compare as an ordered
// list, objects by exact key set and value.
//
// ---- scan_race_vectors.json (ScanAutoRace.h) ----------------------------------------------------------------
// { "schema": 1, "cases": [ { "name", "config": {enabled, alternates, stagger_ms, commit_bytes, probe_total_ms},
//   "candidates": [{id, tier, rank, lkg, eligible}], "live": bool,
//   "steps": [ { "event": "start" | "progress" | "failed" | "commit_failed" | "tick" | "cancel", "id", "bytes",
//                "now_ms", "expect": { "actions": [{kind, id, tier, reason}], "wake_at_ms", "state", "tier" } } ] } ] }
//
// Build/run: build_scan_core.sh  (re-record: build_scan_core.sh --record)
#include "scan_scenarios.h"

#include "../ScanAutoRace.h"
#include "../ScanHostContract.h"
#include "../ScanMachine.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

using namespace avpn;
using namespace scantest;

static int g_fail = 0, g_total = 0;
static void check(bool ok, const QString &what)
{
    ++g_total;
    if (!ok) {
        ++g_fail;
        std::printf("FAIL %s\n", qPrintable(what));
    }
}

// --- summaries ------------------------------------------------------------------------------------------

static QJsonObject candSummary(const ScanHostCandidate &c)
{
    return QJsonObject{{QStringLiteral("id"), c.id}, {QStringLiteral("kind"), QLatin1String(scanProbeKindName(c.kind))},
                       {QStringLiteral("config_len"), c.config.size()},
                       {QStringLiteral("entry"), c.entryIp.isEmpty() ? QString() : c.entryIp + QLatin1Char(':') + QString::number(c.entryPort)},
                       {QStringLiteral("reach_at_ms"), double(c.reachAtMs)}, {QStringLiteral("profile_id"), c.profileId},
                       {QStringLiteral("early_retry"), c.earlyRetry}, {QStringLiteral("dns_plan"), c.dnsPlan},
                       {QStringLiteral("cost_bytes"), double(c.costBytes)}};
}

// The later optional fields join the summary only when set: the recorded expectations of earlier vectors stay.
static QJsonObject candSummaryV23(const ScanHostCandidate &c)
{
    QJsonObject o = candSummary(c);
    if (c.bytes > 0)
        o.insert(QStringLiteral("bytes"), c.bytes);
    if (c.totalMs > 0)
        o.insert(QStringLiteral("total_ms"), c.totalMs);
    return o;
}

static QJsonObject requestSummary(const ScanHostRequest &r)
{
    static const char *names[] = {"scan_caps", "scan_start", "scan_add", "scan_poll", "scan_freeze", "scan_cancel"};
    QJsonObject o{{QStringLiteral("action"), QLatin1String(names[int(r.action)])}};
    if (r.action == ScanHostAction::Caps)
        return o;
    o.insert(QStringLiteral("scan_id"), r.start.scanId);
    if (r.action == ScanHostAction::Poll)
        o.insert(QStringLiteral("since"), double(r.since));
    if (r.action == ScanHostAction::Add) {
        QJsonArray cs;
        for (const ScanHostCandidate &c : r.candidates)
            cs << candSummaryV23(c);
        o.insert(QStringLiteral("candidates"), cs);
    }
    if (r.action == ScanHostAction::Start) {
        o.insert(QStringLiteral("deadline_ms"), double(r.start.deadlineMs));
        o.insert(QStringLiteral("max_bytes"), double(r.start.maxBytes));
        o.insert(QStringLiteral("limits"), scanHostLimitsToJson(r.start.limits));
        o.insert(QStringLiteral("probe"), QJsonObject{{QStringLiteral("base"), r.start.probeBase}, {QStringLiteral("path"), r.start.probePath},
                                                      {QStringLiteral("netinfo_path"), r.start.netinfoPath},
                                                      {QStringLiteral("token_len"), r.start.token.size()},
                                                      {QStringLiteral("warm_bytes"), r.start.warmBytes}, {QStringLiteral("bytes"), r.start.bytes},
                                                      {QStringLiteral("access_asn"), double(r.start.access.asn)},
                                                      {QStringLiteral("access_net_token_len"), r.start.access.netToken.size()}});
        QJsonArray cs;
        for (const ScanHostCandidate &c : r.start.candidates)
            cs << candSummaryV23(c);
        o.insert(QStringLiteral("candidates"), cs);
        if (!r.start.probeBaseIps.isEmpty())
            o.insert(QStringLiteral("probe_base_ips"), QJsonArray::fromStringList(r.start.probeBaseIps));
    }
    return o;
}

static QJsonObject replySummary(const ScanHostReply &r)
{
    QJsonObject o;
    switch (r.kind) {
    case ScanHostReplyKind::Caps:
        o.insert(QStringLiteral("max_full_concurrent"), r.caps.maxFullConcurrent);
        o.insert(QStringLiteral("max_leg_concurrent"), r.caps.maxLegConcurrent);
        o.insert(QStringLiteral("max_awg_concurrent"), r.caps.maxAwgConcurrent);
        o.insert(QStringLiteral("can_verify_composite"), r.caps.canVerifyComposite);
        o.insert(QStringLiteral("dns_plan"), r.caps.dnsPlan);
        o.insert(QStringLiteral("reach_stage"), r.caps.reachStage);
        o.insert(QStringLiteral("needs_vpn"), r.caps.needsVpn);
        o.insert(QStringLiteral("mem_mb"), r.caps.memMb);
        o.insert(QStringLiteral("platform"), r.caps.platform);
        break;
    case ScanHostReplyKind::Ack:
        o.insert(QStringLiteral("scan_id"), r.scanId);
        o.insert(QStringLiteral("accepted"), r.accepted);
        o.insert(QStringLiteral("mem_mb"), r.memMb);
        o.insert(QStringLiteral("final"), r.finalTotals);
        o.insert(QStringLiteral("bytes_spent"), double(r.bytesSpent));
        break;
    case ScanHostReplyKind::FreezeAck:
        o.insert(QStringLiteral("scan_id"), r.scanId);
        o.insert(QStringLiteral("spent"), double(r.bytesSpent));
        o.insert(QStringLiteral("reserved"), double(r.bytesReserved));
        break;
    case ScanHostReplyKind::Progress: {
        const ScanHostProgress &p = r.progress;
        o.insert(QStringLiteral("scan_id"), p.scanId);
        o.insert(QStringLiteral("seq"), double(p.seq));
        o.insert(QStringLiteral("phase"), p.phase);
        o.insert(QStringLiteral("bytes_spent"), double(p.bytesSpent));
        o.insert(QStringLiteral("bytes_reserved"), double(p.bytesReserved));
        o.insert(QStringLiteral("done"), p.done);
        o.insert(QStringLiteral("final"), p.finalTotals);
        o.insert(QStringLiteral("reason"), p.reason);
        const auto att = [](const ScanAccessAttempt &a) {
            return QJsonObject{{QStringLiteral("attempted"), a.attempted}, {QStringLiteral("http_answered"), a.httpAnswered},
                               {QStringLiteral("asn"), double(a.facts.asn)}, {QStringLiteral("net_token_len"), a.facts.netToken.size()},
                               {QStringLiteral("at_ms"), double(a.atMs)},
                               {QStringLiteral("gen"), a.hasGen ? QJsonValue(scanNetSourceToJson(a.gen)) : QJsonValue(QJsonValue::Null)}};
        };
        o.insert(QStringLiteral("access"), att(p.access));
        o.insert(QStringLiteral("access_close"), att(p.accessClose));
        o.insert(QStringLiteral("gen"), p.hasGen ? QJsonValue(scanNetSourceToJson(p.gen)) : QJsonValue(QJsonValue::Null));
        QJsonArray items;
        for (const ScanProbeFacts &f : p.items)
            items << scanProbeFactsToJson(f);
        o.insert(QStringLiteral("items"), items);
        break;
    }
    case ScanHostReplyKind::Error:
        o.insert(QStringLiteral("code"), r.errorCode);
        o.insert(QStringLiteral("mem_mb"), r.memMb);
        o.insert(QStringLiteral("need_mb"), r.needMb);
        break;
    }
    return o;
}

static const char *replyKindName(ScanHostReplyKind k)
{
    switch (k) {
    case ScanHostReplyKind::Caps: return "caps";
    case ScanHostReplyKind::Ack: return "ack";
    case ScanHostReplyKind::Progress: return "progress";
    case ScanHostReplyKind::FreezeAck: return "freeze_ack";
    case ScanHostReplyKind::Error: break;
    }
    return "error";
}

// --- host vectors ----------------------------------------------------------------------------------------

static QJsonObject reqVector(const char *name, const QJsonValue &json, const char *expectError = "", const char *detail = "")
{
    return QJsonObject{{QStringLiteral("name"), QLatin1String(name)}, {QStringLiteral("json"), json},
                       {QStringLiteral("want_error"), QLatin1String(expectError)}, {QStringLiteral("want_detail"), QLatin1String(detail)}};
}

static QByteArray rawOf(const QJsonValue &v)
{
    return v.isString() ? v.toString().toUtf8() : QJsonDocument(v.toObject()).toJson(QJsonDocument::Compact);
}

static QJsonObject requestExpect(const QJsonValue &json)
{
    ScanHostRequest r;
    QString detail;
    const ScanHostError e = scanDecodeRequest(rawOf(json), r, &detail);
    QJsonObject x{{QStringLiteral("error"), QLatin1String(scanHostErrorName(e))}};
    if (e == ScanHostError::BadRequest)
        x.insert(QStringLiteral("detail"), detail);
    x.insert(QStringLiteral("decoded"), e == ScanHostError::None ? QJsonValue(requestSummary(r)) : QJsonValue(QJsonValue::Null));
    return x;
}

static QJsonObject replyExpect(const QJsonValue &json)
{
    const ScanHostReply r = scanDecodeReply(rawOf(json));
    return QJsonObject{{QStringLiteral("kind"), QLatin1String(replyKindName(r.kind))},
                       {QStringLiteral("error"), r.kind == ScanHostReplyKind::Error ? QLatin1String(scanHostErrorName(r.error)) : QLatin1String("")},
                       {QStringLiteral("decoded"), replySummary(r)}};
}

static ScanStartRequest startSample(const ScanHostCaps &caps)
{
    // A real start request: the planner's schedule for the artboard world on this host, joined with test
    // secrets the way the coordinator joins them (scanBuildStartRequest).
    World w = baseWorld("vec", caps, ScanNetKind::Wifi);
    ScanMachine m(caps);
    ScanOpen o;
    o.network = w.net;
    o.current = liveOf(w, QStringLiteral("1"), true);
    m.opened(o, kT0);
    const ScanStep s = m.manifestReady(manifestInputFrom(manifestArgs(w)), kT0 + 80);
    ScanAccess acc;
    acc.asn = 64500;
    acc.netToken = QStringLiteral("net-access");
    const ScanAction *a = s.find(ScanActionKind::StartHostScan);
    ScanStartRequest r = scanBuildStartRequest(*a, QStringLiteral("tsc1.TEST-NOT-A-TOKEN"), QStringLiteral("https://api.example.test"), acc,
                                               [](const ScanCandidate &c) { return QStringLiteral("{\"test-config-for\":\"%1\"}").arg(c.id); });
    // An explicit fixture value since the compiled default became 4096 (lab seam S2): the host vectors are exported
    // into the Go engine's package (recipes/), so they keep the number they were recorded with, byte for byte.
    r.limits.stallAfterBytes = 16384;
    return r;
}

static QJsonObject hostVectors()
{
    QJsonArray reqs;
    const QJsonObject minimal = scanEncodeStart(startSample(hostIosMinimal()));
    const QJsonObject full = scanEncodeStart(startSample(hostMac()));
    reqs << reqVector("caps", scanEncodeCaps());
    reqs << reqVector("start_minimal_ios_host", minimal);
    reqs << reqVector("start_full_host_legs_awg", full);
    ScanHostCandidate fu;
    fu.id = up(3) + QStringLiteral("#full");
    fu.kind = ScanProbeKind::XrayFull;
    fu.config = QStringLiteral("{\"test\":true}");
    fu.profileId = QStringLiteral("00000000000000a3");
    fu.earlyRetry = true;
    fu.costBytes = 82944;
    reqs << reqVector("add_follow_up", scanEncodeAdd(QStringLiteral("scan-1789000000000-1"), {fu}));
    reqs << reqVector("poll", scanEncodePoll(QStringLiteral("scan-1789000000000-1"), 12));
    reqs << reqVector("freeze", scanEncodeFreeze(QStringLiteral("scan-1789000000000-1")));
    reqs << reqVector("cancel", scanEncodeCancel(QStringLiteral("scan-1789000000000-1")));
    QJsonObject np = full;
    QJsonObject probe = np.value(QStringLiteral("probe")).toObject();
    probe.insert(QStringLiteral("netinfo_path"), QStringLiteral("v1/netinfo"));
    np.insert(QStringLiteral("probe"), probe);
    reqs << reqVector("relative_netinfo_path", np, "bad_request", "probe.netinfo_path");
    reqs << reqVector("unknown_action", QJsonObject{{QStringLiteral("action"), QStringLiteral("scan_teleport")}}, "unknown_action");
    reqs << reqVector("other_channel_action", QJsonObject{{QStringLiteral("action"), QStringLiteral("status")}}, "unknown_action");
    QJsonObject v = full;
    v.insert(QStringLiteral("version"), QStringLiteral("tribe-scan-v2"));
    reqs << reqVector("version_mismatch", v, "version");
    QJsonObject nt = full;
    probe = nt.value(QStringLiteral("probe")).toObject();
    probe.remove(QStringLiteral("token"));
    nt.insert(QStringLiteral("probe"), probe);
    reqs << reqVector("missing_token", nt, "bad_request", "probe.token");
    QJsonObject http = full;
    probe = http.value(QStringLiteral("probe")).toObject();
    probe.insert(QStringLiteral("base"), QStringLiteral("http://plain.example"));
    http.insert(QStringLiteral("probe"), probe);
    reqs << reqVector("plain_http_base", http, "bad_request", "probe.base");
    QJsonObject nc = full;
    QJsonArray cs = nc.value(QStringLiteral("candidates")).toArray();
    QJsonObject c0 = cs.at(0).toObject();
    c0.remove(QStringLiteral("config"));
    cs[0] = c0;
    nc.insert(QStringLiteral("candidates"), cs);
    reqs << reqVector("candidate_without_config", nc, "bad_request", "candidates");
    QJsonObject lim = full;
    QJsonObject l = lim.value(QStringLiteral("limits")).toObject();
    l.insert(QStringLiteral("concurrency"), 999);
    lim.insert(QStringLiteral("limits"), l);
    reqs << reqVector("limit_out_of_range", lim, "bad_request", "concurrency");
    QJsonObject old = minimal;
    l = old.value(QStringLiteral("limits")).toObject();
    for (const char *k : {"leg_concurrency", "awg_concurrency", "awg_handshake_ms", "awg_prime_echoes", "awg_spacing_ms", "netinfo_cost_bytes"})
        l.remove(QLatin1String(k));
    old.insert(QStringLiteral("limits"), l);
    reqs << reqVector("app_without_pool_fields", old);
    QJsonObject fut = full;
    fut.insert(QStringLiteral("future_field"), QJsonObject{{QStringLiteral("x"), 1}});
    reqs << reqVector("unknown_field_ignored", fut);
    reqs << reqVector("not_json", QJsonValue(QStringLiteral("{nope")), "bad_request", "json");
    reqs << reqVector("poll_negative_since", QJsonObject{{QStringLiteral("action"), QStringLiteral("scan_poll")}, {QStringLiteral("scan_id"), QStringLiteral("s")},
                                                         {QStringLiteral("since"), -1}}, "bad_request", "since");
    // contract pass of 16.11 (new cases only, appended): probe.base_ips, the typed awg_mini config, per-job
    // bytes / total_ms
    {
        ScanStartRequest awgStart = startSample(hostMac());
        ScanCandidate awg;
        awg.id = QStringLiteral("2");
        awg.kind = ScanProbeKind::AwgMini;
        awg.awgEchoTarget = QStringLiteral("10.8.1.1");
        awg.costBytes = 85292;
        QList<QPair<QString, QString>> refused;
        awgStart.candidates = scanBuildHostCandidates(QList<ScanCandidate>{awg}, [](const ScanCandidate &) { return QString(); },
                                                      [](const ScanCandidate &) { return testAwgInput(); }, &refused);
        check(awgStart.candidates.size() == 1 && refused.isEmpty(), QStringLiteral("typed awg candidate built"));
        awgStart.probeBaseIps = {QStringLiteral("198.51.100.7"), QStringLiteral("2001:db8::7")};
        const QJsonObject awgJson = scanEncodeStart(awgStart);
        reqs << reqVector("start_awg_mini_typed_config_and_base_ips", awgJson);
        ScanStartRequest job = startSample(hostMac());
        job.candidates[0].bytes = 24576;
        job.candidates[0].totalMs = 3000;
        const QJsonObject jobJson = scanEncodeStart(job);
        reqs << reqVector("start_candidate_job_bytes_total_ms", jobJson);
        QJsonObject host = awgJson;
        QJsonObject pr = host.value(QStringLiteral("probe")).toObject();
        pr.insert(QStringLiteral("base_ips"), QJsonArray{QStringLiteral("api.tribe.example")});
        host.insert(QStringLiteral("probe"), pr);
        reqs << reqVector("base_ips_with_a_host_name", host, "bad_request", "probe.base_ips");
        QJsonArray nine;
        for (int i = 1; i <= 9; ++i)
            nine << QStringLiteral("198.51.100.%1").arg(i);
        pr.insert(QStringLiteral("base_ips"), nine);
        host.insert(QStringLiteral("probe"), pr);
        reqs << reqVector("base_ips_more_than_eight", host, "bad_request", "probe.base_ips");
        QJsonObject jb = jobJson;
        QJsonArray jcs = jb.value(QStringLiteral("candidates")).toArray();
        QJsonObject j0 = jcs.at(0).toObject();
        j0.insert(QStringLiteral("total_ms"), 60000);
        jcs[0] = j0;
        jb.insert(QStringLiteral("candidates"), jcs);
        reqs << reqVector("job_total_ms_out_of_range", jb, "bad_request", "candidates");
    }
    QJsonArray outReqs;
    for (const QJsonValue &x : reqs) {
        QJsonObject o = x.toObject();
        o.insert(QStringLiteral("expect"), requestExpect(o.value(QStringLiteral("json"))));
        // self-check: the vector means what its name says
        check(o.value(QStringLiteral("expect")).toObject().value(QStringLiteral("error")).toString() == o.value(QStringLiteral("want_error")).toString(),
              QStringLiteral("request vector ") + o.value(QStringLiteral("name")).toString());
        if (!o.value(QStringLiteral("want_detail")).toString().isEmpty())
            check(o.value(QStringLiteral("expect")).toObject().value(QStringLiteral("detail")).toString() == o.value(QStringLiteral("want_detail")).toString(),
                  QStringLiteral("request vector detail ") + o.value(QStringLiteral("name")).toString());
        o.remove(QStringLiteral("want_error"));
        o.remove(QStringLiteral("want_detail"));
        outReqs << o;
    }

    QJsonArray reps;
    const auto rep = [&reps](const char *name, const QJsonValue &json, const char *wantKind, const char *wantError = "") {
        reps << QJsonObject{{QStringLiteral("name"), QLatin1String(name)}, {QStringLiteral("json"), json},
                            {QStringLiteral("want_kind"), QLatin1String(wantKind)}, {QStringLiteral("want_error"), QLatin1String(wantError)}};
    };
    rep("caps_minimal_ios_host", QJsonObject{{QStringLiteral("type"), QStringLiteral("scan_caps")}, {QStringLiteral("version"), QStringLiteral("tribe-scan-v1")},
                                             {QStringLiteral("max_full_concurrent"), 1}, {QStringLiteral("can_verify_composite"), false},
                                             {QStringLiteral("needs_vpn"), true}, {QStringLiteral("kinds"), QJsonArray{QStringLiteral("xray_full")}},
                                             {QStringLiteral("mem_mb"), 31}}, "caps");
    rep("caps_macos_service", scanEncodeCapsReply(hostMac(), {QStringLiteral("xray_full"), QStringLiteral("xray_leg"), QStringLiteral("awg_mini")}), "caps");
    ScanHostCaps android;
    android.maxFullConcurrent = 1;
    android.maxLegConcurrent = 4;
    android.dnsPlan = true;
    android.maxAwgConcurrent = 2;
    android.platform = QStringLiteral("android");
    rep("caps_android_vpnservice", scanEncodeCapsReply(android, {QStringLiteral("xray_full"), QStringLiteral("xray_leg"), QStringLiteral("awg_mini")}), "caps");
    rep("caps_pools_without_kinds", scanEncodeCapsReply(hostMac(), {QStringLiteral("xray_full")}), "caps");
    rep("caps_version_mismatch", QJsonObject{{QStringLiteral("type"), QStringLiteral("scan_caps")}, {QStringLiteral("version"), QStringLiteral("tribe-scan-v9")}},
        "error", "version");
    rep("ack", scanEncodeAck(QStringLiteral("scan-1789000000000-1"), 12, 38), "ack");
    rep("ack_cancel_final_total", scanEncodeCancelAck(QStringLiteral("scan-1789000000000-1"), 412345, 36), "ack");
    QJsonObject noTotal = scanEncodeAck(QStringLiteral("scan-1789000000000-1"), 0, 36);
    noTotal.insert(QStringLiteral("final"), true);
    rep("malformed_final_ack_without_total", noTotal, "error", "malformed");
    rep("freeze_ack", scanEncodeFreezeAck(QStringLiteral("scan-1789000000000-1"), 182528, 165888), "freeze_ack");
    rep("malformed_freeze_ack_without_reserved", QJsonObject{{QStringLiteral("type"), QStringLiteral("scan_freeze_ack")},
                                                             {QStringLiteral("scan_id"), QStringLiteral("scan-1789000000000-1")},
                                                             {QStringLiteral("spent"), 182528}}, "error", "malformed");
    ScanHostProgress p;
    p.scanId = QStringLiteral("scan-1789000000000-1");
    p.seq = 4;
    p.phase = QStringLiteral("data");
    ScanProbeFacts r1;
    r1.id = QStringLiteral("4:xray");
    r1.stage = ScanStage::Reach;
    r1.seq = 1;
    r1.reachOk = true;
    r1.reachMs = 84;
    ScanProbeFacts r2 = r1;
    r2.id = QStringLiteral("7:xray");
    r2.seq = 2;
    r2.reachOk = false;
    r2.reachMs = 1500;
    r2.error = ScanProbeError::ReachTimeout;
    ScanProbeFacts d1;
    d1.id = up(1);
    d1.seq = 3;
    d1.httpStatus = 200;
    d1.ttfb1Ms = 410;
    d1.rttMs = 62;
    d1.t64Ms = 180;
    d1.durationMs = 760;
    d1.bytesRequested = d1.bytesReceived = 65536;
    d1.shaOk = true;
    d1.egressClass = QStringLiteral("other");
    d1.egressAsn = 64600;
    d1.egressNetToken = QStringLiteral("net-exit");
    d1.dnsExercised = true;
    d1.spentBytes = 83456;
    ScanProbeFacts a1;
    a1.id = QStringLiteral("2");
    a1.seq = 4;
    a1.handshakeOk = true;
    a1.handshakeMs = 70;
    a1.echoSent = 1;
    a1.echoReplies = 0;     // the prime echo was lost (S4): diagnostic only
    a1.httpStatus = 200;
    a1.ttfb1Ms = 390;
    a1.rttMs = 51;
    a1.t64Ms = 230;
    a1.durationMs = 650;
    a1.bytesRequested = a1.bytesReceived = 65536;
    a1.shaOk = true;
    a1.egressClass = QStringLiteral("tribe-node");
    a1.egressNode = QStringLiteral("2");
    a1.spentBytes = 85292;
    p.items << r1 << r2 << d1 << a1;
    ScanProbeFacts x1;
    x1.id = QStringLiteral("4:xray");
    x1.seq = 5;
    x1.httpStatus = 200;
    x1.ttfb1Ms = 300;
    x1.rttMs = 44;
    x1.t64Ms = 150;
    x1.durationMs = 520;
    x1.bytesRequested = x1.bytesReceived = 65536;
    x1.shaOk = true;
    x1.egressClass = QStringLiteral("tribe-node");
    x1.egressNode = QStringLiteral("4");
    x1.spentBytes = 83456;
    p.items << x1;
    p.seq = 5;
    p.bytesSpent = 182528 + 83456;
    p.bytesReserved = 83968 + 10240; // one leg still running + the closing attempt's reservation
    p.memMb = 34;
    const ScanNetSource ne{QStringLiteral("ne"), 0x5eed5eed5eed5eedULL, 3};
    p.access.attempted = true; // the opening attempt answered 200
    p.access.httpAnswered = true;
    p.access.facts.asn = 64500;
    p.access.facts.netToken = QStringLiteral("net-access");
    p.access.atMs = 0;
    p.access.hasGen = true;
    p.access.gen = ne;
    p.hasGen = true;
    p.gen = ne;
    for (ScanProbeFacts *f : {&d1, &a1, &x1}) {
        f->startMs = 100 + 50 * int(f->seq);
        f->endMs = f->startMs + f->durationMs;
    }
    p.items.clear();
    p.items << r1 << r2 << d1 << a1 << x1;
    const QJsonObject pj = scanEncodeProgress(p);
    rep("progress_reach_data_awg", pj, "progress");
    ScanHostProgress done;
    done.scanId = p.scanId;
    done.seq = 4;
    done.phase = QStringLiteral("done");
    done.bytesSpent = 182528;
    done.done = true;
    done.reason = QStringLiteral("deadline");
    rep("progress_done_deadline", scanEncodeProgress(done), "progress");
    // the final progress after freeze + cancel: totals and the closing attempt (plan §2.2b, §2.2c)
    ScanHostProgress fin = done;
    fin.reason = QStringLiteral("cancelled");
    fin.finalTotals = true;
    fin.bytesSpent = 271360;
    fin.access = p.access;
    fin.accessClose.attempted = true;
    fin.accessClose.httpAnswered = true;
    fin.accessClose.facts = p.access.facts;
    fin.accessClose.atMs = 7400;
    fin.accessClose.hasGen = true;
    fin.accessClose.gen = ne;
    fin.hasGen = true;
    fin.gen = ne;
    rep("progress_final_after_cancel", scanEncodeProgress(fin), "progress");
    // a whitelist window: both attempts without any HTTP answer (the exclusion proof's input)
    ScanHostProgress wl = fin;
    wl.access = ScanAccessAttempt();
    wl.access.attempted = true;
    wl.access.atMs = 0;
    wl.access.hasGen = true;
    wl.access.gen = ne;
    wl.accessClose.httpAnswered = false;
    wl.accessClose.facts = ScanAccess();
    rep("progress_final_attempts_network_error", scanEncodeProgress(wl), "progress");
    QJsonObject fnd = scanEncodeProgress(fin);
    fnd.insert(QStringLiteral("done"), false);
    rep("malformed_final_without_done", fnd, "error", "malformed");
    QJsonObject att = scanEncodeProgress(fin);
    att.insert(QStringLiteral("access"), QJsonObject{{QStringLiteral("attempted"), true}});
    rep("malformed_attempt_without_http_answered", att, "error", "malformed");
    QJsonObject gbad = scanEncodeProgress(fin);
    gbad.insert(QStringLiteral("gen"), QJsonObject{{QStringLiteral("source"), QStringLiteral("ne")}, {QStringLiteral("epoch"), 12345}, {QStringLiteral("counter"), 3}});
    rep("malformed_gen_epoch_as_number", gbad, "error", "malformed");
    ScanHostProgress budget = done;
    budget.reason = QStringLiteral("complete");
    budget.phase = QStringLiteral("data");
    ScanProbeFacts b1;
    b1.id = QStringLiteral("10:xray");
    b1.seq = 5;
    b1.bytesRequested = 65536;
    b1.error = ScanProbeError::Budget;
    budget.items << b1;
    rep("progress_item_budget_refusal", scanEncodeProgress(budget), "progress");
    QJsonObject bad = pj;
    QJsonArray items = bad.value(QStringLiteral("items")).toArray();
    QJsonObject it3 = items.at(3).toObject();
    it3.insert(QStringLiteral("echo_replies"), 2); // more replies than echoes sent
    items[3] = it3;
    bad.insert(QStringLiteral("items"), items);
    rep("malformed_more_replies_than_echoes", bad, "error", "malformed");
    bad = pj;
    items = bad.value(QStringLiteral("items")).toArray();
    QJsonObject it2 = items.at(2).toObject();
    it2.insert(QStringLiteral("bytes"), QStringLiteral("65536"));
    items[2] = it2;
    bad.insert(QStringLiteral("items"), items);
    rep("malformed_bytes_as_string", bad, "error", "malformed");
    bad = pj;
    bad.remove(QStringLiteral("done"));
    rep("malformed_missing_done", bad, "error", "malformed");
    bad = pj;
    items = bad.value(QStringLiteral("items")).toArray();
    it2 = items.at(2).toObject();
    it2.remove(QStringLiteral("bytes"));
    items[2] = it2;
    bad.insert(QStringLiteral("items"), items);
    rep("malformed_data_item_without_bytes", bad, "error", "malformed");
    QJsonObject extra = pj;
    extra.insert(QStringLiteral("platform_detail"), QJsonObject{{QStringLiteral("whatever"), 1}});
    rep("unknown_field_ignored", extra, "progress");
    rep("error_unknown_action", QJsonObject{{QStringLiteral("error"), QStringLiteral("unknown_action")}}, "error", "unknown_action");
    rep("error_memory_guard", QJsonObject{{QStringLiteral("error"), QStringLiteral("memory")}, {QStringLiteral("mem_mb"), 44}, {QStringLiteral("need_mb"), 12}},
        "error", "memory");
    rep("error_no_vpn", QJsonObject{{QStringLiteral("error"), QStringLiteral("no_vpn")}}, "error", "no_vpn");
    rep("error_unknown_scan", QJsonObject{{QStringLiteral("error"), QStringLiteral("unknown_scan")}, {QStringLiteral("scan_id"), QStringLiteral("old")}},
        "error", "unknown_scan");
    rep("error_open_set", QJsonObject{{QStringLiteral("error"), QStringLiteral("thermal_throttle")}}, "error", "other");
    rep("raw_not_json", QJsonValue(QStringLiteral("<html>captive portal</html>")), "error", "malformed");
    rep("raw_empty", QJsonValue(QString()), "error", "malformed");
    // contract pass of 16.11 (new cases only, appended): item bind_failed + dns detail, host error bind_failed,
    // an opening attempt that never left the interface (null) next to a failed closing one
    {
        ScanHostProgress bp;
        bp.scanId = QStringLiteral("scan-1789000000000-1");
        bp.seq = 2;
        bp.phase = QStringLiteral("data");
        ScanProbeFacts bf;
        bf.id = up(1);
        bf.seq = 1;
        bf.bytesRequested = 65536;
        bf.error = ScanProbeError::BindFailed;
        bf.spentBytes = 0;
        ScanProbeFacts dl = d1;
        dl.seq = 2;
        bp.items << bf << dl;
        bp.bytesSpent = 75708;
        QJsonObject bj = scanEncodeProgress(bp);
        QJsonArray its = bj.value(QStringLiteral("items")).toArray();
        QJsonObject di = its.at(1).toObject();
        di.insert(QStringLiteral("dns"), QJsonArray{QJsonObject{{QStringLiteral("address"), QStringLiteral("1.1.1.1")}, {QStringLiteral("transport"), QStringLiteral("udp")},
                                                                {QStringLiteral("ok"), true}, {QStringLiteral("ms"), 41}, {QStringLiteral("rcode"), 0},
                                                                {QStringLiteral("answers"), 1}, {QStringLiteral("error"), QString()}}});
        its[1] = di;
        bj.insert(QStringLiteral("items"), its);
        rep("progress_item_bind_failed_and_dns_detail", bj, "progress");
        rep("error_bind_failed", QJsonObject{{QStringLiteral("error"), QStringLiteral("bind_failed")}}, "error", "bind_failed");
        rep("error_internal_kill_switch_detail", QJsonObject{{QStringLiteral("error"), QStringLiteral("internal")}, {QStringLiteral("detail"), QStringLiteral("kill_switch_exemption")}},
            "error", "internal");
        ScanHostProgress na = fin;
        na.access = ScanAccessAttempt(); // the opening could not leave the interface: not an attempt
        na.accessClose.httpAnswered = false;
        na.accessClose.facts = ScanAccess();
        rep("progress_final_opening_not_attempted_closing_failed", scanEncodeProgress(na), "progress");
    }
    QJsonArray outReps;
    for (const QJsonValue &x : reps) {
        QJsonObject o = x.toObject();
        o.insert(QStringLiteral("expect"), replyExpect(o.value(QStringLiteral("json"))));
        const QJsonObject e = o.value(QStringLiteral("expect")).toObject();
        check(e.value(QStringLiteral("kind")).toString() == o.value(QStringLiteral("want_kind")).toString()
                  && e.value(QStringLiteral("error")).toString() == o.value(QStringLiteral("want_error")).toString(),
              QStringLiteral("reply vector ") + o.value(QStringLiteral("name")).toString());
        o.remove(QStringLiteral("want_kind"));
        o.remove(QStringLiteral("want_error"));
        outReps << o;
    }
    // the shared byte gate (F6)
    struct Op {
        const char *op;
        const char *id;
        qint64 bytes;
    };
    const auto gateCase = [](const char *name, qint64 max, const QList<Op> &ops) {
        ScanHostByteGate g(max);
        QJsonArray out;
        for (const Op &o : ops) {
            bool ok = true;
            const QString op = QLatin1String(o.op);
            if (op == QLatin1String("admit"))
                ok = g.admit(QLatin1String(o.id), o.bytes);
            else if (op == QLatin1String("charge"))
                ok = g.charge(o.bytes);
            else if (op == QLatin1String("freeze"))
                g.freeze();
            else
                g.finish(QLatin1String(o.id), o.bytes);
            check(g.maxBytes() < 0 || g.spent() + g.reserved() <= g.maxBytes(), QStringLiteral("gate vector ") + QLatin1String(name));
            out << QJsonObject{{QStringLiteral("op"), op}, {QStringLiteral("id"), QLatin1String(o.id)}, {QStringLiteral("bytes"), double(o.bytes)},
                               {QStringLiteral("expect"), QJsonObject{{QStringLiteral("ok"), ok}, {QStringLiteral("spent"), double(g.spent())},
                                                                      {QStringLiteral("reserved"), double(g.reserved())}}}};
        }
        return QJsonObject{{QStringLiteral("name"), QLatin1String(name)}, {QStringLiteral("max_bytes"), double(max)}, {QStringLiteral("ops"), out}};
    };
    QJsonArray gates;
    gates << gateCase("two_pools_share_one_cap", 200000,
                      {{"admit", "4:xray", 83968}, {"admit", "2", 85292}, {"admit", "up:00000000000000a2#full", 82944},
                       {"finish", "4:xray", 70000}, {"admit", "up:00000000000000a2#full", 82944}, {"finish", "2", 85292},
                       {"finish", "up:00000000000000a2#full", 30000}});
    gates << gateCase("retry_stays_inside_its_reservation", 100000,
                      {{"admit", "up:00000000000000a1", 83456}, {"admit", "up:00000000000000a1", 83456}, {"finish", "up:00000000000000a1", 99999}});
    gates << gateCase("reach_bytes_charged_only_if_they_fit", 1000, {{"charge", "", 512}, {"charge", "", 512}, {"admit", "x", 400}, {"charge", "", 100}});
    gates << gateCase("no_cap", -1, {{"admit", "a", 1 << 20}, {"admit", "b", 1 << 20}, {"finish", "a", 5}, {"finish", "unknown", 7}});
    // plan §2.2b step 5 + §2.2c: the opening attempt first, the closing attempt reserved from the start; after
    // the freeze nothing is admitted (no probe, no retry, no reach byte) but open reservations finish - the
    // closing attempt too - so the ack's spent + reserved bound the rest
    gates << gateCase("freeze_then_drain_with_closing_attempt", 300000,
                      {{"admit", "netinfo_open", 10240}, {"admit", "netinfo_close", 10240}, {"finish", "netinfo_open", 3100},
                       {"admit", "4:xray", 83968}, {"admit", "up:00000000000000a1", 83968}, {"freeze", "", 0},
                       {"admit", "5:xray", 83968}, {"charge", "", 512}, {"finish", "4:xray", 83968},
                       {"finish", "up:00000000000000a1", 20000}, {"finish", "netinfo_close", 1200}});
    return QJsonObject{{QStringLiteral("schema"), 1}, {QStringLiteral("version"), QLatin1String(kScanHostVersion)},
                       {QStringLiteral("requests"), outReqs}, {QStringLiteral("replies"), outReps}, {QStringLiteral("byte_gate"), gates}};
}

static void replayHost(const QJsonObject &f)
{
    check(f.value(QStringLiteral("schema")).toInt() == 1, QStringLiteral("host schema"));
    for (const QJsonValue &x : f.value(QStringLiteral("requests")).toArray()) {
        const QJsonObject o = x.toObject();
        check(requestExpect(o.value(QStringLiteral("json"))) == o.value(QStringLiteral("expect")).toObject(),
              QStringLiteral("request ") + o.value(QStringLiteral("name")).toString());
    }
    for (const QJsonValue &x : f.value(QStringLiteral("replies")).toArray()) {
        const QJsonObject o = x.toObject();
        check(replyExpect(o.value(QStringLiteral("json"))) == o.value(QStringLiteral("expect")).toObject(),
              QStringLiteral("reply ") + o.value(QStringLiteral("name")).toString());
    }
    for (const QJsonValue &x : f.value(QStringLiteral("byte_gate")).toArray()) {
        const QJsonObject c = x.toObject();
        ScanHostByteGate g(qint64(c.value(QStringLiteral("max_bytes")).toDouble()));
        int i = 0;
        for (const QJsonValue &ov : c.value(QStringLiteral("ops")).toArray()) {
            const QJsonObject o = ov.toObject();
            const QString op = o.value(QStringLiteral("op")).toString();
            const QString id = o.value(QStringLiteral("id")).toString();
            const qint64 b = qint64(o.value(QStringLiteral("bytes")).toDouble());
            bool ok = true;
            if (op == QLatin1String("admit"))
                ok = g.admit(id, b);
            else if (op == QLatin1String("charge"))
                ok = g.charge(b);
            else if (op == QLatin1String("freeze"))
                g.freeze();
            else
                g.finish(id, b);
            const QJsonObject e = o.value(QStringLiteral("expect")).toObject();
            check(ok == e.value(QStringLiteral("ok")).toBool() && g.spent() == qint64(e.value(QStringLiteral("spent")).toDouble())
                      && g.reserved() == qint64(e.value(QStringLiteral("reserved")).toDouble()),
                  QStringLiteral("byte_gate ") + c.value(QStringLiteral("name")).toString() + QStringLiteral("#") + QString::number(i++));
        }
    }
    check(!f.value(QStringLiteral("byte_gate")).toArray().isEmpty(), QStringLiteral("byte_gate vectors present"));
}

// --- machine vectors ------------------------------------------------------------------------------------

static QJsonObject machineVectors()
{
    QJsonArray out;
    for (const Scenario &s : scenarios()) {
        Driver d(s.world());
        d.run();
        Fail f;
        checkAllSteps(d, f, s.name);
        s.expect(d, f);
        for (const QString &x : f.list)
            check(false, s.name + QStringLiteral(": ") + x);
        QJsonArray steps;
        QJsonObject prev;
        for (const Recorded &r : d.steps) {
            QJsonObject e{{QStringLiteral("actions"), actionsJson(r.step)}, {QStringLiteral("wake_at_ms"), double(r.step.wakeAtMs)}};
            e.insert(QStringLiteral("view"), r.view == prev ? QJsonValue(QJsonValue::Null) : QJsonValue(r.view));
            prev = r.view;
            steps << QJsonObject{{QStringLiteral("event"), r.event}, {QStringLiteral("expect"), e}};
        }
        QJsonArray rules;
        for (const QString &x : s.rules)
            rules << x;
        out << QJsonObject{{QStringLiteral("name"), s.name}, {QStringLiteral("rules"), rules}, {QStringLiteral("caps"), capsJson(d.w.caps)},
                           {QStringLiteral("ledger"), d.w.ledger}, {QStringLiteral("steps"), steps}};
    }
    return QJsonObject{{QStringLiteral("schema"), 1}, {QStringLiteral("clock"), QStringLiteral("wall-clock ms; a fake origin")},
                       {QStringLiteral("scenarios"), out}};
}

static void replayMachine(const QJsonObject &f)
{
    check(f.value(QStringLiteral("schema")).toInt() == 1, QStringLiteral("machine schema"));
    for (const QJsonValue &sv : f.value(QStringLiteral("scenarios")).toArray()) {
        const QJsonObject s = sv.toObject();
        const QString name = s.value(QStringLiteral("name")).toString();
        ScanMachine m(capsFrom(s.value(QStringLiteral("caps")).toObject()));
        m.restoreBudget(s.value(QStringLiteral("ledger")).toArray());
        QJsonObject lastView;
        int i = 0;
        for (const QJsonValue &stv : s.value(QStringLiteral("steps")).toArray()) {
            const QJsonObject st = stv.toObject();
            const QJsonObject e = st.value(QStringLiteral("event")).toObject();
            const QJsonObject x = st.value(QStringLiteral("expect")).toObject();
            const ScanStep step = applyScanEvent(m, e);
            const qint64 now = qint64(e.value(QStringLiteral("now_ms")).toDouble());
            if (!x.value(QStringLiteral("view")).isNull())
                lastView = x.value(QStringLiteral("view")).toObject();
            const QString where = name + QStringLiteral("#") + QString::number(i++);
            check(actionsJson(step) == x.value(QStringLiteral("actions")).toArray(), where + QStringLiteral(" actions"));
            check(qint64(x.value(QStringLiteral("wake_at_ms")).toDouble()) == step.wakeAtMs, where + QStringLiteral(" wake"));
            check(scanViewToJson(m.view(now)) == lastView, where + QStringLiteral(" view"));
        }
    }
}

// --- race vectors ------------------------------------------------------------------------------------------

struct RaceEv {
    const char *event;
    const char *id;
    qint64 bytes;
    qint64 now;
};

static QJsonObject raceStepJson(const ScanRaceStep &s, const ScanAutoRace &r)
{
    QJsonArray acts;
    for (const ScanRaceAction &a : s.actions)
        acts << QJsonObject{{QStringLiteral("kind"), QLatin1String(scanRaceActionName(a.kind))}, {QStringLiteral("id"), a.id},
                            {QStringLiteral("tier"), a.tier}, {QStringLiteral("reason"), a.reason}};
    return QJsonObject{{QStringLiteral("actions"), acts}, {QStringLiteral("wake_at_ms"), double(s.wakeAtMs)},
                       {QStringLiteral("state"), QLatin1String(scanRaceStateName(r.state()))}, {QStringLiteral("tier"), r.tier()}};
}

static ScanRaceStep raceApply(ScanAutoRace &r, const QJsonObject &c, const QJsonObject &step)
{
    const QString e = step.value(QStringLiteral("event")).toString();
    const qint64 now = qint64(step.value(QStringLiteral("now_ms")).toDouble());
    const QString id = step.value(QStringLiteral("id")).toString();
    if (e == QLatin1String("start")) {
        QList<ScanRaceCandidate> cs;
        for (const QJsonValue &v : c.value(QStringLiteral("candidates")).toArray()) {
            const QJsonObject o = v.toObject();
            cs << ScanRaceCandidate{o.value(QStringLiteral("id")).toString(), o.value(QStringLiteral("tier")).toInt(),
                                    o.value(QStringLiteral("rank")).toInt(), o.value(QStringLiteral("lkg")).toBool(),
                                    o.value(QStringLiteral("eligible")).toBool(true)};
        }
        const QJsonObject k = c.value(QStringLiteral("config")).toObject();
        ScanRaceConfig cfg;
        cfg.enabled = k.value(QStringLiteral("enabled")).toBool();
        cfg.alternates = k.value(QStringLiteral("alternates")).toInt();
        cfg.staggerMs = k.value(QStringLiteral("stagger_ms")).toInt();
        cfg.commitBytes = k.value(QStringLiteral("commit_bytes")).toInt();
        cfg.probeTotalMs = k.value(QStringLiteral("probe_total_ms")).toInt();
        return r.start(cs, c.value(QStringLiteral("live")).toBool(), cfg, now);
    }
    if (e == QLatin1String("progress"))
        return r.probeProgress(id, qint64(step.value(QStringLiteral("bytes")).toDouble()), now);
    if (e == QLatin1String("failed"))
        return r.probeFailed(id, QStringLiteral("no_data"), now);
    if (e == QLatin1String("commit_failed"))
        return r.commitFailed(id, now);
    if (e == QLatin1String("cancel"))
        return r.cancel(now);
    return r.tick(now);
}

static QJsonObject raceCase(const char *name, bool enabled, bool live, const QList<ScanRaceCandidate> &cands, const QList<RaceEv> &evs,
                            int alternates = 3)
{
    const ScanRaceConfig d = scanRaceConfigFrom(ScanTunables(), enabled);
    QJsonObject c{{QStringLiteral("name"), QLatin1String(name)}, {QStringLiteral("live"), live},
                  {QStringLiteral("config"), QJsonObject{{QStringLiteral("enabled"), enabled}, {QStringLiteral("alternates"), alternates},
                                                         {QStringLiteral("stagger_ms"), d.staggerMs}, {QStringLiteral("commit_bytes"), d.commitBytes},
                                                         {QStringLiteral("probe_total_ms"), d.probeTotalMs}}}};
    QJsonArray cs;
    for (const ScanRaceCandidate &x : cands)
        cs << QJsonObject{{QStringLiteral("id"), x.id}, {QStringLiteral("tier"), x.tier}, {QStringLiteral("rank"), x.rank},
                          {QStringLiteral("lkg"), x.lastKnownGood}, {QStringLiteral("eligible"), x.eligible}};
    c.insert(QStringLiteral("candidates"), cs);
    ScanAutoRace r;
    QJsonArray steps;
    for (const RaceEv &e : evs) {
        QJsonObject st{{QStringLiteral("event"), QLatin1String(e.event)}, {QStringLiteral("id"), QLatin1String(e.id)},
                       {QStringLiteral("bytes"), double(e.bytes)}, {QStringLiteral("now_ms"), double(e.now)}};
        const ScanRaceStep s = raceApply(r, c, st);
        check(r.inFlight().size() <= 1 + alternates, QString::fromLatin1(name) + QStringLiteral(": race width"));
        st.insert(QStringLiteral("expect"), raceStepJson(s, r));
        steps << st;
    }
    c.insert(QStringLiteral("steps"), steps);
    return c;
}

static QJsonObject raceVectors()
{
    const QList<ScanRaceCandidate> one{{QStringLiteral("own-a"), 0, 1, false, true}, {QStringLiteral("own-lkg"), 0, 5, true, true},
                                       {QStringLiteral("own-b"), 0, 2, false, true}, {QStringLiteral("own-c"), 0, 3, false, true},
                                       {QStringLiteral("own-d"), 0, 4, false, true}, {QStringLiteral("up-1"), 1, 0, false, true},
                                       {QStringLiteral("up-2"), 1, 1, true, true}, {QStringLiteral("own-x"), 0, 0, false, false}};
    QJsonArray cases;
    cases << raceCase("disabled", false, false, one, {{"start", "", 0, 1000}});
    cases << raceCase("live_session_never_moved", true, true, one, {{"start", "", 0, 1000}, {"tick", "", 0, 2000}});
    cases << raceCase("lkg_first_then_alternates_commit", true, false, one,
                      {{"start", "", 0, 1000}, {"tick", "", 0, 1250}, {"tick", "", 0, 1500}, {"tick", "", 0, 1750}, {"tick", "", 0, 2000},
                       {"progress", "own-b", 12000, 2100}, {"progress", "own-b", 24576, 2300}, {"progress", "own-a", 30000, 2400}});
    cases << raceCase("failure_frees_slot_with_stagger", true, false, one,
                      {{"start", "", 0, 1000}, {"tick", "", 0, 1250}, {"tick", "", 0, 1500}, {"tick", "", 0, 1750},
                       {"failed", "own-lkg", 0, 1800}, {"tick", "", 0, 2000}, {"failed", "own-a", 0, 2100}, {"tick", "", 0, 2350}});
    cases << raceCase("tier_blocked_until_exhausted", true, false, one,
                      {{"start", "", 0, 0}, {"tick", "", 0, 250}, {"tick", "", 0, 500}, {"tick", "", 0, 750},
                       {"failed", "own-lkg", 0, 900}, {"failed", "own-a", 0, 950}, {"tick", "", 0, 1000}, {"failed", "own-b", 0, 1100},
                       {"failed", "own-c", 0, 1200}, {"tick", "", 0, 5250}, {"progress", "up-2", 24576, 5600}});
    cases << raceCase("commit_failed_resumes", true, false, one,
                      {{"start", "", 0, 0}, {"tick", "", 0, 250}, {"progress", "own-lkg", 24576, 400}, {"commit_failed", "own-lkg", 0, 1500},
                       {"tick", "", 0, 1750}});
    cases << raceCase("give_up", true, false, {{QStringLiteral("solo"), 0, 0, true, true}},
                      {{"start", "", 0, 0}, {"tick", "", 0, 5000}});
    cases << raceCase("no_alternates", true, false, one, {{"start", "", 0, 0}, {"tick", "", 0, 250}, {"failed", "own-lkg", 0, 300}}, 0);
    cases << raceCase("cancel", true, false, one, {{"start", "", 0, 0}, {"tick", "", 0, 250}, {"cancel", "", 0, 300}});
    return QJsonObject{{QStringLiteral("schema"), 1}, {QStringLiteral("cases"), cases}};
}

static void replayRace(const QJsonObject &f)
{
    check(f.value(QStringLiteral("schema")).toInt() == 1, QStringLiteral("race schema"));
    for (const QJsonValue &cv : f.value(QStringLiteral("cases")).toArray()) {
        const QJsonObject c = cv.toObject();
        ScanAutoRace r;
        int i = 0;
        for (const QJsonValue &sv : c.value(QStringLiteral("steps")).toArray()) {
            const QJsonObject st = sv.toObject();
            const ScanRaceStep s = raceApply(r, c, st);
            check(raceStepJson(s, r) == st.value(QStringLiteral("expect")).toObject(),
                  c.value(QStringLiteral("name")).toString() + QStringLiteral("#") + QString::number(i++));
        }
    }
}

// --- files ---------------------------------------------------------------------------------------------------

static QJsonObject readJson(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        check(false, QStringLiteral("cannot read ") + path);
        return QJsonObject();
    }
    QJsonParseError e{};
    const QJsonDocument d = QJsonDocument::fromJson(f.readAll(), &e);
    check(e.error == QJsonParseError::NoError && d.isObject(), QStringLiteral("parse ") + path);
    return d.object();
}

static bool writeJson(const QString &path, const QJsonObject &o)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    return f.write(QJsonDocument(o).toJson(QJsonDocument::Indented)) > 0;
}

// The machine file: one compact line per step (line-based diffs, about a quarter of the indented size).
static bool writeMachineJson(const QString &path, const QJsonObject &o)
{
    const auto c = [](const QJsonValue &v) {
        return v.isObject() ? QJsonDocument(v.toObject()).toJson(QJsonDocument::Compact)
                            : QJsonDocument(v.toArray()).toJson(QJsonDocument::Compact);
    };
    QByteArray out = "{\n\"schema\": 1,\n\"clock\": " + c(QJsonArray{o.value(QStringLiteral("clock"))}).mid(1).chopped(1)
                     + ",\n\"scenarios\": [\n";
    const QJsonArray sc = o.value(QStringLiteral("scenarios")).toArray();
    for (int i = 0; i < sc.size(); ++i) {
        QJsonObject head = sc.at(i).toObject();
        const QJsonArray steps = head.take(QStringLiteral("steps")).toArray();
        QByteArray h = c(head);
        h.chop(1);
        out += h + ",\"steps\": [\n";
        for (int k = 0; k < steps.size(); ++k)
            out += c(steps.at(k)) + (k + 1 < steps.size() ? ",\n" : "\n");
        out += i + 1 < sc.size() ? "]},\n" : "]}\n";
    }
    out += "]\n}\n";
    QJsonParseError e{};
    if (QJsonDocument::fromJson(out, &e) != QJsonDocument(o) || e.error != QJsonParseError::NoError)
        return false; // the text must read back as exactly the same document
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    return f.write(out) == out.size();
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const QStringList args = app.arguments();
    const int di = args.indexOf(QStringLiteral("--dir"));
    const QString dir = di > 0 && di + 1 < args.size() ? args.at(di + 1) : QStringLiteral("vectors");
    if (args.contains(QStringLiteral("--record"))) {
        const QJsonObject host = hostVectors();
        const QJsonObject machine = machineVectors();
        const QJsonObject race = raceVectors();
        // the recorded files must replay against the same code before they may be written
        replayHost(host);
        replayMachine(machine);
        replayRace(race);
        if (g_fail) {
            std::printf("recording REFUSED: %d of %d self-checks failed - nothing written\n", g_fail, g_total);
            return 1;
        }
        const bool ok = writeJson(dir + QStringLiteral("/scan_host_vectors.json"), host)
                        && writeMachineJson(dir + QStringLiteral("/scan_machine_vectors.json"), machine)
                        && writeJson(dir + QStringLiteral("/scan_race_vectors.json"), race);
        std::printf(ok ? "recorded into %s (%d self-checks)\n" : "FAILED to write into %s\n", qPrintable(dir), g_total);
        return ok ? 0 : 1;
    }
    replayHost(readJson(dir + QStringLiteral("/scan_host_vectors.json")));
    replayMachine(readJson(dir + QStringLiteral("/scan_machine_vectors.json")));
    replayRace(readJson(dir + QStringLiteral("/scan_race_vectors.json")));
    if (g_fail) {
        std::printf("scan_vectors_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("scan_vectors_check: OK (%d checks)\n", g_total);
    return 0;
}
