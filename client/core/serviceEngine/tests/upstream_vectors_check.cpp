// AVPN upstream nodes: shared test vectors for a second implementation (the iOS extension cannot link Qt
// and re-implements the lease machine in Swift). This program REPLAYS tests/vectors/*.json against the
// real C++ code (default) - so the files can never drift from the C++ behaviour - and can re-record them
// from the scenario definitions below (--record <dir>; only after a deliberate behaviour change, and the
// diff of the JSON is then part of the review). Keys: one Ed25519 test key derived from a fixed public
// seed (kTestSeed) - NOT a real key, never trusted by any build.
//
// ---- upstream_lease_vectors.json (UpstreamLeaseMachine) ---------------------------------------------
// { "schema": 1,
//   "timing": { max_ttl_s, min_renew_s, default_renew_s, retry_base_s, retry_max_s, max_retry_after_s },
//   "request_ids": "...",                      // rule: see below
//   "scenarios": [ { "name": str, "rules": [str], "app_only": bool, "steps": [ STEP ] } ] }
// app_only = true: a provisional (standby-pack) scenario. Only the app process starts sessions from the
// standby pack; the iOS extension only ever receives an already granted lease, so the Swift twin may
// SKIP these scenarios (and the events start_provisional / tunnel_up).
// A scenario starts with a NEW machine. STEP = { "event": EVENT, "args": {...}, "now_ms": int, "expect": EXPECT }
//   EVENT / args:
//     "start"          { profile_id, kind: "session"|"probe", meter_scope: "proxy"|"tunnel", known_revision }
//     "start_provisional" { profile_id, meter_scope, config_sha256, tunnel_api_base, known_revision,
//                          confirm_budget_ms }                       (app_only)
//     "tunnel_up"      {}                                            (app_only)
//     "acquire_reply"  { request_id, reply: ACQ }    ACQ = { kind: "granted", grant: GRANT }
//                                                       | { kind: "refused", error: ERR } | { kind: "failed", why }
//     "renew_reply"    { request_id, reply: REN }    REN = { kind: "granted", renewal: RENEWAL } | refused | failed
//     "tunnel_bytes"   { rx, tx }                    (cumulative counters; now_ms unused)
//     "baseline_bytes" { rx, tx }                    (now_ms unused)
//     "tick"           {}
//     "disconnect"     {}
//   GRANT   = { lease_id, profile_id, kind, expires_at_ms, ttl_s, renew_after_s, seq, upstream_revision,
//               traffic_accounting_epoch, renew_token, tunnel_api_base, config_sha256, config_changed }
//               (expires_at_ms = server clock)
//   RENEWAL = { status: "ok"|"rebaseline", lease_id, expires_at_ms, renew_after_s, seq, upstream_revision,
//               traffic_accounting_epoch, config_changed, applied_bytes, shadow_bytes }
//   ERR     = { code: "not_entitled"|...|"unknown", retry_after_s (-1 = absent), upstream_revision (0 = absent) }
//   EXPECT  = { "actions": [ACTION], "wake_at_ms": int (-1 = none; null for tunnel_bytes/baseline_bytes),
//               "state": { phase, lease_id, last_seq, epoch, known_revision, deadline_ms, report_in_doubt,
//                          unreported_rx, unreported_tx, meter_scope, renew_token, api_base } }
//   ACTION  = { "kind": "send_acquire" | "send_renew" | "send_release" | "lease_ready" | "lease_confirmed" |
//               "leave_node" | "try_next_candidate" | "restart_byte_counters" | "config_changed" |
//               "revision_changed", ... }
//     send_acquire: request_id, profile_id, lease_kind, standby, config_sha256, renew_token, api_base
//     send_renew / send_release: request_id, lease_id, meter { seq, rx, tx, scope, epoch }, renew_token, api_base
//       (epoch = the accounting epoch the device believes when the report is SENT: the grant's, replaced
//        by a rebaseline answer's or a re-acquire's; 0 = none known - the body still carries "epoch": 0)
//     lease_ready: lease_id, renew_token, api_base, provisional
//     lease_confirmed: lease_id, renew_token, api_base
//     leave_node / try_next_candidate: reason
//     revision_changed: upstream_revision
//   Actions compare as an ordered list, objects by exact key set and value.
//   Request ids: per machine, starting at 1, +1 for every send_* action (acquire, renew, release, also
//   the release of a cancelled acquire's late grant), kept across start().
//
// ---- upstream_wire_vectors.json (classifyAcquireReply / classifyRenewReply) -------------------------
// { "schema": 1, "pub_key_hex": hex, "context": "tribe-upstream-lease-v1",
//   "cases": [ { name, op: "acquire"|"renew", http_status (0 = no answer), body (UTF-8 bytes = the string),
//                sig (base64, acquire only), tribe_api (acquire only, optional: the answer carried
//                `X-Tribe-Api: 1`; absent = false), expect: { kind: "granted"|"refused"|"failed", why,
//                grant: {...GRANT fields + config, config_changed} | renewal: {...} | error: ERR,
//                may_start_provisional (acquire only: mayStartProvisional of that answer) } } ] }
//   why is compared for "failed" only; grant/renewal for "granted"; error for "refused".
//
// ---- upstream_signature_vectors.json (signingInput + verifyDetachedWithContext) ---------------------
// { "schema": 1, "seed_hex": hex, "pub_key_hex": hex,
//   "cases": [ { name, context ("" = none), body, signing_input_hex ("" = refused context), sig,
//                verifies_with_context: bool, verifies_bare: bool } ] }
//
// Build/run: build_upstream_vectors.sh  (re-record: build_upstream_vectors.sh --record)
#include "../SignedContext.h"
#include "../UpstreamLeaseMachine.h"
#include "../UpstreamLeaseWire.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimeZone>

#include <openssl/evp.h>

#include <cstdio>
#include <functional>

using namespace avpn;

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static const char *kTestSeed = "tribe-upstream-test-vectors-NOT-A-REAL-KEY";

// --- test key ------------------------------------------------------------------------------------------
struct TestKey {
    EVP_PKEY *k = nullptr;
    QByteArray seed;
    TestKey()
    {
        seed = QCryptographicHash::hash(QByteArray(kTestSeed), QCryptographicHash::Sha256);
        k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                         reinterpret_cast<const unsigned char *>(seed.constData()), size_t(seed.size()));
    }
    ~TestKey() { EVP_PKEY_free(k); }
    QString pubHex() const
    {
        unsigned char raw[32];
        size_t len = sizeof raw;
        EVP_PKEY_get_raw_public_key(k, raw, &len);
        return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(raw), int(len)).toHex());
    }
    QByteArray sign(const QByteArray &msg) const
    {
        unsigned char sig[64];
        size_t len = sizeof sig;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, k);
        EVP_DigestSign(ctx, sig, &len, reinterpret_cast<const unsigned char *>(msg.constData()), size_t(msg.size()));
        EVP_MD_CTX_free(ctx);
        return QByteArray(reinterpret_cast<const char *>(sig), int(len)).toBase64();
    }
};

// --- names --------------------------------------------------------------------------------------------
static const char *actionName(LeaseActionKind k)
{
    switch (k) {
    case LeaseActionKind::SendAcquire: return "send_acquire";
    case LeaseActionKind::SendRenew: return "send_renew";
    case LeaseActionKind::SendRelease: return "send_release";
    case LeaseActionKind::LeaseReady: return "lease_ready";
    case LeaseActionKind::LeaseConfirmed: return "lease_confirmed";
    case LeaseActionKind::LeaveNode: return "leave_node";
    case LeaseActionKind::TryNextCandidate: return "try_next_candidate";
    case LeaseActionKind::RestartByteCounters: return "restart_byte_counters";
    case LeaseActionKind::ConfigChanged: return "config_changed";
    case LeaseActionKind::RevisionChanged: return "revision_changed";
    }
    return "?";
}
static const char *phaseName(LeasePhase p)
{
    switch (p) {
    case LeasePhase::Idle: return "idle";
    case LeasePhase::Acquiring: return "acquiring";
    case LeasePhase::Active: return "active";
    case LeasePhase::Released: return "released";
    case LeasePhase::Left: return "left";
    case LeasePhase::Failed: return "failed";
    case LeasePhase::Provisional: return "provisional";
    }
    return "?";
}
static LeaseKind kindFrom(const QString &s) { return s == QLatin1String("probe") ? LeaseKind::Probe : LeaseKind::Session; }
static MeterScope scopeFrom(const QString &s) { return s == QLatin1String("proxy") ? MeterScope::Proxy : MeterScope::Tunnel; }
static double num(qint64 v) { return double(v); }
static qint64 i64(const QJsonValue &v) { return qint64(v.toDouble()); }

// --- serialization of machine outputs -----------------------------------------------------------------
static QJsonObject meterJson(const UpstreamMeter &m)
{
    return QJsonObject{{"seq", num(m.seq)}, {"rx", num(m.rxDelta)}, {"tx", num(m.txDelta)}, {"scope", meterScopeName(m.scope)},
                       {"epoch", num(m.epoch)}};
}
static QJsonObject actionJson(const LeaseAction &a)
{
    QJsonObject o{{"kind", actionName(a.kind)}};
    switch (a.kind) {
    case LeaseActionKind::SendAcquire:
        o.insert("request_id", num(qint64(a.requestId)));
        o.insert("profile_id", a.profileId);
        o.insert("lease_kind", leaseKindName(a.leaseKind));
        o.insert("standby", a.standby);
        o.insert("config_sha256", a.configSha256);
        o.insert("renew_token", a.route.renewToken);
        o.insert("api_base", a.route.apiBase);
        break;
    case LeaseActionKind::SendRenew:
    case LeaseActionKind::SendRelease:
        o.insert("request_id", num(qint64(a.requestId)));
        o.insert("lease_id", a.leaseId);
        o.insert("meter", meterJson(a.meter));
        o.insert("renew_token", a.route.renewToken);
        o.insert("api_base", a.route.apiBase);
        break;
    case LeaseActionKind::LeaseReady:
        o.insert("provisional", a.provisional);
        Q_FALLTHROUGH();
    case LeaseActionKind::LeaseConfirmed:
        o.insert("lease_id", a.leaseId);
        o.insert("renew_token", a.route.renewToken);
        o.insert("api_base", a.route.apiBase);
        break;
    case LeaseActionKind::LeaveNode:
    case LeaseActionKind::TryNextCandidate: o.insert("reason", a.reason); break;
    case LeaseActionKind::RevisionChanged: o.insert("upstream_revision", num(a.upstreamRevision)); break;
    default: break;
    }
    return o;
}
static QJsonObject stateJson(const UpstreamLeaseMachine &m)
{
    return QJsonObject{{"phase", phaseName(m.phase())}, {"lease_id", m.leaseId()}, {"last_seq", num(m.lastAcceptedSeq())},
                       {"epoch", num(m.accountingEpoch())}, {"known_revision", num(m.knownRevision())},
                       {"deadline_ms", num(m.deadlineMs())}, {"report_in_doubt", m.reportInDoubt()},
                       {"unreported_rx", num(m.unreportedRx())}, {"unreported_tx", num(m.unreportedTx())},
                       {"meter_scope", meterScopeName(m.meterScope())}, {"renew_token", m.route().renewToken},
                       {"api_base", m.route().apiBase}};
}
static QJsonObject expectJson(const LeaseStep *s, const UpstreamLeaseMachine &m)
{
    QJsonArray acts;
    if (s)
        for (const LeaseAction &a : s->actions)
            acts << actionJson(a);
    return QJsonObject{{"actions", acts}, {"wake_at_ms", s ? QJsonValue(num(s->wakeAtMs)) : QJsonValue()},
                       {"state", stateJson(m)}};
}

// --- parsing of inputs --------------------------------------------------------------------------------
static UpstreamErrorReply errorFrom(const QJsonObject &e)
{
    UpstreamErrorReply r;
    r.code = upstreamErrorCodeFrom(e.value("code").toString());
    r.retryAfterS = e.value("retry_after_s").toInt(-1);
    r.upstreamRevision = i64(e.value("upstream_revision"));
    return r;
}
static AcquireReply acquireFrom(const QJsonObject &o)
{
    AcquireReply r;
    const QString k = o.value("kind").toString();
    if (k == QLatin1String("granted")) {
        const QJsonObject g = o.value("grant").toObject();
        r.kind = LeaseReplyKind::Granted;
        r.grant.leaseId = g.value("lease_id").toString();
        r.grant.profileId = g.value("profile_id").toString();
        r.grant.kind = kindFrom(g.value("kind").toString());
        r.grant.expiresAtMs = i64(g.value("expires_at_ms"));
        r.grant.ttlS = g.value("ttl_s").toInt();
        r.grant.renewAfterS = g.value("renew_after_s").toInt();
        r.grant.seq = i64(g.value("seq"));
        r.grant.upstreamRevision = i64(g.value("upstream_revision"));
        r.grant.accountingEpoch = i64(g.value("traffic_accounting_epoch"));
        r.grant.renewToken = g.value("renew_token").toString();
        r.grant.tunnelApiBase = g.value("tunnel_api_base").toString();
        r.grant.configSha256 = g.value("config_sha256").toString();
        r.grant.configChanged = g.value("config_changed").toBool();
    } else if (k == QLatin1String("refused")) {
        r.kind = LeaseReplyKind::Refused;
        r.error = errorFrom(o.value("error").toObject());
    } else {
        r.kind = LeaseReplyKind::Failed;
        r.why = o.value("why").toString();
    }
    return r;
}
static RenewReply renewFrom(const QJsonObject &o)
{
    RenewReply r;
    const QString k = o.value("kind").toString();
    if (k == QLatin1String("granted")) {
        const QJsonObject w = o.value("renewal").toObject();
        r.kind = LeaseReplyKind::Granted;
        r.renewal.rebaseline = w.value("status").toString() == QLatin1String("rebaseline");
        r.renewal.leaseId = w.value("lease_id").toString();
        r.renewal.expiresAtMs = i64(w.value("expires_at_ms"));
        r.renewal.renewAfterS = w.value("renew_after_s").toInt();
        r.renewal.seq = i64(w.value("seq"));
        r.renewal.upstreamRevision = i64(w.value("upstream_revision"));
        r.renewal.accountingEpoch = i64(w.value("traffic_accounting_epoch"));
        r.renewal.configChanged = w.value("config_changed").toBool();
        r.renewal.appliedBytes = i64(w.value("applied_bytes"));
        r.renewal.shadowBytes = i64(w.value("shadow_bytes"));
    } else if (k == QLatin1String("refused")) {
        r.kind = LeaseReplyKind::Refused;
        r.error = errorFrom(o.value("error").toObject());
    } else {
        r.kind = LeaseReplyKind::Failed;
        r.why = o.value("why").toString();
    }
    return r;
}

// Applies one recorded event to a machine; returns its expectation object (actual behaviour).
static QJsonObject apply(UpstreamLeaseMachine &m, const QJsonObject &step)
{
    const QString ev = step.value("event").toString();
    const QJsonObject a = step.value("args").toObject();
    const qint64 now = i64(step.value("now_ms"));
    LeaseStep s;
    if (ev == QLatin1String("start_provisional"))
        s = m.startProvisional(a.value("profile_id").toString(), scopeFrom(a.value("meter_scope").toString()),
                               a.value("config_sha256").toString(), a.value("tunnel_api_base").toString(),
                               i64(a.value("known_revision")), i64(a.value("confirm_budget_ms")), now);
    else if (ev == QLatin1String("tunnel_up"))
        s = m.tunnelUp(now);
    else if (ev == QLatin1String("start"))
        s = m.start(a.value("profile_id").toString(), kindFrom(a.value("kind").toString()),
                    scopeFrom(a.value("meter_scope").toString()), i64(a.value("known_revision")), now);
    else if (ev == QLatin1String("acquire_reply"))
        s = m.onAcquireReply(quint64(i64(a.value("request_id"))), acquireFrom(a.value("reply").toObject()), now);
    else if (ev == QLatin1String("renew_reply"))
        s = m.onRenewReply(quint64(i64(a.value("request_id"))), renewFrom(a.value("reply").toObject()), now);
    else if (ev == QLatin1String("tick"))
        s = m.tick(now);
    else if (ev == QLatin1String("disconnect"))
        s = m.disconnect(now);
    else if (ev == QLatin1String("tunnel_bytes") || ev == QLatin1String("baseline_bytes")) {
        if (ev == QLatin1String("tunnel_bytes"))
            m.onTunnelBytes(i64(a.value("rx")), i64(a.value("tx")));
        else
            m.baselineBytes(i64(a.value("rx")), i64(a.value("tx")));
        return expectJson(nullptr, m);
    } else {
        std::printf("unknown event %s\n", qPrintable(ev));
        ++g_fail;
    }
    return expectJson(&s, m);
}

// --- scenario recorder ---------------------------------------------------------------------------------
static const QString kP = QStringLiteral("3f9c2a7b1d4e8f60");
static const QString kLA = QStringLiteral("leaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
static const QString kLB = QStringLiteral("leaseBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
static const qint64 T = 1000000;
static const qint64 S0 = 1763117000000LL;

static QJsonObject grantJ(const QString &lease = kLA, qint64 seq = 0, qint64 expiresServer = S0 + 900000,
                          const char *kind = "session", int renewAfter = 300, qint64 epoch = 1, qint64 rev = 100,
                          const QString &token = QString(), const QString &base = QString(), const QString &profile = kP,
                          const QString &sha = QString(64, QLatin1Char('a')), bool configChanged = false)
{
    return QJsonObject{{"kind", "granted"},
                       {"grant", QJsonObject{{"lease_id", lease}, {"profile_id", profile}, {"kind", kind},
                                             {"expires_at_ms", num(expiresServer)}, {"ttl_s", 900},
                                             {"renew_after_s", renewAfter}, {"seq", num(seq)},
                                             {"upstream_revision", num(rev)}, {"traffic_accounting_epoch", num(epoch)},
                                             {"renew_token", token}, {"tunnel_api_base", base},
                                             {"config_sha256", sha}, {"config_changed", configChanged}}}};
}
static QJsonObject renewalJ(qint64 seq, qint64 expiresServer, bool rebaseline = false, bool configChanged = false,
                            qint64 epoch = 1, const QString &lease = kLA, int renewAfter = 300, qint64 rev = 100)
{
    return QJsonObject{{"kind", "granted"},
                       {"renewal", QJsonObject{{"status", rebaseline ? "rebaseline" : "ok"}, {"lease_id", lease},
                                               {"expires_at_ms", num(expiresServer)}, {"renew_after_s", renewAfter},
                                               {"seq", num(seq)}, {"upstream_revision", num(rev)},
                                               {"traffic_accounting_epoch", num(epoch)},
                                               {"config_changed", configChanged}, {"applied_bytes", 0},
                                               {"shadow_bytes", 0}}}};
}
static QJsonObject refusedJ(const char *code, int retryAfter = -1, qint64 rev = 0)
{
    return QJsonObject{{"kind", "refused"},
                       {"error", QJsonObject{{"code", code}, {"retry_after_s", retryAfter}, {"upstream_revision", num(rev)}}}};
}
static QJsonObject failedJ(const char *why = "transport")
{
    return QJsonObject{{"kind", "failed"}, {"why", why}};
}

struct Rec {
    QString name;
    QStringList rules;
    bool appOnly = false;
    UpstreamLeaseMachine m;
    QJsonArray steps;
    QJsonObject last; // expectation of the last step
    QHash<QString, qint64> sent; // the latest request id per send_* kind, over all steps
    qint64 pendingRenew = 0;     // a renewal sent and not answered yet
    qint64 wakeAt = -1;          // the latest wake_at_ms a step asked for
    qint64 now = 0;

    QJsonObject ev(const char *event, const QJsonObject &args, qint64 at)
    {
        // A recorded scenario never ticks to "nothing scheduled" and never answers request 0.
        CHECK(at >= 0);
        if (QLatin1String(event).endsWith(QLatin1String("_reply")))
            CHECK(i64(args.value("request_id")) > 0);
        now = at;
        QJsonObject step{{"event", event}, {"args", args}, {"now_ms", num(at)}};
        last = apply(m, step);
        step.insert("expect", last);
        steps << step;
        if (QLatin1String(event) == QLatin1String("renew_reply") && i64(args.value("request_id")) == pendingRenew)
            pendingRenew = 0;
        for (const QJsonValue &a : last.value("actions").toArray()) {
            const QString k = a.toObject().value("kind").toString();
            if (k.startsWith(QLatin1String("send_")))
                sent.insert(k, i64(a.toObject().value("request_id")));
            if (k == QLatin1String("send_renew"))
                pendingRenew = i64(a.toObject().value("request_id"));
        }
        if (!last.value("wake_at_ms").isNull())
            wakeAt = i64(last.value("wake_at_ms"));
        return last;
    }
    // The latest request id of that kind (0 = never sent).
    qint64 id(const char *kind) const { return sent.value(QLatin1String(kind), 0); }
    // The last step sent that kind.
    bool lastHas(const char *kind) const
    {
        for (const QJsonValue &a : last.value("actions").toArray())
            if (a.toObject().value("kind").toString() == QLatin1String(kind))
                return true;
        return false;
    }
    qint64 wake() const { return wakeAt; }
    qint64 deadline() const { return i64(last.value("state").toObject().value("deadline_ms")); }
    void start(const char *kind = "session", const char *scope = "tunnel", qint64 rev = 100, qint64 at = T,
               const QString &profile = kP)
    {
        ev("start", {{"profile_id", profile}, {"kind", kind}, {"meter_scope", scope}, {"known_revision", num(rev)}}, at);
    }
    void startProvisional(const char *scope = "tunnel", qint64 budget = 12000, qint64 at = T,
                          const QString &sha = QString(64, QLatin1Char('a')), const QString &base = QStringLiteral("https://t.example.net"))
    {
        appOnly = true;
        ev("start_provisional", {{"profile_id", kP}, {"meter_scope", scope}, {"config_sha256", sha},
                                 {"tunnel_api_base", base}, {"known_revision", 100}, {"confirm_budget_ms", num(budget)}}, at);
    }
    void tunnelUp(qint64 at) { ev("tunnel_up", {}, at); }
    void acquire(const QJsonObject &reply, qint64 at) { ev("acquire_reply", {{"request_id", num(id("send_acquire"))}, {"reply", reply}}, at); }
    void acquireId(qint64 rid, const QJsonObject &reply, qint64 at) { ev("acquire_reply", {{"request_id", num(rid)}, {"reply", reply}}, at); }
    void renew(const QJsonObject &reply, qint64 at) { ev("renew_reply", {{"request_id", num(id("send_renew"))}, {"reply", reply}}, at); }
    void renewId(qint64 rid, const QJsonObject &reply, qint64 at) { ev("renew_reply", {{"request_id", num(rid)}, {"reply", reply}}, at); }
    void bytes(qint64 rx, qint64 tx) { ev("tunnel_bytes", {{"rx", num(rx)}, {"tx", num(tx)}}, now); }
    void baseline(qint64 rx, qint64 tx) { ev("baseline_bytes", {{"rx", num(rx)}, {"tx", num(tx)}}, now); }
    void tick(qint64 at) { ev("tick", {}, at); }
    void disconnect(qint64 at) { ev("disconnect", {}, at); }
    // Fails renewals until the machine sends an acquire (the TTL passed).
    void failUntilAcquire()
    {
        for (int i = 0; i < 100 && !lastHas("send_acquire"); ++i) {
            if (pendingRenew)
                renewId(pendingRenew, failedJ(), now);
            else
                tick(wake());
        }
        CHECK(lastHas("send_acquire"));
    }
    QJsonObject json() const
    {
        QJsonArray r;
        for (const QString &x : rules)
            r << x;
        return QJsonObject{{"name", name}, {"rules", r}, {"app_only", appOnly}, {"steps", steps}};
    }
};

static QJsonArray leaseScenarios()
{
    QJsonArray out;
    const auto add = [&out](const char *name, const QStringList &rules, const std::function<void(Rec &)> &body) {
        Rec r;
        r.name = QLatin1String(name);
        r.rules = rules;
        body(r);
        out << r.json();
    };
    add("fresh_session_renew_ok", {"seq_from_server", "renew_schedule", "deltas", "deadline_from_send", "one_request_at_a_time"},
        [](Rec &r) {
            r.start();
            r.acquire(grantJ(kLA, 5), T + 200);
            r.tick(T + 200 + 299999);
            r.bytes(100, 50);
            r.bytes(300, 80);
            r.tick(T + 200 + 300000);
            r.tick(T + 300250);
            r.renew(renewalJ(6, S0 + 300200 + 900000), T + 300300);
            r.bytes(500, 100);
            r.tick(r.wake());
        });
    add("renew_retry_same_seq", {"retry_same_seq_same_deltas", "late_answer_ignored", "backoff_15_30", "no_leave_on_transport"},
        [](Rec &r) {
            r.start();
            r.acquire(grantJ(kLA, 0), T);
            r.bytes(1000, 10);
            r.tick(T + 300000);
            const qint64 first = r.id("send_renew");
            r.renew(failedJ(), T + 301000);
            r.bytes(1500, 20);
            r.tick(T + 315999);
            r.tick(T + 316000);
            const qint64 second = r.id("send_renew");
            r.renewId(first, renewalJ(1, S0 + 1200000), T + 316500); // late answer to the first try: ignored
            r.renewId(second, failedJ(), T + 317000);
            r.tick(r.wake());
            r.renew(renewalJ(1, S0 + 347000 + 900000), T + 347100);
            r.tick(r.wake());
        });
    add("backoff_cap_and_retry_after", {"backoff_cap_120", "retry_after_honoured", "retry_after_capped_900"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(), T);
        qint64 at = T + 300000;
        for (int i = 0; i < 6; ++i) {
            r.tick(at);
            r.renew(failedJ(), at);
            at = r.wake();
        }
        r.tick(at);
        r.renew(refusedJ("rate_limited", 42), at);
        r.tick(r.wake());
        r.renew(refusedJ("upstream_unavailable", 5000), r.now);
    });
    add("seq_monotonic", {"seq_never_back", "seq_follows_server_max"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(kLA, 10), T);
        r.tick(T + 300000);
        r.renew(renewalJ(3, S0 + 1200000), T + 300100);
        r.tick(r.wake());
        r.renew(renewalJ(20, S0 + 1500000), r.now + 100);
        r.tick(r.wake());
    });
    add("rebaseline_and_config_changed", {"rebaseline_zeroes_counters", "new_epoch_kept", "config_changed_once", "counter_restart"},
        [](Rec &r) {
            r.start();
            r.acquire(grantJ(), T);
            r.bytes(5000, 500);
            r.tick(T + 300000);
            r.bytes(5600, 560);
            r.renew(renewalJ(1, S0 + 1200000, true, false, 2), T + 300100);
            r.bytes(5700, 570);
            r.tick(r.wake());
            r.renew(renewalJ(2, S0 + 1500000, false, true, 2), r.now + 100);
            r.tick(r.wake());
            r.renew(renewalJ(3, S0 + 1800000, false, true, 2), r.now + 100);
            r.bytes(40, 4);
            r.baseline(1000, 100);
            r.bytes(1010, 101);
        });
    // Backend review 14.11: the server fences every report by `epoch` (a report with another epoch is not
    // charged and is answered rebaseline). After a rebaseline the NEXT report - a fresh one and a retry of
    // an unanswered one alike - and the release must carry the new epoch, never the stale one.
    add("epoch_fence", {"epoch_on_every_report", "epoch_after_rebaseline", "epoch_on_retry", "epoch_on_release",
                        "epoch_after_reacquire", "cancelled_release_grant_epoch"},
        [](Rec &r) {
            r.start();
            r.acquire(grantJ(kLA, 0, S0 + 900000, "session", 300, /*epoch=*/7), T);
            r.bytes(1000, 100);
            r.tick(T + 300000);                                                   // renew seq 1, epoch 7
            r.renew(renewalJ(1, S0 + 1200000, /*rebaseline=*/true, false, /*epoch=*/8), T + 300100);
            r.bytes(1500, 150);
            r.tick(r.wake());                                                     // renew seq 2, epoch 8
            r.renew(failedJ(), r.now + 100);                                      // no answer
            r.tick(r.wake());                                                     // retry seq 2, epoch 8
            r.renew(renewalJ(2, S0 + 1500000, false, false, 8), r.now + 100);
            r.bytes(1600, 160);
            r.disconnect(r.now + 1000);                                           // release seq 3, epoch 8
            // A re-acquire after the TTL moved the epoch: the reports of the new lease carry it.
            r.start("session", "tunnel", 100, r.now + 2000);
            r.acquire(grantJ(kLB, 0, S0 + 5000000, "session", 300, /*epoch=*/8), r.now + 100);
            r.tick(r.wake());
            r.failUntilAcquire();
            r.acquire(grantJ(kLB, 1, S0 + 9000000, "session", 300, /*epoch=*/9), r.now + 100);
            r.bytes(2000, 200);
            r.tick(r.wake());                                                     // renew of the re-acquired lease, epoch 9
            r.renew(renewalJ(2, S0 + 9300000, false, false, 9, kLB), r.now + 100);
            r.disconnect(r.now + 100);
            // A cancelled acquire's late grant is given back with that grant's own epoch.
            r.start("session", "tunnel", 100, r.now + 1000);
            const qint64 cancelled = r.id("send_acquire");
            r.disconnect(r.now + 10);
            r.acquireId(cancelled, grantJ(kLA, 4, S0 + 9900000, "session", 300, /*epoch=*/11), r.now + 50);
        });
    for (const char *code : {"not_entitled", "over_quota", "disabled", "lease_gone"}) {
        add(qPrintable(QStringLiteral("terminal_on_renew_%1").arg(QLatin1String(code))), {"terminal_leaves", "no_release_after_terminal"},
            [code](Rec &r) {
                r.start();
                r.acquire(grantJ(), T);
                r.tick(T + 300000);
                r.renew(refusedJ(code), T + 300100);
                r.tick(T + 10000000);
                r.disconnect(T + 10000001);
            });
        add(qPrintable(QStringLiteral("terminal_before_bringup_%1").arg(QLatin1String(code))), {"terminal_leaves"},
            [code](Rec &r) {
                r.start();
                r.acquire(refusedJ(code), T + 10);
            });
    }
    for (const char *code : {"no_seat", "rate_limited", "upstream_unavailable"})
        add(qPrintable(QStringLiteral("try_next_before_bringup_%1").arg(QLatin1String(code))), {"no_seat_try_next", "transient_try_next"},
            [code](Rec &r) {
                r.start();
                r.acquire(refusedJ(code, 30, 300), T + 10);
                r.tick(T + 10000000);
            });
    add("try_next_before_bringup_transport", {"transient_try_next"}, [](Rec &r) {
        r.start();
        r.acquire(failedJ("transport"), T + 10);
    });
    add("try_next_before_bringup_invalid", {"transient_try_next"}, [](Rec &r) {
        r.start();
        r.acquire(failedJ("signature"), T + 10);
    });
    add("grant_mismatch_and_restart", {"grant_must_match_request", "stale_answer_ignored", "start_ignored_while_running"},
        [](Rec &r) {
            r.start("probe");
            const qint64 oldId = r.id("send_acquire");
            r.acquire(grantJ(), T + 10); // a session grant for a probe request
            r.start("session", "tunnel", 100, T + 20, QStringLiteral("0000000000000001"));
            r.acquireId(oldId, grantJ(), T + 30);
            r.start("session", "tunnel", 100, T + 40);
        });
    add("expiry_reacquire_new_lease", {"dead_lease_reacquired", "reacquire_at_deadline_immediately", "seq_restarts_on_new_lease", "doubt_dropped_on_new_lease", "unsent_bytes_carry"},
        [](Rec &r) {
            r.start();
            r.acquire(grantJ(kLA, 4), T);
            r.bytes(700, 70);
            r.tick(T + 300000);
            r.bytes(900, 90);
            r.failUntilAcquire();
            r.acquire(grantJ(kLB, 0, S0 + 2000000), r.now + 50);
            r.tick(r.wake());
        });
    add("expiry_same_lease_not_applied", {"doubt_kept_if_not_applied"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(kLA, 4), T);
        r.bytes(700, 70);
        r.tick(T + 300000);
        r.failUntilAcquire();
        r.acquire(grantJ(kLA, 4), r.now + 1);
        r.tick(r.now + 1000);
    });
    add("expiry_immediate_despite_pending_retry", {"reacquire_at_deadline_immediately", "backoff_after_the_immediate_attempt", "immediate_again_for_the_next_lease"},
        [](Rec &r) {
            r.start();
            r.acquire(grantJ(), T);
            r.tick(T + 300000);
            r.renew(refusedJ("upstream_unavailable", 900), T + 300000); // retry pending until T + 1200000
            r.tick(r.deadline() - 1);
            r.tick(r.deadline());                                          // re-acquire at the deadline
            r.acquire(failedJ(), r.now + 100);
            r.tick(r.now + 100);                                           // backoff: nothing yet
            r.tick(r.wake());
            r.acquire(grantJ(kLB, 0, S0 + 3000000), r.now + 1);
            r.tick(r.wake());                                              // renewal of the new lease
            r.renew(refusedJ("rate_limited", 900), r.now);
            r.tick(r.wake());                                              // = the new deadline
        });
    add("renew_in_flight_across_deadline", {"reacquire_at_deadline_immediately"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(kLA, 0, S0 + 900000, "session", 450), T);
        r.tick(T + 450000);
        r.renew(refusedJ("rate_limited", 449), T + 450000);
        r.tick(r.wake());                                  // T + 899000: the retry, just before the deadline
        r.renew(failedJ(), r.deadline() + 500);           // its failure lands after the deadline
        r.tick(r.wake());                                  // re-acquire at once
    });
    add("expiry_same_lease_applied", {"doubt_dropped_if_applied"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(kLA, 4), T);
        r.bytes(700, 70);
        r.tick(T + 300000);
        r.failUntilAcquire();
        r.acquire(grantJ(kLA, 5), r.now + 1);
    });
    add("reacquire_no_seat_leaves", {"no_seat_reacquire"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(), T);
        r.tick(r.deadline());
        r.acquire(refusedJ("no_seat", 60), r.now);
        r.disconnect(r.now + 1);
    });
    add("reacquire_transient_then_disabled", {"reacquire_transient_retried", "terminal_leaves"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(), T);
        r.tick(r.deadline());
        r.acquire(refusedJ("upstream_unavailable", 60), r.now);
        r.tick(r.now + 59999);
        r.tick(r.now + 1);
        r.acquire(failedJ(), r.now);
        r.tick(r.wake());
        r.acquire(refusedJ("disabled"), r.now + 100);
    });
    add("reacquire_new_epoch", {"epoch_change_restarts_counters"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(), T);
        r.bytes(100, 10);
        r.tick(r.deadline());
        r.acquire(grantJ(kLB, 0, S0 + 1800000, "session", 300, 2), r.now + 5);
    });
    add("clock_skew_and_backwards", {"skew_free_deadline", "deadline_moves_by_server_difference", "deadline_capped_max_ttl", "clock_back_read_as_last"},
        [](Rec &r) {
            const qint64 far = S0 + 86400000LL * 400;
            r.start("session", "tunnel", 100, 5);
            r.acquire(grantJ(kLA, 0, far), 300);
            r.tick(300300);
            r.renew(renewalJ(1, far + 300000), 300400);
            r.tick(600400);
            r.renew(renewalJ(2, far + 86400000LL * 30), 600500);
            r.tick(10);
            r.tick(600500);
        });
    add("probe_never_renewed", {"probe_no_renew", "probe_no_reacquire", "probe_release_metered"}, [](Rec &r) {
        r.start("probe");
        r.acquire(grantJ(kLA, 0, S0 + 60000, "probe", 0), T + 10);
        r.bytes(65536, 4096);
        r.tick(T + 300000);
        r.tick(T + 900000);
        r.tick(T + 3600000);
        r.disconnect(T + 3600000);
    });
    add("release_clean_and_in_doubt", {"release_next_seq", "release_resends_doubt_with_newer_bytes", "release_once", "late_renew_after_release_ignored"},
        [](Rec &r) {
            r.start();
            r.acquire(grantJ(kLA, 3), T);
            r.bytes(100, 10);
            r.tick(T + 300000);
            const qint64 rid = r.id("send_renew");
            r.bytes(150, 15);
            r.disconnect(T + 300500);
            r.renewId(rid, renewalJ(4, S0 + 1200000), T + 300600);
            r.disconnect(T + 300700);
            r.start("session", "tunnel", 100, T + 400000);
            r.acquire(grantJ(kLA, 3), T + 400000);
            r.bytes(10, 1);
            r.disconnect(T + 401000);
        });
    add("cancelled_acquire_released", {"cancelled_grant_released", "cancelled_release_own_route_old_scope"}, [](Rec &r) {
        r.start("session", "proxy");
        const qint64 aid = r.id("send_acquire");
        r.disconnect(T + 5);
        r.start("session", "tunnel", 100, T + 6);
        r.acquireId(aid, grantJ(kLA, 2, S0 + 900000, "session", 300, 1, 100, "tokA", "https://a.example.net"), T + 50);
        r.acquireId(aid, grantJ(kLA, 2), T + 60);
    });
    add("renew_wrong_lease_id", {"renewal_must_match_lease"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(), T);
        r.tick(T + 300000);
        r.renew(renewalJ(1, S0 + 1200000, false, false, 1, kLB), T + 300100);
    });
    add("revisions", {"revision_changed_forward_only", "error_revision"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(kLA, 0, S0 + 900000, "session", 300, 1, 150), T);
        r.tick(T + 300000);
        r.renew(renewalJ(1, S0 + 1200000, false, false, 1, kLA, 300, 150), T + 300100);
        r.tick(r.wake());
        r.renew(renewalJ(2, S0 + 1500000, false, false, 1, kLA, 300, 149), r.now + 100);
    });
    for (int renewAfter : {300, 5000, 10, 0})
        add(qPrintable(QStringLiteral("renew_after_%1").arg(renewAfter)), {"renew_after_clamped_30_to_ttl_half", "renew_default_when_absent"},
            [renewAfter](Rec &r) {
                r.start();
                r.acquire(grantJ(kLA, 0, S0 + 900000, "session", renewAfter), T);
            });
    add("route_and_scope", {"route_on_ready_renew_release", "scope_on_every_report", "scope_fixed_across_new_lease", "new_lease_own_route"},
        [](Rec &r) {
            r.start("session", "proxy");
            r.acquire(grantJ(kLA, 0, S0 + 900000, "session", 300, 1, 100, "tokA", "https://a.example.net"), T);
            r.bytes(10, 1);
            r.tick(T + 300000);
            r.renew(failedJ(), T + 300000);
            r.tick(r.wake());
            r.failUntilAcquire();
            r.acquire(grantJ(kLB, 0, S0 + 2000000, "session", 300, 1, 100, "tokB"), r.now + 1);
            r.disconnect(r.now + 2);
        });
    // --- provisional (standby pack) sessions: app_only ---
    add("provisional_confirmed", {"provisional_ready_before_lease", "standby_acquire_through_tunnel", "bytes_kept_on_confirm", "confirmed_session_is_normal"},
        [](Rec &r) {
            r.startProvisional("proxy");
            r.bytes(4000, 400);                       // carried before the tunnel is reported up
            r.tick(T + 1000);                         // nothing until tunnel_up
            r.tunnelUp(T + 2000);
            r.bytes(9000, 900);
            r.acquire(grantJ(kLA, 0, S0 + 900000, "session", 300, 1, 100, "tokA", QString()), T + 2500);
            r.tick(r.wake());                         // first report carries everything since bring-up
            r.renew(renewalJ(1, S0 + 1200000), r.now + 100);
        });
    add("provisional_config_changed", {"confirm_with_other_sha_keeps_session"}, [](Rec &r) {
        r.startProvisional();
        r.tunnelUp(T + 2000);
        r.acquire(grantJ(kLA, 0, S0 + 900000, "session", 300, 1, 100, "tokA", "https://g.example.net", kP,
                         QString(64, QLatin1Char('b'))), T + 2500);
    });
    add("provisional_config_changed_flag", {"confirm_with_config_changed_keeps_session"}, [](Rec &r) {
        r.startProvisional();
        r.tunnelUp(T + 2000);
        r.acquire(grantJ(kLA, 0, S0 + 900000, "session", 300, 1, 100, "tokA", QString(), kP,
                         QString(64, QLatin1Char('a')), true), T + 2500);
    });
    add("provisional_no_seat", {"no_seat_standby"}, [](Rec &r) {
        r.startProvisional();
        r.tunnelUp(T + 2000);
        r.acquire(refusedJ("no_seat", 30), T + 2500);
        r.disconnect(T + 2600);
    });
    for (const char *code : {"not_entitled", "over_quota", "disabled", "lease_gone"})
        add(qPrintable(QStringLiteral("provisional_terminal_%1").arg(QLatin1String(code))), {"terminal_leaves"}, [code](Rec &r) {
            r.startProvisional();
            r.tunnelUp(T + 2000);
            r.acquire(refusedJ(code), T + 2500);
        });
    // Lab 14.11 D3: transient answers of the seat confirmation are retried on the SHORT early spacing
    // (300, 600, 1200, 2000 ms; the profile may refuse every connection in its first seconds) until the
    // confirm budget; the server's retry_after_s is honoured; at the budget: standby_unconfirmed.
    add("provisional_unconfirmed", {"provisional_transient_retried_early_spacing", "standby_unconfirmed_at_budget"}, [](Rec &r) {
        r.startProvisional("tunnel", 12000);
        r.tunnelUp(T + 2000);
        r.acquire(failedJ(), T + 2010);           // refused at once: retry in 300 ms
        for (int i = 0; i < 30 && !r.lastHas("leave_node"); ++i) {
            r.tick(r.wake());
            if (r.lastHas("send_acquire"))
                r.acquire(i == 3 ? refusedJ("upstream_unavailable", 3) : failedJ(), r.now + 10);
        }
        CHECK(r.lastHas("leave_node"));
        r.disconnect(r.now + 1);
    });
    add("provisional_warmup_then_grant", {"provisional_transient_retried_early_spacing", "provisional_confirmed"}, [](Rec &r) {
        r.startProvisional("tunnel", 12000);
        r.tunnelUp(T);
        r.acquire(failedJ(), T + 5);              // the first ~1.2 s: every connection refused
        r.tick(r.wake());
        r.acquire(failedJ(), r.now + 5);
        r.tick(r.wake());
        r.acquire(failedJ(), r.now + 5);
        r.tick(r.wake());
        r.acquire(grantJ(kLA, 0, S0 + 900000, "session", 300, 1, 100, "tokA"), r.now + 80);
        r.disconnect(r.now + 100);
    });
    add("provisional_late_failure_after_budget", {"standby_unconfirmed_at_budget"}, [](Rec &r) {
        r.startProvisional("tunnel", 5000);
        r.tunnelUp(T + 2000);
        r.acquire(failedJ(), T + 9000);           // the answer itself came after the budget
    });
    add("provisional_disconnect_before_grant", {"nothing_to_release_before_grant", "late_grant_released"}, [](Rec &r) {
        r.startProvisional();
        r.disconnect(T + 500);                    // before tunnel_up: nothing in flight
        r.startProvisional("proxy", 12000, T + 1000);
        r.tunnelUp(T + 2000);
        const qint64 aid = r.id("send_acquire");
        r.disconnect(T + 2100);
        r.acquireId(aid, grantJ(kLA, 0, S0 + 900000, "session", 300, 1, 100, "tokA"), T + 2200);
    });
    // Lab 14.11 D2: renewals our server rejects as malformed are retried, but kUpstreamRenewRejectedLimit in
    // a row leave the node (renew_rejected); a transport failure in between does not break the row.
    add("renew_rejected_in_row", {"renew_rejected_leaves", "transport_keeps_row"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(), T);
        r.tick(T + 300000);
        r.renew(refusedJ("invalid_request"), r.now + 100);
        r.tick(r.wake());
        r.renew(failedJ("transport"), r.now + 100);
        r.tick(r.wake());
        r.renew(failedJ("http_422"), r.now + 100);
        r.tick(r.wake());
        r.renew(refusedJ("invalid_request"), r.now + 100); // the third: leave
        r.tick(r.now + 10000000);
        r.disconnect(r.now + 1);
    });
    add("renew_rejected_row_broken", {"renew_rejected_leaves", "other_answer_breaks_row"}, [](Rec &r) {
        r.start();
        r.acquire(grantJ(), T);
        r.tick(T + 300000);
        r.renew(refusedJ("invalid_request"), r.now + 100);
        r.tick(r.wake());
        r.renew(refusedJ("invalid_request"), r.now + 100);
        r.tick(r.wake());
        r.renew(refusedJ("rate_limited", 20), r.now + 100); // another HTTP answer: the row starts again
        r.tick(r.wake());
        r.renew(refusedJ("invalid_request"), r.now + 100);
        r.tick(r.wake());
        r.renew(refusedJ("invalid_request"), r.now + 100); // two in the new row: still on the node
        r.disconnect(r.now + 100);
    });
    return out;
}

// --- wire vectors -------------------------------------------------------------------------------------
static QString iso(qint64 ms) { return QDateTime::fromMSecsSinceEpoch(ms, QTimeZone::UTC).toString(Qt::ISODateWithMs); }
static const QByteArray kCfg = R"({"inbounds":[],"outbounds":[{"protocol":"vless","tag":"proxy"}]})";

static QJsonObject leaseBody()
{
    return QJsonObject{{"type", "upstream_lease"}, {"lease_id", kLA}, {"profile_id", kP}, {"kind", "session"},
                       {"expires_at", iso(S0 + 900000)}, {"ttl_s", 900}, {"renew_after_s", 300}, {"seq", 0},
                       {"config", QString::fromUtf8(kCfg)},
                       {"config_sha256", QString::fromLatin1(QCryptographicHash::hash(kCfg, QCryptographicHash::Sha256).toHex())},
                       {"upstream_revision", num(100)}, {"traffic_accounting_epoch", 1}};
}
static QJsonObject renewBody()
{
    return QJsonObject{{"status", "ok"}, {"lease_id", kLA}, {"expires_at", iso(S0 + 1200000)}, {"renew_after_s", 300},
                       {"seq", 1}, {"upstream_revision", num(100)}, {"traffic_accounting_epoch", 1},
                       {"config_changed", false}, {"applied_bytes", 4096}};
}

static QJsonObject acquireResultJson(const AcquireReply &r)
{
    QJsonObject o{{"kind", r.kind == LeaseReplyKind::Granted ? "granted" : r.kind == LeaseReplyKind::Refused ? "refused" : "failed"},
                  {"may_start_provisional", mayStartProvisional(r)}};
    if (r.kind == LeaseReplyKind::Failed)
        o.insert("why", r.why);
    if (r.kind == LeaseReplyKind::Refused)
        o.insert("error", QJsonObject{{"code", upstreamErrorCodeName(r.error.code)}, {"retry_after_s", r.error.retryAfterS},
                                      {"upstream_revision", num(r.error.upstreamRevision)}});
    if (r.kind == LeaseReplyKind::Granted) {
        const UpstreamLeaseGrant &g = r.grant;
        o.insert("grant", QJsonObject{{"lease_id", g.leaseId}, {"profile_id", g.profileId}, {"kind", leaseKindName(g.kind)},
                                      {"expires_at_ms", num(g.expiresAtMs)}, {"ttl_s", g.ttlS}, {"renew_after_s", g.renewAfterS},
                                      {"seq", num(g.seq)}, {"config", QString::fromUtf8(g.config)},
                                      {"config_sha256", g.configSha256}, {"upstream_revision", num(g.upstreamRevision)},
                                      {"traffic_accounting_epoch", num(g.accountingEpoch)}, {"renew_token", g.renewToken},
                                      {"tunnel_api_base", g.tunnelApiBase}, {"config_changed", g.configChanged}});
    }
    return o;
}
static QJsonObject renewResultJson(const RenewReply &r)
{
    QJsonObject o{{"kind", r.kind == LeaseReplyKind::Granted ? "granted" : r.kind == LeaseReplyKind::Refused ? "refused" : "failed"}};
    if (r.kind == LeaseReplyKind::Failed)
        o.insert("why", r.why);
    if (r.kind == LeaseReplyKind::Refused)
        o.insert("error", QJsonObject{{"code", upstreamErrorCodeName(r.error.code)}, {"retry_after_s", r.error.retryAfterS},
                                      {"upstream_revision", num(r.error.upstreamRevision)}});
    if (r.kind == LeaseReplyKind::Granted) {
        const UpstreamRenewal &w = r.renewal;
        o.insert("renewal", QJsonObject{{"status", w.rebaseline ? "rebaseline" : "ok"}, {"lease_id", w.leaseId},
                                        {"expires_at_ms", num(w.expiresAtMs)}, {"renew_after_s", w.renewAfterS},
                                        {"seq", num(w.seq)}, {"upstream_revision", num(w.upstreamRevision)},
                                        {"traffic_accounting_epoch", num(w.accountingEpoch)},
                                        {"config_changed", w.configChanged}, {"applied_bytes", num(w.appliedBytes)},
                                        {"shadow_bytes", num(w.shadowBytes)}});
    }
    return o;
}

static QJsonObject wireRun(const QJsonObject &c, const QString &pub)
{
    const QByteArray body = c.value("body").toString().toUtf8();
    const int status = c.value("http_status").toInt();
    if (c.value("op").toString() == QLatin1String("acquire"))
        return acquireResultJson(classifyAcquireReply(status, body, c.value("sig").toString().toLatin1(), pub,
                                                      c.value("tribe_api").toBool(false)));
    return renewResultJson(classifyRenewReply(status, body));
}

static QJsonObject wireVectors(const TestKey &key)
{
    QJsonArray cases;
    const auto add = [&](const char *name, const char *op, int status, const QByteArray &body, const QByteArray &sig,
                         bool tribeApi = false) {
        QJsonObject c{{"name", name}, {"op", op}, {"http_status", status}, {"body", QString::fromUtf8(body)},
                      {"sig", QString::fromLatin1(sig)}};
        if (tribeApi)
            c.insert("tribe_api", true);
        c.insert("expect", wireRun(c, key.pubHex()));
        cases << c;
    };
    const auto ser = [](const QJsonObject &o) { return QJsonDocument(o).toJson(QJsonDocument::Compact); };
    const auto lsig = [&key](const QByteArray &b) { return key.sign(QByteArray("tribe-upstream-lease-v1\n") + b); };
    const auto acq = [&](const char *name, const QJsonObject &o) { const QByteArray b = ser(o); add(name, "acquire", 200, b, lsig(b)); };
    const auto edit = [](const std::function<void(QJsonObject &)> &f) { QJsonObject o = leaseBody(); f(o); return o; };

    acq("grant_ok", leaseBody());
    acq("grant_route", edit([](QJsonObject &o) { o.insert("renew_token", "rt.Opaque-123_~"); o.insert("tunnel_api_base", "https://t.example.net/api/"); }));
    acq("grant_probe", edit([](QJsonObject &o) { o.insert("kind", "probe"); o.insert("renew_after_s", 0); }));
    { const QByteArray b = ser(leaseBody()); add("bare_signature_refused", "acquire", 200, b, key.sign(b)); }
    { const QByteArray b = ser(leaseBody()); add("no_signature", "acquire", 200, b, QByteArray()); }
    { const QByteArray b = ser(leaseBody()); add("body_changed_after_signing", "acquire", 200, b + " ", lsig(b)); }
    acq("type_wrong", edit([](QJsonObject &o) { o.insert("type", "upstream_renewal"); }));
    acq("type_missing", edit([](QJsonObject &o) { o.remove("type"); }));
    acq("config_sha_mismatch", edit([](QJsonObject &o) { o.insert("config", QString::fromUtf8(kCfg) + QLatin1Char(' ')); }));
    for (const char *f : {"lease_id", "profile_id", "kind", "expires_at", "ttl_s", "renew_after_s", "seq", "config",
                          "config_sha256", "upstream_revision", "traffic_accounting_epoch"})
        acq(qPrintable(QStringLiteral("missing_%1").arg(QLatin1String(f))), edit([f](QJsonObject &o) { o.remove(QLatin1String(f)); }));
    acq("lease_id_short", edit([](QJsonObject &o) { o.insert("lease_id", "short"); }));
    acq("lease_id_path", edit([](QJsonObject &o) { o.insert("lease_id", "lease/../../AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); }));
    acq("seq_negative", edit([](QJsonObject &o) { o.insert("seq", -1); }));
    acq("epoch_zero", edit([](QJsonObject &o) { o.insert("traffic_accounting_epoch", 0); }));
    acq("expires_at_garbage", edit([](QJsonObject &o) { o.insert("expires_at", "tomorrow"); }));
    acq("renew_token_space", edit([](QJsonObject &o) { o.insert("renew_token", "has space"); }));
    acq("renew_token_empty", edit([](QJsonObject &o) { o.insert("renew_token", ""); }));
    acq("api_base_http", edit([](QJsonObject &o) { o.insert("tunnel_api_base", "http://t.example.net"); }));
    acq("api_base_userinfo", edit([](QJsonObject &o) { o.insert("tunnel_api_base", "https://u:p@t.example.net"); }));
    acq("api_base_null_is_absent", edit([](QJsonObject &o) { o.insert("tunnel_api_base", QJsonValue()); }));
    acq("grant_config_changed", edit([](QJsonObject &o) { o.insert("config_changed", true); }));
    acq("grant_config_changed_not_bool", edit([](QJsonObject &o) { o.insert("config_changed", "yes"); }));
    add("acquire_no_seat", "acquire", 409, R"({"code":"no_seat","retry_after_s":30,"upstream_revision":200})", {});
    add("acquire_not_entitled", "acquire", 403, R"({"code":"not_entitled"})", {});
    add("acquire_403_html_is_transient", "acquire", 403, "<html>blocked</html>", {});
    add("acquire_unknown_code_is_transient", "acquire", 403, R"({"code":"new_code"})", {});
    add("acquire_transport", "acquire", 0, {}, {});
    // Lab 14.11 D1: `X-Tribe-Api: 1` = our server answered - never a provisional start, whatever the body.
    add("acquire_429_tribe_api_unknown_body", "acquire", 429, R"({"detail":"rate limit exceeded"})", {}, true);
    add("acquire_429_no_header_unknown_body", "acquire", 429, R"({"detail":"rate limit exceeded"})", {});
    add("acquire_rate_limited_tribe_api", "acquire", 429, R"({"code":"rate_limited","retry_after_s":60})", {}, true);
    add("acquire_401_tribe_api", "acquire", 401, R"({"detail":"Not authenticated"})", {}, true);
    { const QByteArray b = ser(leaseBody()); add("bare_signature_tribe_api", "acquire", 200, b, key.sign(b), true); }
    add("acquire_422_invalid_request", "acquire", 422, R"({"code":"invalid_request"})", {});
    add("renew_ok", "renew", 200, ser(renewBody()), {});
    { QJsonObject o = renewBody(); o.insert("status", "rebaseline"); o.insert("traffic_accounting_epoch", 3); o.insert("config_changed", true); add("renew_rebaseline", "renew", 200, ser(o), {}); }
    { QJsonObject o = renewBody(); o.insert("shadow_bytes", 8192); add("renew_shadow_bytes", "renew", 200, ser(o), {}); }
    { QJsonObject o = renewBody(); o.insert("shadow_bytes", -1); add("renew_shadow_bytes_negative", "renew", 200, ser(o), {}); }
    { QJsonObject o = renewBody(); o.insert("status", "fine"); add("renew_status_unknown", "renew", 200, ser(o), {}); }
    { QJsonObject o = renewBody(); o.remove("config_changed"); add("renew_missing_config_changed", "renew", 200, ser(o), {}); }
    add("renew_lease_gone", "renew", 404, R"({"code":"lease_gone"})", {});
    add("renew_rate_limited", "renew", 429, R"({"code":"rate_limited","retry_after_s":42})", {});
    add("renew_502_empty", "renew", 502, {}, {});
    // Lab 14.11 D2: 422 invalid_request is a code of its own (not terminal); a 422 without one is failed.
    add("renew_422_invalid_request", "renew", 422, R"({"code":"invalid_request"})", {});
    add("renew_422_no_code", "renew", 422, R"({"detail":[{"loc":["body","epoch"],"type":"missing"}]})", {});
    add("renew_transport", "renew", 0, {}, {});
    return QJsonObject{{"schema", 1}, {"pub_key_hex", key.pubHex()}, {"context", kUpstreamLeaseSigContext}, {"cases", cases}};
}

// --- signature vectors --------------------------------------------------------------------------------
static QJsonObject sigRun(const QJsonObject &c, const QString &pub)
{
    const QByteArray body = c.value("body").toString().toUtf8();
    const QString ctx = c.value("context").toString();
    const QByteArray sig = c.value("sig").toString().toLatin1();
    return QJsonObject{{"signing_input_hex", QString::fromLatin1(signingInput(body, ctx).toHex())},
                       {"verifies_with_context", verifyDetachedWithContext(pub, ctx, body, sig)},
                       {"verifies_bare", verifyDetached(pub, body, sig)}};
}
static QJsonObject sigVectors(const TestKey &key)
{
    QJsonArray cases;
    const auto add = [&](const char *name, const QString &ctx, const QByteArray &body, const QByteArray &signedMsg) {
        QJsonObject c{{"name", name}, {"context", ctx}, {"body", QString::fromUtf8(body)}, {"sig", QString::fromLatin1(key.sign(signedMsg))}};
        const QJsonObject r = sigRun(c, key.pubHex());
        for (auto it = r.begin(); it != r.end(); ++it)
            c.insert(it.key(), it.value());
        cases << c;
    };
    const QByteArray lease = R"({"type":"upstream_lease","lease_id":"x"})";
    add("lease_context", QStringLiteral("tribe-upstream-lease-v1"), lease, QByteArray("tribe-upstream-lease-v1\n") + lease);
    add("no_context_config_body", QString(), R"({"features":{"upstream_nodes":true}})", R"({"features":{"upstream_nodes":true}})");
    add("scan_manifest_context", QStringLiteral("tribe-scan-manifest-v1"), R"({"entries":[]})",
        QByteArray("tribe-scan-manifest-v1\n") + R"({"entries":[]})");
    add("lease_signed_without_newline_fails", QStringLiteral("tribe-upstream-lease-v1"), lease,
        QByteArray("tribe-upstream-lease-v1") + lease);
    add("invalid_context_refused", QStringLiteral("Tribe-Lease"), lease, QByteArray("Tribe-Lease\n") + lease);
    const QByteArray standby = R"({"type":"upstream_standby","version":1,"entries":[]})";
    add("standby_context", QStringLiteral("tribe-upstream-standby-v1"), standby,
        QByteArray("tribe-upstream-standby-v1\n") + standby);
    add("standby_body_signed_as_lease_fails", QStringLiteral("tribe-upstream-standby-v1"), standby,
        QByteArray("tribe-upstream-lease-v1\n") + standby);
    return QJsonObject{{"schema", 1}, {"seed_hex", QString::fromLatin1(key.seed.toHex())}, {"pub_key_hex", key.pubHex()},
                       {"cases", cases}};
}

// --- files --------------------------------------------------------------------------------------------
static QJsonObject leaseFile()
{
    const UpstreamLeaseTiming t;
    return QJsonObject{{"schema", 1},
                       {"timing", QJsonObject{{"max_ttl_s", t.maxTtlS}, {"min_renew_s", t.minRenewS},
                                              {"default_renew_s", t.defaultRenewS}, {"retry_base_s", t.retryBaseS},
                                              {"retry_max_s", t.retryMaxS}, {"max_retry_after_s", t.maxRetryAfterS}}},
                       {"request_ids", "per machine from 1, +1 for every send_* action, kept across start()"},
                       {"scenarios", leaseScenarios()}};
}

static bool writeJson(const QString &path, const QJsonObject &o)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
    return true;
}
static QJsonObject readJson(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        std::printf("FAIL cannot read %s\n", qPrintable(path));
        ++g_fail;
        return {};
    }
    return QJsonDocument::fromJson(f.readAll()).object();
}

static void replayLease(const QJsonObject &file)
{
    const UpstreamLeaseTiming t;
    const QJsonObject timing = file.value("timing").toObject();
    CHECK(timing.value("max_ttl_s").toInt() == t.maxTtlS && timing.value("retry_base_s").toInt() == t.retryBaseS
          && timing.value("retry_max_s").toInt() == t.retryMaxS && timing.value("min_renew_s").toInt() == t.minRenewS
          && timing.value("default_renew_s").toInt() == t.defaultRenewS
          && timing.value("max_retry_after_s").toInt() == t.maxRetryAfterS);
    const QJsonArray scenarios = file.value("scenarios").toArray();
    CHECK(scenarios.size() >= 30);
    int steps = 0;
    for (const QJsonValue &sv : scenarios) {
        const QJsonObject sc = sv.toObject();
        UpstreamLeaseMachine m;
        int i = 0;
        for (const QJsonValue &st : sc.value("steps").toArray()) {
            const QJsonObject step = st.toObject();
            const QJsonObject actual = apply(m, step);
            ++g_total;
            ++steps;
            if (actual != step.value("expect").toObject()) {
                ++g_fail;
                std::printf("FAIL lease vector %s step %d (%s)\n  expected %s\n  actual   %s\n", qPrintable(sc.value("name").toString()), i,
                            qPrintable(step.value("event").toString()),
                            QJsonDocument(step.value("expect").toObject()).toJson(QJsonDocument::Compact).constData(),
                            QJsonDocument(actual).toJson(QJsonDocument::Compact).constData());
                break; // the rest of the scenario follows from a wrong state
            }
            ++i;
        }
    }
    CHECK(steps >= 200);
}

static void replayWire(const QJsonObject &file)
{
    const QString pub = file.value("pub_key_hex").toString();
    CHECK(file.value("context").toString() == QLatin1String(kUpstreamLeaseSigContext));
    const QJsonArray cases = file.value("cases").toArray();
    CHECK(cases.size() >= 30);
    for (const QJsonValue &cv : cases) {
        const QJsonObject c = cv.toObject();
        const QJsonObject actual = wireRun(c, pub);
        ++g_total;
        if (actual != c.value("expect").toObject()) {
            ++g_fail;
            std::printf("FAIL wire vector %s\n  expected %s\n  actual   %s\n", qPrintable(c.value("name").toString()),
                        QJsonDocument(c.value("expect").toObject()).toJson(QJsonDocument::Compact).constData(),
                        QJsonDocument(actual).toJson(QJsonDocument::Compact).constData());
        }
    }
}

static void replaySig(const QJsonObject &file)
{
    const QString pub = file.value("pub_key_hex").toString();
    // The key is the one derived from the published test seed - never a real key.
    TestKey key;
    CHECK(pub == key.pubHex() && file.value("seed_hex").toString() == QString::fromLatin1(key.seed.toHex()));
    CHECK(pub != QLatin1String("67bddcb248215a35ee2d8c2145ce415071ba02c5bcf888e35cc4491957aac78f")
          && pub != QLatin1String("95da1bd9062653d9c185c3ca5cae995516a8e353abccd3cf98cd12cd2f3a075a"));
    const QJsonArray cases = file.value("cases").toArray();
    CHECK(cases.size() >= 3);
    for (const QJsonValue &cv : cases) {
        const QJsonObject c = cv.toObject();
        const QJsonObject actual = sigRun(c, pub);
        for (auto it = actual.begin(); it != actual.end(); ++it) {
            ++g_total;
            if (c.value(it.key()) != it.value()) {
                ++g_fail;
                std::printf("FAIL signature vector %s field %s\n", qPrintable(c.value("name").toString()), qPrintable(it.key()));
            }
        }
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const QStringList args = app.arguments();
    const int ri = args.indexOf(QStringLiteral("--record"));
    const int di = args.indexOf(QStringLiteral("--dir"));
    const QString dir = di > 0 && di + 1 < args.size() ? args.at(di + 1) : QStringLiteral("vectors");
    TestKey key;
    if (ri > 0) {
        const bool ok = writeJson(dir + QStringLiteral("/upstream_lease_vectors.json"), leaseFile())
                        && writeJson(dir + QStringLiteral("/upstream_wire_vectors.json"), wireVectors(key))
                        && writeJson(dir + QStringLiteral("/upstream_signature_vectors.json"), sigVectors(key));
        if (g_fail) {
            std::printf("recording FAILED (%d checks) - files are not to be committed\n", g_fail);
            return 1;
        }
        std::printf(ok ? "recorded into %s\n" : "FAILED to write into %s\n", qPrintable(dir));
        return ok ? 0 : 1;
    }
    replayLease(readJson(dir + QStringLiteral("/upstream_lease_vectors.json")));
    replayWire(readJson(dir + QStringLiteral("/upstream_wire_vectors.json")));
    replaySig(readJson(dir + QStringLiteral("/upstream_signature_vectors.json")));
    if (g_fail) {
        std::printf("upstream_vectors_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("upstream_vectors_check: OK (%d checks)\n", g_total);
    return 0;
}
