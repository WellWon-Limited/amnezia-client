// AVPN upstream nodes (plan provider-pool v2, D6/D13): the signature with a context, the lease wire format
// and the pure lease state machine (seq, retries, renew schedule, rebaseline, terminal codes, the expiry
// rule, probe leases, release). Keys are generated in the test; data is synthetic.
// Build/run: build_upstream_lease.sh
#include "../SignedContext.h"
#include "../UpstreamLeaseMachine.h"
#include "../UpstreamLeaseWire.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QTimeZone>
#include <QJsonDocument>
#include <QJsonObject>

#include <openssl/evp.h>

#include <cstdio>

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

// --- an Ed25519 key of the test ---------------------------------------------------------------------
struct Key {
    EVP_PKEY *k = nullptr;
    Key()
    {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        EVP_PKEY_keygen_init(c);
        EVP_PKEY_keygen(c, &k);
        EVP_PKEY_CTX_free(c);
    }
    ~Key() { EVP_PKEY_free(k); }
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

static const QString kProfileId = QStringLiteral("3f9c2a7b1d4e8f60");
static const QString kLeaseA = QStringLiteral("leaseAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
static const QString kLeaseB = QStringLiteral("leaseBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
static const QByteArray kConfig = R"({"inbounds":[],"outbounds":[{"protocol":"vless","tag":"proxy"}]})";
static const qint64 kServerT0 = 1763117000000LL; // server clock at the first grant (any value)

static QString iso(qint64 ms)
{
    return QDateTime::fromMSecsSinceEpoch(ms, QTimeZone::UTC).toString(Qt::ISODateWithMs);
}

static QJsonObject leaseJson(const QString &leaseId = kLeaseA, qint64 seq = 0, qint64 expiresServer = kServerT0 + 900000,
                             const QString &kind = QStringLiteral("session"), int renewAfter = 300, qint64 epoch = 1,
                             qint64 revision = 100)
{
    return QJsonObject{{"type", "upstream_lease"}, {"lease_id", leaseId}, {"profile_id", kProfileId},
                       {"kind", kind}, {"expires_at", iso(expiresServer)}, {"ttl_s", 900},
                       {"renew_after_s", renewAfter}, {"seq", double(seq)},
                       {"config", QString::fromUtf8(kConfig)},
                       {"config_sha256", QString::fromLatin1(QCryptographicHash::hash(kConfig, QCryptographicHash::Sha256).toHex())},
                       {"upstream_revision", double(revision)}, {"traffic_accounting_epoch", double(epoch)}};
}

static QByteArray bytes(const QJsonObject &o)
{
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

static AcquireReply granted(const QJsonObject &lease)
{
    UpstreamLeaseGrant g;
    QString why;
    const bool ok = parseUpstreamLeaseGrant(bytes(lease), g, why);
    CHECK(ok);
    AcquireReply r;
    r.kind = LeaseReplyKind::Granted;
    r.grant = g;
    return r;
}

static AcquireReply acquireRefused(UpstreamErrorCode c, int retryAfter = -1, qint64 rev = 0)
{
    AcquireReply r;
    r.kind = LeaseReplyKind::Refused;
    r.error.code = c;
    r.error.retryAfterS = retryAfter;
    r.error.upstreamRevision = rev;
    return r;
}

static AcquireReply acquireFailed()
{
    AcquireReply r;
    r.why = QStringLiteral("transport");
    return r;
}

static RenewReply renewed(qint64 seq, qint64 expiresServer, bool rebaseline = false, bool configChanged = false,
                          qint64 epoch = 1, const QString &leaseId = kLeaseA, int renewAfter = 300, qint64 revision = 100)
{
    RenewReply r;
    r.kind = LeaseReplyKind::Granted;
    r.renewal.rebaseline = rebaseline;
    r.renewal.leaseId = leaseId;
    r.renewal.expiresAtMs = expiresServer;
    r.renewal.renewAfterS = renewAfter;
    r.renewal.seq = seq;
    r.renewal.upstreamRevision = revision;
    r.renewal.accountingEpoch = epoch;
    r.renewal.configChanged = configChanged;
    return r;
}

static RenewReply renewRefused(UpstreamErrorCode c, int retryAfter = -1)
{
    RenewReply r;
    r.kind = LeaseReplyKind::Refused;
    r.error.code = c;
    r.error.retryAfterS = retryAfter;
    return r;
}

static RenewReply renewFailed()
{
    RenewReply r;
    r.why = QStringLiteral("transport");
    return r;
}

// --- 1) signature with a context -------------------------------------------------------------------
static void signature()
{
    Key key, other;
    const QByteArray body = R"({"type":"upstream_lease","x":1})";
    const QByteArray bare = key.sign(body);
    const QByteArray ctx = key.sign(QByteArray("tribe-upstream-lease-v1\n") + body);
    CHECK(signingInput(body, QString()) == body);
    CHECK(signingInput(body, QLatin1String(kUpstreamLeaseSigContext)) == QByteArray("tribe-upstream-lease-v1\n") + body);
    // Empty context = today's verifyDetached, byte for byte.
    CHECK(verifyDetachedWithContext(key.pubHex(), QString(), body, bare));
    CHECK(verifyDetachedWithContext(key.pubHex(), QString(), body, bare) == verifyDetached(key.pubHex(), body, bare));
    CHECK(!verifyDetachedWithContext(key.pubHex(), QString(), body, ctx));
    // Context: only the domain-separated message verifies.
    CHECK(verifyDetachedWithContext(key.pubHex(), QLatin1String(kUpstreamLeaseSigContext), body, ctx));
    CHECK(!verifyDetachedWithContext(key.pubHex(), QLatin1String(kUpstreamLeaseSigContext), body, bare));
    CHECK(!verifyDetached(key.pubHex(), body, ctx)); // a lease never verifies as a config body
    CHECK(!verifyDetachedWithContext(key.pubHex(), QStringLiteral("tribe-scan-manifest-v1"), body, ctx));
    CHECK(!verifyDetachedWithContext(other.pubHex(), QLatin1String(kUpstreamLeaseSigContext), body, ctx));
    CHECK(!verifyDetachedWithContext(key.pubHex(), QLatin1String(kUpstreamLeaseSigContext), body + " ", ctx));
    // Invalid context labels are refused outright (also when the signature covers them).
    for (const char *bad : {"Tribe-upstream", "ab", "-abc", "a\nb", "tribe upstream", "trïbe-x"}) {
        const QString c = QString::fromUtf8(bad);
        CHECK(signingInput(body, c).isEmpty());
        CHECK(!verifyDetachedWithContext(key.pubHex(), c, body, key.sign(c.toUtf8() + '\n' + body)));
    }
}

// --- 2) wire format -----------------------------------------------------------------------------------
static void wire()
{
    Key key;
    const QByteArray body = bytes(leaseJson());
    const QByteArray sig = key.sign(QByteArray("tribe-upstream-lease-v1\n") + body);
    AcquireReply r = classifyAcquireReply(200, body, sig, key.pubHex());
    CHECK(r.kind == LeaseReplyKind::Granted);
    CHECK(r.grant.leaseId == kLeaseA && r.grant.profileId == kProfileId && r.grant.kind == LeaseKind::Session);
    CHECK(r.grant.config == kConfig && r.grant.ttlS == 900 && r.grant.renewAfterS == 300 && r.grant.seq == 0);
    CHECK(r.grant.expiresAtMs == kServerT0 + 900000 && r.grant.accountingEpoch == 1 && r.grant.upstreamRevision == 100);
    // Bare signature (a config-style signature) is not a lease signature.
    CHECK(classifyAcquireReply(200, body, key.sign(body), key.pubHex()).kind == LeaseReplyKind::Failed);
    CHECK(classifyAcquireReply(200, body, key.sign(body), key.pubHex()).why == QLatin1String("signature"));
    CHECK(classifyAcquireReply(200, body, QByteArray(), key.pubHex()).kind == LeaseReplyKind::Failed);
    // Signed but wrong: type, sha, fields.
    const auto signedWith = [&key](const QJsonObject &o) {
        const QByteArray b = bytes(o);
        return classifyAcquireReply(200, b, key.sign(QByteArray("tribe-upstream-lease-v1\n") + b), key.pubHex());
    };
    QJsonObject o = leaseJson();
    o.insert("type", "upstream_renewal");
    CHECK(signedWith(o).kind == LeaseReplyKind::Failed && signedWith(o).why == QLatin1String("type"));
    o = leaseJson();
    o.remove("type");
    CHECK(signedWith(o).kind == LeaseReplyKind::Failed);
    o = leaseJson();
    o.insert("config", QString::fromUtf8(kConfig) + QLatin1Char(' '));
    CHECK(signedWith(o).why == QLatin1String("config_sha256_mismatch"));
    for (const char *field : {"lease_id", "profile_id", "kind", "expires_at", "ttl_s", "renew_after_s", "seq",
                              "config", "config_sha256", "upstream_revision", "traffic_accounting_epoch"}) {
        o = leaseJson();
        o.remove(QLatin1String(field));
        CHECK(signedWith(o).kind == LeaseReplyKind::Failed);
    }
    o = leaseJson(QStringLiteral("short"));
    CHECK(signedWith(o).why == QLatin1String("lease_id"));
    o = leaseJson(QStringLiteral("lease/../../AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    CHECK(signedWith(o).why == QLatin1String("lease_id"));
    o = leaseJson();
    o.insert("seq", -1);
    CHECK(signedWith(o).kind == LeaseReplyKind::Failed);
    o = leaseJson();
    o.insert("traffic_accounting_epoch", 0);
    CHECK(signedWith(o).kind == LeaseReplyKind::Failed);
    o = leaseJson();
    o.insert("expires_at", "tomorrow");
    CHECK(signedWith(o).why == QLatin1String("expires_at"));
    // Errors: only a known code is terminal; the status alone never is.
    CHECK(classifyAcquireReply(0, {}, {}, key.pubHex()).kind == LeaseReplyKind::Failed);
    CHECK(classifyAcquireReply(0, {}, {}, key.pubHex()).why == QLatin1String("transport"));
    r = classifyAcquireReply(409, R"({"code":"no_seat","retry_after_s":30,"upstream_revision":200})", {}, key.pubHex());
    CHECK(r.kind == LeaseReplyKind::Refused && r.error.code == UpstreamErrorCode::NoSeat && r.error.retryAfterS == 30
          && r.error.upstreamRevision == 200);
    CHECK(classifyAcquireReply(403, "<html>blocked</html>", {}, key.pubHex()).kind == LeaseReplyKind::Failed);
    CHECK(classifyAcquireReply(403, R"({"code":"new_code"})", {}, key.pubHex()).kind == LeaseReplyKind::Failed);
    CHECK(classifyAcquireReply(403, R"({"code":"not_entitled"})", {}, key.pubHex()).error.code == UpstreamErrorCode::NotEntitled);
    CHECK(classifyRenewReply(404, R"({"code":"lease_gone"})").kind == LeaseReplyKind::Refused);
    CHECK(classifyRenewReply(502, {}).kind == LeaseReplyKind::Failed);
    CHECK(classifyRenewReply(0, {}).kind == LeaseReplyKind::Failed);
    const QJsonObject rw{{"status", "rebaseline"}, {"lease_id", kLeaseA}, {"expires_at", iso(kServerT0)},
                         {"renew_after_s", 300}, {"seq", 4}, {"upstream_revision", 7},
                         {"traffic_accounting_epoch", 3}, {"config_changed", true}, {"applied_bytes", 0}};
    RenewReply rr = classifyRenewReply(200, bytes(rw));
    CHECK(rr.kind == LeaseReplyKind::Granted && rr.renewal.rebaseline && rr.renewal.seq == 4
          && rr.renewal.accountingEpoch == 3 && rr.renewal.configChanged && rr.renewal.expiresAtMs == kServerT0);
    QJsonObject rw2 = rw;
    rw2.insert("status", "ok");
    CHECK(classifyRenewReply(200, bytes(rw2)).renewal.rebaseline == false);
    rw2.insert("status", "fine");
    CHECK(classifyRenewReply(200, bytes(rw2)).kind == LeaseReplyKind::Failed);
    rw2 = rw;
    rw2.remove("config_changed");
    CHECK(classifyRenewReply(200, bytes(rw2)).kind == LeaseReplyKind::Failed);
    // Codes and the terminal set.
    int terminal = 0;
    for (const char *c : {"not_entitled", "over_quota", "disabled", "lease_gone", "no_seat", "rate_limited",
                          "upstream_unavailable"}) {
        const UpstreamErrorCode e = upstreamErrorCodeFrom(QLatin1String(c));
        CHECK(QLatin1String(upstreamErrorCodeName(e)) == QLatin1String(c));
        terminal += isTerminalUpstreamError(e) ? 1 : 0;
    }
    CHECK(terminal == 4);
    CHECK(!isTerminalUpstreamError(UpstreamErrorCode::Unknown) && !isTerminalUpstreamError(UpstreamErrorCode::NoSeat));
    // Request bodies.
    CHECK(QJsonDocument::fromJson(upstreamAcquireBody(kProfileId, LeaseKind::Probe)).object()
          == QJsonObject({{"profile_id", kProfileId}, {"kind", "probe"}}));
    const QJsonObject m = QJsonDocument::fromJson(upstreamMeterBody({7, 1000, -5})).object();
    CHECK(m.value("seq").toInteger() == 7 && m.value("rx_bytes_delta").toInteger() == 1000
          && m.value("tx_bytes_delta").toInteger() == 0);
    CHECK(QJsonDocument::fromJson(upstreamMeterBody({1, kUpstreamMaxDeltaBytes * 2, 0})).object()
              .value("rx_bytes_delta").toInteger() == kUpstreamMaxDeltaBytes);
    // Backend review 14.11 + lab 14.11 D2: `epoch` is ALWAYS sent (the backend requires it), also as 0.
    CHECK(QJsonDocument::fromJson(upstreamMeterBody({1, 2, 3, MeterScope::Tunnel, 9})).object().value("epoch").toInteger() == 9);
    {
        const QJsonObject zero = QJsonDocument::fromJson(upstreamMeterBody({1, 2, 3, MeterScope::Tunnel, 0})).object();
        CHECK(zero.contains("epoch") && zero.value("epoch").isDouble() && zero.value("epoch").toInteger() == 0);
        CHECK(QJsonDocument::fromJson(upstreamMeterBody({1, 2, 3, MeterScope::Tunnel, -4})).object().value("epoch").toInteger() == 0);
        CHECK(upstreamMeterBody({6, 10, 2, MeterScope::Tunnel, 0})
              == QByteArray(R"({"epoch":0,"meter_scope":"tunnel","rx_bytes_delta":10,"seq":6,"tx_bytes_delta":2})"));
    }
    // Lab 14.11 D2: 422 invalid_request is its own code (never terminal by itself); a 422 without a code
    // is "rejected" too; nothing else is.
    {
        const RenewReply bad = classifyRenewReply(422, R"({"code":"invalid_request"})");
        CHECK(bad.kind == LeaseReplyKind::Refused && bad.error.code == UpstreamErrorCode::InvalidRequest);
        CHECK(!isTerminalUpstreamError(UpstreamErrorCode::InvalidRequest));
        CHECK(upstreamRenewRejected(bad));
        CHECK(upstreamRenewRejected(classifyRenewReply(422, R"({"detail":[{"loc":["body","epoch"]}]})")));
        CHECK(!upstreamRenewRejected(classifyRenewReply(400, R"({"detail":"x"})")));
        CHECK(!upstreamRenewRejected(classifyRenewReply(0, {})));
        CHECK(!upstreamRenewRejected(classifyRenewReply(429, R"({"code":"rate_limited"})")));
        CHECK(QLatin1String(upstreamErrorCodeName(UpstreamErrorCode::InvalidRequest)) == QLatin1String("invalid_request"));
    }
    // Lab 14.11 D1: the X-Tribe-Api header is read exactly ("1"), and only on an HTTP answer.
    CHECK(upstreamFromTribeApi("1") && upstreamFromTribeApi(" 1 ") && !upstreamFromTribeApi("") && !upstreamFromTribeApi("0")
          && !upstreamFromTribeApi("true"));
    CHECK(classifyAcquireReply(429, R"({"detail":"rate limit exceeded"})", {}, QString(), true).fromTribeApi);
    CHECK(!classifyAcquireReply(0, {}, {}, QString(), true).fromTribeApi); // no HTTP answer: no header either
    CHECK(classifyAcquireReply(429, R"({"detail":"rate limit exceeded"})", {}, QString(), true).why == QLatin1String("http_429"));
}

// --- 3) the machine -----------------------------------------------------------------------------------
static const qint64 T = 1000000; // the device clock at start (deliberately far from server time)

static UpstreamLeaseMachine started(LeaseStep &s, LeaseKind kind = LeaseKind::Session)
{
    UpstreamLeaseMachine m;
    s = m.start(kProfileId, kind, MeterScope::Tunnel, 100, T);
    return m;
}

// The action of that kind (a missing one is a failed check, never a crash).
static LeaseAction must(const LeaseStep &s, LeaseActionKind k)
{
    const LeaseAction *a = s.find(k);
    CHECK(a != nullptr);
    return a ? *a : LeaseAction();
}

static quint64 sentId(const LeaseStep &s, LeaseActionKind k)
{
    const LeaseAction *a = s.find(k);
    return a ? a->requestId : 0;
}

static void freshSession()
{
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    CHECK(m.phase() == LeasePhase::Acquiring && s.actions.size() == 1 && s.has(LeaseActionKind::SendAcquire));
    CHECK(s.actions[0].profileId == kProfileId && s.actions[0].leaseKind == LeaseKind::Session);
    const quint64 id = sentId(s, LeaseActionKind::SendAcquire);
    s = m.onAcquireReply(id, granted(leaseJson(kLeaseA, 5)), T + 200);
    CHECK(m.phase() == LeasePhase::Active && m.lastAcceptedSeq() == 5 && m.leaseId() == kLeaseA);
    CHECK(s.has(LeaseActionKind::LeaseReady) && s.has(LeaseActionKind::RestartByteCounters));
    CHECK(!s.has(LeaseActionKind::RevisionChanged)); // 100 = known
    CHECK(s.wakeAtMs == T + 200 + 300000);
    CHECK(m.deadlineMs() == T + 900000); // from the SEND time, on the device clock
    // Nothing before the renew time.
    CHECK(m.tick(T + 200 + 299999).actions.isEmpty());
    m.onTunnelBytes(100, 50);
    m.onTunnelBytes(300, 80);
    s = m.tick(T + 200 + 300000);
    const LeaseAction *rn = s.find(LeaseActionKind::SendRenew);
    CHECK(rn && rn->leaseId == kLeaseA && rn->meter.seq == 6 && rn->meter.rxDelta == 300 && rn->meter.txDelta == 80);
    CHECK(s.wakeAtMs == -1); // waiting for the answer
    CHECK(m.tick(T + 300250).actions.isEmpty()); // one request at a time
    // Renewal ok: seq 6 accepted, deadline moves by the server's difference.
    s = m.onRenewReply(rn ? rn->requestId : 0, renewed(6, kServerT0 + 300200 + 900000), T + 300300);
    CHECK(m.lastAcceptedSeq() == 6 && !m.reportInDoubt());
    CHECK(m.deadlineMs() == T + 900000 + 300200);
    CHECK(s.wakeAtMs == T + 300300 + 300000);
    m.onTunnelBytes(500, 100);
    s = m.tick(T + 600300);
    rn = s.find(LeaseActionKind::SendRenew);
    CHECK(rn && rn->meter.seq == 7 && rn->meter.rxDelta == 200 && rn->meter.txDelta == 20);
}

// A renewal without an answer: retried with the same seq and the same deltas; later bytes go with the
// next seq; the sum reported equals the bytes seen.
static void retrySameSeq()
{
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 0)), T);
    m.onTunnelBytes(1000, 10);
    s = m.tick(T + 300000);
    LeaseAction first = must(s, LeaseActionKind::SendRenew);
    CHECK(first.meter.seq == 1 && first.meter.rxDelta == 1000);
    s = m.onRenewReply(first.requestId, renewFailed(), T + 301000);
    CHECK(!s.has(LeaseActionKind::LeaveNode) && m.phase() == LeasePhase::Active && m.reportInDoubt());
    CHECK(s.wakeAtMs == T + 301000 + 15000);
    m.onTunnelBytes(1500, 20); // +500 / +10 while in doubt
    CHECK(m.tick(T + 315999).actions.isEmpty());
    s = m.tick(T + 316000);
    LeaseAction second = must(s, LeaseActionKind::SendRenew);
    CHECK(second.meter.seq == 1 && second.meter.rxDelta == 1000 && second.meter.txDelta == 10);
    CHECK(second.requestId != first.requestId);
    // A late answer to the first attempt is ignored.
    CHECK(m.onRenewReply(first.requestId, renewed(1, kServerT0 + 1200000), T + 316500).actions.isEmpty());
    CHECK(m.reportInDoubt());
    s = m.onRenewReply(second.requestId, renewFailed(), T + 317000);
    CHECK(s.wakeAtMs == T + 317000 + 30000); // 15 s doubling
    s = m.tick(T + 347000);
    LeaseAction third = must(s, LeaseActionKind::SendRenew);
    CHECK(third.meter.seq == 1 && third.meter.rxDelta == 1000);
    s = m.onRenewReply(third.requestId, renewed(1, kServerT0 + 347000 + 900000), T + 347100);
    CHECK(m.lastAcceptedSeq() == 1 && !m.reportInDoubt());
    s = m.tick(T + 347100 + 300000);
    const LeaseAction *next = s.find(LeaseActionKind::SendRenew);
    CHECK(next && next->meter.seq == 2 && next->meter.rxDelta == 500 && next->meter.txDelta == 10);
    CHECK(first.meter.rxDelta + next->meter.rxDelta == 1500);
    // Backoff caps at 120 s; the server's retry_after_s wins and is capped at 900 s.
    UpstreamLeaseMachine b = started(s);
    s = b.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    qint64 now = T + 300000;
    qint64 lastDelay = 0;
    for (int i = 0; i < 6; ++i) {
        s = b.tick(now);
        const quint64 id = sentId(s, LeaseActionKind::SendRenew);
        CHECK(id != 0);
        s = b.onRenewReply(id, renewFailed(), now);
        lastDelay = s.wakeAtMs - now;
        now = s.wakeAtMs;
    }
    CHECK(lastDelay == 120000);
    s = b.tick(now);
    s = b.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewRefused(UpstreamErrorCode::RateLimited, 42), now);
    CHECK(!s.has(LeaseActionKind::LeaveNode) && s.wakeAtMs == qMin(now + 42000, b.deadlineMs()));
}

// seq only grows: a duplicate answer with a lower seq never moves it back.
static void seqMonotonic()
{
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 10)), T);
    s = m.tick(T + 300000);
    CHECK(must(s, LeaseActionKind::SendRenew).meter.seq == 11);
    s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(3, kServerT0 + 1200000), T + 300100);
    CHECK(m.lastAcceptedSeq() == 11);
    s = m.tick(T + 600100);
    CHECK(must(s, LeaseActionKind::SendRenew).meter.seq == 12);
    s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(20, kServerT0 + 1500000), T + 600200);
    CHECK(m.lastAcceptedSeq() == 20); // the server's last accepted is higher: follow it
    s = m.tick(T + 900200);
    CHECK(must(s, LeaseActionKind::SendRenew).meter.seq == 21);
}

static void rebaselineAndConfigChanged()
{
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 0, kServerT0 + 900000,
                                                                                     "session", 300, 1)), T);
    m.onTunnelBytes(5000, 500);
    s = m.tick(T + 300000);
    const quint64 id = sentId(s, LeaseActionKind::SendRenew);
    m.onTunnelBytes(5600, 560); // after the report was frozen
    s = m.onRenewReply(id, renewed(1, kServerT0 + 1200000, /*rebaseline=*/true, false, /*epoch=*/2), T + 300100);
    CHECK(s.has(LeaseActionKind::RestartByteCounters) && !s.has(LeaseActionKind::LeaveNode));
    CHECK(m.accountingEpoch() == 2 && m.unreportedRx() == 0 && m.unreportedTx() == 0 && m.lastAcceptedSeq() == 1);
    m.onTunnelBytes(5700, 570); // counters not reset by the owner: only bytes after the rebaseline count
    s = m.tick(T + 600100);
    const LeaseAction *rn = s.find(LeaseActionKind::SendRenew);
    CHECK(rn && rn->meter.seq == 2 && rn->meter.rxDelta == 100 && rn->meter.txDelta == 10);
    // config_changed: reported once, the session stays.
    s = m.onRenewReply(rn ? rn->requestId : 0, renewed(2, kServerT0 + 1500000, false, true, 2), T + 600200);
    CHECK(s.has(LeaseActionKind::ConfigChanged) && !s.has(LeaseActionKind::LeaveNode) && m.phase() == LeasePhase::Active);
    s = m.tick(T + 900200);
    s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(3, kServerT0 + 1800000, false, true, 2), T + 900300);
    CHECK(!s.has(LeaseActionKind::ConfigChanged));
    // An owner that resets its counters after RestartByteCounters: a counter that went back = restart.
    m.onTunnelBytes(40, 4);
    CHECK(m.unreportedRx() == 40 && m.unreportedTx() == 4);
    m.baselineBytes(1000, 100);
    m.onTunnelBytes(1010, 101);
    CHECK(m.unreportedRx() == 50 && m.unreportedTx() == 5);
}

// Backend review 14.11: the server fences reports by `epoch`. Every renew/release carries the epoch the
// machine believes when it SENDS: the grant's, the rebaseline answer's after it (a fresh report and the
// retry of an unanswered one alike), and a cancelled acquire's late grant is released with its own.
static void epochFence()
{
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 0, kServerT0 + 900000,
                                                                                     "session", 300, 7)), T);
    s = m.tick(T + 300000);
    CHECK(must(s, LeaseActionKind::SendRenew).meter.epoch == 7);
    s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(1, kServerT0 + 1200000, true, false, 8), T + 300100);
    s = m.tick(T + 600100);
    const LeaseAction r2 = must(s, LeaseActionKind::SendRenew);
    CHECK(r2.meter.epoch == 8 && r2.meter.seq == 2);
    s = m.onRenewReply(r2.requestId, RenewReply(), T + 600200); // no answer: retried
    s = m.tick(T + 700000);
    const LeaseAction r2b = must(s, LeaseActionKind::SendRenew);
    CHECK(r2b.meter.seq == 2 && r2b.meter.epoch == 8);
    CHECK(QJsonDocument::fromJson(upstreamMeterBody(r2b.meter)).object().value("epoch").toInteger() == 8);
    s = m.disconnect(T + 700100);
    CHECK(must(s, LeaseActionKind::SendRelease).meter.epoch == 8);
    // Cancelled acquire: released with the late grant's own epoch.
    LeaseStep s2;
    UpstreamLeaseMachine c = started(s2);
    const quint64 aid = sentId(s2, LeaseActionKind::SendAcquire);
    c.disconnect(T + 10);
    s2 = c.onAcquireReply(aid, granted(leaseJson(kLeaseA, 4, kServerT0 + 900000, "session", 300, 11)), T + 20);
    CHECK(must(s2, LeaseActionKind::SendRelease).meter.epoch == 11);
}

static void terminalCodes()
{
    for (UpstreamErrorCode c : {UpstreamErrorCode::NotEntitled, UpstreamErrorCode::OverQuota,
                                UpstreamErrorCode::Disabled, UpstreamErrorCode::LeaseGone}) {
        LeaseStep s;
        UpstreamLeaseMachine m = started(s);
        s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
        s = m.tick(T + 300000);
        s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewRefused(c), T + 300100);
        const LeaseAction *leave = s.find(LeaseActionKind::LeaveNode);
        CHECK(leave && leave->reason == QLatin1String(upstreamErrorCodeName(c)) && m.phase() == LeasePhase::Left);
        CHECK(m.tick(T + 10000000).actions.isEmpty() && m.tick(T + 10000000).wakeAtMs == -1);
        CHECK(m.disconnect(T + 10000001).actions.isEmpty());
        // The same code before bring-up: the node is not used (LeaveNode, not "try next").
        UpstreamLeaseMachine p = started(s);
        s = p.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireRefused(c), T + 10);
        CHECK(s.has(LeaseActionKind::LeaveNode) && !s.has(LeaseActionKind::TryNextCandidate)
              && p.phase() == LeasePhase::Left);
    }
    // Non-terminal answers to a renewal never leave the node.
    for (UpstreamErrorCode c : {UpstreamErrorCode::NoSeat, UpstreamErrorCode::RateLimited,
                                UpstreamErrorCode::UpstreamUnavailable, UpstreamErrorCode::Unknown}) {
        LeaseStep s;
        UpstreamLeaseMachine m = started(s);
        s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
        s = m.tick(T + 300000);
        s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewRefused(c), T + 300100);
        CHECK(!s.has(LeaseActionKind::LeaveNode) && m.phase() == LeasePhase::Active && m.reportInDoubt());
    }
}

// Lab 14.11 D2: renewals rejected as malformed (422) are retried like a transient failure, but
// kUpstreamRenewRejectedLimit in a row leave the node with "renew_rejected"; another HTTP answer in between
// breaks the row, a transport failure does not.
static void renewRejectedInRow()
{
    const RenewReply bad = classifyRenewReply(422, R"({"code":"invalid_request"})");
    const RenewReply bare422 = classifyRenewReply(422, "{}");
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    s = m.tick(T + 300000);
    qint64 now = T + 300000;
    const auto answer = [&](const RenewReply &r) {
        const quint64 id = sentId(s, LeaseActionKind::SendRenew);
        CHECK(id != 0);
        s = m.onRenewReply(id, r, now + 100);
        if (!s.has(LeaseActionKind::LeaveNode)) {
            now = s.wakeAtMs;
            s = m.tick(now);
        }
    };
    answer(bad);
    CHECK(m.renewRejectedInRow() == 1 && m.phase() == LeasePhase::Active && !s.has(LeaseActionKind::LeaveNode));
    answer(renewFailed()); // no HTTP answer: the row stays
    CHECK(m.renewRejectedInRow() == 1);
    answer(bare422);
    CHECK(m.renewRejectedInRow() == 2 && m.phase() == LeasePhase::Active);
    answer(renewRefused(UpstreamErrorCode::RateLimited, 5)); // another HTTP answer: the row is broken
    CHECK(m.renewRejectedInRow() == 0 && m.phase() == LeasePhase::Active);
    answer(bad);
    answer(bad);
    CHECK(m.renewRejectedInRow() == 2 && m.phase() == LeasePhase::Active && !s.has(LeaseActionKind::LeaveNode));
    answer(bad);
    const LeaseAction *leave = s.find(LeaseActionKind::LeaveNode);
    CHECK(leave && leave->reason == QLatin1String("renew_rejected") && m.phase() == LeasePhase::Left);
    CHECK(m.disconnect(now + 1000).actions.isEmpty()); // a left lease sends nothing more
    // A granted renewal resets the row.
    UpstreamLeaseMachine g = started(s);
    s = g.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    s = g.tick(T + 300000);
    s = g.onRenewReply(sentId(s, LeaseActionKind::SendRenew), bad, T + 300100);
    s = g.tick(s.wakeAtMs);
    s = g.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(1, kServerT0 + 1200000), s.wakeAtMs + 100);
    CHECK(g.renewRejectedInRow() == 0 && g.phase() == LeasePhase::Active);
}

// Before bring-up: no_seat and every transient problem = try the next candidate.
static void beforeBringUp()
{
    struct Case { AcquireReply r; const char *reason; };
    AcquireReply invalid;
    invalid.why = QStringLiteral("signature");
    const Case cases[] = {{acquireRefused(UpstreamErrorCode::NoSeat, 30), "no_seat"},
                          {acquireRefused(UpstreamErrorCode::RateLimited), "rate_limited"},
                          {acquireRefused(UpstreamErrorCode::UpstreamUnavailable), "upstream_unavailable"},
                          {acquireFailed(), "transport"},
                          {invalid, "invalid_answer"}};
    for (const Case &c : cases) {
        LeaseStep s;
        UpstreamLeaseMachine m = started(s);
        s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), c.r, T + 10);
        const LeaseAction *next = s.find(LeaseActionKind::TryNextCandidate);
        CHECK(next && next->reason == QLatin1String(c.reason));
        CHECK(!s.has(LeaseActionKind::LeaveNode) && !s.has(LeaseActionKind::LeaseReady) && m.phase() == LeasePhase::Failed);
        CHECK(m.tick(T + 10000000).actions.isEmpty());
    }
    // A grant for another profile or kind is not ours.
    LeaseStep s;
    UpstreamLeaseMachine m;
    s = m.start(kProfileId, LeaseKind::Probe, MeterScope::Tunnel, 100, T);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T + 10); // session grant
    CHECK(s.has(LeaseActionKind::TryNextCandidate) && !s.has(LeaseActionKind::LeaseReady));
    // A failed candidate can be restarted on another profile; old answers stay stale.
    const quint64 oldId = 1;
    s = m.start(QStringLiteral("0000000000000001"), LeaseKind::Session, MeterScope::Tunnel, 100, T + 20);
    CHECK(sentId(s, LeaseActionKind::SendAcquire) > oldId && m.phase() == LeasePhase::Acquiring);
    CHECK(m.onAcquireReply(oldId, granted(leaseJson()), T + 30).actions.isEmpty());
    // start() while a session runs is ignored.
    CHECK(m.start(kProfileId, LeaseKind::Session, MeterScope::Tunnel, 100, T + 40).actions.isEmpty());
}

// Fails every renewal (no answer) until the machine turns to a fresh acquire; returns that moment. On the
// way: never a renewal past the deadline, never a leave.
static qint64 failUntilAcquire(UpstreamLeaseMachine &m, LeaseStep &s, qint64 now)
{
    for (int i = 0; i < 200; ++i) {
        if (s.has(LeaseActionKind::SendAcquire))
            return now;
        if (s.has(LeaseActionKind::SendRenew)) {
            CHECK(now < m.deadlineMs());
            s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewFailed(), now);
            CHECK(!s.has(LeaseActionKind::LeaveNode) && m.phase() == LeasePhase::Active);
        }
        CHECK(s.wakeAtMs >= now);
        now = s.wakeAtMs;
        s = m.tick(now);
    }
    CHECK(false);
    return now;
}

// The expiry rule: past the TTL without a successful renewal the next contact is a fresh acquire.
static void expiryRule()
{
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 4)), T);
    m.onTunnelBytes(700, 70);
    qint64 now = T + 300000;
    s = m.tick(now);
    const LeaseAction frozen = must(s, LeaseActionKind::SendRenew);
    CHECK(frozen.meter.seq == 5);
    // The API is unreachable for longer than the TTL.
    m.onTunnelBytes(900, 90); // +200/+20 never sent
    const qint64 acquiredAt = failUntilAcquire(m, s, now);
    CHECK(acquiredAt >= m.deadlineMs() && s.has(LeaseActionKind::SendAcquire) && !s.has(LeaseActionKind::SendRenew));
    CHECK(m.phase() == LeasePhase::Active); // the working session stays
    // The server hands out a NEW lease: seq restarts at its value; the report in doubt is dropped (it may
    // have been applied), the bytes never sent carry over.
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire),
                         granted(leaseJson(kLeaseB, 0, kServerT0 + 2000000)), acquiredAt + 50);
    CHECK(m.leaseId() == kLeaseB && m.lastAcceptedSeq() == 0 && !m.reportInDoubt());
    CHECK(!s.has(LeaseActionKind::LeaseReady) && !s.has(LeaseActionKind::RestartByteCounters));
    s = m.tick(acquiredAt + 50 + 300000);
    const LeaseAction *rn = s.find(LeaseActionKind::SendRenew);
    CHECK(rn && rn->leaseId == kLeaseB && rn->meter.seq == 1 && rn->meter.rxDelta == 200 && rn->meter.txDelta == 20);

    // The same lease comes back (server clock behind): seq < the report's seq -> it was not applied: kept.
    UpstreamLeaseMachine k = started(s);
    s = k.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 4)), T);
    k.onTunnelBytes(700, 70);
    s = k.tick(T + 300000);
    const qint64 kAt = failUntilAcquire(k, s, T + 300000);
    CHECK(s.has(LeaseActionKind::SendAcquire));
    s = k.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 4)), kAt + 1);
    CHECK(k.reportInDoubt());
    s = k.tick(k.deadlineMs() - 1000);
    rn = s.find(LeaseActionKind::SendRenew);
    CHECK(rn && rn->meter.seq == 5 && rn->meter.rxDelta == 700);
    // ... and seq >= the report's seq: it was applied: dropped.
    UpstreamLeaseMachine d = started(s);
    s = d.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 4)), T);
    d.onTunnelBytes(700, 70);
    s = d.tick(T + 300000);
    const qint64 dAt = failUntilAcquire(d, s, T + 300000);
    s = d.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 5)), dAt + 1);
    CHECK(!d.reportInDoubt() && d.lastAcceptedSeq() == 5);

    // A re-acquire during the session answered no_seat: the seat went to someone else while the lease
    // was dead - leave (decision of 14.11), with its own reason, not "try next".
    UpstreamLeaseMachine q = started(s);
    s = q.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    s = q.tick(q.deadlineMs());
    s = q.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireRefused(UpstreamErrorCode::NoSeat, 60), q.deadlineMs());
    CHECK(s.find(LeaseActionKind::LeaveNode) && s.find(LeaseActionKind::LeaveNode)->reason == QLatin1String("no_seat_reacquire"));
    CHECK(!s.has(LeaseActionKind::TryNextCandidate) && q.phase() == LeasePhase::Left);
    CHECK(q.disconnect(q.deadlineMs() + 1).actions.isEmpty());

    // A re-acquire during the session answered 503 / transport: the session stays, retried.
    UpstreamLeaseMachine r = started(s);
    s = r.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    s = r.tick(r.deadlineMs());
    CHECK(s.has(LeaseActionKind::SendAcquire));
    s = r.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireRefused(UpstreamErrorCode::UpstreamUnavailable, 60), r.deadlineMs());
    CHECK(!s.has(LeaseActionKind::TryNextCandidate) && !s.has(LeaseActionKind::LeaveNode) && r.phase() == LeasePhase::Active);
    CHECK(s.wakeAtMs == r.deadlineMs() + 60000);
    CHECK(r.tick(r.deadlineMs() + 59999).actions.isEmpty());
    s = r.tick(r.deadlineMs() + 60000);
    CHECK(s.has(LeaseActionKind::SendAcquire));
    s = r.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireFailed(), r.deadlineMs() + 60000);
    CHECK(!s.has(LeaseActionKind::TryNextCandidate) && r.phase() == LeasePhase::Active);
    s = r.tick(s.wakeAtMs);
    s = r.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireRefused(UpstreamErrorCode::Disabled), r.deadlineMs() + 200000);
    CHECK(s.has(LeaseActionKind::LeaveNode) && r.phase() == LeasePhase::Left);
    // At the deadline the re-acquire goes out AT ONCE, even with a long retry pending (here the server
    // asked for 900 s right before the deadline); after that attempt fails, the normal backoff applies.
    UpstreamLeaseMachine w = started(s);
    s = w.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    s = w.tick(T + 300000);
    s = w.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewRefused(UpstreamErrorCode::UpstreamUnavailable, 900), T + 300000);
    const qint64 dl = w.deadlineMs();
    CHECK(s.wakeAtMs == dl);                         // not T + 1200000
    CHECK(w.tick(dl - 1).actions.isEmpty());
    s = w.tick(dl);
    CHECK(s.has(LeaseActionKind::SendAcquire) && !s.has(LeaseActionKind::SendRenew));
    s = w.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireFailed(), dl + 100);
    CHECK(s.wakeAtMs > dl + 100);                    // backoff, not another immediate attempt
    CHECK(w.tick(dl + 200).actions.isEmpty());
    s = w.tick(s.wakeAtMs);
    CHECK(s.has(LeaseActionKind::SendAcquire));
    // The rule holds again for the NEXT lease: granted, renewals fail past its deadline -> at once again.
    s = w.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseB, 0, kServerT0 + 3000000)), w.deadlineMs() + 1);
    const qint64 t2 = w.deadlineMs() - 1000;
    s = w.tick(t2 - 100000);
    s = w.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewRefused(UpstreamErrorCode::RateLimited, 900), t2 - 100000);
    CHECK(s.wakeAtMs == w.deadlineMs());
    s = w.tick(w.deadlineMs());
    CHECK(s.has(LeaseActionKind::SendAcquire));
    // A renewal sent before the deadline and failing after it: the re-acquire is due at once.
    UpstreamLeaseMachine y = started(s);
    s = y.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 0, kServerT0 + 900000, "session", 450)), T);
    s = y.tick(T + 450000);
    s = y.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewRefused(UpstreamErrorCode::RateLimited, 449), T + 450000);
    CHECK(s.wakeAtMs == T + 899000);
    s = y.tick(T + 899000);
    CHECK(s.has(LeaseActionKind::SendRenew));
    s = y.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewFailed(), y.deadlineMs() + 500);
    CHECK(s.wakeAtMs == y.deadlineMs() + 500);       // immediate, not the 30 s backoff
    s = y.tick(y.deadlineMs() + 500);
    CHECK(s.has(LeaseActionKind::SendAcquire));
    // A new accounting epoch on the re-acquire: counters restart.
    UpstreamLeaseMachine e = started(s);
    s = e.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    e.onTunnelBytes(100, 10);
    s = e.tick(e.deadlineMs());
    s = e.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire),
                         granted(leaseJson(kLeaseB, 0, kServerT0 + 1800000, "session", 300, 2)), e.deadlineMs() + 5);
    CHECK(s.has(LeaseActionKind::RestartByteCounters) && e.unreportedRx() == 0 && e.accountingEpoch() == 2);
}

// The device clock is wrong by a day: nothing changes (only the device's own elapsed time counts).
static void clockSkewAndBackwards()
{
    LeaseStep s;
    UpstreamLeaseMachine m;
    s = m.start(kProfileId, LeaseKind::Session, MeterScope::Tunnel, 100, 5);
    const qint64 farServer = kServerT0 + 86400000LL * 400;
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 0, farServer)), 300);
    CHECK(m.deadlineMs() == 5 + 900000 && s.wakeAtMs == 300 + 300000);
    // A renewal 300 s later: the server's expiry moves by 300 s -> the deadline moves by 300 s.
    s = m.tick(300300);
    s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(1, farServer + 300000), 300400);
    CHECK(m.deadlineMs() == 5 + 900000 + 300000);
    // A garbage far-future expiry is capped by maxTtl from the request.
    s = m.tick(600400);
    s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(2, farServer + 86400000LL * 30), 600500);
    CHECK(m.deadlineMs() == 600400 + 3600000LL);
    // The clock goes back: read as the last value, nothing fires twice.
    CHECK(m.tick(10).actions.isEmpty());
    CHECK(m.tick(600500).actions.isEmpty());
}

static void probeLease()
{
    LeaseStep s;
    UpstreamLeaseMachine m = started(s, LeaseKind::Probe);
    CHECK(s.actions[0].leaseKind == LeaseKind::Probe);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire),
                         granted(leaseJson(kLeaseA, 0, kServerT0 + 60000, "probe", 0)), T + 10);
    CHECK(s.has(LeaseActionKind::LeaseReady) && m.kind() == LeaseKind::Probe);
    CHECK(s.wakeAtMs == m.deadlineMs()); // only the end of the lease
    m.onTunnelBytes(65536, 4096);
    for (qint64 t = T; t < T + 3600000; t += 10000) {
        const LeaseStep pt = m.tick(t); // one tick per moment: a second call would hide an acquire in flight
        CHECK(!pt.has(LeaseActionKind::SendRenew) && !pt.has(LeaseActionKind::SendAcquire));
    }
    s = m.disconnect(T + 3600000);
    const LeaseAction *rel = s.find(LeaseActionKind::SendRelease);
    CHECK(rel && rel->leaseId == kLeaseA && rel->meter.seq == 1 && rel->meter.rxDelta == 65536 && rel->meter.txDelta == 4096);
    CHECK(m.phase() == LeasePhase::Released);
}

static void release()
{
    // Clean state: final deltas under the next seq.
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 3)), T);
    m.onTunnelBytes(10, 1);
    s = m.disconnect(T + 1000);
    const LeaseAction *rel = s.find(LeaseActionKind::SendRelease);
    CHECK(rel && rel->meter.seq == 4 && rel->meter.rxDelta == 10 && rel->meter.txDelta == 1);
    CHECK(m.phase() == LeasePhase::Released && m.tick(T + 9000000).actions.isEmpty());
    CHECK(m.disconnect(T + 9000001).actions.isEmpty()); // only once
    // A report in doubt: resent under its own seq with the newer bytes added.
    UpstreamLeaseMachine d = started(s);
    s = d.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 3)), T);
    d.onTunnelBytes(100, 10);
    s = d.tick(T + 300000);
    const quint64 rid = sentId(s, LeaseActionKind::SendRenew);
    d.onTunnelBytes(150, 15);
    s = d.disconnect(T + 300500); // the renewal is still in flight
    rel = s.find(LeaseActionKind::SendRelease);
    CHECK(rel && rel->meter.seq == 4 && rel->meter.rxDelta == 150 && rel->meter.txDelta == 15);
    CHECK(d.onRenewReply(rid, renewed(4, kServerT0 + 1200000), T + 300600).actions.isEmpty()); // late: ignored
    // Disconnect while the first acquire is in flight: nothing to release now; a late grant is given back.
    UpstreamLeaseMachine c = started(s);
    const quint64 aid = sentId(s, LeaseActionKind::SendAcquire);
    CHECK(c.disconnect(T + 5).actions.isEmpty() && c.phase() == LeasePhase::Released);
    s = c.onAcquireReply(aid, granted(leaseJson(kLeaseA, 2)), T + 50);
    rel = s.find(LeaseActionKind::SendRelease);
    CHECK(rel && rel->leaseId == kLeaseA && rel->meter.seq == 3 && rel->meter.rxDelta == 0);
    CHECK(!s.has(LeaseActionKind::LeaseReady));
    CHECK(c.onAcquireReply(aid, granted(leaseJson(kLeaseA, 2)), T + 60).actions.isEmpty()); // once
    // A renewal answer for another lease id is not ours: retried, nothing accepted.
    UpstreamLeaseMachine o = started(s);
    s = o.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 0)), T);
    s = o.tick(T + 300000);
    s = o.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(1, kServerT0 + 1200000, false, false, 1, kLeaseB), T + 300100);
    CHECK(o.reportInDoubt() && o.lastAcceptedSeq() == 0 && s.wakeAtMs == T + 300100 + 15000);
}

static void revisions()
{
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 0, kServerT0 + 900000,
                                                                                     "session", 300, 1, 150)), T);
    const LeaseAction *rev = s.find(LeaseActionKind::RevisionChanged);
    CHECK(rev && rev->upstreamRevision == 150 && m.knownRevision() == 150);
    s = m.tick(T + 300000);
    s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(1, kServerT0 + 1200000, false, false, 1, kLeaseA, 300, 150), T + 300100);
    CHECK(!s.has(LeaseActionKind::RevisionChanged));
    s = m.tick(T + 600100);
    s = m.onRenewReply(sentId(s, LeaseActionKind::SendRenew), renewed(2, kServerT0 + 1500000, false, false, 1, kLeaseA, 300, 149), T + 600200);
    CHECK(!s.has(LeaseActionKind::RevisionChanged)); // never backwards
    // An error with a newer revision is reported too (no_seat / disabled carry one).
    UpstreamLeaseMachine n = started(s);
    s = n.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireRefused(UpstreamErrorCode::NoSeat, 5, 300), T);
    CHECK(s.has(LeaseActionKind::RevisionChanged) && s.has(LeaseActionKind::TryNextCandidate));
}

static void renewSchedule()
{
    const auto firstRenewDelay = [](int renewAfter) {
        LeaseStep s;
        UpstreamLeaseMachine m;
        s = m.start(kProfileId, LeaseKind::Session, MeterScope::Tunnel, 100, T);
        s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire),
                             granted(leaseJson(kLeaseA, 0, kServerT0 + 900000, "session", renewAfter)), T);
        return s.wakeAtMs - T;
    };
    CHECK(firstRenewDelay(300) == 300000);
    CHECK(firstRenewDelay(5000) == 450000); // never later than ttl/2
    CHECK(firstRenewDelay(10) == 30000);    // never sooner than 30 s
    CHECK(firstRenewDelay(0) == 300000);    // a session lease without a value: the tunable default
    UpstreamLeaseTiming t;
    t.defaultRenewS = 120;
    LeaseStep s;
    UpstreamLeaseMachine m(t);
    s = m.start(kProfileId, LeaseKind::Session, MeterScope::Tunnel, 100, T);
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson(kLeaseA, 0, kServerT0 + 900000, "session", 0)), T);
    CHECK(s.wakeAtMs - T == 120000);
}


// Contract additions of 14.11: renew_token + tunnel_api_base on the grant, meter_scope on every report,
// shadow_bytes on renewals.
static void routeAndScope()
{
    Key key;
    const auto signedWith = [&key](const QJsonObject &o) {
        const QByteArray b = bytes(o);
        return classifyAcquireReply(200, b, key.sign(QByteArray("tribe-upstream-lease-v1\n") + b), key.pubHex());
    };
    QJsonObject o = leaseJson();
    AcquireReply r = signedWith(o);
    CHECK(r.kind == LeaseReplyKind::Granted && r.grant.renewToken.isEmpty() && r.grant.tunnelApiBase.isEmpty());
    o.insert("renew_token", "rt.Opaque-123_~");
    o.insert("tunnel_api_base", "https://t.example.net/api/");
    r = signedWith(o);
    CHECK(r.kind == LeaseReplyKind::Granted && r.grant.renewToken == QLatin1String("rt.Opaque-123_~")
          && r.grant.tunnelApiBase == QLatin1String("https://t.example.net/api"));
    o.insert("tunnel_api_base", QJsonValue());
    CHECK(signedWith(o).kind == LeaseReplyKind::Granted && signedWith(o).grant.tunnelApiBase.isEmpty());
    for (const QJsonValue &bad : {QJsonValue("http://t.example.net"), QJsonValue("https://u:p@t.example.net"),
                                  QJsonValue("https://t.example.net/?x=1"), QJsonValue("not a url"), QJsonValue(5),
                                  QJsonValue("")}) {
        o.insert("tunnel_api_base", bad);
        CHECK(signedWith(o).kind == LeaseReplyKind::Failed && signedWith(o).why == QLatin1String("tunnel_api_base"));
    }
    o.remove("tunnel_api_base");
    for (const QJsonValue &bad : {QJsonValue("has space"), QJsonValue(""), QJsonValue(7),
                                  QJsonValue(QString(1025, QLatin1Char('a'))), QJsonValue(QStringLiteral("t\u00e9"))}) {
        o.insert("renew_token", bad);
        CHECK(signedWith(o).kind == LeaseReplyKind::Failed && signedWith(o).why == QLatin1String("renew_token"));
    }
    // shadow_bytes: optional on a renewal.
    QJsonObject rw{{"status", "ok"}, {"lease_id", kLeaseA}, {"expires_at", iso(kServerT0)}, {"renew_after_s", 300},
                   {"seq", 1}, {"upstream_revision", 7}, {"traffic_accounting_epoch", 1}, {"config_changed", false},
                   {"applied_bytes", 10}};
    CHECK(classifyRenewReply(200, bytes(rw)).renewal.shadowBytes == 0);
    rw.insert("shadow_bytes", 4096);
    CHECK(classifyRenewReply(200, bytes(rw)).renewal.shadowBytes == 4096);
    rw.insert("shadow_bytes", -1);
    CHECK(classifyRenewReply(200, bytes(rw)).kind == LeaseReplyKind::Failed);
    // meter_scope in the body.
    CHECK(QJsonDocument::fromJson(upstreamMeterBody({1, 2, 3, MeterScope::Proxy})).object().value("meter_scope")
          == QJsonValue("proxy"));
    CHECK(QJsonDocument::fromJson(upstreamMeterBody({1, 2, 3, MeterScope::Tunnel})).object().value("meter_scope")
          == QJsonValue("tunnel"));

    // The machine: the route rides on LeaseReady / renew / release; the scope on every report, unchanged
    // across a new lease of the same session.
    QJsonObject g1 = leaseJson(kLeaseA, 0);
    g1.insert("renew_token", "tokA");
    g1.insert("tunnel_api_base", "https://a.example.net");
    QJsonObject g2 = leaseJson(kLeaseB, 0, kServerT0 + 2000000);
    g2.insert("renew_token", "tokB");
    UpstreamLeaseMachine m;
    LeaseStep st = m.start(kProfileId, LeaseKind::Session, MeterScope::Proxy, 100, T);
    st = m.onAcquireReply(sentId(st, LeaseActionKind::SendAcquire), granted(g1), T);
    const LeaseRoute ra{QStringLiteral("tokA"), QStringLiteral("https://a.example.net")};
    CHECK(must(st, LeaseActionKind::LeaseReady).route == ra && must(st, LeaseActionKind::LeaseReady).leaseId == kLeaseA);
    CHECK(m.meterScope() == MeterScope::Proxy && m.route() == ra);
    st = m.tick(T + 300000);
    CHECK(must(st, LeaseActionKind::SendRenew).route == ra && must(st, LeaseActionKind::SendRenew).meter.scope == MeterScope::Proxy);
    const quint64 rid = sentId(st, LeaseActionKind::SendRenew);
    st = m.onRenewReply(rid, renewFailed(), T + 300000);
    st = m.tick(st.wakeAtMs);
    CHECK(must(st, LeaseActionKind::SendRenew).meter.scope == MeterScope::Proxy); // the retry too
    const qint64 at = failUntilAcquire(m, st, T + 315000);
    st = m.onAcquireReply(sentId(st, LeaseActionKind::SendAcquire), granted(g2), at + 1);
    CHECK(m.route() == (LeaseRoute{QStringLiteral("tokB"), QString()}));       // the new lease's own route
    st = m.disconnect(at + 2);
    CHECK(must(st, LeaseActionKind::SendRelease).route == (LeaseRoute{QStringLiteral("tokB"), QString()}));
    CHECK(must(st, LeaseActionKind::SendRelease).meter.scope == MeterScope::Proxy);
    // A cancelled acquire's late grant is released with that grant's own route and the old scope.
    UpstreamLeaseMachine c;
    st = c.start(kProfileId, LeaseKind::Session, MeterScope::Proxy, 100, T);
    const quint64 aid = sentId(st, LeaseActionKind::SendAcquire);
    c.disconnect(T + 1);
    c.start(kProfileId, LeaseKind::Session, MeterScope::Tunnel, 100, T + 2);
    st = c.onAcquireReply(aid, granted(g1), T + 3);
    CHECK(must(st, LeaseActionKind::SendRelease).route == ra && must(st, LeaseActionKind::SendRelease).meter.scope == MeterScope::Proxy);
}


// Provisional start from a standby-pack entry (decision of 14.11).
static void provisional()
{
    const QString packSha = QString::fromLatin1(QCryptographicHash::hash(kConfig, QCryptographicHash::Sha256).toHex());
    const QString base = QStringLiteral("https://t.example.net");
    UpstreamLeaseMachine m;
    LeaseStep s = m.startProvisional(kProfileId, MeterScope::Proxy, packSha, base, 100, 12000, T);
    const LeaseAction ready = must(s, LeaseActionKind::LeaseReady);
    CHECK(ready.provisional && ready.leaseId.isEmpty() && ready.route == (LeaseRoute{QString(), base}));
    CHECK(s.has(LeaseActionKind::RestartByteCounters) && !s.has(LeaseActionKind::SendAcquire) && s.wakeAtMs == -1);
    CHECK(m.phase() == LeasePhase::Provisional && m.provisional());
    CHECK(m.tick(T + 1000).actions.isEmpty());                          // nothing before the tunnel is up
    CHECK(m.start(kProfileId, LeaseKind::Session, MeterScope::Tunnel, 100, T + 1).actions.isEmpty()); // busy
    m.onTunnelBytes(3000, 300);
    s = m.tunnelUp(T + 2000);
    const LeaseAction acq = must(s, LeaseActionKind::SendAcquire);
    CHECK(acq.standby && acq.configSha256 == packSha && acq.route == (LeaseRoute{QString(), base}) && acq.leaseKind == LeaseKind::Session);
    CHECK(m.tunnelUp(T + 2001).actions.isEmpty());                      // once
    m.onTunnelBytes(5000, 500);
    QJsonObject g = leaseJson(kLeaseA, 2);
    g.insert("renew_token", "tokP");
    s = m.onAcquireReply(acq.requestId, granted(g), T + 2500);
    const LeaseAction conf = must(s, LeaseActionKind::LeaseConfirmed);
    CHECK(conf.leaseId == kLeaseA && conf.route == (LeaseRoute{QStringLiteral("tokP"), base})); // pack base kept
    CHECK(!s.has(LeaseActionKind::LeaseReady) && !s.has(LeaseActionKind::RestartByteCounters) && !s.has(LeaseActionKind::ConfigChanged));
    CHECK(m.phase() == LeasePhase::Active && m.lastAcceptedSeq() == 2 && m.deadlineMs() == T + 2000 + 900000);
    s = m.tick(s.wakeAtMs);
    const LeaseAction rn = must(s, LeaseActionKind::SendRenew);
    CHECK(rn.meter.seq == 3 && rn.meter.rxDelta == 5000 && rn.meter.txDelta == 500 && rn.meter.scope == MeterScope::Proxy);
    CHECK(rn.route == (LeaseRoute{QStringLiteral("tokP"), base}));

    // Another sha, or config_changed: the session stays, ConfigChanged once.
    for (int variant = 0; variant < 2; ++variant) {
        UpstreamLeaseMachine c;
        s = c.startProvisional(kProfileId, MeterScope::Tunnel, variant == 0 ? QString(64, QLatin1Char('e')) : packSha, base, 100, 12000, T);
        s = c.tunnelUp(T + 1);
        QJsonObject gc = leaseJson();
        if (variant == 1)
            gc.insert("config_changed", true);
        s = c.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(gc), T + 2);
        CHECK(s.has(LeaseActionKind::LeaseConfirmed) && s.has(LeaseActionKind::ConfigChanged) && !s.has(LeaseActionKind::LeaveNode));
        CHECK(c.phase() == LeasePhase::Active);
    }
    // no_seat -> no_seat_standby; terminal codes -> the code; nothing released afterwards.
    const auto refusedAfterUp = [&](UpstreamErrorCode code) {
        UpstreamLeaseMachine q;
        LeaseStep st = q.startProvisional(kProfileId, MeterScope::Tunnel, packSha, base, 100, 12000, T);
        st = q.tunnelUp(T + 1);
        st = q.onAcquireReply(sentId(st, LeaseActionKind::SendAcquire), acquireRefused(code), T + 2);
        const QString reason = must(st, LeaseActionKind::LeaveNode).reason;
        CHECK(q.phase() == LeasePhase::Left && q.disconnect(T + 3).actions.isEmpty());
        return reason;
    };
    CHECK(refusedAfterUp(UpstreamErrorCode::NoSeat) == QLatin1String("no_seat_standby"));
    for (UpstreamErrorCode c : {UpstreamErrorCode::NotEntitled, UpstreamErrorCode::OverQuota, UpstreamErrorCode::Disabled,
                                UpstreamErrorCode::LeaseGone})
        CHECK(refusedAfterUp(c) == QLatin1String(upstreamErrorCodeName(c)));
    // Transient (lab 14.11 D3): the profile refuses every connection in its first seconds - retried on the
    // SHORT early spacing (300, 600, 1200, 2000, 2000 ms) or the server's retry_after_s, then
    // standby_unconfirmed exactly at the budget.
    UpstreamLeaseMachine u;
    s = u.startProvisional(kProfileId, MeterScope::Tunnel, packSha, base, 100, 12000, T);
    s = u.tunnelUp(T + 2000);
    qint64 at = T + 2010;
    for (qint64 spacing : {300, 600, 1200, 2000, 2000}) {
        s = u.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireFailed(), at);
        CHECK(!s.has(LeaseActionKind::LeaveNode) && s.wakeAtMs == at + spacing);
        CHECK(u.tick(at + spacing - 1).actions.isEmpty());
        s = u.tick(at + spacing);
        CHECK(must(s, LeaseActionKind::SendAcquire).standby);
        at += spacing + 10;
    }
    s = u.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireRefused(UpstreamErrorCode::RateLimited, 9), at);
    CHECK(s.wakeAtMs == T + 2000 + 12000); // retry_after 9 s (from T+8160) capped by the budget
    s = u.tick(T + 13999);
    CHECK(s.actions.isEmpty());
    s = u.tick(T + 14000);
    CHECK(must(s, LeaseActionKind::LeaveNode).reason == QLatin1String("standby_unconfirmed") && u.phase() == LeasePhase::Left);
    // The server's retry_after_s inside the budget is honoured as before.
    UpstreamLeaseMachine ra;
    s = ra.startProvisional(kProfileId, MeterScope::Tunnel, packSha, base, 100, 40000, T);
    s = ra.tunnelUp(T + 2000);
    s = ra.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireRefused(UpstreamErrorCode::RateLimited, 5), T + 2500);
    CHECK(s.wakeAtMs == T + 7500);
    // Refused for the first ~1.2 s, then the seat: confirmed (one early refusal never decides).
    UpstreamLeaseMachine warm;
    s = warm.startProvisional(kProfileId, MeterScope::Tunnel, packSha, base, 100, 12000, T);
    s = warm.tunnelUp(T);
    s = warm.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireFailed(), T + 5);
    s = warm.tick(T + 305);
    s = warm.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireFailed(), T + 310);
    s = warm.tick(T + 910);
    s = warm.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireFailed(), T + 915);
    s = warm.tick(T + 2115);
    s = warm.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T + 2200);
    CHECK(s.has(LeaseActionKind::LeaseConfirmed) && warm.phase() == LeasePhase::Active);
    // A failure answering after the budget: leave at once.
    UpstreamLeaseMachine late;
    s = late.startProvisional(kProfileId, MeterScope::Tunnel, packSha, base, 100, 5000, T);
    s = late.tunnelUp(T);
    s = late.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), acquireFailed(), T + 5000);
    CHECK(must(s, LeaseActionKind::LeaveNode).reason == QLatin1String("standby_unconfirmed"));
    // A provisional start is ignored while a session runs (normal or provisional).
    UpstreamLeaseMachine busy;
    s = busy.start(kProfileId, LeaseKind::Session, MeterScope::Tunnel, 100, T);
    s = busy.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    CHECK(busy.startProvisional(kProfileId, MeterScope::Proxy, packSha, base, 100, 12000, T + 1).actions.isEmpty());
    CHECK(busy.phase() == LeasePhase::Active && busy.leaseId() == kLeaseA && busy.meterScope() == MeterScope::Tunnel);
    UpstreamLeaseMachine twice;
    s = twice.startProvisional(kProfileId, MeterScope::Proxy, packSha, base, 100, 12000, T);
    s = twice.tunnelUp(T + 1);
    CHECK(twice.startProvisional(kProfileId, MeterScope::Tunnel, packSha, base, 100, 12000, T + 2).actions.isEmpty());
    CHECK(twice.phase() == LeasePhase::Provisional && twice.meterScope() == MeterScope::Proxy);
    // ... but a GRANT after the budget is taken (the seat is ours).
    UpstreamLeaseMachine lg;
    s = lg.startProvisional(kProfileId, MeterScope::Tunnel, packSha, base, 100, 5000, T);
    s = lg.tunnelUp(T);
    s = lg.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T + 9000);
    CHECK(s.has(LeaseActionKind::LeaseConfirmed) && lg.phase() == LeasePhase::Active);
    // A grant for another profile is not ours: retried.
    UpstreamLeaseMachine wrong;
    s = wrong.startProvisional(QStringLiteral("0000000000000001"), MeterScope::Tunnel, packSha, base, 100, 12000, T);
    s = wrong.tunnelUp(T);
    s = wrong.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T + 1);
    CHECK(!s.has(LeaseActionKind::LeaseConfirmed) && wrong.phase() == LeasePhase::Provisional
          && s.wakeAtMs == T + 1 + 300); // the first early retry (lab 14.11 D3)
    // disconnect before a grant: nothing to release; a late grant is given back.
    UpstreamLeaseMachine d;
    s = d.startProvisional(kProfileId, MeterScope::Proxy, packSha, base, 100, 12000, T);
    CHECK(d.disconnect(T + 1).actions.isEmpty() && d.phase() == LeasePhase::Released);
    s = d.startProvisional(kProfileId, MeterScope::Proxy, packSha, base, 100, 12000, T + 2);
    s = d.tunnelUp(T + 3);
    const quint64 aid = sentId(s, LeaseActionKind::SendAcquire);
    CHECK(d.disconnect(T + 4).actions.isEmpty());
    s = d.onAcquireReply(aid, granted(leaseJson(kLeaseA, 7)), T + 5);
    const LeaseAction rel = must(s, LeaseActionKind::SendRelease);
    CHECK(rel.leaseId == kLeaseA && rel.meter.seq == 8 && rel.meter.scope == MeterScope::Proxy);
}

struct FakeIo : IUpstreamLeaseIo {
    QStringList calls;
    void acquire(quint64 id, const QString &p, LeaseKind k, const QString &, const LeaseRoute &) override
    {
        calls << QStringLiteral("acquire %1 %2 %3").arg(id).arg(p, leaseKindName(k));
    }
    void renew(quint64 id, const QString &l, const UpstreamMeter &m, const LeaseRoute &) override
    {
        calls << QStringLiteral("renew %1 %2 %3").arg(id).arg(l).arg(m.seq);
    }
    void release(quint64 id, const QString &l, const UpstreamMeter &m, const LeaseRoute &) override
    {
        calls << QStringLiteral("release %1 %2 %3").arg(id).arg(l).arg(m.seq);
    }
};

static void dispatch()
{
    FakeIo io;
    LeaseStep s;
    UpstreamLeaseMachine m = started(s);
    CHECK(dispatchLeaseIo(s, io).isEmpty() && io.calls.size() == 1 && io.calls[0].startsWith("acquire"));
    s = m.onAcquireReply(sentId(s, LeaseActionKind::SendAcquire), granted(leaseJson()), T);
    const QVector<LeaseAction> rest = dispatchLeaseIo(s, io);
    CHECK(rest.size() == 2 && io.calls.size() == 1);
    s = m.tick(T + 300000);
    dispatchLeaseIo(s, io);
    CHECK(io.calls.size() == 2 && io.calls[1].endsWith(kLeaseA + QStringLiteral(" 1")));
    s = m.disconnect(T + 300001);
    dispatchLeaseIo(s, io);
    CHECK(io.calls.size() == 3 && io.calls[2].startsWith("release"));
    CHECK(UpstreamLeaseTiming::fromTuning().defaultRenewS == 300);
}

// Owner's iPhone 16.11 (build 140): both seat releases ended "net_error 5" 40-80 ms after they were sent - aborted
// by the API reset of the tunnel transition they preceded - and were never sent again. One resend, only for an
// abort of our own (not the release's own 1.5 s timeout, not an answer).
static void releaseResend()
{
    CHECK(upstreamReleaseResend(0, /*canceled=*/true, /*timedOut=*/false));
    CHECK(!upstreamReleaseResend(1, true, false));  // once
    CHECK(!upstreamReleaseResend(0, true, true));   // its own timeout: the server frees the seat at TTL
    CHECK(!upstreamReleaseResend(0, false, false)); // an answer or another error
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0); // FAIL lines survive a crash of a mutated build
    signature();
    wire();
    freshSession();
    retrySameSeq();
    seqMonotonic();
    rebaselineAndConfigChanged();
    epochFence();
    terminalCodes();
    renewRejectedInRow();
    beforeBringUp();
    expiryRule();
    clockSkewAndBackwards();
    probeLease();
    release();
    revisions();
    renewSchedule();
    dispatch();
    routeAndScope();
    provisional();
    releaseResend();
    if (g_fail) {
        std::printf("upstream_lease_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("upstream_lease_check: OK (%d checks)\n", g_total);
    return 0;
}
