// AVPN upstream nodes: the standby pack (UpstreamStandbyPack.h) - parse and refusals, age on the wall
// clock, the stale-entry rule - and the decision "may a failed direct acquire fall back to the pack"
// (UpstreamLeaseWire.h::mayStartProvisional), the standby acquire body and the grant's config_changed.
// Keys are generated in the test; data is synthetic. Build/run: build_upstream_standby.sh
#include "../UpstreamStandbyPack.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QPair>
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

static const qint64 kIssued = 1763117000000LL;
static const QByteArray kCfgA = R"({"inbounds":[],"outbounds":[{"protocol":"vless","tag":"a"}]})";
static const QByteArray kCfgB = R"({"inbounds":[],"outbounds":[{"protocol":"hysteria","tag":"b"}]})";

static QString sha(const QByteArray &b)
{
    return QString::fromLatin1(QCryptographicHash::hash(b, QCryptographicHash::Sha256).toHex());
}
static QString iso(qint64 ms) { return QDateTime::fromMSecsSinceEpoch(ms, QTimeZone::UTC).toString(Qt::ISODateWithMs); }

static QJsonObject entry(const char *id, const QByteArray &cfg)
{
    return QJsonObject{{"profile_id", id}, {"node_id", QStringLiteral("up:") + QLatin1String(id)},
                       {"label", "Provider profile"}, {"country_code", "fi"}, {"tier", 1},
                       {"probe_class", "single"}, {"config", QString::fromUtf8(cfg)}, {"config_sha256", sha(cfg)}};
}

static QJsonObject pack()
{
    return QJsonObject{{"type", "upstream_standby"}, {"version", 1}, {"issued_at", iso(kIssued)}, {"max_age_s", 259200},
                       {"upstream_revision", 500.0}, {"tunnel_api_base", "https://t.example.net/"},
                       {"entries", QJsonArray{entry("aaaaaaaaaaaaaaaa", kCfgA), entry("bbbbbbbbbbbbbbbb", kCfgB)}}};
}

static QByteArray ser(const QJsonObject &o) { return QJsonDocument(o).toJson(QJsonDocument::Compact); }

static Key &key()
{
    static Key k;
    return k;
}

static StandbyParse parsed(const QJsonObject &o)
{
    const QByteArray b = ser(o);
    return parseStandbyPack(b, key().sign(QByteArray("tribe-upstream-standby-v1\n") + b), key().pubHex());
}

static bool refused(const StandbyParse &p, StandbyRefusal r)
{
    if (p.refusal != r)
        std::printf("   got %s (%s), expected %s\n", standbyRefusalCode(p.refusal), qPrintable(p.detail), standbyRefusalCode(r));
    return p.refusal == r && p.pack.entries.isEmpty();
}

static void parse()
{
    StandbyParse p = parsed(pack());
    CHECK(p.ok() && p.code() == QLatin1String("ok"));
    CHECK(p.pack.version == 1 && p.pack.issuedAtMs == kIssued && p.pack.maxAgeS == 259200 && p.pack.upstreamRevision == 500);
    CHECK(p.pack.tunnelApiBase == QLatin1String("https://t.example.net"));
    CHECK(p.pack.entries.size() == 2 && p.pack.find("bbbbbbbbbbbbbbbb") && p.pack.find("bbbbbbbbbbbbbbbb")->config == kCfgB);
    CHECK(p.pack.find("aaaaaaaaaaaaaaaa")->countryCode == QLatin1String("FI") && !p.pack.find("cccccccccccccccc"));
    CHECK(p.pack.find("aaaaaaaaaaaaaaaa")->probeClass == UpstreamProbeClass::Single);
    // Release A display parts of an entry: absent = 0 / false; present = parsed; malformed = ignored, not refused.
    CHECK(p.pack.find("aaaaaaaaaaaaaaaa")->ordinal == 0 && !p.pack.find("aaaaaaaaaaaaaaaa")->labelCustom);
    {
        QJsonObject o = pack();
        QJsonArray es = o.value("entries").toArray();
        QJsonObject e0 = es.at(0).toObject();
        e0.insert("ordinal", 3);
        e0.insert("label_custom", true);
        QJsonObject e1 = es.at(1).toObject();
        e1.insert("ordinal", "three");
        e1.insert("label_custom", "yes");
        es.replace(0, e0);
        es.replace(1, e1);
        o.insert("entries", es);
        const StandbyParse q = parsed(o);
        CHECK(q.ok() && q.pack.find("aaaaaaaaaaaaaaaa")->ordinal == 3 && q.pack.find("aaaaaaaaaaaaaaaa")->labelCustom);
        CHECK(q.pack.find("bbbbbbbbbbbbbbbb")->ordinal == 0 && !q.pack.find("bbbbbbbbbbbbbbbb")->labelCustom);
    }
    // Signature: the standby context only.
    const QByteArray b = ser(pack());
    CHECK(refused(parseStandbyPack(b, key().sign(b), key().pubHex()), StandbyRefusal::Signature));
    CHECK(refused(parseStandbyPack(b, key().sign(QByteArray("tribe-upstream-lease-v1\n") + b), key().pubHex()), StandbyRefusal::Signature));
    CHECK(refused(parseStandbyPack(b + " ", key().sign(QByteArray("tribe-upstream-standby-v1\n") + b), key().pubHex()), StandbyRefusal::Signature));
    Key other;
    CHECK(refused(parseStandbyPack(b, key().sign(QByteArray("tribe-upstream-standby-v1\n") + b), other.pubHex()), StandbyRefusal::Signature));
    CHECK(refused(parseStandbyPack(QByteArray(kStandbyMaxBodyBytes + 1, ' '), QByteArray(), key().pubHex()), StandbyRefusal::TooLarge));
    {
        const QByteArray arr = "[1]";
        CHECK(refused(parseStandbyPack(arr, key().sign(QByteArray("tribe-upstream-standby-v1\n") + arr), key().pubHex()), StandbyRefusal::NotObject));
    }
    const auto with = [](const std::function<void(QJsonObject &)> &f) { QJsonObject o = pack(); f(o); return parsed(o); };
    CHECK(refused(with([](QJsonObject &o) { o.insert("type", "upstream_lease"); }), StandbyRefusal::Type));
    CHECK(refused(with([](QJsonObject &o) { o.remove("type"); }), StandbyRefusal::Type));
    CHECK(refused(with([](QJsonObject &o) { o.insert("version", 2); }), StandbyRefusal::Version));
    CHECK(refused(with([](QJsonObject &o) { o.remove("version"); }), StandbyRefusal::Version));
    CHECK(refused(with([](QJsonObject &o) { o.insert("issued_at", "yesterday"); }), StandbyRefusal::IssuedAt));
    CHECK(refused(with([](QJsonObject &o) { o.insert("max_age_s", 0); }), StandbyRefusal::MaxAge));
    CHECK(refused(with([](QJsonObject &o) { o.insert("max_age_s", "1"); }), StandbyRefusal::MaxAge));
    CHECK(refused(with([](QJsonObject &o) { o.insert("upstream_revision", -1); }), StandbyRefusal::Revision));
    CHECK(refused(with([](QJsonObject &o) { o.insert("tunnel_api_base", "http://t.example.net"); }), StandbyRefusal::ApiBase));
    CHECK(refused(with([](QJsonObject &o) { o.insert("tunnel_api_base", 5); }), StandbyRefusal::ApiBase));
    CHECK(with([](QJsonObject &o) { o.remove("tunnel_api_base"); }).ok());
    CHECK(with([](QJsonObject &o) { o.insert("tunnel_api_base", QJsonValue()); }).pack.tunnelApiBase.isEmpty());
    CHECK(refused(with([](QJsonObject &o) { o.remove("entries"); }), StandbyRefusal::Entries));
    CHECK(refused(with([](QJsonObject &o) {
                      QJsonArray many;
                      for (int i = 0; i < kStandbyMaxEntries + 1; ++i)
                          many << entry(qPrintable(QStringLiteral("p%1").arg(i)), kCfgA);
                      o.insert("entries", many);
                  }),
                  StandbyRefusal::Entries));
    CHECK(with([](QJsonObject &o) { o.insert("entries", QJsonArray()); }).ok()); // an empty pack is valid, useless
    // Entries.
    const auto withEntry = [&with](const std::function<void(QJsonObject &)> &f) {
        return with([&f](QJsonObject &o) {
            QJsonArray a = o.value("entries").toArray();
            QJsonObject e = a.at(1).toObject();
            f(e);
            a[1] = e;
            o.insert("entries", a);
        });
    };
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("profile_id", "bad id"); }), StandbyRefusal::EntryField));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("node_id", "up:other"); }), StandbyRefusal::EntryNodeId));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("node_id", "7"); }), StandbyRefusal::EntryNodeId));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("label", 5); }), StandbyRefusal::EntryField));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("country_code", "FIN"); }), StandbyRefusal::EntryField));
    CHECK(withEntry([](QJsonObject &e) { e.insert("country_code", QJsonValue()); }).ok());
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("tier", 0); }), StandbyRefusal::EntryField));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("probe_class", "chain"); }), StandbyRefusal::EntryField));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("config", ""); }), StandbyRefusal::EntryField));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("config_sha256", QString(63, QLatin1Char('a'))); }), StandbyRefusal::EntryField));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("config_sha256", sha(kCfgA)); }), StandbyRefusal::EntrySha));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("config", QString::fromUtf8(kCfgB) + QLatin1Char(' ')); }), StandbyRefusal::EntrySha));
    CHECK(refused(withEntry([](QJsonObject &e) {
                      const QByteArray big = QByteArray(R"({"pad":")") + QByteArray(kUpstreamProfileMaxBytes, 'x') + "\"}";
                      e.insert("config", QString::fromUtf8(big));
                      e.insert("config_sha256", sha(big));
                  }),
                  StandbyRefusal::EntrySize));
    CHECK(refused(withEntry([](QJsonObject &e) { e.insert("profile_id", "aaaaaaaaaaaaaaaa"); e.insert("node_id", "up:aaaaaaaaaaaaaaaa"); e.insert("config", QString::fromUtf8(kCfgA)); e.insert("config_sha256", sha(kCfgA)); }),
                  StandbyRefusal::EntryDuplicate));
    CHECK(refused(with([](QJsonObject &o) { o.insert("entries", QJsonArray{5}); }), StandbyRefusal::EntryField));
}

static void age()
{
    const StandbyPack p = parsed(pack()).pack;
    const int cap = upstreamStandbyMaxAgeSFrom(259200);
    CHECK(standbyPackUsable(p, kIssued, cap).usable);
    CHECK(standbyPackUsable(p, kIssued + 259200LL * 1000 - 1, cap).usable);
    CHECK(!standbyPackUsable(p, kIssued + 259200LL * 1000, cap).usable);
    CHECK(standbyPackUsable(p, kIssued + 259200LL * 1000, cap).reason == QLatin1String("expired"));
    // The tuned cap shortens a pack's own max_age_s, never lengthens it.
    CHECK(!standbyPackUsable(p, kIssued + 3600LL * 1000, upstreamStandbyMaxAgeSFrom(3600)).usable);
    CHECK(standbyPackUsable(p, kIssued + 3599LL * 1000, upstreamStandbyMaxAgeSFrom(3600)).usable);
    StandbyPack shortLived = p;
    shortLived.maxAgeS = 600;
    CHECK(!standbyPackUsable(shortLived, kIssued + 600000, upstreamStandbyMaxAgeSFrom(1209600)).usable);
    // A device clock before issued_at: within the tolerance = age 0; beyond it = not trustworthy.
    CHECK(standbyPackUsable(p, kIssued - kStandbyClockBackToleranceMs, cap).usable);
    CHECK(!standbyPackUsable(p, kIssued - kStandbyClockBackToleranceMs - 1, cap).usable);
    CHECK(standbyPackUsable(p, kIssued - kStandbyClockBackToleranceMs - 1, cap).reason == QLatin1String("clock_before_issue"));
    CHECK(standbyPackUsable(p, kIssued - 10 * 60000, cap, 5 * 60000).reason == QLatin1String("clock_before_issue"));
    // Tunables.
    TuningStore::reset();
    CHECK(upstreamStandbyMaxAgeSTuned() == 259200 && upstreamStandbyRefreshSTuned() == 21600);
    TuningStore::set({{QStringLiteral("upstream_standby_max_age_s"), 60}, {QStringLiteral("upstream_standby_refresh_s"), 1e9}}, {});
    CHECK(upstreamStandbyMaxAgeSTuned() == 3600 && upstreamStandbyRefreshSTuned() == 86400);
    TuningStore::set({{QStringLiteral("upstream_standby_max_age_s"), 1e9}, {QStringLiteral("upstream_standby_refresh_s"), 10}}, {});
    CHECK(upstreamStandbyMaxAgeSTuned() == 1209600 && upstreamStandbyRefreshSTuned() == 900);
    TuningStore::reset();
}

static void staleRule()
{
    const StandbyPack p = parsed(pack()).pack; // revision 500
    const StandbyEntry &e = *p.find("aaaaaaaaaaaaaaaa");
    UpstreamStub same;
    same.configSha256 = e.configSha256;
    UpstreamStub other;
    other.configSha256 = QString(64, QLatin1Char('f'));
    CHECK(standbyEntryUsable(e, nullptr, 900, p.upstreamRevision).usable);                 // no stub: unknown
    CHECK(standbyEntryUsable(e, &same, 900, p.upstreamRevision).usable);                    // same config
    CHECK(standbyEntryUsable(e, &same, 900, p.upstreamRevision).reason == QLatin1String("same_config"));
    StandbyUse u = standbyEntryUsable(e, &other, 900, p.upstreamRevision);                  // newer subscription
    CHECK(!u.usable && u.reason == QLatin1String("entry_stale"));
    u = standbyEntryUsable(e, &other, 500, p.upstreamRevision);                             // same revision, other sha
    CHECK(!u.usable && u.reason == QLatin1String("entry_stale"));
    u = standbyEntryUsable(e, &other, 499, p.upstreamRevision);                             // pack newer
    CHECK(u.usable && u.reason == QLatin1String("entry_newer_than_subscription"));
    CHECK(standbyEntryUsable(e, &other, 0, p.upstreamRevision).usable);                     // subscription w/o revision
}

static void fallbackDecision()
{
    AcquireReply r;
    r.kind = LeaseReplyKind::Failed;
    for (const char *why : {"transport", "http_403", "http_502", "signature"}) {
        r.why = QLatin1String(why);
        CHECK(mayStartProvisional(r));
    }
    for (const char *why : {"type", "config_sha256_mismatch", "lease_id", "renew_token", "mismatch", ""}) {
        r.why = QLatin1String(why);
        CHECK(!mayStartProvisional(r));
    }
    r = AcquireReply();
    r.kind = LeaseReplyKind::Refused;
    for (UpstreamErrorCode c : {UpstreamErrorCode::NotEntitled, UpstreamErrorCode::OverQuota, UpstreamErrorCode::Disabled,
                                UpstreamErrorCode::LeaseGone, UpstreamErrorCode::NoSeat, UpstreamErrorCode::RateLimited,
                                UpstreamErrorCode::UpstreamUnavailable}) {
        r.error.code = c;
        CHECK(!mayStartProvisional(r)); // the server spoke: never the pack
        r.why = QStringLiteral("transport");
        CHECK(!mayStartProvisional(r)); // whatever else the reply carries
        r.why.clear();
    }
    r = AcquireReply();
    r.kind = LeaseReplyKind::Granted;
    CHECK(!mayStartProvisional(r));
    // The classifier's real outputs.
    CHECK(mayStartProvisional(classifyAcquireReply(0, {}, {}, key().pubHex())));
    CHECK(mayStartProvisional(classifyAcquireReply(403, "<html>blocked</html>", {}, key().pubHex())));
    CHECK(mayStartProvisional(classifyAcquireReply(200, "<html>portal</html>", {}, key().pubHex())));
    CHECK(!mayStartProvisional(classifyAcquireReply(409, R"({"code":"no_seat"})", {}, key().pubHex())));
    CHECK(!mayStartProvisional(classifyAcquireReply(429, R"({"code":"rate_limited"})", {}, key().pubHex())));
    // Lab 14.11 D1: `X-Tribe-Api: 1` = our server answered - never the pack, whatever the body; the same
    // answers without the header keep today's rule.
    for (const auto &c : QList<QPair<int, QByteArray>>{{429, R"({"detail":"rate limit exceeded"})"},
                                                       {401, R"({"detail":"Not authenticated"})"},
                                                       {403, "<html>blocked</html>"},
                                                       {502, {}},
                                                       {200, "<html>portal</html>"}}) {
        CHECK(!mayStartProvisional(classifyAcquireReply(c.first, c.second, {}, key().pubHex(), /*fromTribeApi=*/true)));
        CHECK(mayStartProvisional(classifyAcquireReply(c.first, c.second, {}, key().pubHex(), /*fromTribeApi=*/false)));
    }
    CHECK(mayStartProvisional(classifyAcquireReply(0, {}, {}, key().pubHex(), true))); // no answer, no header
    CHECK(!mayStartProvisional(classifyAcquireReply(422, R"({"code":"invalid_request"})", {}, key().pubHex())));
}

static void wireAdditions()
{
    CHECK(QJsonDocument::fromJson(upstreamAcquireBody("p1", LeaseKind::Session)).object()
          == QJsonObject({{"profile_id", "p1"}, {"kind", "session"}}));
    CHECK(QJsonDocument::fromJson(upstreamAcquireBody("p1", LeaseKind::Session, QString(64, QLatin1Char('a')))).object()
          == QJsonObject({{"profile_id", "p1"}, {"kind", "session"}, {"standby", true},
                          {"config_sha256", QString(64, QLatin1Char('a'))}}));
    QJsonObject g{{"type", "upstream_lease"}, {"lease_id", QString(40, QLatin1Char('L'))}, {"profile_id", "p1"},
                  {"kind", "session"}, {"expires_at", iso(kIssued)}, {"ttl_s", 900}, {"renew_after_s", 300},
                  {"seq", 0}, {"config", QString::fromUtf8(kCfgA)}, {"config_sha256", sha(kCfgA)},
                  {"upstream_revision", 1}, {"traffic_accounting_epoch", 1}};
    UpstreamLeaseGrant out;
    QString why;
    CHECK(parseUpstreamLeaseGrant(ser(g), out, why) && !out.configChanged);
    g.insert("config_changed", true);
    CHECK(parseUpstreamLeaseGrant(ser(g), out, why) && out.configChanged);
    g.insert("config_changed", "yes");
    CHECK(!parseUpstreamLeaseGrant(ser(g), out, why) && why == QLatin1String("config_changed"));
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    parse();
    age();
    staleRule();
    fallbackDecision();
    wireAdditions();
    if (g_fail) {
        std::printf("upstream_standby_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("upstream_standby_check: OK (%d checks)\n", g_total);
    return 0;
}
