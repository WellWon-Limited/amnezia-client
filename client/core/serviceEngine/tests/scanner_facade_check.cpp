// AVPN Scanner - coordinator checks (lane L6a): TribeScanner + ScanApiClient driven end to end on a fake
// clock, with a fake probe host that speaks real `tribe-scan-v1` JSON (ScanHostContract.h encoders and
// decoders: freeze ack, final totals, opening / closing access attempts, the shared byte gate), a fake HTTP
// layer playing the server (signed manifest with ETag and 304, scan token, signed probe-batch, release,
// outcomes) and a fake engine (the three tunnel actions, report checks). One QTcpServer case
// proves the production QNAM layer cuts an answer at its reservation.
// Build + run: tests/build_scanner_facade.sh (--mutate: the coordinator rule breaks, each must fail here).

#include "../ScanApiClient.h"
#include "../TribeScanner.h"

#include <QCoreApplication>
#include <QMetaProperty>
#include <QElapsedTimer>
#include <QTimeZone>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMultiMap>
#include <QNetworkAccessManager>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QHostAddress>

#include <openssl/evp.h>
#include <zlib.h>

#include <cstdio>
#include <cstdlib>
#include <functional>

using namespace avpn;

static int g_checks = 0;
static int g_fail = 0;
static QString g_case;

#define CHECK(cond)                                                                                          \
    do {                                                                                                     \
        ++g_checks;                                                                                          \
        if (!(cond)) {                                                                                       \
            ++g_fail;                                                                                        \
            std::fprintf(stderr, "FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, qPrintable(g_case), #cond);     \
        }                                                                                                    \
    } while (0)

#define CHECK_EQ(a, b)                                                                                       \
    do {                                                                                                     \
        ++g_checks;                                                                                          \
        const auto va = (a);                                                                                 \
        const auto vb = (b);                                                                                 \
        if (!(va == vb)) {                                                                                   \
            ++g_fail;                                                                                        \
            std::fprintf(stderr, "FAIL %s:%d [%s] %s == %s (%s vs %s)\n", __FILE__, __LINE__, qPrintable(g_case), \
                         #a, #b, qPrintable(QVariant::fromValue(va).toString()),                             \
                         qPrintable(QVariant::fromValue(vb).toString()));                                    \
        }                                                                                                    \
    } while (0)

static const qint64 kT0 = 1789000000000LL;
// What the fake live-tunnel probe really transfers: one TLS estimate + the warm and the data request as read
// (body + 400 bytes of headers each) - reported as is, never clamped (review F2).
static const qint64 kLiveSpent = 8192 + (1024 + 400) + (65536 + 400);

// --- markers that must never reach a log line -------------------------------------------------------------
static const char *kApiBase = "https://api.leakhost.example";
static const char *kTunnelBase = "https://tunnel.leakhost.example";
static const char *kDeviceToken = "DEVICE-TOKEN-SECRET";
static const char *kProviderHost = "provider-leak.example";
static const char *kProviderIp = "203.0.113.77";
static const char *kProviderConfig = "SECRET-PROVIDER-CONFIG";
static const QStringList kLeakMarkers = {QStringLiteral("leakhost.example"), QStringLiteral("provider-leak.example"),
                                         QStringLiteral("203.0.113.77"), QStringLiteral("198.51.100."),
                                         QStringLiteral("tsc1."), QStringLiteral("LEASEID"), QStringLiteral("DEVICE-TOKEN"),
                                         QStringLiteral("SECRET-PROVIDER-CONFIG"), QStringLiteral("OWN-CONFIG"),
                                         QStringLiteral("net-access"), QStringLiteral("net-exit"), QStringLiteral("10.8.0.5"),
                                         QStringLiteral("192.0.2."), QStringLiteral("2001:db8"), QStringLiteral("private_key"),
                                         QStringLiteral("AWGPRIVKEY")};

// --- test key (a public seed, never a real key) --------------------------------------------------------------
struct TestKey {
    EVP_PKEY *k = nullptr;
    explicit TestKey(const char *seedText)
    {
        const QByteArray seed = QCryptographicHash::hash(QByteArray(seedText), QCryptographicHash::Sha256);
        k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(seed.constData()),
                                         size_t(seed.size()));
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

// --- the event loop of the fake world ------------------------------------------------------------------------
struct World;

struct FakeClock : IScanClock {
    qint64 t = kT0;
    qint64 nowMs() override { return t; }
};

struct FakeTimer : IScanTimer {
    FakeClock *clock = nullptr;
    qint64 due = -1;
    void arm(qint64 delayMs) override { due = clock->t + qMax<qint64>(0, delayMs); }
    void cancel() override { due = -1; }
};

struct MemStore : IScanStore {
    QHash<QString, QByteArray> m;
    QByteArray read(const QString &key) const override { return m.value(key); }
    bool write(const QString &key, const QByteArray &value) override
    {
        m.insert(key, value);
        return true;
    }
    void remove(const QString &key) override { m.remove(key); }
};

struct Events {
    FakeClock *clock = nullptr;
    QMultiMap<qint64, std::function<void()>> q;
    void at(qint64 delayMs, std::function<void()> f) { q.insert(clock->t + qMax<qint64>(0, delayMs), std::move(f)); }
};

// --- the fake engine ------------------------------------------------------------------------------------------
struct FakeEngine : IScanEngine {
    Events *ev = nullptr;
    QJsonArray offered; // offerScanNodes: the stub nodes the batch's provider rows carried
    void offerScanNodes(const QJsonArray &nodes) override
    {
        for (const QJsonValue &v : nodes)
            offered << v;
    }
    ScanCurrent cur;
    ScanNetFacts net;
    QList<ScanOwnNode> own;
    int userConnects = 0;
    int cancels = 0;
    struct RowCall {
        QString id;
        QStringList order;
        qint64 ttl = 0;
        bool userOrigin = false;
        bool force = false;
    };
    QList<RowCall> rowCalls;
    int reports = 0;
    QString lastReportId;
    QHash<QString, ScanAwgNodeInput> awg;
    QHash<QString, QStringList> knownIps;
    QString liveBase;
    bool queueFull = false;

    bool names = false; // providerRowName: the app's naming of provider rows (false = none, the server's label)
    QString providerRowName(const ScanManifestUpstream &u) const override
    {
        return names ? QStringLiteral("Имя ") + u.profileId : QString();
    }
    ScanCurrent current() const override { return cur; }
    ScanNetFacts network() const override { return net; }
    void fillManifestInput(ScanManifestInput &in) const override
    {
        in.ownNodes = own;
    }
    QString ownProbeConfig(const ScanCandidate &c) const override { return QStringLiteral("OWN-CONFIG-") + c.id; }
    QString liveProbeBase(const ScanCurrent &) const override { return liveBase; }
    bool awgProbeInput(const QString &nodeId, ScanAwgNodeInput &out) const override
    {
        if (!awg.contains(nodeId))
            return false;
        out = awg.value(nodeId);
        return true;
    }
    QStringList knownHostIps(const QString &host) const override { return knownIps.value(host); }
    bool reportQueueFull() const override { return queueFull; }
    QString uiLanguage() const override { return QStringLiteral("ru"); }
    void userConnectForScan() override { ++userConnects; }
    void cancelPendingConnect() override { ++cancels; }
    void connectRow(const QString &nodeId, const QStringList &order, qint64 ttl, bool userOrigin, bool force) override
    {
        rowCalls << RowCall{nodeId, order, ttl, userOrigin, force};
    }
    void startReportCheck(const QString &id, const QJsonObject &, bool) override
    {
        ++reports;
        lastReportId = id;
    }
};

// --- the fake server (HTTP) -------------------------------------------------------------------------------------
struct Server {
    TestKey key{"tribe-scanner-facade-test-NOT-A-REAL-KEY"};
    TestKey wrong{"tribe-scanner-facade-wrong-key"};
    bool badManifestSig = false;
    bool badBatchSig = false;
    qint64 revision = 7;
    qint64 tokenRevision = 7;
    int tokenSerial = 0;
    QByteArray etag = "\"sm1.AAAAAAAAAAAAAAAAAAAAAA\"";
    QList<ScanManifestUpstream> unused;
    QJsonArray nodes;     // ScanManifestNode objects
    QJsonArray upstream;  // ScanManifestUpstream objects
    QHash<QString, QString> refuse; // profile id -> refusal code
    QHash<QString, QByteArray> configs; // profile id -> the normalized config a probe grant carries (+ its sha256)
    QJsonObject numbers;  // manifest numbers
    bool scopeApi = false;  // contract 1.14.0: /v1/scan/pool and /v1/scan/candidates answer (else 404: an older server)
    QJsonArray extraUpstream; // provider rows only /v1/scan/candidates offers (beyond the manifest's)
    QList<QJsonObject> candidateRequests;
    int manifestStatus = 0; // non-zero: /v1/scan/manifest answers this status (no body)
    int tokenStatus = 0;    // non-zero: /v1/scan/token answers this status
    int batchPad = 0;     // extra bytes in the probe-batch answer (to pass its reservation)
    int manifestLatency = 40;
    int latency = 40;
    int batchLatency = -1; // -1 = latency
    qint64 deviceBytesPerHour = 0;
    int leaseSerial = 0;
    QStringList releasedLeases;
    int cancelReleases = 0; // the next N probe-seat releases are cut by our own tunnel transition (canceled, no answer)
    QList<int> releaseStatuses; // the next probe-seat releases are answered with these statuses (nothing released)
    int releaseTries = 0;
    // Contract 1.15.0: a batch's operation id. The server's side of an operation: its answer items (a resend gets
    // the same seats), the lease ids it granted (released by the id).
    int cancelBatches = 0;  // the next N probe-batch sends are cut by our own transition AFTER the server granted
    QString foreignOp;      // non-empty: the batch answer echoes this id instead of the request's
    QHash<QString, QJsonArray> opItems;
    QHash<QString, QStringList> opLeases;
    QStringList batchOps;   // the operation id of every batch send, in order
    QStringList releasedOps;
    int outcomeItems = 0;
    QList<IScanHttp::Request> calls;

    QByteArray manifestBody(qint64 now)
    {
        const QString exp = QDateTime::fromMSecsSinceEpoch(now + 24LL * 3600 * 1000, QTimeZone::UTC).toString(Qt::ISODate);
        const QString texp = QDateTime::fromMSecsSinceEpoch(now + 600000, QTimeZone::UTC).toString(Qt::ISODate);
        const QJsonObject o{{"type", "scan_manifest"}, {"version", 1}, {"issued_at", exp}, {"expires_at", exp}, {"ttl_s", 86400},
                            {"network_key", "wifi"}, {"upstream_revision", double(revision)}, {"upstream_eligible", true},
                            {"direct_api_base", QString::fromLatin1(kApiBase)}, {"tunnel_api_base", QString::fromLatin1(kTunnelBase)},
                            {"scan_token", QJsonObject{{"token", QStringLiteral("tsc1.MANIFEST-TOKEN-%1").arg(++tokenSerial)},
                                                       {"expires_at", texp}, {"ttl_s", 600}, {"max_requests", 400},
                                                       {"max_bytes", 67108864}}},
                            {"device_budget", QJsonObject{{"requests_per_hour", 2000}, {"bytes_per_hour", double(deviceBytesPerHour)}}},
                            {"probe", QJsonObject{{"path", "/v1/probe"}, {"default_bytes", 65536}, {"max_bytes", 1048576},
                                                  {"scheme", "tribe-probe-v1"}}},
                            {"numbers", numbers}, {"nodes", nodes}, {"upstream", upstream}};
        return QJsonDocument(o).toJson(QJsonDocument::Compact);
    }

    IScanHttp::Response handle(const IScanHttp::Request &r, qint64 now)
    {
        calls << r;
        IScanHttp::Response out;
        const QUrl url(r.url);
        const QString path = url.path();
        const auto auth = [&r]() {
            for (const auto &h : r.headers)
                if (h.first == "Authorization")
                    return h.second;
            return QByteArray();
        };
        const auto hdr = [&r](const char *name) {
            for (const auto &h : r.headers)
                if (h.first == name)
                    return h.second;
            return QByteArray();
        };
        if (auth() != QByteArray("Bearer ") + kDeviceToken) {
            out.status = 401;
            return out;
        }
        if (path == QLatin1String("/v1/scan/manifest") && manifestStatus) {
            out.status = manifestStatus;
            out.body = R"({"error":"x"})";
            return out;
        }
        if (path == QLatin1String("/v1/scan/token") && tokenStatus) {
            out.status = tokenStatus;
            out.body = R"({"error":"x"})";
            return out;
        }
        if (path == QLatin1String("/v1/scan/manifest")) {
            if (!hdr("If-None-Match").isEmpty() && hdr("If-None-Match") == etag) {
                out.status = 304;
                out.headers.insert("etag", etag);
                return out;
            }
            out.status = 200;
            out.body = manifestBody(now);
            const QByteArray msg = QByteArray("tribe-scan-manifest-v1\n") + out.body;
            out.headers.insert("x-tribe-sig", badManifestSig ? wrong.sign(msg) : key.sign(msg));
            out.headers.insert("etag", etag);
            return out;
        }
        if (path == QLatin1String("/v1/scan/token")) {
            out.status = 200;
            out.body = QJsonDocument(QJsonObject{{"type", "scan_token"}, {"scan_token", QStringLiteral("tsc1.POST-TOKEN-%1").arg(++tokenSerial)},
                                                 {"expires_in_s", 600}, {"upstream_revision", double(tokenRevision)},
                                                 {"budgets", QJsonObject{{"max_requests", 400}, {"max_bytes", 67108864},
                                                                         {"requests_per_hour", 2000}, {"bytes_per_hour", 268435456}}}})
                           .toJson(QJsonDocument::Compact);
            return out;
        }
        if (path == QLatin1String("/v1/upstream/lease/probe-batch")) {
            const QJsonObject req = QJsonDocument::fromJson(r.body).object();
            const bool cfg = req.value("include_config").toBool();
            const QString op = req.value("operation_id").toString();
            batchOps << op;
            QJsonArray items;
            const bool repeat = !op.isEmpty() && opItems.contains(op);
            if (repeat)
                items = opItems.value(op); // the same seats, no new ones
            for (const QJsonValue &v : repeat ? QJsonArray() : req.value("profile_ids").toArray()) {
                const QString pid = v.toString();
                if (refuse.contains(pid)) {
                    items << QJsonObject{{"profile_id", pid}, {"granted", false}, {"code", refuse.value(pid)}};
                    continue;
                }
                QJsonObject it{{"profile_id", pid}, {"granted", true},
                               {"lease_id", QStringLiteral("LEASEIDLEASEIDLEASEIDLEASEID%1").arg(++leaseSerial, 4, 10, QLatin1Char('0'))},
                               {"expires_in_s", 60}};
                if (cfg && configs.contains(pid)) {
                    it.insert("config", QString::fromUtf8(configs.value(pid)));
                    it.insert("config_sha256", QString::fromLatin1(
                        QCryptographicHash::hash(configs.value(pid), QCryptographicHash::Sha256).toHex()));
                } else if (cfg) {
                    it.insert("config", QString::fromLatin1(kProviderConfig));
                }
                items << it;
                if (!op.isEmpty())
                    opLeases[op] << it.value("lease_id").toString();
            }
            if (!op.isEmpty())
                opItems.insert(op, items);
            if (cancelBatches > 0) {
                --cancelBatches;
                out.canceled = true; // granted on the server, the answer never reached the app
                return out;
            }
            QJsonObject body{{"type", "upstream_probe_batch"}, {"upstream_revision", double(revision)}, {"items", items}};
            if (!foreignOp.isEmpty())
                body.insert("operation_id", foreignOp);
            else if (!op.isEmpty())
                body.insert("operation_id", op);
            if (batchPad > 0)
                body.insert("pad", QString(batchPad, QLatin1Char('x')));
            out.status = 200;
            out.body = QJsonDocument(body).toJson(QJsonDocument::Compact);
            const QByteArray msg = QByteArray("tribe-upstream-lease-v1\n") + out.body;
            out.headers.insert("x-tribe-sig", badBatchSig ? wrong.sign(msg) : key.sign(msg));
            return out;
        }
        if (path == QLatin1String("/v1/upstream/lease/probe-batch/release")) {
            ++releaseTries;
            if (!releaseStatuses.isEmpty()) {
                out.status = releaseStatuses.takeFirst(); // e.g. 502 of an API restart: nothing released
                return out;
            }
            if (cancelReleases > 0) {
                --cancelReleases;
                out.canceled = true; // status 0: never reached the server
                return out;
            }
            const QJsonObject rel = QJsonDocument::fromJson(r.body).object();
            for (const QJsonValue &v : rel.value("lease_ids").toArray())
                if (!releasedLeases.contains(v.toString()))
                    releasedLeases << v.toString();
            const QString op = rel.value("operation_id").toString();
            if (!op.isEmpty()) {
                releasedOps << op;
                for (const QString &l : opLeases.value(op)) // every seat of the operation, also unseen ones
                    if (!releasedLeases.contains(l))
                        releasedLeases << l;
            }
            out.status = 204;
            return out;
        }
        if (scopeApi && path == QLatin1String("/v1/scan/pool")) {
            QHash<QString, QPair<int, int>> per;
            for (const QJsonValue &v : nodes)
                per[v.toObject().value("country_code").toString(QStringLiteral("DE"))].first += 1;
            for (const QJsonValue &v : upstream)
                per[v.toObject().value("country_code").toString()].second += 1;
            QJsonArray cs;
            for (auto it = per.constBegin(); it != per.constEnd(); ++it)
                cs << QJsonObject{{"country_code", it.key()}, {"own", it.value().first}, {"provider", it.value().second}};
            out.status = 200;
            out.body = QJsonDocument(QJsonObject{{"type", "scan_pool"}, {"version", 1}, {"upstream_revision", double(revision)},
                                                 {"upstream_eligible", true}, {"countries", cs},
                                                 {"functions", QJsonArray{QJsonObject{{"kind", "whitelist"}, {"provider", 2}}}}})
                           .toJson(QJsonDocument::Compact);
            return out;
        }
        if (scopeApi && path == QLatin1String("/v1/scan/candidates")) {
            const QJsonObject rq = QJsonDocument::fromJson(r.body).object();
            candidateRequests << rq;
            QSet<QString> seen;
            for (const QJsonValue &v : rq.value("seen").toArray())
                seen.insert(v.toString());
            const QString cc = rq.value("country").toString();
            const int limit = rq.value("limit").toInt(12);
            QJsonArray ns, us;
            int left = 0;
            for (const QJsonValue &v : nodes) {
                const QJsonObject n = v.toObject();
                if (seen.contains(n.value("node_id").toString()))
                    continue;
                if (ns.size() + us.size() < limit)
                    ns << n;
                else
                    ++left;
            }
            QJsonArray allUp = upstream;
            for (const QJsonValue &v : extraUpstream)
                allUp << v;
            for (const QJsonValue &v : allUp) {
                QJsonObject u = v.toObject();
                const QString id = QStringLiteral("up:") + u.value("profile_id").toString();
                if (seen.contains(id) || (!cc.isEmpty() && u.value("country_code").toString() != cc))
                    continue;
                if (ns.size() + us.size() < limit) {
                    u.insert("node", QJsonObject{{"node_id", id}, {"proto", "xray"}, {"upstream", QJsonObject{{"profile_id", u.value("profile_id")}}}});
                    us << u;
                } else {
                    ++left;
                }
            }
            if (!cc.isEmpty())
                ns = QJsonArray(); // the fixture's own nodes carry no country on the wire: a country page is providers only
            out.status = 200;
            out.body = QJsonDocument(QJsonObject{{"type", "scan_candidates"}, {"version", 1}, {"issued_at", "2026-11-18T10:00:00Z"},
                                                 {"network_key", rq.value("network_key")}, {"scope", rq.value("scope")},
                                                 {"country", cc.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(cc)},
                                                 {"upstream_revision", double(revision)}, {"exhausted", left == 0},
                                                 {"nodes", ns}, {"upstream", us},
                                                 {"probe_seats", QJsonArray{QJsonObject{{"tier", 1}, {"free", 8}}}}})
                           .toJson(QJsonDocument::Compact);
            out.headers.insert("x-tribe-sig", key.sign(QByteArray("tribe-scan-candidates-v1\n") + out.body));
            return out;
        }
        if (path == QLatin1String("/v1/telemetry/path-outcomes")) {
            outcomeItems += QJsonDocument::fromJson(r.body).object().value("items").toArray().size();
            out.status = 200;
            out.body = R"({"accepted":1,"duplicate":0,"ignored":0,"rejected":0})";
            return out;
        }
        out.status = 404;
        return out;
    }
};

struct FakeHttp : IScanHttp {
    Events *ev = nullptr;
    Server *server = nullptr;
    struct Sent {
        Request req;
        Response resp;
    };
    QList<Sent> sent;
    qint64 totalBytes = 0;
    void send(const Request &r, DoneFn done) override
    {
        Response resp = server->handle(r, ev->clock->t);
        qint64 bytes = scanHttpRequestBytes(r) + 16 + resp.body.size();
        for (auto it = resp.headers.constBegin(); it != resp.headers.constEnd(); ++it)
            bytes += it.key().size() + it.value().size() + 4;
        if (r.maxBytes >= 0 && bytes > r.maxBytes) { // the production layer aborts there (checked below)
            resp.status = 0;
            resp.body.clear();
            resp.cut = true;
            bytes = r.maxBytes;
        }
        resp.bytes = bytes;
        sent << Sent{r, resp};
        totalBytes += bytes;
        const QString path = QUrl(r.url).path();
        const int lat = path == QLatin1String("/v1/scan/manifest") ? server->manifestLatency
                        : path == QLatin1String("/v1/upstream/lease/probe-batch") && server->batchLatency >= 0 ? server->batchLatency
                                                                                                                 : server->latency;
        ev->at(lat, [done, resp]() { done(resp); });
    }
    int count(const char *path) const
    {
        int n = 0;
        for (const Sent &s : sent)
            n += QUrl(s.req.url).path() == QLatin1String(path) ? 1 : 0;
        return n;
    }
    // A copy (the list grows while the world runs); req.url empty = none.
    Sent last(const char *path) const
    {
        for (int i = sent.size() - 1; i >= 0; --i)
            if (QUrl(sent.at(i).req.url).path() == QLatin1String(path))
                return sent.at(i);
        return Sent();
    }
};

// --- the fake probe host (real tribe-scan-v1 JSON) ---------------------------------------------------------------
struct Outcome {
    bool works = true;
    int rtt = 60;
    int durMs = 400;
};

struct FakeHost : IScanHost {
    Events *ev = nullptr;
    ScanHostCaps known;
    ScanHostCaps real;
    ScanHostAvailability avail = ScanHostAvailability::Available;
    bool genKnown = false;
    ScanNetSource gen{QStringLiteral("service"), 0x5e5e5e5e5e5e5e5eULL, 1};
    bool progressGen = true;
    enum class Freeze { Ack, NoAck };
    enum class Cancel { FinalInPoll, FinalInAck, NoFinal };
    Freeze freeze = Freeze::Ack;
    Cancel cancel = Cancel::FinalInPoll;
    QString accessOpen = QStringLiteral("answered"); // answered | network_error | none
    QString refuseStart;          // non-empty: scan_start answered {"error": refuseStart, "detail": refuseDetail}
    QString refuseDetail;
    QString reason = QStringLiteral("service_off"); // unavailableReason() while not Available
    QByteArray pollReplyOnce;     // non-empty: the next poll is answered with exactly this
    bool awgWithheld = false;     // the caps reply withholds AWG for this scan (desktop: live peer unknown)
    QList<QByteArray> startNotNow; // the next scan_start messages are answered with these (one each)
    QList<QByteArray> addNotNow;   // the same for scan_add
    QList<int> startLatency;       // per scan_start: the host takes it (and answers) after this many ms
    QList<int> startReplyLag;      // per scan_start: the host takes it AT ONCE, its answer comes this much later
    qint64 loseScansAt = -1;      // the host forgets every scan from this clock time on (unknown_scan)
    bool capsGen = false;         // the caps reply carries the host's element ("gen", as the iOS extension)
    int awgLivePeerUnknown = 0;   // 1: starts / adds WITH awg_mini are refused (live peer unknown); 2: every start
    QHash<QString, Outcome> outcomes;
    int latency = 5;
    int stopAlls = 0;
    QList<QJsonObject> requests; // decoded (raw JSON objects, for assertions)
    QStringList actions;
    // Scripted ORDER (review R1-R3): for a message this returns true for, the host takes it after `processAfter` ms and
    // its answer comes `replyAfter` ms later - empty when `lose` (the host's reply lost: IScanHost's "no answer").
    std::function<bool(const QJsonObject &req, int &processAfter, int &replyAfter, bool &lose)> script;
    bool replaceForgets = false;               // a new scan_start drops the running scan (the engine: unknown_scan after)
    QString replyingFor;                       // the scan id of the message whose answer is being delivered right now
    QSet<QString> taken;                       // every scan id the host ever started
    QHash<QString, QList<qint64>> finals;      // scan id -> every final total it reported (progress or cancel ack)
    QHash<QString, QList<qint64>> freezeBounds; // scan id -> spent + reserved of every freeze ack it gave
    QHash<QString, qint64> endSpent;           // scan id -> its bytes when it was dropped by a new start

    void deliver(const ReplyFn &reply, const QByteArray &answer, const QString &scan)
    {
        replyingFor = scan;
        reply(answer);
        replyingFor.clear();
    }
    // What the scan really spent so far (the engine's gate), for the "never below" checks.
    qint64 spentOf(const QString &scan) const
    {
        if (endSpent.contains(scan))
            return endSpent.value(scan);
        return scans.contains(scan) ? scans.value(scan).gate.spent() : 0;
    }

    struct Probe {
        ScanHostCandidate c;
        qint64 launchAt = -1;
        qint64 finishAt = -1;
        bool emitted = false;
    };
    struct Scan {
        QString id;
        QString token;
        qint64 startAt = 0;
        qint64 deadline = 0;
        int bytes = 65536;
        ScanHostByteGate gate;
        QList<Probe> probes;
        qint64 seq = 0;
        bool cancelled = false;
        bool ended = false;   // final reported
        bool deadlineHit = false;
        ScanAccessAttempt open;
        ScanAccessAttempt close;
        QList<ScanProbeFacts> items;
    };
    QHash<QString, Scan> scans;
    QString current;

    ScanHostCaps knownCaps() const override { return known; }
    ScanHostAvailability availability() const override { return avail; }
    QString unavailableReason() const override
    {
        return avail == ScanHostAvailability::Available ? QString()
               : avail == ScanHostAvailability::NeedsVpn ? QStringLiteral("no_vpn") : reason;
    }
    bool generation(ScanNetSource &out) const override
    {
        if (!genKnown)
            return false;
        out = gen;
        return true;
    }
    void stopAll() override { ++stopAlls; }

    void sendMessage(const QByteArray &request, ReplyFn reply) override
    {
        const QJsonObject o = QJsonDocument::fromJson(request).object();
        requests << o;
        actions << o.value("action").toString();
        const QString sid = o.value("scan_id").toString();
        if (avail == ScanHostAvailability::Unavailable) { // gone: no answer within the host's bound
            ev->at(2000, [this, reply, sid]() { deliver(reply, QByteArray(), sid); });
            return;
        }
        int proc = 0, after = 0;
        bool lose = false;
        if (script && script(o, proc, after, lose)) {
            ev->at(proc, [this, request, reply, after, lose, sid]() {
                const QByteArray answer = avail == ScanHostAvailability::Available ? handle(request) : QByteArray();
                ev->at(after, [this, reply, answer, lose, sid]() { deliver(reply, lose ? QByteArray() : answer, sid); });
            });
            return;
        }
        if (o.value("action").toString() == QLatin1String("scan_start")) {
            const int lat = startLatency.isEmpty() ? latency : startLatency.takeFirst();
            const int lag = startReplyLag.isEmpty() ? 0 : startReplyLag.takeFirst();
            if (lag > 0) {
                const QByteArray answer = handle(request); // taken now, answered later
                ev->at(lag, [this, reply, answer, sid]() { deliver(reply, answer, sid); });
                return;
            }
            if (lat != latency && avail == ScanHostAvailability::Available) {
                ev->at(lat, [this, request, reply, sid]() { deliver(reply, handle(request), sid); });
                return;
            }
        }
        if (avail == ScanHostAvailability::NeedsVpn) { // the extension is not running (the iOS host's answer)
            ev->at(latency, [this, reply, sid]() { deliver(reply, QByteArrayLiteral("{\"error\":\"no_vpn\"}"), sid); });
            return;
        }
        ev->at(latency, [this, request, reply, sid]() { deliver(reply, handle(request), sid); });
    }

    void launch(Scan &s, qint64 now)
    {
        for (Probe &p : s.probes) {
            if (p.launchAt >= 0 || s.cancelled || s.gate.frozen() || now > s.startAt + s.deadline)
                continue;
            if (!s.gate.admit(p.c.id, p.c.costBytes))
                continue;
            p.launchAt = now;
            const Outcome o = outcomes.value(scanXrayBurstBaseOf(p.c.id.section(QLatin1Char('#'), 0, 0)), Outcome()); // a burst part as its probe
            p.finishAt = now + o.durMs;
        }
    }

    ScanProbeFacts itemOf(Scan &s, Probe &p, ScanProbeError err)
    {
        ScanProbeFacts f;
        f.id = p.c.id;
        f.stage = ScanStage::Data;
        f.seq = ++s.seq;
        const QString cid = scanXrayBurstBaseOf(p.c.id.section(QLatin1Char('#'), 0, 0)); // a burst part answers as its probe
        const Outcome o = outcomes.value(cid, Outcome());
        const int bytes = p.c.bytes > 0 ? p.c.bytes : s.bytes;
        f.bytesRequested = bytes;
        f.startMs = p.launchAt - s.startAt;
        f.endMs = qMax(f.startMs, (err == ScanProbeError::None ? p.finishAt : ev->clock->t) - s.startAt);
        f.error = err;
        f.handshakeOk = p.c.kind == ScanProbeKind::AwgMini && err == ScanProbeError::None && o.works;
        if (err == ScanProbeError::None && o.works) {
            f.httpStatus = 200;
            f.ttfb1Ms = 150;
            f.rttMs = o.rtt;
            f.t64Ms = 120;
            f.durationMs = o.durMs;
            f.bytesReceived = bytes;
            f.shaOk = true;
            if (cid.startsWith(QLatin1String("up:"))) {
                f.egressClass = QStringLiteral("other");
                f.egressAsn = 65001;
                f.egressNetToken = QStringLiteral("net-exit-") + cid.mid(3, 4);
                f.dnsExercised = true;
            } else {
                f.egressClass = QStringLiteral("tribe-node");
                f.egressNode = scanHostPartOf(cid);
            }
        } else if (err == ScanProbeError::None) {
            f.httpStatus = 503;
            f.durationMs = o.durMs;
        }
        const qint64 used = qMin<qint64>(p.c.costBytes, err == ScanProbeError::None ? bytes + 1024 + 8192 : 4096);
        f.spentBytes = used;
        s.gate.finish(p.c.id, used);
        p.emitted = true;
        return f;
    }

    void advance(Scan &s, qint64 now)
    {
        launch(s, now);
        if (!s.cancelled && now >= s.startAt + s.deadline && !s.deadlineHit) {
            s.deadlineHit = true;
            for (Probe &p : s.probes)
                if (p.launchAt >= 0 && !p.emitted)
                    s.items << itemOf(s, p, ScanProbeError::Deadline);
        }
        for (Probe &p : s.probes)
            if (p.launchAt >= 0 && !p.emitted && p.finishAt <= now && !s.deadlineHit)
                s.items << itemOf(s, p, ScanProbeError::None);
    }

    ScanAccessAttempt attempt(const QString &mode, qint64 atMs)
    {
        ScanAccessAttempt a;
        if (mode == QLatin1String("none"))
            return a;
        a.attempted = true;
        a.httpAnswered = mode == QLatin1String("answered");
        if (a.httpAnswered) {
            a.facts.asn = 64500;
            a.facts.netToken = QStringLiteral("net-access");
        }
        a.atMs = atMs;
        a.hasGen = true;
        a.gen = gen;
        return a;
    }

    void closeScan(Scan &s, qint64 now)
    {
        for (Probe &p : s.probes)
            if (p.launchAt >= 0 && !p.emitted)
                s.items << itemOf(s, p, ScanProbeError::Cancelled);
        if (s.close.attempted == false) {
            s.close = attempt(accessOpen, now - s.startAt);
            s.gate.finish(QStringLiteral("netinfo_close"), 2048);
        }
    }

    QByteArray progressOf(Scan &s, qint64 since, bool final)
    {
        ScanHostProgress p;
        p.scanId = s.id;
        for (const ScanProbeFacts &f : s.items)
            if (f.seq > since)
                p.items << f;
        p.seq = s.seq;
        bool allDone = true;
        for (const Probe &pr : s.probes)
            allDone = allDone && pr.emitted;
        p.phase = s.items.isEmpty() ? QStringLiteral("reach") : QStringLiteral("data");
        p.bytesSpent = s.gate.spent();
        p.bytesReserved = s.gate.reserved();
        p.access = s.open;
        if (final) {
            p.done = true;
            p.finalTotals = true;
            p.phase = QStringLiteral("done");
            p.reason = s.deadlineHit ? QStringLiteral("deadline") : QStringLiteral("cancelled");
            p.accessClose = s.close;
            p.bytesReserved = 0;
            s.ended = true;
            finals[s.id] << p.bytesSpent;
        } else if (allDone && !s.probes.isEmpty()) {
            p.done = true;
            p.reason = QStringLiteral("complete");
        }
        if (progressGen) {
            p.hasGen = true;
            p.gen = gen;
        }
        return scanCompact(scanEncodeProgress(p));
    }

    QByteArray handle(const QByteArray &request)
    {
        const qint64 now = ev->clock->t;
        ScanHostRequest r;
        QString detail;
        const ScanHostError e = scanDecodeRequest(request, r, &detail);
        if (loseScansAt >= 0 && now >= loseScansAt) {
            scans.clear();
            current.clear();
        }
        if (e == ScanHostError::UnknownAction)
            return R"({"error":"unknown_action"})";
        if (e != ScanHostError::None)
            return R"({"error":"bad_request","detail":"decode"})";
        switch (r.action) {
        case ScanHostAction::Caps: {
            QStringList kinds;
            if (real.maxFullConcurrent > 0) kinds << QStringLiteral("xray_full");
            if (real.maxLegConcurrent > 0) kinds << QStringLiteral("xray_leg");
            if (real.maxAwgConcurrent > 0) kinds << QStringLiteral("awg_mini");
            QJsonObject cr = scanEncodeCapsReply(real, kinds);
            if (awgWithheld)
                cr.insert(QLatin1String(kScanCapsAwgWithheldField), QStringLiteral("awg_live_peer_unknown"));
            if (capsGen)
                cr.insert(QStringLiteral("gen"), scanNetSourceToJson(gen));
            return scanCompact(cr);
        }
        case ScanHostAction::Start: {
            if (!startNotNow.isEmpty())
                return startNotNow.takeFirst();
            bool hasAwg = false;
            for (const ScanHostCandidate &c : r.start.candidates)
                hasAwg = hasAwg || c.kind == ScanProbeKind::AwgMini;
            if ((awgLivePeerUnknown == 1 && hasAwg) || awgLivePeerUnknown == 2)
                return QByteArrayLiteral("{\"error\":\"internal\",\"detail\":\"awg_live_peer_unknown\"}");
            if (!refuseStart.isEmpty())
                return scanCompact(refuseDetail.isEmpty() ? QJsonObject{{"error", refuseStart}}
                                                          : QJsonObject{{"error", refuseStart}, {"detail", refuseDetail}});
            Scan s;
            s.id = r.start.scanId;
            s.token = r.start.token;
            s.startAt = now;
            s.deadline = r.start.deadlineMs;
            s.bytes = r.start.bytes;
            s.gate = ScanHostByteGate(r.start.maxBytes);
            if (accessOpen != QLatin1String("none") && s.gate.admit(QStringLiteral("netinfo_open"), r.start.limits.netinfoCostBytes)) {
                s.gate.finish(QStringLiteral("netinfo_open"), 2048);
                s.open = attempt(accessOpen, 0);
            }
            s.gate.admit(QStringLiteral("netinfo_close"), r.start.limits.netinfoCostBytes);
            for (const ScanHostCandidate &c : r.start.candidates)
                s.probes << Probe{c};
            if (!current.isEmpty() && scans.contains(current)) {
                if (replaceForgets) { // the engine: the running scan ends as cancelled and is no longer known
                    Scan &old = scans[current];
                    advance(old, now);
                    closeScan(old, now);
                    endSpent.insert(old.id, old.gate.spent());
                    scans.remove(current);
                } else {
                    scans[current].cancelled = true;
                }
            }
            taken.insert(s.id);
            current = s.id;
            scans.insert(s.id, s);
            launch(scans[s.id], now);
            return scanCompact(scanEncodeAck(s.id, r.start.candidates.size(), 30));
        }
        case ScanHostAction::Add: {
            if (!addNotNow.isEmpty())
                return addNotNow.takeFirst();
            if (!scans.contains(r.start.scanId))
                return scanCompact(QJsonObject{{"error", "unknown_scan"}, {"scan_id", r.start.scanId}});
            for (const ScanHostCandidate &c : r.candidates)
                if (awgLivePeerUnknown && c.kind == ScanProbeKind::AwgMini)
                    return QByteArrayLiteral("{\"error\":\"internal\",\"detail\":\"awg_live_peer_unknown\"}");
            Scan &s = scans[r.start.scanId];
            for (const ScanHostCandidate &c : r.candidates)
                s.probes << Probe{c};
            launch(s, now);
            return scanCompact(scanEncodeAck(s.id, r.candidates.size(), 30));
        }
        case ScanHostAction::Poll: {
            if (!pollReplyOnce.isEmpty()) {
                const QByteArray once = pollReplyOnce;
                pollReplyOnce.clear();
                return once;
            }
            if (!scans.contains(r.start.scanId))
                return scanCompact(QJsonObject{{"error", "unknown_scan"}, {"scan_id", r.start.scanId}});
            Scan &s = scans[r.start.scanId];
            advance(s, now);
            const bool final = (s.cancelled && cancel == Cancel::FinalInPoll) || s.deadlineHit || s.ended;
            if (final && !s.ended)
                closeScan(s, now);
            if (s.cancelled && cancel == Cancel::NoFinal && !s.deadlineHit)
                return progressOf(s, r.since, false);
            return progressOf(s, r.since, final);
        }
        case ScanHostAction::Freeze: {
            if (!scans.contains(r.start.scanId))
                return scanCompact(QJsonObject{{"error", "unknown_scan"}, {"scan_id", r.start.scanId}});
            if (freeze == Freeze::NoAck)
                return QByteArray();
            Scan &s = scans[r.start.scanId];
            advance(s, now);
            s.gate.freeze();
            freezeBounds[s.id] << s.gate.spent() + s.gate.reserved();
            return scanCompact(scanEncodeFreezeAck(s.id, s.gate.spent(), s.gate.reserved()));
        }
        case ScanHostAction::Cancel: {
            if (!scans.contains(r.start.scanId))
                return scanCompact(QJsonObject{{"error", "unknown_scan"}, {"scan_id", r.start.scanId}});
            Scan &s = scans[r.start.scanId];
            advance(s, now);
            s.cancelled = true;
            if (cancel == Cancel::FinalInAck) {
                closeScan(s, now);
                s.ended = true;
                finals[s.id] << s.gate.spent();
                return scanCompact(scanEncodeCancelAck(s.id, s.gate.spent(), 30));
            }
            return scanCompact(scanEncodeAck(s.id, 0, 30));
        }
        }
        return R"({"error":"internal"})";
    }
    int count(const char *action) const { return actions.count(QLatin1String(action)); }
    const QJsonObject *lastRequest(const char *action) const
    {
        for (int i = requests.size() - 1; i >= 0; --i)
            if (requests.at(i).value("action").toString() == QLatin1String(action))
                return &requests.at(i);
        return nullptr;
    }
};

// --- the world ---------------------------------------------------------------------------------------------------
static ScanHostCaps capsMac()
{
    ScanHostCaps c;
    c.maxFullConcurrent = 2;
    c.canVerifyComposite = true;
    c.maxLegConcurrent = 6;
    c.dnsPlan = true;
    c.maxAwgConcurrent = 0;
    c.needsVpn = false;
    c.platform = QStringLiteral("macos");
    return c;
}

static ScanHostCaps capsIos()
{
    ScanHostCaps c;
    c.maxFullConcurrent = 1;
    c.canVerifyComposite = false;
    c.maxLegConcurrent = 4;
    c.dnsPlan = true;
    c.maxAwgConcurrent = 0;
    c.needsVpn = true;
    c.platform = QStringLiteral("ios");
    return c;
}

static const QStringList kPids = {QStringLiteral("a1a1a1a1a1a1a1a1"), QStringLiteral("b2b2b2b2b2b2b2b2"), QStringLiteral("c3c3c3c3c3c3c3c3")};

struct FakeResolver : IScanResolver {
    Events *ev = nullptr;
    QHash<QString, QStringList> answers; // absent host = never answers
    int delayMs = 100;
    QStringList asked;
    void lookup(const QString &host, std::function<void(const QStringList &)> done) override
    {
        asked << host;
        if (!answers.contains(host))
            return;
        const QStringList ips = answers.value(host);
        ev->at(delayMs, [done, ips]() { done(ips); });
    }
};

struct World {
    FakeClock clock;
    FakeResolver resolver;
    QMap<QString, bool> flags;
    FakeTimer timer;
    MemStore store;
    Events ev;
    FakeEngine engine;
    Server server;
    FakeHttp http;
    FakeHost host;
    std::unique_ptr<TribeScanner> s;
    QStringList logs;
    QList<UpstreamLeaseClient::ProbeRequest> liveProbes;
    bool liveWorks = true;
    bool liveBadDigest = false; // the body arrives in full but is not the one the nonce defines
    QList<QPair<int, bool>> liveScript; // per runner call (warm, data, ...): {delay ms, bad digest}; empty = 120 ms, liveBadDigest
    QList<QPair<QString, qint64>> charges; // the coordinator's own host charges (onHostCharge): host scan id, bytes
    int crossEvents = 0;                // machine events a host answer caused for ANOTHER scan than its own (must stay 0)
    bool poolOnOpen = false;
    QStringList hostEvents;             // "event scan" of every machine event caused by a host answer / held message

    explicit World(const ScanHostCaps &caps = capsMac(), ScanNetKind kind = ScanNetKind::Wifi, int ownNodes = 8)
    {
        timer.clock = &clock;
        ev.clock = &clock;
        resolver.ev = &ev;
        // the engine knows the probe base's address (the resolved active API base): no resolution wait
        engine.knownIps.insert(QStringLiteral("tunnel.leakhost.example"), {QStringLiteral("192.0.2.10")});
        engine.ev = &ev;
        http.ev = &ev;
        http.server = &server;
        host.ev = &ev;
        host.known = caps;
        host.real = caps;
        engine.net.kind = kind;
        engine.net.reportingKey = kind == ScanNetKind::Cellular ? QStringLiteral("cell:250-02:4g") : QStringLiteral("wifi");
        engine.net.appSources = {ScanNetSource{QStringLiteral("app"), 0xa1a1a1a1a1a1a1a1ULL, 1}};
        for (int i = 0; i < ownNodes; ++i) {
            const QString id = QStringLiteral("%1:xray").arg(4 + i);
            ScanOwnNode n;
            n.nodeId = id;
            n.label = QStringLiteral("Node %1").arg(4 + i);
            n.countryCode = i % 2 ? QStringLiteral("NL") : QStringLiteral("DE");
            n.transport = ScanTransport::Xray;
            n.entryIp = QStringLiteral("198.51.100.%1").arg(10 + i);
            n.transportVersion = QStringLiteral("v-%1").arg(4 + i); // the node pool's version (the row chip)
            n.entryPort = 443;
            engine.own << n;
            server.nodes << QJsonObject{{"node_id", id}, {"tier", 0}, {"rank", i}, {"crowd_works", false}};
            host.outcomes.insert(id, Outcome{true, 50 + 10 * i, 350 + 40 * i});
        }
        for (int i = 0; i < kPids.size(); ++i) {
            const QString pid = kPids.at(i);
            const QString addr = i == 0 ? QString::fromLatin1(kProviderIp) : QString::fromLatin1(kProviderHost);
            const QJsonObject leg{{"tag", "proxy"}, {"protocol", "vless"},
                                  {"outbound", QJsonObject{{"protocol", "vless"}, {"settings", QJsonObject{{"vnext", QJsonArray{QJsonObject{{"address", addr}, {"port", 443}}}}}}}},
                                  {"dialer", QJsonValue::Null}, {"standalone", true}};
            const QJsonObject route{{"route", "leg"}, {"leg", "proxy"}};
            const QJsonObject projection{{"version", 1}, {"legs", QJsonArray{leg}},
                                         {"catch_all", QJsonObject{{"tcp", route}, {"udp", route}}},
                                         {"dns", QJsonArray{QJsonObject{{"address", "1.1.1.1"}, {"tag", QJsonValue::Null}, {"transport", "udp"}, {"route", "leg"}, {"leg", "proxy"}}}}};
            server.upstream << QJsonObject{{"profile_id", pid}, {"label", QStringLiteral("Provider %1").arg(i + 1)}, {"ordinal", 1},
                                           {"label_custom", false}, {"country_code", "FI"}, {"tier", 1}, {"rank", i}, {"crowd_works", false},
                                           {"priority", 0}, {"probe_class", "single"}, {"config_sha256", QString(64, QLatin1Char('a'))},
                                           {"protocols", QJsonArray{"proto:vless"}}, {"trimmed", false}, {"legs_total", 1},
                                           {"projection", projection}};
            host.outcomes.insert(QStringLiteral("up:") + pid, Outcome{true, 70 + 10 * i, 500});
        }
    }

    void start()
    {
        QMap<QString, bool> f = flags;
        f.insert(QStringLiteral("scanner"), true);
        TuningStore::set({}, f);
        TribeScanner::Deps d;
        d.resolver = &resolver;
        d.engine = &engine;
        d.host = &host;
        d.http = &http;
        d.store = &store;
        d.clock = &clock;
        d.timer = &timer;
        d.fetchPoolOnOpen = poolOnOpen; // byte-exact cases count every request of the scan; the 1.14.0 case asks the pool
        s = std::make_unique<TribeScanner>(d);
        s->log = [this](const QString &l) { logs << l; };
        s->onHostCharge = [this](const QString &id, qint64 bytes) { charges << qMakePair(id, bytes); };
        s->onHostEvent = [this](const char *event, const QString &scan) {
            hostEvents << QString::fromLatin1(event) + QLatin1Char(' ') + scan;
            if (!host.replyingFor.isEmpty() && scan != host.replyingFor) {
                ++crossEvents; // (a): an answer of one scan moved another scan's state
                std::fprintf(stderr, "CROSS %s: answer of %s acted on %s\n", event, qPrintable(host.replyingFor), qPrintable(scan));
            }
        };
        s->api()->log = [this](const QString &l) { logs << QStringLiteral("api ") + l; };
        s->configureApi(nullptr, []() { return QString::fromLatin1(kApiBase); }, [this]() { return server.key.pubHex(); },
                        []() { return QString::fromLatin1(kDeviceToken); });
        s->api()->setProbeRunner([this](const UpstreamLeaseClient::ProbeRequest &r, std::function<void(const UpstreamProbeFacts &)> done) {
            liveProbes << r;
            int delay = 120;
            bool bad = liveBadDigest;
            if (!liveScript.isEmpty()) {
                delay = liveScript.first().first;
                bad = liveScript.first().second;
                liveScript.removeFirst();
            }
            UpstreamProbeFacts f;
            f.bytesRequested = r.bytes;
            f.nonce = r.nonce;
            f.httpStatus = liveWorks ? 200 : 502;
            f.bytesReceived = liveWorks ? r.bytes : 0;
            f.bodySha256Hex = liveWorks ? tribeProbeExpectedSha256Hex(bad ? QByteArray("other-nonce") : r.nonce, r.bytes) : QByteArray();
            f.wireBytes = f.bytesReceived + 400;
            f.ttfbMs = 90;
            f.elapsedMs = 160;
            f.maxStallMs = 0;
            f.egressClass = QStringLiteral("tribe-node");
            f.egressNode = scanHostPartOf(engine.cur.nodeId);
            f.egressAsnHeader = QStringLiteral("unknown");
            ev.at(delay, [done, f]() { done(f); });
        });
    }

    void liveOn(const QString &nodeId, bool working = true)
    {
        engine.cur = ScanCurrent();
        engine.cur.nodeId = nodeId;
        engine.cur.live = true;
        engine.cur.dataFlowing = working;
        engine.cur.connecting = !working;
        engine.cur.liveRttMs = 45;
        engine.cur.origin = nodeId.startsWith(QLatin1String("up:")) ? ScanOrigin::Upstream : ScanOrigin::Own;
        engine.cur.label = QStringLiteral("Live");
        engine.cur.countryCode = QStringLiteral("DE");
        engine.cur.transport = ScanTransport::Xray;
        engine.cur.transportVersion = QStringLiteral("v-live");
    }

    // Advance the fake clock to `until`, delivering every reply and firing the one timer when it is due.
    void runUntil(qint64 until)
    {
        for (int guard = 0; guard < 200000; ++guard) {
            QCoreApplication::processEvents();
            qint64 next = -1;
            if (!ev.q.isEmpty())
                next = ev.q.firstKey();
            if (timer.due >= 0 && (next < 0 || timer.due < next))
                next = timer.due;
            if (next < 0 || next > until) {
                clock.t = qMax(clock.t, until);
                QCoreApplication::processEvents();
                return;
            }
            clock.t = qMax(clock.t, next);
            if (!ev.q.isEmpty() && ev.q.firstKey() <= clock.t) {
                auto f = ev.q.first();
                ev.q.erase(ev.q.begin());
                f();
                continue;
            }
            if (timer.due >= 0 && timer.due <= clock.t) {
                timer.due = -1;
                s->timerFired();
            }
        }
        CHECK(!"event loop runaway");
        // An unbounded wait (a timer re-armed for ever) is a broken rule: the remaining worlds would each spin to the
        // guard too - stop here with the failure.
        std::fprintf(stderr, "scanner_facade_check: event loop runaway in [%s], stopping\n", qPrintable(g_case));
        std::exit(1);
    }
    void run(qint64 ms) { runUntil(clock.t + ms); }

    QString phase() const { return s->view().value(QStringLiteral("phase")).toString(); }
    QVariantList rows() const { return s->view().value(QStringLiteral("rows")).toList(); }
    QVariantMap row(const QString &id) const
    {
        for (const QVariant &v : rows())
            if (v.toMap().value("id").toString() == id)
                return v.toMap();
        return QVariantMap();
    }
    bool rowFlag(const QString &id, const char *flag) const { return row(id).value("flags").toStringList().contains(QLatin1String(flag)); }
    // the live row stays unproven after its check ended badly: not verified, and no longer «проверяем загрузку…»
    bool liveUnprovenSettled(const QString &id) const
    {
        bool unproven = false;
        for (const ScanRowView &r : s->machine().view(clock.t).rows)
            if (r.id == id)
                unproven = r.current && !r.verified;
        return unproven && rowFlag(id, "current") && !rowFlag(id, "live_unverified");
    }
    qint64 ledgerLast() const
    {
        const auto &e = s->machine().ledger().entries();
        return e.isEmpty() ? 0 : e.last().bytes;
    }
    int ledgerCount() const { return s->machine().ledger().entries().size(); }
    int ledgerEntriesOf(qint64 bytes) const
    {
        int n = 0;
        for (const ScanLedgerEntry &e : s->machine().ledger().entries())
            n += e.bytes == bytes ? 1 : 0;
        return n;
    }
    qint64 ledgerSum(int cellular = -1) const // -1 = all; 0 / 1 = only Wi-Fi / cellular entries
    {
        qint64 n = 0;
        for (const ScanLedgerEntry &e : s->machine().ledger().entries())
            if (cellular < 0 || e.cellular == (cellular == 1))
                n += e.bytes;
        return n;
    }
    // The coordinator's own charges of one host scan (settleRecord), in order.
    QList<qint64> chargesOf(const QString &scan) const
    {
        QList<qint64> out;
        for (const auto &c : charges)
            if (c.first == scan)
                out << c.second;
        return out;
    }
    qint64 grantOf(const QString &scan) const
    {
        for (int i = host.requests.size() - 1; i >= 0; --i)
            if (host.requests.at(i).value("action").toString() == QLatin1String("scan_start")
                && host.requests.at(i).value("scan_id").toString() == scan)
                return qint64(host.requests.at(i).value("max_bytes").toDouble(-1));
        return -1;
    }
    int sentFor(const char *action, const QString &scan) const
    {
        int n = 0;
        for (const QJsonObject &r : host.requests)
            n += r.value("action").toString() == QLatin1String(action) && r.value("scan_id").toString() == scan ? 1 : 0;
        return n;
    }
    bool logsClean() const
    {
        for (const QString &l : logs)
            for (const QString &m : kLeakMarkers)
                if (l.contains(m)) {
                    std::fprintf(stderr, "LEAK in log line: marker %s\n", qPrintable(m));
                    return false;
                }
        return true;
    }
};

// --- cases -------------------------------------------------------------------------------------------------------

// A full scan end to end: manifest (signed 200, stored with its ETag), caps, the host scan, the seats, the
// live-tunnel proof, the stop (freeze, cancel, final), outcomes, cache, ledger.
static void caseFullScan()
{
    g_case = QStringLiteral("full_scan");
    World w;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    CHECK_EQ(w.phase(), QStringLiteral("preparing"));
    w.run(20000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 1);
    CHECK(w.host.count("scan_caps") >= 1);
    CHECK_EQ(w.host.count("scan_start"), 1);
    const QJsonObject *st = w.host.lastRequest("scan_start");
    CHECK(st && st->value("probe").toObject().value("token").toString().startsWith(QLatin1String("tsc1.MANIFEST-TOKEN")));
    CHECK(st && st->value("probe").toObject().value("base").toString() == QLatin1String(kTunnelBase));
    // own candidates carry the engine's config, a provider leg its projection's outbound
    bool ownCfg = false;
    if (st)
        for (const QJsonValue &v : st->value("candidates").toArray())
            ownCfg = ownCfg || v.toObject().value("config").toString().startsWith(QLatin1String("OWN-CONFIG-"));
    CHECK(ownCfg);
    const QJsonObject *add = w.host.lastRequest("scan_add");
    CHECK(add != nullptr);
    if (add) {
        bool legCfg = false;
        for (const QJsonValue &v : add->value("candidates").toArray())
            legCfg = legCfg || v.toObject().value("config").toString().contains(QLatin1String("\"outbound\""));
        CHECK(legCfg);
    }
    CHECK_EQ(w.http.count("/v1/upstream/lease/probe-batch"), 1);
    // stop protocol: freeze first, then the cancel, then the final through a poll
    const int fi = w.host.actions.indexOf(QStringLiteral("scan_freeze"));
    const int ci = w.host.actions.indexOf(QStringLiteral("scan_cancel"));
    CHECK(fi >= 0 && ci > fi);
    CHECK(!w.s->machine().draining());
    CHECK_EQ(w.s->pollsActive(), 0);
    // rows: own rows works, the live row proven by the tunnel probe, providers verified with this scan's access
    CHECK(w.s->view().value("verified").toInt() >= 10);
    CHECK_EQ(w.row(QStringLiteral("4:xray")).value("state").toString(), QStringLiteral("connected"));
    CHECK(w.rowFlag(QStringLiteral("4:xray"), "current"));
    CHECK(!w.rowFlag(QStringLiteral("4:xray"), "live_unverified")); // proven by the live-tunnel probe
    CHECK_EQ(w.liveProbes.size(), 2); // warm + data on one connection
    CHECK(w.liveProbes.size() == 2 && w.liveProbes.at(0).scanToken == st->value("probe").toObject().value("token").toString());
    // seats released with their lease ids, outcomes sent, cache + ledger persisted
    CHECK(!w.server.releasedLeases.isEmpty());
    CHECK(w.server.outcomeItems > 0);
    CHECK(w.store.m.contains(QLatin1String(kScanBudgetStoreKey)));
    CHECK(w.store.m.contains(scanCacheStoreKey(QStringLiteral("wifi"), w.s->lastNetwork().fingerprint)));
    CHECK_EQ(w.engine.userConnects, 0);
    CHECK_EQ(w.engine.cancels, 0);
    CHECK(w.engine.rowCalls.isEmpty());
    // the one allowance: the ledger entry = every app request's real bytes + the host's final total
    qint64 hostFinal = 0;
    for (const FakeHost::Scan &sc : w.host.scans)
        hostFinal += sc.gate.spent();
    const qint64 live = kLiveSpent;
    CHECK_EQ(w.ledgerLast(), w.http.totalBytes + hostFinal + live);
    CHECK(w.logsClean());
}

// Owner's iPhone 16.11 (build 140): the Scanner probed provider profiles the connect then refused. A full-profile
// probe now passes the connect's own profile check first (XrayProfileSanitizer.h::upstreamProfileCheck): a profile
// with helper outbounds (freedom / blackhole) is probed as delivered; a profile the connect would refuse never
// reaches the host and its row is not «works». Synthetic normalized profiles (documentation addresses only).
static QByteArray syntheticProfile(bool forbiddenSection)
{
    QByteArray p = R"({)";
    if (forbiddenSection)
        p += R"("api":{"tag":"api"},)";
    p += R"("inbounds":[{"listen":"127.0.0.1","port":"__TRIBE_SOCKS_PORT__","protocol":"socks",)"
         R"("settings":{"accounts":[{"pass":"__TRIBE_SOCKS_PASS__","user":"__TRIBE_SOCKS_USER__"}],"auth":"password","udp":true},)"
         R"("tag":"tribe-in"}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"192.0.2.31","port":443,)"
         R"("users":[{"encryption":"none","id":"11111111-2222-4333-8444-555555555555"}]}]},"tag":"proxy"},)"
         R"({"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}],)"
         R"("providerExtra":{"marker":"SECRET-PROVIDER-CONFIG"},)"
         R"("routing":{"rules":[{"ip":["geoip:private"],"outboundTag":"direct"},{"network":"tcp,udp","outboundTag":"proxy"}]}})";
    return p;
}

static void caseFullProbeProfileRule()
{
    g_case = QStringLiteral("full_probe_profile_rule");
    World w;
    // Two composite profiles: full probes on Wi-Fi with the config in the grant.
    for (int i = 0; i < 2; ++i) {
        QJsonObject u = w.server.upstream.at(i).toObject();
        u.insert("probe_class", "composite");
        w.server.upstream[i] = u;
    }
    w.server.configs.insert(kPids.at(0), syntheticProfile(false));
    w.server.configs.insert(kPids.at(1), syntheticProfile(true));
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(20000);
    QStringList sentConfigs;
    for (const QJsonObject &rq : w.host.requests)
        if (rq.value("action").toString() == QLatin1String("scan_start") || rq.value("action").toString() == QLatin1String("scan_add"))
            for (const QJsonValue &v : rq.value("candidates").toArray())
                if (v.toObject().value("profile_id").toString() == kPids.at(0)
                    || v.toObject().value("profile_id").toString() == kPids.at(1))
                    sentConfigs << v.toObject().value("profile_id").toString() + QLatin1Char('|')
                                       + v.toObject().value("kind").toString() + QLatin1Char('|')
                                       + v.toObject().value("config").toString();
    bool fullA = false, anyB = false;
    for (const QString &c : sentConfigs) {
        fullA = fullA || (c.startsWith(kPids.at(0) + QLatin1String("|xray_full|"))
                          && c.endsWith(QString::fromUtf8(syntheticProfile(false))));
        anyB = anyB || (c.startsWith(kPids.at(1) + QLatin1String("|xray_full|")));
    }
    CHECK(fullA); // the profile with freedom / blackhole outbounds: probed as delivered
    CHECK(!anyB); // the one the connect would refuse: never probed in full
    CHECK(w.row(QStringLiteral("up:") + kPids.at(1)).value("state").toString() != QLatin1String("works"));
    bool refusedLogged = false;
    for (const QString &l : w.logs)
        refusedLogged = refusedLogged || l.contains(QLatin1String("probe_profile_refused code=profile_forbidden_section"));
    CHECK(refusedLogged);
    CHECK(w.logsClean());
}

// The live row is proven only by the digest the device computes itself: a full body with another digest
// leaves it «Подключено», unproven, not counted.
static void caseLiveDigest()
{
    g_case = QStringLiteral("live_bad_digest");
    World w;
    w.liveBadDigest = true;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    CHECK_EQ(w.liveProbes.size(), 2);
    CHECK(w.liveUnprovenSettled(QStringLiteral("4:xray")));
}

// 304: the stored copy is revalidated with its exact ETag; the scan uses the token of POST /v1/scan/token.
// A token grant with a newer revision refetches without If-None-Match.
static void caseManifest304()
{
    g_case = QStringLiteral("manifest_304");
    World w;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    w.s->close();
    w.run(31000);
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 2);
    const FakeHttp::Sent m = w.http.last("/v1/scan/manifest");
    QByteArray inm;
    for (const auto &h : m.req.headers)
        if (h.first == "If-None-Match")
            inm = h.second;
    CHECK_EQ(inm, w.server.etag);
    CHECK_EQ(m.resp.status, 304);
    CHECK_EQ(w.http.count("/v1/scan/token"), 1);
    const QJsonObject *st = w.host.lastRequest("scan_start");
    CHECK(st && st->value("probe").toObject().value("token").toString().startsWith(QLatin1String("tsc1.POST-TOKEN")));
    CHECK_EQ(w.host.count("scan_start"), 2);
    // the manifest request id got the real bytes of the 304 + the token (ledger = every real byte)
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    // a newer revision in the token grant: the stored copy is dropped, the manifest refetched unconditionally
    w.server.tokenRevision = 9;
    w.server.revision = 9;
    w.s->close();
    w.run(31000);
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 4);
    const FakeHttp::Sent m2 = w.http.last("/v1/scan/manifest");
    bool cond = false;
    for (const auto &h : m2.req.headers)
        cond = cond || h.first == "If-None-Match";
    CHECK(!cond && m2.resp.status == 200);
    CHECK(w.logsClean());
}

// A manifest whose signature fails is never used or stored: NoScan "manifest_invalid", no host scan.
static void caseManifestSignature()
{
    g_case = QStringLiteral("manifest_signature");
    World w;
    w.server.badManifestSig = true;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(5000);
    CHECK_EQ(w.phase(), QStringLiteral("no_scan"));
    CHECK_EQ(w.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("manifest_invalid"));
    CHECK_EQ(w.host.count("scan_start"), 0);
    CHECK(!w.store.m.contains(scanManifestStoreKey(QStringLiteral("wifi"))));
    CHECK(w.logsClean());
}

// probe-batch: one granted, one no_seat («Не проверено»), one disabled (dropped); only the grant is probed
// and released; a batch with a bad signature grants nothing.
static void caseBatchPartial()
{
    g_case = QStringLiteral("batch_partial");
    World w(capsMac(), ScanNetKind::Wifi, 6);
    w.server.refuse.insert(kPids.at(1), QStringLiteral("no_seat"));
    w.server.refuse.insert(kPids.at(2), QStringLiteral("disabled"));
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    const QString up0 = QStringLiteral("up:") + kPids.at(0);
    const QString up1 = QStringLiteral("up:") + kPids.at(1);
    const QString up2 = QStringLiteral("up:") + kPids.at(2);
    CHECK_EQ(w.row(up0).value("state").toString(), QStringLiteral("works"));
    CHECK(w.rowFlag(up1, "unverified"));
    CHECK(w.row(up2).isEmpty());
    CHECK_EQ(w.server.releasedLeases.size(), 1);
    CHECK(w.server.releasedLeases.size() == 1 && w.server.releasedLeases.first().startsWith(QLatin1String("LEASEID")));
    bool addedOther = false;
    for (const QJsonObject &r : w.host.requests)
        if (r.value("action").toString() == QLatin1String("scan_add"))
            for (const QJsonValue &v : r.value("candidates").toArray())
                addedOther = addedOther || v.toObject().value("id").toString() != up0;
    CHECK(!addedOther);

    g_case = QStringLiteral("batch_bad_signature");
    World b(capsMac(), ScanNetKind::Wifi, 6);
    b.server.badBatchSig = true;
    b.liveOn(QStringLiteral("4:xray"));
    b.start();
    b.s->open();
    b.run(20000);
    CHECK_EQ(b.host.count("scan_add"), 0);
    CHECK(b.rowFlag(up0, "unverified"));
    // an unverified answer grants nothing; the seats the server did grant are released by the operation id at once
    CHECK_EQ(b.server.releasedOps.size(), 1);
    CHECK(b.server.releasedLeases == b.server.opLeases.value(b.server.releasedOps.value(0)) && b.server.releasedLeases.size() == 3);
}

// Cellular: the app slice is reserved first; the host's grant = the allowance minus the app slice; every app
// request carries its reservation as its cut, and an answer past it is cut (a transport failure).
static void caseCellularBudget()
{
    g_case = QStringLiteral("cellular_budget");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    w.liveOn(QStringLiteral("4:xray"));
    w.server.batchPad = 20000; // the probe-batch answer passes its 12 KiB reservation
    w.start();
    w.s->open();
    w.run(150);
    const ScanTunables t = w.s->machine().tunables();
    const FakeHttp::Sent m = w.http.last("/v1/scan/manifest");
    CHECK_EQ(m.req.maxBytes, qint64(t.costManifestBytes) + t.costApiBytes);
    w.run(20000);
    const QJsonObject *st = w.host.lastRequest("scan_start");
    CHECK(st != nullptr);
    const qint64 grant = st ? qint64(st->value("max_bytes").toDouble(-1)) : -1;
    const qint64 a = t.budgetScanBytes; // a fresh hour: A = scan_budget_scan_bytes
    const qint64 slice = m.resp.bytes + t.costTunnelProbeBytes + t.costOutcomesBytes
                         + t.costBatchBytes + t.costApiBytes;
    CHECK_EQ(grant, a - slice);

    const FakeHttp::Sent b = w.http.last("/v1/upstream/lease/probe-batch");
    CHECK_EQ(b.req.maxBytes, qint64(t.costBatchBytes));
    CHECK(b.resp.cut && b.resp.bytes == t.costBatchBytes);
    // the cut batch = a transport failure: providers «Не проверено», never probed
    CHECK(w.rowFlag(QStringLiteral("up:") + kPids.at(0), "unverified"));
    CHECK_EQ(w.host.count("scan_add"), 0);
    const FakeHttp::Sent o = w.http.last("/v1/telemetry/path-outcomes");
    CHECK_EQ(o.req.maxBytes, qint64(t.costOutcomesBytes));
    // the ledger never passes the allowance and equals the real bytes
    CHECK(w.ledgerLast() <= a);
    qint64 hostFinal = 0;
    for (const FakeHost::Scan &sc : w.host.scans)
        hostFinal += sc.gate.spent();
    qint64 live = kLiveSpent;
    // the cut batch's seats are released by its operation id at once: that request is charged outside the scan
    qint64 outside = 0;
    for (const FakeHttp::Sent &x : w.http.sent)
        if (QUrl(x.req.url).path() == QLatin1String("/v1/upstream/lease/probe-batch/release") && x.req.body.contains("operation_id"))
            outside += x.resp.bytes;
    CHECK(outside > 0 && w.server.releasedOps.size() == 1 && w.ledgerEntriesOf(outside) == 1);
    CHECK_EQ(w.ledgerLast(), w.http.totalBytes - outside + hostFinal + live);
    CHECK(w.logsClean());
}

// Stop -> freeze -> drain: the three charges of the host share (final total; ack spent + reserved; the whole
// grant), plus the final total carried by the cancel ack.
static qint64 drainCase(FakeHost::Freeze fz, FakeHost::Cancel cn, qint64 *grantOut, qint64 *ackOut, qint64 *finalOut,
                        qint64 *appOut, bool *pollsDuringDrain)
{
    World w(capsMac(), ScanNetKind::Cellular, 8);
    w.server.latency = 2; // every app answer is in before the host settles (else it is charged at its worst case)
    w.host.freeze = fz;
    w.host.cancel = cn;
    for (int i = 0; i < 8; ++i)
        w.host.outcomes[QStringLiteral("%1:xray").arg(4 + i)].durMs = 2500 + 100 * i; // still in flight at the stop
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(1500);
    CHECK(w.phase() == QStringLiteral("reach") || w.phase() == QStringLiteral("data"));
    const int pollsBefore = w.host.count("scan_poll");
    w.s->stop(); // «Остановить»: the scan stops, the screen closes, the VPN stays as it is
    const qint64 ackSnapshotAt = w.clock.t;
    Q_UNUSED(ackSnapshotAt);
    w.run(800);
    *pollsDuringDrain = w.host.count("scan_poll") > pollsBefore;
    w.run(15000);
    CHECK(!w.s->machine().draining());
    const QJsonObject *st = w.host.lastRequest("scan_start");
    *grantOut = st ? qint64(st->value("max_bytes").toDouble(-1)) : -1;
    qint64 ack = 0, fin = 0;
    for (const FakeHost::Scan &sc : w.host.scans)
        fin += sc.gate.spent();
    *ackOut = ack;
    *finalOut = fin;
    const ScanTunables t = w.s->machine().tunables();
    qint64 live = kLiveSpent;
    *appOut = w.http.totalBytes + live;
    CHECK_EQ(w.engine.cancels, 0);
    CHECK_EQ(w.engine.userConnects, 0);
    return w.ledgerLast();
}

static void caseDrain()
{
    qint64 grant = 0, ack = 0, fin = 0, app = 0;
    bool polls = false;
    g_case = QStringLiteral("drain_final_in_poll");
    qint64 ledger = drainCase(FakeHost::Freeze::Ack, FakeHost::Cancel::FinalInPoll, &grant, &ack, &fin, &app, &polls);
    CHECK(polls); // the coordinator keeps polling while the machine drains
    CHECK_EQ(ledger, app + fin);
    CHECK(fin < grant);

    g_case = QStringLiteral("drain_final_in_ack");
    ledger = drainCase(FakeHost::Freeze::Ack, FakeHost::Cancel::FinalInAck, &grant, &ack, &fin, &app, &polls);
    CHECK_EQ(ledger, app + fin);

    g_case = QStringLiteral("drain_ack_no_final");
    {
        World w(capsMac(), ScanNetKind::Cellular, 8);
        w.server.latency = 2;
        w.host.cancel = FakeHost::Cancel::NoFinal;
        for (int i = 0; i < 8; ++i)
            w.host.outcomes[QStringLiteral("%1:xray").arg(4 + i)].durMs = 2500 + 100 * i;
        w.liveOn(QStringLiteral("4:xray"));
        w.start();
        w.s->open();
        w.run(1500);
        // the freeze ack's numbers, as the host computes them at that moment
        w.s->stop();
        w.run(6); // the freeze is answered (latency 5)
        qint64 spent = 0, reserved = 0;
        for (const FakeHost::Scan &sc : w.host.scans) {
            spent = sc.gate.spent();
            reserved = sc.gate.reserved();
        }
        w.run(15000);
        const ScanTunables t = w.s->machine().tunables();
        qint64 live = kLiveSpent;
        CHECK(!w.s->machine().draining());
        CHECK_EQ(w.ledgerLast(), w.http.totalBytes + live + spent + reserved);
    }

    g_case = QStringLiteral("drain_no_ack");
    ledger = drainCase(FakeHost::Freeze::NoAck, FakeHost::Cancel::FinalInPoll, &grant, &ack, &fin, &app, &polls);
    CHECK_EQ(ledger, app + grant);
}

// Network change mid-scan (the app's path monitor counts a change): the scan is cancelled and restarted on the
// new tuple; a host element that CHANGES is a network change too; a host element first seen inside a scan is
// folded in at the next open.
// Device round air9 (19.11, 10:08): back on Wi-Fi the Scanner adopted the network before its facts were complete;
// the facts then changed with the SAME generation (the engine published its key, the gateway became known) and the
// engine forwarded nothing, so the cached Germany result of that Wi-Fi never came back. The Scanner's own identity
// (kind, reporting key, fingerprint, generation - ScanNetwork) is the one judge of a change: every notice reaches it
// (AvpnEngineQml::scanNotifyNetwork: scanNetworkNoticeDue, facade_policy_check) and a key-only change with the same generation
// adopts that network and its cached result; a notice with nothing new changes nothing.
static void caseNetworkKeySameGeneration()
{
    g_case = QStringLiteral("network_key_same_generation");
    World w;
    w.engine.net.gatewayHash = QStringLiteral("a1b2c3d4e5f60718"); // the VPN off: no live row on any list
    w.start();
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    const ScanNetFacts wifi = w.engine.net;
    // cellular
    w.engine.net.kind = ScanNetKind::Cellular;
    w.engine.net.reportingKey = QStringLiteral("cell:250-02:4g");
    w.engine.net.gatewayHash.clear();
    w.engine.net.appSources[0].counter = 2;
    w.s->networkChanged();
    CHECK(w.s->view().value(QStringLiteral("rows")).toList().isEmpty());
    // back on Wi-Fi: the first notice comes before the gateway is known (another fingerprint: no cached result) ...
    w.engine.net = wifi;
    w.engine.net.gatewayHash.clear();
    w.engine.net.appSources[0].counter = 3;
    w.s->networkChanged();
    CHECK(w.s->view().value(QStringLiteral("rows")).toList().isEmpty());
    const QString gen = w.s->lastNetwork().generation();
    // ... then the facts complete with the same generation: the Scanner adopts them, the result comes back as cache
    w.engine.net.gatewayHash = wifi.gatewayHash;
    w.s->networkChanged();
    CHECK_EQ(w.s->lastNetwork().generation(), gen);
    CHECK_EQ(w.s->lastNetwork().fingerprint, scanNetFingerprint(QStringLiteral("wifi"), wifi.reportingKey, wifi.gatewayHash));
    const QVariantList rows = w.s->view().value(QStringLiteral("rows")).toList();
    CHECK(!rows.isEmpty() && rows.first().toMap().value(QStringLiteral("flags")).toStringList().contains(QStringLiteral("cache")));
    // a notice with nothing new: the same view, no scan
    const int starts = w.host.count("scan_start");
    const QVariant before = w.s->view().value(QStringLiteral("list_build"));
    w.s->networkChanged();
    CHECK(w.s->view().value(QStringLiteral("list_build")) == before && w.host.count("scan_start") == starts);
}

static void caseNetworkChange()
{
    g_case = QStringLiteral("network_change_app");
    World w;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(1200);
    CHECK(w.phase() == QStringLiteral("reach") || w.phase() == QStringLiteral("data"));
    const QString first = w.s->machine().scanId();
    const QString gen0 = w.s->lastNetwork().generation();
    w.engine.net.appSources[0].counter = 2;
    w.s->networkChanged();
    CHECK(w.s->lastNetwork().generation() != gen0);
    w.run(20000);
    CHECK_EQ(w.host.count("scan_start"), 2);
    CHECK(w.s->machine().scanId() != first);
    CHECK(w.host.count("scan_freeze") >= 1);
    CHECK_EQ(w.phase(), QStringLiteral("done"));

    g_case = QStringLiteral("network_change_host_gen");
    World h;
    h.host.genKnown = true; // the host gives its element before the scan: it is in the tuple from the open
    h.liveOn(QStringLiteral("4:xray"));
    h.start();
    h.s->open();
    h.run(1200);
    const ScanNetSource *in = scanNetSourceOf(h.s->lastNetwork().sources, QStringLiteral("service"));
    CHECK(in != nullptr);
    const QString hfirst = h.s->machine().scanId();
    h.host.gen.counter = 2; // the host's path monitor counted a change (scan_progress.gen)
    h.run(20000);
    CHECK(h.s->machine().scanId() != hfirst);
    CHECK_EQ(h.host.count("scan_start"), 2);

    g_case = QStringLiteral("host_gen_first_seen_in_scan");
    World f;
    f.liveOn(QStringLiteral("4:xray"));
    f.start();
    f.s->open();
    f.run(20000);
    CHECK_EQ(f.host.count("scan_start"), 1); // seen only inside scan_progress: no restart, never joins
    CHECK_EQ(f.phase(), QStringLiteral("done"));
    CHECK(scanNetSourceOf(f.s->lastNetwork().sources, QStringLiteral("service")) == nullptr);
    f.s->close();
    f.run(1000);
    f.s->open(); // inside the cooldown: the same tuple, the last result, no new scan (S6)
    f.run(500);
    CHECK(scanNetSourceOf(f.s->lastNetwork().sources, QStringLiteral("service")) == nullptr);
    CHECK_EQ(f.host.count("scan_start"), 1);
}

// Cooldown: reopening inside scan_manual_cooldown_s shows the last result and starts nothing; the countdown
// view is refreshed at its nextChangeAtMs without any event; after it «Повторить» scans again.
static void caseCooldown()
{
    g_case = QStringLiteral("cooldown");
    World w;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(12000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    w.s->close();
    w.run(1000);
    w.s->open();
    w.run(500);
    CHECK_EQ(w.host.count("scan_start"), 1);
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 1);
    CHECK_EQ(w.s->view().value("bar").toMap().value("button").toString(), QStringLiteral("retry_in_s"));
    CHECK(w.s->view().value("cooldown_ends_at_ms").toDouble() > double(w.clock.t));
    w.run(25000); // no event: the timer re-reads the view at its next change
    CHECK_EQ(w.s->view().value("bar").toMap().value("button").toString(), QStringLiteral("retry"));
    w.s->retry();
    w.run(15000);
    CHECK_EQ(w.host.count("scan_start"), 2);
}

// An abandoned manifest (a network change while Preparing asked again) still gets its real bytes; the live
// probe and the access evidence use the token of the manifest the scan really runs on.
static void caseAbandonedManifest()
{
    g_case = QStringLiteral("abandoned_manifest");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    w.liveOn(QStringLiteral("4:xray"));
    w.server.manifestLatency = 600; // the first answer comes after the second, while the scan still runs
    w.start();
    w.s->open();
    w.run(100);
    CHECK_EQ(w.phase(), QStringLiteral("preparing"));
    w.server.manifestLatency = 40;
    w.engine.net.appSources[0].counter = 2;
    w.s->networkChanged();
    w.run(20000);
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 2);
    CHECK_EQ(w.host.count("scan_start"), 1);
    const QJsonObject *st = w.host.lastRequest("scan_start");
    const QString token = st ? st->value("probe").toObject().value("token").toString() : QString();
    CHECK(!token.isEmpty());
    for (const auto &p : w.liveProbes)
        CHECK_EQ(p.scanToken, token);
    // the scan's ledger entry = every real byte: the abandoned manifest counts its real bytes, not 280 KiB
    const ScanTunables t = w.s->machine().tunables();
    qint64 hostFinal = 0;
    for (const FakeHost::Scan &sc : w.host.scans)
        hostFinal += sc.gate.spent();
    const qint64 live = kLiveSpent;
    CHECK_EQ(w.ledgerCount(), 1);
    CHECK_EQ(w.ledgerLast(), w.http.totalBytes + hostFinal + live);
    // the engine moves to a node the scan did not prove (chosen elsewhere): its live proof uses the token of
    // the scan the screen shows
    w.liveOn(QStringLiteral("12:xray"));
    w.s->engineStateChanged();
    w.run(3000);
    CHECK_EQ(w.liveProbes.size(), 4);
    for (const auto &p : w.liveProbes)
        CHECK_EQ(p.scanToken, token);
}

// Access facts only from THIS scan's host attempts: a later scan whose host made no attempt never reuses the
// earlier scan's facts (its provider rows stay «Не проверено»).
static void caseAccessScope()
{
    g_case = QStringLiteral("access_scope");
    World w(capsMac(), ScanNetKind::Wifi, 6);
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(20000);
    const QString up0 = QStringLiteral("up:") + kPids.at(0);
    CHECK_EQ(w.row(up0).value("state").toString(), QStringLiteral("works"));
    w.host.accessOpen = QStringLiteral("none");
    w.s->close();
    w.run(31000);
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.host.count("scan_start"), 2);
    CHECK(w.rowFlag(up0, "unverified"));
}

// A row tap: the connect request carries userOrigin + forceConnect and the visible order; nothing else ever
// reaches the tunnel (VPN off on macOS: no connect on open). iPhone with the VPN off: the ordinary connect on
// open, and back before «Подключено» cancels exactly that connect.
static void caseConnectPaths()
{
    g_case = QStringLiteral("row_tap");
    World w;
    w.start(); // VPN off, macOS host: the scan runs without a tunnel
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    CHECK_EQ(w.engine.userConnects, 0);
    w.s->tapRow(QStringLiteral("5:xray"));
    CHECK_EQ(w.engine.rowCalls.size(), 1);
    if (!w.engine.rowCalls.isEmpty()) {
        const FakeEngine::RowCall c = w.engine.rowCalls.first();
        CHECK_EQ(c.id, QStringLiteral("5:xray"));
        CHECK(c.userOrigin);
        CHECK(c.force);
        CHECK(!c.order.isEmpty() && !c.order.contains(QStringLiteral("5:xray")));
        CHECK(c.ttl > 0);
    }
    CHECK_EQ(w.engine.userConnects, 0);
    CHECK_EQ(w.engine.cancels, 0);

    g_case = QStringLiteral("connect_on_open_ios");
    World i(capsIos());
    i.host.avail = ScanHostAvailability::NeedsVpn;
    i.start();
    i.s->open();
    CHECK_EQ(i.engine.userConnects, 1);
    CHECK_EQ(i.phase(), QStringLiteral("connecting"));
    i.run(300);
    i.s->close(); // back before «Подключено»: the ordinary cancel of THAT connect
    CHECK_EQ(i.engine.cancels, 1);
    i.run(1000);
    CHECK_EQ(i.engine.cancels, 1);
    CHECK(i.engine.rowCalls.isEmpty());

    g_case = QStringLiteral("connect_on_open_ios_connected");
    World j(capsIos());
    j.host.avail = ScanHostAvailability::NeedsVpn;
    j.start();
    j.s->open();
    CHECK_EQ(j.engine.userConnects, 1);
    j.run(400);
    j.liveOn(QStringLiteral("4:xray"));
    j.host.avail = ScanHostAvailability::Available;
    if (j.host.onAvailabilityChanged)
        j.host.onAvailabilityChanged();
    j.s->engineStateChanged();
    j.run(20000);
    CHECK_EQ(j.host.count("scan_start"), 1);
    j.s->close(); // after «Подключено»: nothing turns the VPN off
    j.run(1000);
    CHECK_EQ(j.engine.cancels, 0);
    CHECK_EQ(j.engine.userConnects, 1);
}

static bool onlyScanEntryAppSide(const World &w, qint64 appSlice, const ScanTunables &t);

// No host: the scan ends with NoScan host_* and nothing is sent or polled.
static void caseHostUnavailable()
{
    g_case = QStringLiteral("host_unavailable");
    World w;
    w.host.avail = ScanHostAvailability::Unavailable;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(5000);
    CHECK_EQ(w.phase(), QStringLiteral("no_scan"));
    CHECK_EQ(w.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("service_off"));
    CHECK(!w.s->machine().draining());
    CHECK_EQ(w.host.count("scan_start"), 0);
    CHECK_EQ(w.host.count("scan_poll"), 0);
    CHECK_EQ(w.engine.userConnects, 0);

    // the start never reached a host (the iPhone's tunnel is up but its extension does not answer yet):
    // settled at once (no eternal drain), the host charged nothing
    g_case = QStringLiteral("host_not_ready_cellular");
    World c(capsIos(), ScanNetKind::Cellular, 6);
    c.host.avail = ScanHostAvailability::NeedsVpn;
    c.liveOn(QStringLiteral("4:xray"));
    c.start();
    c.s->open();
    c.run(200); // manifest (40 ms) in: the start never leaves the app
    CHECK_EQ(c.phase(), QStringLiteral("no_scan"));
    CHECK_EQ(c.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("host_no_vpn"));
    CHECK_EQ(c.host.count("scan_start"), 0);
    CHECK(!c.s->machine().draining());
    const ScanTunables t = c.s->machine().tunables();
    const qint64 appSlice = qint64(t.costManifestBytes) + t.costApiBytes + t.costTunnelProbeBytes
                            + t.costOutcomesBytes + t.costBatchBytes + t.costApiBytes;
    CHECK(onlyScanEntryAppSide(c, appSlice, t)); // the app side only: host charge 0
}

// The ledger after a scan whose host never took the start: exactly ONE entry for the scan (the first: the
// app side, no host charge) and after it only the post-scan requests the core charges at their worst case
// one by one (e.g. the release of a seat granted after the stop) - never a host grant.
static bool onlyScanEntryAppSide(const World &w, qint64 appSlice, const ScanTunables &t)
{
    const QList<ScanLedgerEntry> &e = w.s->machine().ledger().entries();
    if (e.isEmpty() || e.first().bytes <= 0 || e.first().bytes > appSlice)
        return false;
    const qint64 postMax = qMax(qMax<qint64>(t.costApiBytes, t.costOutcomesBytes), qint64(t.costTunnelProbeBytes));
    for (int i = 1; i < e.size(); ++i)
        if (e.at(i).bytes > postMax)
            return false;
    return true;
}

// The desktop host's unavailable reasons: service_off and the version mismatch get their own NoScan reasons
// (no start is ever sent); "connecting" waits for the host, bounded by scan_stop_ms.
static void caseHostReasons()
{
    const QList<QPair<QString, QString>> map = {{QStringLiteral("service_off"), QStringLiteral("service_off")},
                                               {QStringLiteral("service_old"), QStringLiteral("service_old")},
                                               {QStringLiteral("service_mismatch"), QStringLiteral("service_mismatch")},
                                               {QStringLiteral("something_new"), QStringLiteral("service_off")}};
    for (const auto &m : map) {
        g_case = QStringLiteral("host_reason_") + m.first;
        World w;
        w.host.avail = ScanHostAvailability::Unavailable;
        w.host.reason = m.first;
        w.liveOn(QStringLiteral("4:xray"));
        w.start();
        w.s->open();
        w.run(500);
        CHECK_EQ(w.phase(), QStringLiteral("no_scan"));
        CHECK_EQ(w.s->view().value("empty").toMap().value("reason").toString(), m.second);
        CHECK_EQ(w.host.count("scan_start"), 0);
        CHECK(!w.s->machine().draining());
        CHECK_EQ(w.engine.cancels, 0);
    }

    g_case = QStringLiteral("host_connecting_then_ready");
    World c;
    c.host.avail = ScanHostAvailability::Unavailable;
    c.host.reason = QStringLiteral("connecting");
    c.liveOn(QStringLiteral("4:xray"));
    c.start();
    c.s->open();
    c.run(1000);
    CHECK_EQ(c.phase(), QStringLiteral("preparing")); // waiting for the service, nothing sent to it
    CHECK_EQ(c.host.count("scan_start"), 0);
    c.host.avail = ScanHostAvailability::Available;
    c.host.onAvailabilityChanged();
    c.run(300); // the held manifest goes on as soon as the service's caps are in
    CHECK_EQ(c.host.count("scan_start"), 1);
    c.run(20000);
    CHECK_EQ(c.host.count("scan_start"), 1);
    CHECK_EQ(c.phase(), QStringLiteral("done"));

    g_case = QStringLiteral("host_connecting_forever");
    World f;
    f.host.avail = ScanHostAvailability::Unavailable;
    f.host.reason = QStringLiteral("connecting");
    f.liveOn(QStringLiteral("4:xray"));
    f.start();
    f.s->open();
    f.run(f.s->machine().tunables().stopMs - 500);
    CHECK_EQ(f.phase(), QStringLiteral("preparing"));
    f.run(1000); // the bound (scan_stop_ms) passed: the service never came
    CHECK_EQ(f.phase(), QStringLiteral("no_scan"));
    CHECK_EQ(f.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("service_off"));
    CHECK_EQ(f.host.count("scan_start"), 0);
    CHECK(!f.s->machine().draining());
}

// The desktop service's other answers: a kill switch it cannot open for probes stops the scan with
// host_kill_switch; rate_limited / ipc_refused at the start are host errors (NoScan host_other, settled at
// once); a poll refused by the IPC bounds is a skipped round; ipc_refused shutting_down ends the scan bounded.
static void caseServiceErrors()
{
    g_case = QStringLiteral("kill_switch_exemption");
    World k;
    k.host.refuseStart = QStringLiteral("internal");
    k.host.refuseDetail = QStringLiteral("kill_switch_exemption");
    k.liveOn(QStringLiteral("4:xray"));
    k.start();
    k.s->open();
    k.run(500);
    CHECK_EQ(k.phase(), QStringLiteral("no_scan"));
    CHECK_EQ(k.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("host_kill_switch"));
    CHECK(!k.s->machine().draining());
    CHECK_EQ(k.engine.cancels, 0);
    k.host.refuseStart.clear(); // a later scan with the switch fixed: the plain reasons again
    k.run(31000);
    k.s->retry();
    k.run(20000);
    CHECK_EQ(k.phase(), QStringLiteral("done"));

    for (const auto &e : QList<QPair<QString, QString>>{{QStringLiteral("rate_limited"), QStringLiteral("scan_start")},
                                                       {QStringLiteral("ipc_refused"), QStringLiteral("queue_full")}}) {
        g_case = QStringLiteral("start_refused_") + e.first;
        World w;
        w.host.refuseStart = e.first;
        w.host.refuseDetail = e.second;
        w.liveOn(QStringLiteral("4:xray"));
        w.start();
        w.s->open();
        w.run(500);
        CHECK_EQ(w.phase(), QStringLiteral("no_scan"));
        CHECK_EQ(w.s->view().value("empty").toMap().value("reason").toString(), e.first == QLatin1String("rate_limited")
                                                                                    ? QStringLiteral("host_rate_limited")
                                                                                    : QStringLiteral("host_") + e.second);
        CHECK(!w.s->machine().draining());
    }

    g_case = QStringLiteral("poll_refused_round");
    World p;
    p.liveOn(QStringLiteral("4:xray"));
    p.start();
    p.s->open();
    p.run(400);
    p.host.pollReplyOnce = QByteArrayLiteral("{\"error\":\"ipc_refused\",\"detail\":\"queue_full\"}");
    p.run(20000);
    CHECK_EQ(p.phase(), QStringLiteral("done"));
    CHECK(p.s->view().value("verified").toInt() >= 10);

    g_case = QStringLiteral("poll_shutting_down");
    World d(capsMac(), ScanNetKind::Wifi, 8);
    for (int i = 0; i < 8; ++i)
        d.host.outcomes[QStringLiteral("%1:xray").arg(4 + i)].durMs = 4000;
    d.liveOn(QStringLiteral("4:xray"));
    d.start();
    d.s->open();
    d.run(1000);
    d.host.pollReplyOnce = QByteArrayLiteral("{\"error\":\"ipc_refused\",\"detail\":\"shutting_down\"}");
    d.run(350); // the refused poll: the scan ends at once (a host failure, not a skipped round)
    CHECK(d.phase() != QStringLiteral("reach") && d.phase() != QStringLiteral("data"));
    d.run(2500); // the drain is bounded (scan_drain_ms after the freeze ack)
    CHECK(d.phase() != QStringLiteral("reach") && d.phase() != QStringLiteral("data"));
    CHECK(!d.s->machine().draining());
}

// A refused scan_start ({"error":"no_vpn"} of the iOS host, or any error answer): draining() false at once,
// host charge 0, one ledger entry; a reopen right after it stays in the cooldown with that one entry.
static void caseRefusedStart()
{
    g_case = QStringLiteral("refused_start");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    w.host.refuseStart = QStringLiteral("no_vpn");
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(60); // manifest 40 ms + the start's answer 5 ms
    CHECK_EQ(w.phase(), QStringLiteral("no_scan"));
    CHECK_EQ(w.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("host_no_vpn"));
    CHECK(!w.s->machine().draining());
    const QJsonObject *st = w.host.lastRequest("scan_start");
    const qint64 grant = st ? qint64(st->value("max_bytes").toDouble(-1)) : -1;
    CHECK(grant > 0);
    const ScanTunables t = w.s->machine().tunables();
    const qint64 appSlice = qint64(t.costManifestBytes) + t.costApiBytes + t.costTunnelProbeBytes
                            + t.costOutcomesBytes + t.costBatchBytes + t.costApiBytes;
    CHECK(onlyScanEntryAppSide(w, appSlice, t));
    CHECK_EQ(w.host.count("scan_freeze"), 0); // nothing to freeze: the host never took it
    w.run(3000);
    CHECK(onlyScanEntryAppSide(w, appSlice, t)); // nothing charged later for the host either
    const int entries = w.ledgerCount();
    CHECK_EQ(w.host.count("scan_poll"), 0);
    // reopen right after the failure: the cooldown holds, nothing new is fetched or started
    w.s->close();
    w.run(500);
    w.s->open();
    w.run(1000);
    CHECK_EQ(w.host.count("scan_start"), 1);
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 1);
    CHECK_EQ(w.ledgerCount(), entries);
    CHECK_EQ(w.s->view().value("bar").toMap().value("button").toString(), QStringLiteral("retry_in_s"));
}

// The host went away mid-scan (the service died / the channel broke) or forgot the running scan: it took the
// start, so the settle is the draining rule - bounded (scan_freeze_ack_ms), the whole grant charged.
static void caseHostDied()
{
    g_case = QStringLiteral("host_died_mid_scan");
    World w(capsMac(), ScanNetKind::Cellular, 8);
    w.server.latency = 2;
    for (int i = 0; i < 8; ++i)
        w.host.outcomes[QStringLiteral("%1:xray").arg(4 + i)].durMs = 4000;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(1500);
    CHECK(w.phase() == QStringLiteral("reach") || w.phase() == QStringLiteral("data"));
    const QJsonObject *st = w.host.lastRequest("scan_start");
    const qint64 grant = st ? qint64(st->value("max_bytes").toDouble(-1)) : -1;
    const int pollsBefore = w.host.count("scan_poll");
    w.host.avail = ScanHostAvailability::Unavailable;
    if (w.host.onAvailabilityChanged)
        w.host.onAvailabilityChanged();
    CHECK(w.phase() != QStringLiteral("reach") && w.phase() != QStringLiteral("data"));
    w.run(1200); // scan_freeze_ack_ms (1000) bounds the settle
    CHECK(!w.s->machine().draining());
    CHECK_EQ(w.ledgerCount(), 1);
    CHECK_EQ(w.host.count("scan_poll"), pollsBefore); // a dead host is not polled
    const ScanTunables t = w.s->machine().tunables();
    const qint64 live = kLiveSpent;
    CHECK_EQ(w.ledgerLast(), w.http.totalBytes + live + grant);

    g_case = QStringLiteral("host_lost_scan");
    World l(capsMac(), ScanNetKind::Cellular, 8);
    l.server.latency = 2;
    for (int i = 0; i < 8; ++i)
        l.host.outcomes[QStringLiteral("%1:xray").arg(4 + i)].durMs = 4000;
    l.liveOn(QStringLiteral("4:xray"));
    l.start();
    l.s->open();
    l.run(1000);
    const QJsonObject *lst = l.host.lastRequest("scan_start");
    const qint64 lgrant = lst ? qint64(lst->value("max_bytes").toDouble(-1)) : -1;
    l.host.loseScansAt = l.clock.t; // the next poll answers unknown_scan for the running scan
    l.run(2000);                    // one poll (300 ms) + the unanswered freeze (1000 ms)
    CHECK(!l.s->machine().draining());
    CHECK(l.phase() != QStringLiteral("reach") && l.phase() != QStringLiteral("data"));
    CHECK_EQ(l.ledgerCount(), 1);
    const qint64 llive = kLiveSpent;
    CHECK_EQ(l.ledgerLast(), l.http.totalBytes + llive + lgrant);
}

// Outside a scan the iOS extension reports its path element in the scan_caps reply: it joins the tuple at the
// next open and a change of it is a network change.
static void caseCapsGen()
{
    g_case = QStringLiteral("caps_gen");
    World w;
    w.host.capsGen = true;
    w.host.progressGen = false;
    w.liveOn(QStringLiteral("4:xray"));
    w.start(); // the construction asks scan_caps: its gen is known before the first open
    w.run(20);
    w.s->open();
    CHECK(scanNetSourceOf(w.s->lastNetwork().sources, QStringLiteral("service")) != nullptr);
    w.run(20000);
    CHECK_EQ(w.host.count("scan_start"), 1);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    w.host.gen.epoch = 0x6f6f6f6f6f6f6f6fULL; // the extension restarted: a new epoch in the next caps reply
    w.host.avail = ScanHostAvailability::Unavailable;
    w.host.onAvailabilityChanged();
    w.host.avail = ScanHostAvailability::Available;
    w.host.onAvailabilityChanged();
    w.run(50);
    // a network change after a finished result: seen (the host's new gen), no scan by itself (owner 19.11)
    CHECK_EQ(w.phase(), QStringLiteral("idle"));
    w.run(20000);
    CHECK_EQ(w.host.count("scan_start"), 1);
}

// The machine is built from the host's own scan_caps answer, not the compiled guess.
static void caseCapsFromHost()
{
    g_case = QStringLiteral("caps_from_host");
    ScanHostCaps guess = capsMac();
    guess.maxLegConcurrent = 0;
    guess.dnsPlan = false;
    World w(guess);
    w.host.real = capsMac();
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(20000);
    const QJsonObject *st = w.host.lastRequest("scan_start");
    bool leg = false;
    if (st)
        for (const QJsonValue &v : st->value("candidates").toArray())
            leg = leg || v.toObject().value("kind").toString() == QLatin1String("xray_leg");
    CHECK(leg);
    CHECK(st && st->value("limits").toObject().value("leg_concurrency").toInt() > 0);
}

// The screen fields the core's JSON leaves out: the row's protocol version, the country menu's localized names, the return-home switch, the network-change shade.
static void caseScreenFields()
{
    g_case = QStringLiteral("screen_fields");
    TuningStore::set({}, {{QStringLiteral("scanner"), true}});
    World w;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    CHECK(!w.s->returnHome());
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    CHECK_EQ(w.row(QStringLiteral("5:xray")).value("version").toString(), QStringLiteral("v-5"));
    CHECK_EQ(w.row(QStringLiteral("4:xray")).value("version").toString(), QStringLiteral("v-live"));
    CHECK(!w.s->view().contains("card")); // the Scanner has no connection card (variant B, 19.11)
    bool de = false, fi = false;
    for (const QVariant &c : w.s->view().value("bar").toMap().value("countries").toList()) {
        const QVariantMap m = c.toMap();
        de = de || (m.value("cc").toString() == QLatin1String("DE") && m.value("name").toString() == QStringLiteral("Германия"));
        fi = fi || (m.value("cc").toString() == QLatin1String("FI") && m.value("name").toString() == QStringLiteral("Финляндия"));
    }
    CHECK(de && fi);
    // scanner_return_home (absent = false) as a property
    TuningStore::set({}, {{QStringLiteral("scanner"), true}, {QStringLiteral("scanner_return_home"), true}});
    w.s->refreshSwitches();
    CHECK(w.s->returnHome());
    TuningStore::set({}, {{QStringLiteral("scanner"), true}});
    w.s->refreshSwitches();
    CHECK(!w.s->returnHome());

    // the server list's figures (owner 17.11): the working rows of this network's result, with their ms; the stored
    // result carries the 1.10 label mark
    {
        g_case = QStringLiteral("list_figures");
        const QHash<QString, int> f = w.s->listFigures();
        int working = 0;
        for (const QVariant &v : w.rows()) {
            const QVariantMap r = v.toMap();
            const QString id = r.value("id").toString();
            const bool verified = !r.value("flags").toStringList().contains(QLatin1String("unverified"))
                                  && r.value("state").toString() != QLatin1String("failed")
                                  && !r.value("flags").toStringList().contains(QLatin1String("live_unverified"));
            if (verified && r.value("ms").toInt() >= 0 && !r.value("flags").toStringList().contains(QLatin1String("current"))) {
                ++working;
                CHECK_EQ(f.value(id, -2), r.value("ms").toInt());
            }
        }
        CHECK(working > 0 && !f.isEmpty());
        bool marked = false;
        for (auto it = w.store.m.constBegin(); it != w.store.m.constEnd(); ++it)
            if (it.key().startsWith(QLatin1String(kScanCacheStorePrefix)))
                marked = QJsonDocument::fromJson(it.value()).object().value(QLatin1String(kScanCachedLabelRuleKey)).toString()
                         == QLatin1String(kScanCachedLabelRule);
        CHECK(marked);
        // another network: nothing from this one
        const ScanNetFacts keep = w.engine.net;
        w.engine.net.reportingKey = QStringLiteral("cell:250-02:4g");
        w.engine.net.kind = ScanNetKind::Cellular;
        CHECK(w.s->listFigures().isEmpty());
        w.engine.net = keep;
        CHECK(!w.s->listFigures().isEmpty()); // (the age rule: scan_core_check rowsAfter17Nov)
        g_case = QStringLiteral("screen_fields");
    }

    // a change while results are shown (owner 19.11: no scan unless the person presses «Сканировать»): no scan by
    // itself, no «проверяем заново» shade - the open page of the new network
    g_case = QStringLiteral("network_changed_results_no_rescan");
    w.run(5000);
    const int startsBefore = w.host.count("scan_start");
    w.engine.net.appSources[0].counter = 5;
    w.s->networkChanged();
    CHECK_EQ(w.phase(), QStringLiteral("idle"));
    CHECK(!w.s->shade().value("visible").toBool());
    w.run(20000);
    CHECK_EQ(w.host.count("scan_start"), startsBefore);
    CHECK_EQ(w.engine.userConnects, 0);

    // a change mid-scan: the person's scan restarts on the new network, the shade says so
    g_case = QStringLiteral("network_changed_shade_scan");
    World m;
    m.liveOn(QStringLiteral("4:xray"));
    m.start();
    m.s->open();
    m.run(1200);
    m.engine.net.appSources[0].counter = 2;
    m.s->networkChanged();
    CHECK(m.s->view().value("phase").toString() == QStringLiteral("preparing"));
    CHECK_EQ(m.s->shade().value("text_key").toString(), QStringLiteral("network_changed"));
    // with the screen closed nothing is shown
    g_case = QStringLiteral("network_changed_no_shade_closed");
    World c;
    c.liveOn(QStringLiteral("4:xray"));
    c.start();
    c.s->open();
    c.run(20000);
    c.s->close();
    c.run(3000);
    c.engine.net.appSources[0].counter = 9;
    c.s->networkChanged();
    CHECK(!c.s->shade().value("visible").toBool());
}


// --- contract pass: typed builder, AWG mini input, base IPs, host error detail, report refusal, speed -------

static ScanHostCaps capsAwg()
{
    ScanHostCaps c = capsMac();
    c.maxAwgConcurrent = 2;
    return c;
}

static ScanAwgNodeInput awgInput()
{
    ScanAwgNodeInput a;
    a.privateKey = QString::fromLatin1(QByteArray("AWGPRIVKEY-0123456789abcdefghijk").left(32).toBase64());
    a.address = QStringLiteral("10.8.0.5/32");
    a.mtu = 1280;
    a.peerPublicKey = QString::fromLatin1(QByteArray(32, 'p').toBase64());
    a.endpoint = QStringLiteral("198.51.100.200:51820");
    a.obfuscation = {{QStringLiteral("jc"), QStringLiteral("4")}, {QStringLiteral("h1"), QStringLiteral("1234")}};
    return a;
}

// An own AmneziaWG node with awg_probe: the engine's input + the probe base's IP become the contract's config;
// a node whose config cannot be built never reaches the host and ends «Не проверено».
static World *awgWorld(bool valid, bool known = true)
{
    auto *w = new World(capsAwg(), ScanNetKind::Wifi, 4);
    w->flags.insert(QStringLiteral("scanner_awg_mini"), true);
    w->server.numbers.insert(QStringLiteral("scan_awg_concurrency"), 2);
    ScanOwnNode n;
    n.nodeId = QStringLiteral("20");
    n.label = QStringLiteral("AWG 20");
    n.countryCode = QStringLiteral("NL");
    n.transport = ScanTransport::Awg;
    n.transportVersion = QStringLiteral("3.1");
    n.entryIp = QStringLiteral("198.51.100.200");
    n.entryPort = 51820;
    w->engine.own << n;
    w->server.nodes << QJsonObject{{"node_id", "20"}, {"tier", 0}, {"rank", 9}, {"crowd_works", false}, {"awg_probe", true},
                                   {"awg_echo_target", "10.8.1.1"}};
    w->host.outcomes.insert(QStringLiteral("20"), Outcome{true, 70, 500});
    w->engine.knownIps.insert(QStringLiteral("tunnel.leakhost.example"), {QStringLiteral("192.0.2.10")});
    if (known) {
        ScanAwgNodeInput a = awgInput();
        if (!valid)
            a.peerPublicKey.clear();
        w->engine.awg.insert(QStringLiteral("20"), a);
    }
    return w;
}

static QJsonObject candidateIn(const QJsonObject *start, const char *id)
{
    if (start)
        for (const QJsonValue &v : start->value("candidates").toArray())
            if (v.toObject().value("id").toString() == QLatin1String(id))
                return v.toObject();
    return QJsonObject();
}

static void caseAwgMini()
{
    g_case = QStringLiteral("awg_mini_config");
    std::unique_ptr<World> w(awgWorld(true));
    w->liveOn(QStringLiteral("4:xray"));
    w->start();
    w->s->open();
    w->run(20000);
    const QJsonObject *st = w->host.lastRequest("scan_start");
    const QJsonObject c = candidateIn(st, "20");
    CHECK_EQ(c.value("kind").toString(), QStringLiteral("awg_mini"));
    const QJsonObject cfg = QJsonDocument::fromJson(c.value("config").toString().toUtf8()).object();
    CHECK_EQ(cfg.value("probe").toObject().value("ip").toString(), QStringLiteral("192.0.2.10"));
    CHECK_EQ(cfg.value("probe").toObject().value("host").toString(), QStringLiteral("tunnel.leakhost.example"));
    CHECK_EQ(cfg.value("prime_echo_target").toString(), QStringLiteral("10.8.1.1"));
    CHECK(cfg.value("uapi").toString().contains(QLatin1String("endpoint=198.51.100.200:51820")));
    CHECK_EQ(w->row(QStringLiteral("20")).value("state").toString(), QStringLiteral("works"));
    CHECK_EQ(w->row(QStringLiteral("20")).value("version").toString(), QStringLiteral("3.1"));
    CHECK(w->logsClean());

    g_case = QStringLiteral("awg_mini_refused");
    std::unique_ptr<World> r(awgWorld(false));
    r->liveOn(QStringLiteral("4:xray"));
    r->start();
    r->s->open();
    r->run(20000);
    CHECK(candidateIn(r->host.lastRequest("scan_start"), "20").isEmpty());
    CHECK(r->rowFlag(QStringLiteral("20"), "unverified"));
    CHECK_EQ(r->phase(), QStringLiteral("done"));

    g_case = QStringLiteral("awg_mini_withheld_by_caps");
    std::unique_ptr<World> h(awgWorld(true));
    h->host.real.maxAwgConcurrent = 0; // the desktop service offers no awg_mini kind for this scan ...
    h->host.awgWithheld = true;        // ... and says why
    h->liveOn(QStringLiteral("4:xray"));
    h->start();
    h->s->open();
    h->run(20000);
    CHECK(candidateIn(h->host.lastRequest("scan_start"), "20").isEmpty());
    CHECK(h->rowFlag(QStringLiteral("20"), "unverified")); // «Не проверено», not absent
    CHECK_EQ(h->phase(), QStringLiteral("done"));
    CHECK_EQ(h->s->machine().lastSummary().value("not_verified_reasons").toObject().value("awg_live_peer_unknown").toInt(), 1);

    g_case = QStringLiteral("awg_mini_no_address");
    std::unique_ptr<World> a(awgWorld(true, false));
    a->liveOn(QStringLiteral("4:xray"));
    a->start();
    a->s->open();
    a->run(20000);
    CHECK(candidateIn(a->host.lastRequest("scan_start"), "20").isEmpty());
    CHECK(a->rowFlag(QStringLiteral("20"), "unverified"));
}

// The iOS extension cannot read the live AmneziaWG peer: a start with awg_mini sessions is refused before its
// engine; the coordinator sends it once more without them (they end «Не проверено»), never a host failure,
// never a loop.
static void caseAwgLivePeerUnknown()
{
    g_case = QStringLiteral("awg_live_peer_unknown");
    std::unique_ptr<World> w(awgWorld(true));
    w->host.awgLivePeerUnknown = 1;
    w->liveOn(QStringLiteral("4:xray"));
    w->start();
    w->s->open();
    w->run(20000);
    CHECK_EQ(w->host.count("scan_start"), 2);
    CHECK(candidateIn(w->host.lastRequest("scan_start"), "20").isEmpty());
    CHECK(!candidateIn(w->host.lastRequest("scan_start"), "5:xray").isEmpty());
    CHECK_EQ(w->phase(), QStringLiteral("done"));
    CHECK(w->rowFlag(QStringLiteral("20"), "unverified"));
    CHECK_EQ(w->row(QStringLiteral("5:xray")).value("state").toString(), QStringLiteral("works"));
    CHECK(w->logsClean());

    g_case = QStringLiteral("awg_live_peer_unknown_twice");
    std::unique_ptr<World> t(awgWorld(true));
    t->host.awgLivePeerUnknown = 2; // refused again without awg: one retry only, then the start's failure
    t->liveOn(QStringLiteral("4:xray"));
    t->start();
    t->s->open();
    t->run(20000);
    CHECK_EQ(t->host.count("scan_start"), 2);
    CHECK_EQ(t->phase(), QStringLiteral("no_scan"));
    CHECK(!t->s->machine().draining());
}

// probe.base_ips: the engine's addresses of the probe base's host, else one bounded resolution per scan,
// else none (the host resolves itself).
static void caseBaseIps()
{
    g_case = QStringLiteral("base_ips_engine");
    World e;
    e.engine.knownIps.insert(QStringLiteral("tunnel.leakhost.example"), {QStringLiteral("192.0.2.10"), QStringLiteral("not-an-ip")});
    e.liveOn(QStringLiteral("4:xray"));
    e.start();
    e.s->open();
    e.run(20000);
    const QJsonObject *st = e.host.lastRequest("scan_start");
    CHECK(st && st->value("probe").toObject().value("base_ips").toArray() == QJsonArray{QStringLiteral("192.0.2.10")});
    CHECK(e.resolver.asked.isEmpty());

    g_case = QStringLiteral("base_ips_resolved");
    World r;
    r.engine.knownIps.clear();
    r.resolver.answers.insert(QStringLiteral("tunnel.leakhost.example"), {QStringLiteral("2001:db8::1"), QStringLiteral("192.0.2.20")});
    r.liveOn(QStringLiteral("4:xray"));
    r.start();
    r.s->open();
    r.run(20000);
    const QJsonObject *rs = r.host.lastRequest("scan_start");
    CHECK(rs && rs->value("probe").toObject().value("base_ips").toArray()
                   == (QJsonArray{QStringLiteral("192.0.2.20"), QStringLiteral("2001:db8::1")}));
    CHECK_EQ(r.resolver.asked.size(), 1);
    CHECK(r.logsClean());

    g_case = QStringLiteral("base_ips_resolution_timeout");
    World n; // the engine knows nothing and the resolver never answers
    n.engine.knownIps.clear();
    n.liveOn(QStringLiteral("4:xray"));
    n.start();
    n.s->open();
    n.run(1000);
    CHECK_EQ(n.host.count("scan_start"), 0); // waiting, bounded
    n.run(1000);                              // scan_stage1_timeout_ms (1500) passed
    CHECK_EQ(n.host.count("scan_start"), 1);
    const QJsonObject *ns = n.host.lastRequest("scan_start");
    CHECK(ns && !ns->value("probe").toObject().contains("base_ips"));
    n.run(20000);
    CHECK_EQ(n.phase(), QStringLiteral("done"));
}

// The engine refuses the full check (another diagnostic runs, the queue filled in a race): a notice, the
// check over, no «sent» text.
static void caseReportRefused()
{
    for (const auto &rc : QList<QPair<QString, QString>>{{QStringLiteral("busy"), QStringLiteral("report_check_busy")},
                                                        {QStringLiteral("queue_full"), QStringLiteral("report_queue_full")}}) {
        g_case = QStringLiteral("report_refused_") + rc.first;
        World w;
        w.liveOn(QStringLiteral("4:xray"));
        w.start();
        w.s->open();
        w.run(20000);
        w.s->checkFromSupport();
        CHECK_EQ(w.engine.reports, 1);
        CHECK(w.s->view().value("support_check").toMap().value("running").toBool());
        w.s->reportCheckRefused(w.engine.lastReportId, rc.first);
        CHECK_EQ(w.s->shade().value("text_key").toString(), rc.second);
        CHECK(!w.s->view().value("support_check").toMap().value("running").toBool());
    }
}

// The Doctor's speed sample: one sized /v1/probe through the live tunnel with the scan's token, its digest
// verified here, charged to the hour at its worst case, refused when the hour cannot cover it; without a
// scan token a token of its own (never the scan's context).
static void caseSpeedSample()
{
    const qint64 mib = 1048576;
    const qint64 cost = mib + 8192 + 2048;
    const auto sample = [](World &w, qint64 bytes) {
        ScanSpeedSample got;
        bool done = false;
        w.s->sampleSpeed(bytes, 8000, [&](const ScanSpeedSample &s) {
            got = s;
            done = true;
        });
        w.run(1000);
        CHECK(done);
        return got;
    };

    g_case = QStringLiteral("speed_after_scan");
    World w;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(20000);
    const QString scanToken = w.host.lastRequest("scan_start")->value("probe").toObject().value("token").toString();
    const int ledgerBefore = w.ledgerCount();
    const ScanSpeedSample s = sample(w, mib);
    CHECK(s.ok && s.digestOk && s.bytes == mib && s.ms >= 0);
    CHECK_EQ(w.liveProbes.last().bytes, mib);
    CHECK_EQ(w.liveProbes.last().scanToken, scanToken);
    CHECK_EQ(w.ledgerCount(), ledgerBefore + 1);
    CHECK_EQ(w.ledgerLast(), cost);
    CHECK_EQ(w.http.count("/v1/scan/token"), 0);

    g_case = QStringLiteral("speed_bad_digest");
    w.liveBadDigest = true;
    const ScanSpeedSample b = sample(w, mib);
    CHECK(b.ok && !b.digestOk);

    g_case = QStringLiteral("speed_budget");
    World c(capsMac(), ScanNetKind::Cellular, 6);
    c.engine.liveBase = QString::fromLatin1(kTunnelBase);
    QJsonArray full; // the cellular hour almost used up (the ledger the scanner restores at its start)
    full << QJsonObject{{"at_ms", double(c.clock.t)}, {"bytes", 5000000.0}, {"cellular", true}};
    c.store.m.insert(QLatin1String(kScanBudgetStoreKey), QJsonDocument(full).toJson(QJsonDocument::Compact));
    c.liveOn(QStringLiteral("4:xray"));
    c.start();
    const int probesBefore = c.liveProbes.size();
    const ScanSpeedSample bb = sample(c, mib);
    CHECK(!bb.ok && bb.error == QStringLiteral("budget"));
    CHECK_EQ(c.liveProbes.size(), probesBefore);
    CHECK_EQ(c.http.count("/v1/scan/token"), 0);

    g_case = QStringLiteral("speed_own_token");
    World t; // no scan ran: no scan token
    t.engine.liveBase = QString::fromLatin1(kTunnelBase);
    t.liveOn(QStringLiteral("4:xray"));
    t.start();
    const ScanSpeedSample ts = sample(t, mib);
    CHECK(ts.ok && ts.digestOk);
    CHECK_EQ(t.http.count("/v1/scan/token"), 1);
    CHECK(!t.liveProbes.isEmpty() && t.liveProbes.last().scanToken.startsWith(QLatin1String("tsc1.POST-TOKEN")));
    CHECK_EQ(t.ledgerCount(), 2); // the token request and the sample, each at its worst case
    CHECK(t.logsClean());

    g_case = QStringLiteral("speed_no_tunnel");
    World n;
    n.start();
    const ScanSpeedSample ns = sample(n, mib);
    CHECK(!ns.ok && ns.error == QStringLiteral("no_tunnel"));
}

// A failing manifest charges its REAL bytes: ten instant retries on cellular (a scan that never reached a host
// arms no cooldown) never spend the manifest's 280 KiB worst case each.
static void caseManifestFailureBytes()
{
    g_case = QStringLiteral("manifest_failure_bytes");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    w.server.manifestStatus = 503;
    w.start(); // no live tunnel: nothing else is sent around the manifest
    w.s->open();
    w.run(200);
    CHECK_EQ(w.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("manifest_unavailable"));
    for (int i = 0; i < 10; ++i) { // instant taps: the core's 1 s manifest backoff sends none of them
        w.s->retry();
        w.run(20);
    }
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 1);
    for (int i = 0; i < 10; ++i) { // ten retries the backoff lets through
        w.run(1000);
        w.s->retry();
        w.run(200);
    }
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 11);
    CHECK_EQ(w.ledgerCount(), 11);
    qint64 real = 0;
    for (const FakeHttp::Sent &x : w.http.sent)
        real += x.resp.bytes;
    qint64 charged = 0;
    for (const ScanLedgerEntry &e : w.s->machine().ledger().entries())
        charged += e.bytes;
    CHECK_EQ(charged, real);
    CHECK(charged < w.s->machine().tunables().costManifestBytes);
}

// A 404 of the scan endpoints = the server's switch is off: NoScan scanner_off (never the service text), and
// nothing more is requested until the switches change.
static void caseScannerOff()
{
    g_case = QStringLiteral("scanner_off_manifest");
    World w;
    w.server.manifestStatus = 404;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(500);
    CHECK_EQ(w.phase(), QStringLiteral("no_scan"));
    CHECK_EQ(w.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("scanner_off"));
    for (int i = 0; i < 3; ++i) {
        w.s->retry();
        w.run(200);
    }
    w.s->close();
    w.run(1000);
    w.s->open();
    w.s->connectAndScan();
    w.run(1000);
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 1);
    CHECK_EQ(w.host.count("scan_start"), 0);
    CHECK_EQ(w.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("scanner_off"));
    // the switches changed (a /v1/config apply): the Scanner may exist again
    w.server.manifestStatus = 0;
    TuningStore::set({}, {{QStringLiteral("scanner"), true}, {QStringLiteral("doctor_legacy"), true}});
    w.s->refreshSwitches();
    w.s->close();
    w.run(31000); // the core's manual cooldown of that attempt (the live tunnel was checked meanwhile)
    w.s->open();
    w.run(20000);
    CHECK_EQ(w.http.count("/v1/scan/manifest"), 2);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    TuningStore::set({}, {{QStringLiteral("scanner"), true}});

    g_case = QStringLiteral("scanner_off_token");
    World t;
    t.liveOn(QStringLiteral("4:xray"));
    t.start();
    t.s->open();
    t.run(20000); // a stored manifest with its ETag
    t.s->close();
    t.run(31000);
    t.server.tokenStatus = 404;
    t.s->open();
    t.run(500); // 304, then the token's 404
    CHECK_EQ(t.http.count("/v1/scan/token"), 1);
    CHECK_EQ(t.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("scanner_off"));
    t.s->retry();
    t.run(500);
    CHECK_EQ(t.http.count("/v1/scan/manifest"), 2);
    CHECK_EQ(t.http.count("/v1/scan/token"), 1);
}


// --- a transient "not now" of the host: tunnel_changed / stop_pending / stale_epoch -----------------------

static const QByteArray kTunnelChanged = "{\"error\":\"tunnel_changed\"}";
static const QByteArray kStopPending = "{\"error\":\"internal\",\"detail\":\"stop_pending\"}";
static const QByteArray kStaleEpoch = "{\"error\":\"stale_epoch\",\"detail\":\"host_epoch\"}";
static const QByteArray kStopping = "{\"error\":\"internal\",\"detail\":\"stopping\"}";

static void caseHostNotNow()
{
    g_case = QStringLiteral("not_now_tunnel_changed_once");
    World w;
    w.host.startNotNow = {kTunnelChanged};
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(300);
    CHECK_EQ(w.host.count("scan_start"), 1);
    CHECK(w.phase() != QStringLiteral("no_scan")); // not a failure: the scan waits for the tunnel
    CHECK_EQ(w.host.count("scan_poll"), 0);        // a start the host has not taken is not polled
    w.s->engineStateChanged();                     // the tunnel reported its state
    w.run(20000);
    CHECK_EQ(w.host.count("scan_start"), 2);
    CHECK_EQ(w.phase(), QStringLiteral("done"));

    g_case = QStringLiteral("not_now_twice_no_loop");
    World t; // no live tunnel: nothing proven, so the refusal is the result (with a live row it would be Done)
    t.host.startNotNow = {kTunnelChanged, kTunnelChanged, kTunnelChanged, kTunnelChanged};
    t.start();
    t.s->open();
    t.run(300);
    t.s->engineStateChanged();
    t.run(300);
    for (int i = 0; i < 3; ++i) {
        t.s->engineStateChanged();
        t.run(500);
    }
    t.run(5000);
    CHECK_EQ(t.host.count("scan_start"), 2);       // once more, never a loop
    CHECK_EQ(t.phase(), QStringLiteral("no_scan"));
    CHECK_EQ(t.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("host_busy"));
    CHECK(!t.s->machine().draining());
    CHECK_EQ(t.host.count("scan_freeze"), 0);

    g_case = QStringLiteral("not_now_stop_pending_waits");
    World p;
    p.host.startNotNow = {kStopPending};
    p.liveOn(QStringLiteral("4:xray"));
    p.start();
    p.s->open();
    p.run(1500);
    CHECK_EQ(p.host.count("scan_start"), 1);       // waiting scan_drain_ms (2000)
    p.run(800);
    CHECK_EQ(p.host.count("scan_start"), 2);
    p.run(20000);
    CHECK_EQ(p.phase(), QStringLiteral("done"));

    g_case = QStringLiteral("not_now_stale_epoch_twice");
    World e(capsMac(), ScanNetKind::Cellular, 6);
    e.host.startNotNow = {kStaleEpoch, kStaleEpoch};
    e.start(); // no live tunnel: nothing was probed, the cooldown is not armed
    e.s->open();
    e.run(300);
    e.s->engineStateChanged(); // stale_epoch waits for the tunnel's state like tunnel_changed
    e.run(5000);
    CHECK_EQ(e.host.count("scan_start"), 2);
    CHECK_EQ(e.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("host_busy"));
    CHECK_EQ(e.s->view().value("bar").toMap().value("button").toString(), QStringLiteral("retry"));
    const QJsonObject *st = e.host.lastRequest("scan_start");
    const qint64 grant = st ? qint64(st->value("max_bytes").toDouble(-1)) : -1;
    CHECK(grant > 0 && e.ledgerLast() < grant); // no host charge
    e.run(1100);
    e.s->retry();
    e.run(20000);
    CHECK_EQ(e.host.count("scan_start"), 3);    // «Повторить» works

    g_case = QStringLiteral("not_now_tunnel_changed_no_event");
    World n;
    n.host.startNotNow = {kTunnelChanged};
    n.start();
    n.s->open();
    n.run(3000); // no vpnState within scan_drain_ms: the start was not taken
    CHECK_EQ(n.host.count("scan_start"), 1);
    CHECK_EQ(n.s->view().value("empty").toMap().value("reason").toString(), QStringLiteral("host_busy"));

    g_case = QStringLiteral("not_now_stop_while_held");
    World s(capsMac(), ScanNetKind::Cellular, 6);
    s.host.startNotNow = {kStopPending};
    s.liveOn(QStringLiteral("4:xray"));
    s.start();
    s.s->open();
    s.run(300);
    s.s->stop();
    s.run(3000);
    CHECK_EQ(s.host.count("scan_start"), 1);       // stopped while held: never sent again
    CHECK_EQ(s.host.count("scan_freeze"), 0);
    CHECK(!s.s->machine().draining());
    const QJsonObject *sst = s.host.lastRequest("scan_start");
    const qint64 sgrant = sst ? qint64(sst->value("max_bytes").toDouble(-1)) : -1;
    for (const ScanLedgerEntry &x : s.s->machine().ledger().entries())
        CHECK(x.bytes < sgrant);                    // the host was never charged

    g_case = QStringLiteral("not_now_add_once");
    World a(capsMac(), ScanNetKind::Wifi, 4);
    a.host.addNotNow = {kStopPending};
    a.liveOn(QStringLiteral("4:xray"));
    a.start();
    a.s->open();
    a.run(20000);
    CHECK(a.host.count("scan_add") >= 2); // the refused add went once more
    for (int i = 0; i < kPids.size(); ++i)
        CHECK_EQ(a.row(QStringLiteral("up:") + kPids.at(i)).value("state").toString(), QStringLiteral("works"));

    g_case = QStringLiteral("not_now_teardown_pending");
    World d; // the desktop service's name of stop_pending
    d.host.startNotNow = {QByteArrayLiteral("{\"error\":\"teardown_pending\"}")};
    d.liveOn(QStringLiteral("4:xray"));
    d.start();
    d.s->open();
    d.run(1500);
    CHECK_EQ(d.host.count("scan_start"), 1);
    d.run(800);
    CHECK_EQ(d.host.count("scan_start"), 2);
    d.run(20000);
    CHECK_EQ(d.phase(), QStringLiteral("done"));

    g_case = QStringLiteral("not_now_engine_stopping");
    World g; // the engine's name: internal + stopping (a teardown still running) = stop_pending
    g.host.startNotNow = {kStopping};
    g.liveOn(QStringLiteral("4:xray"));
    g.start();
    g.s->open();
    g.run(1500);
    CHECK_EQ(g.host.count("scan_start"), 1);
    g.run(800);
    CHECK_EQ(g.host.count("scan_start"), 2);
    g.run(20000);
    CHECK_EQ(g.phase(), QStringLiteral("done"));

    g_case = QStringLiteral("not_now_stale_epoch_waits_for_tunnel");
    World q;
    q.host.startNotNow = {kStaleEpoch};
    q.liveOn(QStringLiteral("4:xray"));
    q.start();
    q.s->open();
    q.run(1000);
    CHECK_EQ(q.host.count("scan_start"), 1); // not on a timer: on the tunnel's report
    q.s->engineStateChanged();
    q.run(100);
    CHECK_EQ(q.host.count("scan_start"), 2);  // at once on that report
    q.run(20000);
    CHECK_EQ(q.host.count("scan_start"), 2);
    CHECK_EQ(q.phase(), QStringLiteral("done"));

    g_case = QStringLiteral("not_now_with_live_row");
    World l; // refused twice with a live connection: its proven row is the result (Done), no third start
    l.host.startNotNow = {kStopPending, kStopPending};
    l.liveOn(QStringLiteral("4:xray"));
    l.start();
    l.s->open();
    l.run(20000);
    CHECK_EQ(l.host.count("scan_start"), 2);
    CHECK_EQ(l.phase(), QStringLiteral("done"));
    CHECK(!l.s->machine().draining());
}

// Review R1: a held scan_add of scan A that fires after scan B started never touches B's candidates; A's seats go
// back as A's.
static void caseHeldAddOfOlderScan()
{
    g_case = QStringLiteral("held_add_older_scan");
    World w(capsMac(), ScanNetKind::Wifi, 2); // one own Xray burst (4 legs) leaves the leg pool room for the adds
    w.host.addNotNow = {kStopPending};             // A's first add is refused for a moment
    for (const QString &pid : kPids)               // B's provider probes still run when A's held add comes due
        w.host.outcomes[QStringLiteral("up:") + pid].durMs = 4000;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(300);                                    // A's first add was refused and is held (2 s)
    const QJsonObject *first = w.host.lastRequest("scan_add");
    CHECK(first != nullptr);
    const QString aScan = w.s->machine().scanId();
    const auto addsOf = [&w](const QString &scan) {
        int n = 0;
        for (const QJsonObject &r : w.host.requests)
            n += r.value("action").toString() == QLatin1String("scan_add") && r.value("scan_id").toString() == scan ? 1 : 0;
        return n;
    };
    const int aAdds = addsOf(aScan);
    w.engine.net.appSources[0].counter = 7;        // the network changes: scan B
    w.s->networkChanged();
    w.run(20000);                                  // B runs; A's held add comes due meanwhile
    CHECK(w.s->machine().scanId() != aScan);
    CHECK_EQ(addsOf(aScan), aAdds);                // A's held add was never sent again
    for (int i = 0; i < kPids.size(); ++i)         // and never refused B's candidates
        CHECK_EQ(w.row(QStringLiteral("up:") + kPids.at(i)).value("state").toString(), QStringLiteral("works"));
    CHECK_EQ(w.server.releasedLeases.size(), 6);   // A's three and B's three, each once
    CHECK_EQ(QSet<QString>(w.server.releasedLeases.begin(), w.server.releasedLeases.end()).size(), 6);
}

// --- review R1-R3: the "not now" retry path, by class --------------------------------------------------------------
// Invariant 1: a host answer acts only through the context captured when its message was SENT. Invariant 2: one
// settlement per host scan id - a stop while a scan_start is UNANSWERED hands that host scan to the coordinator
// (the machine's share zero): cancelled, polled to its final total, else the whole grant; charged once.

// Scripts the host by message: for scan `scan`, the n-th (0-based) message of `action` is taken after `proc` ms and
// answered `after` ms later (lost when `lose`). Unlisted messages go the ordinary way.
struct HostPlan {
    struct Step {
        QString action;
        int nth = 0;
        int proc = 0;
        int after = 0;
        bool lose = false;
    };
    QString scan;
    QList<Step> steps;
    bool loseRest = false; // every other message of `scan` (after its first scan_start) is answered with nothing
    QHash<QString, int> seen;
    bool apply(const QJsonObject &o, int &proc, int &after, bool &lose)
    {
        if (scan.isEmpty() || o.value("scan_id").toString() != scan)
            return false;
        const QString action = o.value("action").toString();
        const int n = seen.value(action, 0);
        seen[action] = n + 1;
        for (const Step &s : steps)
            if (s.action == action && s.nth == n) {
                proc = s.proc;
                after = s.after;
                lose = s.lose;
                return true;
            }
        if (loseRest && !(action == QLatin1String("scan_start") && n == 0)) {
            proc = 0;
            after = 0;
            lose = true;
            return true;
        }
        return false;
    }
};

// A cellular world whose first scan_start is refused "not now" (stop_pending): the retry goes at ~2.05 s.
static void retriedStartWorld(World &w, HostPlan *plan)
{
    w.server.latency = 2;
    if (w.host.startNotNow.isEmpty())
        w.host.startNotNow = {kStopPending};
    for (int i = 0; i < 6; ++i)
        w.host.outcomes[QStringLiteral("%1:xray").arg(4 + i)].durMs = 3000;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.host.script = [plan](const QJsonObject &o, int &proc, int &after, bool &lose) { return plan->apply(o, proc, after, lose); };
    w.s->open();
    w.run(50);
    plan->scan = w.s->machine().scanId();
    plan->seen.insert(QStringLiteral("scan_start"), 1); // the first (refused) start is behind us
}

static void caseStopDuringRetriedStart()
{
    g_case = QStringLiteral("stop_retried_start_taken");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    HostPlan wp;
    wp.steps = {{QStringLiteral("scan_start"), 1, 0, 800, false}}; // the retry is TAKEN at once, its answer 800 ms later
    retriedStartWorld(w, &wp);
    const QString a = wp.scan;
    w.run(2150);                                   // the retry went at ~2.05 s
    CHECK_EQ(w.sentFor("scan_start", a), 2);
    w.s->stop();                                   // before its answer
    w.run(6000);
    CHECK_EQ(w.sentFor("scan_freeze", a), 0);      // no freeze to a start not answered yet (it could overtake it)
    CHECK(w.sentFor("scan_cancel", a) >= 1);
    CHECK(!w.s->machine().draining());
    const QList<qint64> wf = w.host.finals.value(a);
    CHECK(!wf.isEmpty() && wf.last() > 0);
    CHECK_EQ(w.chargesOf(a).size(), 1);            // its final total, once, by the coordinator
    CHECK_EQ(w.chargesOf(a).value(0, -1), wf.value(0, -2));
    CHECK_EQ(w.ledgerEntriesOf(wf.value(0, -2)), 1);
    CHECK_EQ(w.s->hostRecords(), 0);
    CHECK_EQ(w.crossEvents, 0);

    g_case = QStringLiteral("stop_retried_start_never_taken");
    World n(capsMac(), ScanNetKind::Cellular, 6);
    n.host.startNotNow = {kStopPending, kStopPending};
    HostPlan np;
    np.steps = {{QStringLiteral("scan_start"), 1, 0, 800, false}}; // the retry is refused at once, the refusal comes late
    retriedStartWorld(n, &np);
    n.run(2150);
    n.s->stop();
    n.run(6000);
    CHECK(!n.s->machine().draining());
    const qint64 ngrant = n.grantOf(np.scan);
    for (const ScanLedgerEntry &x : n.s->machine().ledger().entries())
        CHECK(x.bytes < ngrant);                   // never taken: zero for the host
    CHECK(n.chargesOf(np.scan).isEmpty());
    CHECK_EQ(n.s->hostRecords(), 0);

    g_case = QStringLiteral("stop_retried_start_taken_late");
    World l(capsMac(), ScanNetKind::Cellular, 6);
    HostPlan lp;
    lp.steps = {{QStringLiteral("scan_start"), 1, 800, 0, false}}; // the retry reaches the host only after the stop
    retriedStartWorld(l, &lp);
    l.run(2150);
    l.s->stop();                                   // a cancel now: unknown_scan (it overtook the start) - proves nothing
    l.run(6000);                                   // then the host takes the start: cancelled again, polled to its final
    const QList<qint64> lf = l.host.finals.value(lp.scan);
    CHECK(l.sentFor("scan_cancel", lp.scan) >= 2);
    CHECK(!lf.isEmpty());
    CHECK_EQ(l.chargesOf(lp.scan).size(), 1);
    CHECK_EQ(l.chargesOf(lp.scan).value(0, -1), lf.value(0, -2)); // what it really used, not zero, not the grant
    CHECK_EQ(l.ledgerEntriesOf(l.grantOf(lp.scan)), 0);
    CHECK_EQ(l.s->hostRecords(), 0);
}

// R2 exactly: a stop overtakes the retried start (unknown_scan), the host then takes the start but its acceptance
// is LOST (an empty answer). The coordinator cancels and polls that host scan: its final total is charged once.
// Without any further answer: the whole grant, once.
static void caseLostAcceptance()
{
    g_case = QStringLiteral("r2_lost_acceptance_final_via_poll");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    HostPlan wp;
    wp.steps = {{QStringLiteral("scan_start"), 1, 800, 0, true}}; // taken 800 ms later, the "accepted" lost
    retriedStartWorld(w, &wp);
    const QString a = wp.scan;
    w.run(2150);
    w.s->stop();
    w.run(8000);
    CHECK(w.host.taken.contains(a));
    const QList<qint64> wf = w.host.finals.value(a);
    CHECK(!wf.isEmpty());
    CHECK_EQ(w.chargesOf(a).size(), 1);
    CHECK_EQ(w.chargesOf(a).value(0, -1), wf.value(0, -2)); // the final total that came with a poll
    CHECK(w.chargesOf(a).value(0, -1) >= w.host.spentOf(a));
    CHECK_EQ(w.ledgerEntriesOf(w.grantOf(a)), 0);
    CHECK_EQ(w.s->hostRecords(), 0);
    CHECK(!w.s->machine().draining());

    g_case = QStringLiteral("r2_lost_acceptance_no_answer");
    World n(capsMac(), ScanNetKind::Cellular, 6);
    HostPlan np;
    np.steps = {{QStringLiteral("scan_start"), 1, 800, 0, true}};
    np.loseRest = true;                            // and nothing about it is ever answered again
    retriedStartWorld(n, &np);
    n.run(2150);
    n.s->stop();
    n.run(12000);
    const qint64 g = n.grantOf(np.scan);
    CHECK(g > 0);
    CHECK_EQ(n.chargesOf(np.scan).size(), 1);
    CHECK_EQ(n.chargesOf(np.scan).value(0, -1), g); // never zero by default: the whole grant
    CHECK_EQ(n.ledgerEntriesOf(g), 1);              // once
    CHECK(n.sentFor("scan_poll", np.scan) >= 1);    // it was asked (bounded)
    n.run(30000);
    CHECK_EQ(n.ledgerEntriesOf(g), 1);
    CHECK_EQ(n.s->hostRecords(), 0);
    CHECK(n.s->pollsActive() == 0 && !n.s->machine().draining());

    // Its acceptance not answered within the start's bound (scan_stop_ms): the whole grant; the "accepted" that comes
    // after is told to stop (one cancel) and adds nothing.
    g_case = QStringLiteral("late_ack_after_conservative");
    World c(capsMac(), ScanNetKind::Cellular, 6);
    HostPlan cp;
    cp.steps = {{QStringLiteral("scan_start"), 1, 0, 9000, false}, // taken at once, answered 9 s later
                {QStringLiteral("scan_cancel"), 0, 0, 0, true}};   // the first cancel's answer lost
    retriedStartWorld(c, &cp);
    c.run(2150);
    c.s->stop();
    c.run(8500);                                   // 10.7 s: the bound passed
    const qint64 cg = c.grantOf(cp.scan);
    CHECK_EQ(c.chargesOf(cp.scan).size(), 1);
    CHECK_EQ(c.chargesOf(cp.scan).value(0, -1), cg);
    const int cc = c.sentFor("scan_cancel", cp.scan);
    c.run(3000);                                   // the late "accepted" at ~11 s
    CHECK_EQ(c.sentFor("scan_cancel", cp.scan), cc + 1);
    CHECK_EQ(c.chargesOf(cp.scan).size(), 1);
    CHECK_EQ(c.ledgerEntriesOf(cg), 1);
    c.run(10000);
    CHECK_EQ(c.s->hostRecords(), 0);

    // The retried start refused, that refusal LOST: unknown_scan to a cancel sent after the (empty) answer proves it
    // never ran - zero, not the grant.
    g_case = QStringLiteral("lost_refusal_unknown_is_zero");
    World z(capsMac(), ScanNetKind::Cellular, 6);
    z.host.startNotNow = {kStopPending, kStopPending};
    HostPlan zp;
    zp.steps = {{QStringLiteral("scan_start"), 1, 0, 800, true}};
    retriedStartWorld(z, &zp);
    z.run(2150);
    z.s->stop();
    z.run(6000);
    CHECK(!z.host.taken.contains(zp.scan));
    CHECK(z.sentFor("scan_cancel", zp.scan) >= 2);
    CHECK(z.chargesOf(zp.scan).isEmpty());
    CHECK_EQ(z.ledgerEntriesOf(z.grantOf(zp.scan)), 0);
    CHECK_EQ(z.s->hostRecords(), 0);
}

// R3: the retried start was taken, its acknowledgement is late; the stop settles it (its final, charged), the network
// changes, then the late acknowledgement comes: no second cancel, no second charge.
static void caseLateAckAfterSettled()
{
    g_case = QStringLiteral("r3_late_ack_after_settled");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    w.host.cancel = FakeHost::Cancel::FinalInAck;  // the engine: the final total in the cancel ack, and the SAME again
    HostPlan wp;
    wp.steps = {{QStringLiteral("scan_start"), 1, 0, 3000, false}};
    retriedStartWorld(w, &wp);
    const QString a = wp.scan;
    w.run(2150);
    w.s->stop();
    w.run(700);
    const QList<qint64> wf = w.host.finals.value(a);
    CHECK(!wf.isEmpty());
    CHECK_EQ(w.chargesOf(a).size(), 1);
    w.engine.net.appSources[0].counter = 9;        // the network changes before the late acknowledgement
    w.s->networkChanged();
    const int cancels = w.sentFor("scan_cancel", a);
    w.run(10000);                                  // the late "accepted" arrives at ~5 s
    CHECK_EQ(w.sentFor("scan_cancel", a), cancels);
    CHECK_EQ(w.chargesOf(a).size(), 1);
    CHECK_EQ(w.chargesOf(a).value(0, -1), wf.value(0, -2));
    CHECK_EQ(w.ledgerEntriesOf(wf.value(0, -2)), 1);
    CHECK_EQ(w.s->hostRecords(), 0);

    g_case = QStringLiteral("r3_machine_settled_no_second_charge");
    World m(capsMac(), ScanNetKind::Cellular, 6);
    m.host.cancel = FakeHost::Cancel::FinalInAck;
    m.host.freeze = FakeHost::Freeze::NoAck;       // the machine settles by its own rule: the whole grant
    HostPlan mp;
    retriedStartWorld(m, &mp);
    m.run(2150);                                   // the retry answered at once: the machine owns it
    m.s->stop();
    m.run(3000);
    const qint64 mg = m.grantOf(mp.scan);
    CHECK(mg > 0);
    CHECK_EQ(m.ledgerEntriesOf(mg), 0);            // the grant only inside the machine's one entry (with the app side)
    CHECK(m.chargesOf(mp.scan).isEmpty());         // the machine charged it; nothing here
    m.run(10000);
    CHECK(m.chargesOf(mp.scan).isEmpty());
    CHECK_EQ(m.s->hostRecords(), 0);
}

// An unknown_scan that overtook a start still in flight proves nothing: the start is taken later - its final total
// is charged, never zero.
static void caseUnknownOvertakesStart()
{
    g_case = QStringLiteral("unknown_scan_overtakes_start");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    HostPlan wp;
    wp.steps = {{QStringLiteral("scan_start"), 1, 800, 0, false}, {QStringLiteral("scan_cancel"), 0, 0, 0, false}};
    retriedStartWorld(w, &wp);
    const QString a = wp.scan;
    w.run(2150);
    w.s->stop();
    w.run(300);
    CHECK(w.chargesOf(a).isEmpty());               // the first cancel's unknown_scan settled nothing
    w.run(8000);
    const QList<qint64> wf = w.host.finals.value(a);
    CHECK(!wf.isEmpty() && wf.value(0) > 0);
    CHECK_EQ(w.chargesOf(a).size(), 1);
    CHECK_EQ(w.chargesOf(a).value(0, -1), wf.value(0, -2));
    CHECK_EQ(w.s->hostRecords(), 0);
}

// Duplicate final totals (a cancel ack with its final, a poll's final, the engine's repeated cancel) in any order: the
// host scan is charged once, at that total.
static void caseDuplicateFinals()
{
    struct Order {
        const char *name;
        QList<HostPlan::Step> steps;
    };
    const QList<Order> orders = {
        // the poll's final first, the first cancel's ack (with the same final) after it
        {"poll_then_cancel_ack", {{QStringLiteral("scan_start"), 1, 0, 600, false}, {QStringLiteral("scan_cancel"), 0, 0, 1500, false}}},
        // the cancel ack's final first, a poll in flight brings it again
        {"cancel_ack_then_poll", {{QStringLiteral("scan_start"), 1, 0, 600, false}, {QStringLiteral("scan_cancel"), 0, 0, 1200, false},
                                  {QStringLiteral("scan_poll"), 0, 0, 1000, false}}},
        // the first cancel's answer lost: a second cancel (the engine answers the same final again) and the polls
        {"repeated_cancel", {{QStringLiteral("scan_start"), 1, 0, 600, false}, {QStringLiteral("scan_cancel"), 0, 0, 50, true},
                             {QStringLiteral("scan_poll"), 0, 0, 700, false}}},
    };
    for (const Order &o : orders) {
        g_case = QStringLiteral("duplicate_finals_%1").arg(QLatin1String(o.name));
        World w(capsMac(), ScanNetKind::Cellular, 6);
        w.host.cancel = FakeHost::Cancel::FinalInAck;
        HostPlan p;
        p.steps = o.steps;
        retriedStartWorld(w, &p);
        w.run(2150);
        w.s->stop();
        w.run(8000);
        const QList<qint64> f = w.host.finals.value(p.scan);
        CHECK(f.size() >= 2);                      // the host did report it more than once
        for (qint64 x : f)
            CHECK_EQ(x, f.value(0));               // the same total each time (the engine's rule)
        CHECK_EQ(w.chargesOf(p.scan).size(), 1);
        CHECK_EQ(w.chargesOf(p.scan).value(0, -1), f.value(0, -2));
        CHECK_EQ(w.ledgerEntriesOf(f.value(0, -2)), 1);
        CHECK_EQ(w.s->hostRecords(), 0);
    }
}

// The settlement record's bound: a host that never answers one message (against IScanHost's rule) - the record is
// forgotten scan_stop_ms after it settled; the very late answer then changes nothing.
static void caseRecordBound()
{
    g_case = QStringLiteral("record_forgotten_at_bound");
    World w(capsMac(), ScanNetKind::Cellular, 6);
    HostPlan p;
    p.steps = {{QStringLiteral("scan_start"), 1, 0, 300, false}, {QStringLiteral("scan_cancel"), 0, 0, 600000, false}};
    retriedStartWorld(w, &p);
    w.run(2150);
    w.s->stop();
    w.run(4000);
    CHECK_EQ(w.chargesOf(p.scan).size(), 1);       // settled by a poll's final; the first cancel still unanswered
    CHECK_EQ(w.s->hostRecords(), 1);
    w.run(10000);
    CHECK_EQ(w.s->hostRecords(), 0);               // forgotten within scan_stop_ms of settling
    w.run(600000);                                 // the cancel's answer finally comes
    CHECK_EQ(w.chargesOf(p.scan).size(), 1);
    CHECK_EQ(w.s->hostRecords(), 0);
}

// R1 exactly: scan A's scan_add is refused "not now", but that answer arrives only after a network change started
// scan B with the SAME provider profiles. B is never touched; A's add is not sent again; every seat released once.
static void caseLateAddRefusal()
{
    g_case = QStringLiteral("r1_add_refusal_after_network_change");
    World w(capsMac(), ScanNetKind::Wifi, 2); // one own Xray burst (4 legs) leaves the leg pool room for the adds
    w.host.addNotNow = {kStopPending};
    for (const QString &pid : kPids)               // B's provider probes still run when A's refusal arrives
        w.host.outcomes[QStringLiteral("up:") + pid].durMs = 4000;
    HostPlan p;
    p.steps = {{QStringLiteral("scan_add"), 0, 0, 1500, false}}; // A's first add: refused at once, the answer 1.5 s later
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.host.script = [&p](const QJsonObject &o, int &proc, int &after, bool &lose) { return p.apply(o, proc, after, lose); };
    p.scan = QStringLiteral("-"); // set below, before the first add
    w.s->open();
    w.run(20);
    p.scan = w.s->machine().scanId();
    const QString a = p.scan;
    w.run(380);
    const int aAdds = w.sentFor("scan_add", a);
    CHECK(aAdds >= 1);                             // A's first add is out, its answer not in yet
    w.engine.net.appSources[0].counter = 7;        // the network changes: scan B, the same profiles
    w.s->networkChanged();
    w.run(20000);
    CHECK(w.s->machine().scanId() != a);
    CHECK_EQ(w.sentFor("scan_add", a), aAdds);     // A's refused add never sent again
    for (int i = 0; i < kPids.size(); ++i)         // and never refused B's candidates
        CHECK_EQ(w.row(QStringLiteral("up:") + kPids.at(i)).value("state").toString(), QStringLiteral("works"));
    for (const QString &e : w.hostEvents)
        CHECK(!e.startsWith(QLatin1String("candidate_refused")));
    CHECK_EQ(w.server.releasedLeases.size(), 6);   // A's three and B's three, each once
    CHECK_EQ(QSet<QString>(w.server.releasedLeases.begin(), w.server.releasedLeases.end()).size(), 6);
    CHECK_EQ(w.crossEvents, 0);
}

static void longProbes(World &w, int ms)
{
    for (const QString &id : w.host.outcomes.keys())
        w.host.outcomes[id].durMs = ms;
}

static bool scanning(const World &w) { return w.phase() == QLatin1String("reach") || w.phase() == QLatin1String("data"); }

// Review 16.11 (progress before ownership): scan A's second poll is taken at once on G1 and answered 1.2 s later; the
// host's path monitor counts a change meanwhile (G1 -> G2, scan B starts on G2); A's answer (G1) comes while A still
// drains. It settles A's bytes only: B is neither cancelled nor restarted, the tuple keeps G2, A is charged once.
static void caseLateProgressOfOlderScan()
{
    g_case = QStringLiteral("late_progress_of_older_scan");
    World w;
    w.host.genKnown = true;                        // G1 (counter 1) joins the tuple at the open
    longProbes(w, 6000);                           // B still runs when A's answer arrives
    HostPlan p;
    p.scan = QStringLiteral("-");
    p.steps = {{QStringLiteral("scan_poll"), 1, 0, 1200, false}};
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.host.script = [&p](const QJsonObject &o, int &proc, int &after, bool &lose) { return p.apply(o, proc, after, lose); };
    w.s->open();
    w.run(20);
    const QString a = w.s->machine().scanId();
    p.scan = a;
    for (int i = 0; i < 300 && w.sentFor("scan_poll", a) < 2; ++i)
        w.run(10);
    CHECK_EQ(w.sentFor("scan_poll", a), 2);        // A's held poll is out: answered on G1
    w.host.gen.counter = 2;                        // G2
    w.host.onGenerationChanged();
    w.run(300);
    const QString b = w.s->machine().scanId();
    CHECK(b != a);
    CHECK_EQ(w.host.count("scan_start"), 2);
    CHECK(scanning(w));
    CHECK(w.s->machine().draining());              // A is still polled: its answer reaches onPollReply
    const QString aProgress = QStringLiteral("host_progress ") + a;
    const int before = w.hostEvents.count(aProgress);
    w.run(1000);                                   // A's answer (G1) arrives
    CHECK(w.hostEvents.count(aProgress) > before); // delivered: A's bytes
    CHECK_EQ(w.s->machine().scanId(), b);          // B neither restarted...
    CHECK_EQ(w.host.count("scan_start"), 2);
    CHECK_EQ(w.sentFor("scan_freeze", b), 0);      // ...nor cancelled
    CHECK_EQ(w.sentFor("scan_cancel", b), 0);
    CHECK(scanning(w));
    const ScanNetSource *in = scanNetSourceOf(w.s->lastNetwork().sources, QStringLiteral("service"));
    CHECK(in != nullptr && in->counter == 2);      // the tuple keeps G2
    w.run(20000);
    CHECK_EQ(w.phase(), QStringLiteral("done"));
    CHECK_EQ(w.host.count("scan_start"), 2);
    CHECK(!w.s->machine().draining());
    CHECK_EQ(w.host.finals.value(a).size(), 1);    // A ended at the host, reported its final once
    CHECK(w.chargesOf(a).isEmpty());               // the machine settled A; nothing charged here as well
    CHECK_EQ(w.ledgerCount(), 2);                  // one ledger entry for A, one for B
    CHECK_EQ(w.s->hostRecords(), 0);
    CHECK_EQ(w.crossEvents, 0);

    // Ownership on its own: A's held poll is taken only after the path moved on again (G3), so its late answer
    // carries a NEWER element than B's G2. It still settles only A: B is restarted by its OWN next report of G3.
    g_case = QStringLiteral("late_progress_newer_gen_of_older_scan");
    World n;
    n.host.genKnown = true;
    longProbes(n, 6000);
    QString sa = QStringLiteral("-"), sb = QStringLiteral("-");
    int aPolls = 0, bPolls = 0;
    n.host.script = [&](const QJsonObject &o, int &proc, int &after, bool &lose) {
        if (o.value("action").toString() != QLatin1String("scan_poll"))
            return false;
        const QString id = o.value("scan_id").toString();
        lose = false;
        if (id == sa && aPolls++ == 1) { // A's second poll: taken 900 ms later, answered at once
            proc = 900;
            after = 0;
            return true;
        }
        if (id == sb && bPolls++ == 0) { // B's first poll: taken at once (G2), answered after A's
            proc = 0;
            after = 700;
            return true;
        }
        return false;
    };
    n.liveOn(QStringLiteral("4:xray"));
    n.start();
    n.s->open();
    n.run(20);
    const QString na = n.s->machine().scanId();
    sa = na;
    for (int i = 0; i < 300 && n.sentFor("scan_poll", na) < 2; ++i)
        n.run(10);
    CHECK_EQ(n.sentFor("scan_poll", na), 2);
    const qint64 t0 = n.clock.t;
    n.host.gen.counter = 2;                        // G2: B starts
    n.host.onGenerationChanged();
    const QString nb = n.s->machine().scanId();
    CHECK(nb != na);
    sb = nb;
    n.ev.at(800, [&n]() { n.host.gen.counter = 3; }); // G3, before the host takes A's held poll
    n.runUntil(t0 + 790);
    CHECK_EQ(n.sentFor("scan_poll", nb), 1);       // B's only poll so far is out, answered on G2
    n.runUntil(t0 + 905);                          // A's answer (G3) has come
    CHECK_EQ(n.s->machine().scanId(), nb);         // it did not restart B
    CHECK_EQ(n.sentFor("scan_freeze", nb), 0);
    in = scanNetSourceOf(n.s->lastNetwork().sources, QStringLiteral("service"));
    CHECK(in != nullptr && in->counter == 2);
    n.run(1500);                                   // B's own next report of G3
    in = scanNetSourceOf(n.s->lastNetwork().sources, QStringLiteral("service"));
    CHECK(in != nullptr && in->counter == 3);
    CHECK(n.s->machine().scanId() != nb);
    n.run(20000);
    CHECK(!n.s->machine().draining());
    CHECK_EQ(n.host.finals.value(na).size(), 1);
    CHECK(n.chargesOf(na).isEmpty());
    CHECK_EQ(n.s->hostRecords(), 0);
    CHECK_EQ(n.crossEvents, 0);
}

static int manifestCalls(const World &w)
{
    int n = 0;
    for (const IScanHttp::Request &r : w.server.calls)
        n += r.url.contains(QLatin1String("/v1/scan/manifest")) ? 1 : 0;
    return n;
}

// Review 16.11 (the same shape in scan_caps): an iOS-like host reports its element in scan_caps and scan_progress. A
// caps query is taken at once on G1 and answered 1.5 s later; meanwhile the current scan's progress moves the element
// to G2 (a higher counter, or a new monitor start) and B's manifest waits for that caps answer. The late G1 never
// moves the tuple back (before: G1 restored, B retargeted to it, then G2 again - two more network changes, two more
// manifest fetches): B is fetched once and runs on G2, nothing restarts it. Then the last caps element (G1, from the
// open) is read again on an availability event: still the past, the result stays.
static void caseLateCapsGen()
{
    for (const bool newEpoch : {false, true}) {
        g_case = QStringLiteral("late_caps_gen_%1").arg(QLatin1String(newEpoch ? "left_epoch" : "older_counter"));
        World w;
        w.host.capsGen = true;
        longProbes(w, 3000);
        int caps = 0;
        int holdCaps = -1;
        w.host.script = [&caps, &holdCaps](const QJsonObject &o, int &proc, int &after, bool &lose) {
            if (o.value("action").toString() != QLatin1String("scan_caps") || caps++ != holdCaps)
                return false;
            proc = 0;
            after = 1500;
            lose = false;
            return true;
        };
        w.liveOn(QStringLiteral("4:xray"));
        w.start();                                 // the construction's caps: G1 known before the open
        w.run(20);
        w.s->open();                               // G1 joins the tuple
        w.run(1200);
        const QString a = w.s->machine().scanId();
        CHECK(scanning(w));
        holdCaps = caps;
        const qint64 tHold = w.clock.t;
        w.host.onAvailabilityChanged();            // still available: scan_caps asked again (held, G1)
        w.run(10);
        CHECK_EQ(w.host.count("scan_caps"), holdCaps + 1);
        if (newEpoch) {
            w.host.gen.epoch = 0x7a7a7a7a7a7a7a7aULL; // the extension restarted: a new monitor start
            w.host.gen.counter = 0;
        } else {
            w.host.gen.counter = 2;
        }
        const ScanNetSource g2 = w.host.gen;
        w.run(600);                                // A's next progress carries G2: A ends, B waits for the caps
        CHECK(w.s->machine().scanId() != a);
        const int fetched = manifestCalls(w);      // A's and B's
        w.runUntil(tHold + 1500);                  // the held caps answer (G1) has just come
        const ScanNetSource *in = scanNetSourceOf(w.s->lastNetwork().sources, QStringLiteral("service"));
        CHECK(in != nullptr && *in == g2);         // the tuple keeps G2
        w.run(2000);                               // B started
        const QString b = w.s->machine().scanId();
        CHECK_EQ(w.host.count("scan_start"), 2);
        CHECK_EQ(manifestCalls(w), fetched);       // no manifest fetched again for a restored G1
        in = scanNetSourceOf(w.s->lastNetwork().sources, QStringLiteral("service"));
        CHECK(in != nullptr && *in == g2);
        w.run(20000);
        CHECK_EQ(w.s->machine().scanId(), b);
        CHECK_EQ(w.host.count("scan_start"), 2);   // B never restarted
        CHECK_EQ(w.phase(), QStringLiteral("done"));
        w.host.onAvailabilityChanged();            // the last caps element read again (G1 from the open)
        w.run(50);
        in = scanNetSourceOf(w.s->lastNetwork().sources, QStringLiteral("service"));
        CHECK(in != nullptr && *in == g2);
        CHECK_EQ(w.phase(), QStringLiteral("done")); // the result is not voided as "network changed"
        CHECK_EQ(w.crossEvents, 0);
    }
}

// --- property: random answer ORDERS for one start / "not now" retry / stop / network change sequence ---------------
struct Rng {
    quint64 s;
    explicit Rng(quint64 seed) : s(seed * 0x9E3779B97F4A7C15ULL + 0x2545F4914F6CDD1DULL) {}
    quint64 next()
    {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    int in(int lo, int hi) { return lo + int(next() % quint64(hi - lo + 1)); }
    bool chance(int pct) { return in(0, 99) < pct; }
};

static const QList<QByteArray> kNotNowAll = {kStopPending, kTunnelChanged, kStaleEpoch, kStopping};

// Every message of scan A (after its first, refused start) is taken at a random moment, answered at a random moment
// later, or its answer lost; a "not now" retry, a stop and a network change land at random moments.
struct RandomRun {
    QString a;
    bool viaStop = false;
    int httpAtChange = -1;
};

static void randomSequence(World &w, Rng &rng, RandomRun &run, bool cellularFirst)
{
    w.host.replaceForgets = true;
    w.host.cancel = rng.chance(50) ? FakeHost::Cancel::FinalInAck : FakeHost::Cancel::FinalInPoll;
    w.host.startNotNow = {kNotNowAll.at(rng.in(0, kNotNowAll.size() - 1))};
    w.start();
    w.host.script = [&w, &rng, &run](const QJsonObject &o, int &proc, int &after, bool &lose) {
        if (run.a.isEmpty() || o.value("scan_id").toString() != run.a)
            return false;
        proc = rng.in(0, 2500);
        after = rng.in(0, 2500);
        lose = rng.chance(25);
        Q_UNUSED(w);
        return true;
    };
    w.s->open();
    w.run(200); // A's first scan_start went out (~80 ms) and was refused "not now"
    run.a = w.s->machine().scanId();
    const auto change = [&w, &run, cellularFirst]() {
        run.httpAtChange = w.http.sent.size();
        if (cellularFirst) {
            w.engine.net.kind = ScanNetKind::Wifi;
            w.engine.net.reportingKey = QStringLiteral("wifi");
        }
        w.engine.net.appSources[0].counter += 1;
        w.s->networkChanged();
    };
    if (rng.chance(80)) // the tunnel's report (tunnel_changed / stale_epoch wait for it; sometimes it never comes)
        w.ev.at(rng.in(0, 2400), [&w]() { w.s->engineStateChanged(); });
    const int tEnd = rng.in(0, 6000);
    run.viaStop = rng.chance(50);
    if (run.viaStop) {
        w.ev.at(tEnd, [&w]() { w.s->stop(); });
        const int tNet = tEnd + rng.in(0, 3000);
        w.ev.at(tNet, change);
        w.ev.at(tNet + rng.in(1100, 2500), [&w]() { w.s->open(); });
    } else {
        w.ev.at(tEnd, change);
        w.ev.at(tEnd + rng.in(1100, 2500), [&w]() { w.s->open(); }); // a no-op while B scans
    }
    w.run(45000);
}

// (a) no machine event of scan B caused by an answer of scan A; (b) per host scan id the ledger got its host charge
// exactly once and never below what the engine reported or spent; settlement records all forgotten.
static void propertyBytes()
{
    int withB = 0, coordinatorSettled = 0;
    for (int seed = 1; seed <= 200; ++seed) {
        g_case = QStringLiteral("property_bytes_seed_%1").arg(seed);
        Rng rng{quint64(seed)};
        RandomRun run;
        World w(capsMac(), ScanNetKind::Cellular, 2);
        w.server.upstream = QJsonArray(); // no seats here: every cellular byte is A's manifest or A's host scan
        for (int i = 0; i < 2; ++i)
            w.host.outcomes[QStringLiteral("%1:xray").arg(4 + i)].durMs = 60000;
        randomSequence(w, rng, run, true);
        const QString a = run.a;
        withB += w.s->machine().scanId() != a ? 1 : 0;
        coordinatorSettled += w.chargesOf(a).isEmpty() ? 0 : 1;
        // A ran on cellular, everything after the change on Wi-Fi: the cellular entries are A's alone.
        qint64 appA = 0;
        for (int i = 0; i < run.httpAtChange && i < w.http.sent.size(); ++i)
            appA += w.http.sent.at(i).resp.bytes;
        const qint64 hostA = w.ledgerSum(1) - appA;
        const qint64 g = w.grantOf(a);
        QSet<qint64> allowed{g};
        for (qint64 f : w.host.finals.value(a))
            allowed << f;
        for (qint64 b : w.host.freezeBounds.value(a))
            allowed << b;
        if (!w.host.taken.contains(a))
            allowed << 0;
        qint64 floor = w.host.spentOf(a);
        for (qint64 f : w.host.finals.value(a))
            floor = qMax(floor, f);
        const bool once = allowed.contains(hostA);
        CHECK(once);                               // exactly one of its legitimate charges - never two of them
        CHECK(hostA >= floor);                     // never below its final total / what it spent
        if (!once || hostA < floor)
            std::fprintf(stderr, "  seed %d: host charge %lld (grant %lld, floor %lld, taken %d, finals %d, coordinator %d)\n",
                         seed, (long long)hostA, (long long)g, (long long)floor, int(w.host.taken.contains(a)),
                         int(w.host.finals.value(a).size()), int(w.chargesOf(a).size()));
        CHECK(w.chargesOf(a).size() <= 1);
        CHECK_EQ(w.crossEvents, 0);
        CHECK_EQ(w.s->hostRecords(), 0);
        CHECK(!w.s->machine().draining());
    }
    g_case = QStringLiteral("property_bytes_coverage");
    CHECK(withB >= 50);                            // the sequence did start scan B in many runs
    CHECK(coordinatorSettled >= 20);               // and handed unanswered starts to the coordinator in many
    std::printf("property_bytes: 200 runs, scan B in %d, coordinator-settled in %d\n", withB, coordinatorSettled);
}

// (a) and (c) with seats: every lease id granted is released, once.
static void propertySeats()
{
    int withB = 0;
    for (int seed = 1; seed <= 120; ++seed) {
        g_case = QStringLiteral("property_seats_seed_%1").arg(seed);
        Rng rng{quint64(seed) + 1000};
        RandomRun run;
        World w(capsMac(), ScanNetKind::Wifi, 2);
        for (int i = 0; i < 2; ++i)
            w.host.outcomes[QStringLiteral("%1:xray").arg(4 + i)].durMs = 60000;
        for (const QString &pid : kPids)
            w.host.outcomes[QStringLiteral("up:") + pid].durMs = rng.chance(50) ? 60000 : 1500;
        if (rng.chance(50))
            w.host.addNotNow = {kNotNowAll.at(rng.in(0, kNotNowAll.size() - 1))};
        randomSequence(w, rng, run, false);
        withB += w.s->machine().scanId() != run.a ? 1 : 0;
        QSet<QString> released;
        for (const QString &l : w.server.releasedLeases)
            released << l;
        CHECK_EQ(released.size(), w.server.releasedLeases.size()); // no seat released twice
        for (int i = 1; i <= w.server.leaseSerial; ++i)
            CHECK(released.contains(QStringLiteral("LEASEIDLEASEIDLEASEIDLEASEID%1").arg(i, 4, 10, QLatin1Char('0'))));
        CHECK_EQ(w.crossEvents, 0);
        CHECK_EQ(w.s->hostRecords(), 0);
    }
    g_case = QStringLiteral("property_seats_coverage");
    CHECK(withB >= 30);
    std::printf("property_seats: 120 runs, scan B in %d\n", withB);
}

// --- review F1 / F5 / F2: replies bound to their scan, the wire allowance of a probe ------------------------

// F1: a live-probe result that comes after the network changed (a new scan probes the same live node) never
// proves the new scan's row; its bytes are still accounted.
static void caseStaleLiveProbe()
{
    g_case = QStringLiteral("stale_live_probe");
    World w;
    // runner calls: A warm 50 ms, A data 3000 ms (good, late), B warm 50 ms, B data 4000 ms (BAD digest)
    w.liveScript = {{50, false}, {3000, false}, {50, false}, {4000, true}};
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(400);
    CHECK_EQ(w.liveProbes.size(), 2);           // A's data request is in flight
    const QString a = w.s->machine().scanId();
    w.engine.net.appSources[0].counter = 7;    // the network changes: scan B
    w.s->networkChanged();
    w.run(20000);
    CHECK(w.s->machine().scanId() != a);
    CHECK_EQ(w.liveProbes.size(), 4);
    CHECK(w.liveUnprovenSettled(QStringLiteral("4:xray"))); // only B's own (bad) result counts
    CHECK(w.logsClean());
}

// F5: a probe-batch reply that comes after the network changed never touches the new scan: its seats are
// released at once, the new scan's leases and verdicts stay its own.
static void caseStaleBatch()
{
    g_case = QStringLiteral("stale_batch");
    World w(capsMac(), ScanNetKind::Wifi, 4);
    w.server.batchLatency = 1500;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->open();
    w.run(300);
    CHECK_EQ(w.http.count("/v1/upstream/lease/probe-batch"), 1); // A's batch in flight
    w.engine.net.appSources[0].counter = 7;
    w.s->networkChanged();
    w.run(1400); // A's reply (granted 0001..0003) arrives; B's is still in flight
    QStringList aLeases;
    for (int i = 1; i <= 3; ++i)
        aLeases << QStringLiteral("LEASEIDLEASEIDLEASEIDLEASEID%1").arg(i, 4, 10, QLatin1Char('0'));
    for (const QString &l : aLeases)
        CHECK(w.server.releasedLeases.contains(l)); // released at once, not handed to scan B
    CHECK_EQ(w.host.count("scan_add"), 0);         // nothing of A reached B's host scan
    w.run(20000);
    for (int i = 0; i < kPids.size(); ++i)
        CHECK_EQ(w.row(QStringLiteral("up:") + kPids.at(i)).value("state").toString(), QStringLiteral("works"));
    // B's grants (0004..0006) were probed with their own lease ids and released by B
    const QJsonObject *add = w.host.lastRequest("scan_add");
    CHECK(add != nullptr);
    for (int i = 4; i <= 6; ++i)
        CHECK(w.server.releasedLeases.contains(QStringLiteral("LEASEIDLEASEIDLEASEIDLEASEID%1").arg(i, 4, 10, QLatin1Char('0'))));
    CHECK_EQ(w.server.releasedLeases.size(), 6);
}

// F2: the live-tunnel probe's allowance is enforced on the wire (headers + body as read, aborted at once) and
// the ledger gets what really came - an oversized error body, oversized headers - never a clamped figure.
static void caseWireCap()
{
    g_case = QStringLiteral("wire_cap");
    QTcpServer srv;
    CHECK(srv.listen(QHostAddress::LocalHost, 0));
    QString mode = QStringLiteral("big_error");
    qint64 streamed = 0;
    QObject::connect(&srv, &QTcpServer::newConnection, [&srv, &mode, &streamed]() {
        while (QTcpSocket *c = srv.nextPendingConnection()) {
            QObject::connect(c, &QTcpSocket::readyRead, c, [c, &mode, &streamed]() {
                c->readAll();
                if (mode == QLatin1String("stream")) {
                    // an unbounded body: written as fast as the socket takes it, until the client goes
                    c->write("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
                    auto *t = new QTimer(c);
                    QObject::connect(t, &QTimer::timeout, c, [c, &streamed]() {
                        if (c->state() != QAbstractSocket::ConnectedState || c->bytesToWrite() > 262144)
                            return;
                        const QByteArray chunk(65536, 's');
                        streamed += c->write(chunk);
                    });
                    t->start(2);
                    return;
                }
                if (mode == QLatin1String("big_headers")) {
                    c->write("HTTP/1.1 200 OK\r\nX-Pad: " + QByteArray(60000, 'h') + "\r\nContent-Length: 4\r\n\r\nbody");
                } else {
                    const QByteArray body(200000, 'e');
                    c->write("HTTP/1.1 503 Service Unavailable\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n\r\n");
                    c->write(body);
                }
            });
        }
    });
    QNetworkAccessManager nam;
    UpstreamLeaseClient lease;
    lease.configure(&nam, []() { return QString(); }, QString(), []() { return QString(); });
    const QString base = QStringLiteral("http://127.0.0.1:%1").arg(srv.serverPort());
    const auto run = [&](qint64 cap, qint64 bytes) {
        UpstreamLeaseClient::ProbeRequest r;
        r.base = base;
        r.scanToken = QStringLiteral("tsc1.test");
        r.bytes = bytes;
        r.nonce = scanProbeNonce();
        r.timeoutMs = 5000;
        r.maxWireBytes = cap;
        bool done = false;
        UpstreamProbeFacts got;
        lease.runProbe(r, [&](const UpstreamProbeFacts &f) {
            got = f;
            done = true;
        });
        QElapsedTimer t;
        t.start();
        while (!done && t.elapsed() < 6000)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        CHECK(done);
        return got;
    };
    // an oversized error body: cut at the allowance, the count is what was read (one chunk past it at most)
    UpstreamProbeFacts e = run(30000, 65536);
    CHECK(e.cutAtCap);
    CHECK(e.wireBytes <= 30000);             // the app never READ more than the allowance
    CHECK(e.wireBytes > 30000 - 16384);
    // oversized headers: counted, cut
    mode = QStringLiteral("big_headers");
    UpstreamProbeFacts h = run(30000, 65536);
    CHECK(h.cutAtCap);
    CHECK(h.wireBytes >= 60000);
    // an unbounded streamed body: the bytes the app reads never pass the allowance, whatever the peer sends
    mode = QStringLiteral("stream");
    UpstreamProbeFacts st = run(30000, 65536);
    CHECK(st.cutAtCap);
    CHECK(st.wireBytes <= 30000);
    CHECK(streamed > st.wireBytes); // the peer did send more: it never reached the app
    mode = QStringLiteral("big_error");
    // no allowance (the upstream session's data check): today's behaviour - the body bounded by `bytes` only
    mode = QStringLiteral("big_error");
    UpstreamProbeFacts d = run(-1, 65536);
    CHECK(!d.cutAtCap);
    CHECK(d.bytesReceived > 65536); // read until past `bytes`, then aborted, as before

    // the coordinator's live probe through the real runner: the ledger figure is what came, past the allowance
    mode = QStringLiteral("big_headers");
    ScanSettingsStore store;
    ScanApiClient api(nullptr, &store);
    api.configure([]() { return QString(); }, []() { return QString(); }, []() { return QString(); });
    api.setNetworkManager(&nam);
    ScanProbeFacts got;
    bool done = false;
    const qint64 cost = 40000;
    api.liveProbe(base, QStringLiteral("tsc1.test"), QString(), 1024, 65536, cost, 5000, [&](const ScanProbeFacts &f) {
        got = f;
        done = true;
    });
    QElapsedTimer t;
    t.start();
    while (!done && t.elapsed() < 6000)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    CHECK(done);
    CHECK(got.error == ScanProbeError::Budget);
    CHECK(got.spentBytes > cost);                 // reported as is, never clamped to the allowance
    CHECK(got.spentBytes <= 8192 + 60000 + 512);  // and the transfer stopped at the headers
    // an oversized error body: stopped by the warm request's own body bound, counted as read
    mode = QStringLiteral("big_error");
    done = false;
    api.liveProbe(base, QStringLiteral("tsc1.test"), QString(), 1024, 65536, cost, 5000, [&](const ScanProbeFacts &f) {
        got = f;
        done = true;
    });
    t.restart();
    while (!done && t.elapsed() < 6000)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    CHECK(done);
    CHECK_EQ(got.httpStatus, 503);
    CHECK(got.spentBytes > 8192 + 1024);          // more than the body asked for: what really came
    CHECK(got.spentBytes <= cost);
}

// The shade queue surface: a machine shade shows, hides after its hold, frees the slot.
static void caseShade()
{
    g_case = QStringLiteral("shade");
    World w;
    w.liveOn(QStringLiteral("4:xray"));
    w.start();
    w.s->showShade(QStringLiteral("warning"), QStringLiteral("test_key"), {QStringLiteral("1")});
    CHECK(w.s->shade().value("visible").toBool());
    CHECK_EQ(w.s->shade().value("text_key").toString(), QStringLiteral("test_key"));
    w.run(1600);
    CHECK(w.s->shade().value("visible").toBool() && !w.s->shade().value("leaving").toBool()); // the hold is 2.5 s
    w.run(1000);
    CHECK(w.s->shade().value("leaving").toBool() || !w.s->shade().value("visible").toBool());
    w.run(1000);
    CHECK(!w.s->shade().value("visible").toBool());
}

// The production HTTP layer cuts an answer the moment it would pass the request's reservation.
static void caseQnamCut()
{
    g_case = QStringLiteral("qnam_cut");
    QTcpServer srv;
    CHECK(srv.listen(QHostAddress::LocalHost, 0));
    QObject::connect(&srv, &QTcpServer::newConnection, [&srv]() {
        QTcpSocket *c = srv.nextPendingConnection();
        QObject::connect(c, &QTcpSocket::readyRead, c, [c]() {
            c->readAll();
            const QByteArray body(200000, 'z');
            c->write("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
                     + QByteArray::number(body.size()) + "\r\n\r\n");
            c->write(body);
        });
    });
    QNetworkAccessManager nam;
    ScanQnamHttp http(&nam);
    IScanHttp::Request rq;
    rq.url = QStringLiteral("http://127.0.0.1:%1/v1/scan/manifest").arg(srv.serverPort());
    rq.maxBytes = 30000;
    rq.timeoutMs = 5000;
    bool done = false;
    IScanHttp::Response got;
    http.send(rq, [&](const IScanHttp::Response &r) {
        got = r;
        done = true;
    });
    QElapsedTimer t;
    t.start();
    while (!done && t.elapsed() < 5000)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    CHECK(done);
    CHECK(got.cut);
    CHECK_EQ(got.status, 0);
    CHECK(got.bytes <= rq.maxBytes);
    CHECK(got.body.isEmpty());

    // and an answer inside the reservation is complete
    IScanHttp::Request ok = rq;
    ok.maxBytes = 400000;
    done = false;
    http.send(ok, [&](const IScanHttp::Response &r) {
        got = r;
        done = true;
    });
    t.restart();
    while (!done && t.elapsed() < 5000)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    CHECK(done && !got.cut && got.status == 200 && got.body.size() == 200000);
}

// Review 19.11 (provider seat price): QNAM's own "Accept-Encoding: gzip, deflate" hands over the INFLATED body, so
// every count and cut was the inflated size (a 7.5 KB provider config answer counted as 30-53 KB). The layer asks gzip
// itself: the count and the cut are wire bytes, the body is inflated here.
static QByteArray gzipOf(const QByteArray &plain)
{
    z_stream zs{};
    deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    QByteArray out(int(deflateBound(&zs, uLong(plain.size()))) + 32, '\0');
    zs.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(plain.constData()));
    zs.avail_in = uInt(plain.size());
    zs.next_out = reinterpret_cast<Bytef *>(out.data());
    zs.avail_out = uInt(out.size());
    deflate(&zs, Z_FINISH);
    out.resize(int(zs.total_out));
    deflateEnd(&zs);
    return out;
}

static void caseQnamGzip()
{
    g_case = QStringLiteral("qnam_gzip");
    QByteArray plain;
    for (int i = 0; plain.size() < 200000; ++i)
        plain += QByteArray("{\"domain\":\"example") + QByteArray::number(i % 977) + ".com\",\"outboundTag\":\"proxy\"},";
    const QByteArray gz = gzipOf(plain);
    QByteArray back;
    CHECK(gz.size() < plain.size() / 4 && scanGunzip(gz, kScanInflateMaxBytes, &back) && back == plain);
    CHECK(!scanGunzip(gz, plain.size() - 1, &back) && back.isEmpty()); // the inflate bound
    CHECK(!scanGunzip(gz.left(gz.size() / 2), kScanInflateMaxBytes, &back)); // a truncated stream
    CHECK(!scanGunzip(plain, kScanInflateMaxBytes, &back));                   // not gzip

    QTcpServer srv;
    CHECK(srv.listen(QHostAddress::LocalHost, 0));
    QByteArray seenEncoding;
    bool corrupt = false;
    QObject::connect(&srv, &QTcpServer::newConnection, [&]() {
        QTcpSocket *c = srv.nextPendingConnection();
        QObject::connect(c, &QTcpSocket::readyRead, c, [&, c]() {
            for (const QByteArray &l : c->readAll().split('\n'))
                if (l.toLower().startsWith("accept-encoding:"))
                    seenEncoding = l.mid(16).trimmed();
            const QByteArray body = corrupt ? gz.left(gz.size() / 2) : gz;
            c->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: "
                     + QByteArray::number(body.size()) + "\r\n\r\n");
            c->write(body);
        });
    });
    QNetworkAccessManager nam;
    ScanQnamHttp http(&nam);
    IScanHttp::Request rq;
    rq.method = QByteArrayLiteral("POST");
    rq.url = QStringLiteral("http://127.0.0.1:%1/v1/upstream/lease/probe-batch").arg(srv.serverPort());
    rq.body = "{}";
    rq.maxBytes = gz.size() + 16384; // far below the inflated size: a cut of the inflated count would abort it
    rq.timeoutMs = 5000;
    bool done = false;
    IScanHttp::Response got;
    const auto send = [&]() {
        done = false;
        http.send(rq, [&](const IScanHttp::Response &r) {
            got = r;
            done = true;
        });
        QElapsedTimer t;
        t.start();
        while (!done && t.elapsed() < 5000)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    };
    send();
    CHECK(done);
    CHECK_EQ(seenEncoding, QByteArray("gzip"));
    CHECK(!got.cut && got.status == 200 && got.body == plain);
    CHECK(got.bytes >= gz.size() && got.bytes <= rq.maxBytes); // wire bytes, not the inflated body
    corrupt = true;
    send();
    CHECK(done && got.status == 0 && got.body.isEmpty() && !got.canceled); // a body that does not inflate is no answer
}

// Coordinator 18.11: «Не удалось запустить проверку» while connected - POST /v1/scan/token cancelled by our own
// tunnel switch (net_error 5) ended the scan as manifest_unavailable. Such a request is sent again (bounded);
// a timeout, a byte cap or an HTTP answer ends as before.
static void caseScanCanceledRetryRule()
{
    CHECK(scanRetryCanceledRequest(0, /*canceled=*/true, 0));
    CHECK(scanRetryCanceledRequest(0, true, kScanCanceledRetries - 1));
    CHECK(!scanRetryCanceledRequest(0, true, kScanCanceledRetries));
    CHECK(!scanRetryCanceledRequest(0, /*canceled=*/false, 0)); // a timeout / transport error
    CHECK(!scanRetryCanceledRequest(503, true, 0));             // an answer decides
}


// Device round of 19.11 (iPhone Air 06:31:22, 06:32:04: a release our own tunnel transition cut; 08:18:42: a 502 of a
// prod API restart): a seat release with no HTTP answer or a 5xx is sent again on the shared spacing
// (seatReleaseNext) until its budget is used, then given up and journalled; 2xx / 4xx are final.
static void caseReleaseSurvivesTransition()
{
    g_case = QStringLiteral("release_survives_transition");
    const QStringList ids{QStringLiteral("LEASEIDLEASEIDLEASEIDLEASEID9001"), QStringLiteral("LEASEIDLEASEIDLEASEIDLEASEID9002")};
    const auto release = [&ids](World &w) {
        bool done = false;
        qint64 bytes = 0;
        w.s->api()->releaseLeases(ids, ScanTunables().costApiBytes, [&](qint64 b) {
            done = true;
            bytes = b;
        });
        QElapsedTimer t;
        t.start();
        while (!done && t.elapsed() < 9000) {
            w.run(50);
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        CHECK(done);
        return bytes;
    };
    const auto logged = [](const World &w, const char *what) {
        for (const QString &l : w.logs)
            if (l.contains(QLatin1String(what)))
                return true;
        return false;
    };
    { // cut twice by our own transition, then answered
        World w;
        w.start();
        w.server.cancelReleases = 2;
        CHECK(release(w) > 0);
        CHECK_EQ(w.server.cancelReleases, 0);
        CHECK_EQ(w.server.releasedLeases, ids); // released once, by the third try
    }
    { // 502 then 204 -> released
        World w;
        w.start();
        w.server.releaseStatuses = {502};
        release(w);
        CHECK_EQ(w.server.releaseTries, 2);
        CHECK_EQ(w.server.releasedLeases, ids);
    }
    { // 502 x N: resent until the spacing budget is used, then given up and journalled
        World w;
        w.start();
        w.s->api()->releaseRetryBudgetMs = 2500; // 300 + 600 ms of spacing: three tries
        w.server.releaseStatuses = {502, 502, 502, 502, 502, 502};
        release(w);
        CHECK_EQ(w.server.releaseTries, 3);
        CHECK(w.server.releasedLeases.isEmpty() && logged(w, "gave_up=1"));
        w.server.releaseStatuses.clear();
        w.server.releaseTries = 0;
        w.server.cancelReleases = 10; // a cut that never ends: the same bound
        release(w);
        CHECK_EQ(w.server.releaseTries, 3);
        CHECK(w.server.releasedLeases.isEmpty());
    }
    { // 404 / 409: final, no resend
        for (const int status : {404, 409}) {
            World w;
            w.start();
            w.server.releaseStatuses = {status, 204};
            release(w);
            CHECK_EQ(w.server.releaseTries, 1);
            CHECK(w.server.releasedLeases.isEmpty() && !logged(w, "gave_up=1"));
        }
    }
}

// Contract 1.15.0 (device round 19.11: the race's batch was cut as a tunnel came up, its seats stayed until their
// TTL). The batch's operation id is made before the first send; a send our own transition cut goes again with the
// same id and gets the same seats; only an answer echoing the id is used; whatever the owner never saw is released by
// the id; a new batch has a new id.
static void caseBatchOperation()
{
    g_case = QStringLiteral("batch_operation");
    const auto runUntil = [](World &w, const std::function<bool()> &cond, int ms) {
        QElapsedTimer t;
        t.start();
        while (!cond() && t.elapsed() < ms) {
            w.run(50);
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        }
    };
    const QStringList one{kPids.at(0)};
    { // a cut send is resent with the same id; the answer gives the seat granted by the cut send
        World w;
        w.start();
        w.server.cancelBatches = 1;
        bool done = false;
        ScanApiClient::Batch got;
        std::unique_ptr<ScanSeatBatch> owner = w.s->api()->probeBatch(one, false, 40000, [&](const ScanApiClient::Batch &b) {
            got = b;
            done = true;
        });
        const QString op = owner->operationId();
        CHECK(scanOperationIdValid(op));
        runUntil(w, [&]() { return done; }, 6000);
        CHECK(done);
        CHECK_EQ(w.server.batchOps.size(), 2);
        CHECK(w.server.batchOps.value(0) == op && w.server.batchOps.value(1) == op); // the resend carries the same id
        CHECK(got.ok && got.resends == 1 && got.items.size() == 1 && got.items.at(0).granted);
        CHECK(got.items.value(0).leaseId == w.server.opLeases.value(op).value(0)); // the seat of the first (cut) send
        CHECK(w.server.releasedOps.isEmpty());                                  // held while its owner holds it
        std::unique_ptr<ScanSeatBatch> second = w.s->api()->probeBatch(one, false, 40000, [](const ScanApiClient::Batch &) {});
        CHECK(second->operationId() != op); // a new batch = a new id
        owner.reset();                       // the owner goes: its seat is released by the id
        runUntil(w, [&]() { return w.server.releasedOps.contains(op); }, 3000);
        CHECK(w.server.releasedOps.contains(op) && w.server.releasedLeases.contains(got.items.value(0).leaseId));
    }
    { // an answer with another operation's id grants nothing; the seats are released by OUR id at once
        World w;
        w.start();
        w.server.foreignOp = QStringLiteral("ffffffffffffffffffffffffffffffff");
        bool done = false;
        ScanApiClient::Batch got;
        std::unique_ptr<ScanSeatBatch> owner = w.s->api()->probeBatch(one, false, 40000, [&](const ScanApiClient::Batch &b) {
            got = b;
            done = true;
        });
        const QString op = owner->operationId();
        runUntil(w, [&]() { return done && w.server.releasedOps.contains(op); }, 3000);
        CHECK(done && !got.ok && got.failCode == QLatin1String("transport") && !got.items.value(0).granted);
        CHECK(w.server.releasedOps == QStringList{op}); // never the foreign id
        CHECK(w.server.releasedLeases == w.server.opLeases.value(op));
    }
    { // the answer never came (every resend cut): the seats the server granted are released by the id
        World w;
        w.start();
        w.server.cancelBatches = kScanCanceledRetries + 1;
        bool done = false;
        ScanApiClient::Batch got;
        std::unique_ptr<ScanSeatBatch> owner = w.s->api()->probeBatch(one, false, 400000, [&](const ScanApiClient::Batch &b) {
            got = b;
            done = true;
        });
        const QString op = owner->operationId();
        runUntil(w, [&]() { return done && w.server.releasedOps.contains(op); }, 9000);
        CHECK(done && !got.ok && got.resends == kScanCanceledRetries);
        CHECK_EQ(w.server.batchOps.size(), kScanCanceledRetries + 1);
        CHECK(w.server.releasedOps == QStringList{op});
        CHECK(!w.server.opLeases.value(op).isEmpty() && w.server.releasedLeases == w.server.opLeases.value(op));
        owner.reset();
        w.run(200);
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        CHECK_EQ(w.server.releasedOps.size(), 1); // released once
    }
    { // the owner goes while the request is in flight and that send is cut: no resend, released by the id
        World w;
        w.start();
        w.server.cancelBatches = 1;
        bool done = false;
        std::unique_ptr<ScanSeatBatch> owner = w.s->api()->probeBatch(one, false, 40000, [&](const ScanApiClient::Batch &) { done = true; });
        const QString op = owner->operationId();
        owner.reset();
        runUntil(w, [&]() { return done && w.server.releasedOps.contains(op); }, 3000);
        CHECK(done && w.server.batchOps.size() == 1 && w.server.releasedOps == QStringList{op});
    }
    { // lease_gone (a resend whose seat already ended): that profile has no seat - an item, not a batch failure
        World w;
        w.start();
        w.server.refuse.insert(kPids.at(1), QStringLiteral("lease_gone"));
        bool done = false;
        ScanApiClient::Batch got;
        std::unique_ptr<ScanSeatBatch> owner = w.s->api()->probeBatch({kPids.at(0), kPids.at(1)}, false, 40000,
                                                                      [&](const ScanApiClient::Batch &b) {
            got = b;
            done = true;
        });
        runUntil(w, [&]() { return done; }, 3000);
        CHECK(done && got.ok && got.items.size() == 2 && got.items.at(0).granted && !got.items.at(1).granted
              && got.items.at(1).code == QLatin1String("lease_gone"));
    }
}

// Contract 1.14.0 end to end: the pool feeds the scope menu when the screen opens; «Найти ещё» asks the server's
// batch with `seen`, the provider rows' stub nodes go to the engine before the rows; an older server (404) falls back.
static void caseServerScope()
{
    g_case = QStringLiteral("server_scope");
    {
        // Device round air7 (19.11): opening the Scanner showed no «Все страны · N серверов» and no country menu
        // although GET /v1/scan/pool answered - the page checks Array.isArray(bar.scope_countries), and a list
        // inside a QVariantMap reaches QML as a sequence that is no Array (Qt 6.11). The QML property is JSON.
        const QMetaObject &mo = TribeScanner::staticMetaObject;
        const int pi = mo.indexOfProperty("view");
        CHECK(pi >= 0 && mo.property(pi).metaType() == QMetaType::fromType<QJsonObject>());
        World w;
        w.server.scopeApi = true;
        w.poolOnOpen = true;
        w.start();
        w.s->show(); // opening the screen: no scan, only the pool
        w.run(5000);
        CHECK_EQ(w.http.count("/v1/scan/pool"), 1);
        CHECK_EQ(w.http.count("/v1/scan/manifest"), 0);
        const QJsonObject bar = w.s->viewJson().value(QStringLiteral("bar")).toObject();
        CHECK(bar.value("scope_countries").isArray() && !bar.value("scope_countries").toArray().isEmpty());
        CHECK(bar.value("scope").isString() && bar.value("scope").toString().isEmpty());
        bool logged = false;
        for (const QString &l : w.logs)
            logged = logged || l.startsWith(QLatin1String("pool fetched countries="));
        CHECK(logged);
        w.s->close();
    }
    {
        World w;
        w.server.scopeApi = true;
        w.poolOnOpen = true;
        w.server.numbers.insert(QStringLiteral("scan_stop_works"), 2); // the first screen stops early: rows are left
        QJsonObject extra = w.server.upstream.at(0).toObject(); // a profile beyond the manifest's rows (and the 24 stubs)
        extra.insert("profile_id", "abcdefabcdefabcd");
        w.server.extraUpstream << extra;
        w.host.outcomes.insert(QStringLiteral("up:abcdefabcdefabcd"), Outcome{true, 90, 500});
        w.engine.names = true;
        w.start();
        w.s->open();
        w.run(20000);
        CHECK_EQ(w.http.count("/v1/scan/pool"), 1);
        const QJsonObject bar = w.s->view().value(QStringLiteral("bar")).toMap().isEmpty()
                                    ? QJsonObject() : QJsonObject::fromVariantMap(w.s->view().value(QStringLiteral("bar")).toMap());
        CHECK(bar.value("scope_countries").toArray().size() >= 1 && bar.value("scope_whitelist").toInt() == 2);
        bool named = true;
        for (const QJsonValue &c : bar.value("scope_countries").toArray())
            named = named && !c.toObject().value("name").toString().isEmpty();
        CHECK(named);
        w.clock.t += 31000;
        w.s->findMore();
        w.run(20000);
        CHECK(w.server.candidateRequests.size() == 1);
        if (!w.server.candidateRequests.isEmpty()) {
            const QJsonObject rq = w.server.candidateRequests.first();
            CHECK(rq.value("scope").toString() == "default" && rq.value("limit").toInt() == kScanMoreBatch && !rq.value("seen").toArray().isEmpty());
        }
        if (w.engine.offered.isEmpty())
            for (const QString &l : w.logs)
                if (l.contains(QLatin1String("candidates")) || l.contains(QLatin1String("find_more")))
                    std::fprintf(stderr, "  log: %s\n", qPrintable(l));
        CHECK(!w.engine.offered.isEmpty()); // the batch's provider rows: their nodes are in the engine's pool
        bool extraProbed = false; // a row beyond the manifest: probed with its own projection's leg (device 18.11 bug)
        for (const QJsonObject &rq : w.host.requests)
            for (const QJsonValue &c : rq.value("candidates").toArray())
                extraProbed = extraProbed || (c.toObject().value("id").toString() == QLatin1String("up:abcdefabcdefabcd")
                                              && !c.toObject().value("config").toString().isEmpty());
        CHECK(extraProbed);
        // the batch's row is named by the app's naming function when it is born, not by the server's label, and
        // keeps that name with no stub in the engine's pool (device round air7: «SE 1» after the 6th batch)
        bool rowNamed = false;
        for (const QVariant &rv : w.s->view().value(QStringLiteral("rows")).toList()) {
            const QVariantMap r = rv.toMap();
            if (r.value("id").toString() == QLatin1String("up:abcdefabcdefabcd"))
                rowNamed = r.value("label").toString() == QStringLiteral("Имя abcdefabcdefabcd");
        }
        CHECK(rowNamed);
        // a batch row is tapped after its stub may have left the engine's newest-48 offered pool: the facade offers it
        // again right before the connect, so the engine knows the node it is asked to connect
        {
            const int offeredBefore = w.engine.offered.size();
            const int callsBefore = w.engine.rowCalls.size();
            w.s->tapRow(QStringLiteral("up:abcdefabcdefabcd"));
            CHECK(w.engine.rowCalls.size() == callsBefore + 1);
            // the tapped row is offered LAST (the engine keeps its newest 48), and the re-offer is bounded
            CHECK(w.engine.offered.size() > offeredBefore && w.engine.offered.size() - offeredBefore <= 24
                  && w.engine.offered.last().toObject().value("node_id").toString() == QLatin1String("up:abcdefabcdefabcd"));
        }

        const QString state = QJsonObject::fromVariantMap(w.s->view().value(QStringLiteral("more")).toMap()).value("state").toString();
        CHECK(state == "exhausted" || state == "available");
        w.s->close();
    }
    {
        World w; // an older server: no pool, the batch request 404 -> the device's own continuation
        w.poolOnOpen = true;
        w.start();
        w.s->open();
        w.run(20000);
        CHECK_EQ(w.http.count("/v1/scan/pool"), 1);
        w.clock.t += 31000;
        w.s->findMore();
        w.run(20000);
        CHECK_EQ(w.http.count("/v1/scan/candidates"), 1);
        CHECK(w.engine.offered.isEmpty() && w.s->view().value(QStringLiteral("batch")).toInt() == 2);
        w.clock.t += 31000;
        w.s->findMore();
        w.run(20000);
        CHECK_EQ(w.http.count("/v1/scan/candidates"), 1); // the session does not ask again
        w.s->close();
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    caseScanCanceledRetryRule();
    caseReleaseSurvivesTransition();
    caseBatchOperation();
    caseFullScan();
    caseFullProbeProfileRule();
    caseServerScope();
    caseLiveDigest();
    caseManifest304();
    caseManifestSignature();
    caseBatchPartial();
    caseCellularBudget();
    caseDrain();
    caseNetworkChange();
    caseNetworkKeySameGeneration();
    caseCooldown();
    caseAbandonedManifest();
    caseAccessScope();
    caseConnectPaths();
    caseHostUnavailable();
    caseRefusedStart();
    caseHostReasons();
    caseServiceErrors();
    caseHostDied();
    caseCapsGen();
    caseCapsFromHost();
    caseShade();
    caseStaleLiveProbe();
    caseHostNotNow();
    caseHeldAddOfOlderScan();
    caseStopDuringRetriedStart();
    caseLostAcceptance();
    caseLateAckAfterSettled();
    caseUnknownOvertakesStart();
    caseDuplicateFinals();
    caseRecordBound();
    caseLateAddRefusal();
    caseLateProgressOfOlderScan();
    caseLateCapsGen();
    propertyBytes();
    propertySeats();
    caseStaleBatch();
    caseWireCap();
    caseManifestFailureBytes();
    caseScannerOff();
    caseAwgMini();
    caseAwgLivePeerUnknown();
    caseBaseIps();
    caseReportRefused();
    caseSpeedSample();
    caseScreenFields();
    caseQnamCut();
    caseQnamGzip();
    if (g_fail) {
        std::fprintf(stderr, "scanner_facade_check: %d of %d checks FAILED\n", g_fail, g_checks);
        return 1;
    }
    std::printf("scanner_facade_check: OK (%d checks)\n", g_checks);
    return 0;
}
