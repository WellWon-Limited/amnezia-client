#include "ScanApiClient.h"
#include "BackgroundTaskHook.h" // AVPN (build 142): background time while a seat release is resent

#include "NetAwait.h" // armTimeout: the per-request bound of the app's API client (no timer of our own)
#include "ScanBudget.h"
#include "ScanTunables.h"
#include "SignedContext.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <QUuid>

#include <zlib.h>

namespace avpn {

namespace {

qint64 isoMs(const QJsonValue &v)
{
    if (!v.isString())
        return 0;
    QDateTime t = QDateTime::fromString(v.toString(), Qt::ISODateWithMs);
    if (!t.isValid())
        t = QDateTime::fromString(v.toString(), Qt::ISODate);
    return t.isValid() ? t.toMSecsSinceEpoch() : 0;
}

QString trimBase(QString b)
{
    while (b.endsWith(QLatin1Char('/')))
        b.chop(1);
    return b;
}

bool leaseIdValid(const QString &s)
{
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9_-]{32,64}$"));
    return re.match(s).hasMatch();
}

bool profileIdValid(const QString &s)
{
    static const QRegularExpression re(QStringLiteral("^[0-9a-f]{16}$"));
    return re.match(s).hasMatch();
}

QByteArray bearer(const QString &token) { return QByteArrayLiteral("Bearer ") + token.toUtf8(); }

QString manifestFilePath(const QString &key)
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return dir + QLatin1Char('/') + key + QStringLiteral(".json");
}

} // namespace

// --- HTTP ------------------------------------------------------------------------------------------------------

qint64 scanHttpRequestBytes(const IScanHttp::Request &r)
{
    qint64 n = kScanTlsOverheadBytes + r.method.size() + r.url.toUtf8().size() + 16 + r.body.size();
    for (const auto &h : r.headers)
        n += h.first.size() + h.second.size() + 4;
    return n;
}

bool scanGunzip(const QByteArray &in, qint64 maxOut, QByteArray *out)
{
    out->clear();
    z_stream zs{};
    if (in.isEmpty() || inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) // 16: the gzip wrapper only
        return false;
    zs.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(in.constData()));
    zs.avail_in = uInt(in.size());
    char buf[16384];
    int rc = Z_OK;
    while (rc == Z_OK) {
        zs.next_out = reinterpret_cast<Bytef *>(buf);
        zs.avail_out = sizeof(buf);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END)
            break;
        out->append(buf, qsizetype(sizeof(buf) - zs.avail_out));
        if (out->size() > maxOut) {
            rc = Z_MEM_ERROR;
            break;
        }
        if (rc == Z_OK && zs.avail_in == 0 && zs.avail_out != 0) {
            rc = Z_DATA_ERROR; // the stream ended before its end mark
            break;
        }
    }
    inflateEnd(&zs);
    if (rc != Z_STREAM_END) {
        out->clear();
        return false;
    }
    return true;
}

ScanQnamHttp::ScanQnamHttp(QNetworkAccessManager *nam, QObject *parent) : QObject(parent), m_nam(nam) {}

void ScanQnamHttp::send(const Request &asked, DoneFn done)
{
    // Our own Accept-Encoding: QNAM then hands the body over as it came (counted and cut as wire bytes) and the
    // answer is inflated below; with QNAM's implicit "gzip, deflate" its counts would be the inflated body.
    Request rq = asked;
    bool hasEncoding = false;
    for (const auto &h : rq.headers)
        hasEncoding = hasEncoding || h.first.compare("Accept-Encoding", Qt::CaseInsensitive) == 0;
    if (!hasEncoding)
        rq.headers << qMakePair(QByteArrayLiteral("Accept-Encoding"), QByteArrayLiteral("gzip"));
    const qint64 sentBytes = scanHttpRequestBytes(rq);
    if (!m_nam || rq.url.isEmpty() || (rq.maxBytes >= 0 && sentBytes > rq.maxBytes)) {
        QTimer::singleShot(0, this, [done, rq, sentBytes]() {
            Response r;
            r.cut = rq.maxBytes >= 0 && sentBytes > rq.maxBytes;
            r.bytes = 0; // nothing was sent
            if (done)
                done(r);
        });
        return;
    }
    QNetworkRequest req{QUrl(rq.url)};
    for (const auto &h : rq.headers)
        req.setRawHeader(h.first, h.second);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    QNetworkReply *reply = nullptr;
    if (rq.method == "GET")
        reply = m_nam->get(req);
    else if (rq.method == "POST")
        reply = m_nam->post(req, rq.body);
    else
        reply = m_nam->sendCustomRequest(req, rq.method, rq.body);
    armTimeout(reply, rq.timeoutMs);
    struct Live {
        QByteArray body;
        qint64 headerBytes = -1;
        bool cut = false;
    };
    auto live = std::make_shared<Live>();
    const qint64 cap = rq.maxBytes;
    auto count = [reply, live, sentBytes, cap]() {
        if (live->headerBytes < 0 && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).isValid()) {
            live->headerBytes = 16;
            for (const auto &p : reply->rawHeaderPairs())
                live->headerBytes += p.first.size() + p.second.size() + 4;
        }
        const QByteArray chunk = reply->readAll();
        live->body += chunk;
        const qint64 total = sentBytes + qMax<qint64>(0, live->headerBytes) + live->body.size();
        if (cap >= 0 && total > cap && reply->isRunning()) {
            live->cut = true;
            reply->abort(); // the reservation is the request's hard limit (plan §2.2b)
        }
    };
    connect(reply, &QNetworkReply::metaDataChanged, reply, count);
    connect(reply, &QNetworkReply::readyRead, reply, count);
    connect(reply, &QNetworkReply::finished, this, [reply, live, sentBytes, cap, count, done]() {
        reply->deleteLater();
        if (!live->cut)
            count();
        Response r;
        const QVariant code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        const int status = code.isValid() ? code.toInt() : 0;
        const bool complete = reply->error() == QNetworkReply::NoError
                              || (status >= 300 && reply->error() != QNetworkReply::OperationCanceledError);
        r.cut = live->cut;
        r.status = (r.cut || !complete) ? 0 : status;
        r.canceled = !r.cut && reply->error() == QNetworkReply::OperationCanceledError
                     && !reply->property("avpn_timed_out").toBool();
        for (const auto &p : reply->rawHeaderPairs())
            r.headers.insert(p.first.toLower(), p.second);
        r.body = r.cut ? QByteArray() : live->body;
        r.bytes = sentBytes + qMax<qint64>(0, live->headerBytes) + live->body.size();
        if (cap >= 0)
            r.bytes = qMin(r.bytes, cap);
        if (!r.cut && r.header("content-encoding").trimmed().toLower() == "gzip") {
            QByteArray plain;
            if (scanGunzip(r.body, kScanInflateMaxBytes, &plain)) {
                r.body = plain;
            } else {
                r.status = 0; // an answer that does not inflate is no answer
                r.body.clear();
            }
        }
        if (done)
            done(r);
    });
}

// --- store -----------------------------------------------------------------------------------------------------

QByteArray ScanSettingsStore::read(const QString &key) const
{
    if (key.startsWith(QLatin1String(kScanManifestStorePrefix))) {
        QFile f(manifestFilePath(key));
        if (!f.open(QIODevice::ReadOnly))
            return QByteArray();
        return f.read(4 * 1024 * 1024);
    }
    QSettings s;
    return s.value(key).toByteArray();
}

bool ScanSettingsStore::write(const QString &key, const QByteArray &value)
{
    if (key.startsWith(QLatin1String(kScanManifestStorePrefix))) {
        const QString path = manifestFilePath(key);
        QDir().mkpath(QFileInfo(path).absolutePath());
        QSaveFile f(path);
        if (!f.open(QIODevice::WriteOnly))
            return false;
        f.write(value);
        return f.commit();
    }
    QSettings s;
    s.setValue(key, value);
    return true;
}

void ScanSettingsStore::remove(const QString &key)
{
    if (key.startsWith(QLatin1String(kScanManifestStorePrefix))) {
        QFile::remove(manifestFilePath(key));
        return;
    }
    QSettings s;
    s.remove(key);
}

// --- helpers ---------------------------------------------------------------------------------------------------

QString scanManifestStoreKey(const QString &networkKey)
{
    const QByteArray h = QCryptographicHash::hash((QStringLiteral("tribe-scan-manifest-store|") + networkKey).toUtf8(),
                                                  QCryptographicHash::Sha256);
    return QLatin1String(kScanManifestStorePrefix) + QString::fromLatin1(h.toHex().left(16));
}

bool scanManifestEtagValid(const QByteArray &etag)
{
    static const QRegularExpression re(QStringLiteral("^\"sm1\\.[A-Za-z0-9_-]{22}\"$"));
    return etag.size() <= 64 && re.match(QString::fromLatin1(etag)).hasMatch();
}

QString scanProviderLegConfig(const QJsonObject &manifestBody, const QString &profileId)
{
    for (const QJsonValue &v : manifestBody.value(QLatin1String("upstream")).toArray()) {
        const QJsonObject u = v.toObject();
        if (u.value(QLatin1String("profile_id")).toString() != profileId)
            continue;
        const QJsonObject projection = u.value(QLatin1String("projection")).toObject();
        const QJsonArray legs = projection.value(QLatin1String("legs")).toArray();
        if (legs.size() != 1)
            return QString();
        const QJsonObject outbound = legs.at(0).toObject().value(QLatin1String("outbound")).toObject();
        if (outbound.isEmpty())
            return QString();
        QJsonArray dns;
        for (const QJsonValue &d : projection.value(QLatin1String("dns")).toArray()) {
            const QJsonObject o = d.toObject();
            if (o.value(QLatin1String("route")).toString() == QLatin1String("none"))
                continue; // fakedns: nothing to exercise
            dns << QJsonObject{{QStringLiteral("address"), o.value(QLatin1String("address"))},
                               {QStringLiteral("tag"), o.value(QLatin1String("tag"))},
                               {QStringLiteral("transport"), o.value(QLatin1String("transport"))}};
        }
        const QJsonObject cfg{{QStringLiteral("outbound"), outbound}, {QStringLiteral("dns"), dns}};
        return QString::fromUtf8(QJsonDocument(cfg).toJson(QJsonDocument::Compact));
    }
    return QString();
}

QByteArray scanProbeNonce()
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    QByteArray n;
    n.reserve(24);
    for (int i = 0; i < 24; ++i)
        n += alphabet[QRandomGenerator::global()->bounded(int(sizeof(alphabet) - 1))];
    return n;
}

QString scanOperationId() { return QUuid::createUuid().toString(QUuid::Id128); }

bool scanOperationIdValid(const QString &id)
{
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9_-]{16,64}$"));
    return re.match(id).hasMatch();
}

// --- the owner of a probe-seat batch ---------------------------------------------------------------------------

struct ScanSeatBatch::State {
    QPointer<ScanApiClient> api;
    QString op;
    QStringList profileIds; // as asked: the answer's order
    qint64 cost = -1;       // every send together
    qint64 spent = 0;
    int resends = 0;
    bool inFlight = true;
    bool owned = true;
    QStringList held;       // granted lease ids nobody released one by one yet
    qint64 releaseCost = 0;
    std::function<void(const ScanApiClient::Batch &)> done;
    std::function<void(qint64)> releaseBytes;
    int releasesOut = 0;            // release requests not answered yet
    std::function<void()> idle;     // retire(): called once when nothing of the batch can spend any more
    // THE way a batch request ends - the network answer, a local refusal (queued or immediate), a client that is gone: the request
    // is over (endRequest), then the result is handed on and a waiting retire() callback fires (deliver, after the bytes of the
    // result were counted). No other place clears inFlight.
    static void endRequest(const std::shared_ptr<State> &st) { st->inFlight = false; }
    static void deliver(const std::shared_ptr<State> &st, const ScanApiClient::Batch &out)
    {
        if (st->done)
            st->done(out);
        noteIdle(st);
    }
    static void noteIdle(const std::shared_ptr<State> &st)
    {
        if (st->inFlight || st->releasesOut > 0 || !st->idle)
            return;
        const std::function<void()> f = std::move(st->idle);
        st->idle = nullptr;
        f();
    }
};

ScanSeatBatch::~ScanSeatBatch()
{
    m_s->owned = false;
    if (!m_s->inFlight && !m_s->held.isEmpty())
        ScanApiClient::releaseBatch(m_s);
    // in flight: no resend any more; the seats go when the request ends (finishBatch)
}

void ScanSeatBatch::retire(std::function<void()> idle)
{
    m_s->owned = false;
    if (!m_s->inFlight && !m_s->held.isEmpty())
        ScanApiClient::releaseBatch(m_s);
    m_s->idle = std::move(idle);
    State::noteIdle(m_s);
}

QString ScanSeatBatch::operationId() const { return m_s->op; }

void ScanSeatBatch::forget(const QStringList &leaseIds)
{
    for (const QString &l : leaseIds)
        m_s->held.removeAll(l);
}

void ScanApiClient::releaseBatch(const std::shared_ptr<ScanSeatBatch::State> &st)
{
    const QStringList ids = st->held;
    st->held.clear();
    if (!st->api)
        return; // the client went with the app: the seats are the server's TTL's
    const std::function<void(qint64)> sink = st->releaseBytes;
    ++st->releasesOut;
    st->api->releaseLeases(ids, st->releaseCost, [sink, st](qint64 bytes) {
        --st->releasesOut;
        if (sink)
            sink(bytes);
        ScanSeatBatch::State::noteIdle(st); // after its bytes were counted
    }, st->op);
}

// --- the client ------------------------------------------------------------------------------------------------

ScanApiClient::ScanApiClient(IScanHttp *http, IScanStore *store, QObject *parent)
    : QObject(parent), m_http(http), m_store(store)
{
}

void ScanApiClient::configure(std::function<QString()> apiBase, std::function<QString()> pubKeyHex,
                              std::function<QString()> deviceToken)
{
    m_apiBase = std::move(apiBase);
    m_pubKeyHex = std::move(pubKeyHex);
    m_deviceToken = std::move(deviceToken);
}

bool ScanApiClient::configured() const { return m_http && m_apiBase && m_pubKeyHex && m_deviceToken; }

void ScanApiClient::setNetworkManager(QNetworkAccessManager *nam)
{
    if (!m_lease) {
        m_lease = new UpstreamLeaseClient(this);
    }
    // runProbe needs only the QNAM; the lease part of that client is never used from here.
    m_lease->configure(nam, m_apiBase ? m_apiBase : std::function<QString()>([]() { return QString(); }),
                       m_pubKeyHex ? m_pubKeyHex() : QString(), m_deviceToken ? m_deviceToken : std::function<QString()>([]() { return QString(); }));
    QPointer<UpstreamLeaseClient> lease(m_lease);
    m_probe = [lease](const UpstreamLeaseClient::ProbeRequest &r, std::function<void(const UpstreamProbeFacts &)> done) {
        if (lease) {
            lease->runProbe(r, std::move(done));
        } else if (done) {
            UpstreamProbeFacts f;
            f.bytesRequested = r.bytes;
            done(f);
        }
    };
}

QString ScanApiClient::base() const { return trimBase(m_apiBase ? m_apiBase() : QString()); }

void ScanApiClient::emitLog(const QString &line) const
{
    if (log)
        log(line);
    else
        qInfo().noquote() << "[scanner-api]" << line;
}

// --- stored manifests ------------------------------------------------------------------------------------------

bool ScanApiClient::verifyAndParse(const QByteArray &body, const QByteArray &sig, Stored &out) const
{
    const QString key = m_pubKeyHex ? m_pubKeyHex() : QString();
    if (key.isEmpty() || sig.isEmpty() || body.isEmpty())
        return false;
    if (!verifyDetachedWithContext(key, QLatin1String(kScanManifestSigContext), body, sig))
        return false;
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(body, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject())
        return false;
    const QJsonObject o = doc.object();
    ScanManifestView v;
    if (!scanManifestViewFromJson(o, v))
        return false;
    out.ok = true;
    out.body = body;
    out.sig = sig;
    out.obj = o;
    out.expiresAtMs = isoMs(o.value(QLatin1String("expires_at")));
    out.tokenExpiresAtMs = isoMs(o.value(QLatin1String("scan_token")).toObject().value(QLatin1String("expires_at")));
    out.revision = v.upstreamRevision;
    return true;
}

ScanApiClient::Stored ScanApiClient::loadStored(const QString &networkKey) const
{
    Stored s;
    if (!m_store)
        return s;
    const QByteArray raw = m_store->read(scanManifestStoreKey(networkKey));
    if (raw.isEmpty())
        return s;
    const QJsonObject o = QJsonDocument::fromJson(raw).object();
    if (o.value(QLatin1String("network_key")).toString() != networkKey)
        return s;
    const QByteArray body = QByteArray::fromBase64(o.value(QLatin1String("body")).toString().toLatin1());
    const QByteArray sig = o.value(QLatin1String("sig")).toString().toLatin1();
    // Re-verified on every load: a file is never trusted by itself.
    if (!verifyAndParse(body, sig, s))
        return Stored();
    const QByteArray etag = o.value(QLatin1String("etag")).toString().toLatin1();
    s.etag = scanManifestEtagValid(etag) ? etag : QByteArray();
    return s;
}

void ScanApiClient::saveStored(const QString &networkKey, const QByteArray &body, const QByteArray &sig, const QByteArray &etag)
{
    if (!m_store)
        return;
    const QJsonObject o{{QStringLiteral("network_key"), networkKey},
                        {QStringLiteral("etag"), scanManifestEtagValid(etag) ? QString::fromLatin1(etag) : QString()},
                        {QStringLiteral("sig"), QString::fromLatin1(sig)},
                        {QStringLiteral("body"), QString::fromLatin1(body.toBase64())}};
    m_store->write(scanManifestStoreKey(networkKey), QJsonDocument(o).toJson(QJsonDocument::Compact));
    QJsonArray idx = QJsonDocument::fromJson(m_store->read(QLatin1String(kScanManifestIndexKey))).array();
    bool have = false;
    for (const QJsonValue &v : idx)
        have = have || v.toString() == networkKey;
    if (!have) {
        idx << networkKey;
        while (idx.size() > 16) {
            m_store->remove(scanManifestStoreKey(idx.first().toString()));
            idx.removeFirst();
        }
        m_store->write(QLatin1String(kScanManifestIndexKey), QJsonDocument(idx).toJson(QJsonDocument::Compact));
    }
}

void ScanApiClient::removeStored(const QString &networkKey)
{
    if (!m_store)
        return;
    m_store->remove(scanManifestStoreKey(networkKey));
    QJsonArray idx = QJsonDocument::fromJson(m_store->read(QLatin1String(kScanManifestIndexKey))).array();
    for (int i = idx.size() - 1; i >= 0; --i)
        if (idx.at(i).toString() == networkKey)
            idx.removeAt(i);
    m_store->write(QLatin1String(kScanManifestIndexKey), QJsonDocument(idx).toJson(QJsonDocument::Compact));
}

void ScanApiClient::dropManifestsBelowRevision(qint64 revision)
{
    if (!m_store)
        return;
    const QJsonArray idx = QJsonDocument::fromJson(m_store->read(QLatin1String(kScanManifestIndexKey))).array();
    for (const QJsonValue &v : idx) {
        const Stored s = loadStored(v.toString());
        if (!s.ok || s.revision < revision)
            removeStored(v.toString());
    }
}

// --- manifest + token ------------------------------------------------------------------------------------------

struct ScanApiClient::ManifestRun {
    QString networkKey;
    qint64 cost = -1;
    qint64 spent = 0;
    qint64 now = 0;
    Stored stored;
    Manifest result;
    bool refetched = false;
    int canceledRetries = 0;
    std::function<void(const Manifest &)> done;

    qint64 left() const { return cost < 0 ? -1 : qMax<qint64>(0, cost - spent); }
};

void ScanApiClient::fetchManifest(const QString &networkKey, qint64 costBytes, qint64 nowMs,
                                  std::function<void(const Manifest &)> done)
{
    auto run = std::make_shared<ManifestRun>();
    run->networkKey = networkKey;
    run->cost = costBytes;
    run->now = nowMs;
    run->done = std::move(done);
    run->stored = loadStored(networkKey);
    const bool conditional = run->stored.ok && !run->stored.etag.isEmpty() && run->stored.expiresAtMs > nowMs;
    if (run->stored.ok && run->stored.expiresAtMs <= nowMs)
        run->stored = Stored(); // expired: never used again, fetched without If-None-Match
    manifestGet(run, conditional);
}

void ScanApiClient::manifestGet(std::shared_ptr<ManifestRun> run, bool conditional)
{
    const QString b = base();
    const QString token = m_deviceToken ? m_deviceToken() : QString();
    if (!configured() || b.isEmpty() || token.isEmpty()) {
        run->result.reason = QStringLiteral("manifest_unavailable");
        QTimer::singleShot(0, this, [this, run]() { manifestFinish(run); });
        return;
    }
    IScanHttp::Request rq;
    QUrl url(b + QStringLiteral("/v1/scan/manifest"));
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("network_key"), scanNetworkKeyValid(run->networkKey) ? run->networkKey : QStringLiteral("unknown"));
    url.setQuery(q);
    rq.url = url.toString(QUrl::FullyEncoded);
    rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(token));
    if (conditional)
        rq.headers << qMakePair(QByteArrayLiteral("If-None-Match"), run->stored.etag);
    rq.maxBytes = run->left();
    QPointer<ScanApiClient> self(this);
    m_http->send(rq, [self, run, conditional](const IScanHttp::Response &r) {
        if (!self)
            return;
        run->spent += r.bytes;
        if (self->retryCanceled(run, r, [self, run, conditional]() { if (self) self->manifestGet(run, conditional); }))
            return;
        run->result.statusManifest = r.status;
        if (r.status == 304 && run->stored.ok) {
            run->result.fromStore = true;
            run->result.body = run->stored.obj;
            self->manifestToken(run);
            return;
        }
        if (r.status == 200) {
            Stored s;
            if (!self->verifyAndParse(r.body, r.header("x-tribe-sig"), s)) {
                run->result.reason = QStringLiteral("manifest_invalid"); // never stored, never used
                self->manifestFinish(run);
                return;
            }
            self->saveStored(run->networkKey, r.body, s.sig, r.header("etag"));
            run->stored = s;
            run->result.body = s.obj;
            run->result.fromStore = false;
            run->result.scanToken = s.obj.value(QLatin1String("scan_token")).toObject().value(QLatin1String("token")).toString();
            run->result.tokenExpiresAtMs = s.tokenExpiresAtMs;
            run->result.ok = !run->result.scanToken.isEmpty();
            if (!run->result.ok)
                run->result.reason = QStringLiteral("manifest_invalid");
            self->manifestFinish(run);
            return;
        }
        if (r.status == 404)
            run->result.reason = QStringLiteral("scanner_off"); // the SERVER switch: no Scanner for this account now
        else if (r.status == 403)
            run->result.reason = QStringLiteral("not_entitled");
        else if (r.status == 410)
            run->result.reason = QStringLiteral("over_quota");
        else
            run->result.reason = QStringLiteral("manifest_unavailable");
        if (r.status == 403 || r.status == 410 || r.status == 404) {
            self->removeStored(run->networkKey); // a device no longer served keeps no copy
        } else if (r.status == 0 && run->stored.ok && run->stored.expiresAtMs > run->now
                   && run->stored.tokenExpiresAtMs > run->now + 60000) {
            // The API is unreachable: the stored copy is usable until its expires_at, with its own token
            // while that is still valid (plan §2.11).
            run->result.body = run->stored.obj;
            run->result.scanToken = run->stored.obj.value(QLatin1String("scan_token")).toObject().value(QLatin1String("token")).toString();
            run->result.fromStore = true;
            run->result.tokenExpiresAtMs = run->stored.tokenExpiresAtMs;
            run->result.ok = !run->result.scanToken.isEmpty();
            run->result.reason.clear();
        }
        self->manifestFinish(run);
    });
}

bool ScanApiClient::retryCanceled(std::shared_ptr<ManifestRun> run, const IScanHttp::Response &r, std::function<void()> again)
{
    if (!scanRetryCanceledRequest(r.status, r.canceled, run->canceledRetries))
        return false;
    ++run->canceledRetries;
    QTimer::singleShot(kScanCanceledRetryDelayMs, this, std::move(again));
    return true;
}

void ScanApiClient::manifestToken(std::shared_ptr<ManifestRun> run)
{
    IScanHttp::Request rq;
    rq.method = QByteArrayLiteral("POST");
    rq.url = base() + QStringLiteral("/v1/scan/token");
    rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(m_deviceToken ? m_deviceToken() : QString()));
    rq.maxBytes = run->left();
    QPointer<ScanApiClient> self(this);
    m_http->send(rq, [self, run](const IScanHttp::Response &r) {
        if (!self)
            return;
        run->spent += r.bytes;
        if (self->retryCanceled(run, r, [self, run]() { if (self) self->manifestToken(run); }))
            return;
        const QJsonObject g = QJsonDocument::fromJson(r.body).object();
        const QString token = g.value(QLatin1String("scan_token")).toString();
        if (r.status != 200 || g.value(QLatin1String("type")).toString() != QLatin1String("scan_token") || token.isEmpty()) {
            run->result.ok = false;
            run->result.reason = r.status == 403 ? QStringLiteral("not_entitled")
                                 : r.status == 410 ? QStringLiteral("over_quota")
                                 : r.status == 404 ? QStringLiteral("scanner_off")
                                                   : QStringLiteral("manifest_unavailable");
            self->manifestFinish(run);
            return;
        }
        const qint64 rev = qint64(g.value(QLatin1String("upstream_revision")).toDouble(0));
        if (rev > run->stored.revision && !run->refetched) {
            // A newer revision: the stored copy is dropped and the manifest refetched without If-None-Match.
            run->refetched = true;
            self->removeStored(run->networkKey);
            run->stored = Stored();
            self->manifestGet(run, false);
            return;
        }
        run->result.scanToken = token;
        run->result.tokenExpiresAtMs = run->now + qint64(g.value(QLatin1String("expires_in_s")).toDouble(600)) * 1000;
        run->result.ok = true;
        self->manifestFinish(run);
    });
}

void ScanApiClient::manifestFinish(std::shared_ptr<ManifestRun> run)
{
    Manifest &m = run->result;
    m.bytes = run->spent;
    if (m.ok) {
        if (!scanManifestViewFromJson(m.body, m.view)) {
            m.ok = false;
            m.reason = QStringLiteral("manifest_invalid");
        }
        m.tunnelApiBase = trimBase(m.body.value(QLatin1String("tunnel_api_base")).toString());
        m.directApiBase = trimBase(m.body.value(QLatin1String("direct_api_base")).toString());
    }
    if (!m.ok) {
        m.body = QJsonObject();
        m.scanToken.clear();
    }
    emitLog(QStringLiteral("manifest status=%1 %2 bytes=%3 %4")
                .arg(m.statusManifest)
                .arg(m.ok ? (m.fromStore ? QStringLiteral("stored") : QStringLiteral("fresh")) : m.reason)
                .arg(m.bytes)
                .arg(m.ok ? QStringLiteral("nodes=%1 upstream=%2").arg(m.view.nodes.size()).arg(m.view.upstream.size()) : QString()));
    if (run->done)
        run->done(m);
}

void ScanApiClient::fetchToken(qint64 costBytes, qint64 nowMs, std::function<void(const QString &, qint64, qint64)> done)
{
    const QString b = base();
    const QString dt = m_deviceToken ? m_deviceToken() : QString();
    if (!configured() || b.isEmpty() || dt.isEmpty()) {
        QTimer::singleShot(0, this, [done]() {
            if (done)
                done(QString(), 0, 0);
        });
        return;
    }
    IScanHttp::Request rq;
    rq.method = QByteArrayLiteral("POST");
    rq.url = b + QStringLiteral("/v1/scan/token");
    rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(dt));
    rq.maxBytes = costBytes;
    QPointer<ScanApiClient> self(this);
    m_http->send(rq, [self, nowMs, done](const IScanHttp::Response &r) {
        const QJsonObject g = QJsonDocument::fromJson(r.body).object();
        const QString token = r.status == 200 && g.value(QLatin1String("type")).toString() == QLatin1String("scan_token")
                                  ? g.value(QLatin1String("scan_token")).toString()
                                  : QString();
        if (self)
            self->emitLog(QStringLiteral("token status=%1 bytes=%2").arg(r.status).arg(r.bytes));
        if (done)
            done(token, token.isEmpty() ? 0 : nowMs + qint64(g.value(QLatin1String("expires_in_s")).toDouble(600)) * 1000, r.bytes);
    });
}

QString ScanApiClient::storedTunnelBase(const QString &networkKey) const
{
    const Stored st = loadStored(networkKey);
    return st.ok ? trimBase(st.obj.value(QLatin1String("tunnel_api_base")).toString()) : QString();
}

// --- the whole pool (contract 1.14.0) -------------------------------------------------------------------------

namespace {
QString scanErrorReason(int status)
{
    switch (status) {
    case 403: return QStringLiteral("not_entitled");
    case 404: return QStringLiteral("scanner_off");
    case 410: return QStringLiteral("over_quota");
    case 422: return QStringLiteral("invalid");
    case 429: return QStringLiteral("rate_limited");
    default: break;
    }
    return QStringLiteral("transport");
}
} // namespace

void ScanApiClient::fetchPool(qint64 costBytes, std::function<void(const Pool &)> done)
{
    const QString b = base();
    const QString dt = m_deviceToken ? m_deviceToken() : QString();
    if (!configured() || b.isEmpty() || dt.isEmpty()) {
        QTimer::singleShot(0, this, [done]() {
            Pool p;
            p.reason = QStringLiteral("transport");
            if (done)
                done(p);
        });
        return;
    }
    IScanHttp::Request rq;
    rq.method = QByteArrayLiteral("GET");
    rq.url = b + QStringLiteral("/v1/scan/pool");
    rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(dt));
    rq.maxBytes = costBytes;
    QPointer<ScanApiClient> self(this);
    m_http->send(rq, [self, done](const IScanHttp::Response &r) {
        Pool p;
        p.bytes = r.bytes;
        p.status = r.status;
        if (r.status == 200) {
            p.ok = scanPoolFromJson(QJsonDocument::fromJson(r.body).object(), p.view);
            if (!p.ok)
                p.reason = QStringLiteral("invalid");
        } else {
            p.reason = scanErrorReason(r.status);
        }
        if (self)
            self->emitLog(QStringLiteral("pool status=%1 countries=%2 bytes=%3").arg(r.status).arg(p.view.countries.size()).arg(r.bytes));
        if (done)
            done(p);
    });
}

void ScanApiClient::fetchCandidates(const QString &networkKey, const QString &scope, const QString &country,
                                    const QStringList &seen, int limit, qint64 costBytes, std::function<void(const Candidates &)> done)
{
    const QString b = base();
    const QString dt = m_deviceToken ? m_deviceToken() : QString();
    if (!configured() || b.isEmpty() || dt.isEmpty()) {
        QTimer::singleShot(0, this, [done]() {
            Candidates c;
            c.reason = QStringLiteral("transport");
            if (done)
                done(c);
        });
        return;
    }
    QJsonObject body{{QStringLiteral("network_key"), networkKey}, {QStringLiteral("scope"), scope},
                     {QStringLiteral("limit"), qBound(1, limit, 24)}};
    if (scope == QLatin1String("country"))
        body.insert(QStringLiteral("country"), country.toUpper());
    QJsonArray s;
    for (const QString &id : seen)
        if (s.size() < 512)
            s << id;
    body.insert(QStringLiteral("seen"), s);
    IScanHttp::Request rq;
    rq.method = QByteArrayLiteral("POST");
    rq.url = b + QStringLiteral("/v1/scan/candidates");
    rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(dt))
               << qMakePair(QByteArrayLiteral("Content-Type"), QByteArrayLiteral("application/json"));
    rq.body = QJsonDocument(body).toJson(QJsonDocument::Compact);
    rq.maxBytes = costBytes;
    QPointer<ScanApiClient> self(this);
    m_http->send(rq, [self, done](const IScanHttp::Response &r) {
        Candidates c;
        c.bytes = r.bytes;
        c.status = r.status;
        if (r.status == 200 && self) {
            const QString key = self->m_pubKeyHex ? self->m_pubKeyHex() : QString();
            const bool sigOk = !key.isEmpty()
                               && verifyDetachedWithContext(key, QLatin1String(kScanCandidatesSigContext), r.body, r.header("x-tribe-sig"));
            const QJsonObject o = QJsonDocument::fromJson(r.body).object();
            c.ok = sigOk && scanCandidatesFromJson(o, c.view);
            if (c.ok)
                c.body = o;
            if (!c.ok)
                c.reason = QStringLiteral("invalid"); // an unverified answer is never used
        } else {
            c.reason = scanErrorReason(r.status);
        }
        if (self)
            self->emitLog(QStringLiteral("candidates status=%1 nodes=%2 upstream=%3 exhausted=%4 bytes=%5")
                              .arg(r.status).arg(c.view.nodes.size()).arg(c.view.upstream.size()).arg(c.view.exhausted).arg(r.bytes));
        if (done)
            done(c);
    });
}

// --- probe-batch -----------------------------------------------------------------------------------------------

// Device round of 19.11: the race asked its probe seats as a tunnel came up; that transition cut the request and
// the seats the server had granted stayed until their TTL, unknown to the app. Contract 1.15.0: the batch carries an
// operation id made here, before the first send; a send our own transition cut (scanRetryCanceledRequest) goes again
// with the SAME body - the server answers the same seats - and only an answer echoing the id is used. The seats
// belong to the returned owner (ScanSeatBatch), released by the id whenever they may be held and unseen.
std::unique_ptr<ScanSeatBatch> ScanApiClient::probeBatch(const QStringList &profileIds, bool includeConfig, qint64 costBytes,
                                                         std::function<void(const Batch &)> done,
                                                         std::function<void(qint64)> releaseBytes)
{
    auto st = std::make_shared<ScanSeatBatch::State>();
    st->api = this;
    st->op = scanOperationId();
    st->profileIds = profileIds;
    st->cost = costBytes;
    st->done = std::move(done);
    st->releaseBytes = std::move(releaseBytes);
    st->releaseCost = qint64(kScanSeatReleaseSends) * ScanTunables().costApiBytes; // the chain's one budget (ScanBudget.h)
    std::unique_ptr<ScanSeatBatch> owner(new ScanSeatBatch(st));
    QStringList ids;
    for (const QString &p : profileIds)
        if (profileIdValid(p) && !ids.contains(p))
            ids << p;
    const QString b = base();
    const QString token = m_deviceToken ? m_deviceToken() : QString();
    if (ids.isEmpty() || !configured() || b.isEmpty() || token.isEmpty()) {
        QTimer::singleShot(0, this, [st]() {
            ScanSeatBatch::State::endRequest(st); // nothing was sent: no seat can exist
            Batch r;
            r.failCode = QStringLiteral("transport");
            for (const QString &p : st->profileIds)
                r.items << BatchItem{p, false, QString(), QString(), QStringLiteral("transport"), QString()};
            ScanSeatBatch::State::deliver(st, r);
        });
        return owner;
    }
    QJsonArray arr;
    for (const QString &p : ids)
        arr << p;
    IScanHttp::Request rq;
    rq.method = QByteArrayLiteral("POST");
    rq.url = b + QStringLiteral("/v1/upstream/lease/probe-batch");
    rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(token))
               << qMakePair(QByteArrayLiteral("Content-Type"), QByteArrayLiteral("application/json"));
    rq.body = QJsonDocument(QJsonObject{{QStringLiteral("profile_ids"), arr}, {QStringLiteral("include_config"), includeConfig},
                                        {QStringLiteral("operation_id"), st->op}})
                  .toJson(QJsonDocument::Compact);
    sendBatch(st, rq, 0);
    return owner;
}

void ScanApiClient::sendBatch(std::shared_ptr<ScanSeatBatch::State> st, IScanHttp::Request rq, int attempt)
{
    rq.maxBytes = st->cost < 0 ? -1 : qMax<qint64>(0, st->cost - st->spent); // the batch's cut covers every send
    QPointer<ScanApiClient> self(this);
    m_http->send(rq, [self, st, rq, attempt](const IScanHttp::Response &r) {
        st->spent += r.bytes;
        const bool again = st->owned && scanRetryCanceledRequest(r.status, r.canceled, attempt)
                           && (st->cost < 0 || st->cost - st->spent > 0);
        if (self && again) {
            ++st->resends;
            self->emitLog(QStringLiteral("probe_batch status=0 canceled=1 resend=%1 op=%2 bytes=%3")
                              .arg(attempt + 1).arg(st->op.left(6)).arg(r.bytes));
            QTimer::singleShot(kScanCanceledRetryDelayMs, self.data(), [self, st, rq, attempt]() {
                if (self)
                    self->sendBatch(st, rq, attempt + 1);
            });
            return;
        }
        if (self) {
            self->finishBatch(st, r);
            return;
        }
        ScanSeatBatch::State::endRequest(st); // the client went with the app: nothing can be released
        Batch out;
        out.failCode = QStringLiteral("transport");
        out.bytes = st->spent;
        for (const QString &p : st->profileIds)
            out.items << BatchItem{p, false, QString(), QString(), QStringLiteral("transport"), QString()};
        ScanSeatBatch::State::deliver(st, out);
    });
}

void ScanApiClient::finishBatch(std::shared_ptr<ScanSeatBatch::State> st, const IScanHttp::Response &r)
{
    Batch out;
    out.bytes = st->spent;
    out.status = r.status;
    out.resends = st->resends;
    const QStringList &profileIds = st->profileIds;
    const auto failAll = [&out, &profileIds](const QString &code) {
        out.ok = false;
        out.failCode = code;
        out.items.clear();
        for (const QString &p : profileIds)
            out.items << BatchItem{p, false, QString(), QString(), code, QString()};
    };
    bool unseen = r.status == 0; // no HTTP answer: the server may have granted seats nobody saw
    QString why;
    if (r.status == 200) {
        const QString key = m_pubKeyHex ? m_pubKeyHex() : QString();
        const bool sigOk = !key.isEmpty()
                           && verifyDetachedWithContext(key, QLatin1String(kUpstreamLeaseSigContext), r.body, r.header("x-tribe-sig"));
        const QJsonObject o = QJsonDocument::fromJson(r.body).object();
        if (!sigOk || o.value(QLatin1String("type")).toString() != QLatin1String("upstream_probe_batch")) {
            failAll(QStringLiteral("transport")); // an unverified answer grants nothing
            unseen = true;
            why = QStringLiteral(" unverified=1");
        } else if (o.value(QLatin1String("operation_id")).toString() != st->op) {
            failAll(QStringLiteral("transport")); // another operation's answer (a late one, a mix-up): not ours to use
            unseen = true;
            why = QStringLiteral(" foreign_op=1");
        } else {
            QHash<QString, BatchItem> got;
            for (const QJsonValue &v : o.value(QLatin1String("items")).toArray()) {
                const QJsonObject it = v.toObject();
                BatchItem bi;
                bi.profileId = it.value(QLatin1String("profile_id")).toString();
                bi.granted = it.value(QLatin1String("granted")).toBool(false);
                bi.leaseId = it.value(QLatin1String("lease_id")).toString();
                bi.config = it.value(QLatin1String("config")).toString();
                bi.configSha256 = it.value(QLatin1String("config_sha256")).toString();
                bi.code = it.value(QLatin1String("code")).toString();
                if (bi.granted && !leaseIdValid(bi.leaseId)) {
                    bi.granted = false;
                    bi.code = QStringLiteral("lease_failed");
                }
                if (!bi.granted && bi.code.isEmpty())
                    bi.code = QStringLiteral("lease_failed");
                if (!got.contains(bi.profileId))
                    got.insert(bi.profileId, bi);
            }
            out.ok = true;
            for (const QString &p : profileIds) {
                out.items << got.value(p, BatchItem{p, false, QString(), QString(), QStringLiteral("lease_failed"), QString()});
                if (out.items.last().granted)
                    st->held << out.items.last().leaseId;
            }
        }
    } else if (r.status == 403) {
        failAll(QStringLiteral("not_entitled"));
    } else if (r.status == 410) {
        failAll(QStringLiteral("over_quota"));
    } else if (r.status == 404) {
        failAll(QStringLiteral("disabled"));
    } else if (r.status == 429) {
        failAll(QStringLiteral("rate_limited"));
    } else {
        failAll(QStringLiteral("transport"));
    }
    ScanSeatBatch::State::endRequest(st);
    int granted = 0;
    for (const BatchItem &bi : out.items)
        granted += bi.granted ? 1 : 0;
    emitLog(QStringLiteral("probe_batch status=%1 asked=%2 granted=%3 bytes=%4 op=%5%6%7%8")
                .arg(r.status)
                .arg(profileIds.size())
                .arg(granted)
                .arg(out.bytes)
                .arg(st->op.left(6))
                .arg(st->resends > 0 ? QStringLiteral(" resends=%1").arg(st->resends) : QString())
                .arg(out.ok ? QString() : QStringLiteral(" fail=") + out.failCode)
                .arg(why));
    // Seats that may be held and that nobody will release one by one: released by the operation id now.
    if (unseen || (!st->owned && !st->held.isEmpty())) {
        emitLog(QStringLiteral("probe_batch release op=%1 reason=%2").arg(st->op.left(6), unseen ? QStringLiteral("unseen") : QStringLiteral("owner_gone")));
        releaseBatch(st);
    }
    ScanSeatBatch::State::deliver(st, out); // (a retired batch: the answer's bytes and any release are counted by now)
}

void ScanApiClient::releaseLeases(const QStringList &leaseIds, qint64 costBytes, std::function<void(qint64)> done,
                                  const QString &operationId)
{
    QJsonArray arr;
    for (const QString &l : leaseIds)
        if (leaseIdValid(l))
            arr << l;
    const bool byOp = scanOperationIdValid(operationId);
    const QString b = base();
    const QString token = m_deviceToken ? m_deviceToken() : QString();
    if ((arr.isEmpty() && !byOp) || !configured() || b.isEmpty() || token.isEmpty()) {
        QTimer::singleShot(0, this, [done]() {
            if (done)
                done(0);
        });
        return;
    }
    IScanHttp::Request rq;
    rq.method = QByteArrayLiteral("POST");
    rq.url = b + QStringLiteral("/v1/upstream/lease/probe-batch/release");
    rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(token))
               << qMakePair(QByteArrayLiteral("Content-Type"), QByteArrayLiteral("application/json"));
    QJsonObject body;
    if (!arr.isEmpty())
        body.insert(QStringLiteral("lease_ids"), arr);
    if (byOp)
        body.insert(QStringLiteral("operation_id"), operationId);
    rq.body = QJsonDocument(body).toJson(QJsonDocument::Compact);
    rq.maxBytes = costBytes;
    rq.timeoutMs = 5000;
    sendRelease(rq, arr.size(), 0, 0, 0, std::move(done));
}

// Device round of 19.11 (iPhone Air, 06:31:22 and 06:32:04): the race's release went out as its winner's tunnel came
// up, that transition aborted it (net_error 5, status 0) and nothing sent it again - both probe seats stayed until
// the server's probe TTL; at 08:18:42 a prod API restart answered a seat release 502. The one rule of every seat
// release (UpstreamLeaseWire.h::seatReleaseNext, shared with the session seat's DELETE): no HTTP answer, a 5xx or an answer
// without the API's mark is sent again on the shared growing spacing within its budget; any other answer is final. Every probe
// release - the batch's own (releaseBatch) and the explicit one (releaseLeases) - ends here, the only caller of the rule.
void ScanApiClient::sendRelease(const IScanHttp::Request &rq, int leases, int attempt, qint64 spent, qint64 spacedMs,
                                std::function<void(qint64)> done, quint64 bgKey)
{
    QPointer<ScanApiClient> self(this);
    // ONE byte budget for the whole chain (round 13 R2): `rq.maxBytes` is the release's allowance, every send is cut at what is left of
    // it, like sendBatch does; the bytes of every send go to `done` as before.
    IScanHttp::Request cur = rq;
    if (rq.maxBytes >= 0)
        cur.maxBytes = qMax<qint64>(0, rq.maxBytes - spent);
    m_http->send(cur, [self, rq, leases, attempt, spent, spacedMs, done, bgKey](const IScanHttp::Response &r) {
        const qint64 total = spent + r.bytes;
        if (!self) {
            if (bgKey)
                avpn::bgtask::end(avpn::bgtask::Reason::Release, bgKey, avpn::bgtask::EndWhy::Settled);
            if (done)
                done(total);
            return;
        }
        // A try cut at its own byte allowance is final: the same allowance would cut it again.
        // Round 12 R5: only the API's own answer (it carries the mark, like the session DELETE's) can finish a release; a blocking
        // proxy's short 200/403 is a transport-class failure: resent on the spacing, then given up.
        const bool fromApi = upstreamFromTribeApi(r.header(kUpstreamTribeApiHeader));
        SeatReleaseNext next = r.cut ? SeatReleaseNext{} : seatReleaseNext(r.status, attempt, spacedMs, self->releaseRetryBudgetMs, fromApi);
        if (next.kind == UpstreamReleaseTry::Resend && rq.maxBytes >= 0 && rq.maxBytes - total <= 0)
            next.kind = UpstreamReleaseTry::NotConfirmed; // the byte budget is used up: the chain ends, the seat is left to its TTL
        const bool again = next.kind == UpstreamReleaseTry::Resend;
        self->emitLog(QStringLiteral("probe_release status=%1 leases=%2 by_op=%3 bytes=%4%5")
                          .arg(r.status).arg(leases).arg(rq.body.contains("\"operation_id\"") ? 1 : 0).arg(r.bytes)
                          .arg(again ? QStringLiteral(" canceled=%1 resend=%2 in_ms=%3").arg(r.canceled ? 1 : 0).arg(attempt + 1).arg(next.delayMs)
                               : next.kind == UpstreamReleaseTry::NotConfirmed ? QStringLiteral(" gave_up=1 tries=%1").arg(attempt + 1)
                                                                               : QString()));
        if (!again) {
            if (bgKey)
                avpn::bgtask::end(avpn::bgtask::Reason::Release, bgKey, avpn::bgtask::EndWhy::Settled);
            if (done)
                done(total);
            return;
        }
        // Build 142: a release waiting to be resent holds background time (BackgroundTaskHook.h, iOS only).
        const quint64 key = bgKey ? bgKey : avpn::bgtask::newKey();
        avpn::bgtask::begin(avpn::bgtask::Reason::Release, key);
        QTimer::singleShot(next.delayMs, self.data(), [self, rq, leases, attempt, total, spacedMs, next, done, key]() {
            if (self)
                self->sendRelease(rq, leases, attempt + 1, total, spacedMs + next.delayMs, done, key);
            else {
                avpn::bgtask::end(avpn::bgtask::Reason::Release, key, avpn::bgtask::EndWhy::Settled);
                if (done)
                    done(total);
            }
        });
    });
}

// --- outcomes, netinfo -----------------------------------------------------------------------------------------

void ScanApiClient::sendOutcomes(const QString &networkKey, const QList<ScanOutcomeItem> &items, qint64 costBytes,
                                 std::function<void(int, qint64)> done)
{
    ScanOutcomeCollector c;
    c.begin(networkKey);
    for (const ScanOutcomeItem &it : items)
        c.add(it);
    const QList<QJsonObject> batches = c.batches();
    const QString b = base();
    const QString token = m_deviceToken ? m_deviceToken() : QString();
    if (batches.isEmpty() || !configured() || b.isEmpty() || token.isEmpty()) {
        QTimer::singleShot(0, this, [done]() {
            if (done)
                done(0, 0);
        });
        return;
    }
    // One reservation for the action: the batches go one after another inside it (normally one batch).
    auto spent = std::make_shared<qint64>(0);
    auto next = std::make_shared<std::function<void(int)>>();
    QPointer<ScanApiClient> self(this);
    *next = [self, batches, b, token, costBytes, spent, next, done](int i) {
        if (!self || i >= batches.size() || (costBytes >= 0 && *spent >= costBytes)) {
            if (done)
                done(i >= batches.size() ? 200 : 0, *spent);
            *next = nullptr; // break the self reference
            return;
        }
        IScanHttp::Request rq;
        rq.method = QByteArrayLiteral("POST");
        rq.url = b + QStringLiteral("/v1/telemetry/path-outcomes");
        rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(token))
                   << qMakePair(QByteArrayLiteral("Content-Type"), QByteArrayLiteral("application/json"));
        rq.body = QJsonDocument(batches.at(i)).toJson(QJsonDocument::Compact);
        rq.maxBytes = costBytes < 0 ? -1 : costBytes - *spent;
        self->m_http->send(rq, [self, spent, next, i, done](const IScanHttp::Response &r) {
            *spent += r.bytes;
            if (self)
                self->emitLog(QStringLiteral("outcomes status=%1 bytes=%2").arg(r.status).arg(r.bytes));
            if (r.status / 100 != 2) {
                if (done)
                    done(r.status, *spent);
                *next = nullptr;
                return;
            }
            if (*next)
                (*next)(i + 1);
        });
    };
    (*next)(0);
}

void ScanApiClient::netinfo(const QString &directApiBase, const QString &scanToken, qint64 costBytes,
                            std::function<void(const ScanAccessAttempt &, qint64)> done)
{
    const QString b = trimBase(directApiBase);
    if (b.isEmpty() || scanToken.isEmpty() || !m_http) {
        QTimer::singleShot(0, this, [done]() {
            if (done)
                done(ScanAccessAttempt(), 0);
        });
        return;
    }
    IScanHttp::Request rq;
    rq.url = b + QStringLiteral("/v1/netinfo");
    rq.headers << qMakePair(QByteArrayLiteral("Authorization"), bearer(scanToken));
    rq.maxBytes = costBytes;
    rq.timeoutMs = 6000;
    QPointer<ScanApiClient> self(this);
    m_http->send(rq, [self, done](const IScanHttp::Response &r) {
        ScanAccessAttempt a;
        a.attempted = true;
        a.httpAnswered = r.status > 0;
        if (r.status == 200) {
            const QJsonObject o = QJsonDocument::fromJson(r.body).object();
            const double asn = o.value(QLatin1String("asn")).toDouble(0);
            a.facts.asn = asn >= 1 && asn <= 4294967295.0 ? qint64(asn) : 0;
            a.facts.netToken = o.value(QLatin1String("net_token")).toString().left(64);
        }
        if (self)
            self->emitLog(QStringLiteral("netinfo status=%1 bytes=%2").arg(r.status).arg(r.bytes));
        if (done)
            done(a, r.bytes);
    });
}

// --- the live-tunnel probe -------------------------------------------------------------------------------------

void ScanApiClient::liveProbe(const QString &probeBase, const QString &scanToken, const QString &profileId, int warmBytes,
                              int bytes, qint64 costBytes, int timeoutMs, std::function<void(const ScanProbeFacts &)> done)
{
    const QString b = trimBase(probeBase);
    if (b.isEmpty() || scanToken.isEmpty() || !m_probe || bytes <= 0) {
        QTimer::singleShot(0, this, [done, bytes]() {
            ScanProbeFacts f;
            f.stage = ScanStage::Data;
            f.bytesRequested = qMax(0, bytes);
            f.error = ScanProbeError::Config; // no verdict: «Подключено» stays unproven
            if (done)
                done(f);
        });
        return;
    }
    UpstreamLeaseClient::ProbeRequest warm;
    warm.base = b;
    warm.scanToken = scanToken;
    warm.bytes = qMax(1024, warmBytes);
    warm.nonce = scanProbeNonce();
    warm.profileId = profileIdValid(profileId) ? profileId : QString();
    warm.timeoutMs = timeoutMs;
    // The allowance is enforced on the wire (review F2): one TLS estimate, then the warm request may use the
    // rest, the data request what the warm one left; what is reported is what was read, never clamped.
    const qint64 wireLeft = costBytes < 0 ? -1 : qMax<qint64>(0, costBytes - kScanTlsOverheadBytes);
    warm.maxWireBytes = wireLeft;
    UpstreamLeaseClient::ProbeRequest data = warm;
    data.bytes = bytes;
    data.nonce = scanProbeNonce();
    QPointer<ScanApiClient> self(this);
    ProbeRunner runner = m_probe;
    runner(warm, [self, runner, data, costBytes, done](const UpstreamProbeFacts &w) {
        ScanProbeFacts f;
        f.stage = ScanStage::Data;
        f.bytesRequested = data.bytes;
        f.ttfb1Ms = w.ttfbMs >= 0 ? int(w.ttfbMs) : -1;
        const qint64 base = kScanTlsOverheadBytes; // one TLS handshake; headers and bodies are counted as read
        if (w.httpStatus != 200 || w.bytesReceived != w.bytesRequested || w.cutAtCap) {
            f.httpStatus = w.cutAtCap ? 0 : w.httpStatus;
            f.durationMs = w.elapsedMs >= 0 ? int(w.elapsedMs) : -1;
            f.spentBytes = base + w.wireBytes; // what really came, an overrun of the last chunk included
            if (w.cutAtCap)
                f.error = ScanProbeError::Budget; // cut at the allowance: no verdict
            if (w.httpStatus == 0)
                f.error = ScanProbeError::Dial;
            if (self)
                self->emitLog(QStringLiteral("live_probe warm status=%1").arg(w.httpStatus));
            if (done)
                done(f);
            return;
        }
        UpstreamLeaseClient::ProbeRequest second = data;
        if (data.maxWireBytes >= 0)
            second.maxWireBytes = qMax<qint64>(0, data.maxWireBytes - w.wireBytes);
        runner(second, [self, w, data, f, costBytes, done](const UpstreamProbeFacts &d) mutable {
            f.httpStatus = d.httpStatus;
            f.rttMs = d.ttfbMs >= 0 ? int(d.ttfbMs) : -1;
            f.t64Ms = (d.elapsedMs >= 0 && d.ttfbMs >= 0) ? int(d.elapsedMs - d.ttfbMs) : -1;
            f.durationMs = (w.elapsedMs >= 0 && d.elapsedMs >= 0) ? int(w.elapsedMs + d.elapsedMs) : -1;
            f.bytesReceived = d.httpStatus == 200 ? d.bytesReceived : 0;
            f.shaOk = d.httpStatus == 200 && d.bytesReceived == data.bytes
                      && d.bodySha256Hex.toLower() == tribeProbeExpectedSha256Hex(data.nonce, data.bytes);
            f.egressClass = d.egressClass;
            f.egressNode = d.egressNode;
            bool ok = false;
            const qint64 asn = d.egressAsnHeader.trimmed().toLongLong(&ok);
            f.egressAsn = ok && asn > 0 && asn <= 4294967295LL ? asn : 0;
            f.egressNetToken = d.egressNetToken.left(64);
            if (d.cutAtCap) {
                f.httpStatus = 0;           // cut at the allowance: no complete answer
                f.bytesReceived = 0;
                f.shaOk = false;
                f.error = ScanProbeError::Budget;
            } else if (d.httpStatus == 0) {
                f.error = ScanProbeError::Dial;
            } else if (d.maxStallMs >= 0 && d.bytesReceived < data.bytes && d.httpStatus == 200) {
                f.error = ScanProbeError::Short;
            }
            Q_UNUSED(costBytes);
            f.spentBytes = base + w.wireBytes + d.wireBytes; // what really came (never clamped to the allowance)
            if (self)
                self->emitLog(QStringLiteral("live_probe status=%1 digest=%2 bytes=%3")
                                  .arg(d.httpStatus)
                                  .arg(f.shaOk ? QStringLiteral("ok") : QStringLiteral("bad"))
                                  .arg(f.spentBytes));
            if (done)
                done(f);
        });
    });
}

void ScanApiClient::speedProbe(const QString &probeBase, const QString &scanToken, const QString &profileId, qint64 bytes,
                               int timeoutMs, std::function<void(const SpeedFacts &)> done)
{
    const QString b = trimBase(probeBase);
    if (b.isEmpty() || scanToken.isEmpty() || !m_probe || bytes <= 0) {
        QTimer::singleShot(0, this, [done]() {
            if (done)
                done(SpeedFacts());
        });
        return;
    }
    UpstreamLeaseClient::ProbeRequest rq;
    rq.base = b;
    rq.scanToken = scanToken;
    rq.bytes = bytes;
    rq.nonce = scanProbeNonce();
    rq.profileId = profileIdValid(profileId) ? profileId : QString();
    rq.timeoutMs = timeoutMs;
    rq.maxWireBytes = bytes + 2048; // the body and its headers: the sample's own allowance (review F2)
    QPointer<ScanApiClient> self(this);
    m_probe(rq, [self, rq, done](const UpstreamProbeFacts &d) {
        SpeedFacts f;
        f.httpStatus = d.cutAtCap ? 0 : d.httpStatus;
        f.wireBytes = d.wireBytes;
        f.bytes = d.httpStatus == 200 ? d.bytesReceived : 0;
        f.ms = d.elapsedMs;
        f.digestOk = d.httpStatus == 200 && d.bytesReceived == rq.bytes
                     && d.bodySha256Hex.toLower() == tribeProbeExpectedSha256Hex(rq.nonce, rq.bytes);
        if (self)
            self->emitLog(QStringLiteral("speed_probe status=%1 digest=%2 bytes=%3")
                              .arg(d.httpStatus)
                              .arg(f.digestOk ? QStringLiteral("ok") : QStringLiteral("bad"))
                              .arg(f.bytes));
        if (done)
            done(f);
    });
}

} // namespace avpn
