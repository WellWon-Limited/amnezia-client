#include "UpstreamLeaseClient.h"
#include "BackgroundTaskHook.h" // AVPN (build 142): background time while a seat release is resent

#include <QDebug>

#include "ConnectTunables.h"
#include "NetAwait.h" // armTimeout: the API client's per-request bound (no timer of our own)

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>

#include <memory>

namespace avpn {

namespace {

QString standbyFilePath()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + QStringLiteral("/upstream_standby.lkg");
}

// HTTP status of a finished reply; 0 = no complete answer: no status at all, or a 2xx whose body was cut
// (our timeout, a reset) - a partial signed body is a transport failure, not "another server".
int answerStatus(QNetworkReply *r)
{
    const QVariant code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    if (!code.isValid())
        return 0;
    const int s = code.toInt();
    if (s >= 200 && s < 300 && r->error() != QNetworkReply::NoError)
        return 0;
    return s;
}

// Bytes of a reply, bounded: a lease answer is at most a 256 KiB config + JSON escaping.
constexpr qint64 kMaxLeaseAnswerBytes = 2 * 1024 * 1024;

} // namespace

UpstreamLeaseClient::UpstreamLeaseClient(QObject *parent) : QObject(parent) {}

void UpstreamLeaseClient::configure(QNetworkAccessManager *nam, std::function<QString()> directBase,
                                    const QString &pubKeyHex, std::function<QString()> token)
{
    m_nam = nam;
    m_directBase = std::move(directBase);
    m_pubKeyHex = pubKeyHex;
    m_token = std::move(token);
}

bool UpstreamLeaseClient::configured() const
{
    return m_nam && m_directBase && m_token && !m_pubKeyHex.isEmpty();
}

QString UpstreamLeaseClient::baseFor(const LeaseRoute &route) const
{
    const QString b = route.apiBase.isEmpty() ? (m_directBase ? m_directBase() : QString()) : route.apiBase;
    QString out = b;
    while (out.endsWith(QLatin1Char('/')))
        out.chop(1);
    return out;
}

QNetworkReply *UpstreamLeaseClient::post(const QString &url, const QByteArray &body, const QString &bearer,
                                        int timeoutMs)
{
    if (!m_nam || bearer.isEmpty())
        return nullptr;
    QNetworkRequest req{QUrl(url)};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + bearer.toUtf8());
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *r = m_nam->post(req, body);
    armTimeout(r, timeoutMs);
    return r;
}

void UpstreamLeaseClient::acquire(quint64 requestId, const QString &profileId, LeaseKind kind,
                                  const QString &standbyConfigSha256, const LeaseRoute &route)
{
    const QString base = baseFor(route);
    const QString token = m_token ? m_token() : QString();
    // Device round 4 (R1a): the server granted seats in 3.8-4.2 s while the client gave up at 4 s - the seat stayed
    // taken and the path was blamed. The attempt stops WAITING at the lease share of its leg (a transport failure
    // for the owner, never recorded against the path), but the request lives on for kUpstreamLateGrantGraceMs: a
    // grant that arrives after that point was a real seat and is released at once over the direct route.
    const int waitMs = (hasStandbyFor && hasStandbyFor(profileId)) ? upstreamAcquireHedgeMsTuned() : upstreamAcquireTimeoutMsTuned();
    QNetworkReply *r = base.isEmpty() ? nullptr
                                      : post(base + QStringLiteral("/v1/upstream/lease"),
                                             upstreamAcquireBody(profileId, kind, standbyConfigSha256), token,
                                             waitMs + kUpstreamLateGrantGraceMs);
    if (!r) {
        // Not sendable (no base / no token): a transport failure, answered from the top of the loop.
        QTimer::singleShot(0, this, [this, requestId]() {
            if (onAcquire)
                onAcquire(requestId, classifyAcquireReply(0, {}, {}, m_pubKeyHex));
        });
        return;
    }
    auto answered = std::make_shared<bool>(false);
    m_acquiresOut.insert(requestId, profileId); // until its HTTP request ends (it outlives the attempt's wait)
    QTimer::singleShot(waitMs, r, [this, requestId, answered, waitMs]() {
        if (*answered)
            return;
        *answered = true; // the attempt stops waiting; the request goes on (a late grant is released below)
        qWarning() << "avpn upstream: lease answer later than" << waitMs
                   << "ms - the attempt moves on, a late grant will be released";
        if (onAcquire)
            onAcquire(requestId, classifyAcquireReply(0, {}, {}, m_pubKeyHex));
    });
    connect(r, &QNetworkReply::finished, this, [this, r, requestId, answered, route, profileId]() {
        r->deleteLater();
        m_acquiresOut.remove(requestId);
        const int status = answerStatus(r); // 0 = no complete HTTP answer (transport, timeout)
        const QByteArray body = r->read(kMaxLeaseAnswerBytes);
        const QByteArray sig = r->rawHeader(QByteArrayLiteral("X-Tribe-Sig"));
        // Lab 14.11 D1: an answer of our server (any status, any body) never starts from the standby pack.
        const bool fromTribeApi = upstreamFromTribeApi(r->rawHeader(QByteArray(kUpstreamTribeApiHeader)));
        const AcquireReply reply = classifyAcquireReply(status, body, sig, m_pubKeyHex, fromTribeApi);
        if (*answered) {
            if (reply.kind == LeaseReplyKind::Granted && upstreamLeaseIdValid(reply.grant.leaseId))
                reportLateGrant(profileId, reply.grant.leaseId, route);
            else
                reportAcquireEnded(profileId, QString());
            return;
        }
        *answered = true;
        if (onAcquire)
            onAcquire(requestId, reply);
        reportAcquireEnded(profileId, reply.kind == LeaseReplyKind::Granted ? reply.grant.leaseId : QString());
    });
}

bool UpstreamLeaseClient::acquireOutFor(const QString &profileId) const
{
    for (auto it = m_acquiresOut.constBegin(); it != m_acquiresOut.constEnd(); ++it)
        if (it.value() == profileId)
            return true;
    return false;
}

// What the client knows and the owner does not: the HTTP requests still alive. It reports the facts; the lease-id
// ledger (UpstreamLeaseOwner.h, "Lease id ledger") decides and sends - the client never releases a late grant itself
// (without an owner wired, as in a bare client, the old rule: give it back at once).
void UpstreamLeaseClient::reportLateGrant(const QString &profileId, const QString &leaseId, const LeaseRoute &route)
{
    if (onLateGrant) {
        onLateGrant(profileId, leaseId, route, acquireOutFor(profileId));
        return;
    }
    qWarning() << "avpn upstream: a late grant arrived after the attempt moved on - releasing it";
    sendRelease(0, leaseId, UpstreamMeter{}, upstreamReleaseRoute(route), /*attempt=*/0);
}

void UpstreamLeaseClient::reportAcquireEnded(const QString &profileId, const QString &grantedLeaseId)
{
    if (onAcquireEnded)
        onAcquireEnded(profileId, grantedLeaseId, acquireOutFor(profileId));
}

void UpstreamLeaseClient::renew(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter,
                                const LeaseRoute &route)
{
    const QString base = baseFor(route);
    const QString bearer = !route.renewToken.isEmpty() ? route.renewToken : (m_token ? m_token() : QString());
    QNetworkReply *r = (base.isEmpty() || !upstreamLeaseIdValid(leaseId))
                           ? nullptr
                           : post(base + QStringLiteral("/v1/upstream/lease/%1/renew").arg(leaseId),
                                  upstreamMeterBody(meter), bearer, kUpstreamRenewTimeoutMs);
    if (!r) {
        QTimer::singleShot(0, this, [this, requestId]() {
            if (onRenew)
                onRenew(requestId, classifyRenewReply(0, {}));
        });
        return;
    }
    connect(r, &QNetworkReply::finished, this, [this, r, requestId]() {
        r->deleteLater();
        const int status = answerStatus(r);
        if (onRenew)
            onRenew(requestId, classifyRenewReply(status, r->read(kMaxLeaseAnswerBytes)));
    });
}

void UpstreamLeaseClient::release(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter,
                                  const LeaseRoute &route)
{
    m_lastReleaseId = requestId;
    const LeaseRoute direct = upstreamReleaseRoute(route); // never through the tunnel being abandoned
    if (upstreamReleaseDue(m_stopPending, m_heldSinceMs, QDateTime::currentMSecsSinceEpoch(), false).hold) {
        m_held.append({requestId, leaseId, meter, direct});
        return;
    }
    sendRelease(requestId, leaseId, meter, direct, /*attempt=*/0);
}

void UpstreamLeaseClient::releaseVia(quint64 requestId, const QString &leaseId, const LeaseRoute &route)
{
    m_lastReleaseId = requestId;
    sendRelease(requestId, leaseId, UpstreamMeter{}, route, /*attempt=*/0); // a route that works: no hold, no strip
}

void UpstreamLeaseClient::holdReleasesForStop()
{
    m_tunnelDown = false; // the app is stopping a tunnel it believes running
    if (!m_stopPending)
        m_heldSinceMs = QDateTime::currentMSecsSinceEpoch();
    m_stopPending = true;
    // Review E5 of 18.11: past the native stop deadline the obligation stays (sent at the next confirmed
    // teardown); the journal says so - never a silent "released".
    QTimer::singleShot(kUpstreamReleaseHoldMaxMs, this, [this]() {
        const UpstreamReleaseDue d = upstreamReleaseDue(m_stopPending, m_heldSinceMs,
                                                        QDateTime::currentMSecsSinceEpoch(), false);
        if (d.overdue && !m_held.isEmpty())
            qWarning() << "avpn upstream: release held - stop not confirmed after" << kUpstreamReleaseHoldMaxMs
                       << "ms, kept until the tunnel is confirmed down, held=" << m_held.size();
    });
}

void UpstreamLeaseClient::holdReleasesForStopIfRunning()
{
    if (!m_tunnelDown) // the stop already happened (review F4 of 19.11): nothing to wait for
        holdReleasesForStop();
}

void UpstreamLeaseClient::tunnelStopped()
{
    m_tunnelDown = true;
    flushHeld(true);
}

void UpstreamLeaseClient::flushHeld(bool tunnelDown)
{
    if (!m_stopPending)
        return;
    if (!upstreamReleaseDue(m_stopPending, m_heldSinceMs, QDateTime::currentMSecsSinceEpoch(), tunnelDown).send)
        return;
    m_stopPending = false;
    const QList<HeldRelease> held = std::exchange(m_held, {});
    for (const HeldRelease &h : held) {
        if (releaseWanted && !releaseWanted(h.requestId))
            continue; // taken back while it waited for the stop
        sendRelease(h.requestId, h.leaseId, h.meter, h.route, /*attempt=*/0);
    }
}

void UpstreamLeaseClient::sendRelease(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter,
                                      const LeaseRoute &route, int attempt, qint64 spacedMs, quint64 bgKey)
{
    const QString base = baseFor(route);
    const QString bearer = !route.renewToken.isEmpty() ? route.renewToken : (m_token ? m_token() : QString());
    QNetworkReply *r = nullptr;
    if (m_nam && !base.isEmpty() && !bearer.isEmpty() && upstreamLeaseIdValid(leaseId)) {
        QNetworkRequest req{QUrl(base + QStringLiteral("/v1/upstream/lease/%1").arg(leaseId))};
        // No report to give (a late grant, a seat the tunnel owner held): no body at all - a report with seq 0
        // is refused 422 by the server and the seat stayed until its TTL (upstreamReleaseBody).
        const QByteArray body = upstreamReleaseBody(meter);
        if (!body.isEmpty())
            req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
        req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + bearer.toUtf8());
        req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
        // Contract §6: bounded to 1.5 s; on failure the server frees the seat at TTL.
        r = m_nam->sendCustomRequest(req, QByteArrayLiteral("DELETE"), body);
        armTimeout(r, kUpstreamReleaseTimeoutMs);
        m_inFlight.insert(requestId);
    }
    if (!r) {
        QTimer::singleShot(0, this, [this, requestId]() {
            if (onReleaseDone)
                onReleaseDone(requestId, false); // not sendable: never reached the server
        });
        return;
    }
    connect(r, &QNetworkReply::finished, this, [this, r, requestId, leaseId, meter, route, attempt, spacedMs, bgKey]() {
        r->deleteLater();
        m_inFlight.remove(requestId); // the DELETE is off the wire: a start of the profile may go
        // The release goes out just before the tunnel transition it belongs to, and that transition aborts every
        // API request in flight (owner's iPhone 16.11: "net_error 5" within 40-80 ms); an API restart answers 502
        // (device round 19.11). seatReleaseNext - the one rule of every seat release: no answer or 5xx is sent again
        // on the shared growing spacing within its budget; any other HTTP answer is final.
        const QVariant code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        const int status = code.isValid() ? code.toInt() : 0;
        const SeatReleaseNext next = seatReleaseNext(status, attempt, spacedMs, releaseRetryBudgetMs);
        switch (next.kind) {
        case UpstreamReleaseTry::Resend:
            if (releaseWanted && !releaseWanted(requestId)) { // taken back by a newer start of the profile
                qInfo() << "avpn upstream: seat release withdrawn by a newer start - not resent";
                if (bgKey)
                    avpn::bgtask::end(avpn::bgtask::Reason::Release, bgKey, avpn::bgtask::EndWhy::Settled);
                return;
            }
            qInfo().noquote() << QStringLiteral("avpn upstream: seat release status=%1 net_error=%2 resend=%3 in %4 ms")
                                     .arg(status).arg(int(r->error())).arg(attempt + 1).arg(next.delayMs);
            // Build 142: a release waiting to be resent holds background time (iOS), so the resend is not
            // delayed by a suspended app; BackgroundTaskHook.h (no-op off iOS). The key ends with the release.
            {
                const quint64 key = bgKey ? bgKey : avpn::bgtask::newKey();
                avpn::bgtask::begin(avpn::bgtask::Reason::Release, key);
                QTimer::singleShot(next.delayMs, this, [this, requestId, leaseId, meter, route, attempt, spacedMs, next, key]() {
                    if (releaseWanted && !releaseWanted(requestId)) {
                        avpn::bgtask::end(avpn::bgtask::Reason::Release, key, avpn::bgtask::EndWhy::Settled);
                        return;
                    }
                    sendRelease(requestId, leaseId, meter, route, attempt + 1, spacedMs + next.delayMs, key);
                });
            }
            return;
        case UpstreamReleaseTry::Answered:
            if (bgKey)
                avpn::bgtask::end(avpn::bgtask::Reason::Release, bgKey, avpn::bgtask::EndWhy::Settled);
            if (onReleaseDone)
                onReleaseDone(requestId, true);
            return;
        case UpstreamReleaseTry::NotConfirmed:
            qWarning().noquote() << QStringLiteral("avpn upstream: seat release gave up status=%1 net_error=%2 tries=%3 - left to the server's TTL")
                                        .arg(status).arg(int(r->error())).arg(attempt + 1);
            if (bgKey)
                avpn::bgtask::end(avpn::bgtask::Reason::Release, bgKey, avpn::bgtask::EndWhy::Settled);
            if (onReleaseDone)
                onReleaseDone(requestId, false);
            return;
        }
    });
}

bool UpstreamLeaseClient::fetchStandby(const QString &networkKey,
                                       std::function<void(int, const QByteArray &, const QByteArray &)> done)
{
    if (!configured() || !m_standbyReply.isNull())
        return false;
    const QString base = baseFor(LeaseRoute());
    const QString token = m_token();
    if (base.isEmpty() || token.isEmpty())
        return false;
    QUrl url(base + QStringLiteral("/v1/upstream/standby"));
    if (upstreamNetworkKeyValid(networkKey)) {
        QUrlQuery q;
        q.addQueryItem(QStringLiteral("network_key"), networkKey);
        url.setQuery(q);
    }
    QNetworkRequest req{url};
    req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + token.toUtf8());
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *r = m_nam->get(req);
    armTimeout(r);
    m_standbyReply = r;
    connect(r, &QNetworkReply::finished, this, [this, r, done]() {
        r->deleteLater();
        m_standbyReply.clear();
        const QVariant code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        const int status = code.isValid() ? code.toInt() : 0;
        const QByteArray body = r->read(kStandbyMaxBodyBytes + 1);
        const QByteArray sig = r->rawHeader(QByteArrayLiteral("X-Tribe-Sig"));
        if (done)
            done(status, body, sig);
    });
    return true;
}

bool UpstreamLeaseClient::saveStandby(const StandbyStored &s)
{
    QSaveFile f(standbyFilePath());
    if (!f.open(QIODevice::WriteOnly))
        return false;
    f.write(serializeStandbyStored(s));
    return f.commit();
}

bool UpstreamLeaseClient::loadStandby(StandbyStored &out)
{
    QFile f(standbyFilePath());
    if (!f.open(QIODevice::ReadOnly))
        return false;
    return parseStandbyStored(f.read(2 * kStandbyMaxBodyBytes), out);
}

void UpstreamLeaseClient::clearStandby()
{
    QFile::remove(standbyFilePath());
}

void UpstreamLeaseClient::runProbe(const ProbeRequest &pr, std::function<void(const UpstreamProbeFacts &)> done)
{
    auto facts = std::make_shared<UpstreamProbeFacts>();
    facts->bytesRequested = pr.bytes;
    facts->nonce = pr.nonce;
    if (!m_nam || pr.base.isEmpty() || pr.scanToken.isEmpty() || pr.bytes <= 0) {
        QTimer::singleShot(0, this, [facts, done]() {
            if (done)
                done(*facts);
        });
        return;
    }
    QUrl url(pr.base + pr.path);
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("bytes"), QString::number(pr.bytes));
    q.addQueryItem(QStringLiteral("nonce"), QString::fromLatin1(pr.nonce));
    if (!pr.profileId.isEmpty())
        q.addQueryItem(QStringLiteral("profile_id"), pr.profileId);
    url.setQuery(q);
    QNetworkRequest req{url};
    // Backend 14.11: the scan token travels as Authorization Bearer, exactly as the lease answer gave it
    // (the edge logs every request header except Authorization); the token is bound to its lease
    // server-side, so no lease header is sent.
    req.setRawHeader(QByteArrayLiteral("Authorization"), upstreamProbeAuthorization(pr.scanToken));
    if (!pr.accessNetToken.isEmpty())
        req.setRawHeader(QByteArrayLiteral("X-Tribe-Access-Net-Token"), pr.accessNetToken.toUtf8());
    if (pr.accessAsn > 0)
        req.setRawHeader(QByteArrayLiteral("X-Tribe-Access-Asn"), QByteArray::number(pr.accessAsn));
    // The body is hashed byte for byte: no transparent decompression, no cache.
    req.setRawHeader(QByteArrayLiteral("Accept-Encoding"), QByteArrayLiteral("identity"));
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *r = m_nam->get(req);
    armTimeout(r, qMax(1000, pr.timeoutMs));
    if (pr.onStarved && pr.firstByteShareMs >= 0)
        watchFirstByte(r, pr.firstByteShareMs, pr.onStarved);
    struct Live {
        QCryptographicHash hash{QCryptographicHash::Sha256};
        QElapsedTimer clock;
        qint64 lastChunkMs = -1;
        bool headersCounted = false;
    };
    auto live = std::make_shared<Live>();
    live->clock.start();
    const qint64 cap = pr.bytes;
    // AVPN Scanner (review F2, follow-up): the wire allowance of a scan probe. The app never READS more than it:
    // header bytes are charged first (Qt hands them over parsed, as one block), then every read is min(chunk,
    // what is left), Qt's own buffer ahead of us is bounded to what is left (setReadBufferSize, so TCP backpressure
    // holds the peer back), and the reply is aborted the moment nothing is left. What can still arrive beyond it
    // is only what was in transit: the kernel's socket receive buffer plus one TLS record (16 KiB) - never read,
    // never counted. -1 = not set (the upstream session's check, unchanged).
    const qint64 wireCap = pr.maxWireBytes;
    static constexpr qint64 kChunk = 16384;
    const auto left = [facts, wireCap]() { return wireCap - facts->wireBytes; };
    const auto boundBuffer = [r, left, wireCap]() {
        if (wireCap >= 0 && left() > 0)
            r->setReadBufferSize(qMin(kChunk, left())); // never 0: that would mean "unbounded"
    };
    if (wireCap >= 0)
        r->setReadBufferSize(qMin(kChunk, qMax<qint64>(1, wireCap))); // before the event loop sends the request
    auto cut = [r, facts]() {
        facts->cutAtCap = true;
        if (r->isRunning())
            r->abort();
    };
    auto countHeaders = [r, facts, live, wireCap, left, cut, boundBuffer]() {
        if (live->headersCounted || !r->attribute(QNetworkRequest::HttpStatusCodeAttribute).isValid())
            return;
        live->headersCounted = true;
        qint64 h = 16; // the status line
        for (const auto &p : r->rawHeaderPairs())
            h += p.first.size() + p.second.size() + 4;
        facts->wireBytes += h;
        if (wireCap >= 0 && left() < 0)
            cut(); // the headers alone passed it: nothing of the body is read
        else
            boundBuffer();
    };
    auto drain = [r, facts, live, cap, wireCap, countHeaders, left, cut, boundBuffer]() {
        countHeaders();
        for (;;) {
            if (facts->cutAtCap)
                return;
            qint64 want = kChunk;
            if (wireCap >= 0) {
                if (left() <= 0) {
                    if (r->bytesAvailable() > 0 || r->isRunning())
                        cut(); // nothing is left of the allowance: stop at once
                    return;
                }
                want = qMin(want, left());
            }
            const QByteArray chunk = wireCap >= 0 ? r->read(want) : r->readAll();
            if (chunk.isEmpty())
                return;
            const qint64 t = live->clock.elapsed();
            if (facts->ttfbMs < 0)
                facts->ttfbMs = t;
            if (live->lastChunkMs >= 0)
                facts->maxStallMs = qMax(facts->maxStallMs, t - live->lastChunkMs);
            live->lastChunkMs = t;
            facts->bytesReceived += chunk.size();
            facts->wireBytes += chunk.size();
            live->hash.addData(chunk);
            if (facts->bytesReceived > cap) {
                if (r->isRunning())
                    r->abort(); // oversize: not the body we asked for - stop downloading it
                return;
            }
            if (wireCap < 0)
                return; // readAll took everything there was
            boundBuffer();
        }
    };
    connect(r, &QNetworkReply::metaDataChanged, r, countHeaders);
    connect(r, &QNetworkReply::readyRead, r, drain);
    connect(r, &QNetworkReply::finished, this, [r, facts, live, drain, done]() {
        r->deleteLater();
        drain();
        const QVariant code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        facts->httpStatus = code.isValid() ? code.toInt() : 0;
        facts->elapsedMs = live->clock.elapsed();
        if (facts->maxStallMs < 0 && facts->ttfbMs >= 0)
            facts->maxStallMs = 0;
        facts->bodySha256Hex = live->hash.result().toHex();
        facts->egressClass = QString::fromLatin1(r->rawHeader(QByteArrayLiteral("X-Tribe-Egress-Class")));
        facts->egressAsnHeader = QString::fromLatin1(r->rawHeader(QByteArrayLiteral("X-Tribe-Egress-Asn")));
        facts->egressNetToken = QString::fromLatin1(r->rawHeader(QByteArrayLiteral("X-Tribe-Net-Token")));
        facts->egressNode = QString::fromLatin1(r->rawHeader(QByteArrayLiteral("X-Tribe-Egress-Node")));
        if (done)
            done(*facts);
    });
}

} // namespace avpn
