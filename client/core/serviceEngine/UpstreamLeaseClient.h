// client/core/serviceEngine/UpstreamLeaseClient.h
// AVPN serviceEngine - the Qt network I/O of upstream nodes and nothing else: lease acquire / renew /
// release (IUpstreamLeaseIo of UpstreamLeaseMachine), the standby pack fetch and its file at rest, and the
// sized data probe GET /v1/probe. Every decision lives in the pure headers (UpstreamLeaseWire.h,
// UpstreamLeaseOwner.h, UpstreamEngine.h, UpstreamVerdict.h); this class only sends, measures and hands
// the classified answer back. [IN-FORK BUILD: QtNetwork]
//
// Rules (CONNECT-INVARIANTS §1, §17.2): asynchronous only (QNetworkReply + armTimeout, never a nested
// event loop); every request has its bound (acquire upstreamAcquireTimeoutMsTuned, renew 15 s, release
// 1.5 s, probe the caller's); the device token or the lease's renew token goes into the Authorization
// header and nowhere else; nothing here logs a token, a lease id, a config, a host or a URL.
// Routing (decision A, contract §1/§2): route.apiBase empty = the app's usual API base (direct: the tunnel
// is down at bring-up); non-empty = the lease's tunnel_api_base (requests from the app process go INTO
// the running tunnel on macOS and iOS). Upstream Amnezia has no counterpart.
#pragma once

#include "UpstreamEngine.h"
#include "UpstreamLeaseMachine.h"

#include <QObject>
#include <QPointer>
#include <QString>

#include <functional>

class QNetworkAccessManager;
class QNetworkReply;

namespace avpn {

class UpstreamLeaseClient : public QObject, public IUpstreamLeaseIo
{
    Q_OBJECT
public:
    explicit UpstreamLeaseClient(QObject *parent = nullptr);

    // nam = the app's API client (its connection-cache resets on tunnel transitions cover these requests
    // too); directBase = the active API base at the moment of the call; pubKeyHex = the /v1/config key;
    // token = the device subscription token at the moment of the call.
    void configure(QNetworkAccessManager *nam, std::function<QString()> directBase, const QString &pubKeyHex,
                   std::function<QString()> token);
    bool configured() const;
    QString publicKeyHex() const { return m_pubKeyHex; }

    // Answers (GUI thread). The classification is the pure one (classifyAcquireReply / classifyRenewReply).
    std::function<void(quint64, const AcquireReply &)> onAcquire;
    std::function<void(quint64, const RenewReply &)> onRenew;
    // A release ended: confirmed = the server answered; false = it never did (its own timeout, a network error,
    // local resets past the bound, not sendable) - the seat is then left to the server's TTL.
    std::function<void(quint64, bool confirmed)> onReleaseDone;

    // IUpstreamLeaseIo
    void acquire(quint64 requestId, const QString &profileId, LeaseKind kind, const QString &standbyConfigSha256,
                 const LeaseRoute &route) override;
    void renew(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route) override;
    void release(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route) override;
    quint64 lastReleaseRequestId() const { return m_lastReleaseId; }

    // GET /v1/upstream/standby?network_key= with the device token on the direct base. done(httpStatus,
    // body, X-Tribe-Sig) - status 0 = no answer. One fetch at a time (false = one is in flight / not
    // configured).
    bool fetchStandby(const QString &networkKey, std::function<void(int, const QByteArray &, const QByteArray &)> done);
    bool standbyInFlight() const { return !m_standbyReply.isNull(); }

    // The pack at rest: the exact signed body + signature (UpstreamEngine.h::StandbyStored) in a file of
    // the app's data directory, written atomically (QSaveFile), the same way the signed bypass lists are
    // kept (BypassListService). Re-verified on every load by the caller (parseStandbyPack).
    static bool saveStandby(const StandbyStored &s);
    static bool loadStandby(StandbyStored &out);
    static void clearStandby();

    // One sized data probe through the tunnel (decision D): GET {base}{path}?bytes=N&nonce=...&profile_id=
    // with the scan token as Authorization Bearer (+ X-Tribe-Access-* for the server's learning), no
    // decompression, no cache; bytes hashed as they arrive; first byte and the longest gap measured.
    struct ProbeRequest {
        QString base;            // the lease's tunnel_api_base
        QString path = QStringLiteral("/v1/probe");
        QString scanToken;       // secret
        qint64 bytes = 0;
        QByteArray nonce;
        QString profileId;
        qint64 accessAsn = 0;
        QString accessNetToken;
        int timeoutMs = 5000;
        // The Scanner's byte allowance of this request: response headers + body as read, the reply aborted the
        // moment the count would pass it (read in bounded chunks). -1 (default) = today's behaviour: only the
        // body is bounded, by `bytes` (the upstream session's data check is unchanged).
        qint64 maxWireBytes = -1;
    };
    void runProbe(const ProbeRequest &req, std::function<void(const UpstreamProbeFacts &)> done);

    // Lease answers are never dropped here: a late answer goes to the machine, which ignores it by request
    // id or gives a cancelled acquire's seat back at once.

private:
    QString baseFor(const LeaseRoute &route) const;
    void sendRelease(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route,
                     int attempt);
    QNetworkReply *post(const QString &url, const QByteArray &body, const QString &bearer, int timeoutMs);

    QPointer<QNetworkAccessManager> m_nam;
    std::function<QString()> m_directBase;
    std::function<QString()> m_token;
    QString m_pubKeyHex;
    quint64 m_lastReleaseId = 0;
    QPointer<QNetworkReply> m_standbyReply;
};

} // namespace avpn
