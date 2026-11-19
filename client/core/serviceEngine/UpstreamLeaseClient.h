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

#include <QHash>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QString>

#include <functional>

class QNetworkAccessManager;
class QNetworkReply;

namespace avpn {

class UpstreamLeaseClient : public QObject, public IUpstreamLeaseIo
{
    Q_OBJECT
public:
    bool acquireOutFor(const QString &profileId) const;
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
    // A release ended: confirmed = the server answered it (2xx, or a final 4xx); false = it never did after the
    // resends of seatReleaseNext (no answer / 5xx past its budget, not sendable) - the seat is then left to the
    // server's TTL.
    std::function<void(quint64, bool confirmed)> onReleaseDone;
    // Facts for the lease-id ledger (UpstreamLeaseOwner.h): an acquire answered AFTER the attempt stopped waiting
    // (the grant it carries has no taker unless the owner says so), and the end of any acquire request.
    // newerOut / stillOut = another acquire of the same profile is still alive.
    std::function<void(const QString &profileId, const QString &leaseId, const LeaseRoute &route, bool newerOut)> onLateGrant;
    std::function<void(const QString &profileId, const QString &grantedLeaseId, bool stillOut)> onAcquireEnded;
    // Asked before every resend of a release and before a held one is sent: false = the owner took the release back
    // (a start of its profile - UpstreamLeaseOwner.h, row S1): it is dropped silently, no onReleaseDone.
    std::function<bool(quint64 requestId)> releaseWanted;
    // How long the attempt waits for the direct acquire of this profile (UpstreamLeaseOwner::hasStandbyFor decides:
    // a profile with a standby-pack entry waits only the hedge, row S4). Unset = the full lease share.
    std::function<bool(const QString &profileId)> hasStandbyFor;
    void releaseVia(quint64 requestId, const QString &leaseId, const LeaseRoute &route) override;
    bool releaseInFlight(quint64 requestId) const override { return m_inFlight.contains(requestId); }
    bool acquireAlive(const QString &profileId) const override { return acquireOutFor(profileId); }
    // The spacing budget of a release's resends (UpstreamLeaseWire.h::seatReleaseNext; tests shorten it).
    qint64 releaseRetryBudgetMs = kSeatReleaseRetryBudgetMs;

    // IUpstreamLeaseIo
    void acquire(quint64 requestId, const QString &profileId, LeaseKind kind, const QString &standbyConfigSha256,
                 const LeaseRoute &route) override;
    void renew(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route) override;
    void release(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route) override;
    quint64 lastReleaseRequestId() const { return m_lastReleaseId; }
    // Decision of 18.11 (UpstreamLeaseWire.h::upstreamReleaseDue): the tunnel is being stopped - releases wait for
    // tunnelStopped() (the confirmed teardown; never a timer - review E5 of 18.11) and then go over the direct path.
    void holdReleasesForStop();
    void tunnelStopped();
    // The release after a confirmed stop (ReleaseAfterStop): holds for the stop only while a tunnel is believed
    // running - a Disconnected that already happened is not waited for again (review F4 of 19.11).
    void holdReleasesForStopIfRunning();
    void tunnelStarted() { m_tunnelDown = false; } // the adapter saw the native tunnel come up / connecting
    int heldReleases() const { return int(m_held.size()); }

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
        // T1 for provider legs: the data check's first-byte watch (NetAwait.h::watchFirstByte), the same one the
        // own-server check (whoami) has - starving / receiving again go to onStarved. Unset (the Scanner): none.
        qint64 firstByteShareMs = -1;
        std::function<void(bool)> onStarved;
    };
    void runProbe(const ProbeRequest &req, std::function<void(const UpstreamProbeFacts &)> done);

    // Lease answers are never dropped here: a late answer goes to the machine, which ignores it by request
    // id or gives a cancelled acquire's seat back at once.

private:
    QString baseFor(const LeaseRoute &route) const;
    void sendRelease(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route,
                     int attempt, qint64 spacedMs = 0, quint64 bgKey = 0);
    void reportLateGrant(const QString &profileId, const QString &leaseId, const LeaseRoute &route);
    void reportAcquireEnded(const QString &profileId, const QString &grantedLeaseId);
    QNetworkReply *post(const QString &url, const QByteArray &body, const QString &bearer, int timeoutMs);

    QPointer<QNetworkAccessManager> m_nam;
    std::function<QString()> m_directBase;
    std::function<QString()> m_token;
    QString m_pubKeyHex;
    quint64 m_lastReleaseId = 0;
    QPointer<QNetworkReply> m_standbyReply;
    struct HeldRelease {
        quint64 requestId = 0;
        QString leaseId;
        UpstreamMeter meter;
        LeaseRoute route;
    };
    QList<HeldRelease> m_held;
    QHash<quint64, QString> m_acquiresOut; // acquire request id -> profile, until its HTTP request ends
    QSet<quint64> m_inFlight; // release request ids with a DELETE on the wire
    bool m_tunnelDown = true; // the last tunnel event was a confirmed stop (or none yet)
    bool m_stopPending = false;
    qint64 m_heldSinceMs = 0;
    void flushHeld(bool tunnelDown);
};

} // namespace avpn
