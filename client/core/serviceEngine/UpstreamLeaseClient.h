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
    // The edge walk's next edge after a given one (ConfigService::nextEdgeAfter; "" = none): where a lease request on the direct
    // route goes when the last lease request to the walk's edge ended silent - ONE rule for acquire, renew and release
    // (UpstreamLeaseWire.h::upstreamDirectBase, device round air-C 24.11). Unset = the walk's edge only (a bare client).
    void setNextDirectBase(std::function<QString(const QString &)> next) { m_nextDirectBase = std::move(next); }
    // The app's own native state: a tunnel of ours is up now, in any state in which it may carry the app's requests (the facade's
    // fact, the one ConfigService reads too). With the client's own start / stop facts it decides the ACTUAL path of every request
    // (UpstreamLeaseWire.h::upstreamRequestPath, review round 44 F1). Unset = the client's own facts only.
    void setTunnelUpSource(std::function<bool()> up) { m_tunnelUpFn = std::move(up); }
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
    // route = the late grant's own token and the base it was asked on; acquireId = the request that was answered.
    std::function<void(const QString &profileId, const QString &leaseId, const LeaseRoute &route, bool newerOut, quint64 acquireId)> onLateGrant;
    // acquireId = the request that ended; seatUnknown = nobody can tell whether the server granted it (UpstreamLeaseWire.h::
    // upstreamAcquireOutcomeUnknown: no answer, a cut one, our own abort) - the ledger then owes that start's seat back by nonce.
    std::function<void(const QString &profileId, const QString &grantedLeaseId, bool stillOut, quint64 acquireId, bool seatUnknown)> onAcquireEnded;
    // An acquire request got an HTTP answer of the API (any status, any body except a cut one): its route works. Fired once per
    // request, in every path (in time or after the attempt stopped waiting), after the owner was told of the answer.
    std::function<void(quint64 requestId)> onRouteProved;
    // An acquire answer of the API carries `min_session_order` (contract 1.21.0, upstreamOrderFloorOf): the counter of the start
    // orders is raised to at least that value. Fired for every such answer, whichever start it belongs to, before the owner sees it.
    std::function<void(qint64 floorOrder)> onSessionOrderFloor;
    // Asked before every resend of a release and before a held one is sent: false = the owner took the release back
    // (a start of its profile - UpstreamLeaseOwner.h, row S1): it is dropped silently, no onReleaseDone.
    std::function<bool(quint64 requestId)> releaseWanted;
    void releaseVia(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route) override;
    bool acquireAlive(const QString &profileId) const override { return acquireOutFor(profileId); }
    // The spacing budget of a release's resends (UpstreamLeaseWire.h::seatReleaseNext; tests shorten it).
    qint64 releaseRetryBudgetMs = kSeatReleaseRetryBudgetMs;

    // IUpstreamLeaseIo
    void acquire(quint64 requestId, const QString &profileId, LeaseKind kind, const QString &standbyConfigSha256,
                 const LeaseRoute &route, const QString &sessionNonce, qint64 sessionOrder, bool hedged) override;
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
    void tunnelStarted() // the adapter saw the native tunnel come up / connecting
    {
        m_tunnelDown = false;
        m_stopConfirmed = false;
    }
    int heldReleases() const { return int(m_held.size()); }
    // Round mac-D2: no seat release of this client is held for a stop or still waiting for its answer (resends
    // included). The quit of the GUI waits for this, not only for the tunnel to stop (UpstreamEngine.h::runUpstreamQuit):
    // the release goes out when the stop is confirmed, and a quit that ended right then cut it off (device round D2).
    bool releasesSettled() const { return m_held.isEmpty() && m_releasesOpen.isEmpty(); }

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
    // Where a request goes and by which path, decided when it is built (targetFor) and kept with it until it ends.
    struct LeaseTarget {
        QString base;
        UpstreamRequestPath path = UpstreamRequestPath::Direct;
        bool redirected = false; // sent to the walk's next edge by the host rule
    };
    LeaseTarget targetFor(const LeaseRoute &route) const;
    // A lease request ended: the host rule's mark follows its outcome (the direct path only).
    void noteHostOutcome(const LeaseTarget &target, QNetworkReply *reply);
    void noteHostSilent(const LeaseTarget &target); // the attempt's wait passed with no answer
    void sendRelease(quint64 requestId, const QString &leaseId, const UpstreamMeter &meter, const LeaseRoute &route,
                     int attempt, qint64 spacedMs = 0, quint64 bgKey = 0);
    void reportLateGrant(const QString &profileId, const QString &leaseId, const LeaseRoute &route, quint64 acquireId);
    void reportAcquireEnded(const QString &profileId, const QString &grantedLeaseId, quint64 acquireId, bool seatUnknown);
    QNetworkReply *post(const QString &url, const QByteArray &body, const QString &bearer, int timeoutMs);

    QPointer<QNetworkAccessManager> m_nam;
    std::function<QString()> m_directBase;
    std::function<QString(const QString &)> m_nextDirectBase;
    std::function<bool()> m_tunnelUpFn;
    UpstreamEdgeMark m_edgeMark; // the direct edge whose last lease request ended silent (UpstreamLeaseWire.h host rule)
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
    QSet<quint64> m_releasesOpen; // round mac-D2: releases sent and not finished yet (answered, given up, withdrawn)
    QHash<quint64, QString> m_acquiresOut; // acquire request id -> profile, until its HTTP request ends
    bool m_tunnelDown = true; // the last tunnel event was a confirmed stop (or none yet)
    bool m_stopConfirmed = false; // the last tunnel event was a confirmed stop (not "none yet")
    bool m_stopPending = false;
    qint64 m_heldSinceMs = 0;
    void flushHeld(bool tunnelDown);
};

} // namespace avpn
