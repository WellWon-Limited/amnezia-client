// Tribe catalog v2 — DNS-gated HTTPS traffic proof with purpose-separated signed receipts.
#pragma once

#include "CatalogKeyset.h"
#include "ConnectionReducer.h"

#include <QHash>
#include <QElapsedTimer>
#include <QHostInfo>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QUrl>

#include <functional>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

namespace avpn {

// Shared receipt wire bound. Providers may emit a shorter lifetime; green expires at the
// earliest quorum receipt and is never extended locally.
inline constexpr int kReceiptMaximumLifetimeSeconds = 300;
inline constexpr int kReceiptMaximumFutureIssuedSkewSeconds = 30;

struct ReceiptVerificationProvider {
    QString id;
    QString trustDomain;
    QUrl endpoint;
    QHash<QString, QString> receiptPublicKeysHex;
    QSet<QString> protectedAuthorityIps;
};

struct ReceiptVerifierAuthority {
    // Short-lived receipt-only credential from the accepted signed catalog. Passing the primary
    // subscription bearer to independent verification providers is forbidden by type/field name.
    QByteArray verificationToken;
    QString deviceAudience;
    quint64 catalogRevision = 0;
    quint64 keysetEpoch = 0;
    QDateTime expiresAt;
    QList<ReceiptVerificationProvider> providers; // exact two independent providers/quorum=2
};

bool buildReceiptVerifierAuthority(const Catalog &acceptedCatalog,
                                   const CatalogAcceptedKeyrings &acceptedKeyrings,
                                   ReceiptVerifierAuthority &authority,
                                   QString &error);

using ReceiptNetworkFactory =
    std::function<QNetworkAccessManager *(QObject *attemptOwner)>;
using ReceiptDnsCallback = std::function<void(const QHostInfo &)>;
using ReceiptDnsLookup = std::function<int(const QString &host, QObject *attemptOwner,
                                            ReceiptDnsCallback callback)>;
using ReceiptDnsAbort = std::function<void(int lookupId)>;

class IReceiptAuthorityVerifier : public IPostTunnelVerifier {
public:
    virtual bool setAuthority(ReceiptVerifierAuthority authority, QString &error) = 0;
    virtual void clearAuthority() = 0;
};

class PostTunnelReceiptVerifier final : public QObject, public IReceiptAuthorityVerifier {
public:
    PostTunnelReceiptVerifier(IConnectionClock *trustedClock, QObject *parent = nullptr,
                              int timeoutMs = 15000, int minimumProbeBytes = 32768,
                              ReceiptNetworkFactory networkFactory = {},
                              ReceiptDnsLookup dnsLookup = {},
                              ReceiptDnsAbort dnsAbort = {});
    ~PostTunnelReceiptVerifier() override;

    bool setAuthority(ReceiptVerifierAuthority authority, QString &error) override;
    void clearAuthority() override;

    void setObserver(IPostTunnelVerificationObserver *observer) override
    { m_observer = observer; }
    void clearObserver(IPostTunnelVerificationObserver *expected) override
    { if (m_observer == expected) m_observer = nullptr; }
    bool start(const CatalogCandidate &candidate, VerificationToken verification,
               QString &error) override;
    void cancel(VerificationToken verification) override;

private:
    enum class Phase { Idle, ResolvingDns, RequestingReceipt };
    void beginProvider(int providerIndex);
    void onDnsResolved(int lookupId, VerificationToken verification, int providerIndex,
                       const QHostInfo &info);
    void beginProviderIpAttempt(int providerIndex);
    void onReplyFinished(QNetworkReply *reply, VerificationToken verification,
                         int providerIndex, QString requestNonce);
    bool consumeReplyBody(QNetworkReply *reply, VerificationToken verification,
                          int providerIndex);
    void complete(VerificationDisposition disposition, ConnectionFailureStage stage,
                  const QString &reason, const QString &egress = {}, qint64 latencyMs = -1,
                  int retryAfterSeconds = 0,
                  VerificationRetryDirective retryDirective =
                      VerificationRetryDirective::None);
    void stage(PostTunnelVerificationStage value);
    void resetActive();

    QPointer<QNetworkAccessManager> m_network;
    QPointer<QNetworkReply> m_reply;
    QTimer *m_timer = nullptr;
    IConnectionClock *m_clock = nullptr;
    IPostTunnelVerificationObserver *m_observer = nullptr;
    ReceiptVerifierAuthority m_authority;
    ReceiptNetworkFactory m_networkFactory;
    ReceiptDnsLookup m_dnsLookup;
    ReceiptDnsAbort m_dnsAbort;
    VerificationToken m_active;
    CatalogCandidate m_candidate;
    Phase m_phase = Phase::Idle;
    int m_lookupId = -1;
    int m_timeoutMs = 10000;
    int m_minimumProbeBytes = 32768;
    QElapsedTimer m_elapsed;
    quint64 m_callbackEpoch = 0;
    int m_providerIndex = -1;
    QStringList m_providerIpAttempts;
    int m_providerIpAttemptIndex = -1;
    QStringList m_observedEgressIds;
    bool m_providerInfrastructureUnavailable = false;
    QString m_providerInfrastructureReason;
    QDateTime m_receiptExpiresAt;
    QByteArray m_responseBody;
};

} // namespace avpn
