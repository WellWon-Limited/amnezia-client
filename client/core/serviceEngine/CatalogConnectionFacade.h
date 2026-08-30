// Tribe catalog v2 — secret-free QML facade. QML expresses intent; the coordinator owns authority.
#pragma once

#include "CatalogRuntimeState.h"
#include "ConnectionReducer.h"

#include <QObject>
#include <QElapsedTimer>
#include <QVariantList>

class QTimer;

namespace avpn {

class ICatalogConnectionActions {
public:
    virtual ~ICatalogConnectionActions() = default;
    virtual bool requestConnectionMode(ConnectionMode mode, QString &error) = 0;
    virtual bool requestLocationMode(const QString &locationMode, QString &error) = 0;
    virtual bool requestCatalogRefresh(QString &error) = 0;
    virtual bool requestConnect(QString &error) = 0;
    virtual void requestDisconnect() = 0;
    virtual bool requestVerificationRetry(QString &error) = 0;
    // V2-owned alternatives/diagnostics. Implementations must never route these through the
    // legacy TribeEngine because the catalog reducer owns the exact inner+outer sessions.
    virtual bool requestReselect(QString &error) = 0;
    virtual bool requestDoctor(QString &error) = 0;
};

class CatalogConnectionFacade final : public QObject,
                                      public IConnectionReducerObserver {
    Q_OBJECT
    Q_PROPERTY(QString connectionMode READ connectionMode NOTIFY connectionModeChanged)
    Q_PROPERTY(QString actualTransport READ actualTransport NOTIFY actualTransportChanged)
    Q_PROPERTY(QString connectionStage READ connectionStage NOTIFY connectionStageChanged)
    Q_PROPERTY(QString errorCode READ errorCode NOTIFY errorCodeChanged)
    Q_PROPERTY(QString fallbackReason READ fallbackReason NOTIFY fallbackChanged)
    Q_PROPERTY(QString fallbackFrom READ fallbackFrom NOTIFY fallbackChanged)
    Q_PROPERTY(QString fallbackTo READ fallbackTo NOTIFY fallbackChanged)
    Q_PROPERTY(QString verificationState READ verificationState NOTIFY verificationStateChanged)
    Q_PROPERTY(qint64 verificationAgeSeconds READ verificationAgeSeconds
               NOTIFY verificationAgeSecondsChanged)
    Q_PROPERTY(bool verified READ verified NOTIFY verifiedChanged)
    Q_PROPERTY(bool catalogAvailable READ catalogAvailable NOTIFY catalogAvailableChanged)
    Q_PROPERTY(bool v2Authoritative READ v2Authoritative NOTIFY v2AuthorityChanged)
    Q_PROPERTY(bool legacyV1Allowed READ legacyV1Allowed NOTIFY v2AuthorityChanged)
    Q_PROPERTY(QString selectedLocationMode READ selectedLocationMode
               NOTIFY selectedLocationModeChanged)
    Q_PROPERTY(QString currentLocationId READ currentLocationId NOTIFY currentLocationIdChanged)
    Q_PROPERTY(qint64 catalogAgeSeconds READ catalogAgeSeconds NOTIFY catalogAgeSecondsChanged)
    Q_PROPERTY(qint64 authorityRemainingSeconds READ authorityRemainingSeconds
               NOTIFY authorityRemainingSecondsChanged)
    Q_PROPERTY(bool autoAvailable READ autoAvailable NOTIFY availabilityChanged)
    Q_PROPERTY(bool awgAvailable READ awgAvailable NOTIFY availabilityChanged)
    Q_PROPERTY(bool xrayAvailable READ xrayAvailable NOTIFY availabilityChanged)
    Q_PROPERTY(QVariantList catalogLocations READ catalogLocations NOTIFY catalogLocationsChanged)
    Q_PROPERTY(QVariantList doctorTimeline READ doctorTimeline NOTIFY doctorTimelineChanged)
    Q_PROPERTY(QVariantList engineVersions READ engineVersions NOTIFY engineVersionsChanged)

public:
    explicit CatalogConnectionFacade(QObject *parent = nullptr);
    ~CatalogConnectionFacade() override;

    QString connectionMode() const;
    QString actualTransport() const { return m_actualTransport; }
    QString connectionStage() const { return m_connectionStage; }
    QString errorCode() const { return m_errorCode; }
    QString fallbackReason() const { return m_fallbackReason; }
    QString fallbackFrom() const { return m_fallbackFrom; }
    QString fallbackTo() const { return m_fallbackTo; }
    QString verificationState() const { return m_verificationState; }
    qint64 verificationAgeSeconds() const;
    bool verified() const;
    bool catalogAvailable() const { return m_catalogAvailable; }
    bool v2Authoritative() const { return m_v2Authoritative; }
    bool legacyV1Allowed() const { return !m_v2Authoritative; }
    QString selectedLocationMode() const { return m_selectedLocationMode; }
    QString currentLocationId() const { return m_currentLocationId; }
    qint64 catalogAgeSeconds() const;
    qint64 authorityRemainingSeconds() const;
    bool autoAvailable() const { return m_autoAvailable; }
    bool awgAvailable() const { return m_awgAvailable; }
    bool xrayAvailable() const { return m_xrayAvailable; }
    QVariantList catalogLocations() const { return m_catalogLocations; }
    QVariantList doctorTimeline() const { return m_doctorTimeline; }
    QVariantList engineVersions() const { return m_engineVersions; }

    Q_INVOKABLE bool requestConnectionMode(const QString &mode);
    Q_INVOKABLE bool setLocationMode(const QString &locationMode);
    Q_INVOKABLE bool refreshCatalog();
    Q_INVOKABLE bool connectV2();
    Q_INVOKABLE void disconnectV2();
    Q_INVOKABLE bool retryVerification();
    Q_INVOKABLE bool reselectV2();
    Q_INVOKABLE bool startDoctorV2();

    void setActions(ICatalogConnectionActions *actions) { m_actions = actions; }
    void clearActions(ICatalogConnectionActions *expected)
    { if (m_actions == expected) m_actions = nullptr; }
    void setCatalogView(const Catalog &catalog,
                        const QList<CatalogCandidate> &compatibleCandidates,
                        const QHash<QString, CandidateHistory> &pathHistory,
                        bool awgAvailable, bool xrayAvailable, bool autoAvailable,
                        const QDateTime &trustedNowUtc);
    void clearCatalog(const QString &typedReason = {});
    void setV2AuthorityState(bool authoritative);
    void clearV2AuthorityAfterSecureLogout();
    // Relaunch preference restore. This updates requested mode/location only; actual transport,
    // verification, and active-location facts remain reducer-owned and start empty.
    void restoreUserIntent(ConnectionMode mode, const QString &pinnedLocationId);
    void setCoordinatorStage(const QString &stage, const QString &typedReason = {});
    void setEngineVersions(QVariantList redactedVersions);
    // Re-anchor age/deadline presentation to the coordinator's rollback-aware clock after wake.
    // This is UI freshness only; it never grants runtime authority.
    void updateTrustedPresentationNow(const QDateTime &trustedNowUtc);
    // Coordinator/app-lifecycle hook. QElapsedTimer is not a cross-platform suspend-inclusive
    // authority, so wake/network-path change invalidates presentation green immediately.
    void invalidateVerificationPresentation(
        const QString &typedReason = QStringLiteral("verification_stale_after_wake"));
    void onConnectionReducerSnapshot(const ConnectionRuntimeSnapshot &snapshot) override;

signals:
    void changed();
    void connectionModeChanged();
    void actualTransportChanged();
    void connectionStageChanged();
    void errorCodeChanged();
    void fallbackChanged();
    void verificationStateChanged();
    void verificationAgeSecondsChanged();
    void verifiedChanged();
    void catalogAvailableChanged();
    void v2AuthorityChanged();
    void selectedLocationModeChanged();
    void currentLocationIdChanged();
    void catalogAgeSecondsChanged();
    void authorityRemainingSecondsChanged();
    void availabilityChanged();
    void catalogLocationsChanged();
    void doctorTimelineChanged();
    void engineVersionsChanged();
    // Emitted only by the coordinator after exact native teardown and successful secure-store
    // tombstone/wipe. Unlike v2AuthorityChanged, this is not a broad derived-property NOTIFY.
    void secureLogoutCompleted();

private:
    void emitAllChanged();
    void actionRejected(const QString &reason);
    void rebuildLocations(const Catalog &catalog,
                          const QList<CatalogCandidate> &compatibleCandidates,
                          const QHash<QString, CandidateHistory> &pathHistory,
                          const QDateTime &nowUtc);

    ICatalogConnectionActions *m_actions = nullptr;
    ConnectionMode m_connectionMode = ConnectionMode::Auto;
    QString m_actualTransport = QStringLiteral("none");
    QString m_connectionStage = QStringLiteral("idle");
    QString m_errorCode;
    QString m_fallbackReason;
    QString m_fallbackFrom;
    QString m_fallbackTo;
    QString m_verificationState = QStringLiteral("idle");
    bool m_catalogAvailable = false;
    bool m_v2Authoritative = false;
    QString m_selectedLocationMode = QStringLiteral("auto");
    QString m_currentLocationId;
    bool m_autoAvailable = false;
    bool m_awgAvailable = false;
    bool m_xrayAvailable = false;
    QVariantList m_catalogLocations;
    Catalog m_catalogSnapshot;
    QList<CatalogCandidate> m_compatibleSnapshot;
    QHash<QString, CandidateHistory> m_pathHistorySnapshot;
    QVariantList m_doctorTimeline;
    QVariantList m_engineVersions;
    QDateTime m_catalogIssuedAt;
    QDateTime m_authorityDeadline;
    QDateTime m_verifiedAt;
    QDateTime m_verifiedUntil;
    QDateTime m_trustedNowAtUpdate;
    QElapsedTimer m_ageElapsed;
    QTimer *m_ageTimer = nullptr;
};

} // namespace avpn
