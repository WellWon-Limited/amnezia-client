#include "CatalogConnectionFacade.h"

#include <QTimer>
#include <QSet>
#include <QVariantMap>

#include <algorithm>
#include <cmath>

namespace avpn {
namespace {

QString modeName(ConnectionMode mode)
{
    switch (mode) {
    case ConnectionMode::Auto: return QStringLiteral("auto");
    case ConnectionMode::ForceAwg: return QStringLiteral("awg");
    case ConnectionMode::ForceXray: return QStringLiteral("xray");
    }
    return QStringLiteral("auto");
}

bool parseMode(const QString &value, ConnectionMode &mode)
{
    if (value == QLatin1String("auto")) mode = ConnectionMode::Auto;
    else if (value == QLatin1String("awg")) mode = ConnectionMode::ForceAwg;
    else if (value == QLatin1String("xray")) mode = ConnectionMode::ForceXray;
    else return false;
    return true;
}

QString phaseName(ConnectionPhase phase)
{
    switch (phase) {
    case ConnectionPhase::Idle: return QStringLiteral("idle");
    case ConnectionPhase::SelectingCandidate: return QStringLiteral("selecting");
    case ConnectionPhase::ArmingGuard: return QStringLiteral("starting");
    case ConnectionPhase::StartingTransport: return QStringLiteral("starting");
    case ConnectionPhase::TunnelReady: return QStringLiteral("tunnel_ready");
    case ConnectionPhase::VerifyingDns: return QStringLiteral("dns");
    case ConnectionPhase::VerifyingTraffic: return QStringLiteral("traffic");
    case ConnectionPhase::ConnectedHealthy: return QStringLiteral("verified");
    case ConnectionPhase::VerificationUnknown: return QStringLiteral("unknown");
    case ConnectionPhase::StoppingOld: return QStringLiteral("fallback");
    case ConnectionPhase::Disconnecting: return QStringLiteral("disconnecting");
    case ConnectionPhase::ReleasingGuard: return QStringLiteral("disconnecting");
    case ConnectionPhase::Failed: return QStringLiteral("failed");
    }
    return QStringLiteral("failed");
}

QString verificationName(ConnectionPhase phase)
{
    switch (phase) {
    case ConnectionPhase::StartingTransport:
    case ConnectionPhase::ArmingGuard:
    case ConnectionPhase::TunnelReady: return QStringLiteral("starting");
    case ConnectionPhase::VerifyingDns: return QStringLiteral("dns");
    case ConnectionPhase::VerifyingTraffic: return QStringLiteral("traffic");
    case ConnectionPhase::ConnectedHealthy: return QStringLiteral("verified");
    case ConnectionPhase::VerificationUnknown: return QStringLiteral("unknown");
    case ConnectionPhase::Failed: return QStringLiteral("failed");
    default: return QStringLiteral("idle");
    }
}

double candidateQuality(const CatalogCandidate &candidate,
                        const CandidateHistory &history,
                        const QDateTime &nowUtc)
{
    double value = 0.5;
    if (candidateHealthHintsFresh(candidate, nowUtc))
        value = bounded01(candidate.serverHealth, 0.5) * 0.55
                + bounded01(candidate.capacityHeadroom, 0.5) * 0.10 + 0.175;
    if (candidateHistoryMatches(candidate, history)) {
        if (history.verifiedSuccessEwma >= 0.0)
            value = value * 0.65 + bounded01(history.verifiedSuccessEwma, 0.0) * 0.25;
        if (history.survival5mEwma >= 0.0)
            value += bounded01(history.survival5mEwma, 0.0) * 0.10;
        if (history.verifiedStartLatencyMs >= 0.0)
            value -= qBound(0.0, history.verifiedStartLatencyMs / 60000.0, 0.15);
    }
    return qBound(0.0, value, 1.0);
}

QString redactedTimelineLabel(const QString &entry)
{
    if (entry.contains(QLatin1String("guard"))) return QStringLiteral("session_guard");
    if (entry.contains(QLatin1String("receipt"))) return QStringLiteral("receipt_verification");
    if (entry.contains(QLatin1String("DNS"), Qt::CaseInsensitive)) return QStringLiteral("dns");
    if (entry.contains(QLatin1String("catalog"))) return QStringLiteral("catalog_reconcile");
    if (entry.contains(QLatin1String("candidate"))) return QStringLiteral("candidate_attempt");
    if (entry.contains(QLatin1String("transport"))) return QStringLiteral("transport");
    if (entry.contains(QLatin1String("disconnect"))) return QStringLiteral("disconnect");
    if (entry.contains(QLatin1String("stop"))) return QStringLiteral("stop");
    return QStringLiteral("connection_event");
}

} // namespace

CatalogConnectionFacade::CatalogConnectionFacade(QObject *parent)
    : QObject(parent), m_ageTimer(new QTimer(this))
{
    m_ageTimer->setInterval(1000);
    connect(m_ageTimer, &QTimer::timeout, this, [this]() {
        emit verificationAgeSecondsChanged();
        emit catalogAgeSecondsChanged();
        emit authorityRemainingSecondsChanged();
        emit verifiedChanged();
        emit changed();
    });
    m_ageTimer->start();
}

CatalogConnectionFacade::~CatalogConnectionFacade()
{
    m_actions = nullptr;
}

QString CatalogConnectionFacade::connectionMode() const
{
    return modeName(m_connectionMode);
}

qint64 CatalogConnectionFacade::verificationAgeSeconds() const
{
    if (!m_verifiedAt.isValid() || !m_trustedNowAtUpdate.isValid()) return -1;
    const QDateTime now = m_trustedNowAtUpdate.addMSecs(
        m_ageElapsed.isValid() ? m_ageElapsed.elapsed() : 0);
    return qMax<qint64>(0, m_verifiedAt.secsTo(now));
}

bool CatalogConnectionFacade::verified() const
{
    if (m_verificationState != QLatin1String("verified")
        || !m_verifiedUntil.isValid() || !m_trustedNowAtUpdate.isValid()) return false;
    const QDateTime now = m_trustedNowAtUpdate.addMSecs(
        m_ageElapsed.isValid() ? m_ageElapsed.elapsed() : 0);
    return now < m_verifiedUntil;
}

qint64 CatalogConnectionFacade::catalogAgeSeconds() const
{
    if (!m_catalogIssuedAt.isValid() || !m_trustedNowAtUpdate.isValid()) return -1;
    const QDateTime now = m_trustedNowAtUpdate.addMSecs(
        m_ageElapsed.isValid() ? m_ageElapsed.elapsed() : 0);
    return qMax<qint64>(0, m_catalogIssuedAt.secsTo(now));
}

qint64 CatalogConnectionFacade::authorityRemainingSeconds() const
{
    if (!m_authorityDeadline.isValid() || !m_trustedNowAtUpdate.isValid()) return -1;
    const QDateTime now = m_trustedNowAtUpdate.addMSecs(
        m_ageElapsed.isValid() ? m_ageElapsed.elapsed() : 0);
    return qMax<qint64>(0, now.secsTo(m_authorityDeadline));
}

bool CatalogConnectionFacade::requestConnectionMode(const QString &value)
{
    ConnectionMode parsed = ConnectionMode::Auto;
    QString error;
    if (!parseMode(value, parsed) || !m_actions
        || !m_actions->requestConnectionMode(parsed, error)) {
        actionRejected(error.isEmpty() ? QStringLiteral("invalid_connection_mode") : error);
        return false;
    }
    m_connectionMode = parsed;
    emitAllChanged();
    return true;
}

bool CatalogConnectionFacade::setLocationMode(const QString &value)
{
    QString error;
    if (value.isEmpty() || !m_actions || !m_actions->requestLocationMode(value, error)) {
        actionRejected(error.isEmpty() ? QStringLiteral("invalid_location_mode") : error);
        return false;
    }
    m_selectedLocationMode = value;
    if (m_catalogSnapshot.schemaVersion == 2) {
        rebuildLocations(m_catalogSnapshot, m_compatibleSnapshot,
                         m_pathHistorySnapshot,
                         m_trustedNowAtUpdate.isValid()
                             ? m_trustedNowAtUpdate : QDateTime::currentDateTimeUtc());
    }
    emitAllChanged();
    return true;
}

bool CatalogConnectionFacade::refreshCatalog()
{
    QString error;
    if (!m_actions || !m_actions->requestCatalogRefresh(error)) {
        actionRejected(error.isEmpty() ? QStringLiteral("catalog_refresh_unavailable") : error);
        return false;
    }
    return true;
}

bool CatalogConnectionFacade::connectV2()
{
    QString error;
    if (!m_actions || !m_actions->requestConnect(error)) {
        actionRejected(error.isEmpty() ? QStringLiteral("catalog_v2_unavailable") : error);
        return false;
    }
    return true;
}

void CatalogConnectionFacade::disconnectV2()
{
    if (m_actions) m_actions->requestDisconnect();
}

bool CatalogConnectionFacade::retryVerification()
{
    QString error;
    if (!m_actions || !m_actions->requestVerificationRetry(error)) {
        actionRejected(error.isEmpty() ? QStringLiteral("verification_retry_unavailable") : error);
        return false;
    }
    return true;
}

bool CatalogConnectionFacade::reselectV2()
{
    QString error;
    if (!m_actions || !m_actions->requestReselect(error)) {
        actionRejected(error.isEmpty() ? QStringLiteral("reselect_unavailable") : error);
        return false;
    }
    return true;
}

bool CatalogConnectionFacade::startDoctorV2()
{
    QString error;
    if (!m_actions || !m_actions->requestDoctor(error)) {
        actionRejected(error.isEmpty() ? QStringLiteral("doctor_unavailable") : error);
        return false;
    }
    return true;
}

void CatalogConnectionFacade::setCatalogView(
    const Catalog &catalog, const QList<CatalogCandidate> &compatibleCandidates,
    const QHash<QString, CandidateHistory> &pathHistory, bool awgAvailable,
    bool xrayAvailable, bool autoAvailable, const QDateTime &trustedNowUtc)
{
    m_catalogAvailable = catalog.schemaVersion == 2 && !compatibleCandidates.isEmpty();
    m_awgAvailable = awgAvailable;
    m_xrayAvailable = xrayAvailable;
    if (catalog.locationDirectory.has_value()) {
        m_awgAvailable = false;
        m_xrayAvailable = false;
        for (const CatalogDirectoryLocation &location
             : catalog.locationDirectory->locations) {
            for (const CatalogDirectoryTransport &transport : location.transports) {
                if (transport.availability != CatalogDirectoryAvailability::Selectable)
                    continue;
                if (transport.transport == TransportKind::Awg) m_awgAvailable = true;
                if (transport.transport == TransportKind::Xray) m_xrayAvailable = true;
            }
        }
    }
    // Auto means "select the best compatible registered transport". Dual transport is
    // preferred but not a prerequisite: a platform that has proved only one exact runtime can
    // still use Auto without pretending the other engine is present.
    m_autoAvailable = autoAvailable && (m_awgAvailable || m_xrayAvailable);
    m_catalogIssuedAt = catalog.issuedAt.toUTC();
    m_trustedNowAtUpdate = trustedNowUtc.toUTC();
    m_ageElapsed.restart();
    m_catalogSnapshot = catalog;
    m_compatibleSnapshot = compatibleCandidates;
    m_pathHistorySnapshot = pathHistory;
    rebuildLocations(catalog, compatibleCandidates, pathHistory, m_trustedNowAtUpdate);
    emitAllChanged();
}

void CatalogConnectionFacade::clearCatalog(const QString &typedReason)
{
    m_catalogAvailable = false;
    m_autoAvailable = m_awgAvailable = m_xrayAvailable = false;
    m_catalogLocations.clear();
    m_catalogSnapshot = {};
    m_compatibleSnapshot.clear();
    m_pathHistorySnapshot.clear();
    m_catalogIssuedAt = {};
    m_authorityDeadline = {};
    if (!typedReason.isEmpty()) m_errorCode = typedReason;
    emitAllChanged();
}

void CatalogConnectionFacade::setV2AuthorityState(bool authoritative)
{
    if (m_v2Authoritative == authoritative) return;
    // Monotonic within the installation lifecycle. Clearing requires the secure coordinator's
    // explicit logout/wipe operation, never a transient endpoint/network failure.
    if (m_v2Authoritative && !authoritative) return;
    m_v2Authoritative = authoritative;
    emit v2AuthorityChanged();
    emit changed();
}

void CatalogConnectionFacade::clearV2AuthorityAfterSecureLogout()
{
    m_v2Authoritative = false;
    m_connectionMode = ConnectionMode::Auto;
    m_selectedLocationMode = QStringLiteral("auto");
    clearCatalog(QStringLiteral("signed_out"));
    emit v2AuthorityChanged();
    emit secureLogoutCompleted();
    emit changed();
}

void CatalogConnectionFacade::restoreUserIntent(ConnectionMode mode,
                                                const QString &pinnedLocationId)
{
    m_connectionMode = mode;
    m_selectedLocationMode = pinnedLocationId.isEmpty()
                                 ? QStringLiteral("auto") : pinnedLocationId;
    if (m_catalogSnapshot.schemaVersion == 2) {
        rebuildLocations(m_catalogSnapshot, m_compatibleSnapshot,
                         m_pathHistorySnapshot,
                         m_trustedNowAtUpdate.isValid()
                             ? m_trustedNowAtUpdate : QDateTime::currentDateTimeUtc());
    }
    // Deliberately leave m_actualTransport, m_currentLocationId and all verification facts alone.
    emitAllChanged();
}

void CatalogConnectionFacade::setCoordinatorStage(const QString &stage,
                                                   const QString &typedReason)
{
    static const QSet<QString> allowed{
        QStringLiteral("idle"), QStringLiteral("resolving"), QStringLiteral("preparing"),
        QStringLiteral("selecting"), QStringLiteral("starting"),
        QStringLiteral("tunnel_ready"), QStringLiteral("dns"), QStringLiteral("traffic"),
        QStringLiteral("fallback"), QStringLiteral("renewing"),
        QStringLiteral("verified"), QStringLiteral("unknown"),
        QStringLiteral("disconnecting"), QStringLiteral("failed")};
    m_connectionStage = allowed.contains(stage) ? stage : QStringLiteral("failed");
    m_errorCode = typedReason;
    emitAllChanged();
}

void CatalogConnectionFacade::setEngineVersions(QVariantList redactedVersions)
{
    m_engineVersions = std::move(redactedVersions);
    emit engineVersionsChanged();
    emit changed();
}

void CatalogConnectionFacade::updateTrustedPresentationNow(const QDateTime &trustedNowUtc)
{
    if (!trustedNowUtc.isValid()) return;
    m_trustedNowAtUpdate = trustedNowUtc.toUTC();
    m_ageElapsed.restart();
    emit verificationAgeSecondsChanged();
    emit catalogAgeSecondsChanged();
    emit authorityRemainingSecondsChanged();
    emit verifiedChanged();
    emit changed();
}

void CatalogConnectionFacade::invalidateVerificationPresentation(const QString &typedReason)
{
    m_verifiedAt = {};
    m_verifiedUntil = {};
    if (m_verificationState == QLatin1String("verified")
        || m_verificationState == QLatin1String("starting")
        || m_verificationState == QLatin1String("dns")
        || m_verificationState == QLatin1String("traffic")) {
        m_verificationState = QStringLiteral("unknown");
        m_connectionStage = QStringLiteral("unknown");
    }
    m_errorCode = typedReason.left(96);
    emitAllChanged();
}

void CatalogConnectionFacade::onConnectionReducerSnapshot(
    const ConnectionRuntimeSnapshot &snapshot)
{
    const QString previousTransport = m_actualTransport;
    m_actualTransport = snapshot.profileId.isEmpty()
                            ? QStringLiteral("none")
                            : transportKindName(snapshot.transport);
    m_connectionStage = phaseName(snapshot.phase);
    m_verificationState = verificationName(snapshot.phase);
    m_errorCode = snapshot.lastTypedReason;
    m_currentLocationId = snapshot.locationId;
    m_authorityDeadline = snapshot.nativeProfileExpiresAt;
    if (snapshot.catalogFreshnessDeadline.isValid()
        && (!m_authorityDeadline.isValid()
            || snapshot.catalogFreshnessDeadline < m_authorityDeadline))
        m_authorityDeadline = snapshot.catalogFreshnessDeadline;
    if (snapshot.entitlementDeadline.isValid()
        && (!m_authorityDeadline.isValid()
            || snapshot.entitlementDeadline < m_authorityDeadline))
        m_authorityDeadline = snapshot.entitlementDeadline;
    m_verifiedAt = snapshot.verifiedAtUtc;
    m_verifiedUntil = snapshot.verifiedUntilUtc;
    if (!m_trustedNowAtUpdate.isValid()) {
        m_trustedNowAtUpdate = QDateTime::currentDateTimeUtc();
        m_ageElapsed.restart();
    }
    if (snapshot.phase == ConnectionPhase::StoppingOld) {
        // The reducer has not selected the replacement yet. Do not expose a stale/guessed
        // fallback target to QML; the exact from/to pair is published only after startNext().
        m_fallbackFrom = previousTransport == QLatin1String("none")
                             ? QString() : previousTransport;
        m_fallbackTo.clear();
        m_fallbackReason = snapshot.lastTypedReason;
    } else if (previousTransport != QLatin1String("none")
        && m_actualTransport != QLatin1String("none")
        && previousTransport != m_actualTransport) {
        m_fallbackFrom = previousTransport;
        m_fallbackTo = m_actualTransport;
        m_fallbackReason = snapshot.lastTypedReason.isEmpty()
                               ? QStringLiteral("candidate_fallback")
                               : snapshot.lastTypedReason;
    }
    QVariantList timeline;
    const int first = qMax(0, snapshot.timeline.size() - 32);
    for (int index = first; index < snapshot.timeline.size(); ++index)
        timeline.append(QVariantMap{{QStringLiteral("label"),
                                     redactedTimelineLabel(snapshot.timeline.at(index))}});
    m_doctorTimeline = std::move(timeline);
    if (snapshot.hasAcceptedV2)
        setV2AuthorityState(true);
    emitAllChanged();
}

void CatalogConnectionFacade::emitAllChanged()
{
    emit connectionModeChanged();
    emit actualTransportChanged();
    emit connectionStageChanged();
    emit errorCodeChanged();
    emit fallbackChanged();
    emit verificationStateChanged();
    emit verificationAgeSecondsChanged();
    emit verifiedChanged();
    emit catalogAvailableChanged();
    emit v2AuthorityChanged();
    emit selectedLocationModeChanged();
    emit currentLocationIdChanged();
    emit catalogAgeSecondsChanged();
    emit authorityRemainingSecondsChanged();
    emit availabilityChanged();
    emit catalogLocationsChanged();
    emit doctorTimelineChanged();
    emit changed();
}

void CatalogConnectionFacade::actionRejected(const QString &reason)
{
    m_errorCode = reason.left(96);
    emit errorCodeChanged();
    emit changed();
}

void CatalogConnectionFacade::rebuildLocations(
    const Catalog &catalog, const QList<CatalogCandidate> &compatibleCandidates,
    const QHash<QString, CandidateHistory> &pathHistory, const QDateTime &nowUtc)
{
    const qint64 catalogAgeAtView = catalog.issuedAt.isValid()
        ? qMax<qint64>(0, catalog.issuedAt.toUTC().secsTo(nowUtc)) : -1;
    QHash<QString, QList<CatalogCandidate>> byLocation;
    for (const CatalogCandidate &candidate : compatibleCandidates)
        byLocation[candidate.locationId].append(candidate);
    QVariantList rows;
    const bool hasDirectory = catalog.locationDirectory.has_value();
    QList<CatalogDirectoryLocation> directoryLocations;
    if (hasDirectory) {
        directoryLocations = catalog.locationDirectory->locations;
    } else {
        for (const CatalogLocation &location : catalog.locations) {
            CatalogDirectoryLocation summary;
            summary.id = location.id;
            summary.country = location.country;
            summary.city = location.city;
            summary.displayKey = location.displayKey;
            directoryLocations.append(std::move(summary));
        }
    }
    for (const CatalogDirectoryLocation &location : directoryLocations) {
        const QList<CatalogCandidate> candidates = byLocation.value(location.id);
        auto transportRow = [&](TransportKind transport) -> QVariantMap {
            bool available = !hasDirectory && std::any_of(
                candidates.cbegin(), candidates.cend(), [transport](const auto &candidate) {
                    return candidate.transport == transport;
                });
            QString state = available ? QStringLiteral("selectable")
                                      : QStringLiteral("unsupported");
            double predictedQuality = -1.0;
            qint64 predictedAge = -1;
            if (hasDirectory) {
                for (const CatalogDirectoryTransport &summary : location.transports) {
                    if (summary.transport != transport) continue;
                    if (summary.availability == CatalogDirectoryAvailability::Selectable) {
                        available = true;
                        state = QStringLiteral("selectable");
                    } else if (summary.availability
                               == CatalogDirectoryAvailability::TemporarilyUnavailable) {
                        state = QStringLiteral("temporarily_unavailable");
                    }
                    if (summary.predictedQuality.has_value())
                        predictedQuality = *summary.predictedQuality;
                    if (summary.observedAt.isValid()) {
                        const qint64 age = summary.observedAt.toUTC().secsTo(nowUtc);
                        if (age >= 0) predictedAge = age;
                    }
                    break;
                }
            }
            double quality = -1.0;
            qint64 lastVerifiedAge = -1;
            for (const CatalogCandidate &candidate : candidates) {
                if (candidate.transport != transport) continue;
                const CandidateHistory history = pathHistory.value(candidate.profileId);
                quality = qMax(quality, candidateQuality(candidate, history, nowUtc));
                if (candidateHistoryMatches(candidate, history)
                    && history.lastVerifiedAtUtc.isValid()) {
                    const qint64 age = history.lastVerifiedAtUtc.toUTC().secsTo(nowUtc);
                    if (age >= 0 && (lastVerifiedAge < 0 || age < lastVerifiedAge))
                        lastVerifiedAge = age;
                }
            }
            return {{QStringLiteral("available"), available},
                    {QStringLiteral("state"), state},
                    {QStringLiteral("quality"), quality >= 0.0
                         ? QVariant(quality) : QVariant()},
                    {QStringLiteral("predicted_quality"), predictedQuality >= 0.0
                         ? QVariant(predictedQuality) : QVariant()},
                    {QStringLiteral("predicted_age"), predictedAge >= 0
                         ? QVariant(predictedAge) : QVariant()},
                    {QStringLiteral("last_verified"), lastVerifiedAge >= 0
                         ? QVariant(lastVerifiedAge) : QVariant()},
                    // `last_verified` is the age at this immutable view anchor. QML advances it
                    // with the facade's rollback-aware catalogAgeSeconds instead of Date.now(),
                    // so the label cannot freeze or trust a user-adjustable wall clock.
                    {QStringLiteral("age_anchor_catalog_age"),
                     catalogAgeAtView >= 0 ? QVariant(catalogAgeAtView) : QVariant()}};
        };
        const QVariantMap awg = transportRow(TransportKind::Awg);
        const QVariantMap xray = transportRow(TransportKind::Xray);
        const double awgQuality = awg.value(QStringLiteral("quality"), -1.0).toDouble();
        const double xrayQuality = xray.value(QStringLiteral("quality"), -1.0).toDouble();
        const double aggregate = qMax(awgQuality, xrayQuality);
        rows.append(QVariantMap{
            {QStringLiteral("id"), location.id},
            {QStringLiteral("country"), location.country},
            // display_key is a localization identifier (for example location.fi.hel), not
            // user-facing text. Until a bounded localization resolver is injected, expose only
            // signed human-safe city/country fields and never leak the raw key into UI.
            {QStringLiteral("name"), location.city.isEmpty()
                 ? location.country : location.city},
            {QStringLiteral("selected"),
             m_selectedLocationMode == location.id || m_currentLocationId == location.id},
            {QStringLiteral("awg"), awg},
            {QStringLiteral("xray"), xray},
            {QStringLiteral("aggregate_quality"), aggregate >= 0.0
                 ? QVariant(aggregate) : QVariant()},
        });
    }
    if (m_selectedLocationMode != QLatin1String("auto")) {
        const bool selectedPresent = std::any_of(
            directoryLocations.cbegin(), directoryLocations.cend(), [this](const auto &location) {
                return location.id == m_selectedLocationMode;
            });
        if (!selectedPresent) {
            const QVariantMap unavailableTransport{
                {QStringLiteral("available"), false},
                {QStringLiteral("state"), QStringLiteral("temporarily_unavailable")},
                {QStringLiteral("quality"), QVariant()},
                {QStringLiteral("predicted_quality"), QVariant()},
                {QStringLiteral("predicted_age"), QVariant()},
                {QStringLiteral("last_verified"), QVariant()},
                {QStringLiteral("age_anchor_catalog_age"),
                 catalogAgeAtView >= 0 ? QVariant(catalogAgeAtView) : QVariant()},
            };
            rows.append(QVariantMap{
                {QStringLiteral("id"), m_selectedLocationMode},
                {QStringLiteral("country"), QStringLiteral("??")},
                {QStringLiteral("name"), QString()},
                {QStringLiteral("selected"), true},
                {QStringLiteral("retained_pin"), true},
                {QStringLiteral("awg"), unavailableTransport},
                {QStringLiteral("xray"), unavailableTransport},
                {QStringLiteral("aggregate_quality"), QVariant()},
            });
        }
    }
    m_catalogLocations = std::move(rows);
}

} // namespace avpn
