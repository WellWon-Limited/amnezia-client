#include "CatalogTrustedClock.h"

namespace avpn {

CatalogTrustedClock::CatalogTrustedClock(ICatalogClockSource *source,
                                         int rollbackToleranceS,
                                         int signedFutureSkewS)
    : m_source(source),
      m_rollbackToleranceS(qBound(0, rollbackToleranceS, 15 * 60)),
      m_signedFutureSkewS(qBound(0, signedFutureSkewS, 15 * 60))
{}

bool CatalogTrustedClock::validState(const CatalogTrustedClockState &state) const
{
    const bool signedValid = state.highestSignedIssuedAtUtc.isValid();
    const bool wallValid = state.highestObservedWallUtc.isValid();
    if (signedValid != wallValid) return false;
    if (!signedValid) return true;
    return state.highestSignedIssuedAtUtc.timeSpec() != Qt::LocalTime
           && state.highestObservedWallUtc.timeSpec() != Qt::LocalTime;
}

bool CatalogTrustedClock::restore(const CatalogTrustedClockState &state, QString &error)
{
    error.clear();
    m_rollbackDetected = false;
    if (!m_source || !validState(state)) {
        error = QStringLiteral("trusted clock source/state unavailable");
        return false;
    }
    const QDateTime wall = m_source->wallUtc().toUTC();
    const qint64 monotonic = m_source->monotonicMs();
    if (!wall.isValid() || monotonic < 0) {
        error = QStringLiteral("trusted clock inputs invalid");
        return false;
    }
    if (state.highestObservedWallUtc.isValid()
        && wall.addSecs(m_rollbackToleranceS)
               < state.highestObservedWallUtc.toUTC()) {
        m_rollbackDetected = true;
        error = QStringLiteral("wall clock rollback exceeds trusted tolerance");
        return false;
    }
    m_state = state;
    if (m_state.highestSignedIssuedAtUtc.isValid())
        m_state.highestSignedIssuedAtUtc = m_state.highestSignedIssuedAtUtc.toUTC();
    if (m_state.highestObservedWallUtc.isValid())
        m_state.highestObservedWallUtc = m_state.highestObservedWallUtc.toUTC();
    m_anchorUtc = wall;
    if (m_state.highestSignedIssuedAtUtc.isValid()
        && m_state.highestSignedIssuedAtUtc > m_anchorUtc)
        m_anchorUtc = m_state.highestSignedIssuedAtUtc;
    m_anchorMonotonicMs = monotonic;
    return true;
}

bool CatalogTrustedClock::observeAcceptedSignedTime(const QDateTime &issuedAtUtc,
                                                    QString &error)
{
    error.clear();
    const QDateTime now = nowUtc();
    const QDateTime issued = issuedAtUtc.toUTC();
    if (!now.isValid() || !issuedAtUtc.isValid()
        || issued > now.addSecs(m_signedFutureSkewS)) {
        error = QStringLiteral("accepted signed time is outside trusted bounds");
        return false;
    }
    if (!m_state.highestSignedIssuedAtUtc.isValid()
        || issued > m_state.highestSignedIssuedAtUtc)
        m_state.highestSignedIssuedAtUtc = issued;
    const QDateTime wall = m_source->wallUtc().toUTC();
    if (!m_state.highestObservedWallUtc.isValid() || wall > m_state.highestObservedWallUtc)
        m_state.highestObservedWallUtc = wall;
    if (issued > m_anchorUtc) {
        m_anchorUtc = issued;
        m_anchorMonotonicMs = m_source->monotonicMs();
    }
    return true;
}

QDateTime CatalogTrustedClock::nowUtc() const
{
    if (!m_source || !m_anchorUtc.isValid() || m_anchorMonotonicMs < 0
        || m_rollbackDetected) return {};
    const QDateTime wall = m_source->wallUtc().toUTC();
    const qint64 monotonic = m_source->monotonicMs();
    if (!wall.isValid() || monotonic < m_anchorMonotonicMs) return {};
    if (m_state.highestObservedWallUtc.isValid()
        && wall.addSecs(m_rollbackToleranceS) < m_state.highestObservedWallUtc) {
        m_rollbackDetected = true;
        return {};
    }
    const QDateTime derived = m_anchorUtc.addMSecs(monotonic - m_anchorMonotonicMs);
    QDateTime result = wall > derived ? wall : derived;
    if (m_state.highestSignedIssuedAtUtc.isValid()
        && m_state.highestSignedIssuedAtUtc > result)
        result = m_state.highestSignedIssuedAtUtc;
    return result.toUTC();
}

CatalogTrustedClockState CatalogTrustedClock::stateForPersistence() const
{
    CatalogTrustedClockState result = m_state;
    // Before the first accepted signed instant, wall time is only a bootstrap input and cannot be
    // promoted into durable anti-rollback authority on its own. The persisted schema intentionally
    // requires signed+wall high-water as an inseparable pair.
    if (!result.highestSignedIssuedAtUtc.isValid()) {
        result.highestObservedWallUtc = {};
        return result;
    }
    const QDateTime now = nowUtc();
    if (now.isValid()
        && (!result.highestObservedWallUtc.isValid()
            || now > result.highestObservedWallUtc))
        result.highestObservedWallUtc = now;
    return result;
}

} // namespace avpn
