// Tribe catalog v2 — rollback-aware UTC derived from signed authority time + monotonic runtime.
#pragma once

#include "TransportAdapter.h"

#include <QDateTime>
#include <QElapsedTimer>

namespace avpn {

struct CatalogTrustedClockState {
    QDateTime highestSignedIssuedAtUtc;
    QDateTime highestObservedWallUtc;
};

class ICatalogClockSource {
public:
    virtual ~ICatalogClockSource() = default;
    virtual QDateTime wallUtc() const = 0;
    virtual qint64 monotonicMs() const = 0;
};

class SystemCatalogClockSource final : public ICatalogClockSource {
public:
    SystemCatalogClockSource() { m_monotonic.start(); }
    QDateTime wallUtc() const override { return QDateTime::currentDateTimeUtc(); }
    qint64 monotonicMs() const override { return m_monotonic.elapsed(); }
private:
    QElapsedTimer m_monotonic;
};

class CatalogTrustedClock final : public IConnectionClock {
public:
    explicit CatalogTrustedClock(ICatalogClockSource *source, int rollbackToleranceS = 300,
                                 int signedFutureSkewS = 300);

    bool restore(const CatalogTrustedClockState &state, QString &error);
    // Call only after the containing signature/trust policy has passed. This cannot bootstrap an
    // arbitrary server/body time and never accepts a signed instant too far in local future.
    bool observeAcceptedSignedTime(const QDateTime &issuedAtUtc, QString &error);
    QDateTime nowUtc() const override;
    CatalogTrustedClockState stateForPersistence() const;
    bool rollbackDetected() const { return m_rollbackDetected; }

private:
    bool validState(const CatalogTrustedClockState &state) const;

    ICatalogClockSource *m_source = nullptr;
    CatalogTrustedClockState m_state;
    QDateTime m_anchorUtc;
    qint64 m_anchorMonotonicMs = -1;
    int m_rollbackToleranceS = 300;
    int m_signedFutureSkewS = 300;
    mutable bool m_rollbackDetected = false;
};

} // namespace avpn
