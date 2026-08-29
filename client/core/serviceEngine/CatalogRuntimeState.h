// Tribe catalog v2 — redacted durable candidate history and idempotent outcome queue.
#pragma once

#include "CandidateSelector.h"
#include "CatalogTrustedClock.h"

#include <QJsonObject>

#include <optional>

namespace avpn {

enum class CatalogNetworkClass { Unknown = 0, Wifi, Cellular, Wired };

// Privacy-safe local path identity. `epoch` is an app-local monotonic generation bumped on a
// material OS network-path change; it is never an SSID/BSSID/carrier identifier and is never
// uploaded. A new epoch intentionally gets a fresh cooldown/history namespace.
struct CatalogNetworkPathScope {
    CatalogNetworkClass networkClass = CatalogNetworkClass::Unknown;
    quint64 epoch = 0;
    bool isValid() const { return epoch != 0; }
};

QString catalogNetworkClassName(CatalogNetworkClass value);
QString scopedCatalogHistoryKey(const CatalogNetworkPathScope &scope,
                                const QString &profileId);
QHash<QString, CandidateHistory> candidateHistoryForPath(
    const struct CatalogRuntimeState &state,
    const CatalogNetworkPathScope &scope,
    const QList<CatalogCandidate> &candidates);
bool mergeCandidateHistoryForPath(struct CatalogRuntimeState &state,
                                  const CatalogNetworkPathScope &scope,
                                  const QHash<QString, CandidateHistory> &history,
                                  QString &error);
enum class CatalogOutcomeStage {
    Policy = 0,
    Compile,
    TransportStart,
    TransportRuntime,
    VerificationDns,
    VerificationTraffic,
    VerificationEgress,
    VerificationUnknown,
    Connected,
    Disconnected,
};

struct CatalogOutcomeEvent {
    QString eventId; // canonical lowercase UUIDv4
    QString deviceAudience;
    QString profileId;
    quint64 configGeneration = 0;
    quint64 bindingGeneration = 0;
    quint64 catalogRevision = 0;
    QString context;
    TransportKind transport = TransportKind::Unknown;
    CatalogNetworkClass networkClass = CatalogNetworkClass::Unknown;
    CatalogOutcomeStage stage = CatalogOutcomeStage::Policy;
    QString errorCode;
    int connectMs = -1;
    int dnsMs = -1;
    int receiptMs = -1;
    qint64 sessionMs = -1;
    bool verifiedSuccess = false;
    std::optional<bool> survived5m;
    QDateTime queuedAtUtc; // local durability/expiry only; excluded from upload ABI
};

struct CatalogRuntimeState {
    QHash<QString, CandidateHistory> candidateHistory;
    QList<CatalogOutcomeEvent> pendingOutcomes;
    CatalogTrustedClockState trustedClock;
    // Durable allocator. Epochs are never reused after restart, so an unrelated new Wi-Fi path
    // cannot inherit an old path's cooldown merely because both processes started counting at 1.
    quint64 nextNetworkPathEpoch = 1;
};

bool allocateCatalogNetworkPathScope(CatalogRuntimeState &state,
                                     CatalogNetworkClass networkClass,
                                     CatalogNetworkPathScope &scope,
                                     QString &error);

struct CatalogRuntimeStateLimits {
    int maximumHistories = 512;
    int maximumOutcomes = 128;
    int maximumBytes = 128 * 1024;
};

QString newCatalogOutcomeEventId();
bool appendCatalogOutcome(CatalogRuntimeState &state, CatalogOutcomeEvent event,
                          QString &error, CatalogRuntimeStateLimits limits = {});
bool buildCatalogOutcomeUpload(const CatalogOutcomeEvent &event, QJsonObject &body,
                               QString &error);
bool serializeCatalogRuntimeState(const CatalogRuntimeState &state, QByteArray &bytes,
                                  QString &error, CatalogRuntimeStateLimits limits = {});
bool parseCatalogRuntimeState(const QByteArray &bytes, CatalogRuntimeState &state,
                              QString &error, CatalogRuntimeStateLimits limits = {});

} // namespace avpn
