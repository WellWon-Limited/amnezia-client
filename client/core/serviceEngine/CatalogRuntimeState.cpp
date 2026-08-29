#include "CatalogRuntimeState.h"

#include "CatalogResolve.h"
#include "SignedEnvelope.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QUuid>

#include <algorithm>
#include <cmath>
#include <utility>

namespace avpn {
namespace {

constexpr quint64 kMaxSafeJsonInteger = 9007199254740991ULL;

QString networkName(CatalogNetworkClass value)
{
    switch (value) {
    case CatalogNetworkClass::Unknown: return QStringLiteral("unknown");
    case CatalogNetworkClass::Wifi: return QStringLiteral("wifi");
    case CatalogNetworkClass::Cellular: return QStringLiteral("cellular");
    case CatalogNetworkClass::Wired: return QStringLiteral("wired");
    }
    return {};
}

bool parseNetwork(const QString &value, CatalogNetworkClass &out)
{
    if (value == QLatin1String("unknown")) out = CatalogNetworkClass::Unknown;
    else if (value == QLatin1String("wifi")) out = CatalogNetworkClass::Wifi;
    else if (value == QLatin1String("cellular")) out = CatalogNetworkClass::Cellular;
    else if (value == QLatin1String("wired")) out = CatalogNetworkClass::Wired;
    else return false;
    return true;
}

QString stageName(CatalogOutcomeStage value)
{
    switch (value) {
    case CatalogOutcomeStage::Policy: return QStringLiteral("policy");
    case CatalogOutcomeStage::Compile: return QStringLiteral("compile");
    case CatalogOutcomeStage::TransportStart: return QStringLiteral("transport_start");
    case CatalogOutcomeStage::TransportRuntime: return QStringLiteral("transport_runtime");
    case CatalogOutcomeStage::VerificationDns: return QStringLiteral("verification_dns");
    case CatalogOutcomeStage::VerificationTraffic: return QStringLiteral("verification_traffic");
    case CatalogOutcomeStage::VerificationEgress: return QStringLiteral("verification_egress");
    case CatalogOutcomeStage::VerificationUnknown: return QStringLiteral("verification_unknown");
    case CatalogOutcomeStage::Connected: return QStringLiteral("connected");
    case CatalogOutcomeStage::Disconnected: return QStringLiteral("disconnected");
    }
    return {};
}

bool parseStage(const QString &value, CatalogOutcomeStage &out)
{
    for (CatalogOutcomeStage stage : {CatalogOutcomeStage::Policy, CatalogOutcomeStage::Compile,
             CatalogOutcomeStage::TransportStart, CatalogOutcomeStage::TransportRuntime,
             CatalogOutcomeStage::VerificationDns, CatalogOutcomeStage::VerificationTraffic,
             CatalogOutcomeStage::VerificationEgress, CatalogOutcomeStage::VerificationUnknown,
             CatalogOutcomeStage::Connected, CatalogOutcomeStage::Disconnected}) {
        if (stageName(stage) == value) { out = stage; return true; }
    }
    return false;
}

bool safeId(const QString &value)
{
    static const QRegularExpression id(QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"));
    return id.match(value).hasMatch();
}

bool safeOutcomeProfileId(const QString &value)
{
    static const QRegularExpression id(QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$"));
    return id.match(value).hasMatch();
}

bool safeOutcomeContext(const QString &value)
{
    static const QRegularExpression id(QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$"));
    return id.match(value).hasMatch();
}

bool safeError(const QString &value)
{
    static const QRegularExpression code(QStringLiteral("^[a-z][a-z0-9_.-]{0,95}$"));
    return value.isEmpty() || code.match(value).hasMatch();
}

bool canonicalUuidV4(const QString &value)
{
    static const QRegularExpression uuid(
        QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"));
    return uuid.match(value).hasMatch();
}

bool safeDuration(qint64 value) { return value == -1 || (value >= 0 && value <= 86400000); }

bool safeEvent(const CatalogOutcomeEvent &event)
{
    if (!canonicalUuidV4(event.eventId) || !canonicalCatalogOpaque32(event.deviceAudience)
        || !safeOutcomeProfileId(event.profileId) || event.configGeneration == 0
        || event.configGeneration > kMaxSafeJsonInteger || event.bindingGeneration == 0
        || event.bindingGeneration > kMaxSafeJsonInteger || event.catalogRevision == 0
        || event.catalogRevision > kMaxSafeJsonInteger || !safeOutcomeContext(event.context)
        || event.transport == TransportKind::Unknown || networkName(event.networkClass).isEmpty()
        || stageName(event.stage).isEmpty() || !safeError(event.errorCode)
        || !safeDuration(event.connectMs) || !safeDuration(event.dnsMs)
        || !safeDuration(event.receiptMs) || !safeDuration(event.sessionMs)
        || !event.queuedAtUtc.isValid()) return false;
    if (event.verifiedSuccess)
        return event.stage == CatalogOutcomeStage::Connected && event.errorCode.isEmpty()
               && (!event.survived5m.value_or(false) || event.sessionMs >= 300000);
    if (event.stage == CatalogOutcomeStage::Connected || event.survived5m.has_value()) return false;
    return !event.errorCode.isEmpty() || event.stage == CatalogOutcomeStage::VerificationUnknown
           || event.stage == CatalogOutcomeStage::Disconnected;
}

bool exactKeys(const QJsonObject &object, const QSet<QString> &required,
               const QSet<QString> &optional = {})
{
    for (const QString &key : required)
        if (!object.contains(key)) return false;
    for (auto it = object.constBegin(); it != object.constEnd(); ++it)
        if (!required.contains(it.key()) && !optional.contains(it.key())) return false;
    return true;
}

bool scopedHistoryEpoch(const QString &key, quint64 &epoch)
{
    static const QRegularExpression pattern(QStringLiteral(
        "^path\\.v1\\.(?:unknown|wifi|cellular|wired)\\.([1-9][0-9]{0,15})\\.[A-Za-z0-9_-]{43}$"));
    const QRegularExpressionMatch match = pattern.match(key);
    if (!match.hasMatch()) return false;
    bool ok = false;
    epoch = match.captured(1).toULongLong(&ok);
    return ok && epoch >= 1 && epoch <= kMaxSafeJsonInteger;
}

QString scopedHistoryPrefix(const CatalogNetworkPathScope &scope)
{
    if (!scope.isValid() || networkName(scope.networkClass).isEmpty()) return {};
    return QStringLiteral("path.v1.%1.%2.")
        .arg(networkName(scope.networkClass), QString::number(scope.epoch));
}

bool jsonUInt(const QJsonValue &value, quint64 &out)
{
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < 1 || number > double(kMaxSafeJsonInteger)
        || std::floor(number) != number) return false;
    out = quint64(number); return true;
}

bool jsonDuration(const QJsonValue &value, qint64 &out)
{
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < 0 || number > 86400000
        || std::floor(number) != number) return false;
    out = qint64(number); return true;
}

void addOptionalDuration(QJsonObject &object, const QString &key, qint64 value)
{
    if (value >= 0) object.insert(key, double(value));
}

QJsonObject outcomeObject(const CatalogOutcomeEvent &event, bool durable)
{
    QJsonObject object{
        {QStringLiteral("schema_version"), 1},
        {QStringLiteral("event_id"), event.eventId},
        {QStringLiteral("device_audience"), event.deviceAudience},
        {QStringLiteral("profile_id"), event.profileId},
        {QStringLiteral("config_generation"), double(event.configGeneration)},
        {QStringLiteral("binding_generation"), double(event.bindingGeneration)},
        {QStringLiteral("catalog_revision"), double(event.catalogRevision)},
        {QStringLiteral("context"), event.context},
        {QStringLiteral("transport"), transportKindName(event.transport)},
        {QStringLiteral("network_class"), networkName(event.networkClass)},
        {QStringLiteral("stage"), stageName(event.stage)},
        {QStringLiteral("verified_success"), event.verifiedSuccess},
    };
    if (!event.errorCode.isEmpty()) object.insert(QStringLiteral("error_code"), event.errorCode);
    addOptionalDuration(object, QStringLiteral("connect_ms"), event.connectMs);
    addOptionalDuration(object, QStringLiteral("dns_ms"), event.dnsMs);
    addOptionalDuration(object, QStringLiteral("receipt_ms"), event.receiptMs);
    addOptionalDuration(object, QStringLiteral("session_ms"), event.sessionMs);
    if (event.survived5m.has_value())
        object.insert(QStringLiteral("survived_5m"), *event.survived5m);
    if (durable)
        object.insert(QStringLiteral("queued_at"),
                      event.queuedAtUtc.toUTC().toString(Qt::ISODateWithMs));
    return object;
}

bool parseEvent(const QJsonObject &object, CatalogOutcomeEvent &event)
{
    const QSet<QString> required{
        QStringLiteral("schema_version"), QStringLiteral("event_id"),
        QStringLiteral("device_audience"), QStringLiteral("profile_id"),
        QStringLiteral("config_generation"), QStringLiteral("binding_generation"),
        QStringLiteral("catalog_revision"),
        QStringLiteral("context"), QStringLiteral("transport"),
        QStringLiteral("network_class"), QStringLiteral("stage"),
        QStringLiteral("verified_success"), QStringLiteral("queued_at")};
    const QSet<QString> optional{
        QStringLiteral("error_code"), QStringLiteral("connect_ms"), QStringLiteral("dns_ms"),
        QStringLiteral("receipt_ms"), QStringLiteral("session_ms"), QStringLiteral("survived_5m")};
    quint64 schemaVersion = 0;
    if (!exactKeys(object, required, optional)
        || !jsonUInt(object.value(QStringLiteral("schema_version")), schemaVersion)
        || schemaVersion != 1
        || !object.value(QStringLiteral("verified_success")).isBool()) return false;
    event.eventId = object.value(QStringLiteral("event_id")).toString();
    event.deviceAudience = object.value(QStringLiteral("device_audience")).toString();
    event.profileId = object.value(QStringLiteral("profile_id")).toString();
    event.context = object.value(QStringLiteral("context")).toString();
    event.transport = transportKindFromName(object.value(QStringLiteral("transport")).toString());
    event.errorCode = object.value(QStringLiteral("error_code")).toString();
    event.verifiedSuccess = object.value(QStringLiteral("verified_success")).toBool();
    event.queuedAtUtc = QDateTime::fromString(object.value(QStringLiteral("queued_at")).toString(),
                                              Qt::ISODateWithMs).toUTC();
    if (!jsonUInt(object.value(QStringLiteral("config_generation")), event.configGeneration)
        || !jsonUInt(object.value(QStringLiteral("binding_generation")), event.bindingGeneration)
        || !jsonUInt(object.value(QStringLiteral("catalog_revision")), event.catalogRevision)
        || !parseNetwork(object.value(QStringLiteral("network_class")).toString(), event.networkClass)
        || !parseStage(object.value(QStringLiteral("stage")).toString(), event.stage)) return false;
    auto duration = [&](const QString &key, qint64 &target) {
        if (!object.contains(key)) { target = -1; return true; }
        return jsonDuration(object.value(key), target);
    };
    qint64 connect = -1, dns = -1, receipt = -1;
    if (!duration(QStringLiteral("connect_ms"), connect)
        || !duration(QStringLiteral("dns_ms"), dns)
        || !duration(QStringLiteral("receipt_ms"), receipt)
        || !duration(QStringLiteral("session_ms"), event.sessionMs)) return false;
    event.connectMs = int(connect); event.dnsMs = int(dns); event.receiptMs = int(receipt);
    if (object.contains(QStringLiteral("survived_5m"))) {
        if (!object.value(QStringLiteral("survived_5m")).isBool()) return false;
        event.survived5m = object.value(QStringLiteral("survived_5m")).toBool();
    }
    return safeEvent(event);
}

} // namespace

QString catalogNetworkClassName(CatalogNetworkClass value)
{
    return networkName(value);
}

QString scopedCatalogHistoryKey(const CatalogNetworkPathScope &scope,
                                const QString &profileId)
{
    if (!scope.isValid() || networkName(scope.networkClass).isEmpty()
        || profileId.isEmpty() || profileId.size() > 128)
        return {};
    const QByteArray digest = QCryptographicHash::hash(profileId.toUtf8(),
                                                       QCryptographicHash::Sha256);
    const QByteArray token = digest.toBase64(QByteArray::Base64UrlEncoding
                                              | QByteArray::OmitTrailingEquals);
    return QStringLiteral("path.v1.%1.%2.%3")
        .arg(networkName(scope.networkClass), QString::number(scope.epoch),
             QString::fromLatin1(token));
}

bool allocateCatalogNetworkPathScope(CatalogRuntimeState &state,
                                     CatalogNetworkClass networkClass,
                                     CatalogNetworkPathScope &scope,
                                     QString &error)
{
    scope = {};
    error.clear();
    if (networkName(networkClass).isEmpty() || state.nextNetworkPathEpoch == 0
        || state.nextNetworkPathEpoch > kMaxSafeJsonInteger) {
        error = QStringLiteral("network path epoch allocator exhausted/invalid");
        return false;
    }
    scope = {networkClass, state.nextNetworkPathEpoch};
    if (state.nextNetworkPathEpoch == kMaxSafeJsonInteger) {
        // Never wrap/reuse an epoch. The allocated terminal value is valid for the current
        // process, but future allocation will fail closed.
        state.nextNetworkPathEpoch = 0;
    } else {
        ++state.nextNetworkPathEpoch;
    }
    return true;
}

QHash<QString, CandidateHistory> candidateHistoryForPath(
    const CatalogRuntimeState &state,
    const CatalogNetworkPathScope &scope,
    const QList<CatalogCandidate> &candidates)
{
    QHash<QString, CandidateHistory> result;
    if (!scope.isValid()) return result;
    for (const CatalogCandidate &candidate : candidates) {
        const QString key = scopedCatalogHistoryKey(scope, candidate.profileId);
        if (!key.isEmpty() && state.candidateHistory.contains(key))
            result.insert(candidate.profileId, state.candidateHistory.value(key));
    }
    return result;
}

bool mergeCandidateHistoryForPath(CatalogRuntimeState &state,
                                  const CatalogNetworkPathScope &scope,
                                  const QHash<QString, CandidateHistory> &history,
                                  QString &error)
{
    error.clear();
    if (!scope.isValid() || history.size() > 512) {
        error = QStringLiteral("candidate history path scope invalid");
        return false;
    }
    QHash<QString, CandidateHistory> replacements;
    for (auto it = history.constBegin(); it != history.constEnd(); ++it) {
        const QString key = scopedCatalogHistoryKey(scope, it.key());
        if (key.isEmpty() || it.value().configGeneration == 0
            || it.value().bindingGeneration == 0) {
            error = QStringLiteral("candidate history path entry invalid");
            return false;
        }
        replacements.insert(key, it.value());
    }
    for (auto it = replacements.constBegin(); it != replacements.constEnd(); ++it)
        state.candidateHistory.insert(it.key(), it.value());
    const QString currentPrefix = scopedHistoryPrefix(scope);
    QStringList staleCurrent;
    for (auto it = state.candidateHistory.constBegin(); it != state.candidateHistory.constEnd(); ++it)
        if (it.key().startsWith(currentPrefix) && !replacements.contains(it.key()))
            staleCurrent.append(it.key());
    for (const QString &key : staleCurrent) state.candidateHistory.remove(key);

    // Deterministic epoch retention: oldest non-current path generations are pruned first. The
    // active scope is never evicted, and no raw SSID/BSSID/timestamp is needed for the ordering.
    // The encrypted runtime-state byte ceiling (128 KiB by default) is tighter than the nominal
    // item ceiling for worst-case timestamps/metrics. Retain a conservative deterministic 320 so
    // merge cannot create a state that will inevitably fail its next atomic persistence.
    constexpr int maximumHistories = 320;
    if (state.candidateHistory.size() > maximumHistories) {
        struct Prunable { quint64 epoch; QString key; };
        QList<Prunable> prunable;
        for (auto it = state.candidateHistory.constBegin(); it != state.candidateHistory.constEnd(); ++it) {
            if (it.key().startsWith(currentPrefix)) continue;
            quint64 epoch = 0;
            if (!scopedHistoryEpoch(it.key(), epoch)) {
                error = QStringLiteral("persisted candidate history scope is invalid");
                return false;
            }
            prunable.append({epoch, it.key()});
        }
        std::sort(prunable.begin(), prunable.end(), [](const Prunable &left,
                                                        const Prunable &right) {
            return left.epoch != right.epoch ? left.epoch < right.epoch
                                             : left.key < right.key;
        });
        int index = 0;
        while (state.candidateHistory.size() > maximumHistories
               && index < prunable.size())
            state.candidateHistory.remove(prunable.at(index++).key);
        if (state.candidateHistory.size() > maximumHistories) {
            error = QStringLiteral("current network path history exceeds bound");
            return false;
        }
    }
    return true;
}

QString newCatalogOutcomeEventId()
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
}

bool appendCatalogOutcome(CatalogRuntimeState &state, CatalogOutcomeEvent event,
                          QString &error, CatalogRuntimeStateLimits limits)
{
    error.clear();
    if (!safeEvent(event)) { error = QStringLiteral("outcome event violates redacted ABI"); return false; }
    for (const CatalogOutcomeEvent &existing : state.pendingOutcomes)
        if (existing.eventId == event.eventId) {
            error = QStringLiteral("duplicate outcome event id"); return false;
        }
    const int maximum = qBound(1, limits.maximumOutcomes, 512);
    while (state.pendingOutcomes.size() >= maximum) state.pendingOutcomes.removeFirst();
    state.pendingOutcomes.append(std::move(event));
    return true;
}

bool buildCatalogOutcomeUpload(const CatalogOutcomeEvent &event, QJsonObject &body, QString &error)
{
    body = {}; error.clear();
    if (!safeEvent(event)) { error = QStringLiteral("outcome upload event invalid"); return false; }
    body = outcomeObject(event, false);
    return true;
}

bool serializeCatalogRuntimeState(const CatalogRuntimeState &state, QByteArray &bytes,
                                  QString &error, CatalogRuntimeStateLimits limits)
{
    bytes.clear(); error.clear();
    if (state.candidateHistory.size() > qBound(1, limits.maximumHistories, 2048)
        || state.pendingOutcomes.size() > qBound(1, limits.maximumOutcomes, 512)) {
        error = QStringLiteral("catalog runtime state exceeds item bounds"); return false;
    }
    QJsonArray histories;
    QStringList ids = state.candidateHistory.keys();
    std::sort(ids.begin(), ids.end());
    for (const QString &id : ids) {
        const CandidateHistory history = state.candidateHistory.value(id);
        if (!safeId(id) || history.configGeneration == 0 || history.bindingGeneration == 0
            || history.configGeneration > kMaxSafeJsonInteger
            || history.bindingGeneration > kMaxSafeJsonInteger) {
            error = QStringLiteral("candidate history identity/generation invalid"); return false;
        }
        const auto ewma = [](double value) { return value == -1.0 || (std::isfinite(value) && value >= 0.0 && value <= 1.0); };
        const auto latency = [](double value) { return value == -1.0 || (std::isfinite(value) && value >= 0.0 && value <= 86400000.0); };
        if (!ewma(history.verifiedSuccessEwma) || !ewma(history.survival5mEwma)
            || !latency(history.verifiedStartLatencyMs) || !latency(history.weakProbeRttMs)) {
            error = QStringLiteral("candidate history metric invalid"); return false;
        }
        histories.append(QJsonObject{
            {QStringLiteral("profile_id"), id},
            {QStringLiteral("config_generation"), double(history.configGeneration)},
            {QStringLiteral("binding_generation"), double(history.bindingGeneration)},
            {QStringLiteral("verified_success_ewma"), history.verifiedSuccessEwma},
            {QStringLiteral("survival_5m_ewma"), history.survival5mEwma},
            {QStringLiteral("verified_start_latency_ms"), history.verifiedStartLatencyMs},
            {QStringLiteral("weak_probe_rtt_ms"), history.weakProbeRttMs},
            {QStringLiteral("last_verified_at"), history.lastVerifiedAtUtc.isValid()
                 ? history.lastVerifiedAtUtc.toUTC().toString(Qt::ISODateWithMs) : QString()},
            {QStringLiteral("cooldown_until"), history.cooldownUntil.isValid()
                 ? history.cooldownUntil.toUTC().toString(Qt::ISODateWithMs) : QString()},
        });
    }
    QJsonArray outcomes;
    QSet<QString> outcomeIds;
    for (const CatalogOutcomeEvent &event : state.pendingOutcomes) {
        if (!safeEvent(event) || outcomeIds.contains(event.eventId)) {
            error = QStringLiteral("outcome queue invalid/duplicate"); return false;
        }
        outcomeIds.insert(event.eventId);
        outcomes.append(outcomeObject(event, true));
    }
    const bool clockEmpty = !state.trustedClock.highestSignedIssuedAtUtc.isValid()
                            && !state.trustedClock.highestObservedWallUtc.isValid();
    const bool clockComplete = state.trustedClock.highestSignedIssuedAtUtc.isValid()
                               && state.trustedClock.highestObservedWallUtc.isValid();
    if (!clockEmpty && !clockComplete) {
        error = QStringLiteral("trusted clock runtime state is partial"); return false;
    }
    const QJsonValue clock = clockEmpty ? QJsonValue(QJsonValue::Null)
        : QJsonValue(QJsonObject{
            {QStringLiteral("highest_signed_issued_at"),
             state.trustedClock.highestSignedIssuedAtUtc.toUTC().toString(Qt::ISODateWithMs)},
            {QStringLiteral("highest_observed_wall"),
             state.trustedClock.highestObservedWallUtc.toUTC().toString(Qt::ISODateWithMs)},
        });
    if (state.nextNetworkPathEpoch == 0
        || state.nextNetworkPathEpoch > kMaxSafeJsonInteger) {
        bytes.clear(); error = QStringLiteral("network path epoch allocator invalid"); return false;
    }
    quint64 maximumStoredEpoch = 0;
    for (const QString &id : ids) {
        quint64 epoch = 0;
        if (!scopedHistoryEpoch(id, epoch)) {
            bytes.clear(); error = QStringLiteral("candidate history scope invalid"); return false;
        }
        maximumStoredEpoch = qMax(maximumStoredEpoch, epoch);
    }
    if (state.nextNetworkPathEpoch <= maximumStoredEpoch) {
        bytes.clear(); error = QStringLiteral("network path epoch allocator would reuse history");
        return false;
    }
    bytes = QJsonDocument(QJsonObject{{QStringLiteral("schema"), 3},
                                      {QStringLiteral("next_path_epoch"),
                                       double(state.nextNetworkPathEpoch)},
                                      {QStringLiteral("histories"), histories},
                                      {QStringLiteral("outcomes"), outcomes},
                                      {QStringLiteral("trusted_clock"), clock}})
                .toJson(QJsonDocument::Compact);
    if (bytes.size() > qBound(4096, limits.maximumBytes, 512 * 1024)) {
        bytes.clear(); error = QStringLiteral("catalog runtime state exceeds byte bound"); return false;
    }
    return true;
}

bool parseCatalogRuntimeState(const QByteArray &bytes, CatalogRuntimeState &state,
                              QString &error, CatalogRuntimeStateLimits limits)
{
    state = {}; error.clear();
    QJsonDocument document;
    const int maximum = qBound(4096, limits.maximumBytes, 512 * 1024);
    const QSet<QString> rootV2Keys{QStringLiteral("schema"), QStringLiteral("histories"),
                                   QStringLiteral("outcomes"), QStringLiteral("trusted_clock")};
    QSet<QString> rootV3Keys = rootV2Keys;
    rootV3Keys.insert(QStringLiteral("next_path_epoch"));
    quint64 parsedSchema = 0;
    if (!parseStrictJsonDocument(bytes, document, error, maximum) || !document.isObject()
        || !jsonUInt(document.object().value(QStringLiteral("schema")), parsedSchema)
        || (parsedSchema != 2 && parsedSchema != 3)
        || !exactKeys(document.object(),
                      parsedSchema == 3
                          ? rootV3Keys : rootV2Keys)
        || !document.object().value(QStringLiteral("histories")).isArray()
        || !document.object().value(QStringLiteral("outcomes")).isArray()) {
        state = {}; error = QStringLiteral("catalog runtime state root invalid"); return false;
    }
    const QJsonArray histories = document.object().value(QStringLiteral("histories")).toArray();
    const QJsonArray outcomes = document.object().value(QStringLiteral("outcomes")).toArray();
    const int schema = int(parsedSchema);
    if (schema == 3
        && !jsonUInt(document.object().value(QStringLiteral("next_path_epoch")),
                     state.nextNetworkPathEpoch)) {
        state = {}; error = QStringLiteral("network path epoch allocator invalid"); return false;
    }
    if (histories.size() > qBound(1, limits.maximumHistories, 2048)
        || outcomes.size() > qBound(1, limits.maximumOutcomes, 512)) {
        error = QStringLiteral("catalog runtime arrays exceed bounds"); return false;
    }
    const QJsonValue clockValue = document.object().value(QStringLiteral("trusted_clock"));
    if (!clockValue.isNull()) {
        const QSet<QString> clockKeys{QStringLiteral("highest_signed_issued_at"),
                                      QStringLiteral("highest_observed_wall")};
        if (!clockValue.isObject() || !exactKeys(clockValue.toObject(), clockKeys)) {
            error = QStringLiteral("trusted clock runtime state shape invalid"); return false;
        }
        state.trustedClock.highestSignedIssuedAtUtc = QDateTime::fromString(
            clockValue.toObject().value(QStringLiteral("highest_signed_issued_at")).toString(),
            Qt::ISODateWithMs).toUTC();
        state.trustedClock.highestObservedWallUtc = QDateTime::fromString(
            clockValue.toObject().value(QStringLiteral("highest_observed_wall")).toString(),
            Qt::ISODateWithMs).toUTC();
        if (!state.trustedClock.highestSignedIssuedAtUtc.isValid()
            || !state.trustedClock.highestObservedWallUtc.isValid()) {
            error = QStringLiteral("trusted clock runtime timestamps invalid"); return false;
        }
    }
    const QSet<QString> historyKeys{
        QStringLiteral("profile_id"), QStringLiteral("config_generation"),
        QStringLiteral("binding_generation"), QStringLiteral("verified_success_ewma"),
        QStringLiteral("survival_5m_ewma"), QStringLiteral("verified_start_latency_ms"),
        QStringLiteral("weak_probe_rtt_ms"), QStringLiteral("cooldown_until")};
    const QSet<QString> optionalHistoryKeys{QStringLiteral("last_verified_at")};
    QString previous;
    quint64 maximumStoredEpoch = 0;
    for (const QJsonValue &value : histories) {
        if (!value.isObject()
            || !exactKeys(value.toObject(), historyKeys, optionalHistoryKeys)) {
            state = {}; error = QStringLiteral("candidate history shape invalid"); return false;
        }
        const QJsonObject object = value.toObject();
        const QString id = object.value(QStringLiteral("profile_id")).toString();
        CandidateHistory history;
        if (!safeId(id) || (!previous.isEmpty() && id <= previous)
            || !jsonUInt(object.value(QStringLiteral("config_generation")), history.configGeneration)
            || !jsonUInt(object.value(QStringLiteral("binding_generation")), history.bindingGeneration)) {
            state = {}; error = QStringLiteral("candidate history identity invalid"); return false;
        }
        previous = id;
        quint64 historyEpoch = 0;
        if (!scopedHistoryEpoch(id, historyEpoch)) {
            state = {}; error = QStringLiteral("candidate history scope invalid"); return false;
        }
        maximumStoredEpoch = qMax(maximumStoredEpoch, historyEpoch);
        history.verifiedSuccessEwma = object.value(QStringLiteral("verified_success_ewma")).toDouble(-2);
        history.survival5mEwma = object.value(QStringLiteral("survival_5m_ewma")).toDouble(-2);
        history.verifiedStartLatencyMs = object.value(QStringLiteral("verified_start_latency_ms")).toDouble(-2);
        history.weakProbeRttMs = object.value(QStringLiteral("weak_probe_rtt_ms")).toDouble(-2);
        const QString lastVerified = object.value(QStringLiteral("last_verified_at")).toString();
        if (!lastVerified.isEmpty()) {
            history.lastVerifiedAtUtc = QDateTime::fromString(
                lastVerified, Qt::ISODateWithMs).toUTC();
            if (!history.lastVerifiedAtUtc.isValid()) {
                state = {};
                error = QStringLiteral("candidate last verification timestamp invalid");
                return false;
            }
        }
        const QString cooldown = object.value(QStringLiteral("cooldown_until")).toString();
        if (!cooldown.isEmpty()) {
            history.cooldownUntil = QDateTime::fromString(cooldown, Qt::ISODateWithMs).toUTC();
            if (!history.cooldownUntil.isValid()) {
                state = {}; error = QStringLiteral("candidate cooldown invalid"); return false;
            }
        }
        CatalogRuntimeState one;
        one.candidateHistory.insert(id, history);
        if (historyEpoch >= kMaxSafeJsonInteger) {
            state = {}; error = QStringLiteral("candidate history epoch exhausted"); return false;
        }
        one.nextNetworkPathEpoch = historyEpoch + 1;
        QByteArray checked;
        if (!serializeCatalogRuntimeState(one, checked, error, limits)) { state = {}; return false; }
        state.candidateHistory.insert(id, history);
    }
    if (schema == 2) {
        // N-1 migration: derive the first never-used durable epoch from authenticated keys.
        if (maximumStoredEpoch >= kMaxSafeJsonInteger) {
            state = {}; error = QStringLiteral("network path epoch migration exhausted"); return false;
        }
        state.nextNetworkPathEpoch = maximumStoredEpoch + 1;
        if (state.nextNetworkPathEpoch == 0) state.nextNetworkPathEpoch = 1;
    } else if (state.nextNetworkPathEpoch <= maximumStoredEpoch) {
        state = {}; error = QStringLiteral("network path epoch rollback/reuse detected"); return false;
    }
    QSet<QString> eventIds;
    for (const QJsonValue &value : outcomes) {
        CatalogOutcomeEvent event;
        if (!value.isObject() || !parseEvent(value.toObject(), event)
            || eventIds.contains(event.eventId)) {
            state = {}; error = QStringLiteral("outcome queue event invalid/duplicate"); return false;
        }
        eventIds.insert(event.eventId);
        state.pendingOutcomes.append(event);
    }
    return true;
}

} // namespace avpn
