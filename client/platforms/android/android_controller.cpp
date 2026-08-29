#include <QJniEnvironment>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QSet>
#include <QStringList>
#include <QUuid>
#include <QQmlFile>
#include <QEventLoop>
#include <QImage>

#include <limits>
#include <cmath>

#include <android/bitmap.h>

#include "android_controller.h"
#include "android_utils.h"
#include "avpn_fcm_bridge.h" // AVPN (Task 9): FCM natives + запрос токена
#include "ui/controllers/importUiController.h"

namespace
{
    AndroidController *s_instance = nullptr;

    constexpr auto QT_ANDROID_CONTROLLER_CLASS = "org/amnezia/vpn/qt/QtAndroidController";
    constexpr auto ANDROID_LOG_CLASS = "org/amnezia/vpn/util/Log";
    constexpr auto TAG = "AmneziaQt";

    quint64 jsonUint64(const QJsonValue &value, bool *ok = nullptr)
    {
        const QString text = value.isString() ? value.toString() : QString();
        bool canonical = !text.isEmpty()
                && (text == QLatin1String("0") || text.front() != QLatin1Char('0'));
        for (const QChar ch : text) {
            if (ch < QLatin1Char('0') || ch > QLatin1Char('9')) {
                canonical = false;
                break;
            }
        }
        bool parsed = false;
        const quint64 result = canonical ? text.toULongLong(&parsed, 10) : 0;
        if (ok) *ok = parsed;
        return result;
    }

    quint64 saturatingAdd(quint64 lhs, quint64 rhs)
    {
        return rhs > std::numeric_limits<quint64>::max() - lhs
                ? std::numeric_limits<quint64>::max() : lhs + rhs;
    }

    bool schemaOne(const QJsonValue &value)
    {
        return value.isDouble() && value.toDouble() == 1.0;
    }

    bool positiveJsonInteger(const QJsonValue &value)
    {
        if (!value.isDouble()) return false;
        const double number = value.toDouble();
        return std::isfinite(number) && std::floor(number) == number
                && number > 0 && number <= std::numeric_limits<qint32>::max();
    }

    bool safeAsciiOpaque(const QString &value)
    {
        if (value.isEmpty() || value.size() > 200) return false;
        for (const QChar ch : value) {
            const ushort c = ch.unicode();
            const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            const bool digit = c >= '0' && c <= '9';
            if (!alpha && !digit && c != '-' && c != '_' && c != ':' && c != '.')
                return false;
        }
        return true;
    }

    bool lowerSha256(const QString &value)
    {
        if (value.size() != 64) return false;
        for (const QChar c : value)
            if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9'))
                  || (c >= QLatin1Char('a') && c <= QLatin1Char('f')))) return false;
        return true;
    }

    bool canonicalUuid(const QString &value)
    {
        const QUuid uuid(value);
        return !uuid.isNull()
                && uuid.toString(QUuid::WithoutBraces).toLower() == value;
    }

    bool safeAsciiReason(const QString &value)
    {
        if (value.size() > 96) return false;
        for (const QChar c : value)
            if (c.unicode() < 0x20 || c.unicode() > 0x7e) return false;
        return true;
    }

    bool strictRecoveryReceipt(const QJsonObject &receipt)
    {
        static const QSet<QString> keys{
            QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("action"),
            QStringLiteral("kind"), QStringLiteral("operation"), QStringLiteral("session"),
            QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
            QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason")};
        const QStringList actual = receipt.keys();
        bool operationOk = false;
        bool sessionOk = false;
        const quint64 operation = jsonUint64(receipt.value(QStringLiteral("operation")),
                                             &operationOk);
        const quint64 session = jsonUint64(receipt.value(QStringLiteral("session")),
                                           &sessionOk);
        const QString action = receipt.value(QStringLiteral("action")).toString();
        const QString kind = receipt.value(QStringLiteral("kind")).toString();
        const bool validPair = (action == QLatin1String("adopt")
                                && (kind == QLatin1String("adopted")
                                    || kind == QLatin1String("rejected")))
                || (action == QLatin1String("stop")
                    && (kind == QLatin1String("stopped_released")
                        || kind == QLatin1String("rejected")));
        return QSet<QString>(actual.cbegin(), actual.cend()) == keys
                && receipt.value(QStringLiteral("type"))
                       == QLatin1String("native_session_guard_recovery_v1")
                && schemaOne(receipt.value(QStringLiteral("schema")))
                && operationOk && sessionOk && operation > 0 && session > 0
                && validPair
                && lowerSha256(receipt.value(QStringLiteral("policy_sha256")).toString())
                && safeAsciiOpaque(receipt.value(QStringLiteral("outer_session_id")).toString())
                && canonicalUuid(receipt.value(
                       QStringLiteral("expected_runtime_session_id")).toString())
                && safeAsciiReason(receipt.value(QStringLiteral("reason")).toString());
    }

    bool canonicalGeneration(const QString &value)
    {
        if (value.isEmpty() || value.size() > 20
            || (value.size() > 1 && value.startsWith(QLatin1Char('0')))) return false;
        bool ok = false;
        const quint64 parsed = value.toULongLong(&ok, 10);
        return ok && QString::number(parsed) == value;
    }

    bool canonicalTokenString(const QString &value)
    {
        bool ok = false;
        const quint64 parsed = jsonUint64(QJsonValue(value), &ok);
        return ok && parsed > 0;
    }

    bool canonicalUtcMillis(const QString &value)
    {
        if (value.size() != 24 || !value.endsWith(QLatin1Char('Z'))) return false;
        const QDateTime parsed = QDateTime::fromString(value, Qt::ISODateWithMs);
        return parsed.isValid() && parsed.offsetFromUtc() == 0
                && parsed.toUTC().toString(Qt::ISODateWithMs) == value;
    }

    bool authorityHardDeadline(const QJsonObject &authority, QString &deadline)
    {
        deadline.clear();
        QList<QDateTime> values;
        for (const char *key : {"native_profile_expires_at",
                                "catalog_freshness_deadline",
                                "entitlement_deadline"}) {
            const QString text = authority.value(QLatin1String(key)).toString();
            if (text.isEmpty() || !text.endsWith(QLatin1Char('Z'))) return false;
            QDateTime parsed = QDateTime::fromString(text, Qt::ISODateWithMs);
            if (!parsed.isValid()) parsed = QDateTime::fromString(text, Qt::ISODate);
            if (!parsed.isValid() || parsed.offsetFromUtc() != 0) return false;
            values.append(parsed.toUTC());
        }
        QDateTime hard = values.first();
        for (const QDateTime &value : values)
            if (value < hard) hard = value;
        deadline = hard.toString(Qt::ISODateWithMs);
        return canonicalUtcMillis(deadline);
    }

    bool buildAuthorityRenewalRequest(const QJsonObject &vpnConfig,
                                      const QString &operation,
                                      const QString &session,
                                      const QString &outerSessionId,
                                      const QString &expectedRuntimeSessionId,
                                      const QString &renewalId,
                                      const QString &authorityCommitmentHex,
                                      QJsonObject &request)
    {
        request = {};
        const QJsonObject authority = vpnConfig.value(
            QStringLiteral("runtime_authority_v1")).toObject();
        static const QSet<QString> authorityKeys{
            QStringLiteral("schema_version"), QStringLiteral("device_audience"),
            QStringLiteral("catalog_revision"), QStringLiteral("catalog_payload_sha256"),
            QStringLiteral("catalog_signing_kid"), QStringLiteral("catalog_source"),
            QStringLiteral("profile_id"), QStringLiteral("transport"),
            QStringLiteral("config_generation"), QStringLiteral("binding_generation"),
            QStringLiteral("native_profile_expires_at"),
            QStringLiteral("catalog_freshness_deadline"),
            QStringLiteral("entitlement_deadline"), QStringLiteral("catalog_issued_at"),
            QStringLiteral("trusted_utc_at_dispatch"), QStringLiteral("policy_schema"),
            QStringLiteral("policy_sha256"), QStringLiteral("protected_tunnel_ips"),
            QStringLiteral("receiver_monotonic_policy"),
        };
        const QStringList actualKeys = authority.keys();
        const QString policy = authority.value(QStringLiteral("policy_sha256")).toString();
        const QString configGeneration = authority.value(
            QStringLiteral("config_generation")).toString();
        const QString bindingGeneration = authority.value(
            QStringLiteral("binding_generation")).toString();
        const QString revision = authority.value(QStringLiteral("catalog_revision")).toString();
        const QString payload = authority.value(
            QStringLiteral("catalog_payload_sha256")).toString();
        QString deadline;
        if (vpnConfig.value(QStringLiteral("native_envelope_schema"))
                != QLatin1String("tribe_catalog_v2_native_v1")
            || QSet<QString>(actualKeys.cbegin(), actualKeys.cend()) != authorityKeys
            || !schemaOne(authority.value(QStringLiteral("schema_version")))
            || !canonicalTokenString(operation) || !canonicalTokenString(session)
            || !safeAsciiOpaque(outerSessionId) || !canonicalUuid(expectedRuntimeSessionId)
            || !canonicalUuid(renewalId) || !lowerSha256(policy)
            || !canonicalGeneration(configGeneration)
            || !canonicalGeneration(bindingGeneration) || !canonicalGeneration(revision)
            || !lowerSha256(payload) || !lowerSha256(authorityCommitmentHex)
            || !authorityHardDeadline(authority, deadline)) return false;
        request = {
            {QStringLiteral("type"), QStringLiteral("runtime_authority_renewal_request_v1")},
            {QStringLiteral("schema"), 1},
            {QStringLiteral("operation"), operation},
            {QStringLiteral("session"), session},
            {QStringLiteral("renewal_id"), renewalId},
            {QStringLiteral("policy_sha256"), policy},
            {QStringLiteral("outer_session_id"), outerSessionId},
            {QStringLiteral("expected_runtime_session_id"), expectedRuntimeSessionId},
            {QStringLiteral("config_generation"), configGeneration},
            {QStringLiteral("binding_generation"), bindingGeneration},
            {QStringLiteral("catalog_revision"), revision},
            {QStringLiteral("catalog_payload_sha256"), payload},
            {QStringLiteral("authority_commitment_sha256"), authorityCommitmentHex},
            {QStringLiteral("hard_deadline"), deadline},
        };
        return true;
    }

    bool strictAuthorityRenewalReceipt(const QJsonObject &receipt)
    {
        static const QSet<QString> keys{
            QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("kind"),
            QStringLiteral("operation"), QStringLiteral("session"),
            QStringLiteral("renewal_id"), QStringLiteral("policy_sha256"),
            QStringLiteral("outer_session_id"),
            QStringLiteral("expected_runtime_session_id"),
            QStringLiteral("config_generation"), QStringLiteral("binding_generation"),
            QStringLiteral("catalog_revision"), QStringLiteral("catalog_payload_sha256"),
            QStringLiteral("authority_commitment_sha256"),
            QStringLiteral("hard_deadline"), QStringLiteral("reason"),
        };
        const QStringList actualKeys = receipt.keys();
        const QString kind = receipt.value(QStringLiteral("kind")).toString();
        const QString reason = receipt.value(QStringLiteral("reason")).toString();
        const QString deadline = receipt.value(QStringLiteral("hard_deadline")).toString();
        return QSet<QString>(actualKeys.cbegin(), actualKeys.cend()) == keys
            && receipt.value(QStringLiteral("type"))
                == QLatin1String("runtime_authority_renewal_v1")
            && schemaOne(receipt.value(QStringLiteral("schema")))
            && canonicalTokenString(receipt.value(QStringLiteral("operation")).toString())
            && canonicalTokenString(receipt.value(QStringLiteral("session")).toString())
            && canonicalUuid(receipt.value(QStringLiteral("renewal_id")).toString())
            && lowerSha256(receipt.value(QStringLiteral("policy_sha256")).toString())
            && safeAsciiOpaque(receipt.value(QStringLiteral("outer_session_id")).toString())
            && canonicalUuid(receipt.value(
                QStringLiteral("expected_runtime_session_id")).toString())
            && canonicalGeneration(receipt.value(
                QStringLiteral("config_generation")).toString())
            && canonicalGeneration(receipt.value(
                QStringLiteral("binding_generation")).toString())
            && canonicalGeneration(receipt.value(QStringLiteral("catalog_revision")).toString())
            && lowerSha256(receipt.value(
                QStringLiteral("catalog_payload_sha256")).toString())
            && lowerSha256(receipt.value(
                QStringLiteral("authority_commitment_sha256")).toString())
            && safeAsciiReason(reason)
            && ((kind == QLatin1String("applied") && reason.isEmpty()
                 && canonicalUtcMillis(deadline))
                || (kind == QLatin1String("rejected") && !reason.isEmpty()
                    && deadline.isEmpty()));
    }

    bool renewalReceiptMatches(const QJsonObject &receipt, const QJsonObject &request)
    {
        for (const char *key : {"operation", "session", "renewal_id", "policy_sha256",
                                "outer_session_id", "expected_runtime_session_id",
                                "config_generation", "binding_generation", "catalog_revision",
                                "catalog_payload_sha256", "authority_commitment_sha256"}) {
            if (receipt.value(QLatin1String(key)) != request.value(QLatin1String(key))) return false;
        }
        return receipt.value(QStringLiteral("kind")) == QLatin1String("rejected")
            || receipt.value(QStringLiteral("hard_deadline"))
                == request.value(QStringLiteral("hard_deadline"));
    }

    QJsonObject rejectedRenewalReceipt(const QJsonObject &request, const QString &reason)
    {
        QJsonObject receipt = request;
        receipt.insert(QStringLiteral("type"), QStringLiteral("runtime_authority_renewal_v1"));
        receipt.insert(QStringLiteral("kind"), QStringLiteral("rejected"));
        receipt.insert(QStringLiteral("hard_deadline"), QString());
        receipt.insert(QStringLiteral("reason"), reason);
        return receipt;
    }
} // namespace

AndroidController::AndroidController() : QObject()
{
    connect(this, &AndroidController::status, this,
            [this](AndroidController::ConnectionState state) {
                qDebug() << "Android event: status =" << textConnectionState(state);
                if (isWaitingStatus) {
                    qDebug() << "Initialization by service status";
                    isWaitingStatus = false;
                    emit initConnectionState(convertState(state));
                }
            },
            Qt::QueuedConnection);

    connect(
        this, &AndroidController::serviceDisconnected, this,
        [this]() {
            qDebug() << "Android event: service disconnected";
            isWaitingStatus = true;
            emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::serviceError, this,
        [this]() {
            qDebug() << "Android event: service error";
            // todo: add error message
            emit connectionStateChanged(Vpn::ConnectionState::Error);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::vpnPermissionRejected, this,
        [this]() {
            qWarning() << "Android event: VPN permission rejected";
            emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::vpnStateChanged, this,
        [this](AndroidController::ConnectionState state) {
            qDebug() << "Android event: VPN state changed:" << textConnectionState(state);
            emit connectionStateChanged(convertState(state));
        },
        Qt::QueuedConnection);

    connect(
        this, &AndroidController::configImported, this,
        [this](const QString& config) {
            qDebug() << "Android event: config import";
            emit importConfigFromOutside(config);
        },
        Qt::QueuedConnection);
}

AndroidController *AndroidController::instance()
{
    if (!s_instance) {
        s_instance = new AndroidController();
    }

    return s_instance;
}

bool AndroidController::initialize()
{
    qDebug() << "Initialize AndroidController";

    const JNINativeMethod methods[] = {
        {"onStatus", "(I)V", reinterpret_cast<void *>(onStatus)},
        {"onServiceDisconnected", "()V", reinterpret_cast<void *>(onServiceDisconnected)},
        {"onServiceError", "()V", reinterpret_cast<void *>(onServiceError)},
        {"onVpnPermissionRejected", "()V", reinterpret_cast<void *>(onVpnPermissionRejected)},
        {"onNotificationStateChanged", "()V", reinterpret_cast<void *>(onNotificationStateChanged)},
        {"onVpnStateChanged", "(I)V", reinterpret_cast<void *>(onVpnStateChanged)},
        {"onStatisticsUpdate", "(JJJ)V", reinterpret_cast<void *>(onStatisticsUpdate)}, // AVPN: +handshake long
        {"onRuntimeStatus", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onRuntimeStatus)}, // AVPN
        {"onEngineManifest", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onEngineManifest)}, // AVPN
        {"onSessionGuardEvent", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onSessionGuardEvent)},
        {"onSessionGuardRecoveryReceipt", "(Ljava/lang/String;)V",
         reinterpret_cast<void *>(onSessionGuardRecoveryReceipt)},
        {"onRuntimeAuthorityRenewalReceipt", "(Ljava/lang/String;)V",
         reinterpret_cast<void *>(onRuntimeAuthorityRenewalReceipt)},
        {"onFileOpened", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onFileOpened)},
        {"onConfigImported", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onConfigImported)},
        {"onAuthResult", "(Z)V", reinterpret_cast<void *>(onAuthResult)},
        {"decodeQrCode", "(Ljava/lang/String;)Z", reinterpret_cast<bool *>(decodeQrCode)},
        {"onImeInsetsChanged", "(I)V", reinterpret_cast<void *>(onImeInsetsChanged)},
        {"onSystemBarsInsetsChanged", "(II)V", reinterpret_cast<void *>(onSystemBarsInsetsChanged)},
        {"onActivityPaused", "()V", reinterpret_cast<void *>(onActivityPaused)},
        {"onActivityResumed", "()V", reinterpret_cast<void *>(onActivityResumed)}
    };

    QJniEnvironment env;
    bool registered = env.registerNativeMethods(QT_ANDROID_CONTROLLER_CLASS, methods,
                                                sizeof(methods) / sizeof(JNINativeMethod));
    if (!registered) {
        qCritical() << "Failed native method registration";
        return false;
    }

    // AVPN (Task 9, FCM): natives пуш-сервиса + старт Kotlin-половины (см. avpn_fcm_bridge.cpp).
    // Неуспех НЕ валит контроллер: без Play Services пуши деградируют до поллинга чата.
    avpn::registerFcmNatives();
    qtAndroidControllerInitialized();
    return true;
}

// static
template <typename Ret, typename ...Args>
auto AndroidController::callActivityMethod(const char *methodName, const char *signature, Args &&...args)
{
    qDebug() << "Call activity method:" << methodName;
    QJniObject activity = AndroidUtils::getActivity();
    Q_ASSERT(activity.isValid());
    return activity.callMethod<Ret>(methodName, signature, std::forward<Args>(args)...);
}

// static
template <typename ...Args>
void AndroidController::callActivityMethod(const char *methodName, const char *signature, Args &&...args)
{
    callActivityMethod<void>(methodName, signature, std::forward<Args>(args)...);
}

ErrorCode AndroidController::start(const QJsonObject &vpnConfig)
{
    isWaitingStatus = false;
    QJsonObject dispatch = vpnConfig;
    // Legacy/manual profiles enter through this distinct native API path and receive an explicit
    // discriminator before the one-shot encrypted handoff. Catalog-v2 already carries its own
    // immutable discriminator from the final C++ sanitizer; Android never infers legacy merely
    // because runtime_authority_v1 is absent.
    if (!dispatch.contains(QStringLiteral("native_envelope_schema"))) {
        dispatch.insert(QStringLiteral("native_envelope_schema"),
                        QStringLiteral("amnezia_legacy_native_v1"));
    }
    auto config = QJsonDocument(dispatch).toJson();
    callActivityMethod("start", "(Ljava/lang/String;)V",
                       QJniObject::fromString(config).object<jstring>());

    return ErrorCode::NoError;
}

bool AndroidController::renewRuntimeAuthority(const QJsonObject &vpnConfig,
                                              const QString &operation,
                                              const QString &session,
                                              const QString &outerSessionId,
                                              const QString &expectedRuntimeSessionId,
                                              const QString &renewalId,
                                              const QString &authorityCommitmentHex)
{
    QJsonObject request;
    if (vpnConfig.isEmpty() || !m_pendingAuthorityRenewalRequest.isEmpty()
        || m_armedGuardReceipt.isEmpty()
        || !buildAuthorityRenewalRequest(vpnConfig, operation, session, outerSessionId,
                                         expectedRuntimeSessionId, renewalId,
                                         authorityCommitmentHex, request)) return false;
    for (const char *key : {"operation", "session", "policy_sha256", "outer_session_id",
                            "expected_runtime_session_id"}) {
        if (request.value(QLatin1String(key))
                != m_armedGuardReceipt.value(QLatin1String(key))) return false;
    }
    if (!m_runtimeSessionId.isEmpty() && m_runtimeSessionId != expectedRuntimeSessionId)
        return false;
    m_pendingAuthorityRenewalRequest = request;
    const QByteArray config = QJsonDocument(vpnConfig).toJson(QJsonDocument::Compact);
    const QByteArray requestBytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
    callActivityMethod("renewRuntimeAuthority",
                       "(Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(QString::fromUtf8(config)).object<jstring>(),
                       QJniObject::fromString(QString::fromUtf8(requestBytes)).object<jstring>());
    return true;
}

bool AndroidController::requestSessionGuardArm(const QJsonObject &vpnConfig,
                                               const QString &operation,
                                               const QString &session,
                                               const QString &policyHashHex,
                                               const QString &expectedRuntimeSessionId)
{
    if (vpnConfig.isEmpty() || operation.isEmpty() || session.isEmpty()
            || policyHashHex.size() != 64 || expectedRuntimeSessionId.isEmpty()) return false;
    const QUuid runtimeUuid(expectedRuntimeSessionId);
    if (runtimeUuid.isNull()
            || runtimeUuid.toString(QUuid::WithoutBraces).toLower()
                    != expectedRuntimeSessionId
            || !m_pendingGuardRequest.isEmpty()) return false;
    bool operationOk = false;
    bool sessionOk = false;
    const quint64 operationValue = jsonUint64(QJsonValue(operation), &operationOk);
    const quint64 sessionValue = jsonUint64(QJsonValue(session), &sessionOk);
    bool policyCanonical = policyHashHex.size() == 64;
    for (const QChar c : policyHashHex)
        policyCanonical = policyCanonical
                && ((c >= QLatin1Char('0') && c <= QLatin1Char('9'))
                    || (c >= QLatin1Char('a') && c <= QLatin1Char('f')));
    if (!operationOk || !sessionOk || operationValue == 0 || sessionValue == 0
            || !policyCanonical) return false;
    const QString requestedOuterSessionId = QStringLiteral("android:")
            + QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    m_expectedCatalogRuntimeSessionId = expectedRuntimeSessionId;
    m_pendingGuardRequest = {
        {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), operation},
        {QStringLiteral("session"), session},
        {QStringLiteral("kind"), QStringLiteral("lost")},
        {QStringLiteral("policy_sha256"), policyHashHex},
        {QStringLiteral("outer_session_id"), requestedOuterSessionId},
        {QStringLiteral("expected_runtime_session_id"), expectedRuntimeSessionId},
        {QStringLiteral("reason"), QStringLiteral("service_channel_lost")},
    };
    const QByteArray config = QJsonDocument(vpnConfig).toJson(QJsonDocument::Compact);
    callActivityMethod("prepareNativeSessionGuard",
                       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(QString::fromUtf8(config)).object<jstring>(),
                       QJniObject::fromString(operation).object<jstring>(),
                       QJniObject::fromString(session).object<jstring>(),
                       QJniObject::fromString(policyHashHex).object<jstring>(),
                       QJniObject::fromString(expectedRuntimeSessionId).object<jstring>(),
                       QJniObject::fromString(requestedOuterSessionId).object<jstring>());
    return true;
}

bool AndroidController::activateNativeSession(const QJsonObject &vpnConfig,
                                              const QString &operation,
                                              const QString &session,
                                              const QString &outerSessionId,
                                              const QString &expectedRuntimeSessionId)
{
    if (vpnConfig.isEmpty() || operation.isEmpty() || session.isEmpty()
            || outerSessionId.isEmpty() || expectedRuntimeSessionId.isEmpty()
            || m_armedGuardReceipt.isEmpty()
            || m_armedGuardReceipt.value(QStringLiteral("operation")).toString() != operation
            || m_armedGuardReceipt.value(QStringLiteral("session")).toString() != session
            || m_armedGuardReceipt.value(QStringLiteral("outer_session_id")).toString()
                    != outerSessionId
            || m_armedGuardReceipt.value(
                   QStringLiteral("expected_runtime_session_id")).toString()
                    != expectedRuntimeSessionId) return false;
    const QByteArray config = QJsonDocument(vpnConfig).toJson(QJsonDocument::Compact);
    callActivityMethod("activateNativeSession",
                       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(QString::fromUtf8(config)).object<jstring>(),
                       QJniObject::fromString(operation).object<jstring>(),
                       QJniObject::fromString(session).object<jstring>(),
                       QJniObject::fromString(outerSessionId).object<jstring>(),
                       QJniObject::fromString(expectedRuntimeSessionId).object<jstring>());
    return true;
}

bool AndroidController::stopNativeSession(const QString &outerSessionId,
                                          const QString &expectedRuntimeSessionId)
{
    if (outerSessionId.isEmpty() || expectedRuntimeSessionId.isEmpty()) return false;
    callActivityMethod("stopNativeSession",
                       "(Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(outerSessionId).object<jstring>(),
                       QJniObject::fromString(expectedRuntimeSessionId).object<jstring>());
    return true;
}

bool AndroidController::requestSessionGuardRelease(const QString &operation,
                                                    const QString &session,
                                                    const QString &outerSessionId)
{
    if (operation.isEmpty() || session.isEmpty() || outerSessionId.isEmpty()
            || !m_pendingGuardReleaseRequest.isEmpty() || m_armedGuardReceipt.isEmpty()
            || m_armedGuardReceipt.value(QStringLiteral("operation")).toString() != operation
            || m_armedGuardReceipt.value(QStringLiteral("session")).toString() != session
            || m_armedGuardReceipt.value(QStringLiteral("outer_session_id"))
                   .toString() != outerSessionId) return false;
    m_pendingGuardReleaseRequest = m_armedGuardReceipt;
    callActivityMethod("releaseNativeSessionGuard",
                       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(operation).object<jstring>(),
                       QJniObject::fromString(session).object<jstring>(),
                       QJniObject::fromString(outerSessionId).object<jstring>());
    return true;
}

bool AndroidController::requestSessionGuardReconcileArm(
    const QString &operation, const QString &session, const QString &policyHashHex,
    const QString &expectedRuntimeSessionId)
{
    if (m_pendingGuardRequest.isEmpty()
            || m_pendingGuardRequest.value(QStringLiteral("operation")).toString() != operation
            || m_pendingGuardRequest.value(QStringLiteral("session")).toString() != session
            || m_pendingGuardRequest.value(QStringLiteral("policy_sha256")).toString()
                   != policyHashHex
            || m_pendingGuardRequest.value(QStringLiteral("expected_runtime_session_id"))
                   .toString() != expectedRuntimeSessionId) return false;
    const QString outer = m_pendingGuardRequest.value(
        QStringLiteral("outer_session_id")).toString();
    if (!safeAsciiOpaque(outer)) return false;
    callActivityMethod("reconcileNativeSessionGuardArm",
                       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(operation).object<jstring>(),
                       QJniObject::fromString(session).object<jstring>(),
                       QJniObject::fromString(policyHashHex).object<jstring>(),
                       QJniObject::fromString(outer).object<jstring>(),
                       QJniObject::fromString(expectedRuntimeSessionId).object<jstring>());
    return true;
}

bool AndroidController::requestSessionGuardReconcileRelease(
    const QString &operation, const QString &session, const QString &policyHashHex,
    const QString &outerSessionId, const QString &expectedRuntimeSessionId)
{
    if (m_pendingGuardReleaseRequest.isEmpty()) return false;
    const QJsonObject &expected = m_pendingGuardReleaseRequest;
    if (expected.value(QStringLiteral("operation")).toString() != operation
            || expected.value(QStringLiteral("session")).toString() != session
            || expected.value(QStringLiteral("policy_sha256")).toString() != policyHashHex
            || expected.value(QStringLiteral("outer_session_id")).toString() != outerSessionId
            || expected.value(QStringLiteral("expected_runtime_session_id"))
                   .toString() != expectedRuntimeSessionId) return false;
    callActivityMethod("reconcileNativeSessionGuardRelease",
                       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(operation).object<jstring>(),
                       QJniObject::fromString(session).object<jstring>(),
                       QJniObject::fromString(policyHashHex).object<jstring>(),
                       QJniObject::fromString(outerSessionId).object<jstring>(),
                       QJniObject::fromString(expectedRuntimeSessionId).object<jstring>());
    return true;
}

void AndroidController::requestSessionGuardRecoveryStatus()
{
    callActivityMethod("requestNativeSessionGuardRecoveryStatus", "()V");
}

bool AndroidController::requestSessionGuardRecoveryResolution(
    const QJsonObject &exactRecoveryEvent, const QString &action,
    const QJsonObject &validatedConfiguration)
{
    if (!m_guardRecoveryPending || m_guardRecoveryResolutionPending
            || exactRecoveryEvent != m_guardRecoveryEvent
            || (action != QLatin1String("adopt") && action != QLatin1String("stop"))
            || (action == QLatin1String("adopt") && validatedConfiguration.isEmpty())
            || (action == QLatin1String("stop") && !validatedConfiguration.isEmpty())) {
        return false;
    }
    const QByteArray event = QJsonDocument(exactRecoveryEvent).toJson(QJsonDocument::Compact);
    const QByteArray configuration = validatedConfiguration.isEmpty()
            ? QByteArray() : QJsonDocument(validatedConfiguration).toJson(QJsonDocument::Compact);
    m_guardRecoveryResolutionPending = true;
    m_guardRecoveryAction = action;
    callActivityMethod("resolveNativeSessionGuardRecovery",
                       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(QString::fromUtf8(event)).object<jstring>(),
                       QJniObject::fromString(action).object<jstring>(),
                       QJniObject::fromString(QString::fromUtf8(configuration)).object<jstring>());
    return true;
}

void AndroidController::stop()
{
    callActivityMethod("stop", "()V");
}

void AndroidController::resetLastServer(int serverIndex)
{
    callActivityMethod("resetLastServer", "(I)V", serverIndex);
}

void AndroidController::showUpdateCover()
{
    callActivityMethod("showUpdateCover", "()V");
}

void AndroidController::hideUpdateCover()
{
    callActivityMethod("hideUpdateCover", "()V");
}

void AndroidController::showUpdatePrompt(const QString &title, const QString &message, const QString &updateTitle,
                                        const QString &skipTitle, const QString &storeUrl)
{
    callActivityMethod("showUpdatePrompt",
                       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(title).object<jstring>(),
                       QJniObject::fromString(message).object<jstring>(),
                       QJniObject::fromString(updateTitle).object<jstring>(),
                       QJniObject::fromString(skipTitle).object<jstring>(),
                       QJniObject::fromString(storeUrl).object<jstring>());
}

void AndroidController::saveFile(const QString &fileName, const QString &data)
{
    callActivityMethod("saveFile", "(Ljava/lang/String;Ljava/lang/String;)V",
                       QJniObject::fromString(fileName).object<jstring>(),
                       QJniObject::fromString(data).object<jstring>());
}

QString AndroidController::openFile(const QString &filter)
{
    QEventLoop wait;
    QString fileName;
    connect(this, &AndroidController::fileOpened, this,
            [&fileName, &wait](const QString &uri) {
                fileName = uri;
                wait.quit();
            },
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::SingleShotConnection));
    callActivityMethod("openFile", "(Ljava/lang/String;)V",
                       QJniObject::fromString(filter).object<jstring>());
    wait.exec();
    return fileName;
}

int AndroidController::getFd(const QString &fileName)
{
    return callActivityMethod<jint>("getFd", "(Ljava/lang/String;)I",
                                    QJniObject::fromString(fileName).object<jstring>());
}

void AndroidController::closeFd()
{
    callActivityMethod("closeFd", "()V");
}

QString AndroidController::getFileName(const QString &uri)
{
    auto fileName = callActivityMethod<jstring, jstring>("getFileName", "(Ljava/lang/String;)Ljava/lang/String;",
                                                         QJniObject::fromString(uri).object<jstring>());
    QJniEnvironment env;
    return AndroidUtils::convertJString(env.jniEnv(), fileName.object<jstring>());
}

bool AndroidController::isCameraPresent()
{
    return callActivityMethod<jboolean>("isCameraPresent", "()Z");
}

bool AndroidController::isOnTv()
{
    return callActivityMethod<jboolean>("isOnTv", "()Z");
}

bool AndroidController::isEdgeToEdgeEnabled()
{
    return callActivityMethod<jboolean>("isEdgeToEdgeEnabled", "()Z");
}

int AndroidController::getStatusBarHeight()
{
    return callActivityMethod<jint>("getStatusBarHeight", "()I");
}

int AndroidController::getNavigationBarHeight()
{
    return callActivityMethod<jint>("getNavigationBarHeight", "()I");
}

void AndroidController::startQrReaderActivity()
{
    callActivityMethod("startQrCodeReader", "()V");
}

void AndroidController::setSaveLogs(bool enabled)
{
    callActivityMethod("setSaveLogs", "(Z)V", enabled);
}

void AndroidController::exportLogsFile(const QString &fileName)
{
    callActivityMethod("exportLogsFile", "(Ljava/lang/String;)V",
                       QJniObject::fromString(fileName).object<jstring>());
}

void AndroidController::clearLogs()
{
    callActivityMethod("clearLogs", "()V");
}

void AndroidController::setScreenshotsEnabled(bool enabled)
{
    callActivityMethod("setScreenshotsEnabled", "(Z)V", enabled);
}

void AndroidController::setNavigationBarColor(unsigned int color)
{
    callActivityMethod("setNavigationBarColor", "(I)V", color);
}

void AndroidController::minimizeApp()
{
    callActivityMethod("minimizeApp", "()V");
}

QJsonArray AndroidController::getAppList()
{
    QJniObject appList = callActivityMethod<jstring>("getAppList", "()Ljava/lang/String;");
    QJsonArray jsonAppList = QJsonDocument::fromJson(appList.toString().toUtf8()).array();
    return jsonAppList;
}

QPixmap AndroidController::getAppIcon(const QString &package, QSize *size, const QSize &requestedSize)
{
    QJniObject bitmap = callActivityMethod<jobject>("getAppIcon", "(Ljava/lang/String;II)Landroid/graphics/Bitmap;",
                                                    QJniObject::fromString(package).object<jstring>(),
                                                    requestedSize.width(), requestedSize.height());

    QJniEnvironment env;
    AndroidBitmapInfo info;
    if (AndroidBitmap_getInfo(env.jniEnv(), bitmap.object(), &info) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    void *pixels;
    if (AndroidBitmap_lockPixels(env.jniEnv(), bitmap.object(), &pixels) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    int width = info.width;
    int height = info.height;

    size->setWidth(width);
    size->setHeight(height);

    QImage image(width, height, QImage::Format_RGBA8888);
    if (info.stride == uint32_t(image.bytesPerLine())) {
        memcpy((void *) image.constBits(), pixels, info.stride * height);
    } else {
        auto *bmpPtr = static_cast<uchar *>(pixels);
        for (int i = 0; i < height; i++, bmpPtr += info.stride)
            memcpy((void *) image.constScanLine(i), bmpPtr, width);
    }

    if (AndroidBitmap_unlockPixels(env.jniEnv(), bitmap.object()) != ANDROID_BITMAP_RESULT_SUCCESS) return {};

    return QPixmap::fromImage(image);
}

bool AndroidController::isNotificationPermissionGranted()
{
    return callActivityMethod<jboolean>("isNotificationPermissionGranted", "()Z");
}

void AndroidController::requestNotificationPermission()
{
    callActivityMethod("requestNotificationPermission", "()V");
}

bool AndroidController::requestAuthentication()
{
    QEventLoop wait;
    bool result;
    connect(this, &AndroidController::authenticationResult, this,
            [&result, &wait](const bool &authResult){
                qDebug() << "Android authentication result:" << authResult;
                result = authResult;
                wait.quit();
            },
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::SingleShotConnection));
    callActivityMethod("requestAuthentication", "()V");
    wait.exec();
    return result;
}

void AndroidController::sendTouch(float x, float y)
{
    callActivityMethod("sendTouch", "(FF)V", x, y);
}

// Moving log processing to the Android side
jclass AndroidController::log;
jmethodID AndroidController::logDebug;
jmethodID AndroidController::logInfo;
jmethodID AndroidController::logWarning;
jmethodID AndroidController::logError;
jmethodID AndroidController::logFatal;

// static
bool AndroidController::initLogging()
{
    QJniEnvironment env;

    log = env.findClass(ANDROID_LOG_CLASS);
    if (log == nullptr) {
        qCritical() << "Android log class" << ANDROID_LOG_CLASS << "not found";
        return false;
    }

    auto logMethodSignature = "(Ljava/lang/String;Ljava/lang/String;)V";

    logDebug = env.findStaticMethod(log, "d", logMethodSignature);
    if (logDebug == nullptr) {
        qCritical() << "Android debug log method not found";
        return false;
    }

    logInfo = env.findStaticMethod(log, "i", logMethodSignature);
    if (logInfo == nullptr) {
        qCritical() << "Android info log method not found";
        return false;
    }

    logWarning = env.findStaticMethod(log, "w", logMethodSignature);
    if (logWarning == nullptr) {
        qCritical() << "Android warning log method not found";
        return false;
    }

    logError = env.findStaticMethod(log, "e", logMethodSignature);
    if (logError == nullptr) {
        qCritical() << "Android error log method not found";
        return false;
    }

    logFatal = env.findStaticMethod(log, "f", logMethodSignature);
    if (logFatal == nullptr) {
        qCritical() << "Android fatal log method not found";
        return false;
    }

    qInstallMessageHandler(messageHandler);
    return true;
}

// static
void AndroidController::messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
    jmethodID logMethod = logDebug;
    switch (type) {
        case QtDebugMsg:
            logMethod = logDebug;
            break;
        case QtInfoMsg:
            logMethod = logInfo;
            break;
        case QtWarningMsg:
            logMethod = logWarning;
            break;
        case QtCriticalMsg:
            logMethod = logError;
            break;
        case QtFatalMsg:
            logMethod = logFatal;
            break;
    }
    QString formattedMessage = qFormatLogMessage(type, context, message);
    QJniObject::callStaticMethod<void>(log, logMethod,
                                       QJniObject::fromString(TAG).object<jstring>(),
                                       QJniObject::fromString(formattedMessage).object<jstring>());
}

void AndroidController::qtAndroidControllerInitialized()
{
    callActivityMethod("qtAndroidControllerInitialized", "()V");
}

// static
Vpn::ConnectionState AndroidController::convertState(AndroidController::ConnectionState state)
{
    switch (state) {
        case AndroidController::ConnectionState::CONNECTED: return Vpn::ConnectionState::Connected;
        case AndroidController::ConnectionState::CONNECTING: return Vpn::ConnectionState::Connecting;
        case AndroidController::ConnectionState::DISCONNECTED: return Vpn::ConnectionState::Disconnected;
        case AndroidController::ConnectionState::DISCONNECTING: return Vpn::ConnectionState::Disconnecting;
        case AndroidController::ConnectionState::RECONNECTING: return Vpn::ConnectionState::Reconnecting;
        case AndroidController::ConnectionState::UNKNOWN: return Vpn::ConnectionState::Unknown;
    }
}

// static
QString AndroidController::textConnectionState(AndroidController::ConnectionState state)
{
    switch (state) {
        case AndroidController::ConnectionState::CONNECTED: return "CONNECTED";
        case AndroidController::ConnectionState::CONNECTING: return "CONNECTING";
        case AndroidController::ConnectionState::DISCONNECTED: return "DISCONNECTED";
        case AndroidController::ConnectionState::DISCONNECTING: return "DISCONNECTING";
        case AndroidController::ConnectionState::RECONNECTING: return "RECONNECTING";
        case AndroidController::ConnectionState::UNKNOWN: return "UNKNOWN";
    }
}

// JNI functions called by Android
// static
void AndroidController::onStatus(JNIEnv *env, jobject thiz, jint stateCode)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    auto state = ConnectionState(stateCode);

    emit AndroidController::instance()->status(state);
}

// static
void AndroidController::onServiceDisconnected(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    AndroidController *controller = AndroidController::instance();
    if (!controller->m_pendingAuthorityRenewalRequest.isEmpty()) {
        const QJsonObject receipt = rejectedRenewalReceipt(
            controller->m_pendingAuthorityRenewalRequest,
            QStringLiteral("service_channel_lost"));
        controller->m_pendingAuthorityRenewalRequest = {};
        emit controller->runtimeAuthorityRenewalReceipt(receipt);
    }
    controller->publishGuardChannelLoss();
    controller->m_runtimeStatus = {};
    controller->m_runtimeSessionId.clear();
    controller->m_runtimeServiceEpoch.clear();
    controller->m_runtimeSessionGeneration = 0;
    controller->m_runtimeCounterEpoch.clear();
    controller->m_runtimeHasRawCounters = false;
    controller->m_runtimeStopping = false;
    controller->m_runtimeTerminal = false;
    if (!controller->m_guardRecoveryPending)
        controller->m_expectedCatalogRuntimeSessionId.clear();
    emit controller->serviceDisconnected();
}

void AndroidController::publishGuardChannelLoss()
{
    QJsonObject event;
    if (!m_armedGuardReceipt.isEmpty()) {
        event = m_armedGuardReceipt;
        event.insert(QStringLiteral("kind"), QStringLiteral("lost"));
        event.insert(QStringLiteral("reason"), QStringLiteral("service_channel_lost"));
    } else if (!m_pendingGuardRequest.isEmpty()) {
        event = m_pendingGuardRequest;
    }
    m_pendingGuardRequest = {};
    m_armedGuardReceipt = {};
    m_pendingGuardReleaseRequest = {};
    if (!event.isEmpty()) {
        m_guardRecoveryPending = true;
        m_guardRecoveryEvent = event;
        emit sessionGuardEvent(event);
        emit sessionGuardRecoveryRequired(event);
    }
}

// static
void AndroidController::onServiceError(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->serviceError();
}

// static
void AndroidController::onVpnPermissionRejected(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->vpnPermissionRejected();
}

// static
void AndroidController::onNotificationStateChanged(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->notificationStateChanged();
}

// static
void AndroidController::onVpnStateChanged(JNIEnv *env, jobject thiz, jint stateCode)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    auto state = ConnectionState(stateCode);

    emit AndroidController::instance()->vpnStateChanged(state);
}

// static
void AndroidController::onStatisticsUpdate(JNIEnv *env, jobject thiz, jlong rxBytes, jlong txBytes,
                                           jlong lastHandshakeSec)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->statisticsUpdated((quint64) rxBytes, (quint64) txBytes);
    // AVPN: возраст хендшейка наружу (<=0 → 0 «неизвестно») — serviceEngine HealthLoop DEAD-детект.
    emit AndroidController::instance()->handshakeUpdated(lastHandshakeSec > 0 ? (qint64) lastHandshakeSec : 0);
}

// static
void AndroidController::onRuntimeStatus(JNIEnv *env, jobject thiz, jstring json)
{
    Q_UNUSED(thiz);
    const QJsonDocument document = QJsonDocument::fromJson(
            AndroidUtils::convertJString(env, json).toUtf8());
    const QJsonObject status = document.object();
    const QJsonObject core = status.value(QStringLiteral("core")).toObject();
    const QJsonObject counters = status.value(QStringLiteral("counters")).toObject();
    const QString protocol = status.value(QStringLiteral("protocol")).toString();
    const QString runtimeState = status.value(QStringLiteral("runtime_state")).toString();
    const QString adapter = core.value(QStringLiteral("adapter")).toString();
    const QString abi = core.value(QStringLiteral("abi")).toString();
    const QString coreVersion = core.value(QStringLiteral("version")).toString();
    const QString counterEpoch = counters.value(QStringLiteral("epoch")).toString();
    const QString sessionId = status.value(QStringLiteral("session_id")).toString();
    AndroidController *controller = AndroidController::instance();
    const QUuid directRuntimeUuid(sessionId);
    const bool catalogV2Session = !directRuntimeUuid.isNull()
            && directRuntimeUuid.toString(QUuid::WithoutBraces).toLower() == sessionId;
    const QStringList sessionParts = sessionId.split(QLatin1Char(':'));
    const QString serviceEpoch = !catalogV2Session && sessionParts.size() == 2
            ? sessionParts.at(0) : QString();
    bool legacyGenerationOk = false;
    const quint64 sessionGeneration = !catalogV2Session && sessionParts.size() == 2
            ? jsonUint64(QJsonValue(sessionParts.at(1)), &legacyGenerationOk) : 0;
    const QUuid epochUuid(serviceEpoch);
    const bool legacySession = legacyGenerationOk && sessionGeneration > 0
            && !epochUuid.isNull()
            && epochUuid.toString(QUuid::WithoutBraces).toLower() == serviceEpoch;
    // V2 is accepted only against the reducer-issued PREPARE identity. A callback cannot teach
    // this value, so a delayed N-2 status can never capture the replacement session.
    const bool sessionOk = catalogV2Session
            ? !controller->m_expectedCatalogRuntimeSessionId.isEmpty()
                  && sessionId == controller->m_expectedCatalogRuntimeSessionId
            : legacySession && controller->m_expectedCatalogRuntimeSessionId.isEmpty();
    bool counterFieldsValid = true;
    for (const char *field : {"rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                              "rx_bytes_delta", "tx_bytes_delta", "rx_packets_delta",
                              "tx_packets_delta", "reset_count"}) {
        bool fieldOk = false;
        jsonUint64(counters.value(QLatin1String(field)), &fieldOk);
        counterFieldsValid = counterFieldsValid && fieldOk;
    }

    const bool stateValid = runtimeState == QLatin1String("starting")
            || runtimeState == QLatin1String("running")
            || runtimeState == QLatin1String("stopping")
            || runtimeState == QLatin1String("stopped")
            || runtimeState == QLatin1String("reconnecting")
            || runtimeState == QLatin1String("failed")
            || runtimeState == QLatin1String("unknown");
    const bool engineValid = (protocol == QLatin1String("awg")
                              && adapter == QLatin1String("awg-android")
                              && abi == QLatin1String(
                                      "awg-android-jni-uapi-v3.1-protected-start.1"))
            || (protocol == QLatin1String("xray")
                && adapter == QLatin1String("amnezia-libxray")
                && abi == QLatin1String("gomobile-libxray-v2-controller-slot"));
    const bool valid = document.isObject()
            && status.value(QStringLiteral("type")).toString()
                   == QLatin1String("tunnel_runtime_status_v1")
            && schemaOne(status.value(QStringLiteral("schema")))
            && sessionOk
            && counterFieldsValid
            && stateValid && engineValid
            && !coreVersion.isEmpty() && !counterEpoch.isEmpty()
            && status.value(QStringLiteral("core")).isObject()
            && status.value(QStringLiteral("counters")).isObject();
    if (!valid) {
        qWarning() << "Rejected incompatible Android tunnel runtime status";
        return;
    }

    if (!catalogV2Session && !controller->m_runtimeServiceEpoch.isEmpty()
            && serviceEpoch != controller->m_runtimeServiceEpoch) {
        qWarning() << "Discarded Android runtime status from a different service epoch";
        return;
    }
    if (!catalogV2Session && serviceEpoch == controller->m_runtimeServiceEpoch
            && sessionGeneration < controller->m_runtimeSessionGeneration) {
        qWarning() << "Discarded stale Android tunnel runtime session" << sessionId;
        return;
    }
    const bool newSession = catalogV2Session
            ? controller->m_runtimeSessionId != sessionId
            : controller->m_runtimeServiceEpoch.isEmpty()
                  || sessionGeneration > controller->m_runtimeSessionGeneration;
    if (newSession) {
        controller->m_runtimeSessionId = sessionId;
        controller->m_runtimeServiceEpoch = catalogV2Session ? QString() : serviceEpoch;
        controller->m_runtimeSessionGeneration = sessionGeneration;
        controller->m_runtimeCounterEpoch.clear();
        controller->m_runtimeRawRx = 0;
        controller->m_runtimeRawTx = 0;
        controller->m_runtimeNormalizedRx = 0;
        controller->m_runtimeNormalizedTx = 0;
        controller->m_runtimeHasRawCounters = false;
        controller->m_runtimeStopping = false;
        controller->m_runtimeTerminal = false;
    }

    // Messenger delivery is ordered, but native teardown may leave already
    // queued callbacks.  Once stopping/terminal is observed, do not let an old
    // running callback resurrect the same session.
    if (controller->m_runtimeTerminal
            || (controller->m_runtimeStopping
                && (runtimeState == QLatin1String("starting")
                    || runtimeState == QLatin1String("running")
                    || runtimeState == QLatin1String("reconnecting")))) {
        qWarning() << "Discarded stale Android runtime callback for session" << sessionId;
        return;
    }
    if (runtimeState == QLatin1String("stopping"))
        controller->m_runtimeStopping = true;
    if (runtimeState == QLatin1String("stopped") || runtimeState == QLatin1String("failed"))
        controller->m_runtimeTerminal = true;

    controller->m_runtimeStatus = status;
    emit controller->runtimeStatusChanged(status);

    if (runtimeState == QLatin1String("running")) {
        emit controller->vpnStateChanged(ConnectionState::CONNECTED);
    } else if (runtimeState == QLatin1String("starting")) {
        emit controller->vpnStateChanged(ConnectionState::CONNECTING);
    } else if (runtimeState == QLatin1String("reconnecting")) {
        emit controller->vpnStateChanged(ConnectionState::RECONNECTING);
    } else if (runtimeState == QLatin1String("stopping")) {
        emit controller->vpnStateChanged(ConnectionState::DISCONNECTING);
    } else if (runtimeState == QLatin1String("stopped")) {
        emit controller->vpnStateChanged(ConnectionState::DISCONNECTED);
    } else if (runtimeState == QLatin1String("failed")) {
        emit controller->serviceError();
    }

    // Availability and runtime state are separate facts.  Zero counters are a
    // valid idle sample; unavailable counters simply produce no byte update.
    if (counters.value(QStringLiteral("available")).toBool(false)) {
        bool rxOk = false;
        bool txOk = false;
        const quint64 rawRx = jsonUint64(counters.value(QStringLiteral("rx_bytes")), &rxOk);
        const quint64 rawTx = jsonUint64(counters.value(QStringLiteral("tx_bytes")), &txOk);
        if (rxOk && txOk) {
            if (controller->m_runtimeCounterEpoch != counterEpoch) {
                controller->m_runtimeCounterEpoch = counterEpoch;
                controller->m_runtimeHasRawCounters = false;
            }
            if (controller->m_runtimeHasRawCounters) {
                const quint64 rxDelta = rawRx >= controller->m_runtimeRawRx
                        ? rawRx - controller->m_runtimeRawRx : 0;
                const quint64 txDelta = rawTx >= controller->m_runtimeRawTx
                        ? rawTx - controller->m_runtimeRawTx : 0;
                controller->m_runtimeNormalizedRx = saturatingAdd(
                        controller->m_runtimeNormalizedRx, rxDelta);
                controller->m_runtimeNormalizedTx = saturatingAdd(
                        controller->m_runtimeNormalizedTx, txDelta);
            }
            controller->m_runtimeRawRx = rawRx;
            controller->m_runtimeRawTx = rawTx;
            controller->m_runtimeHasRawCounters = true;
            emit controller->statisticsUpdated(controller->m_runtimeNormalizedRx,
                                               controller->m_runtimeNormalizedTx);
        }
    }

    if (protocol == QLatin1String("awg")) {
        bool handshakeOk = false;
        const quint64 handshake = jsonUint64(
                status.value(QStringLiteral("last_handshake_time_sec")), &handshakeOk);
        emit controller->handshakeUpdated(handshakeOk ? static_cast<qint64>(handshake) : 0);
    }
}

// static
void AndroidController::onEngineManifest(JNIEnv *env, jobject thiz, jstring json)
{
    Q_UNUSED(thiz);
    const QJsonDocument document = QJsonDocument::fromJson(
        AndroidUtils::convertJString(env, json).toUtf8());
    const QJsonObject manifest = document.object();
    const QJsonArray engines = manifest.value(QStringLiteral("engines")).toArray();
    const QJsonObject app = manifest.value(QStringLiteral("app")).toObject();
    bool hasAwg = false;
    bool hasXray = false;
    for (const QJsonValue &value : engines) {
        const QJsonObject engine = value.toObject();
        const QJsonArray caps = engine.value(QStringLiteral("capabilities")).toArray();
        const QString protocol = engine.value(QStringLiteral("protocol")).toString();
        if (protocol == QLatin1String("awg")) {
            hasAwg = caps.contains(QStringLiteral("awg.random_trailers"))
                    && caps.contains(QStringLiteral("awg.disable_cookies"))
                    && caps.contains(QStringLiteral("tribe.guarded_settings_owner"))
                    && engine.value(QStringLiteral("abi")).toString()
                           == QLatin1String(
                                   "awg-android-jni-uapi-v3.1-protected-start.1");
        } else if (protocol == QLatin1String("xray")) {
            hasXray = caps.contains(QStringLiteral("xray.vless.reality.vision.tcp"))
                    && caps.contains(QStringLiteral("xray.socket_protection_slot"))
                    && caps.contains(QStringLiteral("tribe.guarded_settings_owner"))
                    && engine.value(QStringLiteral("abi")).toString()
                           == QLatin1String("gomobile-libxray-v2-controller-slot");
        }
    }
    const bool valid = document.isObject()
            && manifest.value(QStringLiteral("type")).toString()
                   == QLatin1String("engine_manifest_v1")
            && schemaOne(manifest.value(QStringLiteral("schema")))
            && !app.value(QStringLiteral("version")).toString().isEmpty()
            && positiveJsonInteger(app.value(QStringLiteral("build")))
            && engines.size() == 2 && hasAwg && hasXray;
    QMetaObject::invokeMethod(AndroidController::instance(), [manifest, valid]() {
        AndroidController *controller = AndroidController::instance();
        controller->m_engineManifest = valid ? manifest : QJsonObject();
        if (!valid) {
            qWarning() << "Rejected invalid Android engine manifest";
        }
        emit controller->engineManifestChanged(controller->m_engineManifest);
    }, Qt::QueuedConnection);
}

// static
void AndroidController::onSessionGuardEvent(JNIEnv *env, jobject thiz, jstring json)
{
    Q_UNUSED(thiz);
    const QJsonDocument document = QJsonDocument::fromJson(
        AndroidUtils::convertJString(env, json).toUtf8());
    const QJsonObject event = document.object();
    const QString operation = event.value(QStringLiteral("operation")).toString();
    const QString session = event.value(QStringLiteral("session")).toString();
    const QString kind = event.value(QStringLiteral("kind")).toString();
    const QString policy = event.value(QStringLiteral("policy_sha256")).toString();
    const QString outer = event.value(QStringLiteral("outer_session_id")).toString();
    const QString runtime = event.value(
        QStringLiteral("expected_runtime_session_id")).toString();
    const QString reason = event.value(QStringLiteral("reason")).toString();
    static const QSet<QString> exactKeys = {
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("operation"),
        QStringLiteral("session"), QStringLiteral("kind"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason"),
    };
    bool operationOk = false;
    bool sessionOk = false;
    const quint64 operationValue = jsonUint64(operation, &operationOk);
    const quint64 sessionValue = jsonUint64(session, &sessionOk);
    const QUuid runtimeUuid(runtime);
    const bool runtimeCanonical = !runtimeUuid.isNull()
            && runtimeUuid.toString(QUuid::WithoutBraces).toLower() == runtime;
    bool policyCanonical = policy.size() == 64;
    for (const QChar c : policy)
        policyCanonical = policyCanonical
                && ((c >= QLatin1Char('0') && c <= QLatin1Char('9'))
                    || (c >= QLatin1Char('a') && c <= QLatin1Char('f')));
    bool reasonSafe = reason.size() <= 96;
    for (const QChar c : reason)
        reasonSafe = reasonSafe && c.unicode() >= 0x20 && c.unicode() <= 0x7e;
    const bool ownerRequired = kind == QLatin1String("armed")
            || kind == QLatin1String("released") || kind == QLatin1String("lost");
    const bool valid = document.isObject()
            && [&event]() {
                const QStringList eventKeys = event.keys();
                return QSet<QString>(eventKeys.cbegin(), eventKeys.cend()) == exactKeys;
            }()
            && event.value(QStringLiteral("type")) == QLatin1String("native_session_guard_v1")
            && schemaOne(event.value(QStringLiteral("schema")))
            && operationOk && sessionOk && operationValue != 0 && sessionValue != 0
            && (kind == QLatin1String("armed") || kind == QLatin1String("arm_rejected")
                || kind == QLatin1String("released") || kind == QLatin1String("release_rejected")
                || kind == QLatin1String("lost"))
            && policyCanonical && runtimeCanonical && reasonSafe
            && ((ownerRequired && safeAsciiOpaque(outer))
                || (!ownerRequired && (outer.isEmpty() || safeAsciiOpaque(outer))));
    if (!valid) return;
    QMetaObject::invokeMethod(AndroidController::instance(), [event]() {
        AndroidController *controller = AndroidController::instance();
        const QString kind = event.value(QStringLiteral("kind")).toString();
        const QString runtime = event.value(
            QStringLiteral("expected_runtime_session_id")).toString();
        const auto sameIdentity = [&event](const QJsonObject &expected,
                                           bool requireOuter) {
            if (expected.isEmpty()) return false;
            for (const char *key : {"operation", "session", "policy_sha256",
                                    "expected_runtime_session_id"}) {
                if (expected.value(QLatin1String(key))
                        != event.value(QLatin1String(key))) return false;
            }
            return !requireOuter
                    || expected.value(QStringLiteral("outer_session_id"))
                           == event.value(QStringLiteral("outer_session_id"));
        };
        if (kind == QLatin1String("lost")) {
            const bool pendingLoss = sameIdentity(controller->m_pendingGuardRequest, true);
            const bool armedLoss = sameIdentity(controller->m_armedGuardReceipt, true);
            if (!pendingLoss && !armedLoss) return;
            if (pendingLoss) controller->m_pendingGuardRequest = {};
            if (armedLoss) {
                controller->m_armedGuardReceipt = {};
                controller->m_pendingGuardReleaseRequest = {};
            }
            controller->m_guardRecoveryPending = true;
            controller->m_guardRecoveryEvent = event;
            emit controller->sessionGuardEvent(event);
            emit controller->sessionGuardRecoveryRequired(event);
            return;
        }
        if ((kind == QLatin1String("armed") || kind == QLatin1String("arm_rejected"))
                && sameIdentity(controller->m_pendingGuardRequest,
                                kind == QLatin1String("armed"))) {
            controller->m_pendingGuardRequest = {};
            if (kind == QLatin1String("armed")) {
                controller->m_armedGuardReceipt = event;
            } else if (controller->m_expectedCatalogRuntimeSessionId == runtime) {
                controller->m_expectedCatalogRuntimeSessionId.clear();
            }
        } else if ((kind == QLatin1String("released")
                    || kind == QLatin1String("release_rejected"))
                   && sameIdentity(controller->m_pendingGuardReleaseRequest, true)
                   && sameIdentity(controller->m_armedGuardReceipt, true)) {
            controller->m_pendingGuardReleaseRequest = {};
            if (kind == QLatin1String("released")) {
                controller->m_armedGuardReceipt = {};
                if (controller->m_expectedCatalogRuntimeSessionId == runtime)
                    controller->m_expectedCatalogRuntimeSessionId.clear();
            }
        } else {
            // A syntactically valid stale/mismatched receipt is not authority to mutate or notify.
            return;
        }
        emit controller->sessionGuardEvent(event);
    }, Qt::QueuedConnection);
}

// static
void AndroidController::onSessionGuardRecoveryReceipt(JNIEnv *env, jobject thiz, jstring json)
{
    Q_UNUSED(thiz);
    const QJsonDocument document = QJsonDocument::fromJson(
        AndroidUtils::convertJString(env, json).toUtf8());
    const QJsonObject receipt = document.object();
    if (!document.isObject() || !strictRecoveryReceipt(receipt)) return;
    QMetaObject::invokeMethod(AndroidController::instance(), [receipt]() {
        AndroidController *controller = AndroidController::instance();
        if (!controller->m_guardRecoveryPending
                || !controller->m_guardRecoveryResolutionPending
                || receipt.value(QStringLiteral("action")).toString()
                    != controller->m_guardRecoveryAction) return;
        const QJsonObject expected = controller->m_guardRecoveryEvent;
        const auto matches = [&receipt, &expected](const char *key) {
            return receipt.value(QLatin1String(key)) == expected.value(QLatin1String(key));
        };
        if (!matches("operation") || !matches("session") || !matches("policy_sha256")
                || !matches("outer_session_id")
                || !matches("expected_runtime_session_id")) return;
        controller->m_guardRecoveryResolutionPending = false;
        controller->m_guardRecoveryAction.clear();
        const QString kind = receipt.value(QStringLiteral("kind")).toString();
        if (kind == QLatin1String("adopted")) {
            QJsonObject armed = expected;
            armed.insert(QStringLiteral("kind"), QStringLiteral("armed"));
            armed.insert(QStringLiteral("reason"), QString());
            controller->m_armedGuardReceipt = armed;
            controller->m_expectedCatalogRuntimeSessionId = receipt.value(
                QStringLiteral("expected_runtime_session_id")).toString();
            controller->m_guardRecoveryPending = false;
            controller->m_guardRecoveryEvent = {};
        } else if (kind == QLatin1String("stopped_released")) {
            controller->m_pendingGuardRequest = {};
            controller->m_armedGuardReceipt = {};
            controller->m_pendingGuardReleaseRequest = {};
            controller->m_expectedCatalogRuntimeSessionId.clear();
            controller->m_guardRecoveryPending = false;
            controller->m_guardRecoveryEvent = {};
        }
        emit controller->sessionGuardRecoveryResolved(receipt);
    }, Qt::QueuedConnection);
}

// static
void AndroidController::onRuntimeAuthorityRenewalReceipt(JNIEnv *env, jobject thiz, jstring json)
{
    Q_UNUSED(thiz);
    const QJsonDocument document = QJsonDocument::fromJson(
        AndroidUtils::convertJString(env, json).toUtf8());
    const QJsonObject receipt = document.object();
    if (!document.isObject() || !strictAuthorityRenewalReceipt(receipt)) return;
    QMetaObject::invokeMethod(AndroidController::instance(), [receipt]() {
        AndroidController *controller = AndroidController::instance();
        if (controller->m_pendingAuthorityRenewalRequest.isEmpty()
            || !renewalReceiptMatches(receipt,
                                      controller->m_pendingAuthorityRenewalRequest)) return;
        controller->m_pendingAuthorityRenewalRequest = {};
        emit controller->runtimeAuthorityRenewalReceipt(receipt);
    }, Qt::QueuedConnection);
}

// static
void AndroidController::onFileOpened(JNIEnv *env, jobject thiz, jstring uri)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->fileOpened(AndroidUtils::convertJString(env, uri));
}

// static
void AndroidController::onConfigImported(JNIEnv *env, jobject thiz, jstring data)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->configImported(AndroidUtils::convertJString(env, data));
}

// static
void AndroidController::onAuthResult(JNIEnv *env, jobject thiz, jboolean result)
{
    Q_UNUSED(thiz);

    emit AndroidController::instance()->authenticationResult(result);
}

// static
bool AndroidController::decodeQrCode(JNIEnv *env, jobject thiz, jstring data)
{
    Q_UNUSED(thiz);

    return ImportUiController::decodeQrCode(AndroidUtils::convertJString(env, data));
}
// static
void AndroidController::onImeInsetsChanged(JNIEnv *env, jobject thiz, jint heightDp)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    qDebug() << "Android IME insets changed: height =" << heightDp << "dp";
    emit AndroidController::instance()->imeInsetsChanged(heightDp);
}

// static
void AndroidController::onSystemBarsInsetsChanged(JNIEnv *env, jobject thiz, jint navBarHeightDp, jint statusBarHeightDp)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    qDebug() << "Android system bars insets changed: nav bar =" << navBarHeightDp << "dp, status bar =" << statusBarHeightDp << "dp";
    emit AndroidController::instance()->systemBarsInsetsChanged(navBarHeightDp, statusBarHeightDp);
}

// static
void AndroidController::onActivityPaused(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->activityPaused();
}

// static
void AndroidController::onActivityResumed(JNIEnv *env, jobject thiz)
{
    Q_UNUSED(env);
    Q_UNUSED(thiz);

    emit AndroidController::instance()->activityResumed();
}
