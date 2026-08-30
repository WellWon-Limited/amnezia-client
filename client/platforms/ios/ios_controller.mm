#include "ios_controller.h"

#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QSet>
#include <QStringList>
#include <QThread>
#include <QUuid>
#include <QEventLoop>

#include <cerrno>
#include <cstdlib>
#include <limits>

#include "../core/protocols/vpnProtocol.h"
#import "ios_controller_wrapper.h"
#import <os/lock.h> // AVPN: os_unfair_lock — владение m_currentTunnel (ревью 2026-07-11)
#import "core/utils/swiftBridge.h"
#include "core/serviceEngine/TuningStore.h" // AVPN backend-first (Task 6): xray_* NE timeouts + network_change_debounce_ms
#include "version.h"

const char* Action::start = "start";
const char* Action::restart = "restart";
const char* Action::stop = "stop";
const char* Action::getTunnelId = "getTunnelId";
const char* Action::getStatus = "status";
const char* Action::rebind = "rebind"; // AVPN BUG-4 auto-heal

const char* MessageKey::action = "action";
const char* MessageKey::tunnelId = "tunnelId";
const char* MessageKey::config = "config";
const char* MessageKey::errorCode = "errorCode";
const char* MessageKey::host = "host";
const char* MessageKey::port = "port";
const char* MessageKey::isOnDemand = "is-on-demand";
const char* MessageKey::SplitTunnelType = "SplitTunnelType";
const char* MessageKey::SplitTunnelSites = "SplitTunnelSites";

using namespace ProtocolUtils;

#if !MACOS_NE
static UIViewController* getViewController() {
    UIApplication *application = [UIApplication sharedApplication];

    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in application.connectedScenes) {
            if (scene.activationState != UISceneActivationStateForegroundActive) {
                continue;
            }

            if (![scene isKindOfClass:[UIWindowScene class]]) {
                continue;
            }

            UIWindowScene *windowScene = (UIWindowScene *)scene;

            for (UIWindow *window in windowScene.windows) {
                if (window.isKeyWindow && window.rootViewController) {
                    return window.rootViewController;
                }
            }

            for (UIWindow *window in windowScene.windows) {
                if (!window.isHidden && window.rootViewController) {
                    return window.rootViewController;
                }
            }
        }
    }

    for (UIWindow *window in application.windows) {
        if (window.isKeyWindow && window.rootViewController) {
            return window.rootViewController;
        }
    }

    for (UIWindow *window in application.windows) {
        if (window.rootViewController) {
            return window.rootViewController;
        }
    }

    return nil;
}
#endif

Vpn::ConnectionState iosStatusToState(NEVPNStatus status) {
  switch (status) {
    case NEVPNStatusInvalid:
        return Vpn::ConnectionState::Unknown;
    case NEVPNStatusDisconnected:
        return Vpn::ConnectionState::Disconnected;
    case NEVPNStatusConnecting:
        return Vpn::ConnectionState::Connecting;
    case NEVPNStatusConnected:
        return Vpn::ConnectionState::Connected;
    case NEVPNStatusReasserting:
        return Vpn::ConnectionState::Connecting;
    case NEVPNStatusDisconnecting:
        return Vpn::ConnectionState::Disconnecting;
    default:
        return Vpn::ConnectionState::Unknown;
}
}

namespace {
constexpr int kHandshakeTimeoutMs = 12000;
constexpr uint64_t kHandshakeRxThreshold = 4096;
constexpr int kHandshakeMaxTimeouts = 3;   // AVPN: столько таймаутов без рукопожатия → Error + stop (нода недоступна).
                                           // NB (аудит N9): полный цикл 3×12с достижим только для OS-инициированных
                                           // стартов (App Intent/Настройки iOS); app-старт ограничен сторожем
                                           // reconcile-машины 15с (AvpnEngineQml m_watchdog) — это осознанно.
bool isWireGuardBasedProto(amnezia::Proto proto) {
    return proto == amnezia::Proto::WireGuard || proto == amnezia::Proto::Awg;
}

bool isXrayBasedProto(amnezia::Proto proto) {
    return proto == amnezia::Proto::Xray || proto == amnezia::Proto::SSXray;
}

// AVPN backend-first (T20): handshake-пороги из rawConfig (numbers.handshake_timeout_ms /
// numbers.handshake_max_timeouts, засеяны VpnConnectionTunnelControl::up), фолбэк — константы
// выше. Пусто/не число → фолбэк (byte-for-byte старое поведение).
int intFromRawConfig(const QJsonObject &cfg, const char *key, int fallback) {
    const QJsonValue v = cfg.value(QLatin1String(key));
    return v.isDouble() ? v.toInt(fallback) : fallback;
}

uint64_t uint64FromResponse(NSDictionary *response, NSString *key, uint64_t fallback = 0) {
    id value = response[key];
    if (!value || value == [NSNull null]) {
        return fallback;
    }
    if ([value isKindOfClass:[NSNumber class]]) {
        return [(NSNumber *)value unsignedLongLongValue];
    }
    if ([value isKindOfClass:[NSString class]]) {
        const char *str = [(NSString *)value UTF8String];
        if (str && *str) {
            return strtoull(str, nullptr, 10);
        }
    }
    return fallback;
}

bool canonicalUint64FromResponse(NSDictionary *response, NSString *key, uint64_t *result) {
    id value = response[key];
    if (![value isKindOfClass:[NSString class]]) {
        return false;
    }
    const char *str = [(NSString *)value UTF8String];
    if (!str || !*str || (str[0] == '0' && str[1] != '\0')) {
        return false;
    }
    for (const char *cursor = str; *cursor; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
    }
    errno = 0;
    char *end = nullptr;
    const unsigned long long parsed = strtoull(str, &end, 10);
    if (errno == ERANGE || !end || *end != '\0') {
        return false;
    }
    if (result) {
        *result = static_cast<uint64_t>(parsed);
    }
    return true;
}

bool canonicalTokenString(const QString &value)
{
    if (value.isEmpty() || value.size() > 20
        || (value.size() > 1 && value.startsWith(QLatin1Char('0')))) return false;
    bool ok = false;
    const quint64 parsed = value.toULongLong(&ok, 10);
    return ok && parsed > 0 && QString::number(parsed) == value;
}

bool canonicalRuntimeUuid(const QString &value)
{
    const QUuid uuid(value);
    return !uuid.isNull() && uuid.toString(QUuid::WithoutBraces).toLower() == value;
}

bool lowerSha256(const QString &value)
{
    if (value.size() != 64) return false;
    for (const QChar ch : value)
        if (!((ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
              || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f')))) return false;
    return true;
}

bool schemaOne(const QJsonValue &value)
{
    return value.isDouble() && value.toDouble() == 1.0;
}

bool objcSchemaOne(id value)
{
    return [value isKindOfClass:[NSNumber class]]
            && [(NSNumber *)value doubleValue] == 1.0;
}

bool safeGuardOpaque(const QString &value, bool allowEmpty = false)
{
    if (value.isEmpty()) return allowEmpty;
    if (value.size() > 200) return false;
    for (const QChar ch : value) {
        const ushort c = ch.unicode();
        const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        const bool digit = c >= '0' && c <= '9';
        if (!alpha && !digit && c != '-' && c != '_' && c != ':' && c != '.')
            return false;
    }
    return true;
}

bool safeAsciiReason(const QString &value)
{
    if (value.size() > 96) return false;
    for (const QChar ch : value)
        if (ch.unicode() < 0x20 || ch.unicode() > 0x7e) return false;
    return true;
}

bool strictNativeGuardEvent(NSDictionary *response, QJsonObject &event)
{
    event = {};
    if (![response isKindOfClass:[NSDictionary class]] || response.count != 9) return false;
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:response options:0 error:&error];
    if (!data || error) return false;
    const QByteArray bytes(reinterpret_cast<const char *>(data.bytes), data.length);
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) return false;
    const QJsonObject candidate = document.object();
    static const QSet<QString> exactKeys = {
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("operation"),
        QStringLiteral("session"), QStringLiteral("kind"), QStringLiteral("policy_sha256"),
        QStringLiteral("outer_session_id"), QStringLiteral("expected_runtime_session_id"),
        QStringLiteral("reason"),
    };
    const QStringList candidateKeys = candidate.keys();
    if (QSet<QString>(candidateKeys.cbegin(), candidateKeys.cend()) != exactKeys
        || candidate.value(QStringLiteral("type"))
             != QLatin1String("native_session_guard_v1")
        || !schemaOne(candidate.value(QStringLiteral("schema")))) return false;
    const QString operation = candidate.value(QStringLiteral("operation")).toString();
    const QString session = candidate.value(QStringLiteral("session")).toString();
    const QString kind = candidate.value(QStringLiteral("kind")).toString();
    const QString policy = candidate.value(QStringLiteral("policy_sha256")).toString();
    const QString outer = candidate.value(QStringLiteral("outer_session_id")).toString();
    const QString expected = candidate.value(
        QStringLiteral("expected_runtime_session_id")).toString();
    const QString reason = candidate.value(QStringLiteral("reason")).toString();
    const bool validKind = kind == QLatin1String("armed")
                           || kind == QLatin1String("arm_rejected")
                           || kind == QLatin1String("released")
                           || kind == QLatin1String("release_rejected")
                           || kind == QLatin1String("lost");
    const bool outerMayBeEmpty = kind == QLatin1String("arm_rejected");
    if (!canonicalTokenString(operation) || !canonicalTokenString(session) || !validKind
        || !lowerSha256(policy) || !canonicalRuntimeUuid(expected)
        || !safeGuardOpaque(outer, outerMayBeEmpty) || reason.size() > 96) return false;
    for (const QChar ch : reason)
        if (ch.unicode() < 0x20 || ch.unicode() > 0x7e) return false;
    event = candidate;
    return true;
}

bool strictNativeGuardRecoveryReceipt(NSDictionary *response, QJsonObject &receipt)
{
    receipt = {};
    if (![response isKindOfClass:[NSDictionary class]] || response.count != 10) return false;
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:response options:0 error:&error];
    if (!data || error) return false;
    const QByteArray bytes(reinterpret_cast<const char *>(data.bytes), data.length);
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) return false;
    const QJsonObject candidate = document.object();
    static const QSet<QString> exactKeys = {
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("action"),
        QStringLiteral("kind"), QStringLiteral("operation"), QStringLiteral("session"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason"),
    };
    const QStringList candidateKeys = candidate.keys();
    if (QSet<QString>(candidateKeys.cbegin(), candidateKeys.cend()) != exactKeys
        || candidate.value(QStringLiteral("type"))
             != QLatin1String("native_session_guard_recovery_v1")
        || !schemaOne(candidate.value(QStringLiteral("schema")))) return false;
    const QString action = candidate.value(QStringLiteral("action")).toString();
    const QString kind = candidate.value(QStringLiteral("kind")).toString();
    const bool validPair = (action == QLatin1String("adopt")
                            && (kind == QLatin1String("adopted")
                                || kind == QLatin1String("rejected")))
                           || (action == QLatin1String("stop")
                               && (kind == QLatin1String("stopped_released")
                                   || kind == QLatin1String("rejected")));
    const QString reason = candidate.value(QStringLiteral("reason")).toString();
    if (!validPair
        || !canonicalTokenString(candidate.value(QStringLiteral("operation")).toString())
        || !canonicalTokenString(candidate.value(QStringLiteral("session")).toString())
        || !lowerSha256(candidate.value(QStringLiteral("policy_sha256")).toString())
        || !safeGuardOpaque(candidate.value(QStringLiteral("outer_session_id")).toString())
        || !canonicalRuntimeUuid(candidate.value(
            QStringLiteral("expected_runtime_session_id")).toString())
        || reason.size() > 96) return false;
    for (const QChar ch : reason)
        if (ch.unicode() < 0x20 || ch.unicode() > 0x7e) return false;
    receipt = candidate;
    return true;
}

bool canonicalGeneration(const QString &value)
{
    if (value.isEmpty() || value.size() > 20
        || (value.size() > 1 && value.startsWith(QLatin1Char('0')))) return false;
    bool ok = false;
    const quint64 parsed = value.toULongLong(&ok, 10);
    return ok && QString::number(parsed) == value;
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
                            "catalog_freshness_deadline", "entitlement_deadline"}) {
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
                                  const QString &operation, const QString &session,
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
        || !safeGuardOpaque(outerSessionId) || !canonicalRuntimeUuid(expectedRuntimeSessionId)
        || !canonicalRuntimeUuid(renewalId) || !lowerSha256(policy)
        || !canonicalGeneration(configGeneration) || !canonicalGeneration(bindingGeneration)
        || !canonicalGeneration(revision) || !lowerSha256(payload)
        || !lowerSha256(authorityCommitmentHex)
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

bool strictAuthorityRenewalReceipt(NSDictionary *response, QJsonObject &receipt)
{
    receipt = {};
    if (![response isKindOfClass:[NSDictionary class]] || response.count != 16) return false;
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:response options:0 error:&error];
    if (!data || error) return false;
    const QByteArray bytes(reinterpret_cast<const char *>(data.bytes), data.length);
    const QJsonDocument document = QJsonDocument::fromJson(bytes);
    if (!document.isObject()) return false;
    const QJsonObject candidate = document.object();
    static const QSet<QString> exactKeys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("kind"),
        QStringLiteral("operation"), QStringLiteral("session"),
        QStringLiteral("renewal_id"), QStringLiteral("policy_sha256"),
        QStringLiteral("outer_session_id"), QStringLiteral("expected_runtime_session_id"),
        QStringLiteral("config_generation"), QStringLiteral("binding_generation"),
        QStringLiteral("catalog_revision"), QStringLiteral("catalog_payload_sha256"),
        QStringLiteral("authority_commitment_sha256"),
        QStringLiteral("hard_deadline"), QStringLiteral("reason"),
    };
    const QStringList keys = candidate.keys();
    const QString kind = candidate.value(QStringLiteral("kind")).toString();
    const QString deadline = candidate.value(QStringLiteral("hard_deadline")).toString();
    const QString reason = candidate.value(QStringLiteral("reason")).toString();
    if (QSet<QString>(keys.cbegin(), keys.cend()) != exactKeys
        || candidate.value(QStringLiteral("type"))
            != QLatin1String("runtime_authority_renewal_v1")
        || !schemaOne(candidate.value(QStringLiteral("schema")))
        || !canonicalTokenString(candidate.value(QStringLiteral("operation")).toString())
        || !canonicalTokenString(candidate.value(QStringLiteral("session")).toString())
        || !canonicalRuntimeUuid(candidate.value(QStringLiteral("renewal_id")).toString())
        || !lowerSha256(candidate.value(QStringLiteral("policy_sha256")).toString())
        || !safeGuardOpaque(candidate.value(QStringLiteral("outer_session_id")).toString())
        || !canonicalRuntimeUuid(candidate.value(
            QStringLiteral("expected_runtime_session_id")).toString())
        || !canonicalGeneration(candidate.value(
            QStringLiteral("config_generation")).toString())
        || !canonicalGeneration(candidate.value(
            QStringLiteral("binding_generation")).toString())
        || !canonicalGeneration(candidate.value(QStringLiteral("catalog_revision")).toString())
        || !lowerSha256(candidate.value(
            QStringLiteral("catalog_payload_sha256")).toString())
        || !lowerSha256(candidate.value(
            QStringLiteral("authority_commitment_sha256")).toString())
        || !safeAsciiReason(reason)
        || !((kind == QLatin1String("applied") && reason.isEmpty()
              && canonicalUtcMillis(deadline))
             || (kind == QLatin1String("rejected") && !reason.isEmpty()
                 && deadline.isEmpty()))) return false;
    receipt = candidate;
    return true;
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

long long int64FromResponse(NSDictionary *response, NSString *key, long long fallback = 0) {
    id value = response[key];
    if (!value || value == [NSNull null]) {
        return fallback;
    }
    if ([value isKindOfClass:[NSNumber class]]) {
        return [(NSNumber *)value longLongValue];
    }
    if ([value isKindOfClass:[NSString class]]) {
        const char *str = [(NSString *)value UTF8String];
        if (str && *str) {
            return strtoll(str, nullptr, 10);
        }
    }
    return fallback;
}
}

namespace {
IosController* s_instance = nullptr;
}

IosController::IosController() : QObject()
{
    s_instance = this;
    m_iosControllerWrapper = [[IosControllerWrapper alloc] initWithCppController:this];

    [[NSNotificationCenter defaultCenter]
        removeObserver: (__bridge NSObject *)m_iosControllerWrapper];
    [[NSNotificationCenter defaultCenter]
        addObserver: (__bridge NSObject *)m_iosControllerWrapper selector:@selector(vpnStatusDidChange:) name:NEVPNStatusDidChangeNotification object:nil];
    [[NSNotificationCenter defaultCenter]
        addObserver: (__bridge NSObject *)m_iosControllerWrapper selector:@selector(vpnConfigurationDidChange:) name:NEVPNConfigurationChangeNotification object:nil];

}

void IosController::emitConnectionStateIfChanged(Vpn::ConnectionState state)
{
    if (m_lastEmittedState == state) {
        return;
    }
    m_lastEmittedState = state;
    emit connectionStateChanged(state);
}

IosController* IosController::Instance() {
    if (!s_instance) {
        s_instance = new IosController();
    }

    return s_instance;
}

QJsonObject IosController::engineManifest() const
{
    auto compileOnlyEngine = [](const QString &protocol, const QString &adapter,
                                const QString &adapterVersion,
                                const QString &declaredCoreVersion,
                                const QString &sourceCommit, const QString &abi,
                                const QJsonArray &capabilities) {
        QJsonObject engine;
        engine.insert(QStringLiteral("protocol"), protocol);
        engine.insert(QStringLiteral("adapter"), adapter);
        engine.insert(QStringLiteral("adapterVersion"), adapterVersion);
        engine.insert(QStringLiteral("declaredCoreVersion"), declaredCoreVersion);
        engine.insert(QStringLiteral("sourceCommit"), sourceCommit);
        engine.insert(QStringLiteral("abi"), abi);
        engine.insert(QStringLiteral("capabilities"), capabilities);
        engine.insert(QStringLiteral("runtimeCoreVersion"), QJsonValue::Null);
        engine.insert(QStringLiteral("runtimeVersionProbed"), false);
        engine.insert(QStringLiteral("versionEvidence"),
                      QStringLiteral("compile_time_lock_only"));
        return engine;
    };
    const QJsonObject awg = compileOnlyEngine(
        QStringLiteral("awg"), QStringLiteral("awg-apple"),
        QStringLiteral(TRIBE_APPLE_AWG_ADAPTER_VERSION),
        QStringLiteral(TRIBE_APPLE_AWG_CORE_VERSION),
        QStringLiteral(TRIBE_APPLE_AWG_SOURCE_COMMIT),
        QStringLiteral("awg-apple-c-uapi-v3.1"),
        QJsonArray{QStringLiteral("awg.random_trailers"),
                   QStringLiteral("awg.disable_cookies"), QStringLiteral("uapi.readback"),
                   QStringLiteral("tribe.split_dns"), QStringLiteral("tribe.warmup"),
                   QStringLiteral("tribe.rebind"),
                   QStringLiteral("tribe.guarded_settings_owner")});
    const QJsonObject xray = compileOnlyEngine(
        QStringLiteral("xray"), QStringLiteral("amnezia-libxray"),
        QStringLiteral(TRIBE_APPLE_XRAY_ADAPTER_VERSION),
        QStringLiteral(TRIBE_APPLE_XRAY_CORE_VERSION),
        QStringLiteral(TRIBE_APPLE_XRAY_SOURCE_COMMIT),
        QStringLiteral(TRIBE_APPLE_XRAY_SOCKET_ABI),
        QJsonArray{QStringLiteral("xray.vless.reality.vision.tcp"),
                   QStringLiteral("xray.embedded"), QStringLiteral("xray.runtime_version"),
                   QStringLiteral("xray.socket_callback"),
                   QStringLiteral("xray.socket_protection_result"),
                   QStringLiteral("tribe.guarded_settings_owner")});
    return QJsonObject{
        {QStringLiteral("type"), QStringLiteral("engine_manifest_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("app"), QJsonObject{
            {QStringLiteral("version"), QStringLiteral(APP_VERSION)},
            {QStringLiteral("build"), APP_BUILD}}},
        {QStringLiteral("engines"), QJsonArray{awg, xray}}};
}

// AVPN (краш-фикс UAF, 2026-07-06): единственная точка владения m_currentTunnel. Без retain
// менеджер из autoreleased-массива loadAllFromPreferences жил только в кеше NE-фреймворка;
// после ночного фона кеш освобождался → m_checkTimer (QThread) → checkStatus →
// objc_msgSend(m_currentTunnel, 'connection') по трупу = SIGSEGV (AmneziaVPN-2026-07-06-091741.ips).
// AVPN (ревью 2026-07-11): владение m_currentTunnel — строго под локом. Гонка: checkStatus
// уходит на глобальную dispatch-очередь и читает менеджер с фонового треда, а быстрый реконнект
// (connectVpn → setCurrentTunnel(nil)) параллельно делает release на главном → UAF (тот же класс,
// что AmneziaVPN-2026-07-06-091741.ips). IosController — синглтон, статик-лок достаточен.
static os_unfair_lock s_tunnelOwnershipLock = OS_UNFAIR_LOCK_INIT;

void IosController::setCurrentTunnel(NETunnelProviderManager *tunnel)
{
    os_unfair_lock_lock(&s_tunnelOwnershipLock);
    if (tunnel == m_currentTunnel) {
        os_unfair_lock_unlock(&s_tunnelOwnershipLock);
        return;
    }
    NETunnelProviderManager *old = m_currentTunnel;
    [tunnel retain];
    m_currentTunnel = tunnel;
    os_unfair_lock_unlock(&s_tunnelOwnershipLock);
    [old release]; // release ВНЕ лока (dealloc может дёргать KVO/колбэки)
}

NETunnelProviderManager *IosController::retainedCurrentTunnel()
{
    os_unfair_lock_lock(&s_tunnelOwnershipLock);
    NETunnelProviderManager *t = [m_currentTunnel retain];
    os_unfair_lock_unlock(&s_tunnelOwnershipLock);
    return t; // caller обязан release
}

bool IosController::initialize()
{
    m_initializationResolved = false;
    m_guardRecoveryUnresolved = false;
    m_guardRecoveryResolutionPending = false;
    m_guardRecoveryEvent = {};
    __block bool ok = true;
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> * _Nullable managers, NSError * _Nullable error) {
        @try {
            if (error) {
                qWarning() << "IosController::initialize : loadAllFromPreferences failed:"
                           << [error.localizedDescription UTF8String]
                           << "domain:" << [error.domain UTF8String] << "code:" << error.code;
                ok = false;
                return;
            }

            NSInteger managerCount = managers.count;
            qDebug() << "IosController::initialize : We have received managers:" << (long)managerCount;


            for (NETunnelProviderManager *manager in managers) {
                qDebug() << "IosController::initialize : VPNC: " << manager.localizedDescription;

                if (manager.connection.status == NEVPNStatusConnected) {
                    setCurrentTunnel(manager); // AVPN: владеющее присвоение (retain)
                    qDebug() << "IosController::initialize : VPN already connected with" << manager.localizedDescription;
                    NETunnelProviderProtocol *provider =
                        (NETunnelProviderProtocol *)manager.protocolConfiguration;
                    if ([provider.providerConfiguration[@"guarded_inner_switch"] boolValue]) {
                        // A previous app process may have died while the NE still owns default
                        // routes. Block all new dispatch until product recovery reconciles this
                        // exact provider receipt against encrypted trusted state.
                        m_guardRecoveryUnresolved = true;
                        requestCurrentNativeGuardStatus();
                    }
                    emit connectionStateChanged(Vpn::ConnectionState::Connected);
                    break;

                    // TODO: show connected state
                }
            }
            m_initializationResolved = true;
            emit engineManifestChanged(engineManifest());
        }
        @catch (NSException *exception) {
            qDebug() << "IosController::setTunnel : exception" << QString::fromNSString(exception.reason);
            ok = false;
        }
    }];

    return ok;
}

bool IosController::ensureTunnelManager()
{
    NETunnelProviderManager *existing = retainedCurrentTunnel();
    if (existing) {
        [[NSNotificationCenter defaultCenter]
            removeObserver:(__bridge NSObject *)m_iosControllerWrapper];
        [[NSNotificationCenter defaultCenter]
            addObserver:(__bridge NSObject *)m_iosControllerWrapper
               selector:@selector(vpnStatusDidChange:)
                   name:NEVPNStatusDidChangeNotification
                 object:existing.connection];
        [existing release];
        return true;
    }
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block bool ok = true;
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(
        NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        @try {
            if (error) {
                ok = false;
            } else {
                for (NETunnelProviderManager *manager in managers) {
                    if (isOurManager(manager)) {
                        setCurrentTunnel(manager);
                        break;
                    }
                }
                if (!m_currentTunnel)
                    setCurrentTunnel([[[NETunnelProviderManager alloc] init] autorelease]);
                m_currentTunnel.localizedDescription = @"Tribe VPN";
            }
        } @catch (NSException *) {
            ok = false;
        } @finally {
            dispatch_semaphore_signal(semaphore);
        }
    }];
    if (dispatch_semaphore_wait(
            semaphore, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) != 0) return false;
    if (!ok || !m_currentTunnel) return false;
    [[NSNotificationCenter defaultCenter]
        removeObserver:(__bridge NSObject *)m_iosControllerWrapper];
    [[NSNotificationCenter defaultCenter]
        addObserver:(__bridge NSObject *)m_iosControllerWrapper
           selector:@selector(vpnStatusDidChange:)
               name:NEVPNStatusDidChangeNotification
             object:m_currentTunnel.connection];
    return true;
}

bool IosController::connectVpn(amnezia::Proto proto, const QJsonObject& configuration)
{
    if (!m_initializationResolved || m_guardRecoveryUnresolved) return false;
    m_proto = proto;
    m_rawConfig = configuration;
    m_serverAddress = configuration.value(configKey::hostName).toString().toNSString();

    const QString serverDescription = configuration.value(configKey::description).toString().trimmed();
    QString tunnelName;
    if (serverDescription.isEmpty()) {
        tunnelName = ProtocolUtils::protoToString(proto);
    } else {
        tunnelName = QString("%1 %2")
          .arg(serverDescription)
          .arg(ProtocolUtils::protoToString(proto));
    }

    qDebug() << "IosController::connectVpn" << tunnelName;

    // AVPN (фикс 2-го коннекта): сбрасываем стейт прошлого цикла. Без этого m_handshakeConfirmed оставался
    // true со старого туннеля → 2-й Connected эмитился БЕЗ реального handshake новой ноды («зелёный орб,
    // но трафика нет» = Network Error); m_lastEmittedState глушил нужный переход (dedup); m_statusRequestInFlight
    // блокировал checkStatus. (void)tunnelName — имя больше не используем для матчинга (см. ниже).
    (void)tunnelName;
    setCurrentTunnel(nil); // AVPN: release старого менеджера

    m_handshakeConfirmed = false;
    m_handshakeAwaiting = false;
    m_handshakeTimer.invalidate();
    m_handshakeTimeouts = 0;
    m_statusRequestInFlight = false;
    m_lastEmittedState = Vpn::ConnectionState::Unknown;
    m_rxBytes = 0;
    m_txBytes = 0;
    m_counterEpoch.clear();
    m_runtimeStatus = {};
    m_runtimeSessionId.clear();
    m_expectedRuntimeSessionId.clear();
    ++m_statusGeneration; // AVPN: инвалидируем ответы checkStatus прошлой сессии (стейл-гонка)

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block bool ok = true;

    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> * _Nullable managers, NSError * _Nullable error) {
        @try {
            if (error) {
                qDebug() << "IosController::connectVpn : loadAllFromPreferences error:" << [error.localizedDescription UTF8String];
                emit connectionStateChanged(Vpn::ConnectionState::Error);
                ok = false;
                return;
            }

            qDebug() << "IosController::connectVpn : managers received:" << (long)managers.count;

            // AVPN (фикс смены сервера): ПЕРЕИСПОЛЬЗУЕМ ОДИН менеджер (как официальный WireGuard iOS),
            // НЕ плодим по имени-с-сервером. Раньше localizedDescription = "<сервер> <proto>" → на каждый
            // сервер создавался НОВЫЙ NETunnelProviderManager → они копились в системе → конфликты
            // save/load/start у iOS-NE → вис «коннектинг» + Network Error при смене сервера. Берём наш
            // менеджер по bundle-id провайдера (isOurManager), все лишние/битые/дубли — удаляем.
            NSMutableArray<NETunnelProviderManager *> *extras = [NSMutableArray array];
            for (NETunnelProviderManager *manager in managers) {
                if (!m_currentTunnel && isOurManager(manager)) {
                    setCurrentTunnel(manager); // AVPN: владеющее присвоение (retain)
                } else {
                    [extras addObject:manager];
                }
            }
            for (NETunnelProviderManager *m in extras) {
                [m removeFromPreferencesWithCompletionHandler:^(NSError *e) {
                    if (e) qDebug() << "IosController::connectVpn : remove extra manager error" << e.localizedDescription.UTF8String;
                }];
            }

            if (!m_currentTunnel) {
                // AVPN: setCurrentTunnel ретейнит, поэтому alloc-объект отдаём в autorelease (иначе утечка +1)
                setCurrentTunnel([[[NETunnelProviderManager alloc] init] autorelease]);
                qDebug() << "IosController::connectVpn : creating new tunnel manager";
            }
            // AVPN: стабильное имя — чтобы конфиг в Настройках iOS назывался понятно и не плодился по серверам.
            m_currentTunnel.localizedDescription = @"Tribe VPN";
        }
        @catch (NSException *exception) {
            qDebug() << "IosController::connectVpn : exception" << QString::fromNSString(exception.reason);
            ok = false;
            setCurrentTunnel(nil); // AVPN: release старого менеджера
        }
        @finally {
            dispatch_semaphore_signal(semaphore);
        }
    }];

    // AVPN: таймаут вместо DISPATCH_TIME_FOREVER — если completion не пришёл (битые prefs / лимит NE-профилей),
    // не виснем на потоке навсегда; считаем ошибкой и выходим.
    // AVPN (краш-фикс): 3 c < iOS-watchdog 5 c. Блокировка потока на 10 c при suspend/terminate
    // (главный поток ждёт join этого воркера) перебивала watchdog → 0x8BADF00D. Таймаут = ошибка коннекта.
    if (dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC))) != 0) {
        qDebug() << "IosController::connectVpn : loadAllFromPreferences timed out";
        return false;
    }
    if (!ok) return false;

    [[NSNotificationCenter defaultCenter]
        removeObserver:(__bridge NSObject *)m_iosControllerWrapper];

    [[NSNotificationCenter defaultCenter]
        addObserver:(__bridge NSObject *)m_iosControllerWrapper
            selector:@selector(vpnStatusDidChange:)
            name:NEVPNStatusDidChangeNotification
            object:m_currentTunnel.connection];


    if (proto == amnezia::Proto::OpenVpn) {
        return setupOpenVPN();
    }
    if (proto == amnezia::Proto::WireGuard) {
        return setupWireGuard();
    }
    if (proto == amnezia::Proto::Awg) {
        return setupAwg();
    }
    if (proto == amnezia::Proto::Xray) {
        return setupXray();
    }
    if (proto == amnezia::Proto::SSXray) {
        return setupSSXray();
    }

    return false;
}

bool IosController::requestSessionGuardArm(const QJsonObject &vpnConfig,
                                           const QString &operation,
                                           const QString &session,
                                           const QString &policyHashHex,
                                           const QString &expectedRuntimeSessionId)
{
#if MACOS_NE
    Q_UNUSED(vpnConfig); Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(policyHashHex);
    Q_UNUSED(expectedRuntimeSessionId);
    return false;
#else
    if (!m_initializationResolved || m_guardRecoveryUnresolved) return false;
    if (!canonicalTokenString(operation) || !canonicalTokenString(session)
        || !lowerSha256(policyHashHex) || !canonicalRuntimeUuid(expectedRuntimeSessionId)
        || vpnConfig.value(QStringLiteral("native_envelope_schema"))
             != QLatin1String("tribe_catalog_v2_native_v1")) return false;
    const QString protocolName = vpnConfig.value(QStringLiteral("protocol")).toString();
    const bool awg = protocolName == QLatin1String("awg");
    const bool xray = protocolName == QLatin1String("xray");
    if (!awg && !xray) return false;
    const QJsonObject authority = vpnConfig.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    if (authority.value(QStringLiteral("policy_sha256")).toString() != policyHashHex)
        return false;
    if (!ensureTunnelManager()) return false;

    const QByteArray bytes = QJsonDocument(vpnConfig).toJson(QJsonDocument::Compact);
    NSData *configData = [NSData dataWithBytes:bytes.constData() length:bytes.size()];
    NSString *reference = [TribeTunnelConfigVault
        stageConfig:configData protocolName:protocolName.toNSString()
        sessionId:expectedRuntimeSessionId.toNSString()];
    if (!reference) return false;

    if (!m_pendingGuardOperation.isEmpty()) {
        [TribeTunnelConfigVault discardReference:reference];
        return false;
    }
    m_pendingGuardOperation = operation;
    m_pendingGuardSession = session;
    m_pendingGuardPolicySha256 = policyHashHex;
    m_pendingGuardExpectedRuntimeSessionId = expectedRuntimeSessionId;
    m_expectedRuntimeSessionId = expectedRuntimeSessionId;
    m_proto = awg ? amnezia::Proto::Awg : amnezia::Proto::Xray;
    m_rawConfig = vpnConfig;
    m_serverAddress = vpnConfig.value(configKey::hostName).toString().toNSString();

    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel) {
        [TribeTunnelConfigVault discardReference:reference];
        m_pendingGuardOperation.clear();
        m_pendingGuardSession.clear();
        m_pendingGuardPolicySha256.clear();
        m_pendingGuardExpectedRuntimeSessionId.clear();
        return false;
    }
    if (tunnel.connection.status == NEVPNStatusConnected) {
        NSString *ownedReference = [reference copy];
        NSDictionary *message = @{
            @"action": @"native_guard_prepare_v1",
            @"operation": operation.toNSString(), @"session": session.toNSString(),
            @"policy_sha256": policyHashHex.toNSString(),
            @"expected_runtime_session_id": expectedRuntimeSessionId.toNSString(),
            @"tribe_config_ref": reference, @"tribe_protocol": protocolName.toNSString(),
            @"tribe_session_id": expectedRuntimeSessionId.toNSString(),
        };
        sendVpnExtensionMessage(tunnel, message, [this, ownedReference](NSDictionary *response) {
            if (!response) [TribeTunnelConfigVault discardReference:ownedReference];
            consumeNativeGuardResponse(response);
            [ownedReference release];
        });
        [tunnel release];
        return true;
    }

    NETunnelProviderProtocol *protocol = [[NETunnelProviderProtocol alloc] init];
    protocol.providerBundleIdentifier = [NSString stringWithUTF8String:VPN_NE_BUNDLEID];
    protocol.providerConfiguration = @{
        @"tribe_config_schema": @1, @"tribe_protocol": protocolName.toNSString(),
        @"tribe_config_ref": reference, @"guarded_inner_switch": @YES,
        @"tribe_session_id": expectedRuntimeSessionId.toNSString(),
    };
    protocol.serverAddress = m_serverAddress;
    if (@available(iOS 14.0, *)) {
        const bool fullTunnel = vpnConfig.value(configKey::splitTunnelType).toInt(0) == 0;
        protocol.includeAllNetworks = fullTunnel;
        protocol.excludeLocalNetworks = NO;
        if (@available(iOS 14.2, *)) protocol.enforceRoutes = YES;
    }
    tunnel.protocolConfiguration = protocol;
    [protocol release];
    [tunnel release];
    NSDictionary *options = @{
        @"action": @"native_guard_prepare_v1",
        @"operation": operation.toNSString(), @"session": session.toNSString(),
        @"policy_sha256": policyHashHex.toNSString(),
        @"expected_runtime_session_id": expectedRuntimeSessionId.toNSString(),
    };
    startTunnel(options);
    return true;
#endif
}

bool IosController::renewRuntimeAuthority(const QJsonObject &vpnConfig,
                                          const QString &operation,
                                          const QString &session,
                                          const QString &outerSessionId,
                                          const QString &expectedRuntimeSessionId,
                                          const QString &renewalId,
                                          const QString &authorityCommitmentHex)
{
#if MACOS_NE
    Q_UNUSED(vpnConfig); Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(outerSessionId);
    Q_UNUSED(expectedRuntimeSessionId); Q_UNUSED(renewalId);
    Q_UNUSED(authorityCommitmentHex);
    return false;
#else
    QJsonObject request;
    if (!m_initializationResolved || m_guardRecoveryUnresolved
        || !m_pendingAuthorityRenewalRequest.isEmpty() || !m_guardReceiptArmed
        || !buildAuthorityRenewalRequest(vpnConfig, operation, session, outerSessionId,
                                         expectedRuntimeSessionId, renewalId,
                                         authorityCommitmentHex, request)) return false;
    const QJsonObject activeIdentity{
        {QStringLiteral("operation"), m_guardOperation},
        {QStringLiteral("session"), m_guardSession},
        {QStringLiteral("policy_sha256"), m_guardPolicySha256},
        {QStringLiteral("outer_session_id"), m_guardOuterSessionId},
        {QStringLiteral("expected_runtime_session_id"), m_guardExpectedRuntimeSessionId},
    };
    for (const char *key : {"operation", "session", "policy_sha256", "outer_session_id",
                            "expected_runtime_session_id"}) {
        if (request.value(QLatin1String(key))
                != activeIdentity.value(QLatin1String(key))) return false;
    }
    const QString protocolName = vpnConfig.value(QStringLiteral("protocol")).toString();
    if (protocolName != QLatin1String("awg") && protocolName != QLatin1String("xray"))
        return false;
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel || tunnel.connection.status != NEVPNStatusConnected) {
        if (tunnel) [tunnel release];
        return false;
    }
    const QByteArray configBytes = QJsonDocument(vpnConfig).toJson(QJsonDocument::Compact);
    NSData *configData = [NSData dataWithBytes:configBytes.constData()
                                        length:configBytes.size()];
    NSString *reference = [TribeTunnelConfigVault
        stageConfig:configData protocolName:protocolName.toNSString()
        sessionId:expectedRuntimeSessionId.toNSString()];
    if (!reference) {
        [tunnel release];
        return false;
    }
    const QByteArray requestBytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
    NSData *requestData = [NSData dataWithBytes:requestBytes.constData()
                                         length:requestBytes.size()];
    NSError *jsonError = nil;
    NSDictionary *requestDictionary = [NSJSONSerialization JSONObjectWithData:requestData
        options:0 error:&jsonError];
    if (jsonError || ![requestDictionary isKindOfClass:[NSDictionary class]]) {
        [TribeTunnelConfigVault discardReference:reference];
        [tunnel release];
        return false;
    }
    NSString *ownedReference = [reference copy];
    m_pendingAuthorityRenewalRequest = request;
    NSDictionary *message = @{
        @"action": @"runtime_authority_renew_v1",
        @"renewal_request": requestDictionary,
        @"tribe_config_ref": reference,
        @"tribe_protocol": protocolName.toNSString(),
        @"tribe_session_id": expectedRuntimeSessionId.toNSString(),
    };
    sendVpnExtensionMessage(tunnel, message, [this, ownedReference](NSDictionary *response) {
        QJsonObject receipt;
        if (!response || !strictAuthorityRenewalReceipt(response, receipt)) {
            [TribeTunnelConfigVault discardReference:ownedReference];
            if (!response && !m_pendingAuthorityRenewalRequest.isEmpty()) {
                const QJsonObject rejected = rejectedRenewalReceipt(
                    m_pendingAuthorityRenewalRequest,
                    QStringLiteral("extension_no_receipt"));
                m_pendingAuthorityRenewalRequest = {};
                QMetaObject::invokeMethod(this, [this, rejected]() {
                    emit runtimeAuthorityRenewalReceipt(rejected);
                }, Qt::QueuedConnection);
            }
            [ownedReference release];
            return;
        }
        if (!m_pendingAuthorityRenewalRequest.isEmpty()
            && renewalReceiptMatches(receipt, m_pendingAuthorityRenewalRequest)) {
            m_pendingAuthorityRenewalRequest = {};
            QMetaObject::invokeMethod(this, [this, receipt]() {
                emit runtimeAuthorityRenewalReceipt(receipt);
            }, Qt::QueuedConnection);
        }
        [ownedReference release];
    });
    [tunnel release];
    return true;
#endif
}

bool IosController::activateNativeSession(const QJsonObject &vpnConfig,
                                          const QString &operation,
                                          const QString &session,
                                          const QString &outerSessionId,
                                          const QString &expectedRuntimeSessionId)
{
#if MACOS_NE
    Q_UNUSED(vpnConfig); Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(outerSessionId);
    Q_UNUSED(expectedRuntimeSessionId);
    return false;
#else
    if (!m_guardReceiptArmed || operation != m_guardOperation || session != m_guardSession
        || outerSessionId != m_guardOuterSessionId
        || expectedRuntimeSessionId != m_guardExpectedRuntimeSessionId
        || !safeGuardOpaque(outerSessionId) || !canonicalRuntimeUuid(expectedRuntimeSessionId))
        return false;
    const QString protocolName = vpnConfig.value(QStringLiteral("protocol")).toString();
    if (protocolName != QLatin1String("awg") && protocolName != QLatin1String("xray"))
        return false;
    const QJsonObject authority = vpnConfig.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    if (authority.value(QStringLiteral("policy_sha256")).toString()
        != m_guardPolicySha256) return false;
    const QByteArray bytes = QJsonDocument(vpnConfig).toJson(QJsonDocument::Compact);
    NSData *configData = [NSData dataWithBytes:bytes.constData() length:bytes.size()];
    NSString *reference = [TribeTunnelConfigVault
        stageConfig:configData protocolName:protocolName.toNSString()
        sessionId:expectedRuntimeSessionId.toNSString()];
    if (!reference) return false;
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel || tunnel.connection.status != NEVPNStatusConnected) {
        if (tunnel) [tunnel release];
        [TribeTunnelConfigVault discardReference:reference];
        return false;
    }
    NSString *ownedReference = [reference copy];
    m_proto = protocolName == QLatin1String("awg") ? amnezia::Proto::Awg
                                                     : amnezia::Proto::Xray;
    m_rawConfig = vpnConfig;
    m_expectedRuntimeSessionId = expectedRuntimeSessionId;
    m_runtimeSessionId.clear();
    m_runtimeStatus = {};
    ++m_statusGeneration;
    NSDictionary *message = @{
        @"action": @"native_session_activate_v1",
        @"operation": operation.toNSString(), @"session": session.toNSString(),
        @"policy_sha256": m_guardPolicySha256.toNSString(),
        @"outer_session_id": outerSessionId.toNSString(),
        @"expected_runtime_session_id": expectedRuntimeSessionId.toNSString(),
        @"tribe_config_ref": reference, @"tribe_protocol": protocolName.toNSString(),
        @"tribe_session_id": expectedRuntimeSessionId.toNSString(),
    };
    sendVpnExtensionMessage(tunnel, message, [this, ownedReference](NSDictionary *response) {
        if (!response) [TribeTunnelConfigVault discardReference:ownedReference];
        NSDictionary *guardEvent = [response[@"guard_event"]
            isKindOfClass:[NSDictionary class]] ? response[@"guard_event"] : nil;
        if (guardEvent) consumeNativeGuardResponse(guardEvent);
        if (response && [response[@"ok"] boolValue]) checkStatus();
        [ownedReference release];
    });
    [tunnel release];
    return true;
#endif
}

bool IosController::stopNativeSession(const QString &outerSessionId,
                                      const QString &expectedRuntimeSessionId)
{
#if MACOS_NE
    Q_UNUSED(outerSessionId); Q_UNUSED(expectedRuntimeSessionId);
    return false;
#else
    if (!m_guardReceiptArmed || outerSessionId != m_guardOuterSessionId
        || expectedRuntimeSessionId != m_guardExpectedRuntimeSessionId) return false;
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel || tunnel.connection.status != NEVPNStatusConnected) {
        if (tunnel) [tunnel release];
        return false;
    }
    NSDictionary *message = @{
        @"action": @"native_session_stop_v1",
        @"outer_session_id": outerSessionId.toNSString(),
        @"expected_runtime_session_id": expectedRuntimeSessionId.toNSString(),
    };
    sendVpnExtensionMessage(tunnel, message, [this](NSDictionary *response) {
        NSDictionary *guardEvent = [response[@"guard_event"]
            isKindOfClass:[NSDictionary class]] ? response[@"guard_event"] : nil;
        if (guardEvent) consumeNativeGuardResponse(guardEvent);
        checkStatus();
    });
    [tunnel release];
    return true;
#endif
}

bool IosController::requestSessionGuardRelease(const QString &operation,
                                               const QString &session,
                                               const QString &outerSessionId)
{
#if MACOS_NE
    Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(outerSessionId);
    return false;
#else
    if (!m_guardReceiptArmed || operation != m_guardOperation || session != m_guardSession
        || outerSessionId != m_guardOuterSessionId) return false;
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel || tunnel.connection.status != NEVPNStatusConnected) {
        if (tunnel) [tunnel release];
        return false;
    }
    NSDictionary *message = @{
        @"action": @"native_guard_release_v1",
        @"operation": operation.toNSString(), @"session": session.toNSString(),
        @"outer_session_id": outerSessionId.toNSString(),
    };
    [tunnel retain];
    sendVpnExtensionMessage(tunnel, message, [this, tunnel](NSDictionary *response) {
        consumeNativeGuardResponse(response);
        const bool released = [response[@"kind"] isEqualToString:@"released"];
        QMetaObject::invokeMethod(this, [tunnel, released]() {
            if (released && [tunnel.connection isKindOfClass:[NETunnelProviderSession class]])
                [(NETunnelProviderSession *)tunnel.connection stopTunnel];
            [tunnel release];
        }, Qt::QueuedConnection);
    });
    [tunnel release];
    return true;
#endif
}

bool IosController::requestSessionGuardReconcileArm(
    const QString &operation, const QString &session, const QString &policyHashHex,
    const QString &expectedRuntimeSessionId)
{
#if MACOS_NE
    Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(policyHashHex);
    Q_UNUSED(expectedRuntimeSessionId);
    return false;
#else
    if (operation != m_pendingGuardOperation || session != m_pendingGuardSession
        || policyHashHex != m_pendingGuardPolicySha256
        || expectedRuntimeSessionId != m_pendingGuardExpectedRuntimeSessionId
        || !canonicalTokenString(operation) || !canonicalTokenString(session)
        || !lowerSha256(policyHashHex) || !canonicalRuntimeUuid(expectedRuntimeSessionId))
        return false;
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel || tunnel.connection.status != NEVPNStatusConnected) {
        if (tunnel) [tunnel release];
        return false;
    }
    NSDictionary *message = @{
        @"action": @"native_guard_reconcile_v1", @"reconcile_kind": @"arm",
        @"operation": operation.toNSString(), @"session": session.toNSString(),
        @"policy_sha256": policyHashHex.toNSString(),
        @"expected_runtime_session_id": expectedRuntimeSessionId.toNSString(),
    };
    sendVpnExtensionMessage(tunnel, message, [this](NSDictionary *response) {
        consumeNativeGuardResponse(response);
    });
    [tunnel release];
    return true;
#endif
}

bool IosController::requestSessionGuardReconcileRelease(
    const QString &operation, const QString &session, const QString &policyHashHex,
    const QString &outerSessionId, const QString &expectedRuntimeSessionId)
{
#if MACOS_NE
    Q_UNUSED(operation); Q_UNUSED(session); Q_UNUSED(policyHashHex);
    Q_UNUSED(outerSessionId); Q_UNUSED(expectedRuntimeSessionId);
    return false;
#else
    if (!m_guardReceiptArmed || operation != m_guardOperation || session != m_guardSession
        || policyHashHex != m_guardPolicySha256 || outerSessionId != m_guardOuterSessionId
        || expectedRuntimeSessionId != m_guardExpectedRuntimeSessionId
        || !canonicalTokenString(operation) || !canonicalTokenString(session)
        || !lowerSha256(policyHashHex) || !safeGuardOpaque(outerSessionId)
        || !canonicalRuntimeUuid(expectedRuntimeSessionId)) return false;
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel || tunnel.connection.status != NEVPNStatusConnected) {
        if (tunnel) [tunnel release];
        return false;
    }
    NSDictionary *message = @{
        @"action": @"native_guard_reconcile_v1", @"reconcile_kind": @"release",
        @"operation": operation.toNSString(), @"session": session.toNSString(),
        @"policy_sha256": policyHashHex.toNSString(),
        @"outer_session_id": outerSessionId.toNSString(),
        @"expected_runtime_session_id": expectedRuntimeSessionId.toNSString(),
    };
    [tunnel retain];
    sendVpnExtensionMessage(tunnel, message, [this, tunnel](NSDictionary *response) {
        consumeNativeGuardResponse(response);
        const bool released = [response[@"kind"] isEqualToString:@"released"];
        QMetaObject::invokeMethod(this, [tunnel, released]() {
            if (released && [tunnel.connection isKindOfClass:[NETunnelProviderSession class]])
                [(NETunnelProviderSession *)tunnel.connection stopTunnel];
            [tunnel release];
        }, Qt::QueuedConnection);
    });
    [tunnel release];
    return true;
#endif
}

bool IosController::requestSessionGuardRecoveryResolution(
    const QJsonObject &exactRecoveryEvent, const QString &action,
    const QJsonObject &validatedConfiguration)
{
#if MACOS_NE
    Q_UNUSED(exactRecoveryEvent); Q_UNUSED(action); Q_UNUSED(validatedConfiguration);
    return false;
#else
    if (!m_guardRecoveryUnresolved || m_guardRecoveryResolutionPending
        || exactRecoveryEvent.isEmpty() || exactRecoveryEvent != m_guardRecoveryEvent
        || (action != QLatin1String("adopt") && action != QLatin1String("stop"))) return false;
    const QString operation = exactRecoveryEvent.value(QStringLiteral("operation")).toString();
    const QString session = exactRecoveryEvent.value(QStringLiteral("session")).toString();
    const QString policy = exactRecoveryEvent.value(QStringLiteral("policy_sha256")).toString();
    const QString outer = exactRecoveryEvent.value(QStringLiteral("outer_session_id")).toString();
    const QString expected = exactRecoveryEvent.value(
        QStringLiteral("expected_runtime_session_id")).toString();
    if (!canonicalTokenString(operation) || !canonicalTokenString(session)
        || !lowerSha256(policy) || !safeGuardOpaque(outer)
        || !canonicalRuntimeUuid(expected)) return false;

    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel || tunnel.connection.status != NEVPNStatusConnected) {
        if (tunnel) [tunnel release];
        return false;
    }
    NSMutableDictionary *message = [@{
        @"action": @"native_guard_recovery_resolve_v1",
        @"resolution_action": action.toNSString(),
        @"operation": operation.toNSString(), @"session": session.toNSString(),
        @"policy_sha256": policy.toNSString(), @"outer_session_id": outer.toNSString(),
        @"expected_runtime_session_id": expected.toNSString(),
    } mutableCopy];
    NSString *ownedReference = nil;
    QString protocolName;
    if (action == QLatin1String("adopt")) {
        if (validatedConfiguration.value(QStringLiteral("native_envelope_schema"))
                != QLatin1String("tribe_catalog_v2_native_v1")) {
            [message release]; [tunnel release]; return false;
        }
        protocolName = validatedConfiguration.value(QStringLiteral("protocol")).toString();
        const QJsonObject authority = validatedConfiguration.value(
            QStringLiteral("runtime_authority_v1")).toObject();
        if ((protocolName != QLatin1String("awg") && protocolName != QLatin1String("xray"))
            || authority.value(QStringLiteral("policy_sha256")).toString() != policy) {
            [message release]; [tunnel release]; return false;
        }
        const QByteArray bytes = QJsonDocument(validatedConfiguration).toJson(
            QJsonDocument::Compact);
        NSData *data = [NSData dataWithBytes:bytes.constData() length:bytes.size()];
        NSString *reference = [TribeTunnelConfigVault
            stageConfig:data protocolName:protocolName.toNSString()
            sessionId:expected.toNSString()];
        if (!reference) { [message release]; [tunnel release]; return false; }
        ownedReference = [reference copy];
        message[@"tribe_config_ref"] = reference;
        message[@"tribe_protocol"] = protocolName.toNSString();
        message[@"tribe_session_id"] = expected.toNSString();
    }

    m_guardRecoveryResolutionPending = true;
    NSDictionary *immutableMessage = [[message copy] autorelease];
    [message release];
    const QString requestedAction = action;
    const QString requestedProtocol = protocolName;
    const QJsonObject adoptedConfiguration = validatedConfiguration;
    sendVpnExtensionMessage(tunnel, immutableMessage,
        [this, requestedAction, requestedProtocol, adoptedConfiguration,
         ownedReference](NSDictionary *response) {
            NSDictionary *receiptDictionary = response;
            NSDictionary *runtimeDictionary = nil;
            NSDictionary *guardDictionary = nil;
            if (requestedAction == QLatin1String("stop")
                && [response isKindOfClass:[NSDictionary class]]
                && response.count == 3
                && [response[@"runtime_status"] isKindOfClass:[NSDictionary class]]
                && [response[@"guard_event"] isKindOfClass:[NSDictionary class]]
                && [response[@"recovery_receipt"] isKindOfClass:[NSDictionary class]]) {
                runtimeDictionary = response[@"runtime_status"];
                guardDictionary = response[@"guard_event"];
                receiptDictionary = response[@"recovery_receipt"];
            }
            QJsonObject receipt;
            QJsonObject guardEvent;
            QJsonObject runtimeStatus;
            bool valid = strictNativeGuardRecoveryReceipt(receiptDictionary, receipt)
                && receipt.value(QStringLiteral("action")).toString() == requestedAction;
            if (valid && receipt.value(QStringLiteral("kind"))
                    == QLatin1String("stopped_released")) {
                valid = strictNativeGuardEvent(guardDictionary, guardEvent)
                    && guardEvent.value(QStringLiteral("kind")) == QLatin1String("released")
                    && guardEvent.value(QStringLiteral("operation"))
                        == receipt.value(QStringLiteral("operation"))
                    && guardEvent.value(QStringLiteral("session"))
                        == receipt.value(QStringLiteral("session"))
                    && guardEvent.value(QStringLiteral("policy_sha256"))
                        == receipt.value(QStringLiteral("policy_sha256"))
                    && guardEvent.value(QStringLiteral("outer_session_id"))
                        == receipt.value(QStringLiteral("outer_session_id"))
                    && guardEvent.value(QStringLiteral("expected_runtime_session_id"))
                        == receipt.value(QStringLiteral("expected_runtime_session_id"));
                NSError *error = nil;
                NSData *runtimeData = [NSJSONSerialization dataWithJSONObject:runtimeDictionary
                    options:0 error:&error];
                QJsonParseError parseError;
                if (!runtimeData || error) {
                    valid = false;
                } else {
                    runtimeStatus = QJsonDocument::fromJson(QByteArray(
                        reinterpret_cast<const char *>(runtimeData.bytes), runtimeData.length),
                        &parseError).object();
                    valid = valid && parseError.error == QJsonParseError::NoError
                        && runtimeStatus.value(QStringLiteral("type"))
                            == QLatin1String("tunnel_runtime_status_v1")
                        && schemaOne(runtimeStatus.value(QStringLiteral("schema")))
                        && runtimeStatus.value(QStringLiteral("runtime_state"))
                            == QLatin1String("stopped")
                        && runtimeStatus.value(QStringLiteral("session_id"))
                            == receipt.value(QStringLiteral("expected_runtime_session_id"))
                        && (runtimeStatus.value(QStringLiteral("protocol"))
                                == QLatin1String("awg")
                            || runtimeStatus.value(QStringLiteral("protocol"))
                                == QLatin1String("xray"));
                }
            }
            if (ownedReference)
                [TribeTunnelConfigVault discardReference:ownedReference];
            [ownedReference release];
            QMetaObject::invokeMethod(this,
                [this, valid, receipt, guardEvent, runtimeStatus, requestedAction,
                 requestedProtocol, adoptedConfiguration]() {
                    if (!m_guardRecoveryResolutionPending) return;
                    m_guardRecoveryResolutionPending = false;
                    if (!valid || receipt.value(QStringLiteral("operation"))
                            != m_guardRecoveryEvent.value(QStringLiteral("operation"))
                        || receipt.value(QStringLiteral("session"))
                            != m_guardRecoveryEvent.value(QStringLiteral("session"))
                        || receipt.value(QStringLiteral("policy_sha256"))
                            != m_guardRecoveryEvent.value(QStringLiteral("policy_sha256"))
                        || receipt.value(QStringLiteral("outer_session_id"))
                            != m_guardRecoveryEvent.value(QStringLiteral("outer_session_id"))
                        || receipt.value(QStringLiteral("expected_runtime_session_id"))
                            != m_guardRecoveryEvent.value(
                                QStringLiteral("expected_runtime_session_id"))) return;
                    const QString kind = receipt.value(QStringLiteral("kind")).toString();
                    if (requestedAction == QLatin1String("adopt")
                        && kind == QLatin1String("adopted")) {
                        m_guardOperation = receipt.value(QStringLiteral("operation")).toString();
                        m_guardSession = receipt.value(QStringLiteral("session")).toString();
                        m_guardPolicySha256 = receipt.value(
                            QStringLiteral("policy_sha256")).toString();
                        m_guardOuterSessionId = receipt.value(
                            QStringLiteral("outer_session_id")).toString();
                        m_guardExpectedRuntimeSessionId = receipt.value(
                            QStringLiteral("expected_runtime_session_id")).toString();
                        m_expectedRuntimeSessionId = m_guardExpectedRuntimeSessionId;
                        m_proto = requestedProtocol == QLatin1String("awg")
                            ? amnezia::Proto::Awg : amnezia::Proto::Xray;
                        m_rawConfig = adoptedConfiguration;
                        m_guardReceiptArmed = true;
                        m_guardRecoveryUnresolved = false;
                        m_guardRecoveryEvent = {};
                        emit sessionGuardRecoveryResolved(receipt);
                        checkStatus();
                    } else if (requestedAction == QLatin1String("stop")
                               && kind == QLatin1String("stopped_released")) {
                        m_runtimeStatus = runtimeStatus;
                        m_runtimeSessionId = runtimeStatus.value(
                            QStringLiteral("session_id")).toString();
                        emit runtimeStatusChanged(runtimeStatus);
                        emit sessionGuardEvent(guardEvent);
                        m_guardRecoveryUnresolved = false;
                        m_guardRecoveryEvent = {};
                        emit sessionGuardRecoveryResolved(receipt);
                        NETunnelProviderManager *activeTunnel = retainedCurrentTunnel();
                        if (activeTunnel
                            && [activeTunnel.connection isKindOfClass:
                                [NETunnelProviderSession class]])
                            [(NETunnelProviderSession *)activeTunnel.connection stopTunnel];
                        [activeTunnel release];
                    } else {
                        emit sessionGuardRecoveryResolved(receipt);
                    }
                }, Qt::QueuedConnection);
        });
    [tunnel release];
    return true;
#endif
}

void IosController::disconnectVpn()
{
    // AVPN: если гасить нечего (нет менеджера / нет сессии / уже опущен) — эмитим Disconnected СРАЗУ,
    // чтобы движок не повис в ожидании. Если сессия ЖИВАЯ — только stopTunnel; РЕАЛЬНЫЙ Disconnected
    // прилетит из vpnStatusDidChange (его и ждёт reconcile перед реконнектом на новый сервер — это и есть
    // «как в Amnezia»: не стартуем новый туннель, пока старый не дошёл до Disconnected).
    if (!m_currentTunnel || ![m_currentTunnel.connection isKindOfClass:[NETunnelProviderSession class]]) {
        emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        return;
    }
    NEVPNStatus st = m_currentTunnel.connection.status;
    if (st == NEVPNStatusDisconnected || st == NEVPNStatusInvalid) {
        emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        return;
    }
    [(NETunnelProviderSession *)m_currentTunnel.connection stopTunnel];
}


void IosController::checkStatus()
{
    // AVPN (ревью 2026-07-11): менеджер — только retained-копией (гонка с release на реконнекте),
    // ответ — только для СВОЕЙ сессии (gen): стейл-ответ старой сессии, долетевший после
    // реконнекта, перезаписывал m_rxBytes старым большим кумулятивом → следующая дельта
    // rxBytes - m_rxBytes уходила в quint64-underflow (~2^64) в bytesChanged.
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel) {
        return;
    }

    if (tunnel.connection.status != NEVPNStatusConnected) {
        [tunnel release];
        return;
    }

    if (m_statusRequestInFlight.exchange(true)) {
        [tunnel release];
        return;
    }
    const uint64_t gen = m_statusGeneration.load();
    const QString expectedSessionId = m_expectedRuntimeSessionId;

    NSString *actionKey = [NSString stringWithUTF8String:MessageKey::action];
    NSString *actionValue = [NSString stringWithUTF8String:Action::getStatus];
    NSString *tunnelIdKey = [NSString stringWithUTF8String:MessageKey::tunnelId];
    NSString *tunnelIdValue = !m_tunnelId.isEmpty() ? m_tunnelId.toNSString() : @"";

    NSDictionary* message = @{actionKey: actionValue, tunnelIdKey: tunnelIdValue};
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    // tunnel: наш retain (retainedCurrentTunnel) отпускается в КОНЦЕ блока — синхронно после
    // sendProviderMessage (ответ-хендлер менеджер не трогает; release в колбэке был бы двойным
    // при callback(nil)-ветках). Сам блок дополнительно держит tunnel как object-capture.
    sendVpnExtensionMessage(tunnel, message, [this, gen, expectedSessionId](NSDictionary* response){
        if (!response) {
            QMetaObject::invokeMethod(this, [this, gen]() {
                if (m_statusGeneration.load() == gen)
                    m_statusRequestInFlight = false;
            }, Qt::QueuedConnection);
            return;
        }

        const bool expectsTypedRuntimeStatus = isXrayBasedProto(m_proto)
                || isWireGuardBasedProto(m_proto);
        const bool xrayRuntimeStateAuthoritative = isXrayBasedProto(m_proto);
        const bool isTypedStatus = [response[@"type"] isEqual:@"tunnel_runtime_status_v1"]
                && objcSchemaOne(response[@"schema"]);
        NSDictionary *counterResponse = [response[@"counters"] isKindOfClass:[NSDictionary class]]
                ? (NSDictionary *)response[@"counters"] : response;
        NSDictionary *coreResponse = [response[@"core"] isKindOfClass:[NSDictionary class]]
                ? (NSDictionary *)response[@"core"] : nil;
        const QString responseProtocol = QString::fromNSString(
                [response[@"protocol"] isKindOfClass:[NSString class]] ? response[@"protocol"] : @"");
        const QString runtimeState = QString::fromNSString(
                [response[@"runtime_state"] isKindOfClass:[NSString class]] ? response[@"runtime_state"] : @"");
        const QString counterEpoch = QString::fromNSString(
                [counterResponse[@"epoch"] isKindOfClass:[NSString class]] ? counterResponse[@"epoch"] : @"");
        NSString *sessionIdValue = [response[@"session_id"] isKindOfClass:[NSString class]]
                ? (NSString *)response[@"session_id"] : @"";
        const QString responseSessionId = QString::fromNSString(sessionIdValue);
        NSUUID *sessionUuid = sessionIdValue.length > 0
                ? [[[NSUUID alloc] initWithUUIDString:sessionIdValue] autorelease] : nil;
        const QString coreAbi = QString::fromNSString(
                [coreResponse[@"abi"] isKindOfClass:[NSString class]] ? coreResponse[@"abi"] : @"");
        const QString coreAdapter = QString::fromNSString(
                [coreResponse[@"adapter"] isKindOfClass:[NSString class]] ? coreResponse[@"adapter"] : @"");
        const bool countersAvailable = !isTypedStatus || [counterResponse[@"available"] boolValue];
        uint64_t typedTxBytes = 0;
        uint64_t typedRxBytes = 0;
        uint64_t ignoredCounter = 0;
        const bool typedCountersValid = !isTypedStatus || (
                canonicalUint64FromResponse(counterResponse, @"tx_bytes", &typedTxBytes)
                && canonicalUint64FromResponse(counterResponse, @"rx_bytes", &typedRxBytes)
                && canonicalUint64FromResponse(counterResponse, @"tx_packets", &ignoredCounter)
                && canonicalUint64FromResponse(counterResponse, @"rx_packets", &ignoredCounter)
                && canonicalUint64FromResponse(counterResponse, @"tx_bytes_delta", &ignoredCounter)
                && canonicalUint64FromResponse(counterResponse, @"rx_bytes_delta", &ignoredCounter)
                && canonicalUint64FromResponse(counterResponse, @"tx_packets_delta", &ignoredCounter)
                && canonicalUint64FromResponse(counterResponse, @"rx_packets_delta", &ignoredCounter)
                && canonicalUint64FromResponse(counterResponse, @"reset_count", &ignoredCounter));
        const bool typedEngineValid = (responseProtocol == QLatin1String("xray")
                    && coreAdapter == QLatin1String("amnezia-libxray")
                    && coreAbi == QLatin1String(TRIBE_APPLE_XRAY_SOCKET_ABI))
                || (responseProtocol == QLatin1String("awg")
                    && coreAdapter == QLatin1String("awg-apple")
                    && coreAbi == QLatin1String("awg-apple-c-uapi-v3.1"));
        const bool typedRuntimeStatusValid = isTypedStatus
                && typedEngineValid
                && sessionUuid != nil
                && !expectedSessionId.isEmpty()
                && responseSessionId == expectedSessionId
                && !counterEpoch.isEmpty()
                && typedCountersValid
                && (runtimeState == QLatin1String("starting")
                    || runtimeState == QLatin1String("running")
                    || runtimeState == QLatin1String("stopping")
                    || runtimeState == QLatin1String("stopped")
                    || runtimeState == QLatin1String("reconnecting")
                    || runtimeState == QLatin1String("failed"));

        if (expectsTypedRuntimeStatus && !typedRuntimeStatusValid) {
            qWarning() << "IosController::checkStatus : rejected incompatible tunnel runtime status";
            QMetaObject::invokeMethod(this, [this, gen]() {
                if (m_statusGeneration.load() != gen)
                    return;
                m_statusRequestInFlight = false;
                emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
            }, Qt::QueuedConnection);
            return;
        }

        const uint64_t txBytes = isTypedStatus
                ? typedTxBytes : uint64FromResponse(counterResponse, @"tx_bytes");
        const uint64_t rxBytes = isTypedStatus
                ? typedRxBytes : uint64FromResponse(counterResponse, @"rx_bytes");
        uint64_t typedHandshake = 0;
        const bool typedHandshakeValid = isTypedStatus && responseProtocol == QLatin1String("awg")
                && canonicalUint64FromResponse(response, @"last_handshake_time_sec", &typedHandshake)
                && typedHandshake <= static_cast<uint64_t>(std::numeric_limits<long long>::max());
        const long long last_handshake_time_sec = isTypedStatus
                ? (typedHandshakeValid ? static_cast<long long>(typedHandshake) : -2)
                : int64FromResponse(response, @"last_handshake_time_sec");
        QJsonObject typedRuntimeStatus;
        if (expectsTypedRuntimeStatus) {
            NSData *statusData = [NSJSONSerialization dataWithJSONObject:response options:0 error:nil];
            if (statusData) {
                typedRuntimeStatus = QJsonDocument::fromJson(
                        QByteArray(reinterpret_cast<const char *>(statusData.bytes),
                                   static_cast<int>(statusData.length))).object();
            }
        }

        QMetaObject::invokeMethod(this, [this, gen, txBytes, rxBytes, last_handshake_time_sec,
                                         runtimeState, counterEpoch, expectsTypedRuntimeStatus,
                                         xrayRuntimeStateAuthoritative,
                                         countersAvailable, responseSessionId, typedRuntimeStatus]() {
            // AVPN: ответ чужого (старого) поколения сессии — выбросить целиком.
            if (m_statusGeneration.load() != gen)
                return;
            // AVPN backend-first (T20): пороги — из m_rawConfig (засеяны VpnConnectionTunnelControl::up
            // ключами awg_handshake_timeout_ms/awg_handshake_max_timeouts), пусто/офлайн → constexpr-фолбэк.
            const int handshakeTimeoutMs =
                    intFromRawConfig(m_rawConfig, "awg_handshake_timeout_ms", kHandshakeTimeoutMs);
            const int handshakeMaxTimeouts =
                    intFromRawConfig(m_rawConfig, "awg_handshake_max_timeouts", kHandshakeMaxTimeouts);
            // AVPN backend-first (Task 5): rx-порог подтверждения рукопожатия — тоже из m_rawConfig
            // (awg_handshake_rx_threshold_bytes, засеян VpnConnectionTunnelControl::up).
            // intFromRawConfig не гарантирует положительность — порог <= 0 бессмыслен, откатываемся на фолбэк.
            const int handshakeRxThresholdRaw =
                    intFromRawConfig(m_rawConfig, "awg_handshake_rx_threshold_bytes", (int)kHandshakeRxThreshold);
            const uint64_t handshakeRxThreshold =
                    handshakeRxThresholdRaw > 0 ? (uint64_t)handshakeRxThresholdRaw : kHandshakeRxThreshold;
            if (isWireGuardBasedProto(m_proto) && m_handshakeAwaiting) {
                const bool hasHandshakeData = (last_handshake_time_sec >= 0);
                // AVPN: tx НЕ доказывает рукопожатие — init-ретраи можно бесконечно слать в чёрную дыру
                // без ответа (на сотовой rx=0, а tx рос → срабатывал старый txBytes-клауз → ЛОЖНЫЙ Connected,
                // «зелёный орб, трафика нет»). Реальный handshake подтверждают ТОЛЬКО: last_handshake_time_sec>0
                // (авторитетно, wireguard-go ставит время завершённого рукопожатия) или приход данных назад (rx).
                const bool hasFreshHandshake = hasHandshakeData &&
                        ((last_handshake_time_sec > 0) ||
                         (rxBytes >= handshakeRxThreshold));

                if (hasFreshHandshake) {
                    m_handshakeConfirmed = true;
                    m_handshakeAwaiting = false;
                    m_handshakeTimer.invalidate();
                    m_handshakeTimeouts = 0;
                    qDebug() << "IosController::checkStatus : handshake confirmed";
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Connected);
                } else if (m_handshakeTimer.isValid() &&
                           m_handshakeTimer.elapsed() > handshakeTimeoutMs) {
                    m_handshakeTimer.restart();
                    // AVPN: нода не отвечает (rx=0). Не висим в Reconnecting вечно — после N таймаутов
                    // честно отдаём Error и гасим туннель (типично: IP:порт ноды режется оператором).
                    if (++m_handshakeTimeouts >= handshakeMaxTimeouts) {
                        qWarning() << "IosController::checkStatus : handshake failed after"
                                   << m_handshakeTimeouts << "timeouts — stopping tunnel";
                        m_handshakeAwaiting = false;
                        m_handshakeTimer.invalidate();
                        emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                        if (m_currentTunnel &&
                            [m_currentTunnel.connection isKindOfClass:[NETunnelProviderSession class]]) {
                            [(NETunnelProviderSession *)m_currentTunnel.connection stopTunnel];
                        }
                    } else {
                        qDebug() << "IosController::checkStatus : handshake timed out, keeping tunnel alive"
                                 << m_handshakeTimeouts << "/" << handshakeMaxTimeouts;
                        emitConnectionStateIfChanged(Vpn::ConnectionState::Reconnecting);
                    }
                }
            }

            if (expectsTypedRuntimeStatus) {
                m_runtimeSessionId = responseSessionId;
                if (!typedRuntimeStatus.isEmpty()) {
                    m_runtimeStatus = typedRuntimeStatus;
                    emit runtimeStatusChanged(m_runtimeStatus);
                }
            }

            if (xrayRuntimeStateAuthoritative) {
                // Xray has no WireGuard handshake.  The engine/provider state
                // is authoritative; zero counters are a valid idle tunnel and
                // never evidence of failure.
                if (runtimeState == QLatin1String("running")) {
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Connected);
                } else if (runtimeState == QLatin1String("starting")) {
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Connecting);
                } else if (runtimeState == QLatin1String("stopping")) {
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Disconnecting);
                } else if (runtimeState == QLatin1String("reconnecting")) {
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Reconnecting);
                } else if (runtimeState == QLatin1String("stopped")) {
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Disconnected);
                } else if (runtimeState == QLatin1String("failed")) {
                    emitConnectionStateIfChanged(Vpn::ConnectionState::Error);
                }
            }

            // AVPN: счётчик «поехал назад» (рестарт NE-сессии/гонка) — пересев без эмиссии дельты,
            // иначе беззнаковое вычитание даёт «дельту» ~2^64 (второй рубеж — guard в accumulateByteDelta).
            if (countersAvailable) {
                if (!counterEpoch.isEmpty() && counterEpoch != m_counterEpoch) {
                    // New provider/counter epoch: seed only.  Traffic from a
                    // previous Xray restart must not be emitted as a spike.
                    m_counterEpoch = counterEpoch;
                } else {
                    const uint64_t rxDelta = rxBytes >= m_rxBytes ? rxBytes - m_rxBytes : 0;
                    const uint64_t txDelta = txBytes >= m_txBytes ? txBytes - m_txBytes : 0;
                    emit bytesChanged(rxDelta, txDelta);
                }
                m_rxBytes = rxBytes;
                m_txBytes = txBytes;
            }
            // AVPN: отдаём возраст хендшейка наружу (unix sec; <=0 → 0 «неизвестно») — serviceEngine
            // HealthLoop использует его для DEAD-детекта на iOS (раньше latestHandshakeEpoch был 0).
            if (isWireGuardBasedProto(m_proto))
                emit handshakeChanged(last_handshake_time_sec > 0 ? (qint64) last_handshake_time_sec : 0);
            m_statusRequestInFlight = false;
        }, Qt::QueuedConnection);
    });
    [tunnel release]; // парный к retainedCurrentTunnel() в checkStatus
    });
}

// AVPN (BUG-4 auto-heal): ребайнд сокета живого NE-туннеля. Тот же канал, что checkStatus
// (retained-менеджер + provider message), но fire-and-forget: подтверждение heal'а — сам
// data-plane (HealthLoop увидит оживший rx/handshake либо повторный DEAD → failover).
bool IosController::rebindTunnel()
{
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel)
        return false;
    if (tunnel.connection.status != NEVPNStatusConnected) {
        [tunnel release];
        return false;
    }
    NSString *actionKey = [NSString stringWithUTF8String:MessageKey::action];
    NSString *actionValue = [NSString stringWithUTF8String:Action::rebind];
    NSString *tunnelIdKey = [NSString stringWithUTF8String:MessageKey::tunnelId];
    NSString *tunnelIdValue = !m_tunnelId.isEmpty() ? m_tunnelId.toNSString() : @"";
    NSDictionary *message = @{actionKey : actionValue, tunnelIdKey : tunnelIdValue};
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // tunnel: наш retain отпускается в конце блока (паттерн checkStatus) — ответ-хендлер
        // менеджер не трогает, только лог.
        sendVpnExtensionMessage(tunnel, message, [](NSDictionary *response) {
            const bool ok = response && [response[@"ok"] boolValue];
            qInfo() << "IosController::rebindTunnel : extension replied" << (ok ? "ok" : "no/ignored");
        });
        [tunnel release];
    });
    return true;
}

void IosController::consumeNativeGuardResponse(NSDictionary *response)
{
    QJsonObject event;
    if (!strictNativeGuardEvent(response, event)) return;
    const QString operation = event.value(QStringLiteral("operation")).toString();
    const QString session = event.value(QStringLiteral("session")).toString();
    const QString policy = event.value(QStringLiteral("policy_sha256")).toString();
    const QString expected = event.value(
        QStringLiteral("expected_runtime_session_id")).toString();
    const QString kind = event.value(QStringLiteral("kind")).toString();
    const QString outer = event.value(QStringLiteral("outer_session_id")).toString();
    const bool pendingKind = kind == QLatin1String("armed")
                             || kind == QLatin1String("arm_rejected");
    const bool matchesPending = operation == m_pendingGuardOperation
                                && session == m_pendingGuardSession
                                && policy == m_pendingGuardPolicySha256
                                && expected == m_pendingGuardExpectedRuntimeSessionId;
    const bool matchesActive = operation == m_guardOperation && session == m_guardSession
                               && policy == m_guardPolicySha256
                               && expected == m_guardExpectedRuntimeSessionId;
    if (!matchesPending && !matchesActive && m_guardRecoveryUnresolved
        && m_pendingGuardOperation.isEmpty() && m_guardOperation.isEmpty()) {
        QMetaObject::invokeMethod(this, [this, event]() {
            m_guardRecoveryEvent = event;
            emit sessionGuardRecoveryRequired(event);
        }, Qt::QueuedConnection);
        return;
    }
    if ((pendingKind && !matchesPending && !matchesActive)
        || (!pendingKind && !matchesActive)) return;
    QMetaObject::invokeMethod(this, [this, event, kind, outer]() {
        if (kind == QLatin1String("armed")) {
            if (!m_pendingGuardOperation.isEmpty()) {
                m_guardOperation = m_pendingGuardOperation;
                m_guardSession = m_pendingGuardSession;
                m_guardPolicySha256 = m_pendingGuardPolicySha256;
                m_guardExpectedRuntimeSessionId = m_pendingGuardExpectedRuntimeSessionId;
                m_pendingGuardOperation.clear();
                m_pendingGuardSession.clear();
                m_pendingGuardPolicySha256.clear();
                m_pendingGuardExpectedRuntimeSessionId.clear();
            }
            m_guardReceiptArmed = true;
            m_guardOuterSessionId = outer;
        } else if (kind == QLatin1String("arm_rejected")) {
            m_pendingGuardOperation.clear();
            m_pendingGuardSession.clear();
            m_pendingGuardPolicySha256.clear();
            m_pendingGuardExpectedRuntimeSessionId.clear();
        } else if (kind == QLatin1String("released")
                   || kind == QLatin1String("lost")) {
            if (kind == QLatin1String("lost")) {
                m_guardRecoveryUnresolved = true;
                m_guardRecoveryEvent = event;
            }
            m_guardReceiptArmed = false;
            m_guardOuterSessionId.clear();
            m_guardOperation.clear();
            m_guardSession.clear();
            m_guardPolicySha256.clear();
            m_guardExpectedRuntimeSessionId.clear();
        }
        emit sessionGuardEvent(event);
        if (kind == QLatin1String("lost"))
            emit sessionGuardRecoveryRequired(event);
    }, Qt::QueuedConnection);
}

void IosController::requestCurrentNativeGuardStatus()
{
    NETunnelProviderManager *tunnel = retainedCurrentTunnel();
    if (!tunnel || tunnel.connection.status != NEVPNStatusConnected) {
        if (tunnel) [tunnel release];
        return;
    }
    sendVpnExtensionMessage(tunnel, @{@"action": @"native_guard_status_v1"},
        [this](NSDictionary *response) { consumeNativeGuardResponse(response); });
    [tunnel release];
}

void IosController::vpnStatusDidChange(void *pNotification)
{
    NETunnelProviderSession *session = (NETunnelProviderSession *)pNotification;

    if (!session) {
        return;
    }
    if (!m_currentTunnel || (NETunnelProviderSession *)m_currentTunnel.connection != session) {
        return;
    }

    qDebug() << "IosController::vpnStatusDidChange" << iosStatusToState(session.status) << session;

        if (session.status == NEVPNStatusDisconnected) {
            if (@available(iOS 16.0, *)) {
                [session fetchLastDisconnectErrorWithCompletionHandler:^(NSError * _Nullable error) {
                    if (error != nil) {
                        qDebug() << "Disconnect error" << error.domain << error.code << error.localizedDescription;

                        if ([error.domain isEqualToString:NEVPNConnectionErrorDomain]) {
                            switch (error.code) {
                                case NEVPNConnectionErrorOverslept:
                                    qDebug() << "Disconnect error info" << "The VPN connection was terminated because the system slept for an extended period of time.";
                                    break;
                                case NEVPNConnectionErrorNoNetworkAvailable:
                                    qDebug() << "Disconnect error info" << "The VPN connection could not be established because the system is not connected to a network.";
                                    break;
                                case NEVPNConnectionErrorUnrecoverableNetworkChange:
                                    qDebug() << "Disconnect error info" << "The VPN connection was terminated because the network conditions changed in such a way that the VPN connection could not be maintained.";
                                    break;
                                case NEVPNConnectionErrorConfigurationFailed:
                                    qDebug() << "Disconnect error info" << "The VPN connection could not be established because the configuration is invalid. ";
                                    break;
                                case NEVPNConnectionErrorServerAddressResolutionFailed:
                                    qDebug() << "Disconnect error info" << "The address of the VPN server could not be determined.";
                                    break;
                                case NEVPNConnectionErrorServerNotResponding:
                                    qDebug() << "Disconnect error info" << "Network communication with the VPN server has failed.";
                                    break;
                                case NEVPNConnectionErrorServerDead:
                                    qDebug() << "Disconnect error info" << "The VPN server is no longer functioning.";
                                    break;
                                case NEVPNConnectionErrorAuthenticationFailed:
                                    qDebug() << "Disconnect error info" << "The user credentials were rejected by the VPN server.";
                                    break;
                                case NEVPNConnectionErrorClientCertificateInvalid:
                                    qDebug() << "Disconnect error info" << "The client certificate is invalid.";
                                    break;
                                case NEVPNConnectionErrorClientCertificateNotYetValid:
                                    qDebug() << "Disconnect error info" << "The client certificate will not be valid until some future point in time.";
                                    break;
                                case NEVPNConnectionErrorClientCertificateExpired:
                                    qDebug() << "Disconnect error info" << "The validity period of the client certificate has passed.";
                                    break;
                                case NEVPNConnectionErrorPluginFailed:
                                    qDebug() << "Disconnect error info" << "The VPN plugin died unexpectedly.";
                                    break;
                                case NEVPNConnectionErrorConfigurationNotFound:
                                    qDebug() << "Disconnect error info" << "The VPN configuration could not be found.";
                                    break;
                                case NEVPNConnectionErrorPluginDisabled:
                                    qDebug() << "Disconnect error info" << "The VPN plugin could not be found or needed to be updated.";
                                    break;
                                case NEVPNConnectionErrorNegotiationFailed:
                                    qDebug() << "Disconnect error info" << "The VPN protocol negotiation failed.";
                                    break;
                                case NEVPNConnectionErrorServerDisconnected:
                                    qDebug() << "Disconnect error info" << "The VPN server terminated the connection.";
                                    break;
                                case NEVPNConnectionErrorServerCertificateInvalid:
                                    qDebug() << "Disconnect error info" << "The server certificate is invalid.";
                                    break;
                                case NEVPNConnectionErrorServerCertificateNotYetValid:
                                    qDebug() << "Disconnect error info" << "The server certificate will not be valid until some future point in time.";
                                    break;
                                case NEVPNConnectionErrorServerCertificateExpired:
                                    qDebug() << "Disconnect error info" << "The validity period of the server certificate has passed.";
                                    break;
                                default:
                                    qDebug() << "Disconnect error info" << "Unknown code.";
                                    break;
                            }
                        }

                        NSError *underlyingError = error.userInfo[@"NSUnderlyingError"];
                        if (underlyingError != nil) {
                            qDebug() << "Disconnect underlying error" << underlyingError.domain << underlyingError.code << underlyingError.localizedDescription;

                            if ([underlyingError.domain isEqualToString:@"NEAgentErrorDomain"]) {
                                switch (underlyingError.code) {
                                    case 1:
                                        qDebug() << "Disconnect underlying error" << "General. Use sysdiagnose.";
                                        break;
                                    case 2:
                                        qDebug() << "Disconnect underlying error" << "Plug-in unavailable. Use sysdiagnose.";
                                        break;
                                    default:
                                        qDebug() << "Disconnect underlying error" << "Unknown code. Use sysdiagnose.";
                                        break;
                                }
                            }
                        }
                    }
                }];
            } else {
                qDebug() << "Disconnect error is unavailable on iOS < 16.0";
            }
        }

        if (session.status == NEVPNStatusConnected
            && (!m_pendingGuardOperation.isEmpty() || !m_guardOperation.isEmpty())) {
            requestCurrentNativeGuardStatus();
        }

        if (session.status == NEVPNStatusDisconnected
            && !m_pendingAuthorityRenewalRequest.isEmpty()) {
            const QJsonObject rejected = rejectedRenewalReceipt(
                m_pendingAuthorityRenewalRequest,
                QStringLiteral("provider_disconnected"));
            m_pendingAuthorityRenewalRequest = {};
            emit runtimeAuthorityRenewalReceipt(rejected);
        }

        if (session.status == NEVPNStatusDisconnected
            && (!m_pendingGuardOperation.isEmpty() || !m_guardOperation.isEmpty())) {
            const bool active = m_guardReceiptArmed && !m_guardOperation.isEmpty();
            QJsonObject terminal{
                {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
                {QStringLiteral("schema"), 1},
                {QStringLiteral("operation"), active ? m_guardOperation
                                                       : m_pendingGuardOperation},
                {QStringLiteral("session"), active ? m_guardSession
                                                     : m_pendingGuardSession},
                {QStringLiteral("kind"), active
                    ? QStringLiteral("lost") : QStringLiteral("arm_rejected")},
                {QStringLiteral("policy_sha256"), active ? m_guardPolicySha256
                                                          : m_pendingGuardPolicySha256},
                {QStringLiteral("outer_session_id"), active
                    ? m_guardOuterSessionId : QString()},
                {QStringLiteral("expected_runtime_session_id"),
                    active ? m_guardExpectedRuntimeSessionId
                           : m_pendingGuardExpectedRuntimeSessionId},
                {QStringLiteral("reason"), QStringLiteral("provider_disconnected")},
            };
            m_guardReceiptArmed = false;
            m_guardOuterSessionId.clear();
            m_guardOperation.clear();
            m_guardSession.clear();
            m_guardPolicySha256.clear();
            m_guardExpectedRuntimeSessionId.clear();
            m_pendingGuardOperation.clear();
            m_pendingGuardSession.clear();
            m_pendingGuardPolicySha256.clear();
            m_pendingGuardExpectedRuntimeSessionId.clear();
            emit sessionGuardEvent(terminal);
        }

        // NEVPNStatusDisconnected is the OS-owned proof that this exact
        // provider session no longer owns a TUN. Publish its terminal receipt
        // before invalidating provider callbacks so a replacement cannot be
        // blocked waiting for a final poll that will never run.
        if (session.status == NEVPNStatusDisconnected
                && !m_runtimeSessionId.isEmpty()
                && m_runtimeStatus.value(QStringLiteral("type")).toString()
                        == QLatin1String("tunnel_runtime_status_v1")
                && schemaOne(m_runtimeStatus.value(QStringLiteral("schema")))
                && m_runtimeStatus.value(QStringLiteral("session_id")).toString()
                        == m_runtimeSessionId) {
            QJsonObject terminal = m_runtimeStatus;
            terminal.insert(QStringLiteral("runtime_state"), QStringLiteral("stopped"));
            terminal.insert(QStringLiteral("teardown_state"),
                            QStringLiteral("os_tunnel_disconnected"));
            m_runtimeStatus = terminal;
            emit runtimeStatusChanged(terminal);
        }

        Vpn::ConnectionState nextState = iosStatusToState(session.status);
        if (session.status == NEVPNStatusConnected && isWireGuardBasedProto(m_proto)) {
            if (!m_handshakeConfirmed) {
                nextState = Vpn::ConnectionState::Connecting;
                if (!m_handshakeAwaiting) {
                    m_handshakeAwaiting = true;
                    m_handshakeTimer.restart();
                    m_handshakeTimeouts = 0;
                }
            }
        } else if (session.status != NEVPNStatusConnected) {
            ++m_statusGeneration; // invalidate provider replies from the session being stopped/switched.
            m_handshakeAwaiting = false;
            m_handshakeConfirmed = false;
            m_handshakeTimer.invalidate();
            m_handshakeTimeouts = 0;
            m_statusRequestInFlight = false;
            m_counterEpoch.clear();
        }
        emitConnectionStateIfChanged(nextState);
}

void IosController::vpnConfigurationDidChange(void *pNotification)
{
    qDebug() << "IosController::vpnConfigurationDidChange" << pNotification;
    // AVPN (фикс краша «удалил VPN-конфиг в Настройках»): если наш менеджер удалён извне, дальше любое
    // обращение к m_currentTunnel.connection (checkStatus/start) — это разыменование удалённого объекта.
    // Проверяем актуальность; если наш менеджер пропал из системы — сбрасываем ссылку и стейт, чтобы
    // следующий connect пересоздал менеджер с нуля (как делают другие VPN-приложения — без краша).
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
        if (error)
            return;
        bool stillExists = false;
        for (NETunnelProviderManager *m in managers) {
            if (m == m_currentTunnel) { stillExists = true; break; }
        }
        if (!stillExists && m_currentTunnel) {
            qDebug() << "IosController::vpnConfigurationDidChange : our manager was removed externally — clearing";
            setCurrentTunnel(nil); // AVPN: release (менеджер удалён извне)
            m_handshakeConfirmed = false;
            m_handshakeAwaiting = false;
            m_handshakeTimer.invalidate();
            m_statusRequestInFlight = false;
            ++m_statusGeneration;
            m_counterEpoch.clear();
            m_lastEmittedState = Vpn::ConnectionState::Unknown;
            emit connectionStateChanged(Vpn::ConnectionState::Disconnected);
        }
    }];
}

bool IosController::setupOpenVPN()
{
    QJsonObject ovpn = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::OpenVpn)].toObject();
    QString ovpnConfig = ovpn[configKey::config].toString();

    QJsonObject openVPNConfig {};
    openVPNConfig.insert(configKey::config, ovpnConfig);

    if (ovpn.contains(configKey::mtu)) {
        openVPNConfig.insert(configKey::mtu, ovpn[configKey::mtu]);
    } else {
        openVPNConfig.insert(configKey::mtu, protocols::openvpn::defaultMtu);
    }

    openVPNConfig.insert(configKey::splitTunnelType, m_rawConfig[configKey::splitTunnelType]);

    QJsonArray splitTunnelSites = m_rawConfig[configKey::splitTunnelSites].toArray();

    for(int index = 0; index < splitTunnelSites.count(); index++) {
        splitTunnelSites[index] = splitTunnelSites[index].toString().remove(" ");
    }

    openVPNConfig.insert(configKey::splitTunnelSites, splitTunnelSites);

    QJsonDocument openVPNConfigDoc(openVPNConfig);
    QString openVPNConfigStr(openVPNConfigDoc.toJson(QJsonDocument::Compact));

    return startOpenVPN(openVPNConfigStr);
}

static void insertNonEmptyAwgParams(QJsonObject &wgConfig, const QJsonObject &config)
{
    const QStringList awgProtocolKeys = configKey::awgProtocolKeys();

    for (const QString &key : awgProtocolKeys) {
        const QJsonValue value = config.value(key);
        if (value.isString() && !value.toString().isEmpty()) {
            wgConfig.insert(key, value);
        }
    }
}

bool IosController::setupWireGuard()
{
    if (m_rawConfig.value(QStringLiteral("native_envelope_schema"))
            == QLatin1String("tribe_catalog_v2_native_v1")) {
        return startWireGuard(QString::fromUtf8(
                QJsonDocument(m_rawConfig).toJson(QJsonDocument::Compact)));
    }
    QJsonObject config = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::WireGuard)].toObject();

    QJsonObject wgConfig {};
    wgConfig.insert(configKey::dns1, m_rawConfig[configKey::dns1]);
    wgConfig.insert(configKey::dns2, m_rawConfig[configKey::dns2]);

    if (config.contains(configKey::mtu)) {
        wgConfig.insert(configKey::mtu, config[configKey::mtu]);
    } else {
        wgConfig.insert(configKey::mtu, protocols::wireguard::defaultMtu);
    }

    wgConfig.insert(configKey::hostName, config[configKey::hostName]);
    wgConfig.insert(configKey::port, config[configKey::port]);
    wgConfig.insert(configKey::clientIp, config[configKey::clientIp]);
    wgConfig.insert(configKey::clientPrivKey, config[configKey::clientPrivKey]);
    wgConfig.insert(configKey::serverPubKey, config[configKey::serverPubKey]);
    wgConfig.insert(configKey::pskKey, config[configKey::pskKey]);
    wgConfig.insert(configKey::splitTunnelType, m_rawConfig[configKey::splitTunnelType]);

    QJsonArray splitTunnelSites = m_rawConfig[configKey::splitTunnelSites].toArray();

    for(int index = 0; index < splitTunnelSites.count(); index++) {
        splitTunnelSites[index] = splitTunnelSites[index].toString().remove(" ");
    }

    wgConfig.insert(configKey::splitTunnelSites, splitTunnelSites);

    if (config.contains(configKey::allowedIps) && config[configKey::allowedIps].isArray()) {
        wgConfig.insert(configKey::allowedIps, config[configKey::allowedIps]);
    } else {
        QJsonArray allowed_ips { "0.0.0.0/0", "::/0" };
        wgConfig.insert(configKey::allowedIps, allowed_ips);
    }

    if (config.contains(configKey::persistentKeepAlive)) {
        wgConfig.insert(configKey::persistentKeepAlive, config[configKey::persistentKeepAlive]);
    }

    insertNonEmptyAwgParams(wgConfig, config);

    QJsonDocument wgConfigDoc(wgConfig);
    QString wgConfigDocStr(wgConfigDoc.toJson(QJsonDocument::Compact));

    return startWireGuard(wgConfigDocStr);
}

bool IosController::setupXray()
{
    if (m_rawConfig.value(QStringLiteral("native_envelope_schema"))
            == QLatin1String("tribe_catalog_v2_native_v1")) {
        return startXray(QString::fromUtf8(
                QJsonDocument(m_rawConfig).toJson(QJsonDocument::Compact)));
    }
    QJsonObject config = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::Xray)].toObject();
    QString xrayConfigStr = config.value(configKey::config).toString();

    QJsonObject finalConfig;
    finalConfig.insert(configKey::dns1, m_rawConfig[configKey::dns1].toString());
    finalConfig.insert(configKey::dns2, m_rawConfig[configKey::dns2].toString());
    finalConfig.insert(configKey::splitTunnelType, m_rawConfig[configKey::splitTunnelType]);

    QJsonArray splitTunnelSites = m_rawConfig[configKey::splitTunnelSites].toArray();

    for (int index = 0; index < splitTunnelSites.count(); index++) {
        splitTunnelSites[index] = splitTunnelSites[index].toString().remove(" ");
    }

    finalConfig.insert(configKey::splitTunnelSites, splitTunnelSites);
    finalConfig.insert(configKey::config, xrayConfigStr);
    // AVPN backend-first (Task 6): tun2socks connect/read-write timeouts + network-change reconnect
    // debounce, server-tunable via TuningStore (numbers.xray_connect_timeout_ms/xray_rw_timeout_ms/
    // network_change_debounce_ms). Fallbacks byte-for-byte match the pre-Task-6 NE literals
    // (setupAndRunTun2socks: 5000/60000; scheduleNetworkChangeHandling: 1000) — absent/offline ⇒
    // identical behavior. Decoded as optional Int? on the Swift side (XrayConfig).
    // Clamped: an operator typo (0/negative) in the backend config must not reach the NE — 0
    // connect-timeout would go into the tun2socks YAML as-is, 0/negative debounce would cause a
    // reconnect storm on a flapping network.
    finalConfig.insert(configKey::xrayConnectTimeoutMs,
                       qBound(100, int(avpn::TuningStore::numberOr(QStringLiteral("xray_connect_timeout_ms"), 5000)), 300000));
    finalConfig.insert(configKey::xrayRwTimeoutMs,
                       qBound(1000, int(avpn::TuningStore::numberOr(QStringLiteral("xray_rw_timeout_ms"), 60000)), 600000));
    finalConfig.insert(configKey::networkChangeDebounceMs,
                       qBound(200, int(avpn::TuningStore::numberOr(QStringLiteral("network_change_debounce_ms"), 1000)), 30000));
    // The embedded Go runtime must have a finite soft memory limit inside the
    // Network Extension.  Prefer the already-resolved per-connection value,
    // otherwise use the same backend-tunable 50 MiB default as Android.
    const qint64 xrayMemoryDefault = 50LL * 1024 * 1024;
    const qint64 xrayMemoryRequested = m_rawConfig.value(configKey::xrayMaxMemoryBytes).isDouble()
            ? m_rawConfig.value(configKey::xrayMaxMemoryBytes).toInteger(xrayMemoryDefault)
            : static_cast<qint64>(avpn::TuningStore::numberOr(QStringLiteral("xray_max_memory_bytes"),
                                                              static_cast<double>(xrayMemoryDefault)));
    finalConfig.insert(configKey::xrayMaxMemoryBytes,
                       qBound(16LL * 1024 * 1024, xrayMemoryRequested, 512LL * 1024 * 1024));

    QJsonDocument finalConfigDoc(finalConfig);
    QString finalConfigStr(finalConfigDoc.toJson(QJsonDocument::Compact));

    return startXray(finalConfigStr);
}

bool IosController::setupSSXray()
{
    QJsonObject config = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::SSXray)].toObject();
    QString ssXrayConfigStr = config.value(configKey::config).toString();

    QJsonObject finalConfig;
    finalConfig.insert(configKey::dns1, m_rawConfig[configKey::dns1]);
    finalConfig.insert(configKey::dns2, m_rawConfig[configKey::dns2]);
    finalConfig.insert(configKey::config, ssXrayConfigStr);
    // AVPN backend-first (Task 6): same tun2socks/network-change knobs as setupXray() above — SSXray
    // shares the same NE "xray" provider-configuration blob and XrayConfig Decodable on the Swift side.
    // Clamped for the same reason as setupXray(): operator typo (0/negative) must not reach the NE.
    finalConfig.insert(configKey::xrayConnectTimeoutMs,
                       qBound(100, int(avpn::TuningStore::numberOr(QStringLiteral("xray_connect_timeout_ms"), 5000)), 300000));
    finalConfig.insert(configKey::xrayRwTimeoutMs,
                       qBound(1000, int(avpn::TuningStore::numberOr(QStringLiteral("xray_rw_timeout_ms"), 60000)), 600000));
    finalConfig.insert(configKey::networkChangeDebounceMs,
                       qBound(200, int(avpn::TuningStore::numberOr(QStringLiteral("network_change_debounce_ms"), 1000)), 30000));
    const qint64 xrayMemoryDefault = 50LL * 1024 * 1024;
    const qint64 xrayMemoryRequested = m_rawConfig.value(configKey::xrayMaxMemoryBytes).isDouble()
            ? m_rawConfig.value(configKey::xrayMaxMemoryBytes).toInteger(xrayMemoryDefault)
            : static_cast<qint64>(avpn::TuningStore::numberOr(QStringLiteral("xray_max_memory_bytes"),
                                                              static_cast<double>(xrayMemoryDefault)));
    finalConfig.insert(configKey::xrayMaxMemoryBytes,
                       qBound(16LL * 1024 * 1024, xrayMemoryRequested, 512LL * 1024 * 1024));

    QJsonDocument finalConfigDoc(finalConfig);
    QString finalConfigStr(finalConfigDoc.toJson(QJsonDocument::Compact));

    return startXray(finalConfigStr);
}

bool IosController::setupAwg()
{
    if (m_rawConfig.value(QStringLiteral("native_envelope_schema"))
            == QLatin1String("tribe_catalog_v2_native_v1")) {
        return startWireGuard(QString::fromUtf8(
                QJsonDocument(m_rawConfig).toJson(QJsonDocument::Compact)));
    }
    QJsonObject config = m_rawConfig[ProtocolUtils::key_proto_config_data(amnezia::Proto::Awg)].toObject();

    QJsonObject wgConfig {};
    wgConfig.insert(configKey::dns1, m_rawConfig[configKey::dns1]);
    wgConfig.insert(configKey::dns2, m_rawConfig[configKey::dns2]);

    if (config.contains(configKey::mtu)) {
        wgConfig.insert(configKey::mtu, config[configKey::mtu]);
    } else {
        wgConfig.insert(configKey::mtu, protocols::awg::defaultMtu);
    }

    wgConfig.insert(configKey::hostName, config[configKey::hostName]);
    wgConfig.insert(configKey::port, config[configKey::port]);
    wgConfig.insert(configKey::clientIp, config[configKey::clientIp]);
    wgConfig.insert(configKey::clientPrivKey, config[configKey::clientPrivKey]);
    wgConfig.insert(configKey::serverPubKey, config[configKey::serverPubKey]);
    wgConfig.insert(configKey::pskKey, config[configKey::pskKey]);
    wgConfig.insert(configKey::splitTunnelType, m_rawConfig[configKey::splitTunnelType]);

    QJsonArray splitTunnelSites = m_rawConfig[configKey::splitTunnelSites].toArray();

    for(int index = 0; index < splitTunnelSites.count(); index++) {
        splitTunnelSites[index] = splitTunnelSites[index].toString().remove(" ");
    }

    wgConfig.insert(configKey::splitTunnelSites, splitTunnelSites);

    // AVPN split-DNS форвардер: корневые ключи cfg (VpnConnectionTunnelControl::up) → JSON для NE
    // (WGConfig.swift; значения — СТРОКИ). Отсутствуют = форвардер выключен.
    if (m_rawConfig.contains(QLatin1String("dnsFwdOn"))) {
        wgConfig.insert(QLatin1String("dnsFwdOn"), m_rawConfig[QLatin1String("dnsFwdOn")]);
        wgConfig.insert(QLatin1String("dnsFwdSuffixes"), m_rawConfig[QLatin1String("dnsFwdSuffixes")]);
        wgConfig.insert(QLatin1String("dnsFwdServer"), m_rawConfig[QLatin1String("dnsFwdServer")]);
    }

    if (config.contains(configKey::allowedIps) && config[configKey::allowedIps].isArray()) {
        wgConfig.insert(configKey::allowedIps, config[configKey::allowedIps]);
    } else {
        QJsonArray allowed_ips { "0.0.0.0/0", "::/0" };
        wgConfig.insert(configKey::allowedIps, allowed_ips);
    }

    if (config.contains(configKey::persistentKeepAlive)) {
        wgConfig.insert(configKey::persistentKeepAlive, config[configKey::persistentKeepAlive]);
    }

    insertNonEmptyAwgParams(wgConfig, config);

    QJsonDocument wgConfigDoc(wgConfig);
    QString wgConfigDocStr(wgConfigDoc.toJson(QJsonDocument::Compact));

    return startWireGuard(wgConfigDocStr);
}

bool IosController::startOpenVPN(const QString &config)
{
    qDebug() << "IosController::startOpenVPN";

    NETunnelProviderProtocol *tunnelProtocol = [[NETunnelProviderProtocol alloc] init];
    tunnelProtocol.providerBundleIdentifier = [NSString stringWithUTF8String:VPN_NE_BUNDLEID];
    QByteArray configUtf8 = config.toUtf8();
    NSData *ovpnConfigData = [NSData dataWithBytes:configUtf8.constData() length:configUtf8.size()];
    tunnelProtocol.providerConfiguration = @{@"ovpn": ovpnConfigData};
    tunnelProtocol.serverAddress = m_serverAddress;
    if (@available(iOS 14.0, macOS 11.0, *)) {
        int splitTunnelType = 0;
        QJsonParseError parseError;
        QJsonDocument doc = QJsonDocument::fromJson(config.toUtf8(), &parseError);
        if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
            QJsonObject obj = doc.object();
            splitTunnelType = obj.value(configKey::splitTunnelType).toInt(0);
        }
#if defined(MACOS_NE)
        // On macOS NE use route-based full tunnel. includeAllNetworks enables
        // policy-based drop-all mode and causes enforceRoutes to be ignored.
        tunnelProtocol.includeAllNetworks = NO;
        if (splitTunnelType == 0) {
            tunnelProtocol.enforceRoutes = YES;
            if (@available(iOS 14.2, macOS 11.0, *)) {
                tunnelProtocol.excludeLocalNetworks = YES;
            }
        }
#else
        tunnelProtocol.includeAllNetworks = (splitTunnelType == 0);
        if (@available(iOS 14.2, macOS 11.0, *)) {
            // Keep existing iOS behavior.
            if (splitTunnelType == 0) {
                tunnelProtocol.excludeLocalNetworks = NO;
            }
        }
#endif
    }

    m_currentTunnel.protocolConfiguration = tunnelProtocol;

    NETunnelProviderProtocol *appliedProtocol = (NETunnelProviderProtocol *)m_currentTunnel.protocolConfiguration;
    NSData *ovpnPayload = appliedProtocol.providerConfiguration[@"ovpn"];

    qDebug().noquote() << "IosController::startOpenVPN protocolConfiguration"
                       << "bundleId=" << QString::fromNSString(appliedProtocol.providerBundleIdentifier ?: @"")
                       << "serverAddress=" << QString::fromNSString(appliedProtocol.serverAddress ?: @"")
                       << "providerKeys=" << QString::fromNSString([[appliedProtocol.providerConfiguration.allKeys description] copy])
                       << "ovpnBytes=" << (ovpnPayload != nil ? ovpnPayload.length : 0);

    startTunnel();
    return true; // AVPN(N3): не было return — UB; результат сейчас игнорируется, но поток обязан вернуть значение
}

bool IosController::startWireGuard(const QString &config)
{
    qDebug() << "IosController::startWireGuard";

#if MACOS_NE
    // The optional legacy macOS NE target has no production Tribe vault
    // entitlement shared with the app. Never persist a bearer profile there;
    // the shipping macOS path is the authenticated privileged daemon.
    qWarning() << "IosController::startWireGuard : secure NE handoff unavailable on macOS";
    emit connectionStateChanged(Vpn::ConnectionState::Error);
    return false;
#else
    QJsonParseError parseError;
    QJsonDocument configDocument = QJsonDocument::fromJson(config.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !configDocument.isObject()) {
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return false;
    }
    QJsonObject envelope = configDocument.object();
    const QString schema = envelope.value(QStringLiteral("native_envelope_schema")).toString();
    if (schema.isEmpty()) {
        envelope.insert(QStringLiteral("native_envelope_schema"),
                        QStringLiteral("amnezia_legacy_native_v1"));
        envelope.insert(QStringLiteral("protocol"), QStringLiteral("awg"));
    } else if (schema != QLatin1String("tribe_catalog_v2_native_v1")
               && schema != QLatin1String("amnezia_legacy_native_v1")) {
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return false;
    }
    if (schema == QLatin1String("tribe_catalog_v2_native_v1")
            && envelope.value(QStringLiteral("protocol")) != QLatin1String("awg")) {
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return false;
    }
    const QByteArray configUtf8 = QJsonDocument(envelope).toJson(QJsonDocument::Compact);
    NSData *configData = [NSData dataWithBytes:configUtf8.constData() length:configUtf8.size()];
    NSString *sessionId = [[[NSUUID UUID] UUIDString] lowercaseString];
    NSString *reference = [TribeTunnelConfigVault stageConfig:configData
                                                 protocolName:@"awg"
                                                     sessionId:sessionId];
    if (!reference) {
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return false;
    }

    NETunnelProviderProtocol *tunnelProtocol = [[NETunnelProviderProtocol alloc] init];
    tunnelProtocol.providerBundleIdentifier = [NSString stringWithUTF8String:VPN_NE_BUNDLEID];
    tunnelProtocol.providerConfiguration = @{
        @"tribe_config_schema": @1,
        @"tribe_protocol": @"awg",
        @"tribe_config_ref": reference,
        @"guarded_inner_switch": @NO,
        @"tribe_session_id": sessionId,
    };
    tunnelProtocol.serverAddress = m_serverAddress;
    if (@available(iOS 14.0, *)) {
        const bool fullTunnel = envelope.value(configKey::splitTunnelType).toInt(0) == 0;
        const bool catalogV2 = schema == QLatin1String("tribe_catalog_v2_native_v1");
        tunnelProtocol.includeAllNetworks = fullTunnel;
        tunnelProtocol.excludeLocalNetworks = NO;
        // For signed include-split profiles the protected verifier/bootstrap host routes must
        // outrank local routes too. Exclude-split remains rejected inside the provider until
        // device readback proves disjoint CIDR semantics on the supported OS matrix.
        if (@available(iOS 14.2, *)) tunnelProtocol.enforceRoutes = fullTunnel || catalogV2;
    }
    m_expectedRuntimeSessionId = QString::fromNSString(sessionId);

    m_currentTunnel.protocolConfiguration = tunnelProtocol;

    startTunnel();
    return true; // AVPN(N3): не было return — UB; результат сейчас игнорируется, но поток обязан вернуть значение
#endif
}

bool IosController::startXray(const QString &config)
{
    qDebug() << "IosController::startXray";

#if MACOS_NE
    qWarning() << "IosController::startXray : secure NE handoff unavailable on macOS";
    emit connectionStateChanged(Vpn::ConnectionState::Error);
    return false;
#else
    QJsonParseError parseError;
    QJsonDocument configDocument = QJsonDocument::fromJson(config.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !configDocument.isObject()) {
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return false;
    }
    QJsonObject envelope = configDocument.object();
    const QString schema = envelope.value(QStringLiteral("native_envelope_schema")).toString();
    if (schema.isEmpty()) {
        envelope.insert(QStringLiteral("native_envelope_schema"),
                        QStringLiteral("amnezia_legacy_native_v1"));
        envelope.insert(QStringLiteral("protocol"), QStringLiteral("xray"));
    } else if (schema != QLatin1String("tribe_catalog_v2_native_v1")
               && schema != QLatin1String("amnezia_legacy_native_v1")) {
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return false;
    }
    if (schema == QLatin1String("tribe_catalog_v2_native_v1")
            && envelope.value(QStringLiteral("protocol")) != QLatin1String("xray")) {
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return false;
    }
    const QByteArray configUtf8 = QJsonDocument(envelope).toJson(QJsonDocument::Compact);
    NSData *configData = [NSData dataWithBytes:configUtf8.constData() length:configUtf8.size()];
    NSString *sessionId = [[[NSUUID UUID] UUIDString] lowercaseString];
    NSString *reference = [TribeTunnelConfigVault stageConfig:configData
                                                 protocolName:@"xray"
                                                     sessionId:sessionId];
    if (!reference) {
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return false;
    }

    NETunnelProviderProtocol *tunnelProtocol = [[NETunnelProviderProtocol alloc] init];
    tunnelProtocol.providerBundleIdentifier = [NSString stringWithUTF8String:VPN_NE_BUNDLEID];
    tunnelProtocol.providerConfiguration = @{
        @"tribe_config_schema": @1,
        @"tribe_protocol": @"xray",
        @"tribe_config_ref": reference,
        @"guarded_inner_switch": @NO,
        @"tribe_session_id": sessionId,
    };
    tunnelProtocol.serverAddress = m_serverAddress;
    if (@available(iOS 14.0, *)) {
        const bool fullTunnel = envelope.value(configKey::splitTunnelType).toInt(0) == 0;
        const bool catalogV2 = schema == QLatin1String("tribe_catalog_v2_native_v1");
        tunnelProtocol.includeAllNetworks = fullTunnel;
        tunnelProtocol.excludeLocalNetworks = NO;
        if (@available(iOS 14.2, *)) tunnelProtocol.enforceRoutes = fullTunnel || catalogV2;
    }
    m_expectedRuntimeSessionId = QString::fromNSString(sessionId);

    m_currentTunnel.protocolConfiguration = tunnelProtocol;

    startTunnel();
    return true; // AVPN(N3): не было return — UB; результат сейчас игнорируется, но поток обязан вернуть значение
#endif
}

void IosController::startTunnel()
{
    startTunnel(nil);
}

void IosController::startTunnel(NSDictionary *options)
{
    // AVPN (фикс краша): без менеджера дальше идёт nil-разыменование (m_currentTunnel.protocolConfiguration
    // и т.д.). Бывает при teardown→reconnect (rotateNext) и при удалённом в Настройках iOS VPN-конфиге.
    if (!m_currentTunnel) {
        qDebug() << "IosController::startTunnel : no current tunnel manager";
        emit connectionStateChanged(Vpn::ConnectionState::Error);
        return;
    }
    NSString *protocolName = @"Unknown";

    NETunnelProviderProtocol *tunnelProtocol = (NETunnelProviderProtocol *)m_currentTunnel.protocolConfiguration;
    NSString *tribeProtocol = [tunnelProtocol.providerConfiguration[@"tribe_protocol"]
            isKindOfClass:[NSString class]] ? tunnelProtocol.providerConfiguration[@"tribe_protocol"] : nil;
    NSString *stagedReference = [tunnelProtocol.providerConfiguration[@"tribe_config_ref"]
            isKindOfClass:[NSString class]] ? tunnelProtocol.providerConfiguration[@"tribe_config_ref"] : nil;
    if ([tribeProtocol isEqualToString:@"awg"]) {
        protocolName = @"AWG";
    } else if ([tribeProtocol isEqualToString:@"xray"]) {
        protocolName = @"Xray";
    } else if (tunnelProtocol.providerConfiguration[@"ovpn"] != nil) {
        protocolName = @"OpenVPN";
    }

    m_rxBytes = 0;
    m_txBytes = 0;

    NETunnelProviderManager *tunnel = m_currentTunnel;
    NSDictionary *startOptions = [[options copy] autorelease];
    [tunnel setEnabled:YES];

    dispatch_async(dispatch_get_main_queue(), ^{
        [tunnel saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (saveError) {
#if !MACOS_NE
                    if (stagedReference) [TribeTunnelConfigVault discardReference:stagedReference];
#endif
                    qDebug().nospace() << "IosController::startTunnel" << protocolName << ": Connect " << protocolName
                                       << " Tunnel Save Error" << saveError.localizedDescription.UTF8String << " domain:"
                                       << saveError.domain.UTF8String << " code:" << saveError.code;
                    emit connectionStateChanged(Vpn::ConnectionState::Error);
                    return;
                }

                [tunnel loadFromPreferencesWithCompletionHandler:^(NSError *loadError) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        if (loadError) {
#if !MACOS_NE
                            if (stagedReference) [TribeTunnelConfigVault discardReference:stagedReference];
#endif
                            qDebug().nospace() << "IosController::startTunnel :" << tunnel.localizedDescription << protocolName
                                               << ": Connect " << protocolName << " Tunnel Load Error"
                                               << loadError.localizedDescription.UTF8String;
                            emit connectionStateChanged(Vpn::ConnectionState::Error);
                            return;
                        }

                        // AVPN: ПРЯМОЙ старт (как ванильная Amnezia). Гейт-ожидание здесь ломало ПЕРВЫЙ
                        // коннект (свежий менеджер в переходном статусе → stopTunnel → «сброс»). Гарантию
                        // «не стартовать поверх живого туннеля» даём РАНЬШЕ: ждём РЕАЛЬНОГО Disconnected
                        // перед connectVpn нового сервера (disconnectVpn + vpnConnection iOS-ветка).
                        NSError *startError = nil;
                        BOOL started = [tunnel.connection
                            startVPNTunnelWithOptions:startOptions andReturnError:&startError];
                        if (!started || startError) {
#if !MACOS_NE
                            if (stagedReference) [TribeTunnelConfigVault discardReference:stagedReference];
#endif
                            qDebug().nospace() << "IosController::startTunnel :" << tunnel.localizedDescription << protocolName
                                               << " : Tunnel Start Error"
                                               << (startError ? startError.localizedDescription.UTF8String : "");
                            emit connectionStateChanged(Vpn::ConnectionState::Error);
                        } else {
                            qDebug().nospace() << "IosController::startTunnel :" << tunnel.localizedDescription << protocolName
                                               << " : started ok";
                        }
                    });
                }];
            });
        }];
    });
}

bool IosController::isOurManager(NETunnelProviderManager* manager) {
    NETunnelProviderProtocol* tunnelProto = (NETunnelProviderProtocol*)manager.protocolConfiguration;

    if (!tunnelProto) {
        qDebug() << "Ignoring manager because the proto is invalid";
        return false;
    }

    if (!tunnelProto.providerBundleIdentifier) {
        qDebug() << "Ignoring manager because the bundle identifier is null";
        return false;
    }

    if (![tunnelProto.providerBundleIdentifier isEqualToString:[NSString stringWithUTF8String:VPN_NE_BUNDLEID]]) {
        qDebug() << "Ignoring manager because the bundle identifier doesn't match";
        return false;
    }

    qDebug() << "Found the manager with the correct bundle identifier:" << QString::fromNSString(tunnelProto.providerBundleIdentifier);

    return true;
}

void IosController::sendVpnExtensionMessage(NETunnelProviderManager *tunnel, NSDictionary* message,
                                            std::function<void(NSDictionary*)> callback)
{
    // AVPN (ревью 2026-07-11): менеджер приходит retained-копией от вызывающего (checkStatus) —
    // ivar m_currentTunnel с фоновой очереди НЕ читаем (гонка с release на главном треде).
    if (!tunnel) {
        qDebug() << "Cannot set an extension callback without a tunnel manager";
        if (callback) {
            callback(nil);
        }
        return;
    }

    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:message options:0 error:&error];

    if (!data || error) {
        qDebug() << "Failed to serialize message to VpnExtension as JSON. Error:"
                 << [error.localizedDescription UTF8String];
        if (callback) {
            callback(nil);
        }
        return;
    }

    void (^completionHandler)(NSData *) = ^(NSData *responseData) {
        if (!responseData) {
            if (callback) callback(nil);
            return;
        }

        NSError *deserializeError = nil;
        NSDictionary *response = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:&deserializeError];

        if (response && [response isKindOfClass:[NSDictionary class]]) {
            if (callback) callback(response);
            return;
        } else if (deserializeError) {
            qDebug() << "Failed to deserialize the VpnExtension response";
        }

        if (callback) callback(nil);
    };

    NETunnelProviderSession *session = (NETunnelProviderSession *)tunnel.connection;

    NSError *sendError = nil;

    if ([session respondsToSelector:@selector(sendProviderMessage:returnError:responseHandler:)]) {
        [session sendProviderMessage:data returnError:&sendError responseHandler:completionHandler];
    } else {
        qDebug() << "Method sendProviderMessage:responseHandler:error: does not exist";
        if (callback) {
            callback(nil);
        }
        return;
    }

    if (sendError) {
        qDebug() << "Failed to send message to VpnExtension. Error:"
                 << [sendError.localizedDescription UTF8String];
        if (callback) {
            callback(nil);
        }
    }

}

bool IosController::shareText(const QStringList& filesToSend) {
    NSMutableArray *sharingItems = [NSMutableArray new];

    for (int i = 0; i < filesToSend.size(); i++) {
        NSURL *logFileUrl = [[NSURL alloc] initFileURLWithPath:filesToSend[i].toNSString()];
        [sharingItems addObject:logFileUrl];
    }
#if !MACOS_NE
    UIViewController *qtController = getViewController();
    if (!qtController) {
        return false;
    }

    UIActivityViewController *activityController = [[UIActivityViewController alloc] initWithActivityItems:sharingItems applicationActivities:nil];
#endif
    __block bool isAccepted = false;
#if !MACOS_NE
    [activityController setCompletionWithItemsHandler:^(NSString *activityType, BOOL completed, NSArray *returnedItems, NSError *activityError) {
        isAccepted = completed;
        emit finished();
    }];

    [qtController presentViewController:activityController animated:YES completion:nil];
    UIPopoverPresentationController *popController = activityController.popoverPresentationController;
    if (popController) {
        popController.sourceView = qtController.view;
        popController.sourceRect = CGRectMake(100, 100, 100, 100);
    }

#endif
    QEventLoop wait;
    QObject::connect(this, &IosController::finished, &wait, &QEventLoop::quit);
    wait.exec();

    return isAccepted;
}

QString IosController::openFile() {
#if !MACOS_NE
    UIDocumentPickerViewController *documentPicker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.item"] inMode:UIDocumentPickerModeOpen];

    DocumentPickerDelegate *documentPickerDelegate = [[DocumentPickerDelegate alloc] init];
    documentPicker.delegate = documentPickerDelegate;

    UIViewController *qtController = getViewController();
    if (!qtController) return QString(); // AVPN(N3): был голый return в QString-функции

    [qtController presentViewController:documentPicker animated:YES completion:nil];

#endif
    __block QString filePath;
#if !MACOS_NE
    documentPickerDelegate.documentPickerClosedCallback = ^(NSString *path) {
        if (path) {
            filePath = QString::fromUtf8(path.UTF8String);
        } else {
            filePath = QString();
        }
        emit finished();
    };
#endif
    QEventLoop wait;
    QObject::connect(this, &IosController::finished, &wait, &QEventLoop::quit);
    wait.exec();

    return filePath;
}

#if 0 // Replaced below by the upstream StoreKit2 bridge; kept out of the build during migration.
void IosController::purchaseProduct(const QString &productId,
                                   std::function<void(bool success,
                                                      const QString &transactionId,
                                                      const QString &purchasedProductId,
                                                      const QString &originalTransactionId,
                                                      const QString &errorString)> &&callback)
{
    qInfo().noquote() << "[IAP][IosController] purchaseProduct called" << productId;
    if (@available(iOS 15.0, macOS 12.0, *)) {
        StoreKitController *controller = [StoreKitController sharedInstance];
        __block auto cb = std::move(callback);
        [controller purchaseProduct:productId.toNSString() completion:^(BOOL s,
                                                                        NSString * _Nullable transactionId,
                                                                        NSString * _Nullable prodId,
                                                                        NSString * _Nullable originalTxId,
                                                                        NSError * _Nullable error) {
            const QString txId = QString::fromUtf8((transactionId ?: @"").UTF8String);
            const QString pId  = QString::fromUtf8((prodId        ?: @"").UTF8String);
            const QString origTxId = QString::fromUtf8((originalTxId ?: @"").UTF8String);
            const QString err  = QString::fromUtf8((error.localizedDescription ?: @"").UTF8String);

            qInfo().noquote() << "[IAP][IosController] purchase completion" << "success=" << s
                              << "transactionId=" << txId << "originalTransactionId=" << origTxId
                              << "productId=" << pId << "error=" << err;

            if (cb) {
                cb(s, txId, pId, origTxId, err);
            }
        }];
    } else {
        if (callback) {
            callback(false, QString(), QString(), QString(), "StoreKit 2 requires iOS 15.0 or later");
        }
    }
}

void IosController::restorePurchases(std::function<void(bool success,
                                                       const QList<QVariantMap> &transactions,
                                                       const QString &errorString)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        StoreKitController *controller = [StoreKitController sharedInstance];
        __block auto cb = std::move(callback);
        [controller restorePurchasesWithCompletion:^(BOOL s,
                                                     NSArray<NSDictionary *> * _Nullable restoredTransactions,
                                                     NSError * _Nullable error) {
            QString err;
            if (error) {
                err = QString::fromUtf8(error.localizedDescription.UTF8String);
            }
            QList<QVariantMap> transactions;
            for (NSDictionary *dict in restoredTransactions ?: @[]) {
                QVariantMap transaction;
                NSString *transactionId = dict[@"transactionId"];
                NSString *productId = dict[@"productId"];
                NSString *originalTransactionId = dict[@"originalTransactionId"];

                if (transactionId) {
                    transaction.insert(QStringLiteral("transactionId"), QString::fromUtf8(transactionId.UTF8String));
                }
                if (productId) {
                    transaction.insert(QStringLiteral("productId"), QString::fromUtf8(productId.UTF8String));
                }
                if (originalTransactionId) {
                    transaction.insert(QStringLiteral("originalTransactionId"),
                                       QString::fromUtf8(originalTransactionId.UTF8String));
                }
                transactions.push_back(transaction);
            }
            if (cb) {
                cb(s, transactions, err);
            }
        }];
    } else {
        if (callback) {
            callback(false, QList<QVariantMap>(), "StoreKit 2 requires iOS 15.0 or later");
        }
    }
}

void IosController::fetchProducts(const QStringList &productIds,
                                  std::function<void(const QList<QVariantMap> &products,
                                                     const QStringList &invalidIds,
                                                     const QString &errorString)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        StoreKitController *controller = [StoreKitController sharedInstance];
        NSMutableSet<NSString *> *ids = [NSMutableSet setWithCapacity:productIds.size()];
        for (const auto &pid : productIds) {
            [ids addObject:pid.toNSString()];
        }
        __block auto cb = std::move(callback);

        [controller fetchProductsWithIdentifiers:ids
                                      completion:^(NSArray<NSDictionary *> * _Nonnull products,
                                                   NSArray<NSString *> * _Nonnull invalidIdentifiers,
                                                   NSError * _Nullable error) {
            QList<QVariantMap> outProducts;
            for (NSDictionary *productInfo in products) {
                QVariantMap productData;
                productData["productId"] = QString::fromUtf8([productInfo[@"productId"] UTF8String]);
                productData["title"] = QString::fromUtf8([productInfo[@"title"] UTF8String]);
                productData["description"] = QString::fromUtf8([productInfo[@"description"] UTF8String]);
                productData["price"] = QString::fromUtf8([productInfo[@"price"] UTF8String]);
                if (productInfo[@"displayPrice"]) {
                    productData["displayPrice"] = QString::fromUtf8([productInfo[@"displayPrice"] UTF8String]);
                }
                productData["currencyCode"] = QString::fromUtf8([productInfo[@"currencyCode"] UTF8String]);
                if (productInfo[@"priceAmount"]) {
                    productData["priceAmount"] = [productInfo[@"priceAmount"] doubleValue];
                }
                if (productInfo[@"subscriptionBillingMonths"]) {
                    productData["subscriptionBillingMonths"] = [productInfo[@"subscriptionBillingMonths"] doubleValue];
                }
                if (productInfo[@"displayPricePerMonth"]) {
                    productData["displayPricePerMonth"] = QString::fromUtf8([productInfo[@"displayPricePerMonth"] UTF8String]);
                }
                outProducts.push_back(productData);
            }

            QStringList invalid;
            for (NSString *inv in invalidIdentifiers) {
                invalid.push_back(QString::fromUtf8(inv.UTF8String));
            }

            QString err;
            if (error) {
                err = QString::fromUtf8(error.localizedDescription.UTF8String);
            }

            if (cb) {
                cb(outProducts, invalid, err);
            }
        }];
    } else {
        if (callback) {
            callback(QList<QVariantMap>(), QStringList(), "StoreKit 2 requires iOS 15.0 or later");
        }
    }
}

#endif

namespace {
constexpr int storeKitErrorCodeCancelled = 1;
constexpr int storeKitErrorCodePending = 2;

IosController::StorePurchaseFailure storePurchaseFailureFromError(NSError *error)
{
    if (!error || ![error.domain isEqualToString:@"StoreKit2Helper"])
        return IosController::StorePurchaseFailure::Other;
    switch (error.code) {
    case storeKitErrorCodeCancelled: return IosController::StorePurchaseFailure::Cancelled;
    case storeKitErrorCodePending: return IosController::StorePurchaseFailure::Pending;
    default: return IosController::StorePurchaseFailure::Other;
    }
}

QVariantMap toTransactionMap(NSDictionary *dict)
{
    QVariantMap transaction;
    for (NSString *key in @[@"transactionId", @"originalTransactionId", @"productId",
                            @"environment"]) {
        NSString *value = dict[key];
        if (value)
            transaction.insert(QString::fromUtf8(key.UTF8String),
                               QString::fromUtf8(value.UTF8String));
    }
    return transaction;
}

QList<QVariantMap> toTransactionList(NSArray<NSDictionary *> *transactions)
{
    QList<QVariantMap> list;
    for (NSDictionary *dict in transactions ?: @[])
        list.push_back(toTransactionMap(dict));
    return list;
}
}

void IosController::purchaseProduct(
    const QString &productId,
    std::function<void(bool, const QString &, const QString &, const QString &, const QString &,
                       const QString &, StorePurchaseFailure)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        __block auto cb = std::move(callback);
        [[StoreKit2Helper shared] purchaseProductWithProductIdentifier:productId.toNSString()
            completion:^(BOOL success, NSString *transactionId, NSString *purchasedProductId,
                         NSString *originalTransactionId, NSString *environment, NSError *error) {
                const StorePurchaseFailure reason = success
                    ? StorePurchaseFailure::Other : storePurchaseFailureFromError(error);
                if (cb) {
                    cb(success,
                       QString::fromUtf8((transactionId ?: @"").UTF8String),
                       QString::fromUtf8((purchasedProductId ?: @"").UTF8String),
                       QString::fromUtf8((originalTransactionId ?: @"").UTF8String),
                       QString::fromUtf8((environment ?: @"").UTF8String),
                       QString::fromUtf8((error.localizedDescription ?: @"").UTF8String),
                       reason);
                }
            }];
    } else if (callback) {
        callback(false, {}, {}, {}, {}, QStringLiteral("StoreKit 2 requires iOS 15.0 or later"),
                 StorePurchaseFailure::Other);
    }
}

void IosController::finishStoreTransaction(const QString &transactionId)
{
    if (transactionId.isEmpty()) return;
    if (@available(iOS 15.0, macOS 12.0, *)) {
        [[StoreKit2Helper shared] finishTransactionWithTransactionId:transactionId.toNSString()
            completion:^(BOOL finished) {
                if (!finished)
                    qWarning() << "StoreKit transaction was not found in the unfinished queue";
            }];
    }
}

void IosController::startStoreTransactionObserver()
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        [[StoreKit2Helper shared] startTransactionUpdatesListenerWithHandler:
            ^(NSDictionary *transaction) { emit storeTransactionUpdated(toTransactionMap(transaction)); }];
    }
}

void IosController::restorePurchases(
    std::function<void(bool, const QList<QVariantMap> &, const QString &)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        __block auto cb = std::move(callback);
        [[StoreKit2Helper shared] fetchCurrentEntitlementsWithCompletion:
            ^(BOOL success, NSArray<NSDictionary *> *transactions, NSError *error) {
                if (cb) cb(success, toTransactionList(transactions),
                           QString::fromUtf8((error.localizedDescription ?: @"").UTF8String));
            }];
    } else if (callback) {
        callback(false, {}, QStringLiteral("StoreKit 2 requires iOS 15.0 or later"));
    }
}

void IosController::fetchLocalEntitlements(
    std::function<void(bool, const QList<QVariantMap> &, const QString &)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        __block auto cb = std::move(callback);
        [[StoreKit2Helper shared] fetchLocalEntitlementsWithCompletion:
            ^(BOOL success, NSArray<NSDictionary *> *transactions, NSError *error) {
                if (cb) cb(success, toTransactionList(transactions),
                           QString::fromUtf8((error.localizedDescription ?: @"").UTF8String));
            }];
    } else if (callback) {
        callback(false, {}, QStringLiteral("StoreKit 2 requires iOS 15.0 or later"));
    }
}

void IosController::fetchProducts(
    const QStringList &productIds,
    std::function<void(const QList<QVariantMap> &, const QStringList &, const QString &)> &&callback)
{
    if (@available(iOS 15.0, macOS 12.0, *)) {
        NSMutableSet<NSString *> *ids = [NSMutableSet setWithCapacity:productIds.size()];
        for (const QString &id : productIds) [ids addObject:id.toNSString()];
        __block auto cb = std::move(callback);
        [[StoreKit2Helper shared] fetchProductsWithIdentifiers:ids
            completion:^(NSArray<NSDictionary *> *products, NSArray<NSString *> *invalidIds,
                         NSError *error) {
                QList<QVariantMap> result;
                for (NSDictionary *info in products) {
                    QVariantMap product;
                    for (NSString *key in @[@"productId", @"title", @"description", @"price",
                                            @"displayPrice", @"currencyCode",
                                            @"displayPricePerMonth", @"introOfferDisplayPrice",
                                            @"introOfferPaymentMode"]) {
                        if (NSString *value = info[key])
                            product[QString::fromUtf8(key.UTF8String)] =
                                QString::fromUtf8(value.UTF8String);
                    }
                    for (NSString *key in @[@"priceAmount", @"subscriptionBillingMonths",
                                            @"trialDays"]) {
                        if (NSNumber *value = info[key])
                            product[QString::fromUtf8(key.UTF8String)] = value.doubleValue;
                    }
                    if (NSNumber *value = info[@"hasFreeTrial"])
                        product[QStringLiteral("hasFreeTrial")] = value.boolValue;
                    result.push_back(product);
                }
                QStringList invalid;
                for (NSString *id in invalidIds)
                    invalid.push_back(QString::fromUtf8(id.UTF8String));
                if (cb) cb(result, invalid,
                           QString::fromUtf8((error.localizedDescription ?: @"").UTF8String));
            }];
    } else if (callback) {
        callback({}, {}, QStringLiteral("StoreKit 2 requires iOS 15.0 or later"));
    }
}

void IosController::requestInetAccess() {
    NSURL *url = [NSURL URLWithString:@"http://captive.apple.com/generate_204"];
    if (!url) {
        qDebug() << "IosController::requestInetAccess URL error";
        return;
    }

    NSURLSession *session = [NSURLSession sharedSession];
    NSURLSessionDataTask *task = [session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            qDebug() << "IosController::requestInetAccess error:" << error.localizedDescription;
        } else {
            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
            QString responseBody = QString::fromUtf8((const char*)data.bytes, data.length);
        }
    }];
    [task resume];
}

bool IosController::isTestFlight() {
    NSURL *receiptURL = [[NSBundle mainBundle] appStoreReceiptURL];
    return receiptURL && [[receiptURL lastPathComponent] isEqualToString:@"sandboxReceipt"];
}

#if !MACOS_NE
static UIWindow *s_updateCoverWindow = nil;

static UIWindowScene *activeWindowScene() {
    UIWindowScene *fallback = nil;
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        fallback = (UIWindowScene *)scene;
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            return (UIWindowScene *)scene;
        }
    }
    return fallback;
}
#endif

void IosController::showUpdateCover() {
#if !MACOS_NE
    void (^build)(void) = ^{
        if (s_updateCoverWindow) {
            return;
        }
        UIWindowScene *scene = activeWindowScene();
        if (!scene) {
            return;
        }
        UIWindow *win = [[UIWindow alloc] initWithWindowScene:scene];
        win.windowLevel = UIWindowLevelAlert + 1;
        UIViewController *vc = [[[UIViewController alloc] init] autorelease];
        vc.view.backgroundColor = [UIColor colorWithRed:0.055 green:0.055 blue:0.063 alpha:1.0];
        win.rootViewController = vc;
        [win makeKeyAndVisible];
        s_updateCoverWindow = win;
    };

    if ([NSThread isMainThread]) {
        build();
    } else {
        dispatch_sync(dispatch_get_main_queue(), build);
    }
#endif
}

void IosController::hideUpdateCover() {
#if !MACOS_NE
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!s_updateCoverWindow) {
            return;
        }
        s_updateCoverWindow.hidden = YES;
        [s_updateCoverWindow release];
        s_updateCoverWindow = nil;
    });
#endif
}

void IosController::showUpdatePrompt(const QString &title, const QString &message, const QString &updateTitle,
                                     const QString &skipTitle, const QString &storeUrl) {
#if !MACOS_NE
    NSString *nsTitle = title.toNSString();
    NSString *nsMessage = message.toNSString();
    NSString *nsUpdate = updateTitle.toNSString();
    NSString *nsSkip = skipTitle.toNSString();
    NSString *nsUrl = storeUrl.toNSString();

    dispatch_async(dispatch_get_main_queue(), ^{
        if (!s_updateCoverWindow) {
            return;
        }
        UIViewController *vc = s_updateCoverWindow.rootViewController;

        void (^dismissCover)(void) = ^{
            s_updateCoverWindow.hidden = YES;
            [s_updateCoverWindow release];
            s_updateCoverWindow = nil;
        };

        UILabel *titleLabel = [[[UILabel alloc] init] autorelease];
        titleLabel.text = nsTitle;
        titleLabel.font = [UIFont boldSystemFontOfSize:22];
        titleLabel.textColor = [UIColor whiteColor];
        titleLabel.textAlignment = NSTextAlignmentCenter;
        titleLabel.numberOfLines = 0;

        UILabel *messageLabel = [[[UILabel alloc] init] autorelease];
        messageLabel.text = nsMessage;
        messageLabel.font = [UIFont systemFontOfSize:16];
        messageLabel.textColor = [UIColor colorWithWhite:0.78 alpha:1.0];
        messageLabel.textAlignment = NSTextAlignmentCenter;
        messageLabel.numberOfLines = 0;

        UIButton *updateButton = [UIButton buttonWithType:UIButtonTypeSystem];
        [updateButton setTitle:nsUpdate forState:UIControlStateNormal];
        [updateButton setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
        updateButton.backgroundColor = [UIColor colorWithRed:1.0 green:0.6 blue:0.0 alpha:1.0];
        updateButton.titleLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightSemibold];
        updateButton.layer.cornerRadius = 12;
        [updateButton.heightAnchor constraintEqualToConstant:52].active = YES;
        [updateButton addAction:[UIAction actionWithHandler:^(__kindof UIAction *action) {
            NSURL *url = [NSURL URLWithString:nsUrl];
            if (url) {
                [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
            }
            dismissCover();
        }] forControlEvents:UIControlEventTouchUpInside];

        UIButton *skipButton = [UIButton buttonWithType:UIButtonTypeSystem];
        [skipButton setTitle:nsSkip forState:UIControlStateNormal];
        [skipButton setTitleColor:[UIColor colorWithWhite:0.7 alpha:1.0] forState:UIControlStateNormal];
        skipButton.titleLabel.font = [UIFont systemFontOfSize:17];
        [skipButton.heightAnchor constraintEqualToConstant:44].active = YES;
        [skipButton addAction:[UIAction actionWithHandler:^(__kindof UIAction *action) {
            dismissCover();
        }] forControlEvents:UIControlEventTouchUpInside];

        UIStackView *stack = [[[UIStackView alloc] initWithArrangedSubviews:@[titleLabel, messageLabel, updateButton, skipButton]] autorelease];
        stack.axis = UILayoutConstraintAxisVertical;
        stack.spacing = 16;
        stack.translatesAutoresizingMaskIntoConstraints = NO;
        [stack setCustomSpacing:28 afterView:messageLabel];
        [vc.view addSubview:stack];

        [NSLayoutConstraint activateConstraints:@[
            [stack.centerYAnchor constraintEqualToAnchor:vc.view.centerYAnchor],
            [stack.leadingAnchor constraintEqualToAnchor:vc.view.leadingAnchor constant:32],
            [stack.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor constant:-32]
        ]];
    });
#else
    Q_UNUSED(title) Q_UNUSED(message) Q_UNUSED(updateTitle) Q_UNUSED(skipTitle) Q_UNUSED(storeUrl)
#endif
}
