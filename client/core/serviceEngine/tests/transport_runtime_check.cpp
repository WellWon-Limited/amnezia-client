#include "../ConnectionReducer.h"
#include "../NativeProfileCompiler.h"
#include "../NativeConnectionPolicy.h"
#include "../NativeDispatchPolicyDigest.h"
#include "../NativeRuntimeIdentity.h"

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QUuid>

#include <cstdio>
#include <algorithm>
#include <utility>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;
#define CHECK(expr) do { ++g_total; if (!(expr)) { ++g_failed; \
    fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr); } } while (0)

static QByteArray fixtureBytes(const QString &name)
{
    QFile file(QFileInfo(QString::fromUtf8(__FILE__)).absolutePath()
               + QStringLiteral("/fixtures/") + name);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll().trimmed();
}

static QString key32(char fill)
{
    return QString::fromLatin1(QByteArray(32, fill).toBase64());
}

static QString key32Url(char fill)
{
    return QString::fromLatin1(QByteArray(32, fill).toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

static CatalogCandidate awgCandidate(const QString &id = QStringLiteral("fi-awg"))
{
    CatalogCandidate candidate;
    candidate.locationId = QStringLiteral("fi-hel");
    candidate.locationCountry = QStringLiteral("FI");
    candidate.profileId = id;
    candidate.transport = TransportKind::Awg;
    candidate.profileKind = QStringLiteral("awg31");
    candidate.failureDomain = QStringLiteral("provider-a/asn-a/host-a");
    candidate.serverHealth = 0.99;
    candidate.capacityHeadroom = 0.8;
    candidate.healthObservedAt = QDateTime::fromString(QStringLiteral("2026-08-28T10:00:00Z"),
                                                       Qt::ISODate);
    candidate.requiredCaps = {QStringLiteral("awg.random_trailers"),
                              QStringLiteral("awg.disable_cookies")};
    candidate.verification.expectedEgressIds = {QStringLiteral("fi-exit")};
    candidate.verification.context = QStringLiteral("opaque-a");
    candidate.nativeProfile.format = QStringLiteral("tribe_native_profile_v1");
    candidate.nativeProfile.containerConfigFormat = QStringLiteral("amnezia_container_config_v1");
    candidate.nativeProfile.containerType = QStringLiteral("amnezia-awg");
    candidate.nativeProfile.profileKind = candidate.profileKind;
    candidate.nativeProfile.configGeneration = 9;
    candidate.nativeProfile.bindingGeneration = 3;
    candidate.nativeProfile.expiresAt = QDateTime::fromString(
        QStringLiteral("2026-09-20T00:00:00Z"), Qt::ISODate);
    candidate.nativeProfile.config = {
        {QStringLiteral("endpoint_host"), QStringLiteral("awg-fi.example.net")},
        {QStringLiteral("endpoint_port"), 51820},
        {QStringLiteral("server_public_key"), key32('\x11')},
        {QStringLiteral("client_public_key"), key32('\x22')},
        {QStringLiteral("address"), QJsonArray{QStringLiteral("10.77.0.2/32"),
                                                QStringLiteral("fd00:77::2/128")}},
        {QStringLiteral("allowed_ips"), QJsonArray{QStringLiteral("0.0.0.0/0"),
                                                    QStringLiteral("::/0")}},
        {QStringLiteral("dns"), QJsonArray{QStringLiteral("1.1.1.1"),
                                            QStringLiteral("1.0.0.1")}},
        {QStringLiteral("mtu"), 1280},
        {QStringLiteral("persistent_keepalive"), 25},
        {QStringLiteral("awg_params"), QJsonObject{
            {QStringLiteral("Jc"), 4}, {QStringLiteral("Jmin"), 40},
            {QStringLiteral("Jmax"), 70}, {QStringLiteral("S1"), 20},
            {QStringLiteral("S2"), 24}, {QStringLiteral("S3"), 28},
            {QStringLiteral("S4"), 32}, {QStringLiteral("H1"), 1001},
            {QStringLiteral("H2"), 1002}, {QStringLiteral("H3"), 1003},
            {QStringLiteral("H4"), 1004},
            {QStringLiteral("I1"), QStringLiteral("<r 2><b 0x8580><rd 4><rc 3><t>")},
            {QStringLiteral("HeaderProtectionKey"), key32('\x33')},
            {QStringLiteral("ContentPaddingAddition"), QStringLiteral("0-64")},
            {QStringLiteral("RekeyAfterTime"), QStringLiteral("120")},
            {QStringLiteral("RekeyTimeout"), QStringLiteral("5")},
            {QStringLiteral("RejectAfterTime"), QStringLiteral("180")},
            {QStringLiteral("KeepaliveTimeout"), QStringLiteral("10")},
            {QStringLiteral("MaxHandshakeAttempts"), QStringLiteral("20")},
            {QStringLiteral("RandomTrailers"), true},
            {QStringLiteral("DisableCookies"), true},
        }},
    };
    return candidate;
}

static CatalogCandidate xrayCandidate(const QString &id = QStringLiteral("fi-xray"))
{
    CatalogCandidate candidate;
    candidate.locationId = QStringLiteral("fi-hel");
    candidate.locationCountry = QStringLiteral("FI");
    candidate.profileId = id;
    candidate.transport = TransportKind::Xray;
    candidate.profileKind = QStringLiteral("xray_vless_reality_vision_tcp");
    candidate.failureDomain = QStringLiteral("provider-b/asn-b/host-b");
    candidate.serverHealth = 0.98;
    candidate.capacityHeadroom = 0.7;
    candidate.healthObservedAt = QDateTime::fromString(QStringLiteral("2026-08-28T10:00:00Z"),
                                                       Qt::ISODate);
    candidate.requiredCaps = {QStringLiteral("xray.vless.reality.vision.tcp")};
    candidate.verification.expectedEgressIds = {QStringLiteral("fi-exit")};
    candidate.verification.context = QStringLiteral("opaque-b");
    candidate.nativeProfile.format = QStringLiteral("tribe_native_profile_v1");
    candidate.nativeProfile.containerConfigFormat = QStringLiteral("amnezia_container_config_v1");
    candidate.nativeProfile.containerType = QStringLiteral("amnezia-xray");
    candidate.nativeProfile.profileKind = candidate.profileKind;
    candidate.nativeProfile.configGeneration = 10;
    candidate.nativeProfile.bindingGeneration = 4;
    candidate.nativeProfile.expiresAt = QDateTime::fromString(
        QStringLiteral("2026-09-20T00:00:00Z"), Qt::ISODate);
    candidate.nativeProfile.config = {
        {QStringLiteral("endpoint_host"), QStringLiteral("xray-fi.example.net")},
        {QStringLiteral("endpoint_port"), 443},
        {QStringLiteral("uuid"), QStringLiteral("123e4567-e89b-42d3-a456-426614174000")},
        {QStringLiteral("network"), QStringLiteral("tcp")},
        {QStringLiteral("security"), QStringLiteral("reality")},
        {QStringLiteral("flow"), QStringLiteral("xtls-rprx-vision")},
        {QStringLiteral("reality_public_key"), key32Url('\x44')},
        {QStringLiteral("short_id"), QStringLiteral("a1b2c3d4")},
        {QStringLiteral("server_name"), QStringLiteral("cdn-fi.example.net")},
        {QStringLiteral("fingerprint"), QStringLiteral("randomized")},
    };
    return candidate;
}

static Catalog catalog()
{
    Catalog out;
    out.schemaVersion = 2;
    out.deviceAudience = key32Url('\x61');
    out.requestNonce = key32Url('\x6e');
    out.catalogRevision = 10;
    out.payloadSha256 = QByteArray(32, '\x7a');
    out.signingKeyId = QStringLiteral("catalog-k1");
    out.issuedAt = QDateTime::fromString(QStringLiteral("2026-08-28T09:59:00Z"),
                                        Qt::ISODate);
    out.expiresAt = QDateTime::fromString(QStringLiteral("2026-08-29T10:00:00Z"), Qt::ISODate);
    out.entitlementExpiresAt = QDateTime::fromString(
        QStringLiteral("2026-09-20T00:00:00Z"), Qt::ISODate);
    out.policy.maxAttempts = 3;
    return out;
}

static CatalogRuntimeAuthority authority(const Catalog &value,
                                         CatalogSource source = CatalogSource::Network,
                                         CatalogTrustLimits limits = {})
{
    return {source, value.deviceAudience, value.catalogRevision, value.payloadSha256,
            catalogFreshnessDeadline(value, source, limits),
            value.entitlementExpiresAt.toUTC(), value.signingKeyId,
            value.issuedAt.toUTC()};
}

static void attachRuntimeAuthority(CompiledNativeProfile &compiled,
                                   CatalogSource source = CatalogSource::Network)
{
    const Catalog value = catalog();
    const CatalogRuntimeAuthority accepted = authority(value, source);
    compiled.runtimeAuthority = {
        accepted.source,
        accepted.deviceAudience,
        accepted.catalogRevision,
        accepted.payloadSha256,
        accepted.catalogSigningKeyId,
        compiled.profileId,
        compiled.transport,
        compiled.configGeneration,
        compiled.bindingGeneration,
        compiled.expiresAt.toUTC(),
        accepted.freshnessDeadline.toUTC(),
        accepted.entitlementDeadline.toUTC(),
        accepted.issuedAt.toUTC(),
        QDateTime::fromString(QStringLiteral("2026-08-28T10:01:00Z"), Qt::ISODate),
    };
}

class FakeAdapter final : public ITransportAdapter {
public:
    FakeAdapter(TransportKind kind, NativeProfileCompileOptions options)
        : m_kind(kind), m_options(std::move(options)) {}
    TransportKind transport() const override { return m_kind; }
    amnezia::DockerContainer nativeContainer() const override
    { return nativeContainerForTransport(m_kind); }
    QSet<QString> supportedProfileKinds() const override
    {
        return m_kind == TransportKind::Awg
            ? QSet<QString>{QStringLiteral("awg31")}
            : QSet<QString>{QStringLiteral("xray_vless_reality_vision_tcp")};
    }
    bool validateAndCompile(const CatalogCandidate &candidate, CompiledNativeProfile &compiled,
                            QString &error) const override
    {
        ++compileCalls;
        return NativeProfileCompiler::compile(candidate, m_options, compiled, error);
    }
    bool prepareStart(const CompiledNativeProfile &compiled,
                      TransportOperationToken,
                      PreparedTransportStart &prepared,
                      QString &) override
    {
        ++prepareCalls;
        prepared.compiled = compiled;
        prepared.finalConfiguration = compiled.vpnConfiguration;
        prepared.finalConfiguration.insert(
            QStringLiteral("native_envelope_schema"),
            QStringLiteral("tribe_catalog_v2_native_v1"));
        prepared.nativeDispatchPolicySha256 = QByteArray(32, 'p');
        return !rejectNextPrepare;
    }
    void setObserver(ITransportAdapterObserver *observer) override { m_observer = observer; }
    void clearObserver(ITransportAdapterObserver *expected) override
    { if (m_observer == expected) { m_observer = nullptr; ++clearObserverCalls; } }
    bool start(const PreparedTransportStart &prepared, TransportOperationToken operation,
               QString &error) override
    {
        const CompiledNativeProfile &compiled = prepared.compiled;
        ++startCalls;
        starts.append(operation);
        startedProfileIds.append(compiled.profileId);
        if (rejectNextStart) {
            rejectNextStart = false;
            nativeOwned = false;
            error = QStringLiteral("rejected");
            return false;
        }
        if (rejectNextStartDeferred) {
            rejectNextStartDeferred = false;
            nativeOwned = false;
            return true;
        }
        nativeOwned = true;
        return true;
    }
    TransportAuthorityRenewalResult renewRuntimeAuthority(
        const CatalogCandidate &candidate, const CatalogRuntimeAuthority &authority,
        TransportOperationToken operation, TransportAuthorityRenewalDispatch &dispatch,
        QString &error) override
    {
        dispatch = {};
        ++renewCalls;
        if (!nativeOwned || starts.isEmpty() || operation != starts.last()
            || candidate.profileId != startedProfileIds.last()
            || authority.catalogRevision == 0) {
            error = QStringLiteral("renew identity mismatch");
            return TransportAuthorityRenewalResult::Rejected;
        }
        if (renewalResult == TransportAuthorityRenewalResult::Dispatched) {
            lastRenewalDispatch = {
                QUuid::createUuid().toString(QUuid::WithoutBraces).toLower(),
                QByteArray(32, 'r'),
                std::min({candidate.nativeProfile.expiresAt.toUTC(),
                          authority.freshnessDeadline.toUTC(),
                          authority.entitlementDeadline.toUTC()}),
            };
            dispatch = lastRenewalDispatch;
        }
        return renewalResult;
    }
    void stop(TransportOperationToken operation) override
    { ++stopCalls; stops.append(operation); }
    TransportTelemetry telemetry() const override { return {}; }
    void emitEvent(TransportOperationToken token, TransportEventKind kind,
                   const QString &reason = {})
    {
        if (kind == TransportEventKind::StartRejected
            || kind == TransportEventKind::Stopped)
            nativeOwned = false;
        if (m_observer) m_observer->onTransportEvent({token, kind, reason});
    }
    void emitAuthorityRenewed()
    {
        emitAuthorityEvent(TransportEventKind::AuthorityRenewed);
    }
    void emitAuthorityEvent(TransportEventKind kind, const QString &reason = {},
                            const QString &renewalId = {},
                            const QByteArray &commitment = {},
                            const QDateTime &deadline = {})
    {
        if (!m_observer || starts.isEmpty() || !lastRenewalDispatch.isValid()) return;
        m_observer->onTransportEvent({
            starts.last(), kind, reason,
            renewalId.isEmpty() ? lastRenewalDispatch.renewalId : renewalId,
            commitment.isEmpty() ? lastRenewalDispatch.authorityCommitmentSha256
                                 : commitment,
            deadline.isValid() ? deadline
                               : lastRenewalDispatch.requestedHardDeadlineUtc,
        });
    }

    TransportKind m_kind;
    NativeProfileCompileOptions m_options;
    mutable int compileCalls = 0;
    int prepareCalls = 0;
    ITransportAdapterObserver *m_observer = nullptr;
    int startCalls = 0;
    int stopCalls = 0;
    int renewCalls = 0;
    int clearObserverCalls = 0;
    bool rejectNextStart = false;
    bool rejectNextPrepare = false;
    bool rejectNextStartDeferred = false;
    bool nativeOwned = false;
    TransportAuthorityRenewalResult renewalResult =
        TransportAuthorityRenewalResult::Dispatched;
    TransportAuthorityRenewalDispatch lastRenewalDispatch;
    QList<TransportOperationToken> starts;
    QList<TransportOperationToken> stops;
    QStringList startedProfileIds;
};

class FakeVerifier final : public IPostTunnelVerifier {
public:
    void setObserver(IPostTunnelVerificationObserver *observer) override { m_observer = observer; }
    void clearObserver(IPostTunnelVerificationObserver *expected) override
    { if (m_observer == expected) { m_observer = nullptr; ++clearObserverCalls; } }
    bool start(const CatalogCandidate &candidate, VerificationToken operation,
               QString &error) override
    {
        ++startCalls;
        lastCandidate = candidate;
        lastToken = operation;
        if (rejectDispatch) { error = QStringLiteral("offline"); return false; }
        return true;
    }
    void cancel(VerificationToken operation) override
    { ++cancelCalls; cancelled.append(operation); }
    void emitResult(const PostTunnelVerificationResult &result)
    { if (m_observer) m_observer->onPostTunnelVerification(result); }
    void emitStage(VerificationToken operation, PostTunnelVerificationStage stage)
    { if (m_observer) m_observer->onPostTunnelVerificationStage(operation, stage); }
    IPostTunnelVerificationObserver *m_observer = nullptr;
    CatalogCandidate lastCandidate;
    VerificationToken lastToken;
    int startCalls = 0;
    int cancelCalls = 0;
    int clearObserverCalls = 0;
    bool rejectDispatch = false;
    QList<VerificationToken> cancelled;
};

class FakeClock final : public IConnectionClock {
public:
    QDateTime nowUtc() const override { return now; }
    QDateTime now = QDateTime::fromString(QStringLiteral("2026-08-28T10:01:00Z"), Qt::ISODate);
};

class FakeGuard final : public IConnectionSessionGuard {
public:
    void setObserver(IConnectionSessionGuardObserver *observer) override
    { m_observer = observer; }
    void clearObserver(IConnectionSessionGuardObserver *expected) override
    { if (m_observer == expected) m_observer = nullptr; }
    bool prepareAndArm(const PreparedTransportStart &prepared,
                       TransportOperationToken operation,
                       QString &error) override
    {
        ++armCalls;
        if (reject || (rejectOnArmCall > 0 && armCalls == rejectOnArmCall)) {
            error = QStringLiteral("guard unavailable");
            return false;
        }
        if (prepared.finalConfiguration.isEmpty()
            || prepared.nativeDispatchPolicySha256.size() != 32
            || QUuid(prepared.expectedRuntimeSessionId).isNull()
            || QUuid(prepared.expectedRuntimeSessionId)
                    .toString(QUuid::WithoutBraces).toLower()
                   != prepared.expectedRuntimeSessionId
            || !operation.isValid()) {
            error = QStringLiteral("invalid prepared policy");
            return false;
        }
        armed = true;
        armedFor = operation;
        outerSessionId = QStringLiteral("outer-%1-%2")
                             .arg(operation.operation).arg(operation.session);
        expectedRuntimeSessionId = prepared.expectedRuntimeSessionId;
        policySha256 = prepared.nativeDispatchPolicySha256;
        if (!deferArm && m_observer) {
            m_observer->onConnectionSessionGuardEvent(
                {operation, ConnectionGuardEventKind::Armed, policySha256,
                 outerSessionId, {}, expectedRuntimeSessionId});
        }
        return true;
    }
    bool releaseExact(TransportOperationToken operation,
                      const QString &exactOuterSessionId,
                      QString &error) override
    {
        ++disarmCalls;
        if (!armed || operation != armedFor || exactOuterSessionId != outerSessionId
            || rejectRelease) {
            error = QStringLiteral("guard release rejected");
            return false;
        }
        if (deferRelease)
            return true;
        armed = false;
        armedFor = {};
        const QString releasedOuter = outerSessionId;
        outerSessionId.clear();
        if (!deferRelease && m_observer) {
            m_observer->onConnectionSessionGuardEvent(
                {operation, ConnectionGuardEventKind::Released, policySha256, releasedOuter,
                 {}, expectedRuntimeSessionId});
        }
        return true;
    }
    bool isArmedFor(TransportOperationToken operation,
                    const QString &exactOuterSessionId = {}) const override
    {
        return armed && armedFor == operation
               && (exactOuterSessionId.isEmpty() || exactOuterSessionId == outerSessionId);
    }
    bool reconcileTimedOutArmExact(const PreparedTransportStart &prepared,
                                   TransportOperationToken operation,
                                   QString &error) override
    {
        ++armReconcileCalls;
        error.clear();
        lastReconciledArm = operation;
        lastReconciledPolicy = prepared.nativeDispatchPolicySha256;
        return !rejectReconcile;
    }
    bool reconcileTimedOutReleaseExact(TransportOperationToken operation,
                                       const QString &exactOuterSessionId,
                                       QString &error) override
    {
        ++releaseReconcileCalls;
        error.clear();
        lastReconciledRelease = operation;
        lastReconciledOuter = exactOuterSessionId;
        return !rejectReconcile;
    }
    bool completeRecoveryReleasedExact(const ConnectionGuardEvent &identity) override
    {
        ++recoveryReleaseCalls;
        if (identity.operation != recoveryIdentity.operation
            || identity.nativeDispatchPolicySha256
                != recoveryIdentity.nativeDispatchPolicySha256
            || identity.outerSessionId != recoveryIdentity.outerSessionId
            || identity.expectedRuntimeSessionId
                != recoveryIdentity.expectedRuntimeSessionId)
            return false;
        recoveryIdentity = {};
        armed = false;
        armedFor = {};
        return true;
    }
    void emitArmCompleted()
    {
        if (m_observer && armed && armedFor.isValid())
            m_observer->onConnectionSessionGuardEvent(
                {armedFor, ConnectionGuardEventKind::Armed, policySha256,
                 outerSessionId, {}, expectedRuntimeSessionId});
    }
    void emitReleased(TransportOperationToken operation, const QString &releasedOuter)
    {
        if (m_observer)
            m_observer->onConnectionSessionGuardEvent(
                {operation, ConnectionGuardEventKind::Released, policySha256, releasedOuter,
                 {}, expectedRuntimeSessionId});
    }
    void completeDeferredRelease()
    {
        if (!armed || !armedFor.isValid()) return;
        const TransportOperationToken operation = armedFor;
        const QString releasedOuter = outerSessionId;
        armed = false;
        armedFor = {};
        outerSessionId.clear();
        emitReleased(operation, releasedOuter);
    }
    bool reject = false;
    int rejectOnArmCall = -1;
    bool rejectRelease = false;
    bool deferArm = false;
    bool deferRelease = false;
    bool armed = false;
    TransportOperationToken armedFor;
    QString outerSessionId;
    QString expectedRuntimeSessionId;
    QByteArray policySha256;
    IConnectionSessionGuardObserver *m_observer = nullptr;
    int armCalls = 0;
    int disarmCalls = 0;
    int armReconcileCalls = 0;
    int releaseReconcileCalls = 0;
    int recoveryReleaseCalls = 0;
    bool rejectReconcile = false;
    TransportOperationToken lastReconciledArm;
    TransportOperationToken lastReconciledRelease;
    QByteArray lastReconciledPolicy;
    QString lastReconciledOuter;
    ConnectionGuardEvent recoveryIdentity;
};

static CandidateSelectionRequest selection()
{
    CandidateSelectionRequest request;
    request.mode = ConnectionMode::Auto;
    request.fixedLocationId = QStringLiteral("fi-hel");
    request.nowUtc = QDateTime::fromString(QStringLiteral("2026-08-28T10:01:00Z"), Qt::ISODate);
    request.maximumCandidates = 3;
    request.deterministicSeed = 7;
    return request;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    NativeProfileCompileOptions options;
    options.awgKeys = {key32('\x55'), key32('\x22')};
    FakeClock clock;

    // Exact compilers and post-compile sanitizers.
    {
        QString error;
        CompiledNativeProfile compiled;
        CatalogCandidate awg = awgCandidate();
        CHECK(NativeProfileCompiler::compile(awg, options, compiled, error));
        CHECK(compiled.container == amnezia::DockerContainer::Awg);
        CHECK(compiled.transport == TransportKind::Awg);
        const QJsonObject awgInner = compiled.vpnConfiguration.value("awg_config_data").toObject();
        CHECK(awgInner.value("client_priv_key").toString() == options.awgKeys.privateKey);
        CHECK(awgInner.value("RandomTrailers").toString() == QLatin1String("1"));
        CHECK(awgInner.value("DisableCookies").toString() == QLatin1String("1"));
        CHECK(!awgInner.contains(QStringLiteral("extra")));

        CompiledNativeProfile awgTampered = compiled;
        QJsonObject tamperedInner = awgTampered.vpnConfiguration.value("awg_config_data").toObject();
        tamperedInner[QStringLiteral("config")] =
            tamperedInner.value(QStringLiteral("config")).toString()
            + QStringLiteral("PostUp = curl attacker.invalid\n");
        awgTampered.vpnConfiguration[QStringLiteral("awg_config_data")] = tamperedInner;
        CHECK(!NativeProfileCompiler::sanitizeCompiled(awg, options, awgTampered, error));

        NativeProfileCompileOptions badLocalKey = options;
        badLocalKey.awgKeys.privateKey = QStringLiteral("not-a-key");
        CHECK(!NativeProfileCompiler::compile(awg, badLocalKey, compiled, error));

        CatalogCandidate wrongBinding = awg;
        wrongBinding.nativeProfile.config[QStringLiteral("client_public_key")] = key32('\x66');
        CHECK(!NativeProfileCompiler::compile(wrongBinding, options, compiled, error));
        CatalogCandidate unknown = awg;
        unknown.nativeProfile.config[QStringLiteral("raw_config")] = QStringLiteral("forbidden");
        CHECK(!NativeProfileCompiler::compile(unknown, options, compiled, error));

        CatalogCandidate xray = xrayCandidate();
        CHECK(NativeProfileCompiler::compile(xray, options, compiled, error));
        CHECK(compiled.container == amnezia::DockerContainer::Xray);
        CHECK(compiled.vpnConfiguration.value("protocol") == QLatin1String("xray"));
        QJsonObject data = compiled.vpnConfiguration.value("xray_config_data").toObject();
        QJsonObject core = QJsonDocument::fromJson(data.value("config").toString().toUtf8()).object();
        CHECK(core.value("inbounds").toArray().size() == 1);
        CHECK(core.value("outbounds").toArray().size() == 1);
        CHECK(!core.contains(QStringLiteral("routing")));
        CHECK(!core.contains(QStringLiteral("api")));
        const QJsonObject xrayOutbound = core.value("outbounds").toArray().first().toObject();
        const QJsonObject xraySettings = xrayOutbound.value("settings").toObject();
        CHECK(xraySettings.value("address") == QLatin1String("xray-fi.example.net"));
        CHECK(xraySettings.value("port").toInt() == 443);
        CHECK(xraySettings.value("id")
              == QLatin1String("123e4567-e89b-42d3-a456-426614174000"));
        CHECK(xraySettings.value("encryption") == QLatin1String("none"));
        CHECK(xraySettings.value("flow") == QLatin1String("xtls-rprx-vision"));
        CHECK(!xraySettings.contains(QStringLiteral("vnext")));
        const QJsonObject reality = xrayOutbound.value("streamSettings").toObject()
                                      .value("realitySettings").toObject();
        CHECK(reality.contains(QStringLiteral("password")));
        CHECK(!reality.contains(QStringLiteral("publicKey")));

        CompiledNativeProfile tampered = compiled;
        core[QStringLiteral("routing")] = QJsonObject{};
        data[QStringLiteral("config")] = QString::fromUtf8(
            QJsonDocument(core).toJson(QJsonDocument::Compact));
        tampered.vpnConfiguration[QStringLiteral("xray_config_data")] = data;
        CHECK(!NativeProfileCompiler::sanitizeCompiled(xray, options, tampered, error));

        CHECK(NativeProfileCompiler::compile(xray, options, compiled, error));
        data = compiled.vpnConfiguration.value("xray_config_data").toObject();
        core = QJsonDocument::fromJson(data.value("config").toString().toUtf8()).object();
        QJsonArray duplicateOutbounds = core.value("outbounds").toArray();
        duplicateOutbounds.append(duplicateOutbounds.first());
        core[QStringLiteral("outbounds")] = duplicateOutbounds;
        data[QStringLiteral("config")] = QString::fromUtf8(
            QJsonDocument(core).toJson(QJsonDocument::Compact));
        compiled.vpnConfiguration[QStringLiteral("xray_config_data")] = data;
        CHECK(!NativeProfileCompiler::sanitizeCompiled(xray, options, compiled, error));

        CHECK(NativeProfileCompiler::compile(xray, options, compiled, error));
        data = compiled.vpnConfiguration.value("xray_config_data").toObject();
        core = QJsonDocument::fromJson(data.value("config").toString().toUtf8()).object();
        QJsonArray inbounds = core.value("inbounds").toArray();
        QJsonObject inbound = inbounds.first().toObject();
        inbound[QStringLiteral("listen")] = QStringLiteral("0.0.0.0");
        inbounds[0] = inbound;
        core[QStringLiteral("inbounds")] = inbounds;
        data[QStringLiteral("config")] = QString::fromUtf8(
            QJsonDocument(core).toJson(QJsonDocument::Compact));
        compiled.vpnConfiguration[QStringLiteral("xray_config_data")] = data;
        CHECK(!NativeProfileCompiler::sanitizeCompiled(xray, options, compiled, error));
    }

    // Local route/DNS policy is an immutable, typed overlay with a second exact sanitizer. Server
    // profiles cannot weaken full-tunnel routes, and RU-direct cannot bypass verifier/auth IPs.
    {
        QString error;
        CompiledNativeProfile awgCompiled;
        CHECK(NativeProfileCompiler::compile(awgCandidate(), options, awgCompiled, error));
        attachRuntimeAuthority(awgCompiled);
        NativeConnectionPolicySnapshot policy;
        policy.ruDirectRequested = true;
        policy.routeExclusions = {QStringLiteral("5.136.0.0/13")};
        policy.protectedTunnelIpLiterals = {QStringLiteral("1.1.1.1")};
        policy.appsSplitEnabled = true;
        policy.appsRouteMode = amnezia::AppsRouteMode::VpnAllExceptApps;
        policy.splitApps = {QStringLiteral("org.example.direct")};
        policy.dnsForwardRequested = true;
        policy.dnsForwardWarmup = false;
        policy.maskDnsServers = {QStringLiteral("77.88.8.8"), QStringLiteral("77.88.8.1")};
        policy.splitDnsSuffixes = {QStringLiteral("ru"), QStringLiteral("xn--p1ai")};
        policy.splitDnsServer = QStringLiteral("77.88.8.8");
        policy.includeDesktopKillSwitch = true;
        policy.killSwitchEnabled = true;
        policy.allowedDnsServers = {QStringLiteral("1.1.1.1")};
        PreparedNativeConnectionPolicy prepared;
        CHECK(NativeConnectionPolicyCompiler::compile(
            awgCompiled, policy, prepared, error));
        CHECK(QJsonDocument(prepared.configuration).toJson(QJsonDocument::Compact)
              == fixtureBytes(QStringLiteral("native_dispatch_awg_v1.json")));
        const QJsonObject nativeAuthority =
            prepared.configuration.value(QStringLiteral("runtime_authority_v1")).toObject();
        CHECK(nativeAuthority.value(QStringLiteral("schema_version")).toInt() == 1);
        CHECK(prepared.configuration.value(QStringLiteral("native_envelope_schema"))
              == QLatin1String("tribe_catalog_v2_native_v1"));
        CHECK(nativeAuthority.value(QStringLiteral("catalog_revision")).toString()
              == QLatin1String("10"));
        CHECK(nativeAuthority.value(QStringLiteral("config_generation")).toString()
              == QString::number(awgCompiled.configGeneration));
        CHECK(nativeAuthority.value(QStringLiteral("binding_generation")).toString()
              == QString::number(awgCompiled.bindingGeneration));
        CHECK(nativeAuthority.value(QStringLiteral("policy_schema"))
              == QLatin1String("native_dispatch_policy_v1"));
        CHECK(nativeAuthority.value(QStringLiteral("protected_tunnel_ips")).toArray()
              == QJsonArray{QStringLiteral("1.1.1.1")});
        QByteArray goldenProjection;
        QJsonObject projectionConfig = prepared.configuration;
        projectionConfig.remove(QStringLiteral("runtime_authority_v1"));
        CHECK(encodeNativeDispatchPolicyV1(awgCompiled, policy, projectionConfig,
                                           goldenProjection, error));
        CHECK(nativeAuthority.value(QStringLiteral("policy_sha256"))
              == QLatin1String("b805559232d851644e2595c599e2b147e9a2fda83b110fd0106030c986826b9c"));
        CHECK(prepared.splitOn);
        CHECK(prepared.configuration.value("splitTunnelType").toInt()
              == amnezia::RouteMode::VpnAllExceptSites);
        CHECK(prepared.configuration.value("splitTunnelSites").toArray()
              == QJsonArray{QStringLiteral("5.136.0.0/13")});
        CHECK(prepared.configuration.value("dnsFwdOn") == QLatin1String("1"));
        CHECK(prepared.configuration.value("dnsFwdWarmup") == QLatin1String("0"));
        CHECK(NativeConnectionPolicyCompiler::sanitizeForDispatch(
            awgCompiled, policy, prepared.configuration, error));

        QJsonObject strippedAuthority = prepared.configuration;
        strippedAuthority.remove(QStringLiteral("runtime_authority_v1"));
        CHECK(!NativeConnectionPolicyCompiler::sanitizeForDispatch(
            awgCompiled, policy, strippedAuthority, error));

        QJsonObject tamperedPolicyEnvelope = prepared.configuration;
        tamperedPolicyEnvelope[QStringLiteral("routing")] = QJsonObject{};
        CHECK(!NativeConnectionPolicyCompiler::sanitizeForDispatch(
            awgCompiled, policy, tamperedPolicyEnvelope, error));

        NativeConnectionPolicySnapshot noProtected = policy;
        noProtected.protectedTunnelIpLiterals.clear();
        CHECK(!NativeConnectionPolicyCompiler::compile(
            awgCompiled, noProtected, prepared, error));
        NativeConnectionPolicySnapshot protectedBypassed = policy;
        protectedBypassed.protectedTunnelIpLiterals = {QStringLiteral("5.136.1.1")};
        CHECK(!NativeConnectionPolicyCompiler::compile(
            awgCompiled, protectedBypassed, prepared, error));
        NativeConnectionPolicySnapshot defaultRoute = policy;
        defaultRoute.routeExclusions = {QStringLiteral("0.0.0.0/0")};
        CHECK(!NativeConnectionPolicyCompiler::compile(
            awgCompiled, defaultRoute, prepared, error));

        CatalogCandidate xrayIpv6 = xrayCandidate();
        xrayIpv6.nativeProfile.config[QStringLiteral("endpoint_host")] =
            QStringLiteral("2001:4860:4860::8888");
        CompiledNativeProfile xrayCompiled;
        CHECK(NativeProfileCompiler::compile(xrayIpv6, options, xrayCompiled, error));
        attachRuntimeAuthority(xrayCompiled);
        NativeConnectionPolicySnapshot xrayPolicy = policy;
        xrayPolicy.routeExclusions = {QStringLiteral("203.0.113.0/24"),
                                      QStringLiteral("5.136.0.0/13")};
        xrayPolicy.splitApps = {QStringLiteral("org.example.direct"),
                                QStringLiteral("org.example.прямой")};
        xrayPolicy.protectedTunnelIpLiterals = {
            QStringLiteral("1.1.1.1"), QStringLiteral("2606:4700:4700::1111")};
        CHECK(NativeConnectionPolicyCompiler::compile(
            xrayCompiled, xrayPolicy, prepared, error));
        CHECK(QJsonDocument(prepared.configuration).toJson(QJsonDocument::Compact)
              == fixtureBytes(QStringLiteral("native_dispatch_xray_v1.json")));
        CHECK(!prepared.configuration.contains(QStringLiteral("dnsFwdOn")));
        CHECK(!prepared.configuration.contains(QStringLiteral("dnsFwdSuffixes")));
        QJsonObject xrayProjection = prepared.configuration;
        const QJsonObject xrayAuthority =
            xrayProjection.take(QStringLiteral("runtime_authority_v1")).toObject();
        CHECK(xrayAuthority.value(QStringLiteral("policy_sha256"))
              == QLatin1String("6a6eed0c33b6bb58d3389e5a3670e6a1d969367ebbd62baec248e27a4f7d61cd"));
        QByteArray xrayDigest;
        CHECK(nativeDispatchPolicySha256(xrayCompiled, xrayPolicy, xrayProjection,
                                         xrayDigest, error));
        CHECK(QString::fromLatin1(xrayDigest.toHex())
              == xrayAuthority.value(QStringLiteral("policy_sha256")).toString());

        QJsonObject reordered = xrayProjection;
        QJsonArray sites = reordered.value(QStringLiteral("splitTunnelSites")).toArray();
        reordered[QStringLiteral("splitTunnelSites")] =
            QJsonArray{sites.at(1), sites.at(0)};
        QByteArray reorderedDigest;
        CHECK(nativeDispatchPolicySha256(xrayCompiled, xrayPolicy, reordered,
                                         reorderedDigest, error));
        CHECK(reorderedDigest == xrayDigest);

        QJsonObject nativeChanged = xrayProjection;
        QJsonObject nativeData = nativeChanged.value(QStringLiteral("xray_config_data")).toObject();
        nativeData[QStringLiteral("config")] =
            nativeData.value(QStringLiteral("config")).toString() + QLatin1Char(' ');
        nativeChanged[QStringLiteral("xray_config_data")] = nativeData;
        QByteArray changedDigest;
        CHECK(nativeDispatchPolicySha256(xrayCompiled, xrayPolicy, nativeChanged,
                                         changedDigest, error));
        CHECK(changedDigest != xrayDigest);
        QJsonObject routeChanged = xrayProjection;
        routeChanged[QStringLiteral("splitTunnelSites")] =
            QJsonArray{QStringLiteral("203.0.114.0/24"), QStringLiteral("5.136.0.0/13")};
        CHECK(nativeDispatchPolicySha256(xrayCompiled, xrayPolicy, routeChanged,
                                         changedDigest, error));
        CHECK(changedDigest != xrayDigest);
        QJsonObject nul = xrayProjection;
        QString nulApp = QStringLiteral("bad");
        nulApp.append(QChar::Null);
        nulApp.append(QStringLiteral("app"));
        nul[QStringLiteral("splitTunnelApps")] = QJsonArray{nulApp};
        CHECK(!nativeDispatchPolicySha256(xrayCompiled, xrayPolicy, nul,
                                          changedDigest, error));
        QJsonObject overlong = xrayProjection;
        overlong[QStringLiteral("splitTunnelApps")] = QJsonArray{QString(300000, QLatin1Char('a'))};
        CHECK(!nativeDispatchPolicySha256(xrayCompiled, xrayPolicy, overlong,
                                          changedDigest, error));
        CompiledNativeProfile zeroGeneration = xrayCompiled;
        zeroGeneration.configGeneration = 0;
        CHECK(!nativeDispatchPolicySha256(zeroGeneration, xrayPolicy, xrayProjection,
                                          changedDigest, error));

        CatalogCandidate ru = awgCandidate(QStringLiteral("ru-awg"));
        ru.locationCountry = QStringLiteral("RU");
        CHECK(NativeProfileCompiler::compile(ru, options, awgCompiled, error));
        attachRuntimeAuthority(awgCompiled);
        noProtected = policy;
        noProtected.protectedTunnelIpLiterals.clear();
        CHECK(NativeConnectionPolicyCompiler::compile(
            awgCompiled, noProtected, prepared, error));
        CHECK(!prepared.splitOn);
        CHECK(prepared.configuration.value("splitTunnelType").toInt()
              == amnezia::RouteMode::VpnAllSites);
        CHECK(prepared.configuration.value("splitTunnelSites").toArray().isEmpty());
        CHECK(!prepared.configuration.contains(QStringLiteral("dnsFwdOn")));
    }

    // Native ownership is an opaque session identity, not callback sequence. A late terminal from
    // the old core after replacement dispatch can never be attributed to the new AWG/Xray attempt.
    {
        const auto runtimeStatus = [](const QString &session, const QString &protocol,
                                      const QString &state) {
            return QJsonObject{
                {QStringLiteral("type"), QStringLiteral("tunnel_runtime_status_v1")},
                {QStringLiteral("schema"), 1},
                {QStringLiteral("session_id"), session},
                {QStringLiteral("protocol"), protocol},
                {QStringLiteral("runtime_state"), state},
            };
        };
        NativeRuntimeIdentityGate gate;
        NativeRuntimeStatus parsed;
        const QString oldSession = QStringLiteral("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        const QString newSession = QStringLiteral("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        gate.resetForDispatch(TransportKind::Xray, newSession);
        CHECK(gate.consume(runtimeStatus(oldSession, QStringLiteral("xray"),
                                         QStringLiteral("stopped")), parsed)
              == NativeRuntimeStatusDisposition::IgnoredStaleSession);
        CHECK(gate.boundSessionId().isEmpty());
        CHECK(gate.consume(runtimeStatus(newSession, QStringLiteral("xray"),
                                         QStringLiteral("starting")), parsed)
              == NativeRuntimeStatusDisposition::Accepted);
        CHECK(gate.boundSessionId() == newSession && parsed.sessionId == newSession);
        CHECK(gate.consume(runtimeStatus(oldSession, QStringLiteral("xray"),
                                         QStringLiteral("stopped")), parsed)
              == NativeRuntimeStatusDisposition::IgnoredStaleSession);
        CHECK(gate.consume(runtimeStatus(newSession, QStringLiteral("awg"),
                                         QStringLiteral("running")), parsed)
              == NativeRuntimeStatusDisposition::RejectedMalformed);
        CHECK(gate.consume(runtimeStatus(newSession, QStringLiteral("xray"),
                                         QStringLiteral("stopped")), parsed)
              == NativeRuntimeStatusDisposition::Accepted);
        const QString nextSession = QStringLiteral("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
        gate.clear();
        gate.resetForDispatch(TransportKind::Xray, nextSession);
        CHECK(gate.consume(runtimeStatus(newSession, QStringLiteral("xray"),
                                         QStringLiteral("stopped")), parsed)
              == NativeRuntimeStatusDisposition::IgnoredStaleSession);
        CHECK(gate.boundSessionId().isEmpty());
        CHECK(gate.consume(runtimeStatus(nextSession, QStringLiteral("xray"),
                                         QStringLiteral("starting")), parsed)
              == NativeRuntimeStatusDisposition::Accepted);
        QJsonObject malformed = runtimeStatus(newSession, QStringLiteral("xray"),
                                               QStringLiteral("running"));
        malformed[QStringLiteral("schema")] = 2;
        CHECK(gate.consume(malformed, parsed)
              == NativeRuntimeStatusDisposition::RejectedMalformed);
    }

    // Reducer: no green before receipt, serialized fallback, exact operation+session stale gates.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        QHash<QString, CandidateHistory> history;
        CandidateHistory preferAwg;
        preferAwg.configGeneration = awgCandidate().nativeProfile.configGeneration;
        preferAwg.bindingGeneration = awgCandidate().nativeProfile.bindingGeneration;
        preferAwg.verifiedSuccessEwma = 1.0;
        preferAwg.survival5mEwma = 1.0;
        preferAwg.verifiedStartLatencyMs = 20;
        history.insert(QStringLiteral("fi-awg"), preferAwg);

        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate(), xrayCandidate()},
                                             history, selection(), authority(catalog()), error));
        CHECK(!reducer.legacyV1Allowed());
        CHECK(guard.armCalls == 1 && guard.armed);
        CHECK(reducer.phase() == ConnectionPhase::StartingTransport);
        CHECK(awg.startCalls == 1);
        const TransportOperationToken first = awg.starts.last();
        CHECK(first.isValid());
        awg.emitEvent({first.operation + 99, first.session}, TransportEventKind::TunnelReady);
        CHECK(reducer.phase() == ConnectionPhase::StartingTransport);
        awg.emitEvent(first, TransportEventKind::TunnelReady);
        CHECK(reducer.phase() == ConnectionPhase::VerifyingDns);
        CHECK(verifier.startCalls == 1);
        const VerificationToken firstVerification = verifier.lastToken;
        CHECK(firstVerification.transportOperation == first && firstVerification.isValid());
        CHECK(reducer.phase() != ConnectionPhase::ConnectedHealthy);
        verifier.emitStage({{first.operation, first.session + 1}, firstVerification.attempt},
                           PostTunnelVerificationStage::Traffic);
        CHECK(reducer.phase() == ConnectionPhase::VerifyingDns);
        verifier.emitStage(firstVerification, PostTunnelVerificationStage::Dns);
        CHECK(reducer.phase() == ConnectionPhase::VerifyingDns);

        // TunnelReady without DNS/real traffic is a broken candidate path, not a verifier outage:
        // exact stop then cross-transport fallback. Only typed provider 429/503 stays yellow.
        verifier.emitResult({firstVerification, VerificationDisposition::CandidateFailed,
                             ConnectionFailureStage::VerificationDns,
                             QStringLiteral("receipt_dns_unavailable"), {}, 20});
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld);
        CHECK(awg.stopCalls == 1 && awg.stops.last() == first);
        CHECK(xray.startCalls == 0);
        awg.emitEvent({first.operation, first.session + 1}, TransportEventKind::Stopped);
        CHECK(xray.startCalls == 0);
        awg.emitEvent(first, TransportEventKind::Stopped);
        CHECK(xray.startCalls == 1);
        CHECK(reducer.phase() == ConnectionPhase::StartingTransport);
        const TransportOperationToken second = xray.starts.last();
        CHECK(second.operation == first.operation && second.session != first.session);
        verifier.emitResult({firstVerification, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {}, QStringLiteral("fi-exit"), 10, 0,
                             clock.now.addSecs(25)});
        CHECK(reducer.phase() == ConnectionPhase::StartingTransport);
        xray.emitEvent(second, TransportEventKind::TunnelReady);
        CHECK(reducer.phase() == ConnectionPhase::VerifyingDns);
        const VerificationToken secondVerification = verifier.lastToken;
        verifier.emitStage(secondVerification, PostTunnelVerificationStage::Traffic);
        CHECK(reducer.phase() == ConnectionPhase::VerifyingTraffic);
        verifier.emitResult({secondVerification, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {}, QStringLiteral("fi-exit"), 15, 0,
                             clock.now.addSecs(25)});
        CHECK(reducer.phase() == ConnectionPhase::ConnectedHealthy);
        CHECK(reducer.snapshot().transport == TransportKind::Xray);
        CHECK(guard.armed); // never dropped during AWG -> Xray fallback

        // Reconcile while connected must stop the old session first; its late Ready is ignored.
        const int startsBeforeReplace = awg.startCalls + xray.startCalls;
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate(), xrayCandidate()},
                                             history, selection(), authority(catalog()), error));
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld);
        CHECK(awg.startCalls + xray.startCalls == startsBeforeReplace);
        xray.emitEvent(second, TransportEventKind::TunnelReady);
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld);
        xray.emitEvent(second, TransportEventKind::Stopped);
        CHECK(awg.startCalls + xray.startCalls == startsBeforeReplace + 1);
        const TransportOperationToken replacement = awg.starts.last();
        CHECK(replacement.operation != second.operation);
        CHECK(replacement.session != second.session);

        awg.emitEvent(replacement, TransportEventKind::TunnelReady);
        const VerificationToken outageVerification = verifier.lastToken;
        verifier.emitStage(outageVerification, PostTunnelVerificationStage::Traffic);
        verifier.emitResult({outageVerification, VerificationDisposition::InfrastructureUnavailable,
                             ConnectionFailureStage::VerificationTraffic,
                             QStringLiteral("verifier_outage"), {}, -1});
        CHECK(reducer.phase() == ConnectionPhase::VerificationUnknown);
        CHECK(reducer.snapshot().verificationRetryDirective
              == VerificationRetryDirective::RetrySameAuthority);
        CHECK(reducer.snapshot().verificationRetryAfterSeconds == 5);
        CHECK(awg.stopCalls == 1); // no fleet flapping on verifier infrastructure outage
        CHECK(reducer.retryVerification(error));
        CHECK(reducer.phase() == ConnectionPhase::VerifyingDns);
        const VerificationToken retryVerification = verifier.lastToken;
        CHECK(retryVerification.transportOperation == outageVerification.transportOperation);
        CHECK(retryVerification.attempt != outageVerification.attempt);
        reducer.onVerificationTimeout(outageVerification);
        CHECK(reducer.phase() == ConnectionPhase::VerifyingDns); // stale pre-retry timer
        verifier.emitResult({outageVerification, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {}, QStringLiteral("fi-exit"), 1, 0,
                             clock.now.addSecs(25)});
        CHECK(reducer.phase() == ConnectionPhase::VerifyingDns); // stale pre-retry callback
        verifier.emitStage(retryVerification, PostTunnelVerificationStage::Traffic);
        CHECK(reducer.phase() == ConnectionPhase::VerifyingTraffic);
        verifier.emitResult({retryVerification, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {}, QStringLiteral("fi-exit"), 12, 0,
                             clock.now.addSecs(25)});
        CHECK(reducer.phase() == ConnectionPhase::ConnectedHealthy);

        reducer.disconnect();
        CHECK(reducer.phase() == ConnectionPhase::Disconnecting);
        CHECK(guard.armed);
        const TransportOperationToken stopping = awg.stops.last();
        reducer.disconnect();
        CHECK(awg.stops.last() == stopping); // idempotent double Disconnect
        awg.emitEvent(stopping, TransportEventKind::Stopped);
        CHECK(reducer.phase() == ConnectionPhase::Idle);
        CHECK(!guard.armed && guard.disarmCalls == 1);
        CHECK(!reducer.legacyV1Allowed());
    }

    // A typed receipt 409 is carried independently from its redacted reason until the exact inner
    // stop and outer guard release are both proven. Coordinator control flow can therefore key on
    // a closed enum without treating an intermediate Failed notification as teardown completion.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        guard.deferRelease = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        const TransportOperationToken live = awg.starts.last();
        awg.emitEvent(live, TransportEventKind::TunnelReady);
        const VerificationToken verification = verifier.lastToken;
        verifier.emitStage(verification, PostTunnelVerificationStage::Traffic);
        verifier.emitResult({verification, VerificationDisposition::CatalogStale,
                             ConnectionFailureStage::VerificationAuthority,
                             QStringLiteral("receipt_binding_stale")});
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld);
        CHECK(reducer.snapshot().terminalDisposition
                  == ConnectionTerminalDisposition::CatalogStale
              && reducer.snapshot().session == live && reducer.snapshot().guardArmed);

        awg.emitEvent(live, TransportEventKind::Stopped);
        CHECK(reducer.phase() == ConnectionPhase::ReleasingGuard);
        CHECK(reducer.snapshot().terminalDisposition
                  == ConnectionTerminalDisposition::CatalogStale
              && reducer.snapshot().session == live && reducer.snapshot().guardArmed);
        guard.completeDeferredRelease();
        const ConnectionRuntimeSnapshot released = reducer.snapshot();
        CHECK(released.phase == ConnectionPhase::Failed && !released.session.isValid()
              && !released.guardArmed && !released.guardOwnershipAmbiguous
              && released.terminalDisposition
                     == ConnectionTerminalDisposition::CatalogStale);
        reducer.disconnect();
        CHECK(reducer.phase() == ConnectionPhase::Idle
              && reducer.snapshot().terminalDisposition
                     == ConnectionTerminalDisposition::None);
    }

    // A hard AWG failure is re-ranked dynamically: different transport + different domain wins
    // before a same-transport alternate. A stale callback from the failed attempt stays inert.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CatalogCandidate primary = awgCandidate(QStringLiteral("fi-awg-primary"));
        primary.failureDomain = QStringLiteral("provider-a/asn-a/host-a");
        CatalogCandidate sameTransport = awgCandidate(QStringLiteral("fi-awg-other"));
        sameTransport.failureDomain = QStringLiteral("provider-b/asn-b/host-b");
        CatalogCandidate crossTransport = xrayCandidate(QStringLiteral("fi-xray-other"));
        crossTransport.failureDomain = sameTransport.failureDomain;
        QHash<QString, CandidateHistory> history;
        history[primary.profileId].configGeneration = primary.nativeProfile.configGeneration;
        history[primary.profileId].bindingGeneration = primary.nativeProfile.bindingGeneration;
        history[primary.profileId].verifiedSuccessEwma = 1.0;
        history[primary.profileId].verifiedStartLatencyMs = 1.0;

        CHECK(reducer.connectAcceptedCatalog(catalog(),
                                             {primary, sameTransport, crossTransport},
                                             history, selection(), authority(catalog()), error));
        CHECK(awg.startedProfileIds.last() == primary.profileId);
        const TransportOperationToken failed = awg.starts.last();
        awg.emitEvent(failed, TransportEventKind::RuntimeError,
                      QStringLiteral("native_runtime_error"));
        awg.emitEvent(failed, TransportEventKind::Stopped);
        CHECK(xray.startCalls == 1);
        CHECK(xray.startedProfileIds.last() == crossTransport.profileId);
        CHECK(awg.startCalls == 1); // same-transport/domain2 profile did not jump the queue
        const TransportOperationToken fallback = xray.starts.last();
        awg.emitEvent(failed, TransportEventKind::TunnelReady);
        CHECK(reducer.snapshot().session == fallback);
        CHECK(reducer.snapshot().attemptsUsed == 2);
        CHECK(reducer.updatedHistory().value(primary.profileId).cooldownUntil.isValid());
    }

    // One failed transport is not host-death evidence. A universal node's Xray profile in the
    // same failure domain remains the final bounded fallback after AWG is blocked.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CatalogCandidate awgSameHost = awgCandidate(QStringLiteral("same-host-awg"));
        CatalogCandidate xraySameHost = xrayCandidate(QStringLiteral("same-host-xray"));
        awgSameHost.failureDomain = xraySameHost.failureDomain =
            QStringLiteral("provider-shared/asn-shared/host-shared");
        QHash<QString, CandidateHistory> history;
        CandidateHistory prefer;
        prefer.configGeneration = awgSameHost.nativeProfile.configGeneration;
        prefer.bindingGeneration = awgSameHost.nativeProfile.bindingGeneration;
        prefer.verifiedSuccessEwma = 1.0;
        history.insert(awgSameHost.profileId, prefer);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgSameHost, xraySameHost}, history,
                                             selection(), authority(catalog()), error));
        const TransportOperationToken failed = awg.starts.last();
        awg.emitEvent(failed, TransportEventKind::RuntimeError,
                      QStringLiteral("awg_path_blocked"));
        awg.emitEvent(failed, TransportEventKind::Stopped);
        CHECK(xray.startCalls == 1);
        CHECK(xray.startedProfileIds.last() == xraySameHost.profileId);
    }

    // maxAttempts bounds one acquisition episode. A verified session resets that budget so a
    // later runtime failure can still reach a third candidate instead of being stranded by the
    // attempts that were consumed before the healthy session existed.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        Catalog bounded = catalog();
        bounded.policy.maxAttempts = 2;
        CatalogCandidate first = awgCandidate(QStringLiteral("episode-awg-first"));
        CatalogCandidate healthy = xrayCandidate(QStringLiteral("episode-xray-healthy"));
        CatalogCandidate later = awgCandidate(QStringLiteral("episode-awg-later"));
        first.failureDomain = QStringLiteral("episode/domain-a");
        healthy.failureDomain = QStringLiteral("episode/domain-b");
        later.failureDomain = QStringLiteral("episode/domain-c");
        QHash<QString, CandidateHistory> history;
        CandidateHistory preferFirst;
        preferFirst.configGeneration = first.nativeProfile.configGeneration;
        preferFirst.bindingGeneration = first.nativeProfile.bindingGeneration;
        preferFirst.verifiedSuccessEwma = 1.0;
        preferFirst.verifiedStartLatencyMs = 1.0;
        history.insert(first.profileId, preferFirst);
        CHECK(reducer.connectAcceptedCatalog(bounded, {first, healthy, later}, history,
                                             selection(), authority(bounded), error));
        const TransportOperationToken firstToken = awg.starts.last();
        awg.emitEvent(firstToken, TransportEventKind::RuntimeError);
        awg.emitEvent(firstToken, TransportEventKind::Stopped);
        const TransportOperationToken healthyToken = xray.starts.last();
        xray.emitEvent(healthyToken, TransportEventKind::TunnelReady);
        const VerificationToken proof = verifier.lastToken;
        verifier.emitStage(proof, PostTunnelVerificationStage::Traffic);
        verifier.emitResult({proof, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {},
                             QStringLiteral("fi-exit"), 10, 0,
                             clock.now.addSecs(25)});
        CHECK(reducer.phase() == ConnectionPhase::ConnectedHealthy
              && reducer.snapshot().attemptsUsed == 0);
        xray.emitEvent(healthyToken, TransportEventKind::RuntimeError);
        xray.emitEvent(healthyToken, TransportEventKind::Stopped);
        CHECK(awg.startCalls == 2
              && awg.startedProfileIds.last() == later.profileId);
    }

    // A newer authoritative catalog with no compatible candidate revokes the old desired set. It
    // closes v1 and serially tears down the owned session instead of orphaning old credentials.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        const TransportOperationToken owned = awg.starts.last();
        CHECK(awg.nativeOwned);
        CHECK(!reducer.connectAcceptedCatalog(catalog(), {}, {}, selection(),
                                              authority(catalog()), error));
        CHECK(!reducer.legacyV1Allowed());
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld);
        CHECK(awg.stopCalls == 1 && awg.nativeOwned);
        awg.emitEvent(owned, TransportEventKind::Stopped);
        CHECK(!awg.nativeOwned);
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(reducer.snapshot().lastTypedReason == QLatin1String("no_candidate"));
        CHECK(awg.startCalls == 1);
    }

    // Compile-only rejection is profile-scoped (same domain remains eligible), but every compile
    // or start-dispatch attempt still consumes max_attempts.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CatalogCandidate invalidA = awgCandidate(QStringLiteral("invalid-a"));
        CatalogCandidate invalidB = awgCandidate(QStringLiteral("invalid-b"));
        invalidA.nativeProfile.config[QStringLiteral("raw_config")] = QStringLiteral("deny");
        invalidB.nativeProfile.config[QStringLiteral("raw_config")] = QStringLiteral("deny");
        invalidA.failureDomain = invalidB.failureDomain = QStringLiteral("same/domain/host");
        Catalog bounded = catalog();
        bounded.policy.maxAttempts = 2;
        CHECK(!reducer.connectAcceptedCatalog(bounded, {invalidA, invalidB}, {},
                                              selection(), authority(bounded), error));
        CHECK(awg.compileCalls == 2);
        CHECK(awg.startCalls == 0);
        CHECK(reducer.snapshot().attemptsUsed == 2);
        const ConnectionRuntimeSnapshot compileFailure = reducer.snapshot();
        CHECK(!compileFailure.session.isValid()
              && (compileFailure.profileId == invalidA.profileId
                  || compileFailure.profileId == invalidB.profileId)
              && compileFailure.configGeneration
                     == invalidA.nativeProfile.configGeneration
              && compileFailure.bindingGeneration
                     == invalidA.nativeProfile.bindingGeneration);
        CHECK(reducer.updatedHistory().contains(invalidA.profileId));
        CHECK(reducer.updatedHistory().contains(invalidB.profileId));
    }

    // Both synchronous start rejection and deferred StartRejected guarantee zero native ownership.
    // Therefore fallback may start immediately without issuing a meaningless or unsafe stop.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        QHash<QString, CandidateHistory> history;
        CandidateHistory preferAwg;
        preferAwg.configGeneration = awgCandidate().nativeProfile.configGeneration;
        preferAwg.bindingGeneration = awgCandidate().nativeProfile.bindingGeneration;
        preferAwg.verifiedSuccessEwma = 1.0;
        history.insert(QStringLiteral("fi-awg"), preferAwg);

        awg.rejectNextStart = true;
        ConnectionReducer synchronous(&registry, &verifier, &guard, &clock);
        CHECK(synchronous.connectAcceptedCatalog(
            catalog(), {awgCandidate(), xrayCandidate()}, history, selection(),
            authority(catalog()), error));
        CHECK(!awg.nativeOwned && awg.stopCalls == 0);
        CHECK(xray.startCalls == 1 && xray.nativeOwned);

        // Complete the first reducer's owned fallback before reusing the fake adapters.
        synchronous.disconnect();
        const TransportOperationToken xrayStop = xray.stops.last();
        xray.emitEvent(xrayStop, TransportEventKind::Stopped);
        CHECK(!xray.nativeOwned);

        FakeGuard deferredGuard;
        awg.rejectNextStartDeferred = true;
        ConnectionReducer deferred(&registry, &verifier, &deferredGuard, &clock);
        CHECK(deferred.connectAcceptedCatalog(
            catalog(), {awgCandidate(), xrayCandidate()}, history, selection(),
            authority(catalog()), error));
        const TransportOperationToken rejected = awg.starts.last();
        CHECK(!awg.nativeOwned);
        awg.emitEvent(rejected, TransportEventKind::StartRejected,
                      QStringLiteral("pre_dispatch_policy_rejected"));
        CHECK(awg.stopCalls == 0);
        CHECK(xray.startCalls == 2 && xray.nativeOwned);
    }

    // Required session guard fails closed before native start.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        guard.reject = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(!reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                              authority(catalog()), error));
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(awg.startCalls == 0);
        CHECK(!reducer.legacyV1Allowed());
    }

    // Guard arming/release are receipt-driven. Stale/duplicate callbacks never start or release a
    // different native attempt, and ambiguous timeout remains blocked fail-closed.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        guard.deferArm = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        CHECK(reducer.phase() == ConnectionPhase::ArmingGuard && awg.startCalls == 0);
        const TransportOperationToken pending = guard.armedFor;
        CHECK(QUuid(guard.expectedRuntimeSessionId)
                  .toString(QUuid::WithoutBraces).toLower()
              == guard.expectedRuntimeSessionId);
        reducer.onConnectionSessionGuardEvent(
            {{pending.operation, pending.session + 1}, ConnectionGuardEventKind::Armed,
             guard.policySha256, QStringLiteral("outer-stale"), {}});
        CHECK(reducer.phase() == ConnectionPhase::ArmingGuard && awg.startCalls == 0);
        reducer.onConnectionSessionGuardEvent(
            {pending, ConnectionGuardEventKind::Armed, guard.policySha256,
             guard.outerSessionId, {},
             QUuid::createUuid().toString(QUuid::WithoutBraces).toLower()});
        CHECK(reducer.phase() == ConnectionPhase::ArmingGuard && awg.startCalls == 0);
        guard.emitArmCompleted();
        CHECK(reducer.phase() == ConnectionPhase::StartingTransport && awg.startCalls == 1);
        guard.emitArmCompleted();
        CHECK(awg.startCalls == 1); // duplicate exact receipt is idempotent
    }
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        guard.deferArm = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        const TransportOperationToken pending = guard.armedFor;
        const QByteArray policy = guard.policySha256;
        reducer.onGuardArmTimeout(pending, policy);
        CHECK(reducer.phase() == ConnectionPhase::Failed && awg.startCalls == 0);
        CHECK(reducer.snapshot().guardOwnershipAmbiguous
              && guard.armReconcileCalls == 1
              && guard.lastReconciledArm == pending
              && guard.lastReconciledPolicy == policy);
        reducer.disconnect();
        CHECK(reducer.phase() == ConnectionPhase::Failed
              && reducer.snapshot().guardOwnershipAmbiguous);
        const int startsBeforeRecovery = awg.startCalls;
        CHECK(!reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                              authority(catalog()), error));
        CHECK(awg.startCalls == startsBeforeRecovery); // no new PREPARE under ambiguity
        guard.deferRelease = true;
        guard.emitArmCompleted();
        CHECK(reducer.phase() == ConnectionPhase::ReleasingGuard && guard.armed
              && !reducer.snapshot().guardOwnershipAmbiguous);
        reducer.disconnect();
        CHECK(reducer.phase() == ConnectionPhase::ReleasingGuard && guard.armed
              && !reducer.snapshot().guardOwnershipAmbiguous);
        guard.completeDeferredRelease();
        CHECK(reducer.phase() == ConnectionPhase::Idle && !guard.armed
              && !reducer.snapshot().guardOwnershipAmbiguous);
    }
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        const TransportOperationToken active = awg.starts.last();
        awg.emitEvent(active, TransportEventKind::TunnelReady);
        guard.deferRelease = true;
        reducer.disconnect();
        awg.emitEvent(active, TransportEventKind::Stopped);
        CHECK(reducer.phase() == ConnectionPhase::ReleasingGuard && guard.armed);
        CHECK(reducer.snapshot().lifecycleWait.kind
                  == ConnectionLifecycleWaitKind::GuardRelease);
        reducer.onGuardReleaseTimeout(active);
        CHECK(reducer.phase() == ConnectionPhase::Failed
              && reducer.snapshot().guardOwnershipAmbiguous
              && guard.releaseReconcileCalls == 1
              && guard.lastReconciledRelease == active);
        reducer.onConnectionSessionGuardEvent(
            {{active.operation, active.session + 1}, ConnectionGuardEventKind::Released,
             {}, QStringLiteral("outer-stale"), {}});
        CHECK(reducer.phase() == ConnectionPhase::Failed && guard.armed
              && reducer.snapshot().guardOwnershipAmbiguous);
        reducer.onConnectionSessionGuardEvent(
            {active, ConnectionGuardEventKind::Released, QByteArray(32, '\x7f'),
             guard.outerSessionId, {}, guard.expectedRuntimeSessionId});
        reducer.onConnectionSessionGuardEvent(
            {active, ConnectionGuardEventKind::Released, guard.policySha256,
             guard.outerSessionId, {},
             QUuid::createUuid().toString(QUuid::WithoutBraces).toLower()});
        CHECK(reducer.phase() == ConnectionPhase::Failed && guard.armed
              && reducer.snapshot().guardOwnershipAmbiguous);
        guard.completeDeferredRelease();
        CHECK(reducer.phase() == ConnectionPhase::Idle && !guard.armed
              && !reducer.snapshot().guardOwnershipAmbiguous);
    }
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        guard.deferArm = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        reducer.disconnect();
        guard.emitArmCompleted();
        CHECK(awg.startCalls == 0 && reducer.phase() == ConnectionPhase::Idle
              && !guard.armed);
    }
    {
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        guard.deferArm = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        const TransportOperationToken pending = guard.armedFor;
        const QByteArray policy = guard.policySha256;
        const QString outer = guard.outerSessionId;
        guard.armed = false;
        const ConnectionGuardEvent lost{
            pending, ConnectionGuardEventKind::Lost, policy, outer,
            QStringLiteral("guard_lost"), guard.expectedRuntimeSessionId};
        guard.recoveryIdentity = lost;
        reducer.onConnectionSessionGuardEvent(lost);
        CHECK(reducer.phase() == ConnectionPhase::Failed && awg.startCalls == 0
              && reducer.snapshot().guardOwnershipAmbiguous);
        reducer.onConnectionSessionGuardEvent(
            {pending, ConnectionGuardEventKind::Armed, policy, outer, {},
             guard.expectedRuntimeSessionId});
        reducer.onConnectionSessionGuardEvent(
            {pending, ConnectionGuardEventKind::ArmRejected, {}, {},
             QStringLiteral("late_reject"), {}});
        CHECK(reducer.phase() == ConnectionPhase::Failed && awg.startCalls == 0);
        ConnectionGuardEvent staleRecovery = lost;
        staleRecovery.operation.session++;
        reducer.onGuardRecoveryReleased(staleRecovery);
        CHECK(reducer.snapshot().guardOwnershipAmbiguous
              && guard.recoveryReleaseCalls == 0);
        reducer.onGuardRecoveryReleased(lost);
        CHECK(!reducer.snapshot().guardOwnershipAmbiguous
              && guard.recoveryReleaseCalls == 1);
    }
    {
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate(), xrayCandidate()}, {},
                                             selection(), authority(catalog()), error));
        const TransportOperationToken active = awg.starts.last();
        awg.emitEvent(active, TransportEventKind::RuntimeError,
                      QStringLiteral("native_runtime_error"));
        const QString outer = guard.outerSessionId;
        guard.armed = false;
        reducer.onConnectionSessionGuardEvent(
            {active, ConnectionGuardEventKind::Lost, guard.policySha256, outer,
             QStringLiteral("guard_lost"), guard.expectedRuntimeSessionId});
        awg.emitEvent(active, TransportEventKind::Stopped);
        CHECK(reducer.phase() == ConnectionPhase::Failed && xray.startCalls == 0);
    }

    // Runtime failure cooldown uses event time (not the hours-old catalog request timestamp), and
    // a lost platform guard blocks the fallback before any second native start.
    {
        FakeClock eventClock;
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &eventClock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate(), xrayCandidate()}, {},
                                             selection(), authority(catalog()), error));
        const TransportOperationToken failed = awg.starts.last();
        eventClock.now = QDateTime::fromString(QStringLiteral("2026-08-28T18:00:00Z"),
                                               Qt::ISODate);
        awg.emitEvent(failed, TransportEventKind::RuntimeError,
                      QStringLiteral("native_runtime_error"));
        CHECK(reducer.updatedHistory().value(QStringLiteral("fi-awg")).cooldownUntil
              == eventClock.now.addSecs(catalog().policy.profileCooldownS));
        guard.armed = false; // simulate platform blocking-route owner being lost unexpectedly
        awg.emitEvent(failed, TransportEventKind::Stopped);
        CHECK(xray.startCalls == 0);
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(reducer.snapshot().lastTypedReason == QLatin1String("guard_lost"));
    }

    // A terminal zero-ownership rejection releases only its exact guard token. Fallback replaces
    // the token atomically without a broad disarm; failed re-prepare releases the retained old
    // token instead of leaving an ambiguous permanent block.
    {
        QString error;
        FakeAdapter only(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        CHECK(registry.add(&only, error));
        FakeVerifier verifier;
        FakeGuard guard;
        only.rejectNextStart = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        // Async guard dispatch was accepted; the synchronous fake immediately reports Armed and
        // the adapter then rejects. The request return value is dispatch acceptance, not outcome.
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(!guard.armed && guard.disarmCalls == 1 && only.stopCalls == 0);
    }
    {
        QString error;
        FakeAdapter only(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        CHECK(registry.add(&only, error));
        FakeVerifier verifier;
        FakeGuard guard;
        only.rejectNextStartDeferred = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        const TransportOperationToken rejected = only.starts.last();
        only.emitEvent(rejected, TransportEventKind::StartRejected,
                       QStringLiteral("start_rejected"));
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(!guard.armed && guard.disarmCalls == 1 && only.stopCalls == 0);
    }
    {
        QString error;
        FakeAdapter only(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        CHECK(registry.add(&only, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {}, selection(),
                                             authority(catalog()), error));
        const TransportOperationToken failed = only.starts.last();
        only.emitEvent(failed, TransportEventKind::RuntimeError);
        CHECK(guard.armed && only.stopCalls == 1);
        only.emitEvent(failed, TransportEventKind::Stopped);
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(guard.armed && guard.disarmCalls == 0 && reducer.snapshot().guardArmed);
        reducer.disconnect();
        CHECK(reducer.phase() == ConnectionPhase::Idle);
        CHECK(!guard.armed && guard.disarmCalls == 1);
    }
    {
        QString error;
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        awg.rejectNextStart = true;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate(), xrayCandidate()}, {},
                                             selection(), authority(catalog()), error));
        CHECK(guard.armCalls == 2 && guard.disarmCalls == 0 && guard.armed);
        CHECK(guard.armedFor == xray.starts.last() && xray.startCalls == 1);
    }
    {
        QString error;
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        awg.rejectNextStart = true;
        guard.rejectOnArmCall = 2;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate(), xrayCandidate()}, {},
                                             selection(), authority(catalog()), error));
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(!guard.armed && guard.disarmCalls == 1 && xray.startCalls == 0);
    }

    // Credential expiry is rechecked on fallback against the trusted runtime clock.
    {
        FakeClock expiryClock;
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &expiryClock);
        CatalogCandidate awgProfile = awgCandidate();
        CatalogCandidate xrayProfile = xrayCandidate();
        const QDateTime deadline = QDateTime::fromString(
            QStringLiteral("2026-08-28T10:02:00Z"), Qt::ISODate);
        awgProfile.nativeProfile.expiresAt = deadline;
        xrayProfile.nativeProfile.expiresAt = deadline;
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgProfile, xrayProfile}, {},
                                             selection(), authority(catalog()), error));
        const TransportOperationToken failed = awg.starts.last();
        awg.emitEvent(failed, TransportEventKind::RuntimeError);
        expiryClock.now = deadline;
        awg.emitEvent(failed, TransportEventKind::Stopped);
        CHECK(xray.startCalls == 0);
        CHECK(reducer.phase() == ConnectionPhase::Failed);
    }

    // LKG freshness is independent from catalog network expiry. The signed offline grace may keep
    // an already provisioned credential usable, but its exact boundary remains a hard stop.
    {
        Catalog graceCatalog = catalog();
        graceCatalog.expiresAt = QDateTime::fromString(
            QStringLiteral("2026-08-28T10:00:00Z"), Qt::ISODate);
        graceCatalog.policy.offlineGraceS = 3600;
        CatalogTrustLimits exactLifetime;
        exactLifetime.allowedClockSkewS = 0;
        FakeClock graceClock;
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &graceClock);
        CHECK(reducer.connectAcceptedCatalog(
            graceCatalog, {awgCandidate()}, {}, selection(),
            authority(graceCatalog, CatalogSource::LastKnownGood, exactLifetime), error));
        CHECK(awg.startCalls == 1);

        FakeClock expiredClock;
        expiredClock.now = graceCatalog.expiresAt.addSecs(graceCatalog.policy.offlineGraceS);
        FakeAdapter expiredAwg(TransportKind::Awg, options);
        TransportAdapterRegistry expiredRegistry;
        CHECK(expiredRegistry.add(&expiredAwg, error));
        FakeVerifier expiredVerifier;
        FakeGuard expiredGuard;
        ConnectionReducer expiredReducer(&expiredRegistry, &expiredVerifier, &expiredGuard,
                                          &expiredClock);
        CandidateSelectionRequest expiredRequest = selection();
        expiredRequest.nowUtc = expiredClock.now;
        CHECK(!expiredReducer.connectAcceptedCatalog(
            graceCatalog, {awgCandidate()}, {}, expiredRequest,
            authority(graceCatalog, CatalogSource::LastKnownGood, exactLifetime), error));
        CHECK(expiredAwg.startCalls == 0);
        CHECK(expiredReducer.snapshot().lastTypedReason
              == QLatin1String("catalog_runtime_policy"));
    }

    {
        // Periodic catalog refresh with byte-identical native generations renews authority on the
        // exact live session. The old deadline timer is stale after renewal; a material generation
        // change still serializes stop -> Stopped -> start.
        FakeClock refreshClock;
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &refreshClock);
        Catalog firstCatalog = catalog();
        CatalogCandidate firstCandidate = awgCandidate();
        CHECK(reducer.connectAcceptedCatalog(firstCatalog, {firstCandidate}, {}, selection(),
                                             authority(firstCatalog), error));
        const TransportOperationToken live = awg.starts.last();
        awg.emitEvent(live, TransportEventKind::TunnelReady);
        const VerificationToken proof = verifier.lastToken;
        verifier.emitStage(proof, PostTunnelVerificationStage::Traffic);
        verifier.emitResult({proof, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {},
                             QStringLiteral("fi-exit"), 10, 0,
                             refreshClock.now.addSecs(25)});
        CHECK(reducer.phase() == ConnectionPhase::ConnectedHealthy);
        CHECK(reducer.snapshot().verifiedAtUtc == refreshClock.now);

        Catalog refreshed = firstCatalog;
        refreshed.catalogRevision = 11;
        refreshed.payloadSha256 = QByteArray(32, '\x6b');
        refreshed.issuedAt = refreshClock.now;
        refreshed.expiresAt = firstCatalog.expiresAt.addDays(1);
        CatalogCandidate renewedCandidate = firstCandidate;
        renewedCandidate.nativeProfile.expiresAt = firstCandidate.nativeProfile.expiresAt.addDays(1);
        CandidateSelectionRequest refreshedSelection = selection();
        refreshedSelection.nowUtc = refreshClock.now;
        CHECK(reducer.reconcileAcceptedCatalog(
            refreshed, {renewedCandidate}, {}, refreshedSelection,
            authority(refreshed), error));
        CHECK(reducer.snapshot().catalogFreshnessDeadline
              == authority(firstCatalog).freshnessDeadline);
        awg.emitAuthorityEvent(TransportEventKind::AuthorityRenewed, {}, {},
                               QByteArray(32, 'x'));
        CHECK(reducer.snapshot().catalogFreshnessDeadline
              == authority(firstCatalog).freshnessDeadline);
        awg.emitAuthorityRenewed();
        CHECK(awg.renewCalls == 1 && awg.startCalls == 1 && awg.stopCalls == 0);
        CHECK(reducer.snapshot().session == live
              && reducer.phase() == ConnectionPhase::ConnectedHealthy
              && reducer.snapshot().catalogFreshnessDeadline
                     == authority(refreshed).freshnessDeadline);

        refreshClock.now = firstCatalog.expiresAt.addSecs(300);
        reducer.onAuthorityDeadline(live); // old catalog deadline: stale after renewal
        CHECK(reducer.phase() == ConnectionPhase::ConnectedHealthy && awg.stopCalls == 0);

        Catalog changed = refreshed;
        changed.catalogRevision = 12;
        changed.payloadSha256 = QByteArray(32, '\x5c');
        changed.issuedAt = refreshClock.now;
        changed.expiresAt = refreshed.expiresAt.addDays(1);
        CatalogCandidate changedCandidate = renewedCandidate;
        changedCandidate.nativeProfile.configGeneration += 1;
        changedCandidate.nativeProfile.expiresAt = renewedCandidate.nativeProfile.expiresAt.addDays(1);
        refreshedSelection.nowUtc = refreshClock.now;
        CHECK(reducer.reconcileAcceptedCatalog(
            changed, {changedCandidate}, {}, refreshedSelection,
            authority(changed), error));
        CHECK(awg.renewCalls == 1 && awg.stopCalls == 1
              && reducer.phase() == ConnectionPhase::StoppingOld);
        awg.emitEvent(live, TransportEventKind::Stopped);
        CHECK(awg.startCalls == 2 && reducer.phase() == ConnectionPhase::StartingTransport);
    }

    {
        // Concurrent refreshes never overwrite an in-flight native identity. The first exact
        // receipt commits revision 11, then immediately dispatches the queued revision 12; only
        // its own receipt advances the effective deadline.
        FakeClock queuedClock;
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &queuedClock);
        Catalog base = catalog();
        CatalogCandidate candidate = awgCandidate();
        CHECK(reducer.connectAcceptedCatalog(base, {candidate}, {}, selection(),
                                             authority(base), error));
        Catalog revision11 = base;
        revision11.catalogRevision = 11;
        revision11.payloadSha256 = QByteArray(32, '\x71');
        revision11.expiresAt = base.expiresAt.addDays(1);
        revision11.issuedAt = queuedClock.now;
        CatalogCandidate candidate11 = candidate;
        candidate11.nativeProfile.expiresAt = candidate.nativeProfile.expiresAt.addDays(1);
        CHECK(reducer.reconcileAcceptedCatalog(revision11, {candidate11}, {}, selection(),
                                               authority(revision11), error));
        const TransportAuthorityRenewalDispatch firstDispatch = awg.lastRenewalDispatch;

        Catalog revision12 = revision11;
        revision12.catalogRevision = 12;
        revision12.payloadSha256 = QByteArray(32, '\x72');
        revision12.expiresAt = revision11.expiresAt.addDays(1);
        CatalogCandidate candidate12 = candidate11;
        candidate12.nativeProfile.expiresAt = candidate11.nativeProfile.expiresAt.addDays(1);
        CHECK(reducer.reconcileAcceptedCatalog(revision12, {candidate12}, {}, selection(),
                                               authority(revision12), error));
        CHECK(awg.renewCalls == 1);
        awg.emitAuthorityEvent(TransportEventKind::AuthorityRenewed, {},
                               firstDispatch.renewalId,
                               firstDispatch.authorityCommitmentSha256,
                               firstDispatch.requestedHardDeadlineUtc);
        CHECK(awg.renewCalls == 2
              && reducer.snapshot().catalogFreshnessDeadline
                     == authority(revision11).freshnessDeadline);
        awg.emitAuthorityRenewed();
        CHECK(reducer.snapshot().catalogFreshnessDeadline
                  == authority(revision12).freshnessDeadline
              && awg.startCalls == 1 && awg.stopCalls == 0);
    }

    {
        // Missing native receipt retains the old authority and falls back to a serialized exact
        // restart. A late Applied callback for the timed-out renewal id is ignored.
        FakeClock timeoutClock;
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &timeoutClock);
        Catalog base = catalog();
        CatalogCandidate candidate = awgCandidate();
        CHECK(reducer.connectAcceptedCatalog(base, {candidate}, {}, selection(),
                                             authority(base), error));
        const TransportOperationToken live = awg.starts.last();
        Catalog refreshed = base;
        refreshed.catalogRevision = 11;
        refreshed.payloadSha256 = QByteArray(32, '\x73');
        refreshed.expiresAt = base.expiresAt.addDays(1);
        CatalogCandidate renewed = candidate;
        renewed.nativeProfile.expiresAt = candidate.nativeProfile.expiresAt.addDays(1);
        CHECK(reducer.reconcileAcceptedCatalog(refreshed, {renewed}, {}, selection(),
                                               authority(refreshed), error));
        const TransportAuthorityRenewalDispatch timed = awg.lastRenewalDispatch;
        awg.emitAuthorityEvent(TransportEventKind::AuthorityRenewalTimedOut,
                               QStringLiteral("receipt_timeout"));
        CHECK(awg.stopCalls == 1 && awg.stops.last() == live
              && reducer.phase() == ConnectionPhase::StoppingOld);
        awg.emitAuthorityEvent(TransportEventKind::AuthorityRenewed, {}, timed.renewalId,
                               timed.authorityCommitmentSha256,
                               timed.requestedHardDeadlineUtc);
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld
              && reducer.snapshot().catalogFreshnessDeadline
                     == authority(refreshed).freshnessDeadline);
    }

    {
        // User OFF wins over an in-flight renewal. The exact session is stopped and a late durable
        // receipt cannot reconnect or resurrect the cleared desired catalog.
        FakeClock offClock;
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &offClock);
        Catalog base = catalog();
        CatalogCandidate candidate = awgCandidate();
        CHECK(reducer.connectAcceptedCatalog(base, {candidate}, {}, selection(),
                                             authority(base), error));
        Catalog refreshed = base;
        refreshed.catalogRevision = 11;
        refreshed.payloadSha256 = QByteArray(32, '\x74');
        refreshed.expiresAt = base.expiresAt.addDays(1);
        CatalogCandidate renewed = candidate;
        renewed.nativeProfile.expiresAt = candidate.nativeProfile.expiresAt.addDays(1);
        CHECK(reducer.reconcileAcceptedCatalog(refreshed, {renewed}, {}, selection(),
                                               authority(refreshed), error));
        const TransportAuthorityRenewalDispatch late = awg.lastRenewalDispatch;
        reducer.disconnect();
        CHECK(awg.stopCalls == 1 && reducer.phase() == ConnectionPhase::Disconnecting);
        awg.emitAuthorityEvent(TransportEventKind::AuthorityRenewed, {}, late.renewalId,
                               late.authorityCommitmentSha256,
                               late.requestedHardDeadlineUtc);
        CHECK(awg.startCalls == 1 && reducer.phase() == ConnectionPhase::Disconnecting);
    }

    {
        // A green session is retained before minimum dwell. Afterwards, switching is allowed only
        // when a generation-matched challenger has materially better locally verified traffic
        // history; the transition remains serialized through exact old-session Stopped.
        FakeClock qualityClock;
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &qualityClock);
        Catalog firstCatalog = catalog();
        firstCatalog.policy.minimumDwellS = 300;
        CatalogCandidate active = awgCandidate();
        CatalogCandidate challenger = xrayCandidate();
        QHash<QString, CandidateHistory> history;
        CandidateHistory poorCurrent;
        poorCurrent.configGeneration = active.nativeProfile.configGeneration;
        poorCurrent.bindingGeneration = active.nativeProfile.bindingGeneration;
        poorCurrent.verifiedSuccessEwma = 0.0;
        poorCurrent.survival5mEwma = 0.0;
        poorCurrent.verifiedStartLatencyMs = 12000.0;
        history.insert(active.profileId, poorCurrent);
        CandidateHistory provenChallenger;
        provenChallenger.configGeneration = challenger.nativeProfile.configGeneration;
        provenChallenger.bindingGeneration = challenger.nativeProfile.bindingGeneration;
        provenChallenger.verifiedSuccessEwma = 1.0;
        provenChallenger.survival5mEwma = 1.0;
        provenChallenger.verifiedStartLatencyMs = 10.0;
        provenChallenger.lastVerifiedAtUtc = qualityClock.now.addSecs(-60);
        history.insert(challenger.profileId, provenChallenger);

        CHECK(reducer.connectAcceptedCatalog(firstCatalog, {active}, history, selection(),
                                             authority(firstCatalog), error));
        const TransportOperationToken live = awg.starts.last();
        awg.emitEvent(live, TransportEventKind::TunnelReady);
        const VerificationToken proof = verifier.lastToken;
        verifier.emitStage(proof, PostTunnelVerificationStage::Traffic);
        verifier.emitResult({proof, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {},
                             QStringLiteral("fi-exit"), 10, 0,
                             qualityClock.now.addSecs(25)});
        CHECK(reducer.phase() == ConnectionPhase::ConnectedHealthy);

        Catalog beforeDwell = firstCatalog;
        beforeDwell.catalogRevision = 11;
        beforeDwell.payloadSha256 = QByteArray(32, '\x61');
        beforeDwell.issuedAt = qualityClock.now;
        beforeDwell.expiresAt = firstCatalog.expiresAt.addDays(1);
        CatalogCandidate activeRenewed = active;
        activeRenewed.nativeProfile.expiresAt = active.nativeProfile.expiresAt.addDays(1);
        CandidateSelectionRequest request = selection();
        request.nowUtc = qualityClock.now;
        CHECK(reducer.reconcileAcceptedCatalog(beforeDwell,
                                               {activeRenewed, challenger}, history, request,
                                               authority(beforeDwell), error));
        awg.emitAuthorityRenewed();
        CHECK(awg.renewCalls == 1 && awg.stopCalls == 0 && xray.startCalls == 0);

        qualityClock.now = qualityClock.now.addSecs(301);
        Catalog afterDwell = beforeDwell;
        afterDwell.catalogRevision = 12;
        afterDwell.payloadSha256 = QByteArray(32, '\x62');
        afterDwell.issuedAt = qualityClock.now;
        afterDwell.expiresAt = beforeDwell.expiresAt.addDays(1);
        activeRenewed.nativeProfile.expiresAt = activeRenewed.nativeProfile.expiresAt.addDays(1);
        challenger.nativeProfile.expiresAt = challenger.nativeProfile.expiresAt.addDays(2);
        request.nowUtc = qualityClock.now;
        CHECK(reducer.reconcileAcceptedCatalog(afterDwell,
                                               {activeRenewed, challenger}, history, request,
                                               authority(afterDwell), error));
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld && awg.stopCalls == 1);
        awg.emitEvent(live, TransportEventKind::Stopped);
        CHECK(xray.startCalls == 1
              && xray.startedProfileIds.last() == challenger.profileId);
    }

    {
        // Even after dwell, extreme signed server hints alone cannot churn a locally verified
        // healthy session. A forced user transport intent remains authoritative and does restart.
        FakeClock qualityClock;
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &qualityClock);
        Catalog firstCatalog = catalog();
        firstCatalog.policy.minimumDwellS = 10;
        CatalogCandidate active = awgCandidate();
        CHECK(reducer.connectAcceptedCatalog(firstCatalog, {active}, {}, selection(),
                                             authority(firstCatalog), error));
        const TransportOperationToken live = awg.starts.last();
        awg.emitEvent(live, TransportEventKind::TunnelReady);
        const VerificationToken proof = verifier.lastToken;
        verifier.emitStage(proof, PostTunnelVerificationStage::Traffic);
        verifier.emitResult({proof, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {},
                             QStringLiteral("fi-exit"), 10, 0,
                             qualityClock.now.addSecs(25)});
        const QString originalOuterGuard = guard.outerSessionId;
        qualityClock.now = qualityClock.now.addSecs(20);

        Catalog hinted = firstCatalog;
        hinted.catalogRevision = 11;
        hinted.payloadSha256 = QByteArray(32, '\x63');
        hinted.issuedAt = qualityClock.now;
        hinted.expiresAt = firstCatalog.expiresAt.addDays(1);
        CatalogCandidate degradedActive = active;
        degradedActive.serverHealth = 0.01;
        degradedActive.capacityHeadroom = 0.0;
        degradedActive.healthObservedAt = qualityClock.now;
        degradedActive.nativeProfile.expiresAt = active.nativeProfile.expiresAt.addDays(1);
        CatalogCandidate unproven = xrayCandidate();
        unproven.serverHealth = 1.0;
        unproven.capacityHeadroom = 1.0;
        unproven.healthObservedAt = qualityClock.now;
        unproven.nativeProfile.expiresAt = unproven.nativeProfile.expiresAt.addDays(1);
        CandidateSelectionRequest request = selection();
        request.nowUtc = qualityClock.now;
        CHECK(reducer.reconcileAcceptedCatalog(hinted,
                                               {degradedActive, unproven}, {}, request,
                                               authority(hinted), error));
        awg.emitAuthorityRenewed();
        CHECK(awg.renewCalls == 1 && awg.stopCalls == 0 && xray.startCalls == 0);

        Catalog forced = hinted;
        forced.catalogRevision = 12;
        forced.payloadSha256 = QByteArray(32, '\x64');
        forced.issuedAt = qualityClock.now;
        forced.expiresAt = hinted.expiresAt.addDays(1);
        request.mode = ConnectionMode::ForceXray;
        CHECK(reducer.reconcileAcceptedCatalog(forced,
                                               {degradedActive, unproven}, {}, request,
                                               authority(forced), error));
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld && awg.stopCalls == 1);
        awg.emitEvent(live, TransportEventKind::Stopped);
        CHECK(xray.startCalls == 1
              && guard.armed && guard.armedFor.isValid()
              && guard.outerSessionId != originalOuterGuard
              && guard.armCalls == 2 && guard.disarmCalls == 0);
    }

    // A live verified transport switch keeps one continuous fail-closed outer owner. If the
    // replacement arm is rejected after the old inner has stopped, no new inner may start and the
    // old exact outer barrier must remain armed until an explicit Disconnect releases it.
    {
        FakeClock switchClock;
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &switchClock);
        Catalog initial = catalog();
        CatalogCandidate active = awgCandidate();
        CatalogCandidate replacement = xrayCandidate();
        CHECK(reducer.connectAcceptedCatalog(initial, {active}, {}, selection(),
                                             authority(initial), error));
        const TransportOperationToken live = awg.starts.last();
        awg.emitEvent(live, TransportEventKind::TunnelReady);
        const VerificationToken proof = verifier.lastToken;
        verifier.emitStage(proof, PostTunnelVerificationStage::Traffic);
        verifier.emitResult({proof, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {},
                             QStringLiteral("fi-exit"), 12, 0,
                             switchClock.now.addSecs(25)});
        CHECK(reducer.phase() == ConnectionPhase::ConnectedHealthy);
        const QString retainedOuter = guard.outerSessionId;

        Catalog forced = initial;
        forced.catalogRevision = 13;
        forced.payloadSha256 = QByteArray(32, '\x65');
        forced.issuedAt = switchClock.now;
        forced.expiresAt = initial.expiresAt.addDays(1);
        CandidateSelectionRequest request = selection();
        request.nowUtc = switchClock.now;
        request.mode = ConnectionMode::ForceXray;
        guard.rejectOnArmCall = 2;
        CHECK(reducer.reconcileAcceptedCatalog(forced, {active, replacement}, {}, request,
                                               authority(forced), error));
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld
              && awg.stopCalls == 1 && guard.disarmCalls == 0);
        awg.emitEvent(live, TransportEventKind::Stopped);
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(xray.startCalls == 0 && guard.armCalls == 2 && guard.disarmCalls == 0);
        CHECK(guard.armed && guard.armedFor == live
              && guard.outerSessionId == retainedOuter
              && reducer.snapshot().guardArmed);

        reducer.disconnect();
        CHECK(reducer.phase() == ConnectionPhase::Idle);
        CHECK(!guard.armed && guard.disarmCalls == 1);
    }

    // Exact authority deadline is a terminal hard stop; an old-session timer cannot stop a newer
    // session after serialized replacement.
    {
        FakeClock deadlineClock;
        FakeAdapter awg(TransportKind::Awg, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &deadlineClock);
        Catalog shortCatalog = catalog();
        shortCatalog.expiresAt = deadlineClock.now.addSecs(30);
        CatalogCandidate candidate = awgCandidate();
        candidate.nativeProfile.expiresAt = deadlineClock.now.addSecs(60);
        CHECK(reducer.connectAcceptedCatalog(shortCatalog, {candidate}, {}, selection(),
                                             authority(shortCatalog), error));
        const TransportOperationToken token = awg.starts.last();
        deadlineClock.now = shortCatalog.expiresAt.addSecs(300);
        reducer.onAuthorityDeadline(token);
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld && awg.stopCalls == 1);
        CHECK(reducer.snapshot().lastTypedReason
              == QLatin1String("runtime_authority_expired"));
        reducer.onAuthorityDeadline({token.operation, token.session + 1});
        CHECK(awg.stopCalls == 1);
    }

    // Reducer destruction detaches both raw observer boundaries and cancels the concrete verify
    // attempt, so queued callbacks cannot dereference freed state.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        VerificationToken liveVerification;
        {
            ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
            CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate()}, {},
                                                 selection(), authority(catalog()), error));
            const TransportOperationToken live = awg.starts.last();
            awg.emitEvent(live, TransportEventKind::TunnelReady);
            liveVerification = verifier.lastToken;
            CHECK(liveVerification.isValid());
        }
        CHECK(verifier.m_observer == nullptr && verifier.clearObserverCalls == 1);
        CHECK(awg.m_observer == nullptr && awg.clearObserverCalls == 1);
        CHECK(verifier.cancelled.contains(liveVerification));
        verifier.emitResult({liveVerification, VerificationDisposition::Verified,
                             ConnectionFailureStage::None, {}, QStringLiteral("fi-exit"), 1, 0,
                             clock.now.addSecs(25)});
    }

    // Stop timeout cannot start a replacement or release the no-leak guard.
    {
        FakeAdapter awg(TransportKind::Awg, options);
        FakeAdapter xray(TransportKind::Xray, options);
        TransportAdapterRegistry registry;
        QString error;
        CHECK(registry.add(&awg, error));
        CHECK(registry.add(&xray, error));
        FakeVerifier verifier;
        FakeGuard guard;
        ConnectionReducer reducer(&registry, &verifier, &guard, &clock);
        QHash<QString, CandidateHistory> history;
        CandidateHistory preferAwg;
        preferAwg.configGeneration = awgCandidate().nativeProfile.configGeneration;
        preferAwg.bindingGeneration = awgCandidate().nativeProfile.bindingGeneration;
        preferAwg.verifiedSuccessEwma = 1.0;
        history.insert(QStringLiteral("fi-awg"), preferAwg);
        CHECK(reducer.connectAcceptedCatalog(catalog(), {awgCandidate(), xrayCandidate()},
                                             history, selection(), authority(catalog()), error));
        const TransportOperationToken token = awg.starts.last();
        awg.emitEvent(token, TransportEventKind::RuntimeError,
                      QStringLiteral("native_runtime_error"));
        CHECK(reducer.phase() == ConnectionPhase::StoppingOld);
        const int startsBefore = awg.startCalls + xray.startCalls;
        reducer.onStopTimeout(token);
        CHECK(reducer.phase() == ConnectionPhase::Failed);
        CHECK(guard.armed);
        CHECK(awg.startCalls + xray.startCalls == startsBefore);
        awg.emitEvent(token, TransportEventKind::Stopped);
        CHECK(awg.startCalls + xray.startCalls == startsBefore + 1); // only after real terminal
    }

    if (g_failed) {
        fprintf(stderr, "transport_runtime_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("transport_runtime_check: OK (%d compiler/sanitizer/reducer/token/guard checks)\n",
           g_total);
    return 0;
}
