#include "../daemon/macosnativesessionguard.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QVector>

#include <cstdlib>
#include <functional>
#include <iostream>
#include <utility>

namespace {

void require(bool condition, const char *message)
{
    if (!condition) {
        std::cerr << "MacosNativeSessionGuardTests: " << message << '\n';
        std::exit(1);
    }
}

QJsonObject fixture(const QString &path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "fixture open failed");
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &error);
    require(error.error == QJsonParseError::NoError && document.isObject(),
            "fixture parse failed");
    return document.object();
}

QJsonObject identityRequest(const QString &type, const QJsonObject &armed,
                            const QString &protocol = {})
{
    QJsonObject request{
        {QStringLiteral("type"), type}, {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), armed.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), armed.value(QStringLiteral("session"))},
        {QStringLiteral("policy_sha256"), armed.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"),
         armed.value(QStringLiteral("outer_session_id"))},
        {QStringLiteral("expected_runtime_session_id"),
         armed.value(QStringLiteral("expected_runtime_session_id"))},
    };
    if (!protocol.isEmpty()) request.insert(QStringLiteral("protocol"), protocol);
    return request;
}

QJsonObject macSupportedConfiguration(QJsonObject config, const QString &endpoint)
{
    config.insert(QStringLiteral("appSplitTunnelType"), 0);
    config.insert(QStringLiteral("splitTunnelApps"), QJsonArray{});
    const QString previousEndpoint = config.value(QStringLiteral("hostName")).toString();
    config.insert(QStringLiteral("hostName"), endpoint);

    const QString protocol = config.value(QStringLiteral("protocol")).toString();
    const QString nativeKey = protocol == QLatin1String("awg")
        ? QStringLiteral("awg_config_data") : QStringLiteral("xray_config_data");
    QJsonObject native = config.value(nativeKey).toObject();
    if (protocol == QLatin1String("awg")) {
        native.insert(QStringLiteral("hostName"), endpoint);
        QString quick = native.value(QStringLiteral("config")).toString();
        quick.replace(QStringLiteral("Endpoint = %1:").arg(previousEndpoint),
                      QStringLiteral("Endpoint = %1:").arg(endpoint));
        native.insert(QStringLiteral("config"), quick);
    } else {
        QJsonDocument document = QJsonDocument::fromJson(
            native.value(QStringLiteral("config")).toString().toUtf8());
        QJsonObject root = document.object();
        QJsonArray outbounds = root.value(QStringLiteral("outbounds")).toArray();
        QJsonObject outbound = outbounds.first().toObject();
        QJsonObject settings = outbound.value(QStringLiteral("settings")).toObject();
        settings.insert(QStringLiteral("address"), endpoint);
        outbound.insert(QStringLiteral("settings"), settings);
        outbounds.replace(0, outbound);
        root.insert(QStringLiteral("outbounds"), outbounds);
        native.insert(QStringLiteral("config"), QString::fromUtf8(
            QJsonDocument(root).toJson(QJsonDocument::Compact)));
    }
    config.insert(nativeKey, native);

    QJsonObject authority = config.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const auto utc = [](const QDateTime &value) {
        return value.toString(Qt::ISODateWithMs);
    };
    authority.insert(QStringLiteral("catalog_issued_at"), utc(now.addSecs(-60)));
    authority.insert(QStringLiteral("trusted_utc_at_dispatch"), utc(now));
    authority.insert(QStringLiteral("catalog_freshness_deadline"), utc(now.addSecs(3600)));
    authority.insert(QStringLiteral("native_profile_expires_at"), utc(now.addSecs(7200)));
    authority.insert(QStringLiteral("entitlement_deadline"), utc(now.addSecs(7200)));
    authority.insert(QStringLiteral("policy_sha256"), QString(64, QLatin1Char('0')));
    config.insert(QStringLiteral("runtime_authority_v1"), authority);

    QString digest;
    QString error;
    require(!MacosNativeSessionGuard::policyDigest(config, digest, &error)
                && digest.size() == 64,
            "modified policy digest was not independently computed");
    authority.insert(QStringLiteral("policy_sha256"), digest);
    config.insert(QStringLiteral("runtime_authority_v1"), authority);
    require(MacosNativeSessionGuard::policyDigest(config, digest, &error),
            "supported macOS policy rejected");
    return config;
}

QJsonObject authorityWindow(QJsonObject config, const QDateTime &trustedUtc,
                            qint64 hardDeadlineMs)
{
    QJsonObject authority = config.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    const auto utc = [](const QDateTime &value) {
        return value.toUTC().toString(Qt::ISODateWithMs);
    };
    authority.insert(QStringLiteral("catalog_issued_at"),
                     utc(trustedUtc.addSecs(-60)));
    authority.insert(QStringLiteral("trusted_utc_at_dispatch"), utc(trustedUtc));
    authority.insert(QStringLiteral("catalog_freshness_deadline"),
                     utc(trustedUtc.addMSecs(hardDeadlineMs)));
    authority.insert(QStringLiteral("native_profile_expires_at"),
                     utc(trustedUtc.addMSecs(hardDeadlineMs + 60'000)));
    authority.insert(QStringLiteral("entitlement_deadline"),
                     utc(trustedUtc.addMSecs(hardDeadlineMs + 60'000)));
    config.insert(QStringLiteral("runtime_authority_v1"), authority);
    return config;
}

QJsonObject authorityRenewal(QJsonObject config, const QDateTime &trustedUtc,
                             qint64 hardDeadlineMs, const QString &revision,
                             QChar payloadByte)
{
    config = authorityWindow(std::move(config), trustedUtc, hardDeadlineMs);
    QJsonObject authority = config.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    authority.insert(QStringLiteral("catalog_revision"), revision);
    authority.insert(QStringLiteral("catalog_payload_sha256"),
                     QString(64, payloadByte));
    config.insert(QStringLiteral("runtime_authority_v1"), authority);
    return config;
}

QJsonObject makeRenewalRequest(const QJsonObject &armed,
                               const QJsonObject &configuration,
                               const QString &renewalId)
{
    QJsonObject request = identityRequest(
        QStringLiteral("runtime_authority_renew_request_v1"), armed);
    request.insert(QStringLiteral("renewal_id"), renewalId);
    request.insert(QStringLiteral("authority_commitment_sha256"),
        QString::fromLatin1(QCryptographicHash::hash(
            QJsonDocument(configuration).toJson(QJsonDocument::Compact),
            QCryptographicHash::Sha256).toHex()));
    request.insert(QStringLiteral("configuration"), configuration);
    return request;
}

struct FakeAuthorityWatchdog
{
    struct Job {
        qint64 delayMs = 0;
        bool cancelled = false;
        std::function<void()> callback;
    };

    QDateTime wallUtc = QDateTime::currentDateTimeUtc();
    qint64 monotonicMs = 10'000;
    bool scheduleAllowed = true;
    qint64 advanceDuringScheduleMs = 0;
    int currentJob = -1;
    QVector<Job> jobs;

    MacosNativeSessionGuard::AuthorityWatchdog hooks()
    {
        return {
            [this]() { return wallUtc; },
            [this]() { return monotonicMs; },
            [this](qint64 delayMs, std::function<void()> callback) {
                if (!scheduleAllowed || delayMs <= 0 || !callback) return false;
                jobs.append(Job{delayMs, false, std::move(callback)});
                currentJob = jobs.size() - 1;
                if (advanceDuringScheduleMs > 0) advance(advanceDuringScheduleMs);
                return true;
            },
            [this]() {
                if (currentJob >= 0 && currentJob < jobs.size())
                    jobs[currentJob].cancelled = true;
                currentJob = -1;
            },
        };
    }

    void advance(qint64 milliseconds)
    {
        require(milliseconds >= 0, "fake watchdog cannot travel backwards");
        wallUtc = wallUtc.addMSecs(milliseconds);
        monotonicMs += milliseconds;
    }

    int latestJob() const
    {
        return jobs.isEmpty() ? -1 : jobs.size() - 1;
    }

    void fire(int index, bool evenIfCancelled = false)
    {
        require(index >= 0 && index < jobs.size(), "fake watchdog job missing");
        if (jobs[index].cancelled && !evenIfCancelled) return;
        std::function<void()> callback = std::move(jobs[index].callback);
        if (currentJob == index) currentJob = -1;
        if (callback) callback();
    }
};

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    require(argc == 3, "expected AWG and Xray fixture paths");

    const QJsonObject awgGolden = fixture(QString::fromLocal8Bit(argv[1]));
    const QJsonObject xrayGolden = fixture(QString::fromLocal8Bit(argv[2]));
    QString digest;
    QString error;
    const bool awgDigestOk = MacosNativeSessionGuard::policyDigest(
        awgGolden, digest, &error);
    if (!awgDigestOk) std::cerr << "AWG digest reason: " << error.toStdString() << '\n';
    require(awgDigestOk, "AWG cross-language digest rejected");
    require(digest == awgGolden.value(QStringLiteral("runtime_authority_v1"))
                          .toObject().value(QStringLiteral("policy_sha256")).toString(),
            "AWG cross-language digest drift");
    const bool xrayDigestOk = MacosNativeSessionGuard::policyDigest(
        xrayGolden, digest, &error);
    if (!xrayDigestOk) std::cerr << "Xray digest reason: " << error.toStdString() << '\n';
    require(xrayDigestOk, "Xray cross-language digest rejected");
    require(digest == xrayGolden.value(QStringLiteral("runtime_authority_v1"))
                          .toObject().value(QStringLiteral("policy_sha256")).toString(),
            "Xray cross-language digest drift");

    QJsonObject fractionalSchema = awgGolden;
    QJsonObject authority = fractionalSchema.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    authority.insert(QStringLiteral("schema_version"), 1.5);
    fractionalSchema.insert(QStringLiteral("runtime_authority_v1"), authority);
    require(!MacosNativeSessionGuard::policyDigest(fractionalSchema, digest, &error),
            "fractional runtime authority schema accepted");

    QJsonObject emptyProtected = awgGolden;
    authority = emptyProtected.value(QStringLiteral("runtime_authority_v1")).toObject();
    authority.insert(QStringLiteral("protected_tunnel_ips"), QJsonArray{});
    emptyProtected.insert(QStringLiteral("runtime_authority_v1"), authority);
    error.clear();
    require(!MacosNativeSessionGuard::policyDigest(emptyProtected, digest, &error)
                && error == QLatin1String("protected_tunnel_ips_rejected"),
            "empty macOS PF protected endpoint set accepted");

    QJsonObject ipv6OnlyProtected = xrayGolden;
    authority = ipv6OnlyProtected.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    authority.insert(QStringLiteral("protected_tunnel_ips"),
                     QJsonArray{QStringLiteral("2606:4700:4700::1111")});
    ipv6OnlyProtected.insert(QStringLiteral("runtime_authority_v1"), authority);
    error.clear();
    require(!MacosNativeSessionGuard::policyDigest(ipv6OnlyProtected, digest, &error)
                && error == QLatin1String("protected_tunnel_ipv4_required"),
            "IPv6-only macOS PF protected endpoint set accepted");

    // Normal macOS PF intentionally accepts only a catalog-pinned canonical public IPv4 literal.
    // Reality SNI remains inside the Xray config and is not rewritten.
    QJsonObject config = macSupportedConfiguration(awgGolden, QStringLiteral("1.1.1.1"));
    digest = config.value(QStringLiteral("runtime_authority_v1")).toObject()
                 .value(QStringLiteral("policy_sha256")).toString();
    QJsonObject fqdnConfig = macSupportedConfiguration(
        awgGolden, QStringLiteral("vpn.example.net"));
    QJsonObject fqdnPrepare{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_prepare_v1")},
        {QStringLiteral("schema"), 1}, {QStringLiteral("operation"), QStringLiteral("6")},
        {QStringLiteral("session"), QStringLiteral("10")},
        {QStringLiteral("policy_sha256"),
         fqdnConfig.value(QStringLiteral("runtime_authority_v1")).toObject()
             .value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("expected_runtime_session_id"),
         QStringLiteral("e8348ad1-ae86-432c-b577-860eabbe50f7")},
        {QStringLiteral("configuration"), fqdnConfig},
    };
    MacosNativeSessionGuard endpointGate;
    require(endpointGate.prepare(fqdnPrepare).value(QStringLiteral("kind"))
                != QLatin1String("armed"),
            "FQDN endpoint bypassed the macOS literal endpoint gate");
    QJsonObject ipv6Config = macSupportedConfiguration(
        xrayGolden, QStringLiteral("2001:4860:4860::8888"));
    QJsonObject ipv6Prepare = fqdnPrepare;
    ipv6Prepare.insert(QStringLiteral("policy_sha256"),
        ipv6Config.value(QStringLiteral("runtime_authority_v1")).toObject()
            .value(QStringLiteral("policy_sha256")));
    ipv6Prepare.insert(QStringLiteral("configuration"), ipv6Config);
    require(endpointGate.prepare(ipv6Prepare).value(QStringLiteral("kind"))
                != QLatin1String("armed"),
            "IPv6 endpoint bypassed the IPv4-only PF endpoint gate");

    int arms = 0;
    int releases = 0;
    MacosNativeSessionGuard guard({
        [&](const QJsonObject &policy) {
            ++arms;
            const QString endpoint = policy.value(QStringLiteral("vpnServer")).toString();
            return endpoint == QLatin1String("1.1.1.1")
                   || endpoint == QLatin1String("8.8.8.8");
        },
        [&]() { ++releases; return true; },
        []() { return true; },
    });
    const QString runtime = QStringLiteral("5f9d2b8a-3667-47b9-9197-bb608cb8ee38");
    QJsonObject prepare{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_prepare_v1")},
        {QStringLiteral("schema"), 1}, {QStringLiteral("operation"), QStringLiteral("7")},
        {QStringLiteral("session"), QStringLiteral("11")},
        {QStringLiteral("policy_sha256"), digest},
        {QStringLiteral("expected_runtime_session_id"), runtime},
        {QStringLiteral("configuration"), config},
    };
    const QJsonObject armed = guard.prepare(prepare);
    require(armed.value(QStringLiteral("kind")) == QLatin1String("armed") && arms == 1,
            "PREPARE did not arm exactly once");

    QJsonObject stale = identityRequest(
        QStringLiteral("native_session_guard_claim_v1"), armed, QStringLiteral("awg"));
    stale.insert(QStringLiteral("expected_runtime_session_id"),
                 QStringLiteral("d8221979-1026-45b6-b600-dc248241cb21"));
    require(!guard.claimInner(stale).value(QStringLiteral("accepted")).toBool(),
            "stale runtime UUID claimed the outer guard");
    QJsonObject unicode = identityRequest(
        QStringLiteral("native_session_guard_claim_v1"), armed, QStringLiteral("awg"));
    unicode.insert(QStringLiteral("outer_session_id"), QStringLiteral("outer-тест"));
    require(guard.claimInner(unicode).isEmpty(), "Unicode opaque identity accepted");

    const QJsonObject claim = identityRequest(
        QStringLiteral("native_session_guard_claim_v1"), armed, QStringLiteral("awg"));
    require(guard.claimInner(claim).value(QStringLiteral("accepted")).toBool(),
            "exact inner claim rejected");
    require(guard.markRunning(identityRequest(
        QStringLiteral("native_session_guard_running_v1"), armed))
                .value(QStringLiteral("accepted")).toBool(),
            "running receipt rejected");

    // Authority-only refresh must be durable/exact and must not touch PF or the inner core.
    QJsonObject renewedConfig = config;
    QJsonObject renewedAuthority = renewedConfig.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    const QDateTime renewalNow = QDateTime::currentDateTimeUtc();
    renewedAuthority.insert(QStringLiteral("catalog_revision"), QStringLiteral("11"));
    renewedAuthority.insert(QStringLiteral("catalog_payload_sha256"), QString(64, 'c'));
    renewedAuthority.insert(QStringLiteral("catalog_issued_at"),
                            renewalNow.toString(Qt::ISODateWithMs));
    renewedAuthority.insert(QStringLiteral("trusted_utc_at_dispatch"),
                            renewalNow.addSecs(1).toString(Qt::ISODateWithMs));
    renewedAuthority.insert(QStringLiteral("catalog_freshness_deadline"),
                            renewalNow.addSecs(5400).toString(Qt::ISODateWithMs));
    renewedConfig.insert(QStringLiteral("runtime_authority_v1"), renewedAuthority);
    const QString renewalId = QStringLiteral("c6083984-96e7-41b3-8283-f8ad3751c14d");
    const QString renewalCommitment = QString::fromLatin1(QCryptographicHash::hash(
        QJsonDocument(renewedConfig).toJson(QJsonDocument::Compact),
        QCryptographicHash::Sha256).toHex());
    QJsonObject renewalRequest = identityRequest(
        QStringLiteral("runtime_authority_renew_request_v1"), armed);
    renewalRequest.insert(QStringLiteral("renewal_id"), renewalId);
    renewalRequest.insert(QStringLiteral("authority_commitment_sha256"),
                          renewalCommitment);
    renewalRequest.insert(QStringLiteral("configuration"), renewedConfig);
    const QJsonObject renewed = guard.renewAuthority(renewalRequest);
    require(renewed.value(QStringLiteral("kind")) == QLatin1String("applied")
                && renewed.value(QStringLiteral("renewal_id")) == renewalId
                && renewed.value(QStringLiteral("authority_commitment_sha256"))
                       == renewalCommitment
                && !renewed.value(QStringLiteral("hard_deadline")).toString().isEmpty()
                && arms == 1 && releases == 0,
            "exact authority renewal was not applied without PF churn");

    QJsonObject collidingConfig = renewedConfig;
    QJsonObject collidingAuthority = renewedAuthority;
    collidingAuthority.insert(QStringLiteral("catalog_payload_sha256"), QString(64, 'd'));
    collidingConfig.insert(QStringLiteral("runtime_authority_v1"), collidingAuthority);
    renewalRequest.insert(QStringLiteral("renewal_id"),
                          QStringLiteral("4c2949f3-d4c8-4d11-b756-4493b67a5c1c"));
    renewalRequest.insert(QStringLiteral("configuration"), collidingConfig);
    renewalRequest.insert(QStringLiteral("authority_commitment_sha256"),
        QString::fromLatin1(QCryptographicHash::hash(
            QJsonDocument(collidingConfig).toJson(QJsonDocument::Compact),
            QCryptographicHash::Sha256).toHex()));
    require(guard.renewAuthority(renewalRequest).value(QStringLiteral("kind"))
                == QLatin1String("rejected"),
            "same-revision catalog payload collision renewed authority");

    QJsonObject changedPolicyConfig = renewedConfig;
    changedPolicyConfig.insert(QStringLiteral("dns1"), QStringLiteral("9.9.9.9"));
    renewalRequest.insert(QStringLiteral("renewal_id"),
                          QStringLiteral("613bd33d-a2a9-41c6-ac80-c4e8c19f75af"));
    renewalRequest.insert(QStringLiteral("configuration"), changedPolicyConfig);
    renewalRequest.insert(QStringLiteral("authority_commitment_sha256"),
        QString::fromLatin1(QCryptographicHash::hash(
            QJsonDocument(changedPolicyConfig).toJson(QJsonDocument::Compact),
            QCryptographicHash::Sha256).toHex()));
    require(guard.renewAuthority(renewalRequest).value(QStringLiteral("kind"))
                == QLatin1String("rejected"),
            "authority renewal changed non-authority route/DNS policy");

    guard.authenticatedChannelLost();
    require(guard.currentGuardEvent().value(QStringLiteral("kind")) == QLatin1String("lost")
                && releases == 0,
            "channel loss removed or forgot PF ownership");
    require(guard.validateRecoveryConfiguration(renewedConfig, &error),
            "exact recovery policy rejected");
    QJsonObject tampered = renewedConfig;
    tampered.insert(QStringLiteral("dns1"), QStringLiteral("9.9.9.9"));
    require(!guard.validateRecoveryConfiguration(tampered, &error),
            "tampered recovery policy accepted");

    bool exactStopCalled = false;
    const QJsonObject recovered = guard.stopAndReleaseRecovered(
        identityRequest(QStringLiteral("native_session_guard_recover_stop_v1"), armed),
        [&]() { exactStopCalled = true; return true; });
    require(exactStopCalled
                && recovered.value(QStringLiteral("kind"))
                       == QLatin1String("stopped_released")
                && releases == 1 && guard.phase() == MacosNativeSessionGuard::Phase::Idle,
            "recovery stop/release postcondition failed");

    // RELEASE cannot run while an inner is still owned. Once the old AWG inner is stopped,
    // PREPARE atomically replaces the PF lease with Xray without disarming the outer guard.
    const QJsonObject armed2 = guard.prepare(prepare);
    require(guard.claimInner(identityRequest(
        QStringLiteral("native_session_guard_claim_v1"), armed2, QStringLiteral("awg")))
                .value(QStringLiteral("accepted")).toBool(),
            "second exact claim rejected");
    require(guard.release(identityRequest(
        QStringLiteral("native_session_guard_release_v1"), armed2))
                .value(QStringLiteral("kind")) == QLatin1String("release_rejected"),
            "release succeeded with nonzero inner ownership");
    require(guard.beginStop(identityRequest(
        QStringLiteral("native_session_guard_stop_begin_v1"), armed2))
                .value(QStringLiteral("accepted")).toBool(),
            "exact stop begin rejected");
    require(guard.markStopped(identityRequest(
        QStringLiteral("native_session_guard_stopped_v1"), armed2))
                .value(QStringLiteral("accepted")).toBool(),
            "exact stopped receipt rejected");
    QJsonObject xrayConfig = macSupportedConfiguration(
        xrayGolden, QStringLiteral("8.8.8.8"));
    const QString xrayDigest = xrayConfig.value(QStringLiteral("runtime_authority_v1"))
                                   .toObject().value(QStringLiteral("policy_sha256")).toString();
    QJsonObject xrayPrepare{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_prepare_v1")},
        {QStringLiteral("schema"), 1}, {QStringLiteral("operation"), QStringLiteral("8")},
        {QStringLiteral("session"), QStringLiteral("12")},
        {QStringLiteral("policy_sha256"), xrayDigest},
        {QStringLiteral("expected_runtime_session_id"),
         QStringLiteral("a5a6fb6d-a05a-40b9-8ede-ca5307f41f89")},
        {QStringLiteral("configuration"), xrayConfig},
    };
    const QJsonObject xrayArmed = guard.prepare(xrayPrepare);
    require(xrayArmed.value(QStringLiteral("kind")) == QLatin1String("armed")
                && arms == 3 && releases == 1,
            "stopped AWG outer guard did not transfer atomically to Xray");
    require(guard.release(identityRequest(
        QStringLiteral("native_session_guard_release_v1"), armed2))
                .value(QStringLiteral("kind")) == QLatin1String("release_rejected"),
            "old AWG identity released transferred Xray PF ownership");
    require(guard.claimInner(identityRequest(
        QStringLiteral("native_session_guard_claim_v1"), xrayArmed,
        QStringLiteral("xray"))).value(QStringLiteral("accepted")).toBool(),
            "transferred Xray inner claim rejected");
    require(guard.markRunning(identityRequest(
        QStringLiteral("native_session_guard_running_v1"), xrayArmed))
                .value(QStringLiteral("accepted")).toBool(),
            "transferred Xray running receipt rejected");
    require(guard.beginStop(identityRequest(
        QStringLiteral("native_session_guard_stop_begin_v1"), xrayArmed))
                .value(QStringLiteral("accepted")).toBool(),
            "transferred Xray stop rejected");
    require(guard.markStopped(identityRequest(
        QStringLiteral("native_session_guard_stopped_v1"), xrayArmed))
                .value(QStringLiteral("accepted")).toBool(),
            "transferred Xray stopped receipt rejected");
    require(guard.release(identityRequest(
        QStringLiteral("native_session_guard_release_v1"), xrayArmed))
                .value(QStringLiteral("kind")) == QLatin1String("released")
                && releases == 2,
            "transferred Xray PF guard did not release after exact stop");

    // A failed policy replacement is not allowed to disarm PF. The backend first leaves a
    // blackhole and then restores the old stopped owner's exact policy.
    int replacementArmCalls = 0;
    MacosNativeSessionGuard failedReplacement({
        [&](const QJsonObject &) {
            ++replacementArmCalls;
            return replacementArmCalls != 2;
        },
        []() { return true; },
        []() { return true; },
    });
    const QJsonObject oldArmed = failedReplacement.prepare(prepare);
    require(oldArmed.value(QStringLiteral("kind")) == QLatin1String("armed"),
            "replacement failure fixture did not arm old policy");
    const QJsonObject rejectedReplacement = failedReplacement.prepare(xrayPrepare);
    require(rejectedReplacement.value(QStringLiteral("kind"))
                == QLatin1String("arm_rejected")
                && failedReplacement.phase() == MacosNativeSessionGuard::Phase::Armed
                && failedReplacement.currentGuardEvent().value(
                       QStringLiteral("outer_session_id"))
                       == oldArmed.value(QStringLiteral("outer_session_id"))
                && replacementArmCalls == 3,
            "failed PF replacement did not restore the exact old stopped lease");

    // Durable root-helper lease: GUI loss and helper restart restore PF as a quarantined owner.
    QTemporaryDir durableDirectory;
    require(durableDirectory.isValid(), "temporary durable directory unavailable");
    QFile::setPermissions(durableDirectory.path(),
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner
                              | QFileDevice::ExeOwner);
    const QString leasePath = durableDirectory.filePath(QStringLiteral("guard.json"));
    int durableArms = 0;
    {
        MacosNativeSessionGuard durable({
            [&](const QJsonObject &) { ++durableArms; return true; },
            []() { return true; },
            []() { return true; },
        }, leasePath);
        const QJsonObject durableArmed = durable.prepare(prepare);
        require(durableArmed.value(QStringLiteral("kind")) == QLatin1String("armed"),
                "durable PREPARE rejected");
        require(durable.claimInner(identityRequest(
            QStringLiteral("native_session_guard_claim_v1"), durableArmed,
            QStringLiteral("awg"))).value(QStringLiteral("accepted")).toBool(),
                "durable inner claim rejected");
        require(durable.markRunning(identityRequest(
            QStringLiteral("native_session_guard_running_v1"), durableArmed))
                    .value(QStringLiteral("accepted")).toBool(),
                "durable running receipt rejected");
        QJsonObject durableRenewal = identityRequest(
            QStringLiteral("runtime_authority_renew_request_v1"), durableArmed);
        durableRenewal.insert(QStringLiteral("renewal_id"), renewalId);
        durableRenewal.insert(QStringLiteral("authority_commitment_sha256"),
                              renewalCommitment);
        durableRenewal.insert(QStringLiteral("configuration"), renewedConfig);
        require(durable.renewAuthority(durableRenewal).value(QStringLiteral("kind"))
                    == QLatin1String("applied"),
                "durable authority renewal receipt rejected");
        durable.authenticatedChannelLost();
    }
    int quarantineCalls = 0;
    MacosNativeSessionGuard restarted({
        [&](const QJsonObject &) { ++durableArms; return true; },
        []() { return true; },
        [&]() { ++quarantineCalls; return true; },
    }, leasePath);
    require(restarted.restoreAfterDaemonStart(&error)
                && restarted.currentGuardEvent().value(QStringLiteral("kind"))
                       == QLatin1String("lost")
                && durableArms == 2,
            "daemon restart did not re-arm durable quarantined PF policy");
    require(restarted.validateRecoveryConfiguration(renewedConfig, &error)
                && !restarted.validateRecoveryConfiguration(config, &error),
            "daemon restart did not retain the renewed durable authority high-water");

    // Recovery adoption is a second authority commit, not just an in-memory phase flip. A newer
    // still-policy-equivalent authority must become the durable high-water before Adopted.
    const QDateTime adoptionTrusted = renewalNow.addSecs(120);
    const QJsonObject adoptionConfig = authorityRenewal(
        renewedConfig, adoptionTrusted, 7'200'000, QStringLiteral("12"),
        QLatin1Char('e'));
    require(restarted.validateRecoveryConfiguration(adoptionConfig, &error),
            "newer recovery authority was rejected before adoption");
    const QJsonObject restartEvent = restarted.currentGuardEvent();
    const QJsonObject adopted = restarted.adoptRecovered(
        identityRequest(QStringLiteral("native_session_guard_recover_adopt_v1"),
                        restartEvent),
        adoptionConfig);
    require(adopted.value(QStringLiteral("kind")) == QLatin1String("adopted")
                && restarted.phase() == MacosNativeSessionGuard::Phase::Running,
            "recovery adoption acknowledged before durable watchdog ownership");
    QFile adoptedLeaseFile(leasePath);
    require(adoptedLeaseFile.open(QIODevice::ReadOnly),
            "adopted lease could not be read");
    const QJsonObject adoptedLease = QJsonDocument::fromJson(
        adoptedLeaseFile.readAll()).object();
    adoptedLeaseFile.close();
    require(adoptedLease.value(QStringLiteral("runtime_authority")).toObject()
                    .value(QStringLiteral("catalog_revision"))
                == QLatin1String("12")
                && adoptedLease.value(
                       QStringLiteral("non_authority_configuration_sha256"))
                       .toString().size() == 64,
            "recovery adoption did not durably replace authority/config commitment");
    restarted.authenticatedChannelLost();
    require(restarted.validateRecoveryConfiguration(adoptionConfig, &error)
                && !restarted.validateRecoveryConfiguration(renewedConfig, &error),
            "adopted authority high-water was not retained after channel loss");

    QTemporaryDir persistFailureDirectory;
    require(persistFailureDirectory.isValid(), "renewal persist-failure directory unavailable");
    const QString persistFailurePath = persistFailureDirectory.filePath(
        QStringLiteral("guard.json"));
    int persistFailureQuarantines = 0;
    MacosNativeSessionGuard persistFailureGuard({
        [](const QJsonObject &) { return true; }, []() { return true; },
        [&]() { ++persistFailureQuarantines; return true; },
    }, persistFailurePath);
    const QJsonObject persistFailureArmed = persistFailureGuard.prepare(prepare);
    require(persistFailureGuard.claimInner(identityRequest(
        QStringLiteral("native_session_guard_claim_v1"), persistFailureArmed,
        QStringLiteral("awg"))).value(QStringLiteral("accepted")).toBool()
            && persistFailureGuard.markRunning(identityRequest(
                QStringLiteral("native_session_guard_running_v1"), persistFailureArmed))
                   .value(QStringLiteral("accepted")).toBool(),
            "persist-failure guard did not reach running");
    QJsonObject failedRenewal = identityRequest(
        QStringLiteral("runtime_authority_renew_request_v1"), persistFailureArmed);
    failedRenewal.insert(QStringLiteral("renewal_id"), renewalId);
    failedRenewal.insert(QStringLiteral("authority_commitment_sha256"),
                         renewalCommitment);
    failedRenewal.insert(QStringLiteral("configuration"), renewedConfig);
    require(QFile::setPermissions(persistFailureDirectory.path(),
                                  QFileDevice::ReadOwner | QFileDevice::ExeOwner),
            "persist-failure directory could not be made read-only");
    const QJsonObject failedReceipt = persistFailureGuard.renewAuthority(failedRenewal);
    require(QFile::setPermissions(persistFailureDirectory.path(),
                                  QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner),
            "persist-failure directory permissions could not be restored");
    require(failedReceipt.value(QStringLiteral("kind")) == QLatin1String("rejected")
                && failedReceipt.value(QStringLiteral("reason"))
                       == QLatin1String("renew_durable_persist_failed")
                && persistFailureGuard.phase()
                       == MacosNativeSessionGuard::Phase::Quarantined
                && persistFailureQuarantines == 1,
            "durable renewal write failure did not quarantine and reject");

    QTemporaryDir adoptionFailureDirectory;
    require(adoptionFailureDirectory.isValid(),
            "adoption persist-failure directory unavailable");
    QFile::setPermissions(adoptionFailureDirectory.path(),
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner
                              | QFileDevice::ExeOwner);
    const QString adoptionFailurePath = adoptionFailureDirectory.filePath(
        QStringLiteral("guard.json"));
    int adoptionFailureQuarantines = 0;
    MacosNativeSessionGuard adoptionFailureGuard({
        [](const QJsonObject &) { return true; }, []() { return true; },
        [&]() { ++adoptionFailureQuarantines; return true; },
    }, adoptionFailurePath);
    const QJsonObject adoptionFailureArmed = adoptionFailureGuard.prepare(prepare);
    require(adoptionFailureGuard.claimInner(identityRequest(
        QStringLiteral("native_session_guard_claim_v1"), adoptionFailureArmed,
        QStringLiteral("awg"))).value(QStringLiteral("accepted")).toBool()
            && adoptionFailureGuard.markRunning(identityRequest(
                QStringLiteral("native_session_guard_running_v1"),
                adoptionFailureArmed)).value(QStringLiteral("accepted")).toBool(),
            "adoption persist-failure guard did not reach running");
    adoptionFailureGuard.authenticatedChannelLost();
    require(QFile::setPermissions(adoptionFailureDirectory.path(),
                                  QFileDevice::ReadOwner | QFileDevice::ExeOwner),
            "adopt persist-failure directory could not be made read-only");
    const QJsonObject failedAdoption = adoptionFailureGuard.adoptRecovered(
        identityRequest(QStringLiteral("native_session_guard_recover_adopt_v1"),
                        adoptionFailureArmed),
        renewedConfig);
    require(QFile::setPermissions(adoptionFailureDirectory.path(),
                                  QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner),
            "adopt persist-failure permissions could not be restored");
    require(failedAdoption.value(QStringLiteral("kind")) == QLatin1String("rejected")
                && failedAdoption.value(QStringLiteral("reason"))
                       == QLatin1String("guard_lease_persist_failed")
                && adoptionFailureGuard.phase()
                       == MacosNativeSessionGuard::Phase::Quarantined
                && adoptionFailureQuarantines == 1,
            "failed recovery adoption was acknowledged or did not quarantine");
    QFile rolledBackLeaseFile(adoptionFailurePath);
    require(rolledBackLeaseFile.open(QIODevice::ReadOnly),
            "rolled-back recovery lease could not be read");
    const QJsonObject rolledBackLease = QJsonDocument::fromJson(
        rolledBackLeaseFile.readAll()).object();
    rolledBackLeaseFile.close();
    require(rolledBackLease.value(QStringLiteral("runtime_authority")).toObject()
                    .value(QStringLiteral("catalog_revision"))
                == config.value(QStringLiteral("runtime_authority_v1")).toObject()
                       .value(QStringLiteral("catalog_revision")),
            "failed recovery adoption advanced the durable authority high-water");

    // Deterministic daemon watchdog: the hard boundary is monotonic, invokes the blackhole
    // backend, persists quarantine, and an expired v2 restart never re-arms the permissive PF.
    QTemporaryDir expiryDirectory;
    require(expiryDirectory.isValid(), "watchdog expiry directory unavailable");
    QFile::setPermissions(expiryDirectory.path(),
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner
                              | QFileDevice::ExeOwner);
    const QString expiryLeasePath = expiryDirectory.filePath(
        QStringLiteral("guard.json"));
    FakeAuthorityWatchdog expiryClock;
    const QJsonObject expiryConfig = authorityWindow(config, expiryClock.wallUtc, 30'000);
    QJsonObject expiryPrepare = prepare;
    expiryPrepare.insert(QStringLiteral("configuration"), expiryConfig);
    int expiryArms = 0;
    int expiryQuarantines = 0;
    {
        MacosNativeSessionGuard expiring({
            [&](const QJsonObject &) { ++expiryArms; return true; },
            []() { return true; },
            [&]() { ++expiryQuarantines; return true; },
        }, expiryLeasePath, expiryClock.hooks());
        const QJsonObject expiryArmed = expiring.prepare(expiryPrepare);
        require(expiryArmed.value(QStringLiteral("kind")) == QLatin1String("armed"),
                "watchdog fixture did not arm");
        require(expiring.claimInner(identityRequest(
            QStringLiteral("native_session_guard_claim_v1"), expiryArmed,
            QStringLiteral("awg"))).value(QStringLiteral("accepted")).toBool()
                && expiring.markRunning(identityRequest(
                    QStringLiteral("native_session_guard_running_v1"), expiryArmed))
                       .value(QStringLiteral("accepted")).toBool(),
                "watchdog fixture did not reach running");
        const int deadlineJob = expiryClock.latestJob();
        expiryClock.advance(30'001);
        expiryClock.fire(deadlineJob);
        require(expiring.phase() == MacosNativeSessionGuard::Phase::Quarantined
                    && expiryQuarantines == 1,
                "live authority expiry did not synchronously quarantine PF");
    }
    MacosNativeSessionGuard expiredRestart({
        [&](const QJsonObject &) { ++expiryArms; return true; },
        []() { return true; },
        [&]() { ++expiryQuarantines; return true; },
    }, expiryLeasePath, expiryClock.hooks());
    require(!expiredRestart.restoreAfterDaemonStart(&error)
                && error == QLatin1String("lease_runtime_authority_expired")
                && expiredRestart.phase()
                       == MacosNativeSessionGuard::Phase::Quarantined
                && expiryQuarantines == 2 && expiryArms == 1,
            "expired v2 restart re-armed endpoint PF or reported recovery success");

    // Publishing a new authority cancels the old generation. Even a malicious/late scheduler
    // delivery cannot expire the renewed lease; only the new monotonic deadline can do so.
    FakeAuthorityWatchdog renewalClock;
    const QJsonObject shortConfig = authorityWindow(config, renewalClock.wallUtc, 60'000);
    QJsonObject shortPrepare = prepare;
    shortPrepare.insert(QStringLiteral("configuration"), shortConfig);
    int renewalQuarantines = 0;
    MacosNativeSessionGuard renewalGuard({
        [](const QJsonObject &) { return true; }, []() { return true; },
        [&]() { ++renewalQuarantines; return true; },
    }, {}, renewalClock.hooks());
    const QJsonObject shortArmed = renewalGuard.prepare(shortPrepare);
    require(shortArmed.value(QStringLiteral("kind")) == QLatin1String("armed")
                && renewalGuard.claimInner(identityRequest(
                    QStringLiteral("native_session_guard_claim_v1"), shortArmed,
                    QStringLiteral("awg"))).value(QStringLiteral("accepted")).toBool()
                && renewalGuard.markRunning(identityRequest(
                    QStringLiteral("native_session_guard_running_v1"), shortArmed))
                       .value(QStringLiteral("accepted")).toBool(),
            "renewal watchdog fixture did not reach running");
    const int staleJob = renewalClock.latestJob();
    const QJsonObject longerConfig = authorityRenewal(
        shortConfig, renewalClock.wallUtc.addSecs(1), 120'000,
        QStringLiteral("999"), QLatin1Char('f'));
    const QJsonObject longerReceipt = renewalGuard.renewAuthority(
        makeRenewalRequest(shortArmed, longerConfig,
            QStringLiteral("b58b5894-f197-4730-a797-7e03e951f8a7")));
    const int extendedJob = renewalClock.latestJob();
    require(longerReceipt.value(QStringLiteral("kind")) == QLatin1String("applied")
                && extendedJob != staleJob,
            "renewal was acknowledged without replacing the watchdog generation");
    // A signed authority may deliberately shorten a deadline for entitlement/profile revocation.
    const QJsonObject shortenedConfig = authorityRenewal(
        longerConfig, renewalClock.wallUtc.addSecs(2), 90'000,
        QStringLiteral("1000"), QLatin1Char('b'));
    const QJsonObject shortenedReceipt = renewalGuard.renewAuthority(
        makeRenewalRequest(shortArmed, shortenedConfig,
            QStringLiteral("9a26935a-68b5-4b28-beb5-f87c833276e3")));
    const int shortenedJob = renewalClock.latestJob();
    require(shortenedReceipt.value(QStringLiteral("kind")) == QLatin1String("applied")
                && shortenedJob != extendedJob,
            "signed deadline shortening/revocation was not enforced");
    renewalClock.advance(60'001);
    renewalClock.fire(staleJob, true);
    renewalClock.fire(extendedJob, true);
    require(renewalGuard.phase() == MacosNativeSessionGuard::Phase::Running
                && renewalQuarantines == 0,
            "cancelled old watchdog callback expired renewed authority");
    renewalClock.advance(32'001);
    renewalClock.fire(shortenedJob);
    require(renewalGuard.phase() == MacosNativeSessionGuard::Phase::Quarantined
                && renewalQuarantines == 1,
            "renewed monotonic hard deadline did not quarantine");

    // A schedule operation can succeed just as the deadline is crossed. The post-publication
    // clock/generation fence must reject instead of leaking an Applied receipt.
    FakeAuthorityWatchdog publicationClock;
    const QJsonObject publicationConfig = authorityWindow(
        config, publicationClock.wallUtc, 300'000);
    QJsonObject publicationPrepare = prepare;
    publicationPrepare.insert(QStringLiteral("configuration"), publicationConfig);
    int publicationQuarantines = 0;
    MacosNativeSessionGuard publicationGuard({
        [](const QJsonObject &) { return true; }, []() { return true; },
        [&]() { ++publicationQuarantines; return true; },
    }, {}, publicationClock.hooks());
    const QJsonObject publicationArmed = publicationGuard.prepare(publicationPrepare);
    require(publicationArmed.value(QStringLiteral("kind")) == QLatin1String("armed")
                && publicationGuard.claimInner(identityRequest(
                    QStringLiteral("native_session_guard_claim_v1"), publicationArmed,
                    QStringLiteral("awg"))).value(QStringLiteral("accepted")).toBool()
                && publicationGuard.markRunning(identityRequest(
                    QStringLiteral("native_session_guard_running_v1"), publicationArmed))
                       .value(QStringLiteral("accepted")).toBool(),
            "publication-race fixture did not reach running");
    const QJsonObject publicationRenewal = authorityRenewal(
        publicationConfig, publicationClock.wallUtc.addSecs(1), 600'000,
        QStringLiteral("1000"), QLatin1Char('a'));
    publicationClock.advanceDuringScheduleMs = 700'000;
    const QJsonObject publicationReceipt = publicationGuard.renewAuthority(
        makeRenewalRequest(publicationArmed, publicationRenewal,
            QStringLiteral("1dccbced-e366-40a6-86f9-f14f7746eada")));
    require(publicationReceipt.value(QStringLiteral("kind")) == QLatin1String("rejected")
                && publicationReceipt.value(QStringLiteral("reason"))
                       == QLatin1String("renew_watchdog_publish_failed")
                && publicationGuard.phase()
                       == MacosNativeSessionGuard::Phase::Quarantined
                && publicationQuarantines == 1,
            "near-deadline watchdog publication returned Applied");

    // Stale callbacks may be delivered after cancellation/destruction by a foreign scheduler.
    // The lifetime gate must make that delivery a no-op without touching the backend.
    FakeAuthorityWatchdog destructorClock;
    const QJsonObject destructorConfig = authorityWindow(
        config, destructorClock.wallUtc, 300'000);
    QJsonObject destructorPrepare = prepare;
    destructorPrepare.insert(QStringLiteral("configuration"), destructorConfig);
    int destructorQuarantines = 0;
    int destructorJob = -1;
    {
        MacosNativeSessionGuard destructible({
            [](const QJsonObject &) { return true; }, []() { return true; },
            [&]() { ++destructorQuarantines; return true; },
        }, {}, destructorClock.hooks());
        require(destructible.prepare(destructorPrepare).value(QStringLiteral("kind"))
                    == QLatin1String("armed"),
                "destructor watchdog fixture did not arm");
        destructorJob = destructorClock.latestJob();
    }
    destructorClock.fire(destructorJob, true);
    require(destructorQuarantines == 0,
            "stale callback used a destroyed native session guard");

    FakeAuthorityWatchdog failedArmClock;
    failedArmClock.scheduleAllowed = false;
    const QJsonObject failedArmConfig = authorityWindow(
        config, failedArmClock.wallUtc, 300'000);
    QJsonObject failedArmPrepare = prepare;
    failedArmPrepare.insert(QStringLiteral("configuration"), failedArmConfig);
    int failedArmQuarantines = 0;
    MacosNativeSessionGuard failedArmGuard({
        [](const QJsonObject &) { return true; }, []() { return true; },
        [&]() { ++failedArmQuarantines; return true; },
    }, {}, failedArmClock.hooks());
    require(failedArmGuard.prepare(failedArmPrepare).value(QStringLiteral("kind"))
                == QLatin1String("lost")
                && failedArmGuard.phase()
                       == MacosNativeSessionGuard::Phase::Quarantined
                && failedArmQuarantines == 1,
            "PREPARE returned Armed without a published daemon watchdog");

    // A v2 lease is root-owned but corruption still fails closed. Validate the complete persisted
    // authority envelope rather than trusting its policy hash/transport alone.
    QTemporaryDir strictLeaseDirectory;
    require(strictLeaseDirectory.isValid(), "strict v2 lease directory unavailable");
    QFile::setPermissions(strictLeaseDirectory.path(),
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner
                              | QFileDevice::ExeOwner);
    const QString strictLeasePath = strictLeaseDirectory.filePath(
        QStringLiteral("guard.json"));
    {
        MacosNativeSessionGuard strictWriter({
            [](const QJsonObject &) { return true; }, []() { return true; },
            []() { return true; },
        }, strictLeasePath);
        require(strictWriter.prepare(prepare).value(QStringLiteral("kind"))
                    == QLatin1String("armed"),
                "strict v2 lease fixture did not persist");
    }
    QFile strictLeaseFile(strictLeasePath);
    require(strictLeaseFile.open(QIODevice::ReadOnly),
            "strict v2 lease fixture could not be read");
    QJsonObject strictLease = QJsonDocument::fromJson(
        strictLeaseFile.readAll()).object();
    strictLeaseFile.close();
    QJsonObject corruptAuthority = strictLease.value(
        QStringLiteral("runtime_authority")).toObject();
    corruptAuthority.insert(QStringLiteral("device_audience"),
                            QStringLiteral("not-base64url-sha256"));
    strictLease.insert(QStringLiteral("runtime_authority"), corruptAuthority);
    require(strictLeaseFile.open(QIODevice::WriteOnly | QIODevice::Truncate),
            "strict v2 corrupt fixture could not be written");
    require(strictLeaseFile.write(QJsonDocument(strictLease).toJson(
                QJsonDocument::Compact)) > 0,
            "strict v2 corrupt fixture write failed");
    strictLeaseFile.close();
    QFile::setPermissions(strictLeasePath,
                          QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    int strictLeaseArms = 0;
    int strictLeaseQuarantines = 0;
    MacosNativeSessionGuard strictReader({
        [&](const QJsonObject &) { ++strictLeaseArms; return true; },
        []() { return true; },
        [&]() { ++strictLeaseQuarantines; return true; },
    }, strictLeasePath);
    require(!strictReader.restoreAfterDaemonStart(&error)
                && strictReader.phase()
                       == MacosNativeSessionGuard::Phase::Quarantined
                && strictLeaseQuarantines == 1 && strictLeaseArms == 0,
            "corrupt persisted runtime authority re-armed PF");

    QFile corrupt(leasePath);
    require(corrupt.open(QIODevice::WriteOnly | QIODevice::Truncate),
            "lease corruption fixture open failed");
    corrupt.write("{\"schema\":1.5}");
    corrupt.flush();
    corrupt.close();
    QFile::setPermissions(leasePath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    MacosNativeSessionGuard corrupted({
        [](const QJsonObject &) { return true; }, []() { return true; },
        [&]() { ++quarantineCalls; return true; },
    }, leasePath);
    require(!corrupted.restoreAfterDaemonStart(&error) && quarantineCalls == 1
                && corrupted.phase() == MacosNativeSessionGuard::Phase::Quarantined,
            "corrupt durable lease did not fail closed");

    std::cout << "macOS native session guard tests passed\n";
    return 0;
}
