#include "NativeConnectionPolicy.h"
#include "NativeDispatchPolicyDigest.h"

#include "core/utils/constants/configKeys.h"

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>
#include <QVariant>

namespace avpn {
namespace {

constexpr int kMaximumRouteExclusions = 32768;
constexpr int kMaximumSplitApps = 512;

bool canonicalIp(const QString &text, QHostAddress &address)
{
    return !text.isEmpty() && address.setAddress(text) && !address.isNull()
           && address.toString() == text;
}

bool canonicalCidr(const QString &text, QHostAddress &network, int &prefix)
{
    const int slash = text.indexOf(QLatin1Char('/'));
    if (slash <= 0 || slash != text.lastIndexOf(QLatin1Char('/')))
        return false;
    const QString addressText = text.left(slash);
    const QString prefixText = text.mid(slash + 1);
    bool ok = false;
    prefix = prefixText.toInt(&ok);
    if (!ok || prefixText != QString::number(prefix) || !canonicalIp(addressText, network))
        return false;
    const int maximum = network.protocol() == QAbstractSocket::IPv4Protocol ? 32
                       : network.protocol() == QAbstractSocket::IPv6Protocol ? 128 : -1;
    const QPair<QHostAddress, int> parsed = QHostAddress::parseSubnet(text);
    return maximum >= 0 && prefix > 0 && prefix <= maximum
           && parsed.second == prefix && parsed.first == network;
}

bool boundedUnique(const QStringList &values, int maximumCount, int maximumBytes)
{
    if (values.size() > maximumCount)
        return false;
    QSet<QString> seen;
    for (const QString &value : values) {
        if (value.isEmpty() || value.toUtf8().size() > maximumBytes || seen.contains(value))
            return false;
        seen.insert(value);
    }
    return true;
}

bool validDnsSuffix(const QString &suffix)
{
    static const QRegularExpression expression(
        QStringLiteral("^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                       "(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"));
    return expression.match(suffix).hasMatch();
}

bool validateSnapshot(const CompiledNativeProfile &compiled,
                      const NativeConnectionPolicySnapshot &snapshot,
                      bool splitOn, QString &error)
{
    if (!hasExpectedNativeEnvelope(compiled, compiled.transport)
        || (compiled.locationCountry.size() != 2
            || compiled.locationCountry != compiled.locationCountry.toUpper())) {
        error = QStringLiteral("compiled native envelope/policy metadata is invalid");
        return false;
    }
    if (!boundedUnique(snapshot.routeExclusions, kMaximumRouteExclusions, 64)
        || !boundedUnique(snapshot.splitApps, kMaximumSplitApps, 1024)
        || !boundedUnique(snapshot.maskDnsServers, 4, 64)
        || !boundedUnique(snapshot.splitDnsSuffixes, 128, 253)
        || !boundedUnique(snapshot.allowedDnsServers, 16, 64)
        || !boundedUnique(snapshot.protectedTunnelIpLiterals, 64, 64)) {
        error = QStringLiteral("local connection policy exceeds bounds or contains duplicates");
        return false;
    }
    if (snapshot.appsRouteMode < amnezia::AppsRouteMode::VpnAllApps
        || snapshot.appsRouteMode > amnezia::AppsRouteMode::VpnAllExceptApps) {
        error = QStringLiteral("local app route mode is invalid");
        return false;
    }
    for (const QString &app : snapshot.splitApps)
        if (app.contains(QChar::Null)) {
            error = QStringLiteral("local app route contains an invalid value");
            return false;
        }
    for (const QString &suffix : snapshot.splitDnsSuffixes)
        if (!validDnsSuffix(suffix)) {
            error = QStringLiteral("local split-DNS suffix is invalid");
            return false;
        }
    for (const QString &dns : snapshot.maskDnsServers) {
        QHostAddress address;
        if (!canonicalIp(dns, address) || address.isLoopback() || address.isLinkLocal()
            || address.isMulticast()) {
            error = QStringLiteral("local DNS mask server is invalid");
            return false;
        }
    }
    if (snapshot.dnsForwardRequested || snapshot.dnsMaskRequested) {
        QHostAddress splitDns;
        if (!canonicalIp(snapshot.splitDnsServer, splitDns) || splitDns.isLoopback()
            || splitDns.isLinkLocal() || splitDns.isMulticast()) {
            error = QStringLiteral("local split-DNS server is invalid");
            return false;
        }
    }
    for (const QString &dns : snapshot.allowedDnsServers) {
        QHostAddress address;
        if (!canonicalIp(dns, address) || address.isMulticast()) {
            error = QStringLiteral("local kill-switch DNS allowlist is invalid");
            return false;
        }
    }

    QList<QPair<QHostAddress, int>> exclusions;
    for (const QString &cidr : snapshot.routeExclusions) {
        QHostAddress network;
        int prefix = -1;
        if (!canonicalCidr(cidr, network, prefix)) {
            error = QStringLiteral("local route exclusion is not a canonical bounded CIDR");
            return false;
        }
        exclusions.append({network, prefix});
    }
    if (splitOn && snapshot.protectedTunnelIpLiterals.isEmpty()) {
        error = QStringLiteral("protected verification/auth destinations are unavailable");
        return false;
    }
    for (const QString &literal : snapshot.protectedTunnelIpLiterals) {
        QHostAddress protectedAddress;
        if (!canonicalIp(literal, protectedAddress)) {
            error = QStringLiteral("protected tunnel destination is not a canonical IP literal");
            return false;
        }
        if (!splitOn)
            continue;
        for (const auto &subnet : exclusions) {
            if (protectedAddress.protocol() == subnet.first.protocol()
                && protectedAddress.isInSubnet(subnet)) {
                error = QStringLiteral("route policy would bypass a protected destination");
                return false;
            }
        }
    }
    return true;
}

bool validRuntimeAuthority(const CompiledNativeProfile &compiled)
{
    const NativeRuntimeAuthority &authority = compiled.runtimeAuthority;
    bool safeKid = !authority.catalogSigningKeyId.isEmpty()
                   && authority.catalogSigningKeyId.size() <= 64;
    for (const QChar ch : authority.catalogSigningKeyId)
        safeKid = safeKid && (ch.isLetterOrNumber() || ch == QLatin1Char('.')
                              || ch == QLatin1Char('_') || ch == QLatin1Char('-'));
    return canonicalCatalogTrustAudience(authority.deviceAudience)
           && authority.catalogRevision > 0
           && authority.catalogRevision <= 9007199254740991ULL
           && authority.catalogPayloadSha256.size() == 32
           && safeKid
           && authority.profileId == compiled.profileId
           && authority.transport == compiled.transport
           && authority.configGeneration == compiled.configGeneration
           && authority.bindingGeneration == compiled.bindingGeneration
           && authority.nativeProfileExpiresAt.toUTC() == compiled.expiresAt.toUTC()
           && authority.catalogFreshnessDeadline.isValid()
           && authority.entitlementDeadline.isValid()
           && authority.catalogIssuedAt.isValid()
           && authority.trustedUtcAtDispatch.isValid()
           && authority.catalogIssuedAt.toUTC() <= authority.trustedUtcAtDispatch.toUTC()
           && authority.trustedUtcAtDispatch.toUTC() < authority.nativeProfileExpiresAt.toUTC()
           && authority.trustedUtcAtDispatch.toUTC() < authority.catalogFreshnessDeadline.toUTC()
           && authority.trustedUtcAtDispatch.toUTC() < authority.entitlementDeadline.toUTC();
}

QString utcText(const QDateTime &value)
{
    return value.toUTC().toString(Qt::ISODateWithMs);
}

QJsonObject runtimeAuthorityObject(const CompiledNativeProfile &compiled,
                                   const NativeConnectionPolicySnapshot &snapshot,
                                   const QByteArray &policySha256)
{
    const NativeRuntimeAuthority &authority = compiled.runtimeAuthority;
    return {
        {QStringLiteral("schema_version"), 1},
        {QStringLiteral("device_audience"), authority.deviceAudience},
        {QStringLiteral("catalog_revision"), QString::number(authority.catalogRevision)},
        {QStringLiteral("catalog_payload_sha256"),
         QString::fromLatin1(authority.catalogPayloadSha256.toHex())},
        {QStringLiteral("catalog_signing_kid"), authority.catalogSigningKeyId},
        {QStringLiteral("catalog_source"), authority.source == CatalogSource::Network
             ? QStringLiteral("network") : QStringLiteral("lkg")},
        {QStringLiteral("profile_id"), authority.profileId},
        {QStringLiteral("transport"), transportKindName(authority.transport)},
        {QStringLiteral("config_generation"), QString::number(authority.configGeneration)},
        {QStringLiteral("binding_generation"), QString::number(authority.bindingGeneration)},
        {QStringLiteral("native_profile_expires_at"), utcText(authority.nativeProfileExpiresAt)},
        {QStringLiteral("catalog_freshness_deadline"), utcText(authority.catalogFreshnessDeadline)},
        {QStringLiteral("entitlement_deadline"), utcText(authority.entitlementDeadline)},
        {QStringLiteral("catalog_issued_at"), utcText(authority.catalogIssuedAt)},
        {QStringLiteral("trusted_utc_at_dispatch"), utcText(authority.trustedUtcAtDispatch)},
        {QStringLiteral("policy_schema"), QLatin1String(kNativeDispatchPolicySchema)},
        {QStringLiteral("policy_sha256"), QString::fromLatin1(policySha256.toHex())},
        {QStringLiteral("protected_tunnel_ips"),
         QJsonArray::fromStringList(snapshot.protectedTunnelIpLiterals)},
        {QStringLiteral("receiver_monotonic_policy"),
         QStringLiteral("anchor_on_validated_dispatch_v1")},
    };
}

bool buildExpected(const CompiledNativeProfile &compiled,
                   const NativeConnectionPolicySnapshot &snapshot,
                   PreparedNativeConnectionPolicy &prepared,
                   QString &error)
{
    prepared = {};
    const bool ruLocation = compiled.locationCountry == QLatin1String("RU");
    const bool requestedSplit = snapshot.ruDirectRequested && !ruLocation;
    const bool splitOn = requestedSplit && !snapshot.routeExclusions.isEmpty();
    if (!validateSnapshot(compiled, snapshot, splitOn, error))
        return false;

    QJsonObject configuration = compiled.vpnConfiguration;
    configuration.insert(amnezia::configKey::splitTunnelType,
                         splitOn ? amnezia::RouteMode::VpnAllExceptSites
                                 : amnezia::RouteMode::VpnAllSites);
    configuration.insert(amnezia::configKey::splitTunnelSites,
                         splitOn ? QJsonArray::fromStringList(snapshot.routeExclusions)
                                 : QJsonArray{});

    const bool appSplitOn = snapshot.appsSplitEnabled && !snapshot.splitApps.isEmpty();
    configuration.insert(amnezia::configKey::appSplitTunnelType,
                         appSplitOn ? snapshot.appsRouteMode
                                    : amnezia::AppsRouteMode::VpnAllApps);
    configuration.insert(amnezia::configKey::splitTunnelApps,
                         appSplitOn ? QJsonArray::fromStringList(snapshot.splitApps)
                                    : QJsonArray{});

    bool dnsMaskApplied = false;
    if (!ruLocation && snapshot.dnsMaskRequested && !snapshot.dnsForwardRequested) {
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
        configuration.insert(QStringLiteral("splitDnsSuffixes"),
                             QJsonArray::fromStringList(snapshot.splitDnsSuffixes));
        configuration.insert(QStringLiteral("splitDnsServer"), snapshot.splitDnsServer);
#else
        if (snapshot.maskDnsServers.size() < 2) {
            error = QStringLiteral("local DNS mask requires two resolvers");
            return false;
        }
        configuration.insert(QStringLiteral("dns1"), snapshot.maskDnsServers.at(0));
        configuration.insert(QStringLiteral("dns2"), snapshot.maskDnsServers.at(1));
#endif
        dnsMaskApplied = true;
    }

    // AWG-only local forwarder settings are never admitted into the Xray native envelope.
    if (compiled.transport == TransportKind::Awg && !ruLocation
        && snapshot.dnsForwardRequested) {
        configuration.insert(QStringLiteral("dnsFwdOn"), QStringLiteral("1"));
        configuration.insert(QStringLiteral("dnsFwdSuffixes"),
                             snapshot.splitDnsSuffixes.join(QLatin1Char(',')));
        configuration.insert(QStringLiteral("dnsFwdServer"), snapshot.splitDnsServer);
        configuration.insert(QStringLiteral("dnsFwdWarmup"),
                             snapshot.dnsForwardWarmup ? QStringLiteral("1")
                                                       : QStringLiteral("0"));
    }

    if (snapshot.includeDesktopKillSwitch) {
        configuration.insert(amnezia::configKey::killSwitchOption,
                             QVariant(snapshot.killSwitchEnabled).toString());
        configuration.insert(amnezia::configKey::allowedDnsServers,
                             QJsonArray::fromStringList(snapshot.allowedDnsServers));
    }

    // Immutable discriminator is outside the authority object, so stripping only that object can
    // never downgrade a catalog-v2 profile into a legacy/manual native profile.
    configuration.insert(QStringLiteral("native_envelope_schema"),
                         QStringLiteral("tribe_catalog_v2_native_v1"));

    if (!validRuntimeAuthority(compiled)) {
        error = QStringLiteral("native runtime authority is missing/expired");
        return false;
    }
    QByteArray policySha256;
    if (!nativeDispatchPolicySha256(compiled, snapshot, configuration, policySha256, error))
        return false;
    configuration.insert(QStringLiteral("runtime_authority_v1"),
                         runtimeAuthorityObject(compiled, snapshot, policySha256));

    prepared.configuration = std::move(configuration);
    prepared.splitOn = splitOn;
    prepared.dnsMaskApplied = dnsMaskApplied;
    return true;
}

} // namespace

bool NativeConnectionPolicyCompiler::compile(
    const CompiledNativeProfile &compiled, const NativeConnectionPolicySnapshot &snapshot,
    PreparedNativeConnectionPolicy &prepared, QString &error)
{
    error.clear();
    return buildExpected(compiled, snapshot, prepared, error);
}

bool NativeConnectionPolicyCompiler::sanitizeForDispatch(
    const CompiledNativeProfile &compiled, const NativeConnectionPolicySnapshot &snapshot,
    const QJsonObject &configuration, QString &error)
{
    error.clear();
    PreparedNativeConnectionPolicy expected;
    if (!buildExpected(compiled, snapshot, expected, error))
        return false;
    if (configuration != expected.configuration) {
        error = QStringLiteral("final native envelope differs from bounded local policy output");
        return false;
    }
    return true;
}

} // namespace avpn
