#include "NativeProfileCompiler.h"

#include "AwgConfigBuilder.h"
#include "CatalogParser.h"

#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/models/protocols/xrayProtocolConfig.h"

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSet>

namespace avpn {
namespace {

bool exactKeys(const QJsonObject &object, const QSet<QString> &allowed)
{
    for (auto it = object.constBegin(); it != object.constEnd(); ++it)
        if (!allowed.contains(it.key()))
            return false;
    return true;
}

bool canonicalBase64Key32(const QString &text)
{
    const QByteArray encoded = text.toLatin1();
    if (QString::fromLatin1(encoded) != text)
        return false;
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    return decoded.decodingStatus == QByteArray::Base64DecodingStatus::Ok
           && decoded.decoded.size() == 32 && decoded.decoded.toBase64() == encoded;
}

QString endpointText(const QString &host, int port)
{
    QHostAddress literal;
    if (literal.setAddress(host) && literal.protocol() == QAbstractSocket::IPv6Protocol)
        return QStringLiteral("[%1]:%2").arg(host).arg(port);
    return QStringLiteral("%1:%2").arg(host).arg(port);
}

QStringList jsonStrings(const QJsonValue &value)
{
    QStringList result;
    for (const QJsonValue &entry : value.toArray())
        result.append(entry.toString());
    return result;
}

void fillMetadata(const CatalogCandidate &candidate, CompiledNativeProfile &compiled)
{
    compiled.transport = candidate.transport;
    compiled.profileId = candidate.profileId;
    compiled.locationId = candidate.locationId;
    compiled.locationCountry = candidate.locationCountry;
    compiled.failureDomain = candidate.failureDomain;
    compiled.configGeneration = candidate.nativeProfile.configGeneration;
    compiled.bindingGeneration = candidate.nativeProfile.bindingGeneration;
    compiled.expiresAt = candidate.nativeProfile.expiresAt.toUTC();
}

bool validLocalOptions(const NativeProfileCompileOptions &options, QString &error)
{
    if (options.dnsServers.isEmpty() || options.dnsServers.size() > 8) {
        error = QStringLiteral("invalid local DNS policy");
        return false;
    }
    for (const QString &dns : options.dnsServers) {
        QHostAddress address;
        if (!address.setAddress(dns) || address.isNull()) {
            error = QStringLiteral("local DNS policy requires IP literals");
            return false;
        }
    }
    if (options.splitTunnelType < 0 || options.splitTunnelType > 2
        || options.configVersion < 0 || options.configVersion > 1000000
        || options.xrayMaxMemoryBytes < 16LL * 1024 * 1024
        || options.xrayMaxMemoryBytes > 512LL * 1024 * 1024) {
        error = QStringLiteral("local native compile options outside safety bounds");
        return false;
    }
    return true;
}

AwgParams awgParamsFromTyped(const QJsonObject &object)
{
    AwgParams out;
    out.Jc = object.value(QStringLiteral("Jc")).toInt();
    out.Jmin = object.value(QStringLiteral("Jmin")).toInt();
    out.Jmax = object.value(QStringLiteral("Jmax")).toInt();
    out.S1 = object.value(QStringLiteral("S1")).toInt();
    out.S2 = object.value(QStringLiteral("S2")).toInt();
    if (object.contains(QStringLiteral("S3")) && !object.value(QStringLiteral("S3")).isNull())
        out.S3 = object.value(QStringLiteral("S3")).toInt();
    if (object.contains(QStringLiteral("S4")) && !object.value(QStringLiteral("S4")).isNull())
        out.S4 = object.value(QStringLiteral("S4")).toInt();
    out.H1 = object.value(QStringLiteral("H1")).toInt();
    out.H2 = object.value(QStringLiteral("H2")).toInt();
    out.H3 = object.value(QStringLiteral("H3")).toInt();
    out.H4 = object.value(QStringLiteral("H4")).toInt();
    out.I1 = object.value(QStringLiteral("I1")).toString();
    out.I2 = object.value(QStringLiteral("I2")).toString();
    out.I3 = object.value(QStringLiteral("I3")).toString();
    out.I4 = object.value(QStringLiteral("I4")).toString();
    out.I5 = object.value(QStringLiteral("I5")).toString();
    out.headerProtectionKey = object.value(QStringLiteral("HeaderProtectionKey")).toString();
    out.contentPaddingAddition = object.value(QStringLiteral("ContentPaddingAddition")).toString();
    out.rekeyAfterTime = object.value(QStringLiteral("RekeyAfterTime")).toString();
    out.rekeyTimeout = object.value(QStringLiteral("RekeyTimeout")).toString();
    out.rejectAfterTime = object.value(QStringLiteral("RejectAfterTime")).toString();
    out.keepaliveTimeout = object.value(QStringLiteral("KeepaliveTimeout")).toString();
    out.maxHandshakeAttempts = object.value(QStringLiteral("MaxHandshakeAttempts")).toString();
    out.randomTrailers = object.value(QStringLiteral("RandomTrailers")).toBool();
    out.disableCookies = object.value(QStringLiteral("DisableCookies")).toBool();
    return out;
}

QJsonObject expectedAwgRoot(const CatalogCandidate &candidate,
                            const NativeProfileCompileOptions &options)
{
    const QJsonObject typed = candidate.nativeProfile.config;
    Subscription subscription;
    subscription.version = 2;
    subscription.address = jsonStrings(typed.value(QStringLiteral("address")));
    SubscriptionNode node;
    node.nodeId = candidate.profileId;
    node.region = candidate.locationId;
    node.countryCode = candidate.locationCountry;
    node.endpoint = endpointText(typed.value(QStringLiteral("endpoint_host")).toString(),
                                 typed.value(QStringLiteral("endpoint_port")).toInt());
    node.serverPubkey = typed.value(QStringLiteral("server_public_key")).toString();
    node.proto = QStringLiteral("awg");
    node.allowedIps = jsonStrings(typed.value(QStringLiteral("allowed_ips")));
    node.dns = jsonStrings(typed.value(QStringLiteral("dns")));
    node.mtu = typed.value(QStringLiteral("mtu")).toInt();
    node.persistentKeepalive = typed.value(QStringLiteral("persistent_keepalive")).toInt();
    node.awg = awgParamsFromTyped(typed.value(QStringLiteral("awg_params")).toObject());

    QJsonObject root = AwgConfigBuilder::build(subscription, node, options.awgKeys);
    // AwgConfigBuilder's legacy endpoint splitter predates IPv6 literals; enforce the already
    // validated unbracketed host in native JSON while wg-quick retains [v6]:port.
    root.insert(QStringLiteral("hostName"), typed.value(QStringLiteral("endpoint_host")));
    QJsonObject inner = root.value(QStringLiteral("awg_config_data")).toObject();
    inner.insert(QStringLiteral("hostName"), typed.value(QStringLiteral("endpoint_host")));
    inner.insert(QStringLiteral("port"), typed.value(QStringLiteral("endpoint_port")));
    root.insert(QStringLiteral("awg_config_data"), inner);
    root.insert(QStringLiteral("splitTunnelType"), options.splitTunnelType);
    root.insert(QStringLiteral("config_version"), options.configVersion);
    return root;
}

bool sanitizeAwg(const CatalogCandidate &candidate,
                 const NativeProfileCompileOptions &options,
                 const CompiledNativeProfile &compiled,
                 QString &error)
{
    const QJsonObject typed = candidate.nativeProfile.config;
    const QJsonObject awg = typed.value(QStringLiteral("awg_params")).toObject();
    const QJsonObject root = compiled.vpnConfiguration;
    static const QSet<QString> rootKeys = {
        QStringLiteral("protocol"), QStringLiteral("awg_config_data"),
        QStringLiteral("hostName"), QStringLiteral("dns1"), QStringLiteral("dns2"),
        QStringLiteral("splitTunnelType"), QStringLiteral("config_version"),
    };
    if (!exactKeys(root, rootKeys) || root.value(QStringLiteral("protocol")) != QLatin1String("awg")
        || root.size() != rootKeys.size()
        || root.value(QStringLiteral("hostName")) != typed.value(QStringLiteral("endpoint_host"))
        || root != expectedAwgRoot(candidate, options)) {
        error = QStringLiteral("malformed AWG native root");
        return false;
    }
    const QJsonObject inner = root.value(QStringLiteral("awg_config_data")).toObject();
    static const QSet<QString> innerKeys = {
        QStringLiteral("client_ip"), QStringLiteral("client_priv_key"),
        QStringLiteral("client_pub_key"), QStringLiteral("client_id"),
        QStringLiteral("server_pub_key"), QStringLiteral("hostName"), QStringLiteral("port"),
        QStringLiteral("allowed_ips"), QStringLiteral("persistent_keep_alive"),
        QStringLiteral("mtu"), QStringLiteral("Jc"), QStringLiteral("Jmin"),
        QStringLiteral("Jmax"), QStringLiteral("S1"), QStringLiteral("S2"),
        QStringLiteral("S3"), QStringLiteral("S4"), QStringLiteral("H1"),
        QStringLiteral("H2"), QStringLiteral("H3"), QStringLiteral("H4"),
        QStringLiteral("I1"), QStringLiteral("I2"), QStringLiteral("I3"),
        QStringLiteral("I4"), QStringLiteral("I5"),
        QStringLiteral("HeaderProtectionKey"), QStringLiteral("ContentPaddingAddition"),
        QStringLiteral("RekeyAfterTime"), QStringLiteral("RekeyTimeout"),
        QStringLiteral("RejectAfterTime"), QStringLiteral("KeepaliveTimeout"),
        QStringLiteral("MaxHandshakeAttempts"), QStringLiteral("RandomTrailers"),
        QStringLiteral("DisableCookies"), QStringLiteral("isObfuscationEnabled"),
        QStringLiteral("config"),
    };
    if (!exactKeys(inner, innerKeys)
        || inner.value(QStringLiteral("client_priv_key")).toString() != options.awgKeys.privateKey
        || inner.value(QStringLiteral("client_pub_key")) != typed.value(QStringLiteral("client_public_key"))
        || inner.value(QStringLiteral("client_id")) != typed.value(QStringLiteral("client_public_key"))
        || inner.value(QStringLiteral("server_pub_key")) != typed.value(QStringLiteral("server_public_key"))
        || inner.value(QStringLiteral("hostName")) != typed.value(QStringLiteral("endpoint_host"))
        || inner.value(QStringLiteral("port")) != typed.value(QStringLiteral("endpoint_port"))
        || inner.value(QStringLiteral("RandomTrailers")).toString() != QLatin1String("1")
        || inner.value(QStringLiteral("DisableCookies")).toString() != QLatin1String("1")
        || inner.value(QStringLiteral("isObfuscationEnabled")) != true
        || !inner.value(QStringLiteral("config")).isString()
        || !inner.value(QStringLiteral("config")).toString().contains(
            QStringLiteral("RandomTrailers = 1\n"))
        || !inner.value(QStringLiteral("config")).toString().contains(
            QStringLiteral("DisableCookies = 1\n"))) {
        error = QStringLiteral("AWG native output failed binding/sanitizer checks");
        return false;
    }
    for (const QString &key : {QStringLiteral("Jc"), QStringLiteral("Jmin"),
                               QStringLiteral("Jmax"), QStringLiteral("S1"),
                               QStringLiteral("S2"), QStringLiteral("H1"),
                               QStringLiteral("H2"), QStringLiteral("H3"),
                               QStringLiteral("H4")}) {
        if (inner.value(key).toString() != QString::number(awg.value(key).toInt())) {
            error = QStringLiteral("AWG native parameter mismatch");
            return false;
        }
    }
    return true;
}

bool sanitizeXray(const CatalogCandidate &candidate,
                  const NativeProfileCompileOptions &options,
                  const CompiledNativeProfile &compiled,
                  QString &error)
{
    const QJsonObject typed = candidate.nativeProfile.config;
    const QJsonObject root = compiled.vpnConfiguration;
    static const QSet<QString> rootKeys = {
        QStringLiteral("protocol"), QStringLiteral("xray_config_data"),
        QStringLiteral("hostName"), QStringLiteral("dns1"), QStringLiteral("dns2"),
        QStringLiteral("splitTunnelType"), QStringLiteral("config_version"),
        QStringLiteral("xray_max_memory_bytes"),
    };
    if (!exactKeys(root, rootKeys) || root.value(QStringLiteral("protocol")) != QLatin1String("xray")
        || root.size() != rootKeys.size()
        || root.value(QStringLiteral("hostName")) != typed.value(QStringLiteral("endpoint_host"))
        || root.value(QStringLiteral("dns1")).toString() != options.dnsServers.value(0)
        || root.value(QStringLiteral("dns2")).toString()
               != options.dnsServers.value(options.dnsServers.size() > 1 ? 1 : 0)
        || root.value(QStringLiteral("splitTunnelType")).toInt() != options.splitTunnelType
        || root.value(QStringLiteral("config_version")).toInt() != options.configVersion
        || qint64(root.value(QStringLiteral("xray_max_memory_bytes")).toDouble())
               != options.xrayMaxMemoryBytes) {
        error = QStringLiteral("malformed Xray native root");
        return false;
    }
    const QJsonObject data = root.value(QStringLiteral("xray_config_data")).toObject();
    static const QSet<QString> dataKeys = {
        QStringLiteral("config"), QStringLiteral("local_port"), QStringLiteral("clientId"),
    };
    if (!exactKeys(data, dataKeys) || data.size() != dataKeys.size()
        || data.value(QStringLiteral("local_port")).toString()
               != QLatin1String(amnezia::protocols::xray::defaultLocalProxyPort)
        || data.value(QStringLiteral("clientId")) != typed.value(QStringLiteral("uuid"))) {
        error = QStringLiteral("malformed Xray native config envelope");
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(
        data.value(QStringLiteral("config")).toString().toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        error = QStringLiteral("compiled Xray core config is not valid JSON");
        return false;
    }
    const QJsonObject core = document.object();
    if (!exactKeys(core, {QStringLiteral("log"), QStringLiteral("inbounds"),
                          QStringLiteral("outbounds")}) || core.size() != 3) {
        error = QStringLiteral("Xray core config contains forbidden top-level sections");
        return false;
    }
    const QJsonObject log = core.value(QStringLiteral("log")).toObject();
    if (log.size() != 1 || log.value(QStringLiteral("loglevel")) != QLatin1String("error")) {
        error = QStringLiteral("Xray file/access logging is forbidden");
        return false;
    }
    const QJsonArray inbounds = core.value(QStringLiteral("inbounds")).toArray();
    if (inbounds.size() != 1 || !inbounds.first().isObject()) {
        error = QStringLiteral("Xray requires exactly one inbound");
        return false;
    }
    const QJsonObject inbound = inbounds.first().toObject();
    if (!exactKeys(inbound, {QStringLiteral("listen"), QStringLiteral("port"),
                             QStringLiteral("protocol"), QStringLiteral("settings")})
        || inbound.size() != 4
        || inbound.value(QStringLiteral("listen"))
               != QLatin1String(amnezia::protocols::xray::defaultLocalListenAddr)
        || inbound.value(QStringLiteral("port")).toInt()
               != QLatin1String(amnezia::protocols::xray::defaultLocalProxyPort).toInt()
        || inbound.value(QStringLiteral("protocol")) != QLatin1String("socks")) {
        error = QStringLiteral("Xray inbound must be the bundled loopback SOCKS listener");
        return false;
    }
    const QJsonObject inboundSettings = inbound.value(QStringLiteral("settings")).toObject();
    if (inboundSettings.size() != 1 || inboundSettings.value(QStringLiteral("udp")) != true) {
        error = QStringLiteral("Xray inbound settings mismatch");
        return false;
    }
    const QJsonArray outbounds = core.value(QStringLiteral("outbounds")).toArray();
    if (outbounds.size() != 1 || !outbounds.first().isObject()) {
        error = QStringLiteral("Xray requires exactly one outbound");
        return false;
    }
    const QJsonObject outbound = outbounds.first().toObject();
    if (!exactKeys(outbound, {QStringLiteral("protocol"), QStringLiteral("settings"),
                              QStringLiteral("streamSettings")})
        || outbound.size() != 3
        || outbound.value(QStringLiteral("protocol")) != QLatin1String("vless")) {
        error = QStringLiteral("Xray outbound must be exactly one VLESS outbound");
        return false;
    }
    const QJsonObject settings = outbound.value(QStringLiteral("settings")).toObject();
    if (!exactKeys(settings, {QStringLiteral("address"), QStringLiteral("port"),
                              QStringLiteral("id"), QStringLiteral("encryption"),
                              QStringLiteral("flow")})
        || settings.size() != 5) {
        error = QStringLiteral("Xray VLESS binding shape mismatch");
        return false;
    }
    if (settings.value(QStringLiteral("address"))
            != typed.value(QStringLiteral("endpoint_host"))
        || settings.value(QStringLiteral("port"))
            != typed.value(QStringLiteral("endpoint_port"))) {
        error = QStringLiteral("Xray endpoint does not match signed profile");
        return false;
    }
    if (settings.value(QStringLiteral("id")) != typed.value(QStringLiteral("uuid"))
        || settings.value(QStringLiteral("encryption")) != QLatin1String("none")
        || settings.value(QStringLiteral("flow")) != typed.value(QStringLiteral("flow"))) {
        error = QStringLiteral("Xray device binding/flow mismatch");
        return false;
    }
    const QJsonObject stream = outbound.value(QStringLiteral("streamSettings")).toObject();
    const QJsonObject reality = stream.value(QStringLiteral("realitySettings")).toObject();
    if (!exactKeys(stream, {QStringLiteral("network"), QStringLiteral("security"),
                            QStringLiteral("realitySettings")})
        || stream.size() != 3 || stream.value(QStringLiteral("network")) != QLatin1String("tcp")
        || stream.value(QStringLiteral("security")) != QLatin1String("reality")
        || !exactKeys(reality, {QStringLiteral("fingerprint"), QStringLiteral("serverName"),
                                QStringLiteral("password"), QStringLiteral("shortId"),
                                QStringLiteral("spiderX")})
        || reality.size() != 5
        || reality.value(QStringLiteral("fingerprint")) != typed.value(QStringLiteral("fingerprint"))
        || reality.value(QStringLiteral("serverName")) != typed.value(QStringLiteral("server_name"))
        || reality.value(QStringLiteral("password"))
               != typed.value(QStringLiteral("reality_public_key"))
        || reality.value(QStringLiteral("shortId")) != typed.value(QStringLiteral("short_id"))
        || reality.value(QStringLiteral("spiderX")).toString() != QString()) {
        error = QStringLiteral("Xray Reality/TCP sanitizer mismatch");
        return false;
    }
    return true;
}

} // namespace

bool NativeProfileCompiler::compile(const CatalogCandidate &candidate,
                                    const NativeProfileCompileOptions &options,
                                    CompiledNativeProfile &compiled,
                                    QString &error)
{
    if (candidate.transport == TransportKind::Awg)
        return compileAwg31(candidate, options, compiled, error);
    if (candidate.transport == TransportKind::Xray)
        return compileXrayRealityVisionTcp(candidate, options, compiled, error);
    compiled = CompiledNativeProfile{};
    error = QStringLiteral("unknown transport compiler");
    return false;
}

bool NativeProfileCompiler::compileAwg31(const CatalogCandidate &candidate,
                                         const NativeProfileCompileOptions &options,
                                         CompiledNativeProfile &compiled,
                                         QString &error)
{
    compiled = CompiledNativeProfile{};
    error.clear();
    CatalogParseError typedError;
    if (candidate.transport != TransportKind::Awg
        || !CatalogParser::validateTypedNativeProfile(candidate, typedError)) {
        error = QStringLiteral("AWG typed profile rejected by sanitizer");
        return false;
    }
    if (!validLocalOptions(options, error)
        || !canonicalBase64Key32(options.awgKeys.privateKey)
        || !canonicalBase64Key32(options.awgKeys.publicKey)) {
        if (error.isEmpty()) error = QStringLiteral("device AWG keys are unavailable");
        return false;
    }
    const QJsonObject typed = candidate.nativeProfile.config;
    if (typed.value(QStringLiteral("client_public_key")).toString()
        != options.awgKeys.publicKey) {
        error = QStringLiteral("AWG catalog binding does not match device public key");
        return false;
    }

    compiled.container = amnezia::DockerContainer::Awg;
    compiled.vpnConfiguration = expectedAwgRoot(candidate, options);
    fillMetadata(candidate, compiled);
    return sanitizeCompiled(candidate, options, compiled, error);
}

bool NativeProfileCompiler::compileXrayRealityVisionTcp(
    const CatalogCandidate &candidate, const NativeProfileCompileOptions &options,
    CompiledNativeProfile &compiled, QString &error)
{
    compiled = CompiledNativeProfile{};
    error.clear();
    CatalogParseError typedError;
    if (candidate.transport != TransportKind::Xray
        || !CatalogParser::validateTypedNativeProfile(candidate, typedError)) {
        error = QStringLiteral("Xray typed profile rejected by sanitizer");
        return false;
    }
    if (!validLocalOptions(options, error))
        return false;
    const QJsonObject typed = candidate.nativeProfile.config;

    // Exact native template used by XrayConfigurator::buildClientProtocolConfig: one loopback
    // SOCKS inbound and one VLESS Reality/TCP/Vision outbound. No server-provided raw JSON enters.
    const QJsonObject reality{{QStringLiteral("fingerprint"),
                               typed.value(QStringLiteral("fingerprint"))},
                              {QStringLiteral("serverName"),
                               typed.value(QStringLiteral("server_name"))},
                              {QStringLiteral("password"),
                               typed.value(QStringLiteral("reality_public_key"))},
                              {QStringLiteral("shortId"),
                               typed.value(QStringLiteral("short_id"))},
                              {QStringLiteral("spiderX"), QString()}};
    const QJsonObject outbound{
        {QStringLiteral("protocol"), QStringLiteral("vless")},
        {QStringLiteral("settings"),
         QJsonObject{{QStringLiteral("address"), typed.value(QStringLiteral("endpoint_host"))},
                     {QStringLiteral("port"), typed.value(QStringLiteral("endpoint_port"))},
                     {QStringLiteral("id"), typed.value(QStringLiteral("uuid"))},
                     {QStringLiteral("encryption"), QStringLiteral("none")},
                     {QStringLiteral("flow"), typed.value(QStringLiteral("flow"))}}},
        {QStringLiteral("streamSettings"),
         QJsonObject{{QStringLiteral("network"), QStringLiteral("tcp")},
                     {QStringLiteral("security"), QStringLiteral("reality")},
                     {QStringLiteral("realitySettings"), reality}}}};
    const QJsonObject inbound{
        {QStringLiteral("listen"),
         QLatin1String(amnezia::protocols::xray::defaultLocalListenAddr)},
        {QStringLiteral("port"),
         QLatin1String(amnezia::protocols::xray::defaultLocalProxyPort).toInt()},
        {QStringLiteral("protocol"), QStringLiteral("socks")},
        {QStringLiteral("settings"), QJsonObject{{QStringLiteral("udp"), true}}}};
    const QJsonObject core{
        {QStringLiteral("log"),
         QJsonObject{{QStringLiteral("loglevel"), QStringLiteral("error")}}},
        {QStringLiteral("inbounds"), QJsonArray{inbound}},
        {QStringLiteral("outbounds"), QJsonArray{outbound}}};
    const QString nativeJson = QString::fromUtf8(
        QJsonDocument(core).toJson(QJsonDocument::Compact));
    // Reuse the native Amnezia model for the platform envelope. The upstream configurator's
    // client builder is private and SSH-coupled, so only the bounded core template above is kept
    // local and independently post-sanitized; envelope key/shape ownership stays native.
    amnezia::XrayClientConfig nativeClient;
    nativeClient.nativeConfig = nativeJson;
    nativeClient.localPort = QLatin1String(amnezia::protocols::xray::defaultLocalProxyPort);
    nativeClient.id = typed.value(QStringLiteral("uuid")).toString();
    const QJsonObject data = nativeClient.toJson();
    const QString dns1 = options.dnsServers.value(0);
    const QString dns2 = options.dnsServers.value(options.dnsServers.size() > 1 ? 1 : 0);
    compiled.container = amnezia::DockerContainer::Xray;
    compiled.vpnConfiguration = {
        {QStringLiteral("protocol"), QStringLiteral("xray")},
        {QStringLiteral("xray_config_data"), data},
        {QStringLiteral("hostName"), typed.value(QStringLiteral("endpoint_host"))},
        {QStringLiteral("dns1"), dns1}, {QStringLiteral("dns2"), dns2},
        {QStringLiteral("splitTunnelType"), options.splitTunnelType},
        {QStringLiteral("config_version"), options.configVersion},
        {QStringLiteral("xray_max_memory_bytes"), double(options.xrayMaxMemoryBytes)},
    };
    fillMetadata(candidate, compiled);
    return sanitizeCompiled(candidate, options, compiled, error);
}

bool NativeProfileCompiler::sanitizeCompiled(const CatalogCandidate &candidate,
                                             const NativeProfileCompileOptions &options,
                                             const CompiledNativeProfile &compiled,
                                             QString &error)
{
    error.clear();
    CatalogParseError typedError;
    if (!CatalogParser::validateTypedNativeProfile(candidate, typedError)) {
        error = QStringLiteral("typed native profile failed pre-execution sanitizer");
        return false;
    }
    if (compiled.container != nativeContainerForTransport(candidate.transport)
        || compiled.transport != candidate.transport || compiled.profileId != candidate.profileId
        || compiled.locationId != candidate.locationId
        || compiled.locationCountry != candidate.locationCountry
        || compiled.failureDomain != candidate.failureDomain
        || compiled.configGeneration != candidate.nativeProfile.configGeneration
        || compiled.bindingGeneration != candidate.nativeProfile.bindingGeneration
        || !compiled.expiresAt.isValid()
        || compiled.expiresAt.toUTC() != candidate.nativeProfile.expiresAt.toUTC()
        || !hasExpectedNativeEnvelope(compiled, candidate.transport)) {
        error = QStringLiteral("compiled transport metadata/envelope mismatch");
        return false;
    }
    return candidate.transport == TransportKind::Awg
               ? sanitizeAwg(candidate, options, compiled, error)
               : sanitizeXray(candidate, options, compiled, error);
}

} // namespace avpn
