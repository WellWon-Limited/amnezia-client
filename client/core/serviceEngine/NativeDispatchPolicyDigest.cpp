#include "NativeDispatchPolicyDigest.h"

#include "core/utils/constants/configKeys.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>

#include <algorithm>

namespace avpn {
namespace {

constexpr int kMaximumProjectionBytes = 512 * 1024;

bool appendRecord(QByteArray &out, const QByteArray &name, const QString &value,
                  QString &error)
{
    const QByteArray bytes = value.toUtf8();
    if (value.contains(QChar::Null) || bytes.size() > 256 * 1024) {
        error = QStringLiteral("native dispatch projection value is invalid");
        return false;
    }
    out += name;
    out += ':';
    out += QByteArray::number(bytes.size());
    out += ':';
    out += bytes;
    out += '\n';
    if (out.size() > kMaximumProjectionBytes) {
        error = QStringLiteral("native dispatch projection exceeds local bound");
        return false;
    }
    return true;
}

bool appendList(QByteArray &out, const QByteArray &name, QStringList values,
                QString &error)
{
    std::sort(values.begin(), values.end(), [](const QString &left, const QString &right) {
        return left.toUtf8() < right.toUtf8();
    });
    if (!appendRecord(out, name + "_count", QString::number(values.size()), error))
        return false;
    for (int index = 0; index < values.size(); ++index)
        if (!appendRecord(out, name + '_' + QByteArray::number(index), values.at(index), error))
            return false;
    return true;
}

bool jsonStringList(const QJsonValue &value, QStringList &out)
{
    out.clear();
    if (value.isUndefined())
        return true;
    if (!value.isArray())
        return false;
    for (const QJsonValue &item : value.toArray()) {
        if (!item.isString())
            return false;
        out.append(item.toString());
    }
    return true;
}

bool canonicalInteger(const QJsonValue &value, qint64 minimum, qint64 maximum, QString &out)
{
    if (!value.isDouble())
        return false;
    const double number = value.toDouble();
    const qint64 integer = qint64(number);
    if (double(integer) != number || integer < minimum || integer > maximum)
        return false;
    out = QString::number(integer);
    return true;
}

bool endpointPort(const CompiledNativeProfile &compiled, const QJsonObject &data,
                  QString &port)
{
    if (compiled.transport == TransportKind::Awg)
        return canonicalInteger(data.value(QStringLiteral("port")), 1, 65535, port);
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(
        data.value(QStringLiteral("config")).toString().toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
        return false;
    const QJsonArray outbounds = document.object().value(QStringLiteral("outbounds")).toArray();
    if (outbounds.size() != 1)
        return false;
    const QJsonObject settings = outbounds.first().toObject()
                                     .value(QStringLiteral("settings")).toObject();
    return canonicalInteger(settings.value(QStringLiteral("port")),
                            1, 65535, port);
}

} // namespace

bool encodeNativeDispatchPolicyV1(const CompiledNativeProfile &compiled,
                                  const NativeConnectionPolicySnapshot &snapshot,
                                  const QJsonObject &configuration,
                                  QByteArray &canonicalBytes,
                                  QString &error)
{
    canonicalBytes.clear();
    error.clear();
    if (!hasExpectedNativeEnvelope(compiled, compiled.transport)
        || compiled.profileId.isEmpty() || compiled.profileId.size() > 128
        || compiled.profileId.contains(QChar::Null)
        || compiled.configGeneration == 0
        || compiled.configGeneration > 9007199254740991ULL
        || compiled.bindingGeneration == 0
        || compiled.bindingGeneration > 9007199254740991ULL
        || configuration.contains(QStringLiteral("runtime_authority_v1"))) {
        error = QStringLiteral("native dispatch projection input is not pre-authority config");
        return false;
    }
    const QJsonObject data = configuration.value(
        nativeConfigDataKeyForTransport(compiled.transport)).toObject();
    const QString nativeConfig = data.value(QStringLiteral("config")).toString();
    QString port;
    QString mtu = QStringLiteral("0");
    QString address;
    if (!endpointPort(compiled, data, port)) {
        error = QStringLiteral("native dispatch endpoint port is unavailable");
        return false;
    }
    if (compiled.transport == TransportKind::Awg) {
        address = data.value(QStringLiteral("client_ip")).toString();
        bool ok = false;
        const QString mtuText = data.value(QStringLiteral("mtu")).toString();
        const int parsedMtu = mtuText.toInt(&ok);
        if (!ok || mtuText != QString::number(parsedMtu)
            || parsedMtu < 576 || parsedMtu > 1500) {
            error = QStringLiteral("native dispatch MTU is invalid");
            return false;
        }
        mtu = QString::number(parsedMtu);
    }
    QString splitMode;
    QString appSplitMode;
    QString configVersion;
    if (!canonicalInteger(configuration.value(amnezia::configKey::splitTunnelType),
                          0, 2, splitMode)
        || !canonicalInteger(configuration.value(amnezia::configKey::appSplitTunnelType),
                             0, 2, appSplitMode)
        || !canonicalInteger(configuration.value(QStringLiteral("config_version")),
                             0, 9007199254740991LL, configVersion)) {
        error = QStringLiteral("native dispatch route/config mode is invalid");
        return false;
    }
    QString xrayMemory = QStringLiteral("0");
    if (compiled.transport == TransportKind::Xray
        && !canonicalInteger(configuration.value(QStringLiteral("xray_max_memory_bytes")),
                             8 * 1024 * 1024, 1024LL * 1024 * 1024, xrayMemory)) {
        error = QStringLiteral("native dispatch Xray memory bound is invalid");
        return false;
    }
    QStringList splitSites;
    QStringList splitApps;
    QStringList splitDnsSuffixes;
    QStringList allowedDns;
    if (!jsonStringList(configuration.value(amnezia::configKey::splitTunnelSites), splitSites)
        || !jsonStringList(configuration.value(amnezia::configKey::splitTunnelApps), splitApps)
        || !jsonStringList(configuration.value(QStringLiteral("splitDnsSuffixes")),
                           splitDnsSuffixes)
        || !jsonStringList(configuration.value(amnezia::configKey::allowedDnsServers),
                           allowedDns)) {
        error = QStringLiteral("native dispatch policy list is malformed");
        return false;
    }

    canonicalBytes = QByteArrayLiteral("tribe-native-dispatch-policy-v1\n");
    const auto field = [&](const QByteArray &name, const QString &value) {
        return appendRecord(canonicalBytes, name, value, error);
    };
    if (!field("transport", transportKindName(compiled.transport))
        || !field("native_envelope_schema",
                  configuration.value(QStringLiteral("native_envelope_schema")).toString())
        || !field("profile_id", compiled.profileId)
        || !field("config_generation", QString::number(compiled.configGeneration))
        || !field("binding_generation", QString::number(compiled.bindingGeneration))
        || !field("endpoint_host", configuration.value(QStringLiteral("hostName")).toString())
        || !field("endpoint_port", port)
        || !field("tunnel_address", address)
        || !field("dns1", configuration.value(QStringLiteral("dns1")).toString())
        || !field("dns2", configuration.value(QStringLiteral("dns2")).toString())
        || !field("mtu", mtu)
        || !field("config_version", configVersion)
        || !field("xray_max_memory_bytes", xrayMemory)
        || !field("split_tunnel_type", splitMode)
        || !appendList(canonicalBytes, "split_site", splitSites, error)
        || !field("app_split_tunnel_type", appSplitMode)
        || !appendList(canonicalBytes, "split_app", splitApps, error)
        || !appendList(canonicalBytes, "split_dns_suffix", splitDnsSuffixes, error)
        || !field("split_dns_server",
                  configuration.value(QStringLiteral("splitDnsServer")).toString())
        || !field("dns_forward_on", configuration.value(QStringLiteral("dnsFwdOn")).toString())
        || !field("dns_forward_suffixes",
                  configuration.value(QStringLiteral("dnsFwdSuffixes")).toString())
        || !field("dns_forward_server",
                  configuration.value(QStringLiteral("dnsFwdServer")).toString())
        || !field("dns_forward_warmup",
                  configuration.value(QStringLiteral("dnsFwdWarmup")).toString())
        || !field("kill_switch",
                  configuration.value(amnezia::configKey::killSwitchOption).toString())
        || !appendList(canonicalBytes, "allowed_dns", allowedDns, error)
        || !appendList(canonicalBytes, "protected_tunnel_ip",
                       snapshot.protectedTunnelIpLiterals, error)
        || !field("native_config_sha256", QString::fromLatin1(
                      QCryptographicHash::hash(nativeConfig.toUtf8(), QCryptographicHash::Sha256)
                          .toHex()))) {
        canonicalBytes.clear();
        return false;
    }
    return true;
}

bool nativeDispatchPolicySha256(const CompiledNativeProfile &compiled,
                                const NativeConnectionPolicySnapshot &snapshot,
                                const QJsonObject &configurationWithoutAuthority,
                                QByteArray &digest,
                                QString &error)
{
    QByteArray canonical;
    if (!encodeNativeDispatchPolicyV1(compiled, snapshot, configurationWithoutAuthority,
                                      canonical, error)) {
        digest.clear();
        return false;
    }
    digest = QCryptographicHash::hash(canonical, QCryptographicHash::Sha256);
    return digest.size() == 32;
}

} // namespace avpn
