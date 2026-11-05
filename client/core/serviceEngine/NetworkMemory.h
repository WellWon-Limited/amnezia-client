#pragma once
// AVPN (plan v3 step 5, 2026-11-05): network memory - "the last server that carried data on this
// network". Pure helpers over a small JSON blob kept in QSettings (avpn/netMemory); the facade
// reads/writes it, ServiceEngine::connect uses the remembered node as the first candidate right
// after the user's manual choice. Test: tests/whoami_verdict_check.cpp.
//
// Network key: "wifi" (Wi-Fi or wired - no SSID: on iOS it needs the location permission) or
// "cellular:<MCC-MNC>" (anonymous operator code, the same one the Doctor reports; plain
// "cellular" when the code is unknown, e.g. iOS 16+ without a manual choice). Unknown medium ->
// empty key -> the memory is neither read nor written.
// Stored value: JSON array [{"k":key,"n":nodeId,"t":epochSec}], newest first, at most
// kNetworkMemoryMax entries; entries older than 7 days are ignored on lookup.

#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

namespace avpn {

constexpr int kNetworkMemoryMax = 16;
// An entry older than this is ignored (the network or the fleet has likely changed since).
constexpr qint64 kNetworkMemoryMaxAgeSec = 7 * 24 * 3600;

inline QString networkMemoryKey(const QString &netType, const QString &carrierCode)
{
    if (netType == QLatin1String("cellular")) {
        const QString code = carrierCode.trimmed();
        return code.isEmpty() ? QStringLiteral("cellular") : QStringLiteral("cellular:") + code;
    }
    if (netType == QLatin1String("wifi") || netType == QLatin1String("ethernet"))
        return QStringLiteral("wifi");
    return {};
}

namespace netmemory_detail {
inline QJsonArray load(const QByteArray &json)
{
    const QJsonDocument d = QJsonDocument::fromJson(json);
    return d.isArray() ? d.array() : QJsonArray{};
}
inline QByteArray save(const QJsonArray &a)
{
    return QJsonDocument(a).toJson(QJsonDocument::Compact);
}
} // namespace netmemory_detail

// The remembered node for the key, or empty when there is none or it is older than maxAgeSec
// (an entry without a timestamp counts as old).
inline QString networkMemoryLookup(const QByteArray &json, const QString &key, qint64 nowSec,
                                   qint64 maxAgeSec = kNetworkMemoryMaxAgeSec)
{
    if (key.isEmpty())
        return {};
    for (const QJsonValue &v : netmemory_detail::load(json)) {
        const QJsonObject o = v.toObject();
        if (o.value(QStringLiteral("k")).toString() != key)
            continue;
        const QJsonValue t = o.value(QStringLiteral("t"));
        if (!t.isDouble() || nowSec - qint64(t.toDouble()) > maxAgeSec)
            return {};
        return o.value(QStringLiteral("n")).toString();
    }
    return {};
}

// The node carried data on this network: it becomes the entry for the key (moved to the front).
inline QByteArray networkMemoryRemember(const QByteArray &json, const QString &key, const QString &nodeId,
                                        qint64 nowSec)
{
    if (key.isEmpty() || nodeId.isEmpty())
        return json;
    QJsonArray out;
    out.append(QJsonObject{{QStringLiteral("k"), key}, {QStringLiteral("n"), nodeId},
                           {QStringLiteral("t"), double(nowSec)}});
    for (const QJsonValue &v : netmemory_detail::load(json)) {
        if (out.size() >= kNetworkMemoryMax)
            break;
        const QJsonObject o = v.toObject();
        const QString k = o.value(QStringLiteral("k")).toString();
        if (k.isEmpty() || k == key)
            continue;
        out.append(o);
    }
    return netmemory_detail::save(out);
}

// The remembered node failed the check on this network: drop the entry, but only if it still
// points at that node (a newer success on the same key is kept).
inline QByteArray networkMemoryForget(const QByteArray &json, const QString &key, const QString &nodeId)
{
    if (key.isEmpty() || nodeId.isEmpty())
        return json;
    const QJsonArray in = netmemory_detail::load(json);
    QJsonArray out;
    bool removed = false;
    for (const QJsonValue &v : in) {
        const QJsonObject o = v.toObject();
        if (o.value(QStringLiteral("k")).toString() == key && o.value(QStringLiteral("n")).toString() == nodeId) {
            removed = true;
            continue;
        }
        out.append(o);
    }
    return removed ? netmemory_detail::save(out) : json;
}

} // namespace avpn
