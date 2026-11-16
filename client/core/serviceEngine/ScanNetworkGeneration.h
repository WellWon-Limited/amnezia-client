// client/core/serviceEngine/ScanNetworkGeneration.h
// AVPN serviceEngine - the Scanner's two LOCAL network identities (plan scanner-client-plan.md §2.11a, review
// v2.1 F10, lead decision 3 of 16.11). [header-only, QtCore; pure]
//
//  - The strict generation TUPLE stamps CURRENT evidence (this scan's verdicts, «рабочие» counts, the S6
//    result, access facts, the exclusion bracket). One element per path monitor: {source, epoch, counter}.
//    `epoch` is a random 64-bit id the monitor picks when it starts (a process or monitor restart = a new
//    epoch, counter back to 0); `counter` grows on every physical-path change it sees (interface type or index,
//    address set, default-gateway set - compared as a local hash). There is no max() of counters: the
//    generation changes when ANY component of ANY source changes - a higher counter, a new epoch, a source that
//    appears or vanishes. Evidence stamped with another value is invalid, so it dies on any change and on every
//    relaunch.
//  - The weak FINGERPRINT keys CACHED rows only (drawn as cache with their age, never verified, never S6,
//    never access or exclusion): interface kind + the operator-level reporting key + a hash of the gateway /
//    subnet where the platform gives it (absent = not part of it). It survives a relaunch, so the last result
//    of a network shows at once while the new scan runs (artboard fig. 18).
// Neither ever leaves the device: requests, outcomes and summaries carry only the reporting key.
//
// Sources per platform (plan §2.11a): iOS `app` (nw_path_monitor) + `ne` (the extension's defaultPath observer,
// reported by the probe host in scan_progress.gen); Android `app` + `xray_service`; macOS / Windows `app` +
// `service` (relayed in the service's scan replies; a one-element tuple until that lane relays it).
//
// Upstream Amnezia has no counterpart. Tests: tests/scan_core_check.cpp (build_scan_core.sh).
#pragma once

#include <QCryptographicHash>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QString>
#include <QStringList>

#include <cmath>

namespace avpn {

// One element of the strict tuple: one path monitor's state.
struct ScanNetSource {
    QString source;       // "app" | "ne" | "xray_service" | "service" (<= 16 chars)
    quint64 epoch = 0;    // random per monitor start
    qint64 counter = 0;   // path changes seen by that monitor since it started
    bool operator==(const ScanNetSource &o) const { return source == o.source && epoch == o.epoch && counter == o.counter; }
    bool operator!=(const ScanNetSource &o) const { return !(*this == o); }
};

inline QString scanNetEpochHex(quint64 epoch) { return QString::number(epoch, 16).rightJustified(16, QLatin1Char('0')); }

// The canonical stamp of a tuple: sha256 over the sorted "source/epoch/counter" elements, 16 hex. Every
// component is in it; the order of the list does not matter; an empty tuple has its own stamp.
inline QString scanNetGeneration(const QList<ScanNetSource> &sources)
{
    QStringList parts;
    for (const ScanNetSource &x : sources)
        parts << x.source + QLatin1Char('/') + scanNetEpochHex(x.epoch) + QLatin1Char('/') + QString::number(x.counter);
    parts.sort();
    const QByteArray in = (QStringLiteral("tribe-scan-gen-v1|") + parts.join(QLatin1Char(';'))).toUtf8();
    return QString::fromLatin1(QCryptographicHash::hash(in, QCryptographicHash::Sha256).toHex().left(16));
}

// The element of `source` in a tuple, or nullptr.
inline const ScanNetSource *scanNetSourceOf(const QList<ScanNetSource> &sources, const QString &source)
{
    for (const ScanNetSource &x : sources)
        if (x.source == source)
            return &x;
    return nullptr;
}

// The weak fingerprint from what the platform gives without permissions: interface kind ("wifi", "cellular",
// ...), the operator-level reporting key, and an optional local hash of gateway / subnet ("" = not part of it).
inline QString scanNetFingerprint(const QString &interfaceKind, const QString &reportingKey, const QString &gatewaySubnetHash = QString())
{
    QString in = QStringLiteral("tribe-scan-fp-v1|") + interfaceKind + QLatin1Char('|') + reportingKey;
    if (!gatewaySubnetHash.isEmpty())
        in += QLatin1Char('|') + gatewaySubnetHash;
    return QString::fromLatin1(QCryptographicHash::hash(in.toUtf8(), QCryptographicHash::Sha256).toHex().left(16));
}

// Wire form of one element (scan_progress.gen, ATTEMPT.gen of ScanHostContract.h):
// {"source": str <= 16, "epoch": 16 lowercase hex chars, "counter": int >= 0}. The epoch is a string because a
// 64-bit integer does not survive a JSON number.
inline QJsonObject scanNetSourceToJson(const ScanNetSource &s)
{
    return QJsonObject{{QStringLiteral("source"), s.source},
                       {QStringLiteral("epoch"), scanNetEpochHex(s.epoch)},
                       {QStringLiteral("counter"), double(qMax<qint64>(0, s.counter))}};
}

inline bool scanNetSourceFromJson(const QJsonValue &v, ScanNetSource &out)
{
    if (!v.isObject())
        return false;
    const QJsonObject o = v.toObject();
    const QJsonValue src = o.value(QLatin1String("source"));
    const QJsonValue ep = o.value(QLatin1String("epoch"));
    const QJsonValue ct = o.value(QLatin1String("counter"));
    if (!src.isString() || src.toString().isEmpty() || src.toString().size() > 16)
        return false;
    if (!ep.isString() || ep.toString().size() != 16)
        return false;
    for (const QChar c : ep.toString())
        if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9')) || (c >= QLatin1Char('a') && c <= QLatin1Char('f'))))
            return false;
    if (!ct.isDouble())
        return false;
    const double d = ct.toDouble();
    if (!std::isfinite(d) || d != std::floor(d) || d < 0 || d > 9007199254740991.0)
        return false;
    bool ok = false;
    out.source = src.toString();
    out.epoch = ep.toString().toULongLong(&ok, 16);
    out.counter = qint64(d);
    return ok;
}

} // namespace avpn
