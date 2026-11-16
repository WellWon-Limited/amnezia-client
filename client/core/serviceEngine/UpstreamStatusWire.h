// client/core/serviceEngine/UpstreamStatusWire.h
// AVPN serviceEngine (upstream nodes, release C, lane P1) - the tunnel owner's status object (contract
// section 5) as it travels on Android, and the late hand-over message (contract section 2). Pure QtCore:
// the decode/normalize/change rules are the Qt twin of the iOS bridge's (IosNativePolicy.h
// normalizeUpstreamStatus / upstreamStatusChanged), so one shape serves iOS, macOS and Android.
// [header-only, QtCore; no I/O, no globals]
//
// Wire (~/avpn-build/plans/provider-pool/android-ipc-contract.md):
//  - status event (service -> app, ServiceEvent.UPSTREAM_STATUS -> JNI onUpstreamStatus):
//    {"upstream":{state, code, seq, renewed_ms_ago, expires_in_ms, revision, config_changed,
//                 applied_bytes, shadow_bytes, meter_scope}} - the macOS owner's UpstreamLeaseOwner::statusJson
//    and the iOS status reply's "upstream" are the same object;
//  - hand-over (app -> service, activity upstreamLeaseSet -> Action.UPSTREAM_LEASE_SET):
//    {"action":"upstream_lease_set","upstream_lease":{...contract section 1...}} - the iOS provider message.
// Never logs: the lease object carries the renew token.
//
// Tests: tests/upstream_status_wire_check.cpp (build_upstream_status_wire.sh).
#pragma once

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>
#include <QVariantMap>

#include <cmath>

namespace avpn {

struct UpstreamTunnelStatus {
    bool present = false;          // the event carried an "upstream" object
    QString state = QStringLiteral("none");
    QString code;
    qint64 seq = 0;
    qint64 renewedMsAgo = -1;
    qint64 expiresInMs = 0;
    qint64 revision = 0;
    bool configChanged = false;
    qint64 appliedBytes = 0;
    qint64 shadowBytes = 0;
    QString meterScope = QStringLiteral("tunnel");
};

// The terminal codes the owner may send: contract section 5, plus renew_rejected - the shared lease machine
// ends a renewing session with it after kUpstreamRenewRejectedLimit 422 answers in a row
// (UpstreamLeaseMachine.h, vectors renew_rejected_in_row). The iOS bridge's list (IosNativePolicy.h
// upstreamTerminalCodeKnown) lacks it today: there the code reads as "" and the app still leaves the node,
// without the notice and the journal code (reported to the iOS lane).
inline bool upstreamStatusTerminalCodeKnown(const QString &c)
{
    return c == QLatin1String("disabled") || c == QLatin1String("lease_gone") || c == QLatin1String("not_entitled")
           || c == QLatin1String("over_quota") || c == QLatin1String("no_seat_reacquire")
           || c == QLatin1String("standby_unconfirmed") || c == QLatin1String("renew_rejected");
}

// Keeps only contract values (the iOS bridge's rule): an unknown state reads as "none", a code outside the
// list (or on a non-terminal state) as "", negative counters as their floor, a scope other than "proxy" as
// "tunnel". An unknown terminal code still leaves the node: decideUpstreamStatus maps "" to "terminal".
inline UpstreamTunnelStatus normalizeUpstreamTunnelStatus(UpstreamTunnelStatus f)
{
    if (f.state != QLatin1String("none") && f.state != QLatin1String("pending") && f.state != QLatin1String("active")
        && f.state != QLatin1String("terminal"))
        f.state = QStringLiteral("none");
    if (f.state != QLatin1String("terminal") || !upstreamStatusTerminalCodeKnown(f.code))
        f.code.clear();
    if (f.seq < 0) f.seq = 0;
    if (f.renewedMsAgo < -1) f.renewedMsAgo = -1;
    if (f.expiresInMs < 0) f.expiresInMs = 0;
    if (f.revision < 0) f.revision = 0;
    if (f.appliedBytes < 0) f.appliedBytes = 0;
    if (f.shadowBytes < 0) f.shadowBytes = 0;
    if (f.meterScope != QLatin1String("proxy")) f.meterScope = QStringLiteral("tunnel");
    return f;
}

// A JSON number that is a whole value inside qint64 (2^53 keeps it exact); anything else = fallback.
inline qint64 upstreamWireInt(const QJsonValue &v, qint64 fallback)
{
    if (!v.isDouble())
        return fallback;
    const double d = v.toDouble();
    if (!std::isfinite(d) || d != std::floor(d) || std::fabs(d) > 9007199254740992.0)
        return fallback;
    return qint64(d);
}

// The "upstream" object itself (the value of the key), decoded with the iOS bridge's type rules: a string
// field of another type reads as "", a number field as its default, config_changed only as a JSON boolean.
inline UpstreamTunnelStatus upstreamTunnelStatusFromObject(const QJsonObject &o)
{
    UpstreamTunnelStatus f;
    f.present = true;
    const auto text = [&o](const char *key) {
        const QJsonValue v = o.value(QLatin1String(key));
        return v.isString() ? v.toString() : QString();
    };
    f.state = text("state");
    f.code = text("code");
    f.seq = upstreamWireInt(o.value(QLatin1String("seq")), 0);
    f.renewedMsAgo = upstreamWireInt(o.value(QLatin1String("renewed_ms_ago")), -1);
    f.expiresInMs = upstreamWireInt(o.value(QLatin1String("expires_in_ms")), 0);
    f.revision = upstreamWireInt(o.value(QLatin1String("revision")), 0);
    const QJsonValue cc = o.value(QLatin1String("config_changed"));
    f.configChanged = cc.isBool() && cc.toBool();
    f.appliedBytes = upstreamWireInt(o.value(QLatin1String("applied_bytes")), 0);
    f.shadowBytes = upstreamWireInt(o.value(QLatin1String("shadow_bytes")), 0);
    f.meterScope = text("meter_scope");
    return normalizeUpstreamTunnelStatus(f);
}

// The Android status event: a JSON object whose "upstream" member is the status object. Not JSON, no
// object, no "upstream" object -> present = false (nothing to apply).
inline UpstreamTunnelStatus decodeUpstreamStatusEvent(const QByteArray &json)
{
    QJsonParseError err{};
    const QJsonDocument d = QJsonDocument::fromJson(json, &err);
    if (err.error != QJsonParseError::NoError || !d.isObject())
        return UpstreamTunnelStatus();
    const QJsonValue up = d.object().value(QLatin1String("upstream"));
    if (!up.isObject())
        return UpstreamTunnelStatus();
    return upstreamTunnelStatusFromObject(up.toObject());
}

// The event is worth emitting when it says something the engine acts on: another state or code, a newer
// seq (a renewal landed), another revision, config_changed, the scope. Only ms counters moved -> quiet.
inline bool upstreamTunnelStatusChanged(const UpstreamTunnelStatus &prev, const UpstreamTunnelStatus &next)
{
    if (!next.present)
        return false;
    if (!prev.present)
        return true;
    return prev.state != next.state || prev.code != next.code || prev.seq != next.seq || prev.revision != next.revision
           || prev.configChanged != next.configChanged || prev.meterScope != next.meterScope;
}

// The map AvpnEngineQml::applyUpstreamTunnelStatus reads (QJsonObject::fromVariantMap) - the same keys and
// types as the iOS bridge's upstreamStatusMap.
inline QVariantMap upstreamTunnelStatusMap(const UpstreamTunnelStatus &f)
{
    return {
        {QStringLiteral("state"), f.state},
        {QStringLiteral("code"), f.code},
        {QStringLiteral("seq"), qlonglong(f.seq)},
        {QStringLiteral("renewed_ms_ago"), qlonglong(f.renewedMsAgo)},
        {QStringLiteral("expires_in_ms"), qlonglong(f.expiresInMs)},
        {QStringLiteral("revision"), qlonglong(f.revision)},
        {QStringLiteral("config_changed"), f.configChanged},
        {QStringLiteral("applied_bytes"), qlonglong(f.appliedBytes)},
        {QStringLiteral("shadow_bytes"), qlonglong(f.shadowBytes)},
        {QStringLiteral("meter_scope"), f.meterScope},
    };
}

// The late hand-over message (contract section 2), the iOS provider message byte for byte in content:
// {"action":"upstream_lease_set","upstream_lease":<lease>}. Empty lease -> empty message (nothing to send).
inline QByteArray upstreamLeaseSetMessage(const QJsonObject &lease)
{
    if (lease.isEmpty())
        return QByteArray();
    return QJsonDocument(QJsonObject{{QStringLiteral("action"), QStringLiteral("upstream_lease_set")},
                                     {QStringLiteral("upstream_lease"), lease}})
        .toJson(QJsonDocument::Compact);
}

} // namespace avpn
