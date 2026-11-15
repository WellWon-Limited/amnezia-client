// client/core/serviceEngine/TunnelWatchPlan.h
//
// AVPN (iOS tunnel-side data watch, build 140; design docs/specs/2026-11-14-ios-tunnel-side-data-watch-design.md
// §5.3 and §0a, contract C1): the policy plan the app hands to the packet tunnel extension in the App Group
// file TribeWatchPlan.json. Only the app writes it; the extension validates and clamps again.
//
// Pure: no I/O, no clocks, no Qt GUI. The facade collects the inputs (AvpnEngineQml::writeTunnelWatchPlan),
// IosController::writeTunnelWatchPlanFile writes the bytes. Tests: tests/tunnel_watch_check.cpp.
//
// Stage 1: `candidates` is always empty (stage 2 fills it). The file exists only on an install where
// features.ios_tunnel_watch has been true at least once (decideWatchPlanWrite): before that - the
// behaviour of build 139, no file at all; after it - the file is kept and carries the flag, so turning the
// flag off reaches the extension (kill switch).
#pragma once

#include "ConnectTunables.h"
#include "NetworkMemory.h"

#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

namespace avpn {

constexpr int kWatchPlanSchema = 1;
constexpr qsizetype kWatchPlanMaxBytes = 64 * 1024; // the extension refuses a bigger plan
constexpr char kWatchPlanFileName[] = "TribeWatchPlan.json";
constexpr char kWatchPlanEverOnSettingsKey[] = "avpn/tunnelWatchPlanEverOn";

// Node ids of the pool are strings ("16", Xray listeners "16:xray", "16:xray:2"); the plan carries the
// integer node id (the leading digits). Anything else - 0 (unknown).
inline int watchPlanNodeId(const QString &nodeId)
{
    int i = 0;
    long long v = 0;
    while (i < nodeId.size() && nodeId.at(i).isDigit()) {
        v = v * 10 + nodeId.at(i).digitValue();
        if (v > 2147483647LL)
            return 0;
        ++i;
    }
    if (i == 0 || (i < nodeId.size() && nodeId.at(i) != QLatin1Char(':')))
        return 0;
    return int(v);
}

// Engine transport-mode names (NodeRotation.h: auto / awg / xray) -> contract names.
inline QString watchPlanTransportMode(const QString &engineMode)
{
    if (engineMode == QLatin1String("awg"))
        return QStringLiteral("amnezia");
    if (engineMode == QLatin1String("xray"))
        return QStringLiteral("xray");
    return QStringLiteral("auto");
}

inline QString watchPlanProto(const QString &engineProto)
{
    return engineProto.startsWith(QLatin1String("xray")) ? QStringLiteral("xray") : QStringLiteral("awg");
}

// One live entry of the network memory (NetworkMemory.h, same JSON blob): the node and when it was saved.
struct WatchPlanMemoryEntry {
    QString key;
    int nodeId = 0;
    qint64 savedMs = 0;
};

// The entry for `key` if it is live by the same rule as networkMemoryLookup (newer than maxAgeSec, has a
// timestamp, the node id is an integer); otherwise nodeId == 0.
inline WatchPlanMemoryEntry watchPlanMemoryEntry(const QByteArray &json, const QString &key, qint64 nowSec,
                                                 qint64 maxAgeSec = kNetworkMemoryMaxAgeSec)
{
    WatchPlanMemoryEntry e;
    e.key = key;
    if (key.isEmpty())
        return e;
    for (const QJsonValue &v : netmemory_detail::load(json)) {
        const QJsonObject o = v.toObject();
        if (o.value(QStringLiteral("k")).toString() != key)
            continue;
        const QJsonValue t = o.value(QStringLiteral("t"));
        if (!t.isDouble() || nowSec - qint64(t.toDouble()) > maxAgeSec)
            return e;
        e.nodeId = watchPlanNodeId(o.value(QStringLiteral("n")).toString());
        e.savedMs = e.nodeId ? qint64(t.toDouble()) * 1000 : 0;
        return e;
    }
    return e;
}

struct WatchPlanInputs {
    qint64 nowMs = 0;              // wall clock of the write
    qint64 configFetchedMs = 0;    // when the signed /v1/config in effect was received; 0 = unknown
    bool watch = false;            // features.ios_tunnel_watch
    bool watchSwitch = false;      // features.ios_tunnel_watch_switch (carried only in stage 1)
    bool bgArm = false;            // features.ios_on_demand_bg_arm
    qint64 poolRevision = 0;
    QString engineTransportMode;   // NodeRotation.h names
    QString pinCountry;
    QString pinNodeId;             // engine id ("16", "16:xray"); empty = no pin
    QString sessionNodeId;
    QString sessionProto;          // engine proto
    QString sessionCountry;
    QString cellularKey;           // networkMemoryKey("cellular", carrier): "cellular:<MCC-MNC>" or "cellular"
    QList<WatchPlanMemoryEntry> memory; // entries for "wifi" and cellularKey (dead ones are dropped here)
    QList<QPair<QString, long long>> numbers; // clamped plan numbers (key, value) in table order
    bool sanityUrlsKnown = false;  // lists.ios_tw_sanity_urls present in the config
    QStringList sanityUrls;
};

// The clamped plan numbers from a raw lookup (TuningStore in the app, a map in tests): every toPlan row
// of kIosTunnelWatchNumbers, in table order.
template <class Lookup>
inline QList<QPair<QString, long long>> watchPlanNumbers(Lookup rawOrDefault)
{
    QList<QPair<QString, long long>> out;
    for (const TunnelWatchNumberSpec &s : kIosTunnelWatchNumbers) {
        if (!s.toPlan)
            continue;
        out.append({QLatin1String(s.key), clampTunnelWatchNumber(s, rawOrDefault(s))});
    }
    return out;
}

inline long long watchPlanNumber(const QList<QPair<QString, long long>> &numbers, const char *key)
{
    for (const auto &p : numbers)
        if (p.first == QLatin1String(key))
            return p.second;
    const TunnelWatchNumberSpec *s = tunnelWatchNumberSpec(key);
    return s ? std::llround(s->def) : 0;
}

inline QJsonObject buildWatchPlan(const WatchPlanInputs &in)
{
    QJsonObject numbers;
    for (const auto &p : in.numbers)
        numbers.insert(p.first, double(p.second));
    const long long ttlH = watchPlanNumber(in.numbers, "ios_tw_plan_ttl_h");
    const long long policyH = watchPlanNumber(in.numbers, "ios_tw_policy_max_age_h");

    QJsonObject memory;
    for (const WatchPlanMemoryEntry &e : in.memory) {
        if (e.key.isEmpty() || e.nodeId <= 0)
            continue; // only live entries (watchPlanMemoryEntry already applied the 7-day rule)
        if (e.key != QLatin1String("wifi") && e.key != in.cellularKey)
            continue; // only the two keys of net_keys
        memory.insert(e.key, QJsonObject{{QStringLiteral("node_id"), e.nodeId},
                                         {QStringLiteral("saved_ms"), double(e.savedMs)}});
    }

    QJsonObject plan{
        {QStringLiteral("schema"), kWatchPlanSchema},
        {QStringLiteral("written_ms"), double(in.nowMs)},
        {QStringLiteral("config_fetched_ms"), double(in.configFetchedMs > 0 ? in.configFetchedMs : 0)},
        {QStringLiteral("expires_ms"), double(in.nowMs + ttlH * 3600LL * 1000LL)},
        {QStringLiteral("policy_max_age_ms"), double(policyH * 3600LL * 1000LL)},
        {QStringLiteral("pool_revision"), double(in.poolRevision)},
        {QStringLiteral("transport_mode"), watchPlanTransportMode(in.engineTransportMode)},
        {QStringLiteral("pin"), QJsonObject{{QStringLiteral("country"), in.pinNodeId.isEmpty() ? QString() : in.pinCountry},
                                            {QStringLiteral("node_id"), watchPlanNodeId(in.pinNodeId)}}},
        {QStringLiteral("session"), QJsonObject{{QStringLiteral("node_id"), watchPlanNodeId(in.sessionNodeId)},
                                                {QStringLiteral("proto"), watchPlanProto(in.sessionProto)},
                                                {QStringLiteral("country"), in.sessionCountry}}},
        {QStringLiteral("net_keys"), QJsonObject{{QStringLiteral("wifi"), QStringLiteral("wifi")},
                                                 {QStringLiteral("cellular"), in.cellularKey.isEmpty()
                                                      ? QStringLiteral("cellular") : in.cellularKey}}},
        {QStringLiteral("net_memory"), memory},
        {QStringLiteral("features"), QJsonObject{{QStringLiteral("ios_tunnel_watch"), in.watch},
                                                 {QStringLiteral("ios_tunnel_watch_switch"), in.watchSwitch},
                                                 {QStringLiteral("ios_on_demand_bg_arm"), in.bgArm}}},
        {QStringLiteral("numbers"), numbers},
        {QStringLiteral("candidates"), QJsonArray{}}, // stage 1: always empty
    };
    if (in.sanityUrlsKnown && !in.sanityUrls.isEmpty())
        plan.insert(QStringLiteral("sanity_urls"), QJsonArray::fromStringList(in.sanityUrls));
    return plan;
}

// Compact bytes; empty when the plan would break the extension's 64 KB limit (the writer then keeps the
// previous file and journals it - stage 1 is ~2 KB, so this only guards a runaway list from the server).
inline QByteArray serializeWatchPlan(const QJsonObject &plan)
{
    const QByteArray body = QJsonDocument(plan).toJson(QJsonDocument::Compact);
    return body.size() > kWatchPlanMaxBytes ? QByteArray() : body;
}

// Whether the plan file is written at this trigger. Never on this install (the flag has never been true)
// and off now - no file, as in 139. Otherwise the file is (re)written; everOnAfter is what to persist.
struct WatchPlanWrite {
    bool write = false;
    bool everOnAfter = false;
};
inline WatchPlanWrite decideWatchPlanWrite(bool flagNow, bool everOnBefore)
{
    const bool everOn = everOnBefore || flagNow;
    return {everOn, everOn};
}

// The journal line of a written plan (design appendix, the app journal formats).
inline QString watchPlanJournalLine(const QJsonObject &plan, const QString &why)
{
    const QJsonObject pin = plan.value(QStringLiteral("pin")).toObject();
    const int pinNode = pin.value(QStringLiteral("node_id")).toInt();
    const QString pinText = pinNode > 0 ? QString::number(pinNode)
                                        : (pin.value(QStringLiteral("country")).toString().isEmpty()
                                               ? QStringLiteral("-") : pin.value(QStringLiteral("country")).toString());
    const QJsonObject f = plan.value(QStringLiteral("features")).toObject();
    return QStringLiteral("watch_plan_written candidates=%1 switch=%2 pool_rev=%3 mode=%4 pin=%5 watch=%6 why=%7")
        .arg(plan.value(QStringLiteral("candidates")).toArray().size())
        .arg(int(f.value(QStringLiteral("ios_tunnel_watch_switch")).toBool()))
        .arg(qint64(plan.value(QStringLiteral("pool_revision")).toDouble()))
        .arg(plan.value(QStringLiteral("transport_mode")).toString(), pinText)
        .arg(int(f.value(QStringLiteral("ios_tunnel_watch")).toBool()))
        .arg(why);
}

} // namespace avpn
