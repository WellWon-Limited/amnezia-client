// client/core/serviceEngine/TunnelWatchPlan.h
//
// AVPN (iOS tunnel-side data watch, build 141; design docs/specs/2026-11-14-ios-tunnel-side-data-watch-design.md
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
//
// Plans are ordered by `seq` - the app's own counter, one step per written plan - and `written_ms`. The
// pool revision is carried for the journal only: the server's revision is not monotonic (deleting a node
// lowers it), so it cannot order anything.
#pragma once

#include "ConnectTunables.h"

#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

namespace avpn {

constexpr int kWatchPlanSchema = 2; // 2: `seq`, `sanity_targets`
constexpr qsizetype kWatchPlanMaxBytes = 64 * 1024; // the extension refuses a bigger plan
constexpr char kWatchPlanFileName[] = "TribeWatchPlan.json";
constexpr char kWatchPlanEverOnSettingsKey[] = "avpn/tunnelWatchPlanEverOn";
constexpr char kWatchPlanSeqSettingsKey[] = "avpn/tunnelWatchPlanSeq";
constexpr int kWatchPlanMaxSanityTargets = 4; // the extension takes no more

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

// The cellular key the extension files its evidence under: "cellular:<MCC-MNC>", plain "cellular" when the code is
// unknown (the format the extension reads; the app's own per-network memory is the path engine's ledger now).
inline QString watchPlanCellularKey(const QString &carrierCode)
{
    const QString code = carrierCode.trimmed();
    return code.isEmpty() ? QStringLiteral("cellular") : QStringLiteral("cellular:") + code;
}

// Stage 2: one node the extension may switch to in place. `peer` is the node's part of the tunnel
// configuration by the keys of the provider configuration (AwgConfigBuilder::buildInner), strings only.
struct WatchPlanCandidate {
    QString nodeId;
    QString country;
    QJsonObject peer;
};
constexpr int kWatchPlanMaxCandidates = 5; // spare nodes; the current one is in the profile





struct WatchPlanInputs {
    qint64 nowMs = 0;              // wall clock of the write
    qint64 seq = 0;                // the app's own counter of written plans (set by writeWatchPlan)
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
    QString cellularKey;           // watchPlanCellularKey(carrier): "cellular:<MCC-MNC>" or "cellular"
    QList<QPair<QString, long long>> numbers; // clamped plan numbers (key, value) in table order
    QStringList sanityTargets;     // watchPlanSanityTargets(); empty = the extension's built-in ones
    // Stage 2: where the extension may switch to, in the ladder's order. Written only with BOTH flags on
    // (a node's preshared key lies in the file; with the switch off nothing of a node is written).
    QList<WatchPlanCandidate> candidates;
};

// Targets of the extension's request that bypasses the tunnel ("is the physical network a real path to
// the Internet?"). The operator's own list (lists.ios_tw_sanity_urls) wins. Without it the targets are the
// hosts the white-list detector already probes for the same purpose: the marketplace tier
// (lists.whitelist_probe_domains - they answer inside Russia also on a mobile network in white-list mode,
// and do not answer on a zero balance, which is what "no usable network" means) and then one independent
// anchor (lists.whitelist_anchor_domains) for a phone that is abroad. A bare host name is a TLS handshake
// (no HTTP request is sent). Nothing to offer - empty: the extension uses its built-in three.
inline QStringList watchPlanSanityTargets(const QStringList &own, const QStringList &whitelistProbe,
                                          const QStringList &whitelistAnchors)
{
    QStringList out;
    auto add = [&out](const QString &raw) {
        const QString t = raw.trimmed();
        if (!t.isEmpty() && !out.contains(t) && out.size() < kWatchPlanMaxSanityTargets)
            out.append(t);
    };
    if (!own.isEmpty()) {
        for (const QString &u : own)
            add(u);
        return out;
    }
    for (const QString &d : whitelistProbe) {
        if (out.size() >= kWatchPlanMaxSanityTargets - 1)
            break; // one slot is kept for the anchor
        add(d);
    }
    if (!whitelistAnchors.isEmpty())
        add(whitelistAnchors.first());
    return out;
}

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
    // Stage 2: the permission to switch is a lease, renewed by every plan the app writes. A phone
    // whose app is not running stops switching when it lapses - that is how fast a server-side "off"
    // reaches it; the verdict itself goes on working.
    const long long leaseMin = watchPlanNumber(in.numbers, "ios_tw_switch_lease_min");
    const bool switching = in.watch && in.watchSwitch;

    // net_memory: the extension still reads the field; the app keeps no per-network memory of its own any more
    // (the path engine's ledger), so it is always empty.
    const QJsonObject memory;

    QJsonArray candidates;
    if (in.watch && in.watchSwitch) {
        for (const WatchPlanCandidate &c : in.candidates) {
            if (candidates.size() >= kWatchPlanMaxCandidates)
                break;
            const int node = watchPlanNodeId(c.nodeId);
            if (node <= 0 || c.nodeId.contains(QLatin1Char(':')) || c.peer.isEmpty())
                continue; // AmneziaWG nodes only ("16:xray" is an Xray listener)
            candidates.append(QJsonObject{{QStringLiteral("node_id"), node},
                                          {QStringLiteral("country"), c.country},
                                          {QStringLiteral("peer"), c.peer}});
        }
    }

    QJsonObject plan{
        {QStringLiteral("schema"), kWatchPlanSchema},
        {QStringLiteral("seq"), double(in.seq)},
        {QStringLiteral("written_ms"), double(in.nowMs)},
        {QStringLiteral("config_fetched_ms"), double(in.configFetchedMs > 0 ? in.configFetchedMs : 0)},
        {QStringLiteral("expires_ms"), double(in.nowMs + ttlH * 3600LL * 1000LL)},
        {QStringLiteral("switch_lease_until_ms"), double(switching ? in.nowMs + leaseMin * 60LL * 1000LL : 0)},
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
        {QStringLiteral("candidates"), candidates}, // empty unless the switch key is on
    };
    if (!in.sanityTargets.isEmpty())
        plan.insert(QStringLiteral("sanity_targets"), QJsonArray::fromStringList(in.sanityTargets));
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

// One write of the plan, start to end, with its effects handed in: the facade cannot write a plan on an
// install whose flag was never on, cannot skip the sequence step and cannot forget the journal line -
// all of it is here and tested. `writeFile(bytes) -> bool` puts the bytes into the App Group container.
struct WatchPlanWriteOutcome {
    bool attempted = false; // false: the flag has never been on here - no file, as build 139
    bool written = false;
    bool everOnAfter = false; // to persist (kWatchPlanEverOnSettingsKey)
    qint64 seqAfter = 0;      // to persist (kWatchPlanSeqSettingsKey)
    QString journal;          // empty when nothing was attempted
};
inline QString watchPlanJournalLine(const QJsonObject &plan, const QString &why);
template <class WriteFile>
inline WatchPlanWriteOutcome writeWatchPlan(WatchPlanInputs in, bool everOnBefore, qint64 seqBefore, const QString &why,
                                            WriteFile writeFile)
{
    WatchPlanWriteOutcome out;
    const WatchPlanWrite w = decideWatchPlanWrite(in.watch, everOnBefore);
    out.everOnAfter = w.everOnAfter;
    out.seqAfter = seqBefore;
    if (!w.write)
        return out;
    out.attempted = true;
    // A number is spent whether or not the write succeeds: two plans never share one.
    out.seqAfter = seqBefore < 0 ? 1 : seqBefore + 1;
    in.seq = out.seqAfter;
    const QJsonObject plan = buildWatchPlan(in);
    const QByteArray body = serializeWatchPlan(plan);
    if (body.isEmpty()) {
        out.journal = QStringLiteral("watch_plan_not_written why=too_big at=%1").arg(why);
        return out;
    }
    out.written = writeFile(body);
    out.journal = out.written ? watchPlanJournalLine(plan, why)
                              : QStringLiteral("watch_plan_not_written why=io at=%1").arg(why);
    return out;
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
    return QStringLiteral("watch_plan_written seq=%8 candidates=%1 switch=%2 pool_rev=%3 mode=%4 pin=%5 watch=%6 why=%7")
        .arg(plan.value(QStringLiteral("candidates")).toArray().size())
        .arg(int(f.value(QStringLiteral("ios_tunnel_watch_switch")).toBool()))
        .arg(qint64(plan.value(QStringLiteral("pool_revision")).toDouble()))
        .arg(plan.value(QStringLiteral("transport_mode")).toString(), pinText)
        .arg(int(f.value(QStringLiteral("ios_tunnel_watch")).toBool()))
        .arg(why)
        .arg(qint64(plan.value(QStringLiteral("seq")).toDouble()));
}

} // namespace avpn
