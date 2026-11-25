// AVPN Scanner tests: the event codec (JSON event -> ScanMachine call), a fake world on a fake clock (probe
// host with pools, reach stage, byte cap and deadline; probe leases; the report check; the
// engine's connect ladder) and the artboard scenarios. Shared by scan_core_check.cpp (assertions) and
// scan_vectors_check.cpp (records / replays tests/vectors/scan_machine_vectors.json).
//
// Every input reaches the machine as a JSON event, so the recorded vectors are exactly what a later lane
// replays: { "event": name, "now_ms": int, "args": {...} }. Events and args:
//   opened {network, current, cached, with_check}   closed {}   stop {}   retry {}   got_it {}
//   filter {cc}   network_changed {network, cached, app_in_front}   app_foreground {}
//   vpn_state {current}   manifest_ready {manifest (server body), own_nodes, fresh_failures, last_known_good,
//   access, strict_unverifiable, upstream_names}   manifest_unavailable {reason}
//   host_failed {scan_id, error, start_accepted (default true), detail}   candidate_refused {probe_id, reason}
//   report_check_refused {report_id, reason}   host_progress {reply (the host's scan_progress JSON, decoded by
//   ScanHostContract.h)}   lease_granted {node_id, access}   lease_refused {node_id, code}
//   row_tapped {node_id}   connect_failed {node_id}   attempt_ended {}   support_check_tapped {}   report_link_tapped {}
//   tunnel_no_data {ids: [..]} (the engine's path ledger: rows whose real tunnel carried no data here)
//   report_check_started {}   report_check_progress {step, total}   report_check_done {delivery, report_id}
//   connect_and_scan_tapped {}   live_probe_result {node_id, facts (a data ITEM of ScanHostContract.h)}
//   host_cancel_ack {scan_id, bytes_spent}   host_freeze_ack {scan_id, spent, reserved}
//   app_request_done {request_id, bytes}   report_queue_state {full}   tick {}
//   opened also takes connect_on_open (default true); manifest_ready also api_bytes,
//   awg_address_known (default true), probe_base_ips
//   network = {kind, key, fingerprint, sources: [{source, epoch (16 hex), counter}]}; current = {node_id, live,
//   connecting, data_flowing, failed, live_rtt_ms, origin, label, cc, transport, version, tier};
//   cached = ScanTypes.h scanCachedResultToJson.
#pragma once

#include "../ScanMachine.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QMultiMap>
#include <QSet>
#include <QString>
#include <QStringList>

#include <functional>

namespace scantest {

using namespace avpn;

inline constexpr qint64 kT0 = 1789000000000LL; // fake wall clock origin

// --- JSON of inputs --------------------------------------------------------------------------------------------

inline constexpr quint64 kAppEpoch = 0xa1a1a1a1a1a1a1a1ULL; // the app monitor's epoch in this process
inline constexpr quint64 kNeEpoch = 0x0e0e0e0e0e0e0e0eULL;  // the probe host's monitor epoch

// A test network: the app's path monitor at `counter`, the weak fingerprint of kind + key (+ a gateway hash).
inline ScanNetwork scanNet(ScanNetKind kind, const QString &key, qint64 counter = 1, const QString &gateway = QString())
{
    ScanNetwork n;
    n.kind = kind;
    n.key = key;
    n.sources = {ScanNetSource{QStringLiteral("app"), kAppEpoch, counter}};
    n.fingerprint = scanNetFingerprint(QLatin1String(scanNetKindName(kind)), key, gateway);
    return n;
}

inline QJsonObject netJson(const ScanNetwork &n)
{
    QJsonArray src;
    for (const ScanNetSource &x : n.sources)
        src << scanNetSourceToJson(x);
    return QJsonObject{{QStringLiteral("kind"), QLatin1String(scanNetKindName(n.kind))}, {QStringLiteral("key"), n.key},
                       {QStringLiteral("fingerprint"), n.fingerprint}, {QStringLiteral("sources"), src}};
}

inline ScanNetwork netFrom(const QJsonObject &o)
{
    ScanNetwork n;
    n.kind = scanNetKindFrom(o.value(QLatin1String("kind")).toString());
    n.key = o.value(QLatin1String("key")).toString(QStringLiteral("unknown"));
    n.fingerprint = o.value(QLatin1String("fingerprint")).toString();
    for (const QJsonValue &v : o.value(QLatin1String("sources")).toArray()) {
        ScanNetSource x;
        if (scanNetSourceFromJson(v, x))
            n.sources << x;
    }
    return n;
}

inline ScanProbeFacts factsFrom(const QJsonObject &o)
{
    ScanProbeFacts f;
    scanDecodeItem(o, f);
    return f;
}

inline QJsonObject currentJson(const ScanCurrent &c)
{
    QJsonObject o;
    o.insert(QStringLiteral("node_id"), c.nodeId);
    o.insert(QStringLiteral("live"), c.live);
    o.insert(QStringLiteral("connecting"), c.connecting);
    o.insert(QStringLiteral("data_flowing"), c.dataFlowing);
    o.insert(QStringLiteral("failed"), c.failed);
    if (!c.attemptNodeId.isEmpty())
        o.insert(QStringLiteral("attempt_node_id"), c.attemptNodeId);
    o.insert(QStringLiteral("live_rtt_ms"), c.liveRttMs);
    o.insert(QStringLiteral("origin"), c.origin == ScanOrigin::Upstream ? QStringLiteral("upstream") : QStringLiteral("own"));
    o.insert(QStringLiteral("label"), c.label);
    o.insert(QStringLiteral("cc"), c.countryCode);
    o.insert(QStringLiteral("transport"), QLatin1String(scanTransportName(c.transport)));
    o.insert(QStringLiteral("version"), c.transportVersion);
    o.insert(QStringLiteral("tier"), c.tier);
    return o;
}

inline ScanCurrent currentFrom(const QJsonObject &o)
{
    ScanCurrent c;
    c.nodeId = o.value(QLatin1String("node_id")).toString();
    c.live = o.value(QLatin1String("live")).toBool();
    c.connecting = o.value(QLatin1String("connecting")).toBool();
    c.dataFlowing = o.value(QLatin1String("data_flowing")).toBool();
    c.failed = o.value(QLatin1String("failed")).toBool();
    c.attemptNodeId = o.value(QLatin1String("attempt_node_id")).toString();
    c.liveRttMs = o.value(QLatin1String("live_rtt_ms")).toInt(-1);
    c.origin = o.value(QLatin1String("origin")).toString() == QLatin1String("upstream") ? ScanOrigin::Upstream : ScanOrigin::Own;
    c.label = o.value(QLatin1String("label")).toString();
    c.countryCode = o.value(QLatin1String("cc")).toString();
    c.transport = scanTransportFrom(o.value(QLatin1String("transport")).toString());
    c.transportVersion = o.value(QLatin1String("version")).toString();
    c.tier = o.value(QLatin1String("tier")).toInt(0);
    return c;
}

inline QJsonObject capsJson(const ScanHostCaps &c)
{
    return QJsonObject{{QStringLiteral("max_full_concurrent"), c.maxFullConcurrent},
                       {QStringLiteral("can_verify_composite"), c.canVerifyComposite},
                       {QStringLiteral("max_leg_concurrent"), c.maxLegConcurrent},
                       {QStringLiteral("dns_plan"), c.dnsPlan},
                       {QStringLiteral("max_awg_concurrent"), c.maxAwgConcurrent},
                       {QStringLiteral("reach_stage"), c.reachStage},
                       {QStringLiteral("needs_vpn"), c.needsVpn}};
}

inline ScanHostCaps capsFrom(const QJsonObject &o)
{
    ScanHostCaps c;
    c.maxFullConcurrent = o.value(QLatin1String("max_full_concurrent")).toInt(1);
    c.canVerifyComposite = o.value(QLatin1String("can_verify_composite")).toBool();
    c.maxLegConcurrent = o.value(QLatin1String("max_leg_concurrent")).toInt(0);
    c.dnsPlan = o.value(QLatin1String("dns_plan")).toBool();
    c.maxAwgConcurrent = o.value(QLatin1String("max_awg_concurrent")).toInt(0);
    c.reachStage = o.value(QLatin1String("reach_stage")).toBool(true);
    c.needsVpn = o.value(QLatin1String("needs_vpn")).toBool();
    return c;
}

inline ScanOwnNode ownFrom(const QJsonObject &o)
{
    ScanOwnNode n;
    n.nodeId = o.value(QLatin1String("node_id")).toString();
    n.label = o.value(QLatin1String("label")).toString();
    n.countryCode = o.value(QLatin1String("cc")).toString();
    n.transport = scanTransportFrom(o.value(QLatin1String("transport")).toString());
    n.transportVersion = o.value(QLatin1String("version")).toString();
    n.entryIp = o.value(QLatin1String("entry_ip")).toString();
    n.entryPort = o.value(QLatin1String("entry_port")).toInt();
    n.manualOnly = o.value(QLatin1String("manual_only")).toBool();
    n.ru = o.value(QLatin1String("ru")).toBool();
    n.configAvailable = o.value(QLatin1String("config")).toBool(true);
    return n;
}

inline ScanManifestInput manifestInputFrom(const QJsonObject &a)
{
    ScanManifestInput in;
    scanManifestViewFromJson(a.value(QLatin1String("manifest")).toObject(), in.manifest);
    for (const QJsonValue &v : a.value(QLatin1String("own_nodes")).toArray())
        in.ownNodes << ownFrom(v.toObject());
    for (const QJsonValue &v : a.value(QLatin1String("fresh_failures")).toArray())
        in.freshFailures.insert(v.toString());
    in.lastKnownGood = a.value(QLatin1String("last_known_good")).toString();
    const QJsonObject acc = a.value(QLatin1String("access")).toObject();
    in.access.asn = qint64(acc.value(QLatin1String("asn")).toDouble(0));
    in.access.netToken = acc.value(QLatin1String("net_token")).toString();
    const QJsonObject names = a.value(QLatin1String("upstream_names")).toObject();
    for (auto it = names.constBegin(); it != names.constEnd(); ++it)
        in.upstreamNames.insert(it.key(), it.value().toString());
    in.restrictCountry = a.value(QLatin1String("restrict_country")).toString();
    in.awgMiniEnabled = a.value(QLatin1String("awg_mini_enabled")).toBool();
    in.awgProbeIpKnown = a.value(QLatin1String("awg_probe_ip_known")).toBool();
    in.strictUnverifiable = a.value(QLatin1String("strict_unverifiable")).toBool();
    in.apiBytes = qint64(a.value(QLatin1String("api_bytes")).toDouble(-1));
    in.awgAddressKnown = a.value(QLatin1String("awg_address_known")).toBool(true);
    for (const QJsonValue &v : a.value(QLatin1String("probe_base_ips")).toArray())
        in.probeBaseIps << v.toString();
    return in;
}

inline ScanAccess accessFrom(const QJsonObject &o)
{
    ScanAccess a;
    a.asn = qint64(o.value(QLatin1String("asn")).toDouble(0));
    a.netToken = o.value(QLatin1String("net_token")).toString();
    return a;
}

// A fixed AmneziaWG mini-session input (fake keys 01..20 / 21..40): the shape the engine lane fills.
inline ScanAwgMiniInput testAwgInput()
{
    ScanAwgMiniInput in;
    // Obviously fake keys (any 32 bytes are a WireGuard key): repeated bytes, nothing a secret
    // scanner reads as one in the public fork.
    const QByteArray priv(32, char(0x11)), peer(32, char(0x22));
    in.privateKey = QString::fromLatin1(priv.toBase64()); // base64 as the subscription carries it
    in.peerPublicKey = QString::fromLatin1(peer.toHex());  // hex works too
    in.address = QStringLiteral("100.64.0.250");
    in.mtu = 1280;
    in.endpoint = QStringLiteral("203.0.113.5:51820");
    in.obfuscation = {{QStringLiteral("jc"), QStringLiteral("4")}, {QStringLiteral("jmin"), QStringLiteral("40")},
                      {QStringLiteral("jmax"), QStringLiteral("70")}, {QStringLiteral("s1"), QStringLiteral("50")},
                      {QStringLiteral("s2"), QStringLiteral("100")}, {QStringLiteral("h1"), QStringLiteral("1234")},
                      {QStringLiteral("h2"), QStringLiteral("5678")}, {QStringLiteral("h3"), QStringLiteral("91011")},
                      {QStringLiteral("h4"), QStringLiteral("121314")}, {QStringLiteral("I1"), QStringLiteral("<b 0xf6ab3267fa>")}};
    in.probeHost = QStringLiteral("api.tribe.example");
    in.probeIp = QStringLiteral("198.51.100.7");
    in.probePort = 443;
    in.echoTarget = QStringLiteral("10.8.1.1");
    in.boundIf = 4;
    return in;
}

// --- the dispatcher ------------------------------------------------------------------------------------------

inline ScanStep applyScanEvent(ScanMachine &m, const QJsonObject &ev, bool *known = nullptr)
{
    const QString e = ev.value(QLatin1String("event")).toString();
    const qint64 now = qint64(ev.value(QLatin1String("now_ms")).toDouble(0));
    const QJsonObject a = ev.value(QLatin1String("args")).toObject();
    if (known)
        *known = true;
    if (e == QLatin1String("opened") || e == QLatin1String("shown")) {
        ScanOpen o;
        o.network = netFrom(a.value(QLatin1String("network")).toObject());
        o.current = currentFrom(a.value(QLatin1String("current")).toObject());
        o.cached = scanCachedResultFromJson(a.value(QLatin1String("cached")).toObject());
        o.withCheck = a.value(QLatin1String("with_check")).toBool();
        o.connectOnOpen = a.value(QLatin1String("connect_on_open")).toBool(true);
        // shown: the page opens without a scan (the Scan button starts one); opened: the page opens and scans
        return e == QLatin1String("shown") ? m.shown(o, now) : m.opened(o, now);
    }
    if (e == QLatin1String("more")) return m.moreTapped(a.value(QLatin1String("cc")).toString(), now);
    if (e == QLatin1String("connect_and_scan_tapped")) return m.connectAndScanTapped(now);
    if (e == QLatin1String("live_probe_result"))
        return m.liveProbeResult(a.value(QLatin1String("node_id")).toString(), factsFrom(a.value(QLatin1String("facts")).toObject()), now);
    if (e == QLatin1String("host_cancel_ack"))
        return m.hostCancelAck(a.value(QLatin1String("scan_id")).toString(), qint64(a.value(QLatin1String("bytes_spent")).toDouble()), now);
    if (e == QLatin1String("host_freeze_ack"))
        return m.hostFreezeAck(a.value(QLatin1String("scan_id")).toString(), qint64(a.value(QLatin1String("spent")).toDouble()),
                               qint64(a.value(QLatin1String("reserved")).toDouble()), now);
    if (e == QLatin1String("app_request_done"))
        return m.appRequestDone(a.value(QLatin1String("request_id")).toString(), qint64(a.value(QLatin1String("bytes")).toDouble(-1)), now);
    if (e == QLatin1String("report_queue_state")) return m.reportQueueState(a.value(QLatin1String("full")).toBool(), now);
    if (e == QLatin1String("closed")) return m.closed(now);
    if (e == QLatin1String("stop")) return m.stopTapped(now);
    if (e == QLatin1String("retry")) return m.retryTapped(now);
    if (e == QLatin1String("tunnel_no_data")) {
        QStringList ids;
        for (const QJsonValue &x : a.value(QLatin1String("ids")).toArray())
            ids << x.toString();
        return m.tunnelNoDataHere(ids, now);
    }
    if (e == QLatin1String("got_it")) return m.gotItTapped(now);
    if (e == QLatin1String("filter")) return m.filterChosen(a.value(QLatin1String("cc")).toString(), now);
    if (e == QLatin1String("network_changed"))
        return m.networkChanged(netFrom(a.value(QLatin1String("network")).toObject()),
                                scanCachedResultFromJson(a.value(QLatin1String("cached")).toObject()), now);
    if (e == QLatin1String("vpn_state")) return m.vpnState(currentFrom(a.value(QLatin1String("current")).toObject()), now);
    if (e == QLatin1String("manifest_ready")) return m.manifestReady(manifestInputFrom(a), now);
    if (e == QLatin1String("manifest_unavailable")) return m.manifestUnavailable(a.value(QLatin1String("reason")).toString(), now);
    if (e == QLatin1String("host_failed"))
        return m.hostFailed(a.value(QLatin1String("scan_id")).toString(), scanHostErrorFrom(a.value(QLatin1String("error")).toString()), now,
                            a.value(QLatin1String("start_accepted")).toBool(true), a.value(QLatin1String("detail")).toString());
    if (e == QLatin1String("candidate_refused"))
        return m.candidateRefused(a.value(QLatin1String("probe_id")).toString(), a.value(QLatin1String("reason")).toString(), now);
    if (e == QLatin1String("report_check_refused"))
        return m.reportCheckRefused(a.value(QLatin1String("report_id")).toString(), a.value(QLatin1String("reason")).toString(), now);
    if (e == QLatin1String("host_progress")) {
        const ScanHostReply r = scanDecodeReply(QJsonDocument(a.value(QLatin1String("reply")).toObject()).toJson(QJsonDocument::Compact));
        if (r.kind != ScanHostReplyKind::Progress)
            return m.tick(now);
        return m.hostProgress(r.progress, now);
    }
    if (e == QLatin1String("lease_granted"))
        return m.probeLeaseGranted(a.value(QLatin1String("node_id")).toString(), accessFrom(a.value(QLatin1String("access")).toObject()), now);
    if (e == QLatin1String("lease_refused"))
        return m.probeLeaseRefused(a.value(QLatin1String("node_id")).toString(), a.value(QLatin1String("code")).toString(), now);
    if (e == QLatin1String("row_tapped")) return m.rowTapped(a.value(QLatin1String("node_id")).toString(), now);
    if (e == QLatin1String("connect_failed")) return m.connectFailed(a.value(QLatin1String("node_id")).toString(), now);
    if (e == QLatin1String("attempt_ended")) return m.attemptEnded(now);
    if (e == QLatin1String("support_check_tapped")) return m.supportCheckTapped(now);
    if (e == QLatin1String("report_link_tapped")) return m.reportLinkTapped(now);
    if (e == QLatin1String("report_check_started")) return m.reportCheckStarted(now);
    if (e == QLatin1String("report_check_progress"))
        return m.reportCheckProgress(a.value(QLatin1String("step")).toInt(), a.value(QLatin1String("total")).toInt(4), now);
    if (e == QLatin1String("report_check_done"))
        return m.reportCheckDone(a.value(QLatin1String("delivery")).toString() == QLatin1String("queued") ? ScanReportDelivery::Queued
                                                                                                       : ScanReportDelivery::Sent,
                                 now, a.value(QLatin1String("report_id")).toString());
    if (known)
        *known = false;
    return m.tick(now);
}

inline QJsonObject ev(const char *name, qint64 now, const QJsonObject &args = {})
{
    return QJsonObject{{QStringLiteral("event"), QLatin1String(name)}, {QStringLiteral("now_ms"), double(now)}, {QStringLiteral("args"), args}};
}

inline QJsonArray actionsJson(const ScanStep &s)
{
    QJsonArray a;
    for (const ScanAction &x : s.actions)
        a << scanActionToJson(x);
    return a;
}

// --- the world -----------------------------------------------------------------------------------------------

struct NodeSpec {
    QString id;          // engine id ("4:xray", "2", "up:<pid>")
    QString label;
    QString cc;
    ScanTransport transport = ScanTransport::Xray;
    QString version;
    QString entryIp;
    int entryPort = 0;
    int tier = 0;
    int rank = 0;
    bool provider = false;
    bool composite = false;
    bool trimmed = false;
    bool dnsThroughLeg = true; // provider single: DNS plan through the leg
    bool crowd = false;
    bool manualOnly = false;
    bool awgProbe = true;      // own AWG: the device's peer is on the node (manifest awg_probe)
};

struct Outcome {
    bool reachOk = true;
    int reachMs = 90;
    int durMs = 600;
    bool works = true;
    int ttfb1 = 320;
    int rtt = 60;
    int t64 = 160;
    bool sameNet = false;      // provider exit equal to the access net -> leak
    bool dnsOk = true;
    ScanProbeError error = ScanProbeError::None;
    int fullWorks = -1;        // follow-up result: -1 = as works
    bool handshake = true;     // awg
    QString egressNode;        // "" = the candidate's own host; "-" = no header
    bool egressOther = false;  // class "other" (exit not in the whoami map)
    int burstNoData = 0;       // own Xray: this burst part (1..3) gets no answer - a network that drops the second
                               // ClientHello segment when several connections open at once; 0 = every part passes
};

struct World {
    QString name;
    QStringList rules;
    ScanHostCaps caps;
    ScanNetwork net = scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64500"));
    QList<NodeSpec> nodes;
    QMap<QString, Outcome> out;
    QString current;           // live connection at open
    QMap<QString, QString> leaseRefuse;
    int leaseDelayMs = 120;
    QSet<QString> connectFails;
    int connectMs = 1300;
    QString lkg;               // ConnectForScan target
    bool connectForScanFails = false;
    int vpnUpMs = 1600;
    ScanCachedResult cached;
    QJsonArray ledger;
    bool manifestUnavailable = false;
    ScanReportDelivery delivery = ScanReportDelivery::Sent;
    bool withCheck = false;
    QString lastKnownGood;
    QMap<QString, double> numbers;
    qint64 deviceBytesPerHour = 0;
    bool awgMini = false;      // features.scanner_awg_mini
    bool awgIpKnown = true;
    bool liveProbeWorks = true; // the sized check through the live tunnel
    // the probe host on a stop (plan §2.2b step 5)
    enum class Stop { Final, CancelAckTotal, AckNoFinal, NoAck };
    Stop stop = Stop::Final;
    // the host's direct access attempts (plan §2.2c): "answered" (200 with facts), "http_error" (an HTTP error
    // status), "network_error" (no HTTP answer), "none" (the host makes none); close "" = as open
    QString accessOpen = QStringLiteral("answered");
    QString accessClose;
    int hostGenBumpAtMs = -1;   // the host's path monitor counts a change at this offset after the host start
    // the coordinator's app requests: actual bytes = this percent of the reservation; cutApp = the request
    // whose answer passes its reservation (cut there; for the batch the grants then fail with transport)
    int appActualPct = 50;
    QString cutApp;
    int appOverrunBytes = 0;    // the cut reply still passed its reservation by this much (one chunk late, <= kScanAppOvershootMaxBytes)
    int liveOverrunBytes = 0;   // the live probe read this much past its reservation before the cut
    bool strict = false;        // features.upstream_unverifiable_strict
    QString hostRefusesStart;   // the host answers scan_start with this error (e.g. "memory"): nothing admitted
    QString hostRefusesDetail;  // ... and this "detail" (e.g. "kill_switch_exemption")
    QString reportRefuse;       // the engine refuses the full check with this reason ("" = it runs)
    bool openingSkipped = false; // the opening access attempt could not leave the interface (dns, bind, no_route)
    bool awgAddressKnown = true; // the device's own tunnel address is known
    bool manifestAccess = true;  // the app's own netinfo facts come with the manifest
    QStringList probeBaseIps;   // given to the machine with the manifest
    int manifestBytes = 20480;  // what the manifest + token really cost (a 304 + the token; a full 200 ~ 270000)
    // scripted events: time offset -> event builder (gets the driver to read state)
    QList<QPair<qint64, std::function<QJsonObject(qint64)>>> script;
    qint64 runMs = 20000;
};

inline const NodeSpec *specOf(const World &w, const QString &id)
{
    for (const NodeSpec &n : w.nodes)
        if (n.id == id)
            return &n;
    return nullptr;
}

inline QString pidOf(const QString &id) { return id.startsWith(QLatin1String("up:")) ? id.mid(3) : QString(); }

inline QJsonObject manifestBody(const World &w)
{
    QJsonArray nodes, ups;
    for (const NodeSpec &n : w.nodes) {
        if (!n.provider) {
            QJsonObject o{{QStringLiteral("node_id"), n.id}, {QStringLiteral("tier"), 0}, {QStringLiteral("rank"), n.rank},
                          {QStringLiteral("crowd_works"), n.crowd}};
            if (n.transport == ScanTransport::Awg)
                o.insert(QStringLiteral("awg_probe"), n.awgProbe);
            nodes << o;
            continue;
        }
        const QString tag = QStringLiteral("proxy");
        QJsonObject leg{{QStringLiteral("tag"), tag}, {QStringLiteral("protocol"), QStringLiteral("vless")},
                        {QStringLiteral("outbound"), QJsonObject{{QStringLiteral("settings"), QJsonObject{{QStringLiteral("vnext"),
                            QJsonArray{QJsonObject{{QStringLiteral("address"), n.entryIp}, {QStringLiteral("port"), n.entryPort}}}}}}}},
                        {QStringLiteral("dialer"), QJsonValue::Null}, {QStringLiteral("standalone"), true}};
        QJsonArray legs{leg};
        if (n.composite)
            legs << QJsonObject{{QStringLiteral("tag"), QStringLiteral("proxy2")}, {QStringLiteral("standalone"), true}};
        const QJsonObject route{{QStringLiteral("route"), QStringLiteral("leg")}, {QStringLiteral("leg"), tag}};
        QJsonArray dns;
        dns << QJsonObject{{QStringLiteral("address"), QStringLiteral("1.1.1.1")}, {QStringLiteral("tag"), QJsonValue::Null},
                           {QStringLiteral("transport"), QStringLiteral("udp")},
                           {QStringLiteral("route"), n.dnsThroughLeg ? QStringLiteral("leg") : QStringLiteral("direct")},
                           {QStringLiteral("leg"), n.dnsThroughLeg ? tag : QString()}};
        const QJsonObject projection{{QStringLiteral("version"), 1}, {QStringLiteral("legs"), legs},
                                     {QStringLiteral("catch_all"), QJsonObject{{QStringLiteral("tcp"), route}, {QStringLiteral("udp"), route}}},
                                     {QStringLiteral("dns"), dns}};
        ups << QJsonObject{{QStringLiteral("profile_id"), pidOf(n.id)}, {QStringLiteral("label"), n.label},
                           {QStringLiteral("ordinal"), 1}, {QStringLiteral("label_custom"), false},
                           {QStringLiteral("country_code"), n.cc}, {QStringLiteral("tier"), n.tier}, {QStringLiteral("rank"), n.rank},
                           {QStringLiteral("priority"), 0}, {QStringLiteral("probe_class"), n.composite ? QStringLiteral("composite") : QStringLiteral("single")},
                           {QStringLiteral("config_sha256"), QString(64, QLatin1Char('a'))}, {QStringLiteral("protocols"), QJsonArray{QStringLiteral("proto:vless")}},
                           {QStringLiteral("trimmed"), n.trimmed}, {QStringLiteral("legs_total"), legs.size()},
                           {QStringLiteral("projection"), projection}, {QStringLiteral("crowd_works"), n.crowd}};
    }
    QJsonObject numbers;
    for (auto it = w.numbers.constBegin(); it != w.numbers.constEnd(); ++it)
        numbers.insert(it.key(), it.value());
    return QJsonObject{{QStringLiteral("type"), QStringLiteral("scan_manifest")}, {QStringLiteral("version"), 1},
                       {QStringLiteral("network_key"), w.net.key}, {QStringLiteral("upstream_revision"), 7},
                       {QStringLiteral("upstream_eligible"), true},
                       {QStringLiteral("probe"), QJsonObject{{QStringLiteral("path"), QStringLiteral("/v1/probe")}, {QStringLiteral("default_bytes"), 65536},
                                                             {QStringLiteral("max_bytes"), 1048576}, {QStringLiteral("scheme"), QStringLiteral("tribe-probe-v1")}}},
                       {QStringLiteral("scan_token"), QJsonObject{{QStringLiteral("token"), QStringLiteral("tsc1.TEST-NOT-A-TOKEN")},
                                                                  {QStringLiteral("ttl_s"), 600}, {QStringLiteral("max_requests"), 400},
                                                                  {QStringLiteral("max_bytes"), 67108864}}},
                       {QStringLiteral("device_budget"), QJsonObject{{QStringLiteral("requests_per_hour"), 2000},
                                                                     {QStringLiteral("bytes_per_hour"), double(w.deviceBytesPerHour)}}},
                       {QStringLiteral("numbers"), numbers}, {QStringLiteral("nodes"), nodes}, {QStringLiteral("upstream"), ups},
                       {QStringLiteral("awg_echo_target"), QStringLiteral("10.8.1.1")}};
}

inline QJsonObject manifestArgs(const World &w)
{
    QJsonArray own;
    for (const NodeSpec &n : w.nodes)
        if (!n.provider)
            own << QJsonObject{{QStringLiteral("node_id"), n.id}, {QStringLiteral("label"), n.label}, {QStringLiteral("cc"), n.cc},
                               {QStringLiteral("transport"), QLatin1String(scanTransportName(n.transport))},
                               {QStringLiteral("version"), n.version}, {QStringLiteral("entry_ip"), n.entryIp},
                               {QStringLiteral("entry_port"), n.entryPort}, {QStringLiteral("manual_only"), n.manualOnly}};
    QJsonObject args{{QStringLiteral("manifest"), manifestBody(w)}, {QStringLiteral("own_nodes"), own},
                      {QStringLiteral("fresh_failures"), QJsonArray()}, {QStringLiteral("last_known_good"), w.lastKnownGood},
                      {QStringLiteral("access"), QJsonObject{{QStringLiteral("asn"), 64500}, {QStringLiteral("net_token"), QStringLiteral("net-access")}}},
                      {QStringLiteral("awg_mini_enabled"), w.awgMini}, {QStringLiteral("awg_probe_ip_known"), w.awgIpKnown},
                      {QStringLiteral("api_bytes"), w.manifestBytes},
                      {QStringLiteral("strict_unverifiable"), w.strict}};
    // later inputs only when set (the recorded vectors of earlier scenarios stay byte for byte)
    if (!w.awgAddressKnown)
        args.insert(QStringLiteral("awg_address_known"), false);
    if (!w.manifestAccess)
        args.insert(QStringLiteral("access"), QJsonObject());
    if (!w.probeBaseIps.isEmpty())
        args.insert(QStringLiteral("probe_base_ips"), QJsonArray::fromStringList(w.probeBaseIps));
    return args;
}

inline ScanCurrent liveOf(const World &w, const QString &id, bool working)
{
    ScanCurrent c;
    if (id.isEmpty())
        return c;
    const NodeSpec *n = specOf(w, id);
    c.nodeId = id;
    c.live = true;
    c.connecting = !working;
    c.dataFlowing = working;
    c.liveRttMs = working ? (w.out.contains(id) ? w.out.value(id).rtt : 45) : -1;
    if (n) {
        c.origin = n->provider ? ScanOrigin::Upstream : ScanOrigin::Own;
        c.label = n->label;
        c.countryCode = n->cc;
        c.transport = n->transport;
        c.transportVersion = n->version;
        c.tier = n->tier;
    }
    return c;
}

struct Recorded {
    QJsonObject event;
    ScanStep step;
    QJsonObject view;
    // the machine right after this step (invariants are judged per step, not on the final state)
    qint64 spent = 0;
    qint64 reserved = 0;
    qint64 cap = -1;
    qint64 allowance = -1;     // the scan's one allowance (F6) and what of it is spent or reserved
    qint64 allowanceUsed = 0;
    bool draining = false;     // a scan still settling its host bytes (must always have a wake)
    qint64 overrunBound = 0;   // what the reports so far may have put past the allowance (overruns x one chunk)
    QJsonObject summary;       // the machine's lastSummary() right after this step (the Doctor `scan` block)
    quint64 listBuilds = 0;    // the machine's listBuilds(): how many times its list was built from empty so far
};

// The rows' order and lifetime (owner 19.11, device rounds air7-air9: rows jumped, a row appeared and vanished). The
// machine owns them; the page draws the view's rows as they are. ListSteps judges every step against the one before:
//  - within one list (no build between the two steps) rows only JOIN ITS END: an emitted row never changes its index
//    and never disappears - not while a scan runs, not when it ends;
//  - a «Не проверено» row never joins while a scan runs (only once its outcome is final); the live connection's row
//    («Подключено», flag current) is the one row there before its proof;
//  - a list is built from empty only by the page's open, a scope choice, a network change, or a scan the person starts
//    («Сканировать» always; «Найти ещё» only with no list or another scope); right after a build its rows are in speed order (verified rows by speed class, then
//    ms; «Не проверено» rows after them) - the order of a finished result read back.
inline bool scanPhaseNameScanning(const QString &p)
{
    return p == QLatin1String("preparing") || p == QLatin1String("connecting") || p == QLatin1String("reach")
           || p == QLatin1String("data");
}

// One run's steps in order: step() judges each against the one before (the first against an empty screen).
struct ListSteps {
    explicit ListSteps(const ScanTunables &t) : t(&t) {}
    const ScanTunables *t;
    QJsonObject prevView;
    quint64 prevBuilds = 0;
    QSet<QString> base;   // rows on the list when it was built or its series began: admitted under earlier caps
    QSet<QString> joined; // rows that joined since
    int joinedVerified = 0, joinedUnverified = 0;

    void step(const Recorded &r, QStringList &fails, const QString &where)
    {
        const auto check = [&fails](bool ok, const QString &what) {
            if (!ok)
                fails << what;
        };
        const auto flagged = [](const QJsonObject &row, const char *flag) {
            return row.value(QLatin1String("flags")).toArray().contains(QLatin1String(flag));
        };
        const auto idOf = [](const QJsonValue &v) { return v.toObject().value(QLatin1String("id")).toString(); };
        const QString e = r.event.value(QLatin1String("event")).toString();
        const QJsonArray a = prevView.value(QLatin1String("rows")).toArray();
        const QJsonArray b = r.view.value(QLatin1String("rows")).toArray();
        const bool scanning = scanPhaseNameScanning(r.view.value(QLatin1String("phase")).toString());
        const int batch = qMax(1, r.view.value(QLatin1String("batch")).toInt());
        const int prevBatch = qMax(1, prevView.value(QLatin1String("batch")).toInt());
        const bool scanStart = e == QLatin1String("retry") || e == QLatin1String("connect_and_scan_tapped") || e == QLatin1String("more")
                               || e == QLatin1String("opened") || e == QLatin1String("network_changed");
        const bool built = r.listBuilds != prevBuilds;
        if (!built) {
            check(b.size() >= a.size(), where + QStringLiteral(": a row left the list"));
            for (int i = 0; i < a.size(); ++i)
                check(i < b.size() && idOf(b.at(i)) == idOf(a.at(i)), where + QStringLiteral(": an emitted row moved or left: ") + idOf(a.at(i)));
            for (int i = a.size(); i < b.size(); ++i)
                check(!(scanning && flagged(b.at(i).toObject(), "unverified")),
                      where + QStringLiteral(": a «Не проверено» row joined while the scan runs: ") + idOf(b.at(i)));
        } else {
            // A build: only on the events that may start a new list.
            const QString prevScope = prevView.value(QLatin1String("more_country")).toString();
            const QString scope = r.view.value(QLatin1String("more_country")).toString();
            const QString prevChosen = prevView.value(QLatin1String("bar")).toObject().value(QLatin1String("scope")).toString();
            check(e == QLatin1String("opened") || e == QLatin1String("shown") || e == QLatin1String("filter") || e == QLatin1String("network_changed")
                      || e == QLatin1String("retry") || e == QLatin1String("connect_and_scan_tapped") // «Сканировать» always builds its own list
                      || e == QLatin1String("stop") // owner 24.11: Stop keeps the screen open; the cancelled scan's list goes
                      || (scanStart && (a.isEmpty() || prevScope != scope || prevChosen != scope)),
                  where + QStringLiteral(": the list was rebuilt on ") + e);
            int lastRank = -1, lastMs = -1, verified = 0, unverified = 0;
            bool seenUnverified = false;
            for (const QJsonValue &v : b) {
                const QJsonObject row = v.toObject();
                if (flagged(row, "unverified")) {
                    seenUnverified = true;
                    ++unverified;
                    continue;
                }
                verified += flagged(row, "cache") ? 0 : 1;
                check(!seenUnverified, where + QStringLiteral(": a verified row after an unverified one in a built list"));
                const int rank = scanSpeedRank(scanSpeedFrom(row.value(QLatin1String("speed")).toString()));
                const int rawMs = row.value(QLatin1String("ms")).toInt();
                const int ms = rawMs < 0 ? INT_MAX : rawMs; // no figure sorts last inside its speed class
                // The current row shows its live ms but keeps the place of its own facts: it is skipped here.
                const bool current = flagged(row, "current");
                check(rank >= lastRank, where + QStringLiteral(": a built list out of speed order"));
                if (rank != lastRank)
                    lastMs = -1;
                if (!current && rank == lastRank && lastMs >= 0)
                    check(ms >= lastMs, where + QStringLiteral(": a built list out of ms order inside a speed class"));
                lastRank = rank;
                if (!current)
                    lastMs = ms;
            }
            // owner 19.11 (device round 13, A7/A8): wherever the VPN is connected the connected server is the first row
            for (int i = 1; i < b.size(); ++i)
                check(!flagged(b.at(i).toObject(), "current"), where + QStringLiteral(": a built list has the live connection's row below the first"));
            check(verified <= t->listTargetWorks * batch, where + QStringLiteral(": a built list above the cap of verified rows"));
            check(unverified <= t->unverifiedRowsMax, where + QStringLiteral(": a built list above the cap of «Не проверено» rows"));
        }
        // Caps of what JOINS a list (judged when it joins): scan_list_target_works proven rows and scan_unverified_rows_max
        // «Не проверено» rows per batch of the series. Rows shown before in the same list are never dropped.
        if (built || batch < prevBatch || (scanStart && scanning && batch == 1)) {
            base.clear();
            for (const QJsonValue &v : built ? b : a)
                base.insert(idOf(v));
            joined.clear();
            joinedVerified = joinedUnverified = 0;
        }
        for (const QJsonValue &v : b) {
            const QString id = idOf(v);
            if (base.contains(id) || joined.contains(id))
                continue;
            joined.insert(id);
            const QJsonObject row = v.toObject();
            if (flagged(row, "current"))
                continue; // the live connection's row always joins
            if (flagged(row, "unverified"))
                ++joinedUnverified;
            else if (!flagged(row, "cache"))
                ++joinedVerified;
        }
        check(joinedVerified <= t->listTargetWorks * batch, where + QStringLiteral(": more proven rows joined than the cap"));
        check(joinedUnverified <= t->unverifiedRowsMax * batch, where + QStringLiteral(": more «Не проверено» rows joined than the cap"));
        prevView = r.view;
        prevBuilds = r.listBuilds;
    }
};

// The driver: the coordinator + host + engine stand-in, all on the fake clock.
class Driver
{
public:
    explicit Driver(const World &w) : w(w), m(w.caps)
    {
        if (!w.ledger.isEmpty())
            m.restoreBudget(w.ledger);
    }

    World w;
    ScanMachine m;
    QList<Recorded> steps;
    qint64 now = kT0;
    QStringList closes;
    int releases = 0;
    int batches = 0;
    int maxReleaseIds = 0;
    QStringList leasesAsked;
    QJsonObject lastView;

    // fake host
    struct HC {
        ScanCandidate c;         // the candidate; a burst part's own reach, entry and cost
        QString probeId;
        int part = 0;            // the Xray burst part (0 = the data part)
        int bodyBytes = 65536;   // the body it asks
        qint64 addedAt = 0;
        qint64 reachAt = -1;   // when its reach item is due (-1 none)
        bool reachEmitted = false;
        bool reachOk = true;
        qint64 readyAt = -1;
        qint64 startAt = -1;
        qint64 endAt = -1;
        bool done = false;
    };
    QString hostId;
    qint64 hostT0 = 0;
    qint64 hostDeadline = 0;
    qint64 hostMax = -1;
    ScanHostLimits limits;
    QList<HC> hq;
    QList<ScanProbeFacts> items;
    qint64 seq = 0;
    qint64 spent = 0;
    ScanHostByteGate gate;
    bool hostActive = false;
    bool hostEnded = false;
    bool frozen = false;
    bool finalSent = false;
    bool hostDead = false;
    bool closingReserved = false;
    ScanAccessAttempt opening, closing;
    QString hostReason;
    qint64 polledSeq = 0;
    qint64 nextPoll = -1;
    qint64 simAt = 0;
    // engine stand-in
    QStringList attemptOrder;
    QString target;
    QMultiMap<qint64, QJsonObject> pending;

    ScanStep apply(const QJsonObject &e)
    {
        now = qint64(e.value(QLatin1String("now_ms")).toDouble());
        if (e.value(QLatin1String("event")).toString() == QLatin1String("host_failed")
            && !e.value(QLatin1String("args")).toObject().value(QLatin1String("host_alive")).toBool()) {
            hostActive = false; // the host is gone: no poll, no freeze ack, no final
            hostDead = true;
        }
        const ScanStep s = applyScanEvent(m, e);
        Recorded r{e, s, scanViewToJson(m.view(now)), m.spentBytes(), m.leaseReservedBytes(), m.capBytes(), m.allowanceBytes(), m.allowanceUsed(),
                   m.draining(), overruns * kScanAppOvershootMaxBytes, m.lastSummary(), m.listBuilds()};
        steps << r;
        react(s);
        return s;
    }

    void schedule(qint64 at, const QJsonObject &e) { pending.insert(at, e); }

    void run()
    {
        for (const auto &p : w.script)
            scriptAt << QPair<qint64, std::function<QJsonObject(qint64)>>(kT0 + p.first, p.second);
        const qint64 until = kT0 + w.runMs;
        for (int guard = 0; guard < 20000; ++guard) {
            qint64 t = -1;
            const auto take = [&t](qint64 x) {
                if (x >= 0 && (t < 0 || x < t))
                    t = x;
            };
            if (!pending.isEmpty())
                take(pending.firstKey());
            for (const auto &p : scriptAt)
                take(p.first);
            if (hostActive && !finalSent)
                take(nextPoll);
            take(lastWake);
            if (t < 0 || t > until)
                break;
            simulate(t);
            // scripted first (user/env), then reactive events, then the host poll, then ticks
            bool did = false;
            for (int i = 0; i < scriptAt.size(); ++i)
                if (scriptAt.at(i).first == t) {
                    const auto f = scriptAt.at(i).second;
                    scriptAt.removeAt(i);
                    const QJsonObject e = f(t);
                    if (!e.isEmpty())
                        stepAndWake(e);
                    did = true;
                    break;
                }
            if (did)
                continue;
            if (!pending.isEmpty() && pending.firstKey() == t) {
                const QJsonObject e = pending.take(t);
                if (e.value(QLatin1String("event")).toString() == QLatin1String("__engine_try")) {
                    now = t;
                    engineTry(e.value(QLatin1String("args")).toObject().value(QLatin1String("node_id")).toString());
                } else {
                    stepAndWake(e);
                }
                continue;
            }
            if (hostActive && !finalSent && nextPoll == t) {
                poll(t);
                continue;
            }
            if (lastWake == t) {
                lastWake = -1;
                stepAndWake(ev("tick", t));
                continue;
            }
        }
    }

    qint64 lastWake = -1;
    QList<QPair<qint64, std::function<QJsonObject(qint64)>>> scriptAt;

    void stepAndWake(const QJsonObject &e)
    {
        const ScanStep s = apply(e);
        if (s.wakeAtMs >= 0)
            lastWake = qMax(s.wakeAtMs, now);
        else
            lastWake = -1;
    }

    // --- reactions to the machine's actions ------------------------------------------------------------
    void react(const ScanStep &s)
    {
        for (const ScanAction &a : s.actions) {
            appDone(a);
            switch (a.kind) {
            case ScanActionKind::RequestManifest:
                if (w.manifestUnavailable)
                    schedule(now + 80, ev("manifest_unavailable", now + 80, {{QStringLiteral("reason"), QStringLiteral("service_off")}}));
                else {
                    schedule(now + 80, ev("manifest_ready", now + 80, manifestArgs(w)));
                    appBytesReported += w.manifestBytes;
                    if (w.manifestBytes > a.costBytes)
                        ++overruns;
                }
                break;
            case ScanActionKind::StartHostScan:
                if (!w.hostRefusesStart.isEmpty()) {
                    const qint64 at = now + 20; // the error reply to scan_start
                    QJsonObject args{{QStringLiteral("scan_id"), a.scanId}, {QStringLiteral("error"), w.hostRefusesStart},
                                     {QStringLiteral("start_accepted"), false}};
                    if (!w.hostRefusesDetail.isEmpty())
                        args.insert(QStringLiteral("detail"), w.hostRefusesDetail);
                    schedule(at, ev("host_failed", at, args));
                    break;
                }
                hostStart(a);
                break;
            case ScanActionKind::AddHostCandidates:
                for (const ScanCandidate &c : a.candidates)
                    hostAdd(c, now);
                break;
            case ScanActionKind::FreezeHostScan:
                hostFreeze(a.scanId);
                break;
            case ScanActionKind::StopHostScan:
                hostCancel(a.scanId);
                break;
            case ScanActionKind::ProbeLiveTunnel: {
                const qint64 at = now + 600;
                const ScanProbeFacts lf = liveFacts(a.nodeId);
                appBytesReported += lf.spentBytes;
                if (lf.spentBytes > a.costBytes)
                    ++overruns;
                schedule(at, ev("live_probe_result", at, {{QStringLiteral("node_id"), a.nodeId}, {QStringLiteral("facts"), scanProbeFactsToJson(liveFacts(a.nodeId))}}));
                break;
            }
            case ScanActionKind::RequestProbeBatch: {
                ++batches;
                const qint64 at = now + w.leaseDelayMs; // one signed answer; the coordinator reports each item
                for (const QString &id : a.ids) {
                    leasesAsked << id;
                    if (w.cutApp == QLatin1String("batch")) // the answer passed its reservation: cut, no grants
                        schedule(at, ev("lease_refused", at, {{QStringLiteral("node_id"), id}, {QStringLiteral("code"), QStringLiteral("transport")}}));
                    else if (w.leaseRefuse.contains(id))
                        schedule(at, ev("lease_refused", at, {{QStringLiteral("node_id"), id}, {QStringLiteral("code"), w.leaseRefuse.value(id)}}));
                    else
                        schedule(at, ev("lease_granted", at, {{QStringLiteral("node_id"), id},
                                                              {QStringLiteral("access"), QJsonObject{{QStringLiteral("asn"), 64500}, {QStringLiteral("net_token"), QStringLiteral("net-access")}}}}));
                }
                break;
            }
            case ScanActionKind::ReleaseProbeLeases:
                releases += a.ids.size();
                maxReleaseIds = qMax(maxReleaseIds, int(a.ids.size()));
                break;
            case ScanActionKind::StartReportCheck: {
                if (!w.reportRefuse.isEmpty()) {
                    schedule(now + 300, ev("report_check_refused", now + 300, {{QStringLiteral("report_id"), a.reportId},
                                                                                {QStringLiteral("reason"), w.reportRefuse}}));
                    break;
                }
                const QString d = w.delivery == ScanReportDelivery::Queued ? QStringLiteral("queued") : QStringLiteral("sent");
                if (a.withConnection) {
                    for (int k = 1; k <= 3; ++k)
                        schedule(now + 600 * k, ev("report_check_progress", now + 600 * k, {{QStringLiteral("step"), k}, {QStringLiteral("total"), 4}}));
                    schedule(now + 2400, ev("report_check_done", now + 2400, {{QStringLiteral("delivery"), d}, {QStringLiteral("report_id"), a.reportId}}));
                } else {
                    schedule(now + 1600, ev("report_check_done", now + 1600, {{QStringLiteral("delivery"), d}, {QStringLiteral("report_id"), a.reportId}}));
                }
                break;
            }
            case ScanActionKind::ConnectRow:
                attemptOrder = a.ids;
                engineTry(a.nodeId);
                break;
            case ScanActionKind::UserConnectForScan:
                if (w.connectForScanFails) {
                    ScanCurrent off;
                    off.failed = true;
                    schedule(now + w.vpnUpMs, ev("vpn_state", now + w.vpnUpMs, {{QStringLiteral("current"), currentJson(off)}}));
                } else {
                    schedule(now + 200, ev("vpn_state", now + 200, {{QStringLiteral("current"), currentJson(liveOf(w, w.lkg, false))}}));
                    schedule(now + w.vpnUpMs, ev("vpn_state", now + w.vpnUpMs, {{QStringLiteral("current"), currentJson(liveOf(w, w.lkg, true))}}));
                }
                break;
            case ScanActionKind::CancelPendingConnect:
                pending.clear(); // the connect in flight is gone
                schedule(now + 50, ev("vpn_state", now + 50, {{QStringLiteral("current"), currentJson(ScanCurrent())}}));
                break;
            case ScanActionKind::CloseScreen:
                closes << QString::number(now - kT0);
                break;
            default:
                break;
            }
        }
    }

    // The coordinator reports the real bytes of every app request it made (the manifest's come with
    // manifest_ready, the live probe's with its result): a share of the reservation, or all of it when cut.
    void appDone(const ScanAction &a)
    {
        if (a.requestId.isEmpty() || a.kind == ScanActionKind::RequestManifest || a.kind == ScanActionKind::ProbeLiveTunnel)
            return;
        const QString what = a.requestId.section(QLatin1Char('/'), 1).section(QLatin1Char('#'), 0, 0);
        const bool cut = !w.cutApp.isEmpty() && what == w.cutApp;
        const qint64 bytes = cut ? a.costBytes + w.appOverrunBytes : a.costBytes * w.appActualPct / 100;
        if (bytes > a.costBytes)
            ++overruns;
        appBytesReported += bytes;
        const qint64 at = now + (a.kind == ScanActionKind::RequestProbeBatch ? w.leaseDelayMs : 60);
        schedule(at, ev("app_request_done", at, {{QStringLiteral("request_id"), a.requestId}, {QStringLiteral("bytes"), double(bytes)}}));
    }
    qint64 appBytesReported = 0; // real bytes of the app requests the coordinator reported (incl. manifest, live)
    int overruns = 0;            // reports above their reservation

    ScanProbeFacts liveFacts(const QString &id) const
    {
        const NodeSpec *n = specOf(w, id);
        ScanProbeFacts f;
        f.id = id;
        f.stage = ScanStage::Data;
        f.seq = 1;
        f.bytesRequested = 65536;
        if (!w.liveProbeWorks) {
            f.httpStatus = 200;
            f.bytesReceived = 18000; // the operator freezes the flow after ~18 KB
            f.error = ScanProbeError::Stalled;
            return f;
        }
        f.httpStatus = 200;
        f.bytesReceived = 65536;
        f.shaOk = true;
        f.ttfb1Ms = 300;
        f.rttMs = w.out.contains(id) ? w.out.value(id).rtt : 45;
        f.t64Ms = 150;
        f.durationMs = 500;
        if (n && n->provider) {
            f.egressClass = QStringLiteral("other");
            f.egressAsn = 64600;
            f.egressNetToken = QStringLiteral("net-exit");
        } else {
            f.egressClass = QStringLiteral("tribe-node");
            f.egressNode = scanHostPartOf(id);
        }
        f.spentBytes = w.liveOverrunBytes > 0 ? 82944 + w.liveOverrunBytes : 1024 + 65536 + 8192;
        return f;
    }

    void engineTry(const QString &id)
    {
        target = id;
        schedule(now + 150, ev("vpn_state", now + 150, {{QStringLiteral("current"), currentJson(liveOf(w, id, false))}}));
        const qint64 at = now + 150 + w.connectMs;
        if (w.connectFails.contains(id)) {
            schedule(at, ev("connect_failed", at, {{QStringLiteral("node_id"), id}}));
            // the engine's ladder: the next of the hint
            triedFail.insert(id);
            QString next;
            for (const QString &x : attemptOrder)
                if (x != id && !triedFail.contains(x)) {
                    next = x;
                    break;
                }
            if (next.isEmpty()) {
                ScanCurrent off;
                off.failed = true;
                schedule(at + 10, ev("attempt_ended", at + 10));
                schedule(at + 20, ev("vpn_state", at + 20, {{QStringLiteral("current"), currentJson(off)}}));
            } else {
                schedule(at + 50, ev("__engine_try", at + 50, {{QStringLiteral("node_id"), next}}));
            }
        } else {
            schedule(at, ev("vpn_state", at, {{QStringLiteral("current"), currentJson(liveOf(w, id, true))}}));
        }
    }
    QSet<QString> triedFail;

    // --- fake host --------------------------------------------------------------------------------------
    ScanNetSource hostGen() const
    {
        const bool bumped = w.hostGenBumpAtMs >= 0 && now >= hostT0 + w.hostGenBumpAtMs;
        return ScanNetSource{QStringLiteral("ne"), kNeEpoch, bumped ? 2 : 1};
    }

    // One direct access attempt (plan §2.2c) admitted by the gate under `id`; mode as World::accessOpen.
    ScanAccessAttempt attempt(const QString &mode, const QString &id, bool reserved)
    {
        ScanAccessAttempt x;
        if (mode == QLatin1String("none") || (!reserved && !gate.admit(id, limits.netinfoCostBytes)))
            return x;
        x.attempted = true;
        x.atMs = now - hostT0;
        x.hasGen = true;
        x.gen = hostGen();
        x.httpAnswered = mode != QLatin1String("network_error");
        if (mode == QLatin1String("answered")) {
            x.facts.asn = 64500;
            x.facts.netToken = QStringLiteral("net-access");
        }
        gate.finish(id, x.httpAnswered ? 3000 : 1200);
        spent = gate.spent();
        return x;
    }

    void hostStart(const ScanAction &a)
    {
        hostId = a.scanId;
        hostT0 = now;
        hostDeadline = now + a.deadlineMs;
        hostMax = a.maxBytes;
        gate = ScanHostByteGate(a.maxBytes);
        limits = a.limits;
        hq.clear();
        items.clear();
        seq = 0;
        spent = 0;
        polledSeq = 0;
        hostActive = true;
        hostEnded = false;
        frozen = false;
        finalSent = false;
        hostDead = false;
        hostReason.clear();
        simAt = now;
        nextPoll = now + 300;
        // the opening attempt first, then the closing attempt's reservation for the whole scan
        opening = w.openingSkipped ? ScanAccessAttempt() : attempt(w.accessOpen, QStringLiteral("netinfo_open"), false);
        closingReserved = w.accessOpen != QLatin1String("none") && gate.admit(QStringLiteral("netinfo_close"), limits.netinfoCostBytes);
        closing = ScanAccessAttempt();
        for (const ScanCandidate &c : a.candidates)
            hostAdd(c, now);
    }

    // scan_freeze: no admission from now on; the ack carries spent + reserved (unless this host never acks).
    void hostFreeze(const QString &scanId)
    {
        if (scanId != hostId || hostDead)
            return;
        frozen = true;
        gate.freeze();
        if (w.stop == World::Stop::NoAck)
            return;
        const qint64 at = now + 30;
        schedule(at, ev("host_freeze_ack", at, {{QStringLiteral("scan_id"), scanId}, {QStringLiteral("spent"), double(gate.spent())},
                                                {QStringLiteral("reserved"), double(gate.reserved())}}));
    }

    // The host ends its scan (cancel, deadline): probes in flight stop, then the closing attempt.
    void hostEnd(const QString &reason)
    {
        for (HC &h : hq)
            if (!h.done && h.startAt >= 0) {
                ScanProbeFacts f;
                f.id = h.probeId;
                f.stage = ScanStage::Data;
                f.seq = ++seq;
                f.error = reason == QLatin1String("deadline") ? ScanProbeError::Deadline : ScanProbeError::Cancelled;
                f.spentBytes = qMin<qint64>(h.c.costBytes, 9000);
                gate.finish(h.probeId, f.spentBytes);
                items << f;
                h.done = true;
            } else if (!h.done) {
                h.done = true;
            }
        if (closingReserved && !closing.attempted)
            closing = attempt(w.accessClose.isEmpty() ? w.accessOpen : w.accessClose, QStringLiteral("netinfo_close"), true);
        spent = gate.spent();
        hostEnded = true;
        hostReason = reason;
    }

    // scan_cancel: everything stops; the totals come in the final progress or in the cancel ack.
    void hostCancel(const QString &scanId)
    {
        if (scanId != hostId || finalSent || hostDead)
            return;
        hostEnd(QStringLiteral("cancelled"));
        hostActive = false;
        if (w.stop == World::Stop::AckNoFinal || w.stop == World::Stop::NoAck)
            return;
        finalSent = true;
        const qint64 at = now + 120;
        if (w.stop == World::Stop::CancelAckTotal)
            schedule(at, ev("host_cancel_ack", at, {{QStringLiteral("scan_id"), scanId}, {QStringLiteral("bytes_spent"), double(gate.spent())}}));
        else
            schedule(at, ev("host_progress", at, {{QStringLiteral("reply"), scanEncodeProgress(progressNow(true))}}));
    }

    ScanHostProgress progressNow(bool finalTotals)
    {
        ScanHostProgress p;
        p.scanId = hostId;
        p.seq = seq;
        bool reachLeft = false;
        bool allDone = true;
        for (const HC &h : hq) {
            reachLeft = reachLeft || (h.reachAt >= 0 && !h.reachEmitted);
            allDone = allDone && h.done;
        }
        p.phase = hostEnded ? QStringLiteral("done") : reachLeft ? QStringLiteral("reach") : QStringLiteral("data");
        for (const ScanProbeFacts &f : items)
            if (f.seq > polledSeq)
                p.items << f;
        polledSeq = seq;
        p.bytesSpent = spent;
        p.done = hostEnded || allDone;
        p.finalTotals = finalTotals;
        p.bytesReserved = finalTotals ? 0 : gate.reserved();
        p.reason = hostEnded ? hostReason : allDone ? QStringLiteral("complete") : QString();
        p.access = opening;
        p.accessClose = closing;
        p.hasGen = true;
        p.gen = hostGen();
        return p;
    }

    // The coordinator's host jobs of one candidate (TribeScanner::withXrayBursts): own Xray as its burst.
    void hostAdd(const ScanCandidate &c, qint64 at)
    {
        const QList<ScanHostCandidate> parts = scanXrayBurstOf(scanHostCandidateOf(c, QString()), scanXrayBurstPartsOf(c), m.tunables());
        for (int n = 0; n < parts.size(); ++n) {
            const ScanHostCandidate &p = parts.at(n);
            HC h;
            h.c = c;
            h.c.reachAtMs = p.reachAtMs;
            h.c.entryIp = p.entryIp;
            h.c.entryPort = p.entryPort;
            h.c.costBytes = p.costBytes;
            h.probeId = p.id;
            h.part = n;
            h.bodyBytes = p.bytes > 0 ? p.bytes : 65536;
            h.addedAt = at;
            const Outcome o = w.out.value(c.id);
            if (h.c.hasReach()) {
                h.reachAt = hostT0 + h.c.reachAtMs + o.reachMs;
                if (h.reachAt < at)
                    h.reachAt = at + o.reachMs;
                h.reachOk = o.reachOk;
            } else {
                h.readyAt = at;
            }
            hq << h;
        }
    }

    int poolOf(const HC &h) const
    {
        return h.c.kind == ScanProbeKind::XrayLeg ? 1 : h.c.kind == ScanProbeKind::AwgMini ? 2 : 0;
    }
    int poolLimit(int p) const { return p == 1 ? limits.legConcurrency : p == 2 ? limits.awgConcurrency : limits.concurrency; }

    void emitData(HC &h, qint64 t)
    {
        const Outcome o = w.out.value(h.c.id);
        ScanProbeFacts f;
        f.id = h.probeId;
        f.stage = ScanStage::Data;
        f.seq = ++seq;
        f.durationMs = int(t - h.startAt);
        if (h.c.kind == ScanProbeKind::AwgMini) {
            f.handshakeOk = o.handshake;
            f.handshakeMs = o.handshake ? 80 : -1;
            f.echoSent = o.handshake ? limits.awgPrimeEchoes : 0;
            f.echoReplies = f.echoSent;
            f.bytesRequested = 65536;
            if (o.handshake && o.works) {
                f.httpStatus = 200;
                f.bytesReceived = 65536;
                f.shaOk = true;
                f.ttfb1Ms = o.ttfb1;
                f.rttMs = o.rtt;
                f.t64Ms = o.t64;
                f.egressClass = o.egressOther ? QStringLiteral("other") : QStringLiteral("tribe-node");
                if (!o.egressOther && o.egressNode != QLatin1String("-"))
                    f.egressNode = o.egressNode.isEmpty() ? scanHostPartOf(h.c.id) : o.egressNode;
            } else if (o.handshake) {
                f.httpStatus = 200;
                f.bytesReceived = 20000;
                f.ttfb1Ms = o.ttfb1;
                f.error = ScanProbeError::Stalled;
            }
            f.spentBytes = qMin<qint64>(h.c.costBytes, 2048 + 300 * f.echoSent + 1024 + f.bytesReceived + 16384);
        } else {
            const bool works = h.c.followUp && o.fullWorks >= 0 ? o.fullWorks == 1 : o.works;
            f.bytesRequested = h.bodyBytes;
            if (o.error != ScanProbeError::None) {
                f.error = o.error;
            } else if (h.part > 0 && h.part == o.burstNoData) {
                f.error = ScanProbeError::TtfbTimeout; // its ClientHello never completed: no answer at all
            } else if (works) {
                f.httpStatus = 200;
                f.bytesReceived = h.bodyBytes;
                f.shaOk = true;
                f.ttfb1Ms = o.ttfb1;
                f.rttMs = o.rtt;
                f.t64Ms = o.t64;
                if (h.c.origin == ScanOrigin::Own) {
                    f.egressClass = o.egressOther ? QStringLiteral("other") : QStringLiteral("tribe-node");
                    if (!o.egressOther && o.egressNode != QLatin1String("-"))
                        f.egressNode = o.egressNode.isEmpty() ? scanHostPartOf(h.c.id) : o.egressNode;
                } else {
                    f.egressClass = QStringLiteral("other");
                    f.egressAsn = 64600;
                    f.egressNetToken = o.sameNet ? QStringLiteral("net-access") : QStringLiteral("net-exit");
                }
                f.dnsExercised = h.c.kind == ScanProbeKind::XrayLeg && o.dnsOk && h.c.dnsThroughLeg && h.c.dnsResolvers > 0;
            } else {
                f.httpStatus = 200;
                f.bytesReceived = qMin(20000, h.bodyBytes / 2);
                f.ttfb1Ms = o.ttfb1;
                f.error = ScanProbeError::Stalled;
            }
            f.spentBytes = qMin<qint64>(h.c.costBytes, 1024 + f.bytesReceived + 16384);
        }
        f.startMs = h.startAt - hostT0;
        f.endMs = t - hostT0;
        gate.finish(h.probeId, f.spentBytes);
        spent = gate.spent();
        items << f;
        h.done = true;
        h.endAt = t;
    }

    void simulate(qint64 t)
    {
        if (!hostActive || hostEnded)
            return;
        for (qint64 x = simAt; x <= t; x += 10) {
            if (x >= hostDeadline) {
                const qint64 keep = now;
                now = x;
                hostEnd(QStringLiteral("deadline"));
                now = keep;
                break;
            }
            for (HC &h : hq) {
                if (h.done)
                    continue;
                if (h.reachAt >= 0 && !h.reachEmitted && x >= h.reachAt) {
                    h.reachEmitted = true;
                    ScanProbeFacts f;
                    f.id = h.probeId;
                    f.stage = ScanStage::Reach;
                    f.seq = ++seq;
                    f.reachOk = h.reachOk;
                    f.reachMs = w.out.value(h.c.id).reachMs;
                    f.error = h.reachOk ? ScanProbeError::None : ScanProbeError::ReachTimeout;
                    gate.charge(512);
                    spent = gate.spent();
                    items << f;
                    if (!h.reachOk)
                        h.done = true;
                    else
                        h.readyAt = x;
                }
                if (h.startAt >= 0 && x >= h.endAt && !h.done)
                    emitData(h, x);
            }
            for (HC &h : hq) {
                if (frozen || h.done || h.startAt >= 0 || h.readyAt < 0 || x < h.readyAt)
                    continue;
                int busy = 0;
                for (const HC &o : hq)
                    if (!o.done && o.startAt >= 0 && poolOf(o) == poolOf(h))
                        ++busy;
                if (busy >= poolLimit(poolOf(h)))
                    continue;
                if (!gate.admit(h.probeId, h.c.costBytes - (h.c.hasReach() ? 512 : 0))) {
                    ScanProbeFacts f;
                    f.id = h.probeId;
                    f.stage = ScanStage::Data;
                    f.seq = ++seq;
                    f.error = ScanProbeError::Budget;
                    items << f;
                    h.done = true;
                    continue;
                }
                h.startAt = x;
                h.endAt = x + w.out.value(h.c.id).durMs;
            }
        }
        simAt = ((t / 10) + 1) * 10;
    }

    void poll(qint64 t)
    {
        // A host that ended by itself (deadline) sends its final progress once; polls stop after it.
        const bool fin = hostEnded && !finalSent;
        if (fin)
            finalSent = true;
        const ScanHostProgress p = progressNow(fin);
        nextPoll = t + 300;
        stepAndWake(ev("host_progress", t, {{QStringLiteral("reply"), scanEncodeProgress(p)}}));
    }
};

} // namespace scantest
