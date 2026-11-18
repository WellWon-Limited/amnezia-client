// client/core/serviceEngine/IosAppScanHost.h
// AVPN serviceEngine - the iPhone probe host IN THE APP PROCESS (path engine design 2026-11-17 §5, variant A): the
// same Go engine as the tunnel extension (awg-apple libwg-go.a, ABI libxray-tribe-scan-v1, LibXrayTribeScanMessage)
// called directly in the app, its probe sockets bound to the app's own physical path (IP_BOUND_IF to the
// interface index of IosScanHost::appBindInterfaceIndex), so candidates can be probed BEFORE a tunnel exists and
// beside a live one without the extension's memory ceiling.
//
// Compiled only with the CMake option AVPN_IOS_APP_SCAN_HOST (default OFF; client/cmake/avpn.cmake): without it
// the app references no Go symbol, the linker drops libwg-go.a from the app binary and nothing changes. With it,
// coreController.cpp installs IosHybridScanHost instead of IosScanHost, which routes every scan by the mode of the
// control file (iosAppScanControlPath, read once when the host is made):
//   off            - every message to the extension (today's IosScanHost, needs_vpn)
//   before_tunnel  - a scan that starts with no tunnel runs in the app; with a tunnel (any state but
//                    Disconnected / Error) it goes to the extension; in-app scans stop when a tunnel starts
//   always         - default: in-app while the app is in front; awg_mini beside a tunnel goes to the extension
//                    (only it knows the live AmneziaWG peer, CONNECT-INVARIANTS §32 p. 3a), or is refused
//                    awg_live_peer_unknown while the extension does not answer (the coordinator retries without AWG)
// In every mode the in-app scans stop when the app leaves the foreground (iOS suspends the process; a probe
// frozen mid-flight would report a false timeout).
//
// The rules of IScanHost.h hold: request bytes to the engine unchanged, reply bytes back unchanged except the one
// host addition of the extension's kind (scan_caps: needs_vpn false - the in-app engine needs no tunnel), `reply`
// once on the GUI thread, never from inside sendMessage, per-action bound iosScanReplyTimeoutMs. Nothing here
// touches the tunnel. The pure parts below are QtCore only and carry the tests
// (client/platforms/ios/tests/ios_app_scan_host_check.cpp, build_ios_scan_host_check.sh).
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "IosScanHost.h"
#include "ScanHostContract.h"
#include "ScanNetworkGeneration.h"
#include "ScanTypes.h"

#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QPair>
#include <QString>
#include <QtGlobal>

#include <memory>

namespace avpn {

enum class IosAppScanMode { Off, BeforeTunnel, Always };

inline IosAppScanMode iosAppScanModeFrom(const QString &s, IosAppScanMode def = IosAppScanMode::Always)
{
    if (s == QLatin1String("off"))
        return IosAppScanMode::Off;
    if (s == QLatin1String("before_tunnel"))
        return IosAppScanMode::BeforeTunnel;
    if (s == QLatin1String("always"))
        return IosAppScanMode::Always;
    return def;
}

inline const char *iosAppScanModeName(IosAppScanMode m)
{
    switch (m) {
    case IosAppScanMode::Off: return "off";
    case IosAppScanMode::BeforeTunnel: return "before_tunnel";
    case IosAppScanMode::Always: break;
    }
    return "always";
}

// The control file of a build with the option on (Documents of the app container; devicectl copies it in and the
// results out): {"mode": "off"|"before_tunnel"|"always", "autorun_s": n (0 = no autorun; else one Scanner run n s
// after start, once the Scanner is enabled and the app is in front), "close_after_s": n (default 45)}.
struct IosAppScanControl {
    IosAppScanMode mode = IosAppScanMode::Always;
    // "awg_beside_tunnel": "extension" (default: a scan with awg_mini beside a tunnel goes to the extension, which
    // knows the live peer) | "refuse" (refused awg_live_peer_unknown: the coordinator retries without AWG, in-app).
    bool awgBesideTunnelRefuse = false;
    int autorunS = 0;
    int closeAfterS = 45;
};

inline IosAppScanControl iosAppScanControlFrom(const QByteArray &json)
{
    IosAppScanControl c;
    const QJsonObject o = QJsonDocument::fromJson(json).object();
    c.mode = iosAppScanModeFrom(o.value(QLatin1String("mode")).toString(), IosAppScanMode::Always);
    c.awgBesideTunnelRefuse = o.value(QLatin1String("awg_beside_tunnel")).toString() == QLatin1String("refuse");
    c.autorunS = qBound(0, o.value(QLatin1String("autorun_s")).toInt(0), 600);
    c.closeAfterS = qBound(10, o.value(QLatin1String("close_after_s")).toInt(45), 600);
    return c;
}

// What the in-app host can do before its engine answered scan_caps: the extension's fixture (the same engine and
// the same iOS pools: full 1, legs 6 in one instance, awg 2), but no tunnel needed.
inline ScanHostCaps iosAppScanKnownCaps()
{
    ScanHostCaps c = iosScanKnownCaps();
    c.needsVpn = false;
    return c;
}

// --- reading a request (never rewritten) -----------------------------------------------------------------------

struct IosAppScanRequestFacts {
    QString action;
    QString scanId;
    bool hasAwgMini = false;
    QList<QPair<QString, QString>> candidates; // (id, kind) of a scan_start / scan_add, for the journal
};

inline IosAppScanRequestFacts iosAppScanRequestFacts(const QByteArray &request)
{
    IosAppScanRequestFacts f;
    const QJsonObject o = QJsonDocument::fromJson(request).object();
    f.action = o.value(QLatin1String("action")).toString();
    f.scanId = o.value(QLatin1String("scan_id")).toString();
    const QJsonArray cands = o.value(QLatin1String("candidates")).toArray();
    for (const QJsonValue &v : cands) {
        const QJsonObject c = v.toObject();
        const QString kind = c.value(QLatin1String("kind")).toString();
        f.hasAwgMini = f.hasAwgMini || kind == QLatin1String("awg_mini");
        f.candidates << qMakePair(c.value(QLatin1String("id")).toString(), kind);
    }
    return f;
}

// --- routing -----------------------------------------------------------------------------------------------------

enum class IosAppScanRoute {
    App,                   // the in-app engine
    Extension,             // the tunnel extension (IosScanHost: its own no_vpn when it does not run)
    RefuseLivePeerUnknown, // {"error":"internal","detail":"awg_live_peer_unknown"} (the coordinator retries without AWG)
    RefuseNoPath,          // {"error":"bad_request","detail":"host_options.bind_interface"} (no physical path)
};

inline const char *iosAppScanRouteName(IosAppScanRoute r)
{
    switch (r) {
    case IosAppScanRoute::App: return "app";
    case IosAppScanRoute::Extension: return "extension";
    case IosAppScanRoute::RefuseLivePeerUnknown: return "refuse_live_peer_unknown";
    case IosAppScanRoute::RefuseNoPath: break;
    }
    return "refuse_no_path";
}

struct IosAppScanState {
    IosAppScanMode mode = IosAppScanMode::Always;
    bool tunnelDown = true;        // the tunnel is Disconnected / Error (not preparing, connecting, up, stopping)
    bool extensionRunning = false; // the extension answers (Connected / Reasserting)
    bool foreground = true;        // the app is in front (an in-app probe needs a running process)
    unsigned bindIndex = 0;        // the app path's physical interface (0 = none)
    bool pathSatisfied = false;
    bool awgBesideTunnelRefuse = false; // IosAppScanControl::awgBesideTunnelRefuse
};

// Where a scan_start goes. A start of the app engine needs a physical interface to bind to (the engine refuses one
// without it as well; refused here so the extension never sees a start it would run unbound).
inline IosAppScanRoute iosAppScanRouteStart(const IosAppScanState &s, bool hasAwgMini)
{
    if (s.mode == IosAppScanMode::Off)
        return IosAppScanRoute::Extension;
    const bool appPath = s.bindIndex > 0 && s.pathSatisfied;
    if (s.tunnelDown) {
        if (!s.foreground && s.extensionRunning)
            return IosAppScanRoute::Extension; // cannot happen with the tunnel down; kept total
        return appPath ? IosAppScanRoute::App : IosAppScanRoute::RefuseNoPath;
    }
    // A tunnel exists (or is coming up / going down).
    if (s.mode == IosAppScanMode::BeforeTunnel)
        return IosAppScanRoute::Extension;
    if (hasAwgMini) // only the extension knows the live AmneziaWG peer (§32 p. 3a): never in-app beside a tunnel
        return s.extensionRunning && !s.awgBesideTunnelRefuse ? IosAppScanRoute::Extension : IosAppScanRoute::RefuseLivePeerUnknown;
    if (!s.foreground)
        return s.extensionRunning ? IosAppScanRoute::Extension : IosAppScanRoute::RefuseNoPath;
    return appPath ? IosAppScanRoute::App : (s.extensionRunning ? IosAppScanRoute::Extension : IosAppScanRoute::RefuseNoPath);
}

// A scan_add for a scan that runs in the app: awg_mini beside a tunnel is refused the same way (its start had none,
// or the tunnel came up after the start).
inline bool iosAppScanAddRefusedAwg(const IosAppScanState &s, bool hasAwgMini) { return hasAwgMini && !s.tunnelDown; }

// In-app scans stop when a tunnel starts coming up only in before_tunnel mode; when the app leaves the front in
// every mode.
inline bool iosAppScanStopOnTunnelUp(IosAppScanMode m) { return m == IosAppScanMode::BeforeTunnel; }

// Which scans run where (scan_id -> route), the last 8 starts. A message of an unknown scan goes to the app engine
// (it answers unknown_scan), unless the mode is off.
class IosAppScanRoutes
{
public:
    void set(const QString &scanId, IosAppScanRoute r)
    {
        if (scanId.isEmpty())
            return;
        for (int i = 0; i < m_list.size(); ++i)
            if (m_list.at(i).first == scanId) {
                m_list.removeAt(i);
                break;
            }
        m_list << qMakePair(scanId, r);
        while (m_list.size() > 8)
            m_list.removeFirst();
    }
    IosAppScanRoute of(const QString &scanId, IosAppScanMode mode) const
    {
        if (mode == IosAppScanMode::Off)
            return IosAppScanRoute::Extension;
        for (int i = m_list.size() - 1; i >= 0; --i)
            if (m_list.at(i).first == scanId)
                return m_list.at(i).second;
        return IosAppScanRoute::App;
    }
    bool anyApp() const
    {
        for (const auto &p : m_list)
            if (p.second == IosAppScanRoute::App)
                return true;
        return false;
    }

private:
    QList<QPair<QString, IosAppScanRoute>> m_list;
};

// --- host options and replies ------------------------------------------------------------------------------------

// Host options of one message to the app engine (engine.go HostOptions): the bind index with scan_start, the app's
// path element as `gen` when known (the engine stamps progress and access attempts with it; the coordinator's tuple
// has the same "app" element, so the exclusion bracket compares like for like), host_epoch always.
inline QByteArray iosAppScanHostOptions(unsigned bindIndex, bool hasGen, const ScanNetSource &gen, quint64 epoch)
{
    QJsonObject o;
    if (bindIndex > 0)
        o.insert(QStringLiteral("bind_interface_index"), double(bindIndex));
    if (hasGen)
        o.insert(QStringLiteral("gen"), scanNetSourceToJson(gen));
    o.insert(QStringLiteral("host_epoch"), double(epoch));
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

inline QByteArray iosAppScanLivePeerUnknownReply()
{
    return QByteArrayLiteral("{\"error\":\"internal\",\"detail\":\"awg_live_peer_unknown\"}");
}
inline QByteArray iosAppScanNoPathReply()
{
    return QByteArrayLiteral("{\"error\":\"bad_request\",\"detail\":\"host_options.bind_interface\"}");
}

// The engine's scan_caps reply with the in-app host's one addition: needs_vpn false (the engine's iOS platform says
// true: it was built for the extension). Every other byte stays; a reply that is not a scan_caps object, or one
// without needs_vpn true, comes back as it is.
inline QByteArray iosAppScanDecorateCaps(const QByteArray &reply)
{
    const QJsonObject o = QJsonDocument::fromJson(reply).object();
    if (o.value(QLatin1String("type")).toString() != QLatin1String("scan_caps") || o.contains(QLatin1String("error"))
        || o.value(QLatin1String("needs_vpn")) != QJsonValue(true))
        return reply;
    static const QByteArray from = QByteArrayLiteral("\"needs_vpn\":true");
    static const QByteArray to = QByteArrayLiteral("\"needs_vpn\":false");
    if (reply.count(from) == 1) {
        QByteArray out = reply;
        out.replace(from, to);
        return out;
    }
    QJsonObject copy = o; // not compact Go output: re-encode (the coordinator decodes JSON, never bytes)
    copy.insert(QStringLiteral("needs_vpn"), false);
    return QJsonDocument(copy).toJson(QJsonDocument::Compact);
}

// --- the measurement journal (only ids, kinds, codes, timings, sizes, ASNs: never configs, hosts or tokens) --------

// One journal record per probe item of a scan_progress reply, plus the scan-level facts; `sinceStartMs` = host clock
// since the scan_start was sent to the engine. firstProven: the first data item with a verified digest (the race's
// "time to first proven candidate"), set once per scan by the caller.
inline QList<QJsonObject> iosAppScanProgressRecords(const QByteArray &reply, qint64 sinceStartMs,
                                                     const QList<QPair<QString, QString>> &kinds)
{
    QList<QJsonObject> out;
    const ScanHostReply r = scanDecodeReply(reply);
    if (r.kind != ScanHostReplyKind::Progress)
        return out;
    const ScanHostProgress &p = r.progress;
    auto kindOf = [&kinds](const QString &id) {
        for (const auto &k : kinds)
            if (k.first == id)
                return k.second;
        return QString();
    };
    for (const ScanProbeFacts &f : p.items) {
        QJsonObject o{{QStringLiteral("ev"), QStringLiteral("item")},
                      {QStringLiteral("scan"), p.scanId},
                      {QStringLiteral("t_ms"), double(sinceStartMs)},
                      {QStringLiteral("id"), f.id},
                      {QStringLiteral("kind"), kindOf(f.id)},
                      {QStringLiteral("stage"), f.stage == ScanStage::Reach ? QStringLiteral("reach") : QStringLiteral("data")},
                      {QStringLiteral("err"), QLatin1String(scanProbeErrorName(f.error))}};
        if (f.stage == ScanStage::Reach) {
            o.insert(QStringLiteral("reach_ok"), f.reachOk);
            o.insert(QStringLiteral("reach_ms"), f.reachMs);
        } else {
            o.insert(QStringLiteral("http"), f.httpStatus);
            o.insert(QStringLiteral("sha_ok"), f.shaOk);
            o.insert(QStringLiteral("ttfb1_ms"), f.ttfb1Ms);
            o.insert(QStringLiteral("rtt_ms"), f.rttMs);
            o.insert(QStringLiteral("dur_ms"), f.durationMs);
            o.insert(QStringLiteral("bytes_rx"), double(f.bytesReceived));
            o.insert(QStringLiteral("start_ms"), double(f.startMs));
            o.insert(QStringLiteral("end_ms"), double(f.endMs));
            if (!f.egressClass.isEmpty())
                o.insert(QStringLiteral("egress_class"), f.egressClass);
            if (!f.egressNode.isEmpty())
                o.insert(QStringLiteral("egress_node"), f.egressNode);
            if (f.egressAsn > 0)
                o.insert(QStringLiteral("egress_asn"), double(f.egressAsn));
            if (f.handshakeMs >= 0 || f.handshakeOk) {
                o.insert(QStringLiteral("hs_ok"), f.handshakeOk);
                o.insert(QStringLiteral("hs_ms"), f.handshakeMs);
            }
        }
        out << o;
    }
    QJsonObject s{{QStringLiteral("ev"), QStringLiteral("progress")},
                  {QStringLiteral("scan"), p.scanId},
                  {QStringLiteral("t_ms"), double(sinceStartMs)},
                  {QStringLiteral("phase"), p.phase},
                  {QStringLiteral("items"), int(p.items.size())},
                  {QStringLiteral("mem_mb"), p.memMb},
                  {QStringLiteral("bytes_spent"), double(p.bytesSpent)},
                  {QStringLiteral("done"), p.done},
                  {QStringLiteral("final"), p.finalTotals}};
    if (!p.reason.isEmpty())
        s.insert(QStringLiteral("reason"), p.reason);
    // The access attempts: the probe host's /v1/netinfo on a socket bound like every probe - the server's view of
    // the source (the ASN of the address the request came from). Beside a tunnel it is the bypass proof: the
    // phone's own operator, not the exit node's.
    auto access = [&s](const char *key, const ScanAccessAttempt &a) {
        if (!a.attempted)
            return;
        s.insert(QLatin1String(key), QJsonObject{{QStringLiteral("http"), a.httpAnswered},
                                                 {QStringLiteral("asn"), double(a.facts.asn)},
                                                 {QStringLiteral("at_ms"), double(a.atMs)}});
    };
    access("access", p.access);
    access("access_close", p.accessClose);
    out << s;
    return out;
}

// A data item that proves the candidate: a verified digest of the sized body.
inline bool iosAppScanItemProven(const QJsonObject &record)
{
    return record.value(QLatin1String("ev")).toString() == QLatin1String("item")
           && record.value(QLatin1String("stage")).toString() == QLatin1String("data")
           && record.value(QLatin1String("sha_ok")).toBool(false);
}

#if defined(Q_OS_IOS)
class TribeScanner;

// IScanHost of the option: the in-app engine and the extension (IosScanHost) behind one host, routed per scan.
class IosHybridScanHost final : public IScanHost
{
public:
    IosHybridScanHost();
    ~IosHybridScanHost() override;

    ScanHostCaps knownCaps() const override;
    ScanHostAvailability availability() const override;
    QString unavailableReason() const override;
    void sendMessage(const QByteArray &request, ReplyFn reply) override;
    bool generation(ScanNetSource &out) const override;
    void stopAll() override;

    // The control file (Documents/tribe-app-probe.json) and the results journal (Documents/tribe-app-probe.jsonl).
    static QString controlPath();
    static QString resultsPath();
    static IosAppScanControl readControl();

    // Debug autorun of a build with the option (control file autorun_s > 0): one Scanner run without UI taps.
    static void installAutorun(TribeScanner *scanner);

    struct State;

private:
    std::shared_ptr<State> m_state;
};
#endif

} // namespace avpn
