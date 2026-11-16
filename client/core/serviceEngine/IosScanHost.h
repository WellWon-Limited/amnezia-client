// client/core/serviceEngine/IosScanHost.h
// AVPN serviceEngine - the iOS probe host of the Scanner (IScanHost.h) over IosController's scan channel to the
// tunnel extension, whose Go engine answers tribe-scan-v1 (PacketTunnelProvider+Scan.swift, TribeScanHost.swift),
// and the app process's own path monitor element ("app") of the strict generation tuple (ScanNetworkGeneration.h).
// Plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md v2.2 §2.3, §2.11a; lane L4. [IosScanHost.mm is
// iOS-only; the inline helpers below are pure QtCore and carry the tests:
// client/platforms/ios/tests/build_ios_scan_host_check.sh]
//
// Relay rules (IScanHost.h): request bytes to the extension unchanged, reply bytes back unchanged, `reply` exactly
// once on the GUI thread and never from inside sendMessage, an empty reply = no answer. The host's own answers:
// {"error":"no_vpn"} while the extension does not run (availability NeedsVpn - the engine lives in the tunnel
// process; this host never starts it). The extension adds its "ne" element as `gen` to scan_caps and
// scan_progress replies; generation() is the last one seen while the extension runs.
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "IScanHost.h"
#include "ScanNetworkGeneration.h"
#include "ScanTypes.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <functional>
#include <memory>

namespace avpn {

// What the iOS host can do as far as the app knows before the extension answered scan_caps: the platform fixture
// hostIosFull of tests/scan_scenarios.h (the extension offers the engine's awg_mini pool, lowered by its memory
// headroom; the app gates awg_mini by the server switch, the concurrency number and the manifest flag).
// needsVpn: probes run inside the tunnel extension.
inline ScanHostCaps iosScanKnownCaps()
{
    ScanHostCaps c;
    c.maxFullConcurrent = 1;
    c.canVerifyComposite = false;
    c.maxLegConcurrent = 4;
    c.dnsPlan = true;
    c.maxAwgConcurrent = 2;
    c.reachStage = true;
    c.needsVpn = true;
    c.platform = QStringLiteral("ios");
    return c;
}

// The bound of one relayed message by its action (the extension is in another process; every bound is ours): a
// scan_start that replaces a running scan is answered after up to 3 s (recipes/awg-apple/README.md "tribe-scan"),
// and it also waits for the extension's live-peer read (<= 0.5 s) and its lifecycle gate, which a tunnel core stop
// may hold for up to 2 s; scan_add waits for the gate too; the host-local scan_stop_all waits up to 2 s in the
// engine. Everything else - scan_cancel included: it answers at once and the final total comes in a later
// scan_progress with "final" - is answered at once.
inline int iosScanReplyTimeoutMs(const QByteArray &request)
{
    const QString action = QJsonDocument::fromJson(request).object().value(QLatin1String("action")).toString();
    if (action == QLatin1String("scan_start"))
        return 6000;
    if (action == QLatin1String("scan_add"))
        return 3500;
    if (action == QLatin1String("scan_stop_all"))
        return 3000;
    return 2000;
}

// The extension's own answer while it does not run (contract error no_vpn: the host needs a running tunnel).
inline QByteArray iosScanNoVpnReply() { return QByteArrayLiteral("{\"error\":\"no_vpn\"}"); }

// The host-local stop of every scan (PacketTunnelProvider+Scan.swift: the engine's LibXrayTribeScanStopAll under
// the lifecycle gate); not a contract action, the engine never sees it.
inline QByteArray iosScanStopAllRequest() { return QByteArrayLiteral("{\"action\":\"scan_stop_all\"}"); }

// The `gen` element of a scan_caps / scan_progress reply of the extension; false when absent, null or malformed.
// Read only: the reply bytes go to the coordinator unchanged.
inline bool iosScanReplyGen(const QByteArray &reply, ScanNetSource &out)
{
    const QJsonObject o = QJsonDocument::fromJson(reply).object();
    const QString type = o.value(QLatin1String("type")).toString();
    if (o.contains(QLatin1String("error"))
        || (type != QLatin1String("scan_caps") && type != QLatin1String("scan_progress")))
        return false;
    ScanNetSource s;
    if (!scanNetSourceFromJson(o.value(QLatin1String("gen")), s))
        return false;
    out = s;
    return true;
}

// The app process's path signature: whether the path is usable, the physical interfaces it uses ("type:name:
// index"), their addresses ("name/address"). Order-insensitive; kept in memory as a hash only, never sent.
inline QByteArray iosAppPathSignature(bool satisfied, QStringList interfaces, QStringList addresses)
{
    interfaces.sort();
    addresses.sort();
    const QByteArray in = QByteArrayLiteral("s=") + (satisfied ? "1" : "0") + "|i=" + interfaces.join(QLatin1Char(',')).toUtf8()
                          + "|a=" + addresses.join(QLatin1Char(',')).toUtf8();
    return QCryptographicHash::hash(in, QCryptographicHash::Sha256);
}

// The physical network kind of the app's path from the interface types it uses ("wifi", "cellular", "wired" as
// iosAppPathSignature's interface entries name them, or bare type names): wired > wifi > cellular when several are
// listed; "" when none is physical (no path, only other/loopback). Wire names: "ethernet" | "wifi" | "cellular".
inline QString iosAppPathKind(const QStringList &interfaceTypes)
{
    bool wired = false, wifi = false, cellular = false;
    for (const QString &entry : interfaceTypes) {
        const QString t = entry.section(QLatin1Char(':'), 0, 0);
        wired = wired || t == QLatin1String("wired");
        wifi = wifi || t == QLatin1String("wifi");
        cellular = cellular || t == QLatin1String("cellular");
    }
    if (wired)
        return QStringLiteral("ethernet");
    if (wifi)
        return QStringLiteral("wifi");
    if (cellular)
        return QStringLiteral("cellular");
    return QString();
}

// The "app" source of the strict tuple: a random epoch per monitor start, the counter grows on every change of
// the signature (the first one is the baseline) and never goes back. Not thread-safe (IosScanHost.mm locks it).
class IosAppNetGeneration
{
public:
    explicit IosAppNetGeneration(quint64 epoch) : m_epoch(epoch) {}

    // true = the counter moved.
    bool observe(const QByteArray &signature)
    {
        if (!m_seen) {
            m_seen = true;
            m_last = signature;
            return false;
        }
        if (signature == m_last)
            return false;
        m_last = signature;
        ++m_counter;
        return true;
    }

    bool seen() const { return m_seen; }

    ScanNetSource element() const
    {
        ScanNetSource s;
        s.source = QStringLiteral("app");
        s.epoch = m_epoch;
        s.counter = m_counter;
        return s;
    }

private:
    quint64 m_epoch = 0;
    qint64 m_counter = 0;
    bool m_seen = false;
    QByteArray m_last;
};

#if defined(Q_OS_IOS)
class IosScanHost final : public IScanHost
{
public:
    IosScanHost();
    ~IosScanHost() override;

    ScanHostCaps knownCaps() const override { return iosScanKnownCaps(); }
    ScanHostAvailability availability() const override;
    QString unavailableReason() const override { return availability() == ScanHostAvailability::Available ? QString() : QStringLiteral("no_vpn"); }
    void sendMessage(const QByteArray &request, ReplyFn reply) override;
    bool generation(ScanNetSource &out) const override;
    void stopAll() override;

    // The app process's own element (source "app") for ScanNetFacts.appSources on iOS (the engine lane's
    // IScanEngine::network()); false before its monitor saw the first path. The monitor starts on the first call
    // (or with the first IosScanHost). onChanged runs on the GUI thread after every change.
    static bool appGeneration(ScanNetSource &out);
    static void setAppGenerationChanged(std::function<void()> onChanged);
    // The physical network kind of the same monitor's last path (iosAppPathKind): "ethernet" | "wifi" | "cellular",
    // "" before the first path or when the path names no physical interface. Thread-safe; no extra monitor.
    static QString appPathKind();

    struct State;

private:
    std::shared_ptr<State> m_state;
};
#endif

} // namespace avpn
