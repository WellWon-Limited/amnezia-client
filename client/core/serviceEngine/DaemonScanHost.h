// client/core/serviceEngine/DaemonScanHost.h
// AVPN serviceEngine - the Scanner's probe host on macOS and Windows desktop: IScanHost over the root
// service's QtRO source IpcScanInterface (ipc/ipc_scan_interface.rep, service side
// service/server/tribe_scan.{h,cpp}). Plan scanner-client-plan.md §2.4, §2.6; API note
// ~/avpn-build/plans/provider-pool/scanner-api-note.md (a).
//
//  - sendMessage relays the request bytes unchanged (scanSubmit) and hands the scanReply bytes back
//    unchanged; exactly one reply per message, always queued on the GUI thread, never from inside
//    sendMessage. Own bound per message (kDaemonScanReplyMs, a scan_start kDaemonScanStartReplyMs: the
//    service queues messages behind a replacing scan_start that may wait 3 s); an empty reply = no answer
//    (the service is gone, the call failed, or the bound elapsed). A refusal of the service's IPC bounds
//    comes back as {"error":"ipc_refused","detail":"too_large"|"rate_limited"|"queue_full"|
//    "shutting_down"} (ScanHostError::Other for the coordinator).
//  - availability(): Available only while the service offers IpcScanInterface with a known version;
//    unavailableReason() tells why not: "connecting" (the first seconds after the start), "service_off"
//    (no service answers), "service_old" (the service answers IpcInterface but has no IpcScanInterface,
//    or another shape of it: installed before the Scanner - the app never calls a missing slot),
//    "service_mismatch" (even IpcInterface differs: a service of another build). The screen shows
//    «Служба Tribe VPN не запущена» for every reason (coordinator: NoScan service_off).
//  - generation(): the service's path element (source "service"), pushed by the service as the
//    scanGeneration property, so it is known BEFORE the first scan_start.
//  - The adapter owns a QRemoteObjectNode of its own (IpcClient's node is untouched): the IpcInterface
//    replica on it is a witness only (its state tells "service up" from "service off"); no IpcInterface
//    slot is ever called from here.
//  - Never logs request or reply bytes; nothing here touches the tunnel.
// Upstream Amnezia has no counterpart. Tests: tests/build_daemon_scan_host.sh.
#pragma once

#include "IScanHost.h"

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QRemoteObjectReplica>
#include <QString>
#include <QUrl>

#include <functional>
#include <memory>

namespace avpn {

inline constexpr int kDaemonScanReplyMs = 3500;
inline constexpr int kDaemonScanStartReplyMs = 6000;
inline constexpr int kDaemonScanStartupMs = 3000;      // "connecting" before "service_off"
inline constexpr int kDaemonScanOldGraceMs = 1500;     // IpcInterface valid, IpcScanInterface still missing
inline constexpr qsizetype kDaemonScanMaxMessageBytes = 8 * 1024 * 1024; // = kTribeScanMaxMessageBytes

// The IPC as the adapter sees it (QtRO in production, a fake in tests). Callbacks on the GUI thread.
class DaemonScanTransport
{
public:
    enum class State { Connecting, ServiceOff, ServiceOld, ServiceMismatch, Ready };
    virtual ~DaemonScanTransport() = default;
    virtual State state() const = 0;
    virtual QString generationJson() const = 0; // the scanGeneration property ("" = unknown)
    // Queue one message; `accepted` gets the slot's answer once (0 = accepted, 1..4 = the service's
    // refusal codes, -1 = the call failed), never from inside submit().
    virtual void submit(quint64 requestId, const QString &message, std::function<void(int code)> accepted) = 0;
    virtual void stopAll() = 0;

    std::function<void()> onStateChanged;
    std::function<void()> onGenerationChanged;
    std::function<void(quint64 requestId, const QString &reply)> onReply;
};

// Pure: the transport state from the two replicas (witness = IpcInterface, scan = IpcScanInterface).
DaemonScanTransport::State daemonScanTransportState(QRemoteObjectReplica::State witness, QRemoteObjectReplica::State scan,
                                                    int scanIpcVersion, bool startupOver, bool oldGraceOver);
QString daemonScanUnavailableReason(DaemonScanTransport::State s); // "" for Ready
// The adapter's bound for one request (a scan_start waits longer, see the header comment).
int daemonScanReplyBoundMs(const QByteArray &request);
// The reply the adapter answers for a refusal code of scanSubmit; "" for 0 and -1.
QByteArray daemonScanRefusalReply(int code);

class DaemonScanHost : public IScanHost
{
public:
    explicit DaemonScanHost(std::unique_ptr<DaemonScanTransport> transport);
    ~DaemonScanHost() override;

    // Production: the root service's socket (amnezia::getIpcServiceUrl()); `url` overrides it (tests).
    static std::unique_ptr<DaemonScanTransport> serviceTransport(const QUrl &url = QUrl());

    // What the desktop host offers before the service answers its first scan_caps: the engine's answer for
    // the default configuration of this build's service (macOS: the bindings' 2 full / 6 legs / composites /
    // DNS plans, plus awg_mini 4 with the probe-capable amneziawg-go the payload ships; Windows: no
    // awg_mini; needs_vpn false). Kept equal to the real answer by tribe_scan_engine_check. The service may
    // answer less (no probe binary, a live AmneziaWG tunnel whose peer is unknown): its answer wins.
    static ScanHostCaps compiledCaps();
    ScanHostCaps knownCaps() const override;
    ScanHostAvailability availability() const override;
    void sendMessage(const QByteArray &request, ReplyFn reply) override;
    bool generation(ScanNetSource &out) const override;
    void stopAll() override;

    QString unavailableReason() const override;
    int pendingCount() const { return m_pending.size(); }

    // Test seam: how a message's own bound is armed (default: a precise single-shot timer on the GUI
    // thread). Gets the bound in ms and `expire` (answers that message with no reply); returns an object
    // deleted when the message is answered.
    using BoundTimer = std::function<QObject *(int boundMs, std::function<void()> expire)>;
    void setBoundTimerForTest(BoundTimer t) { m_boundTimer = std::move(t); }

private:
    void finish(quint64 id, const QByteArray &reply);
    void stateChanged();

    struct Pending {
        ReplyFn reply;
        QObject *timer = nullptr;
    };
    QObject m_ctx; // parent of the bound timers; context of every queued delivery
    QHash<quint64, Pending> m_pending;
    quint64 m_nextId = 0;
    BoundTimer m_boundTimer;
    DaemonScanTransport::State m_state = DaemonScanTransport::State::Connecting;
    std::unique_ptr<DaemonScanTransport> m_t; // declared last: destroyed first (its callbacks capture this)
};

} // namespace avpn
