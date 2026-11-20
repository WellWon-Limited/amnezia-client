// client/core/serviceEngine/IScanHost.h
// AVPN serviceEngine - the probe host as the Scanner's coordinator (TribeScanner) sees it: an asynchronous
// relay of `tribe-scan-v1` JSON messages (ScanHostContract.h) plus the few facts the coordinator needs
// before it can ask the host anything. [header-only, QtCore; no platform types]
//
// Plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md §2.2-§2.6, §2.11a, §5.1 (lanes L4 iOS, L5
// macOS/Windows, A3 Android implement it; L6a consumes it). API note for the other lanes:
// ~/avpn-build/plans/provider-pool/scanner-api-note.md.
//
// Rules every implementation keeps (CONNECT-INVARIANTS §32):
//  - The host only RELAYS: the request bytes go to the probe engine (iOS: the tunnel extension's
//    {"action": ...} channel; macOS / Windows: the service's QtRO slots scanStart/scanPoll/scanCancel...;
//    Android: :amneziaXrayService IPC) exactly as given, and the engine's reply bytes come back exactly as
//    received. No decision, no rewriting, no caching of replies, no retry. The coordinator decodes and
//    decides (ScanHostContract.h::scanDecodeReply).
//  - `reply` is called EXACTLY ONCE per sendMessage, on the GUI thread, never from inside sendMessage itself
//    (queue it: QTimer::singleShot(0, ...) or the platform's queued delivery). An empty QByteArray = no answer
//    (the host process is gone, the IPC failed, or the host's own bound elapsed). Every implementation bounds
//    its wait PER ACTION, at most 6 s (the iOS host: scan_start 6 s, scan_add 3.5 s, scan_cancel and stop-all
//    3 s, every other action 2 s); the coordinator relies only on the answer coming once, not on its timing.
//    A host whose engine process is not running answers {"error":"no_vpn"} (or nothing). Requests may overlap
//    (a poll, an add and a freeze in flight together); replies may come in any order.
//  - Nothing here touches the tunnel: no connect, no stop, no restart, no route change. A host whose engine
//    lives in the tunnel process (iOS NE, Android Xray service) reports NeedsVpn while that process is not
//    running and NEVER starts it; the coordinator asks the engine lane for the ordinary user connect
//    (REQ S3 (b)) when the user opens the screen.
//  - Secrets: request bytes carry the scan token and candidate configs. Never log, store or echo them; a
//    journal line about a message uses ScanHostContract.h::scanRedactForLog on the decoded object, never the
//    raw bytes.
//  - Sockets of probes use the scan's own protector (plan §2.2a); a probe's failure never reaches the
//    tunnel's failure path. That is the host engine's job; this interface carries no socket.
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanNetworkGeneration.h"
#include "ScanTypes.h"

#include <QByteArray>

#include <functional>

namespace avpn {

// Whether the host can take a message right now.
enum class ScanHostAvailability {
    Available,   // messages are relayed
    NeedsVpn,    // the engine runs only inside the tunnel process, which is not running (iOS, Android)
    Unavailable, // no host at all on this device / build (service missing, kill switch, unsupported tunnel)
};

// The one capability fact behind every Scanner entry point (home «Сканер» and its round button, the server list's
// «Запустить сканер», the Support check, the coordinator's own opening): this build has a probe host the Scanner can
// scan with. iOS: the tunnel extension / in-app host; macOS (service build), Windows, Linux: the root service's host.
// Android: no - the in-tunnel host of release 140 probes only inside an Xray tunnel, and the owner decided (16.11) that
// Android shows the Scanner only with its own probe process (scanner_android_probe_process, plan «процесс проб
// Android»), which this build does not have; Android keeps the Doctor, as the public build. The macOS NE build: no host.
// Without a host the Scanner does not exist on this build, whatever the server's switch says (scannerSwitchOn).
inline constexpr bool kScanHostOnThisBuild =
#if defined(Q_OS_ANDROID) || defined(MACOS_NE)
    false;
#else
    true;
#endif

// The `scanner` switch as every reader takes it (the engine's scannerEnabled for QML, the coordinator's enabled): the
// server's switch AND a probe host on this build.
inline constexpr bool scannerSwitchOn(bool serverSwitch, bool hostOnBuild) { return serverSwitch && hostOnBuild; }

inline const char *scanHostAvailabilityName(ScanHostAvailability a)
{
    switch (a) {
    case ScanHostAvailability::Available: return "available";
    case ScanHostAvailability::NeedsVpn: return "needs_vpn";
    case ScanHostAvailability::Unavailable: break;
    }
    return "unavailable";
}

class IScanHost
{
public:
    virtual ~IScanHost() = default;

    // What this platform's host can do as far as the app knows WITHOUT asking it (compiled per platform, e.g.
    // iOS {legs 4, full 1, composite false, awg 2, dns_plan true, needs_vpn true}). Used to build the machine
    // before the first `scan_caps` answer, and while the host cannot answer (NeedsVpn): `needsVpn` decides
    // whether opening the screen with the VPN off goes through «Подключаемся…». The coordinator replaces it
    // by the decoded `scan_caps` reply as soon as the host answers one.
    virtual ScanHostCaps knownCaps() const = 0;

    virtual ScanHostAvailability availability() const = 0;

    // Why availability() is not Available, as a stable code ("" while Available). Desktop (DaemonScanHost):
    // "connecting" (transient: the first seconds after the app started - the coordinator waits for
    // onAvailabilityChanged, bounded), "service_off" (no service answers), "service_old" / "service_mismatch"
    // (the installed service is of another version than the app: the Scanner is unavailable until it is
    // updated, connecting still works). iOS / Android: "no_vpn" while the tunnel process is not running.
    // The coordinator maps Unavailable to NoScan "service_off", "service_old" or "service_mismatch" (any other
    // code = service_off).
    virtual QString unavailableReason() const = 0;

    // Relay one request (compact JSON of a ScanHostContract.h encoder: scan_caps, scan_start, scan_add,
    // scan_poll, scan_freeze, scan_cancel, or any future action - an unknown one must come back as
    // {"error":"unknown_action"} from the engine). See the rules above for `reply`.
    using ReplyFn = std::function<void(const QByteArray &reply)>;
    virtual void sendMessage(const QByteArray &request, ReplyFn reply) = 0;

    // The host's own path monitor element of the strict generation tuple (ScanNetworkGeneration.h,
    // plan §2.11a): {source ("ne", "service", "xray_service"), epoch (random per monitor start), counter (path
    // changes seen)}, known OUTSIDE a scan. false = not known here. Two ways to give it, either is enough: answer
    // it here (e.g. macOS: the service's route monitor), or let the engine put it as "gen" into its scan_caps
    // reply (the iOS extension does) - the coordinator reads that field itself and uses it when this returns
    // false. The element joins the tuple at the coordinator's open(); afterwards a change of it (here, in a
    // scan_caps "gen" or in scan_progress.gen) or its disappearance is a network change. An element seen only
    // inside scan_progress never joins (TribeScanner.h "Network").
    virtual bool generation(ScanNetSource &out) const = 0;

    // Best effort, no reply: end every scan this app started on the host (the Scanner switched off, the app
    // quits). Never touches the tunnel.
    virtual void stopAll() = 0;

    // Set by the coordinator; the host calls them on the GUI thread when availability() or generation()
    // changed (a missing callback is never called).
    std::function<void()> onAvailabilityChanged;
    std::function<void()> onGenerationChanged;
};

} // namespace avpn
