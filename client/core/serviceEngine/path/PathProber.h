// client/core/serviceEngine/path/PathProber.h
// AVPN path engine, stage 2 - the platform's light-probe host as the race (PathRace.h) sees it. [header-only, pure
// contract; no platform types]
//
// An implementation runs light probes beside or before a tunnel (iOS: the in-app host IosHybridScanHost behind the
// build switch AVPN_IOS_APP_SCAN_HOST; macOS / Windows: the service's probe engine; Android: none yet). Rules:
//  - start(): one probe of `path`, bounded by timeoutMs; the result comes back ONCE through
//    ServiceEngine::onProbeResult(stamp, outcome, bytesSpent) on the GUI thread, never from inside start().
//    outcome: ProbeOk (the probe moved its payload through the path - ScanPathProber: a 24 KB body for the AmneziaWG
//    mini-probe and a provider profile, own Xray as its burst) or anything else = not proven (never recorded). bytesSpent = what the host reported (the one byte
//    ledger the Scanner charges).
//  - cancel(): best effort; a result that still comes is dropped by its stamp.
//  - Provider probes take a PROBE seat through the existing batch API and release it; never a session seat.
//  - Nothing here touches the tunnel (no connect, stop, route change).
//  - caps().available == false: no host on this platform / build / server switch - the engine keeps stage-1
//    behaviour exactly (no race, the owner walks one path at a time).
#pragma once

#include "PathRace.h"

namespace avpn::path {

class IPathProber {
public:
    virtual ~IPathProber() = default;
    virtual ProberCaps caps() const = 0;
    // Optional warm-up (no result): the engine calls it when the prober is attached, when the network generation
    // changes and at every tap before a race - the host's caps and the probe session of this network can be fetched
    // ahead, so the adapter needs no timer of its own. Idempotent; never touches the tunnel.
    virtual void prepare(const NetworkKey &net) { Q_UNUSED(net) }
    virtual void start(const ProbeStamp &stamp, const PathCandidate &path, int timeoutMs) = 0;
    virtual void cancel(const ProbeStamp &stamp) = 0;
};

} // namespace avpn::path
