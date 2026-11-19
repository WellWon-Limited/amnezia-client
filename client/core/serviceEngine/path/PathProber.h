// client/core/serviceEngine/path/PathProber.h
// AVPN path engine, stage 2 - the platform's light-probe host as the race (PathRace.h) sees it. [header-only, pure
// contract; no platform types]
//
// An implementation runs light probes beside or before a tunnel (iOS: the in-app host IosHybridScanHost behind the
// build switch AVPN_IOS_APP_SCAN_HOST; macOS / Windows: the service's probe engine; Android: none yet). Rules:
//  - start(): one probe of `path`, bounded by timeoutMs; the result comes back ONCE through
//    ServiceEngine::onProbeResult(stamp, outcome, bytesSeen) on the GUI thread, never from inside start().
//    outcome: ProbeOk (the probe moved its payload through the path - ScanPathProber: a 24 KB body for the AmneziaWG
//    mini-probe and a provider profile, own Xray as its burst) or anything else = not proven (never recorded).
//    bytesSeen is for the journal only (what the host's items of this probe showed); nothing is charged by it.
//  - Bytes: every REAL byte of the race's traffic (the host's own counter as deltas, the API calls' bytes) goes out
//    ONCE through the sink the engine sets (setSpendSink); the engine puts it on the race's cap and on the Scanner's
//    hour ledger. A prober never charges a byte anywhere else.
//  - raceEnded(race): the race is over (done, stopped, a new one began): the host scan of that race may be ended.
//  - cancel(): best effort; a result that still comes is dropped by its stamp.
//  - Provider probes take a PROBE seat through the existing batch API and release it; never a session seat.
//  - Nothing here touches the tunnel (no connect, stop, route change).
//  - caps().available == false: no host on this platform / build / server switch - the engine keeps stage-1
//    behaviour exactly (no race, the owner walks one path at a time).
#pragma once

#include "PathRace.h"

#include <functional>

namespace avpn::path {

class IPathProber {
public:
    virtual ~IPathProber() = default;
    virtual ProberCaps caps() const = 0;
    // Optional warm-up (no result): the engine calls it when the prober is attached, when the network generation
    // changes and at every tap before a race - the host's caps and the probe session of this network can be fetched
    // ahead, so the adapter needs no timer of its own. Idempotent; never touches the tunnel.
    virtual void prepare(const NetworkKey &net) { Q_UNUSED(net) }
    // Every real byte, with the race it belongs to (the hour ledger takes all, the race's cap only its own).
    virtual void setSpendSink(std::function<void(quint64 race, qint64 bytes)> sink) { Q_UNUSED(sink) }
    // A cancelled probe's spend is final (see PathRace::settled). A prober that returns true from holdsAfterCancel() calls the
    // sink when that is so; any other prober's cancel settles at once (the engine does it).
    virtual bool holdsAfterCancel() const { return false; }
    virtual void setSettleSink(std::function<void(const ProbeStamp &)> sink) { Q_UNUSED(sink) }
    virtual void raceEnded(quint64 race) { Q_UNUSED(race) }
    virtual void start(const ProbeStamp &stamp, const PathCandidate &path, int timeoutMs) = 0;
    virtual void cancel(const ProbeStamp &stamp) = 0;
    // The most one probe of each kind can cost on the wire as this host runs it - every part of it (an Xray burst),
    // its handshakes, a provider's seat batch answer with its config. The race pays a probe's cost from its byte cap
    // for admission (PathRace.h: spent + held + its own bound <= cap), so these must be upper bounds.
    virtual PathRace::Costs costs() const { return PathRace::Costs{}; }
};

} // namespace avpn::path
