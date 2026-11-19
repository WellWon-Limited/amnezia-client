// client/core/serviceEngine/path/PathTunables.h
// AVPN path engine (design 2026-11-17 "one mechanism to choose a path", stage 1) - every number of the path
// core in one place. [header-only, no Qt]
//
// ALL DEFAULTS BELOW ARE PRELIMINARY - TO BE CALIBRATED ON DEVICE (design §2 and §8 stage 0: iPhone Air on the
// owner's Wi-Fi and on cellular). They become server numbers later (design §6: "probe, quarantine and budget
// terms are server numbers"); until then the integration passes these defaults.
//
#pragma once

#include <array>

namespace avpn::path {

// One connect attempt (AttemptOwner.h). Server-tunable through TuningStore (ConnectTunables.h::
// attemptTimingsTuned); these are the compiled defaults.
struct AttemptTimings {
    // Start deadline per path kind: from "start path" to "tunnel up" (AmneziaWG: handshake confirmed; Xray and
    // provider: the native side reports connected). Measured on iPhone Air 17-18.11: a working AmneziaWG start
    // reaches data in 4.0-5.7 s in total, own Xray in 2.6-4.6 s, a provider profile in 2.4-3.4 s.
    int awgStartMs = 4500;      // to be calibrated on device
    int xrayStartMs = 5000;     // to be calibrated on device
    int providerStartMs = 6000; // to be calibrated on device (the native start after the seat lease)
    // A provider leg has two phases inside its one start deadline (review E6 of 18.11): the seat lease (its
    // acquisition is bounded by this, ConnectTunables.h::upstreamAcquireTimeoutMsTuned reads the same number;
    // 0.2-0.6 s observed) and then the native start (providerStartMs). With the direct API blocked the cached
    // profile starts only after the lease timed out - the leg's deadline still covers its whole native start.
    int providerLeaseMs = 6000; // device round 4: the server granted in 3.8-4.2 s - sized against that, tunable
    // The one in-tunnel data check: from "tunnel up" to "data proven".
    int dataCheckMs = 4000; // to be calibrated on device
    // The check itself answers by dataCheckMs (complete payload = works, possibly slow; nothing = no data). The
    // owner's own deadline is only a backstop for a check that never answers: dataCheckMs + this. A payload that
    // completed is always judged before a timeout (review E4 of 18.11).
    int checkGraceMs = 1500;
    // A check that could not decide (inconclusive, not interrupted by a suspension) runs again on the same tunnel
    // at most this many times before the leg is given up (nothing recorded either way).
    int maxRechecks = 1;
    // Overall budget of the attempt on one network: nothing proven within it -> honest failure. Stage 1 walks
    // the candidates one at a time, so one tap must be able to walk a hostile network (coordinator 18.11);
    // the 20 s target of the design applies once the probe race exists (stage 2).
    int budgetMs = 45000; // to be calibrated on device
    // At most this many paths are brought up per attempt and network (design §4 "limit of candidates"; it also
    // bounds the provider seats one tap can take).
    int maxPaths = 12;
    // A stop that is never confirmed must not block the attempt: after this long the platform is taken as
    // stopped (an outcome of the platform, never of the path - nothing is recorded). The native stop deadline
    // (IosNativePolicy.h NativeTimings: 10 s).
    int stopConfirmMs = 10000;
    // A gap between two events longer than this is a suspension (the app was suspended, the main thread was
    // stopped): none of it counts against deadlines (review E3 of 18.11). Must exceed the platform tick period
    // (1 s). After it, the leg in flight gets at least resumeGraceMs for the platform's answers to arrive, and a
    // data check that was running is run again on the same tunnel (it did not happen - design R12).
    int clockJumpMs = 2500;
    int resumeGraceMs = 2000;
};

// The evidence store (PathLedger.h).
struct LedgerTunables {
    // Quarantine of a path that failed again on a network: 2 min -> 10 min -> 1 h -> 6 h (design §3); the
    // first failure only makes the path "suspect", the second starts the ladder.
    std::array<long long, 4> quarantineMs { 2LL * 60 * 1000, 10LL * 60 * 1000, 60LL * 60 * 1000,
                                            6LL * 60 * 60 * 1000 };
    // How long a proof through the tunnel ("data ok") and a light probe ("probe ok") count as "working".
    long long dataOkTtlMs = 7LL * 24 * 3600 * 1000;
    long long probeOkTtlMs = 10LL * 60 * 1000;
    // An entry nothing touched for this long is ignored and pruned (the network or the fleet has changed).
    long long evidenceTtlMs = 7LL * 24 * 3600 * 1000;
    // A server refusal or "no free seat" keeps the path out of the first places for this long, without
    // touching the quarantine ladder (it says nothing about the network).
    long long refusalCooldownMs = 2LL * 60 * 1000;
    // Speed of a working path (PathLedger.h "Speed"): the weight of a new time-to-data sample in the decayed average
    // and the half-life of the older value's weight.
    double speedWeight = 0.5;
    long long speedHalfLifeMs = 6LL * 3600 * 1000;
    // Bound of the store (entries = network x path).
    int maxEntries = 512;
};

} // namespace avpn::path
