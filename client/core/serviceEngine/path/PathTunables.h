// client/core/serviceEngine/path/PathTunables.h
// AVPN path engine (design 2026-11-17 "one mechanism to choose a path", stage 1) - every number of the path
// core in one place. [header-only, no Qt]
//
// ALL DEFAULTS BELOW ARE PRELIMINARY - TO BE CALIBRATED ON DEVICE (design §2 and §8 stage 0: iPhone Air on the
// owner's Wi-Fi and on cellular). They become server numbers later (design §6: "probe, quarantine and budget
// terms are server numbers"); until then the integration passes these defaults.
//
// Nothing outside path/ reads these values yet: the core is not wired into the engine in this step.
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
    int providerStartMs = 6000; // to be calibrated on device (includes the seat lease, 0.2-0.6 s observed)
    // The one in-tunnel data check: from "tunnel up" to "data proven".
    int dataCheckMs = 4000; // to be calibrated on device
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
    // A gap between two events longer than this is a clock jump (the app was suspended, the main thread was
    // stopped): only this much of it counts against deadlines. Must exceed the platform tick period (1 s).
    int clockJumpMs = 2500;
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
    // Bound of the store (entries = network x path).
    int maxEntries = 512;
};

} // namespace avpn::path
