#pragma once
// AVPN (floor of "tap -> data proven", 19.11.2026): one rule for the first seconds of every data check through a
// freshly raised tunnel - the own-server whoami (WhoamiVerdict.h::whoamiNext) and the provider probe
// (UpstreamEngine.h::decideUpstreamEarlyRetry), and the provisional seat confirmation (UpstreamLeaseMachine.h).
//
// The check is sent as soon as the tunnel is reported up - no wait by the clock. The 800 ms "routes/DNS of a fresh
// tunnel settle" delay (Xray verify of 02.09, copied into whoami 05.11 and the provider check 14.11) guarded a race
// nobody measured on the current path: on iOS the system reports Connected only after the extension's network
// settings (routes, DNS) are applied, and AmneziaWG only after its handshake. What remains of that race shows as a
// try that got nothing at all (no route / DNS not answered / connection refused or reset before any byte), and such
// a try is retried at once on a short growing spacing inside the SAME check budget, so the wait is paid only when
// the race really happens. A provider profile's first-second refusals (lab 14.11 D3) are the same class of failure.
// No timer of its own: the caller's check loop runs it; the caller's clock gives budgetLeftMs. Pure.

#include <QtGlobal>

namespace avpn {

// Spacing before the n-th retry (n >= 1): 300, 600, 1200, 2000, 2000, ... ms.
inline constexpr qint64 kDataCheckRetryBaseMs = 300;
inline constexpr qint64 kDataCheckRetryCapMs = 2000;
// A retry is only worth it when at least this much of the budget is left after the spacing.
inline constexpr qint64 kDataCheckRetryMinLeftMs = 1000;

inline qint64 dataCheckRetryDelayMs(int retryNumber)
{
    const int n = qBound(1, retryNumber, 16);
    return qMin<qint64>(kDataCheckRetryBaseMs << (n - 1), kDataCheckRetryCapMs);
}

struct DataCheckRetry {
    bool retry = false; // false = the outcome of this try is the check's outcome
    qint64 delayMs = 0; // retry: wait this long, then the next try
};

// notYet = this try got nothing at all (the caller's classification); retriesSoFar = retries already made in this
// check; budgetLeftMs = what is left of the check's budget now.
inline DataCheckRetry decideDataCheckRetry(bool notYet, int retriesSoFar, qint64 budgetLeftMs)
{
    DataCheckRetry d;
    if (!notYet)
        return d;
    const qint64 delay = dataCheckRetryDelayMs(retriesSoFar + 1);
    if (budgetLeftMs - delay < kDataCheckRetryMinLeftMs)
        return d;
    d.retry = true;
    d.delayMs = delay;
    return d;
}

} // namespace avpn
