// Tribe catalog v2 — pure ownership decisions at the legacy/v2 composition boundary.
#pragma once

namespace avpn {

inline bool delayedLegacyOwnerMustBlockV2(bool v2Authoritative,
                                          bool teardownAlreadyPending,
                                          bool v2OwnsUserIntent,
                                          bool nativeDisconnected)
{
    return !v2Authoritative && !teardownAlreadyPending && v2OwnsUserIntent
           && !nativeDisconnected;
}

inline bool queuedV2OffMustTearDownLegacy(bool v2Authoritative,
                                         bool legacyOperationInFlight,
                                         bool nativeDisconnected)
{
    return !v2Authoritative && (legacyOperationInFlight || !nativeDisconnected);
}

// After durable v2 authority is restored/published, a late shared VpnConnection callback can still
// reveal a surviving legacy owner. Stop it only while the reducer proves it owns no v2 session or
// guard; otherwise a generic callback is never sufficient authority to tear down exact v2 state.
inline bool authoritativeUnexpectedLegacyOwnerMustStop(bool v2Authoritative,
                                                        bool teardownAlreadyPending,
                                                        bool nativeRecoveryPending,
                                                        bool v2RuntimeOwnsNative,
                                                        bool nativeDisconnected)
{
    return v2Authoritative && !teardownAlreadyPending && !nativeRecoveryPending
           && !v2RuntimeOwnsNative && !nativeDisconnected;
}

} // namespace avpn
