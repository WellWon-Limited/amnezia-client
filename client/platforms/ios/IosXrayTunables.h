#pragma once
// AVPN upstream nodes (plan provider-pool, release A, lane L3; contract client-envelope-contract.md
// section 3): `xray_tunables` of the iOS Xray envelope, from the /v1/config numbers in TuningStore.
// Applies to own Xray sessions too. A number the server does not send is not sent to the extension
// either (absent key = the behaviour before: Go limit Int64.max, hev task-stack-size 20480, hev
// defaults), so nothing changes until the operator publishes the numbers. Clamps: the memory limit
// is the engine's (UpstreamNode.h::xrayMemoryLimitMiBFrom, 20..40, default 30); the hev sizes are
// IosNativePolicy.h (the extension clamps again, XrayTunables.swift).

#include "IosNativePolicy.h"
#include "core/serviceEngine/TuningStore.h"
#include "core/serviceEngine/UpstreamNode.h"

#include <QJsonObject>
#include <QString>

#include <cmath>
#include <limits>

namespace avpn_ios {

inline constexpr char kXrayHevTcpBufferSizeKey[] = "xray_hev_tcp_buffer_size";
inline constexpr char kXrayHevMaxSessionCountKey[] = "xray_hev_max_session_count";
inline constexpr char kXrayHevTaskStackSizeKey[] = "xray_hev_task_stack_size";

// The number of /v1/config `numbers` under key, or NaN when the server did not send it.
inline double xrayTuningNumberOrAbsent(const char *key)
{
    return avpn::TuningStore::numberOr(QLatin1String(key), std::numeric_limits<double>::quiet_NaN());
}

inline bool xrayTuningPresent(double v) { return !std::isnan(v); }

// Getters next to UpstreamNode.h::xrayMemoryLimitMiBTuned (which answers the default when absent):
// these answer -1 when the number is absent, so the envelope can leave the key out.
inline int xrayMemoryLimitMiBConfigured()
{
    const double v = xrayTuningNumberOrAbsent(avpn::kXrayMemoryLimitKey);
    return xrayTuningPresent(v) ? avpn::xrayMemoryLimitMiBFrom(v) : -1;
}
inline int xrayHevTcpBufferSizeConfigured()
{
    const double v = xrayTuningNumberOrAbsent(kXrayHevTcpBufferSizeKey);
    return xrayTuningPresent(v) ? hevTcpBufferSizeFrom(v) : -1;
}
inline int xrayHevMaxSessionCountConfigured()
{
    const double v = xrayTuningNumberOrAbsent(kXrayHevMaxSessionCountKey);
    return xrayTuningPresent(v) ? hevMaxSessionCountFrom(v) : -1;
}
inline int xrayHevTaskStackSizeConfigured()
{
    const double v = xrayTuningNumberOrAbsent(kXrayHevTaskStackSizeKey);
    return xrayTuningPresent(v) ? hevTaskStackSizeFrom(v) : -1;
}

// The `xray_tunables` object; empty = no number configured (the caller then leaves the key out).
inline QJsonObject xrayTunablesForEnvelope()
{
    QJsonObject o;
    if (const int v = xrayMemoryLimitMiBConfigured(); v > 0)
        o.insert(QStringLiteral("memory_limit_mib"), v);
    if (const int v = xrayHevTcpBufferSizeConfigured(); v > 0)
        o.insert(QStringLiteral("hev_tcp_buffer_size"), v);
    if (const int v = xrayHevMaxSessionCountConfigured(); v > 0)
        o.insert(QStringLiteral("hev_max_session_count"), v);
    if (const int v = xrayHevTaskStackSizeConfigured(); v > 0)
        o.insert(QStringLiteral("hev_task_stack_size"), v);
    return o;
}

} // namespace avpn_ios
