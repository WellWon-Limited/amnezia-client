// Tribe serviceEngine v2 — immutable local route/DNS/kill-switch policy compiler.
#pragma once

#include "TransportAdapter.h"

#include "core/utils/routeModes.h"

#include <QJsonObject>
#include <QStringList>

namespace avpn {

// Snapshot on VpnConnection's owner thread. It contains local policy only; signed catalog data
// never controls route exclusions, app bypass, kill-switch state, or DNS masking.
struct NativeConnectionPolicySnapshot {
    bool ruDirectRequested = false;
    QStringList routeExclusions;

    bool appsSplitEnabled = false;
    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QStringList splitApps;

    bool dnsMaskRequested = false;
    bool dnsForwardRequested = false;
    bool dnsForwardWarmup = true;
    QStringList maskDnsServers;
    QStringList splitDnsSuffixes;
    QString splitDnsServer;

    bool includeDesktopKillSwitch = false;
    bool killSwitchEnabled = false;
    QStringList allowedDnsServers;

    // Resolved verification/auth authorities that must stay inside the tunnel when RU-direct is
    // enabled. The network coordinator owns resolution/refresh. An empty set with a non-empty
    // exclusion list is a hard start rejection, not an assumed-safe configuration.
    QStringList protectedTunnelIpLiterals;
};

struct PreparedNativeConnectionPolicy {
    QJsonObject configuration;
    bool splitOn = false;
    bool dnsMaskApplied = false;
};

class NativeConnectionPolicyCompiler {
public:
    static bool compile(const CompiledNativeProfile &compiled,
                        const NativeConnectionPolicySnapshot &snapshot,
                        PreparedNativeConnectionPolicy &prepared,
                        QString &error);

    // Rebuilds the expected post-overlay envelope and compares it byte-for-byte at the JSON value
    // level. This is the final gate immediately before native dispatch.
    static bool sanitizeForDispatch(const CompiledNativeProfile &compiled,
                                    const NativeConnectionPolicySnapshot &snapshot,
                                    const QJsonObject &configuration,
                                    QString &error);
};

} // namespace avpn
