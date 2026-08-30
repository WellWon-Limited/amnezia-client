// Tribe serviceEngine v2 — strict typed catalog profile -> native Amnezia envelope compilers.
#pragma once

#include "AwgConfigBuilder.h"
#include "TransportAdapter.h"

#include <QStringList>

namespace avpn {

struct NativeProfileCompileOptions {
    // Device-local AWG secret. Only the public half is compared with the signed binding; the
    // private half is inserted after verification and is never accepted from the catalog.
    ClientKeys awgKeys;
    QStringList dnsServers{QStringLiteral("1.1.1.1"), QStringLiteral("1.0.0.1")};
    int splitTunnelType = 0;
    int configVersion = 0;
    qint64 xrayMaxMemoryBytes = 50LL * 1024 * 1024;
    // Resolved coordinator/verifier/auth authorities that local RU-direct policy must never route
    // outside the tunnel. Consumed only by the concrete dispatch policy, not emitted by compilers.
    QStringList protectedTunnelIpLiterals;
};

class NativeProfileCompiler {
public:
    static bool compile(const CatalogCandidate &candidate,
                        const NativeProfileCompileOptions &options,
                        CompiledNativeProfile &compiled,
                        QString &error);

    static bool compileAwg31(const CatalogCandidate &candidate,
                             const NativeProfileCompileOptions &options,
                             CompiledNativeProfile &compiled,
                             QString &error);
    static bool compileXrayRealityVisionTcp(const CatalogCandidate &candidate,
                                            const NativeProfileCompileOptions &options,
                                            CompiledNativeProfile &compiled,
                                            QString &error);

    // Re-check the produced native shape against the typed source. This is deliberately strict:
    // unknown root/core keys, public listeners, extra outbounds/routing/API/log sinks fail closed.
    static bool sanitizeCompiled(const CatalogCandidate &candidate,
                                 const NativeProfileCompileOptions &options,
                                 const CompiledNativeProfile &compiled,
                                 QString &error);
};

} // namespace avpn
