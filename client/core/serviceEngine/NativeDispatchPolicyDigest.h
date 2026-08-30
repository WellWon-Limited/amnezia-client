// Tribe serviceEngine v2 — cross-platform digest of the exact native dispatch policy.
#pragma once

#include "NativeConnectionPolicy.h"

#include <QByteArray>
#include <QJsonObject>

namespace avpn {

inline constexpr char kNativeDispatchPolicySchema[] = "native_dispatch_policy_v1";

// Fixed-order UTF-8 length-prefixed records avoid JSON member-order/numeric-rendering drift
// between Qt, Kotlin and Swift. Native recovery implementations mirror this exact encoder.
bool encodeNativeDispatchPolicyV1(const CompiledNativeProfile &compiled,
                                  const NativeConnectionPolicySnapshot &snapshot,
                                  const QJsonObject &configurationWithoutAuthority,
                                  QByteArray &canonicalBytes,
                                  QString &error);

bool nativeDispatchPolicySha256(const CompiledNativeProfile &compiled,
                                const NativeConnectionPolicySnapshot &snapshot,
                                const QJsonObject &configurationWithoutAuthority,
                                QByteArray &digest,
                                QString &error);

} // namespace avpn
