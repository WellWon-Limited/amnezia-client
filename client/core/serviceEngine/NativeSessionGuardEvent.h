// Tribe catalog v2 — pure closed-schema native guard receipt parser.
#pragma once

#include "TransportAdapter.h"

#include <QJsonObject>

namespace avpn {

// Shared by the live guard bridge and product relaunch coordinator. Callers retain only this
// typed projection and must never log the raw event (it contains opaque ownership identifiers).
bool parseNativeSessionGuardEvent(const QJsonObject &event,
                                  ConnectionGuardEvent &parsed,
                                  QString &error);

enum class NativeGuardRecoveryAction { Adopt = 0, Stop };
enum class NativeGuardRecoveryKind { Adopted = 0, StoppedReleased, Rejected };

struct NativeGuardRecoveryReceipt {
    NativeGuardRecoveryAction action = NativeGuardRecoveryAction::Stop;
    NativeGuardRecoveryKind kind = NativeGuardRecoveryKind::Rejected;
    ConnectionGuardEvent identity;
};

bool parseNativeSessionGuardRecoveryReceipt(const QJsonObject &receipt,
                                            NativeGuardRecoveryReceipt &parsed,
                                            QString &error);

} // namespace avpn
