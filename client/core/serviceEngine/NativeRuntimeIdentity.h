// Tribe serviceEngine v2 — pure opaque native runtime session ownership gate.
#pragma once

#include "dto/Catalog.h"

#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>

namespace avpn {

enum class NativeRuntimeStatusDisposition {
    Accepted = 0,
    IgnoredStaleSession,
    RejectedMalformed,
};

struct NativeRuntimeStatus {
    QString sessionId;
    TransportKind transport = TransportKind::Unknown;
    QString state;
};

class NativeRuntimeIdentityGate {
public:
    void resetForDispatch(TransportKind transport, const QString &expectedSessionId)
    {
        m_transport = transport;
        m_expectedSessionId = expectedSessionId;
        m_seenExpectedSession = false;
    }

    void clear()
    {
        m_transport = TransportKind::Unknown;
        m_expectedSessionId.clear();
        m_seenExpectedSession = false;
    }

    NativeRuntimeStatusDisposition consume(const QJsonObject &object,
                                           NativeRuntimeStatus &status)
    {
        status = {};
        static const QRegularExpression opaqueId(
            QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{7,191}$"));
        static const QSet<QString> states = {
            QStringLiteral("starting"), QStringLiteral("running"),
            QStringLiteral("stopping"), QStringLiteral("stopped"),
            QStringLiteral("reconnecting"), QStringLiteral("failed"),
            QStringLiteral("unknown"),
        };
        const QString sessionId = object.value(QStringLiteral("session_id")).toString();
        const TransportKind transport = transportKindFromName(
            object.value(QStringLiteral("protocol")).toString());
        const QString state = object.value(QStringLiteral("runtime_state")).toString();
        if (m_transport == TransportKind::Unknown
            || object.value(QStringLiteral("type")).toString()
                   != QLatin1String("tunnel_runtime_status_v1")
            || !object.value(QStringLiteral("schema")).isDouble()
            || object.value(QStringLiteral("schema")).toDouble() != 1.0
            || !opaqueId.match(sessionId).hasMatch() || transport != m_transport
            || !states.contains(state)) {
            return NativeRuntimeStatusDisposition::RejectedMalformed;
        }
        // Expected identity is allocated by the platform PREPARE/ARM transaction before native
        // activation. Never trust-on-first-use a callback: a delayed old terminal may arrive first.
        if (m_expectedSessionId.isEmpty() || sessionId != m_expectedSessionId)
            return NativeRuntimeStatusDisposition::IgnoredStaleSession;
        m_seenExpectedSession = true;
        status = {sessionId, transport, state};
        return NativeRuntimeStatusDisposition::Accepted;
    }

    QString boundSessionId() const
    { return m_seenExpectedSession ? m_expectedSessionId : QString{}; }

private:
    TransportKind m_transport = TransportKind::Unknown;
    QString m_expectedSessionId;
    bool m_seenExpectedSession = false;
};

} // namespace avpn
