// client/core/serviceEngine/SignedContext.h
// AVPN serviceEngine - Ed25519 detached signature with a domain-separation context. [header-only;
// links Ed25519Verify.cpp]
//
// The backend signs every answer with the /v1/config key (crypto_sign.signing_input). With no context
// the signature covers the exact body bytes (/v1/config, /v1/edges, /v1/bypass-lists - unchanged). An
// answer of another kind is signed over ASCII(context) || 0x0A || body, so it can never be replayed as
// a config body (and the other way round). Contexts in use: "tribe-upstream-lease-v1" (POST
// /v1/upstream/lease), "tribe-scan-manifest-v1" (scan manifest, later). A context is a fixed lower-case
// ASCII label, regex [a-z0-9][a-z0-9.-]{2,63} on both sides; anything else is refused here.
//
// Tests: tests/upstream_nodes_check.cpp (keys generated in the test, no fixtures).
#pragma once

#include "Ed25519Verify.h"

#include <QByteArray>
#include <QRegularExpression>
#include <QString>

namespace avpn {

inline constexpr char kUpstreamLeaseSigContext[] = "tribe-upstream-lease-v1";

// The exact bytes the signature covers (mirror of the backend's signing_input). Empty context = the
// body itself. An invalid context gives an empty array (and verification fails).
inline QByteArray signingInput(const QByteArray &body, const QString &context)
{
    if (context.isEmpty())
        return body;
    static const QRegularExpression re(QStringLiteral("^[a-z0-9][a-z0-9.-]{2,63}$"));
    if (!re.match(context).hasMatch())
        return QByteArray();
    return context.toLatin1() + '\n' + body;
}

// true only for a valid signature by pubHex over signingInput(body, context). Empty context = exactly
// verifyDetached(pubHex, body, sigB64) (today's config path, byte-identical).
inline bool verifyDetachedWithContext(const QString &pubHex, const QString &context, const QByteArray &body,
                                      const QByteArray &sigB64)
{
    if (context.isEmpty())
        return verifyDetached(pubHex, body, sigB64);
    const QByteArray message = signingInput(body, context);
    if (message.isEmpty())
        return false;
    return verifyDetached(pubHex, message, sigB64);
}

} // namespace avpn
