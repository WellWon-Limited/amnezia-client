// client/core/serviceEngine/Ed25519Verify.h
// AVPN: верификация ed25519 detached-подписи серверного конфига (OpenSSL EVP).
#pragma once
#include <QByteArray>
#include <QString>

namespace avpn {

// pubHex — hex 32-байтного ed25519-публичного ключа; body — точные подписанные байты;
// sigB64 — base64 подписи. true только при валидной подписи. Любой битый вход → false.
bool verifyDetached(const QString &pubHex, const QByteArray &body, const QByteArray &sigB64);

} // namespace avpn
