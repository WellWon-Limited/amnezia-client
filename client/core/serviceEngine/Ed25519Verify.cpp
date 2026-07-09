// client/core/serviceEngine/Ed25519Verify.cpp
#include "Ed25519Verify.h"

#include <openssl/evp.h>

namespace avpn {

bool verifyDetached(const QString &pubHex, const QByteArray &body, const QByteArray &sigB64)
{
    // Строгая проверка hex: fromHex молча выбрасывает невалидные символы, поэтому
    // требуем ровно 64 hex-символа И round-trip (стрей/выпавшие символы завалят сверку).
    const QByteArray pubLatin = pubHex.toLatin1();
    const QByteArray raw = QByteArray::fromHex(pubLatin);
    if (raw.size() != 32 || pubLatin.size() != 64 || raw.toHex() != pubLatin.toLower())
        return false;

    // Строгий base64: AbortOnBase64DecodingErrors ловит мусорные символы,
    // которые обычный fromBase64 молча проглатывает.
    const auto dec = QByteArray::fromBase64Encoding(
        sigB64, QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    if (dec.decodingStatus != QByteArray::Base64DecodingStatus::Ok)
        return false;
    const QByteArray sig = dec.decoded;
    if (sig.size() != 64)
        return false;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char *>(raw.constData()), raw.size());
    if (!pkey)
        return false;

    bool ok = false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        // Ed25519 — one-shot: DigestVerifyInit с nullptr md, затем DigestVerify.
        if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
            ok = EVP_DigestVerify(
                     ctx,
                     reinterpret_cast<const unsigned char *>(sig.constData()), sig.size(),
                     reinterpret_cast<const unsigned char *>(body.constData()), body.size()) == 1;
        }
        EVP_MD_CTX_free(ctx);
    }
    EVP_PKEY_free(pkey);
    return ok;
}

} // namespace avpn
