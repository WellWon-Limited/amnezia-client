// AVPN serviceEngine — device_fingerprint: якорь железа для anti-hijack (угон устройства по
// утёкшему device_id) + anti-farm (фарм триалов переустановкой). Контракт — Tribe-Backend
// api/openapi.yaml 0.7.2 (+ DEVICE-FIRST-SPEC §4.1): optional-поле в POST /v1/trial,
// /v1/code/redeem, /v1/transfer/redeem; мисматч со штампом на строке устройства → 403.
//
// Якоря по платформам (все тихие, без разрешений/диалогов):
//   iOS     — секретный fpSeed из keychain-якоря identity (IdentityAnchor; ThisDeviceOnly).
//             Именно СЕКРЕТ, не hash(installationUuid): fingerprint невычислим из утёкшего
//             device_id — иначе rehome-гейт на iOS был бы декорацией.
//   Android — ANDROID_ID (SSAID, per-app-signing-key): переживает переустановку.
//   macOS   — IOPlatformUUID (плата): переживает переустановку.
//   Windows — MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography): переживает переустановку.
//
// Инварианты (куплены у бэка, FINGERPRINT-HANDOFF):
//   1) стабильность: якорь переживает переустановку и одинаков во всех трёх запросах;
//   2) не достали якорь → поле НЕ слать вообще (случайный fallback = ложные 403 владельцу);
//   3) наружу уходит ТОЛЬКО sha256-hex — сырой якорь не покидает устройство.
#pragma once

#include <QCryptographicHash>
#include <QString>

namespace avpn {

class DeviceFingerprint {
public:
    // sha256-hex платформенного якоря; ПУСТО = якорь не достали → поле в тело не класть.
    // Успешное значение кешируется на процесс (все три запроса шлют одно и то же); провал
    // не кешируется — следующий вызов попробует снова (якоря детерминированы, значение от
    // ретрая не меняется). Звать с потока движка (как enroll/redeem) — как весь serviceEngine.
    static QString get();

    // --- чистая (тестируемая) ---
    // sha256 от UTF-8 якоря, lower-hex (64 симв.,匹 паттерну бэка ^[A-Fa-f0-9._-]{16,128}$).
    // Нормализация = «как есть, байт-в-байт»; НЕ менять НИКОГДА: изменение = другой fingerprint
    // у всего флота = массовые ложные 403 на rehome-гейте.
    static QString hashAnchor(const QString &anchor)
    {
        return QString::fromLatin1(
            QCryptographicHash::hash(anchor.toUtf8(), QCryptographicHash::Sha256).toHex());
    }

private:
    static QString platformAnchor(); // сырой якорь; НИКОГДА не покидает устройство
};

} // namespace avpn
