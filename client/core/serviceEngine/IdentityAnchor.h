// AVPN serviceEngine — Keychain-якорь идентичности устройства (анти-фрод/анти-потеря, DEVICE-FIRST-SPEC §4).
//
// Identity (installationUuid + WG-ключи + subscription_token) живёт в QSettings и на iOS стирается
// при удалении приложения → переустановка = НОВЫЙ триал (накрутка) и ПОТЕРЯ оплаченных дней.
// Якорь = один блоб в Keychain (сервис "AVPN-Keychain", как SecureQSettings): iOS Keychain переживает
// uninstall, доступ молчаливый (никаких диалогов/разрешений). Восстанавливаем ПОЛНУЮ связку
// (uuid + ключи + токен) → /v1/trial отвечает идемпотентным replay СТАРОГО аккаунта (тот же pubkey —
// не задевает гейт key-rotation бэка).
//
// Правила: стор — ИСТИНА, якорь — резервная копия. Обновление якоря: на старте + при ротации токена
// (Enrollment::saveToken). Восстановление: только когда стор пуст (переустановка).
// Чистые decide/pack/unpack — inline (автономный тест identity_anchor_check.cpp, ТОЛЬКО QtCore);
// Keychain-I/O — в .cpp (гейт AVPN_ANCHOR_PURE_ONLY отключает его для standalone-теста).
#pragma once

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

namespace avpn {

class IdentityAnchor {
public:
    // --- чистые (тестируемые) ---

    enum class Action { None, SaveToAnchor, RestoreFromAnchor };

    // Решение на старте. Стор полон → освежить якорь (токен мог ротироваться). Стор пуст, якорь
    // есть → переустановка: восстановить. Оба пусты → свежее устройство, якорь появится после enroll.
    static Action decide(bool storeHasIdentity, bool anchorHasIdentity)
    {
        if (storeHasIdentity)
            return Action::SaveToAnchor;
        if (anchorHasIdentity)
            return Action::RestoreFromAnchor;
        return Action::None;
    }

    // Блоб якоря — компактный JSON {v, uuid, priv, pub, token[, fpSeed]}. Токен/ключи могут быть
    // пустыми (до первого enroll) — восстановим хотя бы uuid. fpSeed — секрет device_fingerprint
    // (DEVICE-FIRST-SPEC §4.1): наружу уходит ТОЛЬКО sha256(fpSeed); в QSettings/plist сид не
    // попадает никогда (plist бэкапится, сид намеренно нет). Пустой сид ключ не пишет (аддитивно,
    // v не бампаем — старый билд такой блоб читает как раньше).
    static QByteArray packIdentity(const QString &uuid, const QString &privKey,
                                   const QString &pubKey, const QString &token,
                                   const QString &fpSeed = QString())
    {
        QJsonObject o;
        o.insert(QStringLiteral("v"), 1);
        o.insert(QStringLiteral("uuid"), uuid);
        o.insert(QStringLiteral("priv"), privKey);
        o.insert(QStringLiteral("pub"), pubKey);
        o.insert(QStringLiteral("token"), token);
        if (!fpSeed.isEmpty())
            o.insert(QStringLiteral("fpSeed"), fpSeed);
        return QJsonDocument(o).toJson(QJsonDocument::Compact);
    }

    // false + error при мусоре/отсутствии uuid (не затираем стор битым якорем).
    // fpSeed — опциональный выход: блоб старого билда сид не несёт → пустая строка.
    static bool unpackIdentity(const QByteArray &blob, QString &uuid, QString &privKey,
                               QString &pubKey, QString &token, QString &error,
                               QString *fpSeed = nullptr)
    {
        QJsonParseError pe;
        const QJsonDocument doc = QJsonDocument::fromJson(blob, &pe);
        if (pe.error != QJsonParseError::NoError) { error = pe.errorString(); return false; }
        if (!doc.isObject()) { error = QStringLiteral("anchor blob is not an object"); return false; }
        const QJsonObject o = doc.object();
        uuid = o.value(QStringLiteral("uuid")).toString();
        privKey = o.value(QStringLiteral("priv")).toString();
        pubKey = o.value(QStringLiteral("pub")).toString();
        token = o.value(QStringLiteral("token")).toString();
        if (fpSeed)
            *fpSeed = o.value(QStringLiteral("fpSeed")).toString();
        if (uuid.isEmpty()) { error = QStringLiteral("anchor without uuid"); return false; }
        return true;
    }

#ifndef AVPN_ANCHOR_PURE_ONLY
    // --- Keychain-I/O (in-fork; QtKeychain, только Apple-платформы — на прочих no-op) ---

    // Вызвать ОДИН раз рано на старте (после QCoreApplication, до первого использования identity —
    // конструктор AvpnEngineQml). Блокирующие QtKeychain-джобы (~мс, паттерн SecureQSettings) —
    // одноразовая цена на старте, НЕ сетевой nested-loop (правило tribe-engine-net-async не задет).
    static void syncAtStartup();

    // Освежить якорь из стора (после ротации токена — Enrollment::saveToken). Пишет в Keychain
    // ТОЛЬКО если блоб изменился (не дёргаем Keychain на каждый запуск зря). Существующий fpSeed
    // из текущего якоря СОХРАНЯЕТСЯ (стор его не знает — сид живёт только в Keychain).
    static void updateFromStore();

    // device_fingerprint (iOS): вернуть fpSeed из якоря; если его нет — сгенерировать, записать
    // атомарно вместе с identity (тот же блоб, одна запись) и вернуть ТОЛЬКО перечитанное из
    // Keychain значение (read-back). Пусто = не достали/не записали → поле НЕ слать (случайный
    // fallback на каждый запуск дал бы ложные 403 владельцу). Не-iOS → всегда пусто.
    static QString ensureFingerprintSeed();
#endif
};

} // namespace avpn
