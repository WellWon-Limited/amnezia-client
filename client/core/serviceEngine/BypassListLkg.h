// client/core/serviceEngine/BypassListLkg.h
// AVPN server-driven АнтиВПН: LKG-кеш bypass-списков (Task 9) — ЧИСТЫЕ (без сети/Settings/
// QNetworkAccessManager) функции сериализации/парсинга/повторной верификации файла кэша
// и анти-downgrade сравнение версий. Вынесено из BypassListService.cpp в отдельный
// header-only слой специально, чтобы юнит (tests/test_bypass_lkg.cpp) гонял их напрямую.
#pragma once

#include "BypassListTypes.h"
#include "Ed25519Verify.h"

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

namespace avpn {

// Сериализовать LKG-запись (сырое тело + подпись + ETag) в JSON-байты для файла на диске.
// body хранится base64 — исходные байты должны дойти до повторной верификации БЕЗ искажений
// (JSON-текст сам по себе может пройти через нормализацию кодировки/переносов).
inline QByteArray serializeBypassListsLkg(const QByteArray &body, const QByteArray &sigB64,
                                          const QByteArray &etag)
{
    QJsonObject o;
    o.insert(QStringLiteral("body_b64"), QString::fromLatin1(body.toBase64()));
    o.insert(QStringLiteral("sig_b64"), QString::fromLatin1(sigB64));
    o.insert(QStringLiteral("etag"), QString::fromUtf8(etag));
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

// Разобрать JSON LKG-файла в сырые поля (БЕЗ верификации подписи). false — битый/неполный JSON
// (нет обязательного body_b64). sig/etag пустыми быть могут формально, но тогда verify ниже
// закономерно провалится (пустая подпись невалидна для verifyDetached).
inline bool parseBypassListsLkgRaw(const QByteArray &lkgJson, QByteArray &bodyOut,
                                   QByteArray &sigB64Out, QByteArray &etagOut)
{
    const QJsonDocument doc = QJsonDocument::fromJson(lkgJson);
    if (!doc.isObject())
        return false;
    const QJsonObject o = doc.object();
    const QString bodyB64 = o.value(QStringLiteral("body_b64")).toString();
    if (bodyB64.isEmpty())
        return false;
    bodyOut = QByteArray::fromBase64(bodyB64.toLatin1());
    sigB64Out = o.value(QStringLiteral("sig_b64")).toString().toLatin1();
    etagOut = o.value(QStringLiteral("etag")).toString().toUtf8();
    return true;
}

// Анти-downgrade/анти-replay: новая версия допустима, ТОЛЬКО если строго больше сохранённой
// (lkgVersion==0 => LKG ещё нет, любая положительная версия проходит). Строго ">" (НЕ ">="),
// чтобы повторная доставка того же тела не считалась «новее» и не гоняла запись LKG вхолостую.
inline bool isBypassListVersionNewer(int newVersion, int lkgVersion)
{
    return newVersion > lkgVersion;
}

// Полный цикл ЗАГРУЗКИ LKG с диска: JSON → ПОВТОРНАЯ верификация подписи (кеш-файл сам по себе
// НЕ доверенный источник — читаем его как чужой вход) → parseBypassLists. true только если ВСЁ
// прошло; err — причина отказа (для одноразового лога в сервисе). etagOut — ETag из LKG, чтобы
// следующий фетч ушёл с If-None-Match.
inline bool loadVerifiedBypassListsLkg(const QByteArray &lkgJson, const QString &pubKeyHex,
                                       BypassLists &out, QByteArray &etagOut, QString &err)
{
    QByteArray body, sig, etag;
    if (!parseBypassListsLkgRaw(lkgJson, body, sig, etag)) {
        err = QStringLiteral("lkg: malformed json");
        return false;
    }
    if (!verifyDetached(pubKeyHex, body, sig)) {
        err = QStringLiteral("lkg: signature verify failed");
        return false;
    }
    if (!parseBypassLists(body, out, err))
        return false; // err уже заполнен parseBypassLists/валидацией
    etagOut = etag;
    return true;
}

} // namespace avpn
