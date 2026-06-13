// AVPN serviceEngine — enrollment: первый вход (POST /v1/trial). Переиспользует сетевой стек форка
// (amnApp->networkManager()), ключи (Identity→WireguardConfigurator::genClientKeys), хранилище
// (SecureAppSettingsRepository). Форк НЕ модифицируем — только зовём его публичные API.
//
// Чистые builders/parsers — inline (тестируются автономно, только QtCore). Сетевой enroll() — в .cpp [IN-FORK].
#pragma once

#include "Identity.h"

#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QSysInfo>
#include <QVariantList>
#include <QVariantMap>

class QNetworkAccessManager;        // fwd (форк отдаёт через amnApp->networkManager())
class SecureAppSettingsRepository;  // fwd (форк)

namespace avpn {

struct TrialResponse {
    QString subscriptionToken;
    QString accountId;
    QString expiresAt;
    qint64  trafficLimit = 0;
};

// AVPN: результат POST /v1/code/redeem (CodeRedeemOut). seatLimit/seatsUsed — для UI «места заняты».
struct CodeRedeemResponse {
    QString subscriptionToken;
    QString accountId;
    QString status;     // trial|active|expired
    QString expiresAt;  // nullable
    int     seatLimit = 0;
    int     seatsUsed = 0;
};

// AVPN: исход redeem — различаем 200 / 401 (неверный код) / 409 (мест нет, есть devices[]).
enum class CodeRedeemResult { Ok, BadCode, SeatLimit, Failed };

// AVPN (Task 13): ответ POST /v1/transfer/redeem (перенос «как SIM» на это устройство).
// Контракт: { subscription_token, account_id, expires_at?, traffic_limit, traffic_used }.
struct TransferRedeemResponse {
    QString subscriptionToken;
    QString accountId;
    QString expiresAt;          // nullable
    qint64  trafficLimit = 0;
    qint64  trafficUsed = 0;
};

// AVPN (Task 13): исход transfer/redeem — 200 / 401 (токен мёртв/истёк) / 409 (мест нет) / прочее.
enum class TransferRedeemResult { Ok, BadToken, SeatLimit, Failed };

// AVPN (Task 13): ответ POST /v1/transfer (генерация переноса). { transfer_token, deep_link }.
struct TransferMintResponse {
    QString transferToken;
    QString deepLink;           // tribe://transfer?t=…
};

class Enrollment {
public:
    // --- чистые (тестируемые) ---

    // Тело POST /v1/trial: { public_key, device_id, platform, model } (model — имя устройства для кабинета)
    static QByteArray buildTrialBody(const QString &publicKey, const QString &deviceId,
                                     const QString &platform, const QString &model = QString())
    {
        QJsonObject o;
        o.insert(QStringLiteral("public_key"), publicKey);
        o.insert(QStringLiteral("device_id"), deviceId);
        o.insert(QStringLiteral("platform"), platform);
        if (!model.isEmpty())
            o.insert(QStringLiteral("model"), model);
        return QJsonDocument(o).toJson(QJsonDocument::Compact);
    }

    // AVPN: имя устройства (показывается в кабинете). Hostname (user-set), фолбэк — продукт.
    static QString deviceModel()
    {
        const QString host = QSysInfo::machineHostName();
        return host.isEmpty() ? QSysInfo::prettyProductName() : host;
    }

    // Разбор ответа TrialOut. false + error при провале.
    static bool parseTrialResponse(const QByteArray &json, TrialResponse &out, QString &error)
    {
        QJsonParseError pe;
        const QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
        if (pe.error != QJsonParseError::NoError) { error = pe.errorString(); return false; }
        if (!doc.isObject()) { error = QStringLiteral("trial response is not an object"); return false; }
        const QJsonObject o = doc.object();
        out.subscriptionToken = o.value(QStringLiteral("subscription_token")).toString();
        out.accountId = o.value(QStringLiteral("account_id")).toString();
        out.expiresAt = o.value(QStringLiteral("expires_at")).toString();
        out.trafficLimit = static_cast<qint64>(o.value(QStringLiteral("traffic_limit")).toDouble());
        if (out.subscriptionToken.isEmpty()) { error = QStringLiteral("missing subscription_token"); return false; }
        return true;
    }

    // AVPN: тело POST /v1/code/redeem (CodeRedeemIn): { code, public_key, device_id, platform, model,
    // evict_device_id? }. evictDeviceId — backend-id из devices[] (1-seat «перенести сюда»).
    static QByteArray buildRedeemBody(const QString &code, const QString &publicKey, const QString &deviceId,
                                      const QString &platform, const QString &model = QString(),
                                      const QString &evictDeviceId = QString())
    {
        QJsonObject o;
        o.insert(QStringLiteral("code"), code);
        o.insert(QStringLiteral("public_key"), publicKey);
        o.insert(QStringLiteral("device_id"), deviceId);
        o.insert(QStringLiteral("platform"), platform);
        if (!model.isEmpty())
            o.insert(QStringLiteral("model"), model);
        if (!evictDeviceId.isEmpty())
            o.insert(QStringLiteral("evict_device_id"), evictDeviceId);
        return QJsonDocument(o).toJson(QJsonDocument::Compact);
    }

    // AVPN: разбор CodeRedeemOut. false + error при провале (нет subscription_token).
    static bool parseRedeemResponse(const QByteArray &json, CodeRedeemResponse &out, QString &error)
    {
        QJsonParseError pe;
        const QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
        if (pe.error != QJsonParseError::NoError) { error = pe.errorString(); return false; }
        if (!doc.isObject()) { error = QStringLiteral("redeem response is not an object"); return false; }
        const QJsonObject o = doc.object();
        out.subscriptionToken = o.value(QStringLiteral("subscription_token")).toString();
        out.accountId = o.value(QStringLiteral("account_id")).toString();
        out.status = o.value(QStringLiteral("status")).toString();
        out.expiresAt = o.value(QStringLiteral("expires_at")).toString();
        out.seatLimit = o.value(QStringLiteral("seat_limit")).toInt();
        out.seatsUsed = o.value(QStringLiteral("seats_used")).toInt();
        if (out.subscriptionToken.isEmpty()) { error = QStringLiteral("missing subscription_token"); return false; }
        return true;
    }

    // AVPN (Task 13): тело POST /v1/transfer/redeem — токен переноса = креденшл (security: []).
    static QByteArray buildTransferRedeemBody(const QString &transferToken, const QString &publicKey,
                                              const QString &deviceId, const QString &platform,
                                              const QString &model = QString())
    {
        QJsonObject o;
        o.insert(QStringLiteral("transfer_token"), transferToken);
        o.insert(QStringLiteral("public_key"), publicKey);
        o.insert(QStringLiteral("device_id"), deviceId);
        o.insert(QStringLiteral("platform"), platform);
        if (!model.isEmpty())
            o.insert(QStringLiteral("model"), model);
        return QJsonDocument(o).toJson(QJsonDocument::Compact);
    }

    // AVPN (Task 13): разбор TransferRedeemOut. false + error при отсутствии subscription_token.
    static bool parseTransferRedeemResponse(const QByteArray &json, TransferRedeemResponse &out, QString &error)
    {
        QJsonParseError pe;
        const QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
        if (pe.error != QJsonParseError::NoError) { error = pe.errorString(); return false; }
        if (!doc.isObject()) { error = QStringLiteral("transfer/redeem response is not an object"); return false; }
        const QJsonObject o = doc.object();
        out.subscriptionToken = o.value(QStringLiteral("subscription_token")).toString();
        out.accountId = o.value(QStringLiteral("account_id")).toString();
        out.expiresAt = o.value(QStringLiteral("expires_at")).toString();
        out.trafficLimit = static_cast<qint64>(o.value(QStringLiteral("traffic_limit")).toDouble());
        out.trafficUsed = static_cast<qint64>(o.value(QStringLiteral("traffic_used")).toDouble());
        if (out.subscriptionToken.isEmpty()) { error = QStringLiteral("missing subscription_token"); return false; }
        return true;
    }

    // AVPN (Task 13): разбор ответа POST /v1/transfer ({ transfer_token, deep_link }).
    static bool parseTransferMintResponse(const QByteArray &json, TransferMintResponse &out, QString &error)
    {
        QJsonParseError pe;
        const QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
        if (pe.error != QJsonParseError::NoError) { error = pe.errorString(); return false; }
        if (!doc.isObject()) { error = QStringLiteral("transfer response is not an object"); return false; }
        const QJsonObject o = doc.object();
        out.transferToken = o.value(QStringLiteral("transfer_token")).toString();
        out.deepLink = o.value(QStringLiteral("deep_link")).toString();
        if (out.transferToken.isEmpty()) { error = QStringLiteral("missing transfer_token"); return false; }
        return true;
    }

    // AVPN: разбор devices[] из тела 409 (device_limit_reached). Каждый элемент — DeviceInfo
    // ({device_id, platform?, label?, last_seen?, is_current}) → QVariantMap для QML-выбора.
    static QVariantList parseDeviceList(const QByteArray &json)
    {
        QVariantList list;
        const QJsonDocument doc = QJsonDocument::fromJson(json);
        if (!doc.isObject())
            return list;
        const QJsonArray arr = doc.object().value(QStringLiteral("devices")).toArray();
        for (const QJsonValue &v : arr) {
            const QJsonObject d = v.toObject();
            QVariantMap m;
            m.insert(QStringLiteral("deviceId"), d.value(QStringLiteral("device_id")).toString());
            m.insert(QStringLiteral("platform"), d.value(QStringLiteral("platform")).toString());
            m.insert(QStringLiteral("label"), d.value(QStringLiteral("label")).toString());
            m.insert(QStringLiteral("lastSeen"), d.value(QStringLiteral("last_seen")).toString());
            m.insert(QStringLiteral("isCurrent"), d.value(QStringLiteral("is_current")).toBool());
            list.append(m);
        }
        return list;
    }

    // Платформа для контракта: ios|android|macos|windows|linux (через Qt, без своих ifdef).
    static QString detectPlatform()
    {
        const QString p = QSysInfo::productType(); // "macos","ios","android","windows","osx",...
        if (p == QLatin1String("ios")) return QStringLiteral("ios");
        if (p == QLatin1String("android")) return QStringLiteral("android");
        if (p == QLatin1String("macos") || p == QLatin1String("osx")) return QStringLiteral("macos");
        if (p == QLatin1String("windows")) return QStringLiteral("windows");
        return QStringLiteral("linux");
    }

    // --- сетевой (in-fork; использует QNetworkAccessManager форка) ---

    // Полный flow: ensure keys → POST {base}/v1/trial → сохранить token в защ. хранилище.
    // baseUrl напр. https://api.tribevpn.com . Возвращает true + out при успехе.
    static bool enroll(QNetworkAccessManager *nam, const QString &baseUrl,
                       Identity &identity, SecureAppSettingsRepository *store,
                       TrialResponse &out, QString &error);

    // GET {base}/v1/subscription с Bearer-токеном. true + body (сырое тело) при 2xx. [IN-FORK]
    static bool fetchSubscription(QNetworkAccessManager *nam, const QString &baseUrl,
                                  const QString &token, QByteArray &body, QString &error);

    // AVPN: POST {base}/v1/code/redeem — вход/восстановление по коду доступа (код = креденшл).
    // 200 → Ok + out + РОТАЦИЯ токена (saveToken). 401 → BadCode. 409 → SeatLimit + devices[] (для
    // UI-выбора кого отключить). Прочее/сеть → Failed + error. Синхронно (QEventLoop, как enroll). [IN-FORK]
    static CodeRedeemResult redeemCode(QNetworkAccessManager *nam, const QString &baseUrl,
                                       Identity &identity, SecureAppSettingsRepository *store,
                                       const QString &code, const QString &evictDeviceId,
                                       CodeRedeemResponse &out, QVariantList &devices, QString &error);

    // AVPN (Task 13): POST {base}/v1/transfer/redeem — принять перенос «как SIM» на ЭТО устройство.
    // Токен переноса САМ является авторизацией (security: []). Тело { transfer_token, public_key,
    // device_id, platform?, model? }. 200 → Ok + out + РОТАЦИЯ токена (saveToken). 401 → BadToken
    // (токен мёртв/истёк). 409 → SeatLimit. Прочее/сеть → Failed + error. Синхронно (QEventLoop). [IN-FORK]
    static TransferRedeemResult redeemTransfer(QNetworkAccessManager *nam, const QString &baseUrl,
                                               Identity &identity, SecureAppSettingsRepository *store,
                                               const QString &transferToken,
                                               TransferRedeemResponse &out, QString &error);

    // AVPN (Task 13): POST {base}/v1/transfer (Bearer authToken) — выпустить одноразовый токен переноса
    // + готовый deep_link (tribe://transfer?t=…) для QR/копирования в UI. true + out при 2xx. [IN-FORK]
    static bool createTransfer(QNetworkAccessManager *nam, const QString &baseUrl,
                               const QString &authToken, TransferMintResponse &out, QString &error);

    // Ключи в защ. хранилище (наш namespace, чтобы не пересекаться с настройками форка).
    static constexpr QLatin1String kTokenKey{"avpn/subscriptionToken"};

    // AVPN: токен храним через SecureQSettings (публичный API форка) — value/setValue у
    // SecureAppSettingsRepository приватные. Org/App из version.h → тот же зашифрованный стор.
    static void    saveToken(const QString &token);
    static QString loadToken();
    static void    clearToken();
};

} // namespace avpn
