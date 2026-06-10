// AVPN serviceEngine — enrollment: первый вход (POST /v1/trial). Переиспользует сетевой стек форка
// (amnApp->networkManager()), ключи (Identity→WireguardConfigurator::genClientKeys), хранилище
// (SecureAppSettingsRepository). Форк НЕ модифицируем — только зовём его публичные API.
//
// Чистые builders/parsers — inline (тестируются автономно, только QtCore). Сетевой enroll() — в .cpp [IN-FORK].
#pragma once

#include "Identity.h"

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QSysInfo>

class QNetworkAccessManager;        // fwd (форк отдаёт через amnApp->networkManager())
class SecureAppSettingsRepository;  // fwd (форк)

namespace avpn {

struct TrialResponse {
    QString subscriptionToken;
    QString accountId;
    QString expiresAt;
    qint64  trafficLimit = 0;
};

class Enrollment {
public:
    // --- чистые (тестируемые) ---

    // Тело POST /v1/trial: { public_key, device_id, platform }
    static QByteArray buildTrialBody(const QString &publicKey, const QString &deviceId,
                                     const QString &platform)
    {
        QJsonObject o;
        o.insert(QStringLiteral("public_key"), publicKey);
        o.insert(QStringLiteral("device_id"), deviceId);
        o.insert(QStringLiteral("platform"), platform);
        return QJsonDocument(o).toJson(QJsonDocument::Compact);
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
    // baseUrl напр. https://apivpn.wellwon.hk . Возвращает true + out при успехе.
    static bool enroll(QNetworkAccessManager *nam, const QString &baseUrl,
                       Identity &identity, SecureAppSettingsRepository *store,
                       TrialResponse &out, QString &error);

    // GET {base}/v1/subscription с Bearer-токеном. true + body (сырое тело) при 2xx. [IN-FORK]
    static bool fetchSubscription(QNetworkAccessManager *nam, const QString &baseUrl,
                                  const QString &token, QByteArray &body, QString &error);

    // Ключи в защ. хранилище (наш namespace, чтобы не пересекаться с настройками форка).
    static constexpr QLatin1String kTokenKey{"avpn/subscriptionToken"};

    // AVPN: токен храним через SecureQSettings (публичный API форка) — value/setValue у
    // SecureAppSettingsRepository приватные. Org/App из version.h → тот же зашифрованный стор.
    static void    saveToken(const QString &token);
    static QString loadToken();
    static void    clearToken();
};

} // namespace avpn
