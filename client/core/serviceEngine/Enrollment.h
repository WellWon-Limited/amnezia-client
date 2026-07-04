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
#include <QUrl>
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
    QString webLink;            // https://tribevpn.com/transfer?t=… (опционально; TRANSFER-KEYS-BACKEND-HANDOFF §4)
    int     expiresInS = 0;     // TTL токена для таймера в модалке (0 = бэк ещё не отдаёт)
};

// AVPN (grant-ключи, TRANSFER-KEYS-BACKEND-HANDOFF §3.B2): ответ POST /v1/key/redeem —
// промо/подарок/компенсация вида TRIBE-XXXX-XXXX-XXXX. Начисление на ТЕКУЩИЙ аккаунт (Bearer),
// токен НЕ ротируется (в отличие от code/redeem — там код=логин).
struct GrantKeyResponse {
    int     grantedDays = 0;
    double  grantedGib = 0;
    QString plan;       // пусто = план не менялся
    QString newExpiry;
};

// AVPN (grant-ключи): исход /v1/key/redeem — 200 / 404 (нет такого) / 409 (уже использован) /
// 410 (истёк или отозван) / прочее.
enum class GrantKeyResult { Ok, NotFound, AlreadyUsed, Expired, Failed };

// AVPN (оплата): ответ POST /v1/cabinet/web-link — одноразовый авто-логин в web-кабинет.
// Контракт: { url: "https://tribevpn.com/account?wl=<token>", expires_in } (wl single-use, TTL ~90с).
struct WebLinkResponse {
    QString url;
    int     expiresIn = 0;
};

// AVPN (auth self-heal): исход запроса к /v1/subscription по HTTP-коду + сетевому флагу.
// Transferred (410) — устройство перенесено «как SIM» на другое (TRANSFER-KEYS-BACKEND-HANDOFF
// §3.B1.4): терминально, НЕ лечится ре-энроллом (иначе молча выбили бы себе новый триал).
enum class FetchOutcome { Ok, Unauthorized, RateLimited, NetworkError, HttpError, Transferred };

// AVPN (auth self-heal): что делать после запроса с токеном.
//   Proceed           — успех, работаем дальше;
//   ReEnrollThenRetry — токен мёртв (401) и он из стора → сбросить токен + один ре-энролл + ретрай;
//   Fail              — отдать ошибку (свежий токен всё равно 401 / уже ретраили / сеть / лимит).
// Лечит корень бага «subscription unauthorized (token)»: стейл-токен после ротации secret на бэкенде.
enum class AuthRecoveryAction { Proceed, ReEnrollThenRetry, Fail };

class Enrollment {
public:
    // --- чистые (тестируемые) ---

    // Тело POST /v1/trial: { public_key, device_id, platform, model, referral_code? }. referral_code —
    // опциональная реферал-атрибуция (код из deep-link /r/<code> друзья или /a/<code> блогеры). LIVE.
    static QByteArray buildTrialBody(const QString &publicKey, const QString &deviceId,
                                     const QString &platform, const QString &model = QString(),
                                     const QString &referralCode = QString())
    {
        QJsonObject o;
        o.insert(QStringLiteral("public_key"), publicKey);
        o.insert(QStringLiteral("device_id"), deviceId);
        o.insert(QStringLiteral("platform"), platform);
        if (!model.isEmpty())
            o.insert(QStringLiteral("model"), model);
        if (!referralCode.isEmpty())
            o.insert(QStringLiteral("referral_code"), referralCode.trimmed());
        return QJsonDocument(o).toJson(QJsonDocument::Compact);
    }

    // AVPN (auth self-heal): классификация исхода запроса к /v1/subscription по HTTP-коду.
    // Сетевой сбой (код 0 + netErr) важен только когда HTTP-кода нет; при наличии кода решает код
    // (401 → Unauthorized даже если выставлен netErr). Зеркалит ветвление в fetchSubscription().
    static FetchOutcome classifyFetch(int httpCode, bool hadNetworkError)
    {
        if (httpCode == 0 && hadNetworkError)  return FetchOutcome::NetworkError;
        if (httpCode == 401)                   return FetchOutcome::Unauthorized;
        if (httpCode == 410)                   return FetchOutcome::Transferred; // перенос «как SIM» (handoff §3.B1.4)
        if (httpCode == 429)                   return FetchOutcome::RateLimited;
        if (httpCode >= 200 && httpCode < 300) return FetchOutcome::Ok;
        return FetchOutcome::HttpError;
    }

    // AVPN (auth self-heal): решение о восстановлении. 401 лечим РОВНО для токена из стора и РОВНО
    // один раз — иначе петля enroll↔401. Сеть/лимит/HTTP токен не трогают (важно для LKG-кэша).
    // Transferred (410) НЕ лечим намеренно: перенос — законное состояние, ре-энролл здесь молча
    // выбил бы новый триал (анти-фрод дыра + ломает «подписка полностью мигрировала»).
    static AuthRecoveryAction decideAuthRecovery(FetchOutcome outcome, bool tokenFromStore,
                                                 bool alreadyReEnrolled)
    {
        if (outcome == FetchOutcome::Ok)
            return AuthRecoveryAction::Proceed;
        if (outcome == FetchOutcome::Unauthorized && tokenFromStore && !alreadyReEnrolled)
            return AuthRecoveryAction::ReEnrollThenRetry;
        return AuthRecoveryAction::Fail;
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
        // опциональные поля (бэк докатит по TRANSFER-KEYS-BACKEND-HANDOFF) — отсутствие НЕ ошибка
        out.webLink = o.value(QStringLiteral("web_link")).toString();
        out.expiresInS = o.value(QStringLiteral("expires_in_s")).toInt(0);
        if (out.transferToken.isEmpty()) { error = QStringLiteral("missing transfer_token"); return false; }
        return true;
    }

    // AVPN (оплата): разбор ответа POST /v1/cabinet/web-link ({ url, expires_in }).
    // false + error при провале (UI уходит на fallback https://tribevpn.com/account).
    static bool parseWebLinkResponse(const QByteArray &json, WebLinkResponse &out, QString &error)
    {
        QJsonParseError pe;
        const QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
        if (pe.error != QJsonParseError::NoError) { error = pe.errorString(); return false; }
        if (!doc.isObject()) { error = QStringLiteral("web-link response is not an object"); return false; }
        const QJsonObject o = doc.object();
        out.url = o.value(QStringLiteral("url")).toString();
        out.expiresIn = o.value(QStringLiteral("expires_in")).toInt();
        if (out.url.isEmpty()) { error = QStringLiteral("missing url"); return false; }
        return true;
    }

    // AVPN (оплата): дописать device_uuid=<install id> к URL кабинета (кабинет откроет шит тарифов
    // на этом устройстве). URL от бэка уже несёт ?wl=… → &; голый fallback → ?. Пустой uuid — no-op.
    static QString appendDeviceUuid(const QString &url, const QString &deviceUuid)
    {
        if (deviceUuid.isEmpty())
            return url;
        const QString sep = url.contains(QLatin1Char('?')) ? QStringLiteral("&") : QStringLiteral("?");
        return url + sep + QStringLiteral("device_uuid=")
               + QString::fromLatin1(QUrl::toPercentEncoding(deviceUuid));
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
    // outcome (необяз.) — машиночитаемый исход (classifyFetch) для авто-хила 401 в startFlow/bootstrap.
    static bool fetchSubscription(QNetworkAccessManager *nam, const QString &baseUrl,
                                  const QString &token, QByteArray &body, QString &error,
                                  FetchOutcome *outcome = nullptr);

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

    // AVPN (grant-ключи): POST {base}/v1/key/redeem (Bearer authToken) — активировать промо/подарочный/
    // компенсационный ключ TRIBE-XXXX-XXXX-XXXX на ТЕКУЩИЙ аккаунт. Токен НЕ ротируется. Бэк — по
    // TRANSFER-KEYS-BACKEND-HANDOFF §3.B2 (до деплоя эндпоинта бэк ответит 404 = «ключ не найден»).
    static GrantKeyResult redeemGrantKey(QNetworkAccessManager *nam, const QString &baseUrl,
                                         const QString &authToken, const QString &key,
                                         GrantKeyResponse &out, QString &error);

    // AVPN (grant-ключи): разбор ответа /v1/key/redeem ({granted_days, granted_gib, plan, new_expiry}).
    static bool parseGrantKeyResponse(const QByteArray &json, GrantKeyResponse &out, QString &error)
    {
        QJsonParseError pe;
        const QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
        if (pe.error != QJsonParseError::NoError) { error = pe.errorString(); return false; }
        if (!doc.isObject()) { error = QStringLiteral("key/redeem response is not an object"); return false; }
        const QJsonObject o = doc.object();
        out.grantedDays = o.value(QStringLiteral("granted_days")).toInt(0);
        out.grantedGib = o.value(QStringLiteral("granted_gib")).toDouble(0);
        out.plan = o.value(QStringLiteral("plan")).toString();
        out.newExpiry = o.value(QStringLiteral("new_expiry")).toString();
        return true;
    }

    // Ключи в защ. хранилище (наш namespace, чтобы не пересекаться с настройками форка).
    static constexpr QLatin1String kTokenKey{"avpn/subscriptionToken"};
    // AVPN (рефералы): код приглашения из deep-link /r/<code>(друзья)|/a/<code>(блогеры), сохранён
    // до ПЕРВОГО /v1/trial (first-touch). Бэк сам различит peer/affiliate по коду.
    static constexpr QLatin1String kReferralKey{"avpn/pendingReferral"};

    // AVPN: токен храним через SecureQSettings (публичный API форка) — value/setValue у
    // SecureAppSettingsRepository приватные. Org/App из version.h → тот же зашифрованный стор.
    static void    saveToken(const QString &token);
    static QString loadToken();
    static void    clearToken();
    // AVPN (рефералы): pending-код приглашения. Пишет мост (AvpnDeepLinkBridge) при открытии /r//a/;
    // читает+чистит enroll() (передаёт в referral_code тела /v1/trial). Не секрет, тот же стор.
    static void    savePendingReferral(const QString &code);
    static QString loadPendingReferral();
    static void    clearPendingReferral();
};

} // namespace avpn
