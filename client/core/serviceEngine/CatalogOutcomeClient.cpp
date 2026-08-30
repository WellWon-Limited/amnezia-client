#include "CatalogOutcomeClient.h"

#include "SignedEnvelope.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSet>
#include <QTimer>

namespace avpn {
namespace {

bool exactKeys(const QJsonObject &object, const QSet<QString> &required,
               const QSet<QString> &optional = {})
{
    for (const QString &key : required)
        if (!object.contains(key)) return false;
    for (auto it = object.constBegin(); it != object.constEnd(); ++it)
        if (!required.contains(it.key()) && !optional.contains(it.key())) return false;
    return true;
}

bool schemaOne(const QJsonValue &value)
{
    return value.isDouble() && value.toDouble() == 1.0;
}

bool noStore(const QHash<QByteArray, QByteArray> &headers)
{
    QSet<QByteArray> tokens;
    const QList<QByteArray> parts = headers.value(QByteArrayLiteral("cache-control"))
                                        .toLower().split(',');
    for (QByteArray part : parts) {
        part = part.trimmed();
        if (part.isEmpty() || tokens.contains(part)) return false;
        if (part != QByteArrayLiteral("private")
            && part != QByteArrayLiteral("no-store")
            && part != QByteArrayLiteral("no-cache")
            && part != QByteArrayLiteral("max-age=0")) return false;
        tokens.insert(part);
    }
    return tokens.contains(QByteArrayLiteral("private"))
           && tokens.contains(QByteArrayLiteral("no-store"));
}

bool retryHeader(const QHash<QByteArray, QByteArray> &headers, int &seconds)
{
    const QByteArray raw = headers.value(QByteArrayLiteral("retry-after")).trimmed();
    static const QRegularExpression decimal(QStringLiteral("^[1-9][0-9]{0,2}$"));
    if (!decimal.match(QString::fromLatin1(raw)).hasMatch()) return false;
    bool ok = false;
    seconds = raw.toInt(&ok);
    return ok && seconds >= 1 && seconds <= 300
           && raw == QByteArray::number(seconds);
}

bool parseV2Error(const QByteArray &body, QJsonObject &object, QString &error, int limit)
{
    QJsonDocument document;
    if (!parseStrictJsonDocument(body, document, error, limit) || !document.isObject())
        return false;
    object = document.object();
    const QSet<QString> required{QStringLiteral("schema_version"),
                                 QStringLiteral("code"), QStringLiteral("message")};
    const QSet<QString> optional{QStringLiteral("retry_after"), QStringLiteral("reason")};
    return exactKeys(object, required, optional)
           && schemaOne(object.value(QStringLiteral("schema_version")))
           && object.value(QStringLiteral("code")).isString()
           && object.value(QStringLiteral("message")).isString()
           && !object.value(QStringLiteral("message")).toString().isEmpty()
           && object.value(QStringLiteral("message")).toString().size() <= 255;
}

} // namespace

bool parseCatalogOutcomeHttpResponse(const CatalogOutcomeHttpResponse &response,
                                     CatalogOutcomeUploadResult &result,
                                     QString &error, int maximumBodyBytes)
{
    result = {};
    error.clear();
    const int limit = qBound(1024, maximumBodyBytes, 64 * 1024);
    if (response.status == 0 || response.transportFailed) {
        result.kind = CatalogOutcomeUploadKind::NetworkUnavailable;
        return true;
    }
    if (response.status >= 300 && response.status < 400) {
        error = QStringLiteral("outcome redirect rejected");
        return false;
    }
    if (response.body.isEmpty() || response.body.size() > limit
        || !noStore(response.headers)
        || response.headers.value(QByteArrayLiteral("content-type")).trimmed().toLower()
               != QByteArrayLiteral("application/json")) {
        error = QStringLiteral("outcome response body/cache/content-type rejected");
        return false;
    }
    if (response.status == 200) {
        if (response.headers.contains(QByteArrayLiteral("retry-after"))) {
            error = QStringLiteral("outcome ack contains retry header");
            return false;
        }
        QJsonDocument document;
        if (!parseStrictJsonDocument(response.body, document, error, limit)
            || !document.isObject()) return false;
        const QJsonObject object = document.object();
        const QSet<QString> keys{QStringLiteral("schema_version"),
                                 QStringLiteral("accepted"), QStringLiteral("duplicate")};
        if (!exactKeys(object, keys)
            || !schemaOne(object.value(QStringLiteral("schema_version")))
            || !object.value(QStringLiteral("accepted")).isBool()
            || !object.value(QStringLiteral("accepted")).toBool()
            || !object.value(QStringLiteral("duplicate")).isBool()) {
            error = QStringLiteral("outcome ack schema rejected");
            return false;
        }
        result.kind = CatalogOutcomeUploadKind::Acknowledged;
        result.duplicate = object.value(QStringLiteral("duplicate")).toBool();
        return true;
    }

    QJsonObject object;
    if (!parseV2Error(response.body, object, error, limit)) {
        error = QStringLiteral("outcome v2 error schema rejected");
        return false;
    }
    const QString code = object.value(QStringLiteral("code")).toString();
    result.serverCode = code.left(96);
    const bool hasRetry = object.contains(QStringLiteral("retry_after"));
    const bool hasRetryHeader = response.headers.contains(QByteArrayLiteral("retry-after"));
    int bodyRetry = 0, headerRetry = 0;
    if (hasRetry) {
        const QJsonValue value = object.value(QStringLiteral("retry_after"));
        const double raw = value.toDouble(-1);
        bodyRetry = int(raw);
        if (!value.isDouble() || raw != bodyRetry || bodyRetry < 1 || bodyRetry > 300)
            return false;
    }
    if (hasRetry != hasRetryHeader
        || (hasRetry && (!retryHeader(response.headers, headerRetry)
                         || headerRetry != bodyRetry))) {
        error = QStringLiteral("outcome Retry-After mismatch");
        return false;
    }
    if (response.status == 429 && code == QLatin1String("rate_limited") && hasRetry) {
        result.kind = CatalogOutcomeUploadKind::Retryable;
        result.retryAfterS = bodyRetry;
        return true;
    }
    if (response.status == 503 && code == QLatin1String("temporarily_unavailable")
        && hasRetry) {
        result.kind = CatalogOutcomeUploadKind::Retryable;
        result.retryAfterS = bodyRetry;
        return true;
    }
    if (response.status == 401 && code == QLatin1String("auth_invalid") && !hasRetry) {
        result.kind = CatalogOutcomeUploadKind::AuthenticationRequired;
        return true;
    }
    if (response.status == 410 && code == QLatin1String("device_revoked") && !hasRetry) {
        result.kind = CatalogOutcomeUploadKind::AuthenticationRequired;
        return true;
    }
    static const QSet<QString> staleCodes{
        QStringLiteral("audience_mismatch"), QStringLiteral("catalog_stale"),
        QStringLiteral("context_mismatch"), QStringLiteral("generation_mismatch"),
        QStringLiteral("binding_stale")};
    if (response.status == 409 && staleCodes.contains(code) && !hasRetry) {
        result.kind = CatalogOutcomeUploadKind::StaleAuthority;
        return true;
    }
    if (response.status == 400 && code == QLatin1String("invalid_request") && !hasRetry) {
        result.kind = CatalogOutcomeUploadKind::ProtocolError;
        return true;
    }
    error = QStringLiteral("outcome HTTP status/code mismatch");
    return false;
}

CatalogOutcomeClient::CatalogOutcomeClient(QNetworkAccessManager *network, QObject *parent,
                                           int timeoutMs, int maximumBodyBytes)
    : QObject(parent), m_network(network), m_timer(new QTimer(this)),
      m_timeoutMs(qBound(3000, timeoutMs, 30000)),
      m_maximumBodyBytes(qBound(1024, maximumBodyBytes, 64 * 1024))
{
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        if (!m_reply || !m_activeOperation) return;
        const quint64 operation = m_activeOperation;
        const QString eventId = m_activeEventId;
        reset(m_reply, true);
        deliver({operation, eventId, CatalogOutcomeUploadKind::NetworkUnavailable});
    });
}

CatalogOutcomeClient::~CatalogOutcomeClient()
{
    m_observer = nullptr;
    if (m_reply) reset(m_reply, true);
}

bool CatalogOutcomeClient::start(const QUrl &apiBaseUrl, QByteArray bearerToken,
                                 const CatalogOutcomeEvent &event,
                                 quint64 &operation, QString &error)
{
    operation = 0;
    error.clear();
    if (!m_network || m_reply || !apiBaseUrl.isValid()
        || apiBaseUrl.scheme() != QLatin1String("https") || apiBaseUrl.host().isEmpty()
        || !apiBaseUrl.userInfo().isEmpty() || !apiBaseUrl.query().isEmpty()
        || !apiBaseUrl.fragment().isEmpty()
        || (!apiBaseUrl.path().isEmpty() && apiBaseUrl.path() != QLatin1String("/"))) {
        error = QStringLiteral("outcome endpoint unavailable/busy");
        return false;
    }
    if (bearerToken.isEmpty() || bearerToken.size() > 8192
        || bearerToken.contains('\r') || bearerToken.contains('\n')) {
        error = QStringLiteral("outcome bearer unavailable");
        return false;
    }
    QJsonObject body;
    if (!buildCatalogOutcomeUpload(event, body, error)) return false;
    const QByteArray encoded = QJsonDocument(body).toJson(QJsonDocument::Compact);
    if (encoded.size() > 16 * 1024) {
        error = QStringLiteral("outcome request exceeds local bound");
        return false;
    }
    QUrl endpoint = apiBaseUrl;
    endpoint.setPath(QStringLiteral("/v2/outcomes"));
    QNetworkRequest request(endpoint);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setRawHeader(QByteArrayLiteral("Accept"), QByteArrayLiteral("application/json"));
    request.setRawHeader(QByteArrayLiteral("Authorization"),
                         QByteArrayLiteral("Bearer ") + bearerToken);
    request.setRawHeader(QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("no-store"));
    request.setRawHeader(QByteArrayLiteral("Pragma"), QByteArrayLiteral("no-cache"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setTransferTimeout(m_timeoutMs);
    QNetworkReply *reply = m_network->post(request, encoded);
    bearerToken.fill('\0');
    if (!reply) {
        error = QStringLiteral("outcome transport did not create reply");
        return false;
    }
    if (++m_counter == 0) ++m_counter;
    m_activeOperation = m_counter;
    m_activeEventId = event.eventId;
    m_reply = reply;
    m_body.clear();
    reply->setReadBufferSize(qint64(m_maximumBodyBytes) + 1);
    connect(reply, &QIODevice::readyRead, this,
            [this, reply, op = m_activeOperation]() { consume(reply, op); });
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, op = m_activeOperation, id = event.eventId]() {
                finish(reply, op, id);
            });
    m_timer->start(m_timeoutMs);
    operation = m_activeOperation;
    return true;
}

void CatalogOutcomeClient::cancel(quint64 operation)
{
    if (m_reply && operation && operation == m_activeOperation) reset(m_reply, true);
}

bool CatalogOutcomeClient::consume(QNetworkReply *reply, quint64 operation)
{
    if (!reply || reply != m_reply || operation != m_activeOperation) return false;
    while (reply->bytesAvailable() > 0) {
        const qint64 remaining = qint64(m_maximumBodyBytes) + 1 - m_body.size();
        if (remaining <= 0) {
            const QString eventId = m_activeEventId;
            reset(reply, true);
            deliver({operation, eventId, CatalogOutcomeUploadKind::ProtocolError});
            return false;
        }
        m_body += reply->read(qMin(remaining, reply->bytesAvailable()));
        if (m_body.size() > m_maximumBodyBytes) {
            const QString eventId = m_activeEventId;
            reset(reply, true);
            deliver({operation, eventId, CatalogOutcomeUploadKind::ProtocolError});
            return false;
        }
    }
    return true;
}

void CatalogOutcomeClient::finish(QNetworkReply *reply, quint64 operation,
                                  const QString &eventId)
{
    if (!reply || reply != m_reply || operation != m_activeOperation) {
        if (reply) reply->deleteLater();
        return;
    }
    if (!consume(reply, operation)) return;
    CatalogOutcomeHttpResponse response;
    response.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    response.transportFailed = reply->error() != QNetworkReply::NoError
                               && response.status == 0;
    for (const QByteArray &header : reply->rawHeaderList())
        response.headers.insert(header.toLower(), reply->rawHeader(header));
    response.body = std::move(m_body);
    reset(reply, false);
    CatalogOutcomeUploadResult result;
    QString parseError;
    if (!parseCatalogOutcomeHttpResponse(response, result, parseError, m_maximumBodyBytes))
        result.kind = CatalogOutcomeUploadKind::ProtocolError;
    result.operation = operation;
    result.eventId = eventId;
    deliver(std::move(result));
}

void CatalogOutcomeClient::reset(QNetworkReply *reply, bool abort)
{
    m_timer->stop();
    m_reply.clear();
    m_activeOperation = 0;
    m_activeEventId.clear();
    m_body.fill('\0');
    m_body.clear();
    if (reply) {
        QObject::disconnect(reply, nullptr, this, nullptr);
        if (abort) reply->abort();
        reply->deleteLater();
    }
}

void CatalogOutcomeClient::deliver(CatalogOutcomeUploadResult result)
{
    if (!m_observer) return;
    QTimer::singleShot(0, this, [this, result = std::move(result)]() {
        if (m_observer) m_observer->onCatalogOutcomeUploadResult(result);
    });
}

} // namespace avpn
