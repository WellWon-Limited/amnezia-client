// Tribe catalog v2 — bounded asynchronous advisory outcome uploader.
#pragma once

#include "CatalogRuntimeState.h"

#include <QHash>
#include <QObject>
#include <QPointer>
#include <QUrl>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

namespace avpn {

enum class CatalogOutcomeUploadKind {
    Acknowledged = 0,
    Retryable,
    AuthenticationRequired,
    StaleAuthority,
    NetworkUnavailable,
    ProtocolError,
};

struct CatalogOutcomeUploadResult {
    quint64 operation = 0;
    QString eventId;
    CatalogOutcomeUploadKind kind = CatalogOutcomeUploadKind::ProtocolError;
    bool duplicate = false;
    int retryAfterS = 0;
    QString serverCode;
};

struct CatalogOutcomeHttpResponse {
    int status = 0;
    QHash<QByteArray, QByteArray> headers; // lower-case names
    QByteArray body;
    bool transportFailed = false;
};

bool parseCatalogOutcomeHttpResponse(const CatalogOutcomeHttpResponse &response,
                                     CatalogOutcomeUploadResult &result,
                                     QString &error,
                                     int maximumBodyBytes = 16 * 1024);

class ICatalogOutcomeUploadObserver {
public:
    virtual ~ICatalogOutcomeUploadObserver() = default;
    virtual void onCatalogOutcomeUploadResult(
        const CatalogOutcomeUploadResult &result) = 0;
};

class ICatalogOutcomeClient {
public:
    virtual ~ICatalogOutcomeClient() = default;
    virtual void setObserver(ICatalogOutcomeUploadObserver *observer) = 0;
    virtual void clearObserver(ICatalogOutcomeUploadObserver *expected) = 0;
    virtual bool start(const QUrl &apiBaseUrl, QByteArray bearerToken,
                       const CatalogOutcomeEvent &event,
                       quint64 &operation, QString &error) = 0;
    virtual void cancel(quint64 operation) = 0;
};

class CatalogOutcomeClient final : public QObject, public ICatalogOutcomeClient {
public:
    explicit CatalogOutcomeClient(QNetworkAccessManager *network,
                                  QObject *parent = nullptr,
                                  int timeoutMs = 10000,
                                  int maximumBodyBytes = 16 * 1024);
    ~CatalogOutcomeClient() override;

    void setObserver(ICatalogOutcomeUploadObserver *observer) override
    { m_observer = observer; }
    void clearObserver(ICatalogOutcomeUploadObserver *expected) override
    { if (m_observer == expected) m_observer = nullptr; }
    bool start(const QUrl &apiBaseUrl, QByteArray bearerToken,
               const CatalogOutcomeEvent &event,
               quint64 &operation, QString &error) override;
    void cancel(quint64 operation) override;

private:
    bool consume(QNetworkReply *reply, quint64 operation);
    void finish(QNetworkReply *reply, quint64 operation, const QString &eventId);
    void reset(QNetworkReply *reply, bool abort);
    void deliver(CatalogOutcomeUploadResult result);

    QPointer<QNetworkAccessManager> m_network;
    QPointer<QNetworkReply> m_reply;
    QTimer *m_timer = nullptr;
    ICatalogOutcomeUploadObserver *m_observer = nullptr;
    QByteArray m_body;
    quint64 m_counter = 0;
    quint64 m_activeOperation = 0;
    QString m_activeEventId;
    int m_timeoutMs = 10000;
    int m_maximumBodyBytes = 16 * 1024;
};

} // namespace avpn
