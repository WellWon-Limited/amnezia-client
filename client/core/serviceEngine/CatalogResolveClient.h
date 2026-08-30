// Tribe catalog v2 — cancellable asynchronous authenticated resolve transport.
#pragma once

#include "CatalogResolve.h"

#include <QHash>
#include <QObject>
#include <QPointer>
#include <QUrl>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

namespace avpn {

enum class CatalogResolveResultKind {
    SignedCatalog = 0,
    Preparing,
    InvalidRequest,
    Unauthorized,
    AccountBlocked,
    DeviceKeyMismatch,
    RevokedOrTransferred,
    UpgradeRequired,
    NoCapacity,
    TemporarilyUnavailable,
    RateLimited,
    NetworkUnavailable,
    ProtocolError,
};

struct CatalogResolveResult {
    quint64 operation = 0;
    CatalogResolveResultKind kind = CatalogResolveResultKind::ProtocolError;
    int httpStatus = 0;
    QByteArray signedEnvelope;
    QString requestNonce;
    QString serverCode;
    int retryAfterS = 0;
    int minimumAppBuild = 0;
    // True only for a schema-valid response from the authenticated v2 endpoint. It suppresses
    // legacy fallback for this/current future lifecycle even when no connectable catalog exists.
    bool authoritativeV2Endpoint = false;
};

struct CatalogResolveHttpResponse {
    int status = 0;
    QHash<QByteArray, QByteArray> headers; // lower-case key expected
    QByteArray body;
    bool transportFailed = false;
};

bool parseCatalogResolveHttpResponse(const CatalogResolveHttpResponse &response,
                                     const QString &requestNonce,
                                     CatalogResolveResult &result,
                                     QString &error,
                                     int maximumBodyBytes = 1024 * 1024);

class ICatalogResolveObserver {
public:
    virtual ~ICatalogResolveObserver() = default;
    virtual void onCatalogResolveResult(const CatalogResolveResult &result) = 0;
};

struct CatalogResolveAttempt {
    quint64 operation = 0;
    QString requestNonce;
    CatalogResolveSelection expectedSelection;
    bool scopedSelectionSent = false;
};

class ICatalogResolveClient {
public:
    virtual ~ICatalogResolveClient() = default;
    virtual void setObserver(ICatalogResolveObserver *observer) = 0;
    virtual void clearObserver(ICatalogResolveObserver *expected) = 0;
    virtual bool start(QUrl apiBaseUrl, QByteArray bearerToken,
                       CatalogResolveRequest runtimeRequest,
                       CatalogResolveAttempt &attempt, QString &error) = 0;
    virtual void cancel(quint64 operation) = 0;
};

class CatalogResolveClient final : public QObject, public ICatalogResolveClient {
public:
    CatalogResolveClient(QNetworkAccessManager *network, QObject *parent = nullptr,
                         int timeoutMs = 15000, int maximumBodyBytes = 1024 * 1024);
    ~CatalogResolveClient() override;

    void setObserver(ICatalogResolveObserver *observer) override { m_observer = observer; }
    void clearObserver(ICatalogResolveObserver *expected) override
    { if (m_observer == expected) m_observer = nullptr; }
    bool start(QUrl apiBaseUrl, QByteArray bearerToken,
               CatalogResolveRequest runtimeRequest,
               CatalogResolveAttempt &attempt, QString &error) override;
    void cancel(quint64 operation) override;

private:
    void finish(QNetworkReply *reply, quint64 operation, QString nonce);
    bool consumeBody(QNetworkReply *reply, quint64 operation, const QString &nonce);
    void failProtocol(QNetworkReply *reply, quint64 operation, const QString &nonce,
                      int httpStatus);
    void deliver(const CatalogResolveResult &result);

    QPointer<QNetworkAccessManager> m_network;
    QPointer<QNetworkReply> m_reply;
    QTimer *m_timer = nullptr;
    ICatalogResolveObserver *m_observer = nullptr;
    quint64 m_counter = 0;
    quint64 m_activeOperation = 0;
    QByteArray m_body;
    int m_timeoutMs = 15000;
    int m_maximumBodyBytes = 1024 * 1024;
};

} // namespace avpn
