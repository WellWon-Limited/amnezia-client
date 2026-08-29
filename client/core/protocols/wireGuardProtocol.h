#ifndef WIREGUARDPROTOCOL_H
#define WIREGUARDPROTOCOL_H

#include <QObject>
#include <QProcess>
#include <QJsonObject>
#include <QString>
#include <QTemporaryFile>
#include <QTimer>

#include "vpnProtocol.h"

#include "mozilla/controllerimpl.h"

class WireguardProtocol : public VpnProtocol
{
    Q_OBJECT

public:
    explicit WireguardProtocol(const QJsonObject& configuration, QObject* parent = nullptr);
    WireguardProtocol(const QJsonObject& configuration,
                      const QString& expectedRuntimeSessionId,
                      QObject* parent = nullptr);
    virtual ~WireguardProtocol() override;

    ErrorCode start() override;
    void stop() override;

    ErrorCode startMzImpl();
    ErrorCode stopMzImpl();

    QJsonObject runtimeStatus() const;
    QString runtimeSessionId() const;
    bool adoptExactSession();

signals:
    void runtimeStatusChanged(const QJsonObject &status);

private:
    void consumeExactRuntimeStatus(const QJsonObject &status);

    QScopedPointer<ControllerImpl> m_impl;
    QString m_expectedRuntimeSessionId;
    QJsonObject m_runtimeStatus;
    bool m_exactStopRequested = false;
    bool m_exactAdoptRequested = false;
};

#endif // WIREGUARDPROTOCOL_H
