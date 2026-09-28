#ifndef WIREGUARDPROTOCOL_H
#define WIREGUARDPROTOCOL_H

#include <QObject>
#include <QProcess>
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
    virtual ~WireguardProtocol() override;

    ErrorCode start() override;
    void stop() override;

    ErrorCode startMzImpl();
    ErrorCode stopMzImpl();
    // AVPN (волна-3): §16-сторож VpnConnection спрашивает демона напрямую ({"type":"status"});
    // ответ приходит как statusUpdated → bytesChanged — это и есть признак живого демона.
    void requestStatus();

private:

    QScopedPointer<ControllerImpl> m_impl;
};

#endif // WIREGUARDPROTOCOL_H
