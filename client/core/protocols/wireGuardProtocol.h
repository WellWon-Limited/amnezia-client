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
    // AVPN (BUG-6, macOS, round mac-B): the app quits and the daemon keeps the AmneziaWG session - the controller (its
    // daemon socket) is released WITHOUT a deactivate; this protocol's stop() / destructor then sends nothing. Called on
    // the protocol's own thread by ~AmneziaApplication only.
    void releaseSessionToDaemon();

signals:
    // AVPN (волна-4): проброс ControllerImpl::daemonSocketLost к VpnConnection::daemonLost.
    void daemonSocketLost();

private:

    QScopedPointer<ControllerImpl> m_impl;
};

#endif // WIREGUARDPROTOCOL_H
