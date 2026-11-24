#ifndef VPNPROTOCOL_H
#define VPNPROTOCOL_H

// Test stand-in for client/core/protocols/vpnProtocol.h (xray_protocol_end_check): the members and the API that
// XrayProtocol uses, without the QML registration and the protocol factory. Copied next to xrayProtocol.h by
// build_xray_protocol_end.sh, so its "vpnProtocol.h" resolves here.

#include <QJsonObject>
#include <QObject>
#include <QString>

#include "core/utils/commonStructs.h"
#include "core/utils/errorCodes.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/routeModes.h"

using namespace amnezia;

namespace Vpn
{
    Q_NAMESPACE
    enum ConnectionState { Unknown, Disconnected, Preparing, Connecting, Connected, Disconnecting, Reconnecting, Error };
    Q_ENUM_NS(ConnectionState)
}

class VpnProtocol : public QObject
{
    Q_OBJECT

public:
    explicit VpnProtocol(const QJsonObject &configuration, QObject *parent = nullptr)
        : QObject(parent), m_rawConfig(configuration)
    {
    }
    ~VpnProtocol() override = default;

    virtual ErrorCode start() = 0;
    virtual void stop() = 0;

    Vpn::ConnectionState connectionState() const { return m_connectionState; }
    ErrorCode lastError() const { return m_lastError; }
    void setLastError(ErrorCode lastError)
    {
        m_lastError = lastError;
        if (lastError)
            setConnectionState(Vpn::ConnectionState::Error);
    }

signals:
    void connectionStateChanged(Vpn::ConnectionState state);
    void protocolError(amnezia::ErrorCode e);

public slots:
    void setConnectionState(Vpn::ConnectionState state)
    {
        if (m_connectionState == state)
            return;
        m_connectionState = state;
        emit connectionStateChanged(state);
    }

protected:
    Vpn::ConnectionState m_connectionState = Vpn::ConnectionState::Unknown;
    QString m_routeGateway;
    QString m_vpnLocalAddress;
    QString m_vpnGateway;
    QJsonObject m_rawConfig;

private:
    ErrorCode m_lastError = ErrorCode::NoError;
};

#endif // VPNPROTOCOL_H
