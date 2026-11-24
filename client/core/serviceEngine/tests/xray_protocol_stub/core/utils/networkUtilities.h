#ifndef NETWORKUTILITIES_H
#define NETWORKUTILITIES_H
// Test stand-in for client/core/utils/networkUtilities.h (xray_protocol_end_check): no lookups.
#include <QHostAddress>
#include <QNetworkInterface>
#include <QPair>
#include <QString>
class NetworkUtilities
{
public:
    static QString getIPAddress(const QString &host) { return host; }
    static QPair<QString, QNetworkInterface> getGatewayAndIface() { return { QStringLiteral("192.0.2.254"), QNetworkInterface() }; }
    static int AdapterIndexTo(const QHostAddress &) { return -1; }
};
#endif
