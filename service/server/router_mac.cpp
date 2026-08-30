#include "router_mac.h"
#include "helper_route_mac.h"

#include <QProcess>
#include <QNetworkInterface>
#include <QThread>
#include <QVector>

#include <core/utils/networkUtilities.h>

namespace {

bool invokeRouteCommand(const QStringList &arguments)
{
    QVector<QByteArray> encoded;
    encoded.reserve(arguments.size());
    for (const QString &argument : arguments) {
        encoded.append(argument.toUtf8());
    }

    QVector<char *> argv;
    argv.reserve(encoded.size());
    for (QByteArray &argument : encoded) {
        argv.append(argument.data());
    }

    const int result = mainRouteIface(argv.size(), argv.data());
    if (result != 0) {
        qWarning() << "Embedded route command failed" << arguments << "result" << result;
    }
    return result == 0;
}

bool processSucceeded(const QProcess &process)
{
    return process.exitStatus() == QProcess::NormalExit
            && process.exitCode() == 0;
}

bool runIfconfig(const QStringList &arguments, int timeoutMs = 2000)
{
    QProcess process;
    process.start(QStringLiteral("/sbin/ifconfig"), arguments);
    if (!process.waitForStarted(1000)) {
        return false;
    }
    if (!process.waitForFinished(timeoutMs)) {
        process.kill();
        process.waitForFinished(500);
        return false;
    }
    return processSucceeded(process);
}

bool interfaceHasAddress(const QString &name, const QHostAddress &address)
{
    const QNetworkInterface interface = QNetworkInterface::interfaceFromName(name);
    if (!interface.isValid() || !(interface.flags() & QNetworkInterface::IsUp)) {
        return false;
    }
    for (const QNetworkAddressEntry &entry : interface.addressEntries()) {
        if (entry.ip() == address) {
            return true;
        }
    }
    return false;
}

QStringList xrayRouteArguments(const QString &operation, const QString &subnet,
                               const QString &ifname, const QString &gateway)
{
    QStringList arguments{QStringLiteral("route"), operation, QStringLiteral("-net"), subnet};
    if (!gateway.isEmpty()) {
        arguments.append(gateway);
    }
    arguments.append({QStringLiteral("-ifscope"), ifname});
    return arguments;
}

} // namespace

RouterMac &RouterMac::Instance()
{
    static RouterMac s;
    return s;
}

bool RouterMac::routeAdd(const QString &ipWithSubnet, const QString &gw)
{
    QString ip = NetworkUtilities::ipAddressFromIpWithSubnet(ipWithSubnet);
    QString mask = NetworkUtilities::netMaskFromIpWithSubnet(ipWithSubnet);

#ifdef MZ_DEBUG
    qDebug().noquote() << "RouterMac::routeAdd: " << ipWithSubnet << gw;
#endif

    if (!NetworkUtilities::checkIPv4Format(ip) || !NetworkUtilities::checkIPv4Format(gw)) {
        qCritical().noquote() << "Critical, trying to add invalid route: " << ip << gw;
        return false;
    }

    QStringList arguments;
    if (mask == "255.255.255.255") {
        arguments = {QStringLiteral("route"), QStringLiteral("add"), QStringLiteral("-host"), ip, gw};
    }
    else {
        arguments = {QStringLiteral("route"), QStringLiteral("add"), QStringLiteral("-net"), ip, gw, mask};
    }

    if (!invokeRouteCommand(arguments)) {
        return false;
    }
    m_addedRoutes.append({ipWithSubnet, gw});
    return true;
}

int RouterMac::routeAddList(const QString &gw, const QStringList &ips)
{
    int cnt = 0;
    for (const QString &ip: ips) {
        if (routeAdd(ip, gw)) cnt++;
    }
    return cnt;
}

bool RouterMac::clearSavedRoutes()
{
    int cnt = 0;
    for (const Route &r: m_addedRoutes) {
        if (routeDelete(r.dst, r.gw)) cnt++;
    }
    bool ret = (cnt == m_addedRoutes.count());
    m_addedRoutes.clear();
    return ret;
}

bool RouterMac::routeDelete(const QString &ipWithSubnet, const QString &gw)
{
    QString ip = NetworkUtilities::ipAddressFromIpWithSubnet(ipWithSubnet);
    QString mask = NetworkUtilities::netMaskFromIpWithSubnet(ipWithSubnet);

#ifdef MZ_DEBUG
    qDebug().noquote() << "RouterMac::routeDelete: " << ipWithSubnet << gw;
#endif

    if (!NetworkUtilities::checkIPv4Format(ip) || !NetworkUtilities::checkIPv4Format(gw)) {
        qCritical().noquote() << "Critical, trying to remove invalid route: " << ip << gw;
        return false;
    }

    if (ipWithSubnet == "0.0.0.0/0") {
        qDebug().noquote() << "Warning, trying to remove default route, skipping: " << ip << gw;
        return true;
    }

    QStringList arguments;
    if (mask == "255.255.255.255") {
        arguments = {QStringLiteral("route"), QStringLiteral("delete"), QStringLiteral("-host"), ip, gw};
    }
    else {
        arguments = {QStringLiteral("route"), QStringLiteral("delete"), QStringLiteral("-net"), ip, gw, mask};
    }
    return invokeRouteCommand(arguments);
}

bool RouterMac::routeDeleteList(const QString &gw, const QStringList &ips)
{
    int cnt = 0;
    for (const QString &ip: ips) {
        if (routeDelete(ip, gw)) cnt++;
    }
    return cnt;
}

bool RouterMac::createTun(const QString &dev, const QString &subnet) {
    qDebug().noquote() << "createTun start";
    const QHostAddress address(subnet);
    if (address.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    // This code already runs inside the root helper.  Invoking sudo here both
    // expands the trusted surface and hid non-zero ifconfig exits.
    if (!runIfconfig({dev, QStringLiteral("inet"), subnet, subnet,
                      QStringLiteral("up")})) {
        qWarning() << "Could not configure tun device" << dev;
        return false;
    }
    if (!interfaceHasAddress(dev, address)) {
        qWarning() << "Tun configuration readback failed" << dev;
        runIfconfig({dev, QStringLiteral("down")});
        return false;
    }
    return true;
}

bool RouterMac::updateResolvers(const QString& ifname, const QList<QHostAddress>& resolvers)
{
    return m_dnsUtil->updateResolvers(ifname, resolvers);
}

bool RouterMac::restoreResolvers() {
    return m_dnsUtil->restoreResolvers();
}

bool RouterMac::routeAddXray(const QString& ifname, const QString& gateway)
{
    const QNetworkInterface interface = QNetworkInterface::interfaceFromName(ifname);
    if (ifname.isEmpty() || gateway.isEmpty() || !interface.isValid() || interface.index() <= 0
            || !NetworkUtilities::checkIPv4Format(gateway)) {
        qWarning().noquote() << "routeAddXray: invalid iface/gateway:" << ifname << gateway;
        return false;
    }

    const QString lowHalf = QStringLiteral("0.0.0.0/1");
    const QString highHalf = QStringLiteral("128.0.0.0/1");
    if (!invokeRouteCommand(xrayRouteArguments(QStringLiteral("add"), lowHalf, ifname, gateway))) {
        return false;
    }
    if (!invokeRouteCommand(xrayRouteArguments(QStringLiteral("add"), highHalf, ifname, gateway))) {
        const bool rolledBack = invokeRouteCommand(
                xrayRouteArguments(QStringLiteral("delete"), lowHalf, ifname, gateway));
        if (!rolledBack) {
            qCritical() << "Failed to roll back partial Xray route transaction" << ifname;
        }
        return false;
    }

    qDebug().noquote() << "Installed xray routes via" << gateway << "on" << ifname;
    return true;
}

bool RouterMac::routeDeleteXray(const QString& ifname, const QString& gateway)
{
    if (ifname.isEmpty()) {
        return false;
    }
    if (!QNetworkInterface::interfaceFromName(ifname).isValid()) {
        // Scoped routes are removed by Darwin with the vanished interface.
        // Treat that OS postcondition as clean instead of quarantining the
        // daemon forever on a Wi-Fi/Ethernet handoff.
        qWarning() << "Xray uplink vanished; scoped escape routes no longer exist" << ifname;
        return true;
    }

    const bool lowRemoved = invokeRouteCommand(xrayRouteArguments(
            QStringLiteral("delete"), QStringLiteral("0.0.0.0/1"), ifname, gateway));
    const bool highRemoved = invokeRouteCommand(xrayRouteArguments(
            QStringLiteral("delete"), QStringLiteral("128.0.0.0/1"), ifname, gateway));

    if (lowRemoved && highRemoved) {
        qDebug().noquote() << "Removed xray routes on" << ifname;
    }
    return lowRemoved && highRemoved;
}

bool RouterMac::deleteTun(const QString &dev)
{
    qDebug().noquote() << "deleteTun start";
    const QNetworkInterface before = QNetworkInterface::interfaceFromName(dev);
    if (!before.isValid()) {
        return true;
    }
    if (!runIfconfig({dev, QStringLiteral("down")})) {
        return false;
    }
    const QNetworkInterface after = QNetworkInterface::interfaceFromName(dev);
    return !after.isValid()
            || !(after.flags() & (QNetworkInterface::IsUp
                                  | QNetworkInterface::IsRunning));
}

bool RouterMac::flushDns()
{
    // sudo killall -HUP mDNSResponder
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);

    p.start(QStringLiteral("/usr/bin/killall"),
            QStringList() << "-HUP" << "mDNSResponder");
    if (!p.waitForStarted(1000) || !p.waitForFinished(2000)) {
        p.kill();
        return false;
    }
    
    qDebug().noquote() << "OUTPUT killall -HUP mDNSResponder: " + p.readAll();
    return processSucceeded(p);
}
