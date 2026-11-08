// AVPN (волна-3, 2026-09-28): фолбэк UplinkMonitor для платформ без nw_path_monitor —
// QNetworkInformation (Windows/Linux/Android/iOS). Не авторитетен: при поднятом VPN может
// показывать «online» по самому туннелю; решения о намерении на нём принимаются мягче.
// 5.1.108: physicalUp() here is strict - unknown reachability or a non-physical medium = no.
#include "UplinkMonitor.h"

#include <QCoreApplication>
#include <QDebug>
#include <QNetworkInformation>

namespace avpn {

UplinkMonitor *UplinkMonitor::instance()
{
    static UplinkMonitor *s_instance = new UplinkMonitor(QCoreApplication::instance());
    return s_instance;
}

UplinkMonitor::UplinkMonitor(QObject *parent) : QObject(parent)
{
    start();
}

UplinkMonitor::~UplinkMonitor() = default;

namespace {
UplinkReach reachOf(QNetworkInformation::Reachability r)
{
    switch (r) {
    case QNetworkInformation::Reachability::Disconnected: return UplinkReach::Disconnected;
    case QNetworkInformation::Reachability::Local:        return UplinkReach::Local;
    case QNetworkInformation::Reachability::Site:         return UplinkReach::Site;
    case QNetworkInformation::Reachability::Online:       return UplinkReach::Online;
    default:                                              return UplinkReach::Unknown;
    }
}
UplinkMedium mediumOf(const QNetworkInformation *ni)
{
    if (!ni->supports(QNetworkInformation::Feature::TransportMedium))
        return UplinkMedium::Unknown;
    switch (ni->transportMedium()) {
    case QNetworkInformation::TransportMedium::Ethernet:  return UplinkMedium::Ethernet;
    case QNetworkInformation::TransportMedium::WiFi:      return UplinkMedium::WiFi;
    case QNetworkInformation::TransportMedium::Cellular:  return UplinkMedium::Cellular;
    case QNetworkInformation::TransportMedium::Bluetooth: return UplinkMedium::Bluetooth;
    default:                                              return UplinkMedium::Unknown;
    }
}
} // namespace

void UplinkMonitor::start()
{
    if (!QNetworkInformation::loadDefaultBackend())
        return; // m_up stays true (lenient), m_physicalUp stays false (unknown = no)
    auto *ni = QNetworkInformation::instance();
    if (!ni)
        return;
    m_up = ni->reachability() != QNetworkInformation::Reachability::Disconnected;
    m_physicalUp = fallbackPhysicalUp(reachOf(ni->reachability()), mediumOf(ni));
    const auto refreshPhysical = [this, ni]() {
        m_physicalUp = fallbackPhysicalUp(reachOf(ni->reachability()), mediumOf(ni));
    };
    connect(ni, &QNetworkInformation::reachabilityChanged, this, [this, refreshPhysical](QNetworkInformation::Reachability r) {
        refreshPhysical();
        setUp(r != QNetworkInformation::Reachability::Disconnected);
    });
    connect(ni, &QNetworkInformation::transportMediumChanged, this, [refreshPhysical](QNetworkInformation::TransportMedium) {
        refreshPhysical();
    });
}

void UplinkMonitor::setUp(bool up, int)
{
    if (m_up == up)
        return;
    m_up = up;
    qInfo() << "[uplink]" << (up ? "up" : "down") << "(QNetworkInformation)";
    emit changed(up);
}

} // namespace avpn
