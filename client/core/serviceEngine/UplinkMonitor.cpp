// AVPN (волна-3, 2026-09-28): фолбэк UplinkMonitor для платформ без nw_path_monitor —
// QNetworkInformation (Windows/Linux/Android/iOS). Не авторитетен: при поднятом VPN может
// показывать «online» по самому туннелю; решения о намерении на нём принимаются мягче.
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

void UplinkMonitor::start()
{
    if (!QNetworkInformation::loadDefaultBackend())
        return;
    auto *ni = QNetworkInformation::instance();
    if (!ni)
        return;
    m_up = ni->reachability() != QNetworkInformation::Reachability::Disconnected;
    connect(ni, &QNetworkInformation::reachabilityChanged, this, [this](QNetworkInformation::Reachability r) {
        setUp(r != QNetworkInformation::Reachability::Disconnected);
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
