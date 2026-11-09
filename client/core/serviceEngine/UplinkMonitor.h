#pragma once
// AVPN (волна-3, 2026-09-28): физический аплинк устройства, БЕЗ учёта собственного туннеля.
//
// Зачем: на macOS QNetworkInformation смотрит на default route, а при поднятом VPN default —
// наш же utun: через 0,4 с после activate он сообщает «online», хотя маршрут по умолчанию на en0
// вернулся только через 43 с (журнал Mac 26.09 12:43). Все решения «есть ли сеть» (учёт попыток
// старта, пауза health-loop, повтор после сна) на этом сигнале врали. Здесь — nw_path_monitor с
// запретом интерфейсов типа other (utun/ipsec/ppp): виден только реальный uplink (Wi-Fi/Ethernet/
// сотовая). На остальных платформах — QNetworkInformation (там своя логика; iOS/Android не
// используют этот монитор для решений о намерении).
//
// 5.1.108 (audit of 137): iOS also asks "is there a physical network" for the §25 stop of a dead
// adopted session (IosController::setUplinkProbe). The authoritative .mm cannot build on iOS - its
// source of truth is the route table (sysctl NET_RT_DUMP, <net/route.h>), which the iPhoneOS SDK does
// not ship, and nw_path_monitor alone is not trusted under a VPN (macOS, 28.09: "unsatisfied reason 0"
// under a foreign NE VPN with a live en0). So iOS keeps the QNetworkInformation fallback, and the
// question "physical path known to exist" (physicalUp) is answered strictly: unknown = no. up() keeps
// its old lenient meaning (unknown = up: never block a start or pause health on an unknown state).
#include <QObject>

namespace avpn {

// Fallback (QNetworkInformation) inputs, mirrored to keep the decision pure (tested without QtNetwork).
enum class UplinkReach { Unknown, Disconnected, Local, Site, Online };
enum class UplinkMedium { Unknown, Ethernet, WiFi, Cellular, Bluetooth };

// Is a PHYSICAL path known to exist (fallback)? Reachability must be known and not Disconnected, and
// the medium must be a physical one: Unknown reachability (the backend did not answer yet / cannot
// tell) and an Unknown medium (a path over our own utun reports no physical medium) are "no".
inline bool fallbackPhysicalUp(UplinkReach reach, UplinkMedium medium)
{
    if (reach == UplinkReach::Unknown || reach == UplinkReach::Disconnected)
        return false;
    return medium == UplinkMedium::Ethernet || medium == UplinkMedium::WiFi || medium == UplinkMedium::Cellular;
}

class UplinkMonitor : public QObject
{
    Q_OBJECT
public:
    static UplinkMonitor *instance();
    // true — есть физический путь в сеть (без учёта VPN-интерфейсов). До первого события — true
    // (не блокировать старт при неизвестном состоянии).
    bool up() const { return m_up; }
    // Есть ли достоверный источник (nw_path_monitor). false — фолбэк на QNetworkInformation.
    bool authoritative() const { return m_authoritative; }
    // 5.1.108: a physical path is KNOWN to exist (unknown = false). Authoritative source - up();
    // fallback - fallbackPhysicalUp(). For decisions that must not act on an unknown state (§25 stop).
    bool physicalUp() const { return m_authoritative ? m_up : m_physicalUp; }

signals:
    void changed(bool up);

private:
    explicit UplinkMonitor(QObject *parent = nullptr);
    ~UplinkMonitor() override;
    void start();
    void setUp(bool up, int reason = -1);

    bool m_up = true;
    bool m_authoritative = false;
    bool m_physicalUp = false; // fallback only: fallbackPhysicalUp() of the last reading
    void *m_impl = nullptr; // nw_path_monitor_t на macOS
};

} // namespace avpn
