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
#include <QObject>

namespace avpn {

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

signals:
    void changed(bool up);

private:
    explicit UplinkMonitor(QObject *parent = nullptr);
    ~UplinkMonitor() override;
    void start();
    void setUp(bool up, int reason = -1);

    bool m_up = true;
    bool m_authoritative = false;
    void *m_impl = nullptr; // nw_path_monitor_t на macOS
};

} // namespace avpn
