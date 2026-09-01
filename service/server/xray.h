#ifndef XRAY_H
#define XRAY_H

#include <QElapsedTimer> // AVPN
#include <QJsonObject>   // AVPN
#include <QString>

// AVPN: reset-safe аккумулятор кумулятивных счётчиков интерфейса tun2socks (utun).
// Контракт CONNECT-INVARIANTS §17.1: наружу отдаём КУМУЛЯТИВ с подъёма xray-сессии, не дельты.
//  - первый замер после старта — база (utun мог существовать до нас с чужими байтами);
//  - счётчик откатился (интерфейс пересоздан: tun2socks перезапустился, «resource busy»-ретрай) —
//    без underflow и без «дельты размером с аптайм»: новое значение считаем набранным с момента
//    отката (реальный трафик новой инкарнации интерфейса), откат считаем в resets;
//  - «интерфейса нет» — не замер: база не сбрасывается, кумулятив не трогается.
// Чистая структура без зависимостей от Qt-рантайма — покрыта юнитом
// service/server/tests/xray_traffic_check.cpp (build_xray_traffic.sh).
struct XrayTrafficAccumulator
{
    bool haveBase = false;
    quint64 lastRx = 0;
    quint64 lastTx = 0;
    quint64 totalRx = 0;
    quint64 totalTx = 0;
    quint64 resets = 0;

    void reset()
    {
        haveBase = false;
        lastRx = lastTx = 0;
        totalRx = totalTx = 0;
        resets = 0;
    }

    // Один замер сырых счётчиков интерфейса (ifi_ibytes / ifi_obytes).
    void sample(quint64 rx, quint64 tx)
    {
        if (!haveBase) {
            haveBase = true;
            lastRx = rx;
            lastTx = tx;
            return;
        }
        const bool rolledBack = rx < lastRx || tx < lastTx;
        if (rolledBack) {
            ++resets;
            // Откат любого из счётчиков = новая инкарнация интерфейса: оба стартовали с нуля.
            totalRx += rx;
            totalTx += tx;
        } else {
            totalRx += rx - lastRx;
            totalTx += tx - lastTx;
        }
        lastRx = rx;
        lastTx = tx;
    }
};

class Xray
{
public:
    static Xray& getInstance()
    {
        static Xray instance;
        return instance;
    }

    bool startXray(const QString& cfg);
    bool stopXray();

    // AVPN: статус xray-пути демона для health-контура GUI (IPC xrayRuntimeStatus).
    // ifaceHint — имя utun tun2socks, которое знает клиент (xrayProtocol.cpp tunName, "utun22");
    // пусто → дефолт демона. Поля: running, iface, iface_found, rx_bytes, tx_bytes (кумулятив
    // с подъёма сессии, §17.1), resets, since_ms (аптайм сессии), started_at_ms (epoch),
    // unsupported (true вне macOS — счётчики честные нули), source.
    QJsonObject runtimeStatus(const QString& ifaceHint);

private:
    static void ctxSockCallback(uintptr_t fd, void* ctx) {
        reinterpret_cast<Xray*>(ctx)->sockCallback(fd);
    }
    static void ctxLogHandler(char* str, void* ctx) {
        reinterpret_cast<Xray*>(ctx)->logHandler(str);
    }

    void sockCallback(uintptr_t fd);
    void logHandler(char* str);

#ifdef Q_OS_LINUX
    QByteArray m_defaultIfaceName;
#else
    int m_defaultIfaceIdx;
#endif

#ifdef Q_OS_MAC
    QString m_uplinkIfaceName;
    QString m_uplinkGateway;
#endif

    // AVPN: состояние сессии для runtimeStatus (только главный поток демона — IPC-слоты QtRO
    // сериализованы; sockCallback из Go-потоков этих полей не касается).
    bool m_running = false;
    qint64 m_startedAtMs = 0;
    QElapsedTimer m_since;
    XrayTrafficAccumulator m_traffic;
};

#endif // XRAY_H
