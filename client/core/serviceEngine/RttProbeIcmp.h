// AVPN serviceEngine — нативный ICMP-пробер (реализация IRttProbe) для «выбора по скорости».
// Кроссплатформенно: POSIX unprivileged ICMP (Darwin/iOS/macOS/Linux/Android — SOCK_DGRAM/IPPROTO_ICMP,
// БЕЗ entitlement); Windows — graceful-стаб (нет измерения → движок откатится на health, см. NodeRanking).
// Параллельно пингует все цели на одном сокете; матч ответа по эхо-payload (magic+seq) — устойчиво к
// перезаписи icmp_id ядром на SOCK_DGRAM. Интегрирован в Qt-eventloop через QSocketNotifier (без потоков).
#pragma once

#include "IRttProbe.h"

#include <QElapsedTimer>
#include <QHash>
#include <QHostAddress>
#include <QObject>

class QSocketNotifier;
class QTimer;

namespace avpn {

// Без Q_OBJECT намеренно: новых сигналов/слотов нет, всё через functor-connect (moc не нужен — удобно
// для автономной сборки тестом и для per-platform .cpp).
class RttProbeIcmp : public QObject, public IRttProbe {
public:
    explicit RttProbeIcmp(QObject *parent = nullptr);
    ~RttProbeIcmp() override;

    void probeAll(const QList<RttTarget> &targets, int timeoutMs, SampleCb onSample,
                  DoneCb onDone) override;
    void cancel() override;

private:
    struct Pending {
        QString      nodeId;
        QHostAddress addr;
        quint16      seq = 0;
        bool         done = false;
    };

    void onReadable();
    void onTimeout();
    void sendEcho(int idx);
    void finishIdx(int idx, int rttMs);
    void maybeDone();
    void cleanup();

    int              m_fd = -1;
    QSocketNotifier *m_notifier = nullptr;
    QTimer          *m_timer = nullptr;
    QElapsedTimer    m_clock;
    SampleCb         m_onSample;
    DoneCb           m_onDone;
    quint16          m_magic = 0;
    quint16          m_seqBase = 0;

    QList<Pending>      m_pending;
    int                 m_gen = 0; // AVPN (аудит N8): поколение прогона — гвард стейл-DNS-колбэков
    QHash<quint16, int> m_seqToIdx;
    int                 m_remaining = 0;
    bool                m_doneFired = false;
};

} // namespace avpn
