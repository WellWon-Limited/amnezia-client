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
#include <QtGlobal>

class QSocketNotifier;
class QTimer;

namespace avpn {

// AVPN (фикс-волна 2026-09-22, B9, жалоба 1 «US вместо EE»): одно эхо на цель — один потерянный
// пакет выкидывал EE из ранжирования, и выбиралась дальняя US. Теперь kEchoes эха на цель с шагом
// kEchoSpacingMs; RTT цели = МИНИМУМ по ответившим. Цель «оседает» досрочно: все эха ответили, или
// все отправлены, есть хотя бы один ответ и после последней отправки прошло settleGraceMs(best)
// (запоздавшее эхо уже не улучшит минимум). Без ответа — до общего таймаута раунда (фасад: 1.5 с).
// Чистая логика (без сокетов/таймеров) — покрыта tests/rtt_icmp_check.cpp.
struct RttEchoAggregate {
    static constexpr int kEchoes = 3;
    static constexpr int kEchoSpacingMs = 120;

    qint64 sentAt[kEchoes] = { -1, -1, -1 };
    bool   replied[kEchoes] = { false, false, false };
    bool   sendFailed[kEchoes] = { false, false, false };
    int    best = -1;
    int    answered = 0;
    int    accounted = 0; // отправлено или провалено при отправке
    qint64 lastSentAt = -1;

    static int settleGraceMs(int bestMs) { return qBound(100, 2 * bestMs + 50, 500); }

    void markSent(int k, qint64 atMs)
    {
        if (k < 0 || k >= kEchoes || sentAt[k] >= 0 || sendFailed[k])
            return;
        sentAt[k] = atMs;
        lastSentAt = atMs;
        ++accounted;
    }
    void markSendFailed(int k)
    {
        if (k < 0 || k >= kEchoes || sentAt[k] >= 0 || sendFailed[k])
            return;
        sendFailed[k] = true;
        ++accounted;
    }
    // true = ответ принят (первый на это эхо).
    bool markReply(int k, qint64 atMs)
    {
        if (k < 0 || k >= kEchoes || sentAt[k] < 0 || replied[k])
            return false;
        replied[k] = true;
        ++answered;
        const qint64 rtt = qMax<qint64>(0, atMs - sentAt[k]);
        if (best < 0 || rtt < best)
            best = int(rtt);
        return true;
    }
    bool allAccounted() const { return accounted >= kEchoes; }
    // Все отправленные ответили (или отправлять больше нечего и ответов нет — недостижимо сразу).
    bool complete() const
    {
        if (!allAccounted())
            return false;
        int sentCount = 0;
        for (int k = 0; k < kEchoes; ++k)
            if (sentAt[k] >= 0)
                ++sentCount;
        return answered >= sentCount;
    }
    bool settled(qint64 nowMs) const
    {
        if (complete())
            return true;
        return best >= 0 && allAccounted() && lastSentAt >= 0
               && nowMs - lastSentAt >= settleGraceMs(best);
    }
};

// Без Q_OBJECT намеренно: новых сигналов/слотов нет, всё через functor-connect (moc не нужен — удобно
// для автономной сборки тестом и для per-platform .cpp).
class RttProbeIcmp : public QObject, public IRttProbe {
public:
    explicit RttProbeIcmp(QObject *parent = nullptr);
    ~RttProbeIcmp() override;

    void probeAll(const QList<RttTarget> &targets, int timeoutMs, SampleCb onSample,
                  DoneCb onDone) override;
    void cancel() override;

    // AVPN bench v5 (MTU-проба): одиночный echo с паддингом до payloadLen байт и Don't-Fragment
    // (Darwin IP_DONTFRAG / Linux+Android IP_MTU_DISCOVER=DO; Windows-стаб → done(false)).
    // done(true) = reply дошёл ⇒ path-MTU ≥ payloadLen+28. Самодостаточна (свой сокет/таймер),
    // состояние probeAll не трогает — можно звать между probeAll-прогонами.
    void probeMtuOne(const QString &ipv4, int payloadLen, int timeoutMs,
                     std::function<void(bool ok)> done) override;

private:
    struct Pending {
        QString      nodeId;
        QHostAddress addr;
        quint16      seq[RttEchoAggregate::kEchoes] = { 0, 0, 0 };
        RttEchoAggregate agg;
        bool         done = false;
    };

    void onReadable();
    void onTimeout();
    void onSweep();
    void sendEcho(int idx);            // AVPN B9: эхо №0 сразу, №1..N-1 — с шагом kEchoSpacingMs
    void sendOne(int idx, int echo);
    void finishIdx(int idx, int rttMs);
    void maybeDone();
    void cleanup();

    int              m_fd = -1;
    QSocketNotifier *m_notifier = nullptr;
    QTimer          *m_timer = nullptr;
    QTimer          *m_sweep = nullptr; // AVPN B9: досрочное «оседание» целей (RttEchoAggregate::settled)
    QElapsedTimer    m_clock;
    SampleCb         m_onSample;
    DoneCb           m_onDone;
    quint16          m_magic = 0;
    quint16          m_seqBase = 0;

    QList<Pending>      m_pending;
    int                 m_gen = 0; // AVPN (аудит N8): поколение прогона — гвард стейл-DNS-колбэков
    QHash<quint16, int> m_seqToIdx;   // seq → idx цели
    QHash<quint16, int> m_seqToEcho;  // seq → номер эха у цели
    int                 m_remaining = 0;
    bool                m_doneFired = false;
};

} // namespace avpn
