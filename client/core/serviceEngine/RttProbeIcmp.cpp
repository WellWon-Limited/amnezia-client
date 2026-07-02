#include "RttProbeIcmp.h"

#include <QHostInfo>
#include <QSocketNotifier>
#include <QTimer>
#include <QtGlobal>

namespace avpn {

// ───────────────────────── общая часть (все платформы) ─────────────────────────

RttProbeIcmp::RttProbeIcmp(QObject *parent) : QObject(parent) {}
RttProbeIcmp::~RttProbeIcmp() { cleanup(); }

void RttProbeIcmp::finishIdx(int idx, int rttMs)
{
    if (idx < 0 || idx >= m_pending.size())
        return;
    Pending &p = m_pending[idx];
    if (p.done)
        return;
    p.done = true;
    --m_remaining;
    if (m_onSample)
        m_onSample(p.nodeId, rttMs);
    maybeDone();
}

void RttProbeIcmp::maybeDone()
{
    if (m_doneFired || m_remaining > 0)
        return;
    m_doneFired = true;
    DoneCb cb = m_onDone; // снять до cleanup: cb может пере-запустить probeAll (cancel внутри)
    cleanup();
    if (cb)
        cb();
}

} // namespace avpn

// ─────────────────────────────── POSIX (Darwin/iOS/macOS/Linux/Android) ───────────────────────────────
#ifndef Q_OS_WIN

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace avpn {

namespace {
struct __attribute__((packed)) IcmpEchoHdr {
    quint8  type;
    quint8  code;
    quint16 cksum;
    quint16 id;
    quint16 seq;
};
constexpr int kPayloadLen = 16; // magic(2)+seq(2)+pad(12)

quint16 inetChecksum(const void *data, int len)
{
    const quint8 *p = static_cast<const quint8 *>(data);
    quint32 sum = 0;
    while (len > 1) {
        quint16 word;
        std::memcpy(&word, p, 2);
        sum += word;
        p += 2;
        len -= 2;
    }
    if (len > 0)
        sum += *p;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<quint16>(~sum);
}
} // namespace

void RttProbeIcmp::cleanup()
{
    if (m_notifier) {
        m_notifier->setEnabled(false);
        m_notifier->deleteLater();
        m_notifier = nullptr;
    }
    if (m_timer) {
        m_timer->stop();
        m_timer->deleteLater();
        m_timer = nullptr;
    }
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
    m_pending.clear();
    m_seqToIdx.clear();
    m_remaining = 0;
}

void RttProbeIcmp::cancel()
{
    // Прерывание без onDone (шторка закрылась / connected). Идемпотентно.
    m_onSample = nullptr;
    m_onDone = nullptr;
    m_doneFired = true; // подавить отложенные maybeDone
    cleanup();
}

void RttProbeIcmp::probeAll(const QList<RttTarget> &targets, int timeoutMs, SampleCb onSample,
                            DoneCb onDone)
{
    cancel(); // снять предыдущий замер, если был
    ++m_gen;  // AVPN (аудит N8): инвалидируем отложенные DNS-колбэки прошлого прогона (см. lookupHost)
    m_onSample = std::move(onSample);
    m_onDone = std::move(onDone);
    m_doneFired = false;

    if (targets.isEmpty()) {
        m_remaining = 0;
        maybeDone();
        return;
    }

    m_fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (m_fd < 0) {
        // Нет unprivileged ICMP (напр. Android с закрытым ping_group_range): всё -1, как «нет измерения».
        m_remaining = targets.size();
        for (int i = 0; i < targets.size(); ++i) {
            Pending p;
            p.nodeId = targets[i].nodeId;
            m_pending.append(p);
        }
        for (int i = 0; i < m_pending.size(); ++i)
            finishIdx(i, -1);
        return;
    }
    ::fcntl(m_fd, F_SETFL, O_NONBLOCK);

    m_magic = static_cast<quint16>((reinterpret_cast<quintptr>(this) >> 4) & 0xffff) ^ 0xA5A5;
    m_seqBase = static_cast<quint16>(m_seqBase + 1);
    m_remaining = targets.size();
    m_clock.restart();

    for (int i = 0; i < targets.size(); ++i) {
        Pending p;
        p.nodeId = targets[i].nodeId;
        p.seq = static_cast<quint16>(m_seqBase + i * 251 + 1); // разнести seq между целями
        m_pending.append(p);
        m_seqToIdx.insert(p.seq, i);
    }

    m_notifier = new QSocketNotifier(m_fd, QSocketNotifier::Read, this);
    QObject::connect(m_notifier, &QSocketNotifier::activated, this, [this]() { onReadable(); });

    m_timer = new QTimer(this);
    m_timer->setSingleShot(true);
    QObject::connect(m_timer, &QTimer::timeout, this, [this]() { onTimeout(); });
    m_timer->start(timeoutMs > 0 ? timeoutMs : 1500);

    // Резолв + отправка. IP-литерал → шлём сразу; иначе async-резолв.
    for (int i = 0; i < targets.size(); ++i) {
        const QString host = targets[i].host;
        QHostAddress lit(host);
        if (!lit.isNull() && lit.protocol() == QAbstractSocket::IPv4Protocol) {
            m_pending[i].addr = lit;
            sendEcho(i);
        } else if (!lit.isNull()) {
            finishIdx(i, -1); // IPv6-литерал — v1 не меряем
        } else {
            // AVPN (аудит N8): гвард по поколению — колбэк отменённого прогона мог сработать после
            // нового probeAll и записать адрес СТАРОГО хоста в новый m_pending[i] (индексы совпадают)
            // → RTT приписался бы чужой ноде. Проверки size/done это не ловили (список пересоздан).
            const int gen = m_gen;
            QHostInfo::lookupHost(host, this, [this, i, gen](const QHostInfo &info) {
                if (gen != m_gen || i >= m_pending.size() || m_pending[i].done)
                    return;
                for (const QHostAddress &a : info.addresses()) {
                    if (a.protocol() == QAbstractSocket::IPv4Protocol) {
                        m_pending[i].addr = a;
                        sendEcho(i);
                        return;
                    }
                }
                finishIdx(i, -1); // не зарезолвилось в IPv4
            });
        }
    }
}

void RttProbeIcmp::sendEcho(int idx)
{
    if (m_fd < 0 || idx < 0 || idx >= m_pending.size())
        return;
    Pending &p = m_pending[idx];

    quint8 pkt[sizeof(IcmpEchoHdr) + kPayloadLen];
    std::memset(pkt, 0, sizeof(pkt));
    auto *h = reinterpret_cast<IcmpEchoHdr *>(pkt);
    h->type = 8; // ICMP_ECHO
    h->code = 0;
    h->cksum = 0;
    h->id = htons(m_magic);
    h->seq = htons(p.seq);
    quint8 *pl = pkt + sizeof(IcmpEchoHdr);
    const quint16 nMagic = htons(m_magic);
    const quint16 nSeq = htons(p.seq);
    std::memcpy(pl, &nMagic, 2);
    std::memcpy(pl + 2, &nSeq, 2);
    h->cksum = inetChecksum(pkt, sizeof(pkt));

    sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(p.addr.toIPv4Address());

    const ssize_t n =
        ::sendto(m_fd, pkt, sizeof(pkt), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    if (n < 0)
        finishIdx(idx, -1); // не ушло — недостижимо
}

void RttProbeIcmp::onReadable()
{
    if (m_fd < 0)
        return;
    for (;;) {
        quint8 buf[2048];
        sockaddr_in src;
        socklen_t sl = sizeof(src);
        const ssize_t n =
            ::recvfrom(m_fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&src), &sl);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            break;
        }
        // На SOCK_DGRAM ICMP IP-заголовка обычно нет; но если платформа его включила — пропускаем.
        int off = 0;
        if (n >= 1 && (buf[0] >> 4) == 4) {
            const int ihl = (buf[0] & 0x0f) * 4;
            if (ihl > 0 && n >= ihl + static_cast<int>(sizeof(IcmpEchoHdr)))
                off = ihl;
        }
        if (n - off < static_cast<int>(sizeof(IcmpEchoHdr)) + 4)
            continue;
        const auto *h = reinterpret_cast<const IcmpEchoHdr *>(buf + off);
        if (h->type != 0) // не echo-reply
            continue;
        const quint8 *pl = buf + off + sizeof(IcmpEchoHdr);
        quint16 magic, seq;
        std::memcpy(&magic, pl, 2);
        std::memcpy(&seq, pl + 2, 2);
        magic = ntohs(magic);
        seq = ntohs(seq);
        if (magic != m_magic)
            continue; // чужой ICMP
        const int idx = m_seqToIdx.value(seq, -1);
        if (idx < 0)
            continue;
        const qint64 ms = m_clock.elapsed();
        finishIdx(idx, ms < 0 ? 0 : static_cast<int>(ms));
        if (m_doneFired)
            break;
    }
}

void RttProbeIcmp::onTimeout()
{
    for (int i = 0; i < m_pending.size(); ++i)
        if (!m_pending[i].done)
            finishIdx(i, -1);
}

} // namespace avpn

// ─────────────────────────────── Windows (graceful-стаб) ───────────────────────────────
#else // Q_OS_WIN

namespace avpn {

void RttProbeIcmp::cleanup()
{
    m_pending.clear();
    m_seqToIdx.clear();
    m_remaining = 0;
}

void RttProbeIcmp::cancel()
{
    m_onSample = nullptr;
    m_onDone = nullptr;
    m_doneFired = true;
    cleanup();
}

void RttProbeIcmp::probeAll(const QList<RttTarget> &targets, int /*timeoutMs*/, SampleCb onSample,
                            DoneCb onDone)
{
    // TODO(win): IcmpSendEcho. Пока — нет измерения (всё -1) → движок откатится на health (NodeRanking).
    cancel();
    m_onSample = std::move(onSample);
    m_onDone = std::move(onDone);
    m_doneFired = false;
    m_remaining = targets.size();
    for (const RttTarget &t : targets)
        m_pending.append(Pending{ t.nodeId, {}, 0, false });
    for (int i = 0; i < m_pending.size(); ++i)
        finishIdx(i, -1);
}

void RttProbeIcmp::sendEcho(int) {}
void RttProbeIcmp::onReadable() {}
void RttProbeIcmp::onTimeout() {}

} // namespace avpn

#endif
