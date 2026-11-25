#ifndef TUN2SOCKSOUTPUTREADER_H
#define TUN2SOCKSOUTPUTREADER_H

// AVPN (macOS crash 24.11.2026, build 140, EXC_BAD_ACCESS in the Stack Guard of the VpnConnection thread): the
// reader of the tun2socks stderr behind the service's process replica (ipc/ipc_process_interface.rep).
//
// Before (upstream origin/dev xrayProtocol.cpp reads the same way): every queued readyReadStandardError ran
// readAllStandardError().waitForFinished() - a nested event loop inside a queued slot. That loop delivered the
// next queued readyReadStandardError, whose handler opened the next nested loop, and so on: after a dark wake
// 331 signals were queued and the handlers re-entered each other until the thread's stack ran out.
//
// Now: at most one read is in flight and nothing waits for it. A ready signal that comes while a read is in
// flight only marks that more output may be waiting; the read issued after the completion takes it
// (readAllStandardError returns everything the service has buffered, so nothing is lost). The completion
// arrives on a QRemoteObjectPendingCallWatcher; the lines go to the sink, which may block (XrayProtocol sets up
// the routing there) - ready signals during that only set the mark, they never start a second read or re-enter
// the sink.
//
// Tests: client/core/serviceEngine/tests/tun2socks_reader_check.cpp (build_tun2socks_reader.sh) against a real
// QtRO source of ipc/ipc_process_interface.rep; call sites - check_xray_quit_wiring.sh.

#include <QByteArray>
#include <QDebug>
#include <QElapsedTimer>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QRemoteObjectPendingCall>

#include <functional>
#include <utility>

#include "rep_ipc_process_interface_replica.h"

namespace avpn {

// When to read. Pure, no Qt objects.
struct OutputReadPump
{
    bool inFlight = false;
    bool more = false;

    // A ready signal. True: issue a read now. False: a read is in flight, and the one after it is now due.
    bool onReady()
    {
        if (inFlight) {
            more = true;
            return false;
        }
        inFlight = true;
        return true;
    }

    // The read in flight completed (with data, empty or failed). True: issue the next read now.
    bool onReadDone()
    {
        inFlight = more;
        more = false;
        return inFlight;
    }
};

// Complete lines of a byte stream: a line split between two reads is joined, empty lines are dropped. The
// unterminated tail is capped, so a writer that never ends a line cannot grow it without bound.
class LineAssembler
{
public:
    static constexpr int kMaxTail = 64 * 1024;

    QList<QByteArray> feed(const QByteArray &chunk)
    {
        m_tail += chunk;
        QList<QByteArray> lines;
        qsizetype from = 0;
        for (qsizetype nl = m_tail.indexOf('\n'); nl >= 0; nl = m_tail.indexOf('\n', from)) {
            const QByteArray line = m_tail.mid(from, nl - from).trimmed();
            if (!line.isEmpty())
                lines.append(line);
            from = nl + 1;
        }
        m_tail.remove(0, from);
        if (m_tail.size() > kMaxTail) {
            lines.append(m_tail.trimmed());
            m_tail.clear();
        }
        return lines;
    }

private:
    QByteArray m_tail;
};

// The stderr of one privileged process. Owned by its protocol (QObject parent); stop() before dropping it.
class ProcessStderrReader : public QObject
{
public:
    using Sink = std::function<void(const QList<QByteArray> &lines)>;

    ProcessStderrReader(IpcProcessInterfaceReplica *process, Sink sink, QObject *parent = nullptr)
        : QObject(parent), m_process(process), m_sink(std::move(sink))
    {
        m_clock.start(); // round mac-D2: the reader's own timeline in the log (its first signal and reads)
        connect(
                process, &IpcProcessInterfaceReplica::readyReadStandardError, this,
                [this]() {
                    if (!m_readyNoted) {
                        m_readyNoted = true;
                        qInfo().noquote() << QStringLiteral("[proc reader] first ready signal at +%1 ms (stopped=%2 in_flight=%3)")
                                                 .arg(m_clock.elapsed()).arg(m_stopped ? 1 : 0).arg(m_pump.inFlight ? 1 : 0);
                    }
                    if (!m_stopped && m_pump.onReady())
                        issueRead();
                },
                Qt::QueuedConnection);
    }

    // No read is issued after this, and the lines of the read in flight are dropped.
    void stop() { m_stopped = true; }

    int readsIssued() const { return m_readsIssued; }

private:
    void issueRead()
    {
        if (!m_process) {
            m_pump = OutputReadPump{};
            return;
        }
        ++m_readsIssued;
        auto *watcher = new QRemoteObjectPendingCallWatcher(m_process->readAllStandardError(), this);
        connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
                [this, watcher](QRemoteObjectPendingCallWatcher *) {
                    watcher->deleteLater();
                    if (m_stopped)
                        return;
                    QList<QByteArray> lines;
                    if (watcher->error() == QRemoteObjectPendingCall::NoError)
                        lines = m_lines.feed(watcher->returnValue().toByteArray());
                    if (m_readsNoted < 2) { // round mac-D2: the first reads of this process, in the log
                        ++m_readsNoted;
                        qInfo().noquote() << QStringLiteral("[proc reader] read %1 answered at +%2 ms error=%3 bytes=%4 lines=%5")
                                                 .arg(m_readsNoted).arg(m_clock.elapsed()).arg(int(watcher->error()))
                                                 .arg(watcher->error() == QRemoteObjectPendingCall::NoError
                                                          ? watcher->returnValue().toByteArray().size() : -1)
                                                 .arg(lines.size());
                    }
                    if (!lines.isEmpty()) {
                        // The sink may block, stop this reader or destroy it (with its protocol).
                        const QPointer<ProcessStderrReader> self(this);
                        m_sink(lines);
                        if (!self || m_stopped)
                            return;
                    }
                    if (m_pump.onReadDone())
                        issueRead();
                });
    }

    QPointer<IpcProcessInterfaceReplica> m_process;
    Sink m_sink;
    OutputReadPump m_pump;
    LineAssembler m_lines;
    bool m_stopped = false;
    int m_readsIssued = 0;
    QElapsedTimer m_clock;     // round mac-D2
    bool m_readyNoted = false; // round mac-D2
    int m_readsNoted = 0;      // round mac-D2
};

} // namespace avpn

#endif // TUN2SOCKSOUTPUTREADER_H
