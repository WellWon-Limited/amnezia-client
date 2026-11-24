// client/core/serviceEngine/tests/tun2socks_reader_check.cpp
// AVPN (macOS crash 24.11.2026): the tun2socks stderr reader (client/core/protocols/tun2socksOutputReader.h)
// against a real QtRO source of ipc/ipc_process_interface.rep on a local socket, as XrayProtocol uses it.
//   R1  a burst of queued ready signals (331 after the dark wake on the owner's Mac; 400 here): everything is
//       read, in order, with at most one read in flight - the lines never reach the sink from inside a nested
//       event loop and the sink is never re-entered;
//   R2  a sink that blocks in a nested event loop (XrayProtocol::setupRouting waits on the service) while
//       more output and ready signals come: no second read, no re-entry, the rest is read afterwards;
//   R3  stop(): the read in flight is dropped and no read follows any later signal;
//   R4  a sink that destroys the reader (the protocol goes with it): nothing runs on the dead reader;
//   R5  lines split between reads are joined; empty lines dropped; an endless line is capped;
//   R6  the pump rule itself.
// The old handler (readAllStandardError().waitForFinished() in the queued slot) fails R1 and R2.
// Run by build_tun2socks_reader.sh.
#include "core/protocols/tun2socksOutputReader.h"

#include "rep_ipc_process_interface_source.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QRemoteObjectHost>
#include <QRemoteObjectNode>
#include <QThread>
#include <QTimer>

#include <cstdio>
#include <memory>

using namespace avpn;

static int g_checks = 0;
static int g_failed = 0;
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        if (!(cond)) {                                                                                                 \
            ++g_failed;                                                                                                \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                       \
        }                                                                                                              \
    } while (0)

template <typename P>
static bool waitFor(P pred, int ms = 5000)
{
    QElapsedTimer t;
    t.start();
    while (!pred()) {
        if (t.elapsed() > ms)
            return false;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return true;
}

static void pump(int ms)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
}

// The service side: a process whose stderr is a buffer the test fills.
class FakeProcess : public IpcProcessInterfaceSource
{
public:
    QByteArray err;
    int errReads = 0;

    void write(const QByteArray &bytes, bool signal = true)
    {
        err += bytes;
        if (signal)
            emit readyReadStandardError();
    }

    void start() override {}
    void terminate() override {}
    void kill() override {}
    void close() override {}
    void setArguments(const QStringList &) override {}
    void setInputChannelMode(QProcess::InputChannelMode) override {}
    void setNativeArguments(const QString &) override {}
    void setProcessChannelMode(QProcess::ProcessChannelMode) override {}
    void setProgram(int) override {}
    void setWorkingDirectory(const QString &) override {}
    QByteArray readAll() override { return {}; }
    QByteArray readAllStandardError() override
    {
        ++errReads;
        return std::exchange(err, QByteArray());
    }
    QByteArray readAllStandardOutput() override { return {}; }
    bool waitForFinished() override { return true; }
    bool waitForFinished(int) override { return true; }
    bool waitForStarted() override { return true; }
    bool waitForStarted(int) override { return true; }
};

struct SinkProbe
{
    QList<QByteArray> lines;
    int depth = 0;
    int maxDepth = 0;
    int calls = 0;
    int maxLoopLevel = -1; // QThread::loopLevel() when the sink is entered: 0 = straight from the test's pump
    std::function<void(const QList<QByteArray> &)> extra;

    ProcessStderrReader::Sink sink()
    {
        return [this](const QList<QByteArray> &got) {
            ++depth;
            ++calls;
            maxDepth = qMax(maxDepth, depth);
            maxLoopLevel = qMax(maxLoopLevel, int(QThread::currentThread()->loopLevel()));
            lines += got;
            if (extra)
                extra(got);
            --depth;
        };
    }
};

static QByteArray lineNo(int i) { return QByteArray("line ") + QByteArray::number(i); }

static bool inOrder(const QList<QByteArray> &lines, int from, int to)
{
    if (lines.size() != to - from)
        return false;
    for (int i = from; i < to; ++i) {
        if (lines.at(i - from) != lineNo(i))
            return false;
    }
    return true;
}

struct Rig
{
    FakeProcess source;
    std::unique_ptr<QRemoteObjectHost> host;
    std::unique_ptr<QRemoteObjectNode> node;
    std::unique_ptr<IpcProcessInterfaceReplica> replica;

    bool up(const char *tag)
    {
        const QUrl url(QStringLiteral("local:%1/trc-%2-%3")
                               .arg(QDir::tempPath())
                               .arg(QCoreApplication::applicationPid())
                               .arg(QLatin1String(tag)));
        host = std::make_unique<QRemoteObjectHost>(url);
        if (!host->enableRemoting(&source))
            return false;
        node = std::make_unique<QRemoteObjectNode>();
        node->connectToNode(url);
        replica.reset(node->acquire<IpcProcessInterfaceReplica>());
        return waitFor([this]() { return replica->isInitialized(); });
    }
};

static void burst()
{
    Rig rig;
    CHECK(rig.up("burst"));
    SinkProbe probe;
    ProcessStderrReader reader(rig.replica.get(), probe.sink());
    constexpr int kSignals = 400;
    for (int i = 0; i < kSignals; ++i)
        rig.source.write(lineNo(i) + '\n');
    CHECK(waitFor([&]() { return probe.lines.size() >= kSignals; }));
    pump(200); // late completions, if any
    CHECK(inOrder(probe.lines, 0, kSignals));
    CHECK(probe.maxDepth == 1);
    CHECK(probe.maxLoopLevel == 0); // never inside a nested event loop
    CHECK(reader.readsIssued() == rig.source.errReads);
    CHECK(rig.source.errReads >= 1 && rig.source.errReads <= 3);
    std::fprintf(stderr, "R1 burst: %d signals -> %d reads, %d sink calls, max sink depth %d, max loop level %d\n",
                 kSignals, rig.source.errReads, probe.calls, probe.maxDepth, probe.maxLoopLevel);
}

static void blockingSink()
{
    Rig rig;
    CHECK(rig.up("block"));
    SinkProbe probe;
    int nestedRuns = 0;
    // The first lines make the sink block in a nested event loop for 300 ms (the routing setup waits on the
    // service); a timer keeps writing lines with a ready signal each meanwhile.
    QTimer writer;
    int next = 1;
    QObject::connect(&writer, &QTimer::timeout, [&]() {
        if (next <= 60)
            rig.source.write(lineNo(next++) + '\n');
    });
    probe.extra = [&](const QList<QByteArray> &got) {
        if (nestedRuns > 0 || !got.contains(lineNo(0)))
            return;
        ++nestedRuns;
        writer.start(2);
        QEventLoop loop;
        QTimer::singleShot(300, &loop, &QEventLoop::quit);
        loop.exec();
    };
    ProcessStderrReader reader(rig.replica.get(), probe.sink());
    rig.source.write(lineNo(0) + '\n');
    CHECK(waitFor([&]() { return probe.lines.size() >= 61; }, 8000));
    writer.stop();
    pump(200);
    CHECK(nestedRuns == 1);
    CHECK(inOrder(probe.lines, 0, 61));
    CHECK(probe.maxDepth == 1); // the sink was never re-entered from its own nested loop
    CHECK(probe.maxLoopLevel == 0);
    CHECK(reader.readsIssued() == rig.source.errReads);
    std::fprintf(stderr, "R2 blocking sink: 61 signals -> %d reads, %d sink calls, max sink depth %d\n",
                 rig.source.errReads, probe.calls, probe.maxDepth);
}

static void stopDropsAndEnds()
{
    Rig rig;
    CHECK(rig.up("stop"));
    SinkProbe probe;
    ProcessStderrReader reader(rig.replica.get(), probe.sink());
    rig.source.write(lineNo(0) + '\n');
    // One pass at a time, so the stop comes right after the read is issued and before its reply is handled.
    QElapsedTimer t;
    t.start();
    while (reader.readsIssued() == 0 && t.elapsed() < 5000)
        QCoreApplication::processEvents(QEventLoop::AllEvents);
    CHECK(reader.readsIssued() == 1);
    reader.stop();
    pump(200);
    CHECK(rig.source.errReads == 1); // the read reached the service
    CHECK(probe.calls == 0);         // and its reply was dropped
    for (int i = 1; i < 20; ++i)
        rig.source.write(lineNo(i) + '\n');
    pump(300);
    CHECK(rig.source.errReads == 1); // no read after stop()
    CHECK(probe.calls == 0);
}

static void sinkDestroysReader()
{
    Rig rig;
    CHECK(rig.up("destroy"));
    SinkProbe probe;
    auto *owner = new QObject; // the protocol that owns the reader
    ProcessStderrReader *reader = nullptr;
    probe.extra = [&](const QList<QByteArray> &) {
        delete owner; // the reader goes with its parent, inside its own completion
        owner = nullptr;
    };
    reader = new ProcessStderrReader(rig.replica.get(), probe.sink(), owner);
    Q_UNUSED(reader)
    rig.source.write(lineNo(0) + '\n');
    for (int i = 1; i < 10; ++i)
        rig.source.write(lineNo(i) + '\n', false);
    CHECK(waitFor([&]() { return probe.calls == 1; }));
    for (int i = 10; i < 20; ++i)
        rig.source.write(lineNo(i) + '\n');
    pump(300);
    CHECK(owner == nullptr);
    CHECK(probe.calls == 1); // nothing reached a destroyed reader
}

static void lines()
{
    LineAssembler a;
    CHECK(a.feed("one\ntw") == QList<QByteArray>{"one"});
    CHECK(a.feed("o\n\n  \nthree\r\nfo") == (QList<QByteArray>{"two", "three"}));
    CHECK(a.feed(QByteArray()).isEmpty());
    CHECK(a.feed("ur\n") == QList<QByteArray>{"four"});
    LineAssembler capped;
    const QByteArray endless(LineAssembler::kMaxTail + 10, 'x');
    const QList<QByteArray> out = capped.feed(endless);
    CHECK(out.size() == 1 && out.first().size() == endless.size());
    CHECK(capped.feed("tail\n") == QList<QByteArray>{"tail"});
}

static void pumpRule()
{
    OutputReadPump p;
    CHECK(p.onReady());   // idle -> read
    CHECK(!p.onReady());  // in flight -> marked
    CHECK(!p.onReady());  // still one mark
    CHECK(p.onReadDone()); // the mark -> one more read
    CHECK(!p.onReadDone()); // nothing marked meanwhile -> idle
    CHECK(p.onReady());
    CHECK(!p.onReadDone());
    CHECK(!p.inFlight && !p.more);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    pumpRule();
    lines();
    burst();
    blockingSink();
    stopDropsAndEnds();
    sinkDestroysReader();
    if (g_failed) {
        std::fprintf(stderr, "tun2socks_reader_check: %d of %d checks FAILED\n", g_failed, g_checks);
        return 1;
    }
    std::printf("tun2socks_reader_check: all %d checks passed\n", g_checks);
    return 0;
}
