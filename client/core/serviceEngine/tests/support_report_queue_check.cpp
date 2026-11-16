// AVPN - L9 (F12): checks of the support-report queue (SupportReportQueue.h) and, with
// SRQ_WITH_CHAT, of TribeSupportChat's delivery through it against a local fake backend.
// Run: tests/build_support_report_queue.sh (QT_ROOT=$HOME/Qt/6.11.1/macos);
//      tests/build_support_report_queue.sh --mutate = the mutation pass (queue part only).
// The header is included with angle brackets on purpose: the mutation pass puts a mutated copy
// first on the include path.
#include <SupportReportQueue.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QTemporaryDir>
#include <QUuid>

#include <cstdio>
#include <memory>

#ifdef SRQ_WITH_CHAT
#include <QElapsedTimer>
#include <QEventLoop>
#include <QHostAddress>
#include <QNetworkAccessManager>
#include <QStandardPaths>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QUuid>

#include "../TribeSupportChat.h"
#endif

using namespace avpn::srq;

namespace {

int g_checks = 0;
int g_failed = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_checks;                                                                                \
        if (!(cond)) {                                                                             \
            ++g_failed;                                                                            \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
        }                                                                                          \
    } while (0)

constexpr qint64 kT0 = 1763251200000; // 2025-11-16 00:00 UTC

struct World {
    QTemporaryDir tmp;
    qint64 now = kT0;
    QString dir() const { return tmp.path() + QStringLiteral("/q"); }
    std::unique_ptr<SupportReportQueue> open(Limits l = Limits(), SupportReportQueue::IdGen ids = {})
    {
        auto q = std::make_unique<SupportReportQueue>(dir(), [this] { return now; }, l, std::move(ids));
        q->load();
        return q;
    }
};

// Ids that sort AGAINST creation order: ordering by id instead of the sequence is caught.
SupportReportQueue::IdGen descendingIds()
{
    auto n = std::make_shared<quint32>(0xfffffff0u);
    return [n] { return QStringLiteral("%1-0000-4000-8000-000000000000").arg((*n)--, 8, 16, QLatin1Char('0')); };
}

QList<PartInput> report(const QByteArray &human, const QByteArray &diag = QByteArray(),
                        const QByteArray &bench = QByteArray())
{
    QList<PartInput> parts;
    if (!human.isEmpty())
        parts.append({PartKind::Text, human});
    if (!diag.isEmpty())
        parts.append({PartKind::Log, diag});
    if (!bench.isEmpty())
        parts.append({PartKind::Bench, bench});
    return parts;
}

int reportFiles(const QString &dir)
{
    int n = 0;
    for (const QString &name : QDir(dir).entryList({QStringLiteral("*.json")}, QDir::Files))
        if (name != QLatin1String("outcomes.json"))
            ++n;
    return n;
}

QString partId(const SupportReportQueue &q, const QString &reportId, PartKind kind)
{
    for (const Entry &e : q.entries())
        if (e.id == reportId)
            for (const PartInfo &p : e.parts)
                if (p.kind == kind)
                    return p.id;
    return QString();
}

const PartInfo *partOf(const SupportReportQueue &q, const QString &reportId, PartKind kind)
{
    for (const Entry &e : q.entries())
        if (e.id == reportId)
            for (const PartInfo &p : e.parts)
                if (p.kind == kind)
                    return &p;
    return nullptr;
}

// The decoded payload of one part as stored in a report file ("" when absent or broken).
QByteArray storedPayload(const QString &path, PartKind kind)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return QByteArray();
    const QJsonArray parts = QJsonDocument::fromJson(f.readAll()).object().value(QStringLiteral("parts")).toArray();
    for (const QJsonValue &v : parts)
        if (v.toObject().value(QStringLiteral("kind")).toString() == kindName(kind))
            return QByteArray::fromBase64(v.toObject().value(QStringLiteral("data")).toString().toLatin1());
    return QByteArray();
}

// Enqueues a text+log report and has the server reject its log (413); returns its id.
QString rejectOne(SupportReportQueue &q, const QByteArray &tag)
{
    const QString id = q.enqueue(report(tag, QByteArray("diag ") + tag)).reportId;
    for (int guard = 0; guard < 4; ++guard) {
        const auto d = q.takeNext();
        if (!d)
            break;
        if (d->kind == PartKind::Log)
            q.fail(d->reportId, d->partId, Response::Terminal, 413);
        else
            q.ack(d->reportId, d->partId);
        if (q.status(id).state == ReportState::Rejected)
            break;
    }
    return id;
}

// Takes the next part and acknowledges it; returns "<reportId>/<kind>" or "" when nothing is due.
QString deliverOne(SupportReportQueue &q)
{
    const auto due = q.takeNext();
    if (!due)
        return QString();
    q.ack(due->reportId, due->partId);
    return due->reportId + QLatin1Char('/') + kindName(due->kind);
}

void tEnqueueAckById()
{
    World w;
    auto q = w.open();
    const EnqueueOutcome a = q->enqueue(report("hello", "diag"));
    CHECK(a.result == EnqueueResult::Queued);
    CHECK(!QUuid(a.reportId).isNull());
    CHECK(q->count() == 1);
    CHECK(QFile::exists(q->pathFor(a.reportId)));
    const QString textId = partId(*q, a.reportId, PartKind::Text);
    const QString logId = partId(*q, a.reportId, PartKind::Log);
    CHECK(!textId.isEmpty() && !logId.isEmpty() && textId != logId && textId != a.reportId);

    const auto d1 = q->takeNext();
    CHECK(d1 && d1->kind == PartKind::Text && d1->data == "hello" && d1->partId == textId);
    CHECK(q->inFlight());
    CHECK(!q->takeNext()); // one in flight
    CHECK(q->status(a.reportId).state == ReportState::Sending);
    CHECK(q->ack(a.reportId, textId) == AckResult::Acked);
    CHECK(q->count() == 1 && QFile::exists(q->pathFor(a.reportId)));
    CHECK(q->status(a.reportId).state == ReportState::Queued);

    const auto d2 = q->takeNext();
    CHECK(d2 && d2->kind == PartKind::Log && d2->data == "diag" && d2->partId == logId);
    CHECK(q->ack(a.reportId, logId) == AckResult::Finished);
    CHECK(q->count() == 0 && !QFile::exists(q->pathFor(a.reportId)));
    const Status s = q->status(a.reportId);
    CHECK(s.state == ReportState::Delivered);
    CHECK(s.parts.value(QStringLiteral("text")) == QLatin1String("acked"));
    CHECK(s.parts.value(QStringLiteral("log")) == QLatin1String("acked"));
    CHECK(q->ack(a.reportId, logId) == AckResult::UnknownReport);
    CHECK(q->status(QUuid::createUuid().toString(QUuid::WithoutBraces)).state == ReportState::Unknown);
}

void tTwoOfflineThenOnline()
{
    World w;
    auto q = w.open(Limits(), descendingIds());
    const QString a = q->enqueue(report("A", "diag A")).reportId;
    const QString b = q->enqueue(report("B", "diag B")).reportId; // same clock ms as A
    CHECK(b < a); // ids sort against creation order
    auto d = q->takeNext();
    CHECK(d && d->reportId == a && d->kind == PartKind::Text);
    q->fail(d->reportId, d->partId, classify(PartKind::Text, 0), 0); // offline
    CHECK(!q->takeNext()); // A's head is held; B waits behind A
    CHECK(q->status(a).state == ReportState::Queued);

    q = w.open(Limits(), descendingIds()); // restart while offline
    CHECK(q->count() == 2);
    CHECK(q->entries().at(0).id == a && q->entries().at(1).id == b);
    q->networkBack(); // a live answer arrived
    QStringList order;
    for (QString s = deliverOne(*q); !s.isEmpty(); s = deliverOne(*q))
        order << s;
    CHECK(order == (QStringList{a + "/text", a + "/log", b + "/text", b + "/log"}));
    CHECK(q->status(a).state == ReportState::Delivered && q->status(b).state == ReportState::Delivered);
    CHECK(reportFiles(w.dir()) == 0);
}

void tPartOrderCanonical()
{
    World w;
    auto q = w.open();
    const QString id = q->enqueue({{PartKind::Log, "L"}, {PartKind::Text, "T"}}).reportId;
    const auto d = q->takeNext();
    CHECK(d && d->reportId == id && d->kind == PartKind::Text);
}

void tKillBetweenSteps()
{
    World w;
    {
        auto q = w.open();
        q->setCrashHook([](const char *step) { return qstrcmp(step, "enqueue_before_commit") != 0; });
        CHECK(q->enqueue(report("x", "y")).result == EnqueueResult::IoError);
        CHECK(q->count() == 0);
    }
    CHECK(w.open()->count() == 0 && reportFiles(w.dir()) == 0); // death before commit: nothing half-written

    QString id;
    {
        auto q = w.open();
        id = q->enqueue(report("x", "y")).reportId;
    }
    QString textId;
    {
        auto q = w.open(); // death after the write, before any send
        CHECK(q->count() == 1);
        textId = partId(*q, id, PartKind::Text);
        const auto d = q->takeNext();
        CHECK(d && d->partId == textId);
    }
    {
        auto q = w.open(); // death while in flight: the same part again
        const auto d = q->takeNext();
        CHECK(d && d->partId == textId);
        q->setCrashHook([](const char *step) { return qstrcmp(step, "persist_before_commit") != 0; });
        CHECK(q->ack(id, textId) == AckResult::Acked);
    }
    {
        auto q = w.open(); // death between the server's accept and the local ack: sent again (at least once)
        CHECK(partOf(*q, id, PartKind::Text)->state == PartState::Pending);
        const auto d = q->takeNext();
        CHECK(d && d->partId == textId);
        CHECK(q->ack(id, textId) == AckResult::Acked);
    }
    QString logId;
    {
        auto q = w.open(); // the ack survived
        CHECK(partOf(*q, id, PartKind::Text)->state == PartState::Acked);
        const auto d = q->takeNext();
        CHECK(d && d->kind == PartKind::Log);
        logId = d->partId;
        q->setCrashHook([](const char *step) { return qstrcmp(step, "finalize_after_journal") != 0; });
        CHECK(q->ack(id, logId) == AckResult::Finished);
        CHECK(QFile::exists(q->pathFor(id))); // died before the file removal
    }
    {
        auto q = w.open(); // the journal settles it: not sent again
        CHECK(q->count() == 0);
        CHECK(!q->takeNext());
        CHECK(!QFile::exists(q->pathFor(id)));
        CHECK(q->status(id).state == ReportState::Delivered);
    }
    {
        auto q = w.open();
        const QString id2 = q->enqueue(report("z")).reportId;
        const auto d = q->takeNext();
        q->setCrashHook([](const char *step) { return qstrcmp(step, "persist_before_commit") != 0; });
        q->fail(id2, d->partId, Response::RetryServer, 503);
        auto q2 = w.open(); // death before the hold was written: due at once, nothing lost
        CHECK(q2->count() == 1);
        CHECK(q2->takeNext().has_value());
    }
}

void tFullQueueRefusesKeepsAll()
{
    World w;
    auto q = w.open();
    QStringList ids;
    for (int i = 0; i < 20; ++i) {
        const EnqueueOutcome o = q->enqueue(report(QByteArray("r") + QByteArray::number(i), "d"));
        CHECK(o.result == EnqueueResult::Queued);
        ids << o.reportId;
    }
    CHECK(q->count() == 20);
    CHECK(!q->canAccept() && q->full());
    CHECK(q->reserve().isEmpty());
    CHECK(q->enqueue(report("21st", "d")).result == EnqueueResult::Full);
    CHECK(q->count() == 20 && reportFiles(w.dir()) == 20);
    q = w.open();
    CHECK(q->count() == 20);
    QStringList loaded;
    for (const Entry &e : q->entries())
        loaded << e.id;
    CHECK(loaded == ids); // nothing dropped, order kept
    // Acks free the space and lift the backpressure.
    CHECK(deliverOne(*q) == ids.at(0) + "/text");
    CHECK(!q->canAccept()); // a log part still pending: the report still occupies its slot
    CHECK(deliverOne(*q) == ids.at(0) + "/log");
    CHECK(q->canAccept() && !q->reserve().isEmpty());
}

void tDiskBoundBefore20()
{
    World w;
    auto q = w.open();
    const QByteArray big(int(q->limits().maxLogBytes), 'x');
    int n = 0;
    EnqueueResult last = EnqueueResult::Queued;
    while (n < 25) {
        last = q->enqueue(report("big", big)).result;
        if (last != EnqueueResult::Queued)
            break;
        ++n;
    }
    CHECK(last == EnqueueResult::Full);
    CHECK(n > 0 && n < 20);
    CHECK(q->diskBytes() <= q->limits().maxDiskBytes);
    CHECK(q->diskBytes() + q->entries().first().fileBytes > q->limits().maxDiskBytes);
    CHECK(!q->canAccept());
    CHECK(w.open()->count() == n);
}

void tReservations()
{
    World w;
    auto q = w.open();
    for (int i = 0; i < 19; ++i)
        q->enqueue(report("r"));
    const QString t = q->reserve();
    CHECK(!t.isEmpty());
    CHECK(q->reservations() == 1);
    CHECK(!q->canAccept());
    CHECK(q->reserve().isEmpty());
    CHECK(q->enqueue(report("no token")).result == EnqueueResult::Full);
    CHECK(q->enqueue(report("with token"), t).result == EnqueueResult::Queued); // admitted at its start
    CHECK(q->count() == 20 && q->reservations() == 0);
    CHECK(!q->release(t));

    World w2;
    auto q2 = w2.open();
    for (int i = 0; i < 19; ++i)
        q2->enqueue(report("r"));
    const QString t2 = q2->reserve();
    CHECK(!t2.isEmpty() && !q2->canAccept());
    w2.now += q2->limits().reservationTtlMs + 1; // a check that never finished
    CHECK(q2->canAccept());
    CHECK(q2->enqueue(report("after expiry")).result == EnqueueResult::Queued);
    const QString t3 = q2->reserve();
    CHECK(t3.isEmpty()); // 20 on disk
    World w3;
    auto q3 = w3.open();
    const QString t4 = q3->reserve();
    CHECK(q3->release(t4) && q3->reservations() == 0);
}

void tOversizedAndInvalid()
{
    World w;
    auto q = w.open();
    const Limits &l = q->limits();
    CHECK(q->enqueue(report("", QByteArray(int(l.maxLogBytes) + 1, 'x'))).result == EnqueueResult::TooLarge);
    CHECK(q->enqueue(report("", QByteArray(int(l.maxLogBytes), 'x'))).result == EnqueueResult::Queued);
    QString emoji;
    for (int i = 0; i < l.maxTextCodePoints; ++i)
        emoji += QString::fromUcs4(U"\U0001F600", 1);
    CHECK(emoji.size() == 2 * l.maxTextCodePoints); // UTF-16 units, the server counts code points
    CHECK(q->enqueue({{PartKind::Text, emoji.toUtf8()}}).result == EnqueueResult::Queued);
    CHECK(q->enqueue({{PartKind::Text, QByteArray(l.maxTextCodePoints + 1, 'a')}}).result
          == EnqueueResult::TooLarge);
    CHECK(q->enqueue({{PartKind::Text, QByteArray(l.maxTextCodePoints, 'a')}}).result == EnqueueResult::Queued);
    CHECK(q->enqueue(report("", "", QByteArray(int(l.maxBenchBytes) + 1, '{'))).result
          == EnqueueResult::TooLarge);
    CHECK(q->enqueue(report("", "", QByteArray(int(l.maxBenchBytes), '{'))).result == EnqueueResult::Queued);
    const int files = reportFiles(w.dir());
    CHECK(files == q->count() && files == 4);
    CHECK(q->enqueue({}).result == EnqueueResult::Empty);
    CHECK(q->enqueue({{PartKind::Text, "   \n"}}).result == EnqueueResult::Empty);
    CHECK(q->enqueue({{PartKind::Log, QByteArray()}}).result == EnqueueResult::Empty);
    CHECK(q->enqueue({{PartKind::Log, "a"}, {PartKind::Log, "b"}}).result == EnqueueResult::Invalid);
    CHECK(q->enqueue({{PartKind::Text, QByteArray("\xff\xfe bad", 6)}}).result == EnqueueResult::Invalid);
    CHECK(reportFiles(w.dir()) == files); // a refused report leaves nothing on disk
    CHECK(worstCaseFileBytes(l) < qint64(4) * 1024 * 1024);
}

void tRateLimitKept()
{
    World w;
    auto q = w.open();
    const QString a = q->enqueue(report("A")).reportId;
    auto d = q->takeNext();
    q->fail(a, d->partId, classify(PartKind::Text, 429), 429);
    CHECK(q->count() == 1 && q->status(a).state == ReportState::Queued);
    q->networkBack();
    q->foreground();
    CHECK(!q->takeNext()); // the server's window is respected
    w.now += q->limits().supportRateHoldMs - 1;
    CHECK(!q->takeNext());
    q = w.open(); // the hold survives a restart
    CHECK(!q->takeNext());
    w.now += 1;
    d = q->takeNext();
    CHECK(d && d->reportId == a);
    q->ack(a, d->partId);

    const QString b = q->enqueue(report("", "", "{\"schema\":5}")).reportId;
    d = q->takeNext();
    CHECK(d && d->kind == PartKind::Bench && d->data == "{\"schema\":5}");
    q->fail(b, d->partId, classify(PartKind::Bench, 429), 429);
    w.now += q->limits().supportRateHoldMs + 1;
    q->networkBack();
    CHECK(!q->takeNext()); // bench: one hour per device
    w.now += q->limits().benchRateHoldMs - q->limits().supportRateHoldMs - 1;
    CHECK(q->takeNext().has_value());
}

void tTerminalSetAside()
{
    World w;
    auto q = w.open();
    const QString a = q->enqueue(report("A", "diag A")).reportId;
    const QString b = q->enqueue(report("B")).reportId;
    CHECK(deliverOne(*q) == a + "/text");
    auto d = q->takeNext();
    CHECK(d && d->reportId == a && d->kind == PartKind::Log);
    q->fail(a, d->partId, classify(PartKind::Log, 413), 413);
    const Status s = q->status(a);
    CHECK(s.state == ReportState::Rejected);
    CHECK(s.reason == QLatin1String("log:413"));
    CHECK(s.parts.value(QStringLiteral("text")) == QLatin1String("acked"));
    CHECK(s.parts.value(QStringLiteral("log")) == QLatin1String("rejected"));
    CHECK(s.kept);
    // F4: the payload is kept - moved to the rejected store, not deleted.
    CHECK(!QFile::exists(q->pathFor(a)) && QFile::exists(q->rejectedPathFor(a)));
    CHECK(q->rejected().size() == 1 && q->count() == 1);
    CHECK(storedPayload(q->rejectedPathFor(a), PartKind::Log) == "diag A");
    CHECK(storedPayload(q->rejectedPathFor(a), PartKind::Text) == "A");
    CHECK(deliverOne(*q) == b + "/text"); // the queue is not blocked
    q = w.open();
    CHECK(q->status(a).state == ReportState::Rejected && q->status(a).reason == QLatin1String("log:413"));
    CHECK(q->status(a).kept && q->rejected().size() == 1 && q->count() == 0);
    CHECK(!q->takeNext()); // a rejected report is not sent again on its own

    // The journal is bounded.
    QString first;
    for (int i = 0; i < 40; ++i) {
        const QString id = q->enqueue(report("j")).reportId;
        if (i == 0)
            first = id;
        deliverOne(*q);
    }
    CHECK(q->outcomes().size() == q->limits().maxOutcomes);
    q = w.open();
    CHECK(q->outcomes().size() == q->limits().maxOutcomes);
    CHECK(q->status(first).state == ReportState::Unknown);
}

void tRejectedStoreBound()
{
    World w;
    auto q = w.open();
    const QString queued = q->enqueue(report("", "", "{\"schema\":5}")).reportId; // stays queued throughout
    {
        const auto d = q->takeNext();
        q->fail(d->reportId, d->partId, Response::RateLimited, 429);
    }
    QStringList ids;
    for (int i = 0; i < 7; ++i) {
        ids << rejectOne(*q, QByteArray("R") + QByteArray::number(i));
        w.now += 1000;
    }
    CHECK(q->rejected().size() == q->limits().maxRejected);
    CHECK(q->status(ids.at(0)).state == ReportState::Rejected && !q->status(ids.at(0)).kept);
    CHECK(q->status(ids.at(0)).reason == QLatin1String("evicted:log:413")); // the removal is journalled
    CHECK(q->status(ids.at(1)).reason == QLatin1String("evicted:log:413"));
    CHECK(!QFile::exists(q->rejectedPathFor(ids.at(0))) && !QFile::exists(q->rejectedPathFor(ids.at(1))));
    for (int i = 2; i < 7; ++i)
        CHECK(q->status(ids.at(i)).kept && QFile::exists(q->rejectedPathFor(ids.at(i))));
    CHECK(q->count() == 1 && q->entries().first().id == queued); // queued reports are never evicted
    q = w.open();
    CHECK(q->rejected().size() == q->limits().maxRejected && q->count() == 1);

    // The byte bound evicts the oldest too.
    World w2;
    Limits l;
    const qint64 one = [&] {
        World probe;
        auto pq = probe.open();
        const QString id = rejectOne(*pq, "B0");
        return QFileInfo(pq->rejectedPathFor(id)).size();
    }();
    l.maxRejectedBytes = 3 * one + one / 2;
    auto q2 = w2.open(l);
    QStringList big;
    for (int i = 0; i < 5; ++i) {
        big << rejectOne(*q2, QByteArray("B") + QByteArray::number(i));
        w2.now += 1000;
    }
    CHECK(q2->rejected().size() == 3 && q2->rejectedBytes() <= l.maxRejectedBytes);
    CHECK(!q2->status(big.at(0)).kept && !q2->status(big.at(1)).kept && q2->status(big.at(4)).kept);
}

void tRejectedRetryOnce()
{
    World w;
    auto q = w.open();
    q->setContext(QStringLiteral("5.1.110"), QStringLiteral("L1"));
    const QString a = rejectOne(*q, "A");
    CHECK(q->retryRejected() == 0); // same context: nothing to retry
    q = w.open();
    q->setContext(QStringLiteral("5.1.110"), QStringLiteral("L1"));
    CHECK(q->retryRejected() == 0);
    q->setContext(QStringLiteral("5.1.111"), QStringLiteral("L1")); // the app was updated
    CHECK(q->retryRejected() == 1);
    CHECK(q->status(a).state == ReportState::Queued && q->rejected().isEmpty());
    CHECK(!QFile::exists(q->rejectedPathFor(a)) && QFile::exists(q->pathFor(a)));
    CHECK(partOf(*q, a, PartKind::Text)->state == PartState::Acked); // only the rejected part goes again
    q = w.open(); // the retry survives a restart as a queued report
    q->setContext(QStringLiteral("5.1.111"), QStringLiteral("L1"));
    CHECK(q->count() == 1 && q->status(a).state == ReportState::Queued);
    auto d = q->takeNext();
    CHECK(d && d->reportId == a && d->kind == PartKind::Log && d->data == "diag A");
    q->fail(a, d->partId, Response::Terminal, 413); // rejected again
    CHECK(q->status(a).kept);
    q = w.open();
    q->setContext(QStringLiteral("5.1.112"), QStringLiteral("L2"));
    CHECK(q->retryRejected() == 0); // once
    CHECK(q->status(a).kept && q->count() == 0);
    CHECK(q->resendRejected() == 1); // the user's «Отправить логи» still sends it
    CHECK(q->status(a).state == ReportState::Queued);

    // A change of the server's limits is the other signal; an unknown context never counts.
    World w2;
    auto q2 = w2.open();
    q2->setContext(QStringLiteral("5.1.110"), QStringLiteral("L1"));
    const QString b = rejectOne(*q2, "B");
    q2->setContext(QStringLiteral("5.1.110"), QString());
    const QString c = rejectOne(*q2, "C"); // limits not observed yet
    q2->setContext(QStringLiteral("5.1.110"), QStringLiteral("L2"));
    CHECK(q2->retryRejected() == 1);
    CHECK(q2->status(b).state == ReportState::Queued && q2->status(c).kept);

    // No room in the queue: the retry waits, nothing is lost.
    World w3;
    auto q3 = w3.open();
    q3->setContext(QStringLiteral("1"), QString());
    const QString r = rejectOne(*q3, "R");
    for (int i = 0; i < 20; ++i)
        q3->enqueue(report("fill"));
    q3->setContext(QStringLiteral("2"), QString());
    CHECK(q3->retryRejected() == 0 && q3->status(r).kept && q3->count() == 20);
}

void tRejectedKillSteps()
{
    // Death after the final rewrite, before the journal: load() journals and moves it.
    for (const char *step : {"reject_after_persist", "reject_after_journal"}) {
        World w;
        QString a;
        {
            auto q = w.open();
            const std::string st = step;
            q->setCrashHook([st](const char *s) { return st != s; });
            a = rejectOne(*q, "A");
            CHECK(QFile::exists(q->pathFor(a))); // died before the move
        }
        auto q = w.open();
        CHECK(q->count() == 0 && q->status(a).kept && QFile::exists(q->rejectedPathFor(a)));
        CHECK(storedPayload(q->rejectedPathFor(a), PartKind::Log) == "diag A");
        CHECK(q->status(a).reason == QLatin1String("log:413"));
    }
    {
        // Death before the final rewrite reached the disk: the part is simply pending again (sent again).
        World w;
        QString a;
        {
            auto q = w.open();
            q->setCrashHook([](const char *s) {
                return qstrcmp(s, "reject_after_persist") != 0 && qstrcmp(s, "persist_before_commit") != 0;
            });
            a = rejectOne(*q, "A");
        }
        auto q = w.open();
        CHECK(q->count() == 1 && partOf(*q, a, PartKind::Log)->state == PartState::Pending);
    }
    {
        // Death after the eviction's journal, before the removal: the bound holds after load().
        World w;
        QString first;
        {
            auto q = w.open();
            for (int i = 0; i < q->limits().maxRejected; ++i) {
                const QString id = rejectOne(*q, QByteArray("E") + QByteArray::number(i));
                if (i == 0)
                    first = id;
                w.now += 1000;
            }
            q->setCrashHook([](const char *s) { return qstrcmp(s, "evict_after_journal") != 0; });
            rejectOne(*q, "E5");
            CHECK(QFile::exists(q->rejectedPathFor(first)));
        }
        auto q = w.open();
        CHECK(q->rejected().size() == q->limits().maxRejected);
        CHECK(!QFile::exists(q->rejectedPathFor(first)) && q->status(first).reason.startsWith(QLatin1String("evicted:")));
    }
    // Death inside a retry move, after the mark or after the journal: load() finishes the move.
    for (const char *step : {"requeue_after_mark", "requeue_after_journal"}) {
        World w;
        QString a;
        {
            auto q = w.open();
            q->setContext(QStringLiteral("1"), QString());
            a = rejectOne(*q, "A");
            q->setContext(QStringLiteral("2"), QString());
            const std::string st = step;
            q->setCrashHook([st](const char *s) { return st != s; });
            CHECK(q->retryRejected() == 0);
        }
        auto q = w.open();
        CHECK(q->count() == 1 && q->rejected().isEmpty() && q->status(a).state == ReportState::Queued);
        CHECK(QFile::exists(q->pathFor(a)) && !QFile::exists(q->rejectedPathFor(a)));
        const auto d = q->takeNext();
        CHECK(d && d->kind == PartKind::Log && d->data == "diag A");
        q->fail(a, d->partId, Response::Terminal, 413);
        q = w.open();
        q->setContext(QStringLiteral("3"), QString());
        CHECK(q->retryRejected() == 0 && q->status(a).kept); // the interrupted move used the one retry
    }
}

// F4 addition: an evicted rejected report leaves a notice that rides on the next report's text.
void tEvictionNotices()
{
    World w;
    auto q = w.open();
    QStringList ids;
    qint64 firstCreated = 0;
    for (int i = 0; i < 6; ++i) { // the 6th rejection evicts the oldest
        if (i == 0)
            firstCreated = w.now;
        ids << rejectOne(*q, QByteArray("R") + QByteArray::number(i));
        w.now += 60000;
    }
    CHECK(q->notices().size() == 1);
    const Notice n = q->notices().first();
    CHECK(n.reportId == ids.at(0) && n.createdAtMs == firstCreated);
    CHECK(n.refused.value(QStringLiteral("log")) == 413 && n.refused.size() == 1);
    CHECK(n.delivered == QStringList{QStringLiteral("text")});
    q = w.open();
    CHECK(q->notices().size() == 1); // journalled

    // The next report's text carries one line per notice, after the user's own text.
    const QString carrier = q->enqueue(report("Human N", "diag N")).reportId;
    const QString second = q->enqueue(report("Human M")).reportId;
    auto d = q->takeNext();
    CHECK(d && d->reportId == carrier && d->kind == PartKind::Text);
    CHECK(d->data.startsWith("Human N\n\n") && d->data.contains(defaultNoticeLine(n).toUtf8()));
    CHECK(d->data.contains("413 for its log") && d->data.contains("delivered: text"));
    q->fail(carrier, d->partId, Response::RetryNetwork, 0); // not delivered yet: the notice stays
    CHECK(q->notices().size() == 1);
    q = w.open();
    CHECK(q->notices().size() == 1);
    CHECK(q->entries().at(1).id == second && !q->entries().at(1).text.contains(QStringLiteral("could not be delivered")));
    // A log ack does not clear it; only the carrying text part's ack does.
    CHECK(q->ack(carrier, partId(*q, carrier, PartKind::Log)) == AckResult::Acked);
    CHECK(q->notices().size() == 1);
    CHECK(q->ack(carrier, partId(*q, carrier, PartKind::Text)) == AckResult::Finished);
    CHECK(q->notices().isEmpty());
    q = w.open();
    CHECK(q->notices().isEmpty());

    // A log-only report gets a text part for the notices; a full text keeps them for a later report.
    World w2;
    auto q2 = w2.open();
    for (int i = 0; i < 6; ++i) {
        rejectOne(*q2, QByteArray("S") + QByteArray::number(i));
        w2.now += 1000;
    }
    const QString capped = q2->enqueue({{PartKind::Text, QByteArray(q2->limits().maxTextCodePoints, 'a')}}).reportId;
    CHECK(q2->entries().last().id == capped && q2->entries().last().text.size() == q2->limits().maxTextCodePoints);
    CHECK(q2->entries().last().noticeIds.isEmpty());
    const QString logOnly = q2->enqueue(report("", "only a log")).reportId;
    const Entry &lo = q2->entries().last();
    CHECK(lo.id == logOnly && lo.partOfKind(PartKind::Text) && lo.noticeIds.size() == 1);
    CHECK(lo.text.contains(QStringLiteral("could not be delivered")));
    // The carrier's text refused (422): the notice is free again for the next report.
    deliverOne(*q2); // capped text
    d = q2->takeNext();
    CHECK(d && d->reportId == logOnly && d->kind == PartKind::Text);
    q2->fail(logOnly, d->partId, Response::Terminal, 422);
    CHECK(q2->notices().size() == 1);
    const QString again = q2->enqueue(report("Again")).reportId;
    CHECK(q2->entries().last().id == again && q2->entries().last().noticeIds.size() == 1);

    // The text delivered while the log still waits: the notice is cleared at once, not carried twice.
    World w4;
    auto q4 = w4.open();
    for (int i = 0; i < 6; ++i) {
        rejectOne(*q4, QByteArray("U") + QByteArray::number(i));
        w4.now += 1000;
    }
    const QString c4 = q4->enqueue(report("Carrier", "diag")).reportId;
    CHECK(deliverOne(*q4) == c4 + "/text");
    CHECK(q4->notices().isEmpty() && q4->count() == 1);
    q4->enqueue(report("After"));
    CHECK(q4->entries().last().noticeIds.isEmpty());

        // Bounded: the last 10. These reports' texts are refused (422), so no carrier delivers the notices.
    World w3;
    auto q3 = w3.open();
    QStringList evicted;
    for (int i = 0; i < 17; ++i) {
        const QString id = q3->enqueue(report(QByteArray("T") + QByteArray::number(i))).reportId;
        const auto t = q3->takeNext();
        CHECK(t && t->reportId == id);
        q3->fail(id, t->partId, Response::Terminal, 422);
        evicted << id;
        w3.now += 1000;
    }
    CHECK(q3->notices().size() == q3->limits().maxNotices);
    CHECK(q3->notices().first().reportId == evicted.at(2) && q3->notices().last().reportId == evicted.at(11));
}

void tEvictionNoticeKillSteps()
{
    for (const char *step : {"evict_before_journal", "evict_after_journal"}) {
        World w;
        QString first;
        {
            auto q = w.open();
            for (int i = 0; i < 5; ++i) {
                const QString id = rejectOne(*q, QByteArray("K") + QByteArray::number(i));
                if (i == 0)
                    first = id;
                w.now += 1000;
            }
            const std::string st = step;
            q->setCrashHook([st](const char *s) { return st != s; });
            rejectOne(*q, "K5"); // dies between the eviction and its notice / the file removal
        }
        auto q = w.open();
        CHECK(q->rejected().size() == q->limits().maxRejected);
        CHECK(!QFile::exists(q->rejectedPathFor(first)));
        CHECK(q->notices().size() == 1 && q->notices().first().reportId == first); // exactly once
        q = w.open();
        CHECK(q->notices().size() == 1);
    }
    {
        // Death between the carrying text's ack reaching the report file and the journal write.
        World w;
        QString carrier;
        {
            auto q = w.open();
            for (int i = 0; i < 6; ++i) {
                rejectOne(*q, QByteArray("A") + QByteArray::number(i));
                w.now += 1000;
            }
            carrier = q->enqueue(report("C", "diag C")).reportId;
            q->setCrashHook([](const char *s) { return qstrcmp(s, "ack_after_persist") != 0; });
            CHECK(deliverOne(*q) == carrier + "/text");
            CHECK(q->notices().size() == 1); // died before the journal write
        }
        auto q = w.open();
        CHECK(q->notices().isEmpty()); // the report file says the text was delivered
        CHECK(partOf(*q, carrier, PartKind::Text)->state == PartState::Acked);
    }
    {
        // Death after the carrier was written: it still carries the notice after a restart (no second copy).
        World w;
        {
            auto q = w.open();
            for (int i = 0; i < 6; ++i) {
                rejectOne(*q, QByteArray("B") + QByteArray::number(i));
                w.now += 1000;
            }
            q->enqueue(report("first"));
        }
        auto q = w.open();
        q->enqueue(report("second"));
        CHECK(q->entries().size() == 2);
        CHECK(q->entries().at(0).noticeIds.size() == 1 && q->entries().at(1).noticeIds.isEmpty());
    }
}

void tLegacyMigration()
{
    World w;
    const QString ini = w.tmp.path() + QStringLiteral("/settings.ini");
    const QString key = QStringLiteral("AvpnSupport/pendingDiag");
    {
        QSettings st(ini, QSettings::IniFormat);
        st.setValue(key, QStringLiteral("legacy diag"));
        st.sync();
        auto q = w.open();
        const EnqueueOutcome o = q->migrateLegacySetting(st);
        CHECK(o.result == EnqueueResult::Queued);
        CHECK(!st.contains(key));
        CHECK(q->count() == 1 && q->entries().first().parts.size() == 1);
        CHECK(q->entries().first().parts.first().kind == PartKind::Log);
        const auto d = q->takeNext();
        CHECK(d && d->data == "legacy diag");
        q->abandon();
        CHECK(q->migrateLegacySetting(st).result == EnqueueResult::Empty); // once
        CHECK(q->count() == 1);
    }
    World w2;
    {
        QSettings st(w2.tmp.path() + QStringLiteral("/s.ini"), QSettings::IniFormat);
        st.setValue(key, QStringLiteral("legacy 2"));
        auto q = w2.open();
        q->setCrashHook([](const char *step) { return qstrcmp(step, "migrate_before_key_removal") != 0; });
        q->migrateLegacySetting(st);
        CHECK(st.contains(key)); // died before the key removal
        q = w2.open();
        CHECK(q->migrateLegacySetting(st).result == EnqueueResult::Queued);
        CHECK(q->count() == 1 && !st.contains(key)); // no duplicate
        const QString id = q->entries().first().id;
        deliverOne(*q);
        st.setValue(key, QStringLiteral("legacy 2")); // the same old value again after delivery
        q = w2.open();
        q->migrateLegacySetting(st);
        CHECK(q->count() == 0 && q->status(id).state == ReportState::Delivered);
    }
    World w4;
    {
        QSettings st(w4.tmp.path() + QStringLiteral("/s.ini"), QSettings::IniFormat);
        st.setValue(key, QStringLiteral("legacy rejected"));
        auto q = w4.open();
        q->migrateLegacySetting(st);
        const auto d = q->takeNext();
        q->fail(d->reportId, d->partId, Response::Terminal, 415);
        CHECK(q->rejected().size() == 1);
        st.setValue(key, QStringLiteral("legacy rejected")); // the old value again
        q = w4.open();
        q->migrateLegacySetting(st);
        CHECK(q->count() == 0 && q->rejected().size() == 1); // no second copy
    }
    World w3;
    {
        QSettings st(w3.tmp.path() + QStringLiteral("/s.ini"), QSettings::IniFormat);
        auto q = w3.open();
        for (int i = 0; i < 20; ++i)
            q->enqueue(report("r"));
        st.setValue(key, QStringLiteral("legacy while full"));
        CHECK(q->migrateLegacySetting(st).result == EnqueueResult::Queued); // accepted earlier: never dropped
        CHECK(q->count() == 21 && !st.contains(key));
    }
}

void tAckWhileOtherInFlight()
{
    {
        // A younger report finishes while an older one waits: only the younger leaves.
        World w0;
        auto q0 = w0.open();
        const QString x = q0->enqueue(report("", "", "{\"schema\":5}")).reportId;
        const QString y = q0->enqueue(report("Y")).reportId;
        auto d0 = q0->takeNext();
        CHECK(d0 && d0->reportId == x);
        q0->fail(x, d0->partId, Response::RateLimited, 429);
        d0 = q0->takeNext();
        CHECK(d0 && d0->reportId == y);
        CHECK(q0->ack(y, d0->partId) == AckResult::Finished);
        CHECK(q0->count() == 1 && q0->entries().first().id == x);
        CHECK(QFile::exists(q0->pathFor(x)) && !QFile::exists(q0->pathFor(y)));
        CHECK(w0.open()->count() == 1);
    }
    World w;
    auto q = w.open();
    const QString a = q->enqueue(report("", "", "{\"schema\":5}")).reportId;
    const QString b = q->enqueue(report("B")).reportId;
    auto d = q->takeNext();
    CHECK(d && d->reportId == a);
    const QString aBench = d->partId;
    q->fail(a, aBench, Response::RateLimited, 429);
    d = q->takeNext();
    CHECK(d && d->reportId == b);
    const QString bText = d->partId;
    CHECK(q->ack(b, aBench) == AckResult::UnknownPart); // a part id of A under B's id
    CHECK(q->inFlight() && q->inFlightReport() == b);
    CHECK(q->ack(a, aBench) == AckResult::Finished); // late ack of A
    CHECK(q->status(a).state == ReportState::Delivered);
    CHECK(q->inFlight() && q->inFlightReport() == b && q->inFlightPart() == bText);
    CHECK(q->count() == 1 && q->entries().first().id == b);
    CHECK(partOf(*q, b, PartKind::Text)->state == PartState::Pending);
    CHECK(q->status(b).state == ReportState::Sending);
    CHECK(q->ack(b, bText) == AckResult::Finished);
    CHECK(!q->inFlight());
}

void tAttachmentParts()
{
    World w;
    auto q = w.open();
    const QString id = q->enqueue(report("T", "L", "{\"schema\":5}")).reportId;
    const QString t = partId(*q, id, PartKind::Text);
    const QString l = partId(*q, id, PartKind::Log);
    const QString b = partId(*q, id, PartKind::Bench);
    CHECK(QSet<QString>({t, l, b, id}).size() == 4);
    CHECK(q->ack(id, l) == AckResult::Acked); // the log ack arrives first
    CHECK(q->count() == 1 && partOf(*q, id, PartKind::Text)->state == PartState::Pending);
    CHECK(q->status(id).state == ReportState::Queued);
    auto d = q->takeNext();
    CHECK(d && d->partId == t);
    CHECK(q->ack(id, t) == AckResult::Acked);
    d = q->takeNext();
    CHECK(d && d->partId == b && d->kind == PartKind::Bench);
    CHECK(q->ack(id, l) == AckResult::NotPending);
    CHECK(q->inFlight()); // a stale ack does not clear another part's flight
    CHECK(q->ack(id, b) == AckResult::Finished);
    CHECK(q->status(id).state == ReportState::Delivered);
}

void tCorruptFiles()
{
    World w;
    auto q = w.open();
    const QString a = q->enqueue(report("A", "diag A")).reportId;
    const QString b = q->enqueue(report("B", "diag B")).reportId;
    const QString e = q->enqueue(report("E", "diag E")).reportId;
    const QString garbage = QUuid::createUuid().toString(QUuid::WithoutBraces);
    {
        QFile f(q->pathFor(garbage));
        CHECK(f.open(QIODevice::WriteOnly));
        f.write("not json at all");
    }
    {
        QFile f(q->pathFor(a)); // truncated in the middle
        CHECK(f.open(QIODevice::ReadOnly));
        const QByteArray raw = f.readAll();
        f.close();
        CHECK(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
        f.write(raw.left(raw.size() / 2));
    }
    {
        QFile f(q->pathFor(b)); // one payload byte changed, JSON still valid
        CHECK(f.open(QIODevice::ReadOnly));
        QJsonObject root = QJsonDocument::fromJson(f.readAll()).object();
        f.close();
        QJsonArray parts = root.value(QStringLiteral("parts")).toArray();
        QJsonObject p = parts.at(1).toObject();
        p.insert(QStringLiteral("data"), QString::fromLatin1(QByteArray("diag X").toBase64()));
        parts[1] = p;
        root.insert(QStringLiteral("parts"), parts);
        CHECK(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
        f.write(QJsonDocument(root).toJson());
    }
    q = w.open();
    CHECK(q->count() == 1 && q->entries().first().id == e);
    CHECK(q->loadProblems().size() == 3);
    CHECK(q->loadProblems().filter(QStringLiteral("corrupt:")).size() == 3);
    CHECK(q->loadProblems().filter(b + QStringLiteral(":checksum")).size() == 1);
    CHECK(!QFile::exists(q->pathFor(a)) && !QFile::exists(q->pathFor(b)) && !QFile::exists(q->pathFor(garbage)));
    CHECK(q->status(a).state == ReportState::Rejected && q->status(a).reason.startsWith(QLatin1String("corrupt:")));
    CHECK(deliverOne(*q) == e + "/text");

    // Unreadable: left in place, counted, loaded once readable again.
    const QString f = q->enqueue(report("F")).reportId;
    QFile::setPermissions(q->pathFor(f), QFileDevice::Permissions());
    q = w.open();
    CHECK(q->count() == 1 && q->blockedFiles() == 1);
    CHECK(QFile::exists(q->pathFor(f)));
    CHECK(q->loadProblems().filter(QStringLiteral("unreadable:") + f).size() == 1);
    CHECK(q->diskBytes() >= QFileInfo(q->pathFor(f)).size());
    QFile::setPermissions(q->pathFor(f), QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    q = w.open();
    CHECK(q->count() == 2 && q->blockedFiles() == 0);

    // A newer format after a rollback: left alone.
    const QString g = QUuid::createUuid().toString(QUuid::WithoutBraces);
    {
        QFile file(q->pathFor(g));
        CHECK(file.open(QIODevice::WriteOnly));
        file.write(QJsonDocument(QJsonObject{{QStringLiteral("format"), QStringLiteral("tribe-support-report")},
                                             {QStringLiteral("v"), 2},
                                             {QStringLiteral("id"), g}})
                       .toJson());
    }
    q = w.open();
    CHECK(QFile::exists(q->pathFor(g)) && q->blockedFiles() == 1);
    CHECK(q->loadProblems().filter(QStringLiteral("future:") + g).size() == 1);
    QFile::remove(q->pathFor(g));

    // A file that vanished under a pending report: reported, the queue moves on.
    World w2;
    auto q2 = w2.open();
    const QString h = q2->enqueue(report("", "diag H")).reportId;
    const QString i = q2->enqueue(report("", "diag I")).reportId;
    QFile::remove(q2->pathFor(h));
    const auto d = q2->takeNext();
    CHECK(d && d->reportId == i);
    CHECK(q2->status(h).state == ReportState::Rejected && q2->status(h).reason == QLatin1String("corrupt:missing"));
}

void tBackoffAndClock()
{
    World w;
    auto q = w.open();
    const QString a = q->enqueue(report("A")).reportId;
    const qint64 expect[] = {30000, 60000, 120000, 240000, 480000, 600000, 600000, 600000};
    for (const qint64 delay : expect) {
        const auto d = q->takeNext();
        CHECK(d.has_value());
        if (!d)
            return;
        q->fail(a, d->partId, Response::RetryNetwork, 0);
        CHECK(partOf(*q, a, PartKind::Text)->nextTryAtMs == w.now + delay);
        CHECK(!q->takeNext());
        w.now += delay;
    }
    // Server hold: networkBack keeps it, foreground clears it.
    auto d = q->takeNext();
    q->fail(a, d->partId, Response::RetryServer, 503);
    q->networkBack();
    CHECK(!q->takeNext());
    q->foreground();
    d = q->takeNext();
    CHECK(d.has_value());
    // Network hold: networkBack clears it.
    q->fail(a, d->partId, Response::RetryNetwork, 0);
    q->networkBack();
    d = q->takeNext();
    CHECK(d.has_value());
    // The wall clock moved back a day after the hold was written: due within the hold's maximum.
    q->fail(a, d->partId, Response::RetryNetwork, 0);
    w.now -= qint64(24) * 3600 * 1000;
    CHECK(!q->takeNext());
    w.now += q->limits().backoffMaxMs;
    CHECK(q->takeNext().has_value());
}

void tClassify()
{
    CHECK(classify(PartKind::Text, 200) == Response::Ack);
    CHECK(classify(PartKind::Log, 201) == Response::Ack);
    CHECK(classify(PartKind::Bench, 201, false) == Response::RetryServer);
    CHECK(classify(PartKind::Bench, 201, true) == Response::Ack);
    CHECK(classify(PartKind::Text, 0) == Response::RetryNetwork);
    CHECK(classify(PartKind::Bench, 429) == Response::RateLimited);
    CHECK(classify(PartKind::Text, 429) == Response::RateLimited);
    for (const int c : {401, 403, 408, 425, 500, 502, 503})
        CHECK(classify(PartKind::Log, c) == Response::RetryServer);
    for (const int c : {400, 404, 405, 413, 415, 422})
        CHECK(classify(PartKind::Log, c) == Response::Terminal);
}

void tWriteFailure()
{
    World w;
    auto q = w.open();
    QFile::setPermissions(w.dir(), QFileDevice::ReadOwner | QFileDevice::ExeOwner);
    CHECK(q->enqueue(report("A")).result == EnqueueResult::IoError);
    CHECK(q->count() == 0);
    QFile::setPermissions(w.dir(), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    CHECK(q->enqueue(report("A")).result == EnqueueResult::Queued);
}

#ifdef SRQ_WITH_CHAT
// ── TribeSupportChat over the queue, against a local fake backend ─────────────────────────────
class FakeBackend : public QObject {
public:
    struct Req {
        QString path;
        QByteArray body;
    };
    QList<Req> got;
    std::function<int(const QString &path)> statusFor = [](const QString &) { return 200; };

    bool start()
    {
        connect(&m_srv, &QTcpServer::newConnection, this, [this] {
            while (QTcpSocket *s = m_srv.nextPendingConnection()) {
                auto buf = std::make_shared<QByteArray>();
                connect(s, &QTcpSocket::readyRead, this, [this, s, buf] {
                    buf->append(s->readAll());
                    const int hdrEnd = buf->indexOf("\r\n\r\n");
                    if (hdrEnd < 0)
                        return;
                    const QByteArray head = buf->left(hdrEnd);
                    qint64 len = 0;
                    for (const QByteArray &line : head.split('\n'))
                        if (line.toLower().startsWith("content-length:"))
                            len = line.mid(15).trimmed().toLongLong();
                    if (buf->size() < hdrEnd + 4 + len)
                        return;
                    const QByteArray firstLine = head.left(head.indexOf('\r'));
                    const QString path = QString::fromLatin1(firstLine.split(' ').value(1));
                    respond(s, path, buf->mid(hdrEnd + 4, len));
                    buf->clear();
                });
                connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
            }
        });
        return m_srv.listen(QHostAddress::LocalHost, 0);
    }
    QString url() const { return QStringLiteral("http://127.0.0.1:%1").arg(m_srv.serverPort()); }
    QStringList posts() const
    {
        QStringList out;
        for (const Req &r : got)
            if (r.path.startsWith(QLatin1String("/v1/support/messages")) || r.path.startsWith(QLatin1String("/v1/support/attachments"))
                || r.path.startsWith(QLatin1String("/v1/bench/report")))
                out << r.path;
        return out;
    }

private:
    void respond(QTcpSocket *s, const QString &path, const QByteArray &body)
    {
        got.append({path, body});
        int code = statusFor(path);
        QByteArray out;
        if (code >= 200 && code < 300) {
            if (path.startsWith(QLatin1String("/v1/support/unread"))) {
                out = "{\"count\":0}";
            } else if (path.startsWith(QLatin1String("/v1/support/thread"))) {
                out = "{\"status\":\"open\",\"messages\":[]}";
            } else if (path.startsWith(QLatin1String("/v1/bench/report"))) {
                code = 201;
                out = "{\"id\":\"" + QUuid::createUuid().toString(QUuid::WithoutBraces).toLatin1() + "\"}";
            } else {
                const bool att = path.startsWith(QLatin1String("/v1/support/attachments"));
                const int msgId = ++m_seq;
                out = "{\"id\":" + QByteArray::number(msgId)
                    + ",\"sender\":\"client\",\"body\":\"\",\"created_at\":\"2026-11-16T10:00:00+00:00\","
                      "\"attachments\":"
                    + (att ? "[{\"id\":" + QByteArray::number(msgId + 1000)
                                 + ",\"kind\":\"log\",\"mime\":\"text/plain\",\"name\":\"diag.log\",\"bytes\":1}]"
                           : QByteArray("[]"))
                    + "}";
            }
        } else {
            out = "{\"detail\":\"x\"}";
        }
        s->write("HTTP/1.1 " + QByteArray::number(code) + " X\r\nContent-Type: application/json\r\nContent-Length: "
                 + QByteArray::number(out.size()) + "\r\nConnection: close\r\n\r\n" + out);
        s->disconnectFromHost();
    }
    QTcpServer m_srv;
    int m_seq = 100;
};

bool waitFor(const std::function<bool()> &cond, int ms = 8000)
{
    QElapsedTimer t;
    t.start();
    while (!cond() && t.elapsed() < ms) {
        QEventLoop loop;
        QTimer::singleShot(20, &loop, &QEventLoop::quit);
        loop.exec();
    }
    return cond();
}

QString closedPortUrl()
{
    QTcpServer s;
    s.listen(QHostAddress::LocalHost, 0);
    const quint16 port = s.serverPort();
    s.close();
    return QStringLiteral("http://127.0.0.1:%1").arg(port);
}

void tChatOfflineThenOnline()
{
    QTemporaryDir tmp;
    const QString qdir = tmp.path() + QStringLiteral("/queue");
    QSettings().setValue(QStringLiteral("AvpnSupport/pendingDiag"), QStringLiteral("legacy diag"));
    QSettings().sync();
    QNetworkAccessManager nam;
    QString idA, idB;
    {
        avpn::TribeSupportChat chat(&nam, nullptr, qdir);
        chat.setBaseUrl(closedPortUrl()); // offline: connection refused
        CHECK(!QSettings().contains(QStringLiteral("AvpnSupport/pendingDiag")));
        CHECK(chat.reportsPending() == 1); // the legacy report moved into the queue
        idA = chat.submitReport(QStringLiteral("Human A"), QStringLiteral("diag A")).value("id").toString();
        idB = chat.submitReport(QStringLiteral("Human B"), QStringLiteral("diag B"), QStringLiteral("{\"type\":\"doctor\",\"schema\":5}"))
                  .value("id").toString();
        CHECK(!idA.isEmpty() && !idB.isEmpty());
        CHECK(chat.reportsPending() == 3);
        waitFor([&] { return false; }, 600); // the first attempt fails against the closed port
        CHECK(chat.reportResult(idA) == QLatin1String("queued"));
        bool pendingRow = false;
        for (const QVariant &v : chat.messages())
            if (v.toMap().value("body").toString() == QLatin1String("Human A"))
                pendingRow = v.toMap().value("pending").toBool() && !v.toMap().value("failed").toBool();
        CHECK(pendingRow); // shown as pending, never "failed"
    }
    FakeBackend be;
    CHECK(be.start());
    {
        avpn::TribeSupportChat chat(&nam, nullptr, qdir); // a restart, then the network is back
        chat.setBaseUrl(be.url());
        CHECK(chat.reportsPending() == 3);
        QStringList statuses;
        QObject::connect(&chat, &avpn::TribeSupportChat::reportStatusChanged,
                         [&](const QString &id, const QString &r) { if (id == idB) statuses << r; });
        chat.refreshUnread(); // a live answer → the queue goes
        CHECK(waitFor([&] { return chat.reportResult(idB) == QLatin1String("delivered"); }));
        CHECK(chat.reportsPending() == 0);
        CHECK(statuses.contains(QStringLiteral("delivered")));
        const QStringList posts = be.posts();
        CHECK(posts == (QStringList{"/v1/support/attachments", "/v1/support/messages", "/v1/support/attachments",
                                    "/v1/support/messages", "/v1/support/attachments", "/v1/bench/report"}));
        QStringList bodies;
        for (const FakeBackend::Req &r : be.got)
            if (r.path != QLatin1String("/v1/support/unread") && r.path != QLatin1String("/v1/support/thread"))
                bodies << QString::fromUtf8(r.body);
        CHECK(bodies.size() == 6 && bodies.at(0).contains("legacy diag") && bodies.at(1).contains("Human A")
              && bodies.at(2).contains("diag A") && bodies.at(3).contains("Human B") && bodies.at(4).contains("diag B")
              && bodies.at(5).contains("\"schema\":5"));
        CHECK(chat.reportResult(idA) == QLatin1String("delivered"));
        CHECK(reportFiles(qdir) == 0);
    }
    {
        avpn::TribeSupportChat chat(&nam, nullptr, qdir);
        CHECK(chat.reportsPending() == 0);
        CHECK(chat.reportResult(idA) == QLatin1String("delivered")); // from the journal
        CHECK(chat.reportStatus(idB).value("parts").toMap().value("bench").toString() == QLatin1String("acked"));
    }
}

void tChatRateLimitAndTerminal()
{
    QTemporaryDir tmp;
    QNetworkAccessManager nam;
    FakeBackend be;
    CHECK(be.start());
    int messages429 = 1;
    be.statusFor = [&](const QString &p) {
        if (p.startsWith(QLatin1String("/v1/support/messages")) && messages429-- > 0)
            return 429;
        if (p.startsWith(QLatin1String("/v1/support/attachments")))
            return 413;
        return 200;
    };
    avpn::TribeSupportChat chat(&nam, nullptr, tmp.path() + QStringLiteral("/q"));
    chat.setBaseUrl(be.url());
    QStringList failures;
    QObject::connect(&chat, &avpn::TribeSupportChat::sendFailed, [&](const QString &r) { failures << r; });
    const QString id = chat.submitReport(QStringLiteral("Human C"), QStringLiteral("diag C")).value("id").toString();
    CHECK(waitFor([&] { return be.posts().size() == 1; }));
    waitFor([&] { return false; }, 300);
    CHECK(chat.reportResult(id) == QLatin1String("queued")); // 429: kept
    chat.refreshUnread(); // a live answer does not override the server's window
    waitFor([&] { return false; }, 500);
    CHECK(be.posts().size() == 1);
    CHECK(failures.isEmpty()); // a retry is not a user-facing failure

    // A terminal 413 on the log of the next report sets that part aside, the text still arrives.
    QTemporaryDir tmp2;
    messages429 = 0;
    avpn::TribeSupportChat chat2(&nam, nullptr, tmp2.path() + QStringLiteral("/q"));
    chat2.setBaseUrl(be.url());
    QObject::connect(&chat2, &avpn::TribeSupportChat::sendFailed, [&](const QString &r) { failures << r; });
    const QString id2 = chat2.submitReport(QStringLiteral("Human D"), QStringLiteral("diag D")).value("id").toString();
    CHECK(waitFor([&] { return chat2.reportResult(id2) == QLatin1String("rejected"); }));
    const QVariantMap st = chat2.reportStatus(id2);
    CHECK(st.value("reason").toString() == QLatin1String("log:413"));
    CHECK(st.value("parts").toMap().value("text").toString() == QLatin1String("acked"));
    CHECK(st.value("kept").toBool()); // F4: the payload is kept in the rejected store
    CHECK(failures.size() == 1);
    CHECK(chat2.reportsPending() == 0 && chat2.reportsRejected() == 1);
    // The user's «Отправить логи» sends the rejected report again together with the new one.
    const int attachmentsBefore = int(be.posts().filter(QStringLiteral("/v1/support/attachments")).size());
    chat2.sendDiagReport(QStringLiteral("diag E"));
    CHECK(waitFor([&] {
        return be.posts().filter(QStringLiteral("/v1/support/attachments")).size() == attachmentsBefore + 2
            && chat2.reportsPending() == 0;
    }));
    CHECK(chat2.reportsRejected() == 2); // both refused again (413), both still kept
    CHECK(chat2.reportStatus(id2).value("kept").toBool());

    // Backpressure: a full queue refuses a new check and the legacy entry point says why.
    QTemporaryDir tmp3;
    avpn::TribeSupportChat chat3(&nam, nullptr, tmp3.path() + QStringLiteral("/q"));
    chat3.setBaseUrl(closedPortUrl());
    for (int i = 0; i < 19; ++i)
        chat3.submitReport(QStringLiteral("r%1").arg(i), QString());
    const QString slot = chat3.reserveReport(); // a check admitted at its start
    CHECK(!slot.isEmpty() && chat3.reportsFull());
    CHECK(chat3.submitReport(QString(), QString(), QString(), slot).value("result").toString()
          == QLatin1String("empty"));
    CHECK(!chat3.reportsFull()); // a check that produced nothing frees its slot
    chat3.submitReport(QStringLiteral("r19"), QString());
    CHECK(chat3.reportsPending() == 20 && chat3.reportsFull());
    CHECK(chat3.reserveReport().isEmpty());
    CHECK(chat3.submitReport(QStringLiteral("21"), QString()).value("result").toString() == QLatin1String("full"));
    QStringList f3;
    QObject::connect(&chat3, &avpn::TribeSupportChat::sendFailed, [&](const QString &r) { f3 << r; });
    chat3.sendDiagReport(QStringLiteral("diag"));
    CHECK(f3.size() == 1 && f3.first().contains(QStringLiteral("20")));
    CHECK(chat3.reportsPending() == 20);
}

// F4 addition: after six refused logs, the next report's text tells support about the evicted one.
void tChatEvictionNotice()
{
    QTemporaryDir tmp;
    QNetworkAccessManager nam;
    FakeBackend be;
    CHECK(be.start());
    be.statusFor = [](const QString &p) { return p.startsWith(QLatin1String("/v1/support/attachments")) ? 413 : 200; };
    avpn::TribeSupportChat chat(&nam, nullptr, tmp.path() + QStringLiteral("/q"));
    chat.setBaseUrl(be.url());
    for (int i = 0; i < 6; ++i) {
        const QString id = chat.submitReport(QStringLiteral("Human %1").arg(i), QStringLiteral("diag %1").arg(i))
                               .value("id").toString();
        CHECK(waitFor([&] { return chat.reportResult(id) == QLatin1String("rejected"); }));
    }
    CHECK(chat.reportsRejected() == 5);
    be.statusFor = [](const QString &) { return 200; };
    const QString next = chat.submitReport(QStringLiteral("Human next"), QStringLiteral("diag next")).value("id").toString();
    CHECK(waitFor([&] { return chat.reportResult(next) == QLatin1String("delivered"); }));
    QString lastText;
    for (const FakeBackend::Req &r : be.got)
        if (r.path == QLatin1String("/v1/support/messages"))
            lastText = QString::fromUtf8(r.body);
    CHECK(lastText.contains(QStringLiteral("Human next")));
    CHECK(lastText.contains(QStringLiteral("Более ранний отчёт от")));
    CHECK(lastText.contains(QStringLiteral("413 на лог")) && lastText.contains(QStringLiteral("доставлено: текст")));
}

// F3: the queue cannot write (storage full): an honest result, never "queued".
void tChatUnsaved()
{
    QTemporaryDir tmp;
    const QString qdir = tmp.path() + QStringLiteral("/q");
    QNetworkAccessManager nam;
    FakeBackend be;
    CHECK(be.start());
    avpn::TribeSupportChat chat(&nam, nullptr, qdir);
    chat.setBaseUrl(be.url());
    QFile::setPermissions(qdir, QFileDevice::ReadOwner | QFileDevice::ExeOwner);
    QStringList finals;
    QObject::connect(&chat, &avpn::TribeSupportChat::reportStatusChanged,
                     [&](const QString &id, const QString &r) { finals << id + QLatin1Char(':') + r; });

    const QVariantMap r1 = chat.submitReport(QStringLiteral("Human U"), QStringLiteral("diag U"),
                                             QStringLiteral("{\"type\":\"doctor\",\"schema\":5}"));
    const QString id1 = r1.value("id").toString();
    CHECK(r1.value("result").toString() == QLatin1String("unsaved_sending") && !id1.isEmpty());
    CHECK(chat.reportResult(id1) == QLatin1String("unsaved_sending"));
    CHECK(chat.reportsPending() == 0); // nothing pretends to be queued
    CHECK(waitFor([&] { return chat.reportResult(id1) == QLatin1String("sent_unsaved"); }));
    CHECK(finals.contains(id1 + QStringLiteral(":sent_unsaved")));
    const QVariantMap st1 = chat.reportStatus(id1);
    CHECK(st1.value("parts").toMap().value("text").toString() == QLatin1String("acked"));
    CHECK(st1.value("parts").toMap().value("log").toString() == QLatin1String("acked"));
    CHECK(!st1.value("kept").toBool() && st1.value("reason").toString() == QLatin1String("not_persisted"));
    CHECK(waitFor([&] { return be.posts().contains(QStringLiteral("/v1/bench/report")); })); // one bench attempt

    chat.setBaseUrl(closedPortUrl()); // and offline
    const QVariantMap r2 = chat.submitReport(QStringLiteral("Human V"), QStringLiteral("diag V"));
    const QString id2 = r2.value("id").toString();
    CHECK(r2.value("result").toString() == QLatin1String("unsaved_sending"));
    CHECK(waitFor([&] { return chat.reportResult(id2) == QLatin1String("not_saved"); }));
    CHECK(finals.contains(id2 + QStringLiteral(":not_saved")));
    bool failedBubble = false;
    for (const QVariant &v : chat.messages())
        if (v.toMap().value("body").toString() == QLatin1String("Human V"))
            failedBubble = v.toMap().value("failed").toBool() && !v.toMap().value("pending").toBool();
    CHECK(failedBubble); // the chat's own «не отправлено», not a queue bubble

    // No support part to send directly: not saved, at once.
    CHECK(chat.submitReport(QString(), QString(), QStringLiteral("{\"schema\":5}")).value("result").toString()
          == QLatin1String("not_saved"));
    QFile::setPermissions(qdir, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    CHECK(chat.submitReport(QStringLiteral("Human W"), QString()).value("result").toString() == QLatin1String("queued"));
}
#endif

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
#ifdef SRQ_WITH_CHAT
    QStandardPaths::setTestModeEnabled(true);
    QTemporaryDir settingsDir;
    QCoreApplication::setOrganizationName(QStringLiteral("tribe-srq-check"));
    QCoreApplication::setApplicationName(QStringLiteral("tribe-srq-check"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDir.path());
    qunsetenv("AVPN_API_URL");
#endif
    tEnqueueAckById();
    tTwoOfflineThenOnline();
    tPartOrderCanonical();
    tKillBetweenSteps();
    tFullQueueRefusesKeepsAll();
    tDiskBoundBefore20();
    tReservations();
    tOversizedAndInvalid();
    tRateLimitKept();
    tTerminalSetAside();
    tRejectedStoreBound();
    tRejectedRetryOnce();
    tRejectedKillSteps();
    tEvictionNotices();
    tEvictionNoticeKillSteps();
    tLegacyMigration();
    tAckWhileOtherInFlight();
    tAttachmentParts();
    tCorruptFiles();
    tBackoffAndClock();
    tClassify();
    tWriteFailure();
#ifdef SRQ_WITH_CHAT
    tChatOfflineThenOnline();
    tChatRateLimitAndTerminal();
    tChatUnsaved();
    tChatEvictionNotice();
#endif
    std::printf("support_report_queue_check: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
