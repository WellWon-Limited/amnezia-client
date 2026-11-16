// AVPN Scanner (lane L6b): the report check's path through the support report queue (SupportReportQueue.h, lane
// L9) as AvpnEngineQml drives it - reservation before the check (backpressure when full), one schema-5 report
// (DoctorReport.h::buildCheckReport, validated) with its text, log and bench parts, and the card's shade decided
// per report id from the queue's part states (DoctorReport.h::checkDelivery). Plan scanner-client-plan.md §3.1.
// Build and run: tests/build_scan_report_flow.sh (QtCore only, a temp directory, a fake clock).
#include "../DoctorReport.h"
#include "../SupportReportQueue.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QTemporaryDir>

#include <cstdio>

using namespace avpn;
using namespace doctor;

static int g_fail = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static CheckDelivery deliveryOf(const srq::SupportReportQueue &q, const QString &id, bool boundPassed = false)
{
    const srq::Status st = q.status(id);
    return checkDelivery(srq::reportStateName(st.state), st.parts.value(QStringLiteral("text")),
                         st.parts.value(QStringLiteral("log")), boundPassed);
}

static QByteArray checkReportJson()
{
    QList<StageResult> st;
    st << networkStage(0, QStringLiteral("wifi"), QString(), -1, -1, -1) << connectStage(true, true, 3)
       << serverStage(QStringLiteral("Латвия"), QStringLiteral("LV"), 120) << servicesStage(4, 4, {}, false, false)
       << ruSplitStage({}, {}, false) << speedStage(24.0, 40, 90);
    const QJsonObject scan{{QStringLiteral("schema"), 1}, {QStringLiteral("network_key"), QStringLiteral("wifi")},
                           {QStringLiteral("candidates"), 5}, {QStringLiteral("counts"), QJsonObject{{QStringLiteral("works"), 3}}}};
    const QJsonObject rep = fitCheckReport(buildCheckReport(st, {{QStringLiteral("app_ver"), QStringLiteral("t")}}, scan));
    CHECK(checkReportValid(rep));
    return QJsonDocument(rep).toJson(QJsonDocument::Compact);
}

// The queue's next due part for `id`, acknowledged or failed as the server answered.
static bool answerNext(srq::SupportReportQueue &q, const QString &id, srq::PartKind kind, srq::Response r, int code)
{
    const std::optional<srq::Due> due = q.takeNext();
    if (!due || due->reportId != id || due->kind != kind)
        return false;
    if (r == srq::Response::Ack)
        q.ack(due->reportId, due->partId);
    else
        q.fail(due->reportId, due->partId, r, code);
    return true;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;
    CHECK(dir.isValid());
    qint64 clk = 1'000'000;
    srq::SupportReportQueue q(dir.path(), [&clk]() { return clk; });
    q.load();
    const QByteArray bench = checkReportJson();
    CHECK(bench.size() <= q.limits().maxBenchBytes); // the fitted check is within the bench part's cap

    // One check: a slot first, then its report - text (the human summary), log (diag.log), bench (schema 5).
    const QString slot = q.reserve();
    CHECK(!slot.isEmpty());
    const srq::EnqueueOutcome a = q.enqueue({{srq::PartKind::Text, QByteArrayLiteral("Диагностика Tribe VPN")},
                                             {srq::PartKind::Log, QByteArrayLiteral("=== SCANNER CHECK ===")},
                                             {srq::PartKind::Bench, bench}},
                                            slot);
    CHECK(a.result == srq::EnqueueResult::Queued);
    CHECK(q.reservations() == 0); // the slot was consumed by its report
    CHECK(deliveryOf(q, a.reportId) == CheckDelivery::Wait);
    CHECK(deliveryOf(q, a.reportId, /*boundPassed=*/true) == CheckDelivery::Queued); // offline: «уйдёт, когда появится связь»
    // Text acked, log not yet: still waiting (the support thread has only half of it).
    CHECK(answerNext(q, a.reportId, srq::PartKind::Text, srq::Response::Ack, 201));
    CHECK(deliveryOf(q, a.reportId) == CheckDelivery::Wait);
    CHECK(answerNext(q, a.reportId, srq::PartKind::Log, srq::Response::Ack, 201));
    CHECK(deliveryOf(q, a.reportId) == CheckDelivery::Sent); // both support parts: «Отчёт отправлен в поддержку»
    // The bench copy hits the hourly limit (429): the report stays queued, the shade stays "sent".
    CHECK(answerNext(q, a.reportId, srq::PartKind::Bench, srq::Response::RateLimited, 429));
    CHECK(q.count() == 1);
    CHECK(srq::reportStateName(q.status(a.reportId).state) == QLatin1String("queued"));
    CHECK(deliveryOf(q, a.reportId) == CheckDelivery::Sent);

    // Backpressure: the queue fills; a new check gets no slot (the engine refuses it), nothing is dropped.
    QStringList ids;
    while (true) {
        const QString t = q.reserve();
        if (t.isEmpty())
            break;
        const srq::EnqueueOutcome o = q.enqueue({{srq::PartKind::Text, QByteArrayLiteral("x")}, {srq::PartKind::Log, QByteArrayLiteral("y")}}, t);
        CHECK(o.result == srq::EnqueueResult::Queued);
        ids << o.reportId;
        if (ids.size() > 40)
            break;
    }
    CHECK(q.count() == q.limits().maxReports);
    CHECK(q.full());
    CHECK(q.reserve().isEmpty());
    CHECK(srq::reportStateName(q.status(a.reportId).state) == QLatin1String("queued")); // the first one still there
    // Per-id acks: report B's parts settle B only; C keeps waiting.
    clk += 3'600'001; // the bench hold of A passes: A's bench goes first (oldest), accepted this time
    CHECK(answerNext(q, a.reportId, srq::PartKind::Bench, srq::Response::Ack, 201));
    CHECK(srq::reportStateName(q.status(a.reportId).state) == QLatin1String("delivered"));
    CHECK(deliveryOf(q, a.reportId) == CheckDelivery::Sent);
    const QString b = ids.value(0), c = ids.value(1);
    CHECK(answerNext(q, b, srq::PartKind::Text, srq::Response::Ack, 201));
    CHECK(answerNext(q, b, srq::PartKind::Log, srq::Response::Ack, 201));
    CHECK(deliveryOf(q, b) == CheckDelivery::Sent);
    CHECK(deliveryOf(q, c) == CheckDelivery::Wait);
    // Delivered reports free their slots: the backpressure lifts.
    CHECK(!q.full());
    CHECK(!q.reserve().isEmpty());
    // A terminal refusal of a support part: while the log is pending the shade waits (at the bound: rejected);
    // once the report is settled it is rejected - kept by the queue, never «уйдёт» (queue lane F4).
    CHECK(answerNext(q, c, srq::PartKind::Text, srq::Response::Terminal, 415));
    CHECK(deliveryOf(q, c) == CheckDelivery::Wait);
    CHECK(deliveryOf(q, c, /*boundPassed=*/true) == CheckDelivery::Rejected);
    CHECK(answerNext(q, c, srq::PartKind::Log, srq::Response::Ack, 201));
    CHECK(srq::reportStateName(q.status(c).state) == QLatin1String("rejected"));
    CHECK(deliveryOf(q, c) == CheckDelivery::Rejected);

    if (g_fail) {
        std::printf("scan_report_flow_check: %d FAILED\n", g_fail);
        return 1;
    }
    std::printf("scan_report_flow_check: OK\n");
    return 0;
}
