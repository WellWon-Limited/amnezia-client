// AVPN Scanner: the contract between ScanMachine.h (buildSummary, the `scan` block of the connection check) and
// DoctorReport.h (scanSummaryValid / checkReportValid, the app's own copy of the server's schema-5 rules).
// Lab seam S1 (first real end-to-end scan, 16.11): the machine wrote `seats_requested` and the row `evidence`
// (contract 1.7.0) while the validator did not know them, so AvpnEngineQml::scanCheckSubmit dropped the whole
// `scan` block from every report copy and support never saw a scan. Hand-written summaries in the validator's
// own test could not catch it; this test feeds the REAL machine's lastSummary() - every distinct summary of every
// scenario of the shared scenario set, driven end to end (scan_world.h Driver), plus the summary each
// StartReportCheck really carries - through the REAL validator and the real report builder, and asserts it
// passes UNCHANGED (the report's `scan` == the machine's summary, byte for byte). It also asserts the set covers
// the kinds the server sees: rows with evidence direct and exclusion, «Не проверено» rows, an empty result, a
// scan stopped with probes in flight, seats asked.
//
// Build/run: build_scan_summary_contract.sh (QtCore only, headers only).
#include "scan_scenarios.h"

#include "../DoctorReport.h"
#include "../ScanMachine.h"

#include <QCoreApplication>
#include <QJsonDocument>

#include <cstdio>

using namespace avpn;
using namespace scantest;

static int g_fail = 0, g_total = 0;
static void check(bool ok, const QString &what)
{
    ++g_total;
    if (!ok) {
        ++g_fail;
        std::printf("FAIL %s\n", qPrintable(what));
    }
}

static QByteArray compact(const QJsonObject &o) { return QJsonDocument(o).toJson(QJsonDocument::Compact); }

struct Coverage {
    bool direct = false, exclusion = false, unverifiedRow = false, empty = false, stoppedInFlight = false, seats = false,
         liveRow = false;
};

// The report as AvpnEngineQml::scanCheckSubmit builds it for a VPN-off check (stages of that path, extra of
// the check), around the given summary.
static QJsonObject reportAround(const QJsonObject &scan, const QJsonObject &machineReport)
{
    QList<doctor::StageResult> st;
    st << doctor::networkStage(0, QStringLiteral("wifi"), QString(), -1, -1, -1) << doctor::connectStageNoVpn();
    const QJsonObject extra{{QStringLiteral("doctor_mode"), QStringLiteral("check")},
                            {QStringLiteral("check"), QJsonObject{{QStringLiteral("id"), machineReport.value(QStringLiteral("id"))},
                                                                  {QStringLiteral("created_at_ms"), machineReport.value(QStringLiteral("created_at_ms"))},
                                                                  {QStringLiteral("with_connection"), false},
                                                                  {QStringLiteral("scan_stats"), machineReport.value(QStringLiteral("scan_stats"))}}}};
    return doctor::fitCheckReport(doctor::buildCheckReport(st, extra, scan));
}

static void judge(const QJsonObject &sum, const QJsonObject &machineReport, const QString &where, Coverage &cov)
{
    QString why;
    check(doctor::scanSummaryValid(sum, &why), where + QStringLiteral(": the validator refuses the machine's summary: ") + why
                                                   + QStringLiteral(" ") + QString::fromUtf8(compact(sum)).left(600));
    const QJsonObject rep = reportAround(sum, machineReport);
    QString why2;
    check(doctor::checkReportValid(rep, &why2), where + QStringLiteral(": report refused: ") + why2);
    check(compact(rep.value(QStringLiteral("scan")).toObject()) == compact(sum), where + QStringLiteral(": the scan block changed in the report"));
    // the app's own copy of the server's strict schema (scan_scenarios.h) agrees, and every candidate is in a bucket
    check(summaryBucketsWhy(sum).isEmpty(), where + QStringLiteral(": ") + summaryBucketsWhy(sum));
    for (const QJsonValue &v : sum.value(QStringLiteral("top")).toArray()) {
        const QJsonObject r = v.toObject();
        cov.direct = cov.direct || r.value(QStringLiteral("evidence")).toString() == QLatin1String("direct");
        cov.exclusion = cov.exclusion || r.value(QStringLiteral("evidence")).toString() == QLatin1String("exclusion");
        cov.unverifiedRow = cov.unverifiedRow || r.value(QStringLiteral("class")).toString() == QLatin1String("not_verified");
        cov.liveRow = cov.liveRow || r.value(QStringLiteral("probe")).toString() == QLatin1String("tunnel");
    }
    cov.empty = cov.empty || sum.value(QStringLiteral("top")).toArray().isEmpty();
    cov.stoppedInFlight = cov.stoppedInFlight || sum.value(QStringLiteral("not_verified_reasons")).toObject().contains(QStringLiteral("cancelled"));
    cov.seats = cov.seats || sum.value(QStringLiteral("seats_requested")).toInt() > 0;
}

static void drive(const QString &name, const World &w, Coverage &cov, int *summaries)
{
    Driver d(w);
    d.run();
    QSet<QByteArray> seen;
    for (int i = 0; i < d.steps.size(); ++i) {
        const Recorded &r = d.steps.at(i);
        const QString where = name + QStringLiteral("#") + QString::number(i);
        if (!r.summary.isEmpty() && !seen.contains(compact(r.summary))) {
            seen.insert(compact(r.summary));
            ++*summaries;
            judge(r.summary, QJsonObject(), where, cov);
        }
        // what the coordinator really hands to the engine's full check
        for (const ScanAction &a : r.step.actions)
            if (a.kind == ScanActionKind::StartReportCheck && a.report.value(QStringLiteral("scan")).isObject())
                judge(a.report.value(QStringLiteral("scan")).toObject(), a.report, where + QStringLiteral(" start_report_check"), cov);
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    Coverage cov;
    int summaries = 0;
    for (const Scenario &s : scenarios())
        drive(s.name, s.world(), cov, &summaries);
    // the lab's scan: desktop, the VPN off, a probe frozen by the operator still in flight at the deadline
    {
        World w = baseWorld("lab_freeze_in_flight", hostMac(), ScanNetKind::Wifi);
        w.out[up(3)].durMs = 60000;
        w.out[QStringLiteral("5:xray")].durMs = 60000;
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.script << qMakePair(qint64(12000), at("report_link_tapped"));
        w.runMs = 16000;
        drive(w.name, w, cov, &summaries);
    }
    std::printf("scan_summary_contract_check: %d distinct summaries; evidence direct %d exclusion %d, «Не проверено» rows %d, "
                "empty %d, stopped with probes in flight %d, seats asked %d, live row %d\n",
                summaries, cov.direct, cov.exclusion, cov.unverifiedRow, cov.empty, cov.stoppedInFlight, cov.seats, cov.liveRow);
    check(summaries >= 20, QStringLiteral("the scenario set yields summaries"));
    check(cov.direct && cov.exclusion && cov.unverifiedRow && cov.empty && cov.stoppedInFlight && cov.seats && cov.liveRow,
          QStringLiteral("coverage: both evidence kinds, «Не проверено» rows, an empty result, a stopped scan, seats, the live row"));
    // and the other way round: what the validator refuses, the machine never writes (a key outside the schema)
    {
        QJsonObject probe;
        for (const Scenario &s : scenarios())
            if (s.name == QLatin1String("wifi_all_works_legs")) {
                Driver d(s.world());
                d.run();
                probe = d.m.lastSummary();
            }
        QJsonObject extraKey = probe;
        extraKey.insert(QStringLiteral("seats_granted"), 1);
        check(!probe.isEmpty() && doctor::scanSummaryValid(probe) && !doctor::scanSummaryValid(extraKey),
              QStringLiteral("the validator stays strict (an unknown key is refused)"));
    }
    if (g_fail) {
        std::printf("scan_summary_contract_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("scan_summary_contract_check: OK (%d checks)\n", g_total);
    return 0;
}
