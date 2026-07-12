// AVPN backend-first-3 (Task 4): юнит TribeDiagReport — единый text/plain диагностический отчёт
// (JSON-снапшот пула/RTT/байпаса + хвост лога). Только QtCore. Инварианты:
//  (а) обе секции присутствуют; (б) JSON парсится; (в) хвост длинного файла обрезан по капу и
//  начинается с начала строки; (г) у нод есть proto/rttMs; (д) «секрет» из лога сохраняется
//  (лог маскирует сам Logger), но в JSON-секции подставного токена НЕТ; (е) кламп 2МБ-4КБ
//  режет лог-хвост (не JSON), сохраняя самые свежие строки.
#include "../TribeDiagReport.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

static const char *kJsonMarker = "=== TRIBE DIAG v1 ===";
static const char *kLogMarker = "=== LOG TAIL ===";

// Секция JSON = текст между маркерами; секция лога = всё после маркера лога.
static void splitReport(const QString &report, QString &jsonSection, QString &logSection)
{
    const int j = report.indexOf(QLatin1String(kJsonMarker));
    const int l = report.indexOf(QLatin1String(kLogMarker));
    jsonSection = (j >= 0 && l > j) ? report.mid(j, l - j) : QString();
    logSection = (l >= 0) ? report.mid(l + int(strlen(kLogMarker))) : QString();
}

static avpn::DebugSnapshot makeSnapshot()
{
    avpn::DebugSnapshot s;
    s.state = QStringLiteral("connected");
    s.currentNodeId = QStringLiteral("node-fi-1");
    s.latestHandshakeAgeSec = 12;
    s.rxBytes = 1024;
    s.txBytes = 2048;
    s.subStatus = QStringLiteral("active");
    s.expiresAt = QStringLiteral("2026-12-31T00:00:00Z");
    s.graceUntil = QStringLiteral("2027-01-01T00:00:00Z");
    s.trafficUsed = 100;
    s.trafficLimit = 0;
    s.lkgStale = true;
    s.bypassListVersion = 7;
    avpn::NodeDebugRow a;
    a.nodeId = QStringLiteral("node-fi-1");
    a.region = QStringLiteral("fi");
    a.countryCode = QStringLiteral("FI");
    a.endpoint = QStringLiteral("1.2.3.4:51820");
    a.proto = QStringLiteral("awg");
    a.scoreMs = 42.0;
    a.weight = 2.0;
    a.healthAgg = 0.9;
    a.alive = true;
    a.current = true;
    a.reason = QStringLiteral("current");
    avpn::NodeDebugRow b;
    b.nodeId = QStringLiteral("node-us-1");
    b.region = QStringLiteral("us");
    b.proto = QStringLiteral("awg");
    b.scoreMs = 180.0;
    b.alive = true;
    s.pool << a << b;
    s.switchLog << QStringLiteral("switch node-us-1→node-fi-1: dead");
    return s;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir dir;

    // ── лог-файл: > капа (256 КБ) из пронумерованных строк + «секрет» в хвосте ──
    const QString logPath = dir.filePath(QStringLiteral("app.log"));
    {
        QFile f(logPath);
        if (!f.open(QIODevice::WriteOnly)) { printf("FAIL cannot create temp log\n"); return 1; }
        for (int i = 0; i < 12000; ++i)
            f.write(QStringLiteral("line-%1 lorem ipsum diagnostic payload padding\n")
                        .arg(i, 6, 10, QLatin1Char('0')).toUtf8());
        f.write("line-LAST TOP-SECRET-TOKEN-abc123 masked-by-logger\n");
    }

    const QString tail = avpn::TribeDiagReport::readLogTail(logPath);
    CHECK(tail.toUtf8().size() <= avpn::TribeDiagReport::kLogTailCapBytes,
          "readLogTail: хвост <= капа 256 КБ");
    CHECK(tail.startsWith(QLatin1String("line-")),
          "readLogTail: хвост выровнен по началу строки");
    CHECK(tail.contains(QLatin1String("line-LAST")), "readLogTail: последняя строка файла на месте");

    avpn::DiagMeta meta;
    meta.appVersion = QStringLiteral("5.1.51");
    meta.platform = QStringLiteral("macos 15.5");
    meta.lang = QStringLiteral("ru");
    meta.configAppliedAgeSec = 33;
    const QString report = avpn::TribeDiagReport::build(makeSnapshot(), true, tail, meta);

    // (а) обе секции присутствуют
    CHECK(report.contains(QLatin1String(kJsonMarker)), "(а) секция TRIBE DIAG v1 присутствует");
    CHECK(report.contains(QLatin1String(kLogMarker)), "(а) секция LOG TAIL присутствует");

    QString jsonSection, logSection;
    splitReport(report, jsonSection, logSection);

    // (б) JSON парсится
    const QString jsonText = jsonSection.mid(int(strlen(kJsonMarker))).trimmed();
    QJsonParseError perr{};
    const QJsonDocument doc = QJsonDocument::fromJson(jsonText.toUtf8(), &perr);
    CHECK(perr.error == QJsonParseError::NoError && doc.isObject(), "(б) JSON-секция парсится");
    const QJsonObject o = doc.object();
    CHECK(o.value(QLatin1String("app_version")).toString() == QLatin1String("5.1.51"),
          "(б) app_version в JSON");
    CHECK(o.value(QLatin1String("state")).toString() == QLatin1String("connected"), "(б) state в JSON");
    CHECK(o.value(QLatin1String("bypassMasterOn")).toBool(false) == true, "(б) bypassMasterOn в JSON");
    CHECK(o.value(QLatin1String("bypassListVersion")).toInt() == 7, "(б) bypassListVersion в JSON");
    CHECK(o.value(QLatin1String("configAppliedAgeSec")).toInt(-1) == 33, "(б) configAppliedAgeSec в JSON");
    CHECK(o.value(QLatin1String("graceUntil")).toString() == QLatin1String("2027-01-01T00:00:00Z"),
          "(б) graceUntil в JSON");
    CHECK(o.value(QLatin1String("switchLog")).toArray().size() == 1, "(б) switchLog в JSON");

    // configAppliedAgeSec < 0 → ключ опущен
    avpn::DiagMeta metaNoCfg = meta;
    metaNoCfg.configAppliedAgeSec = -1;
    {
        QString js, ls;
        splitReport(avpn::TribeDiagReport::build(makeSnapshot(), false, tail, metaNoCfg), js, ls);
        const QJsonObject o2 = QJsonDocument::fromJson(
            js.mid(int(strlen(kJsonMarker))).trimmed().toUtf8()).object();
        CHECK(!o2.contains(QLatin1String("configAppliedAgeSec")),
              "(б) configAppliedAgeSec опущен при неизвестном timestamp");
        CHECK(o2.value(QLatin1String("bypassMasterOn")).toBool(true) == false,
              "(б) bypassMasterOn=false прокидывается");
    }

    // (в) хвост обрезан по капу и начинается с начала строки — проверено выше на readLogTail;
    //     здесь: в отчёте лог-секция начинается с той же выровненной строки
    CHECK(logSection.trimmed().startsWith(QLatin1String("line-")),
          "(в) лог-секция отчёта начинается с начала строки");

    // (г) поля proto/rttMs у нод
    const QJsonArray pool = o.value(QLatin1String("pool")).toArray();
    CHECK(pool.size() == 2, "(г) pool: обе ноды в JSON");
    const QJsonObject n0 = pool.at(0).toObject();
    CHECK(n0.value(QLatin1String("proto")).toString() == QLatin1String("awg"), "(г) proto у ноды");
    CHECK(n0.value(QLatin1String("rttMs")).toDouble() == 42.0, "(г) rttMs у ноды из RTT-кэша");
    CHECK(n0.value(QLatin1String("current")).toBool() == true, "(г) current у ноды");

    // (д) секрет из лога СОХРАНЯЕТСЯ в лог-секции (маскирует сам Logger), но в JSON его НЕТ
    CHECK(logSection.contains(QLatin1String("TOP-SECRET-TOKEN-abc123")),
          "(д) секрет из лога сохранён в LOG TAIL (не фильтруем лог)");
    CHECK(!jsonSection.contains(QLatin1String("TOP-SECRET-TOKEN-abc123")),
          "(д) подставного токена НЕТ в JSON-секции");

    // (е) кламп итога 2 МБ - 4 КБ: гигантский хвост режется (лог, не JSON), свежие строки выживают
    {
        QString huge;
        huge.reserve(3 * 1024 * 1024 + 64);
        int i = 0;
        while (huge.size() < 3 * 1024 * 1024)
            huge += QStringLiteral("huge-%1 padding padding padding padding padding\n").arg(i++);
        huge += QStringLiteral("huge-LAST freshest line\n");
        const QString clamped = avpn::TribeDiagReport::build(makeSnapshot(), true, huge, meta);
        CHECK(clamped.toUtf8().size() <= avpn::TribeDiagReport::kMaxReportBytes,
              "(е) итоговый отчёт <= 2 МБ - 4 КБ");
        QString js, ls;
        splitReport(clamped, js, ls);
        CHECK(QJsonDocument::fromJson(js.mid(int(strlen(kJsonMarker))).trimmed().toUtf8()).isObject(),
              "(е) JSON-секция цела после клампа");
        CHECK(ls.contains(QLatin1String("huge-LAST")), "(е) самые свежие строки лога выжили");
        CHECK(ls.trimmed().startsWith(QLatin1String("huge-")),
              "(е) обрезанный хвост выровнен по началу строки");
    }

    // readLogTail: несуществующий файл → пусто (не падаем)
    CHECK(avpn::TribeDiagReport::readLogTail(dir.filePath(QStringLiteral("no-such.log"))).isEmpty(),
          "readLogTail: несуществующий файл => пусто");

    printf(g_fail ? "\n%d FAILED\n" : "\nALL PASSED\n", g_fail);
    return g_fail ? 1 : 0;
}
