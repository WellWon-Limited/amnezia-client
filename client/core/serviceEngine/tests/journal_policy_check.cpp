// AVPN (журнал тестирования, Tribe-Backend docs/specs/2026-09-23-tester-journal-design.md):
// чистые решения JournalPolicy.h — видимость/включение, разбор времени строк логов Qt и NE,
// строка лога → JSON-событие, пачка по смещениям источников (полные строки, кап, сдвиг при
// ротации/обрезке файла), решение об обрезке отправленного лога.
#include "../JournalPolicy.h"

#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <cstdio>

using namespace avpn::journal;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr, what)                                                                           \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            std::printf("FAIL: %s (%s:%d)\n", what, __FILE__, __LINE__);                            \
        }                                                                                           \
    } while (0)

static QJsonObject obj(const QByteArray &line)
{
    return QJsonDocument::fromJson(line).object();
}

static void write(const QString &path, const QByteArray &data)
{
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(data);
}

static void visibility()
{
    CHECK(!journalVisible(false, false, false), "store build, not admin, not forced -> hidden");
    CHECK(journalVisible(true, false, false), "TestFlight -> visible");
    CHECK(journalVisible(false, true, false), "admin -> visible");
    CHECK(journalVisible(false, false, true), "forced -> visible");
    CHECK(!journalEnabled(false, false, true), "visible but user off -> off");
    CHECK(journalEnabled(true, false, true), "visible and user on -> on");
    CHECK(!journalEnabled(true, false, false), "user on but no longer visible -> off");
    CHECK(journalEnabled(false, true, true), "forced wins over user off");
}

static void timestamps()
{
    const QByteArray qt = "[2026-09-23 10:37:07.900Z] [INFO] AmneziaVPN  : [avpn reseed] applied";
    CHECK(parseTimestamp(qt, TextFormat::QtLog, 0) == QStringLiteral("2026-09-23T10:37:07.900Z"),
          "Qt log UTC timestamp");
    // NE: локальное время устройства без зоны → UTC по смещению (МСК = +3 ч)
    const QByteArray ne = "2026-09-23 13:37:07 info NE: WG: Handshake did not complete";
    CHECK(parseTimestamp(ne, TextFormat::NeLog, 3 * 3600) == QStringLiteral("2026-09-23T10:37:07.000Z"),
          "NE log local time -> UTC");
    CHECK(parseTimestamp("garbage", TextFormat::QtLog, 0).isEmpty(), "no timestamp -> empty");
    CHECK(parseTimestamp("2026-13-99 25:61:00 info x", TextFormat::NeLog, 0).isEmpty(),
          "invalid date -> empty");
}

static void lineToEvent()
{
    const QByteArray qt = "[2026-09-23 10:37:07.900Z] [WARNING] AmneziaVPN  : edge flip";
    const QJsonObject e = obj(textLineToEvent(qt, TextFormat::QtLog, QStringLiteral("app"), 0,
                                              QStringLiteral("2026-09-23T11:00:00.000Z")));
    CHECK(e.value("t").toString() == "2026-09-23T10:37:07.900Z", "event t from line");
    CHECK(e.value("src").toString() == "app" && e.value("ev").toString() == "log", "src/ev");
    CHECK(e.value("msg").toString() == QString::fromUtf8(qt), "msg keeps the whole line");

    // строка без времени (продолжение многострочного сообщения) — время «последней известной»
    const QJsonObject c = obj(textLineToEvent("   continuation", TextFormat::NeLog,
                                              QStringLiteral("ne"), 0,
                                              QStringLiteral("2026-09-23T11:00:00.000Z")));
    CHECK(c.value("t").toString() == "2026-09-23T11:00:00.000Z", "fallback t");
    CHECK(textLineToEvent("   ", TextFormat::NeLog, QStringLiteral("ne"), 0, QString()).isEmpty(),
          "blank line -> nothing");

    // очень длинная строка обрезается (кап события)
    const QByteArray huge = "[2026-09-23 10:37:07.900Z] [INFO] x : " + QByteArray(20000, 'a');
    const QJsonObject h = obj(textLineToEvent(huge, TextFormat::QtLog, QStringLiteral("app"), 0, QString()));
    CHECK(h.value("msg").toString().size() <= kMaxMessageChars + 1, "long line capped");
}

static void offsets()
{
    CHECK(effectiveOffset(100, 500) == 100, "offset inside file kept");
    CHECK(effectiveOffset(900, 500) == 0, "file shrank (truncated/rotated) -> restart from 0");
    CHECK(effectiveOffset(-5, 500) == 0, "negative -> 0");

    CHECK(completePrefix("a\nb\nc", 100) == 4, "stop after last complete line");
    CHECK(completePrefix("abc", 100) == 0, "no complete line yet -> wait");
    CHECK(completePrefix("aaaa\nbbbb\n", 6) == 5, "cap keeps whole lines");
    // одна строка длиннее капа — режем по капу, иначе источник встал бы навсегда
    CHECK(completePrefix(QByteArray(50, 'x') + "\n", 10) == 10, "single oversize line cut at cap");

    CHECK(!shouldTruncate(1000, 1000), "small fully-sent log stays");
    CHECK(shouldTruncate(kTextLogCapBytes + 1, kTextLogCapBytes + 1), "big fully-sent log truncated");
    CHECK(!shouldTruncate(kTextLogCapBytes + 1, 10), "big but unsent log kept");
    CHECK(shouldTruncate(kTextLogHardCapBytes + 1, 0), "over hard cap truncated even unsent");
}

static void batches()
{
    QTemporaryDir dir;
    const QString structured = dir.filePath("app.jsonl");
    const QString qtlog = dir.filePath("AmneziaVPN.log");
    const QString nelog = dir.filePath("ne.log");
    write(structured,
          "{\"t\":\"2026-09-23T10:37:07.900Z\",\"src\":\"app\",\"ev\":\"ring\",\"msg\":\"guarded_stop\"}\n"
          "not json\n");
    write(qtlog, "[2026-09-23 10:37:08.000Z] [INFO] AmneziaVPN  : hello\npartial-without-newline");
    write(nelog, "\n2026-09-23 13:37:09 info NE: WG: bump\n");

    const QList<JournalSource> sources{
        {QStringLiteral("struct"), structured, TextFormat::Structured, QStringLiteral("app")},
        {QStringLiteral("qt"), qtlog, TextFormat::QtLog, QStringLiteral("app")},
        {QStringLiteral("ne"), nelog, TextFormat::NeLog, QStringLiteral("ne")},
    };
    QHash<QString, qint64> offs;
    BatchPlan p = planBatch(sources, offs, 64 * 1024, 3 * 3600, QStringLiteral("2026-09-23T11:00:00.000Z"));
    CHECK(p.events == 3, "struct(1 valid) + qt(1 complete) + ne(1)");
    CHECK(p.srcTag == QStringLiteral("mix"), "app+ne -> mix");
    CHECK(p.jsonl.count('\n') == 3, "one JSON line per event");
    const QList<QByteArray> lines = p.jsonl.split('\n');
    CHECK(obj(lines.at(0)).value("ev").toString() == "ring", "structured passes through");
    CHECK(obj(lines.at(2)).value("t").toString() == "2026-09-23T10:37:09.000Z", "NE time -> UTC");
    // смещения: structured до конца (мусорная строка пропущена, но прочитана), qt — только до
    // полной строки, ne — до конца
    CHECK(p.newOffsets.value("struct") == QFile(structured).size(), "struct offset at end");
    CHECK(p.newOffsets.value("qt") < QFile(qtlog).size(), "qt stops before partial line");
    CHECK(p.newOffsets.value("ne") == QFile(nelog).size(), "ne offset at end");

    // повтор с новыми смещениями — пусто
    for (auto it = p.newOffsets.begin(); it != p.newOffsets.end(); ++it)
        offs.insert(it.key(), it.value());
    BatchPlan again = planBatch(sources, offs, 64 * 1024, 0, QStringLiteral("2026-09-23T11:00:00.000Z"));
    CHECK(again.events == 0 && again.jsonl.isEmpty(), "nothing new -> empty batch");

    // кап пачки: большой лог уходит частями, смещение двигается частично
    QByteArray big;
    for (int i = 0; i < 200; ++i)
        big += "[2026-09-23 10:40:00.000Z] [INFO] AmneziaVPN  : line " + QByteArray::number(i) + "\n";
    write(qtlog, big);
    QHash<QString, qint64> fresh;
    BatchPlan part = planBatch({sources.at(1)}, fresh, 2048, 0, QString());
    CHECK(part.events > 0 && part.newOffsets.value("qt") <= 2048, "batch consumes at most maxRaw input");
    CHECK(part.jsonl.size() <= 3 * 2048, "json output within ~3x of input");
    CHECK(part.newOffsets.value("qt") > 0 && part.newOffsets.value("qt") < big.size(), "partial advance");
    CHECK(part.srcTag == QStringLiteral("app"), "only app sources -> app");

    // одна строка длиннее капа пачки: источник не встаёт, режется по капу
    write(qtlog, "[2026-09-23 10:41:00.000Z] [INFO] AmneziaVPN  : " + QByteArray(5000, 'z') + "\n");
    QHash<QString, qint64> none;
    BatchPlan cut = planBatch({sources.at(1)}, none, 1024, 0, QString());
    CHECK(cut.events == 1 && cut.newOffsets.value("qt") == 1024, "oversize line cut at batch cap");
}

// Разбор журнала 25.09: выкл→вкл журнала сдвигал смещения в конец и выбрасывал ночь
// неотправленного ne.log. Теперь в конец — только первое включение и долгий перерыв с логом.
static void reenable()
{
    CHECK(offsetOnEnable(100, -1, 5000) == 5000, "first enable -> end, old history not sent");
    CHECK(offsetOnEnable(100, 5000, 5000) == 100, "re-enable, log idle while off -> unsent kept");
    CHECK(offsetOnEnable(100, 5000, 6000) == 100, "re-enable, small growth while off -> unsent kept");
    CHECK(offsetOnEnable(100, 5000, 5000 + kReenableGapBytes + 1) == 5000 + kReenableGapBytes + 1,
          "re-enable after big growth while off -> end");
    CHECK(offsetOnEnable(100, 5000, 300) == 300, "log shrank while off (rotation) -> end");
    CHECK(offsetOnEnable(9000, 5000, 5000) == 0, "stored beyond size -> from start, as planBatch");
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    visibility();
    timestamps();
    lineToEvent();
    offsets();
    batches();
    reenable();
    std::printf("journal_policy_check: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
