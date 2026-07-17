// AVPN (наблюдаемость CR-1): юнит ЧИСТОЙ логики CrashGuard.h (namespace crashguard) — парс/сборка
// sentinel, классификация subtype, кодек signal.bin, скраб лог-хвоста, сборка JSON-отчёта §1.3.
// Собирается standalone (только QtCore), как doctor_report_check. Запуск: tests/build_crash_check.sh.
#define CRASHGUARD_PURE_LOGIC_ONLY   // не тянем QObject-фасад/платформенщину
#include "../CrashGuard.h"

#include <QJsonDocument>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; }           \
        else         { std::printf("ok:   %s\n", msg); }                     \
    } while (0)

int main()
{
    using namespace crashguard;

    // ── sentinel round-trip ─────────────────────────────────────────────────────────────────────
    {
        Sentinel s;
        s.valid = true; s.build = QStringLiteral("5.1.57.85"); s.platform = QStringLiteral("macos");
        s.os = QStringLiteral("15.5"); s.phase = QStringLiteral("connected");
        s.uptimeS = 1234; s.startedMs = 1700000000000LL; s.dirtyExitsSinceLast = 2;
        const QByteArray raw = buildSentinel(s);
        const Sentinel r = parseSentinel(raw);
        CHECK(r.valid, "sentinel: round-trip valid");
        CHECK(r.build == QStringLiteral("5.1.57.85"), "sentinel: build сохранён");
        CHECK(r.platform == QStringLiteral("macos"), "sentinel: platform сохранён");
        CHECK(r.phase == QStringLiteral("connected"), "sentinel: phase сохранён");
        CHECK(r.uptimeS == 1234, "sentinel: uptime_s сохранён");
        CHECK(r.dirtyExitsSinceLast == 2, "sentinel: dirty_exits_since_last сохранён");
    }
    CHECK(!parseSentinel(QByteArray("not json")).valid, "sentinel: мусор -> invalid");
    CHECK(!parseSentinel(QByteArray("{\"x\":1}")).valid, "sentinel: без build -> invalid");
    CHECK(parseSentinel(QByteArray()).valid == false, "sentinel: пусто -> invalid (не падаем)");

    // ── классификация subtype (приоритет signal > seh > java > dirty) ───────────────────────────
    CHECK(classify(true,  true,  true,  true)  == Subtype::Signal,    "classify: сигнал приоритетнее всех");
    CHECK(classify(false, true,  true,  true)  == Subtype::Seh,       "classify: seh приоритетнее java");
    CHECK(classify(false, true,  false, true)  == Subtype::Java,      "classify: java при наличии java-файла");
    CHECK(classify(false, false, false, true)  == Subtype::DirtyExit, "classify: только sentinel -> dirty_exit");
    CHECK(classify(false, false, false, false) == Subtype::None,      "classify: нет sentinel -> None (штатный выход)");

    // ── куда шлём: dirty_exit только на десктопе ────────────────────────────────────────────────
    CHECK(shouldEmitReport(Subtype::DirtyExit, /*desktop*/true)  == true,  "emit: dirty_exit на десктопе шлём");
    CHECK(shouldEmitReport(Subtype::DirtyExit, /*desktop*/false) == false, "emit: dirty_exit на мобилке НЕ шлём (только счётчик)");
    CHECK(shouldEmitReport(Subtype::Signal, false) == true, "emit: signal шлём и на мобилке");
    CHECK(shouldEmitReport(Subtype::Java,   false) == true, "emit: java шлём и на мобилке");
    CHECK(shouldEmitReport(Subtype::None,   true)  == false, "emit: None не шлём никогда");

    // ── signal.bin кодек ────────────────────────────────────────────────────────────────────────
    {
        SignalInfo si; si.valid = true; si.kind = 0; si.signalOrCode = 11;
        si.faultAddr = 0xdeadbeefULL; si.imageBase = 0x100000000ULL;
        si.frames = { 0x1000, 0x2000, 0x3000 };
        const QByteArray bin = encodeSignalBin(si);
        const SignalInfo r = parseSignalBin(bin);
        CHECK(r.valid, "signal.bin: round-trip valid");
        CHECK(r.signalOrCode == 11, "signal.bin: номер сигнала");
        CHECK(r.faultAddr == 0xdeadbeefULL, "signal.bin: fault addr");
        CHECK(r.imageBase == 0x100000000ULL, "signal.bin: image base");
        CHECK(r.frames.size() == 3 && r.frames.at(2) == 0x3000, "signal.bin: кадры");
    }
    CHECK(!parseSignalBin(QByteArray("short")).valid, "signal.bin: короткий буфер -> invalid");
    CHECK(!parseSignalBin(QByteArray(kSigHeaderBytes, 'X')).valid, "signal.bin: битый magic -> invalid");
    {
        // кламп кадров: > 32 усекается на кодировании
        SignalInfo si; for (int i = 0; i < 100; ++i) si.frames.append(quint64(i));
        const SignalInfo r = parseSignalBin(encodeSignalBin(si));
        CHECK(r.frames.size() == kMaxFrames, "signal.bin: кадры клампятся в 32");
    }

    // ── скраб лог-хвоста ────────────────────────────────────────────────────────────────────────
    {
        const QString in = QStringLiteral(
            "line ok normal text\n"
            "Authorization: Bearer abc123.DEF-ghi_456\n"
            "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4\n"
            "PrivateKey = qFq3mZ0kLbYf8VtH+aB1cDeFgHiJkLmNoPqRsTuVwX=\n"
            "PresharedKey: sPreSh4red+K3yValueGoesHere0000000000000000=\n"
            "innocent value = hello\n");
        const QString out = scrubLogTail(in);
        CHECK(out.contains(QStringLiteral("line ok normal text")), "scrub: обычная строка цела");
        CHECK(out.contains(QStringLiteral("Bearer <redacted>")), "scrub: Bearer вырезан");
        CHECK(!out.contains(QStringLiteral("abc123.DEF-ghi_456")), "scrub: тело Bearer не осталось");
        CHECK(!out.contains(QStringLiteral("eyJhbGciOiJIUzI1NiJ9")), "scrub: JWT вырезан");
        CHECK(!out.contains(QStringLiteral("qFq3mZ0kLbYf8VtH")), "scrub: PrivateKey вырезан");
        CHECK(out.contains(QStringLiteral("<redacted>")), "scrub: маркер редакции присутствует");
        CHECK(out.contains(QStringLiteral("innocent value = hello")), "scrub: безобидный key=value цел");
    }

    // ── кламп лог-хвоста до 16 КБ + выравнивание по строке ──────────────────────────────────────
    {
        QString big;
        for (int i = 0; i < 5000; ++i) big += QStringLiteral("0123456789ABCDEF line %1\n").arg(i);
        const QString c = clampLogTail(big);
        CHECK(c.toUtf8().size() <= kLogTailCapBytes, "clamp: хвост <= 16 КБ");
        CHECK(big.endsWith(c.right(20)), "clamp: сохранён именно КОНЕЦ (свежие строки)");
        CHECK(!c.startsWith(QStringLiteral("0123456789ABCDEF line ")) || c.indexOf('\n') > 0,
              "clamp: выровнен по началу строки");
    }

    // ── сборка отчёта signal (§1.3 схема) ───────────────────────────────────────────────────────
    {
        Sentinel sen; sen.valid = true; sen.build = QStringLiteral("5.1.57.85");
        sen.platform = QStringLiteral("macos"); sen.os = QStringLiteral("15.5");
        sen.phase = QStringLiteral("connected"); sen.uptimeS = 1234;
        SignalInfo si; si.valid = true; si.kind = 0; si.signalOrCode = 11;
        si.faultAddr = 0xabc; si.imageBase = 0x100000000ULL; si.frames = { 0x1000, 0x2000 };
        const QJsonObject rep = buildReport(Subtype::Signal, sen, &si,
                                            QStringLiteral("tail\nlog"), 0);
        CHECK(rep.value(QStringLiteral("type")).toString() == QLatin1String("crash"), "report: type=crash");
        CHECK(rep.value(QStringLiteral("schema")).toInt() == 1, "report: schema=1");
        CHECK(rep.value(QStringLiteral("subtype")).toString() == QLatin1String("signal"), "report: subtype=signal");
        CHECK(rep.value(QStringLiteral("build")).toString() == QLatin1String("5.1.57.85"), "report: build");
        CHECK(rep.value(QStringLiteral("platform")).toString() == QLatin1String("macos"), "report: platform");
        CHECK(rep.value(QStringLiteral("os")).toString() == QLatin1String("15.5"), "report: os");
        CHECK(rep.value(QStringLiteral("phase")).toString() == QLatin1String("connected"), "report: phase");
        CHECK(rep.value(QStringLiteral("uptime_s")).toDouble() == 1234, "report: uptime_s");
        CHECK(rep.value(QStringLiteral("signal")).toInt() == 11, "report: signal=11");
        CHECK(rep.value(QStringLiteral("fault_addr")).toString() == QLatin1String("0xabc"), "report: fault_addr hex");
        CHECK(rep.value(QStringLiteral("image_base")).toString() == QLatin1String("0x100000000"), "report: image_base hex");
        CHECK(rep.value(QStringLiteral("frames")).toArray().size() == 2, "report: 2 кадра");
        CHECK(rep.value(QStringLiteral("frames")).toArray().at(0).toString() == QLatin1String("0x1000"),
              "report: кадр в hex");
        CHECK(rep.value(QStringLiteral("log_tail")).toString().contains(QStringLiteral("tail")),
              "report: log_tail на месте");
        CHECK(rep.value(QStringLiteral("dirty_exits_since_last")).toInt() == 0, "report: dirty счётчик");
    }

    // ── отчёт dirty_exit: без signal-полей ──────────────────────────────────────────────────────
    {
        Sentinel sen; sen.valid = true; sen.build = QStringLiteral("5.1.57.85");
        sen.platform = QStringLiteral("windows"); sen.os = QStringLiteral("11");
        sen.phase = QStringLiteral("idle"); sen.uptimeS = 5;
        const QJsonObject rep = buildReport(Subtype::DirtyExit, sen, nullptr, QString(), 3);
        CHECK(rep.value(QStringLiteral("subtype")).toString() == QLatin1String("dirty_exit"),
              "report(dirty): subtype");
        CHECK(!rep.contains(QStringLiteral("signal")), "report(dirty): нет поля signal");
        CHECK(!rep.contains(QStringLiteral("frames")), "report(dirty): нет frames");
        CHECK(rep.value(QStringLiteral("dirty_exits_since_last")).toInt() == 3, "report(dirty): счётчик проброшен");
    }

    // ── отчёт seh: seh_code вместо signal ───────────────────────────────────────────────────────
    {
        Sentinel sen; sen.valid = true; sen.build = QStringLiteral("5.1"); sen.platform = QStringLiteral("windows");
        SignalInfo si; si.valid = true; si.kind = 1; si.signalOrCode = 0xC0000005;
        si.faultAddr = 0x7ff; si.imageBase = 0x140000000ULL;
        const QJsonObject rep = buildReport(Subtype::Seh, sen, &si, QString(), 0);
        CHECK(rep.value(QStringLiteral("subtype")).toString() == QLatin1String("seh"), "report(seh): subtype");
        CHECK(rep.value(QStringLiteral("seh_code")).toString() == QLatin1String("0xc0000005"),
              "report(seh): seh_code hex, нет поля signal");
        CHECK(!rep.contains(QStringLiteral("signal")), "report(seh): поля signal нет");
    }

    // ── отчёт java: java_stack, без signal-полей ────────────────────────────────────────────────
    {
        Sentinel sen; sen.valid = true; sen.build = QStringLiteral("5.1"); sen.platform = QStringLiteral("android");
        const QJsonObject rep = buildReport(Subtype::Java, sen, nullptr, QStringLiteral("logtail"),
                                            1, QStringLiteral("java.lang.NullPointerException\n\tat X"));
        CHECK(rep.value(QStringLiteral("subtype")).toString() == QLatin1String("java"), "report(java): subtype");
        CHECK(rep.value(QStringLiteral("java_stack")).toString().contains(QStringLiteral("NullPointer")),
              "report(java): stacktrace в java_stack");
        CHECK(!rep.contains(QStringLiteral("signal")), "report(java): нет signal");
    }

    // ── отчёт целиком без секретов ──────────────────────────────────────────────────────────────
    {
        Sentinel sen; sen.valid = true; sen.build = QStringLiteral("5.1");
        const QString tail = scrubLogTail(QStringLiteral("Bearer SECRETTOKEN123456\nok"));
        const QJsonObject rep = buildReport(Subtype::DirtyExit, sen, nullptr, tail, 0);
        const QByteArray raw = QJsonDocument(rep).toJson();
        CHECK(!raw.contains("SECRETTOKEN123456"), "report: секрет из лог-хвоста не утёк");
    }

    if (g_fail) { std::printf(">>> ПРОВАЛОВ: %d\n", g_fail); return 1; }
    std::printf(">>> crash_guard_check: все проверки зелёные\n");
    return 0;
}
