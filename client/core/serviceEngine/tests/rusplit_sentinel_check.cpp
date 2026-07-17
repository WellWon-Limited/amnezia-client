// AVPN (Доктор D-3 п.26): юнит чистой логики RU-split-дозорного — классификация проб,
// правило «отчёт только на смене состояния + 1/сутки», клампы, парс вахт-листа.
// Запуск: tests/build_rusentinel_check.sh (только QtCore; QObject-часть класса не собирается —
// подключается только namespace rusentinel через сам заголовок при собранных Qt-хедерах).
#include "../RuSplitSentinel.h"

#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; }           \
        else         { std::printf("ok:   %s\n", msg); }                     \
    } while (0)

int main()
{
    using namespace avpn::rusentinel;

    // классификация
    CHECK(classifyProbe(0, 200) == QLatin1String("ok"), "classify: 200 -> ok");
    CHECK(classifyProbe(0, 301) == QLatin1String("ok"), "classify: 301 -> ok (редирект = довели)");
    CHECK(classifyProbe(0, 503) == QLatin1String("http_5xx"), "classify: 503 -> http_5xx");
    CHECK(classifyProbe(3, 0) == QLatin1String("dns"), "classify: HostNotFound -> dns");
    CHECK(classifyProbe(4, 0) == QLatin1String("timeout"), "classify: Timeout -> timeout");
    CHECK(classifyProbe(6, 0) == QLatin1String("tls"), "classify: SslHandshake -> tls");
    CHECK(classifyProbe(99, 0) == QLatin1String("net"), "classify: прочее -> net");
    CHECK(probeOk(QStringLiteral("http_5xx")), "probeOk: 5xx = сайт болеет, маршрут довёл");
    CHECK(!probeOk(QStringLiteral("timeout")), "probeOk: timeout = недоступен");

    // правило отчёта: только переходы, суточный троттлинг
    CHECK(shouldReport(1, false, -1, 100), "report: был ok -> стал fail = слать");
    CHECK(shouldReport(0, true, -1, 100), "report: был fail -> восстановился = слать");
    CHECK(!shouldReport(1, true, -1, 100), "report: ok -> ok = молчим");
    CHECK(!shouldReport(0, false, -1, 100), "report: fail -> fail = молчим (уже слали)");
    CHECK(!shouldReport(-1, true, -1, 100), "report: первый раз и всё ок = молчим");
    CHECK(shouldReport(-1, false, -1, 100), "report: первый раз и сразу fail = слать");
    CHECK(!shouldReport(1, false, 100, 100), "report: переход, но сегодня уже слали = троттлинг");
    CHECK(shouldReport(1, false, 99, 100), "report: переход, слали вчера = слать");

    // кламп интервала
    CHECK(clampIntervalHours(0) == 6, "interval: нет ключа -> 6ч");
    CHECK(clampIntervalHours(0.5) == 1, "interval: низ -> 1ч");
    CHECK(clampIntervalHours(100) == 48, "interval: верх -> 48ч");
    CHECK(clampIntervalHours(12) == 12, "interval: валидный проходит");

    // парс вахт-листа
    QString n, u;
    CHECK(parseWatchEntry(QStringLiteral("Аэрофлот|https://www.aeroflot.ru/"), n, u)
              && n == QStringLiteral("Аэрофлот") && u == QLatin1String("https://www.aeroflot.ru/"),
          "parse: Имя|URL");
    CHECK(parseWatchEntry(QStringLiteral("https://ya.ru/x"), n, u) && n == QLatin1String("ya.ru"),
          "parse: голый URL -> имя = хост");
    CHECK(!parseWatchEntry(QStringLiteral("мусор"), n, u), "parse: не-URL отбрасывается");

    if (g_fail) { std::printf(">>> ПРОВАЛОВ: %d\n", g_fail); return 1; }
    std::printf(">>> ВСЕ ПРОВЕРКИ ЗЕЛЁНЫЕ\n");
    return 0;
}
