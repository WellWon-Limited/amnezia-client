// AVPN (Доктор v1): юнит чистой логики DoctorReport.h — вердикты стадий, клампы,
// humanSummary, сборка отчёта. Запуск: tests/build_doctor_check.sh (только QtCore).
#include "../DoctorReport.h"

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
    using namespace doctor;

    // клампы таймаута стадии
    CHECK(clampStageTimeoutMs(0) == 25000, "timeout: нет ключа -> дефолт 25с");
    CHECK(clampStageTimeoutMs(100) == 5000, "timeout: низ клампится в 5с");
    CHECK(clampStageTimeoutMs(999999) == 60000, "timeout: верх клампится в 60с");
    CHECK(clampStageTimeoutMs(30000) == 30000, "timeout: валидный проходит");

    // стадия подключения
    auto c1 = connectionStage(QStringLiteral("connected"), 200, 0, 5000);
    CHECK(c1.status == Bad, "connection: handshake стар + rx=0 при tx>0 -> Bad (зелёный-но-мёртвый)");
    auto c2 = connectionStage(QStringLiteral("connected"), 10, 4096, 2048);
    CHECK(c2.status == Ok, "connection: свежий handshake + трафик -> Ok");
    auto c3 = connectionStage(QStringLiteral("disconnected"), -1, 0, 0);
    CHECK(c3.status == Skip, "connection: выключен -> Skip (диагностируем прямую сеть)");
    auto c4 = connectionStage(QStringLiteral("connected"), 200, 4096, 2048);
    CHECK(c4.status == Warn, "connection: только старый handshake -> Warn");

    // стадия серверов
    CHECK(serversStage(0, 0, -1, false).status == Bad, "servers: пустой пул -> Bad");
    CHECK(serversStage(5, 0, -1, false).status == Warn, "servers: ноль замеров -> Warn (ICMP-блок не приговор)");
    CHECK(serversStage(5, 5, 48, false).status == Ok, "servers: живой замер -> Ok");
    CHECK(serversStage(5, 3, 420, true).status == Warn, "servers: лучший RTT >=300 -> Warn");

    // стадия оператора
    CHECK(operatorStage(QStringLiteral("cellular"), 0, 4, true, {}).status == Bad,
          "operator: кворум весь красный при живом DNS -> Bad (блокировка)");
    CHECK(operatorStage(QStringLiteral("wifi"), 4, 4, true, QStringLiteral("FI")).status == Ok,
          "operator: кворум зелёный -> Ok");
    CHECK(operatorStage(QStringLiteral("wifi"), 2, 4, true, {}).status == Warn,
          "operator: частичный кворум -> Warn");
    CHECK(operatorStage(QStringLiteral("wifi"), 4, 4, false, {}).status == Warn,
          "operator: DNS мёртв при живых пробах -> Warn");

    // стадия белых списков
    CHECK(whitelistStage(false, false, 0).status == Skip, "whitelist: Wi-Fi -> Skip");
    CHECK(whitelistStage(true, true, 2).status == Bad, "whitelist: детект активен -> Bad");
    CHECK(whitelistStage(true, false, 0).status == Ok, "whitelist: чисто -> Ok");

    // стадия скорости
    CHECK(speedStage(-1, 0, 0).status == Skip, "speed: не мерялась -> Skip");
    CHECK(speedStage(48.0, 40, 60).status == Ok, "speed: быстро без блоата -> Ok");
    CHECK(speedStage(2.0, 40, 60).status == Warn, "speed: медленно -> Warn");
    CHECK(speedStage(2.0, 40, 400).status == Bad, "speed: медленно + bufferbloat -> Bad");
    CHECK(speedStage(48.0, 40, 400).status == Warn, "speed: только bufferbloat -> Warn");

    // humanSummary: худшая стадия побеждает; Skip не участвует
    {
        QList<StageResult> st;
        st << connectionStage(QStringLiteral("connected"), 10, 4096, 2048)   // Ok
           << whitelistStage(false, false, 0)                                // Skip
           << speedStage(2.0, 40, 400);                                      // Bad
        CHECK(humanSummary(st) == speedStage(2.0, 40, 400).note,
              "summary: строка = худшая стадия (Bad скорости)");
    }
    {
        QList<StageResult> st;
        st << connectionStage(QStringLiteral("connected"), 10, 4096, 2048);
        CHECK(humanSummary(st).contains(QStringLiteral("Проблем не найдено")),
              "summary: всё Ok -> «проблем не найдено»");
    }
    {
        QList<StageResult> st;
        st << whitelistStage(false, false, 0);   // только Skip
        CHECK(humanSummary(st) == QStringLiteral("Диагностика выполнена"),
              "summary: только Skip -> нейтральная строка");
    }

    // сборка отчёта
    {
        QList<StageResult> st;
        st << connectionStage(QStringLiteral("connected"), 10, 4096, 2048)
           << speedStage(48.0, 40, 60);
        QJsonObject extra; extra.insert(QStringLiteral("app_ver"), QStringLiteral("test"));
        const QJsonObject rep = buildReport(st, extra);
        CHECK(rep.value(QStringLiteral("type")).toString() == QLatin1String("doctor"),
              "report: type=doctor");
        CHECK(rep.value(QStringLiteral("stages")).toArray().size() == 2, "report: 2 стадии");
        CHECK(rep.value(QStringLiteral("stages")).toArray().at(0).toObject()
                  .value(QStringLiteral("id")).toString() == QLatin1String("connection"),
              "report: id стадии на месте");
        CHECK(!rep.value(QStringLiteral("summary")).toString().isEmpty(), "report: summary не пуст");
        CHECK(rep.value(QStringLiteral("extra")).toObject()
                  .value(QStringLiteral("app_ver")).toString() == QLatin1String("test"),
              "report: extra прокинут");
        // приватность: в отчёте нет ключей/IP-полей
        const QByteArray raw = QJsonDocument(rep).toJson();
        CHECK(!raw.contains("private_key") && !raw.contains("\"ip\""),
              "report: нет ключей и IP");
    }

    if (g_fail) { std::printf(">>> ПРОВАЛОВ: %d\n", g_fail); return 1; }
    std::printf(">>> doctor_report_check: все проверки зелёные\n");
    return 0;
}
