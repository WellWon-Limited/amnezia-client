// AVPN (Доктор v2, активная модель): юнит чистой логики DoctorReport.h — вердикты стадий,
// клампы, humanSummary, сборка отчёта. Запуск: tests/build_doctor_check.sh (только QtCore).
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

    // стадия подключения (активная)
    CHECK(connectStage(false, false, -1).status == Bad,
          "connect: не поднялся -> Bad «не удалось подключиться»");
    CHECK(connectStage(true, false, 200).status == Bad,
          "connect: поднят, но данные не идут -> Bad (зелёный-но-мёртвый)");
    CHECK(connectStage(true, true, 10).status == Ok,
          "connect: поднят + данные идут -> Ok");

    // стадия серверов
    CHECK(serverStage(QStringLiteral("Финляндия"), QStringLiteral("FI"), 28).status == Ok,
          "servers: близкий сервер -> Ok");
    CHECK(serverStage(QStringLiteral("США"), QStringLiteral("US"), 450).status == Warn,
          "servers: RTT>=400 -> Warn (далеко)");
    CHECK(serverStage({}, {}, -1).status == Ok,
          "servers: без региона/RTT -> Ok (нейтрально)");
    CHECK(serverStage(QStringLiteral("Латвия"), QStringLiteral("LV"), 28).note.contains(QStringLiteral("Латвия")),
          "servers: регион попадает в текст");

    // стадия сервисов
    CHECK(servicesStage(4, 4, {}, false, false).status == Ok,
          "services: все works -> Ok");
    CHECK(servicesStage(3, 4, {QStringLiteral("WhatsApp")}, false, false).status == Bad,
          "services: один заблокирован -> Bad с названием");
    CHECK(servicesStage(3, 4, {QStringLiteral("WhatsApp")}, false, false)
              .note.contains(QStringLiteral("WhatsApp")),
          "services: имя заблокированного в тексте");
    CHECK(servicesStage(0, 0, {}, false, false).status == Skip,
          "services: ничего не измерено -> Skip");
    CHECK(servicesStage(2, 4, {}, true, true).status == Bad,
          "services: whitelist активен -> Bad (оператор ограничивает)");
    CHECK(servicesStage(4, 4, {}, true, false).status == Ok,
          "services: whitelist применим, но не активен -> Ok");

    // стадия скорости
    CHECK(speedStage(-1, 0, 0).status == Skip, "speed: не мерялась -> Skip");
    CHECK(speedStage(48.0, 40, 60).status == Ok, "speed: быстро без блоата -> Ok");
    CHECK(speedStage(2.0, 40, 60).status == Warn, "speed: медленно -> Warn");
    CHECK(speedStage(2.0, 40, 400).status == Bad, "speed: медленно + bufferbloat -> Bad");
    CHECK(speedStage(48.0, 40, 400).status == Warn, "speed: только bufferbloat -> Warn");

    // humanSummary: худшая стадия побеждает; Skip не участвует
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10)                      // Ok
           << servicesStage(0, 0, {}, false, false)             // Skip
           << speedStage(2.0, 40, 400);                         // Bad
        CHECK(humanSummary(st) == speedStage(2.0, 40, 400).note,
              "summary: строка = худшая стадия (Bad скорости)");
    }
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10);
        CHECK(humanSummary(st).contains(QStringLiteral("Всё работает")),
              "summary: всё Ok -> «всё работает»");
    }
    {
        QList<StageResult> st;
        st << servicesStage(0, 0, {}, false, false);   // только Skip
        CHECK(humanSummary(st) == QStringLiteral("Диагностика выполнена"),
              "summary: только Skip -> нейтральная строка");
    }

    // страны и человекочитаемое резюме для менеджера
    CHECK(countryNameRu(QStringLiteral("lv")) == QStringLiteral("Латвия"),
          "country: lv -> Латвия (регистронезависимо)");
    CHECK(countryNameRu(QStringLiteral("ZZ")) == QStringLiteral("ZZ"),
          "country: неизвестный код -> код заглавными");
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10)
           << serverStage(QStringLiteral("Латвия"), QStringLiteral("LV"), 28);
        CHECK(!hasProblem(st), "hasProblem: всё Ok -> false");
        st << servicesStage(3, 4, {QStringLiteral("WhatsApp")}, false, false);
        CHECK(hasProblem(st), "hasProblem: есть Bad -> true");
        const QString rep = humanReport(st, QStringLiteral("wifi"), QStringLiteral("Europe/Riga"));
        CHECK(rep.contains(QStringLiteral("[x]")) && rep.contains(QStringLiteral("WhatsApp")),
              "humanReport: маркер и имя сервиса на месте");
        CHECK(rep.contains(QStringLiteral("Wi-Fi")), "humanReport: тип сети словами");
    }
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10) << speedStage(-1, 0, 0);   // Ok + Skip
        CHECK(humanSummary(st).contains(QStringLiteral("часть проверок")),
              "summary: Ok+Skip -> честная оговорка, не «всё работает»");
    }

    // фикс «канал пухнет» на сотовой: относительный рост при МАЛОМ абсолюте — НЕ блоат
    CHECK(speedStage(30.0, 40, 120).status == Ok,
          "speed: 30 Мбит, idle 40 -> loaded 120 (ratio 3, но < 400мс) -> Ok, НЕ «пухнет»");
    CHECK(speedStage(30.0, 100, 450).status == Warn,
          "speed: loaded 450мс при росте — честный Warn «пухнет»");

    // стадия других серверов
    CHECK(altNodesStage({}, {}, {}).status == Skip, "alt: не проверялись -> Skip");
    CHECK(altNodesStage({QStringLiteral("Финляндия")}, {true}, QStringLiteral("Финляндия")).status == Ok,
          "alt: рабочая найдена -> Ok «переключил»");
    CHECK(altNodesStage({QStringLiteral("Финляндия")}, {true}, QStringLiteral("Финляндия"))
              .note.contains(QStringLiteral("Финляндия")),
          "alt: имя ноды в тексте");
    CHECK(altNodesStage({QStringLiteral("A"), QStringLiteral("B")}, {false, false}, {}).status == Bad,
          "alt: все мертвы -> Bad «дело в вашей сети»");

    // стадия РФ-сплита
    CHECK(ruSplitStage({}, {}).status == Skip, "rusplit: не проверялись -> Skip");
    CHECK(ruSplitStage({QStringLiteral("Яндекс"), QStringLiteral("VK")}, {true, true}).status == Ok,
          "rusplit: все открылись -> Ok");
    CHECK(ruSplitStage({QStringLiteral("Яндекс"), QStringLiteral("Аэрофлот")}, {true, false}).status == Warn,
          "rusplit: часть не открылась -> Warn с именами");
    CHECK(ruSplitStage({QStringLiteral("Яндекс"), QStringLiteral("Аэрофлот")}, {true, false})
              .note.contains(QStringLiteral("Аэрофлот")),
          "rusplit: имя упавшего сайта в тексте");
    CHECK(ruSplitStage({QStringLiteral("Яндекс")}, {false}).status == Bad,
          "rusplit: всё мертво -> Bad «проблема с Доступом к РФ»");

    // сборка отчёта
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10) << speedStage(48.0, 40, 60);
        QJsonObject extra; extra.insert(QStringLiteral("app_ver"), QStringLiteral("test"));
        const QJsonObject rep = buildReport(st, extra);
        CHECK(rep.value(QStringLiteral("type")).toString() == QLatin1String("doctor"),
              "report: type=doctor");
        CHECK(rep.value(QStringLiteral("schema")).toInt() == 2, "report: schema=2 (активная)");
        CHECK(rep.value(QStringLiteral("stages")).toArray().size() == 2, "report: 2 стадии");
        CHECK(rep.value(QStringLiteral("stages")).toArray().at(0).toObject()
                  .value(QStringLiteral("id")).toString() == QLatin1String("connect"),
              "report: id стадии на месте");
        CHECK(!rep.value(QStringLiteral("summary")).toString().isEmpty(), "report: summary не пуст");
        CHECK(rep.value(QStringLiteral("extra")).toObject()
                  .value(QStringLiteral("app_ver")).toString() == QLatin1String("test"),
              "report: extra прокинут");
        const QByteArray raw = QJsonDocument(rep).toJson();
        CHECK(!raw.contains("private_key") && !raw.contains("\"ip\""),
              "report: нет ключей и IP");
    }

    if (g_fail) { std::printf(">>> ПРОВАЛОВ: %d\n", g_fail); return 1; }
    std::printf(">>> doctor_report_check: все проверки зелёные\n");
    return 0;
}
