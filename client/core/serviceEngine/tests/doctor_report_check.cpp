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
    // Разбор журнала 26.09: возврат выбора после альтернатив не должен оставлять VPN выключенным,
    // если он был включён на старте Доктора (туннель лежит, потому что его остановил сам Доктор).
    CHECK(restoreKeepsConnected(true, false), "restore: был включён, туннель сейчас лежит -> включить");
    CHECK(restoreKeepsConnected(true, true), "restore: был включён и поднят -> включён");
    CHECK(restoreKeepsConnected(false, true), "restore: был выключен, Доктор поднял -> как раньше, включён");
    CHECK(!restoreKeepsConnected(false, false), "restore: был выключен и лежит -> выключен");
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
    CHECK(serverStage(QStringLiteral("США"), QStringLiteral("US"), 450).status == Ok,
          "servers: 450 мс при дефолтном пороге 800 -> Ok (пересмотр владельца 07-21)");
    CHECK(serverStage(QStringLiteral("США"), QStringLiteral("US"), 900).status == Warn,
          "servers: RTT>=800 (дефолт) -> Warn (далеко)");
    CHECK(serverStage(QStringLiteral("США"), QStringLiteral("US"), 450, 400).status == Warn,
          "servers: порог server-driven — 450 при warnMs=400 -> Warn");
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

    // D-3: стадия сети (network) — captive/поколение/белые списки
    CHECK(networkStage(1, QStringLiteral("wifi"), {}, -1, -1, -1).status == Bad,
          "network: captive-портал -> Bad «залогиньтесь»");
    CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("lte"), -1, -1, 1).status == Bad,
          "network: форс-пробы дали whitelist -> Bad");
    CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("3g"), -1, -1, 0).status == Warn,
          "network: 3G -> Warn «медленно само по себе»");
    CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("lte"), 1, 0, 0).status == Ok,
          "network: LTE без captive/wl -> Ok");
    CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("lte"), -1, 1, 0)
              .note.contains(QStringLiteral("роуминг")),
          "network: роуминг попадает в текст");
    CHECK(networkStage(-1, QStringLiteral("wifi"), {}, -1, -1, -1).status == Ok,
          "network: Wi-Fi, captive не проверялся -> Ok (без вранья)");
    CHECK(!networkStage(-1, {}, {}, -1, -1, -1).data.contains(QStringLiteral("captive")),
          "network: непроверенные поля не пишутся в data");

    // IPv6-волна 2026-09-08: туннель v4-only забирает ::/0 — на сети С глобальным v6 это
    // единственное объяснение «v6-only адресат недостижим». Говорим ТОЛЬКО когда есть о чём.
    {
        const StageResult withV6 = networkStage(0, QStringLiteral("wifi"), {}, -1, -1, 0, {}, 1);
        CHECK(withV6.note.contains(QStringLiteral("IPv6")),
              "network: сеть с глобальным v6 -> в note объяснение про IPv6");
        CHECK(withV6.status == Ok,
              "network: IPv6 выключен туннелем — это НЕ проблема сети, статус остаётся Ok");
        CHECK(withV6.data.value(QStringLiteral("ipv6_lan")).toBool() == true,
              "network: факт v6 у сети едет в отчёт поддержки");
        CHECK(withV6.note.contains(QStringLiteral("Wi-Fi")),
              "network: прежний текст про тип сети не потерян");

        const StageResult noV6 = networkStage(0, QStringLiteral("wifi"), {}, -1, -1, 0, {}, 0);
        CHECK(!noV6.note.contains(QStringLiteral("IPv6")),
              "network: сеть без v6 -> ни слова про IPv6 (незачем пугать)");
        CHECK(noV6.data.value(QStringLiteral("ipv6_lan")).toBool() == false,
              "network: проверено и v6 нет -> false в отчёт");

        const StageResult unknownV6 = networkStage(0, QStringLiteral("wifi"), {}, -1, -1, 0, {}, -1);
        CHECK(!unknownV6.note.contains(QStringLiteral("IPv6")),
              "network: не проверяли -> молчим");
        CHECK(!unknownV6.data.contains(QStringLiteral("ipv6_lan")),
              "network: не проверяли -> поля в отчёте нет (честно)");

        CHECK(networkStage(1, QStringLiteral("wifi"), {}, -1, -1, -1, {}, 1)
                  .note.contains(QStringLiteral("браузер")),
              "network: captive-портал важнее IPv6 — вердикт стадии не подменяется");
        CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("lte"), -1, -1, 1, {}, 1)
                  .note.contains(QStringLiteral("белые списки")),
              "network: «белые списки» важнее IPv6");
    }

    // D-3: коллапс посекундного профиля (ТСПУ-сигнатура)
    const QList<double> flat{20, 21, 19, 20, 22, 20, 21, 20};
    const QList<double> tspu{25, 24, 20, 2.0, 1.5, 1.0, 0.8, 0.5};
    const QList<double> slowAll{2, 2.5, 2, 1.8, 2.2, 2, 2.1};
    CHECK(!speedCollapsed(flat), "collapse: ровный профиль -> нет");
    CHECK(speedCollapsed(tspu), "collapse: летит-потом-душат -> да");
    CHECK(!speedCollapsed(slowAll), "collapse: медленно с самого начала -> нет (не ТСПУ)");
    CHECK(!speedCollapsed({25, 24, 20, 2.0}), "collapse: профиль короче 6с -> нет");
    CHECK(!speedCollapsed({25, 24, 20, 10, 9, 8, 7, 6}), "collapse: плавное снижение -> нет");

    // D-3: speedStage с коллапсом и A/B direct
    CHECK(speedStage(6.0, 40, 60, true, -1).status == Bad,
          "speed: коллапс -> Bad независимо от среднего");
    CHECK(speedStage(6.0, 40, 60, true, 30.0).note.contains(QStringLiteral("напрямую")),
          "speed: коллапс + direct быстрый -> текст про «напрямую быстрая»");
    CHECK(speedStage(3.0, 40, 60, false, 2.5).status == Warn,
          "speed: медленно и без VPN -> Warn «дело не в VPN»");
    CHECK(speedStage(3.0, 40, 60, false, 2.5).note.contains(QStringLiteral("не в VPN")),
          "speed: текст «дело не в VPN» присутствует");
    CHECK(speedStage(48.0, 40, 60, false, -1).status == Ok,
          "speed: direct не мерялся -> поведение прежнее");
    CHECK(!speedStage(48.0, 40, 60).data.contains(QStringLiteral("direct_mbit")),
          "speed: без direct замера поле не пишется");

    // Plan v3 step 5: speed only over a working connection
    {
        QList<StageResult> st;
        st.append(connectStage(true, true, 3));
        CHECK(speedStageApplicable(st, true), "speed: подключение работает -> замер идёт");
        CHECK(!speedStageApplicable(st, false), "speed: туннель не поднят сейчас -> пропуск");
        QList<StageResult> noConn;
        noConn.append(connectStage(false, false, -1));
        CHECK(!speedStageApplicable(noConn, true), "speed: подключиться не удалось -> пропуск");
        QList<StageResult> noData;
        noData.append(connectStage(true, false, 5));
        CHECK(!speedStageApplicable(noData, true), "speed: подключено без данных -> пропуск");
        CHECK(speedStageApplicable({}, true), "speed: стадии connect нет (старый порядок) -> по туннелю");
        const StageResult sk = speedStageSkippedNoConnection();
        CHECK(sk.status == Skip && sk.id == QLatin1String("speed"), "speed: пропуск = Skip стадии speed");
        CHECK(sk.data.value(QStringLiteral("skipped")).toString() == QLatin1String("no_connection"),
              "speed: причина пропуска в отчёте");
        CHECK(sk.note.contains(QStringLiteral("нет рабочего подключения")), "speed: причина пропуска человеку");
    }

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
    // Owner test of 5.1.102: a listener without a label shows a country name, never "ee".
    CHECK(countryDisplayName(QStringLiteral("ee"), QStringLiteral("ru")) == QStringLiteral("Эстония"),
          "country display: ee, ru UI -> Эстония");
    CHECK(countryDisplayName(QStringLiteral("ee"), QStringLiteral("en")) == QStringLiteral("Estonia"),
          "country display: ee, en UI -> Estonia");
    CHECK(countryDisplayName(QStringLiteral("br"), QStringLiteral("ru")) == QStringLiteral("Brazil"),
          "country display: no Russian name in the table -> English, not the code");
    CHECK(countryDisplayName(QStringLiteral("zz"), QStringLiteral("es")) == QStringLiteral("ZZ"),
          "country display: unknown code -> the code in capitals");
    CHECK(countryDisplayName(QString(), QStringLiteral("ru")).isEmpty(), "country display: no code -> empty");
    // U2 (device test 142): own nodes' English country labels follow the UI language, number kept.
    {
        const QString ru = QStringLiteral("ru");
        CHECK(localizedNodeLabel("Finland 1", "FI", ru) == QStringLiteral("Финляндия 1"), "node label: Finland 1 -> Финляндия 1");
        CHECK(localizedNodeLabel("Germany", "DE", ru) == QStringLiteral("Германия"), "node label: no number -> the country only");
        CHECK(localizedNodeLabel("Estonia 3", "EE", ru) == QStringLiteral("Эстония 3"), "node label: Estonia 3");
        CHECK(localizedNodeLabel("USA", "US", ru) == QStringLiteral("США"), "node label: the USA alias");
        CHECK(localizedNodeLabel("United States 2", "us", ru) == QStringLiteral("США 2"), "node label: QLocale name, lower-case code");
        CHECK(localizedNodeLabel("finland  #2", "FI", ru) == QStringLiteral("Финляндия 2"), "node label: case and '#'");
        CHECK(localizedNodeLabel("FI 4", "FI", ru) == QStringLiteral("Финляндия 4"), "node label: the code form");
        CHECK(localizedNodeLabel("Финляндия 1", "FI", "en") == QStringLiteral("Finland 1"), "node label: a Russian label in an English UI");
        CHECK(localizedNodeLabel("Finland 1", "FI", "es") == QStringLiteral("Finlandia 1"), "node label: Spanish UI");
        CHECK(localizedNodeLabel("Helsinki fast", "FI", ru) == QStringLiteral("Helsinki fast"), "node label: the admin's own name stays");
        CHECK(localizedNodeLabel("Germany 1", "FI", ru) == QStringLiteral("Germany 1"), "node label: another country's name stays");
        CHECK(localizedNodeLabel("Finland 1", "", ru) == QStringLiteral("Finland 1"), "node label: no code -> as is");
        CHECK(localizedNodeLabel("", "FI", ru).isEmpty(), "node label: empty stays empty (pickerDisplay fallback)");
        CHECK(localizedNodeLabel("12", "FI", ru) == QStringLiteral("12"), "node label: a bare number stays");
    }
    // 5.1.108: Spanish UI gets Spanish names (QLocale only gives English ones).
    CHECK(countryDisplayName(QStringLiteral("fi"), QStringLiteral("es")) == QStringLiteral("Finlandia"),
          "country display: fi, es UI -> Finlandia");
    CHECK(countryDisplayName(QStringLiteral("DE"), QStringLiteral("es_ES")) == QStringLiteral("Alemania"),
          "country display: DE, es_ES UI -> Alemania");
    CHECK(countryDisplayName(QStringLiteral("br"), QStringLiteral("es")) == QStringLiteral("Brazil"),
          "country display: no Spanish name in the table -> English, not the code");
    // Owner test of 5.1.102: one line per checked alternative while the stage runs.
    CHECK(altNodeResult(2, true) == QStringLiteral("ok"), "alt result: both probes -> ok");
    CHECK(altNodeResult(1, true) == QStringLiteral("no_data"), "alt result: up, data dropped -> no_data");
    CHECK(altNodeResult(0, true) == QStringLiteral("no_data"), "alt result: up, no data -> no_data");
    CHECK(altNodeResult(0, false) == QStringLiteral("unreachable"), "alt result: never came up -> unreachable");
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
    CHECK(ruSplitStage({}, {}, /*enabled=*/false).status == Skip,
          "rusplit: тумблер выключен -> Skip (не Bad)");
    CHECK(ruSplitStage({}, {}, /*enabled=*/false).note.contains(QStringLiteral("выключен")),
          "rusplit: причина Skip — «выключен» видна поддержке");

    // сборка отчёта
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10) << speedStage(48.0, 40, 60);
        QJsonObject extra; extra.insert(QStringLiteral("app_ver"), QStringLiteral("test"));
        const QJsonObject rep = buildReport(st, extra);
        CHECK(rep.value(QStringLiteral("type")).toString() == QLatin1String("doctor"),
              "report: type=doctor");
        CHECK(rep.value(QStringLiteral("schema")).toInt() == 4, "report: schema=4 (волна UX 07-22)");
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

    // ==== AVPN Scanner (lane L6b): the check of «Ваше подключение» - schema 5 (openapi DoctorCheckReport) ====
    {
        // A summary as ScanMachine::buildSummary writes it (keys, types, ranges of DoctorScanSummary).
        const QJsonObject scan{
            {"schema", 1}, {"network_key", "cell:250-02:4g"}, {"manifest_revision", 12}, {"candidates", 23},
            {"counts", QJsonObject{{"works", 8}, {"slow", 2}, {"not_verified", 3}}},
            {"top", QJsonArray{QJsonObject{{"kind", "node"}, {"id", "9"}, {"class", "works"}, {"ms", 41}, {"probe", "tunnel"}},
                               QJsonObject{{"kind", "node"}, {"id", "9:xray"}, {"class", "slow"}, {"ms", 380}, {"probe", "leg"}},
                               QJsonObject{{"kind", "upstream"}, {"id", "0123456789abcdef"}, {"class", "not_verified"}}}},
            {"not_verified_reasons", QJsonObject{{"composite", 2}, {"no_seat", 1}}},
            {"stop_reason", "works"}, {"duration_ms", 4100}, {"bytes_spent", 812345},
            {"caps", QJsonObject{{"leg_probe", true}, {"full_profile", false}, {"full_profile_parallel", false},
                                 {"awg_mini", false}, {"probe_with_vpn_off", false}}}};
        CHECK(scanSummaryValid(scan), "check: a summary of the machine's shape passes");
        QList<StageResult> st;
        st << networkStage(0, "cellular", "lte", -1, -1, -1) << connectStageNoVpn()
           << serverStage("Латвия", "LV", 120) << servicesStage(4, 4, {}, false, false)
           << ruSplitStage({"Яндекс"}, {true}) << speedStage(24.0, 40, 90)
           << altNodesStage({"x"}, {true}, QString()); // not a check stage: dropped by the builder
        const QJsonObject extra{{"app_ver", "test"}};
        const QJsonObject good = buildCheckReport(st, extra, scan);
        QString why;
        CHECK(checkReportValid(good, &why), "check: good report valid");
        CHECK(good.value("schema").toInt() == 5 && good.value("mode").toString() == "check", "check: schema 5, mode check");
        CHECK(good.value("stages").toArray().size() == 6, "check: six stages, altnodes dropped");
        CHECK(good.value("scan").toObject() == scan, "check: the machine's summary is the scan block");
        // No summary of the scan: no `scan` key (the schema has no null for it).
        CHECK(!buildCheckReport(st, extra, QJsonObject()).contains("scan") && checkReportValid(buildCheckReport(st, extra, {})),
              "check: without a scan summary the key is absent and the report valid");
        // The connect stage of a VPN-off check: skipped, never "connected".
        CHECK(connectStageNoVpn().status == Skip && !connectStageNoVpn().data.value("could_connect").toBool(),
              "check: connect stage with the VPN off is skipped");

        auto bad = [&](QJsonObject o, const char *msg) {
            QString w;
            CHECK(!checkReportValid(o, &w) && !w.isEmpty(), msg);
        };
        { QJsonObject o = good; o.remove("mode"); bad(o, "check: missing mode rejected"); }
        { QJsonObject o = good; o.insert("mode", "Check!"); bad(o, "check: malformed mode rejected"); }
        { QJsonObject o = good; o.insert("schema", 4); bad(o, "check: schema 4 is not this report"); }
        { QJsonObject o = good; o.insert("type", "bench"); bad(o, "check: type must be doctor"); }
        for (const char *k : {"cellular", "cell", "wifi:asn:0", "cell:250-2:4g", "wifi:aa:bb:cc:dd:ee:ff", "cell:250-02"}) {
            QJsonObject sc = scan; sc.insert("network_key", k);
            QJsonObject o = good; o.insert("scan", sc);
            bad(o, "check: a bare or malformed network class rejected");
        }
        for (const char *k : {"wifi", "unknown", "wifi:asn:12389", "cell:asn:31133:5g", "cell:250-99:unknown"}) {
            QJsonObject sc = scan; sc.insert("network_key", k);
            QJsonObject o = good; o.insert("scan", sc);
            CHECK(checkReportValid(o), "check: a full network key passes");
        }
        auto withTop = [&](const QJsonObject &row) {
            QJsonObject sc = scan; sc.insert("top", QJsonArray{row});
            QJsonObject o = good; o.insert("scan", sc);
            return o;
        };
        bad(withTop(QJsonObject{{"kind", "node"}, {"id", "203.0.113.7"}, {"class", "works"}}), "check: an address-like node id rejected");
        bad(withTop(QJsonObject{{"kind", "upstream"}, {"id", "up:0123456789abcdef"}, {"class", "works"}}), "check: an engine id up:... rejected");
        bad(withTop(QJsonObject{{"kind", "upstream"}, {"id", "10.0.0.1"}, {"class", "works"}}), "check: an address as a profile id rejected");
        // contract 1.7.0: the row's evidence (direct | exclusion) and the summary's seats_requested (0..48)
        for (const char *e : {"direct", "exclusion"})
            CHECK(checkReportValid(withTop(QJsonObject{{"kind", "upstream"}, {"id", "0123456789abcdef"}, {"class", "works"}, {"evidence", e}})),
                  "check: a row with evidence direct / exclusion passes (1.7.0)");
        bad(withTop(QJsonObject{{"kind", "node"}, {"id", "9"}, {"class", "works"}, {"evidence", "guess"}}), "check: an unknown evidence rejected");
        bad(withTop(QJsonObject{{"kind", "node"}, {"id", "9"}, {"class", "works"}, {"evidence", 1}}), "check: a non-string evidence rejected");
        for (int n : {0, 12, 48}) {
            QJsonObject sc = scan; sc.insert("seats_requested", n);
            QJsonObject o = good; o.insert("scan", sc);
            CHECK(checkReportValid(o), "check: seats_requested 0..48 passes (1.7.0)");
        }
        for (const QJsonValue &v : {QJsonValue(49), QJsonValue(-1), QJsonValue(2.5), QJsonValue("3")}) {
            QJsonObject sc = scan; sc.insert("seats_requested", v);
            QJsonObject o = good; o.insert("scan", sc);
            bad(o, "check: seats_requested out of 0..48 or not an integer rejected");
        }
        for (const char *k : {"wifi:asn:064500", "cell:asn:0123:4g"}) {
            QJsonObject sc = scan; sc.insert("network_key", k);
            QJsonObject o = good; o.insert("scan", sc);
            bad(o, "check: an ASN with a leading zero rejected (as the server's pattern)");
        }
        bad(withTop(QJsonObject{{"kind", "node"}, {"id", "9"}, {"class", "fast"}}), "check: an unknown class rejected");
        bad(withTop(QJsonObject{{"kind", "node"}, {"id", "9"}, {"class", "works"}, {"ms", -1}}), "check: negative ms rejected");
        { QJsonObject sc = scan; sc.insert("leg", "vless://x"); QJsonObject o = good; o.insert("scan", sc); bad(o, "check: an unknown scan key rejected"); }
        { QJsonObject sc = scan; sc.insert("counts", QJsonObject{{"works", 1.5}}); QJsonObject o = good; o.insert("scan", sc); bad(o, "check: a non-integer count rejected"); }
        { QJsonObject sc = scan; sc.insert("candidates", 2000); QJsonObject o = good; o.insert("scan", sc); bad(o, "check: candidates over 1024 rejected"); }
        {
            QJsonArray a = good.value("stages").toArray();
            a.append(a.first());
            QJsonObject o = good; o.insert("stages", a);
            bad(o, "check: a duplicate stage id rejected");
        }
        {
            QJsonArray a = good.value("stages").toArray();
            QJsonObject e = a.first().toObject(); e.insert("id", "altnodes"); a[0] = e;
            QJsonObject o = good; o.insert("stages", a);
            bad(o, "check: a stage outside the six rejected");
        }
        {
            QJsonArray a = good.value("stages").toArray();
            QJsonObject e = a.first().toObject(); e.insert("status", 3); a[0] = e;
            QJsonObject o = good; o.insert("stages", a);
            bad(o, "check: status 3 rejected");
        }
        {
            QJsonArray a = good.value("stages").toArray();
            QJsonObject e = a.first().toObject(); e.insert("note", QString(501, QChar('x'))); a[0] = e;
            QJsonObject o = good; o.insert("stages", a);
            bad(o, "check: a note over 500 rejected");
        }
        { QJsonObject o = good; o.insert("summary", QString(4001, QChar('x'))); bad(o, "check: a summary over 4000 rejected"); }
        // Over 256 KiB: rejected as it is; fitCheckReport gives up `extra` first and the report passes.
        {
            QJsonObject big = extra;
            big.insert("bench", QString(300 * 1024, QChar('b')));
            const QJsonObject huge = buildCheckReport(st, big, scan);
            QString w;
            CHECK(checkReportBytes(huge) > kCheckReportMaxBytes && !checkReportValid(huge, &w) && w == "size",
                  "check: over 256 KiB rejected");
            const QJsonObject fit = fitCheckReport(huge);
            CHECK(checkReportBytes(fit) <= kCheckReportMaxBytes && checkReportValid(fit), "check: fitted report valid");
            CHECK(fit.value("scan").toObject() == scan && fit.value("stages").toArray().size() == 6,
                  "check: fitting never cuts stages or the scan block");
            CHECK(!fit.value("extra").toObject().contains("bench") && fit.value("extra").toObject().value("app_ver") == "test",
                  "check: the bench goes first, the small context stays");
        }
        // The builder itself clamps what the server would refuse.
        {
            QList<StageResult> long1;
            StageResult r = serverStage("x", "LV", 1);
            r.note = QString(800, QChar('n'));
            long1 << r;
            CHECK(checkReportValid(buildCheckReport(long1, {}, {})), "check: the builder clamps a long note");
        }

        // diag.log: the report first, never cut; the whole within the attachment cap, cut on a UTF-8 boundary.
        {
            const QString json = QString::fromUtf8(QJsonDocument(good).toJson(QJsonDocument::Compact));
            const QString diag = checkDiagText(json, QString(600 * 1024, QChar(0x0416)), 300 * 1024); // 'Ж' = 2 bytes
            CHECK(diag.toUtf8().size() <= 300 * 1024, "diag: within the cap");
            CHECK(diag.contains(json), "diag: the report is whole");
            CHECK(diag.endsWith("[truncated]\n") && !diag.contains(QChar::ReplacementCharacter), "diag: cut cleanly");
            CHECK(checkDiagText(json, "short", 300 * 1024).endsWith("short"), "diag: a short diag stays whole");
        }

        // The shade follows the support thread: both parts acked = sent; else wait, and the bound = queued.
        CHECK(checkDelivery("queued", "acked", "acked", false) == CheckDelivery::Sent, "delivery: text + log acked -> sent (bench pending)");
        CHECK(checkDelivery("delivered", "acked", "acked", false) == CheckDelivery::Sent, "delivery: delivered -> sent");
        CHECK(checkDelivery("sending", "acked", "pending", false) == CheckDelivery::Wait, "delivery: log still pending -> wait");
        CHECK(checkDelivery("queued", "acked", "pending", false) == CheckDelivery::Wait, "delivery: between parts -> wait");
        CHECK(checkDelivery("queued", "pending", "pending", true) == CheckDelivery::Queued, "delivery: the Send bound -> queued");
        // Queue lane F3/F4: refused by the server -> kept, retried after an update: rejected, never «уйдёт».
        CHECK(checkDelivery("rejected", "rejected", "acked", false) == CheckDelivery::Rejected, "delivery: text refused -> rejected");
        CHECK(checkDelivery("rejected", "acked", "rejected", false) == CheckDelivery::Rejected, "delivery: log refused -> rejected");
        CHECK(checkDelivery("rejected", "acked", "acked", false) == CheckDelivery::Sent, "delivery: only the bench refused -> sent");
        CHECK(checkDelivery("queued", "rejected", "pending", false) == CheckDelivery::Wait, "delivery: text refused, log pending -> wait");
        CHECK(checkDelivery("queued", "rejected", "pending", true) == CheckDelivery::Rejected, "delivery: ... at the bound -> rejected");
        // Not written to disk: never «уйдёт».
        CHECK(checkDelivery("unknown", "", "", false) == CheckDelivery::NotSaved, "delivery: unknown id -> not saved");
        CHECK(checkDelivery("not_saved", "failed", "pending", false) == CheckDelivery::NotSaved, "delivery: not_saved -> not saved");
        CHECK(checkDelivery("sent_unsaved", "acked", "acked", false) == CheckDelivery::Sent, "delivery: sent_unsaved -> sent");
        CHECK(checkDelivery("sent_unsaved", "", "", false) == CheckDelivery::Sent, "delivery: sent_unsaved without parts -> sent");
        CHECK(checkDelivery("unsaved_sending", "acked", "pending", false) == CheckDelivery::Wait, "delivery: unsaved, sending -> wait");
        CHECK(checkDelivery("unsaved_sending", "acked", "pending", true) == CheckDelivery::NotSaved, "delivery: unsaved at the bound -> not saved");
        CHECK(checkDelivery("queued", "acked", "", false) == CheckDelivery::Sent, "delivery: a report without a log part");

        // The card's facts.
        CHECK(!speedCardFact(-1, Skip).known, "speed card: not measured");
        CHECK(speedCardFact(24.0, Ok).bars == 5 && speedCardFact(24.0, Ok).word == "comfortable", "speed card: fast");
        CHECK(speedCardFact(3.0, Warn).bars == 2 && speedCardFact(3.0, Warn).word == "slow", "speed card: slow");
        bool fresh = true;
        const QVariantList svc{QVariantMap{{"key", "whatsapp"}, {"state", 2}, {"stale", false}},
                               QVariantMap{{"key", "telegram"}, {"state", 0}, {"stale", true}},
                               QVariantMap{{"key", "youtube"}, {"state", -1}, {"stale", false}}};
        const QList<int> chips = scanChipStates(svc, &fresh);
        CHECK(chips == (QList<int>{-1, -1, -1, 2}) && fresh, "chips: order Telegram YouTube Instagram WhatsApp, stale = unknown");
        scanChipStates({QVariantMap{{"key", "telegram"}, {"state", 2}, {"stale", true}}}, &fresh);
        CHECK(!fresh, "chips: only stale ones = «проверим по кнопке»");
    }

    // ==== AVPN Scanner, second pass: the check's speed = one /v1/probe sample (TribeScanner::sampleSpeed) ====
    {
        const StageResult ok = speedStageFromSample(true, 1048576, 800, true, QString());
        CHECK(ok.id == "speed" && ok.status == Ok, "speed sample: 1 MiB in 0.8 s -> ok");
        CHECK(qAbs(ok.data.value("down_mbit").toDouble() - 10.48576) < 0.001, "speed sample: Mbit/s = bytes*8/ms/1000");
        CHECK(ok.data.value("method").toString() == "probe", "speed sample: the method is in the report");
        CHECK(speedCardFact(ok.data.value("down_mbit").toDouble(), ok.status).word == "comfortable", "speed sample: card comfortable");
        const StageResult slow = speedStageFromSample(true, 262144, 1500, true, QString());
        CHECK(slow.status == Warn, "speed sample: 1.4 Mbit/s -> warn");
        const StageResult bad = speedStageFromSample(true, 1048576, 800, /*digestOk=*/false, QString());
        CHECK(bad.status == Warn && bad.data.value("error").toString() == "digest", "speed sample: a failed digest is not a speed");
        CHECK(speedStageFromSample(false, 0, -1, false, "no_tunnel").data.value("skipped").toString() == "no_connection",
              "speed sample: no tunnel -> skipped, no connection");
        for (const char *e : {"busy", "no_base", "no_token", "budget"}) {
            const StageResult r = speedStageFromSample(false, 0, -1, false, e);
            CHECK(r.status == Skip && r.data.value("skipped").toString() == e, "speed sample: a refusal -> skipped with its code");
        }
        const StageResult tr = speedStageFromSample(false, 0, -1, false, "transport");
        CHECK(tr.status == Warn && tr.data.value("error").toString() == "transport", "speed sample: no 200 -> warn");
        CHECK(speedStageFromSample(false, 0, -1, false, "weird").data.value("skipped").toString() == "other",
              "speed sample: an unknown error code -> skipped other");
        // Every sample result is a stage the server accepts.
        QList<StageResult> st;
        st << networkStage(0, "wifi", QString(), -1, -1, -1);
        for (const StageResult &r : {ok, slow, bad, tr, speedStageFromSample(false, 0, -1, false, "budget")}) {
            QList<StageResult> one = st;
            one << r;
            CHECK(checkReportValid(buildCheckReport(one, {}, {})), "speed sample: the stage passes schema 5");
        }
    }

    if (g_fail) { std::printf(">>> ПРОВАЛОВ: %d\n", g_fail); return 1; }
    std::printf(">>> doctor_report_check: все проверки зелёные\n");
    return 0;
}
