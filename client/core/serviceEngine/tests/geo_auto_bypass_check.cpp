// Проверка решающей логики гео-авто тумблера «АвтоVPN» (GeoAutoBypass.h).
// Сценарии — приёмочная таблица спеки 2026-07-04-geo-auto-bypass-toggle-design.md.
// Запуск: tests/build_geo_auto.sh
#include "../GeoAutoBypass.h"
#include <QtCore/QCoreApplication>
#include <cstdio>

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s\n", msg); ++fails; } \
    else { std::fprintf(stderr, "ok:   %s\n", msg); } \
} while (0)

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    using avpn::decideAutoBypass;

    // Ручной режим — вечный: гео не трогает тумблер ни в какую сторону
    CHECK(decideAutoBypass(true, true,  "DE", false) == -1, "userLock: не выключаем за границей");
    CHECK(decideAutoBypass(true, false, "RU", true)  == -1, "userLock: не включаем в РФ");

    // Неизвестность ничего не меняет
    CHECK(decideAutoBypass(false, true,  "", false) == -1, "проба молчит: держим ВКЛ");
    CHECK(decideAutoBypass(false, false, "", true)  == -1, "проба молчит: держим ВЫКЛ");

    // РФ: авто-ВКЛ по одному фактору (egress), но без лишних повторных «включить»
    CHECK(decideAutoBypass(false, false, "RU", false) == 1,  "РФ + выкл → включить");
    CHECK(decideAutoBypass(false, false, "ru", false) == 1,  "loc регистронезависим");
    CHECK(decideAutoBypass(false, true,  "RU", true)  == -1, "РФ + уже вкл → не трогать");

    // Не-РФ: выключение ДВУХФАКТОРНОЕ (egress≠RU И локальные сигналы не-RU)
    CHECK(decideAutoBypass(false, true,  "DE", false) == 0,  "за границей (оба фактора) → выключить");
    CHECK(decideAutoBypass(false, true,  "DE", true)  == -1, "egress≠RU, но таймзона RU (чужой VPN) → не трогать");
    CHECK(decideAutoBypass(false, false, "DE", false) == -1, "за границей + уже выкл → не трогать");

    // Смоук: локальные сигналы читаются без падения (значение зависит от машины)
    const bool lr = avpn::localSignalsRu();
    std::fprintf(stderr, "info: localSignalsRu()=%d (смоук)\n", lr ? 1 : 0);

    if (fails) { std::fprintf(stderr, ">>> ПРОВАЛОВ: %d\n", fails); return 1; }
    std::fprintf(stderr, ">>> все проверки geo_auto_bypass ок\n");
    return 0;
}
