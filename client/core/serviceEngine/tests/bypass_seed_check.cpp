// AVPN: проверка стампа сева АнтиВПН (BypassSeedStamp.h — чистая inline-функция).
// Корень тормозов коннекта (девайс-баг 2026-07-10, билд 74): applyRuBypassSplit на КАЖДОМ
// guardedStart/реконнекте заново строил QMap на ~10801 CIDR + carve + писал всё в QSettings/plist,
// хотя входы сева между реконнектами не менялись. Стамп канонизирует входы: совпал с прошлым
// севом → содержимое sites идентично → сев пропускается целиком.
#include "../BypassSeedStamp.h"

#include <QStringList>

#include <cstdio>

static int failures = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            std::printf("ok   - %s\n", msg);                                                       \
        } else {                                                                                   \
            std::printf("FAIL - %s\n", msg);                                                       \
            ++failures;                                                                            \
        }                                                                                          \
    } while (0)

int main()
{
    using avpn::bypassSeedStamp;

    const QStringList carve = {QStringLiteral("159.194.214.36"), QStringLiteral("1.2.3.4")};

    // Идемпотентность: одинаковые входы → одинаковый стамп (это и позволяет пропустить сев).
    CHECK(bypassSeedStamp(true, true, true, 5, carve) == bypassSeedStamp(true, true, true, 5, carve),
          "одинаковые входы -> одинаковый стамп");

    // Любое изменение входа обязано менять стамп (иначе пропустим сев при изменившемся списке).
    CHECK(bypassSeedStamp(false, true, true, 5, carve) != bypassSeedStamp(true, true, true, 5, carve),
          "masterOn меняет стамп");
    CHECK(bypassSeedStamp(true, false, true, 5, carve) != bypassSeedStamp(true, true, true, 5, carve),
          "liAutoOn меняет стамп");
    CHECK(bypassSeedStamp(true, true, false, 5, carve) != bypassSeedStamp(true, true, true, 5, carve),
          "валидность снапшота меняет стамп (remote vs compiled)");
    CHECK(bypassSeedStamp(true, true, true, 6, carve) != bypassSeedStamp(true, true, true, 5, carve),
          "version снапшота меняет стамп");
    CHECK(bypassSeedStamp(true, true, true, 5, {QStringLiteral("159.194.214.36")})
              != bypassSeedStamp(true, true, true, 5, carve),
          "набор carve-IP меняет стамп");

    // Невалидный снапшот = compiled-фолбэк: version не участвует (иначе мусорный version
    // невалидного снапшота заставлял бы пересевать одинаковый вкомпиленный список).
    CHECK(bypassSeedStamp(true, true, false, 0, carve) == bypassSeedStamp(true, true, false, 7, carve),
          "invalid снапшот: version игнорируется");

    // Порядок carve-IP не важен (m_apiHostIps наполняется async-резолвом в недетерминированном
    // порядке — содержимое сева от порядка не зависит).
    const QStringList carveRev = {QStringLiteral("1.2.3.4"), QStringLiteral("159.194.214.36")};
    CHECK(bypassSeedStamp(true, true, true, 5, carve) == bypassSeedStamp(true, true, true, 5, carveRev),
          "порядок carve-IP не меняет стамп");

    if (failures) {
        std::printf(">>> bypass_seed_check: %d FAILURE(S)\n", failures);
        return 1;
    }
    std::printf(">>> bypass_seed_check: все проверки прошли\n");
    return 0;
}
