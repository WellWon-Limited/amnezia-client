// AVPN serviceEngine — автономная проверка авто-хила авторизации (само-восстановление на 401).
// Сборка/запуск: core/serviceEngine/tests/build_auth_heal.sh
//
// Покрывает корень бага macOS «subscription unauthorized (token)»: стейл-токен в сторе → 401
// → клиент ДОЛЖЕН сбросить токен и переэнроллиться один раз, но не зацикливаться, если 401
// прилетел уже на свежевыданный токен или сеть/лимит (там токен не виноват — не трогаем).
//
// Тестируем ДВЕ чистые функции (без сети, только логика):
//   Enrollment::classifyFetch(httpCode, hadNetworkError) -> FetchOutcome
//   Enrollment::decideAuthRecovery(outcome, tokenFromStore, alreadyReEnrolled) -> AuthRecoveryAction

#include "../Enrollment.h"

#include <QCoreApplication>
#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                      \
        }                                                                                           \
    } while (0)

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // --- classifyFetch: HTTP-статус + сетевой флаг -> исход ---
    CHECK(Enrollment::classifyFetch(200, false) == FetchOutcome::Ok);
    CHECK(Enrollment::classifyFetch(204, false) == FetchOutcome::Ok);
    CHECK(Enrollment::classifyFetch(401, false) == FetchOutcome::Unauthorized);
    CHECK(Enrollment::classifyFetch(429, false) == FetchOutcome::RateLimited);
    CHECK(Enrollment::classifyFetch(500, false) == FetchOutcome::HttpError);
    CHECK(Enrollment::classifyFetch(404, false) == FetchOutcome::HttpError);
    // Сетевая ошибка (код 0 + netErr) приоритетнее любого псевдо-кода:
    CHECK(Enrollment::classifyFetch(0, true) == FetchOutcome::NetworkError);
    // 401 при наличии тела ответа = всё равно Unauthorized (код важнее netErr-флага, если код есть):
    CHECK(Enrollment::classifyFetch(401, true) == FetchOutcome::Unauthorized);

    // --- decideAuthRecovery: что делать по исходу ---
    // Успех — просто продолжаем.
    CHECK(Enrollment::decideAuthRecovery(FetchOutcome::Ok, /*fromStore*/ true, /*reEnrolled*/ false)
          == AuthRecoveryAction::Proceed);

    // 401 на токен ИЗ СТОРА, ещё не переэнролливались → сбросить токен и ре-энролл (это и есть фикс).
    CHECK(Enrollment::decideAuthRecovery(FetchOutcome::Unauthorized, true, false)
          == AuthRecoveryAction::ReEnrollThenRetry);

    // 401 на СВЕЖЕвыданный токен (не из стора) → не зацикливаемся, отдаём ошибку.
    CHECK(Enrollment::decideAuthRecovery(FetchOutcome::Unauthorized, false, false)
          == AuthRecoveryAction::Fail);

    // 401 после уже выполненного ре-энролла → стоп (один раз, без петли).
    CHECK(Enrollment::decideAuthRecovery(FetchOutcome::Unauthorized, true, true)
          == AuthRecoveryAction::Fail);

    // Сетевая ошибка / rate-limit → токен НЕ виноват, не сбрасываем, не ре-энроллим (важно для LKG).
    CHECK(Enrollment::decideAuthRecovery(FetchOutcome::NetworkError, true, false)
          == AuthRecoveryAction::Fail);
    CHECK(Enrollment::decideAuthRecovery(FetchOutcome::RateLimited, true, false)
          == AuthRecoveryAction::Fail);
    CHECK(Enrollment::decideAuthRecovery(FetchOutcome::HttpError, true, false)
          == AuthRecoveryAction::Fail);

    if (g_failed == 0) {
        printf(">>> auth_heal_check: OK (%d checks)\n", g_total);
        return 0;
    }
    fprintf(stderr, ">>> auth_heal_check: %d/%d FAILED\n", g_failed, g_total);
    return 1;
}
