// AVPN serviceEngine — автономная проверка хелперов web-link (кнопка «Управлять подпиской»).
// Сборка/запуск: core/serviceEngine/tests/build_web_link.sh
//
// Флоу: POST /v1/cabinet/web-link (Bearer) → { url: "https://tribevpn.com/account?wl=…", expires_in }.
// К url приложение дописывает device_uuid=<localDeviceId()> и открывает во внешнем браузере.
// Тестируем ДВЕ чистые функции (без сети):
//   Enrollment::parseWebLinkResponse(json, out, error) -> bool
//   Enrollment::appendDeviceUuid(url, uuid) -> QString

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

    // --- parseWebLinkResponse: контракт 200 { url, expires_in } ---
    {
        WebLinkResponse out;
        QString err;
        const QByteArray body =
            "{\"url\":\"https://tribevpn.com/account?wl=abc123\",\"expires_in\":90}";
        CHECK(Enrollment::parseWebLinkResponse(body, out, err));
        CHECK(out.url == QStringLiteral("https://tribevpn.com/account?wl=abc123"));
        CHECK(out.expiresIn == 90);
        CHECK(err.isEmpty());
    }
    // url отсутствует → провал с ошибкой (кнопка уйдёт на fallback).
    {
        WebLinkResponse out;
        QString err;
        CHECK(!Enrollment::parseWebLinkResponse("{\"expires_in\":90}", out, err));
        CHECK(!err.isEmpty());
    }
    // Пустой url → тоже провал (нечего открывать).
    {
        WebLinkResponse out;
        QString err;
        CHECK(!Enrollment::parseWebLinkResponse("{\"url\":\"\",\"expires_in\":90}", out, err));
    }
    // Битый JSON / не-объект → провал, не краш.
    {
        WebLinkResponse out;
        QString err;
        CHECK(!Enrollment::parseWebLinkResponse("not json", out, err));
        CHECK(!Enrollment::parseWebLinkResponse("[1,2]", out, err));
    }

    // --- appendDeviceUuid: дописать device_uuid к URL кабинета ---
    // URL от бэка уже несёт ?wl=… → дописываем через &.
    CHECK(Enrollment::appendDeviceUuid(QStringLiteral("https://tribevpn.com/account?wl=abc"),
                                       QStringLiteral("2056f908-f9f4-4edb-95d1-e8ec87660268"))
          == QStringLiteral(
              "https://tribevpn.com/account?wl=abc&device_uuid=2056f908-f9f4-4edb-95d1-e8ec87660268"));
    // Fallback-URL без query → через ?.
    CHECK(Enrollment::appendDeviceUuid(QStringLiteral("https://tribevpn.com/account"),
                                       QStringLiteral("2056f908-f9f4-4edb-95d1-e8ec87660268"))
          == QStringLiteral(
              "https://tribevpn.com/account?device_uuid=2056f908-f9f4-4edb-95d1-e8ec87660268"));
    // Пустой uuid → URL не трогаем.
    CHECK(Enrollment::appendDeviceUuid(QStringLiteral("https://tribevpn.com/account?wl=abc"),
                                       QString())
          == QStringLiteral("https://tribevpn.com/account?wl=abc"));
    // Неожиданные символы в uuid перекодируются (устойчивость к мусору в сторе).
    CHECK(Enrollment::appendDeviceUuid(QStringLiteral("https://tribevpn.com/account"),
                                       QStringLiteral("a b&c"))
          == QStringLiteral("https://tribevpn.com/account?device_uuid=a%20b%26c"));

    if (g_failed == 0) {
        printf(">>> web_link_check: OK (%d checks)\n", g_total);
        return 0;
    }
    fprintf(stderr, ">>> web_link_check: %d/%d FAILED\n", g_failed, g_total);
    return 1;
}
