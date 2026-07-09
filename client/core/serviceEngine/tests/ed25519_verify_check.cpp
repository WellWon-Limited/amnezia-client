// client/core/serviceEngine/tests/ed25519_verify_check.cpp
// AVPN: проверка ed25519-верификации детачед-подписи.
#include "../Ed25519Verify.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // Вставлены фактические значения из команды генерации вектора (dev-ключ, sha256("tribe-dev-config-signing-seed")):
    const QString pub  = QStringLiteral("95da1bd9062653d9c185c3ca5cae995516a8e353abccd3cf98cd12cd2f3a075a");
    const QByteArray sig = QByteArrayLiteral("J5JboOJzdO/TSkQuIfR1WAkCjcoQc09+1t52z8JXOEErf5dl21VAsu1IQkwqaDyUpoolbjbItzJBjGQIWTT9AQ==");
    const QByteArray body = QByteArrayLiteral("hello-tribe");

    CHECK(avpn::verifyDetached(pub, body, sig), "valid signature verifies");
    CHECK(!avpn::verifyDetached(pub, QByteArrayLiteral("hello-tribX"), sig), "tampered body fails");
    CHECK(!avpn::verifyDetached(pub, body, QByteArrayLiteral("AAAA")), "garbage sig fails");
    CHECK(!avpn::verifyDetached(QString(), body, sig), "empty key fails");
    QString wrong = pub; wrong[0] = (wrong[0] == QLatin1Char('a')) ? QLatin1Char('b') : QLatin1Char('a');
    CHECK(!avpn::verifyDetached(wrong, body, sig), "wrong key fails");

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
