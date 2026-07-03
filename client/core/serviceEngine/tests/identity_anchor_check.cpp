// AVPN serviceEngine — автономная проверка чистой логики Keychain-якоря идентичности.
// Сборка/запуск: core/serviceEngine/tests/build_identity_anchor.sh
//
// Анти-фрод/анти-потеря: identity (installationUuid + WG-ключи + subscription_token) на iOS
// стирается при удалении приложения → переустановка = новый триал и ПОТЕРЯ оплаченных дней.
// Якорь = один блоб в Keychain (переживает uninstall). Тестируем чистые функции:
//   IdentityAnchor::decide(storeHas, anchorHas) -> Action (что делать на старте)
//   IdentityAnchor::packIdentity(...) / unpackIdentity(...) — сериализация блоба

#include "../IdentityAnchor.h"

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

    // --- decide: стор — истина; якорь — резервная копия ---
    // Стор полон (обычный запуск) → освежить якорь (токен мог ротироваться).
    CHECK(IdentityAnchor::decide(true, true) == IdentityAnchor::Action::SaveToAnchor);
    CHECK(IdentityAnchor::decide(true, false) == IdentityAnchor::Action::SaveToAnchor);
    // Стор пуст, якорь есть (переустановка!) → ВОССТАНОВИТЬ identity из якоря.
    CHECK(IdentityAnchor::decide(false, true) == IdentityAnchor::Action::RestoreFromAnchor);
    // Свежее устройство (ничего нигде) → ничего; якорь появится после enroll.
    CHECK(IdentityAnchor::decide(false, false) == IdentityAnchor::Action::None);

    // --- pack/unpack: round-trip ---
    {
        const QByteArray blob = IdentityAnchor::packIdentity(
            QStringLiteral("2056f908-f9f4-4edb-95d1-e8ec87660268"),
            QStringLiteral("privKeyBase64="), QStringLiteral("pubKeyBase64="),
            QStringLiteral("jwt.token.here"));
        QString uuid, priv, pub, token, err;
        CHECK(IdentityAnchor::unpackIdentity(blob, uuid, priv, pub, token, err));
        CHECK(uuid == QStringLiteral("2056f908-f9f4-4edb-95d1-e8ec87660268"));
        CHECK(priv == QStringLiteral("privKeyBase64="));
        CHECK(pub == QStringLiteral("pubKeyBase64="));
        CHECK(token == QStringLiteral("jwt.token.here"));
        CHECK(err.isEmpty());
    }
    // Токен может быть пустым (enroll ещё не был) — валидно, восстановим хотя бы uuid+ключи.
    {
        const QByteArray blob = IdentityAnchor::packIdentity(
            QStringLiteral("u-1"), QStringLiteral("p1"), QStringLiteral("p2"), QString());
        QString uuid, priv, pub, token, err;
        CHECK(IdentityAnchor::unpackIdentity(blob, uuid, priv, pub, token, err));
        CHECK(token.isEmpty());
    }
    // Без uuid якорь бессмыслен → провал (не затираем стор мусором).
    {
        const QByteArray blob = IdentityAnchor::packIdentity(
            QString(), QStringLiteral("p1"), QStringLiteral("p2"), QStringLiteral("t"));
        QString uuid, priv, pub, token, err;
        CHECK(!IdentityAnchor::unpackIdentity(blob, uuid, priv, pub, token, err));
        CHECK(!err.isEmpty());
    }
    // Битый блоб (мусор из чужой версии/повреждение) → провал, не краш.
    {
        QString uuid, priv, pub, token, err;
        CHECK(!IdentityAnchor::unpackIdentity("not json", uuid, priv, pub, token, err));
        CHECK(!IdentityAnchor::unpackIdentity(QByteArray(), uuid, priv, pub, token, err));
    }

    if (g_failed == 0) {
        printf(">>> identity_anchor_check: OK (%d checks)\n", g_total);
        return 0;
    }
    fprintf(stderr, ">>> identity_anchor_check: %d/%d FAILED\n", g_failed, g_total);
    return 1;
}
