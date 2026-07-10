// client/core/serviceEngine/tests/test_bypass_lkg.cpp
// AVPN server-driven АнтиВПН: LKG-кеш bypass-списков (BypassListLkg.h) — сериализация/чтение
// файла кэша во временной директории, повторная верификация подписи (кеш недоверенный),
// анти-downgrade. Standalone, БЕЗ сети/QNetworkAccessManager — сервис (BypassListService)
// вынес эту логику в чистые функции именно ради такого юнита.
// Сборка/запуск: tests/build_bypass_lkg.sh (QtCore + libcrypto).
#include "../BypassListLkg.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

// Тестовый ed25519-ключ (сгенерирован ЛОКАЛЬНО для этого юнита openssl genpkey -algorithm
// ed25519 — НЕ прод/dev-ключ бэкенда, используется только здесь для round-trip подписи).
static const QString kTestPubHex =
    QStringLiteral("ae1a54085b87959fd82d3658dfe27b4e4401e3696790664485f2185ba86da40a");

// Ровно та же логика построения тела, что и в test_bypass_types.cpp::makeBody (Task 8):
// ru_cidrs = count валидных /24 в диапазоне 5.0.0.0/8 (вне never-bypass), чтобы пройти
// порог kMinValidRuCidrs и получить out.valid==true после parseBypassLists. Байты ДОЛЖНЫ
// совпадать 1:1 с теми, что подписывались офлайн openssl'ем (сигнатуры ниже — под них).
static QByteArray makeBody(int version, int ruCidrCount)
{
    QJsonArray ru;
    int made = 0;
    for (int a = 0; a < 26 && made < ruCidrCount; ++a) {
        for (int b = 0; b < 250 && made < ruCidrCount; ++b) {
            ru << QStringLiteral("5.%1.%2.0/24").arg(a).arg(b);
            ++made;
        }
    }
    QJsonObject o;
    o[QStringLiteral("version")] = version;
    o[QStringLiteral("ru_cidrs")] = ru;
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    const QByteArray bodyV42 = makeBody(42, 6005);
    const QByteArray bodyV43 = makeBody(43, 6005);
    // Подписи посчитаны офлайн (openssl pkeyutl -sign -rawin) над ИМЕННО этими байтами
    // (см. makeBody выше) приватным ключом, парный kTestPubHex.
    const QByteArray sigV42 = QByteArrayLiteral(
        "sDySJ3EWqiuDsJc2y7nzU8en5UtQWqs7ZLicZURcdwG+HGiJIAorgajn0d6hheQ5G7gZEOBo5CF6QVajR8fNDg==");
    const QByteArray sigV43 = QByteArrayLiteral(
        "EgBxzzhxgIdBQw1qHfCyGlrBtLHzCqxn0ExcPWddXD+H4Mx/Vo/FwaNqkO/LoWwrmp9KePh9gXloqKlX+ZP5AA==");

    CHECK(!bodyV42.isEmpty() && bodyV42 != bodyV43, "sanity: bodies distinct/non-empty");

    // --- 1) Сериализация → диск (QTemporaryDir) → чтение → повторная верификация → parse.
    QTemporaryDir tmp;
    CHECK(tmp.isValid(), "tempdir created");
    const QString lkgPath = tmp.filePath(QStringLiteral("bypass_lists.lkg"));

    const QByteArray lkgJson = avpn::serializeBypassListsLkg(bodyV42, sigV42, QByteArrayLiteral("etag-v42"));
    {
        QFile f(lkgPath);
        CHECK(f.open(QIODevice::WriteOnly), "lkg file opens for write");
        f.write(lkgJson);
        f.close();
    }

    QByteArray onDisk;
    {
        QFile f(lkgPath);
        CHECK(f.open(QIODevice::ReadOnly), "lkg file opens for read");
        onDisk = f.readAll();
    }
    CHECK(onDisk == lkgJson, "roundtrip bytes identical after disk write/read");

    avpn::BypassLists out;
    QByteArray etagOut;
    QString err;
    const bool ok = avpn::loadVerifiedBypassListsLkg(onDisk, kTestPubHex, out, etagOut, err);
    CHECK(ok, "valid LKG (from disk) loads and verifies");
    CHECK(out.valid, "parsed BypassLists marked valid (>= kMinValidRuCidrs)");
    CHECK(out.version == 42, "version roundtrips (42)");
    CHECK(out.ruCidrs.size() == 6005, "ru_cidrs count roundtrips");
    CHECK(etagOut == QByteArrayLiteral("etag-v42"), "etag roundtrips");

    // --- 2) Повреждённая подпись в файле → LKG отвергнут (подпись не совпадает с телом).
    {
        const QByteArray badSigJson =
            avpn::serializeBypassListsLkg(bodyV42, sigV43 /* чужая подпись, не под bodyV42 */,
                                          QByteArrayLiteral("etag-v42"));
        avpn::BypassLists out2;
        QByteArray etag2;
        QString err2;
        CHECK(!avpn::loadVerifiedBypassListsLkg(badSigJson, kTestPubHex, out2, etag2, err2),
              "signature for different body is rejected");
        CHECK(!out2.valid, "rejected LKG leaves out invalid");
        CHECK(!err2.isEmpty(), "rejection sets err");
    }

    // --- 3) Битая base64-подпись (мусор) → отвергнут, не крэш.
    {
        const QByteArray garbageSigJson =
            avpn::serializeBypassListsLkg(bodyV42, QByteArrayLiteral("!!!not-base64!!!"),
                                          QByteArrayLiteral("etag-v42"));
        avpn::BypassLists out3;
        QByteArray etag3;
        QString err3;
        CHECK(!avpn::loadVerifiedBypassListsLkg(garbageSigJson, kTestPubHex, out3, etag3, err3),
              "garbage base64 signature is rejected");
    }

    // --- 4) Битый/неполный JSON (нет body_b64) → отвергнут на этапе parseBypassListsLkgRaw.
    {
        QByteArray bOut, sOut, eOut;
        CHECK(!avpn::parseBypassListsLkgRaw(QByteArrayLiteral("{\"sig_b64\":\"x\"}"), bOut, sOut, eOut),
              "missing body_b64 rejected");
        CHECK(!avpn::parseBypassListsLkgRaw(QByteArrayLiteral("not json at all"), bOut, sOut, eOut),
              "non-json rejected");

        avpn::BypassLists out4;
        QByteArray etag4;
        QString err4;
        CHECK(!avpn::loadVerifiedBypassListsLkg(QByteArrayLiteral("{broken"), kTestPubHex, out4, etag4, err4),
              "loadVerifiedBypassListsLkg on broken json rejected");
        CHECK(!err4.isEmpty(), "broken json rejection sets err");
    }

    // --- 5) Анти-downgrade — чистая функция сравнения версий (строго ">", НЕ ">=").
    CHECK(avpn::isBypassListVersionNewer(43, 42), "43 > 42 => newer");
    CHECK(!avpn::isBypassListVersionNewer(42, 43), "42 > 43 => false (downgrade rejected)");
    CHECK(!avpn::isBypassListVersionNewer(42, 42), "42 > 42 => false (replay rejected, strict >)");
    CHECK(avpn::isBypassListVersionNewer(1, 0), "lkgVersion==0 (no LKG yet) => any positive version newer");

    // --- 6) Сквозной сценарий: текущий LKG = v43, «новый фетч» приносит подписанный v42
    // (валидный сам по себе, но СТАРЕЕ уже сохранённого) → сервис обязан отвергнуть его
    // именно по anti-downgrade, а не по verify/parse (те бы пропустили).
    {
        avpn::BypassLists lkgNow;
        QByteArray etagNow;
        QString errNow;
        const QByteArray lkgJsonV43 =
            avpn::serializeBypassListsLkg(bodyV43, sigV43, QByteArrayLiteral("etag-v43"));
        CHECK(avpn::loadVerifiedBypassListsLkg(lkgJsonV43, kTestPubHex, lkgNow, etagNow, errNow),
              "current LKG (v43) loads fine");
        CHECK(lkgNow.version == 43, "current LKG version is 43");

        avpn::BypassLists fetched;
        QByteArray fetchedErrEtag;
        QString fetchedErr;
        const QByteArray fetchedLkgWrap =
            avpn::serializeBypassListsLkg(bodyV42, sigV42, QByteArrayLiteral("etag-v42"));
        // Верификация/парсинг «нового фетча» сами по себе успешны (валиден и подписан верно) —
        // отбраковка приходит ИМЕННО из anti-downgrade сравнения версий сервисом.
        CHECK(avpn::loadVerifiedBypassListsLkg(fetchedLkgWrap, kTestPubHex, fetched, fetchedErrEtag, fetchedErr),
              "fetched v42 body verifies+parses on its own (valid signature+content)");
        CHECK(!avpn::isBypassListVersionNewer(fetched.version, lkgNow.version),
              "but v42 is NOT newer than current LKG v43 => service must discard it");
    }

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
