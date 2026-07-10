// Автономная проверка LegalDocs (in-app Legal: Privacy/Terms с сайта).
// Сборка/запуск: tests/build_legal_docs.sh (только QtCore).
#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <cstdio>
#include <cstdlib>

#include "../LegalDocs.h"

static int g_fail = 0;
#define CHECK(cond) do { \
    if (!(cond)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } \
} while (0)

int main()
{
    // валидация имён — только известные документы/языки (идут в URL и имя файла кэша)
    CHECK(LegalDocs::isValidDoc(QStringLiteral("privacy")));
    CHECK(LegalDocs::isValidDoc(QStringLiteral("terms")));
    CHECK(!LegalDocs::isValidDoc(QStringLiteral("x")));
    CHECK(!LegalDocs::isValidDoc(QStringLiteral("../etc/passwd")));
    CHECK(LegalDocs::isValidLang(QStringLiteral("ru")));
    CHECK(LegalDocs::isValidLang(QStringLiteral("en")));
    CHECK(LegalDocs::isValidLang(QStringLiteral("es"))); // es live с волны i18n сайта 2026-07-07
    CHECK(!LegalDocs::isValidLang(QStringLiteral("")));
    CHECK(!LegalDocs::isValidLang(QStringLiteral("de")));

    // нормализация локали приложения → язык документа
    CHECK(LegalDocs::normalizeLang(QStringLiteral("ru")) == QStringLiteral("ru"));
    CHECK(LegalDocs::normalizeLang(QStringLiteral("ru_RU")) == QStringLiteral("ru"));
    CHECK(LegalDocs::normalizeLang(QStringLiteral("es")) == QStringLiteral("es"));
    CHECK(LegalDocs::normalizeLang(QStringLiteral("es_MX")) == QStringLiteral("es"));
    CHECK(LegalDocs::normalizeLang(QStringLiteral("de")) == QStringLiteral("en"));
    CHECK(LegalDocs::normalizeLang(QStringLiteral("")) == QStringLiteral("en"));

    // URL документа
    CHECK(LegalDocs::url(QStringLiteral("privacy"), QStringLiteral("ru"))
          == QStringLiteral("https://tribevpn.com/legal/privacy.ru.md"));
    CHECK(LegalDocs::url(QStringLiteral("terms"), QStringLiteral("en"))
          == QStringLiteral("https://tribevpn.com/legal/terms.en.md"));
    // URL документа с кастомной базой (server-driven из config)
    CHECK(LegalDocs::url(QStringLiteral("privacy"), QStringLiteral("ru"),
                         QStringLiteral("https://cdn.example/legal"))
          == QStringLiteral("https://cdn.example/legal/privacy.ru.md"));

    // валидация ответа: markdown, а не HTML/JSON/пусто/гигантский блоб
    CHECK(LegalDocs::looksLikeMarkdown(QByteArrayLiteral("# Privacy Policy\n\ntext")));
    CHECK(LegalDocs::looksLikeMarkdown(QByteArrayLiteral("  \n# Título\n")));
    CHECK(!LegalDocs::looksLikeMarkdown(QByteArray()));
    CHECK(!LegalDocs::looksLikeMarkdown(QByteArrayLiteral("   \n  ")));
    CHECK(!LegalDocs::looksLikeMarkdown(QByteArrayLiteral("<!DOCTYPE html><html>…"))); // captive portal
    CHECK(!LegalDocs::looksLikeMarkdown(QByteArrayLiteral("{\"error\":404}")));
    CHECK(!LegalDocs::looksLikeMarkdown(QByteArray(3 * 1024 * 1024, 'a')));

    // имя файла кэша детерминировано и без путей-инъекций
    CHECK(LegalDocs::cacheFileName(QStringLiteral("privacy"), QStringLiteral("ru"))
          == QStringLiteral("privacy.ru.md"));

    if (g_fail) { std::printf(">>> legal_docs_check: %d FAILED\n", g_fail); return 1; }
    std::printf(">>> legal_docs_check: OK\n");
    return 0;
}
