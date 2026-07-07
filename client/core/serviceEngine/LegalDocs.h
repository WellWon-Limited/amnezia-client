#pragma once
// LegalDocs — in-app юр-документы (Privacy/Terms) с сайта tribevpn.com.
// Чистые функции: URL/кэш/валидация ответа. Сетевая часть — в AvpnEngineQml
// (legalDocCached/legalDocFetch/legalDocReady), UI — Tribe/Pages/PageLegalTribe.qml.
// Контент генерится в репо tribe-backend: scripts/build_legal_md.py →
// site_tribe/legal/<doc>.<lang>.md (см. спеку tribe-front
// docs/superpowers/specs/2026-07-07-in-app-legal-pages-design.md).
// Проверка: tests/build_legal_docs.sh (автономно, только QtCore).

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace LegalDocs {

// Известные документы/языки. Значения идут в URL и имя файла кэша —
// всё прочее отбрасываем (никаких путей/инъекций из QML).
inline bool isValidDoc(const QString &doc)
{
    return doc == QLatin1String("privacy") || doc == QLatin1String("terms");
}

inline bool isValidLang(const QString &lang)
{
    // ru/en/es — языки правового центра сайта (es live с волны i18n 2026-07-07, PR #218 бэка)
    return lang == QLatin1String("ru") || lang == QLatin1String("en")
           || lang == QLatin1String("es");
}

// Локаль приложения ("ru", "ru_RU", "es", …) → язык документа.
inline QString normalizeLang(const QString &appLang)
{
    const QString two = appLang.left(2).toLower();
    return isValidLang(two) ? two : QStringLiteral("en");
}

inline QString url(const QString &doc, const QString &lang)
{
    return QStringLiteral("https://tribevpn.com/legal/%1.%2.md").arg(doc, lang);
}

inline QString cacheFileName(const QString &doc, const QString &lang)
{
    return QStringLiteral("%1.%2.md").arg(doc, lang);
}

// Ответ похож на наш markdown: непустой, разумного размера и не HTML/JSON
// (captive portal / страница ошибки CDN начинаются с '<' или '{').
inline bool looksLikeMarkdown(const QByteArray &body)
{
    if (body.isEmpty() || body.size() > 2 * 1024 * 1024)
        return false;
    const QByteArray t = body.trimmed();
    if (t.isEmpty())
        return false;
    const char c = t.at(0);
    return c != '<' && c != '{';
}

} // namespace LegalDocs
