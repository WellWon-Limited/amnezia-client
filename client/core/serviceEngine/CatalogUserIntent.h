// Tribe catalog v2 — versioned, non-secret user preference only.
//
// This intentionally does not share the encrypted CatalogRuntimeState. Requested transport and a
// pinned signed-catalog location are presentation intent, not runtime authority. In particular,
// no active profile/transport/session fact is ever written here or restored after relaunch.
#pragma once

#include "dto/Catalog.h"

#include <QMetaType>
#include <QRegularExpression>
#include <QSettings>
#include <QSet>

#include <algorithm>

namespace avpn {

struct CatalogUserIntent {
    ConnectionMode mode = ConnectionMode::Auto;
    QString pinnedLocationId; // empty = automatic location
};

inline QString catalogUserIntentModeName(ConnectionMode mode)
{
    switch (mode) {
    case ConnectionMode::Auto: return QStringLiteral("auto");
    case ConnectionMode::ForceAwg: return QStringLiteral("awg");
    case ConnectionMode::ForceXray: return QStringLiteral("xray");
    }
    return {};
}

inline bool parseCatalogUserIntentMode(const QString &value, ConnectionMode &mode)
{
    if (value == QLatin1String("auto")) mode = ConnectionMode::Auto;
    else if (value == QLatin1String("awg")) mode = ConnectionMode::ForceAwg;
    else if (value == QLatin1String("xray")) mode = ConnectionMode::ForceXray;
    else return false;
    return true;
}

inline bool canonicalCatalogUserIntentLocationId(const QString &value)
{
    // Exact catalog-v2 location-id grammar. The pin is additionally checked for membership in
    // every newly accepted signed catalog before it may influence selection.
    static const QRegularExpression pattern(
        QStringLiteral("^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"));
    return value != QLatin1String("auto") && pattern.match(value).hasMatch();
}

inline bool catalogContainsPinnedLocation(const Catalog &catalog,
                                          const QString &pinnedLocationId)
{
    if (pinnedLocationId.isEmpty()) return true;
    return std::any_of(catalog.locations.cbegin(), catalog.locations.cend(),
                       [&](const CatalogLocation &location) {
                           return location.id == pinnedLocationId;
                       });
}

inline bool catalogUserIntentSchemaValue(const QVariant &value)
{
    const int type = value.metaType().id();
    if (type != QMetaType::Int && type != QMetaType::UInt
        && type != QMetaType::LongLong && type != QMetaType::ULongLong)
        return false;
    bool ok = false;
    const qlonglong schema = value.toLongLong(&ok);
    return ok && schema == 1;
}

inline bool persistCatalogUserIntent(QSettings *settings, const CatalogUserIntent &intent,
                                     QString &error)
{
    error.clear();
    if (!settings) return true; // deterministic non-product harnesses may run without prefs
    const QString mode = catalogUserIntentModeName(intent.mode);
    if (mode.isEmpty()
        || (!intent.pinnedLocationId.isEmpty()
            && !canonicalCatalogUserIntentLocationId(intent.pinnedLocationId))) {
        error = QStringLiteral("invalid_user_intent");
        return false;
    }

    settings->beginGroup(QStringLiteral("TribeCatalog/UserIntentV1"));
    settings->remove(QString()); // reject old/unknown fields by replacing the complete record
    settings->setValue(QStringLiteral("schema"), 1);
    settings->setValue(QStringLiteral("requested_transport"), mode);
    settings->setValue(QStringLiteral("pinned_location_id"), intent.pinnedLocationId);
    settings->endGroup();
    settings->sync();
    if (settings->status() != QSettings::NoError) {
        error = QStringLiteral("user_intent_preferences_unavailable");
        return false;
    }
    return true;
}

inline CatalogUserIntent loadCatalogUserIntent(QSettings *settings,
                                                bool *sanitized = nullptr)
{
    if (sanitized) *sanitized = false;
    CatalogUserIntent result;
    if (!settings) return result;

    settings->beginGroup(QStringLiteral("TribeCatalog/UserIntentV1"));
    const QStringList keys = settings->childKeys();
    const QStringList childGroups = settings->childGroups();
    if (keys.isEmpty() && childGroups.isEmpty()) {
        settings->endGroup();
        return result;
    }
    const QSet<QString> actualKeys(keys.cbegin(), keys.cend());
    const QSet<QString> expectedKeys{
        QStringLiteral("schema"), QStringLiteral("requested_transport"),
        QStringLiteral("pinned_location_id")};
    const QVariant schema = settings->value(QStringLiteral("schema"));
    const QVariant modeValue = settings->value(QStringLiteral("requested_transport"));
    const QVariant pinValue = settings->value(QStringLiteral("pinned_location_id"));
    settings->endGroup();

    ConnectionMode parsedMode = ConnectionMode::Auto;
    const bool valid = childGroups.isEmpty() && actualKeys == expectedKeys
        && catalogUserIntentSchemaValue(schema)
        && modeValue.metaType().id() == QMetaType::QString
        && pinValue.metaType().id() == QMetaType::QString
        && parseCatalogUserIntentMode(modeValue.toString(), parsedMode)
        && (pinValue.toString().isEmpty()
            || canonicalCatalogUserIntentLocationId(pinValue.toString()));
    if (valid) {
        result.mode = parsedMode;
        result.pinnedLocationId = pinValue.toString();
        return result;
    }

    // Corrupt, future-schema, or partially written preferences never become connection facts.
    // Reset to the conservative product defaults and best-effort canonicalize the local record.
    if (sanitized) *sanitized = true;
    QString ignored;
    persistCatalogUserIntent(settings, result, ignored);
    return result;
}

} // namespace avpn
