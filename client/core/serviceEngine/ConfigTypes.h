// client/core/serviceEngine/ConfigTypes.h
// AVPN: типы + форвард-совместимый парсер серверного /v1/config.
#pragma once
#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVector>

namespace avpn {

struct ProbeTarget
{
    QString target;
    QString kind = QStringLiteral("tcp");
    QString host;
    int     port = 443;
    int     intervalS = 60;
};

struct RemoteConfig
{
    QMap<QString, QString> minAppVersion;
    QMap<QString, QString> recommendedVersion;
    QVector<ProbeTarget>   probeTargets;
    int                    subscriptionRefreshIntervalS = 43200;
    QStringList            edges;
    QMap<QString, bool>    features;
    QMap<QString, QString> urls;
    QMap<QString, double>  numbers;
    QMap<QString, QStringList> lists;
    bool                   valid = false;
};

inline QMap<QString, QString> parseStrMap(const QJsonObject &o)
{
    QMap<QString, QString> m;
    for (auto it = o.begin(); it != o.end(); ++it)
        if (it.value().isString())
            m.insert(it.key(), it.value().toString());
    return m;
}

inline bool parseConfig(const QByteArray &body, RemoteConfig &out, QString &err)
{
    // Идемпотентность: сбрасываем out ПЕРЕД парсингом, чтобы переиспользуемый
    // struct не аккумулировал edges/probe_targets и не хранил стейл-флаги.
    // Битый JSON тоже оставляет out чистым (не полу-валидным).
    out = RemoteConfig();
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        err = pe.errorString();
        if (err.isEmpty())
            err = QStringLiteral("not a JSON object");
        return false;
    }
    const QJsonObject o = doc.object();
    out.minAppVersion = parseStrMap(o.value(QStringLiteral("min_app_version")).toObject());
    out.recommendedVersion = parseStrMap(o.value(QStringLiteral("recommended_version")).toObject());
    out.urls = parseStrMap(o.value(QStringLiteral("urls")).toObject());
    if (o.contains(QStringLiteral("subscription_refresh_interval_s")))
        out.subscriptionRefreshIntervalS =
            o.value(QStringLiteral("subscription_refresh_interval_s")).toInt(43200);
    const QJsonArray edges = o.value(QStringLiteral("edges")).toArray();
    for (const QJsonValue &v : edges)
        if (v.isString())
            out.edges << v.toString();
    const QJsonObject feats = o.value(QStringLiteral("features")).toObject();
    for (auto it = feats.begin(); it != feats.end(); ++it)
        if (it.value().isBool())
            out.features.insert(it.key(), it.value().toBool());
    const QJsonObject nums = o.value(QStringLiteral("numbers")).toObject();
    for (auto it = nums.begin(); it != nums.end(); ++it)
        if (it.value().isDouble())
            out.numbers.insert(it.key(), it.value().toDouble());
    const QJsonObject lsts = o.value(QStringLiteral("lists")).toObject();
    for (auto it = lsts.begin(); it != lsts.end(); ++it) {
        QStringList vals;
        for (const QJsonValue &v : it.value().toArray())
            if (v.isString())
                vals << v.toString();
        if (!vals.isEmpty())
            out.lists.insert(it.key(), vals);
    }
    const QJsonArray pts = o.value(QStringLiteral("probe_targets")).toArray();
    for (const QJsonValue &v : pts) {
        const QJsonObject p = v.toObject();
        ProbeTarget t;
        t.target = p.value(QStringLiteral("target")).toString();
        t.kind = p.value(QStringLiteral("kind")).toString(QStringLiteral("tcp"));
        t.host = p.value(QStringLiteral("host")).toString();
        t.port = p.value(QStringLiteral("port")).toInt(443);
        t.intervalS = p.value(QStringLiteral("interval_s")).toInt(60);
        if (!t.target.isEmpty() && !t.host.isEmpty())
            out.probeTargets << t;
    }
    out.valid = true;
    return true;
}

inline bool featureFlag(const RemoteConfig &c, const QString &key, bool def)
{
    return c.features.contains(key) ? c.features.value(key) : def;
}

inline double numberOr(const RemoteConfig &c, const QString &key, double def)
{
    return c.numbers.contains(key) ? c.numbers.value(key) : def;
}

} // namespace avpn
