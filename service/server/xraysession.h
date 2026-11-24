#ifndef AVPN_XRAYSESSION_H
#define AVPN_XRAYSESSION_H

// AVPN (macOS own-Xray no-data, owner's Mac 23.11): the service's Xray core session rule and the
// diagnostics of a core session. Pure (QtCore only), covered by service/server/tests/xray_session_check.cpp
// (build_xray_session.sh); where it is called from - client/core/serviceEngine/tests/check_mac_xray_session_wiring.sh.
//
// The bindings keep ONE process-wide core instance (amnezia-xray-bindings main.go: `server`):
// amnezia_xray_configure overwrites it without closing the previous one, amnezia_xray_stop closes it
// and never clears it. So a second stop closes the same, already closed instance again and the core
// answers "app/proxyman/inbound: failed to close all resources" (every tcpWorker/udpWorker hub is
// closed a second time) - the line the owner's service log shows 70 ms after a stop that succeeded,
// because XrayProtocol stops twice (the failover stop, then ~XrayProtocol). And a start that comes
// while an instance is still open (no stop in between) would leave that instance running beside the
// new one. Upstream Amnezia (origin/dev service/server/xray.cpp, Xray::start/stopAny) holds the same
// rule with owner tokens: a start stops a running engine first, a stop of no running engine is a no-op.

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

namespace avpn {

// Whether a core instance exists that has not been closed yet.
struct XrayCoreSession
{
    enum class StartStep { Fresh, CloseOpenFirst };
    enum class StopStep { Close, NothingOpen };

    bool open = false;

    // A start runs only on a closed core: an instance still open is closed first (its inbound,
    // its outbound connections and the service's uplink routes go with it).
    StartStep beforeStart() const { return open ? StartStep::CloseOpenFirst : StartStep::Fresh; }
    // A stop closes the instance once; a stop with nothing open does not touch the core.
    StopStep beforeStop() const { return open ? StopStep::Close : StopStep::NothingOpen; }

    // amnezia_xray_configure created an instance (it holds features from now on, even if start fails).
    void onConfigured() { open = true; }
    // amnezia_xray_stop ran on it - whatever it returned, that instance is not closed a second time.
    void onClosed() { open = false; }
};

// ---- Diagnostics behind the service log switch (IpcServer::setLogsEnabled) ----------------------------

// Rank of an Xray log level, quietest first ("none" < "error" < "warning" < "info" < "debug").
inline int xrayLogLevelRank(const QString &level)
{
    const QString l = level.trimmed().toLower();
    if (l == QLatin1String("debug"))
        return 4;
    if (l == QLatin1String("info"))
        return 3;
    if (l == QLatin1String("warning"))
        return 2;
    if (l == QLatin1String("error"))
        return 1;
    return 0; // "none", empty, unknown
}

struct XrayDiagConfig
{
    QString config;      // the config the core gets
    QString level;       // its log.loglevel
    bool raised = false; // we raised it to "info" (then the info lines are filtered, xrayKeepCoreLine)
};

// With diagnostics on, a core config quieter than "info" gets log.loglevel "info": the core reports a
// failed dial of its outbound ("failed to process outbound traffic > ... failed to find an available
// destination > dial tcp ...: <socket error>") and its DNS failures only at Info. Other log keys
// (access, dnsLog) stay. Diagnostics off, or a config that is not a JSON object: unchanged.
inline XrayDiagConfig xrayDiagConfig(const QString &config, bool diagnostics)
{
    XrayDiagConfig out;
    out.config = config;
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(config.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return out;
    QJsonObject root = doc.object();
    QJsonObject log = root.value(QStringLiteral("log")).toObject();
    out.level = log.value(QStringLiteral("loglevel")).toString();
    if (!diagnostics || xrayLogLevelRank(out.level) >= xrayLogLevelRank(QStringLiteral("info")))
        return out;
    log.insert(QStringLiteral("loglevel"), QStringLiteral("info"));
    root.insert(QStringLiteral("log"), log);
    out.config = QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
    out.level = QStringLiteral("info");
    out.raised = true;
    return out;
}

// A core log line goes to the service log unless it is an [Info] line we asked for only to see
// failures: those pass only when they report one. Access lines ("from ... accepted ...") and
// [Warning]/[Error] lines always pass; nothing is filtered when the level was not raised.
inline bool xrayKeepCoreLine(const QString &line, bool levelRaised)
{
    if (!levelRaised || !line.startsWith(QLatin1String("[Info]")))
        return true;
    static const QRegularExpression failure(
        QStringLiteral("fail|error|timeout|timed out|refused|unreachable|no route|reset|denied|not permitted|rejected|closed"),
        QRegularExpression::CaseInsensitiveOption);
    return failure.match(line).hasMatch();
}

// One line about the config the core gets: no address, no credential. address = ip|domain|none says
// whether the core must resolve its server itself (a domain is resolved through the system resolver,
// which the session points into the tunnel - through the core itself).
inline QString xrayConfigSummary(const QString &config, const QString &level)
{
    const QJsonObject root = QJsonDocument::fromJson(config.toUtf8()).object();
    QStringList outbounds;
    QString addressKind = QStringLiteral("none");
    static const QRegularExpression ipv4(QStringLiteral(R"(^\d{1,3}(\.\d{1,3}){3}$)"));
    for (const QJsonValue &v : root.value(QStringLiteral("outbounds")).toArray()) {
        const QJsonObject ob = v.toObject();
        const QJsonObject stream = ob.value(QStringLiteral("streamSettings")).toObject();
        QString item = ob.value(QStringLiteral("protocol")).toString();
        const QString network = stream.value(QStringLiteral("network")).toString();
        const QString security = stream.value(QStringLiteral("security")).toString();
        if (!network.isEmpty() || !security.isEmpty())
            item += QLatin1Char('/') + network + QLatin1Char('/') + security;
        outbounds.append(item);
        if (addressKind != QLatin1String("none"))
            continue;
        const QJsonObject settings = ob.value(QStringLiteral("settings")).toObject();
        QString address = settings.value(QStringLiteral("address")).toString();
        for (const char *list : { "vnext", "servers" }) {
            if (address.isEmpty())
                address = settings.value(QLatin1String(list)).toArray().at(0).toObject().value(QStringLiteral("address")).toString();
        }
        if (!address.isEmpty())
            addressKind = (ipv4.match(address).hasMatch() || address.contains(QLatin1Char(':'))) ? QStringLiteral("ip")
                                                                                             : QStringLiteral("domain");
    }
    return QStringLiteral("outbounds=%1 address=%2 inbounds=%3 dns_section=%4 loglevel=%5")
        .arg(outbounds.join(QLatin1Char(',')), addressKind)
        .arg(root.value(QStringLiteral("inbounds")).toArray().size())
        .arg(root.contains(QStringLiteral("dns")) ? QStringLiteral("yes") : QStringLiteral("no"),
             level.isEmpty() ? QStringLiteral("default") : level);
}

} // namespace avpn

#endif // AVPN_XRAYSESSION_H
