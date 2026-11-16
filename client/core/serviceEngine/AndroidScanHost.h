// client/core/serviceEngine/AndroidScanHost.h
// AVPN serviceEngine - the Android probe host of the Scanner (IScanHost.h) over AndroidController's scan channel
// to :amneziaXrayService, whose Kotlin host (client/android/xray/src/main/kotlin/scan/) relays tribe-scan-v1 to the
// libxray tribe.3 engine. Plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md v2.2 §2.5, §2.11a; lane A3.
// [AndroidScanHost.cpp is Android-only; the inline helpers below are pure QtCore and carry the tests:
// client/core/serviceEngine/tests/build_android_scan_host.sh]
//
// Relay rules (IScanHost.h): request bytes to the service unchanged, reply bytes back unchanged, `reply` exactly
// once on the GUI thread and never from inside sendMessage, an empty reply = no answer (the per-action bound
// elapsed). Every asynchronous reply is bound to the request that asked for it by a request id: a late reply of
// a request whose bound elapsed is dropped, never given to another request. The host's own answer: {"error":
// "no_vpn"} while the service's probe host is not open (availability NeedsVpn: the engine lives in the Xray tunnel
// process - with an AmneziaWG tunnel or the VPN off there is none, decision A-7; this host never starts it). The
// service pushes {"open":bool,"gen":{...}} (ServiceEvent.SCAN_HOST_STATE) on every change and after STATUS:
// availability and generation() come from it (the element is known outside a scan).
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "IScanHost.h"
#include "ScanNetworkGeneration.h"
#include "ScanTypes.h"

#include <QByteArray>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QString>

#include <algorithm>
#include <functional>
#include <memory>

namespace avpn {

// What the Android host can do before the service answered scan_caps: the engine's Android platform (libxray
// 0013: 1 full, 4 legs, no AmneziaWG runner in this release - plan §2.5), lowered later by the service's memory
// headroom in its scan_caps. needsVpn: probes run inside the Xray tunnel process.
inline ScanHostCaps androidScanKnownCaps()
{
    ScanHostCaps c;
    c.maxFullConcurrent = 1;
    c.canVerifyComposite = false;
    c.maxLegConcurrent = 4;
    c.dnsPlan = true;
    c.maxAwgConcurrent = 0;
    c.reachStage = true;
    c.needsVpn = true;
    c.platform = QStringLiteral("android");
    return c;
}

// The bound of one relayed message by its action - the same table as the service side (ScanHostCore.replyBoundMs)
// and the iOS host: a scan_start may wait for a stop-all in progress and the engine's replacement of a running
// scan; scan_add waits for the same gate; the host-local scan_stop_all waits for the engine.
inline int androidScanReplyTimeoutMs(const QByteArray &request)
{
    const QString action = QJsonDocument::fromJson(request).object().value(QLatin1String("action")).toString();
    if (action == QLatin1String("scan_start"))
        return 6000;
    if (action == QLatin1String("scan_add"))
        return 3500;
    if (action == QLatin1String("scan_cancel") || action == QLatin1String("scan_stop_all"))
        return 3000;
    return 2000;
}

inline QByteArray androidScanNoVpnReply() { return QByteArrayLiteral("{\"error\":\"no_vpn\"}"); }

// The host-local stop of every scan (the service's ScanHostCore: engine stop-all under its gate); not a contract
// action, the engine never sees it.
inline QByteArray androidScanStopAllRequest() { return QByteArrayLiteral("{\"action\":\"scan_stop_all\"}"); }

// The service's state payload {"open":bool,"gen":{...}}; false when malformed. `hasGen` false when gen is absent or
// malformed.
inline bool androidScanStateDecode(const QByteArray &json, bool &open, bool &hasGen, ScanNetSource &gen)
{
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return false;
    const QJsonObject o = doc.object();
    if (!o.value(QLatin1String("open")).isBool())
        return false;
    open = o.value(QLatin1String("open")).toBool();
    ScanNetSource s;
    hasGen = scanNetSourceFromJson(o.value(QLatin1String("gen")), s);
    if (hasGen)
        gen = s;
    return true;
}

// The `gen` element of a scan_caps / scan_progress reply; false when absent, null or malformed. Read only: the reply
// bytes go to the coordinator unchanged.
inline bool androidScanReplyGen(const QByteArray &reply, ScanNetSource &out)
{
    const QJsonObject o = QJsonDocument::fromJson(reply).object();
    const QString type = o.value(QLatin1String("type")).toString();
    if (o.contains(QLatin1String("error"))
        || (type != QLatin1String("scan_caps") && type != QLatin1String("scan_progress")))
        return false;
    ScanNetSource s;
    if (!scanNetSourceFromJson(o.value(QLatin1String("gen")), s))
        return false;
    out = s;
    return true;
}

// Requests in flight, each bound to its id and its deadline. A reply completes only its own id, once; an expired
// id is gone (its late reply is dropped). Pure: the host drives it with its clock and one timer.
class AndroidScanPending
{
public:
    using ReplyFn = std::function<void(const QByteArray &)>;

    qint64 add(ReplyFn fn, qint64 deadlineMs)
    {
        const qint64 id = ++m_lastId;
        m_items.insert(id, Item{std::move(fn), deadlineMs});
        return id;
    }

    // The reply's callback (removed from the table); empty when the id is unknown or already done.
    ReplyFn take(qint64 id)
    {
        auto it = m_items.find(id);
        if (it == m_items.end())
            return ReplyFn();
        ReplyFn fn = std::move(it->fn);
        m_items.erase(it);
        return fn;
    }

    // Every callback whose deadline passed (removed), oldest id first.
    QList<ReplyFn> expire(qint64 nowMs)
    {
        QList<qint64> ids;
        for (auto it = m_items.cbegin(); it != m_items.cend(); ++it)
            if (it->deadlineMs <= nowMs)
                ids << it.key();
        std::sort(ids.begin(), ids.end());
        QList<ReplyFn> out;
        for (qint64 id : ids)
            out << take(id);
        return out;
    }

    // The earliest deadline; -1 when nothing is pending.
    qint64 nextDeadlineMs() const
    {
        qint64 next = -1;
        for (const Item &i : m_items)
            if (next < 0 || i.deadlineMs < next)
                next = i.deadlineMs;
        return next;
    }

    int size() const { return int(m_items.size()); }

private:
    struct Item
    {
        ReplyFn fn;
        qint64 deadlineMs = 0;
    };
    qint64 m_lastId = 0;
    QHash<qint64, Item> m_items;
};

#if defined(Q_OS_ANDROID)
class AndroidScanHost final : public IScanHost
{
public:
    AndroidScanHost();
    ~AndroidScanHost() override;

    ScanHostCaps knownCaps() const override { return androidScanKnownCaps(); }
    ScanHostAvailability availability() const override;
    QString unavailableReason() const override
    {
        return availability() == ScanHostAvailability::Available ? QString() : QStringLiteral("no_vpn");
    }
    void sendMessage(const QByteArray &request, ReplyFn reply) override;
    bool generation(ScanNetSource &out) const override;
    void stopAll() override;

    // The app process's element (source "app") and the physical kind of its underlying network
    // (NetworkState.kt ScanAppNetwork): for ScanNetFacts on Android (the engine lane's IScanEngine::network()).
    // false / "" before its monitor saw a network.
    static bool appGeneration(ScanNetSource &out, QString *kind = nullptr);

    struct State;

private:
    std::shared_ptr<State> m_state;
};
#endif

} // namespace avpn
