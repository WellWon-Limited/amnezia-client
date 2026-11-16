// client/core/serviceEngine/AndroidScanHost.cpp
// AVPN serviceEngine - the Android probe host of the Scanner (AndroidScanHost.h): IScanHost over
// AndroidController::sendScanMessage -> activity -> Action.SCAN_MESSAGE -> :amneziaXrayService (ScanHostCore.kt),
// replies back as ServiceEvent.SCAN_REPLY with the request's id. Plan scanner-client-plan.md v2.2 §2.5, §2.11a;
// lane A3. Compiled for Android only (client/cmake/avpn.cmake, if(ANDROID)).
//
// Nothing here touches the tunnel: no connect, no stop, no restart. A message while the service's probe host is not
// open is answered {"error":"no_vpn"} here; the service is never started from here (IScanHost.h). Request bytes
// carry the scan token and configs: never logged (ids and sizes only).
//
// Upstream Amnezia has no counterpart.
#include "AndroidScanHost.h"

#include "platforms/android/android_controller.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QJniEnvironment>
#include <QJniObject>
#include <QObject>
#include <QTimer>
#include <QtCore/qcoreapplication_platform.h>

namespace avpn {

namespace {
qint64 nowMs() { return QDateTime::currentMSecsSinceEpoch(); }
} // namespace

struct AndroidScanHost::State
{
    AndroidScanHost *host = nullptr;
    QObject context; // receiver of AndroidController's signals, the timer and the queued replies (GUI thread)
    QTimer expiry;
    AndroidScanPending pending;
    bool open = false;      // the service's probe host admits scans (SCAN_HOST_STATE)
    bool connected = false; // the VPN is connected (AndroidController); false = the service's state is stale
    bool hasGen = false;
    ScanNetSource gen;

    bool available() const { return open && connected; }

    void armExpiry()
    {
        const qint64 next = pending.nextDeadlineMs();
        if (next < 0) {
            expiry.stop();
            return;
        }
        const qint64 wait = next - nowMs();
        expiry.start(int(wait < 0 ? 0 : (wait > 10000 ? 10000 : wait)));
    }

    // Availability / generation moved: tell the coordinator (GUI thread).
    void changed(bool wasAvailable, bool hadGen, const ScanNetSource &oldGen)
    {
        if (!host)
            return;
        const bool nowAvailable = available();
        const bool genMoved = (hadGen != (hasGen && nowAvailable)) || (hadGen && hasGen && oldGen != gen);
        if (genMoved && host->onGenerationChanged)
            host->onGenerationChanged();
        if (wasAvailable != nowAvailable && host->onAvailabilityChanged)
            host->onAvailabilityChanged();
    }
};

AndroidScanHost::AndroidScanHost() : m_state(std::make_shared<State>())
{
    m_state->host = this;
    m_state->expiry.setSingleShot(true);
    const std::weak_ptr<State> weak = m_state;
    QObject::connect(&m_state->expiry, &QTimer::timeout, &m_state->context, [weak]() {
        const std::shared_ptr<State> s = weak.lock();
        if (!s)
            return;
        const QList<AndroidScanPending::ReplyFn> late = s->pending.expire(nowMs());
        for (const AndroidScanPending::ReplyFn &fn : late)
            if (fn)
                fn(QByteArray()); // the per-action bound elapsed: no answer
        if (!late.isEmpty())
            qWarning() << "AndroidScanHost: no answer from the Xray service within the bound," << late.size() << "request(s)";
        s->armExpiry();
    });
    QObject::connect(AndroidController::instance(), &AndroidController::scanReplyReceived, &m_state->context,
                     [weak](qint64 id, const QByteArray &reply) {
                         const std::shared_ptr<State> s = weak.lock();
                         if (!s)
                             return;
                         const AndroidScanPending::ReplyFn fn = s->pending.take(id); // only ITS request
                         s->armExpiry();
                         if (!fn)
                             return; // late (its bound elapsed) or unknown: dropped
                         ScanNetSource g;
                         if (s->host && androidScanReplyGen(reply, g) && (!s->hasGen || s->gen != g)) {
                             const bool wasAvailable = s->available();
                             const bool hadGen = s->hasGen && wasAvailable;
                             const ScanNetSource old = s->gen;
                             s->hasGen = true;
                             s->gen = g;
                             s->changed(wasAvailable, hadGen, old);
                         }
                         fn(reply);
                     },
                     Qt::QueuedConnection);
    QObject::connect(AndroidController::instance(), &AndroidController::scanHostStateReceived, &m_state->context,
                     [weak](const QByteArray &json) {
                         const std::shared_ptr<State> s = weak.lock();
                         if (!s)
                             return;
                         bool open = false, hasGen = false;
                         ScanNetSource g;
                         if (!androidScanStateDecode(json, open, hasGen, g))
                             return;
                         const bool wasAvailable = s->available();
                         const bool hadGen = s->hasGen && wasAvailable;
                         const ScanNetSource old = s->gen;
                         s->open = open;
                         s->hasGen = hasGen;
                         if (hasGen)
                             s->gen = g;
                         s->changed(wasAvailable, hadGen, old);
                     },
                     Qt::QueuedConnection);
    QObject::connect(AndroidController::instance(), &AndroidController::connectionStateChanged, &m_state->context,
                     [weak](Vpn::ConnectionState state) {
                         const std::shared_ptr<State> s = weak.lock();
                         if (!s)
                             return;
                         const bool wasAvailable = s->available();
                         const bool hadGen = s->hasGen && wasAvailable;
                         const ScanNetSource old = s->gen;
                         s->connected = state == Vpn::ConnectionState::Connected;
                         if (!s->connected) {
                             s->open = false;   // the service's state is not known while the tunnel is down
                             s->hasGen = false; // nor its element
                         }
                         s->changed(wasAvailable, hadGen, old);
                     },
                     Qt::QueuedConnection);
}

AndroidScanHost::~AndroidScanHost()
{
    m_state->host = nullptr; // a late reply finds no host
}

ScanHostAvailability AndroidScanHost::availability() const
{
    return m_state->available() ? ScanHostAvailability::Available : ScanHostAvailability::NeedsVpn;
}

void AndroidScanHost::sendMessage(const QByteArray &request, ReplyFn reply)
{
    if (!reply)
        return;
    const std::weak_ptr<State> weak = m_state;
    if (!m_state->available()) {
        QTimer::singleShot(0, &m_state->context, [reply]() { reply(androidScanNoVpnReply()); });
        return;
    }
    const qint64 id = m_state->pending.add(reply, nowMs() + androidScanReplyTimeoutMs(request));
    m_state->armExpiry();
    if (!AndroidController::instance()->sendScanMessage(id, request)) {
        // Not handed to a bound service: answered no_vpn, queued (never from inside sendMessage).
        QTimer::singleShot(0, &m_state->context, [weak, id]() {
            const std::shared_ptr<State> s = weak.lock();
            if (!s)
                return;
            const AndroidScanPending::ReplyFn fn = s->pending.take(id);
            s->armExpiry();
            if (fn)
                fn(androidScanNoVpnReply());
        });
    }
}

bool AndroidScanHost::generation(ScanNetSource &out) const
{
    if (!m_state->hasGen || !m_state->available())
        return false;
    out = m_state->gen;
    return true;
}

void AndroidScanHost::stopAll()
{
    if (!m_state->available())
        return;
    const QByteArray request = androidScanStopAllRequest();
    const qint64 id = m_state->pending.add([](const QByteArray &) {}, nowMs() + androidScanReplyTimeoutMs(request));
    m_state->armExpiry();
    if (!AndroidController::instance()->sendScanMessage(id, request))
        m_state->pending.take(id);
}

bool AndroidScanHost::appGeneration(ScanNetSource &out, QString *kind)
{
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    if (!context.isValid())
        return false;
    const QJniObject json = QJniObject::callStaticObjectMethod(
        "org/amnezia/vpn/util/net/ScanAppNetwork", "element", "(Landroid/content/Context;)Ljava/lang/String;",
        context.object());
    QJniEnvironment env;
    if (env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent) || !json.isValid())
        return false;
    const QJsonObject o = QJsonDocument::fromJson(json.toString().toUtf8()).object();
    if (kind)
        *kind = o.value(QLatin1String("kind")).toString();
    ScanNetSource s;
    if (!scanNetSourceFromJson(o, s))
        return false;
    out = s;
    return true;
}

} // namespace avpn
