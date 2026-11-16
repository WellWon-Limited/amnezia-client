// service/server/tests/tribe_scan_fakes.cpp - AVPN test doubles (see tribe_scan_fakes.h).
#include "tribe_scan_fakes.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>

#include <cstdio>
#include <cstdlib>
#include <cstring>


namespace fake {

Engine &engine()
{
    static Engine e;
    return e;
}

void Engine::reset()
{
    QMutexLocker l(&mutex);
    calls.clear();
    order.clear();
    reply = nullptr;
    stopAllResult = true;
    stopAllReply.clear();
    setSockCallbackCalls = 0;
    configureCalls = 0;
    startCalls = 0;
    stopCalls = 0;
    logHandlerCalls = 0;
    tunnelCallbackInvocations = 0;
    tunnelCallback = nullptr;
    tunnelContext = nullptr;
}

QList<Call> Engine::snapshot()
{
    QMutexLocker l(&mutex);
    return calls;
}

QList<QString> Engine::orderSnapshot()
{
    QMutexLocker l(&mutex);
    return order;
}

void Engine::note(const QString &event)
{
    QMutexLocker l(&mutex);
    order << event;
}

void Engine::closeGate()
{
    std::lock_guard<std::mutex> g(gateMutex);
    gateOpen = false;
}

void Engine::openGate()
{
    {
        std::lock_guard<std::mutex> g(gateMutex);
        gateOpen = true;
    }
    gateCv.notify_all();
}

} // namespace fake

namespace {
char *dup(const QByteArray &b)
{
    char *p = static_cast<char *>(std::malloc(size_t(b.size()) + 1));
    std::memcpy(p, b.constData(), size_t(b.size()));
    p[b.size()] = 0;
    return p;
}
} // namespace

extern "C" {

void amnezia_xray_free(void *ptr)
{
    std::free(ptr);
}

char *amnezia_xray_configure(char *)
{
    ++fake::engine().configureCalls;
    return nullptr;
}

char *amnezia_xray_start(void)
{
    ++fake::engine().startCalls;
    return nullptr;
}

char *amnezia_xray_stop(void)
{
    ++fake::engine().stopCalls;
    return nullptr;
}

char *amnezia_xray_setsockcallback(amnezia_xray_sockcallback cb, void *ctx)
{
    fake::Engine &e = fake::engine();
    ++e.setSockCallbackCalls;
    e.tunnelCallback = cb;
    e.tunnelContext = ctx;
    return nullptr;
}

void amnezia_xray_setloghandler(amnezia_xray_loghandler, void *)
{
    ++fake::engine().logHandlerCalls;
}

char *amnezia_xray_scan_message(char *cMessage, char *cHostOptions)
{
    fake::Engine &e = fake::engine();
    const QByteArray message(cMessage);
    const QByteArray options = cHostOptions ? QByteArray(cHostOptions) : QByteArray();
    const QJsonObject mo = QJsonDocument::fromJson(message).object();
    if (mo.value(QLatin1String("action")).toString() == QLatin1String("scan_stop_all")) {
        // The host-only epoch stop: as the engine, {"stopped":true} or {"stopped":false,...flat counts} - never
        // held by the gate (a stop does not wait for a probe message).
        const qint64 wait = qint64(mo.value(QLatin1String("wait_ms")).toDouble(-1));
        const qint64 epoch = qint64(QJsonDocument::fromJson(options).object().value(QLatin1String("host_epoch")).toDouble(-1));
        bool ok = true;
        {
            QMutexLocker l(&e.mutex);
            e.calls << fake::Call{QStringLiteral("stop_all"), message, options, wait, epoch};
            e.order << QStringLiteral("stop_all:%1").arg(wait);
            ok = e.stopAllResult;
            if (!e.stopAllReply.isEmpty())
                return dup(e.stopAllReply);
        }
        return dup(ok ? QByteArrayLiteral("{\"stopped\":true}") : QByteArrayLiteral("{\"stopped\":false}"));
    }
    {
        std::unique_lock<std::mutex> g(e.gateMutex);
        ++e.gateWaiters;
        e.gateCv.wait(g, [&e] { return e.gateOpen; });
        --e.gateWaiters;
    }
    std::function<QByteArray(const QByteArray &, const QByteArray &)> handler;
    {
        QMutexLocker l(&e.mutex);
        e.calls << fake::Call{QStringLiteral("scan_message"), message, options, -1};
        const QJsonDocument d = QJsonDocument::fromJson(message);
        e.order << QStringLiteral("scan_message:%1").arg(d.object().value(QLatin1String("action")).toString());
        handler = e.reply;
    }
    const QByteArray reply = handler ? handler(message, options) : QByteArrayLiteral("{\"error\":\"internal\"}");
    return dup(reply);
}

char *amnezia_xray_scan_stop_all(int64_t waitMs)
{
    fake::Engine &e = fake::engine();
    bool ok = true;
    {
        QMutexLocker l(&e.mutex);
        e.calls << fake::Call{QStringLiteral("stop_all"), QByteArray(), QByteArray(), qint64(waitMs)};
        e.order << QStringLiteral("stop_all:%1").arg(waitMs);
        ok = e.stopAllResult;
    }
    return dup(ok ? QByteArrayLiteral("{\"stopped\":true}") : QByteArrayLiteral("{\"stopped\":false}"));
}

} // extern "C"
