// client/core/serviceEngine/DaemonScanHost.cpp - IScanHost over the service's IpcScanInterface (see the header).
#include "DaemonScanHost.h"

#include <QJsonDocument>
#include <QRandomGenerator>
#include <QRemoteObjectNode>
#include <QRemoteObjectPendingCall>
#include <QTimer>

#include "ipc.h"
#include "rep_ipc_interface_replica.h"
#include "rep_ipc_scan_interface_replica.h"

namespace avpn {

DaemonScanTransport::State daemonScanTransportState(QRemoteObjectReplica::State witness, QRemoteObjectReplica::State scan,
                                                    int scanIpcVersion, bool startupOver, bool oldGraceOver)
{
    using S = DaemonScanTransport::State;
    if (scan == QRemoteObjectReplica::Valid)
        return scanIpcVersion >= 1 ? S::Ready : S::ServiceOld;
    if (scan == QRemoteObjectReplica::SignatureMismatch)
        return S::ServiceOld; // another shape of IpcScanInterface: never call into it
    if (witness == QRemoteObjectReplica::SignatureMismatch)
        return S::ServiceMismatch;
    if (witness == QRemoteObjectReplica::Valid)
        return oldGraceOver ? S::ServiceOld : S::Connecting; // the service answers; its source list had no scan host
    return startupOver ? S::ServiceOff : S::Connecting;
}

QString daemonScanUnavailableReason(DaemonScanTransport::State s)
{
    switch (s) {
    case DaemonScanTransport::State::Ready: return QString();
    case DaemonScanTransport::State::Connecting: return QStringLiteral("connecting");
    case DaemonScanTransport::State::ServiceOff: return QStringLiteral("service_off");
    case DaemonScanTransport::State::ServiceOld: return QStringLiteral("service_old");
    case DaemonScanTransport::State::ServiceMismatch: return QStringLiteral("service_mismatch");
    }
    return QStringLiteral("service_off");
}

int daemonScanReplyBoundMs(const QByteArray &request)
{
    // The contract's encoders write compact JSON with sorted keys: "action" comes first.
    return request.left(64).contains("\"scan_start\"") ? kDaemonScanStartReplyMs : kDaemonScanReplyMs;
}

QByteArray daemonScanRefusalReply(int code)
{
    const char *detail = nullptr;
    switch (code) {
    case 1: detail = "too_large"; break;
    case 2: detail = "rate_limited"; break;
    case 3: detail = "queue_full"; break;
    case 4: detail = "shutting_down"; break;
    default: return QByteArray();
    }
    return QByteArrayLiteral("{\"error\":\"ipc_refused\",\"detail\":\"") + detail + QByteArrayLiteral("\"}");
}

namespace {

// The production transport: an own node on the service's socket, IpcInterface as the witness.
class QtRoDaemonScanTransport : public DaemonScanTransport
{
public:
    explicit QtRoDaemonScanTransport(const QUrl &url)
    {
        m_startup.setSingleShot(true);
        m_startup.setInterval(kDaemonScanStartupMs);
        m_grace.setSingleShot(true);
        m_grace.setInterval(kDaemonScanOldGraceMs);
        QObject::connect(&m_startup, &QTimer::timeout, &m_ctx, [this]() {
            m_startupOver = true;
            reevaluate();
        });
        QObject::connect(&m_grace, &QTimer::timeout, &m_ctx, [this]() {
            m_graceOver = true;
            reevaluate();
        });

        m_node.connectToNode(url);
        m_witness.reset(m_node.acquire<IpcInterfaceReplica>());
        m_scan.reset(m_node.acquire<IpcScanInterfaceReplica>());
        QObject::connect(m_witness.get(), &QRemoteObjectReplica::stateChanged, &m_ctx,
                         [this](QRemoteObjectReplica::State s, QRemoteObjectReplica::State) {
                             if (s == QRemoteObjectReplica::Valid) {
                                 m_startupOver = true; // a service was seen: losing it later is "service_off"
                                 if (!m_graceOver && !m_grace.isActive())
                                     m_grace.start();
                             } else {
                                 m_grace.stop();
                                 m_graceOver = false;
                             }
                             reevaluate();
                         });
        QObject::connect(m_scan.get(), &QRemoteObjectReplica::stateChanged, &m_ctx,
                         [this](QRemoteObjectReplica::State, QRemoteObjectReplica::State) { reevaluate(); });
        QObject::connect(m_scan.get(), &IpcScanInterfaceReplica::scanIpcVersionChanged, &m_ctx, [this](int) { reevaluate(); });
        QObject::connect(m_scan.get(), &IpcScanInterfaceReplica::scanGenerationChanged, &m_ctx, [this](const QString &) {
            if (onGenerationChanged)
                onGenerationChanged();
        });
        QObject::connect(m_scan.get(), &IpcScanInterfaceReplica::scanReply, &m_ctx, [this](quint64 id, const QString &reply) {
            if (onReply)
                onReply(id, reply);
        });
        m_startup.start();
        m_last = state();
    }

    State state() const override
    {
        return daemonScanTransportState(m_witness->state(), m_scan->state(), m_scan->scanIpcVersion(), m_startupOver,
                                        m_graceOver);
    }

    QString generationJson() const override { return m_scan->isReplicaValid() ? m_scan->scanGeneration() : QString(); }

    void submit(quint64 requestId, const QString &message, std::function<void(int)> accepted) override
    {
        if (!m_scan->isReplicaValid()) {
            QTimer::singleShot(0, &m_ctx, [accepted]() { accepted(-1); });
            return;
        }
        QRemoteObjectPendingReply<int> r = m_scan->scanSubmit(requestId, message);
        auto *w = new QRemoteObjectPendingCallWatcher(r, &m_ctx);
        QObject::connect(w, &QRemoteObjectPendingCallWatcher::finished, &m_ctx, [w, accepted](QRemoteObjectPendingCallWatcher *) {
            const int code = w->error() == QRemoteObjectPendingCall::NoError ? w->returnValue().toInt() : -1;
            w->deleteLater();
            accepted(code);
        });
    }

    void stopAll() override
    {
        if (m_scan->isReplicaValid())
            m_scan->scanStopAll();
    }

private:
    void reevaluate()
    {
        const State s = state();
        if (s == m_last)
            return;
        m_last = s;
        if (onStateChanged)
            onStateChanged();
    }

    QObject m_ctx;
    QRemoteObjectNode m_node;
    std::unique_ptr<IpcInterfaceReplica> m_witness;
    std::unique_ptr<IpcScanInterfaceReplica> m_scan;
    QTimer m_startup;
    QTimer m_grace;
    bool m_startupOver = false;
    bool m_graceOver = false;
    State m_last = State::Connecting;
};

} // namespace

std::unique_ptr<DaemonScanTransport> DaemonScanHost::serviceTransport(const QUrl &url)
{
    return std::make_unique<QtRoDaemonScanTransport>(url.isEmpty() ? QUrl(QStringLiteral("local:") + amnezia::getIpcServiceUrl())
                                                                    : url);
}

DaemonScanHost::DaemonScanHost(std::unique_ptr<DaemonScanTransport> transport) : m_t(std::move(transport))
{
    m_nextId = QRandomGenerator::global()->generate64() >> 1; // ids of different app runs never meet
    m_state = m_t->state();
    m_t->onStateChanged = [this]() { stateChanged(); };
    m_t->onGenerationChanged = [this]() {
        if (onGenerationChanged)
            onGenerationChanged();
    };
    m_t->onReply = [this](quint64 id, const QString &reply) { finish(id, reply.toUtf8()); };
}

DaemonScanHost::~DaemonScanHost()
{
    // The transport goes first (member order); pending replies are dropped with the GUI.
    m_t.reset();
}

ScanHostCaps DaemonScanHost::compiledCaps()
{
    ScanHostCaps c;
    c.maxFullConcurrent = 2;
    c.canVerifyComposite = true;
    c.maxLegConcurrent = 6;
    c.dnsPlan = true;
    c.reachStage = true;
    c.needsVpn = false;
#if defined(Q_OS_WIN)
    c.maxAwgConcurrent = 0; // no AmneziaWG probe runner on Windows
    c.platform = QStringLiteral("windows");
#elif defined(Q_OS_MACOS)
    c.maxAwgConcurrent = 4; // the payload's amneziawg-go is built with tribe_probe (root conanfile.py)
    c.platform = QStringLiteral("macos");
#else
    c.maxAwgConcurrent = 0;
    c.platform = QStringLiteral("linux");
#endif
    return c;
}

ScanHostCaps DaemonScanHost::knownCaps() const
{
    return compiledCaps();
}

ScanHostAvailability DaemonScanHost::availability() const
{
    return m_state == DaemonScanTransport::State::Ready ? ScanHostAvailability::Available : ScanHostAvailability::Unavailable;
}

QString DaemonScanHost::unavailableReason() const
{
    return daemonScanUnavailableReason(m_state);
}

void DaemonScanHost::sendMessage(const QByteArray &request, ReplyFn reply)
{
    const quint64 id = ++m_nextId;
    QObject *timer = nullptr;
    if (m_state == DaemonScanTransport::State::Ready) {
        const int bound = daemonScanReplyBoundMs(request);
        if (m_boundTimer) {
            timer = m_boundTimer(bound, [this, id]() { finish(id, QByteArray()); });
        } else {
            auto *t = new QTimer(&m_ctx);
            t->setSingleShot(true);
            t->setTimerType(Qt::PreciseTimer); // a coarse timer may fire 5 % early
            QObject::connect(t, &QTimer::timeout, &m_ctx, [this, id]() { finish(id, QByteArray()); });
            t->start(bound);
            timer = t;
        }
    }
    m_pending.insert(id, Pending{std::move(reply), timer});
    if (m_state != DaemonScanTransport::State::Ready) {
        finish(id, QByteArray()); // no service to ask: no answer (delivered queued)
        return;
    }
    if (request.size() > kDaemonScanMaxMessageBytes) {
        finish(id, daemonScanRefusalReply(1)); // the service would refuse it: not worth the IPC
        return;
    }
    m_t->submit(id, QString::fromUtf8(request), [this, id](int code) {
        if (code == 0)
            return; // the reply follows through onReply
        finish(id, daemonScanRefusalReply(code)); // -1 (the call failed) = no answer
    });
}

void DaemonScanHost::finish(quint64 id, const QByteArray &reply)
{
    const auto it = m_pending.find(id);
    if (it == m_pending.end())
        return; // already answered (bound elapsed, or a late reply)
    Pending p = it.value();
    m_pending.erase(it);
    if (p.timer)
        p.timer->deleteLater();
    // Always queued: never from inside sendMessage, never re-entrant with the caller.
    QTimer::singleShot(0, &m_ctx, [fn = std::move(p.reply), reply]() {
        if (fn)
            fn(reply);
    });
}

void DaemonScanHost::stateChanged()
{
    const DaemonScanTransport::State s = m_t->state();
    if (s == m_state)
        return;
    const bool wasReady = m_state == DaemonScanTransport::State::Ready;
    m_state = s;
    if (wasReady && s != DaemonScanTransport::State::Ready) {
        const QList<quint64> ids = m_pending.keys();
        for (quint64 id : ids)
            finish(id, QByteArray()); // the service went away: those replies never come
    }
    if (onAvailabilityChanged)
        onAvailabilityChanged();
    if (onGenerationChanged)
        onGenerationChanged(); // known only while Ready
}

bool DaemonScanHost::generation(ScanNetSource &out) const
{
    if (m_state != DaemonScanTransport::State::Ready)
        return false;
    const QJsonDocument doc = QJsonDocument::fromJson(m_t->generationJson().toUtf8());
    ScanNetSource g;
    if (!doc.isObject() || !scanNetSourceFromJson(doc.object(), g))
        return false;
    out = g;
    return true;
}

void DaemonScanHost::stopAll()
{
    if (m_state == DaemonScanTransport::State::Ready)
        m_t->stopAll();
}

} // namespace avpn
