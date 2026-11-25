#include "ipcClient.h"
#include "ipc.h"
#include <QDateTime>
#include <QRemoteObjectNode>
#include <QtNetwork/qlocalsocket.h>

IpcClient::IpcClient(QObject *parent) : QObject(parent)
{
    m_node.connectToNode(QUrl("local:" + amnezia::getIpcServiceUrl()));
    m_interface.reset(m_node.acquire<IpcInterfaceReplica>());
}

IpcClient& IpcClient::Instance()
{
    thread_local IpcClient ipcClient;
    return ipcClient;
}

bool IpcClient::interfaceIncompatible()
{
    const QSharedPointer<IpcInterfaceReplica> rep = Instance().m_interface;
    return rep && rep->state() == QRemoteObjectReplica::SignatureMismatch;
}

void IpcClient::refreshIfMismatched(qint64 minIntervalMs)
{
    IpcClient &c = Instance();
    if (!c.m_interface || c.m_interface->state() != QRemoteObjectReplica::SignatureMismatch)
        return;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (c.m_lastRefreshMs > 0 && now - c.m_lastRefreshMs < minIntervalMs)
        return;
    c.m_lastRefreshMs = now;
    qInfo() << "IpcClient: the service's IPC contract differs from this app's - the replica is acquired again";
    c.m_interface.reset(c.m_node.acquire<IpcInterfaceReplica>());
}

QSharedPointer<IpcInterfaceReplica> IpcClient::Interface()
{
    refreshIfMismatched(3000); // AVPN (round mac-E2)
    QSharedPointer<IpcInterfaceReplica> rep = Instance().m_interface;
    if (rep.isNull()) {
        qCritical() << "IpcClient::Interface(): Failed to acquire replica";
        return nullptr;
    }
    if (!rep->waitForSource(1000)) {
        qCritical() << "IpcClient::Interface(): Failed to initialize replica";
        return nullptr;
    }
    if (!rep->isReplicaValid()) {
        qWarning() << "IpcClient::Interface(): Replica is invalid";
    }
    return rep;
}

// AVPN (round mac-B review M1): see ipcClient.h - validity first, no waitForSource.
QSharedPointer<IpcInterfaceReplica> IpcClient::InterfaceIfReady()
{
    refreshIfMismatched(3000); // AVPN (round mac-E2)
    QSharedPointer<IpcInterfaceReplica> rep = Instance().m_interface;
    if (rep.isNull() || !rep->isReplicaValid())
        return nullptr;
    return rep;
}

QSharedPointer<IpcProcessInterfaceReplica> IpcClient::CreatePrivilegedProcess()
{
    return withInterface([](QSharedPointer<IpcInterfaceReplica> &iface) -> QSharedPointer<IpcProcessInterfaceReplica> {
        auto createPrivilegedProcess = iface->createPrivilegedProcess();
        if (!createPrivilegedProcess.waitForFinished()) {
            qCritical() << "Failed to create privileged process";
            return nullptr;
        }

        const int pid = createPrivilegedProcess.returnValue();

        auto* node = new QRemoteObjectNode();
        node->connectToNode(QUrl(QString("local:%1").arg(amnezia::getIpcProcessUrl(pid))));

        QSharedPointer<IpcProcessInterfaceReplica> rep(
            node->acquire<IpcProcessInterfaceReplica>(),
            [node] (IpcProcessInterfaceReplica *ptr) {
                delete ptr;
                node->deleteLater();
            }
        );
        if (rep.isNull()) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Failed to acquire replica";
            return nullptr;
        }
        if (!rep->waitForSource()) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Failed to initialize replica";
            return nullptr;
        }
        if (!rep->isReplicaValid()) {
            qCritical() << "IpcClient::CreatePrivilegedProcess(): Replica is invalid";
            return nullptr;
        }

        return rep;
    },
    []() -> QSharedPointer<IpcProcessInterfaceReplica> {
        return nullptr;
    });
}
