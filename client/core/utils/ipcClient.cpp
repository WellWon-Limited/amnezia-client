#include "ipcClient.h"
#include "ipc.h"
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

bool IpcClient::interfaceValid()
{
    const QSharedPointer<IpcInterfaceReplica> rep = Instance().m_interface;
    return rep && rep->state() == QRemoteObjectReplica::Valid;
}

QSharedPointer<IpcInterfaceReplica> IpcClient::Interface()
{
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
