#include "ipcClient.h"
#include "ipc.h"
#include "ipcsecurity.h"
#include <QFileInfo>
#include <QJsonObject>
#include <QRemoteObjectNode>
#include <QtNetwork/qlocalsocket.h>

IpcClient::IpcClient(QObject *parent) : QObject(parent)
{
#ifdef Q_OS_MACOS
    m_controlSocket = new QLocalSocket(this);
    m_controlSocket->setReadBufferSize(
            amnezia::ipcsecurity::kMaxQtRoReadBufferBytes);
    m_controlSocket->connectToServer(amnezia::getIpcServiceUrl());
    QString securityError;
    if (!m_controlSocket->waitForConnected(2000)
            || !amnezia::ipcsecurity::performClientHandshake(
                    m_controlSocket, {}, &m_sessionCapability, &securityError)) {
        qCritical() << "Secure privileged IPC handshake failed:" << securityError;
        m_controlSocket->abort();
        return;
    }
    m_node.addClientSideConnection(m_controlSocket);
#else
    m_node.connectToNode(QUrl("local:" + amnezia::getIpcServiceUrl()));
#endif
    m_interface.reset(m_node.acquire<IpcInterfaceReplica>());
}

IpcClient& IpcClient::Instance()
{
    thread_local IpcClient ipcClient;
    return ipcClient;
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

QSharedPointer<IpcProcessInterfaceReplica> IpcClient::CreatePrivilegedProcess()
{
    return withInterface([](QSharedPointer<IpcInterfaceReplica> &iface) -> QSharedPointer<IpcProcessInterfaceReplica> {
#ifdef Q_OS_MACOS
        const QByteArray parentCapability = Instance().m_sessionCapability;
        if (!amnezia::ipcsecurity::isCanonicalCapability(parentCapability)) {
            return nullptr;
        }
        auto createPrivilegedProcess = iface->createPrivilegedProcessV2(
                QString::fromLatin1(parentCapability));
#else
        auto createPrivilegedProcess = iface->createPrivilegedProcess();
#endif
        if (!createPrivilegedProcess.waitForFinished(3000)) {
            qCritical() << "Failed to create privileged process";
            return nullptr;
        }

#ifdef Q_OS_MACOS
        const QJsonObject descriptor = createPrivilegedProcess.returnValue();
        const QString endpoint = descriptor.value(QStringLiteral("endpoint")).toString();
        const QByteArray capability = descriptor.value(QStringLiteral("capability"))
                .toString().toLatin1();
        const QString runtimeDirectory = amnezia::ipcsecurity::runtimeDirectory(
                static_cast<quint32>(::geteuid()));
        if (!descriptor.value(QStringLiteral("schema")).isDouble()
                || descriptor.value(QStringLiteral("schema")).toDouble() != 1.0
                || !endpoint.startsWith(runtimeDirectory + QStringLiteral("/process-"))
                || QFileInfo(endpoint).absolutePath() != runtimeDirectory
                || !amnezia::ipcsecurity::isCanonicalCapability(capability)) {
            qCritical() << "Invalid privileged process descriptor";
            return nullptr;
        }
#else
        const int pid = createPrivilegedProcess.returnValue();
#endif

        auto* node = new QRemoteObjectNode();
#ifdef Q_OS_MACOS
        auto *socket = new QLocalSocket(node);
        socket->setReadBufferSize(amnezia::ipcsecurity::kMaxQtRoReadBufferBytes);
        socket->connectToServer(endpoint);
        QByteArray childSession;
        QString securityError;
        if (!socket->waitForConnected(2000)
                || !amnezia::ipcsecurity::performClientHandshake(
                        socket, capability, &childSession, &securityError)) {
            qCritical() << "Secure child IPC handshake failed:" << securityError;
            delete node;
            return nullptr;
        }
        node->addClientSideConnection(socket);
#else
        node->connectToNode(QUrl(QString("local:%1").arg(amnezia::getIpcProcessUrl(pid))));
#endif

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
