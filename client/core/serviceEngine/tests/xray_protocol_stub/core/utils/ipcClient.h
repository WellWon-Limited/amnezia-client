#ifndef IPCCLIENT_H
#define IPCCLIENT_H

// Test stand-in for client/core/utils/ipcClient.h (xray_protocol_end_check): the same API and the same logic as
// the real IpcClient, but the nodes connect to the test's own QtRO hosts in the temp dir - never to the
// installed service (the real one dials /tmp/local:AvpnIpcInterface, the live Tribe-service).

#include <QCoreApplication>
#include <QDir>
#include <QObject>
#include <QRemoteObjectNode>
#include <QSharedPointer>

#include "rep_ipc_interface_replica.h"
#include "rep_ipc_process_interface_replica.h"

namespace avpn_test {
inline QString serviceUrl()
{
    return QStringLiteral("local:%1/xpe-%2-svc").arg(QDir::tempPath()).arg(QCoreApplication::applicationPid());
}
inline QString processUrl(int pid)
{
    return QStringLiteral("local:%1/xpe-%2-p%3").arg(QDir::tempPath()).arg(QCoreApplication::applicationPid()).arg(pid);
}
} // namespace avpn_test

class IpcClient : public QObject
{
public:
    IpcClient()
    {
        m_node.connectToNode(QUrl(avpn_test::serviceUrl()));
        m_interface.reset(m_node.acquire<IpcInterfaceReplica>());
    }

    static IpcClient &Instance()
    {
        thread_local IpcClient ipcClient;
        return ipcClient;
    }

    static QSharedPointer<IpcInterfaceReplica> Interface()
    {
        QSharedPointer<IpcInterfaceReplica> rep = Instance().m_interface;
        if (rep.isNull() || !rep->waitForSource(1000))
            return nullptr;
        return rep;
    }

    // As the real one; a pid < 0 (the service could not create the process) fails at once instead of a 30 s
    // waitForSource on a URL nobody listens on.
    static QSharedPointer<IpcProcessInterfaceReplica> CreatePrivilegedProcess();

    template <typename Func>
    static auto withInterface(Func func)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().m_interface;
        using ReturnType = decltype(func(std::declval<QSharedPointer<IpcInterfaceReplica>>()));
        if (iface.isNull() || !iface->waitForSource(1000) || !iface->isReplicaValid()) {
            if constexpr (std::is_void_v<ReturnType>)
                return;
            else
                return ReturnType{};
        }
        return func(iface);
    }

    template <typename OnSuccess, typename OnFailure>
    static auto withInterface(OnSuccess onSuccess, OnFailure onFailure)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().m_interface;
        if (iface.isNull() || !iface->waitForSource(1000) || !iface->isReplicaValid())
            return onFailure();
        return onSuccess(iface);
    }

private:
    QRemoteObjectNode m_node;
    QSharedPointer<IpcInterfaceReplica> m_interface;
};

inline QSharedPointer<IpcProcessInterfaceReplica> IpcClient::CreatePrivilegedProcess()
{
    return withInterface(
            [](QSharedPointer<IpcInterfaceReplica> &iface) -> QSharedPointer<IpcProcessInterfaceReplica> {
                auto createPrivilegedProcess = iface->createPrivilegedProcess();
                if (!createPrivilegedProcess.waitForFinished())
                    return nullptr;
                const int pid = createPrivilegedProcess.returnValue();
                if (pid < 0)
                    return nullptr;
                auto *node = new QRemoteObjectNode();
                node->connectToNode(QUrl(avpn_test::processUrl(pid)));
                QSharedPointer<IpcProcessInterfaceReplica> rep(node->acquire<IpcProcessInterfaceReplica>(),
                                                               [node](IpcProcessInterfaceReplica *ptr) {
                                                                   delete ptr;
                                                                   node->deleteLater();
                                                               });
                if (rep.isNull() || !rep->waitForSource() || !rep->isReplicaValid())
                    return nullptr;
                return rep;
            },
            []() -> QSharedPointer<IpcProcessInterfaceReplica> { return nullptr; });
}

#endif // IPCCLIENT_H
