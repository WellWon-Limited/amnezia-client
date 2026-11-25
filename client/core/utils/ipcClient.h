#ifndef IPCCLIENT_H
#define IPCCLIENT_H

#include <QLocalSocket>
#include <QObject>

#include "rep_ipc_interface_replica.h"
#include "rep_ipc_process_interface_replica.h"

class IpcClient : public QObject
{
    Q_OBJECT
public:
    explicit IpcClient(QObject *parent = nullptr);

    static IpcClient& Instance();

    static QSharedPointer<IpcInterfaceReplica> Interface();
    // AVPN (round mac-B review M1): this thread's replica only when it is valid right now - never waits. Interface()
    // calls waitForSource(), a nested event loop: a protocol's or a replica's callback must not run one (queued calls
    // of other threads run inside it and may destroy the caller's own objects).
    static QSharedPointer<IpcInterfaceReplica> InterfaceIfReady();
    static QSharedPointer<IpcProcessInterfaceReplica> CreatePrivilegedProcess();
    // AVPN (round mac-E2): the replica's own fact - the service's IPC contract differs from this app's
    // (QRemoteObjectReplica::SignatureMismatch: a service of another build). Non-blocking; this thread's replica.
    static bool interfaceIncompatible();
    // A replica that met a mismatched service never recovers in place, not even acquired again on its node (device E2):
    // the app restarts itself after curing it (AvpnEngineQml::restartForServiceUpdate). This thread's replica is valid.
    static bool interfaceValid();

    template <typename Func>
    static auto withInterface(Func func)
    {
        QSharedPointer<IpcInterfaceReplica> iface = Instance().m_interface;
        using ReturnType = decltype(func(std::declval<QSharedPointer<IpcInterfaceReplica>>()));

        if (iface.isNull() || !iface->waitForSource(1000) || !iface->isReplicaValid()) {
            qWarning() << "IpcClient::withInterface(): Service is not running";

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
        if (iface.isNull() || !iface->waitForSource(1000) || !iface->isReplicaValid()) {
            return onFailure();
        }

        return onSuccess(iface);
    }
signals:

private:
    QRemoteObjectNode m_node;
    QSharedPointer<IpcInterfaceReplica> m_interface;
};

#endif // IPCCLIENT_H
