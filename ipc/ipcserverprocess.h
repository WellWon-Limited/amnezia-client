#ifndef IPCSERVERPROCESS_H
#define IPCSERVERPROCESS_H

#include "ipc.h"
#include <QObject>
#include <limits>
#include <memory>

class QTemporaryFile;

#ifndef Q_OS_IOS
#include "rep_ipc_process_interface_source.h"

class IpcServerProcess : public IpcProcessInterfaceSource
{
    Q_OBJECT
public:
    explicit IpcServerProcess(QObject *parent = nullptr);
    virtual ~IpcServerProcess();

    void setAuthorizedPeerUid(quint32 uid);
    void setRuntimeDirectory(const QString &directory);
    bool isOpenVpnProcess() const;
    QString openVpnDnsSession() const;
    void clearOpenVpnDnsSession();

    void start() override;
    void terminate() override;
    void kill() override;
    void close() override;

    void setArguments(const QStringList &arguments) override;
    void setInputChannelMode(QProcess::InputChannelMode mode) override;
    void setNativeArguments(const QString &arguments) override;
    void setProcessChannelMode(QProcess::ProcessChannelMode mode) override;
    void setProgram(int programId) override;
    void setWorkingDirectory(const QString &dir) override;

    QByteArray readAll() override;
    QByteArray readAllStandardError() override;
    QByteArray readAllStandardOutput() override;

    bool waitForStarted() override;
    bool waitForStarted(int msecs) override;
    bool waitForFinished() override;
    bool waitForFinished(int msecs) override;
    QProcess::ProcessState state() override;

signals:

private:
#ifdef Q_OS_MACOS
    bool prepareOpenVpnArguments(const QStringList &arguments,
                                 QStringList *preparedArguments,
                                 QString *error);
#endif
    amnezia::PermittedProcess m_program = amnezia::PermittedProcess::Invalid;
    QSharedPointer<QProcess> m_process;
    quint32 m_authorizedPeerUid = std::numeric_limits<quint32>::max();
    QString m_runtimeDirectory;
    std::unique_ptr<QTemporaryFile> m_openVpnConfigSnapshot;
    QString m_openVpnDnsSession;
    bool m_argumentsValid = false;
    bool m_openVpnPrepared = false;
    bool m_startAttempted = false;
};

#else
class IpcServerProcess : public QObject
{
    Q_OBJECT

public:
    explicit IpcServerProcess(QObject *parent = nullptr);
};
#endif

#endif // IPCSERVERPROCESS_H
