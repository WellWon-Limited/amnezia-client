#ifndef IPCSERVERPROCESS_H
#define IPCSERVERPROCESS_H

#include "ipc.h"
#include <QObject>

#ifndef Q_OS_IOS
#include "rep_ipc_process_interface_source.h"
#ifndef Q_OS_WIN
#include "ipcprocessowner.h" // AVPN
#endif

class IpcServerProcess : public IpcProcessInterfaceSource
{
    Q_OBJECT
public:
    explicit IpcServerProcess(QObject *parent = nullptr);
    virtual ~IpcServerProcess();

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

#ifndef Q_OS_WIN
    // AVPN (macOS/Linux, ipcprocessowner.h): the child lives as long as a client controls it.
    void controllerConnected();
    // A controlling connection closed. Not Keep: the last one is gone while the child runs (Abandoned - no
    // controller had asked to end it: its client quit or crashed) and the caller ends it with endChild().
    avpn::ControllerLoss controllerLost();
    // SIGTERM now, SIGKILL after a grace if it still runs; never blocks.
    void endChild();
    amnezia::PermittedProcess program() const { return m_program; }
    // The device of a tun2socks child ("-device tun://utun22" -> "utun22"); empty for other programs.
    QString tunDevice() const;
    // The service's Xray session generation this child was started in (XraySessionLedger).
    quint64 xrayGeneration() const { return m_xrayGeneration; }
#endif

signals:

private:
    amnezia::PermittedProcess m_program = amnezia::PermittedProcess::Invalid;
    QSharedPointer<QProcess> m_process;
#ifndef Q_OS_WIN
    avpn::ChildControl m_control; // AVPN
    quint64 m_xrayGeneration = 0; // AVPN (review F2)
#endif
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
