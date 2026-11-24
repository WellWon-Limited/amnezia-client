#include "ipcserverprocess.h"
#include "ipc.h"
#include <QProcess>

#ifndef Q_OS_IOS

IpcServerProcess::IpcServerProcess(QObject *parent) :
    IpcProcessInterfaceSource(parent),
    m_process(QSharedPointer<QProcess>(new QProcess()))
{
    connect(m_process.data(), &QProcess::errorOccurred, this, &IpcServerProcess::errorOccurred);
    connect(m_process.data(), QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &IpcServerProcess::finished);
    connect(m_process.data(), &QProcess::readyRead, this, &IpcServerProcess::readyRead);
    connect(m_process.data(), &QProcess::readyReadStandardError, this, &IpcServerProcess::readyReadStandardError);
    connect(m_process.data(), &QProcess::readyReadStandardOutput, this, &IpcServerProcess::readyReadStandardOutput);
    connect(m_process.data(), &QProcess::started, this, &IpcServerProcess::started);
    connect(m_process.data(), &QProcess::stateChanged, this, &IpcServerProcess::stateChanged);

    connect(m_process.data(), &QProcess::errorOccurred, [&](QProcess::ProcessError error){
        qDebug() << "IpcServerProcess errorOccurred " << error;
    });

#ifndef Q_OS_WIN
    avpn::OwnedChildren::service().add(m_process.data(), m_program); // AVPN
#endif
}

IpcServerProcess::~IpcServerProcess()
{
    qDebug() << "IpcServerProcess::~IpcServerProcess";
#ifndef Q_OS_WIN
    avpn::OwnedChildren::service().remove(m_process.data()); // AVPN
#endif
}

void IpcServerProcess::start()
{
    if (m_process->program().isEmpty()) {
        qDebug() << "IpcServerProcess failed to start, program is empty";
    }

#ifdef Q_OS_WIN
    Utils::killProcessByName(m_process->program());
#else
    // AVPN (macOS orphan tun2socks 24.11.2026): the previous instance of this program is one of our own
    // children - ended by its handle and reaped before the start, so its TUN device is free. Never a search by
    // name: pkill <full path> matched nothing, a name would match other users' and other products' processes.
    if (const int ended = avpn::OwnedChildren::service().endOthersOf(m_program, m_process.data()))
        qDebug() << "IpcServerProcess ended the previous instance(s):" << ended;
    m_control.onStarted();
#endif
    m_process->start();
    qDebug() << "IpcServerProcess started, " << m_process->program() << m_process->arguments();

    m_process->waitForStarted();
}

void IpcServerProcess::terminate() {
#ifndef Q_OS_WIN
    m_control.onEndRequested(); // AVPN
#endif
    m_process->terminate();
}

void IpcServerProcess::kill() {
#ifndef Q_OS_WIN
    m_control.onEndRequested(); // AVPN
#endif
    m_process->kill();
}

void IpcServerProcess::close()
{
#ifndef Q_OS_WIN
    m_control.onEndRequested(); // AVPN
#endif
    m_process->close();
}

#ifndef Q_OS_WIN
void IpcServerProcess::controllerConnected()
{
    m_control.onControllerConnected();
}

avpn::ControllerLoss IpcServerProcess::controllerLost()
{
    const avpn::ControllerLoss loss = m_control.onControllerLost(m_process->state() != QProcess::NotRunning);
    if (loss != avpn::ControllerLoss::Keep)
        qWarning() << "IpcServerProcess: the last controller left a running" << m_process->program()
                   << (loss == avpn::ControllerLoss::Abandoned ? "(abandoned)" : "(end requested)");
    return loss;
}

void IpcServerProcess::endChild()
{
    avpn::endChildLater(m_process.data());
}

QString IpcServerProcess::tunDevice() const
{
    if (m_program != amnezia::PermittedProcess::Tun2Socks)
        return {};
    const QStringList args = m_process->arguments();
    const qsizetype i = args.indexOf(QStringLiteral("-device"));
    if (i < 0 || i + 1 >= args.size() || !args.at(i + 1).startsWith(QStringLiteral("tun://")))
        return {};
    return args.at(i + 1).mid(int(qstrlen("tun://")));
}
#endif

void IpcServerProcess::setArguments(const QStringList &arguments)
{
    m_process->setArguments(amnezia::sanitizeArguments(m_program, arguments));
}

void IpcServerProcess::setInputChannelMode(QProcess::InputChannelMode mode)
{
     m_process->setInputChannelMode(mode);
}

void IpcServerProcess::setNativeArguments(const QString &arguments)
{
#ifdef Q_OS_WIN
    m_process->setNativeArguments(arguments);
#endif
}

void IpcServerProcess::setProcessChannelMode(QProcess::ProcessChannelMode mode)
{
    m_process->setProcessChannelMode(mode);
}

void IpcServerProcess::setProgram(int programId)
{
    Q_ASSERT(programId > static_cast<int>(amnezia::PermittedProcess::Invalid) &&
             programId < static_cast<int>(amnezia::PermittedProcess::PermittedProcessCount));
    m_program = static_cast<amnezia::PermittedProcess>(programId);
    m_process->setProgram(amnezia::permittedProcessPath(m_program));
    m_process->setArguments({});
#ifndef Q_OS_WIN
    avpn::OwnedChildren::service().setProgram(m_process.data(), m_program); // AVPN
#endif
}

void IpcServerProcess::setWorkingDirectory(const QString &dir)
{
    m_process->setWorkingDirectory(dir);
}

QByteArray IpcServerProcess::readAll()
{
    return m_process->readAll();
}

QByteArray IpcServerProcess::readAllStandardError()
{
    return m_process->readAllStandardError();
}

QByteArray IpcServerProcess::readAllStandardOutput()
{
    return m_process->readAllStandardOutput();
}

bool IpcServerProcess::waitForStarted() {
    return m_process->waitForStarted();
}

bool IpcServerProcess::waitForStarted(int msecs) {
    return m_process->waitForStarted(msecs);
}

bool IpcServerProcess::waitForFinished() {
    return m_process->waitForFinished();
}

bool IpcServerProcess::waitForFinished(int msecs) {
    return m_process->waitForFinished(msecs);
}

#endif
