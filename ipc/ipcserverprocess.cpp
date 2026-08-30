#include "ipcserverprocess.h"
#include "ipc.h"
#include "ipcsecurity.h"
#include "openvpnconfigsecurity.h"
#include <QFile>
#include <QHostAddress>
#include <QProcess>
#include <QTemporaryFile>

#ifdef Q_OS_MACOS
#include <sys/stat.h>
#include <unistd.h>
#endif

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

}

IpcServerProcess::~IpcServerProcess()
{
    qDebug() << "IpcServerProcess::~IpcServerProcess";
}

void IpcServerProcess::setAuthorizedPeerUid(quint32 uid)
{
    if (m_process->state() != QProcess::NotRunning || m_openVpnPrepared
            || m_startAttempted) {
        return;
    }
    m_authorizedPeerUid = uid;
    m_runtimeDirectory.clear();
    m_openVpnConfigSnapshot.reset();
    m_openVpnDnsSession.clear();
    m_process->setArguments({});
    m_argumentsValid = false;
}

bool IpcServerProcess::isOpenVpnProcess() const
{
    return m_program == amnezia::PermittedProcess::OpenVPN;
}

QString IpcServerProcess::openVpnDnsSession() const
{
    return isOpenVpnProcess() ? m_openVpnDnsSession : QString{};
}

void IpcServerProcess::clearOpenVpnDnsSession()
{
    m_openVpnDnsSession.clear();
}

void IpcServerProcess::setRuntimeDirectory(const QString &directory)
{
    if (m_process->state() != QProcess::NotRunning || m_openVpnPrepared
            || m_startAttempted) {
        return;
    }
#ifdef Q_OS_MACOS
    m_runtimeDirectory = directory == amnezia::ipcsecurity::runtimeDirectory(
            m_authorizedPeerUid) ? directory : QString{};
#else
    Q_UNUSED(directory);
#endif
}

void IpcServerProcess::start()
{
    if (m_startAttempted || m_process->program().isEmpty()
            || !m_argumentsValid) {
        qWarning() << "IpcServerProcess rejected invalid program/arguments";
        emit errorOccurred(QProcess::FailedToStart);
        return;
    }

    // A privileged child is owned by this exact descriptor.  Never kill by
    // executable name: doing so crosses users/sessions and can terminate an
    // unrelated Amnezia/Tribe process.  A still-running child must be stopped
    // through this descriptor before it can be started again.
    if (m_process->state() != QProcess::NotRunning) {
        qWarning() << "IpcServerProcess rejected start while child is running";
        emit errorOccurred(QProcess::FailedToStart);
        return;
    }
    // Every privileged descriptor is one-shot.  In particular, an OpenVPN
    // descriptor can never be reconfigured in the finished-signal window and
    // thereby lose the immutable DNS recovery token.
    m_startAttempted = true;
    m_process->start();
    // Arguments can contain SOCKS credentials and bearer core configuration.
    qDebug() << "IpcServerProcess started" << m_process->program()
             << "argumentCount" << m_process->arguments().size();

    m_process->waitForStarted();
}

void IpcServerProcess::terminate() {
    m_process->terminate();
}

void IpcServerProcess::kill() {
    m_process->kill();
}

void IpcServerProcess::close()
{
    m_process->close();
}

void IpcServerProcess::setArguments(const QStringList &arguments)
{
    if (m_process->state() != QProcess::NotRunning || m_openVpnPrepared
            || m_startAttempted) {
        qWarning() << "IpcServerProcess rejected argument mutation while running";
        return;
    }
    m_openVpnConfigSnapshot.reset();
    m_openVpnDnsSession.clear();
    if (arguments.size() > 32) {
        m_argumentsValid = false;
        m_process->setArguments({});
        return;
    }
    for (const QString &argument : arguments) {
        if (argument.size() > 2048 || argument.contains(QChar::Null)) {
            m_argumentsValid = false;
            m_process->setArguments({});
            return;
        }
    }
#ifdef Q_OS_MACOS
    if (m_program == amnezia::PermittedProcess::OpenVPN) {
        QStringList prepared;
        QString securityError;
        m_argumentsValid = prepareOpenVpnArguments(
                arguments, &prepared, &securityError);
        if (!m_argumentsValid) {
            qWarning() << "IpcServerProcess rejected OpenVPN configuration:"
                       << securityError;
        }
        m_process->setArguments(m_argumentsValid ? prepared : QStringList{});
        m_openVpnPrepared = m_argumentsValid;
        return;
    }
#endif
    const QStringList sanitized = amnezia::sanitizeArguments(
            m_program, arguments, m_authorizedPeerUid);
    m_argumentsValid = sanitized == arguments;
    m_process->setArguments(m_argumentsValid ? sanitized : QStringList{});
}

#ifdef Q_OS_MACOS
bool IpcServerProcess::prepareOpenVpnArguments(
        const QStringList &arguments, QStringList *preparedArguments,
        QString *error)
{
    if (!preparedArguments || arguments.size() != 6
            || arguments.at(0) != QLatin1String("--config")
            || arguments.at(2) != QLatin1String("--management")
            || arguments.at(5) != QLatin1String("--management-client")) {
        if (error) {
            *error = QStringLiteral("openvpn_cli_shape_invalid");
        }
        return false;
    }
    const QHostAddress managementAddress(arguments.at(3));
    bool portOk = false;
    const int managementPort = arguments.at(4).toInt(&portOk);
    if ((managementAddress != QHostAddress::LocalHost
         && managementAddress != QHostAddress::LocalHostIPv6)
            || !portOk || managementPort <= 0 || managementPort > 65535
            || m_runtimeDirectory
                    != amnezia::ipcsecurity::runtimeDirectory(m_authorizedPeerUid)) {
        if (error) {
            *error = QStringLiteral("openvpn_cli_value_invalid");
        }
        return false;
    }

    QString runtimeError;
    if (!amnezia::ipcsecurity::prepareRuntimeDirectory(
                m_authorizedPeerUid, 0, &runtimeError)) {
        if (error) {
            *error = QStringLiteral("openvpn_runtime_directory_invalid_%1")
                    .arg(runtimeError);
        }
        return false;
    }

    QByteArray source;
    QByteArray privileged;
    const QByteArray dnsSessionToken = amnezia::ipcsecurity::randomCapability();
    if (!amnezia::openvpnconfigsecurity::readPeerOwnedConfig(
                arguments.at(1), m_authorizedPeerUid, &source, error)
            || !amnezia::openvpnconfigsecurity::buildPrivilegedConfig(
                source, dnsSessionToken, &privileged, error)
            || !amnezia::openvpnconfigsecurity::validateTrustedDnsHook(error)) {
        return false;
    }

    auto snapshot = std::make_unique<QTemporaryFile>(
            m_runtimeDirectory + QStringLiteral("/openvpn-config-XXXXXX.ovpn"));
    snapshot->setAutoRemove(true);
    if (!snapshot->open()) {
        if (error) {
            *error = QStringLiteral("openvpn_snapshot_create_failed");
        }
        return false;
    }
    const int snapshotFd = snapshot->handle();
    struct stat snapshotMetadata {};
    if (snapshotFd < 0 || ::fchmod(snapshotFd, 0600) != 0
            || ::fstat(snapshotFd, &snapshotMetadata) != 0
            || !S_ISREG(snapshotMetadata.st_mode)
            || snapshotMetadata.st_uid != 0 || snapshotMetadata.st_nlink != 1
            || (snapshotMetadata.st_mode & 07777) != 0600
            || snapshot->write(privileged) != privileged.size()
            || !snapshot->flush() || ::fsync(snapshotFd) != 0) {
        if (error) {
            *error = QStringLiteral("openvpn_snapshot_write_failed");
        }
        return false;
    }
    const QString snapshotPath = snapshot->fileName();
    snapshot->close();

    struct stat finalMetadata {};
    const QByteArray encodedSnapshot = QFile::encodeName(snapshotPath);
    if (::lstat(encodedSnapshot.constData(), &finalMetadata) != 0
            || !S_ISREG(finalMetadata.st_mode) || S_ISLNK(finalMetadata.st_mode)
            || finalMetadata.st_uid != 0 || finalMetadata.st_nlink != 1
            || (finalMetadata.st_mode & 07777) != 0600
            || finalMetadata.st_size != privileged.size()) {
        if (error) {
            *error = QStringLiteral("openvpn_snapshot_metadata_invalid");
        }
        return false;
    }

    *preparedArguments = arguments;
    (*preparedArguments)[1] = snapshotPath;
    m_openVpnConfigSnapshot = std::move(snapshot);
    m_openVpnDnsSession = QString::fromLatin1(dnsSessionToken);
    return true;
}
#endif

void IpcServerProcess::setInputChannelMode(QProcess::InputChannelMode mode)
{
    if (m_openVpnPrepared || m_startAttempted) return;
     m_process->setInputChannelMode(mode);
}

void IpcServerProcess::setNativeArguments(const QString &arguments)
{
    if (m_openVpnPrepared || m_startAttempted) return;
#ifdef Q_OS_WIN
    m_process->setNativeArguments(arguments);
#else
    Q_UNUSED(arguments);
#endif
}

void IpcServerProcess::setProcessChannelMode(QProcess::ProcessChannelMode mode)
{
    if (m_openVpnPrepared || m_startAttempted) return;
    m_process->setProcessChannelMode(mode);
}

void IpcServerProcess::setProgram(int programId)
{
    if (m_process->state() != QProcess::NotRunning || m_openVpnPrepared
            || m_startAttempted) {
        qWarning() << "IpcServerProcess rejected program mutation while running";
        return;
    }
    m_openVpnConfigSnapshot.reset();
    m_openVpnDnsSession.clear();
    if (programId <= static_cast<int>(amnezia::PermittedProcess::Invalid)
            || programId >= static_cast<int>(amnezia::PermittedProcess::PermittedProcessCount)) {
        m_program = amnezia::PermittedProcess::Invalid;
        m_process->setProgram({});
        m_process->setArguments({});
        m_argumentsValid = false;
        return;
    }
    m_program = static_cast<amnezia::PermittedProcess>(programId);
    m_process->setProgram(amnezia::permittedProcessPath(m_program));
    m_process->setArguments({});
    m_argumentsValid = false;
}

void IpcServerProcess::setWorkingDirectory(const QString &dir)
{
    if (m_openVpnPrepared || m_startAttempted) return;
    // No current privileged child requires a caller-selected working
    // directory. Reject this root path-selection primitive.
    if (dir.isEmpty()) {
        m_process->setWorkingDirectory({});
    }
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

QProcess::ProcessState IpcServerProcess::state()
{
    return m_process->state();
}

#endif
