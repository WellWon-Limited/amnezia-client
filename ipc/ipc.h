#ifndef IPC_H
#define IPC_H

#include <QObject>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QString>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>

#include <limits>

#ifdef Q_OS_MACOS
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "../client/core/utils/utilities.h"

// AVPN: свой сокет — полная изоляция от установленной рядом официальной Amnezia
// (наш клиент ↔ наш демон Tribe-service; см. TRIBE-iOS-DEV §15)
#define IPC_SERVICE_URL "local:AvpnIpcInterface"

namespace amnezia {

enum PermittedProcess {
    Invalid,
    OpenVPN,
    Wireguard,
    Tun2Socks,
    CertUtil,
    PermittedProcessCount
};

inline QString permittedProcessPath(PermittedProcess pid)
{
    switch (pid) {
        case PermittedProcess::OpenVPN:
            return Utils::openVpnExecPath();
        case PermittedProcess::Wireguard:
            return Utils::wireguardExecPath();
        case PermittedProcess::CertUtil:
            return Utils::certUtilPath();
        case PermittedProcess::Tun2Socks:
            return Utils::tun2socksPath();
        default:
            return "";
    }
}


inline QString getIpcServiceUrl(quint32 uid) {
#ifdef Q_OS_WIN
    Q_UNUSED(uid);
    return IPC_SERVICE_URL;
#elif defined(Q_OS_MACOS)
    return QString("/private/var/run/tribevpn/%1/control.sock").arg(uid);
#else
    Q_UNUSED(uid);
    return QString("/tmp/%1").arg(IPC_SERVICE_URL);
#endif
}

inline QString getIpcServiceUrl() {
#ifdef Q_OS_MACOS
    return getIpcServiceUrl(static_cast<quint32>(::geteuid()));
#else
    return getIpcServiceUrl(0);
#endif
}

inline QString getWireguardDaemonUrl(quint32 uid) {
#ifdef Q_OS_MACOS
    return QString("/private/var/run/tribevpn/%1/wireguard.sock").arg(uid);
#elif defined(Q_OS_WIN)
    Q_UNUSED(uid);
    return QStringLiteral("\\\\.\\pipe\\avpn");
#else
    Q_UNUSED(uid);
    return QStringLiteral("/var/run/avpn/daemon.socket");
#endif
}

inline QString getWireguardDaemonUrl() {
#ifdef Q_OS_MACOS
    return getWireguardDaemonUrl(static_cast<quint32>(::geteuid()));
#else
    return getWireguardDaemonUrl(0);
#endif
}

inline QString getIpcProcessUrl(int pid) {
#ifdef Q_OS_WIN
    return QString("%1_%2").arg(IPC_SERVICE_URL).arg(pid);
#elif defined(Q_OS_MACOS)
    // Production macOS uses createPrivilegedProcessV2 with an unguessable,
    // authenticated endpoint. Predictable legacy child sockets are disabled.
    Q_UNUSED(pid);
    return {};
#else
    return QString("/tmp/%1_%2").arg(IPC_SERVICE_URL).arg(pid);
#endif
}

inline QStringList sanitizeArguments(
        PermittedProcess proc, const QStringList &args,
        quint32 peerUid = std::numeric_limits<quint32>::max()) {
    using Validator = std::function<bool(const QString&)>;
    QMap<QString, Validator> namedArgs;
    QList<Validator> positionalArgs;

    switch (proc) {
    case OpenVPN: {
        namedArgs["--config"] = [peerUid](const QString& value) {
#ifdef Q_OS_MACOS
            const QFileInfo info(value);
            struct stat st {};
            struct stat lst {};
            const QByteArray path = QFile::encodeName(info.absoluteFilePath());
            return peerUid != std::numeric_limits<quint32>::max()
                    && !value.isEmpty() && info.isAbsolute() && info.isFile()
                    && info.canonicalFilePath() == info.absoluteFilePath()
                    && ::lstat(path.constData(), &lst) == 0 && !S_ISLNK(lst.st_mode)
                    && ::stat(path.constData(), &st) == 0 && S_ISREG(st.st_mode)
                    && st.st_uid == peerUid && (st.st_mode & 0077) == 0
                    && st.st_size >= 0 && st.st_size <= 1024 * 1024;
#else
            Q_UNUSED(peerUid);
            return !value.isEmpty();
#endif
        };
        namedArgs["--management"] = [](const QString& value) {
            const QHostAddress address(value);
            return address == QHostAddress::LocalHost
                    || address == QHostAddress::LocalHostIPv6;
        };
        namedArgs["--management-client"] = nullptr;
        positionalArgs.append([](const QString& v) {
            bool ok;
            int port = v.toInt(&ok);
            return ok && port > 0 && port <= 65535;
        });
        break;
    }
    case Tun2Socks:
        namedArgs["-device"] = [](const QString& value) {
            static const QRegularExpression pattern(
                    QStringLiteral(R"(^tun://(?:utun|tun)[0-9]{1,3}$)"));
            return pattern.match(value).hasMatch();
        };
        namedArgs["-proxy"] = [](const QString& value) {
            const QUrl url(value, QUrl::StrictMode);
            return url.isValid() && url.scheme() == QLatin1String("socks5")
                    && url.host() == QLatin1String("127.0.0.1")
                    && url.port() > 0 && url.port() <= 65535
                    && !url.userName().isEmpty() && url.userName().size() <= 128
                    && !url.password().isEmpty() && url.password().size() <= 128
                    && url.path().isEmpty() && !url.hasQuery() && !url.hasFragment();
        };
        break;
    case CertUtil:
#ifdef Q_OS_MACOS
        // No macOS production flow needs a caller-controlled root certutil.
        // Keep the legacy enum for the cross-platform QtRO ABI, but expose no
        // argument surface on Darwin.
        return {};
#else
        return args;
#endif
    default:
        return {};
    }

    QStringList sanitized;

    for (int i = 0, pos = 0; i < args.size(); i++) {
        const auto& key = args[i];

        if (const auto found = namedArgs.find(key); found != namedArgs.end()) {
            const auto validator = found.value();

            if (validator) {
                if (i + 1 < args.size()) {
                    const auto& value = args[i+1];
                    if (validator(value)) {
                        sanitized << key << value;
                        i++;
                    }
                }
            } else {
                sanitized << key;
            }
        } else if (pos < positionalArgs.size()) {
            if (const auto validator = positionalArgs[pos]; validator && validator(key)) {
                sanitized << key;
                pos++;
            }
        }
    }

    return sanitized;
}

} // namespace amnezia

#endif // IPC_H
