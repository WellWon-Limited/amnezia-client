#ifndef IPCSECURITY_H
#define IPCSECURITY_H

#include <QByteArray>
#include <QJsonObject>
#include <QString>

class QLocalSocket;

namespace amnezia::ipcsecurity {

constexpr qsizetype kMaxHandshakeFrameBytes = 4096;
constexpr qsizetype kMaxQtRoReadBufferBytes = 1024 * 1024;
constexpr qsizetype kMaxDaemonCommandBytes = 512 * 1024;

struct PeerIdentity {
    quint32 uid = 0;
    quint32 gid = 0;
    qint64 pid = -1;
};

struct SignatureEvidence {
    QString identifier;
    QString teamIdentifier;
    bool validityChecked = false;
};

struct PeerPolicy {
    PeerIdentity expected;
    QString identifier;
    QString teamIdentifier;
};

struct PathMetadata {
    bool exists = false;
    bool directory = false;
    bool socket = false;
    bool symlink = false;
    quint32 owner = 0;
    quint32 mode = 0;
};

bool validatePeerPolicy(const PeerIdentity &actual,
                        const SignatureEvidence &signature,
                        const PeerPolicy &policy,
                        QString *error = nullptr);
bool validateDirectoryMetadata(const PathMetadata &metadata, quint32 owner,
                               quint32 mode, QString *error = nullptr);
bool validateSocketMetadata(const PathMetadata &metadata, quint32 owner,
                            quint32 mode, QString *error = nullptr);

QString runtimeDirectory(quint32 uid);
QString controlSocketPath(quint32 uid);
QString wireguardSocketPath(quint32 uid);
bool prepareRuntimeDirectory(quint32 uid, quint32 gid, QString *error = nullptr);
bool removeVerifiedStaleSocket(const QString &path, quint32 owner,
                               QString *error = nullptr);
bool secureSocketFile(const QString &path, quint32 owner, quint32 group,
                      QString *error = nullptr);

bool consolePeerPolicy(PeerPolicy *policy, QString *error = nullptr);
bool authorizeSocket(QLocalSocket *socket, const PeerPolicy &policy,
                     PeerIdentity *identity = nullptr, QString *error = nullptr);

QByteArray randomCapability();
bool isCanonicalCapability(const QByteArray &capability);
bool constantTimeEqual(const QByteArray &lhs, const QByteArray &rhs);
bool validHandshakeFrameSize(quint32 size);
bool validateChallengeResponse(const QJsonObject &response,
                               const QByteArray &challenge,
                               const QByteArray &expectedCapability,
                               QString *error = nullptr);
bool performServerHandshake(QLocalSocket *socket,
                            const QByteArray &expectedCapability,
                            QByteArray *sessionCapability,
                            QString *error = nullptr);
bool performClientHandshake(QLocalSocket *socket,
                            const QByteArray &capability,
                            QByteArray *sessionCapability,
                            QString *error = nullptr);

} // namespace amnezia::ipcsecurity

#endif // IPCSECURITY_H
