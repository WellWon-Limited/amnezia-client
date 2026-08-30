#include "ipcsecurity.h"

#include <QCryptographicHash>
#include <QDeadlineTimer>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QLocalSocket>
#include <QMutex>
#include <QMutexLocker>
#include <QQueue>
#include <QRandomGenerator>
#include <QSet>
#include <QtEndian>

#include <cstring>
#include <limits>

#ifdef Q_OS_MACOS
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <cerrno>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace amnezia::ipcsecurity {
namespace {

void setError(QString *error, const QString &value)
{
    if (error) {
        *error = value;
    }
}

QByteArray canonicalCapability(const QByteArray &bytes)
{
    return bytes.toBase64(QByteArray::Base64UrlEncoding
                          | QByteArray::OmitTrailingEquals);
}

bool exactObjectKeys(const QJsonObject &object, const QSet<QString> &expected)
{
    const QStringList keys = object.keys();
    return QSet<QString>(keys.cbegin(), keys.cend()) == expected;
}

bool exactSchemaOne(const QJsonObject &object)
{
    const QJsonValue value = object.value(QStringLiteral("schema"));
    return value.isDouble() && value.toDouble() == 1.0;
}

bool writeAll(QLocalSocket *socket, const QByteArray &data, int timeoutMs)
{
    if (!socket || data.size() > kMaxHandshakeFrameBytes + 4) {
        return false;
    }
    qint64 offset = 0;
    QDeadlineTimer deadline(timeoutMs);
    while (offset < data.size() && !deadline.hasExpired()) {
        const qint64 written = socket->write(data.constData() + offset,
                                             data.size() - offset);
        if (written < 0) {
            return false;
        }
        offset += written;
        if (socket->bytesToWrite() > 0
                && !socket->waitForBytesWritten(qMax(1, int(deadline.remainingTime())))) {
            return false;
        }
    }
    return offset == data.size();
}

bool writeFrame(QLocalSocket *socket, const QJsonObject &object, int timeoutMs)
{
    const QByteArray payload = QJsonDocument(object).toJson(QJsonDocument::Compact);
    if (payload.isEmpty() || payload.size() > kMaxHandshakeFrameBytes) {
        return false;
    }
    QByteArray frame(4, Qt::Uninitialized);
    qToBigEndian<quint32>(static_cast<quint32>(payload.size()), frame.data());
    frame.append(payload);
    return writeAll(socket, frame, timeoutMs);
}

bool readBytes(QLocalSocket *socket, qsizetype count, QByteArray *output,
               QDeadlineTimer &deadline)
{
    if (!socket || !output || count < 0 || count > kMaxHandshakeFrameBytes) {
        return false;
    }
    output->clear();
    output->reserve(count);
    while (output->size() < count && !deadline.hasExpired()) {
        if (socket->bytesAvailable() == 0
                && !socket->waitForReadyRead(qMax(1, int(deadline.remainingTime())))) {
            return false;
        }
        output->append(socket->read(count - output->size()));
    }
    return output->size() == count;
}

bool readFrame(QLocalSocket *socket, QJsonObject *object, int timeoutMs)
{
    if (!object) {
        return false;
    }
    QDeadlineTimer deadline(timeoutMs);
    QByteArray header;
    if (!readBytes(socket, 4, &header, deadline)) {
        return false;
    }
    const quint32 size = qFromBigEndian<quint32>(header.constData());
    if (!validHandshakeFrameSize(size)) {
        return false;
    }
    QByteArray payload;
    if (!readBytes(socket, size, &payload, deadline)) {
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return false;
    }
    *object = document.object();
    return true;
}

#ifdef Q_OS_MACOS
PathMetadata metadataForPath(const QString &path)
{
    PathMetadata metadata;
    struct stat st {};
    const QByteArray encoded = QFile::encodeName(path);
    if (::lstat(encoded.constData(), &st) != 0) {
        return metadata;
    }
    metadata.exists = true;
    metadata.directory = S_ISDIR(st.st_mode);
    metadata.socket = S_ISSOCK(st.st_mode);
    metadata.symlink = S_ISLNK(st.st_mode);
    metadata.owner = static_cast<quint32>(st.st_uid);
    metadata.mode = static_cast<quint32>(st.st_mode & 07777);
    return metadata;
}

bool createOrValidateDirectory(const QString &path, uid_t owner, mode_t mode,
                               QString *error)
{
    PathMetadata metadata = metadataForPath(path);
    if (!metadata.exists) {
        const QByteArray encoded = QFile::encodeName(path);
        if (::mkdir(encoded.constData(), mode) != 0 && errno != EEXIST) {
            setError(error, QStringLiteral("directory_create_failed"));
            return false;
        }
        if (::chown(encoded.constData(), owner, 0) != 0
                || ::chmod(encoded.constData(), mode) != 0) {
            setError(error, QStringLiteral("directory_permissions_failed"));
            return false;
        }
        metadata = metadataForPath(path);
    }
    return validateDirectoryMetadata(metadata, owner, mode, error);
}

bool signatureEvidenceForPid(pid_t pid, SignatureEvidence *evidence,
                             QString *error)
{
    if (!evidence || pid <= 1) {
        setError(error, QStringLiteral("invalid_peer_pid"));
        return false;
    }
    CFNumberRef pidNumber = CFNumberCreate(kCFAllocatorDefault,
                                           kCFNumberSInt32Type, &pid);
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {pidNumber};
    CFDictionaryRef attributes = CFDictionaryCreate(
            kCFAllocatorDefault, keys, values, 1,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecCodeRef code = nullptr;
    const OSStatus guestStatus = SecCodeCopyGuestWithAttributes(
            nullptr, attributes, kSecCSDefaultFlags, &code);
    CFRelease(attributes);
    CFRelease(pidNumber);
    if (guestStatus != errSecSuccess || !code) {
        setError(error, QStringLiteral("peer_code_lookup_failed"));
        return false;
    }

    CFDictionaryRef signing = nullptr;
    const OSStatus signingStatus = SecCodeCopySigningInformation(
            code, kSecCSSigningInformation, &signing);
    const OSStatus validityStatus = SecCodeCheckValidity(
            code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, nullptr);
    if (signingStatus == errSecSuccess && signing) {
        auto stringValue = [signing](CFStringRef key) -> QString {
            CFTypeRef value = CFDictionaryGetValue(signing, key);
            if (!value || CFGetTypeID(value) != CFStringGetTypeID()) {
                return {};
            }
            const CFStringRef string = static_cast<CFStringRef>(value);
            const CFIndex length = CFStringGetLength(string);
            QByteArray utf8(qMax<CFIndex>(1, CFStringGetMaximumSizeForEncoding(
                    length, kCFStringEncodingUTF8) + 1), '\0');
            if (!CFStringGetCString(string, utf8.data(), utf8.size(),
                                    kCFStringEncodingUTF8)) {
                return {};
            }
            return QString::fromUtf8(utf8.constData());
        };
        evidence->identifier = stringValue(kSecCodeInfoIdentifier);
        evidence->teamIdentifier = stringValue(kSecCodeInfoTeamIdentifier);
    }
    evidence->validityChecked = validityStatus == errSecSuccess;
    if (signing) {
        CFRelease(signing);
    }
    CFRelease(code);

    if (!evidence->validityChecked) {
        setError(error, QStringLiteral("peer_signature_invalid"));
    }
    return evidence->validityChecked;
}
#endif

} // namespace

bool validatePeerPolicy(const PeerIdentity &actual,
                        const SignatureEvidence &signature,
                        const PeerPolicy &policy, QString *error)
{
    if (actual.pid <= 1 || actual.uid != policy.expected.uid
            || actual.gid != policy.expected.gid) {
        setError(error, QStringLiteral("peer_identity_mismatch"));
        return false;
    }
    if (!signature.validityChecked
            || signature.identifier != policy.identifier
            || signature.teamIdentifier != policy.teamIdentifier) {
        setError(error, QStringLiteral("peer_signature_policy_mismatch"));
        return false;
    }
    return true;
}

bool validateDirectoryMetadata(const PathMetadata &metadata, quint32 owner,
                               quint32 mode, QString *error)
{
    if (!metadata.exists || !metadata.directory || metadata.symlink
            || metadata.owner != owner || metadata.mode != mode) {
        setError(error, QStringLiteral("insecure_directory_metadata"));
        return false;
    }
    return true;
}

bool validateSocketMetadata(const PathMetadata &metadata, quint32 owner,
                            quint32 mode, QString *error)
{
    if (!metadata.exists || !metadata.socket || metadata.symlink
            || metadata.owner != owner || metadata.mode != mode) {
        setError(error, QStringLiteral("insecure_socket_metadata"));
        return false;
    }
    return true;
}

QString runtimeDirectory(quint32 uid)
{
#ifdef Q_OS_MACOS
    return QStringLiteral("/private/var/run/tribevpn/%1").arg(uid);
#else
    Q_UNUSED(uid);
    return {};
#endif
}

QString controlSocketPath(quint32 uid)
{
    return runtimeDirectory(uid) + QStringLiteral("/control.sock");
}

QString wireguardSocketPath(quint32 uid)
{
    return runtimeDirectory(uid) + QStringLiteral("/wireguard.sock");
}

bool prepareRuntimeDirectory(quint32 uid, quint32 gid, QString *error)
{
    Q_UNUSED(gid);
#ifdef Q_OS_MACOS
    if (uid == 0 || uid == std::numeric_limits<quint32>::max()) {
        setError(error, QStringLiteral("invalid_runtime_uid"));
        return false;
    }
    if (!createOrValidateDirectory(QStringLiteral("/private/var/run/tribevpn"),
                                   0, 0755, error)) {
        return false;
    }
    return createOrValidateDirectory(runtimeDirectory(uid), 0, 0711, error);
#else
    setError(error, QStringLiteral("secure_runtime_not_supported"));
    return false;
#endif
}

bool removeVerifiedStaleSocket(const QString &path, quint32 owner, QString *error)
{
#ifdef Q_OS_MACOS
    const PathMetadata metadata = metadataForPath(path);
    if (!metadata.exists) {
        return true;
    }
    if (!validateSocketMetadata(metadata, owner, 0600, error)) {
        return false;
    }
    QLocalSocket probe;
    probe.connectToServer(path);
    if (probe.waitForConnected(100)) {
        probe.abort();
        setError(error, QStringLiteral("socket_already_active"));
        return false;
    }
    if (::unlink(QFile::encodeName(path).constData()) != 0) {
        setError(error, QStringLiteral("stale_socket_remove_failed"));
        return false;
    }
    return true;
#else
    Q_UNUSED(path);
    Q_UNUSED(owner);
    return true;
#endif
}

bool secureSocketFile(const QString &path, quint32 owner, quint32 group,
                      QString *error)
{
#ifdef Q_OS_MACOS
    const QByteArray encoded = QFile::encodeName(path);
    if (::lchown(encoded.constData(), owner, group) != 0
            || ::chmod(encoded.constData(), 0600) != 0) {
        setError(error, QStringLiteral("socket_permissions_failed"));
        return false;
    }
    return validateSocketMetadata(metadataForPath(path), owner, 0600, error);
#else
    Q_UNUSED(path);
    Q_UNUSED(owner);
    Q_UNUSED(group);
    return true;
#endif
}

bool consolePeerPolicy(PeerPolicy *policy, QString *error)
{
    if (!policy) {
        return false;
    }
#ifdef Q_OS_MACOS
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    CFStringRef user = SCDynamicStoreCopyConsoleUser(nullptr, &uid, &gid);
    if (user) {
        CFRelease(user);
    }
    if (uid == 0 || uid == static_cast<uid_t>(-1)
            || gid == static_cast<gid_t>(-1)) {
        setError(error, QStringLiteral("console_user_unavailable"));
        return false;
    }
    policy->expected.uid = uid;
    policy->expected.gid = gid;
    policy->expected.pid = -1;
    policy->identifier = QStringLiteral(TRIBE_MAC_GUI_IDENTIFIER);
    policy->teamIdentifier = QStringLiteral(TRIBE_MAC_TEAM_IDENTIFIER);
    if (policy->identifier.isEmpty() || policy->teamIdentifier.isEmpty()) {
        setError(error, QStringLiteral("signature_policy_unconfigured"));
        return false;
    }
    return true;
#else
    setError(error, QStringLiteral("peer_policy_not_supported"));
    return false;
#endif
}

bool authorizeSocket(QLocalSocket *socket, const PeerPolicy &policy,
                     PeerIdentity *identity, QString *error)
{
#ifdef Q_OS_MACOS
    if (!socket || socket->socketDescriptor() < 0) {
        setError(error, QStringLiteral("invalid_socket_descriptor"));
        return false;
    }
    PeerIdentity actual;
    uid_t uid = 0;
    gid_t gid = 0;
    const int fd = static_cast<int>(socket->socketDescriptor());
    if (::getpeereid(fd, &uid, &gid) != 0) {
        setError(error, QStringLiteral("peer_credentials_unavailable"));
        return false;
    }
    pid_t pid = -1;
    socklen_t pidLength = sizeof(pid);
    if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &pidLength) != 0
            || pidLength != sizeof(pid)) {
        setError(error, QStringLiteral("peer_pid_unavailable"));
        return false;
    }
    actual.uid = uid;
    actual.gid = gid;
    actual.pid = pid;
    SignatureEvidence signature;
    if (!signatureEvidenceForPid(pid, &signature, error)
            || !validatePeerPolicy(actual, signature, policy, error)) {
        return false;
    }
    if (identity) {
        *identity = actual;
    }
    return true;
#else
    Q_UNUSED(socket);
    Q_UNUSED(policy);
    Q_UNUSED(identity);
    setError(error, QStringLiteral("peer_authorization_not_supported"));
    return false;
#endif
}

QByteArray randomCapability()
{
    QByteArray bytes(32, Qt::Uninitialized);
    for (qsizetype offset = 0; offset < bytes.size(); offset += sizeof(quint32)) {
        const quint32 value = QRandomGenerator::system()->generate();
        const qsizetype remaining = qMin<qsizetype>(sizeof(value), bytes.size() - offset);
        memcpy(bytes.data() + offset, &value, remaining);
    }
    return canonicalCapability(bytes);
}

bool isCanonicalCapability(const QByteArray &capability)
{
    if (capability.size() != 43 || capability.contains('=')) {
        return false;
    }
    const QByteArray decoded = QByteArray::fromBase64(
            capability, QByteArray::Base64UrlEncoding
                        | QByteArray::AbortOnBase64DecodingErrors);
    return decoded.size() == 32 && canonicalCapability(decoded) == capability;
}

bool constantTimeEqual(const QByteArray &lhs, const QByteArray &rhs)
{
    const qsizetype size = qMax(lhs.size(), rhs.size());
    unsigned char difference = static_cast<unsigned char>(lhs.size() ^ rhs.size());
    for (qsizetype i = 0; i < size; ++i) {
        const unsigned char left = i < lhs.size()
                ? static_cast<unsigned char>(lhs.at(i)) : 0;
        const unsigned char right = i < rhs.size()
                ? static_cast<unsigned char>(rhs.at(i)) : 0;
        difference |= left ^ right;
    }
    return difference == 0;
}

bool validHandshakeFrameSize(quint32 size)
{
    return size > 0 && size <= static_cast<quint32>(kMaxHandshakeFrameBytes);
}

bool validateChallengeResponse(const QJsonObject &response,
                               const QByteArray &challenge,
                               const QByteArray &expectedCapability,
                               QString *error)
{
    static const QSet<QString> withoutCapability{
        QStringLiteral("type"), QStringLiteral("schema"),
        QStringLiteral("challenge"), QStringLiteral("client_nonce")};
    static const QSet<QString> withCapability{
        QStringLiteral("type"), QStringLiteral("schema"),
        QStringLiteral("challenge"), QStringLiteral("client_nonce"),
        QStringLiteral("capability")};
    const QSet<QString> &expectedKeys = expectedCapability.isEmpty()
            ? withoutCapability : withCapability;
    const QByteArray returnedChallenge = response.value(QStringLiteral("challenge"))
            .toString().toLatin1();
    const QByteArray clientNonce = response.value(QStringLiteral("client_nonce"))
            .toString().toLatin1();
    const QByteArray capability = response.value(QStringLiteral("capability"))
            .toString().toLatin1();
    const bool capabilityValid = expectedCapability.isEmpty()
            ? capability.isEmpty()
            : isCanonicalCapability(capability)
              && constantTimeEqual(capability, expectedCapability);
    if (response.value(QStringLiteral("type")).toString()
                != QLatin1String("tribe_ipc_response_v1")
            || !exactObjectKeys(response, expectedKeys)
            || !exactSchemaOne(response)
            || !isCanonicalCapability(challenge)
            || !constantTimeEqual(returnedChallenge, challenge)
            || !isCanonicalCapability(clientNonce)
            || !capabilityValid) {
        setError(error, QStringLiteral("challenge_response_invalid"));
        return false;
    }
    const QByteArray replayKey = QCryptographicHash::hash(
            challenge + '\0' + clientNonce + '\0' + capability,
            QCryptographicHash::Sha256);
    static QMutex replayMutex;
    static QSet<QByteArray> replaySet;
    static QQueue<QByteArray> replayOrder;
    QMutexLocker locker(&replayMutex);
    if (replaySet.contains(replayKey)) {
        setError(error, QStringLiteral("challenge_response_replayed"));
        return false;
    }
    replaySet.insert(replayKey);
    replayOrder.enqueue(replayKey);
    while (replayOrder.size() > 1024) {
        replaySet.remove(replayOrder.dequeue());
    }
    return true;
}

bool performServerHandshake(QLocalSocket *socket,
                            const QByteArray &expectedCapability,
                            QByteArray *sessionCapability, QString *error)
{
    if (!socket || (sessionCapability == nullptr)
            || (!expectedCapability.isEmpty()
                && !isCanonicalCapability(expectedCapability))) {
        setError(error, QStringLiteral("handshake_arguments_invalid"));
        return false;
    }
    const QByteArray challenge = randomCapability();
    if (!writeFrame(socket, {{QStringLiteral("type"),
                              QStringLiteral("tribe_ipc_challenge_v1")},
                             {QStringLiteral("schema"), 1},
                             {QStringLiteral("challenge"),
                              QString::fromLatin1(challenge)}}, 1500)) {
        setError(error, QStringLiteral("challenge_write_failed"));
        return false;
    }
    QJsonObject response;
    if (!readFrame(socket, &response, 1500)
            || !validateChallengeResponse(response, challenge,
                                          expectedCapability, error)) {
        return false;
    }
    const QByteArray issued = randomCapability();
    if (!writeFrame(socket, {{QStringLiteral("type"),
                              QStringLiteral("tribe_ipc_accepted_v1")},
                             {QStringLiteral("schema"), 1},
                             {QStringLiteral("session_capability"),
                              QString::fromLatin1(issued)}}, 1500)) {
        setError(error, QStringLiteral("accept_write_failed"));
        return false;
    }
    *sessionCapability = issued;
    return true;
}

bool performClientHandshake(QLocalSocket *socket, const QByteArray &capability,
                            QByteArray *sessionCapability, QString *error)
{
    if (!socket || !sessionCapability
            || (!capability.isEmpty() && !isCanonicalCapability(capability))) {
        setError(error, QStringLiteral("handshake_arguments_invalid"));
        return false;
    }
    QJsonObject challengeObject;
    if (!readFrame(socket, &challengeObject, 1500)
            || !exactObjectKeys(challengeObject, {
                    QStringLiteral("type"), QStringLiteral("schema"),
                    QStringLiteral("challenge")})
            || challengeObject.value(QStringLiteral("type")).toString()
                != QLatin1String("tribe_ipc_challenge_v1")
            || !exactSchemaOne(challengeObject)) {
        setError(error, QStringLiteral("challenge_read_failed"));
        return false;
    }
    const QByteArray challenge = challengeObject.value(QStringLiteral("challenge"))
            .toString().toLatin1();
    if (!isCanonicalCapability(challenge)) {
        setError(error, QStringLiteral("challenge_invalid"));
        return false;
    }
    QJsonObject response{{QStringLiteral("type"),
                          QStringLiteral("tribe_ipc_response_v1")},
                         {QStringLiteral("schema"), 1},
                         {QStringLiteral("challenge"), QString::fromLatin1(challenge)},
                         {QStringLiteral("client_nonce"),
                          QString::fromLatin1(randomCapability())}};
    if (!capability.isEmpty()) {
        response.insert(QStringLiteral("capability"),
                        QString::fromLatin1(capability));
    }
    if (!writeFrame(socket, response, 1500)) {
        setError(error, QStringLiteral("response_write_failed"));
        return false;
    }
    QJsonObject accepted;
    if (!readFrame(socket, &accepted, 1500)
            || !exactObjectKeys(accepted, {
                    QStringLiteral("type"), QStringLiteral("schema"),
                    QStringLiteral("session_capability")})
            || accepted.value(QStringLiteral("type")).toString()
                != QLatin1String("tribe_ipc_accepted_v1")
            || !exactSchemaOne(accepted)) {
        setError(error, QStringLiteral("accept_read_failed"));
        return false;
    }
    const QByteArray issued = accepted.value(QStringLiteral("session_capability"))
            .toString().toLatin1();
    if (!isCanonicalCapability(issued)) {
        setError(error, QStringLiteral("session_capability_invalid"));
        return false;
    }
    *sessionCapability = issued;
    return true;
}

} // namespace amnezia::ipcsecurity
