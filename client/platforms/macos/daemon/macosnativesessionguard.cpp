#include "macosnativesessionguard.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QSet>
#include <QTimer>
#include <QUuid>

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

struct MacosNativeSessionGuard::DefaultAuthorityWatchdog
{
    QElapsedTimer monotonic;
    QTimer timer;
    std::function<void()> callback;
};

struct MacosNativeSessionGuard::WatchdogLifetime
{
    QMutex mutex;
    MacosNativeSessionGuard *owner = nullptr;
};

namespace {

constexpr qsizetype kMaximumConfigBytes = 512 * 1024;
constexpr qsizetype kMaximumProjectionBytes = 512 * 1024;
constexpr qsizetype kMaximumLeaseBytes = 128 * 1024;

const QSet<QString> kAuthorityKeys{
    QStringLiteral("schema_version"), QStringLiteral("device_audience"),
    QStringLiteral("catalog_revision"), QStringLiteral("catalog_payload_sha256"),
    QStringLiteral("catalog_signing_kid"), QStringLiteral("catalog_source"),
    QStringLiteral("profile_id"), QStringLiteral("transport"),
    QStringLiteral("config_generation"), QStringLiteral("binding_generation"),
    QStringLiteral("native_profile_expires_at"),
    QStringLiteral("catalog_freshness_deadline"), QStringLiteral("entitlement_deadline"),
    QStringLiteral("catalog_issued_at"), QStringLiteral("trusted_utc_at_dispatch"),
    QStringLiteral("policy_schema"), QStringLiteral("policy_sha256"),
    QStringLiteral("protected_tunnel_ips"),
    QStringLiteral("receiver_monotonic_policy"),
};

bool exactKeys(const QJsonObject &object, const QSet<QString> &expected)
{
    const QStringList keys = object.keys();
    return QSet<QString>(keys.cbegin(), keys.cend()) == expected;
}

bool canonicalDecimal(const QJsonValue &value, bool allowZero, QString *text = nullptr)
{
    if (!value.isString()) return false;
    const QString candidate = value.toString();
    if (candidate.isEmpty() || candidate.size() > 20
        || (candidate.size() > 1 && candidate.startsWith(QLatin1Char('0')))
        || (!allowZero && candidate == QLatin1String("0"))) return false;
    for (const QChar ch : candidate)
        if (ch < QLatin1Char('0') || ch > QLatin1Char('9')) return false;
    bool ok = false;
    const quint64 parsed = candidate.toULongLong(&ok, 10);
    if (!ok || QString::number(parsed) != candidate) return false;
    if (text) *text = candidate;
    return true;
}

bool canonicalInteger(const QJsonValue &value, qint64 minimum, qint64 maximum,
                      QString &text)
{
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || std::floor(number) != number
        || number < double(minimum) || number > double(maximum)) return false;
    const qint64 integer = qint64(number);
    if (double(integer) != number) return false;
    text = QString::number(integer);
    return true;
}

bool asciiIdentifier(const QString &value, int maximum, bool colon)
{
    if (value.isEmpty() || value.size() > maximum) return false;
    for (const QChar ch : value) {
        const ushort c = ch.unicode();
        const bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        const bool digit = c >= '0' && c <= '9';
        if (!alpha && !digit && c != '-' && c != '_' && c != '.'
            && (!colon || c != ':')) return false;
    }
    return true;
}

bool lowerSha256(const QJsonValue &value, QString *text = nullptr)
{
    if (!value.isString()) return false;
    const QString candidate = value.toString();
    if (candidate.size() != 64) return false;
    for (const QChar ch : candidate)
        if (!((ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
              || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f')))) return false;
    if (text) *text = candidate;
    return true;
}

bool canonicalUuid(const QJsonValue &value, QString *text = nullptr)
{
    if (!value.isString()) return false;
    const QString candidate = value.toString();
    const QUuid parsed(candidate);
    if (parsed.isNull()
        || parsed.toString(QUuid::WithoutBraces).toLower() != candidate) return false;
    if (text) *text = candidate;
    return true;
}

bool strictString(const QJsonObject &object, const QString &key, QString &value,
                  bool optional = false)
{
    const QJsonValue candidate = object.value(key);
    if (candidate.isUndefined() && optional) {
        value.clear();
        return true;
    }
    if (!candidate.isString()) return false;
    value = candidate.toString();
    return !value.contains(QChar::Null) && value.toUtf8().size() <= 256 * 1024;
}

bool stringList(const QJsonObject &object, const QString &key, QStringList &values,
                bool optional = false)
{
    values.clear();
    const QJsonValue candidate = object.value(key);
    if (candidate.isUndefined() && optional) return true;
    if (!candidate.isArray()) return false;
    const QJsonArray array = candidate.toArray();
    if (array.size() > 16'384) return false;
    for (const QJsonValue &item : array) {
        if (!item.isString() || item.toString().contains(QChar::Null)
            || item.toString().toUtf8().size() > 256 * 1024) return false;
        values.append(item.toString());
    }
    return true;
}

bool appendRecord(QByteArray &bytes, const QByteArray &name, const QString &value)
{
    const QByteArray encoded = value.toUtf8();
    if (value.contains(QChar::Null) || encoded.size() > 256 * 1024) return false;
    bytes += name;
    bytes += ':';
    bytes += QByteArray::number(encoded.size());
    bytes += ':';
    bytes += encoded;
    bytes += '\n';
    return bytes.size() <= kMaximumProjectionBytes;
}

bool appendList(QByteArray &bytes, const QByteArray &name, QStringList values)
{
    std::sort(values.begin(), values.end(), [](const QString &left, const QString &right) {
        return left.toUtf8() < right.toUtf8();
    });
    if (!appendRecord(bytes, name + "_count", QString::number(values.size()))) return false;
    for (int index = 0; index < values.size(); ++index)
        if (!appendRecord(bytes, name + '_' + QByteArray::number(index), values.at(index)))
            return false;
    return true;
}

bool publicLiteral(const QString &value)
{
    QHostAddress address;
    return address.setAddress(value) && address.toString() == value && address.isGlobal();
}

bool validUtc(const QJsonValue &value, QDateTime &date)
{
    if (!value.isString()) return false;
    static const QRegularExpression form(
        QStringLiteral(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$)"));
    const QString text = value.toString();
    if (!form.match(text).hasMatch()) return false;
    date = QDateTime::fromString(text, Qt::ISODateWithMs);
    if (!date.isValid()) date = QDateTime::fromString(text, Qt::ISODate);
    return date.isValid() && date.timeSpec() == Qt::UTC;
}

bool canonicalAudience(const QJsonValue &value)
{
    if (!value.isString() || value.toString().size() != 43) return false;
    const QString candidate = value.toString();
    for (const QChar ch : candidate) {
        const ushort c = ch.unicode();
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    const QByteArray encoded = candidate.toLatin1();
    const QByteArray decoded = QByteArray::fromBase64(
        encoded, QByteArray::Base64UrlEncoding
                     | QByteArray::AbortOnBase64DecodingErrors);
    return decoded.size() == 32
        && decoded.toBase64(QByteArray::Base64UrlEncoding
                            | QByteArray::OmitTrailingEquals) == encoded;
}

bool validAuthorityObject(const QJsonObject &authority, QString &transport,
                          QString &policySha256, QDateTime *hardDeadline,
                          QString &error)
{
    transport.clear();
    policySha256.clear();
    if (!exactKeys(authority, kAuthorityKeys)) {
        error = QStringLiteral("runtime_authority_shape_rejected");
        return false;
    }
    QString schema;
    if (!canonicalInteger(authority.value(QStringLiteral("schema_version")), 1, 1,
                          schema)
        || authority.value(QStringLiteral("policy_schema"))
               != QLatin1String("native_dispatch_policy_v1")
        || authority.value(QStringLiteral("receiver_monotonic_policy"))
               != QLatin1String("anchor_on_validated_dispatch_v1")
        || !authority.value(QStringLiteral("transport")).isString()) {
        error = QStringLiteral("runtime_authority_shape_rejected");
        return false;
    }
    transport = authority.value(QStringLiteral("transport")).toString();
    if ((transport != QLatin1String("awg") && transport != QLatin1String("xray"))
        || !lowerSha256(authority.value(QStringLiteral("policy_sha256")),
                        &policySha256)
        || !lowerSha256(authority.value(QStringLiteral("catalog_payload_sha256")))
        || !asciiIdentifier(authority.value(QStringLiteral("profile_id")).toString(),
                            96, false)
        || !asciiIdentifier(authority.value(QStringLiteral("catalog_signing_kid")).toString(),
                            96, false)
        || !canonicalDecimal(authority.value(QStringLiteral("catalog_revision")), false)
        || !canonicalDecimal(authority.value(QStringLiteral("config_generation")), false)
        || !canonicalDecimal(authority.value(QStringLiteral("binding_generation")), false)) {
        error = QStringLiteral("runtime_authority_identity_rejected");
        return false;
    }
    const QString source = authority.value(QStringLiteral("catalog_source")).toString();
    if ((source != QLatin1String("network") && source != QLatin1String("lkg"))
        || !canonicalAudience(authority.value(QStringLiteral("device_audience")))) {
        error = QStringLiteral("runtime_authority_source_rejected");
        return false;
    }
    QDateTime profileExpiry, freshness, entitlement, issued, trusted;
    if (!validUtc(authority.value(QStringLiteral("native_profile_expires_at")), profileExpiry)
        || !validUtc(authority.value(QStringLiteral("catalog_freshness_deadline")), freshness)
        || !validUtc(authority.value(QStringLiteral("entitlement_deadline")), entitlement)
        || !validUtc(authority.value(QStringLiteral("catalog_issued_at")), issued)
        || !validUtc(authority.value(QStringLiteral("trusted_utc_at_dispatch")), trusted)) {
        error = QStringLiteral("runtime_authority_deadline_rejected");
        return false;
    }
    const QDateTime deadline = std::min({profileExpiry, freshness, entitlement});
    if (trusted >= deadline || issued > trusted.addSecs(300)) {
        error = QStringLiteral("runtime_authority_expired_or_clock_rejected");
        return false;
    }
    const QJsonValue protectedValue = authority.value(QStringLiteral("protected_tunnel_ips"));
    if (!protectedValue.isArray() || protectedValue.toArray().isEmpty()
        || protectedValue.toArray().size() > 64) {
        error = QStringLiteral("protected_tunnel_ips_rejected");
        return false;
    }
    QSet<QString> protectedIps;
    bool hasPublicIpv4 = false;
    for (const QJsonValue &value : protectedValue.toArray()) {
        if (!value.isString() || !publicLiteral(value.toString())
            || protectedIps.contains(value.toString())) {
            error = QStringLiteral("protected_tunnel_ip_nonpublic_or_duplicate");
            return false;
        }
        protectedIps.insert(value.toString());
        QHostAddress address;
        if (address.setAddress(value.toString())
            && address.protocol() == QAbstractSocket::IPv4Protocol)
            hasPublicIpv4 = true;
    }
    if (!hasPublicIpv4) {
        error = QStringLiteral("protected_tunnel_ipv4_required");
        return false;
    }
    if (hardDeadline) *hardDeadline = deadline;
    return true;
}

bool nativeEndpoint(const QString &transport, const QJsonObject &native,
                    const QString &nativeConfig, QString &host, QString &port)
{
    if (transport == QLatin1String("awg"))
        return strictString(native, QStringLiteral("hostName"), host)
               && canonicalInteger(native.value(QStringLiteral("port")), 1, 65535, port);
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(nativeConfig.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
    const QJsonArray outbounds = document.object().value(QStringLiteral("outbounds")).toArray();
    if (outbounds.size() != 1 || !outbounds.first().isObject()) return false;
    const QJsonObject settings = outbounds.first().toObject()
                                     .value(QStringLiteral("settings")).toObject();
    return strictString(settings, QStringLiteral("address"), host)
           && canonicalInteger(settings.value(QStringLiteral("port")), 1, 65535, port);
}

bool secureLeaseDirectory(const QString &path, int &directoryFd, QByteArray &fileName,
                          QString &error)
{
    directoryFd = -1;
    const QFileInfo info(path);
    const QString directoryPath = info.absolutePath();
    fileName = info.fileName().toUtf8();
    if (!info.isAbsolute() || fileName.isEmpty() || fileName.contains('/')
        || fileName == "." || fileName == "..") {
        error = QStringLiteral("lease_path_rejected");
        return false;
    }
    const QByteArray encodedDirectory = QFile::encodeName(directoryPath);
    struct stat status {};
    if (::lstat(encodedDirectory.constData(), &status) != 0) {
        if (errno != ENOENT || ::mkdir(encodedDirectory.constData(), 0700) != 0) {
            error = QStringLiteral("lease_directory_create_failed");
            return false;
        }
        if (::lstat(encodedDirectory.constData(), &status) != 0) {
            error = QStringLiteral("lease_directory_stat_failed");
            return false;
        }
    }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)
        || status.st_uid != ::geteuid() || (status.st_mode & 0077) != 0) {
        error = QStringLiteral("lease_directory_owner_or_mode_rejected");
        return false;
    }
    directoryFd = ::open(encodedDirectory.constData(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW
                                                  | O_CLOEXEC);
    if (directoryFd < 0) {
        error = QStringLiteral("lease_directory_open_failed");
        return false;
    }
    struct stat opened {};
    if (::fstat(directoryFd, &opened) != 0 || !S_ISDIR(opened.st_mode)
        || opened.st_dev != status.st_dev || opened.st_ino != status.st_ino
        || opened.st_uid != ::geteuid() || (opened.st_mode & 0077) != 0) {
        ::close(directoryFd);
        directoryFd = -1;
        error = QStringLiteral("lease_directory_race_rejected");
        return false;
    }
    return true;
}

bool durableWriteLease(const QString &path, const QByteArray &bytes, QString &error)
{
    if (bytes.isEmpty() || bytes.size() > kMaximumLeaseBytes) {
        error = QStringLiteral("lease_bytes_rejected");
        return false;
    }
    int directoryFd = -1;
    QByteArray fileName;
    if (!secureLeaseDirectory(path, directoryFd, fileName, error)) return false;
    const QByteArray temporary = fileName + ".tmp."
        + QUuid::createUuid().toString(QUuid::WithoutBraces).toLatin1();
    const int descriptor = ::openat(directoryFd, temporary.constData(),
                                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                                    0600);
    if (descriptor < 0) {
        ::close(directoryFd);
        error = QStringLiteral("lease_temporary_open_failed");
        return false;
    }
    bool success = true;
    qsizetype offset = 0;
    while (offset < bytes.size()) {
        const ssize_t written = ::write(descriptor, bytes.constData() + offset,
                                        size_t(bytes.size() - offset));
        if (written <= 0) { success = false; break; }
        offset += written;
    }
    struct stat status {};
    success = success && ::fsync(descriptor) == 0 && ::fstat(descriptor, &status) == 0
        && S_ISREG(status.st_mode) && status.st_uid == ::geteuid()
        && (status.st_mode & 0777) == 0600 && status.st_nlink == 1
        && status.st_size == bytes.size();
    ::close(descriptor);
    if (success)
        success = ::renameat(directoryFd, temporary.constData(),
                             directoryFd, fileName.constData()) == 0
                  && ::fsync(directoryFd) == 0;
    if (!success) ::unlinkat(directoryFd, temporary.constData(), 0);
    ::close(directoryFd);
    if (!success) error = QStringLiteral("lease_atomic_write_failed");
    return success;
}

bool secureReadLease(const QString &path, QByteArray &bytes, QString &error)
{
    bytes.clear();
    int directoryFd = -1;
    QByteArray fileName;
    if (!secureLeaseDirectory(path, directoryFd, fileName, error)) return false;
    const int descriptor = ::openat(directoryFd, fileName.constData(),
                                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        ::close(directoryFd);
        error = errno == ENOENT ? QStringLiteral("lease_missing")
                                : QStringLiteral("lease_open_failed");
        return false;
    }
    struct stat status {};
    bool success = ::fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode)
        && status.st_uid == ::geteuid() && (status.st_mode & 0777) == 0600
        && status.st_nlink == 1 && status.st_size > 0
        && status.st_size <= kMaximumLeaseBytes;
    if (success) {
        bytes.resize(qsizetype(status.st_size));
        qsizetype offset = 0;
        while (offset < bytes.size()) {
            const ssize_t count = ::read(descriptor, bytes.data() + offset,
                                         size_t(bytes.size() - offset));
            if (count <= 0) { success = false; break; }
            offset += count;
        }
    }
    ::close(descriptor);
    ::close(directoryFd);
    if (!success) {
        bytes.fill(0);
        bytes.clear();
        error = QStringLiteral("lease_file_rejected");
    }
    return success;
}

bool durableRemoveLease(const QString &path, QString &error)
{
    int directoryFd = -1;
    QByteArray fileName;
    if (!secureLeaseDirectory(path, directoryFd, fileName, error)) return false;
    const bool success = (::unlinkat(directoryFd, fileName.constData(), 0) == 0
                          || errno == ENOENT) && ::fsync(directoryFd) == 0;
    ::close(directoryFd);
    if (!success) error = QStringLiteral("lease_remove_failed");
    return success;
}

bool authorityAndPolicy(const QJsonObject &configuration, QString &transport,
                        QJsonObject &authority, QString &digest, QString &error)
{
    if (configuration.value(QStringLiteral("native_envelope_schema"))
            != QLatin1String("tribe_catalog_v2_native_v1")
        || !configuration.value(QStringLiteral("runtime_authority_v1")).isObject()) {
        error = QStringLiteral("catalog_v2_envelope_required");
        return false;
    }
    authority = configuration.value(QStringLiteral("runtime_authority_v1")).toObject();
    if (!validAuthorityObject(authority, transport, digest, nullptr, error)) return false;
    if (configuration.value(QStringLiteral("protocol")).toString() != transport) {
        error = QStringLiteral("runtime_authority_protocol_mismatch");
        return false;
    }
    return true;
}

bool authorityObjectUsableAt(const QJsonObject &authority, const QDateTime &nowUtc,
                             QString &error)
{
    QDateTime profileExpiry, freshness, entitlement, issued, trusted;
    if (!validUtc(authority.value(QStringLiteral("native_profile_expires_at")), profileExpiry)
        || !validUtc(authority.value(QStringLiteral("catalog_freshness_deadline")), freshness)
        || !validUtc(authority.value(QStringLiteral("entitlement_deadline")), entitlement)
        || !validUtc(authority.value(QStringLiteral("catalog_issued_at")), issued)
        || !validUtc(authority.value(QStringLiteral("trusted_utc_at_dispatch")), trusted)) {
        error = QStringLiteral("runtime_authority_deadline_rejected");
        return false;
    }
    const QDateTime deadline = std::min({profileExpiry, freshness, entitlement});
    const QDateTime now = nowUtc.toUTC();
    if (!now.isValid()) {
        error = QStringLiteral("runtime_authority_clock_unavailable");
        return false;
    }
    if (now >= deadline || now < issued.addSecs(-300) || now < trusted.addSecs(-300)) {
        error = QStringLiteral("runtime_authority_expired_or_clock_rejected");
        return false;
    }
    return true;
}

bool authorityUsableAt(const QJsonObject &configuration, const QDateTime &nowUtc,
                       QString &error)
{
    return authorityObjectUsableAt(
        configuration.value(QStringLiteral("runtime_authority_v1")).toObject(),
        nowUtc, error);
}

bool authorityUsableNow(const QJsonObject &configuration, QString &error)
{
    return authorityUsableAt(configuration, QDateTime::currentDateTimeUtc(), error);
}

QString compactSha256(QJsonObject object)
{
    return QString::fromLatin1(QCryptographicHash::hash(
        QJsonDocument(object).toJson(QJsonDocument::Compact),
        QCryptographicHash::Sha256).toHex());
}

QString nonAuthorityConfigurationCommitment(QJsonObject configuration)
{
    configuration.remove(QStringLiteral("runtime_authority_v1"));
    return compactSha256(std::move(configuration));
}

QString authorityHardDeadlineText(const QJsonObject &authority)
{
    QDateTime profile, freshness, entitlement;
    if (!validUtc(authority.value(QStringLiteral("native_profile_expires_at")), profile)
        || !validUtc(authority.value(QStringLiteral("catalog_freshness_deadline")), freshness)
        || !validUtc(authority.value(QStringLiteral("entitlement_deadline")), entitlement))
        return {};
    return std::min({profile, freshness, entitlement})
        .toUTC().toString(Qt::ISODateWithMs);
}

bool acceptsAuthorityRenewal(const QJsonObject &current, const QJsonObject &next)
{
    if (!exactKeys(current, kAuthorityKeys) || !exactKeys(next, kAuthorityKeys)) return false;
    for (const QString &field : {
             QStringLiteral("device_audience"), QStringLiteral("profile_id"),
             QStringLiteral("transport"), QStringLiteral("config_generation"),
             QStringLiteral("binding_generation"), QStringLiteral("policy_schema"),
             QStringLiteral("policy_sha256"), QStringLiteral("receiver_monotonic_policy")}) {
        if (current.value(field) != next.value(field)) return false;
    }
    if (current.value(QStringLiteral("protected_tunnel_ips"))
        != next.value(QStringLiteral("protected_tunnel_ips"))) return false;
    QString currentRevisionText, nextRevisionText;
    if (!canonicalDecimal(current.value(QStringLiteral("catalog_revision")), false,
                          &currentRevisionText)
        || !canonicalDecimal(next.value(QStringLiteral("catalog_revision")), false,
                             &nextRevisionText)) return false;
    bool currentOk = false, nextOk = false;
    const quint64 currentRevision = currentRevisionText.toULongLong(&currentOk);
    const quint64 nextRevision = nextRevisionText.toULongLong(&nextOk);
    if (!currentOk || !nextOk || nextRevision < currentRevision) return false;
    if (nextRevision == currentRevision
        && (current.value(QStringLiteral("catalog_payload_sha256"))
                != next.value(QStringLiteral("catalog_payload_sha256"))
            || current.value(QStringLiteral("catalog_signing_kid"))
                != next.value(QStringLiteral("catalog_signing_kid")))) return false;
    QDateTime currentIssued, nextIssued, currentTrusted, nextTrusted;
    return validUtc(current.value(QStringLiteral("catalog_issued_at")), currentIssued)
        && validUtc(next.value(QStringLiteral("catalog_issued_at")), nextIssued)
        && validUtc(current.value(QStringLiteral("trusted_utc_at_dispatch")), currentTrusted)
        && validUtc(next.value(QStringLiteral("trusted_utc_at_dispatch")), nextTrusted)
        && nextIssued >= currentIssued && nextTrusted >= currentTrusted;
}

} // namespace

MacosNativeSessionGuard::MacosNativeSessionGuard(
    Backend backend, QString leasePath, AuthorityWatchdog watchdog)
    : m_backend(std::move(backend)), m_leasePath(std::move(leasePath)),
      m_watchdog(std::move(watchdog)),
      m_watchdogLifetime(std::make_shared<WatchdogLifetime>())
{
    m_watchdogLifetime->owner = this;
    if (!m_watchdog.isComplete()) {
        m_defaultWatchdog = std::make_unique<DefaultAuthorityWatchdog>();
        DefaultAuthorityWatchdog *const runtime = m_defaultWatchdog.get();
        runtime->monotonic.start();
        runtime->timer.setSingleShot(true);
        runtime->timer.setTimerType(Qt::PreciseTimer);
        QObject::connect(&runtime->timer, &QTimer::timeout, &runtime->timer,
                         [runtime]() {
            std::function<void()> callback = std::move(runtime->callback);
            runtime->callback = {};
            if (callback) callback();
        });
        m_watchdog.wallUtcNow = []() { return QDateTime::currentDateTimeUtc(); };
        m_watchdog.monotonicMilliseconds = [runtime]() {
            return runtime->monotonic.isValid() ? runtime->monotonic.elapsed() : qint64(-1);
        };
        m_watchdog.scheduleOnce = [runtime](qint64 delayMs,
                                            std::function<void()> callback) {
            if (delayMs <= 0 || delayMs > std::numeric_limits<int>::max()
                || !callback) return false;
            runtime->timer.stop();
            runtime->callback = std::move(callback);
            runtime->timer.start(int(delayMs));
            return runtime->timer.isActive();
        };
        m_watchdog.cancel = [runtime]() {
            runtime->timer.stop();
            runtime->callback = {};
        };
    }
}

MacosNativeSessionGuard::~MacosNativeSessionGuard()
{
    // Wait for an already-entered callback, then prevent every stale scheduler closure from ever
    // acquiring `this`. This also makes an injected scheduler safe to destroy after the guard.
    if (m_watchdogLifetime) {
        QMutexLocker lifetimeLock(&m_watchdogLifetime->mutex);
        m_watchdogLifetime->owner = nullptr;
    }
    QMutexLocker lock(&m_mutex);
    cancelAuthorityWatchdogLocked();
}

bool MacosNativeSessionGuard::scheduleAuthorityWatchdogTickLocked(
    quint64 generation, qint64 delayMs, QString &error)
{
    if (!m_watchdogArmed || generation == 0 || generation != m_watchdogGeneration
        || delayMs <= 0 || !m_watchdog.scheduleOnce || !m_watchdogLifetime) {
        error = QStringLiteral("authority_watchdog_state_rejected");
        return false;
    }
    const std::shared_ptr<WatchdogLifetime> lifetime = m_watchdogLifetime;
    const bool scheduled = m_watchdog.scheduleOnce(
        delayMs, [lifetime, generation]() {
            QMutexLocker lifetimeLock(&lifetime->mutex);
            if (lifetime->owner)
                lifetime->owner->authorityWatchdogFired(generation);
        });
    if (!scheduled) error = QStringLiteral("authority_watchdog_schedule_failed");
    return scheduled;
}

void MacosNativeSessionGuard::cancelAuthorityWatchdogLocked()
{
    ++m_watchdogGeneration;
    if (m_watchdogGeneration == 0) ++m_watchdogGeneration;
    m_watchdogArmed = false;
    m_watchdogTrustedUtc = {};
    m_watchdogHardDeadlineUtc = {};
    m_watchdogMonotonicAnchorMs = 0;
    m_watchdogDeadlineMonotonicMs = 0;
    if (m_watchdog.cancel) m_watchdog.cancel();
}

bool MacosNativeSessionGuard::armAuthorityWatchdogLocked(
    const QJsonObject &authority, QString &error)
{
    error.clear();
    QString transport, policy;
    QDateTime hardDeadline, trusted;
    if (!validAuthorityObject(authority, transport, policy, &hardDeadline, error)
        || !validUtc(authority.value(QStringLiteral("trusted_utc_at_dispatch")), trusted))
        return false;
    const QDateTime wallNow = m_watchdog.wallUtcNow
        ? m_watchdog.wallUtcNow().toUTC() : QDateTime{};
    const qint64 monotonicNow = m_watchdog.monotonicMilliseconds
        ? m_watchdog.monotonicMilliseconds() : qint64(-1);
    if (!wallNow.isValid() || monotonicNow < 0
        || wallNow < trusted.addSecs(-300)) {
        error = QStringLiteral("authority_watchdog_clock_rejected");
        return false;
    }
    const QDateTime effectiveNow = wallNow > trusted ? wallNow : trusted;
    const qint64 remainingMs = effectiveNow.msecsTo(hardDeadline);
    if (remainingMs <= 0
        || monotonicNow > std::numeric_limits<qint64>::max() - remainingMs) {
        error = QStringLiteral("authority_watchdog_deadline_expired");
        return false;
    }

    cancelAuthorityWatchdogLocked();
    m_watchdogTrustedUtc = trusted;
    m_watchdogHardDeadlineUtc = hardDeadline;
    m_watchdogMonotonicAnchorMs = monotonicNow;
    m_watchdogDeadlineMonotonicMs = monotonicNow + remainingMs;
    m_watchdogArmed = true;
    const quint64 generation = m_watchdogGeneration;
    // Periodic wall checks catch a forward correction quickly; the final tick is always scheduled
    // exactly at the monotonic hard boundary, so wall rollback can never extend authority.
    const qint64 delayMs = qMax<qint64>(1, qMin<qint64>(5000, remainingMs));
    if (!scheduleAuthorityWatchdogTickLocked(generation, delayMs, error)) {
        cancelAuthorityWatchdogLocked();
        return false;
    }
    return true;
}

bool MacosNativeSessionGuard::authorityWatchdogCoversLocked(
    const QJsonObject &authority, Phase requiredPhase, quint64 generation) const
{
    if (!m_watchdogArmed || generation == 0 || generation != m_watchdogGeneration
        || m_phase != requiredPhase || authority != m_runtimeAuthority
        || !m_watchdogTrustedUtc.isValid() || !m_watchdogHardDeadlineUtc.isValid()) {
        return false;
    }
    const QDateTime wallNow = m_watchdog.wallUtcNow
        ? m_watchdog.wallUtcNow().toUTC() : QDateTime{};
    const qint64 monotonicNow = m_watchdog.monotonicMilliseconds
        ? m_watchdog.monotonicMilliseconds() : qint64(-1);
    if (!wallNow.isValid() || monotonicNow < m_watchdogMonotonicAnchorMs
        || monotonicNow >= m_watchdogDeadlineMonotonicMs) {
        return false;
    }
    const qint64 elapsedMs = monotonicNow - m_watchdogMonotonicAnchorMs;
    const QDateTime trustedLowerBound = m_watchdogTrustedUtc.addMSecs(elapsedMs);
    return trustedLowerBound.isValid()
        && wallNow >= trustedLowerBound.addSecs(-300)
        && qMax(wallNow, trustedLowerBound) < m_watchdogHardDeadlineUtc;
}

void MacosNativeSessionGuard::expireAuthorityLocked(const QString &reason)
{
    Q_UNUSED(reason)
    cancelAuthorityWatchdogLocked();
    if (m_phase == Phase::Idle) return;
    m_phase = Phase::Quarantined;
    // Quarantine is attempted before persistence. Even if PF readback or disk fails, this state can
    // never produce an Applied/Adopted receipt and a restart sees either the durable lease or a
    // corrupt/missing-state fail-closed recovery path.
    if (m_backend.quarantinePolicy) m_backend.quarantinePolicy();
    persistLease();
}

void MacosNativeSessionGuard::authorityWatchdogFired(quint64 generation)
{
    QMutexLocker lock(&m_mutex);
    if (!m_watchdogArmed || generation == 0 || generation != m_watchdogGeneration
        || m_phase == Phase::Idle) return;
    const QDateTime wallNow = m_watchdog.wallUtcNow
        ? m_watchdog.wallUtcNow().toUTC() : QDateTime{};
    const qint64 monotonicNow = m_watchdog.monotonicMilliseconds
        ? m_watchdog.monotonicMilliseconds() : qint64(-1);
    if (!wallNow.isValid() || monotonicNow < m_watchdogMonotonicAnchorMs) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_clock_rollback"));
        return;
    }
    const qint64 elapsedMs = monotonicNow - m_watchdogMonotonicAnchorMs;
    const QDateTime trustedLowerBound = m_watchdogTrustedUtc.addMSecs(elapsedMs);
    if (!trustedLowerBound.isValid()
        || wallNow < trustedLowerBound.addSecs(-300)
        || monotonicNow >= m_watchdogDeadlineMonotonicMs
        || qMax(wallNow, trustedLowerBound) >= m_watchdogHardDeadlineUtc) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_expired"));
        return;
    }
    const qint64 remainingMonotonicMs = m_watchdogDeadlineMonotonicMs - monotonicNow;
    const qint64 remainingWallMs = qMax(wallNow, trustedLowerBound)
                                       .msecsTo(m_watchdogHardDeadlineUtc);
    const qint64 delayMs = qMax<qint64>(
        1, qMin<qint64>(5000, qMin(remainingMonotonicMs, remainingWallMs)));
    QString error;
    if (!scheduleAuthorityWatchdogTickLocked(generation, delayMs, error))
        expireAuthorityLocked(QStringLiteral("runtime_authority_watchdog_lost"));
}

bool MacosNativeSessionGuard::persistLease(QString *errorOut) const
{
    if (m_leasePath.isEmpty()) return true;
    if (m_phase == Phase::Idle || m_identity.operation.isEmpty()
        || m_firewallPolicy.isEmpty()) {
        if (errorOut) *errorOut = QStringLiteral("lease_state_incomplete");
        return false;
    }
    const bool authorityTracked = !m_runtimeAuthority.isEmpty()
        && lowerSha256(QJsonValue(m_nonAuthorityConfigurationSha256));
    QJsonObject lease{
        {QStringLiteral("type"), authorityTracked
             ? QStringLiteral("macos_native_session_guard_lease_v2")
             : QStringLiteral("macos_native_session_guard_lease_v1")},
        {QStringLiteral("schema"), authorityTracked ? 2 : 1},
        {QStringLiteral("operation"), m_identity.operation},
        {QStringLiteral("session"), m_identity.session},
        {QStringLiteral("policy_sha256"), m_identity.policySha256},
        {QStringLiteral("outer_session_id"), m_identity.outerSessionId},
        {QStringLiteral("expected_runtime_session_id"),
         m_identity.expectedRuntimeSessionId},
        {QStringLiteral("protocol"), m_protocol},
        {QStringLiteral("firewall_policy"), m_firewallPolicy},
    };
    if (authorityTracked) {
        lease.insert(QStringLiteral("runtime_authority"), m_runtimeAuthority);
        lease.insert(QStringLiteral("non_authority_configuration_sha256"),
                     m_nonAuthorityConfigurationSha256);
    }
    QString error;
    const bool written = durableWriteLease(
        m_leasePath, QJsonDocument(lease).toJson(QJsonDocument::Compact), error);
    if (!written && errorOut) *errorOut = error;
    return written;
}

bool MacosNativeSessionGuard::clearLease(QString *errorOut) const
{
    if (m_leasePath.isEmpty()) return true;
    QString error;
    const bool removed = durableRemoveLease(m_leasePath, error);
    if (!removed && errorOut) *errorOut = error;
    return removed;
}

bool MacosNativeSessionGuard::loadLease(
    Identity &identity, QString &protocol, QJsonObject &firewallPolicy,
    QJsonObject &runtimeAuthority, QString &nonAuthorityConfigurationSha256,
    QString &error) const
{
    identity = {};
    protocol.clear();
    firewallPolicy = {};
    runtimeAuthority = {};
    nonAuthorityConfigurationSha256.clear();
    if (m_leasePath.isEmpty()) {
        error = QStringLiteral("lease_missing");
        return false;
    }
    QByteArray bytes;
    if (!secureReadLease(m_leasePath, bytes, error)) return false;
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    bytes.fill(0);
    static const QSet<QString> v1Keys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("operation"),
        QStringLiteral("session"), QStringLiteral("policy_sha256"),
        QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("protocol"),
        QStringLiteral("firewall_policy"),
    };
    QSet<QString> v2Keys = v1Keys;
    v2Keys.insert(QStringLiteral("runtime_authority"));
    v2Keys.insert(QStringLiteral("non_authority_configuration_sha256"));
    const QJsonObject object = document.object();
    const bool v1 = exactKeys(object, v1Keys)
        && object.value(QStringLiteral("type"))
               == QLatin1String("macos_native_session_guard_lease_v1")
        && object.value(QStringLiteral("schema")).isDouble()
        && object.value(QStringLiteral("schema")).toDouble() == 1.0;
    const bool v2 = exactKeys(object, v2Keys)
        && object.value(QStringLiteral("type"))
               == QLatin1String("macos_native_session_guard_lease_v2")
        && object.value(QStringLiteral("schema")).isDouble()
        && object.value(QStringLiteral("schema")).toDouble() == 2.0;
    if (parseError.error != QJsonParseError::NoError || !document.isObject()
        || (!v1 && !v2)) {
        error = QStringLiteral("lease_json_rejected");
        return false;
    }
    QString schema;
    if (!canonicalInteger(object.value(QStringLiteral("schema")), v2 ? 2 : 1,
                          v2 ? 2 : 1, schema)
        || !canonicalDecimal(object.value(QStringLiteral("operation")), false,
                             &identity.operation)
        || !canonicalDecimal(object.value(QStringLiteral("session")), false,
                             &identity.session)
        || !lowerSha256(object.value(QStringLiteral("policy_sha256")),
                        &identity.policySha256)
        || !canonicalUuid(object.value(QStringLiteral("expected_runtime_session_id")),
                          &identity.expectedRuntimeSessionId)
        || !object.value(QStringLiteral("outer_session_id")).isString()
        || !asciiIdentifier(object.value(QStringLiteral("outer_session_id")).toString(),
                            200, true)
        || !object.value(QStringLiteral("protocol")).isString()
        || !object.value(QStringLiteral("firewall_policy")).isObject()) {
        error = QStringLiteral("lease_identity_rejected");
        return false;
    }
    identity.outerSessionId = object.value(QStringLiteral("outer_session_id")).toString();
    protocol = object.value(QStringLiteral("protocol")).toString();
    if (protocol != QLatin1String("awg") && protocol != QLatin1String("xray")) {
        error = QStringLiteral("lease_protocol_rejected");
        return false;
    }
    firewallPolicy = object.value(QStringLiteral("firewall_policy")).toObject();
    static const QSet<QString> firewallKeys{
        QStringLiteral("splitTunnelType"), QStringLiteral("splitTunnelSites"),
        QStringLiteral("dns1"), QStringLiteral("dns2"),
        QStringLiteral("allowedDnsServers"), QStringLiteral("vpnServer"),
        QStringLiteral("killSwitchOption"),
    };
    QString splitMode;
    if (!exactKeys(firewallPolicy, firewallKeys)
        || !canonicalInteger(firewallPolicy.value(QStringLiteral("splitTunnelType")),
                             0, 2, splitMode)
        || !firewallPolicy.value(QStringLiteral("splitTunnelSites")).isArray()
        || !firewallPolicy.value(QStringLiteral("allowedDnsServers")).isArray()
        || !firewallPolicy.value(QStringLiteral("dns1")).isString()
        || !firewallPolicy.value(QStringLiteral("dns2")).isString()
        || !publicLiteral(firewallPolicy.value(QStringLiteral("vpnServer")).toString())
        || firewallPolicy.value(QStringLiteral("killSwitchOption"))
               != QLatin1String("true")) {
        error = QStringLiteral("lease_firewall_policy_rejected");
        return false;
    }
    if (v2) {
        QString authorityPolicy, authorityTransport;
        QDateTime authorityDeadline;
        if (!object.value(QStringLiteral("runtime_authority")).isObject()
            || !lowerSha256(object.value(
                QStringLiteral("non_authority_configuration_sha256")),
                &nonAuthorityConfigurationSha256)) {
            error = QStringLiteral("lease_runtime_authority_rejected");
            return false;
        }
        runtimeAuthority = object.value(QStringLiteral("runtime_authority")).toObject();
        QString authorityError;
        if (!validAuthorityObject(runtimeAuthority, authorityTransport, authorityPolicy,
                                  &authorityDeadline, authorityError)
            || authorityTransport != protocol
            || authorityPolicy != identity.policySha256
            || !authorityDeadline.isValid()) {
            error = QStringLiteral("lease_runtime_authority_identity_rejected");
            return false;
        }
    }
    return true;
}

bool MacosNativeSessionGuard::restoreAfterDaemonStart(QString *errorOut)
{
    Identity identity;
    QString protocol, error;
    QJsonObject firewall;
    QJsonObject runtimeAuthority;
    QString nonAuthorityConfigurationSha256;
    if (!loadLease(identity, protocol, firewall, runtimeAuthority,
                   nonAuthorityConfigurationSha256, error)) {
        if (error == QLatin1String("lease_missing")) {
            if (errorOut) errorOut->clear();
            return true;
        }
        if (m_backend.quarantinePolicy) m_backend.quarantinePolicy();
        QMutexLocker lock(&m_mutex);
        m_phase = Phase::Quarantined;
        if (errorOut) *errorOut = error;
        return false;
    }
    QMutexLocker lock(&m_mutex);
    m_identity = identity;
    m_protocol = protocol;
    m_firewallPolicy = firewall;
    m_runtimeAuthority = runtimeAuthority;
    m_nonAuthorityConfigurationSha256 = nonAuthorityConfigurationSha256;
    m_phase = Phase::Quarantined;
    if (!m_runtimeAuthority.isEmpty()) {
        const QDateTime wallNow = m_watchdog.wallUtcNow
            ? m_watchdog.wallUtcNow().toUTC() : QDateTime{};
        if (!authorityObjectUsableAt(m_runtimeAuthority, wallNow, error)) {
            cancelAuthorityWatchdogLocked();
            if (m_backend.quarantinePolicy) m_backend.quarantinePolicy();
            persistLease();
            if (errorOut) *errorOut = QStringLiteral("lease_runtime_authority_expired");
            return false;
        }
    }
    if (!m_backend.armPolicy || !m_backend.armPolicy(m_firewallPolicy)) {
        cancelAuthorityWatchdogLocked();
        if (m_backend.quarantinePolicy) m_backend.quarantinePolicy();
        if (errorOut) *errorOut = QStringLiteral("lease_pf_rearm_failed");
        persistLease();
        return false;
    }
    if (!persistLease(&error)) {
        cancelAuthorityWatchdogLocked();
        if (m_backend.quarantinePolicy) m_backend.quarantinePolicy();
        if (errorOut) *errorOut = error;
        return false;
    }
    if (!m_runtimeAuthority.isEmpty()
        && !armAuthorityWatchdogLocked(m_runtimeAuthority, error)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_watchdog_restore_failed"));
        if (errorOut) *errorOut = error.isEmpty()
            ? QStringLiteral("authority_watchdog_restore_failed") : error;
        return false;
    }
    if (!m_runtimeAuthority.isEmpty()) {
        const quint64 publishedGeneration = m_watchdogGeneration;
        if (!authorityWatchdogCoversLocked(
                m_runtimeAuthority, Phase::Quarantined, publishedGeneration)) {
            expireAuthorityLocked(
                QStringLiteral("runtime_authority_watchdog_restore_publish_race"));
            if (errorOut)
                *errorOut = QStringLiteral("authority_watchdog_restore_publish_failed");
            return false;
        }
    }
    if (errorOut) errorOut->clear();
    return true;
}

bool MacosNativeSessionGuard::policyDigest(const QJsonObject &configuration,
                                           QString &digestHex, QString *errorOut)
{
    digestHex.clear();
    QString error;
    QString transport;
    QJsonObject authority;
    QString expectedDigest;
    if (QJsonDocument(configuration).toJson(QJsonDocument::Compact).size()
            > kMaximumConfigBytes
        || !authorityAndPolicy(configuration, transport, authority, expectedDigest, error)) {
        if (errorOut) *errorOut = error.isEmpty() ? QStringLiteral("config_oversized") : error;
        return false;
    }
    const QString nativeKey = transport == QLatin1String("awg")
        ? QStringLiteral("awg_config_data") : QStringLiteral("xray_config_data");
    if (!configuration.value(nativeKey).isObject()) {
        if (errorOut) *errorOut = QStringLiteral("native_config_data_missing");
        return false;
    }
    const QJsonObject native = configuration.value(nativeKey).toObject();
    QString nativeConfig, endpointHost, dns1, dns2;
    if (!strictString(native, QStringLiteral("config"), nativeConfig)
        || !strictString(configuration, QStringLiteral("hostName"), endpointHost)
        || !strictString(configuration, QStringLiteral("dns1"), dns1)
        || !strictString(configuration, QStringLiteral("dns2"), dns2)) {
        if (errorOut) *errorOut = QStringLiteral("native_dispatch_strings_rejected");
        return false;
    }
    QString nativeEndpointHost, port;
    if (!nativeEndpoint(transport, native, nativeConfig, nativeEndpointHost, port)
        || nativeEndpointHost != endpointHost) {
        if (errorOut) *errorOut = QStringLiteral("native_endpoint_port_rejected");
        return false;
    }
    QString address;
    QString mtu = QStringLiteral("0");
    QString xrayMemory = QStringLiteral("0");
    if (transport == QLatin1String("awg")) {
        if (!strictString(native, QStringLiteral("client_ip"), address)
            || !strictString(native, QStringLiteral("mtu"), mtu)) {
            if (errorOut) *errorOut = QStringLiteral("awg_dispatch_fields_rejected");
            return false;
        }
        bool mtuOk = false;
        const int parsedMtu = mtu.toInt(&mtuOk);
        if (!mtuOk || mtu != QString::number(parsedMtu) || parsedMtu < 576 || parsedMtu > 1500) {
            if (errorOut) *errorOut = QStringLiteral("awg_mtu_rejected");
            return false;
        }
    } else if (!canonicalInteger(configuration.value(QStringLiteral("xray_max_memory_bytes")),
                                 8 * 1024 * 1024, 1024LL * 1024 * 1024, xrayMemory)) {
        if (errorOut) *errorOut = QStringLiteral("xray_memory_bound_rejected");
        return false;
    }
    QString configVersion, splitMode, appSplitMode;
    if (!canonicalInteger(configuration.value(QStringLiteral("config_version")), 0,
                          9007199254740991LL, configVersion)
        || !canonicalInteger(configuration.value(QStringLiteral("splitTunnelType")),
                             0, 2, splitMode)
        || !canonicalInteger(configuration.value(QStringLiteral("appSplitTunnelType")),
                             0, 2, appSplitMode)) {
        if (errorOut) *errorOut = QStringLiteral("native_dispatch_integer_rejected");
        return false;
    }
    QStringList splitSites, splitApps, splitDnsSuffixes, allowedDns, protectedIps;
    if (!stringList(configuration, QStringLiteral("splitTunnelSites"), splitSites)
        || !stringList(configuration, QStringLiteral("splitTunnelApps"), splitApps)
        || !stringList(configuration, QStringLiteral("splitDnsSuffixes"), splitDnsSuffixes, true)
        || !stringList(configuration, QStringLiteral("allowedDnsServers"), allowedDns, true)) {
        if (errorOut) *errorOut = QStringLiteral("native_dispatch_list_rejected");
        return false;
    }
    for (const QJsonValue &value : authority.value(QStringLiteral("protected_tunnel_ips")).toArray())
        protectedIps.append(value.toString());
    QString splitDnsServer, dnsForwardOn, dnsForwardSuffixes, dnsForwardServer,
        dnsForwardWarmup, killSwitch;
    if (!strictString(configuration, QStringLiteral("splitDnsServer"), splitDnsServer, true)
        || !strictString(configuration, QStringLiteral("dnsFwdOn"), dnsForwardOn, true)
        || !strictString(configuration, QStringLiteral("dnsFwdSuffixes"),
                         dnsForwardSuffixes, true)
        || !strictString(configuration, QStringLiteral("dnsFwdServer"),
                         dnsForwardServer, true)
        || !strictString(configuration, QStringLiteral("dnsFwdWarmup"),
                         dnsForwardWarmup, true)
        || !strictString(configuration, QStringLiteral("killSwitchOption"), killSwitch, true)) {
        if (errorOut) *errorOut = QStringLiteral("native_dispatch_optional_string_rejected");
        return false;
    }

    QByteArray canonical("tribe-native-dispatch-policy-v1\n");
    const auto record = [&](const QByteArray &name, const QString &value) {
        return appendRecord(canonical, name, value);
    };
    if (!record("transport", transport)
        || !record("native_envelope_schema", QStringLiteral("tribe_catalog_v2_native_v1"))
        || !record("profile_id", authority.value(QStringLiteral("profile_id")).toString())
        || !record("config_generation",
                   authority.value(QStringLiteral("config_generation")).toString())
        || !record("binding_generation",
                   authority.value(QStringLiteral("binding_generation")).toString())
        || !record("endpoint_host", endpointHost) || !record("endpoint_port", port)
        || !record("tunnel_address", address) || !record("dns1", dns1)
        || !record("dns2", dns2) || !record("mtu", mtu)
        || !record("config_version", configVersion)
        || !record("xray_max_memory_bytes", xrayMemory)
        || !record("split_tunnel_type", splitMode)
        || !appendList(canonical, "split_site", splitSites)
        || !record("app_split_tunnel_type", appSplitMode)
        || !appendList(canonical, "split_app", splitApps)
        || !appendList(canonical, "split_dns_suffix", splitDnsSuffixes)
        || !record("split_dns_server", splitDnsServer)
        || !record("dns_forward_on", dnsForwardOn)
        || !record("dns_forward_suffixes", dnsForwardSuffixes)
        || !record("dns_forward_server", dnsForwardServer)
        || !record("dns_forward_warmup", dnsForwardWarmup)
        || !record("kill_switch", killSwitch)
        || !appendList(canonical, "allowed_dns", allowedDns)
        || !appendList(canonical, "protected_tunnel_ip", protectedIps)
        || !record("native_config_sha256", QString::fromLatin1(
            QCryptographicHash::hash(nativeConfig.toUtf8(), QCryptographicHash::Sha256).toHex()))) {
        if (errorOut) *errorOut = QStringLiteral("native_dispatch_projection_oversized");
        return false;
    }
    digestHex = QString::fromLatin1(
        QCryptographicHash::hash(canonical, QCryptographicHash::Sha256).toHex());
    if (digestHex != expectedDigest) {
        if (errorOut) *errorOut = QStringLiteral("native_dispatch_digest_mismatch");
        return false;
    }
    if (errorOut) errorOut->clear();
    return true;
}

bool MacosNativeSessionGuard::parsePrepare(
    const QJsonObject &request, Identity &identity, QJsonObject &configuration,
    QString &protocol, QJsonObject &firewallPolicy, QString &error)
{
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("operation"),
        QStringLiteral("session"), QStringLiteral("policy_sha256"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("configuration"),
    };
    if (!exactKeys(request, keys)
        || request.value(QStringLiteral("type"))
               != QLatin1String("native_session_guard_prepare_v1")) {
        error = QStringLiteral("prepare_shape_rejected");
        return false;
    }
    QString schema;
    if (!canonicalInteger(request.value(QStringLiteral("schema")), 1, 1, schema)
        || !canonicalDecimal(request.value(QStringLiteral("operation")), false,
                             &identity.operation)
        || !canonicalDecimal(request.value(QStringLiteral("session")), false,
                             &identity.session)
        || !lowerSha256(request.value(QStringLiteral("policy_sha256")),
                        &identity.policySha256)
        || !canonicalUuid(request.value(QStringLiteral("expected_runtime_session_id")),
                          &identity.expectedRuntimeSessionId)
        || !request.value(QStringLiteral("configuration")).isObject()) {
        error = QStringLiteral("prepare_identity_rejected");
        return false;
    }
    configuration = request.value(QStringLiteral("configuration")).toObject();
    QString computed;
    if (!policyDigest(configuration, computed, &error)
        || !authorityUsableNow(configuration, error)
        || computed != identity.policySha256) {
        if (error.isEmpty()) error = QStringLiteral("prepare_policy_mismatch");
        return false;
    }
    const QJsonObject authority = configuration.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    protocol = authority.value(QStringLiteral("transport")).toString();

    // Normal macOS does not have a proven per-app PF readback.  Reject that combination rather
    // than advertising a guard which silently routes an excluded app outside the intended policy.
    QString appMode, splitMode;
    if (!canonicalInteger(configuration.value(QStringLiteral("appSplitTunnelType")), 0, 0,
                          appMode)
        || !configuration.value(QStringLiteral("splitTunnelApps")).isArray()
        || !configuration.value(QStringLiteral("splitTunnelApps")).toArray().isEmpty()
        || !canonicalInteger(configuration.value(QStringLiteral("splitTunnelType")), 0, 2,
                             splitMode)) {
        error = QStringLiteral("macos_app_split_guard_unavailable");
        return false;
    }
    QString endpoint = configuration.value(QStringLiteral("hostName")).toString();
    QHostAddress endpointAddress;
    if (!publicLiteral(endpoint) || !endpointAddress.setAddress(endpoint)
        || endpointAddress.protocol() != QAbstractSocket::IPv4Protocol) {
        // Endpoint DNS must be resolved once and bound into the signed dispatch policy before PF
        // can make a zero-leak exception.  Independent re-resolution here would be a rebinding gap.
        // The current PF profile blocks all IPv6, so an IPv6 server literal is also unusable.
        error = QStringLiteral("macos_guard_requires_literal_public_ipv4_endpoint");
        return false;
    }
    QStringList splitSites, allowedDns;
    if (!stringList(configuration, QStringLiteral("splitTunnelSites"), splitSites)
        || !stringList(configuration, QStringLiteral("allowedDnsServers"), allowedDns, true)) {
        error = QStringLiteral("macos_guard_route_list_rejected");
        return false;
    }
    // The existing PF profile is IPv4 plus an explicit IPv6 block.  IPv6 route exceptions are
    // therefore unsupported but remain fail-closed (blocked, never direct).
    for (const QString &site : splitSites) {
        const auto subnet = QHostAddress::parseSubnet(site);
        if (subnet.first.protocol() != QAbstractSocket::IPv4Protocol
            || subnet.second < 0 || subnet.second > 32) {
            error = QStringLiteral("macos_guard_ipv6_split_unavailable");
            return false;
        }
    }
    firewallPolicy = {
        {QStringLiteral("splitTunnelType"), configuration.value(QStringLiteral("splitTunnelType"))},
        {QStringLiteral("splitTunnelSites"), configuration.value(QStringLiteral("splitTunnelSites"))},
        {QStringLiteral("dns1"), configuration.value(QStringLiteral("dns1"))},
        {QStringLiteral("dns2"), configuration.value(QStringLiteral("dns2"))},
        {QStringLiteral("allowedDnsServers"), QJsonArray::fromStringList(allowedDns)},
        {QStringLiteral("vpnServer"), endpoint},
        {QStringLiteral("killSwitchOption"), QStringLiteral("true")},
    };
    return true;
}

bool MacosNativeSessionGuard::parseIdentityRequest(
    const QJsonObject &request, const QString &type, bool requireOuter,
    Identity &identity, QString *protocol, QString &error)
{
    QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("operation"),
        QStringLiteral("session"), QStringLiteral("policy_sha256"),
        QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"),
    };
    if (protocol) keys.insert(QStringLiteral("protocol"));
    QString schema;
    if (!exactKeys(request, keys) || request.value(QStringLiteral("type")) != type
        || !canonicalInteger(request.value(QStringLiteral("schema")), 1, 1, schema)
        || !canonicalDecimal(request.value(QStringLiteral("operation")), false,
                             &identity.operation)
        || !canonicalDecimal(request.value(QStringLiteral("session")), false,
                             &identity.session)
        || !lowerSha256(request.value(QStringLiteral("policy_sha256")),
                        &identity.policySha256)
        || !canonicalUuid(request.value(QStringLiteral("expected_runtime_session_id")),
                          &identity.expectedRuntimeSessionId)
        || !request.value(QStringLiteral("outer_session_id")).isString()) {
        error = QStringLiteral("guard_command_shape_rejected");
        return false;
    }
    identity.outerSessionId = request.value(QStringLiteral("outer_session_id")).toString();
    if ((requireOuter && !asciiIdentifier(identity.outerSessionId, 200, true))
        || (!requireOuter && !identity.outerSessionId.isEmpty()
            && !asciiIdentifier(identity.outerSessionId, 200, true))) {
        error = QStringLiteral("guard_outer_identity_rejected");
        return false;
    }
    if (protocol) {
        if (!request.value(QStringLiteral("protocol")).isString()) return false;
        *protocol = request.value(QStringLiteral("protocol")).toString();
        if (*protocol != QLatin1String("awg") && *protocol != QLatin1String("xray")) {
            error = QStringLiteral("guard_protocol_rejected");
            return false;
        }
    }
    return true;
}

QJsonObject MacosNativeSessionGuard::event(const Identity &identity,
                                           const QString &kind,
                                           const QString &reason)
{
    return {
        {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), identity.operation},
        {QStringLiteral("session"), identity.session},
        {QStringLiteral("kind"), kind},
        {QStringLiteral("policy_sha256"), identity.policySha256},
        {QStringLiteral("outer_session_id"), identity.outerSessionId},
        {QStringLiteral("expected_runtime_session_id"), identity.expectedRuntimeSessionId},
        {QStringLiteral("reason"), reason},
    };
}

QJsonObject MacosNativeSessionGuard::recoveryReceipt(
    const Identity &identity, const QString &action, const QString &kind,
    const QString &reason)
{
    return {
        {QStringLiteral("type"), QStringLiteral("native_session_guard_recovery_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("action"), action},
        {QStringLiteral("kind"), kind},
        {QStringLiteral("operation"), identity.operation},
        {QStringLiteral("session"), identity.session},
        {QStringLiteral("policy_sha256"), identity.policySha256},
        {QStringLiteral("outer_session_id"), identity.outerSessionId},
        {QStringLiteral("expected_runtime_session_id"), identity.expectedRuntimeSessionId},
        {QStringLiteral("reason"), reason},
    };
}

QJsonObject MacosNativeSessionGuard::commandReceipt(
    const QString &action, const Identity &identity, bool accepted,
    const QString &reason)
{
    return {
        {QStringLiteral("type"), QStringLiteral("native_session_guard_command_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("action"), action},
        {QStringLiteral("accepted"), accepted},
        {QStringLiteral("operation"), identity.operation},
        {QStringLiteral("session"), identity.session},
        {QStringLiteral("policy_sha256"), identity.policySha256},
        {QStringLiteral("outer_session_id"), identity.outerSessionId},
        {QStringLiteral("expected_runtime_session_id"), identity.expectedRuntimeSessionId},
        {QStringLiteral("reason"), reason},
    };
}

QJsonObject MacosNativeSessionGuard::authorityRenewalReceipt(
    const QJsonObject &request, const QString &kind,
    const QString &hardDeadline, const QString &reason)
{
    const QJsonObject configuration = request.value(
        QStringLiteral("configuration")).toObject();
    const QJsonObject authority = configuration.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    return {
        {QStringLiteral("type"), QStringLiteral("runtime_authority_renewal_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("kind"), kind},
        {QStringLiteral("operation"), request.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), request.value(QStringLiteral("session"))},
        {QStringLiteral("renewal_id"), request.value(QStringLiteral("renewal_id"))},
        {QStringLiteral("policy_sha256"), request.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"),
         request.value(QStringLiteral("outer_session_id"))},
        {QStringLiteral("expected_runtime_session_id"),
         request.value(QStringLiteral("expected_runtime_session_id"))},
        {QStringLiteral("config_generation"),
         authority.value(QStringLiteral("config_generation"))},
        {QStringLiteral("binding_generation"),
         authority.value(QStringLiteral("binding_generation"))},
        {QStringLiteral("catalog_revision"),
         authority.value(QStringLiteral("catalog_revision"))},
        {QStringLiteral("catalog_payload_sha256"),
         authority.value(QStringLiteral("catalog_payload_sha256"))},
        {QStringLiteral("authority_commitment_sha256"),
         request.value(QStringLiteral("authority_commitment_sha256"))},
        {QStringLiteral("hard_deadline"), hardDeadline},
        {QStringLiteral("reason"), reason},
    };
}

bool MacosNativeSessionGuard::sameIdentity(const Identity &identity,
                                           bool requireOuter) const
{
    return identity.operation == m_identity.operation
           && identity.session == m_identity.session
           && identity.policySha256 == m_identity.policySha256
           && identity.expectedRuntimeSessionId == m_identity.expectedRuntimeSessionId
           && (!requireOuter || identity.outerSessionId == m_identity.outerSessionId);
}

QJsonObject MacosNativeSessionGuard::prepare(const QJsonObject &request)
{
    Identity identity;
    QJsonObject configuration, firewall;
    QString protocol, error;
    if (!parsePrepare(request, identity, configuration, protocol, firewall, error))
        return identity.policySha256.isEmpty() ? QJsonObject{}
            : event(identity, QStringLiteral("arm_rejected"), error);
    QMutexLocker lock(&m_mutex);
    if (m_phase != Phase::Idle && m_phase != Phase::Armed)
        return event(identity, QStringLiteral("arm_rejected"),
                     QStringLiteral("outer_guard_busy"));
    const bool replacingStoppedOwner = m_phase == Phase::Armed;
    const QJsonObject previousFirewall = m_firewallPolicy;
    if (!m_backend.armPolicy || !m_backend.armPolicy(firewall)) {
        // armPolicy leaves PF in a blackhole on failure. Restore the previous stopped owner's
        // exact policy when possible; otherwise quarantine it rather than pretending PREPARE had
        // no side effect.
        if (replacingStoppedOwner
            && (!m_backend.armPolicy || !m_backend.armPolicy(previousFirewall))) {
            m_phase = Phase::Quarantined;
            persistLease();
        }
        return event(identity, QStringLiteral("arm_rejected"),
                     replacingStoppedOwner && m_phase == Phase::Quarantined
                         ? QStringLiteral("pf_replace_failed_old_guard_quarantined")
                         : QStringLiteral("pf_arm_readback_failed"));
    }
    identity.outerSessionId = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    m_identity = identity;
    m_protocol = protocol;
    m_firewallPolicy = firewall;
    m_runtimeAuthority = configuration.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    m_nonAuthorityConfigurationSha256 =
        nonAuthorityConfigurationCommitment(configuration);
    m_phase = Phase::Armed;
    if (!persistLease(&error)) {
        cancelAuthorityWatchdogLocked();
        // The atomic rename may already have made the new lease visible even when its directory
        // fsync reports failure. Keep the new identity/config internally consistent and blackhole
        // PF; mixing the old authority into the new protocol/identity would create an unloadable
        // v2 lease and make exact recovery impossible.
        m_phase = Phase::Quarantined;
        if (m_backend.quarantinePolicy) m_backend.quarantinePolicy();
        persistLease();
        return event(m_identity, QStringLiteral("lost"),
                     QStringLiteral("guard_lease_persist_failed"));
    }
    if (!armAuthorityWatchdogLocked(m_runtimeAuthority, error)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_watchdog_arm_failed"));
        return event(m_identity, QStringLiteral("lost"),
                     QStringLiteral("authority_watchdog_arm_failed"));
    }
    const quint64 publishedGeneration = m_watchdogGeneration;
    if (!authorityWatchdogCoversLocked(
            m_runtimeAuthority, Phase::Armed, publishedGeneration)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_prepare_publish_race"));
        return event(m_identity, QStringLiteral("lost"),
                     QStringLiteral("authority_watchdog_publish_failed"));
    }
    return event(m_identity, QStringLiteral("armed"));
}

QJsonObject MacosNativeSessionGuard::claimInner(const QJsonObject &request)
{
    Identity identity;
    QString protocol, error;
    if (!parseIdentityRequest(request, QStringLiteral("native_session_guard_claim_v1"),
                              true, identity, &protocol, error)) return {};
    QMutexLocker lock(&m_mutex);
    bool accepted = m_phase == Phase::Armed && sameIdentity(identity, true)
                    && protocol == m_protocol;
    if (accepted && !m_runtimeAuthority.isEmpty()
        && !authorityWatchdogCoversLocked(
            m_runtimeAuthority, Phase::Armed, m_watchdogGeneration)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_expired_before_claim"));
        accepted = false;
    }
    if (accepted) {
        m_phase = Phase::Starting;
        if (!persistLease(&error)) {
            m_phase = Phase::Quarantined;
            return commandReceipt(QStringLiteral("claim"), identity, false,
                                  QStringLiteral("guard_lease_persist_failed"));
        }
    }
    return commandReceipt(QStringLiteral("claim"), identity, accepted,
                          accepted ? QString() : QStringLiteral("claim_identity_or_phase_rejected"));
}

QJsonObject MacosNativeSessionGuard::beginStop(const QJsonObject &request)
{
    Identity identity;
    QString error;
    if (!parseIdentityRequest(request, QStringLiteral("native_session_guard_stop_begin_v1"),
                              true, identity, nullptr, error)) return {};
    QMutexLocker lock(&m_mutex);
    const bool accepted = sameIdentity(identity, true)
        && (m_phase == Phase::Starting || m_phase == Phase::Running
            || m_phase == Phase::Quarantined);
    if (accepted) {
        m_phase = Phase::Stopping;
        if (!persistLease(&error)) {
            m_phase = Phase::Quarantined;
            return commandReceipt(QStringLiteral("stop_begin"), identity, false,
                                  QStringLiteral("guard_lease_persist_failed"));
        }
    }
    return commandReceipt(QStringLiteral("stop_begin"), identity, accepted,
                          accepted ? QString() : QStringLiteral("stop_identity_or_phase_rejected"));
}

QJsonObject MacosNativeSessionGuard::markRunning(const QJsonObject &request)
{
    Identity identity;
    QString error;
    if (!parseIdentityRequest(request, QStringLiteral("native_session_guard_running_v1"),
                              true, identity, nullptr, error)) return {};
    QMutexLocker lock(&m_mutex);
    bool accepted = m_phase == Phase::Starting && sameIdentity(identity, true);
    if (accepted && !m_runtimeAuthority.isEmpty()
        && !authorityWatchdogCoversLocked(
            m_runtimeAuthority, Phase::Starting, m_watchdogGeneration)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_expired_before_running"));
        accepted = false;
    }
    if (accepted) {
        m_phase = Phase::Running;
        if (!persistLease(&error)) {
            m_phase = Phase::Quarantined;
            return commandReceipt(QStringLiteral("running"), identity, false,
                                  QStringLiteral("guard_lease_persist_failed"));
        }
    }
    return commandReceipt(QStringLiteral("running"), identity, accepted,
                          accepted ? QString() : QStringLiteral("running_identity_or_phase_rejected"));
}

QJsonObject MacosNativeSessionGuard::markStopped(const QJsonObject &request)
{
    Identity identity;
    QString error;
    if (!parseIdentityRequest(request, QStringLiteral("native_session_guard_stopped_v1"),
                              true, identity, nullptr, error)) return {};
    QMutexLocker lock(&m_mutex);
    const bool accepted = sameIdentity(identity, true)
        && (m_phase == Phase::Stopping || m_phase == Phase::Starting
            || m_phase == Phase::Quarantined);
    if (accepted) {
        m_phase = Phase::Armed;
        if (!persistLease(&error)) {
            m_phase = Phase::Quarantined;
            return commandReceipt(QStringLiteral("stopped"), identity, false,
                                  QStringLiteral("guard_lease_persist_failed"));
        }
    }
    return commandReceipt(QStringLiteral("stopped"), identity, accepted,
                          accepted ? QString() : QStringLiteral("stopped_identity_or_phase_rejected"));
}

QJsonObject MacosNativeSessionGuard::renewAuthority(const QJsonObject &request)
{
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"),
        QStringLiteral("operation"), QStringLiteral("session"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("renewal_id"),
        QStringLiteral("authority_commitment_sha256"),
        QStringLiteral("configuration"),
    };
    QString schema, renewalId, commitment;
    if (!exactKeys(request, keys)
        || request.value(QStringLiteral("type"))
               != QLatin1String("runtime_authority_renew_request_v1")
        || !canonicalInteger(request.value(QStringLiteral("schema")), 1, 1, schema)
        || !canonicalUuid(request.value(QStringLiteral("renewal_id")), &renewalId)
        || !lowerSha256(request.value(QStringLiteral("authority_commitment_sha256")),
                        &commitment)
        || !request.value(QStringLiteral("configuration")).isObject()) return {};

    const QJsonObject identityRequest{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_authority_renew_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), request.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), request.value(QStringLiteral("session"))},
        {QStringLiteral("policy_sha256"), request.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"),
         request.value(QStringLiteral("outer_session_id"))},
        {QStringLiteral("expected_runtime_session_id"),
         request.value(QStringLiteral("expected_runtime_session_id"))},
    };
    Identity identity;
    QString error;
    if (!parseIdentityRequest(identityRequest,
                              QStringLiteral("native_session_guard_authority_renew_v1"),
                              true, identity, nullptr, error)) return {};

    const QJsonObject requestedConfiguration = request.value(
        QStringLiteral("configuration")).toObject();
    if (compactSha256(requestedConfiguration) != commitment) {
        return authorityRenewalReceipt(request, QStringLiteral("rejected"), {},
                                       QStringLiteral("renew_commitment_mismatch"));
    }
    QJsonObject parsedConfiguration, firewall;
    QString protocol;
    Identity parsedIdentity;
    const QJsonObject prepareProjection{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_prepare_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), request.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), request.value(QStringLiteral("session"))},
        {QStringLiteral("policy_sha256"), request.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("expected_runtime_session_id"),
         request.value(QStringLiteral("expected_runtime_session_id"))},
        {QStringLiteral("configuration"), requestedConfiguration},
    };
    if (!parsePrepare(prepareProjection, parsedIdentity, parsedConfiguration,
                      protocol, firewall, error)) {
        return authorityRenewalReceipt(request, QStringLiteral("rejected"), {},
                                       QStringLiteral("renew_configuration_rejected"));
    }
    parsedIdentity.outerSessionId = identity.outerSessionId;
    const QJsonObject nextAuthority = requestedConfiguration.value(
        QStringLiteral("runtime_authority_v1")).toObject();
    const QString nextNonAuthority =
        nonAuthorityConfigurationCommitment(requestedConfiguration);
    const QString hardDeadline = authorityHardDeadlineText(nextAuthority);

    QMutexLocker lock(&m_mutex);
    if (m_phase != Phase::Running || !sameIdentity(identity, true)
        || !sameIdentity(parsedIdentity, true) || protocol != m_protocol
        || firewall != m_firewallPolicy || m_runtimeAuthority.isEmpty()
        || m_nonAuthorityConfigurationSha256.isEmpty()
        || nextNonAuthority != m_nonAuthorityConfigurationSha256
        || !acceptsAuthorityRenewal(m_runtimeAuthority, nextAuthority)
        || hardDeadline.isEmpty()) {
        return authorityRenewalReceipt(request, QStringLiteral("rejected"), {},
                                       QStringLiteral("renew_identity_or_phase_rejected"));
    }

    const QJsonObject oldAuthority = m_runtimeAuthority;
    const quint64 oldGeneration = m_watchdogGeneration;
    if (!authorityWatchdogCoversLocked(oldAuthority, Phase::Running,
                                       oldGeneration)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_expired_before_renewal"));
        return authorityRenewalReceipt(
            request, QStringLiteral("rejected"), {},
            QStringLiteral("renew_current_authority_not_enforced"));
    }

    m_runtimeAuthority = nextAuthority;
    if (!persistLease(&error)) {
        // Disk state is uncertain after an fsync/rename failure. Keep PF, quarantine the lease and
        // force exact native teardown; never acknowledge application from in-memory state alone.
        m_runtimeAuthority = oldAuthority;
        expireAuthorityLocked(QStringLiteral("runtime_authority_renew_persist_failed"));
        return authorityRenewalReceipt(request, QStringLiteral("rejected"), {},
                                       QStringLiteral("renew_durable_persist_failed"));
    }

    if (!armAuthorityWatchdogLocked(nextAuthority, error)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_renew_watchdog_failed"));
        return authorityRenewalReceipt(request, QStringLiteral("rejected"), {},
                                       QStringLiteral("renew_watchdog_arm_failed"));
    }
    const quint64 publishedGeneration = m_watchdogGeneration;
    if (!authorityWatchdogCoversLocked(nextAuthority, Phase::Running,
                                       publishedGeneration)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_renew_publish_race"));
        return authorityRenewalReceipt(request, QStringLiteral("rejected"), {},
                                       QStringLiteral("renew_watchdog_publish_failed"));
    }
    return authorityRenewalReceipt(request, QStringLiteral("applied"),
                                   hardDeadline, {});
}

QJsonObject MacosNativeSessionGuard::release(const QJsonObject &request)
{
    Identity identity;
    QString error;
    if (!parseIdentityRequest(request, QStringLiteral("native_session_guard_release_v1"),
                              true, identity, nullptr, error)) return {};
    QMutexLocker lock(&m_mutex);
    if (m_phase != Phase::Armed || !sameIdentity(identity, true))
        return event(identity, QStringLiteral("release_rejected"),
                     QStringLiteral("release_identity_or_inner_ownership_rejected"));
    if (!clearLease(&error))
        return event(identity, QStringLiteral("release_rejected"),
                     QStringLiteral("guard_lease_remove_failed"));
    if (!m_backend.releasePolicy || !m_backend.releasePolicy()) {
        m_phase = Phase::Quarantined;
        persistLease();
        return event(identity, QStringLiteral("release_rejected"),
                     QStringLiteral("pf_release_readback_failed"));
    }
    const QJsonObject receipt = event(m_identity, QStringLiteral("released"));
    m_identity = {};
    m_protocol.clear();
    m_firewallPolicy = {};
    m_runtimeAuthority = {};
    m_nonAuthorityConfigurationSha256.clear();
    m_phase = Phase::Idle;
    cancelAuthorityWatchdogLocked();
    return receipt;
}

void MacosNativeSessionGuard::authenticatedChannelLost()
{
    QMutexLocker lock(&m_mutex);
    if (m_phase != Phase::Idle) {
        m_phase = Phase::Quarantined;
        persistLease();
    }
}

QJsonObject MacosNativeSessionGuard::currentGuardEvent() const
{
    QMutexLocker lock(&m_mutex);
    if (m_phase == Phase::Idle) return {};
    return event(m_identity, m_phase == Phase::Quarantined
                 ? QStringLiteral("lost") : QStringLiteral("armed"),
                 m_phase == Phase::Quarantined ? QStringLiteral("gui_channel_lost") : QString());
}

bool MacosNativeSessionGuard::validateRecoveryConfiguration(
    const QJsonObject &configuration, QString *error) const
{
    QString localError;
    QMutexLocker lock(&m_mutex);
    QJsonObject authority;
    QString nonAuthority;
    const bool matches = recoveryConfigurationMatchesLocked(
        configuration, authority, nonAuthority, localError);
    if (error) *error = matches ? QString() : localError;
    return matches;
}

bool MacosNativeSessionGuard::recoveryConfigurationMatchesLocked(
    const QJsonObject &configuration, QJsonObject &authority,
    QString &nonAuthorityConfigurationSha256, QString &error) const
{
    authority = {};
    nonAuthorityConfigurationSha256.clear();
    if (m_phase != Phase::Quarantined) {
        error = QStringLiteral("recovery_phase_rejected");
        return false;
    }
    if (!m_runtimeAuthority.isEmpty()
        && !authorityWatchdogCoversLocked(
            m_runtimeAuthority, Phase::Quarantined, m_watchdogGeneration)) {
        error = QStringLiteral("recovery_current_authority_not_enforced");
        return false;
    }

    QString digest;
    if (!policyDigest(configuration, digest, &error)) return false;
    const QDateTime wallNow = m_watchdog.wallUtcNow
        ? m_watchdog.wallUtcNow().toUTC() : QDateTime{};
    if (!authorityUsableAt(configuration, wallNow, error)) return false;

    authority = configuration.value(QStringLiteral("runtime_authority_v1")).toObject();
    nonAuthorityConfigurationSha256 =
        nonAuthorityConfigurationCommitment(configuration);
    const bool matches = digest == m_identity.policySha256
        && authority.value(QStringLiteral("transport")).toString() == m_protocol
        && (m_nonAuthorityConfigurationSha256.isEmpty()
            || nonAuthorityConfigurationSha256
                   == m_nonAuthorityConfigurationSha256)
        && (m_runtimeAuthority.isEmpty()
            || authority == m_runtimeAuthority
            || acceptsAuthorityRenewal(m_runtimeAuthority, authority));
    if (!matches) error = QStringLiteral("recovery_policy_or_authority_mismatch");
    return matches;
}

QJsonObject MacosNativeSessionGuard::adoptRecovered(
    const QJsonObject &request, const QJsonObject &configuration)
{
    Identity identity;
    QString error;
    if (!parseIdentityRequest(request, QStringLiteral("native_session_guard_recover_adopt_v1"),
                              true, identity, nullptr, error)) return {};
    QMutexLocker lock(&m_mutex);
    if (m_phase == Phase::Quarantined && sameIdentity(identity, true)
        && !m_runtimeAuthority.isEmpty()
        && !authorityWatchdogCoversLocked(
            m_runtimeAuthority, Phase::Quarantined, m_watchdogGeneration)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_expired_before_adoption"));
        return recoveryReceipt(m_identity, QStringLiteral("adopt"),
                               QStringLiteral("rejected"),
                               QStringLiteral("recovery_current_authority_not_enforced"));
    }
    QJsonObject nextAuthority;
    QString nextNonAuthority;
    if (!sameIdentity(identity, true)
        || !recoveryConfigurationMatchesLocked(
            configuration, nextAuthority, nextNonAuthority, error)) {
        return recoveryReceipt(identity, QStringLiteral("adopt"),
                               QStringLiteral("rejected"),
                               error.isEmpty()
                                   ? QStringLiteral("recovery_identity_rejected")
                                   : error);
    }

    const QJsonObject oldAuthority = m_runtimeAuthority;
    const QString oldNonAuthority = m_nonAuthorityConfigurationSha256;
    m_runtimeAuthority = nextAuthority;
    m_nonAuthorityConfigurationSha256 = nextNonAuthority;
    m_phase = Phase::Running;
    if (!persistLease(&error)) {
        m_runtimeAuthority = oldAuthority;
        m_nonAuthorityConfigurationSha256 = oldNonAuthority;
        expireAuthorityLocked(QStringLiteral("runtime_authority_adopt_persist_failed"));
        return recoveryReceipt(m_identity, QStringLiteral("adopt"),
                               QStringLiteral("rejected"),
                               QStringLiteral("guard_lease_persist_failed"));
    }

    if (!armAuthorityWatchdogLocked(nextAuthority, error)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_adopt_watchdog_failed"));
        return recoveryReceipt(m_identity, QStringLiteral("adopt"),
                               QStringLiteral("rejected"),
                               QStringLiteral("authority_watchdog_arm_failed"));
    }
    const quint64 publishedGeneration = m_watchdogGeneration;
    if (!authorityWatchdogCoversLocked(nextAuthority, Phase::Running,
                                       publishedGeneration)) {
        expireAuthorityLocked(QStringLiteral("runtime_authority_adopt_publish_race"));
        return recoveryReceipt(m_identity, QStringLiteral("adopt"),
                               QStringLiteral("rejected"),
                               QStringLiteral("authority_watchdog_publish_failed"));
    }
    return recoveryReceipt(m_identity, QStringLiteral("adopt"),
                           QStringLiteral("adopted"));
}

QJsonObject MacosNativeSessionGuard::stopAndReleaseRecovered(
    const QJsonObject &request, const std::function<bool()> &exactStop)
{
    Identity identity;
    QString error;
    if (!parseIdentityRequest(request, QStringLiteral("native_session_guard_recover_stop_v1"),
                              true, identity, nullptr, error)) return {};
    QMutexLocker lock(&m_mutex);
    if (m_phase != Phase::Quarantined || !sameIdentity(identity, true))
        return recoveryReceipt(identity, QStringLiteral("stop"), QStringLiteral("rejected"),
                               QStringLiteral("recovery_identity_rejected"));
    m_phase = Phase::Stopping;
    if (!exactStop || !exactStop()) {
        m_phase = Phase::Quarantined;
        return recoveryReceipt(m_identity, QStringLiteral("stop"),
                               QStringLiteral("rejected"),
                               QStringLiteral("exact_inner_stop_failed"));
    }
    m_phase = Phase::Armed;
    if (!clearLease(&error)) {
        m_phase = Phase::Quarantined;
        return recoveryReceipt(m_identity, QStringLiteral("stop"),
                               QStringLiteral("rejected"),
                               QStringLiteral("guard_lease_remove_failed"));
    }
    if (!m_backend.releasePolicy || !m_backend.releasePolicy()) {
        m_phase = Phase::Quarantined;
        persistLease();
        return recoveryReceipt(m_identity, QStringLiteral("stop"),
                               QStringLiteral("rejected"),
                               QStringLiteral("pf_release_readback_failed"));
    }
    const QJsonObject receipt = recoveryReceipt(
        m_identity, QStringLiteral("stop"), QStringLiteral("stopped_released"));
    m_identity = {};
    m_protocol.clear();
    m_firewallPolicy = {};
    m_runtimeAuthority = {};
    m_nonAuthorityConfigurationSha256.clear();
    m_phase = Phase::Idle;
    cancelAuthorityWatchdogLocked();
    return receipt;
}

MacosNativeSessionGuard::Phase MacosNativeSessionGuard::phase() const
{
    QMutexLocker lock(&m_mutex);
    return m_phase;
}

QString MacosNativeSessionGuard::protocol() const
{
    QMutexLocker lock(&m_mutex);
    return m_protocol;
}

QString MacosNativeSessionGuard::expectedRuntimeSessionId() const
{
    QMutexLocker lock(&m_mutex);
    return m_identity.expectedRuntimeSessionId;
}

QString MacosNativeSessionGuard::outerSessionId() const
{
    QMutexLocker lock(&m_mutex);
    return m_identity.outerSessionId;
}
