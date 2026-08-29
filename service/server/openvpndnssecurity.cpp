#include "openvpndnssecurity.h"

#include <QByteArray>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcessEnvironment>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSet>
#include <QTimer>

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <utility>

namespace amnezia::openvpndnssecurity {
namespace {

constexpr auto kStateDirectory = "/private/var/db/TribeVPN";
constexpr auto kStatePath = "/private/var/db/TribeVPN/openvpn-dns-state-v1.json";
constexpr auto kLockPath = "/private/var/db/TribeVPN/openvpn-dns.lock";
constexpr qsizetype kMaxStateBytes = 512 * 1024;
constexpr qsizetype kMaxServiceRecords = 32;

enum class JournalPhase {
    Prepared,
    Applied
};

struct DnsRecord {
    QString service;
    bool hadOriginal = false;
    // baseline is the pre-VPN value to restore, preimage is the value proven
    // immediately before the pending write, and applied is the value Tribe
    // intends to own after that write.  Keeping all three makes both sides of
    // an interrupted same-session DNS update recoverable.
    QByteArray originalPlist;
    QByteArray preimagePlist;
    QByteArray appliedPlist;
    bool ownsSearchDomains = false;
    JournalPhase phase = JournalPhase::Prepared;
};

struct DnsState {
    QString session;
    QString device;
    QStringList servers;
    QStringList searchDomains;
    QStringList activeServices;
    QList<DnsRecord> records;
};

// WAL v3 stores only the two DNS fields owned by Tribe.  Legacy v1/v2 full
// dictionaries are projected through this helper whenever they are rewritten.
QByteArray ownedFieldsPlist(const QByteArray &plist);

void setError(QString *error, const QString &value)
{
    if (error) {
        *error = value;
    }
}

bool secureDirectoryMetadata(const char *path, mode_t exactMode,
                             QString *error)
{
    struct stat st {};
    if (::lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)
            || st.st_uid != 0 || (st.st_mode & 07777) != exactMode) {
        setError(error, QStringLiteral("openvpn_dns_state_directory_insecure"));
        return false;
    }
    return true;
}

bool prepareStateDirectory(QString *error)
{
    if (::geteuid() != 0
            || !secureDirectoryMetadata("/private", 0755, error)
            || !secureDirectoryMetadata("/private/var", 0755, error)
            || !secureDirectoryMetadata("/private/var/db", 0755, error)) {
        return false;
    }
    if (::mkdir(kStateDirectory, 0700) != 0 && errno != EEXIST) {
        setError(error, QStringLiteral("openvpn_dns_state_directory_create_failed"));
        return false;
    }
    return secureDirectoryMetadata(kStateDirectory, 0700, error);
}

class StateLock final {
public:
    ~StateLock()
    {
        if (m_fd >= 0) {
            ::flock(m_fd, LOCK_UN);
            ::close(m_fd);
        }
    }

    bool acquire(QString *error)
    {
        m_fd = ::open(kLockPath, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                      0600);
        struct stat st {};
        if (m_fd < 0 || ::fchmod(m_fd, 0600) != 0 || ::fstat(m_fd, &st) != 0
                || !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1
                || (st.st_mode & 07777) != 0600
                || ::flock(m_fd, LOCK_EX) != 0) {
            setError(error, QStringLiteral("openvpn_dns_state_lock_failed"));
            return false;
        }
        return true;
    }

private:
    int m_fd = -1;
};

bool writeAll(int fd, const QByteArray &data)
{
    qsizetype offset = 0;
    while (offset < data.size()) {
        const ssize_t count = ::write(fd, data.constData() + offset,
                                      static_cast<size_t>(data.size() - offset));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        offset += static_cast<qsizetype>(count);
    }
    return true;
}

bool syncStateDirectory()
{
    const int fd = ::open(kStateDirectory, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (fd < 0) {
        return false;
    }
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
}

QByteArray canonicalBase64(const QByteArray &bytes)
{
    return bytes.toBase64(QByteArray::Base64UrlEncoding
                          | QByteArray::OmitTrailingEquals);
}

bool decodeCanonicalBase64(const QString &text, QByteArray *bytes)
{
    if (!bytes || text.size() > kMaxStateBytes * 2) {
        return false;
    }
    const QByteArray encoded = text.toLatin1();
    const auto decoded = QByteArray::fromBase64Encoding(
            encoded, QByteArray::Base64UrlEncoding
                             | QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded || canonicalBase64(*decoded) != encoded) {
        return false;
    }
    *bytes = *decoded;
    return true;
}

QByteArray encodeState(const DnsState &state)
{
    QJsonArray records;
    for (const DnsRecord &record : state.records) {
        records.append(QJsonObject{
            {QStringLiteral("service"), record.service},
            {QStringLiteral("had_original"), record.hadOriginal},
            {QStringLiteral("original_plist"),
             QString::fromLatin1(canonicalBase64(
                     ownedFieldsPlist(record.originalPlist)))},
            {QStringLiteral("preimage_plist"),
             QString::fromLatin1(canonicalBase64(
                     ownedFieldsPlist(record.preimagePlist)))},
            {QStringLiteral("applied_plist"),
             QString::fromLatin1(canonicalBase64(
                     ownedFieldsPlist(record.appliedPlist)))},
            {QStringLiteral("owns_search_domains"),
             record.ownsSearchDomains},
            {QStringLiteral("phase"),
             record.phase == JournalPhase::Applied
                     ? QStringLiteral("applied")
                     : QStringLiteral("prepared")}
        });
    }
    const QJsonObject object{
        {QStringLiteral("type"), QStringLiteral("tribe_openvpn_dns_journal_v3")},
        {QStringLiteral("schema"), 3},
        {QStringLiteral("session"), state.session},
        {QStringLiteral("device"), state.device},
        {QStringLiteral("servers"), QJsonArray::fromStringList(state.servers)},
        {QStringLiteral("search_domains"),
         QJsonArray::fromStringList(state.searchDomains)},
        {QStringLiteral("active_services"),
         QJsonArray::fromStringList(state.activeServices)},
        {QStringLiteral("records"), records}
    };
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

bool validServiceIdentifier(const QString &service)
{
    static const QRegularExpression pattern(
            QStringLiteral(R"(^[0-9A-Fa-f-]{8,64}$)"));
    return pattern.match(service).hasMatch();
}

bool validDesiredDns(const QStringList &servers,
                     const QStringList &searchDomains)
{
    if (servers.isEmpty() || servers.size() > 8
            || searchDomains.size() > 16) {
        return false;
    }
    QSet<QString> uniqueServers;
    for (const QString &server : servers) {
        const QHostAddress address(server);
        if (address.isNull() || address.toString() != server
                || uniqueServers.contains(server)) {
            return false;
        }
        uniqueServers.insert(server);
    }
    static const QRegularExpression domainPattern(
            QStringLiteral(R"(^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$)"));
    QSet<QString> uniqueDomains;
    for (const QString &domain : searchDomains) {
        if (!domainPattern.match(domain).hasMatch()
                || uniqueDomains.contains(domain)) {
            return false;
        }
        uniqueDomains.insert(domain);
    }
    return true;
}

bool decodeState(const QByteArray &bytes, DnsState *state)
{
    if (!state || bytes.isEmpty() || bytes.size() > kMaxStateBytes) {
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return false;
    }
    const QJsonObject object = document.object();
    // A v1 journal was used only by pre-release developer builds. Accept it
    // for exact crash recovery, then every new write upgrades to v2.
    if (object.value(QStringLiteral("type"))
                    == QLatin1String("tribe_openvpn_dns_state_v1")) {
        static const QSet<QString> legacyKeys{
            QStringLiteral("type"), QStringLiteral("schema"),
            QStringLiteral("session"), QStringLiteral("device"),
            QStringLiteral("service"), QStringLiteral("had_original"),
            QStringLiteral("original_plist"),
            QStringLiteral("applied_plist")
        };
        const QStringList actual = object.keys();
        DnsState decoded;
        DnsRecord record;
        decoded.session = object.value(QStringLiteral("session")).toString();
        decoded.device = object.value(QStringLiteral("device")).toString();
        record.service = object.value(QStringLiteral("service")).toString();
        record.hadOriginal = object.value(
                QStringLiteral("had_original")).toBool();
        record.phase = JournalPhase::Applied;
        static const QRegularExpression devicePattern(
                QStringLiteral(R"(^(?:utun|tun)[0-9]{1,3}$)"));
        if (QSet<QString>(actual.cbegin(), actual.cend()) != legacyKeys
                || object.value(QStringLiteral("schema")).toDouble() != 1.0
                || !object.value(QStringLiteral("had_original")).isBool()
                || !validSessionToken(decoded.session)
                || !devicePattern.match(decoded.device).hasMatch()
                || !validServiceIdentifier(record.service)
                || !decodeCanonicalBase64(
                        object.value(QStringLiteral("original_plist")).toString(),
                        &record.originalPlist)
                || !decodeCanonicalBase64(
                        object.value(QStringLiteral("applied_plist")).toString(),
                        &record.appliedPlist)
                || record.appliedPlist.isEmpty()
                || (record.hadOriginal != !record.originalPlist.isEmpty())) {
            return false;
        }
        record.preimagePlist = record.originalPlist;
        decoded.activeServices.append(record.service);
        decoded.records.append(record);
        *state = decoded;
        return true;
    }
    static const QSet<QString> keys{
        QStringLiteral("type"), QStringLiteral("schema"),
        QStringLiteral("session"), QStringLiteral("device"),
        QStringLiteral("servers"), QStringLiteral("search_domains"),
        QStringLiteral("active_services"), QStringLiteral("records")
    };
    const QStringList actualKeys = object.keys();
    const bool legacyV2 = object.value(QStringLiteral("type"))
                    == QLatin1String("tribe_openvpn_dns_journal_v2")
            && object.value(QStringLiteral("schema")).isDouble()
            && object.value(QStringLiteral("schema")).toDouble() == 2.0;
    const bool currentV3 = object.value(QStringLiteral("type"))
                    == QLatin1String("tribe_openvpn_dns_journal_v3")
            && object.value(QStringLiteral("schema")).isDouble()
            && object.value(QStringLiteral("schema")).toDouble() == 3.0;
    if (QSet<QString>(actualKeys.cbegin(), actualKeys.cend()) != keys
            || (!legacyV2 && !currentV3)
            || !object.value(QStringLiteral("servers")).isArray()
            || !object.value(QStringLiteral("search_domains")).isArray()
            || !object.value(QStringLiteral("active_services")).isArray()
            || !object.value(QStringLiteral("records")).isArray()) {
        return false;
    }
    DnsState decoded;
    decoded.session = object.value(QStringLiteral("session")).toString();
    decoded.device = object.value(QStringLiteral("device")).toString();
    for (const QJsonValue &value : object.value(
                 QStringLiteral("servers")).toArray()) {
        if (!value.isString()) return false;
        decoded.servers.append(value.toString());
    }
    for (const QJsonValue &value : object.value(
                 QStringLiteral("search_domains")).toArray()) {
        if (!value.isString()) return false;
        decoded.searchDomains.append(value.toString());
    }
    for (const QJsonValue &value : object.value(
                 QStringLiteral("active_services")).toArray()) {
        if (!value.isString()) return false;
        decoded.activeServices.append(value.toString());
    }
    const QJsonArray recordValues = object.value(
            QStringLiteral("records")).toArray();
    if (recordValues.isEmpty() || recordValues.size() > kMaxServiceRecords) {
        return false;
    }
    QSet<QString> uniqueRecords;
    static const QSet<QString> legacyRecordKeys{
        QStringLiteral("service"), QStringLiteral("had_original"),
        QStringLiteral("original_plist"), QStringLiteral("applied_plist"),
        QStringLiteral("phase")
    };
    static const QSet<QString> currentRecordKeys{
        QStringLiteral("service"), QStringLiteral("had_original"),
        QStringLiteral("original_plist"), QStringLiteral("preimage_plist"),
        QStringLiteral("applied_plist"),
        QStringLiteral("owns_search_domains"), QStringLiteral("phase")
    };
    for (const QJsonValue &value : recordValues) {
        if (!value.isObject()) return false;
        const QJsonObject entry = value.toObject();
        const QStringList entryKeys = entry.keys();
        DnsRecord record;
        record.service = entry.value(QStringLiteral("service")).toString();
        record.hadOriginal = entry.value(
                QStringLiteral("had_original")).toBool();
        const QString phase = entry.value(QStringLiteral("phase")).toString();
        record.phase = phase == QLatin1String("applied")
                ? JournalPhase::Applied : JournalPhase::Prepared;
        const QSet<QString> expectedRecordKeys = currentV3
                ? currentRecordKeys : legacyRecordKeys;
        if (QSet<QString>(entryKeys.cbegin(), entryKeys.cend())
                    != expectedRecordKeys
                || !entry.value(QStringLiteral("had_original")).isBool()
                || (phase != QLatin1String("prepared")
                    && phase != QLatin1String("applied"))
                || !validServiceIdentifier(record.service)
                || uniqueRecords.contains(record.service)
                || !decodeCanonicalBase64(
                        entry.value(QStringLiteral("original_plist")).toString(),
                        &record.originalPlist)
                || !decodeCanonicalBase64(
                        entry.value(QStringLiteral("applied_plist")).toString(),
                        &record.appliedPlist)
                || (currentV3
                    && (!entry.value(QStringLiteral("owns_search_domains")).isBool()
                        || !decodeCanonicalBase64(
                                entry.value(QStringLiteral("preimage_plist")).toString(),
                                &record.preimagePlist)))
                || record.appliedPlist.isEmpty()
                || (record.hadOriginal != !record.originalPlist.isEmpty())) {
            return false;
        }
        if (currentV3) {
            record.ownsSearchDomains = entry.value(
                    QStringLiteral("owns_search_domains")).toBool();
        } else {
            record.preimagePlist = record.originalPlist;
            record.ownsSearchDomains = !decoded.searchDomains.isEmpty();
        }
        uniqueRecords.insert(record.service);
        decoded.records.append(record);
    }
    static const QRegularExpression devicePattern(
            QStringLiteral(R"(^(?:utun|tun)[0-9]{1,3}$)"));
    QSet<QString> uniqueActive;
    for (const QString &active : decoded.activeServices) {
        if (!validServiceIdentifier(active) || !uniqueRecords.contains(active)
                || uniqueActive.contains(active)) {
            return false;
        }
        uniqueActive.insert(active);
    }
    if (!validSessionToken(decoded.session)
            || !devicePattern.match(decoded.device).hasMatch()
            || !validDesiredDns(decoded.servers, decoded.searchDomains)
            || decoded.activeServices.isEmpty()
            || decoded.activeServices.size() > kMaxServiceRecords) {
        return false;
    }
    *state = decoded;
    return true;
}

bool readState(DnsState *state, bool *exists, QString *error)
{
    if (!state || !exists) {
        return false;
    }
    *exists = false;
    const int fd = ::open(kStatePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) {
            return true;
        }
        setError(error, QStringLiteral("openvpn_dns_state_open_failed"));
        return false;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0
            || st.st_nlink != 1 || (st.st_mode & 07777) != 0600
            || st.st_size <= 0 || st.st_size > kMaxStateBytes) {
        ::close(fd);
        setError(error, QStringLiteral("openvpn_dns_state_metadata_invalid"));
        return false;
    }
    QByteArray bytes;
    bytes.reserve(static_cast<qsizetype>(st.st_size));
    char buffer[8192];
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 || bytes.size() + count > kMaxStateBytes) {
            ::close(fd);
            setError(error, QStringLiteral("openvpn_dns_state_read_failed"));
            return false;
        }
        bytes.append(buffer, static_cast<qsizetype>(count));
    }
    ::close(fd);
    if (!decodeState(bytes, state)) {
        setError(error, QStringLiteral("openvpn_dns_state_schema_invalid"));
        return false;
    }
    *exists = true;
    return true;
}

bool writeState(const DnsState &state, QString *error)
{
    const QByteArray bytes = encodeState(state);
    if (bytes.isEmpty() || bytes.size() > kMaxStateBytes) {
        setError(error, QStringLiteral("openvpn_dns_state_encode_failed"));
        return false;
    }
    QString temporaryPath;
    int fd = -1;
    for (int attempt = 0; attempt < 8 && fd < 0; ++attempt) {
        temporaryPath = QStringLiteral("%1/.openvpn-dns-state.%2.%3")
                .arg(QLatin1String(kStateDirectory))
                .arg(static_cast<qulonglong>(::getpid()))
                .arg(QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char('0'));
        fd = ::open(QFile::encodeName(temporaryPath).constData(),
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    }
    bool writeOk = fd >= 0;
    if (writeOk) {
        writeOk = ::fchmod(fd, 0600) == 0 && writeAll(fd, bytes)
                && ::fsync(fd) == 0;
        const bool closeOk = ::close(fd) == 0;
        fd = -1;
        writeOk = writeOk && closeOk;
    }
    if (!writeOk) {
        if (fd >= 0) {
            ::close(fd);
        }
        if (!temporaryPath.isEmpty()) {
            ::unlink(QFile::encodeName(temporaryPath).constData());
        }
        setError(error, QStringLiteral("openvpn_dns_state_write_failed"));
        return false;
    }
    if (::rename(QFile::encodeName(temporaryPath).constData(), kStatePath) != 0
            || !syncStateDirectory()) {
        ::unlink(QFile::encodeName(temporaryPath).constData());
        setError(error, QStringLiteral("openvpn_dns_state_commit_failed"));
        return false;
    }
    return true;
}

bool removeState(QString *error)
{
    if (::unlink(kStatePath) != 0 && errno != ENOENT) {
        setError(error, QStringLiteral("openvpn_dns_state_remove_failed"));
        return false;
    }
    if (!syncStateDirectory()) {
        setError(error, QStringLiteral("openvpn_dns_state_directory_sync_failed"));
        return false;
    }
    return true;
}

QString cfString(CFTypeRef value)
{
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
}

CFStringRef makeCfString(const QString &value)
{
    return CFStringCreateWithCString(kCFAllocatorDefault,
                                     value.toUtf8().constData(),
                                     kCFStringEncodingUTF8);
}

QByteArray serializePlist(CFPropertyListRef value)
{
    if (!value) {
        return {};
    }
    CFErrorRef error = nullptr;
    CFDataRef data = CFPropertyListCreateData(
            kCFAllocatorDefault, value, kCFPropertyListBinaryFormat_v1_0,
            0, &error);
    QByteArray result;
    if (data) {
        result = QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(data)),
                            static_cast<qsizetype>(CFDataGetLength(data)));
        CFRelease(data);
    }
    if (error) {
        CFRelease(error);
    }
    return result;
}

CFDictionaryRef decodeDictionary(const QByteArray &bytes)
{
    if (bytes.isEmpty() || bytes.size() > kMaxStateBytes) {
        return nullptr;
    }
    CFDataRef data = CFDataCreate(
            kCFAllocatorDefault,
            reinterpret_cast<const UInt8 *>(bytes.constData()), bytes.size());
    if (!data) {
        return nullptr;
    }
    CFErrorRef error = nullptr;
    CFPropertyListRef value = CFPropertyListCreateWithData(
            kCFAllocatorDefault, data, kCFPropertyListImmutable, nullptr, &error);
    CFRelease(data);
    if (error) {
        CFRelease(error);
    }
    if (!value || CFGetTypeID(value) != CFDictionaryGetTypeID()) {
        if (value) {
            CFRelease(value);
        }
        return nullptr;
    }
    return static_cast<CFDictionaryRef>(value);
}

CFMutableDictionaryRef copyOwnedFields(CFDictionaryRef source)
{
    CFMutableDictionaryRef projection = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFCopyStringDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
    if (!projection) return nullptr;
    const CFStringRef ownedKeys[]{kSCPropNetDNSServerAddresses,
                                  kSCPropNetDNSSearchDomains};
    if (source) {
        for (CFStringRef key : ownedKeys) {
            CFTypeRef value = CFDictionaryGetValue(source, key);
            if (value) CFDictionarySetValue(projection, key, value);
        }
    }
    return projection;
}

QByteArray ownedFieldsPlist(const QByteArray &plist)
{
    if (plist.isEmpty()) return {};
    CFDictionaryRef dictionary = decodeDictionary(plist);
    if (!dictionary) return {};
    CFMutableDictionaryRef projection = copyOwnedFields(dictionary);
    CFRelease(dictionary);
    const QByteArray result = serializePlist(projection);
    if (projection) CFRelease(projection);
    return result;
}

bool dictionaryFieldEqual(CFDictionaryRef left, CFDictionaryRef right,
                          CFStringRef key)
{
    const bool leftHas = left && CFDictionaryContainsKey(left, key);
    const bool rightHas = right && CFDictionaryContainsKey(right, key);
    if (leftHas != rightHas) return false;
    if (!leftHas) return true;
    return CFEqual(CFDictionaryGetValue(left, key),
                   CFDictionaryGetValue(right, key));
}

bool ownedFieldsEqual(CFDictionaryRef current,
                      CFDictionaryRef expectedProjection,
                      bool includeSearchDomains = true)
{
    return dictionaryFieldEqual(current, expectedProjection,
                                kSCPropNetDNSServerAddresses)
            && (!includeSearchDomains
                || dictionaryFieldEqual(current, expectedProjection,
                                        kSCPropNetDNSSearchDomains));
}

void replaceDictionaryField(CFMutableDictionaryRef destination,
                            CFDictionaryRef source, CFStringRef key)
{
    CFDictionaryRemoveValue(destination, key);
    if (source && CFDictionaryContainsKey(source, key)) {
        CFDictionarySetValue(destination, key,
                             CFDictionaryGetValue(source, key));
    }
}

CFMutableDictionaryRef restoreOwnedFields(CFDictionaryRef current,
                                          CFDictionaryRef applied,
                                          CFDictionaryRef preimage,
                                          CFDictionaryRef baseline)
{
    CFMutableDictionaryRef restored = current
            ? CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, current)
            : CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                        &kCFCopyStringDictionaryKeyCallBacks,
                                        &kCFTypeDictionaryValueCallBacks);
    if (!restored) return nullptr;
    const CFStringRef ownedKeys[]{kSCPropNetDNSServerAddresses,
                                  kSCPropNetDNSSearchDomains};
    for (CFStringRef key : ownedKeys) {
        // A field still belongs to Tribe when it equals either side of the
        // durable transition.  A third value is an external winner and must be
        // preserved independently of the other owned field.
        if (shouldRestoreOwnedField(
                    dictionaryFieldEqual(current, applied, key),
                    dictionaryFieldEqual(current, preimage, key))) {
            replaceDictionaryField(restored, baseline, key);
        }
    }
    return restored;
}

bool primaryServices(SCDynamicStoreRef store, QStringList *services,
                     QString *error)
{
    if (!store || !services) return false;
    services->clear();
    const CFStringRef paths[]{CFSTR("State:/Network/Global/IPv4"),
                             CFSTR("State:/Network/Global/IPv6")};
    for (CFStringRef path : paths) {
        CFTypeRef value = SCDynamicStoreCopyValue(store, path);
        if (!value) continue;
        if (CFGetTypeID(value) != CFDictionaryGetTypeID()) {
            CFRelease(value);
            setError(error, QStringLiteral("openvpn_dns_global_type_invalid"));
            return false;
        }
        CFTypeRef primaryValue = CFDictionaryGetValue(
                static_cast<CFDictionaryRef>(value),
                CFSTR("PrimaryService"));
        if (primaryValue
                && CFGetTypeID(primaryValue) != CFStringGetTypeID()) {
            CFRelease(value);
            setError(error, QStringLiteral(
                    "openvpn_dns_primary_service_type_invalid"));
            return false;
        }
        const QString service = cfString(primaryValue);
        CFRelease(value);
        if (!service.isEmpty()) {
            if (!validServiceIdentifier(service)) {
                setError(error, QStringLiteral(
                        "openvpn_dns_primary_service_invalid"));
                return false;
            }
            if (!services->contains(service)) services->append(service);
        }
    }
    return true;
}

bool protectedServices(SCDynamicStoreRef store, QStringList *services,
                       QString *error)
{
    QStringList primaries;
    if (!services || !primaryServices(store, &primaries, error)) return false;
    services->clear();
    for (const QString &primary : primaries) services->append(primary);

    CFArrayRef keys = SCDynamicStoreCopyKeyList(
            store, CFSTR("Setup:/Network/Service/[0-9A-Fa-f-]+"));
    if (keys) {
        static const QRegularExpression keyPattern(QStringLiteral(
                R"(^Setup:/Network/Service/([0-9A-Fa-f-]{8,64})(?:/.*)?$)"));
        QStringList remaining;
        const CFIndex count = CFArrayGetCount(keys);
        for (CFIndex index = 0; index < count; ++index) {
            const QString key = cfString(CFArrayGetValueAtIndex(keys, index));
            const QRegularExpressionMatch match = keyPattern.match(key);
            if (!match.hasMatch()) continue;
            const QString service = match.captured(1);
            if (!services->contains(service) && !remaining.contains(service)) {
                remaining.append(service);
            }
        }
        CFRelease(keys);
        std::sort(remaining.begin(), remaining.end());
        services->append(remaining);
    }
    if (services->size() > kMaxServiceRecords) {
        setError(error, QStringLiteral("openvpn_dns_service_count_exceeded"));
        return false;
    }
    return true;
}

CFStringRef dnsKey(const QString &service)
{
    return makeCfString(QStringLiteral("Setup:/Network/Service/%1/DNS")
                        .arg(service));
}

void setStringArray(CFMutableDictionaryRef dictionary, CFStringRef key,
                    const QStringList &values)
{
    CFMutableArrayRef array = CFArrayCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    for (const QString &value : values) {
        CFStringRef string = makeCfString(value);
        if (string) {
            CFArrayAppendValue(array, string);
            CFRelease(string);
        }
    }
    CFDictionarySetValue(dictionary, key, array);
    CFRelease(array);
}

CFDictionaryRef copyDnsDictionary(SCDynamicStoreRef store, CFStringRef key,
                                  bool *exists, QString *error)
{
    if (exists) *exists = false;
    CFTypeRef current = SCDynamicStoreCopyValue(store, key);
    if (!current) return nullptr;
    if (exists) *exists = true;
    if (CFGetTypeID(current) != CFDictionaryGetTypeID()) {
        CFRelease(current);
        setError(error, QStringLiteral("openvpn_dns_current_type_invalid"));
        return nullptr;
    }
    return static_cast<CFDictionaryRef>(current);
}

int recordIndex(const DnsState &state, const QString &service)
{
    for (int index = 0; index < state.records.size(); ++index) {
        if (state.records.at(index).service == service) return index;
    }
    return -1;
}

CFMutableDictionaryRef desiredDictionary(CFDictionaryRef base,
                                         const DnsState &state,
                                         CFDictionaryRef baseline,
                                         bool previouslyOwnedSearchDomains)
{
    CFMutableDictionaryRef applied = base
            ? CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, base)
            : CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                        &kCFCopyStringDictionaryKeyCallBacks,
                                        &kCFTypeDictionaryValueCallBacks);
    if (!applied) return nullptr;
    setStringArray(applied, kSCPropNetDNSServerAddresses, state.servers);
    if (!state.searchDomains.isEmpty()) {
        setStringArray(applied, kSCPropNetDNSSearchDomains,
                       state.searchDomains);
    } else if (previouslyOwnedSearchDomains) {
        // A same-session update may stop owning SearchDomains. Release that
        // field to the pre-VPN baseline instead of retaining the old pushed
        // value from the current dictionary.
        replaceDictionaryField(applied, baseline,
                               kSCPropNetDNSSearchDomains);
    }
    return applied;
}

bool readbackMatches(SCDynamicStoreRef store, CFStringRef key,
                     bool expectedExists, CFDictionaryRef expected,
                     QString *error)
{
    bool exists = false;
    CFDictionaryRef current = copyDnsDictionary(store, key, &exists, error);
    if (exists && !current) return false;
    const bool matches = exists == expectedExists
            && (!exists || CFEqual(current, expected));
    if (current) CFRelease(current);
    if (!matches) {
        setError(error, QStringLiteral("openvpn_dns_readback_mismatch"));
    }
    return matches;
}

bool persistAfterRecordRemoval(DnsState *state, int index, QString *error)
{
    if (!state || index < 0 || index >= state->records.size()) return false;
    const QString removedService = state->records.at(index).service;
    state->records.removeAt(index);
    state->activeServices.removeAll(removedService);
    if (state->records.isEmpty()) return removeState(error);
    // Recovery may remove the last formerly-active record before older
    // inactive records. Keep the intermediate journal decodable; active
    // services are advisory during recovery and reconciled before use.
    if (state->activeServices.isEmpty()) {
        state->activeServices.append(state->records.constFirst().service);
    }
    return writeState(*state, error);
}

bool restoreRecordLocked(SCDynamicStoreRef store, DnsState *state, int index,
                         QString *error)
{
    if (!state || index < 0 || index >= state->records.size()) return false;
    const DnsRecord record = state->records.at(index);
    CFDictionaryRef applied = decodeDictionary(record.appliedPlist);
    CFDictionaryRef baseline = record.hadOriginal
            ? decodeDictionary(record.originalPlist) : nullptr;
    CFDictionaryRef preimage = record.preimagePlist.isEmpty()
            ? nullptr : decodeDictionary(record.preimagePlist);
    CFStringRef key = dnsKey(record.service);
    if (!applied || (record.hadOriginal && !baseline)
            || (!record.preimagePlist.isEmpty() && !preimage) || !key) {
        if (applied) CFRelease(applied);
        if (baseline) CFRelease(baseline);
        if (preimage) CFRelease(preimage);
        if (key) CFRelease(key);
        setError(error, QStringLiteral("openvpn_dns_state_plist_invalid"));
        return false;
    }

    bool exists = false;
    CFDictionaryRef current = copyDnsDictionary(store, key, &exists, error);
    if (exists && !current) {
        CFRelease(key);
        CFRelease(applied);
        if (baseline) CFRelease(baseline);
        if (preimage) CFRelease(preimage);
        return false;
    }
    CFMutableDictionaryRef restoredValue = restoreOwnedFields(
            current, applied, preimage, baseline);
    if (!restoredValue) {
        if (current) CFRelease(current);
        CFRelease(key);
        CFRelease(applied);
        if (baseline) CFRelease(baseline);
        if (preimage) CFRelease(preimage);
        setError(error, QStringLiteral("openvpn_dns_restore_merge_failed"));
        return false;
    }
    // Preserve a dictionary that existed before Tribe even when its two owned
    // fields were absent.  If it did not exist, retain it only when an external
    // actor added unrelated fields while the tunnel was active.
    const bool expectedExists = record.hadOriginal
            || CFDictionaryGetCount(restoredValue) > 0;
    const bool alreadyRestored = exists == expectedExists
            && (!exists || CFEqual(current, restoredValue));
    bool restored = alreadyRestored;
    if (!alreadyRestored) {
        restored = expectedExists
                ? SCDynamicStoreSetValue(store, key, restoredValue)
                : SCDynamicStoreRemoveValue(store, key);
        if (restored) SCDynamicStoreNotifyValue(store, key);
        if (restored) {
            restored = readbackMatches(store, key, expectedExists,
                                       restoredValue, error);
        }
    }
    if (current) CFRelease(current);
    CFRelease(restoredValue);
    CFRelease(key);
    CFRelease(applied);
    if (baseline) CFRelease(baseline);
    if (preimage) CFRelease(preimage);
    if (!restored) {
        setError(error, QStringLiteral("openvpn_dns_restore_failed"));
        return false;
    }
    return persistAfterRecordRemoval(state, index, error);
}

bool restoreLocked(SCDynamicStoreRef store, const QString &requestedSession,
                   const QString &requestedDevice, bool recovery,
                   bool sessionOnly, QString *error)
{
    DnsState state;
    bool exists = false;
    if (!readState(&state, &exists, error)) {
        return false;
    }
    if (!exists) {
        return true;
    }
    const bool sessionMatches = state.session == requestedSession
            && (sessionOnly || state.device == requestedDevice);
    if (!recovery && !sessionMatches) {
        // A late down hook from an older process cannot restore over the
        // currently-owned session.
        return true;
    }

    while (!state.records.isEmpty()) {
        if (!restoreRecordLocked(store, &state, state.records.size() - 1,
                                 error)) {
            return false;
        }
    }
    return true;
}

enum class ApplyRecordResult {
    Applied,
    PrimaryChanged,
    Failed
};

ApplyRecordResult applyRecordLocked(SCDynamicStoreRef store, DnsState *state,
                                    const QString &service, QString *error)
{
    CFStringRef key = dnsKey(service);
    if (!key || !state) {
        if (key) CFRelease(key);
        setError(error, QStringLiteral("openvpn_dns_service_key_invalid"));
        return ApplyRecordResult::Failed;
    }
    bool exists = false;
    CFDictionaryRef current = copyDnsDictionary(store, key, &exists, error);
    if (exists && !current) {
        CFRelease(key);
        return ApplyRecordResult::Failed;
    }

    int index = recordIndex(*state, service);
    bool hadBaseline = exists;
    bool previouslyOwnedSearchDomains = false;
    bool previousPhaseApplied = false;
    CFDictionaryRef previousApplied = nullptr;
    CFDictionaryRef previousPreimage = nullptr;
    CFMutableDictionaryRef baseline = nullptr;
    CFMutableDictionaryRef applied = nullptr;
    CFMutableDictionaryRef preimageProjection = nullptr;
    CFMutableDictionaryRef appliedProjection = nullptr;
    const auto releaseValues = [&]() {
        if (current) CFRelease(current);
        if (previousApplied) CFRelease(previousApplied);
        if (previousPreimage) CFRelease(previousPreimage);
        if (baseline) CFRelease(baseline);
        if (applied) CFRelease(applied);
        if (preimageProjection) CFRelease(preimageProjection);
        if (appliedProjection) CFRelease(appliedProjection);
        CFRelease(key);
    };

    if (index >= 0) {
        const DnsRecord existing = state->records.at(index);
        previousApplied = decodeDictionary(existing.appliedPlist);
        previousPreimage = existing.preimagePlist.isEmpty()
                ? nullptr : decodeDictionary(existing.preimagePlist);
        CFDictionaryRef persistedBaseline = existing.hadOriginal
                ? decodeDictionary(existing.originalPlist) : nullptr;
        const bool recordValid = previousApplied
                && (existing.preimagePlist.isEmpty() || previousPreimage)
                && (!existing.hadOriginal || persistedBaseline);
        if (!recordValid) {
            if (persistedBaseline) CFRelease(persistedBaseline);
            releaseValues();
            setError(error, QStringLiteral("openvpn_dns_record_applied_invalid"));
            return ApplyRecordResult::Failed;
        }
        previouslyOwnedSearchDomains = existing.ownsSearchDomains;
        previousPhaseApplied = existing.phase == JournalPhase::Applied;
        const bool matchesApplied = ownedFieldsEqual(
                current, previousApplied, previouslyOwnedSearchDomains);
        const bool matchesPreparedPreimage = existing.phase
                        == JournalPhase::Prepared
                && ownedFieldsEqual(current, previousPreimage,
                                    previouslyOwnedSearchDomains);
        if (!matchesApplied && !matchesPreparedPreimage) {
            if (persistedBaseline) CFRelease(persistedBaseline);
            releaseValues();
            setError(error, QStringLiteral("openvpn_dns_owned_field_drift"));
            return ApplyRecordResult::Failed;
        }
        hadBaseline = existing.hadOriginal;
        baseline = persistedBaseline
                ? CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0,
                                                persistedBaseline)
                : copyOwnedFields(nullptr);
        if (persistedBaseline) CFRelease(persistedBaseline);
    } else {
        baseline = copyOwnedFields(current);
    }

    if (!baseline) {
        releaseValues();
        setError(error, QStringLiteral("openvpn_dns_baseline_create_failed"));
        return ApplyRecordResult::Failed;
    }

    // SearchDomains is deliberately not owned when OpenVPN did not push it.
    // If a later same-session update starts owning it, capture the current
    // external value as that field's new baseline before applying the push.
    if (!previouslyOwnedSearchDomains && !state->searchDomains.isEmpty()) {
        replaceDictionaryField(baseline, current,
                               kSCPropNetDNSSearchDomains);
        if (current && CFDictionaryContainsKey(
                    current, kSCPropNetDNSSearchDomains)) {
            hadBaseline = true;
        }
    }

    applied = desiredDictionary(current, *state, baseline,
                                previouslyOwnedSearchDomains);
    const bool nextOwnsSearchDomains = !state->searchDomains.isEmpty();
    if (index >= 0 && previousPhaseApplied
            && previouslyOwnedSearchDomains == nextOwnsSearchDomains
            && exists && applied && CFEqual(current, applied)) {
        const bool activeChanged = !state->activeServices.contains(service);
        if (activeChanged) state->activeServices.append(service);
        releaseValues();
        if (activeChanged && !writeState(*state, error)) {
            return ApplyRecordResult::Failed;
        }
        return ApplyRecordResult::Applied;
    }
    preimageProjection = copyOwnedFields(current);
    appliedProjection = copyOwnedFields(applied);
    DnsRecord record;
    record.service = service;
    record.hadOriginal = hadBaseline;
    record.originalPlist = hadBaseline ? serializePlist(baseline) : QByteArray{};
    record.preimagePlist = exists
            ? serializePlist(preimageProjection) : QByteArray{};
    record.appliedPlist = serializePlist(appliedProjection);
    record.ownsSearchDomains = nextOwnsSearchDomains;
    record.phase = JournalPhase::Prepared;
    if (!applied || !preimageProjection || !appliedProjection
            || record.appliedPlist.isEmpty()
            || (record.hadOriginal && record.originalPlist.isEmpty())
            || (exists && record.preimagePlist.isEmpty())
            || (index < 0 && state->records.size() >= kMaxServiceRecords)) {
        releaseValues();
        setError(error, QStringLiteral("openvpn_dns_record_create_failed"));
        return ApplyRecordResult::Failed;
    }
    if (index >= 0) state->records[index] = record;
    else {
        state->records.append(record);
        index = state->records.size() - 1;
    }
    if (!state->activeServices.contains(service)) {
        state->activeServices.append(service);
    }
    if (!writeState(*state, error)) {
        releaseValues();
        return ApplyRecordResult::Failed;
    }

    // SCDynamicStore has no compare-and-set primitive. Narrow the race by
    // re-reading both ownership and the exact snapshot immediately before the
    // write, then require an exact post-write readback.
    QStringList currentlyProtected;
    if (!protectedServices(store, &currentlyProtected, error)) {
        releaseValues();
        return ApplyRecordResult::Failed;
    }
    bool latestExists = false;
    CFDictionaryRef latest = copyDnsDictionary(store, key, &latestExists, error);
    if (latestExists && !latest) {
        releaseValues();
        return ApplyRecordResult::Failed;
    }
    const bool snapshotUnchanged = latestExists == exists
            && (!exists || CFEqual(latest, current));
    if (latest) CFRelease(latest);
    if (!currentlyProtected.contains(service) || !snapshotUnchanged) {
        releaseValues();
        return ApplyRecordResult::PrimaryChanged;
    }

    const bool writeNeeded = !exists || !CFEqual(current, applied);
    const bool appliedOk = !writeNeeded
            || SCDynamicStoreSetValue(store, key, applied);
    if (appliedOk && writeNeeded) {
        SCDynamicStoreNotifyValue(store, key);
    }
    const bool readbackOk = appliedOk
            && readbackMatches(store, key, true, applied, error);
    releaseValues();
    if (!readbackOk) {
        setError(error, QStringLiteral("openvpn_dns_apply_or_readback_failed"));
        return ApplyRecordResult::Failed;
    }
    state->records[index].phase = JournalPhase::Applied;
    if (!writeState(*state, error)) return ApplyRecordResult::Failed;
    return ApplyRecordResult::Applied;
}

bool reconcileLocked(SCDynamicStoreRef store, DnsState *state, QString *error)
{
    if (!state || !validDesiredDns(state->servers, state->searchDomains)) {
        setError(error, QStringLiteral("openvpn_dns_desired_state_invalid"));
        return false;
    }
    const QByteArray stateBeforeReconcile = encodeState(*state);
    for (int churn = 0; churn < 8; ++churn) {
        QStringList targetServices;
        if (!protectedServices(store, &targetServices, error)) return false;
        if (targetServices.isEmpty()) {
            // During sleep or a route handoff there may be no primary service.
            // Keep every old record applied and let the store notification plus
            // watchdog reconcile as soon as a new service is published.
            return true;
        }

        bool changed = false;
        for (const QString &service : targetServices) {
            const ApplyRecordResult result = applyRecordLocked(
                    store, state, service, error);
            if (result == ApplyRecordResult::Failed) return false;
            if (result == ApplyRecordResult::PrimaryChanged) {
                changed = true;
                break;
            }
        }
        if (changed) continue;

        QStringList confirmedServices;
        if (!protectedServices(store, &confirmedServices, error)) return false;
        if (confirmedServices != targetServices) continue;
        state->activeServices = targetServices;

        // New IPv4/IPv6 primaries are proven first. Only then release records
        // belonging exclusively to an old primary.
        for (int index = state->records.size() - 1; index >= 0; --index) {
            if (targetServices.contains(state->records.at(index).service)) {
                continue;
            }
            QStringList immediatelyCurrent;
            if (!protectedServices(store, &immediatelyCurrent, error)) return false;
            if (immediatelyCurrent != targetServices) {
                changed = true;
                break;
            }
            if (!restoreRecordLocked(store, state, index, error)) return false;
        }
        if (changed) continue;
        state->activeServices = targetServices;
        return encodeState(*state) == stateBeforeReconcile
                || writeState(*state, error);
    }
    setError(error, QStringLiteral("openvpn_dns_primary_service_churn"));
    return false;
}

bool applyLocked(SCDynamicStoreRef store, const QString &session,
                 const QString &device, const QStringList &servers,
                 const QStringList &searchDomains, QString *error)
{
    DnsState state;
    bool exists = false;
    if (!readState(&state, &exists, error)) return false;
    if (exists) {
        if (state.session != session) {
            setError(error, QStringLiteral("openvpn_dns_owner_busy"));
            return false;
        }
        state.device = device;
        state.servers = servers;
        state.searchDomains = searchDomains;
    } else {
        state.session = session;
        state.device = device;
        state.servers = servers;
        state.searchDomains = searchDomains;
    }
    return reconcileLocked(store, &state, error);
}

SCDynamicStoreRef createStore()
{
    return SCDynamicStoreCreate(kCFAllocatorDefault,
                                CFSTR("TribeVPN OpenVPN DNS security"),
                                nullptr, nullptr);
}

} // namespace

bool validSessionToken(const QString &token)
{
    static const QRegularExpression pattern(
            QStringLiteral(R"(^[A-Za-z0-9_-]{43}$)"));
    return pattern.match(token).hasMatch();
}

bool shouldRestoreOwnedField(bool currentMatchesApplied,
                             bool currentMatchesPreimage)
{
    return currentMatchesApplied || currentMatchesPreimage;
}

#ifdef TRIBE_DNS_SECURITY_TESTING
QByteArray restoreOwnedFieldsForTesting(const QByteArray &currentBytes,
                                        const QByteArray &appliedBytes,
                                        const QByteArray &preimageBytes,
                                        const QByteArray &baselineBytes)
{
    CFDictionaryRef current = currentBytes.isEmpty()
            ? nullptr : decodeDictionary(currentBytes);
    CFDictionaryRef applied = decodeDictionary(appliedBytes);
    CFDictionaryRef preimage = preimageBytes.isEmpty()
            ? nullptr : decodeDictionary(preimageBytes);
    CFDictionaryRef baseline = baselineBytes.isEmpty()
            ? nullptr : decodeDictionary(baselineBytes);
    if ((!currentBytes.isEmpty() && !current) || !applied
            || (!preimageBytes.isEmpty() && !preimage)
            || (!baselineBytes.isEmpty() && !baseline)) {
        if (current) CFRelease(current);
        if (applied) CFRelease(applied);
        if (preimage) CFRelease(preimage);
        if (baseline) CFRelease(baseline);
        return {};
    }
    CFMutableDictionaryRef restored = restoreOwnedFields(
            current, applied, preimage, baseline);
    const QByteArray result = serializePlist(restored);
    if (restored) CFRelease(restored);
    if (current) CFRelease(current);
    CFRelease(applied);
    if (preimage) CFRelease(preimage);
    if (baseline) CFRelease(baseline);
    return result;
}
#endif

bool parseForeignOptions(const QStringList &environment, QStringList *servers,
                         QStringList *searchDomains, QString *error)
{
    if (!servers || !searchDomains || environment.size() > 4096) {
        setError(error, QStringLiteral("openvpn_dns_environment_invalid"));
        return false;
    }
    servers->clear();
    searchDomains->clear();
    static const QRegularExpression optionName(
            QStringLiteral(R"(^foreign_option_[0-9]{1,3}$)"));
    static const QRegularExpression domainPattern(
            QStringLiteral(R"(^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$)"));
    for (const QString &entry : environment) {
        const qsizetype equals = entry.indexOf(QLatin1Char('='));
        if (equals <= 0) {
            continue;
        }
        const QString name = entry.left(equals);
        if (!name.startsWith(QLatin1String("foreign_option_"))) {
            continue;
        }
        if (!optionName.match(name).hasMatch()) {
            setError(error, QStringLiteral("openvpn_dns_option_name_invalid"));
            return false;
        }
        const QString value = entry.mid(equals + 1);
        if (value.size() > 512 || value.contains(QChar::Null)
                || value.contains(QLatin1Char('\n'))
                || value.contains(QLatin1Char('\r'))) {
            setError(error, QStringLiteral("openvpn_dns_option_value_invalid"));
            return false;
        }
        const QStringList tokens = value.split(
                QRegularExpression(QStringLiteral(R"(\s+)")), Qt::SkipEmptyParts);
        if (tokens.size() != 3 || tokens.at(0) != QLatin1String("dhcp-option")) {
            continue;
        }
        if (tokens.at(1) == QLatin1String("DNS")) {
            const QHostAddress address(tokens.at(2));
            if (address.isNull() || servers->size() >= 8) {
                setError(error, QStringLiteral("openvpn_dns_server_invalid"));
                return false;
            }
            if (!servers->contains(address.toString())) {
                servers->append(address.toString());
            }
        } else if (tokens.at(1) == QLatin1String("DOMAIN")
                   || tokens.at(1) == QLatin1String("DOMAIN-SEARCH")) {
            if (!domainPattern.match(tokens.at(2)).hasMatch()
                    || searchDomains->size() >= 16) {
                setError(error, QStringLiteral("openvpn_dns_search_domain_invalid"));
                return false;
            }
            if (!searchDomains->contains(tokens.at(2))) {
                searchDomains->append(tokens.at(2));
            }
        }
    }
    if (servers->isEmpty()) {
        setError(error, QStringLiteral("openvpn_dns_server_missing"));
        return false;
    }
    return true;
}

bool validateHookInvocation(const QStringList &arguments,
                            const QProcessEnvironment &environment,
                            QString *error)
{
    // argv[0] is the sealed Tribe-service path, argv[1] is our private
    // selector, and argv[2..7] are appended by the pinned OpenVPN ABI.
    if (arguments.size() != 8
            || arguments.at(1) != QLatin1String(kHookArgument)) {
        setError(error, QStringLiteral("openvpn_dns_hook_argv_shape_invalid"));
        return false;
    }

    const QString device = arguments.at(2);
    static const QRegularExpression devicePattern(
            QStringLiteral(R"(^(?:utun|tun)[0-9]{1,3}$)"));
    if (!devicePattern.match(device).hasMatch()
            || environment.value(QStringLiteral("dev")) != device) {
        setError(error, QStringLiteral("openvpn_dns_hook_argv_device_invalid"));
        return false;
    }

    bool mtuOk = false;
    const int mtu = arguments.at(3).toInt(&mtuOk);
    if (!mtuOk || mtu <= 0 || mtu > 65535
            || QString::number(mtu) != arguments.at(3)
            || environment.value(QStringLiteral("tun_mtu"))
                    != arguments.at(3)
            || arguments.at(4) != QLatin1String("0")) {
        setError(error, QStringLiteral("openvpn_dns_hook_argv_mtu_invalid"));
        return false;
    }

    const auto validOptionalAddress = [](const QString &value) {
        return value.isEmpty() || !QHostAddress(value).isNull();
    };
    const QString local = arguments.at(5);
    const QString remoteOrNetmask = arguments.at(6);
    if (!validOptionalAddress(local) || !validOptionalAddress(remoteOrNetmask)) {
        setError(error, QStringLiteral("openvpn_dns_hook_argv_address_invalid"));
        return false;
    }
    const QString environmentLocal = environment.value(
            QStringLiteral("ifconfig_local"));
    if ((!environment.contains(QStringLiteral("ifconfig_local"))
         && !local.isEmpty())
            || (environment.contains(QStringLiteral("ifconfig_local"))
                && environmentLocal != local)) {
        setError(error, QStringLiteral("openvpn_dns_hook_argv_local_mismatch"));
        return false;
    }
    const bool hasRemote = environment.contains(
            QStringLiteral("ifconfig_remote"));
    const bool hasNetmask = environment.contains(
            QStringLiteral("ifconfig_netmask"));
    if ((!hasRemote && !hasNetmask && !remoteOrNetmask.isEmpty())
            || (hasRemote || hasNetmask)
                    && remoteOrNetmask
                            != (hasRemote
                                    ? environment.value(QStringLiteral(
                                            "ifconfig_remote"))
                                    : environment.value(QStringLiteral(
                                            "ifconfig_netmask")))) {
        setError(error, QStringLiteral("openvpn_dns_hook_argv_remote_mismatch"));
        return false;
    }

    const QString context = arguments.at(7);
    if ((context != QLatin1String("init")
         && context != QLatin1String("restart"))
            || environment.value(QStringLiteral("script_context"))
                    != context) {
        setError(error, QStringLiteral("openvpn_dns_hook_argv_context_invalid"));
        return false;
    }
    const QString action = environment.value(QStringLiteral("script_type"));
    if (action != QLatin1String("up") && action != QLatin1String("down")) {
        setError(error, QStringLiteral("openvpn_dns_hook_argv_action_invalid"));
        return false;
    }
    return true;
}

int runHookFromEnvironment(const QStringList &arguments, QString *error)
{
    const QProcessEnvironment environment =
            QProcessEnvironment::systemEnvironment();
    if (!validateHookInvocation(arguments, environment, error)) {
        return 64;
    }
    const QString action = environment.value(QStringLiteral("script_type"));
    const QString device = environment.value(QStringLiteral("dev"));
    const QString session = environment.value(QStringLiteral(
            "TRIBE_DNS_SESSION"));
    if (!validSessionToken(session)) {
        setError(error, QStringLiteral("openvpn_dns_hook_environment_invalid"));
        return 1;
    }
    // Teardown belongs exclusively to the daemon after the exact QProcess is
    // proven NotRunning.  Keep accepting the old hook ABI for compatibility,
    // but a down invocation must not touch the journal or SystemConfiguration.
    if (action == QLatin1String("down")) {
        return 0;
    }
    if (!prepareStateDirectory(error)) {
        return 1;
    }
    StateLock lock;
    if (!lock.acquire(error)) {
        return 1;
    }
    SCDynamicStoreRef store = createStore();
    if (!store) {
        setError(error, QStringLiteral("openvpn_dns_store_create_failed"));
        return 1;
    }
    QStringList servers;
    QStringList searchDomains;
    const bool ok = parseForeignOptions(
            environment.toStringList(),
            &servers, &searchDomains, error)
            && applyLocked(store, session, device, servers, searchDomains,
                           error);
    CFRelease(store);
    return ok ? 0 : 1;
}

bool recover(QString *error)
{
    if (!prepareStateDirectory(error)) {
        return false;
    }
    StateLock lock;
    if (!lock.acquire(error)) {
        return false;
    }
    SCDynamicStoreRef store = createStore();
    if (!store) {
        setError(error, QStringLiteral("openvpn_dns_store_create_failed"));
        return false;
    }
    const bool ok = restoreLocked(store, {}, {}, true, false, error);
    CFRelease(store);
    return ok;
}

bool recoverSession(const QString &session, QString *error)
{
    if (!validSessionToken(session) || !prepareStateDirectory(error)) {
        if (!validSessionToken(session)) {
            setError(error, QStringLiteral("openvpn_dns_recovery_session_invalid"));
        }
        return false;
    }
    StateLock lock;
    if (!lock.acquire(error)) return false;
    SCDynamicStoreRef store = createStore();
    if (!store) {
        setError(error, QStringLiteral("openvpn_dns_store_create_failed"));
        return false;
    }
    const bool ok = restoreLocked(store, session, {}, false, true, error);
    CFRelease(store);
    return ok;
}

bool reconcileActiveSession(QString *error)
{
    if (!prepareStateDirectory(error)) return false;
    StateLock lock;
    if (!lock.acquire(error)) return false;
    DnsState state;
    bool exists = false;
    if (!readState(&state, &exists, error)) return false;
    if (!exists) return true;
    SCDynamicStoreRef store = createStore();
    if (!store) {
        setError(error, QStringLiteral("openvpn_dns_store_create_failed"));
        return false;
    }
    const bool ok = reconcileLocked(store, &state, error);
    CFRelease(store);
    return ok;
}

namespace {

void dnsStoreChanged(SCDynamicStoreRef, CFArrayRef, void *info)
{
    if (info) {
        static_cast<OpenVpnDnsMonitor *>(info)->notifyStoreChanged();
    }
}

} // namespace

OpenVpnDnsMonitor::OpenVpnDnsMonitor(FailureHandler failureHandler,
                                     QObject *parent)
    : QObject(parent), m_failureHandler(std::move(failureHandler))
{
}

OpenVpnDnsMonitor::~OpenVpnDnsMonitor()
{
    stop();
}

bool OpenVpnDnsMonitor::start(QString *error)
{
    if (m_store) return true;
    SCDynamicStoreContext context{};
    context.info = this;
    SCDynamicStoreRef store = SCDynamicStoreCreate(
            kCFAllocatorDefault, CFSTR("TribeVPN OpenVPN DNS monitor"),
            dnsStoreChanged, &context);
    if (!store) {
        setError(error, QStringLiteral("openvpn_dns_monitor_store_failed"));
        return false;
    }
    const void *keysValues[]{CFSTR("State:/Network/Global/IPv4"),
                             CFSTR("State:/Network/Global/IPv6")};
    CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault, keysValues, 2,
                                    &kCFTypeArrayCallBacks);
    const void *patternValues[]{CFSTR("Setup:/Network/Service/.*")};
    CFArrayRef patterns = CFArrayCreate(kCFAllocatorDefault, patternValues, 1,
                                        &kCFTypeArrayCallBacks);
    const bool subscribed = keys && patterns
            && SCDynamicStoreSetNotificationKeys(store, keys, patterns);
    if (keys) CFRelease(keys);
    if (patterns) CFRelease(patterns);
    if (!subscribed) {
        CFRelease(store);
        setError(error, QStringLiteral("openvpn_dns_monitor_subscribe_failed"));
        return false;
    }
    CFRunLoopSourceRef source = SCDynamicStoreCreateRunLoopSource(
            kCFAllocatorDefault, store, 0);
    if (!source) {
        CFRelease(store);
        setError(error, QStringLiteral("openvpn_dns_monitor_source_failed"));
        return false;
    }
    CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
    m_store = store;
    m_runLoopSource = source;
    m_watchdog = new QTimer(this);
    m_watchdog->setInterval(1000);
    m_watchdog->setTimerType(Qt::CoarseTimer);
    QObject::connect(m_watchdog, &QTimer::timeout, this,
                     [this]() { reconcileNow(); });
    m_watchdog->start();

    QString initialError;
    if (!reconcileActiveSession(&initialError)) {
        stop();
        setError(error, initialError);
        return false;
    }
    return true;
}

void OpenVpnDnsMonitor::stop()
{
    m_scheduled = false;
    if (m_watchdog) {
        m_watchdog->stop();
        delete m_watchdog;
        m_watchdog = nullptr;
    }
    if (m_runLoopSource) {
        auto source = static_cast<CFRunLoopSourceRef>(m_runLoopSource);
        CFRunLoopRemoveSource(CFRunLoopGetMain(), source,
                              kCFRunLoopCommonModes);
        CFRunLoopSourceInvalidate(source);
        CFRelease(source);
        m_runLoopSource = nullptr;
    }
    if (m_store) {
        CFRelease(static_cast<SCDynamicStoreRef>(m_store));
        m_store = nullptr;
    }
}

void OpenVpnDnsMonitor::notifyStoreChanged()
{
    if (m_scheduled || !m_store) return;
    m_scheduled = true;
    QTimer::singleShot(0, this, [this]() {
        m_scheduled = false;
        reconcileNow();
    });
}

void OpenVpnDnsMonitor::reconcileNow()
{
    if (m_reconciling || !m_store) return;
    m_reconciling = true;
    QString error;
    const bool ok = reconcileActiveSession(&error);
    m_reconciling = false;
    if (ok) {
        m_failureNotified = false;
    } else if (!m_failureNotified) {
        m_failureNotified = true;
        if (m_failureHandler) m_failureHandler(error);
    }
}

} // namespace amnezia::openvpndnssecurity
