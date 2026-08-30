#include "openvpnconfigsecurity.h"

#include <QDir>
#include <QFile>
#include <QSet>

#include <cerrno>
#include <limits>

#ifdef Q_OS_MACOS
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace amnezia::openvpnconfigsecurity {
namespace {

void setError(QString *error, const QString &value)
{
    if (error) {
        *error = value;
    }
}

bool containsForbiddenControl(const QByteArray &line)
{
    for (const unsigned char byte : line) {
        if ((byte < 0x20 && byte != '\t') || byte == 0x7f) {
            return true;
        }
    }
    return false;
}

bool canonicalDirectiveName(const QByteArray &name)
{
    if (name.isEmpty() || name.size() > 64) {
        return false;
    }
    for (const unsigned char byte : name) {
        if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9')
              || byte == '-')) {
            return false;
        }
    }
    return true;
}

const QSet<QByteArray> &safeDirectives()
{
    // Closed client-side grammar: network/tunnel/cryptographic tuning only.
    // Anything capable of loading code, selecting a file, writing a file,
    // changing process identity/environment, or defining a script is absent.
    static const QSet<QByteArray> directives{
        "allow-compression", "allow-pull-fqdn", "auth", "auth-nocache",
        "auth-retry", "bind", "block-ipv6", "block-outside-dns", "cipher", "client", "comp-lzo",
        "compress", "connect-retry", "connect-retry-max", "connect-timeout",
        "data-ciphers", "data-ciphers-fallback", "dev", "dev-type",
        "dhcp-option", "disable-dco", "disable-occ", "ecdh-curve",
        "explicit-exit-notify", "fast-io", "float", "fragment", "hand-window",
        "http-proxy-option", "http-proxy-retry", "http-proxy-timeout",
        "ifconfig", "ifconfig-ipv6", "ifconfig-ipv6-nowarn", "ifconfig-nowarn",
        "ifconfig-noexec", "inactive", "keepalive", "key-direction",
        "keying-material-exporter", "link-mtu", "lport", "mssfix", "mtu-disc",
        "mute", "mute-replay-warnings", "ncp-disable", "nobind", "no-replay",
        "ns-cert-type", "opt-verify", "peer-fingerprint", "peer-id", "persist-key",
        "persist-local-ip", "persist-remote-ip", "persist-tun", "ping", "ping-exit",
        "ping-restart", "port", "proto", "proto-force", "pull", "pull-filter",
        "push-peer-info", "rcvbuf", "redirect-gateway", "redirect-private",
        "remote", "remote-cert-eku", "remote-cert-ku", "remote-cert-tls",
        "remote-ip-hint", "remote-random", "remote-random-hostname", "remap-usr1",
        "reneg-bytes", "reneg-pkts", "reneg-sec", "replay-window", "resolv-retry",
        "route", "route-delay", "route-gateway", "route-ipv6",
        "route-ipv6-gateway", "route-metric", "route-nopull", "rport", "server-poll-timeout",
        "sndbuf", "socket-flags", "suppress-timestamps", "tcp-nodelay", "tls-cert-profile",
        "tls-cipher", "tls-ciphersuites", "tls-client", "tls-exit", "tls-groups",
        "tls-timeout", "tls-version-max", "tls-version-min", "topology", "tran-window",
        "tun-mtu", "tun-mtu-extra", "verb", "verify-x509-name", "x509-username-field"
    };
    return directives;
}

const QSet<QByteArray> &inlineBlocks()
{
    static const QSet<QByteArray> blocks{
        "auth-user-pass", "ca", "cert", "extra-certs", "http-proxy-user-pass",
        "key", "tls-auth", "tls-crypt", "tls-crypt-v2"
    };
    return blocks;
}

bool validInlineSelector(const QByteArray &directive, const QByteArray &arguments)
{
    const QByteArray normalized = arguments.simplified();
    if (directive == "auth-user-pass") {
        return normalized.isEmpty() || normalized == "[inline]";
    }
    if (directive == "http-proxy-user-pass") {
        return normalized == "[inline]";
    }
    if (directive == "tls-auth") {
        return normalized == "[inline]" || normalized == "[inline] 0"
                || normalized == "[inline] 1";
    }
    return normalized == "[inline]";
}

bool validDnsSessionToken(const QByteArray &token)
{
    if (token.size() != 43) {
        return false;
    }
    for (const unsigned char byte : token) {
        if (!((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')
              || (byte >= '0' && byte <= '9') || byte == '-' || byte == '_')) {
            return false;
        }
    }
    return true;
}

QList<QByteArray> simpleTokens(const QByteArray &arguments)
{
    if (arguments.isEmpty() || arguments.contains('"')
            || arguments.contains('\'')) {
        return {};
    }
    return arguments.simplified().split(' ');
}

bool validProxyHost(const QByteArray &host)
{
    if (host.isEmpty() || host.size() > 253 || host.startsWith('-')) {
        return false;
    }
    for (const unsigned char byte : host) {
        if (!((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')
              || (byte >= '0' && byte <= '9') || byte == '.' || byte == ':'
              || byte == '_' || byte == '-')) {
            return false;
        }
    }
    return true;
}

bool validProxyPort(const QByteArray &port)
{
    bool ok = false;
    const int value = port.toInt(&ok);
    return ok && value > 0 && value <= 65535;
}

bool validSpecialDirective(const QByteArray &directive,
                           const QByteArray &arguments)
{
    if (directive == "ignore-unknown-option") {
        static const QSet<QByteArray> safeIgnored{
            "block-outside-dns", "compress", "data-ciphers",
            "data-ciphers-fallback", "tls-crypt", "tls-crypt-v2"
        };
        const QList<QByteArray> tokens = simpleTokens(arguments);
        if (tokens.isEmpty() || tokens.size() > 16) {
            return false;
        }
        for (const QByteArray &token : tokens) {
            if (!safeIgnored.contains(token)) {
                return false;
            }
        }
        return true;
    }
    if (directive == "http-proxy" || directive == "socks-proxy") {
        const QList<QByteArray> tokens = simpleTokens(arguments);
        const bool validCount = directive == "http-proxy"
                ? tokens.size() == 2
                : (tokens.size() == 1 || tokens.size() == 2);
        return validCount && validProxyHost(tokens.at(0))
                && (tokens.size() == 1 || validProxyPort(tokens.at(1)));
    }
    return false;
}

bool validateConfigGrammar(const QByteArray &source, QString *error)
{
    if (source.isEmpty() || source.size() > kMaxConfigBytes
            || source.contains('\0')) {
        setError(error, QStringLiteral("openvpn_config_size_or_nul"));
        return false;
    }

    QByteArray activeBlock;
    qsizetype lineNumber = 0;
    const QList<QByteArray> lines = source.split('\n');
    for (QByteArray line : lines) {
        ++lineNumber;
        if (line.endsWith('\r')) {
            line.chop(1);
        }
        if (containsForbiddenControl(line)) {
            setError(error, QStringLiteral("openvpn_config_control_character_line_%1")
                              .arg(lineNumber));
            return false;
        }

        const QByteArray trimmed = line.trimmed();
        if (!activeBlock.isEmpty()) {
            const QByteArray expectedClose = "</" + activeBlock + ">";
            if (trimmed == expectedClose) {
                activeBlock.clear();
                continue;
            }
            // Do not rely on a different interpretation of nested/tag-looking
            // input between this parser and OpenVPN's inline-file parser.
            if (trimmed.startsWith('<') || trimmed.startsWith('>')) {
                setError(error, QStringLiteral("openvpn_config_inline_tag_line_%1")
                                  .arg(lineNumber));
                return false;
            }
            continue;
        }

        if (trimmed.isEmpty() || trimmed.startsWith('#')
                || trimmed.startsWith(';')) {
            continue;
        }
        // OpenVPN accepts backslash escaping/continuation.  Reject it so one
        // physical line always means one directive in both parsers.
        if (line.contains('\\')) {
            setError(error, QStringLiteral("openvpn_config_escape_line_%1")
                              .arg(lineNumber));
            return false;
        }

        if (trimmed.startsWith('<')) {
            if (!trimmed.endsWith('>') || trimmed.startsWith("</")
                    || trimmed.count('<') != 1 || trimmed.count('>') != 1) {
                setError(error, QStringLiteral("openvpn_config_bad_inline_open_line_%1")
                                  .arg(lineNumber));
                return false;
            }
            const QByteArray block = trimmed.mid(1, trimmed.size() - 2);
            if (!inlineBlocks().contains(block)) {
                setError(error, QStringLiteral("openvpn_config_forbidden_inline_block_%1")
                                  .arg(lineNumber));
                return false;
            }
            activeBlock = block;
            continue;
        }

        qsizetype split = 0;
        while (split < trimmed.size() && trimmed.at(split) != ' '
               && trimmed.at(split) != '\t') {
            ++split;
        }
        const QByteArray directive = trimmed.left(split);
        const QByteArray arguments = trimmed.mid(split).trimmed();
        if (!canonicalDirectiveName(directive)) {
            setError(error, QStringLiteral("openvpn_config_bad_directive_line_%1")
                              .arg(lineNumber));
            return false;
        }
        if (inlineBlocks().contains(directive)) {
            if (!validInlineSelector(directive, arguments)) {
                setError(error, QStringLiteral("openvpn_config_external_file_line_%1")
                                  .arg(lineNumber));
                return false;
            }
            continue;
        }
        if (directive == "ignore-unknown-option" || directive == "http-proxy"
                || directive == "socks-proxy") {
            if (!validSpecialDirective(directive, arguments)) {
                setError(error, QStringLiteral("openvpn_config_unsafe_arguments_%1_line_%2")
                                  .arg(QString::fromLatin1(directive)).arg(lineNumber));
                return false;
            }
            continue;
        }
        if (!safeDirectives().contains(directive)) {
            setError(error, QStringLiteral("openvpn_config_forbidden_directive_%1_line_%2")
                              .arg(QString::fromLatin1(directive)).arg(lineNumber));
            return false;
        }
    }

    if (!activeBlock.isEmpty()) {
        setError(error, QStringLiteral("openvpn_config_unclosed_inline_block"));
        return false;
    }
    return true;
}

} // namespace

QString trustedDnsHookPath()
{
    return QStringLiteral(
            "/Library/PrivilegedHelperTools/TribeVPN/Tribe-service");
}

bool trustedParentMetadataAllowed(bool directory, bool symlink, quint32 owner,
                                  quint32 mode)
{
    // /Library/PrivilegedHelperTools is 01755 on stock macOS. Sticky is safe
    // here because only root may write; group/world write and special identity
    // bits remain forbidden.
    return directory && !symlink && owner == 0
            && (mode & 06022) == 0;
}

bool buildPrivilegedConfig(const QByteArray &source,
                           const QByteArray &dnsSessionToken,
                           QByteArray *result,
                           QString *error)
{
    if (!result) {
        setError(error, QStringLiteral("openvpn_config_output_missing"));
        return false;
    }
    result->clear();
    if (!validDnsSessionToken(dnsSessionToken)) {
        setError(error, QStringLiteral("openvpn_dns_session_invalid"));
        return false;
    }
    if (!validateConfigGrammar(source, error)) {
        return false;
    }

    QByteArray privileged = source;
    if (!privileged.endsWith('\n')) {
        privileged.append('\n');
    }
    privileged.append("setenv TRIBE_DNS_SESSION ");
    privileged.append(dnsSessionToken);
    privileged.append("\nscript-security 2\nup ");
    privileged.append(trustedDnsHookPath().toUtf8());
    privileged.append(" --tribe-openvpn-dns-hook-v1\n");
    if (privileged.size() > kMaxConfigBytes + 512) {
        setError(error, QStringLiteral("openvpn_privileged_config_too_large"));
        return false;
    }
    *result = privileged;
    return true;
}

bool readPeerOwnedConfig(const QString &path, quint32 peerUid,
                         QByteArray *result, QString *error)
{
    if (!result) {
        setError(error, QStringLiteral("openvpn_config_output_missing"));
        return false;
    }
    result->clear();
#ifdef Q_OS_MACOS
    if (peerUid == 0 || peerUid == std::numeric_limits<quint32>::max()
            || path.isEmpty() || path.contains(QChar::Null)
            || !QDir::isAbsolutePath(path)) {
        setError(error, QStringLiteral("openvpn_config_path_invalid"));
        return false;
    }
    const QByteArray encoded = QFile::encodeName(path);
    const int fd = ::open(encoded.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        setError(error, QStringLiteral("openvpn_config_open_failed"));
        return false;
    }

    struct FdCloser {
        int value;
        ~FdCloser() { if (value >= 0) { ::close(value); } }
    } closer{fd};
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)
            || st.st_uid != static_cast<uid_t>(peerUid) || st.st_nlink != 1
            || (st.st_mode & 07777) != 0600 || st.st_size <= 0
            || st.st_size > kMaxConfigBytes) {
        setError(error, QStringLiteral("openvpn_config_metadata_invalid"));
        return false;
    }

    QByteArray bytes;
    bytes.reserve(static_cast<qsizetype>(st.st_size));
    char buffer[16 * 1024];
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            setError(error, QStringLiteral("openvpn_config_read_failed"));
            return false;
        }
        if (bytes.size() + count > kMaxConfigBytes) {
            setError(error, QStringLiteral("openvpn_config_grew_too_large"));
            return false;
        }
        bytes.append(buffer, static_cast<qsizetype>(count));
    }
    *result = bytes;
    return true;
#else
    Q_UNUSED(path);
    Q_UNUSED(peerUid);
    setError(error, QStringLiteral("openvpn_secure_read_not_supported"));
    return false;
#endif
}

bool validateTrustedDnsHook(QString *error)
{
#ifdef Q_OS_MACOS
    const char *directories[]{"/Library", "/Library/PrivilegedHelperTools",
                              "/Library/PrivilegedHelperTools/TribeVPN"};
    for (const char *directory : directories) {
        struct stat directoryMetadata {};
        if (::lstat(directory, &directoryMetadata) != 0
                || !trustedParentMetadataAllowed(
                        S_ISDIR(directoryMetadata.st_mode),
                        S_ISLNK(directoryMetadata.st_mode),
                        static_cast<quint32>(directoryMetadata.st_uid),
                        static_cast<quint32>(directoryMetadata.st_mode))) {
            setError(error, QStringLiteral("openvpn_dns_helper_parent_invalid"));
            return false;
        }
    }
    const QByteArray encoded = QFile::encodeName(trustedDnsHookPath());
    struct stat st {};
    if (::lstat(encoded.constData(), &st) != 0 || !S_ISREG(st.st_mode)
            || S_ISLNK(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1
            || (st.st_mode & 07777) != 0755
            || st.st_size <= 0 || st.st_size > 128 * 1024 * 1024) {
        setError(error, QStringLiteral("openvpn_dns_hook_metadata_invalid"));
        return false;
    }
    return true;
#else
    setError(error, QStringLiteral("openvpn_dns_hook_not_supported"));
    return false;
#endif
}

} // namespace amnezia::openvpnconfigsecurity
