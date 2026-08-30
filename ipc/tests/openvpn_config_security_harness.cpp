#include "openvpnconfigsecurity.h"
#include "openvpndnssecurity.h"

#include <QCoreApplication>
#include <QFile>
#include <QProcessEnvironment>
#include <QTemporaryDir>

#include <cstdlib>
#include <iostream>

#ifdef Q_OS_MACOS
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <unistd.h>
#endif

using namespace amnezia::openvpnconfigsecurity;

namespace {

void require(bool condition, const char *message)
{
    if (!condition) {
        std::cerr << "OpenVPN config security harness failed: " << message << '\n';
        std::exit(1);
    }
}

QByteArray validProfile()
{
    QFile fixture(QStringLiteral(
            "ipc/tests/fixtures/tribe_generated_openvpn.ovpn"));
    require(fixture.open(QIODevice::ReadOnly),
            "generated Tribe profile fixture unavailable");
    return fixture.readAll();
}

bool writePrivateFile(const QString &path, const QByteArray &bytes)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)
            || file.write(bytes) != bytes.size() || !file.flush()) {
        return false;
    }
    file.close();
    return QFile::setPermissions(path, QFileDevice::ReadOwner
                                 | QFileDevice::WriteOwner);
}

#ifdef Q_OS_MACOS
CFStringRef makeCfString(const QString &value)
{
    return CFStringCreateWithCString(kCFAllocatorDefault,
                                     value.toUtf8().constData(),
                                     kCFStringEncodingUTF8);
}

void setSingleStringArray(CFMutableDictionaryRef dictionary, CFStringRef key,
                          const QString &value)
{
    if (value.isEmpty()) return;
    CFStringRef string = makeCfString(value);
    const void *values[]{string};
    CFArrayRef array = CFArrayCreate(kCFAllocatorDefault, values, 1,
                                     &kCFTypeArrayCallBacks);
    CFDictionarySetValue(dictionary, key, array);
    CFRelease(array);
    CFRelease(string);
}

QByteArray dnsPlist(const QString &server, const QString &search,
                    const QString &unrelated)
{
    CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFCopyStringDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
    setSingleStringArray(dictionary, kSCPropNetDNSServerAddresses, server);
    setSingleStringArray(dictionary, kSCPropNetDNSSearchDomains, search);
    if (!unrelated.isEmpty()) {
        CFStringRef value = makeCfString(unrelated);
        CFDictionarySetValue(dictionary, CFSTR("UnrelatedFixture"), value);
        CFRelease(value);
    }
    CFErrorRef error = nullptr;
    CFDataRef data = CFPropertyListCreateData(
            kCFAllocatorDefault, dictionary,
            kCFPropertyListBinaryFormat_v1_0, 0, &error);
    QByteArray result;
    if (data) {
        result = QByteArray(
                reinterpret_cast<const char *>(CFDataGetBytePtr(data)),
                static_cast<qsizetype>(CFDataGetLength(data)));
        CFRelease(data);
    }
    if (error) CFRelease(error);
    CFRelease(dictionary);
    return result;
}

QString plistString(const QByteArray &bytes, CFStringRef key, bool arrayValue)
{
    CFDataRef data = CFDataCreate(
            kCFAllocatorDefault,
            reinterpret_cast<const UInt8 *>(bytes.constData()), bytes.size());
    CFErrorRef error = nullptr;
    CFPropertyListRef plist = CFPropertyListCreateWithData(
            kCFAllocatorDefault, data, kCFPropertyListImmutable, nullptr,
            &error);
    CFRelease(data);
    if (error) CFRelease(error);
    if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
        if (plist) CFRelease(plist);
        return {};
    }
    CFTypeRef value = CFDictionaryGetValue(
            static_cast<CFDictionaryRef>(plist), key);
    if (arrayValue && value && CFGetTypeID(value) == CFArrayGetTypeID()
            && CFArrayGetCount(static_cast<CFArrayRef>(value)) == 1) {
        value = CFArrayGetValueAtIndex(static_cast<CFArrayRef>(value), 0);
    }
    QString result;
    if (value && CFGetTypeID(value) == CFStringGetTypeID()) {
        const CFStringRef string = static_cast<CFStringRef>(value);
        const CFIndex length = CFStringGetLength(string);
        QByteArray utf8(CFStringGetMaximumSizeForEncoding(
                                length, kCFStringEncodingUTF8) + 1,
                        '\0');
        if (CFStringGetCString(string, utf8.data(), utf8.size(),
                               kCFStringEncodingUTF8)) {
            result = QString::fromUtf8(utf8.constData());
        }
    }
    CFRelease(plist);
    return result;
}
#endif

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // A real OpenVPN process can execute this probe instead of the privileged
    // helper. It verifies the actual argv assembly/env duplication without
    // touching SystemConfiguration or requiring root.
    if (app.arguments().size() >= 2
            && app.arguments().at(1) == QLatin1String("--argv-probe")) {
        const QStringList probe = app.arguments();
        const QProcessEnvironment environment =
                QProcessEnvironment::systemEnvironment();
        require(probe.size() == 8,
                "bundled OpenVPN did not append exactly six hook arguments");
        require(environment.value(QStringLiteral("dev")) == probe.at(2),
                "bundled OpenVPN dev argv/env mismatch");
        require(environment.value(QStringLiteral("tun_mtu")) == probe.at(3)
                        && probe.at(4) == QLatin1String("0"),
                "bundled OpenVPN MTU ABI mismatch");
        require(environment.value(QStringLiteral("script_context"))
                        == probe.at(7),
                "bundled OpenVPN context argv/env mismatch");
        require(environment.value(QStringLiteral("script_type"))
                        == QLatin1String("up"),
                "bundled OpenVPN probe was not invoked as up hook");
        std::cout << "OpenVPN real hook argv smoke passed\n";
        return 0;
    }

    const QByteArray source = validProfile();
    const QByteArray sessionToken(
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef");
    require(sessionToken.size() == 43, "session token fixture length drifted");
    QByteArray privileged;
    QString error;
    if (!buildPrivilegedConfig(source, sessionToken, &privileged, &error)) {
        std::cerr << "valid profile error: " << error.toStdString() << '\n';
        require(false, "valid profile rejected");
    }
    require(privileged.startsWith(source), "source bytes were rewritten");
    const QByteArray trustedHook = trustedDnsHookPath().toUtf8();
    require(privileged.count("script-security 2") == 1,
            "trusted script-security was not injected exactly once");
    require(privileged.count("setenv TRIBE_DNS_SESSION " + sessionToken) == 1,
            "trusted DNS session was not injected exactly once");
    require(privileged.count("up " + trustedHook
                             + " --tribe-openvpn-dns-hook-v1") == 1
                    && !privileged.contains("\ndown ")
                    && !privileged.contains("\ndown-pre"),
            "only the trusted up hook may be injected");

    const QList<QByteArray> attacks{
        "script-security 2", "up /tmp/owned", "down /tmp/owned",
        "route-up /tmp/owned", "route-pre-down /tmp/owned",
        "tls-verify /tmp/owned", "ipchange /tmp/owned",
        "auth-user-pass-verify /tmp/owned via-env", "plugin /tmp/owned.dylib",
        "config /tmp/extra.conf", "include /tmp/extra.conf", "ca /tmp/ca.pem",
        "cert /tmp/cert.pem", "key /tmp/key.pem", "tls-auth /tmp/key 1",
        "auth-user-pass /tmp/credentials", "management 0.0.0.0 7505",
        "management-client-user root", "log /etc/owned", "log-append /etc/owned",
        "status /etc/owned", "writepid /etc/owned", "cd /tmp", "chroot /tmp",
        "daemon", "user root", "group wheel", "setenv PATH /tmp/owned",
        "setenv BASH_ENV /tmp/owned", "engine /tmp/owned.dylib",
        "providers /tmp/owned", "tls-export-cert /tmp", "tmp-dir /tmp/owned",
        "askpass /tmp/owned", "pkcs12 /tmp/owned.p12", "crl-verify /tmp/owned",
        "socks-proxy 127.0.0.1 1080 /tmp/credentials",
        "http-proxy 127.0.0.1 8080 auto /tmp/credentials",
        "unknown-future-option value"
    };
    for (const QByteArray &attack : attacks) {
        QByteArray rejected;
        const QByteArray profile = QByteArrayLiteral("client\n") + attack + '\n';
        require(!buildPrivilegedConfig(profile, sessionToken, &rejected, &error),
                attack.constData());
    }

        require(!buildPrivilegedConfig(
                    QByteArrayLiteral("client\\\nscript-security 2\n"),
                    sessionToken, &privileged, &error),
            "line-continuation parser differential accepted");
        require(!buildPrivilegedConfig(
                    QByteArrayLiteral("client\n<connection>\nup /tmp/x\n"
                                      "</connection>\n"),
                    sessionToken, &privileged, &error),
            "connection block accepted");
        require(!buildPrivilegedConfig(
                    QByteArrayLiteral("client\n<ca>\ndata\n"),
                    sessionToken, &privileged, &error),
            "unterminated inline block accepted");
        require(!buildPrivilegedConfig(
                    QByteArrayLiteral("client\n<ca>\ndata\n</ca> trailing\n"),
                    sessionToken, &privileged, &error),
            "ambiguous inline close accepted");
    QByteArray nulProfile("client\n", 7);
    nulProfile.append('\0');
    nulProfile.append("plugin /tmp/x\n");
    require(!buildPrivilegedConfig(nulProfile, sessionToken, &privileged, &error),
            "embedded NUL accepted");
    require(!buildPrivilegedConfig(source, QByteArrayLiteral("short"),
                                   &privileged, &error),
            "invalid DNS session token accepted");
    const QByteArray safeImportedProfile = QByteArrayLiteral(
            "client\nignore-unknown-option block-outside-dns\n"
            "http-proxy proxy.example 8080\n"
            "http-proxy-option VERSION 1.1\n"
            "socks-proxy 127.0.0.1 1080\n"
            "auth-user-pass [inline]\n"
            "<auth-user-pass>\nuser\npassword\n</auth-user-pass>\n");
    require(buildPrivilegedConfig(safeImportedProfile, sessionToken,
                                  &privileged, &error),
            "safe imported proxy/inline-auth profile rejected");
    require(trustedParentMetadataAllowed(true, false, 0, 01755),
            "stock sticky PrivilegedHelperTools mode rejected");
    require(!trustedParentMetadataAllowed(true, false, 0, 01775)
                    && !trustedParentMetadataAllowed(true, true, 0, 01755)
                    && !trustedParentMetadataAllowed(true, false, 501, 01755),
            "writable/symlink/non-root helper parent accepted");

    require(amnezia::openvpndnssecurity::validSessionToken(
                    QString::fromLatin1(sessionToken)),
            "DNS helper rejected daemon session token");
    QProcessEnvironment hookEnvironment;
    hookEnvironment.insert(QStringLiteral("script_type"),
                           QStringLiteral("up"));
    hookEnvironment.insert(QStringLiteral("script_context"),
                           QStringLiteral("init"));
    hookEnvironment.insert(QStringLiteral("dev"), QStringLiteral("utun12"));
    hookEnvironment.insert(QStringLiteral("tun_mtu"), QStringLiteral("1500"));
    hookEnvironment.insert(QStringLiteral("ifconfig_local"),
                           QStringLiteral("10.8.0.6"));
    hookEnvironment.insert(QStringLiteral("ifconfig_remote"),
                           QStringLiteral("10.8.0.5"));
    const QStringList hookArguments{
        QStringLiteral("/Library/PrivilegedHelperTools/TribeVPN/Tribe-service"),
        QString::fromLatin1(amnezia::openvpndnssecurity::kHookArgument),
        QStringLiteral("utun12"), QStringLiteral("1500"),
        QStringLiteral("0"), QStringLiteral("10.8.0.6"),
        QStringLiteral("10.8.0.5"), QStringLiteral("init")
    };
    require(amnezia::openvpndnssecurity::validateHookInvocation(
                    hookArguments, hookEnvironment, &error),
            "exact pinned OpenVPN hook ABI rejected");
    for (QStringList malformedArguments : {
             hookArguments.mid(0, 7),
             QStringList(hookArguments) << QStringLiteral("extra"),
             QStringList{hookArguments.at(0), hookArguments.at(1),
                         QStringLiteral("../../dev/utun12"),
                         hookArguments.at(3), hookArguments.at(4),
                         hookArguments.at(5), hookArguments.at(6),
                         hookArguments.at(7)},
             QStringList{hookArguments.at(0), hookArguments.at(1),
                         hookArguments.at(2), QStringLiteral("+1500"),
                         hookArguments.at(4), hookArguments.at(5),
                         hookArguments.at(6), hookArguments.at(7)},
             QStringList{hookArguments.at(0), hookArguments.at(1),
                         hookArguments.at(2), hookArguments.at(3),
                         QStringLiteral("1"), hookArguments.at(5),
                         hookArguments.at(6), hookArguments.at(7)},
             QStringList{hookArguments.at(0), hookArguments.at(1),
                         hookArguments.at(2), hookArguments.at(3),
                         hookArguments.at(4), hookArguments.at(5),
                         hookArguments.at(6), QStringLiteral("other")}
         }) {
        require(!amnezia::openvpndnssecurity::validateHookInvocation(
                        malformedArguments, hookEnvironment, &error),
                "malformed OpenVPN hook argv accepted");
    }
    QProcessEnvironment mismatchedHookEnvironment = hookEnvironment;
    mismatchedHookEnvironment.insert(QStringLiteral("tun_mtu"),
                                     QStringLiteral("1499"));
    require(!amnezia::openvpndnssecurity::validateHookInvocation(
                    hookArguments, mismatchedHookEnvironment, &error),
            "OpenVPN hook argv/env mismatch accepted");
    require(amnezia::openvpndnssecurity::shouldRestoreOwnedField(true, false)
                    && amnezia::openvpndnssecurity::shouldRestoreOwnedField(
                            false, true)
                    && !amnezia::openvpndnssecurity::shouldRestoreOwnedField(
                            false, false),
            "three-way DNS field ownership decision drifted");
    QStringList dnsServers;
    QStringList searchDomains;
    const QStringList validEnvironment{
        QStringLiteral("PATH=/tmp/attacker"),
        QStringLiteral("BASH_ENV=/tmp/attacker"),
        QStringLiteral("foreign_option_1=dhcp-option DNS 1.1.1.1"),
        QStringLiteral("foreign_option_2=dhcp-option DNS 2606:4700:4700::1111"),
        QStringLiteral("foreign_option_3=dhcp-option DOMAIN-SEARCH tribe.example")
    };
    require(amnezia::openvpndnssecurity::parseForeignOptions(
                    validEnvironment, &dnsServers, &searchDomains, &error)
                    && dnsServers.size() == 2 && searchDomains.size() == 1,
            "DNS helper rejected bounded pushed options");
    for (const QStringList &maliciousEnvironment : {
             QStringList{QStringLiteral("foreign_option_bad=dhcp-option DNS 1.1.1.1")},
             QStringList{QStringLiteral("foreign_option_1=dhcp-option DNS -evil")},
             QStringList{QStringLiteral("foreign_option_1=dhcp-option DOMAIN x;touch")},
             QStringList{QStringLiteral("foreign_option_1=dhcp-option DNS 1.1.1.1 extra")},
             QStringList{QStringLiteral("foreign_option_1=plugin /tmp/owned.dylib")}
         }) {
        require(!amnezia::openvpndnssecurity::parseForeignOptions(
                        maliciousEnvironment, &dnsServers, &searchDomains,
                        &error),
                "DNS helper accepted malformed or non-DNS environment");
    }

#ifdef Q_OS_MACOS
    const QByteArray baselineDns = dnsPlist(
            QStringLiteral("192.0.2.53"), QStringLiteral("lan.example"),
            QStringLiteral("baseline"));
    const QByteArray appliedDns = dnsPlist(
            QStringLiteral("10.8.0.1"), QStringLiteral("vpn.example"),
            QStringLiteral("baseline"));
    const QByteArray externallyChangedDns = dnsPlist(
            QStringLiteral("10.8.0.1"), QStringLiteral("external.example"),
            QStringLiteral("external"));
    const QByteArray mergedDns =
            amnezia::openvpndnssecurity::restoreOwnedFieldsForTesting(
                    externallyChangedDns, appliedDns, baselineDns,
                    baselineDns);
    require(plistString(mergedDns, kSCPropNetDNSServerAddresses, true)
                        == QLatin1String("192.0.2.53")
                    && plistString(mergedDns, kSCPropNetDNSSearchDomains, true)
                        == QLatin1String("external.example")
                    && plistString(mergedDns, CFSTR("UnrelatedFixture"), false)
                        == QLatin1String("external"),
            "field-wise DNS restore lost an external winner or retained VPN DNS");

    const QByteArray nextAppliedDns = dnsPlist(
            QStringLiteral("10.9.0.1"), QStringLiteral("vpn-next.example"),
            QStringLiteral("baseline"));
    const QByteArray interruptedUpdate =
            amnezia::openvpndnssecurity::restoreOwnedFieldsForTesting(
                    appliedDns, nextAppliedDns, appliedDns, baselineDns);
    require(plistString(interruptedUpdate,
                        kSCPropNetDNSServerAddresses, true)
                        == QLatin1String("192.0.2.53")
                    && plistString(interruptedUpdate,
                                   kSCPropNetDNSSearchDomains, true)
                        == QLatin1String("lan.example"),
            "prepared same-session DNS update cannot recover its preimage");

    QTemporaryDir temporary;
    require(temporary.isValid(), "temporary directory unavailable");
    const QString profilePath = temporary.filePath(QStringLiteral("profile.ovpn"));
    require(writePrivateFile(profilePath, source), "private fixture write failed");
    QByteArray captured;
    require(readPeerOwnedConfig(profilePath, static_cast<quint32>(::geteuid()),
                                &captured, &error),
            "private regular config rejected");
    require(captured == source, "descriptor read changed source bytes");

    // Once captured from the descriptor, a same-UID rewrite of the pathname
    // cannot alter the root-bound bytes.
    require(writePrivateFile(profilePath,
                             QByteArrayLiteral("plugin /tmp/owned.dylib\n")),
            "same-uid rewrite fixture failed");
    require(buildPrivilegedConfig(captured, sessionToken, &privileged, &error),
            "captured valid bytes changed after pathname rewrite");
    QByteArray current;
    require(readPeerOwnedConfig(profilePath, static_cast<quint32>(::geteuid()),
                                &current, &error)
                    && !buildPrivilegedConfig(current, sessionToken,
                                              &privileged, &error),
            "rewritten malicious bytes were accepted");

    const QString symlinkPath = temporary.filePath(QStringLiteral("link.ovpn"));
    require(QFile::link(profilePath, symlinkPath), "symlink fixture failed");
    require(!readPeerOwnedConfig(symlinkPath, static_cast<quint32>(::geteuid()),
                                 &captured, &error),
            "symlink config accepted");

    const QString hardlinkPath = temporary.filePath(QStringLiteral("hard.ovpn"));
    require(::link(QFile::encodeName(profilePath).constData(),
                   QFile::encodeName(hardlinkPath).constData()) == 0,
            "hard-link fixture failed");
    require(!readPeerOwnedConfig(profilePath, static_cast<quint32>(::geteuid()),
                                 &captured, &error),
            "hard-linked config accepted");
    require(QFile::remove(hardlinkPath), "hard-link fixture cleanup failed");

    require(QFile::setPermissions(profilePath, QFileDevice::ReadOwner
                                  | QFileDevice::WriteOwner
                                  | QFileDevice::ReadGroup),
            "mode fixture setup failed");
    require(!readPeerOwnedConfig(profilePath, static_cast<quint32>(::geteuid()),
                                 &captured, &error),
            "group-readable config accepted");
#endif

    std::cout << "OpenVPN root config security harness passed\n";
    return 0;
}
