#ifndef OPENVPNCONFIGSECURITY_H
#define OPENVPNCONFIGSECURITY_H

#include <QByteArray>
#include <QString>
#include <QtGlobal>

namespace amnezia::openvpnconfigsecurity {

constexpr qsizetype kMaxConfigBytes = 1024 * 1024;

// The OpenVPN child runs as root on macOS.  Treat the GUI-created/provider-
// supplied profile as hostile input: validate the exact bytes read from one
// already-open descriptor and append only the hook installed in the sealed
// privileged runtime.
QString trustedDnsHookPath();
bool trustedParentMetadataAllowed(bool directory, bool symlink, quint32 owner,
                                  quint32 mode);
bool buildPrivilegedConfig(const QByteArray &source,
                           const QByteArray &dnsSessionToken,
                           QByteArray *result,
                           QString *error = nullptr);

// Opens the final path component without following a symlink, verifies the
// authenticated peer's exact private-file contract, and returns the bytes
// from that descriptor.  A later rename or rewrite of the source path cannot
// change the bytes passed to buildPrivilegedConfig().
bool readPeerOwnedConfig(const QString &path, quint32 peerUid,
                         QByteArray *result, QString *error = nullptr);

// Runtime guard for the non-Mach-O DNS hook.  The install-time sealed payload
// is the content anchor; this check makes path substitution/writable runtime
// state fail closed before a privileged child is spawned.
bool validateTrustedDnsHook(QString *error = nullptr);

} // namespace amnezia::openvpnconfigsecurity

#endif // OPENVPNCONFIGSECURITY_H
