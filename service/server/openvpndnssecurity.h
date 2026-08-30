#ifndef OPENVPNDNSSECURITY_H
#define OPENVPNDNSSECURITY_H

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QStringList>

#include <functional>

class QProcessEnvironment;
class QTimer;

namespace amnezia::openvpndnssecurity {

constexpr auto kHookArgument = "--tribe-openvpn-dns-hook-v1";
constexpr auto kRecoveryArgument = "--tribe-openvpn-dns-recover-v1";

bool validSessionToken(const QString &token);
bool shouldRestoreOwnedField(bool currentMatchesApplied,
                             bool currentMatchesPreimage);
#ifdef TRIBE_DNS_SECURITY_TESTING
QByteArray restoreOwnedFieldsForTesting(const QByteArray &current,
                                        const QByteArray &applied,
                                        const QByteArray &preimage,
                                        const QByteArray &baseline);
#endif
bool parseForeignOptions(const QStringList &environment, QStringList *servers,
                         QStringList *searchDomains, QString *error = nullptr);

// The pinned OpenVPN appends exactly six arguments to every --up/--down command:
//   dev tun_mtu 0 ifconfig_local ifconfig_remote init|restart
// Validate both that ABI and OpenVPN's duplicate environment before any
// privileged state is touched.
bool validateHookInvocation(const QStringList &arguments,
                            const QProcessEnvironment &environment,
                            QString *error = nullptr);

// Invoked only by the exact sealed Tribe-service subcommand used as OpenVPN's
// up hook. Legacy down invocations are fully validated but intentionally do no
// state mutation; teardown is owned by the daemon after exact child death.
int runHookFromEnvironment(const QStringList &arguments,
                           QString *error = nullptr);

// Restores a durable orphaned DNS snapshot. The normal daemon calls this on
// startup and after all children are stopped; uninstall has a signed recovery
// path as well.
bool recover(QString *error = nullptr);

// Session-scoped cleanup is owned by the daemon and runs after the exact
// OpenVPN child is proven dead. A stale child token cannot restore a newer
// owner's journal.
bool recoverSession(const QString &session, QString *error = nullptr);

// Re-enforces the durable journal after SystemConfiguration/network changes.
bool reconcileActiveSession(QString *error = nullptr);

class OpenVpnDnsMonitor final : public QObject
{
public:
    using FailureHandler = std::function<void(const QString &)>;

    explicit OpenVpnDnsMonitor(FailureHandler failureHandler,
                               QObject *parent = nullptr);
    ~OpenVpnDnsMonitor() override;

    bool start(QString *error = nullptr);
    void stop();
    void reconcileNow();
    void notifyStoreChanged();

private:
    FailureHandler m_failureHandler;
    const void *m_store = nullptr;
    void *m_runLoopSource = nullptr;
    QTimer *m_watchdog = nullptr;
    bool m_scheduled = false;
    bool m_reconciling = false;
    bool m_failureNotified = false;
};

} // namespace amnezia::openvpndnssecurity

#endif // OPENVPNDNSSECURITY_H
