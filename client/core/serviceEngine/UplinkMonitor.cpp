// AVPN (волна-3, 2026-09-28): фолбэк UplinkMonitor для платформ без nw_path_monitor —
// QNetworkInformation (Windows/Linux/iOS). Не авторитетен: при поднятом VPN может
// показывать «online» по самому туннелю; решения о намерении на нём принимаются мягче.
// 5.1.108: physicalUp() here is strict - unknown reachability or a non-physical medium = no.
// Android (review round 20 R1): authoritative - the set of PHYSICAL networks with internet (NET_CAPABILITY_NOT_VPN)
// the Kotlin side already keeps (NetworkState.kt ScanAppNetwork / PhysicalUplink), told as it changes. The
// QNetworkInformation fallback watched the default network of our UID - our own VPN while it exists - and said
// "down" on every teardown of our tunnel. QNetworkInformation stays only when that source cannot be registered.
#include "UplinkMonitor.h"

#include <QCoreApplication>
#include <QDebug>
#include <QNetworkInformation>
#if defined(Q_OS_ANDROID)
#include <QJniEnvironment>
#include <QJniObject>
#include <QtCore/qcoreapplication_platform.h>
#include <atomic>
#endif

namespace avpn {

#if defined(Q_OS_ANDROID)
namespace {
constexpr char kPhysicalSourceClass[] = "org/amnezia/vpn/util/net/ScanAppNetwork";
// Set before the watch starts: the callback thread never runs instance()'s static initialisation (start() runs
// inside it).
std::atomic<UplinkMonitor *> g_physicalMonitor{nullptr};

// ScanAppNetwork.onPhysicalUplink: the ConnectivityManager callback thread.
void JNICALL onPhysicalUplink(JNIEnv *, jobject, jboolean up)
{
    UplinkMonitor::postPhysicalUp(up == JNI_TRUE);
}
} // namespace

void UplinkMonitor::postPhysicalUp(bool up)
{
    UplinkMonitor *m = g_physicalMonitor.load();
    if (!m)
        return;
    QMetaObject::invokeMethod(m, [m, up]() { m->setUp(up); }, Qt::QueuedConnection); // to the monitor's thread
}

// true = the physical set is the source (m_up set from its initial value); false = no source, keep the fallback.
bool UplinkMonitor::startPhysical()
{
    g_physicalMonitor.store(this);
    const JNINativeMethod methods[] = {
        {"onPhysicalUplink", "(Z)V", reinterpret_cast<void *>(onPhysicalUplink)},
    };
    QJniEnvironment env;
    if (!env.registerNativeMethods(kPhysicalSourceClass, methods, 1)) {
        env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent);
        qWarning() << "[uplink] no physical source in the Kotlin half - QNetworkInformation fallback";
        return false;
    }
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    if (!context.isValid())
        return false;
    const jint initial = QJniObject::callStaticMethod<jint>(kPhysicalSourceClass, "watchUplink",
                                                            "(Landroid/content/Context;)I", context.object());
    const PhysicalSourceStart how = env.checkAndClearExceptions(QJniEnvironment::OutputMode::Silent)
                                        ? PhysicalSourceStart::NoSource
                                        : physicalSourceStart(int(initial));
    if (how == PhysicalSourceStart::NoSource) {
        qWarning() << "[uplink] physical source not started - QNetworkInformation fallback";
        return false;
    }
    m_authoritative = true;
    m_up = how == PhysicalSourceStart::Up;
    qInfo() << "[uplink] physical source, initial" << (initial == 1 ? "up" : initial == 0 ? "down" : "unknown");
    return true;
}
#endif

UplinkMonitor *UplinkMonitor::instance()
{
    static UplinkMonitor *s_instance = new UplinkMonitor(QCoreApplication::instance());
    return s_instance;
}

UplinkMonitor::UplinkMonitor(QObject *parent) : QObject(parent)
{
    start();
}

UplinkMonitor::~UplinkMonitor() = default;

namespace {
UplinkReach reachOf(QNetworkInformation::Reachability r)
{
    switch (r) {
    case QNetworkInformation::Reachability::Disconnected: return UplinkReach::Disconnected;
    case QNetworkInformation::Reachability::Local:        return UplinkReach::Local;
    case QNetworkInformation::Reachability::Site:         return UplinkReach::Site;
    case QNetworkInformation::Reachability::Online:       return UplinkReach::Online;
    default:                                              return UplinkReach::Unknown;
    }
}
UplinkMedium mediumOf(const QNetworkInformation *ni)
{
    if (!ni->supports(QNetworkInformation::Feature::TransportMedium))
        return UplinkMedium::Unknown;
    switch (ni->transportMedium()) {
    case QNetworkInformation::TransportMedium::Ethernet:  return UplinkMedium::Ethernet;
    case QNetworkInformation::TransportMedium::WiFi:      return UplinkMedium::WiFi;
    case QNetworkInformation::TransportMedium::Cellular:  return UplinkMedium::Cellular;
    case QNetworkInformation::TransportMedium::Bluetooth: return UplinkMedium::Bluetooth;
    default:                                              return UplinkMedium::Unknown;
    }
}
} // namespace

void UplinkMonitor::start()
{
#if defined(Q_OS_ANDROID)
    if (startPhysical())
        return;
#endif
    if (!QNetworkInformation::loadDefaultBackend())
        return; // m_up stays true (lenient), m_physicalUp stays false (unknown = no)
    auto *ni = QNetworkInformation::instance();
    if (!ni)
        return;
    m_up = ni->reachability() != QNetworkInformation::Reachability::Disconnected;
    m_physicalUp = fallbackPhysicalUp(reachOf(ni->reachability()), mediumOf(ni));
    const auto refreshPhysical = [this, ni]() {
        m_physicalUp = fallbackPhysicalUp(reachOf(ni->reachability()), mediumOf(ni));
    };
    connect(ni, &QNetworkInformation::reachabilityChanged, this, [this, refreshPhysical](QNetworkInformation::Reachability r) {
        refreshPhysical();
        setUp(r != QNetworkInformation::Reachability::Disconnected);
    });
    connect(ni, &QNetworkInformation::transportMediumChanged, this, [refreshPhysical](QNetworkInformation::TransportMedium) {
        refreshPhysical();
    });
}

void UplinkMonitor::setUp(bool up, int)
{
    if (m_up == up)
        return;
    m_up = up;
    qInfo() << "[uplink]" << (up ? "up" : "down") << (m_authoritative ? "(physical)" : "(QNetworkInformation)");
    emit changed(up);
}

} // namespace avpn
