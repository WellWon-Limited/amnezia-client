#include "VpnConnectionTunnelControl.h"

// [IN-FORK BUILD] заголовки форка:
#include "vpnConnection.h"
#include "core/utils/containerEnum.h"   // AVPN: DockerContainer enum (was wrong path core/defs.h)

#include "ru_prefixes.h"                // AVPN RU-split: «весь рунет» для AllowedIPs RU-пира
#include <QSettings>                    // AVPN RU-split: чтение экспериментального флага avpn/ruSplit

// AVPN: handshake age приходит из платформенного контроллера (iOS: UAPI last_handshake_time_sec
// уже парсится в IosController::checkStatus). Подключаемся к нему НАПРЯМУЮ под платформенным гардом,
// чтобы не трогать кросс-платформенный VpnConnection. Android — свой путь через JNI (см. ниже, TODO).
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif
#if defined(Q_OS_ANDROID)
    #include "platforms/android/android_controller.h"
#endif

#include <QMetaObject>

namespace avpn {

VpnConnectionTunnelControl::VpnConnectionTunnelControl(VpnConnection *conn, QObject *parent)
    : QObject(parent), m_conn(conn)
{
    if (m_conn) {
        connect(m_conn, &VpnConnection::bytesChanged, this,
                &VpnConnectionTunnelControl::onBytesChanged, Qt::QueuedConnection);
    }
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // AVPN: возраст хендшейка → m_stats.latestHandshakeEpoch (на iOS раньше был 0 ⇒ HealthLoop
    // опирался только на rx/tx; теперь DEAD-детект учитывает и устаревший handshake, как на desktop).
    connect(IosController::Instance(), &IosController::handshakeChanged, this,
            [this](qint64 hsEpochSec) { m_stats.latestHandshakeEpoch = hsEpochSec; },
            Qt::QueuedConnection);
#endif
#if defined(Q_OS_ANDROID)
    // AVPN: то же на Android (last_handshake_time_sec из GoBackend.awgGetConfig → Statistics → JNI).
    connect(AndroidController::instance(), &AndroidController::handshakeUpdated, this,
            [this](qint64 hsEpochSec) { m_stats.latestHandshakeEpoch = hsEpochSec; },
            Qt::QueuedConnection);
#endif
}

void VpnConnectionTunnelControl::onBytesChanged(quint64 rx, quint64 tx)
{
    m_stats.rxBytes = static_cast<qint64>(rx);
    m_stats.txBytes = static_cast<qint64>(tx);
    m_stats.valid = true;
}

bool VpnConnectionTunnelControl::invokeConnect(const QJsonObject &cfg, const QString &serverId)
{
    if (!m_conn)
        return false;
    // VpnConnection живёт в своём QThread → только через очередь. // AVPN
    // DockerContainer::Awg (containerEnum.h) и порядок аргументов connectToVpn
    // (serverId, container, vpnConfiguration) сверены с форком — корректно. // AVPN
    return QMetaObject::invokeMethod(
        m_conn, "connectToVpn", Qt::QueuedConnection,
        Q_ARG(QString, serverId),
        Q_ARG(DockerContainer, DockerContainer::Awg),
        Q_ARG(QJsonObject, cfg));
}

TunnelResult VpnConnectionTunnelControl::up(const Subscription &sub, const SubscriptionNode &node)
{
    if (!m_conn)
        return TunnelResult::fail(QStringLiteral("no VpnConnection"));
    if (m_keys.privateKey.isEmpty())
        return TunnelResult::fail(QStringLiteral("client keys not set"));

    // AVPN RU-split (экспериментальный флаг avpn/ruSplit, default OFF — обратимо, см. PageSettings):
    // добавить RU-ноду из пула вторым пиром в ТОТ ЖЕ туннель и завернуть в неё «весь рунет» (ru_prefixes.h).
    // Основной (загран) пир остаётся 0.0.0.0/0 → Ozon/банки/любой РФ-хост идут через РФ, а WhatsApp/Telegram
    // (зарубежные серверы) — через загранузел. ВАЖНО: параметры обфускации [Interface] общие на туннель →
    // RU-нода ОБЯЗАНА делить их с основной нодой (выровнено операционно на стороне ноды).
    QList<SubscriptionNode> extraPeers;
    {
        QSettings s;
        if (s.value(QStringLiteral("AvpnSettings/ruSplit"), false).toBool()) {
            for (const SubscriptionNode &n : sub.nodes) {
                if (n.region.compare(QStringLiteral("ru"), Qt::CaseInsensitive) == 0 && n.nodeId != node.nodeId) {
                    SubscriptionNode ru = n;
                    ru.allowedIps = ruPrefixes();   // весь рунет
                    extraPeers << ru;
                    break;
                }
            }
        }
    }

    const QJsonObject cfg = AwgConfigBuilder::build(sub, node, m_keys, extraPeers);
    if (!invokeConnect(cfg, node.nodeId))
        return TunnelResult::fail(QStringLiteral("connectToVpn invoke failed"));
    return TunnelResult::success();
}

TunnelResult VpnConnectionTunnelControl::applyPeer(const Subscription &sub, const SubscriptionNode &node)
{
    // MVP: быстрый reconnect (VpnConnection не отдаёт server-switch наружу на всех платформах).
    down();
    return up(sub, node);
}

TunnelStats VpnConnectionTunnelControl::readStats()
{
    return m_stats;
}

void VpnConnectionTunnelControl::down()
{
    if (m_conn)
        QMetaObject::invokeMethod(m_conn, "disconnectFromVpn", Qt::QueuedConnection);
    m_stats = TunnelStats{};
}

} // namespace avpn
