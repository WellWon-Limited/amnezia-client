#include "VpnConnectionTunnelControl.h"

// [IN-FORK BUILD] заголовки форка:
#include "vpnConnection.h"
#include "core/utils/containerEnum.h"   // AVPN: DockerContainer enum (was wrong path core/defs.h)

#include <QSettings>                    // AVPN RU-direct: чтение тумблера AvpnBypass/masterOn для DNS-override

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

    // AVPN RU-direct (единый «Доступ к сайтам РФ», AvpnBypass/masterOn, default ON): DNS = РУССКИЙ резолвер
    // (Яндекс 77.88.8.8/.1 ∈ 77.88.0.0/18 ⊂ рунет → уходит МИМО туннеля вместе с рунетом → residential-
    // резолвер). Иначе DNS шёл бы на дефолтный 1.1.1.1 через загранузел, и инфра-сервисы со своим
    // авторитативным DNS (Госуслуги/VK/Кинопоиск) палили бы «нероссийский резолвер» → мягкое «возможно VPN».
    // Магазинам (Ozon/WB) DNS-гео не важно. Сам site-split (рунет CIDR мимо туннеля) сеет движок в
    // репозиторий — AvpnEngineQml::applyRuBypassSplit. RU-нода вторым пиром больше НЕ используется.
    // T2: на самой РФ-ноде (countryCode==RU, форс-pin) DNS не подменяем — там full-tunnel через РФ,
    // резолвер и так российский (сплит на РФ-ноде выключен в applyRuBypassSplit).
    SubscriptionNode primary = node;   // мутабельная копия (DNS-override под РФ-доступ)
    {
        QSettings s;
        const bool ruNode = node.countryCode.compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0;
        if (!ruNode && s.value(QStringLiteral("AvpnBypass/masterOn"), true).toBool())
            primary.dns = QStringList{QStringLiteral("77.88.8.8"), QStringLiteral("77.88.8.1")};
    }

    const QJsonObject cfg = AwgConfigBuilder::build(sub, primary, m_keys);
    if (!invokeConnect(cfg, primary.nodeId))
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
