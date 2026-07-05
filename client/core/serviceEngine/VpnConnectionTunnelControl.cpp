#include "VpnConnectionTunnelControl.h"

// [IN-FORK BUILD] заголовки форка:
#include "vpnConnection.h"
#include "core/utils/containerEnum.h"   // AVPN: DockerContainer enum (was wrong path core/defs.h)
#include "core/repositories/secureAppSettingsRepository.h" // AVPN RU-direct: флаг сплита по факт-ноде

#include <QJsonArray>                   // AVPN split-DNS: список RU-суффиксов в корень cfg
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
    // T2: на самой РФ-ноде (countryCode==RU) DNS не подменяем — там full-tunnel через РФ,
    // резолвер и так российский (сплит на РФ-ноде выключается здесь же, ниже).
    SubscriptionNode primary = node;   // мутабельная копия (DNS-override под РФ-доступ)
    bool splitDns = false;             // AVPN split-DNS: поля в корень cfg (macOS-демон)
    bool splitOnFact = false;          // AVPN bench v5: факт сева сплита — в tunnel.config отчёта
    bool ruNodeFact = false;
    {
        QSettings s;
        const bool ruNode = node.countryCode.compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0;
        const bool masterOn = s.value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
        // AVPN (звонки, 2026-07-03): dnsMaskOn — саб-опция «RU-DNS маскировка» (дефолт ВКЛ). Измерено:
        // Яндекс-DNS-на-всё с загран-egress выдаёт RU-гео edge → WhatsApp-инфра 131мс vs 75мс честного
        // гео (+75%) — страдают звонки/realtime. Поэтому:
        //   • macOS-десктоп (root-демон): SPLIT-DNS — глобальный DNS остаётся бэкендовский (1.1.1.1
        //     через туннель, гео=egress ⇒ звонки/CDN честные), а RU-суффиксы демон направляет на Яндекс
        //     мимо туннеля через /etc/resolver/* (стелс Госуслуг/Кинопоиска сохраняется). ОБА свойства.
        //   • iOS/Android: NE/VpnService дают ОДИН резолвер ⇒ пока прежнее поведение (Яндекс-на-всё);
        //     полный split там = DNS-форвардер в туннель-движке (в плане, см. память tribe-ru-split).
        // dnsMaskOn OFF ⇒ чистый 1.1.1.1 везде (маршрутный RU-байпас не трогается).
        const bool dnsMaskOn = s.value(QStringLiteral("AvpnBypass/dnsMaskOn"), true).toBool();
        if (!ruNode && masterOn && dnsMaskOn) {
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
            splitDns = true; // DNS ноды (1.1.1.1) не подменяем — RU-суффиксы уйдут на Яндекс через демона
#else
            primary.dns = QStringList{QStringLiteral("77.88.8.8"), QStringLiteral("77.88.8.1")};
#endif
        }

        // AVPN RU-direct (T2, аудит 2026-07-02): вкл/выкл сплита — ПО ФАКТИЧЕСКОЙ ноде, здесь, а не по
        // pin в applyRuBypassSplit. Прежний гейт по pinnedNodeIsRu() расходился с реальностью на всех
        // путях, где нода ≠ pin: (а) авто-RU-fallback (все не-RU мертвы) оставлял сплит ВКЛ на РФ-ноде;
        // (б) мёртвый RU-pin → авто не-RU, а сплит остался ВЫКЛ (фича молча отключена); (в) failover
        // (continuePendingSwitch → up() напрямую) сев вообще не пере-выполнял. up() — единственная
        // точка, через которую проходит КАЖДЫЙ подъём туннеля (connect/failover/rotate/pin), поэтому
        // решение тут покрывает все пути. Список CIDR к этому моменту уже засеян (guardedStart →
        // applyRuBypassSplit при masterOn); appendSplitTunnelingConfig прочтёт флаг из этого же стора
        // в connectToVpn (queued — строго после нас). Паттерн тот же, что у DNS-гейта выше.
        // AVPN (китайские сервисы, 2026-07-03): сплит нужен, если активен ЛЮБОЙ байпас-тумблер — RU-байпас
        // (masterOn) ИЛИ Li Auto (liAutoOn, default ВКЛ). На РФ-ноде сплит всё равно ВЫКЛ (full-tunnel через
        // РФ-egress — и рунет, и Li Auto тогда и так идут через российский IP). Список к этому моменту засеян
        // applyRuBypassSplit (объединяет оба набора по тем же тумблерам).
        if (m_appStore) {
            const bool liAutoOn = s.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool();
            const bool splitOn = (masterOn || liAutoOn) && !ruNode;
            if (splitOn)
                m_appStore->setRouteMode(amnezia::RouteMode::VpnAllExceptSites);
            m_appStore->setSitesSplitTunnelingEnabled(splitOn);
            splitOnFact = splitOn;
        }
        ruNodeFact = ruNode;
    }

    QJsonObject cfg = AwgConfigBuilder::build(sub, primary, m_keys);
    if (splitDns) {
        // AVPN split-DNS: RU-суффиксы (TLD рунета + RU-сервисы вне .ru) → Яндекс мимо туннеля.
        // Прокид: localsocketcontroller → демон → /etc/resolver/*. Яндекс отвечает ТОЛЬКО
        // residential-IP (проверено: с ДЦ-egress UDP53 молчит) — потому строго мимо туннеля.
        cfg.insert(QStringLiteral("splitDnsSuffixes"),
                   QJsonArray{ QStringLiteral("ru"), QStringLiteral("su"), QStringLiteral("xn--p1ai"),
                               QStringLiteral("vk.com"), QStringLiteral("userapi.com"),
                               QStringLiteral("yandex.net"), QStringLiteral("yastatic.net") });
        cfg.insert(QStringLiteral("splitDnsServer"), QStringLiteral("77.88.8.8"));
    }
    // AVPN bench v5 (tunnel.config): снапшот того, что РЕАЛЬНО уходит в туннель (primary — уже с
    // dns-override, эффективные mtu/dns из reportSummary) + факты сева этого подъёма.
    m_lastConfigReport = AwgConfigBuilder::reportSummary(sub, primary);
    m_lastConfigReport.insert(QStringLiteral("split_on"), splitOnFact);
    m_lastConfigReport.insert(QStringLiteral("ru_node"), ruNodeFact);
    m_lastConfigReport.insert(QStringLiteral("split_dns"), splitDns);

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
