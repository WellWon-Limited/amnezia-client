#include "VpnConnectionTunnelControl.h"

// [IN-FORK BUILD] заголовки форка:
#include "vpnConnection.h"
#include "core/utils/containerEnum.h"   // AVPN: DockerContainer enum (was wrong path core/defs.h)
#include "core/repositories/secureAppSettingsRepository.h" // AVPN RU-direct: флаг сплита по факт-ноде
#include "BypassListService.h" // AVPN server-driven АнтиВПН (Task 10): split-DNS из BypassListStore
#include "NodeRotation.h"      // AVPN awg31-xray-v1: protoOf/isXrayProto — диспетчер по proto ноды
#include "XrayConfigBuilder.h" // AVPN awg31-xray-v1: конфиг xray (VLESS+Reality) для DockerContainer::Xray

#include <QDebug>                       // AVPN awg31-xray-v1: qWarning при фильтрации wg-quick ключей
#include <QJsonArray>                   // AVPN split-DNS: список RU-суффиксов в корень cfg
#include <QSettings>                    // AVPN RU-direct: чтение тумблера AvpnBypass/masterOn для DNS-override
#include "TuningStore.h"                // AVPN backend-first (T20): server-tunable пороги
#include "ConnectTunables.h"            // AVPN: клампованные handshake-пороги (ревью 2026-07-11)
#include "core/utils/constants/configKeys.h" // AVPN seamless roaming: ключи roam* в корень cfg
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN awg31-xray-v1 (этап D2): статистика xray-пути демона через QtRO (xrayRuntimeStatus), async
    #include "core/utils/ipcClient.h"
    #include <QRemoteObjectPendingCall>
#endif

// AVPN: handshake age приходит из платформенного контроллера (iOS: UAPI last_handshake_time_sec
// уже парсится в IosController::checkStatus). Подключаемся к нему НАПРЯМУЮ под платформенным гардом,
// чтобы не трогать кросс-платформенный VpnConnection. Android — свой путь через JNI (см. ниже, TODO).
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif
#if defined(Q_OS_ANDROID)
    #include "platforms/android/android_controller.h"
#endif

#include <QDateTime>                    // AVPN: посев handshake-epoch ≈ now на Connected (анти-ложный-DEAD)
#include <QMetaObject>
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (BUG-4 auto-heal): прямой fire-and-forget {"type":"rebind"} демону (паттерн BUG-6)
    #include <QFile>
    #include <QJsonDocument>
    #include <QLocalSocket>
    #include <QTimer>
#endif

namespace avpn {

VpnConnectionTunnelControl::VpnConnectionTunnelControl(VpnConnection *conn, QObject *parent)
    : QObject(parent), m_conn(conn)
{
    if (m_conn) {
        connect(m_conn, &VpnConnection::bytesChanged, this,
                &VpnConnectionTunnelControl::onBytesChanged, Qt::QueuedConnection);
        // AVPN (инцидент 2026-07-11, ложный DEAD → самопроизвольный failover): на Connected сеем
        // handshake-epoch ≈ now — данные текут ⇒ рукопожатие только что состоялось (паритет с
        // desktop-UAPI). Иначе на iOS/Windows epoch=0 первые секунды, и hsStale в HealthLoop
        // считал живой туннель «протухшим» на фоне tx-бёрстов проб. Реальный отчёт (>0) уточнит.
        // AVPN awg31-xray-v1: у xray handshake нет по определению — эпоху НЕ сеем (0 = «неизвестно»
        // → hsStale в HealthLoop): DEAD для xray = tx растёт при стоящем rx (плюс провал живой
        // пробы через туннель, ServiceEngine::feedProbeResult), а «Подключено» показывается только
        // после первой удачной пробы (фаза Verifying), так что tx-бёрсты проб на старте не
        // попадают в health-контур.
        connect(m_conn, &VpnConnection::connectionStateChanged, this,
                [this](Vpn::ConnectionState st) {
                    if (st == Vpn::ConnectionState::Connected && !isXrayProto(m_lastUpProto))
                        updateHandshakeEpoch(m_stats, QDateTime::currentSecsSinceEpoch());
                },
                Qt::QueuedConnection);
    }
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN awg31-xray-v1 (этап D2): демон отдаёт кумулятивы rx/tx utun tun2socks по IPC — поллим,
    // пока поднят xray (старт в up(), стоп в down()). Интервал ~2с: чаще health-тика (4с), чтобы
    // HealthLoop видел свежие соседние замеры.
    m_xrayStatsTimer = new QTimer(this);
    m_xrayStatsTimer->setInterval(2000);
    connect(m_xrayStatsTimer, &QTimer::timeout, this, &VpnConnectionTunnelControl::pollXrayRuntimeStatus);
#endif
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // AVPN: возраст хендшейка → m_stats.latestHandshakeEpoch (на iOS раньше был 0 ⇒ HealthLoop
    // опирался только на rx/tx; теперь DEAD-детект учитывает и устаревший handshake, как на desktop).
    // updateHandshakeEpoch: 0 = «неизвестно», известное значение не затирается (ITunnelControl.h).
    connect(IosController::Instance(), &IosController::handshakeChanged, this,
            [this](qint64 hsEpochSec) { updateHandshakeEpoch(m_stats, hsEpochSec); },
            Qt::QueuedConnection);
    // AVPN (девайс-разбор 2026-09-02): ядро Xray не поднялось в NE — текст причины наружу
    // (лог + последний отчёт о конфигурации, который уходит в диагностику). Раньше отказ был
    // безымянным, и «вечное подключение» нечем было объяснить.
    connect(IosController::Instance(), &IosController::xrayStartFailed, this,
            [this](const QString &reason) {
                m_lastXrayStartFailure = reason;
                qWarning() << "[avpn xray] core start failed on device:" << reason;
            },
            Qt::QueuedConnection);
#endif
#if defined(Q_OS_ANDROID)
    // AVPN: то же на Android (last_handshake_time_sec из GoBackend.awgGetConfig → Statistics → JNI).
    connect(AndroidController::instance(), &AndroidController::handshakeUpdated, this,
            [this](qint64 hsEpochSec) { updateHandshakeEpoch(m_stats, hsEpochSec); },
            Qt::QueuedConnection);
#endif
}

void VpnConnectionTunnelControl::onBytesChanged(quint64 rx, quint64 tx)
{
    // bytesChanged на всех платформах = ДЕЛЬТЫ за период (vpnProtocol::setBytesChanged /
    // ios_controller.mm эмитят diff) → аккумулируем в кумулятив, как ждёт HealthLoop
    // (rxStuck/txGrew); контракт и TDD — ITunnelControl.h + tests/parse_check.cpp.
    accumulateByteDelta(m_stats, rx, tx);
}

bool VpnConnectionTunnelControl::invokeConnect(const QJsonObject &cfg, const QString &serverId,
                                                amnezia::DockerContainer container)
{
    if (!m_conn)
        return false;
    // VpnConnection живёт в своём QThread → только через очередь. // AVPN
    // DockerContainer::Awg/Xray (containerEnum.h) и порядок аргументов connectToVpn
    // (serverId, container, vpnConfiguration) сверены с форком — корректно. // AVPN
    // AVPN awg31-xray-v1: контейнер — по proto ноды (единственная точка ветвления протокола):
    // Xray → десктоп XrayProtocol (демон Xray::startXray + tun2socks) / iOS setupXray (NE).
    return QMetaObject::invokeMethod(
        m_conn, "connectToVpn", Qt::QueuedConnection,
        Q_ARG(QString, serverId),
        Q_ARG(DockerContainer, container),
        Q_ARG(QJsonObject, cfg));
}

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
// AVPN awg31-xray-v1 (этап D2): один async-замер статистики xray-пути демона. Реплика на живом
// xray-туннеле уже инициализирована (XrayProtocol::start ходил через неё) — withInterface не ждёт;
// ответ — QRemoteObjectPendingCallWatcher (никакого waitForFinished на GUI-потоке, §1). Демон
// отдаёт КУМУЛЯТИВЫ с подъёма сессии (reset-safe аккумулятор utun) — пишем напрямую, без
// accumulateByteDelta (тот — для дельтовых источников bytesChanged; на xray-пути демона их нет).
void VpnConnectionTunnelControl::pollXrayRuntimeStatus()
{
    if (!isXrayProto(m_lastUpProto))
        return;
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        if (rep.isNull() || !rep->isReplicaValid())
            return;
        // Пустой хинт = дефолт демона (utun22 — tunName из xrayProtocol.cpp на macOS).
        QRemoteObjectPendingReply<QJsonObject> reply = rep->xrayRuntimeStatus(QString());
        auto *watcher = new QRemoteObjectPendingCallWatcher(reply, this);
        connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
                [this, watcher](QRemoteObjectPendingCallWatcher *) {
                    watcher->deleteLater();
                    if (watcher->error() != QRemoteObjectPendingCall::NoError)
                        return;
                    if (!isXrayProto(m_lastUpProto))
                        return; // за время ответа туннель сменился — стейл
                    const QJsonObject o = watcher->returnValue().toJsonObject();
                    if (!o.value(QStringLiteral("running")).toBool()
                        || o.value(QStringLiteral("unsupported")).toBool())
                        return;
                    const qint64 rx = qint64(o.value(QStringLiteral("rx_bytes")).toDouble());
                    const qint64 tx = qint64(o.value(QStringLiteral("tx_bytes")).toDouble());
                    if (rx < 0 || tx < 0)
                        return;
                    // Кумулятив только растёт (аккумулятор демона); откат = новая сессия демона —
                    // не даём HealthLoop'у «rx стоит» из-за скачка вниз: принимаем как есть, ITunnelControl
                    // §17.1 (0 = неизвестно) не нарушаем.
                    m_stats.rxBytes = rx;
                    m_stats.txBytes = tx;
                    m_stats.valid = true;
                });
    });
}
#endif

// AVPN awg31-xray-v1 (независимое ревью волны, MINOR-4): см. объявление в заголовке. Async, без
// nested QEventLoop (§1); идемпотентно (повторный вызов при уже известном xray — no-op).
void VpnConnectionTunnelControl::adoptXrayIfRunning()
{
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (isXrayProto(m_lastUpProto))
        return; // путь уже опознан как xray — поллинг идёт
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        if (rep.isNull() || !rep->isReplicaValid())
            return;
        QRemoteObjectPendingReply<QJsonObject> reply = rep->xrayRuntimeStatus(QString());
        auto *watcher = new QRemoteObjectPendingCallWatcher(reply, this);
        connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
                [this, watcher](QRemoteObjectPendingCallWatcher *) {
                    watcher->deleteLater();
                    if (watcher->error() != QRemoteObjectPendingCall::NoError)
                        return;
                    const QJsonObject o = watcher->returnValue().toJsonObject();
                    if (!o.value(QStringLiteral("running")).toBool()
                        || o.value(QStringLiteral("unsupported")).toBool())
                        return; // демон держит не xray (или ответ от старого демона) — адоптить нечего
                    if (isXrayProto(m_lastUpProto))
                        return; // пока ждали ответ, туннель подняли сами
                    m_lastUpProto = QStringLiteral("xray");
                    m_stats = TunnelStats{}; // кумулятивы демона считаем с этого момента
                    if (m_xrayStatsTimer)
                        m_xrayStatsTimer->start();
                    qInfo() << "avpn: adopted live xray tunnel — runtime stats polling started";
                });
    });
#endif
}

TunnelResult VpnConnectionTunnelControl::up(const Subscription &sub, const SubscriptionNode &node)
{
    if (!m_conn)
        return TunnelResult::fail(QStringLiteral("no VpnConnection"));
    if (m_keys.privateKey.isEmpty())
        return TunnelResult::fail(QStringLiteral("client keys not set"));
    // AVPN awg31-xray-v1: диспетчер по proto ноды. xray без параметров непригодна (парсер такую
    // отбрасывает; страховка для стейл-LKG) — честный отказ до туннеля.
    const bool xrayNode = isXrayProto(protoOf(node));
    if (xrayNode && !node.xray.has_value())
        return TunnelResult::fail(QStringLiteral("xray node without xray_params"));

    // AVPN server-driven АнтиВПН (Task 10): снапшот серверного split_dns (подпись+LKG), один раз.
    // При невалидном снапшоте (офлайн/первый запуск/kill-switch) — прежние вкомпиленные литералы.
    // Значения в КОРЕНЬ cfg остаются СТРОКАМИ, где были строками (JSONDecoder-грабля iOS).
    const avpn::BypassLists bl = avpn::BypassListStore::get();

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
        // AVPN split-DNS форвардер (v1 iOS, дизайн SPLIT-DNS-FORWARDER-DESIGN.md): DNS-прокси в
        // туннель-движке даёт macOS-качество (стелс И честный гео сразу) — при нём маска не нужна
        // и НЕ применяется (тумблер маскировки остаётся в UI, просто игнорируется при dnsFwd=ON).
        const bool dnsFwdOn = s.value(QStringLiteral("AvpnBypass/dnsFwd"), true).toBool();
        if (!ruNode && masterOn && dnsMaskOn && !dnsFwdOn) {
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
            splitDns = true; // DNS ноды (1.1.1.1) не подменяем — RU-суффиксы уйдут на Яндекс через демона
#else
            // AVPN Task 10: mask-DNS пара — серверная (bl.maskDns) при валидном снапшоте, иначе литерал.
            primary.dns = (bl.valid && bl.maskDns.size() >= 2)
                ? QStringList{bl.maskDns[0], bl.maskDns[1]}
                : QStringList{QStringLiteral("77.88.8.8"), QStringLiteral("77.88.8.1")};
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
            bool splitOn = (masterOn || liAutoOn) && !ruNode;
#if !defined(Q_OS_IOS) && !defined(Q_OS_ANDROID) && !defined(MACOS_NE)
            // AVPN awg31-xray-v1: десктопный XrayProtocol::setupRouting умеет ТОЛЬКО VpnAllSites
            // (VpnAllExceptSites для xray на десктопе апстримом не реализован — с ним маршруты в tun
            // не ставятся вовсе = чёрная дыра). Для xray на macOS-демоне — строго full-tunnel;
            // RU-байпас на xray-транспорте десктопа — следующая волна. iOS NE xray split держит.
            if (xrayNode)
                splitOn = false;
#endif
            if (splitOn)
                m_appStore->setRouteMode(amnezia::RouteMode::VpnAllExceptSites);
            m_appStore->setSitesSplitTunnelingEnabled(splitOn);
            splitOnFact = splitOn;
        }
        ruNodeFact = ruNode;
    }

    // AVPN awg31-xray-v1: xray — отдельный конверт (protocol=xray + xray_config_data.config = JSON
    // xray-core + hostName/dns1/dns2/splitTunnelType); AWG-специфичные ключи (dnsFwd*, split-DNS
    // демона, handshake-пороги NE) к нему не относятся — их читают только WG-пути (WGConfig.swift /
    // localsocketcontroller). DNS-override (mask/Яндекс на iOS) применён к primary выше — общий.
    if (xrayNode) {
        QJsonObject xcfg = XrayConfigBuilder::build(sub, primary, m_keys);
        if (xcfg.isEmpty())
            return TunnelResult::fail(QStringLiteral("xray config build failed"));
        m_lastConfigReport = XrayConfigBuilder::reportSummary(sub, primary);
        m_lastConfigReport.insert(QStringLiteral("split_on"), splitOnFact);
        m_lastConfigReport.insert(QStringLiteral("ru_node"), ruNodeFact);
        m_lastConfigReport.insert(QStringLiteral("split_dns"), false);
        m_lastConfigReport.insert(QStringLiteral("dns_fwd"), false);
        m_lastUpProto = QStringLiteral("xray");
        // Свежая сессия: статистика xray-пути начинается с нуля (кумулятивы демона/NE — с подъёма).
        m_stats = TunnelStats{};
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
        if (m_xrayStatsTimer)
            m_xrayStatsTimer->start();
#endif
        if (!invokeConnect(xcfg, primary.nodeId, DockerContainer::Xray))
            return TunnelResult::fail(QStringLiteral("connectToVpn invoke failed"));
        return TunnelResult::success();
    }
    m_lastUpProto = QStringLiteral("awg");
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (m_xrayStatsTimer)
        m_xrayStatsTimer->stop();
#endif

    QJsonObject cfg = AwgConfigBuilder::build(sub, primary, m_keys);
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // AVPN awg31-xray-v1 (инвариант волны §4.5 «незнакомый ключ не доезжает до NE»): awg-apple 3.1.4
    // (TunnelConfiguration+WgQuickConfig.swift) бросает interfaceHasUnrecognizedKey на любом
    // незнакомом ключе wg-quick → туннель молча не поднимается. Фильтруем нативный текст по
    // allowlist ключей этого awg-apple (AwgConfigBuilder::awgAppleWgQuickKeys, зеркало рецепта).
    // Только Apple: awg-go/android/windows к незнакомым ключам мягче, там текст не трогаем.
    {
        QJsonObject inner = cfg.value(QStringLiteral("awg_config_data")).toObject();
        const QString native = inner.value(QStringLiteral("config")).toString();
        const QString stripped = AwgConfigBuilder::stripUnknownWgQuickKeys(native, AwgConfigBuilder::awgAppleWgQuickKeys());
        if (stripped != native) {
            qWarning() << "avpn: wg-quick config had keys unknown to awg-apple — stripped before NE";
            inner.insert(QStringLiteral("config"), stripped);
            cfg.insert(QStringLiteral("awg_config_data"), inner);
        }
    }
#endif
    // AVPN split-DNS форвардер (iOS): ключи в КОРЕНЬ cfg → ios_controller::setupAwg → WGConfig.swift
    // → wgSetSplitDns (Go dnsfwd.go). Значения СТРОКАМИ (JSONDecoder-грабля). Не на РФ-ноде
    // (там full-tunnel через РФ — резолвер и так российский).
    {
        QSettings st;
        const bool fwd = st.value(QStringLiteral("AvpnBypass/dnsFwd"), true).toBool();
        const bool ruN = node.countryCode.compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0;
        if (fwd && !ruN) {
            cfg.insert(QStringLiteral("dnsFwdOn"), QStringLiteral("1"));
            // AVPN Task 10: суффиксы+сервер форвардера — серверные при валидном снапшоте, иначе литералы.
            // Значения СТРОКАМИ (JSONDecoder-грабля iOS): suffixes = join(','), server = строка.
            cfg.insert(QStringLiteral("dnsFwdSuffixes"),
                       bl.valid ? bl.splitDnsSuffixes.join(QLatin1Char(','))
                                : QStringLiteral("ru,su,xn--p1ai,vk.com,userapi.com,yandex.net,yastatic.net"));
            cfg.insert(QStringLiteral("dnsFwdServer"),
                       bl.valid ? bl.splitDnsServer : QStringLiteral("77.88.8.8"));
            // AVPN: прогрев WG-рукопожатия при подъёме — первый DNS не ловит холодный туннель
            // («первый запрос мимо, второй ок»). Kill-switch features.dns_fwd_warmup (default ВКЛ):
            // бэк гасит без релиза, прислав "0". Значение СТРОКОЙ (JSONDecoder-грабля iOS).
            cfg.insert(QStringLiteral("dnsFwdWarmup"),
                       avpn::TuningStore::flag(QStringLiteral("dns_fwd_warmup"), true)
                           ? QStringLiteral("1") : QStringLiteral("0"));
        }
    }
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // AVPN seamless roaming (2026-09-03, CONNECT-INVARIANTS §23): политика адаптера AWG на потерю
    // пути (mesh-роуминг, Wi-Fi <-> сотовая). Ключи в КОРЕНЬ cfg -> ios_controller::setupWireGuard
    // -> WGConfig.swift -> TribeRoamingPolicy. Значения СТРОКАМИ (JSONDecoder-грабля iOS).
    // kill-switch features.ios_awg_seamless_roaming (default ВКЛ): false = поведение апстрима
    // (устройство гасится на первом же unsatisfied, рестарт с новым handshake на возврате).
    {
        const bool seamless = avpn::TuningStore::flag(QStringLiteral("ios_awg_seamless_roaming"), true);
        cfg.insert(configKey::roamKeepBackend, seamless ? QStringLiteral("1") : QStringLiteral("0"));
        cfg.insert(configKey::roamPauseAfterS, QString::number(avpn::roamPauseAfterSTuned()));
        cfg.insert(configKey::roamStallProbeS, QString::number(avpn::roamStallProbeSTuned()));
        cfg.insert(configKey::roamStallRebindS, QString::number(avpn::roamStallRebindSTuned()));
        m_lastConfigReport.insert(QStringLiteral("roaming"),
                                  QStringLiteral("keep=%1 pause=%2 probe=%3 rebind=%4")
                                      .arg(seamless ? 1 : 0)
                                      .arg(avpn::roamPauseAfterSTuned())
                                      .arg(avpn::roamStallProbeSTuned())
                                      .arg(avpn::roamStallRebindSTuned()));
    }
#endif
    // AVPN backend-first: пороги «нода мертва» для iOS NE (numbers.*; фолбэк = константы NE).
    // Клампы ОБЯЗАТЕЛЬНЫ (ревью 2026-07-11): timeout=0 с бэка = каждый iOS-коннект умирает
    // на первом тике checkStatus; связка с watchdog — ConnectTunables.h.
    cfg.insert(QStringLiteral("awg_handshake_timeout_ms"), avpn::handshakeTimeoutMsTuned());
    cfg.insert(QStringLiteral("awg_handshake_max_timeouts"), avpn::handshakeMaxTimeoutsTuned());
    cfg.insert(QStringLiteral("awg_handshake_rx_threshold_bytes"),
               qBound(256,
                      int(avpn::TuningStore::numberOr(QStringLiteral("handshake_rx_threshold_bytes"), 4096)),
                      10485760));
    if (splitDns) {
        // AVPN split-DNS: RU-суффиксы (TLD рунета + RU-сервисы вне .ru) → Яндекс мимо туннеля.
        // Прокид: localsocketcontroller → демон → /etc/resolver/*. Яндекс отвечает ТОЛЬКО
        // residential-IP (проверено: с ДЦ-egress UDP53 молчит) — потому строго мимо туннеля.
        // AVPN Task 10: split-DNS суффиксы+сервер (macOS-демон) — серверные при валидном снапшоте,
        // иначе прежние литералы.
        cfg.insert(QStringLiteral("splitDnsSuffixes"),
                   bl.valid ? QJsonArray::fromStringList(bl.splitDnsSuffixes)
                            : QJsonArray{ QStringLiteral("ru"), QStringLiteral("su"), QStringLiteral("xn--p1ai"),
                                          QStringLiteral("vk.com"), QStringLiteral("userapi.com"),
                                          QStringLiteral("yandex.net"), QStringLiteral("yastatic.net") });
        cfg.insert(QStringLiteral("splitDnsServer"),
                   bl.valid ? bl.splitDnsServer : QStringLiteral("77.88.8.8"));
    }
    // AVPN bench v5 (tunnel.config): снапшот того, что РЕАЛЬНО уходит в туннель (primary — уже с
    // dns-override, эффективные mtu/dns из reportSummary) + факты сева этого подъёма.
    m_lastConfigReport = AwgConfigBuilder::reportSummary(sub, primary);
    m_lastConfigReport.insert(QStringLiteral("split_on"), splitOnFact);
    m_lastConfigReport.insert(QStringLiteral("ru_node"), ruNodeFact);
    m_lastConfigReport.insert(QStringLiteral("split_dns"), splitDns);
    m_lastConfigReport.insert(QStringLiteral("dns_fwd"), cfg.contains(QStringLiteral("dnsFwdOn")));

    if (!invokeConnect(cfg, primary.nodeId, DockerContainer::Awg))
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

// AVPN (BUG-4 auto-heal): ребайнд сокета живого туннеля — новый эфемерный локальный порт
// (UAPI listen_port=0 → BindUpdate awg-go) без рестарта туннеля. Детали в ITunnelControl.h.
bool VpnConnectionTunnelControl::rebindSocket()
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // NE: provider message живому extension'у (тот же канал, что checkStatus/getStatus).
    return IosController::Instance()->rebindTunnel();
#elif defined(Q_OS_MACOS)
    // root-демон: fire-and-forget {"type":"rebind"} его локальным протоколом (паттерн
    // daemonDirectDeactivate BUG-6, без nested loop — NetAwait-доктрина §1). Старый демон на
    // неизвестную команду отвечает warning-логом и живёт дальше — раскатка безопасна в любом
    // порядке; итог heal'а и так меряет HealthLoop (rx оживёт или DEAD вернётся).
    auto *sock = new QLocalSocket(this);
    auto *guard = new QTimer(sock);
    guard->setSingleShot(true);
    connect(guard, &QTimer::timeout, sock, &QObject::deleteLater);
    connect(sock, &QLocalSocket::connected, sock, [sock]() {
        sock->write(QJsonDocument(QJsonObject{ { QStringLiteral("type"), QStringLiteral("rebind") } })
                        .toJson(QJsonDocument::Compact));
        sock->write("\n");
        sock->flush();
        QTimer::singleShot(300, sock, &QObject::deleteLater); // байты ушли — сокет больше не нужен
    });
    connect(sock, &QLocalSocket::errorOccurred, sock, [sock](QLocalSocket::LocalSocketError) {
        sock->deleteLater();
    });
    guard->start(3000);
    const QString primary = QStringLiteral("/var/run/avpn/daemon.socket"); // путь LocalSocketController
    sock->connectToServer(QFile::exists(primary) ? primary : QStringLiteral("/tmp/avpn.socket"));
    return true;
#else
    return false; // Android (нет awgSetConfig в JNI) / Windows (wireguard-nt) — сразу failover
#endif
}

void VpnConnectionTunnelControl::down()
{
    if (m_conn)
        QMetaObject::invokeMethod(m_conn, "disconnectFromVpn", Qt::QueuedConnection);
    m_stats = TunnelStats{};
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (m_xrayStatsTimer)
        m_xrayStatsTimer->stop(); // AVPN awg31-xray-v1: сессия xray закрыта — поллинг демона не нужен
#endif
}

} // namespace avpn
