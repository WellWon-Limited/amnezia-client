#include "VpnConnectionTunnelControl.h"

#include <QPointer>

// [IN-FORK BUILD] заголовки форка:
#include "vpnConnection.h"
#include "core/utils/containerEnum.h"   // AVPN: DockerContainer enum (was wrong path core/defs.h)
#include "core/repositories/secureAppSettingsRepository.h" // AVPN RU-direct: флаг сплита по факт-ноде
#include "BypassListService.h" // AVPN server-driven АнтиВПН (Task 10): split-DNS из BypassListStore
#include "NodeRotation.h"      // AVPN awg31-xray-v1: protoOf/isXrayProto — диспетчер по proto ноды
#include "XrayConfigBuilder.h" // AVPN awg31-xray-v1: конфиг xray (VLESS+Reality) для DockerContainer::Xray
#include "UpstreamEngine.h"      // AVPN upstream nodes: envelope pieces, standby candidate, tunables
#include "UpstreamLeaseClient.h" // AVPN upstream nodes: lease / standby / probe I/O (Qt only)
#include "XrayProfileSanitizer.h"

#include <QDebug>                       // AVPN awg31-xray-v1: qWarning при фильтрации wg-quick ключей
#include <QJsonArray>                   // AVPN split-DNS: список RU-суффиксов в корень cfg
#include <QSettings>                    // AVPN RU-direct: чтение тумблера AvpnBypass/masterOn для DNS-override
#include "TuningStore.h"                // AVPN backend-first (T20): server-tunable пороги
#include "ConnectTunables.h"            // AVPN: клампованные handshake-пороги (ревью 2026-07-11)
#include "core/utils/constants/configKeys.h" // AVPN seamless roaming: ключи roam* в корень cfg
#if AVPN_UPSTREAM_GUI_OWNER // macOS desktop; Windows since release C (UpstreamEngine.h)
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
#include <QElapsedTimer>
#include <QMetaObject>
#include <QRandomGenerator>
#include <QTimer>

#include <utility>
#if defined(Q_OS_MACOS) || defined(Q_OS_IOS)
    #include <time.h> // AVPN upstream nodes: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) - runs during sleep
#elif defined(Q_OS_ANDROID)
    #include <time.h> // AVPN release C: clock_gettime(CLOCK_BOOTTIME) - counts in suspend
    #include "UpstreamStatusWire.h" // AVPN release C: the hand-over message (android-ipc-contract.md §2)
#elif defined(Q_OS_WIN)
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h> // AVPN release C: GetTickCount64 - counts across sleep and hibernation
#endif
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
    // AVPN upstream nodes: the lease I/O and the app-side owner. Decision B: the macOS GUI process owns
    // renewals (the root daemon has no TLS backend and no token); on iOS / macOS NE the extension does.
    m_leaseClient = new UpstreamLeaseClient(this);
    m_upOwner.setIo(m_leaseClient);
    m_upOwner.setOrderStore(
        []() {
            // read before every allocation: another process of this installation may have moved the counter on
            QSettings st;
            st.sync();
            return st.value(QLatin1String(kUpstreamSessionOrderKey), qint64(0)).toLongLong();
        },
        [](qint64 v) {
            QSettings st;
            st.setValue(QLatin1String(kUpstreamSessionOrderKey), v);
            st.sync(); // a start's order must not be lost with the process: the next start would repeat it
        });
    m_leaseClient->onLateGrant = [this](const QString &profile, const QString &lease, const LeaseRoute &route, bool newerOut,
                                       quint64 acquireId) {
        applyUpstreamEvents(m_upOwner.lateGrant(profile, lease, route, newerOut, acquireId));
    };
    m_leaseClient->releaseWanted = [this](quint64 id) {
        QVector<UpstreamOwnerEvent> ev;
        const bool wanted = m_upOwner.releaseWanted(id, upstreamClockMs(), ev);
        applyUpstreamEvents(ev);
        return wanted;
    };
    m_leaseClient->onAcquireEnded = [this](const QString &profile, const QString &lease, bool stillOut, quint64 acquireId,
                                          bool seatUnknown) {
        // seatUnknown: the request ended and nobody can tell whether the server granted it - the ledger owes that start's seat
        // back by nonce (UpstreamLeaseOwner.h, row "answer lost"); the journal line is noteSeatDebts' below.
        applyUpstreamEvents(m_upOwner.acquireEnded(profile, lease, stillOut, acquireId, seatUnknown, upstreamClockMs()));
    };
    m_leaseClient->onRouteProved = [this](quint64 requestId) {
        m_upOwner.routeProved(requestId, upstreamClockMs());
        noteSeatDebts();
    };
    m_leaseClient->onSessionOrderFloor = [this](qint64 floorOrder) { m_upOwner.raiseOrderFloor(floorOrder); };
    {
        UpstreamLeaseOwner::Options o;
#if AVPN_UPSTREAM_GUI_OWNER
        o.keepOwnership = true;
#endif
#if defined(Q_OS_IOS)
        o.keepRecord = true; // C3 of 24.11: the record lets a relaunched app own the seat of the session it adopts (adoptUpstreamSession)
#endif
        o.scope = upstreamMeterScopeForBuild();
        m_upOwner.setOptions(o);
    }
    m_leaseClient->onAcquire = [this](quint64 id, const AcquireReply &r) {
        if (r.kind == LeaseReplyKind::Granted && r.grant.probe.present && r.grant.probe.accessAsn > 0
            && m_upOwner.active() && !m_upOwner.provisionalPending())
            emit upstreamAccessFacts(r.grant.probe.accessAsn);
        applyUpstreamEvents(m_upOwner.onAcquireReply(id, r, upstreamClockMs()));
    };
    m_leaseClient->onRenew = [this](quint64 id, const RenewReply &r) {
        // Lab 14.11 D2: a renewal our server rejects as malformed is a contract bug - journaled with its
        // code (the machine leaves the node after kUpstreamRenewRejectedLimit of them in a row).
        if (upstreamRenewRejected(r))
            qWarning().noquote() << QStringLiteral("avpn upstream: renew rejected by the server code=%1")
                                        .arg(QLatin1String(r.kind == LeaseReplyKind::Refused
                                                               ? upstreamErrorCodeName(r.error.code) : "http_422"));
        applyUpstreamEvents(m_upOwner.onRenewReply(id, r, upstreamClockMs(), QDateTime::currentMSecsSinceEpoch()));
    };
    m_leaseClient->onReleaseDone = [this](quint64 id, bool confirmed) {
        if (!confirmed)
            qWarning() << "avpn upstream: seat release not confirmed by the server - it frees the seat at the lease TTL";
        // The machine first: an acquire of the same profile that waited for this release goes out now.
        applyUpstreamEvents(m_upOwner.onReleaseDone(id, upstreamClockMs(), confirmed));
    };
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
                    if (m_leaseClient && (st == Vpn::ConnectionState::Connecting || st == Vpn::ConnectionState::Connected
                                          || st == Vpn::ConnectionState::Reconnecting))
                        m_leaseClient->tunnelStarted(); // a stop is again something a release can wait for
                    if (st == Vpn::ConnectionState::Connected && !isXrayProto(m_lastUpProto))
                        updateHandshakeEpoch(m_stats, QDateTime::currentSecsSinceEpoch());
                },
                Qt::QueuedConnection);
    }
#if AVPN_UPSTREAM_GUI_OWNER
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
#if defined(Q_OS_IOS)
    // AVPN (awg-apple tribe.17, device round 24.11 B1): the extension's stall verdict (-1 = unknown) with the time it
    // came in. iOS only: the macOS NE build keeps the behaviour of build 141 (its probe rule never sees the field).
    // tribe.18 (second review, G1): dated by its request's send time, never by when the reply was applied (a reply
    // queued before a suspension is applied after it, and must not look fresh then).
    connect(IosController::Instance(), &IosController::dataStallChanged, this,
            [this](qint64 seconds, qint64 measuredAtMs) {
                m_stats.dataStallSec = seconds;
                m_stats.dataStallAtMs = measuredAtMs;
            },
            Qt::QueuedConnection);
#endif
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
    ++m_statsSession; // a new tunnel session: statistics asked on the previous one are stale
#if defined(Q_OS_ANDROID)
    // android2 V2 (21.11): the engine leg of this start rides in the config to the VPN service, which names it in every
    // build report of the start (TribeStart.kt) - a report of an earlier start is never taken for this leg. The key is
    // unknown to every protocol backend (they read their own sections) and is set only on Android.
    QJsonObject withLeg = cfg;
    if (m_startLeg != 0)
        withLeg.insert(QStringLiteral("tribeStartLeg"), qint64(m_startLeg));
    m_startLeg = 0; // one start, one leg
    return QMetaObject::invokeMethod(
        m_conn, "connectToVpn", Qt::QueuedConnection,
        Q_ARG(QString, serverId),
        Q_ARG(DockerContainer, container),
        Q_ARG(QJsonObject, withLeg));
#endif
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

#if AVPN_UPSTREAM_GUI_OWNER
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
        // Bound to the tunnel session it was asked on (review F6 of 17.11): a reply of the old tunnel that arrives
        // after down() / the next connect never reaches the stats or the lease meter of the new session.
        const quint64 statsSession = m_statsSession;
        connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
                [this, watcher, statsSession](QRemoteObjectPendingCallWatcher *) {
                    watcher->deleteLater();
                    if (watcher->error() != QRemoteObjectPendingCall::NoError)
                        return;
                    if (!isXrayProto(m_lastUpProto) || statsSession != m_statsSession)
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
                    // AVPN upstream nodes (contract §4, scope "tunnel"): the lease meter reads the same
                    // cumulatives (utun22 since the session's start; re-based after an adoption).
                    if (m_upOwner.active())
                        m_upOwner.onBytes(rx, tx);
                });
    });
}
#endif

// AVPN awg31-xray-v1 (независимое ревью волны, MINOR-4): см. объявление в заголовке. Async, без
// nested QEventLoop (§1); идемпотентно (повторный вызов при уже известном xray — no-op).
void VpnConnectionTunnelControl::adoptXrayIfRunning()
{
#if AVPN_UPSTREAM_GUI_OWNER
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
                    // AVPN upstream nodes (point 9, §19): the session may be an upstream one this GUI
                    // started before its restart (its record names the node and the session start).
                    adoptUpstreamFromRecord(qint64(o.value(QStringLiteral("started_at_ms")).toDouble()));
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
    // AVPN upstream nodes (decision A): a stub's config comes from the signed lease, never from the
    // subscription - the acquire runs here, asynchronously, inside Connecting.
    if (isUpstreamNode(node))
        return upUpstream(sub, node);
    if (m_upOwner.active())
        applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs())); // an up() without down(): release
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
        // Contract §3: own Xray sessions get only the tunables the server sent (none = today's envelope).
        {
            const QJsonObject tun = xrayTunablesFor(/*upstreamSession=*/false);
            if (!tun.isEmpty())
                xcfg.insert(QStringLiteral("xray_tunables"), tun);
        }
        m_lastConfigReport = XrayConfigBuilder::reportSummary(sub, primary);
        m_lastConfigReport.insert(QStringLiteral("split_on"), splitOnFact);
        m_lastConfigReport.insert(QStringLiteral("ru_node"), ruNodeFact);
        m_lastConfigReport.insert(QStringLiteral("split_dns"), false);
        m_lastConfigReport.insert(QStringLiteral("dns_fwd"), false);
#if defined(Q_OS_IOS)
        // AVPN (floor 19.11, §28 on the Xray path): the same flag as AmneziaWG - the RU split inside the core, not as
        // ~10,800 system routes (ios_controller::setupXray -> XrayDirectSplit.swift). Off by default: routes, as before.
        if (avpn::TuningStore::flag(QStringLiteral("ios_userspace_split"), false))
            xcfg.insert(QStringLiteral("directSplit"), QStringLiteral("1"));
#endif
        m_lastConfigReport.insert(QStringLiteral("userspace_split"), xcfg.contains(QStringLiteral("directSplit")));
        // D2 (release 141): the session's identity goes with every start, Xray as AmneziaWG (NodeRotation.h)
        xcfg.insert(QStringLiteral("tribeSessionMetadata"), ownSessionMetadata(primary));
        m_lastUpProto = QStringLiteral("xray");
        // Свежая сессия: статистика xray-пути начинается с нуля (кумулятивы демона/NE — с подъёма).
        m_stats = TunnelStats{};
#if AVPN_UPSTREAM_GUI_OWNER
        if (m_xrayStatsTimer)
            m_xrayStatsTimer->start();
#endif
        if (!invokeConnect(xcfg, primary.nodeId, DockerContainer::Xray))
            return TunnelResult::fail(QStringLiteral("connectToVpn invoke failed"));
        return TunnelResult::success();
    }
    m_lastUpProto = QStringLiteral("awg");
#if AVPN_UPSTREAM_GUI_OWNER
    if (m_xrayStatsTimer)
        m_xrayStatsTimer->stop();
#endif

    QJsonObject cfg = AwgConfigBuilder::build(sub, primary, m_keys);
    cfg.insert(QStringLiteral("tribeSessionMetadata"), ownSessionMetadata(primary));
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
#if defined(Q_OS_IOS)
    // AVPN разделение РФ внутри расширения (CONNECT-INVARIANTS §28): ключ в КОРЕНЬ cfg ->
    // ios_controller::setupAwg. Флаг features.ios_userspace_split по умолчанию выключен: тогда
    // список идёт системными маршрутами, как у апстрима. Значение СТРОКОЙ (JSONDecoder-грабля).
    if (avpn::TuningStore::flag(QStringLiteral("ios_userspace_split"), false))
        cfg.insert(QStringLiteral("directSplit"), QStringLiteral("1"));
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
    m_lastConfigReport.insert(QStringLiteral("userspace_split"), cfg.contains(QStringLiteral("directSplit")));

    if (!invokeConnect(cfg, primary.nodeId, DockerContainer::Awg))
        return TunnelResult::fail(QStringLiteral("connectToVpn invoke failed"));
    return TunnelResult::success();
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

void VpnConnectionTunnelControl::beginNativeOp(quint64 leg)
{
#if defined(Q_OS_ANDROID)
    m_startLeg = leg; // android2 V2: the start that follows carries it (invokeConnect)
#endif
    if (!m_conn) {
        noteNativeLegSeen(leg);
        return;
    }
    QPointer<VpnConnectionTunnelControl> self(this);
    QMetaObject::invokeMethod(
        m_conn,
        [self, leg] {
            if (self)
                QMetaObject::invokeMethod(
                    self.data(), [self, leg] { if (self) self->noteNativeLegSeen(leg); }, Qt::QueuedConnection);
        },
        Qt::QueuedConnection);
}

void VpnConnectionTunnelControl::down()
{
    // AVPN upstream nodes (decision of 18.11, UpstreamLeaseWire.h::upstreamReleaseDue): the core stops at once; a
    // release this app owns (the macOS / Windows GUI owner, or a lease that never reached a running tunnel) waits
    // for the confirmed stop (upstreamTunnelDown) and goes over the direct path - never through the tunnel being
    // abandoned. Elsewhere the extension releases on its own stop.
    ++m_statsSession; // the tunnel session ends: statistics asked on it are stale
#if defined(Q_OS_IOS)
    IosController::Instance()->clearUpstreamStart(); // abort: an armed, not yet taken start is dropped
#endif
    // A seat taken for a switch (prepareUpstream) outlives the old tunnel's stop: the up() after it brings it up.
    if (m_upOwner.active() && !m_upOwner.preparing()) {
        if (m_leaseClient)
            m_leaseClient->holdReleasesForStopIfRunning(); // no native tunnel: no Disconnected will come to free a hold
        applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));
    }
    if (m_conn)
        QMetaObject::invokeMethod(m_conn, "disconnectFromVpn", Qt::QueuedConnection);
    m_stats = TunnelStats{};
#if AVPN_UPSTREAM_GUI_OWNER
    if (m_xrayStatsTimer)
        m_xrayStatsTimer->stop(); // AVPN awg31-xray-v1: сессия xray закрыта — поллинг демона не нужен
#endif
}

// ---- AVPN upstream nodes (plan provider-pool v2, lane L1) ---------------------------------------------

qint64 VpnConnectionTunnelControl::upstreamClockMs()
{
#if defined(Q_OS_MACOS) || defined(Q_OS_IOS)
    // Contract §7: keeps running while the device sleeps (same counter as mach_continuous_time).
    return qint64(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1000000ULL);
#elif defined(Q_OS_ANDROID)
    // Release C: the boot-time clock counts in suspend (Doze) - the same clock as the Xray service's
    // SystemClock.elapsedRealtime (android-ipc-contract.md §5). CLOCK_MONOTONIC would stop in suspend.
    struct timespec ts {};
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return qint64(ts.tv_sec) * 1000 + qint64(ts.tv_nsec) / 1000000;
#elif defined(Q_OS_WIN)
    // Release C: milliseconds since boot, sleep and hibernation included (QueryUnbiasedInterruptTime
    // would exclude them; QElapsedTimer's performance counter is not documented to count across sleep).
    return qint64(GetTickCount64());
#else
    // Linux: no upstream nodes (no Xray client); a monotonic reference.
    return QElapsedTimer::msecsSinceReference();
#endif
}

void VpnConnectionTunnelControl::configureUpstream(QNetworkAccessManager *nam, std::function<QString()> directBase,
                                                   const QString &pubKeyHex, std::function<QString()> token)
{
    if (m_leaseClient)
        m_leaseClient->configure(nam, std::move(directBase), pubKeyHex, std::move(token));
}

TunnelResult VpnConnectionTunnelControl::upUpstream(const Subscription &sub, const SubscriptionNode &node)
{
    if (!upstreamNodesEnabled())
        return TunnelResult::fail(QStringLiteral("upstream nodes are switched off"));
    if (!m_leaseClient || !m_leaseClient->configured())
        return TunnelResult::fail(QStringLiteral("upstream lease client not configured"));
    // splitTunnelType 0 on every platform (contract §1): the profile routes RU/direct itself;
    // appendSplitTunnelingConfig in connectToVpn reads this flag from the store (queued, after us).
    if (m_appStore)
        m_appStore->setSitesSplitTunnelingEnabled(false);
    m_upStub = node;
    m_lastUpProto = QStringLiteral("xray");
    m_stats = TunnelStats{};
#if AVPN_UPSTREAM_GUI_OWNER
    if (m_xrayStatsTimer)
        m_xrayStatsTimer->stop(); // started with the core (bringUpUpstream)
#endif
    std::optional<StandbyCandidate> standby;
    if (m_standbyPack) {
        StandbyCandidate c;
        QString why;
        if (standbyCandidateFor(*m_standbyPack, node, sub.upstreamRevision, QDateTime::currentMSecsSinceEpoch(),
                                upstreamStandbyMaxAgeSTuned(), c, &why))
            standby = c;
    }
    {
        UpstreamLeaseOwner::Options o = m_upOwner.options();
        // How long a provisional session may run before its seat is confirmed through the tunnel: the data
        // check's budget, at least one acquire round trip after the tunnel is up.
        o.provisionalConfirmBudgetMs = qMax<qint64>(xrayVerifyTimeoutMsTuned(), upstreamAcquireTimeoutMsTuned() + 2000);
        m_upOwner.setOptions(o);
    }
    m_lastConfigReport = XrayConfigBuilder::reportSummaryUpstream(node, false, meterScopeName(m_upOwner.options().scope));
    if (m_upOwner.preparedUsable(node.nodeId, upstreamClockMs())) {
        // Seat first: the seat was acquired (and the profile checked) while the old tunnel still worked.
        m_lastConfigReport.insert(QStringLiteral("stage"), QStringLiteral("prepared"));
        qInfo() << "avpn upstream: bringing up the seat taken before the switch for" << node.nodeId;
        applyUpstreamEvents(m_upOwner.bringUpPrepared(upstreamClockMs()));
        return TunnelResult::success();
    }
    m_lastConfigReport.insert(QStringLiteral("stage"), QStringLiteral("acquiring"));
    m_lastConfigReport.insert(QStringLiteral("standby_usable"), standby.has_value());
    qInfo() << "avpn upstream: acquiring a seat for" << node.nodeId << "standby" << standby.has_value();
    applyUpstreamEvents(m_upOwner.begin(node, sub.upstreamRevision, standby, upstreamClockMs(),
                                        QDateTime::currentMSecsSinceEpoch()));
    return TunnelResult::success();
}

#if defined(Q_OS_IOS)
// The bridge's view of contract §1 upstream_lease (IosNativePolicy.h::UpstreamLeaseEnvelope).
static avpn_ios::UpstreamLeaseEnvelope iosLeaseEnvelope(const QJsonObject &l)
{
    avpn_ios::UpstreamLeaseEnvelope e;
    e.leaseId = l.value(QStringLiteral("lease_id")).toString().toStdString();
    e.renewToken = l.value(QStringLiteral("renew_token")).toString().toStdString();
    e.apiBase = l.value(QStringLiteral("api_base")).toString().toStdString();
    e.renewAfterS = l.value(QStringLiteral("renew_after_s")).toInteger();
    e.ttlS = l.value(QStringLiteral("ttl_s")).toInteger();
    e.expiresInMs = l.value(QStringLiteral("expires_in_ms")).toInteger();
    e.seq = l.value(QStringLiteral("seq")).toInteger();
    e.epoch = l.value(QStringLiteral("epoch")).toInteger();
    e.revision = l.value(QStringLiteral("revision")).toInteger();
    e.meterScope = l.value(QStringLiteral("meter_scope")).toString().toStdString();
    for (const QJsonValue &t : l.value(QStringLiteral("meter_tags")).toArray())
        e.meterTags.push_back(t.toString().toStdString());
    return e;
}
#endif

void VpnConnectionTunnelControl::applyUpstreamEvents(const QVector<UpstreamOwnerEvent> &events)
{
    for (const UpstreamOwnerEvent &e : events) {
        switch (e.kind) {
        case UpstreamOwnerEventKind::BringUp:
            bringUpUpstream(e);
            break;
        case UpstreamOwnerEventKind::StartFailed:
            failUpstreamStart(e.code, e.detail);
            break;
        case UpstreamOwnerEventKind::Leave:
            qWarning() << "avpn upstream: leaving" << m_upOwner.nodeId() << "lease" << e.code << e.detail;
            emit upstreamLeaveRequested(e.code, e.detail);
            break;
        case UpstreamOwnerEventKind::LeaseConfirmed:
            qInfo() << "avpn upstream: seat confirmed through the tunnel on" << m_upOwner.nodeId();
            m_lastConfigReport.insert(QStringLiteral("stage"), QStringLiteral("confirmed"));
            break;
        case UpstreamOwnerEventKind::HandOver:
#if defined(Q_OS_IOS)
            // Contract §2: the provisional session's seat goes to the extension (upstream_lease_set).
            if (!IosController::Instance()->sendUpstreamLeaseSet(iosLeaseEnvelope(e.lease)))
                qWarning() << "avpn upstream: lease hand-over not sent (no live tunnel) - the seat lapses at TTL";
#elif defined(Q_OS_ANDROID)
            // Release C (decision A-1): the same message to the Xray service process, which renews from now
            // on (android-ipc-contract.md §2); its reply comes back as AndroidController::upstreamLeaseEvent.
            if (!AndroidController::instance()->sendUpstreamLeaseSet(upstreamLeaseSetMessage(e.lease)))
                qWarning() << "avpn upstream: lease hand-over not sent (no bound service) - the seat lapses at TTL";
#endif
            emit upstreamLeaseHandover(e.lease);
            break;
        case UpstreamOwnerEventKind::Persist:
#if AVPN_UPSTREAM_GUI_OWNER || defined(Q_OS_IOS) // iOS: the record of the handed-over session (keepRecord, C3 of 24.11)
            QSettings().setValue(QLatin1String(kUpstreamLeaseRecordKey), e.record.toJson());
#endif
            break;
        case UpstreamOwnerEventKind::ClearRecord:
#if AVPN_UPSTREAM_GUI_OWNER || defined(Q_OS_IOS)
            QSettings().remove(QLatin1String(kUpstreamLeaseRecordKey));
#endif
            break;
        case UpstreamOwnerEventKind::RevisionChanged:
            emit upstreamRevisionSeen(e.revision);
            break;
        case UpstreamOwnerEventKind::ConfigChanged:
            qInfo() << "avpn upstream: the profile of" << m_upOwner.nodeId()
                    << "changed on the server - applies at the next connect";
            break;
        case UpstreamOwnerEventKind::Prepared: {
            // The connect's own profile rule now, while the old tunnel works: a refused profile never costs it.
            const QString nodeId = m_upOwner.nodeId();
            const SanitizedProfile chk = upstreamProfileCheck(
                e.config, e.configSha256, m_upStub.upstream ? m_upStub.upstream->protocols : QStringList());
            if (!chk.ok()) {
                qWarning() << "avpn upstream: profile of" << nodeId << "refused before the switch:" << chk.code()
                           << chk.detail;
                applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs())); // the seat goes back
                emit upstreamPrepared(nodeId, e.prepareId, false, QStringLiteral("profile_") + chk.code());
                break;
            }
            qInfo() << "avpn upstream: seat for" << nodeId << "held before the switch";
            emit upstreamPrepared(nodeId, e.prepareId, true, QString());
            break;
        }
        case UpstreamOwnerEventKind::PrepareFailed:
            qWarning() << "avpn upstream: no seat for" << m_upStub.nodeId << "before the switch, code" << e.code;
            emit upstreamPrepared(m_upStub.nodeId, e.prepareId, false,
                                  e.detail.isEmpty() ? e.code : e.code + QLatin1Char('/') + e.detail);
            break;
        case UpstreamOwnerEventKind::ReleaseAfterStop:
            // The seat this process acquired, held by the tunnel owner: given back again after the confirmed stop
            // (the owner's own release with the final report goes first). Without a report (meter seq 0).
            if (m_leaseClient) {
                m_leaseClient->holdReleasesForStopIfRunning(); // a stop that already happened is not waited for
                m_leaseClient->release(e.requestId, e.leaseId, UpstreamMeter{}, e.route); // the owner's own request id
            }
            break;
        }
    }
    noteSeatDebts(); // every step of the owner passes here: what it keeps for a proof of the direct route is looked at once
}

// What the ledger keeps for a route that works (an unsent release, a seat owed by nonce) on a device where nothing runs: no
// start, no tunnel - so no answer of ours will ever prove a route. The owner of the direct route's fact (ConfigService) is asked
// for the proof (upstreamRouteProofOwed -> its one spaced ask); its directRouteProved() comes back as upstreamDirectRouteProved().
// No timer here and nothing that decides: the ask is repeated by ConfigService while upstreamProofOwed() stays true, i.e. until the
// entries are delivered, given up, or their lease's lifetime has passed. The journal says when a seat becomes owed by nonce and when
// that is over (the count last written is kept for these two lines only).
void VpnConnectionTunnelControl::noteSeatDebts()
{
    const int debts = m_upOwner.seatDebts();
    if (debts != m_seatDebtsTold) {
        if (debts > m_seatDebtsTold)
            qInfo() << "avpn upstream: a lease answer was lost - the seat of that start is owed back (asked for by its nonce when the API answers), owed="
                    << debts;
        else
            qInfo() << "avpn upstream: a seat owed after a lost lease answer is settled, owed=" << debts;
        m_seatDebtsTold = debts;
    }
    if (upstreamProofOwed())
        emit upstreamRouteProofOwed();
}

void VpnConnectionTunnelControl::bringUpUpstream(const UpstreamOwnerEvent &e)
{
    if (m_leaseClient)
        m_leaseClient->tunnelStarted(); // the native start is asked for: a stop is from now something a release waits for
    // The bind of the local inbound with random session credentials (XrayProfileSanitizer; the runners
    // keep non-empty credentials and re-pick the port). Never logged.
    const auto randomHex = []() {
        QByteArray b(16, Qt::Uninitialized);
        QRandomGenerator::system()->generate(reinterpret_cast<quint32 *>(b.data()),
                                             reinterpret_cast<quint32 *>(b.data() + b.size()));
        return QString::fromLatin1(b.toHex());
    };
    LocalInboundBind bind;
    bind.port = 10808;
    bind.user = randomHex();
    bind.password = randomHex();
    // The one profile rule shared with the Scanner's probe (XrayProfileSanitizer.h::upstreamProfileOutboundAllowlist):
    // the stub's proto: tags list only the proxy outbounds - the helper outbounds stay allowed.
    const ProfileSanitizerOptions opt =
        upstreamProfileOptions(m_upStub.upstream ? m_upStub.upstream->protocols : QStringList());
    const SanitizedProfile sp = XrayProfileSanitizer::sanitize(e.config, e.configSha256, bind, opt);
    if (!sp.ok()) {
        qWarning() << "avpn upstream: profile of" << m_upStub.nodeId << "refused:" << sp.code() << sp.detail;
        const QString code = QStringLiteral("profile_") + sp.code();
        applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs())); // a granted seat is given back
        failUpstreamStart(code);
        return;
    }
    XrayConfigBuilder::UpstreamEnvelopeInput in;
    in.nodeId = m_upStub.nodeId;
    in.profileId = m_upStub.upstream ? m_upStub.upstream->profileId : m_upOwner.profileId();
    in.configSha256 = e.configSha256;
    in.coreConfig = sp.coreConfig;
    in.dns = m_upStub.dns;
    in.lease = e.provisional ? QJsonObject() : e.lease;
    in.tunables = xrayTunablesFor(/*upstreamSession=*/true);
    QJsonObject xcfg = XrayConfigBuilder::buildUpstream(in);
    if (xcfg.isEmpty()) {
        applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));
        failUpstreamStart(QStringLiteral("envelope"));
        return;
    }
#if defined(Q_OS_IOS)
    // C3 of 24.11: the start's order in the session's identity - the extension keeps it in its provider configuration and
    // returns it with every status reply, so a relaunched app knows which start runs (adoptUpstreamSession). Not a secret.
    {
        QJsonObject meta = xcfg.value(QStringLiteral("tribeSessionMetadata")).toObject();
        meta.insert(QLatin1String(kUpstreamSessionOrderMetaKey), double(m_upOwner.tunnelOrder())); // the tunnel's identity (round 44 F3)
        xcfg.insert(QStringLiteral("tribeSessionMetadata"), meta);
    }
#endif
    m_lastConfigReport = XrayConfigBuilder::reportSummaryUpstream(m_upStub, e.provisional,
                                                                  meterScopeName(m_upOwner.options().scope));
    m_lastConfigReport.insert(QStringLiteral("stage"), e.provisional ? QStringLiteral("provisional")
                                                                       : QStringLiteral("granted"));
    m_lastConfigReport.insert(QStringLiteral("split_on"), false);
    m_lastConfigReport.insert(QStringLiteral("split_dns"), false);
    m_lastConfigReport.insert(QStringLiteral("dns_fwd"), false);
    m_lastUpProto = QStringLiteral("xray");
    m_stats = TunnelStats{};
#if AVPN_UPSTREAM_GUI_OWNER
    if (m_xrayStatsTimer)
        m_xrayStatsTimer->start();
#endif
#if defined(Q_OS_IOS)
    // The bridge arms the NEXT connectVpn for this node (it matches tribeSessionMetadata.node_id) and
    // writes tribeSessionMetadata / upstream_lease into the extension's provider configuration.
    {
        avpn_ios::UpstreamStartEnvelope start;
        start.nodeId = m_upStub.nodeId.toStdString();
        start.profileId = in.profileId.toStdString();
        start.configSha256 = in.configSha256.toStdString();
        start.hasLease = !e.provisional && !e.lease.isEmpty();
        if (start.hasLease)
            start.lease = iosLeaseEnvelope(e.lease);
        if (!IosController::Instance()->setUpstreamStart(start)) {
            applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));
            failUpstreamStart(QStringLiteral("bridge_refused"));
            return;
        }
    }
#endif
    qInfo() << "avpn upstream: starting the core for" << m_upStub.nodeId << (e.provisional ? "(provisional)" : "");
    if (!invokeConnect(xcfg, m_upStub.nodeId, DockerContainer::Xray)) {
        applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));
        failUpstreamStart(QStringLiteral("invoke"));
    }
}

void VpnConnectionTunnelControl::failUpstreamStart(const QString &codeIn, const QString &detail)
{
    const QString code = detail.isEmpty() ? codeIn : codeIn + QLatin1Char('/') + detail;
    const QString nodeId = m_upStub.nodeId;
    qWarning() << "avpn upstream: start failed on" << nodeId << "code" << code;
    m_lastConfigReport.insert(QStringLiteral("stage"), QStringLiteral("failed"));
    m_lastConfigReport.insert(QStringLiteral("start_failure"), code);
#if defined(Q_OS_IOS)
    IosController::Instance()->clearUpstreamStart(); // an armed start never reaches another connect
#endif
    // The engine first (the restart must not pick this node again), then the real tunnel Error through
    // the existing path (queued into VpnConnection's thread; it comes back as connectionStateChanged).
    if (m_upStartFailureSink && !nodeId.isEmpty())
        m_upStartFailureSink(nodeId, code);
    if (m_conn)
        QMetaObject::invokeMethod(m_conn, "setConnectionState", Qt::QueuedConnection,
                                  Q_ARG(Vpn::ConnectionState, Vpn::ConnectionState::Error));
}

void VpnConnectionTunnelControl::adoptUpstreamFromRecord(qint64 daemonStartedAtWallMs)
{
#if AVPN_UPSTREAM_GUI_OWNER
    if (!upstreamNodesEnabled() || !m_leaseClient || !m_leaseClient->configured() || m_upOwner.active())
        return;
    QSettings st;
    const UpstreamLeaseRecord rec =
        UpstreamLeaseRecord::fromJson(st.value(QLatin1String(kUpstreamLeaseRecordKey)).toByteArray());
    if (rec.nodeId.isEmpty())
        return;
    const qint64 nowWall = QDateTime::currentMSecsSinceEpoch();
    if (!upstreamRecordAdoptable(rec, nowWall) || !upstreamRecordMatchesSession(rec, daemonStartedAtWallMs)) {
        st.remove(QLatin1String(kUpstreamLeaseRecordKey)); // another session: the record is stale
        return;
    }
    m_upStub = SubscriptionNode{};
    m_upStub.nodeId = rec.nodeId;
    m_lastUpProto = QStringLiteral("xray");
    qInfo() << "avpn upstream: adopting the live session of" << rec.nodeId;
    applyUpstreamEvents(m_upOwner.adopt(rec, upstreamClockMs(), nowWall));
    emit upstreamSessionAdopted(rec.nodeId);
#else
    Q_UNUSED(daemonStartedAtWallMs)
#endif
}

void VpnConnectionTunnelControl::runAfterUpstreamRelease(std::function<void()> fn)
{
    if (fn)
        fn(); // decision of 18.11: nothing waits for a release any more - it follows the confirmed stop
}

void VpnConnectionTunnelControl::upstreamTunnelDown(bool endsSession)
{
    // A Disconnected nobody asked for ends the session that was running on that tunnel at once (the ledger's
    // tunnelLost): its release goes out now, not at a Disconnected that has already happened (review F4 of 19.11).
    // A stale event of an older tunnel (endsSession false) only frees what was held for it.
    if (endsSession && m_leaseClient) {
        m_leaseClient->tunnelStopped(); // the stop is confirmed: the end below must not hold for another one
        applyUpstreamEvents(m_upOwner.tunnelLost(upstreamClockMs()));
    }
    if (m_leaseClient)
        m_leaseClient->tunnelStopped(); // the held releases go now, over the direct path
}

void VpnConnectionTunnelControl::retryUpstreamAdoption()
{
#if AVPN_UPSTREAM_GUI_OWNER
    if (!isXrayProto(m_lastUpProto) || m_upOwner.active())
        return;
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
                    if (o.value(QStringLiteral("running")).toBool())
                        adoptUpstreamFromRecord(qint64(o.value(QStringLiteral("started_at_ms")).toDouble()));
                });
    });
#endif
}

void VpnConnectionTunnelControl::adoptUpstreamSession()
{
#if defined(Q_OS_IOS)
    // C3 of the device round 24.11 (iPhone Air): connect to a provider row, force-quit, relaunch - the live tunnel was adopted,
    // and the Stop sent no release (no owner of the seat after the relaunch). The facade calls this once the engine adopted the
    // live tunnel (AvpnEngineQml::tryAdoptObservedTunnel, and identifyAdoptedSession when the identity came late).
    if (!m_leaseClient || !m_leaseClient->configured() || m_upOwner.active())
        return;
    const QByteArray raw = QSettings().value(QLatin1String(kUpstreamLeaseRecordKey)).toByteArray();
    if (raw.isEmpty())
        return;
    const QJsonObject meta = QJsonObject::fromVariantMap(IosController::Instance()->sessionMetadata());
    const QString liveNode = meta.value(QStringLiteral("node_id")).toString();
    if (!liveNode.startsWith(QLatin1String("up:")))
        return; // not a provider session: nothing of the record applies to it
    const UpstreamLeaseRecord rec = UpstreamLeaseRecord::fromJson(raw);
    if (!upstreamHandedOverRecordMatches(rec, liveNode, upstreamSessionOrderOf(meta), QDateTime::currentMSecsSinceEpoch())) {
        // Another start, a session started before this rule, or a broken record: not this app's seat to give back. The record
        // stays - a later live session can never carry its order, and the next start replaces it.
        qInfo() << "avpn upstream: the adopted session of" << liveNode << "is not the one the seat record names - its seat stays the extension's";
        return;
    }
    m_upStub = SubscriptionNode{};
    m_upStub.nodeId = rec.nodeId;
    applyUpstreamEvents(m_upOwner.adoptHandedOver(rec, upstreamClockMs()));
    if (m_upOwner.active())
        qInfo() << "avpn upstream: the seat of the adopted session on" << rec.nodeId
                << "is this app's again - renewed by the extension, released after the stop";
#endif
}

// The two KNOWN LIMITS this guard had (rounds 10 R1 and 17 R1: after an iOS relaunch the app had no owner of the extension's provider
// session, so picking the same or another provider ran this seat-first prepare beside it - the server ended the old lease as replaced
// and, with the answer lost, the old tunnel could stay "connected" without its core) are closed by the iOS adoption (C3 of 24.11,
// adoptUpstreamSession): a relaunched app that adopted THE session its record names owns its seat again, m_upOwner.active() is true,
// and the pick takes the live-session path (DebugSnapshot.h::upstreamSeatFirst: stop, the old seat released after the confirmed stop,
// then the new start). What stays as before: a live provider session the record does not name (started by a build without the
// record, or the record is gone) - not adopted, so these two cases still apply to it.
quint64 VpnConnectionTunnelControl::prepareUpstream(const Subscription &sub, const SubscriptionNode &node)
{
    if (!upstreamNodesEnabled() || !m_leaseClient || !m_leaseClient->configured() || m_upOwner.active()
        || !isUpstreamNode(node) || !node.upstream)
        return 0;
    m_upStub = node; // no provider session is live (checked above): the stub of the coming session
    qInfo() << "avpn upstream: taking a seat for" << node.nodeId << "before the switch";
    const QVector<UpstreamOwnerEvent> ev = m_upOwner.prepare(node, sub.upstreamRevision, upstreamClockMs(),
                                                             QDateTime::currentMSecsSinceEpoch());
    const quint64 id = m_upOwner.prepareSerial(); // read before the events: their answer carries this id
    applyUpstreamEvents(ev);
    return id;
}

void VpnConnectionTunnelControl::startRefused()
{
    // Android: the person refused the VPN permission - the seat taken for this start goes back now (review F9).
    applyUpstreamEvents(m_upOwner.abortStart(upstreamClockMs()));
}

void VpnConnectionTunnelControl::cancelUpstreamPrepare()
{
    if (!m_upOwner.preparing())
        return;
    qInfo() << "avpn upstream: the seat taken for" << m_upOwner.nodeId() << "is not needed any more";
    applyUpstreamEvents(m_upOwner.disconnect(upstreamClockMs()));
}

void VpnConnectionTunnelControl::upstreamTunnelUp()
{
    if (m_upOwner.active())
        applyUpstreamEvents(m_upOwner.tunnelUp(upstreamClockMs()));
}

void VpnConnectionTunnelControl::upstreamTick()
{
    if (!m_upOwner.active())
        return;
    const qint64 now = upstreamClockMs();
    const qint64 wake = m_upOwner.wakeAtMs();
    if (wake < 0 || now < wake)
        return; // nothing due: no request, no allocation
    applyUpstreamEvents(m_upOwner.tick(now));
}

} // namespace avpn
