#include "AvpnEngineQml.h"
#include "ScanBudget.h" // attachPathProber: the Scanner's price of a probe
#include "TransportPick.h" // the Doctor's alternatives: exit RTT order (display/measurement only)

#ifdef Q_OS_ANDROID
#include "platforms/android/android_controller.h" // AVPN: адопт снапшота статуса (рассинхрон после фона)
#include "platforms/android/avpn_selfupdate_android.h" // AVPN (2026-11-16): site APK self-update
#endif

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/utils/errorStrings.h" // AVPN: errorString(ErrorCode) → текст для error()
#include "vpnConnection.h"
#include "Enrollment.h" // AVPN: authToken() → Enrollment::loadToken()
#include "SubscriptionParser.h" // AVPN (оплата): refreshSubscription() — device-часы для шапки/CTA
#include "SubscriptionRequest.h"
#include "Identity.h"   // AVPN: localDeviceId() → installation-UUID (раздел «Устройства» всегда показывает ID)
#include "IdentityAnchor.h" // AVPN (анти-фрод): Keychain-якорь identity — restore на старте (переустановка)
#include "DeviceFingerprint.h" // AVPN (anti-farm): якорь железа в async-enroll (паритет с Enrollment::enroll)
#include "DeviceModel.h" // AVPN: нативные имя/ОС текущего устройства (раздел «Устройства»)
#include "QualityProbe.h" // AVPN (реальные палочки): app-layer RTT-проба через туннель
#include "ServiceProbe.h" // AVPN (чипы доступности): проба Telegram/YouTube через туннель
#include "ServiceProbeTargets.h" // AVPN (чипы): вшитые цели + мерж серверного probe_targets (не замещать!)
#include "ConnectTunables.h" // AVPN: клампованные пороги коннекта + связка watchdog>handshake (ревью 2026-07-11)
#include "NodeRanking.h"  // AVPN (выбор по скорости): RTT→палочки + сортировка «быстрые внизу»
#include "NodeRotation.h" // AVPN (Task 10 финал): isSupportedProto — xray-ноды мимо свипа/выбора
#include "RttProbeIcmp.h" // AVPN (выбор по скорости): прямой ICMP-замер RTT до нод off-tunnel
#include "BenchAnalysis.h" // AVPN (панель администратора): вердикты + A/B-сравнение замеров
#include "Ipv6Presence.h" // AVPN (IPv6-волна): есть ли у сети глобальный v6 мимо туннеля (Доктор)
#include "TunnelWatchPlan.h" // AVPN (iOS data watch, 141): plan file for the packet tunnel extension (pure)
#ifdef Q_OS_IOS
#include "platforms/ios/AvpnDiagnostics.h" // AVPN backend-first (2026-07-10): crash-diag следует за edge-walk базой
#include "platforms/ios/AvpnBackgroundGuard.h" // AVPN (разбор 2026-09-23): фоновое время на перезапуск туннеля
#include "platforms/ios/TribeJournalIos.h" // AVPN (журнал тестирования): фоновое время на досылку журнала
#endif
#include "BenchRunner.h"  // AVPN (панель администратора): in-app бенч соединения
#include "BootstrapRetry.h" // AVPN: политика ретраев тихого bootstrap (бэкофф → вечный медленный цикл)
#include "ConfigStore.h" // AVPN remote-config (T6): compareVersions/UpdateVerdict + APP_VERSION (version.h)
#include "BypassListService.h" // AVPN server-driven АнтиВПН (Task 10): серверные bypass-списки + BypassListStore
#include "WhitelistDetector.h" // AVPN (белые списки): детект РКН-режима «работает только whitelist»
#include "CrashGuard.h" // AVPN (CR-1): свой краш-репортинг (sentinel+сигналы) -> type:"crash" в /v1/bench/report
#include "TribeNetInfo.h" // AVPN (Доктор D-3): поколение сотовой/metered/roaming для стадии network
#include "UpstreamLeaseClient.h" // AVPN upstream nodes: standby pack fetch/store, data probe
#include "UplinkMonitor.h" // AVPN (волна-3): физический аплинк без учёта собственного utun
#include "RuSplitSentinel.h" // AVPN (Доктор D-3 п.26): фоновый дозор RU-сайтов при вкл. сплите
#include "TuningStore.h" // AVPN backend-first (T8): потокобезопасный снапшот numbers/features/lists
#include "AnnounceGate.h" // AVPN (announce-quiet): тихое окно попапов объявлений после онбординга
#include "SubscriptionGate.h" // AVPN (sub-grace): «подписка истекла и грейс прошёл» → управляемый stop
#include "ReportDelivery.h"
#include "TribeDiagReport.h" // AVPN (diag-report, Task 4 bff-3): единый диагностический отчёт для чата поддержки
#include "logger.h" // AVPN (diag-report): Logger::userLogsFilePath() — хвост лога приложения в отчёт
#include "TribeScanner.h"     // AVPN Scanner (lane L6b): the coordinator, IScanEngine
#include "../utils/constants/protocolConstants.h" // AVPN Scanner: protocols::awg::defaultMtu (awg_mini as the live tunnel)
#include "TribeSupportChat.h" // AVPN Scanner: the support report queue (reserve / submit / status)
#include "XrayConfigBuilder.h" // AVPN Scanner: an own path's probe config (the exact tunnel config)
#include "UpstreamNode.h"     // AVPN Scanner: upstream display names, isUpstreamNode
#ifdef Q_OS_IOS
#include "IosScanHost.h"      // AVPN Scanner: the app process's path monitor element (iosnetworkwatcher is not in the app)
#endif
#ifdef Q_OS_ANDROID
#include "AndroidScanHost.h"  // AVPN Scanner (lane A3): the app process's network element (NetworkState.kt ScanAppNetwork)
#endif

#include <algorithm> // AVPN (панель администратора): сортировка строк свипа
#include "AvpnIntentBridge.h" // AVPN (Task E): консьюмер «намерений» App Intent авто-паузы → pause/resume
#include "AvpnShareBridge.h" // AVPN: нативный share sheet (рефералка/перенос)
#include "core/utils/qrCodeUtils.h" // AVPN: QR для ссылки переноса (makeQrCode)
#include "AvpnPushBridge.h" // AVPN (Task 9): device token → /v1/devices/push-token; markAllRead → /v1/notifications/read
#include "ru_prefixes.h"          // AVPN RU-direct: весь рунет CIDR для split-tunnel (applyRuBypassSplit)
#include "CidrCarve.h"            // AVPN RU-direct: carve-out IP API из сева (control plane всегда в туннеле)
#include "EdgeWalk.h"             // AVPN (разбор 2026-09-23): хосты всех edge — в carve-out заранее
#include "BypassSeedStamp.h"      // AVPN: стамп входов сева АнтиВПН — скип пересева 10k CIDR при неизменных входах
#include <QHostInfo>              // AVPN RU-direct: async-резолв хоста API для carve-out
#include <QPointer>               // AVPN (разбор 2026-09-23): колбэк истечения фонового времени iOS
#include "LegalDocs.h"            // AVPN in-app Legal: URL/кэш/валидация Privacy/Terms
#include <QDir>                   // AVPN in-app Legal: каталог кэша
#include <QImage>                 // AVPN: QR → PNG для share-листа переноса (shareTextWithQr)
#include <QFile>                  // AVPN in-app Legal: чтение кэша
#include <QLocalSocket>           // AVPN (BUG-6): стартовая проба статуса root-демона (macOS)
#include <QSaveFile>              // AVPN in-app Legal: атомарная запись кэша
#include <QStandardPaths>         // AVPN in-app Legal: AppDataLocation
#ifdef Q_OS_IOS
#include <chrono>   // AVPN: предохранитель watchdog при выходе (см. конструктор)
#include <thread>
#include <unistd.h> // ::_exit
#endif
#include "core/utils/routeModes.h" // AVPN RU-direct: amnezia::RouteMode::VpnAllExceptSites
#include <QMap>                    // AVPN RU-direct: bulk addVpnSites

#include <QCoreApplication> // AVPN (Task 9): applicationVersion() → app_version в push-token
#include <QGuiApplication>
#include <QWindow>            // волна-2: uiForeground()  // AVPN (store-flow E): applicationStateChanged → foreground-рефреш подписки
#include <QDateTime>
#include <QLocale>
#include <QJsonDocument> // AVPN (панель администратора): сериализация результата бенча

#include <QNetworkInformation> // AVPN (авто-A/B): тип сети (Wi-Fi/сотовая) в extra{} бенча
#include <QNetworkInterface>   // AVPN (IPv6-волна): срез адресов для detectLanIpv6()
#include <QSysInfo>      // AVPN (панель администратора): platform в extra{} бенча
#include <QTimeZone>     // AVPN (панель администратора): tz в extra{} — физлокация vs egress
#include "ui/controllers/systemController.h" // AVPN (панель администратора): saveReportFile → файл/шэр отчёта
#include <QThread>   // AVPN Scanner (S2, build 140): loopLevel() - the app is past exec() (scanCancelPendingConnect)
#include <QSettings> // AVPN (Task 7): чтение тумблера AvpnSettings/autoPauseRu (общий стор с QML Settings)
#include <QVariantList>
#include <QScopedValueRollback> // AVPN (краш-фикс): RAII-флаг m_inSyncNetCall вокруг вложенного QEventLoop
// AVPN (Devices+Account): синхронные REST-вызовы к control plane, как fetchSubscription.
#include "NetAwait.h" // AVPN: awaitReply() — ожидание с таймаутом (анти-фриз GUI)

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
// AVPN (P-ANN, macOS): регистрация бейджа дока (platforms/macos/AvpnDockBadge.mm).
extern "C" void AvpnDockBadge_install();
#endif
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QRegularExpression> // AVPN (журнал тестирования): путь запроса без идентификаторов
#include <QNetworkRequest>
#include <QUrl>
#include <QUrlQuery> // AVPN (P-ANN): query-параметры GET /v1/announcements
#include <QCryptographicHash> // plan v3 step 5: sha256 of the /v1/whoami body
#include <QRandomGenerator>   // plan v3 step 5: whoami nonce
#include <memory>             // plan v3 step 5: per-request whoami accumulator
#if defined(Q_OS_IOS) || defined(MACOS_NE)
#include "platforms/ios/ios_controller.h"
#include "platforms/ios/IosNativePolicy.h" // AVPN (ревью CL-A r2): потолок диалога «Разрешить VPN»
#endif
#ifdef Q_OS_IOS
#include "platforms/ios/AvpnIntentController.h"
#endif

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
#include "MacServiceInstaller.h" // AVPN (macOS desktop): авто-установка root-демона из вшитого pkg (ноль терминала)
#include <QThread>
#include "core/utils/ipcClient.h" // AVPN (wake-реконнект): подписка на wakeup/networkChanged реплики демона

#endif

namespace avpn {

// Path engine (design 2026-11-17): the evidence ledger of the attempt owner (PathLedger.h JSON).
static constexpr char kPathLedgerSettingsKey[] = "avpn/pathLedger";

// Ключ платформы для карт версий (определение — ниже, рядом с self-update).
static QString avpnPlatformKey();
static QString reportOutboxDir();


// AVPN awg31-xray-v1: маппер технических ошибок движка (no_transport/unsupported_proto) в человеческий
// текст — определён рядом с humanPinError ниже по файлу, нужен раньше (guardedStart).
static QString humanEngineError(const QString &technical);

// AVPN (CR-1): tee лог-строк в кольцо CrashGuard поверх текущего message-handler (chain —
// апстрим-логгер работает как раньше). Ставится один раз из конструктора движка.
namespace {
QtMessageHandler g_crashPrevHandler = nullptr;
void crashLogTeeHandler(QtMsgType t, const QMessageLogContext &c, const QString &m)
{
    CrashGuard::instance().appendLogLine(m);
    if (g_crashPrevHandler)
        g_crashPrevHandler(t, c, m);
}
void installCrashLogTee()
{
    static bool done = false;
    if (done) return;
    done = true;
    g_crashPrevHandler = qInstallMessageHandler(crashLogTeeHandler);
}
// The tunnel state as the pure decisions see it (DebugSnapshot.h::ObservedTunnel) - the one mapping
// for the teardown latch and the API-transition rule (audit of 137: there were two copies).
ObservedTunnel observedTunnelOf(Vpn::ConnectionState st)
{
    return st == Vpn::Connected ? ObservedTunnel::Connected
         : st == Vpn::Disconnected ? ObservedTunnel::Disconnected
         : st == Vpn::Error ? ObservedTunnel::Error
         : st == Vpn::Unknown ? ObservedTunnel::Unknown : ObservedTunnel::Transitional;
}
} // namespace

// ── AVPN Scanner (lane L6b; CONNECT-INVARIANTS §32) ────────────────────────────────────────────────────────

// The platform probe host behind the client switch: the real host (IosScanHost / DaemonScanHost, made by the
// factory of coreController.cpp) is created only once features.scanner is on - before that nothing of the
// Scanner runs (no path monitor, no message to the tunnel extension or the service). Off again: the host
// stays (it may still drain a scan), but reads Unavailable and relays nothing new; stopAll() always reaches
// it. A pure relay otherwise (IScanHost.h obligations are the inner host's).
class GatedScanHost final : public IScanHost
{
public:
    void setFactory(const ScanHostCaps &caps, std::function<IScanHost *()> make)
    {
        m_caps = caps;
        m_make = std::move(make);
        if (m_enabled && !m_inner) {
            ensure();
            if (m_inner && onAvailabilityChanged)
                onAvailabilityChanged();
        }
    }
    void setEnabled(bool on)
    {
        if (on == m_enabled)
            return;
        m_enabled = on;
        if (on)
            ensure();
        if (onAvailabilityChanged)
            onAvailabilityChanged();
    }
    bool hasInner() const { return bool(m_inner); }
    // Ask the coordinator to look at the host again (the service was just installed / started).
    void poke()
    {
        if (m_enabled && onAvailabilityChanged)
            onAvailabilityChanged();
    }

    ScanHostCaps knownCaps() const override { return m_inner ? m_inner->knownCaps() : m_caps; }
    ScanHostAvailability availability() const override
    {
        return (m_enabled && m_inner) ? m_inner->availability() : ScanHostAvailability::Unavailable;
    }
    // The inner host's code; no host on this platform (Android until lane A3, the macOS NE build) or the
    // switch off = "no_host" (the coordinator reads every unknown code as NoScan service_off).
    QString unavailableReason() const override
    {
        return (m_enabled && m_inner) ? m_inner->unavailableReason() : QStringLiteral("no_host");
    }
    void sendMessage(const QByteArray &request, ReplyFn reply) override
    {
        if (m_enabled && m_inner) {
            m_inner->sendMessage(request, std::move(reply));
            return;
        }
        // No host: "no answer", exactly once and never from inside sendMessage (IScanHost.h point 2).
        QTimer::singleShot(0, &m_context, [reply]() {
            if (reply)
                reply(QByteArray());
        });
    }
    bool generation(ScanNetSource &out) const override { return m_enabled && m_inner && m_inner->generation(out); }
    void stopAll() override
    {
        if (m_inner)
            m_inner->stopAll();
    }

private:
    void ensure()
    {
        if (m_inner || !m_make)
            return;
        m_inner.reset(m_make());
        if (!m_inner)
            return;
        m_inner->onAvailabilityChanged = [this]() {
            if (m_enabled && onAvailabilityChanged)
                onAvailabilityChanged();
        };
        m_inner->onGenerationChanged = [this]() {
            if (m_enabled && onGenerationChanged)
                onGenerationChanged();
        };
    }

    ScanHostCaps m_caps;
    std::function<IScanHost *()> m_make;
    bool m_enabled = false;
    QObject m_context;
    std::unique_ptr<IScanHost> m_inner; // last: destroyed first
};

// IScanEngine (TribeScanner.h) over this engine: the live status, the network, the manifest input, the own
// probe configs - and the only three tunnel paths, forwarded to the engine's own guarded entries.
class ScanEngineAdapter final : public IScanEngine
{
public:
    explicit ScanEngineAdapter(AvpnEngineQml *e) : m_e(e) {}

    ScanCurrent current() const override;
    ScanNetFacts network() const override;
    void fillManifestInput(ScanManifestInput &in) const override;
    QString ownProbeConfig(const ScanCandidate &c) const override;
    QString liveProbeBase(const ScanCurrent &c) const override;
    bool reportQueueFull() const override { return m_e->m_support && m_e->m_support->reportsFull(); }
    QString uiLanguage() const override { return m_e->appLang(); }
    bool awgProbeInput(const QString &nodeId, ScanAwgNodeInput &out) const override;
    QStringList knownHostIps(const QString &host) const override
    {
        return knownIpsForHost(m_e->m_apiHostIpsByHost, host);
    }
    QStringList upstreamProtocolTags(const QString &nodeId) const override
    {
        const avpn::SubscriptionNode *n = m_e->m_engine.nodeById(nodeId);
        return (n && n->upstream) ? n->upstream->protocols : QStringList();
    }
    void userConnectForScan() override { m_e->scanUserConnect(); }
    void cancelPendingConnect() override { m_e->scanCancelPendingConnect(); }
    void connectRow(const QString &nodeId, const QStringList &attemptOrder, qint64 hintTtlMs, bool userOrigin,
                    bool forceConnect) override
    {
        m_e->connectToNode(nodeId, attemptOrder, hintTtlMs, userOrigin, forceConnect);
    }
    void startReportCheck(const QString &reportId, const QJsonObject &report, bool withConnection) override
    {
        m_e->scanStartReportCheck(reportId, report, withConnection);
    }

    // The display name the Connect card would show for a pool row (pickerDisplay / upstreamDisplayName).
    // Contract 1.14.0: provider rows of a /v1/scan/candidates batch beyond the delivered stubs - into the pool before
    // any row of the batch can be tapped.
    void offerScanNodes(const QJsonArray &subscriptionNodes) override
    {
        const int kept = m_e->m_engine.offerScanNodes(subscriptionNodes);
        m_e->syncStandbyCandidates();
        m_e->reliabilityEvent(QStringLiteral("scan_nodes_offered rows=%1 kept=%2").arg(subscriptionNodes.size()).arg(kept));
    }

    bool rowFailedInTunnelHere(const QString &rowId) const override
    {
        const QString node = m_e->m_engine.nodeById(rowId) ? rowId : QStringLiteral("up:") + rowId;
        return m_e->m_engine.failedInTunnelHere(node);
    }

    QString rowDisplayName(const QString &rowId) const override
    {
        // one snapshot per view refresh (the rows of one refresh ask within the same event-loop turn)
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (!m_nameSnap || now - m_nameSnapMs > 200) {
            m_nameSnap = m_e->m_engine.debugSnapshot();
            m_nameSnapMs = now;
        }
        for (const NodeDebugRow &r : m_nameSnap->pool)
            if (r.nodeId == rowId || (r.upstream && r.nodeId == QStringLiteral("up:") + rowId))
                return rowLabel(*m_nameSnap, r);
        return QString();
    }

    QString rowLabel(const DebugSnapshot &s, const NodeDebugRow &r) const
    {
        const QString lang = m_e->appLang();
        const QString country = doctor::countryDisplayName(r.countryCode, lang);
        if (r.upstream)
            return m_e->upstreamRowName(r.name, r.upstreamLabelCustom, r.upstreamOrdinal, r.upstreamKind, r.countryCode);
        QList<PickerRow> loc{{r.location, r.proto, doctor::localizedNodeLabel(r.name, r.countryCode, lang), country, -1}};
        if (r.name.isEmpty() && !r.location.isEmpty())
            for (const NodeDebugRow &o : s.pool)
                if (&o != &r && o.location == r.location)
                    loc.append({o.location, o.proto, doctor::localizedNodeLabel(o.name, o.countryCode, lang), QString(), -1});
        return pickerDisplay(loc).constFirst().name;
    }

private:
    AvpnEngineQml *m_e;
    mutable QString m_kindDisagreement; // the last journalled monitor / interface-list disagreement
    mutable std::optional<DebugSnapshot> m_nameSnap; // R7: the pool the row names were read from
    mutable qint64 m_nameSnapMs = 0;
};

ScanCurrent ScanEngineAdapter::current() const
{
    ScanCurrent c;
    const DebugSnapshot s = m_e->m_engine.debugSnapshot();
    const Vpn::ConnectionState nat = m_e->m_lastTunnelState;
    const bool nativeUp = nat == Vpn::Connected || nat == Vpn::Reconnecting || nat == Vpn::Disconnecting;
    const SubscriptionNode *next = m_e->m_engine.nextCandidate();
    // "Nothing works" only as the attempt's final result (the engine never passes through error mid-walk now).
    const bool attemptFailed = m_e->m_engine.state() == EngineState::Error && !m_e->m_engine.attemptRunning();
    const ScanLiveView v = scanLiveView(s.state, nativeUp, s.currentNodeId, QString(),
                                        m_e->m_engine.pinnedNodeId(), next ? next->nodeId : QString(),
                                        m_e->m_wantConnected, m_e->m_needsRestart || m_e->m_seatFirst.pending,
                                        m_e->m_dataFlowing, attemptFailed);
    c.nodeId = v.nodeId;
    c.live = v.live;
    c.connecting = v.connecting;
    c.failed = v.failed;
    c.attemptNodeId = v.attemptNodeId;
    c.dataFlowing = v.live && m_e->m_dataFlowing;
    c.liveRttMs = v.live ? m_e->m_liveRtt : -1;
    const QString shown = !c.nodeId.isEmpty() ? c.nodeId : c.attemptNodeId;
    for (const NodeDebugRow &r : s.pool) {
        if (r.nodeId != shown)
            continue;
        c.origin = r.upstream ? ScanOrigin::Upstream : ScanOrigin::Own;
        c.countryCode = r.countryCode;
        c.transport = scanTransportFrom(r.proto);
        c.transportVersion = r.upstream || isXrayProto(r.proto) ? QString() : r.protoVersion;
        c.tier = r.upstream ? r.upstreamTier : 0;
        c.label = rowLabel(s, r);
        break;
    }
    return c;
}

// The physical uplink from the interface list (QNetworkInterface types): the medium under the device's own
// tunnel, which the platform's transport medium no longer shows (macOS: the default route is utun).
static QString physicalKindFromInterfaces()
{
    QList<PhysicalIface> list;
    for (const QNetworkInterface &i : QNetworkInterface::allInterfaces()) {
        PhysicalIface p;
        p.name = i.name();
        p.up = i.flags().testFlag(QNetworkInterface::IsUp) && i.flags().testFlag(QNetworkInterface::IsRunning);
        switch (i.type()) {
        case QNetworkInterface::Wifi: p.type = 1; break;
        case QNetworkInterface::Ethernet: p.type = 2; break;
        case QNetworkInterface::Ieee80216:
        case QNetworkInterface::Ieee1394: p.type = 0; break;
        default: p.type = 0; break;
        }
        for (const QNetworkAddressEntry &e : i.addressEntries())
            if (e.ip().protocol() == QAbstractSocket::IPv4Protocol)
                p.ipv4 << e.ip().toString();
        list << p;
    }
    return physicalUplinkKind(list);
}

// The inputs of the network kind (scanNetworkKindPick) and the app's network element the Scanner also needs.
struct NetKindInputs {
    QString pathKind;
    QString interfacesKind;
    bool hasApp = false;
    ScanNetSource app;
    QString gatewayHash; // macOS path monitor only ("" = none)
};

static NetKindInputs netKindInputs()
{
    NetKindInputs in;
#if defined(Q_OS_IOS)
    in.hasApp = IosScanHost::appGeneration(in.app);
    // The app's own path monitor (virtual interfaces prohibited): the physical kind under the VPN. The platform
    // medium is the fallback only - CoreTelephony makes it "cellular" whenever a radio is known, Wi-Fi or not.
    in.pathKind = IosScanHost::appPathKind();
#elif defined(Q_OS_ANDROID)
    // AVPN Scanner (lane A3): the app process's element and the physical kind of the UNDERLYING network (the VPN
    // network excluded, NetworkState.kt ScanAppNetwork); the platform medium is the fallback only.
    in.hasApp = AndroidScanHost::appGeneration(in.app, &in.pathKind);
#else
    // macOS desktop: the authoritative nw_path_monitor (utun/ipsec/ppp excluded; under the Mac's own VPN its kind
    // comes from the route table's physical default route); the QNetworkInformation fallback of the other
    // platforms has no source (epoch 0) - their element comes from their own lane.
    const UplinkMonitor *m = UplinkMonitor::instance();
    if (m->pathEpoch() != 0) {
        in.hasApp = true;
        in.app.source = QStringLiteral("app");
        in.app.epoch = m->pathEpoch();
        in.app.counter = m->pathCounter();
        in.gatewayHash = m->pathGatewayHash();
        in.pathKind = m->pathKind();
    }
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    in.interfacesKind = physicalKindFromInterfaces();
#endif
#endif
    return in;
}

ScanNetFacts ScanEngineAdapter::network() const
{
    ScanNetFacts f;
    const QString platformMedium = m_e->platformNetKind();
    if (!m_e->m_scanSwitches.scanner) {
        f.kind = scanNetKindFrom(platformMedium);
        f.reportingKey = m_e->upstreamNetworkKeyNow();
        return f; // the Scanner does not exist: its facts are not asked for
    }
    const NetKindInputs in = netKindInputs();
    if (in.hasApp)
        f.appSources << in.app;
    f.gatewayHash = in.gatewayHash;
    const QString &pathKind = in.pathKind;
    const QString &interfacesKind = in.interfacesKind;
    const ScanKindPick pick = scanNetworkKindPick(pathKind, interfacesKind, platformMedium);
    if (pick.disagree) {
        const QString pair = pathKind + QLatin1Char('/') + interfacesKind;
        if (pair != m_kindDisagreement) { // once per distinct pair; the monitor's kind is used
            m_kindDisagreement = pair;
            m_e->reliabilityEvent(QStringLiteral("scan_network_kind_disagree path=%1 interfaces=%2 used=path").arg(pathKind, interfacesKind));
        }
    }
    f.kind = scanNetKindFrom(pick.kind);
    // The reporting key from the same kind (never the tunnel's medium, never the last standby fetch's key).
    f.reportingKey = avpn::upstreamNetworkKey(pick.kind, m_e->diagCarrierAuto(), avpn::cellularGeneration(),
                                              m_e->m_accessAsnByNet.value(m_e->m_engine.network().local));
    return f;
}

bool ScanEngineAdapter::awgProbeInput(const QString &nodeId, ScanAwgNodeInput &out) const
{
    // SECRET: the device's own key and the node's peer data, exactly as the live tunnel gets them
    // (DebugSnapshot.h::awgProbeInputFrom); nothing of it is logged or kept here.
    const SubscriptionNode *n = m_e->m_engine.nodeById(nodeId);
    if (!n)
        return false;
    const int defaultMtu = QString::fromLatin1(amnezia::protocols::awg::defaultMtu).toInt();
    return awgProbeInputFrom(m_e->m_engine.subscription(), *n, m_e->m_engine.clientKeys().privateKey, defaultMtu, out);
}

void ScanEngineAdapter::fillManifestInput(ScanManifestInput &in) const
{
    const DebugSnapshot s = m_e->m_engine.debugSnapshot();
    for (const NodeDebugRow &r : s.pool) {
        if (r.upstream) {
            const QString pid = r.nodeId.startsWith(QLatin1String("up:")) ? r.nodeId.mid(3) : r.nodeId;
            in.upstreamNames.insert(pid, rowLabel(s, r));
            continue;
        }
        if (!r.transportSupported)
            continue;
        ScanOwnNode n;
        n.nodeId = r.nodeId;
        n.label = rowLabel(s, r);
        n.countryCode = r.countryCode;
        n.transport = scanTransportFrom(r.proto);
        n.transportVersion = isXrayProto(r.proto) ? QString() : r.protoVersion;
        n.entryIp = endpointHost(r.endpoint);
        n.entryPort = AwgConfigBuilder::port(r.endpoint);
        n.manualOnly = r.manualOnly;
        n.ru = r.countryCode.compare(QLatin1String("RU"), Qt::CaseInsensitive) == 0;
        if (n.transport == ScanTransport::Xray) {
            const SubscriptionNode *node = m_e->m_engine.nodeById(r.nodeId);
            n.configAvailable = node && !XrayConfigBuilder::coreConfig(*node).isEmpty();
        }
        in.ownNodes << n;
    }
    // Every provider of the manifest gets our form of the name (the admin's label, «<country> <n>», «Белые списки
    // <n>») - also one outside the pool, which otherwise fell back to the server's label ("NL 3").
    for (const ScanManifestUpstream &u : in.manifest.upstream)
        if (!in.upstreamNames.contains(u.profileId))
            in.upstreamNames.insert(u.profileId, m_e->upstreamRowName(u.label, u.labelCustom, u.ordinal,
                                                                       upstreamRowKind(u.kind, u.countryCode), u.countryCode));
    in.freshFailures = m_e->m_engine.pathsFailedHere(); // the ledger of this network (path engine)
    in.lastKnownGood = m_e->m_engine.bestWorkingPathHere();
    in.restrictCountry.clear();
    // awg_mini: the device's own tunnel address and key are known (awgProbeInput); the API IP comes from the
    // coordinator (knownHostIps / its own resolution).
    in.awgAddressKnown = !m_e->m_engine.subscription().address.isEmpty() && !m_e->m_engine.clientKeys().privateKey.isEmpty();
    in.awgProbeIpKnown = !knownIpsForHost(m_e->m_apiHostIpsByHost, QUrl(m_e->m_baseUrl).host()).isEmpty();
}

// SECRET: the probe config of an own path. xray_full = the exact core config the tunnel would get;
// xray_leg = its one outbound (the host forces its own tag) without DNS plan; awg_mini = none in this build
// (the host answers such a candidate with error config -> «Не проверено»).
QString ScanEngineAdapter::ownProbeConfig(const ScanCandidate &c) const
{
    if (c.origin != ScanOrigin::Own)
        return {};
    const SubscriptionNode *n = m_e->m_engine.nodeById(c.id);
    if (!n || isUpstreamNode(*n) || !n->xray.has_value())
        return {};
    switch (c.kind) {
    case ScanProbeKind::XrayFull:
        return XrayConfigBuilder::coreConfigText(*n);
    case ScanProbeKind::XrayLeg: {
        const QJsonArray outs = XrayConfigBuilder::coreConfig(*n).value(QStringLiteral("outbounds")).toArray();
        if (outs.isEmpty() || !outs.first().isObject())
            return {};
        const QJsonObject leg{{QStringLiteral("outbound"), outs.first().toObject()}, {QStringLiteral("dns"), QJsonArray()}};
        return QString::fromUtf8(QJsonDocument(leg).toJson(QJsonDocument::Compact));
    }
    default:
        return {};
    }
}

QString ScanEngineAdapter::liveProbeBase(const ScanCurrent &c) const
{
    if (c.origin == ScanOrigin::Upstream || c.nodeId.isEmpty())
        return {}; // the manifest's tunnel_api_base (the lease's for a provider profile)
    return whoamiBaseUrl(m_e->m_baseUrl, c.transport == ScanTransport::Xray, !qgetenv("AVPN_API_URL").isEmpty());
}

AvpnEngineQml::AvpnEngineQml(VpnConnection *conn, SecureAppSettingsRepository *store,
                             QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent), m_tunnel(conn, this), m_store(store), m_nam(nam), m_conn(conn)
{
    // AVPN (анти-фрод, DEVICE-FIRST-SPEC §4): восстановить identity из Keychain ДО первого
    // использования (переустановка на iOS стирает QSettings → без этого новый триал и потеря
    // оплаченных дней). Один блокирующий Keychain-раунд ~мс со сторожем; не-Apple — no-op.
    IdentityAnchor::syncAtStartup();

    // AVPN Scanner (lane L6b): the engine interface of the coordinator and the switch-gated probe host exist
    // from the start (the coordinator is attached by coreController); the switches are read again on every
    // /v1/config apply (configApplied below, scanApplySwitches).
    m_processEpoch = QRandomGenerator::global()->generate64() | 1;
    m_scanAdapter = std::make_unique<ScanEngineAdapter>(this);
    m_scanHost = std::make_unique<GatedScanHost>();
    m_scanSwitches = scannerSwitchesFrom([](const QString &k, bool d) { return avpn::TuningStore::flag(k, d); });

    // dev/E2E: переопределение control plane (напр. http://127.0.0.1:48480 — локальный бэкенд)
    const QByteArray envUrl = qgetenv("AVPN_API_URL");
    if (!envUrl.isEmpty())
        m_baseUrl = QString::fromUtf8(envUrl);
    // Волна-4 (ENG-02): персистнутый рабочий вход API (edge-walk прошлой сессии) — с самого старта.
    // ConfigService поднимает его для себя, но activeEdgeChanged на холодном старте не эмитится, и
    // подписка/регистрация/чат/carve-out били в основной адрес, даже если работало только зеркало.
    // R1a (device round 4): the walk of an earlier run is not restored - every run starts at the Russian entry.
#ifdef Q_OS_IOS
    AvpnDiagnostics_setBase(m_baseUrl.toUtf8().constData());
#endif

    // AVPN RU-direct carve-out (2026-07-05): узнать актуальные IP хоста API, чтобы сев байпаса
    // их исключил (см. applyRuBypassSplit). Async (QHostInfo не блокирует GUI); провал резолва
    // не страшен — в севе всегда есть вкомпиленный фолбэк-IP. Ре-сев на живом туннеле произойдёт
    // при следующем reconcile/up() и подхватит m_apiHostIps.
    // AVPN (watchdog 0x8BADF00D, креш build 53, 2026-07-05): при выходе ~QGuiApplication ждёт
    // QThreadPool::waitForDone (Qt-внутренний пул QHostInfo), а застрявший в блокированной сети
    // DNS-lookup не завершается → iOS убивает процесс за 5с как «Failed to terminate gracefully».
    // Предохранитель: на aboutToQuit синхронно флашим настройки и взводим detached-поток, который
    // через 2с (внутри 5с watchdog) завершает процесс штатно, если teardown не успел сам.
    // Overlay: наш файл, апстрим main.cpp/amneziaApplication.cpp не трогаем.
#if AVPN_UPSTREAM_GUI_OWNER // macOS desktop; Windows since release C (the GUI owns the lease there too)
    // AVPN upstream nodes (point 15, owner 15.11): a REAL quit of the GUI ends an upstream session through the
    // normal user stop (release + stop, bounded); own nodes keep BUG-6. Every deliberate quit ends in
    // quit()/exit() and so here - closing/hiding the window never does. Overlay: hooked from our file, the
    // upstream amneziaApplication.cpp is untouched (as the iOS guard below).
    connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, this, [this] { endUpstreamSessionOnQuit(); });
#endif
#ifdef Q_OS_IOS
    connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, this, [] {
        { QSettings s; s.sync(); }
        std::thread([] {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            ::_exit(0);
        }).detach();
    });
#endif

    // AVPN (разбор 2026-09-23): накопительно (не присваиванием) — параллельно резолвятся хосты всех
    // edge-кандидатов (после создания ConfigService ниже), ответ primary их не затирает.
    resolveApiCarveHosts({QUrl(m_baseUrl).host()});

    m_engine.setTunnel(&m_tunnel);
    m_tunnel.setStore(store); // AVPN RU-direct: гейт сплита по фактической ноде — в up() (T2)
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // 5.1.108: no tun2socks in the installed service = no Xray candidates. Silent here (the
    // reliability ring is restored later in the constructor); guardedStart journals a change.
    avpn::xrayPlatformRuntimeReady().store(avpn::macXrayRuntimePresent());
    // Upstream nodes (point 14): the cut geo pair next to the service - a separate input that withholds
    // upstream candidates only (own Xray untouched); same check points as tun2socks, never per tick.
    avpn::upstreamPlatformRuntimeReady().store(avpn::macUpstreamGeoPresent());
#elif defined(Q_OS_WIN)
    // Release C (lane P1): the Xray runtime (tun2socks.exe, amnezia_xray.dll, wintun.dll) and the cut geo pair
    // with its manifest next to Tribe-service.exe, in the install dir the GUI shares (XrayPlatformGate.h).
    // Checked once: on Windows the installer replaces these files with the app closed (no in-app service
    // install as on macOS). Without features.xray_client_windows neither input is read by any decision.
    {
        const QString installDir = QCoreApplication::applicationDirPath();
        avpn::xrayPlatformRuntimeReady().store(avpn::windowsXrayRuntimePresentIn(installDir));
        avpn::upstreamPlatformRuntimeReady().store(avpn::windowsUpstreamGeoPresentIn(installDir));
    }
#elif defined(Q_OS_ANDROID)
    // Release C (lane P1): the Xray runtime is linked into every Android build (XrayPlatformGate.h). The geo
    // data is no longer inside the AAR (libXray 1.0.3-tribe.2, patch 0010-android-no-embedded-geo): the app
    // ships the cut tribe-xray-geo pair and passes its directory as datDir. The real gate is
    // features.xray_client_android.
    avpn::xrayPlatformRuntimeReady().store(avpn::kAndroidXrayRuntimeBundled);
#endif
    // AVPN upstream nodes (lane L1): a stub's start failure is excluded for the attempt BEFORE the tunnel
    // Error reaches reconcile (the restart picks another node); the lease owner's verdicts come back as
    // signals and are applied deferred (CONNECT-INVARIANTS §3: never from inside a tunnel callback stack).
    m_tunnel.setUpstreamStartFailureSink([this](const QString &nodeId, const QString &code) {
        reliabilityEvent(QStringLiteral("upstream_start_failed node=%1 code=%2").arg(nodeId, code));
        // An outcome of the attempt's leg (no seat / refused); the owner walks on. Deferred: this runs inside the
        // tunnel adapter's stack (CONNECT-INVARIANTS §3).
        QTimer::singleShot(0, this, [this, nodeId, code]() {
            const bool walking = m_engine.attemptRunning();
            m_engine.noteStartRefused(nodeId, code);
            syncAttempt();
            if (walking && m_engine.attemptRunning())
                noticeUpstreamLeft(code);
        });
    });
    connect(&m_tunnel, &avpn::VpnConnectionTunnelControl::upstreamLeaveRequested, this,
            [this](const QString &code, const QString &detail) {
                QTimer::singleShot(0, this, [this, code, detail]() { onUpstreamLeave(code, detail); });
            });
    connect(&m_tunnel, &avpn::VpnConnectionTunnelControl::upstreamPrepared, this,
            [this](const QString &nodeId, quint64 prepareId, bool ok, const QString &code) {
                QTimer::singleShot(0, this, [this, nodeId, prepareId, ok, code]() {
                    onUpstreamPrepared(nodeId, prepareId, ok, code);
                });
            });
    connect(&m_tunnel, &avpn::VpnConnectionTunnelControl::upstreamRevisionSeen, this,
            [this](qint64 rev) { noteUpstreamRevision(rev); });
#if defined(Q_OS_IOS)
    // Contract §5: the extension's upstream status (every change and every upstream_lease_set reply).
    connect(IosController::Instance(), &IosController::upstreamLeaseEvent, this,
            [this](const QVariantMap &upstream) { applyUpstreamTunnelStatus(QJsonObject::fromVariantMap(upstream)); },
            Qt::QueuedConnection);
#elif defined(Q_OS_ANDROID)
    // Release C (decision A-1): the Xray service process owns the lease; its status event (the same contract
    // §5 object, android-ipc-contract.md §3) takes the same path - a terminal state leaves the node.
    connect(AndroidController::instance(), &AndroidController::upstreamLeaseEvent, this,
            [this](const QVariantMap &upstream) { applyUpstreamTunnelStatus(QJsonObject::fromVariantMap(upstream)); },
            Qt::QueuedConnection);
#endif
    connect(&m_tunnel, &avpn::VpnConnectionTunnelControl::upstreamSessionAdopted, this,
            [this](const QString &nodeId) {
                // macOS: the daemon's live Xray session is this upstream node (its record) - identify it.
                m_engine.adoptTunnelConnected(nodeId, QStringLiteral("xray"), QString());
                reliabilityEvent(QStringLiteral("upstream_adopt node=%1").arg(nodeId));
                emit changed();
            });
    connect(&m_tunnel, &avpn::VpnConnectionTunnelControl::upstreamAccessFacts, this, [this](qint64 asn) {
        const QString net = m_engine.network().local;
        if (!net.isEmpty() && asn > 0)
            m_accessAsnByNet.insert(net, asn);
    });

    // AVPN (выбор по скорости): прямой ICMP-пробер RTT до нод (off-tunnel). Кроссплатформенный за швом
    // IRttProbe; Windows — graceful-стаб (нет измерения → health-фолбэк). Запуск — из probeNodeRtt().
    m_rttProbe = new RttProbeIcmp(this);
    // AVPN (Доктор D-3 п.3): отдельный ICMP-инстанс для пробы ЧЕРЕЗ туннель — m_rttProbe
    // гейтится «connected⇒cancel» (off-tunnel семантика), делить нельзя.
    m_docPing = new RttProbeIcmp(this);

    // AVPN (панель администратора): in-app бенч соединения. Запуск ТОЛЬКО вручную (startBench из QML),
    // коннект-путь не трогает; результат — schema:1 (сводится с Mac-замерами tools/connect-bench).
    m_bench = new BenchRunner(m_nam, this);
    connect(m_bench, &BenchRunner::stageChanged, this, [this](const QString &st) {
        m_benchStage = st;
        emit benchChanged();
    });
    // сторож фаз свипа нод + продвижение фазовой машины по каждому changed() (queued: не входить
    // в reconcile-стек синхронно)
    m_sweepGuard.setSingleShot(true);
    connect(&m_sweepGuard, &QTimer::timeout, this, [this] { sweepGuardFired(); });
    connect(this, &AvpnEngineQml::changed, this, [this] { sweepAdvance(); }, Qt::QueuedConnection);
    // AVPN (авто-A/B байпаса): та же схема — сторож фазы + queued-продвижение по changed()
    m_abGuard.setSingleShot(true);
    connect(&m_abGuard, &QTimer::timeout, this, [this] { abGuardFired(); });
    connect(this, &AvpnEngineQml::changed, this, [this] { abAdvance(); }, Qt::QueuedConnection);

    m_ccGuard.setSingleShot(true); // AVPN bench v5 (connect{}): тот же каркас, что свип/A/B
    connect(&m_ccGuard, &QTimer::timeout, this, [this] { ccGuardFired(); });
    connect(this, &AvpnEngineQml::changed, this, [this] { ccAdvance(); }, Qt::QueuedConnection);

    // AVPN bench v5.2 (мастер «Полный тест»): дирижёр слушает завершения готовых машин.
    m_ftGuard.setSingleShot(true);
    connect(&m_ftGuard, &QTimer::timeout, this, [this] { ftStepDone(m_ftPhase, false); });
    connect(this, &AvpnEngineQml::ccFinished, this, [this] { ftStepDone(FtPhase::Cc, true); });
    connect(this, &AvpnEngineQml::abFinished, this, [this] { ftStepDone(FtPhase::Ab, true); });
    connect(this, &AvpnEngineQml::sweepFinished, this, [this] { ftStepDone(FtPhase::Sweep, true); });
    connect(this, &AvpnEngineQml::benchFinished, this, [this] {
        if (m_ftPhase == FtPhase::BenchAmnezia || m_ftPhase == FtPhase::BenchBaseline)
            ftStepDone(m_ftPhase, true);
    });
    // AVPN (Доктор v2): сторож стадии + добор lite-бенча + тик процента Speed + продвижение
    // фазы Connect по changed() (туннель поднялся/упал — queued, не входим в reconcile-стек).
    m_docGuard.setSingleShot(true);
    connect(&m_docGuard, &QTimer::timeout, this, [this] { docGuardFired(); });
    connect(this, &AvpnEngineQml::changed, this, [this] {
        if (m_docConnecting && (m_docPhase == DoctorPhase::Connect
                                || m_docPhase == DoctorPhase::AltNodes))
            docConnectAdvance();
    }, Qt::QueuedConnection);
    connect(m_bench, &BenchRunner::finished, this, [this](const QJsonObject &result) {
        if (m_docPhase != DoctorPhase::Speed || !m_docBenchStarted)
            return;
        m_docBenchStarted = false;
        m_docBenchFull = result; // полный замер (dns/tls/http/ping/…) уходит в extra отчёта
        const QJsonObject thr = result.value(QStringLiteral("throughput")).toObject();
        const QJsonObject nq  = result.value(QStringLiteral("network_quality")).toObject();
        const double down = thr.value(QStringLiteral("down_mbit")).isDouble()
                                ? thr.value(QStringLiteral("down_mbit")).toDouble() : -1.0;
        // D-3 п.18: посекундный профиль -> вердикт «коллапс» (ТСПУ-сигнатура)
        QList<double> prof;
        const QJsonArray profArr = thr.value(QStringLiteral("down_mbit_per_sec")).toArray();
        prof.reserve(profArr.size());
        for (const QJsonValue &v : profArr)
            prof.append(v.toDouble());
        const bool collapsed = doctor::speedCollapsed(prof);
        // D-3 п.19: при подозрении — контрольный замер МИМО туннеля (внутри docDirectSpeed),
        // иначе сразу вердикт
        docDirectSpeed(down,
                       int(nq.value(QStringLiteral("base_rtt_ms")).toDouble(0)),
                       int(nq.value(QStringLiteral("loaded_rtt_ms")).toDouble(0)), collapsed);
    });
    connect(this, &AvpnEngineQml::benchChanged, this, [this] {
        if (m_docPhase == DoctorPhase::Speed && m_docBenchStarted) {
            m_docPercent = 68 + int(28.0 * benchStageFrac());
            emit doctorChanged();
        }
    });

    // ── AVPN (CR-1): краш-репортинг — install СНАЧАЛА классифицирует прошлый запуск,
    // затем пишет свежий sentinel и ставит сигнал-хендлеры. Отчёты прошлых крашей уходят
    // тихо в /v1/bench/report (kill-switch features.crash_report). Спека:
    // tribe-front specs/2026-07-17-observability-crash-telemetry-design.md §1.
    {
        QString ver = QCoreApplication::applicationVersion();
        CrashGuard::instance().install(
            QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                + QStringLiteral("/crash"),
            ver, QSysInfo::productType(), QSysInfo::productVersion());
        auto *hb = new QTimer(this);
        hb->setInterval(30000);
        connect(hb, &QTimer::timeout, this, [] { CrashGuard::instance().heartbeat(); });
        hb->start();
        // штатный выход != dirty_exit
        connect(qApp, &QCoreApplication::aboutToQuit, this,
                [] { CrashGuard::instance().markCleanExit(); });
        // лог-хвост: tee поверх ТЕКУЩЕГО message-handler (chain; апстрим-логгер не трогаем)
        installCrashLogTee();
        // отправка pending прошлых запусков: тихо, когда сеть скорее всего поднялась
        QTimer::singleShot(12000, this, [this] { crashFlushPending(); });
        QTimer::singleShot(120000, this, [this] { crashFlushPending(); });
        // AVPN (self-update v2): безопасный запуск после обновления — rollback.sh в каталоге
        // состояния, отчёт об откате прошлого запуска (уведомление + тихая отправка на сервер).
        avpn::LaunchGuard::instance().install(avpn::LaunchGuard::defaultStateDir(), ver,
                                              avpn::LaunchGuard::installedAppPath());
        {
            const avpn::launchguard::RollbackReport rb = avpn::LaunchGuard::instance().takeRollbackReport();
            if (rb.valid) {
                QSettings st;
                st.setValue(QStringLiteral("AvpnUpdate/rolledBack"), rb.from); // эту версию тихо не ставим
                st.setValue(QStringLiteral("AvpnUpdate/notice"), avpn::launchguard::rollbackNoticeText(rb));
                st.setValue(QStringLiteral("AvpnUpdate/pendingReport"),
                            QString::fromUtf8(QJsonDocument(avpn::launchguard::rollbackReportJson(
                                rb, ver, avpnPlatformKey(), QSysInfo::productVersion())).toJson(QJsonDocument::Compact)));
                st.sync();
                qWarning() << "[launchguard] rolled back" << rb.from << "->" << rb.to << "reason" << rb.reason;
            }
            m_rollbackNotice = QSettings().value(QStringLiteral("AvpnUpdate/notice")).toString();
        }
        QTimer::singleShot(15000, this, [this] { launchGuardFlushReport(); });
        QTimer::singleShot(150000, this, [this] { launchGuardFlushReport(); });
    }
    // BUG-7: недоставленные отчёты прошлых запусков — дослать, когда сеть скорее всего есть
    QTimer::singleShot(25000, this, [this] { outboxFlush(); });
    // ── AVPN (Доктор D-3 п.26): RU-split-дозорный — сам замечает «сайт РФ не открывается»
    // и шлёт rusplit_fail (только на смене состояния, 1/сутки на target, kill-switch
    // rusplit_sentinel). Приватность: только наш вахт-лист, браузинг юзера не трогаем.
    m_ruSentinel = new RuSplitSentinel(
        m_nam,
        [this](const QJsonObject &o) {
            // S-5 (разбор 2026-07-24): без build отчёт не привязать к версии
            // (ингест берёт app_ver из тела, тело его не несло).
            QJsonObject withBuild = o;
            withBuild.insert(QStringLiteral("build"),
                             QCoreApplication::applicationVersion().section(QLatin1Char('.'), -1));
            uploadReport(QString::fromUtf8(
                             QJsonDocument(withBuild).toJson(QJsonDocument::Compact)),
                         /*quiet=*/true);
        },
        [this] { return benchExtra().value(QStringLiteral("net_type")).toString(); },
        [] {
            QSettings st;
            return st.value(QStringLiteral("AvpnBypass/masterOn"), false).toBool();
        },
        this);
    connect(m_ruSentinel, &RuSplitSentinel::sitesStateChanged, this, &AvpnEngineQml::changed);
    connect(this, &AvpnEngineQml::changed, this, [this] {
        const QString st = state();
        if (m_ruSentinel)
            m_ruSentinel->onTunnelStateChanged(st);
        if (m_docPhase == DoctorPhase::Idle) // во время Доктора фаза "doctor" приоритетнее
            CrashGuard::instance().setPhase(st == QLatin1String("connected") ? "connected"
                                            : st == QLatin1String("disconnected") ? "idle"
                                                                                  : "connecting");
        // BUG-7: фронт connected = сеть вернулась → дослать outbox (10с на устаканивание).
        // AVPN (фикс-волна 2026-09-22, A12): не чаще раза в 10 минут (флапы Connected не
        // превращаются в шторм повторных отправок).
        const bool nowConnected = (st == QLatin1String("connected"));
        if (nowConnected && !m_outboxWasConnected) {
            const qint64 now = QDateTime::currentMSecsSinceEpoch();
            if (outboxConnectedFlushDue(m_lastOutboxConnectedFlushMs, now)) {
                m_lastOutboxConnectedFlushMs = now;
                QTimer::singleShot(10000, this, [this] { outboxFlush(); });
            }
        }
        m_outboxWasConnected = nowConnected;
    }, Qt::QueuedConnection);

    // AVPN Scanner (lane L6b): the coordinator reads the live status after every change (deduplicated in
    // scanSyncState, which also follows a row tap's chain); the physical path moving is a network change.
    // Nothing here acts on the tunnel.
    connect(this, &AvpnEngineQml::changed, this, [this] { scanSyncState(); }, Qt::QueuedConnection);
    connect(this, &AvpnEngineQml::dataFlowingChanged, this, [this] { scanSyncState(); }, Qt::QueuedConnection);
    connect(this, &AvpnEngineQml::liveQualityChanged, this, [this] { scanSyncState(); }, Qt::QueuedConnection);
    connect(avpn::UplinkMonitor::instance(), &avpn::UplinkMonitor::pathChanged, this, [this] { scanNotifyNetwork(); });
    connect(avpn::UplinkMonitor::instance(), &avpn::UplinkMonitor::changed, this, [this](bool) { scanNotifyNetwork(); });

    // прогресс-бар мастера: пересчитывать на каждом тике под-машин (v5.4)
    auto ftTick = [this] { if (ftRunning()) ftUpdatePercent(); };
    connect(this, &AvpnEngineQml::benchChanged, this, ftTick);
    connect(this, &AvpnEngineQml::abChanged, this, ftTick);
    connect(this, &AvpnEngineQml::sweepChanged, this, ftTick);
    connect(this, &AvpnEngineQml::ccChanged, this, ftTick);
    // фаза Connect0 (мастер сам подключает) продвигается по changed()
    connect(this, &AvpnEngineQml::changed, this, [this] {
        if (m_ftPhase != FtPhase::Connect0)
            return;
        if (state() == QLatin1String("connected"))
            ftStepDone(FtPhase::Connect0, true);
        else if (state() == QLatin1String("error"))
            ftStepDone(FtPhase::Connect0, false);
    }, Qt::QueuedConnection);

    connect(m_bench, &BenchRunner::finished, this, [this](const QJsonObject &result) {
        m_benchRunning = false;
        emit benchChanged();

        // свип нод: результат забирает фазовая машина (в историю меток не пишем, наружу не эмитим)
        if (m_sweepPhase == SweepPhase::Bench) {
            m_sweepGuard.stop();
            m_sweepResults.append(result);
            QTimer::singleShot(0, this, [this, e = m_sweepEpoch] { if (e == m_sweepEpoch) sweepNextNode(); });
            return;
        }

        // история: последний замер каждой метки (для A/B между запусками)
        const QString label = result.value(QStringLiteral("label")).toString();
        const QString json = QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact));
        QSettings().setValue(QStringLiteral("AvpnBench/last_%1").arg(label), json);

        // авто-A/B байпаса: замер забирает фазовая машина (история выше УЖЕ записана — полный
        // отчёт собирает last_<label>); в UI не эмитим — по завершении пары придёт abFinished
        if (m_abPhase == AbPhase::BenchA || m_abPhase == AbPhase::BenchB) {
            abOnBenchDone(result);
            return;
        }

        QVariantMap s; // плоская сводка для мини-таблицы в UI
        s.insert(QStringLiteral("label"), result.value(QStringLiteral("label")).toString());
        s.insert(QStringLiteral("dns_ms"), result.value(QStringLiteral("dns")).toObject().value(QStringLiteral("median_ms")).toVariant());
        const QJsonObject http = result.value(QStringLiteral("http")).toObject();
        s.insert(QStringLiteral("ttfb_ms"), http.value(QStringLiteral("median_ttfb_ms")).toVariant());
        s.insert(QStringLiteral("total_ms"), http.value(QStringLiteral("median_total_ms")).toVariant());
        s.insert(QStringLiteral("failures"), http.value(QStringLiteral("failures")).toInt());
        const QJsonObject thr = result.value(QStringLiteral("throughput")).toObject();
        s.insert(QStringLiteral("down_mbit"), thr.value(QStringLiteral("down_mbit")).toDouble());
        s.insert(QStringLiteral("up_mbit"), thr.value(QStringLiteral("up_mbit")).toDouble());
        const QJsonObject nq = result.value(QStringLiteral("network_quality")).toObject();
        s.insert(QStringLiteral("base_rtt_ms"), nq.value(QStringLiteral("base_rtt_ms")).toVariant());
        s.insert(QStringLiteral("loaded_rtt_ms"), nq.value(QStringLiteral("loaded_rtt_ms")).toVariant());
        const QJsonObject eg = result.value(QStringLiteral("network")).toObject().value(QStringLiteral("egress")).toObject();
        s.insert(QStringLiteral("egress"), QStringLiteral("%1/%2").arg(eg.value(QStringLiteral("loc")).toString(QStringLiteral("-")),
                                                                       eg.value(QStringLiteral("cf_colo")).toString(QStringLiteral("-"))));
        // вердикты замера (BenchAnalysis) — тексты в UI
        QStringList verdictTexts;
        for (const QJsonValue &v : result.value(QStringLiteral("verdicts")).toArray())
            verdictTexts << v.toObject().value(QStringLiteral("text")).toString();
        s.insert(QStringLiteral("verdicts"), verdictTexts);
        // A/B против истории: существенные ухудшения текущего замера относительно эталонов.
        auto loadPrev = [this](const char *lbl) {
            const QString j = benchLastJson(QLatin1String(lbl));
            return j.isEmpty() ? QJsonObject() : QJsonDocument::fromJson(j.toUtf8()).object();
        };
        auto sigList = [](const QJsonObject &cmp) {
            QStringList out;
            for (const QJsonValue &v : cmp.value(QStringLiteral("significant")).toArray())
                out << v.toString();
            return out;
        };
        if (label != QLatin1String("baseline")) {
            const QJsonObject base = loadPrev("baseline");
            if (!base.isEmpty())
                s.insert(QStringLiteral("vs_baseline"), sigList(bench::compare(base, result)));
        }
        // главная пара методики: tribe-bypass-off ↔ amnezia (одинаковый full-tunnel, та же нода)
        if (label == QLatin1String("amnezia")) {
            const QJsonObject tribe = loadPrev("tribe-bypass-off");
            if (!tribe.isEmpty())
                s.insert(QStringLiteral("tribe_vs_amnezia"), sigList(bench::compare(result, tribe)));
        } else if (label == QLatin1String("tribe-bypass-off")) {
            const QJsonObject amn = loadPrev("amnezia");
            if (!amn.isEmpty())
                s.insert(QStringLiteral("tribe_vs_amnezia"), sigList(bench::compare(amn, result)));
        }
        emit benchFinished(s, QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact)));
    });

    // health-loop driver: периодический tick (3–5с).
    m_healthTimer.setInterval(4000);
    connect(&m_healthTimer, &QTimer::timeout, this, &AvpnEngineQml::onTick);
    // 5.1.108: ONLINE badge - one cached value for both pages, recomputed whenever its inputs may
    // have changed (engine/tunnel state and pathCheck ride changed(), the live probe its own signal).
    connect(this, &AvpnEngineQml::changed, this, &AvpnEngineQml::refreshDataFlowing);
    connect(this, &AvpnEngineQml::liveQualityChanged, this, &AvpnEngineQml::refreshDataFlowing);

    // AVPN backend-first: фоновый LKG-рефреш подписки (H-3 бэклога). Коннект здесь, старт —
    // из configApplied (интервал приходит с сервера; до первого applied — не тикает).
    connect(&m_subRefreshTimer, &QTimer::timeout, this, &AvpnEngineQml::refreshSubscription);

    // AVPN (реальные палочки): app-layer RTT-проба ЧЕРЕЗ туннель. AWG UDP-only ⇒ ICMP/TCP-пинг до
    // эндпоинта пуст; реальный RTT даёт крошечный HTTPS-запрос к generate_204 через поднятый full-tunnel.
    // Эндпоинты по приоритету: свой бэкенд-пинг (тот же путь, что и control plane) → публичный фолбэк.
    // Поток RTT → m_signal (EWMA+гистерезис) → liveBars 0..5. Запуск — из onTick(), когда Connected.
    m_probe = new QualityProbe(m_nam, this);
    m_probe->setEndpoints({livePingUrl(),
                           QStringLiteral("https://connectivitycheck.gstatic.com/generate_204")});
    connect(m_probe, &QualityProbe::result, this, [this](int rttMs, bool reachable) {
        if (m_engine.state() != EngineState::Connected || m_lastTunnelState != Vpn::Connected)
            return;
        m_liveBars = m_signal.feed(rttMs, reachable);
        // 5.1.108: the card's ms is this in-tunnel HTTPS probe for every transport (as on Xray). The
        // ICMP ping to the in-tunnel gateway 100.127.255.254 (wave 3) is gone: on iOS 137 a packet
        // from the app to a CGNAT address raised the system "Local Network" permission prompt.
        m_liveRtt = m_signal.smoothedRtt();
        m_liveReachable = reachable;
        if (reachable)
            m_liveProven = true;     // 5.1.108: ONLINE without node_scan (dataFlowingNow)
        if (reachable)
        // AVPN (красные палочки): различаем «ещё мерю» (m_liveDead=false → плейсхолдер 1 зелёная)
        // и «связь подтверждённо мертва» (m_liveDead=true → 0 зелёных + все красные). Один таймаут
        // в «мертво» НЕ роняем — ждём kLiveDeadStreak неудач подряд (анти-фликер на транзиентном дропе).
        if (reachable) {
            m_liveFailStreak = 0;
            m_liveDead = false;
        } else {
            // AVPN backend-first (final review R-2): пол 1 — 0/минус латчили бы m_liveDead=true мгновенно.
            const int deadStreak = qMax(1,
                (int) TuningStore::numberOr(QStringLiteral("live_dead_streak"), kLiveDeadStreak));
            if (++m_liveFailStreak >= deadStreak)
                m_liveDead = true;
        }
        emit liveQualityChanged();
        // AVPN awg31-xray-v1: для xray та же живая проба — вторая половина DEAD-критерия (у xray нет
        // handshake): N провалов подряд (xray_probe_fail_cycles) → движок уводит на другой транспорт
        // той же локации (двухфазный свитч, как health-DEAD). awg — no-op внутри. Сигнал приходит с
        // верха цикла событий (async-ответ QNetworkReply), не из-под Selector::pick.
        if (m_engine.feedProbeResult(reachable)) { // a dead live session: the failover attempt of the owner
            syncAttempt();
            emit changed();
        }
    });

    // AVPN (чипы доступности): проба «работает ли сервис через ЭТУ ноду» — с устройства через туннель
    // (бэкенд знать не может: доступность = f(юзер,сеть,регион,нода,время)). Все три меряются РЕАЛЬНОЙ
    // работоспособностью, а не reachability (иначе ложно-зелёный при DPI-троттлинге):
    //   • Telegram — login-free MTProto-handshake к seed-DC-IP (resPQ ⇒ дата-плейн жив);
    //   • YouTube/Instagram — GOODPUT: качаем ~128 КБ с реального душимого CDN (googlevideo/cdninstagram)
    //     и меряем kbit/s (RU-троттл ~128 кбит/с ⇒ slow; норм ⇒ works; путь срезан ⇒ blocked). См. ServiceProbe.h.
    {
        // Единый источник целей (seed-DC Telegram, fallback-SNI goodput) — avpn::defaultServiceProbeConfigs()
        // (ServiceProbeTargets.h): те же дефолты — база мержа applyRemoteProbeTargets, не расходятся.
        const QList<ServiceProbeConfig> cfgs = avpn::defaultServiceProbeConfigs();
        m_svcProbe = new ServiceProbe(m_nam, this);
        // AVPN backend-first (Task 4): m_svcCfgsAll — полный (нефильтрованный) список; rebuildServiceChips()
        // применяет lists.service_chips_disabled и заполняет И m_svcProbe (что пробится), И m_serviceStatus
        // (сидирует чипы state=-1 «неизвестно» в порядке cfgs — UI рисует их сразу). Пустой disabled-список
        // (default здесь — до первого /v1/config) => фильтр не убирает ничего, поведение как раньше.
        m_svcCfgsAll = cfgs;
        rebuildServiceChips();
        connect(m_svcProbe, &ServiceProbe::result, this,
                [this](const QString &key, int state, int rttMs) {
                    // rttMs для goodput-сервисов несёт метрику качества (kbit/s или TTFB), для telegram — RTT мс.
                    static const char *stName[] = {"blocked", "slow", "works"};
                    auto nameOf = [](int s) { return (s >= 0 && s <= 2) ? stName[s] : "unknown"; };
                    // AVPN чипы v2 (2026-07-12, анти-флап): сырой вердикт НЕ пишется в UI напрямую —
                    // через гистерезис (ChipLogic::chipHystStep): ухудшение показывается только после
                    // chip_confirm_n согласных прогонов ПОДРЯД (между ними — быстрая пере-проба ниже),
                    // восстановление — с первого успешного, unknown не понижает известное.
                    const int confirmN = qBound(1, int(avpn::TuningStore::numberOr(
                            QStringLiteral("chip_confirm_n"), 2.0)), 5);
                    const avpn::ChipHystStep stp =
                            avpn::chipHystStep(m_chipHyst.value(key), state, confirmN);
                    m_chipHyst.insert(key, stp.next);
                    qInfo("[AVPN svc] %s raw=%s shown=%s metric=%d%s",
                          key.toUtf8().constData(), nameOf(state), nameOf(stp.next.shown), rttMs,
                          stp.wantConfirm ? " (confirm pending)" : "");
                    for (int i = 0; i < m_serviceStatus.size(); ++i) {
                        QVariantMap m = m_serviceStatus.at(i).toMap();
                        if (m.value(QStringLiteral("key")).toString() == key) {
                            m[QStringLiteral("state")] = stp.next.shown;
                            m[QStringLiteral("rttMs")] = rttMs;
                            m[QStringLiteral("stale")] = false; // свежий вердикт ЭТОЙ ноды
                            m_serviceStatus[i] = m;
                            break;
                        }
                    }
                    emit serviceStatusChanged();
                    // Быстрое подтверждение ухудшения (вместо ожидания 3-мин self-heal): пере-проба
                    // одного сервиса через chip_confirm_ms. Бюджет 3 на серию — защита от шторма
                    // «ухудшился→отскочил→ухудшился» (сброс бюджета в probeServices).
                    if (stp.wantConfirm && m_chipConfirms.value(key, 0) < 3) {
                        m_chipConfirms.insert(key, m_chipConfirms.value(key, 0) + 1);
                        const int confirmMs = qBound(1000, int(avpn::TuningStore::numberOr(
                                QStringLiteral("chip_confirm_ms"), 8000.0)), 600000);
                        QTimer::singleShot(confirmMs, this, [this, key]() {
                            if (m_svcProbe && this->state() == QLatin1String("connected"))
                                m_svcProbe->probeOne(key);
                        });
                    }
                    // AVPN (анти-«вечно серый», 2026-07-03): Unknown (state=-1) = «не смогли измерить»
                    // (транзиент сразу после коннекта: маршруты/DNS не осели) — один авто-ретрай через
                    // 20с (per-key, per-connect: m_svcRetried сбрасывается в probeServices). Blocked
                    // сюда больше не входит — его перепроверяет confirm-цикл гистерезиса выше.
                    if (state == -1 && !m_svcRetried.contains(key)) {
                        m_svcRetried.insert(key);
                        // Server-driven (backend-first, Task 3): svc_probe_retry_ms, фолбэк 20с (прежнее).
                        // AVPN backend-first (final review R-3): клампим — 0/минус ретраил бы мгновенно
                        // (антипаттерн), сверху потолок 10 мин.
                        const int retryMs = qBound(1000, int(avpn::TuningStore::numberOr(
                                QStringLiteral("svc_probe_retry_ms"), 20000.0)), 600000);
                        QTimer::singleShot(retryMs, this, [this, key]() {
                            if (m_svcProbe && this->state() == QLatin1String("connected"))
                                m_svcProbe->probeOne(key);
                        });
                    }
                });
    }

    // AVPN remote-config (T6): вшитый публичный ключ (prod, key id k1) + дефолтные edges (baked —
    // обязателен по контракту ConfigService — фолбэк, если LKG-кеш ещё пуст на первом запуске).
    // ПОСЛЕ блока m_svcProbe (выше) НАРОЧНО: ConfigService::start() может синхронно эмитить
    // configApplied прямо из этого вызова (LKG-кеш готов мгновенно, без сети) → applyRemoteProbeTargets
    // должен застать УЖЕ созданный m_svcProbe, иначе серверный оверрайд probe-целей на холодном
    // офлайн-старте молча потерялся бы до следующего живого /v1/config (m_apiHostIps/carve-out эту
    // гонку не разделяют — они читаются из applyRuBypassSplit() в guardedStart(), намного позже ctor).
    // Remote-config signing key: prod by default; dev key only when a dev/E2E backend is pinned
    // via AVPN_API_URL (same env var read above for m_baseUrl override — keeps endpoint and key
    // selection consistent: dev endpoint ⇒ dev key, prod endpoint ⇒ prod key).
    const bool devApi = !qgetenv("AVPN_API_URL").isEmpty();
    const QString kConfigPubKeyHex = devApi
        ? QStringLiteral("95da1bd9062653d9c185c3ca5cae995516a8e353abccd3cf98cd12cd2f3a075a")
        : QStringLiteral("67bddcb248215a35ee2d8c2145ce415071ba02c5bcf888e35cc4491957aac78f");
    static const QStringList kBakedEdges{QStringLiteral("https://api.tribevpn.com"),
                                         QStringLiteral("https://vpn.wellwon.hk")};
    // 5.1.108: AVPN_API_URL pins the control plane - no stored edge, no edge walk to the prod edges.
    m_configPubKeyHex = kConfigPubKeyHex; // AVPN Scanner: the coordinator verifies the manifest with the same key
    m_configSvc = new avpn::ConfigService(m_nam, m_baseUrl, kConfigPubKeyHex, kBakedEdges, this, devApi);
    // S5 (device round 5): after a relaunch with the tunnel still up (the extension outlives the app) the first
    // requests leave through that tunnel before its first status arrives - the edge for a carrying tunnel from the
    // start; the first observed state corrects it either way (syncControlPlaneEdge).
    if (QSettings().value(QStringLiteral("avpn/tunnelCarrying"), false).toBool()) {
        m_sessionEdge = avpn::apiSessionEdgeFor(avpn::ApiRoute::Tunnel, m_configSvc->isPinned(),
                                                QString::fromLatin1(avpn::kWhoamiXrayEdge));
        m_configSvc->setSessionEdge(m_sessionEdge);
        if (!m_sessionEdge.isEmpty())
            m_baseUrl = m_configSvc->activeBaseUrl();
    }
    // AVPN upstream nodes: lease / standby / probe I/O with the same client, key and token as /v1 calls.
    // The direct base is read at each call (edge walk moves m_baseUrl).
    // S1 (device round 5): by the route the request takes NOW - through a tunnel that carries requests (seat-first
    // while the live session stays up) the edge reachable from its exit, otherwise the direct edge (a new leg, a
    // release after a stop: the session edge is cleared outside the carrying phase - syncControlPlaneEdge).
    m_tunnel.configureUpstream(m_nam, [this]() { return m_configSvc ? m_configSvc->activeBaseUrl() : m_baseUrl; },
                               kConfigPubKeyHex,
                               [this]() { return authToken(); });
    // AVPN (разбор 2026-09-23): IP ВСЕХ edge-кандидатов — в carve-out заранее: любой обычный старт
    // уже вырезает каждый вход, поэтому смена edge не требует перезапуска туннеля.
    resolveApiCarveHosts(avpn::edgeHosts(avpn::edgeCandidates(avpn::ConfigStore::loadEdges(), kBakedEdges)));
    connect(m_configSvc, &avpn::ConfigService::configApplied, this,
            [this](const avpn::RemoteConfig &c) {
                avpn::TuningStore::set(c.numbers, c.features, c.lists, c.urls); // AVPN backend-first (T19)
                // AVPN backend-first (T10): health-tick — server-tunable (numbers.health_tick_ms),
                // фолбэк 4000мс. setInterval на живом QTimer безопасен (Qt перезапускает с новым
                // интервалом, ничего не останавливаем/не стартуем).
                m_healthTimer.setInterval(avpn::healthTickMsTuned()); // кламп 1с..60с (0 с бэка = spin-loop)
                // AVPN backend-first: фоновый LKG-рефреш подписки по серверному интервалу
                // (H-3 бэклога). qBound — защита от абсурда: 10 мин..7 суток.
                const int refreshMs = qBound(600, c.subscriptionRefreshIntervalS, 7 * 24 * 3600) * 1000;
                // Periodic config checks must not postpone subscription refresh forever.
                if (!m_subRefreshTimer.isActive() || m_subRefreshTimer.interval() != refreshMs)
                    m_subRefreshTimer.start(refreshMs);
                m_remoteCfg = c;
                // AVPN (разбор 2026-09-23): новые edge с сервера — сразу в carve-out (см. resolveApiCarveHosts).
                if (!c.edges.isEmpty())
                    resolveApiCarveHosts(avpn::edgeHosts(c.edges));
                // AVPN (diag-report, Task 4 bff-3): timestamp применения конфига → возраст в отчёте.
                m_lastConfigAppliedEpoch = QDateTime::currentSecsSinceEpoch();
                // AVPN backend-first (T19): down/up speed-URL бенча — urls.bench_speed_down_url/
                // bench_speed_up_url с сервера, фолбэк = вкомпиленные литералы (BenchRunner ctor).
                if (m_bench)
                    m_bench->setSpeedUrls(
                        configUrl(QStringLiteral("bench_speed_down_url"),
                                  QStringLiteral("https://speed.cloudflare.com/__down?bytes=26214400")),
                        configUrl(QStringLiteral("bench_speed_up_url"),
                                  QStringLiteral("https://speed.cloudflare.com/__up")));
                // force-update вердикт: платформенная ветка — ЕДИНСТВЕННОЕ платформо-специфичное
                // место здесь (PLATFORM-SCOPING: serviceEngine общий, ветка строго под #ifdef Q_OS_*).
                const QString appVer = QStringLiteral(APP_VERSION);
                const QString plat = avpnPlatformKey();
                const avpn::UpdateVerdict v = avpn::compareVersions(
                    appVer, c.minAppVersion.value(plat), c.recommendedVersion.value(plat));
                // AVPN (self-update v2): 3 = текущая версия отозвана сервером (blocked_versions).
                // Приоритет: Block(2) > отозвана(3) > Recommend(1).
                m_updateState = (v == avpn::UpdateVerdict::Block) ? 2
                              : avpn::versionBlocked(c, plat, appVer) ? 3
                              : (v == avpn::UpdateVerdict::Recommend) ? 1 : 0;
                // AVPN (ревью 2026-09-22): LKG-кеш применяется синхронно ещё в конструкторе —
                // по нему ни «жива» (падение через секунды после окна не ловилось), ни тихая
                // установка (по старому blocked/URL ставилась уже отозванная версия).
                if (m_configSvc && m_configSvc->isFresh()) {
                    m_freshConfig = true;
                    avpn::LaunchGuard::instance().onConfigApplied(); // «жива»: окно + свежий конфиг
                    QTimer::singleShot(0, this, [this] { maybeAutoUpdate(); });
                }
#ifdef Q_OS_IOS
                // AVPN (iOS data watch, 141): a fresh signed config is in force - rewrite the extension's
                // plan after this handler (the transport mode is synced below).
                if (m_configSvc && m_configSvc->isFresh())
                    QTimer::singleShot(0, this, [this] { writeTunnelWatchPlan("config"); });
#endif
                applyRemoteProbeTargets(c); // переопределить probe-цели, если пришли с сервера
                refreshQualityEndpoints();  // AVPN (T16): urls.quality_probe_url мог смениться
                // 5.1.109 (S4.1): Xray forbidden -> the mode in force reads as Auto at once; allowed
                // again -> the stored choice "Xray" is admitted back, but only while nothing is
                // running (otherwise it waits for the engine to be idle). No tunnel restart here.
                syncTransportMode(QStringLiteral("config"));
                journalXrayPolicy();
                // AVPN upstream nodes (R11): stubs are dropped at parse while the switch is off (frozen off
                // on a cached config at cold start) - when it turns on, fetch the pool once again. The
                // standby pack is loaded / refreshed only while the switch is on.
                {
                    const bool upOn = avpn::upstreamNodesEnabled();
                    if (avpn::upstreamFlagFlippedOn(m_upstreamFlagWasOn, upOn)) {
                        reliabilityEvent(QStringLiteral("upstream_nodes on: subscription refresh"));
                        if (m_engine.hasSubscription())
                            QTimer::singleShot(0, this, [this]() { refreshSubscription(); });
                        loadStandbyPackFromDisk();
#if AVPN_UPSTREAM_GUI_OWNER
                        // A live Xray session adopted at startup (switch still frozen off then) may be an
                        // upstream one of the previous GUI: confirm its seat now.
                        if (m_lastTunnelState == Vpn::Connected)
                            m_tunnel.retryUpstreamAdoption();
#endif
                    }
                    m_upstreamFlagWasOn = upOn;
                    if (upOn && m_configSvc && m_configSvc->isFresh())
                        maybeRefreshStandby("start");
                }
                scanApplySwitches("config"); // AVPN Scanner: the client switches of this config
                emit changed();
            });
    connect(m_configSvc, &avpn::ConfigService::activeEdgeChanged, this,
            [this](const QString &base) {
                m_baseUrl = base;              // control plane переключился на живой вход (edge-walk)
                refreshQualityEndpoints();     // AVPN (T16): живые палочки — новый /v1/ping-хост
                reliabilityEvent(QStringLiteral("edge_switch to=%1").arg(QUrl(base).host().left(64)));
                rebuildApiCarveOut();          // новый хост — в carve-out (async резолв; туннель НЕ передёргиваем)
                emit apiBaseChanged(base);     // AVPN backend-first: сателлиты (чат поддержки) следуют за edge
#ifdef Q_OS_IOS
                AvpnDiagnostics_setBase(m_baseUrl.toUtf8().constData());
#endif
                emit changed();
            });

    // AVPN server-driven АнтиВПН (Task 10): сервис серверных bypass-списков (/v1/bypass-lists —
    // ru_cidrs/bypass_extra/cn_liauto_cidrs/split_dns, подпись+LKG). Тот же m_nam/kConfigPubKeyHex,
    // что у ConfigService — dev-эндпоинт ⇒ dev-ключ, prod ⇒ prod-ключ. baseUrl берём из
    // m_configSvc->activeBaseUrl() (НЕ из m_baseUrl напрямую): ConfigService уже создан и
    // поднял персистнутый edge на конструкции; activeEdgeChanged эмитится только при СМЕНЕ
    // edge, а не на холодном старте — если бы тут стоял m_baseUrl (ещё primary), а прод уже
    // персистнул рабочий edge с прошлой сессии, bypass-фетч бил бы в заблокированный primary
    // до первой смены edge (которая при живом primary может не наступить вовсе).
    // Kill-switch remote_bypass_lists реализован ВНУТРИ сервиса (onRemoteConfigApplied: при
    // флаге=false → пустой invalid снапшот в BypassListStore + фетч на паузу) ⇒ точки чтения
    // (applyRuBypassSplit / VpnConnectionTunnelControl) проверяют только bl.valid.
    // Порядок: создаём m_bypassListSvc и подключаем оба connect'а ДО m_configSvc->start() —
    // ConfigService::start() может синхронно эмитнуть configApplied на тёплом LKG-старте
    // (без сети), и если бы connect стоял после start(), это первое персистнутое состояние
    // флага remote_bypass_lists терялось бы: офлайн-сеанс мог целиком прожить со стейл-LKG
    // BypassListService вместо актуального флага. Реордер закрывает это окно: оба connect'а
    // гарантированно ловят даже синхронный первый configApplied. m_bypassListSvc->start()
    // (loadLkg + fetch) остаётся ПОСЛЕ m_configSvc->start() — сам старт не участвует в гонке.
    m_bypassListSvc = new avpn::BypassListService(m_nam, m_configSvc->activeBaseUrl(), kConfigPubKeyHex, this);
    connect(m_configSvc, &avpn::ConfigService::configApplied,
            m_bypassListSvc, &avpn::BypassListService::onRemoteConfigApplied);
    connect(m_configSvc, &avpn::ConfigService::activeEdgeChanged,
            m_bypassListSvc, &avpn::BypassListService::setBaseUrl);

    m_configSvc->start();
    m_bypassListSvc->start();

    // AVPN (Task 7): таймер авто-паузы «для покупок». Одноразовый: истёк → бездействие → resume.
    m_pauseTimer.setSingleShot(true);
    connect(&m_pauseTimer, &QTimer::timeout, this, &AvpnEngineQml::onPauseTimeout);

    // AVPN (reconcile-машина): единый сторож. Если терминальный колбэк туннеля (Connected/Disconnected)
    // не прилетит за таймаут (iOS NE иногда не рапортует чистый Disconnected) — разблокируем машину,
    // чтобы отложенный старт/стоп не залип навсегда. Один таймер (не накапливаем singleShot, как раньше).
    m_watchdog.setSingleShot(true);
    m_watchdog.setInterval(15000); // > 12с iOS handshake-timeout, чтобы не прерывать нормальный connect.
                                   // NB (аудит N9): для app-инициированных стартов именно ЭТОТ сторож
                                   // ограничивает ожидание (~1 handshake-таймаут); политика «3 таймаута»
                                   // в ios_controller работает для OS-инициированных стартов (интент/Настройки).
    connect(&m_watchdog, &QTimer::timeout, this, &AvpnEngineQml::onWatchdog);
    // Path engine (design 2026-11-17): the attempt owner's clock. Its deadlines count awake time (a late tick of a
    // frozen process counts at most clockJumpMs), so no freeze shift is needed here.
    m_transitionTimer.setInterval(500);
    connect(&m_transitionTimer, &QTimer::timeout, this, [this]() {
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        const qint64 since = m_lastTransitionTickMs < 0 ? m_transitionTimer.interval() : now - m_lastTransitionTickMs;
        m_lastTransitionTickMs = now;
#ifdef Q_OS_IOS
        tickTunnelWatchFreeze(since); // AVPN (iOS data watch, 141): the resume freeze rides on this tick
#else
        Q_UNUSED(since)
#endif
#if defined(Q_OS_IOS) || defined(MACOS_NE)
        if (m_permissionPromptPending)
            return; // the person reads the system's VPN dialog: no deadline runs meanwhile
#endif
        m_engine.attemptTick();
        if (syncAttempt())
            QTimer::singleShot(0, this, [this]() { reconcile(); });
    });
    m_transitionTimer.start();
    // AVPN (фикс-волна 2026-09-22, A1): ограниченные повторы запроса статуса и стопа (backoff).
    m_statusRetryTimer.setSingleShot(true);
    connect(&m_statusRetryTimer, &QTimer::timeout, this, [this]() {
#if defined(Q_OS_IOS) || defined(MACOS_NE)
        IosController::Instance()->requestReconcileStatus();
#endif
        reconcile(); // следующий шаг backoff (или исчерпание бюджета) решает reconcile
    });
    m_stopRetryTimer.setSingleShot(true);
    connect(&m_stopRetryTimer, &QTimer::timeout, this, &AvpnEngineQml::onStopRetryTimer);
    m_liveSessionTimer.setSingleShot(true);
    connect(&m_liveSessionTimer, &QTimer::timeout, this, &AvpnEngineQml::onLiveSessionTimeout);
    // AVPN (разбор 2026-09-23): каждый переход автомата заканчивается changed() — удержание фонового
    // времени iOS следует за ним (RestartGuard.h).
    connect(this, &AvpnEngineQml::changed, this, &AvpnEngineQml::syncRestartGuard);
#ifdef Q_OS_IOS
    // AVPN (iOS data watch, 141): the extension's `watch` snapshot (resume freeze) and the journal lines
    // of the On-Demand arming in the background. Both are inert while their flags are off.
    setupTunnelWatchResume();
    connect(IosController::Instance(), &IosController::tunnelWatchSnapshot, this,
            &AvpnEngineQml::onTunnelWatchSnapshot, Qt::QueuedConnection);
    connect(IosController::Instance(), &IosController::onDemandBackgroundEvent, this,
            [this](const QString &line) { reliabilityEvent(line); }, Qt::QueuedConnection);
    connect(IosController::Instance(), &IosController::tunnelEngineDown, this,
            &AvpnEngineQml::onTunnelEngineDown, Qt::QueuedConnection);
#endif
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    connect(IosController::Instance(), &IosController::sessionMetadataChanged, this,
            [this](const QVariantMap &metadata) {
#ifdef Q_OS_IOS
        // AVPN (iOS data watch, 141, stage 2): a switch the extension made is told in every status
        // reply; it is adopted from an ordinary poll too, whenever it arrives (TunnelWatchResume.h).
        if (m_watchResume)
            m_watchResume->onSessionMetadata(metadata);
#else
        Q_UNUSED(metadata);
#endif
        adoptNativeIdentity();
    }, Qt::QueuedConnection);
    connect(IosController::Instance(), &IosController::disconnectReason, this,
            [this](const QString &reason, bool intentional) {
        reliabilityEvent(QStringLiteral("native_disconnect=%1 intentional=%2")
                          .arg(reason.left(64)).arg(intentional));
        if (!intentional) return;
        // AVPN (A15, K2): натив гарантирует, что наш собственный стоп не intentional; если всё же
        // пришёл expected_app_stop во время СВОЕГО свитча движка — свитч не отменяем.
        if (!intentionalStopCancelsSwitch(reason,
                                          m_engine.state() == avpn::EngineState::Switching)) {
            reliabilityEvent(QStringLiteral("intentional_stop_ignored_in_switch"));
            return;
        }
        m_userIntentKnown = true;
        m_wantConnected = false;
        m_needsRestart = false;
        cancelStartPreparation();
        m_engine.requestStop();
        if (m_probe) m_probe->cancel();
    }); // Native marshals onto QObject affinity: reason must precede terminal state.
    // AVPN (фикс-волна 2026-09-22, A13/K3): Connect застал СВОЙ живой профиль (поднят Настройками/
    // Shortcuts/прошлым запуском). Натив не стартует поверх и не эмитит Error: отменяем свой
    // Op::Starting, движок забывает свою цель — следующий Connected адоптируется с identity из
    // sessionMetadata(). Намерение «вкл» — пользователь сам нажал Connect.
    connect(IosController::Instance(), &IosController::liveSessionFound, this, [this]() {
        reliabilityEvent(QStringLiteral("live_session_found op=%1").arg(int(m_op)));
        if (m_op == Op::Starting)
            settleOperation("live_session_found");
        cancelStartPreparation();
        m_engine.requestStop();          // onTunnelConnected() вернёт false → путь адопта
        m_latch.needStatusBeforeStart = false;
        m_statusRequestAttempts = 0;
        m_statusRetryTimer.stop();
        m_wantConnected = true;
        m_userIntentKnown = true;
        m_busy = true;                   // реальный статус приходит следом (vpnStatusDidChange)
        if (m_lastTunnelState == Vpn::Connected) { // факт уже был наблюдён — адопт сразу
            m_busy = false;
            m_liveSessionPending = false;
            m_liveSessionTimer.stop();
            if (tryAdoptObservedTunnel("live_session_found"))
                m_healthTimer.start();
        } else {
            // Ревью CL-A r2: ожидание реального статуса ограничено сторожем; Disconnected/Error до
            // Connected — сорвавшийся Connect (повтор старта), а не внешний обрыв с тихим снятием.
            m_liveSessionPending = true;
            m_liveSessionTimer.start(avpn::reconcileWatchdogMsTuned());
        }
        emit changed();
    });
    // AVPN (ревью CL-A r2, C4/K3): натив ждёт системный диалог «Разрешить VPN» (первая установка,
    // Face ID/код). Пока он открыт, сторож старта не должен звать guardedStop → disconnectVpn:
    // натив сменил бы поколение операции, поздний save отбросился бы, и первый коннект рвался.
    // Натив свой дедлайн на время диалога продлил (permissionPromptCapMs) — продлеваем и свой.
    connect(IosController::Instance(), &IosController::permissionPromptPending, this, [this](bool pending) {
        m_permissionPromptPending = pending;
        reliabilityEvent(QStringLiteral("permission_prompt pending=%1 op=%2").arg(pending).arg(int(m_op)));
        // The attempt owner's clock does not run while the dialog is open (the transition timer skips its
        // tick); the first tick after it counts at most clockJumpMs.
    });
    // The physical path for the native's journal of a session that never completed a handshake (an input of the
    // line only: the attempt owner decides about such a session, review of 18.11).
    IosController::Instance()->setUplinkProbe([] { return avpn::UplinkMonitor::instance()->physicalUp(); });
    // AVPN (A13/K4): итог rebind в NE → шаг лечения движка (performed=false = провал шага 1).
    connect(IosController::Instance(), &IosController::rebindFinished, this, [this](bool performed) {
        reliabilityEvent(QStringLiteral("rebind_result performed=%1").arg(performed));
        m_engine.onRebindResult(performed);
    });
#endif

    // AVPN (Task E): консьюмер «намерений» фонового iOS App Intent (Task 8). Интент в фоне уже
    // реально опустил/поднял туннель и записал флаг в App Group; при выходе в foreground натив-слой
    // (QtAppDelegate.mm → Avpn_consumeIntentFlags → AvpnIntentController.mm) эмитит сигналы моста.
    // Здесь согласуем СВОЁ состояние: pause → pauseForShopping (m_paused + гасим failover),
    // resume → resumeFromPause. На desktop мост молчит (Avpn_consumeIntentFlags — no-op).
    connect(avpn::AvpnIntentBridge::instance(), &avpn::AvpnIntentBridge::pauseRequested,
            this, [this]() { pauseForShopping(); });
    connect(avpn::AvpnIntentBridge::instance(), &avpn::AvpnIntentBridge::resumeRequested,
            this, &AvpnEngineQml::resumeFromPause);
    connect(AvpnIntentBridge::instance(), &AvpnIntentBridge::actionRequested, this,
            [this](const QVariantMap &action) {
        const QString generation = action.value(QStringLiteral("generation")).toString();
        if (generation.isEmpty() || generation == m_lastIntentGeneration
            || !action.value(QStringLiteral("applied")).toBool()) return;
        const QString kind = action.value(QStringLiteral("action")).toString();
        if (kind != QLatin1String("pause") && kind != QLatin1String("resume")) return;
        m_lastIntentGeneration = generation;
        settleOperation("intent_applied");
        m_busy = false;
        cancelStartPreparation();
        m_engine.requestStop(); // invalidate any pending GUI switch; native already applied intent.
        if (m_probe) m_probe->cancel();
        m_pauseTimer.stop();
        const bool pause = action.value(QStringLiteral("action")).toString() == QLatin1String("pause");
        const AppliedIntentState intent = appliedIntentState(pause, action.value(QStringLiteral("was_active")).toBool());
        m_paused = intent.paused;
        m_wasConnected = intent.resumeAfterPause;
        m_wantConnected = intent.wantConnected;
        m_userIntentKnown = true;
        m_needsRestart = false;
        // An applied envelope is an observation, not another stop/start request.
        // The original absolute deadline belongs to native; foreground never restarts its 90s.
        reliabilityEvent(pause ? QStringLiteral("intent_pause_applied")
                               : QStringLiteral("intent_resume_applied"));
#ifdef Q_OS_IOS
        if (pause && m_wasConnected) {
            const qint64 remaining = action.value(QStringLiteral("deadline_ms")).toLongLong()
                - QDateTime::currentMSecsSinceEpoch();
            QTimer::singleShot(int(qBound<qint64>(qint64(0), remaining, qint64(86400000))), Qt::PreciseTimer, this,
                              [this, generation]() {
                if (!Avpn_resumeIntentIfCurrent(generation)) return;
                m_paused = false;
                m_wasConnected = false;
                m_wantConnected = true;
                reconcile();
                emit changed();
            });
        }
#endif
#if defined(Q_OS_IOS) || defined(MACOS_NE)
        IosController::Instance()->requestReconcileStatus();
#endif
        emit changed();
    });

    // AVPN (Task 9 — APNs): мост пушей. Натив (AvpnPushController.mm) кладёт device token + окружение в
    // мост; здесь, получив deviceTokenReady, шлём токен на бэк авторизованно (Bearer subscription_token).
    // На desktop мост молчит (нет натив-регистратора). markAllRead из QML → readRequested → сброс
    // серверного счётчика. Singleton-мост, как AvpnIntentBridge.
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::deviceTokenReady,
            this, [this](const QString &token, const QString &platform, const QString &environment) {
                // AVPN (FCM 2026-07-13): платформа токена сквозная — бэк по ней выбирает
                // провайдера (ios→apns, android→fcm, POST /v1/devices/push-token).
                m_pushPlatform = platform;
                registerPushToken(token, environment);
            });
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::readRequested,
            this, &AvpnEngineQml::markNotificationsRead);
    // AVPN (read per-элемент): изменён read-статус / удалён элемент → синк на сервер ТОЛЬКО его.
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::readItemRequested,
            this, &AvpnEngineQml::markNotificationReadById);
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::deleteItemRequested,
            this, &AvpnEngineQml::deleteNotificationById);
    // AVPN (P-ANN): пуш «объявление» → немедленный рефреш списка (попап всплывает сразу).
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::announcementPushReceived,
            this, &AvpnEngineQml::refreshAnnouncements);

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (P-ANN, macOS): бейдж непрочитанных на иконке дока — питается unreadCount моста
    // (aps.badge на десктоп не приходит). Реализация — platforms/macos/AvpnDockBadge.mm.
    AvpnDockBadge_install();
#endif

    // AVPN (Task 9): разрешение на пуши спрашиваем ОДИН раз — после первого успешного коннекта (UX:
    // контекстный запрос). Persist, чтобы не пытаться при каждом коннекте (iOS и так дедупит промпт).
    {
        QSettings s;
        m_pushPermissionAsked = s.value(QStringLiteral("AvpnPush/permissionAsked"), false).toBool();
    }
    loadAnnouncementsLkg(); // AVPN (P-ANN): объявления из LKG до сети (fetch заменит после bootstrap)

    // реактивный failover + правдивый статус: реальное состояние туннеля. // AVPN
    if (m_conn) {
        connect(m_conn, &VpnConnection::connectionStateChanged,
                this, &AvpnEngineQml::onConnectionStateChanged, Qt::QueuedConnection);
        // AVPN: протокол-уровневые ошибки (ErrorCode) идут отдельным сигналом — раньше терялись.
        connect(m_conn, &VpnConnection::vpnProtocolError,
                this, &AvpnEngineQml::onVpnProtocolError, Qt::QueuedConnection);
    }

#ifdef Q_OS_ANDROID
    // AVPN (рассинхрон после фона, 2026-07-07): Android-активити при возврате из фона ре-байндится к
    // сервису и получает СНАПШОТ статуса (REQUEST_STATUS -> STATUS -> JNI onStatus -> сырой сигнал
    // status). До фикса цепочка была дырявой дважды: (1) апстрим слал фейковый Disconnected на каждый
    // onStop (убрано в AmneziaActivity -- состояние больше не «забывается» в фоне), (2) restore-сигнал
    // initConnectionState шёл в ванильный UI-контроллер МИМО VpnConnection/движка. Теперь движок
    // слушает СЫРОЙ AndroidController::status и адоптит ТОЛЬКО РАСХОЖДЕНИЕ факта с нашим состоянием:
    //  - факт Connected, мы «не connected» -> вернуть намерение + adoptTunnelConnected (воскреситель;
    //    покрывает холодный старт при живом туннеле и восстановление после РЕАЛЬНОГО обрыва байндинга
    //    -- те пути всё ещё шлют фейковый Disconnected);
    //  - факт Disconnected, мы «connected» -> честный Disconnected (туннель погас, пока были в фоне);
    //  - состояния согласованы -> НИЧЕГО (никаких пере-проб/вспышек при обычном возврате из фона).
    // Промежуточные снапшоты (Connecting/...) не трогаем -- терминал прилетит обычным путём.
    connect(AndroidController::instance(), &AndroidController::status, this,
            [this](AndroidController::ConnectionState st) {
                const bool thinkConnected = (state() == QLatin1String("connected"));
                if (st == AndroidController::ConnectionState::CONNECTED && !thinkConnected) {
                    m_wantConnected = true;
                    m_engine.adoptTunnelConnected();
                    onConnectionStateChanged(Vpn::Connected);
                } else if (st == AndroidController::ConnectionState::DISCONNECTED && thinkConnected) {
                    onConnectionStateChanged(Vpn::Disconnected);
                }
            },
            Qt::QueuedConnection);
#endif

    // AVPN (Task 11): тихий bootstrap при создании движка — наполнить подписку ДО первого Connect,
    // чтобы бейдж ГБ/дней/subActive был живой сразу. Дефер через singleShot(0): bootstrap() делает
    // синхронный сетевой вызов (QEventLoop), поэтому не блокируем конструктор/инициализацию UI —
    // отдаём управление циклу событий. КРАШ-ФИКС: singleShot(0) слишком рано — bootstrap крутит
    // вложенный QEventLoop, и если он сработает во время загрузки/показа QML, вложенный цикл
    // прокручивает чужие события (таймеры/фокус) на недостроенном дереве → re-entrancy SIGSEGV
    // (QQuickItem::setFocus). 1200мс гарантируют, что окно показано и loop простаивает (как при
    // пользовательском start()). Идемпотентно (m_bootstrapped). // AVPN
    QTimer::singleShot(1200, this, &AvpnEngineQml::bootstrap);

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (BUG-6, адопция при перезапуске GUI): демон держит туннель через выход GUI — спросить
    // его статус на старте и адоптировать живой туннель (см. probeDaemonTunnelOnStartup). 1500мс:
    // после показа окна; чисто async (QLocalSocket), вложенных QEventLoop нет — конфликт с
    // bootstrap(1200мс) исключён.
    QTimer::singleShot(1500, this, &AvpnEngineQml::probeDaemonTunnelOnStartup);
    // Проба ждёт ответа демона ≤3 с: до её конца Unknown — не «VPN выключен» (живой туннель
    // демона ещё не адоптирован), тихая установка ждёт (ревью 2026-09-22).
    QTimer::singleShot(1500 + 3000 + 500, this, [this] {
        m_daemonProbed = true;
        noteStartupTunnelObserved(); // 5.1.109 (S4.1): at the latest here; the probe tells it earlier
        maybeAutoUpdate();
    });
#else
    m_daemonProbed = true;
#endif

    // AVPN (LKG, C-7): мгновенный бейдж/пул из последнего удачного ответа /v1/subscription —
    // холодный старт не мигает «∞» и список серверов не пустой, пока сетевой bootstrap в пути.
    // Чистый парс без сети/QEventLoop — из конструктора безопасно. Источник правды — сервер:
    // успешный фетч перезапишет данные (loadSubscription снимет lkgStale). emit не нужен —
    // QML-биндинги читают Q_PROPERTY при первом создании, т.е. уже ПОСЛЕ этой строки.
    {
        const QByteArray lkg = Enrollment::loadLkgSubscription();
        QString lkgErr;
        if (!lkg.isEmpty() && !m_engine.loadSubscriptionFromLkg(lkg, lkgErr))
            qWarning() << "avpn: lkg subscription cache unusable:" << lkgErr; // не фатально: bootstrap догрузит
    }
    // AVPN awg31-xray-v1 (спека §2.3): локальные настройки транспорта — ручной режим (avpn/transportMode:
    // auto|awg|xray, незнакомое = auto) и the path engine's evidence ledger (avpn/pathLedger, versioned JSON - a
    // broken value reads as empty). Без сети/QEventLoop — из конструктора безопасно.
    // 5.1.109 (S4.1): the engine gets the stored CHOICE here, BEFORE restorePin() below: "Auto" and
    // "Amnezia" are in force at once and a pin the mode cannot serve is refused and stays saved, as
    // before 139. "Xray" waits for the startup observation (TransportModeGate.h); on 138 a stored
    // "xray" read here while the cached config froze Xray became Auto for the whole run and never
    // came back. A "xray" written by 138 or earlier may be stale and is dropped once. The journal
    // lines of this call are written at the end of the constructor (applyModeChange).
    {
        QSettings s;
        const avpn::ServiceEngine::ModeChange loaded = m_engine.loadTransportModeChoice(
            s.value(QStringLiteral("avpn/transportMode"), QStringLiteral("auto")).toString(),
            s.value(QStringLiteral("avpn/transportModeByChoice"), false).toBool());
        if (loaded.storeChoice) {
            s.setValue(QStringLiteral("avpn/transportMode"), avpn::transportModeToString(loaded.storedMode));
            s.setValue(QStringLiteral("avpn/transportModeByChoice"), true);
        }
        bool devLedgerReset = false;
#ifdef AVPN_DEV_TOOLS
        // R6 (device round 4, development builds only): Documents/tribe-reset-ledger -> start from an empty ledger once.
        {
            const QString control = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
                                  + QStringLiteral("/tribe-reset-ledger");
            if (QFile::exists(control)) {
                s.remove(QLatin1String(kPathLedgerSettingsKey));
                QFile::remove(control);
                qWarning() << "[avpn dev] path ledger reset by the control file";
                devLedgerReset = true;
            }
        }
#endif
        m_engine.loadPathLedger(s.value(QLatin1String(kPathLedgerSettingsKey)).toByteArray());
        m_reliabilityRing.lines = s.value(QStringLiteral("avpn/reliabilityLog")).toStringList().mid(0, 128);
        if (devLedgerReset)
            m_reliabilityRing.lines.prepend(QStringLiteral("ledger_reset why=dev_control_file"));
        m_savedPinCountry = s.value(QStringLiteral("avpn/pinnedCountry")).toString(); // review E8: the preference survives a pool without the node
        m_savedPin = s.value(QStringLiteral("avpn/pinnedNode")).toString();
        restorePin();
    }

    // AVPN (фикс «на сотовой ∞ навсегда»): единый member-таймер ретрая bootstrap (вместо
    // одноразовых singleShot) — kickBootstrap() может его поджать при появлении сети/foreground.
    m_bootstrapRetryTimer.setSingleShot(true);
    connect(&m_bootstrapRetryTimer, &QTimer::timeout, this, &AvpnEngineQml::tryBootstrapSubscription);

    // AVPN (фикс «на сотовой ∞ навсегда»): появление сети / смена Wi-Fi↔сотовая → поджать ретрай.
    // ТОЛЬКО ускоряет фетч подписки, когда она ещё не загружена (kickBootstrap — no-op после
    // успеха); туннель/коннект/выбор ноды НЕ трогает — хождение между роутерами с поднятым VPN
    // сюда не попадает. loadDefaultBackend идемпотентен (второй вызов в benchExtra — ок).
    // AVPN (store-flow E, 2026-07-09): foreground-рефреш подписки НА УРОВНЕ ДВИЖКА. Раньше жил
    // только в PageConnectTribe (Connections на Qt.application), а вкладки существуют ПО ОДНОЙ
    // (goToTabBarPageUrl = clear+replace) → вернулся из браузера после оплаты на вкладке
    // Поддержка/Настройки — рефреша НЕ было, бейдж/золотая CTA стейл до захода на главную.
    // Движок живёт всегда → покрывает все страницы и платформы. Троттл 30с (как у QML-пути;
    // QML-путь в PageConnectTribe оставлен — он же дёргает kickBootstrap/refreshAccount; лишний
    // параллельный GET /v1/subscription в момент резюма дёшев и безвреден). Async, no-op без токена.
    // Волна-4 (P2-4): ОДИН координатор выхода на экран. Раньше на каждый Inactive→Active (Пункт
    // управления, системный алерт, свап окон) срабатывали пять независимых обработчиков (движок,
    // PageConnectTribe, Настройки, чат, журнал) — 5–8 запросов на открытие, их таймауты после
    // заморозки кормили смену API-эджа. Теперь: возврат после реальной заморозки/скрытия (или
    // долгого Inactive на десктопе), дебаунс 1 с, одна пачка (onForegroundDebounced).
    m_fgTimer.setSingleShot(true);
    m_fgTimer.setInterval(1000);
    connect(&m_fgTimer, &QTimer::timeout, this, &AvpnEngineQml::onForegroundDebounced);
    if (auto *guiApp = qobject_cast<QGuiApplication *>(QCoreApplication::instance())) {
        connect(guiApp, &QGuiApplication::applicationStateChanged, this,
                [this](Qt::ApplicationState st) {
                    const qint64 now = QDateTime::currentMSecsSinceEpoch();
                    if (st == Qt::ApplicationSuspended || st == Qt::ApplicationHidden) {
#ifdef Q_OS_IOS
                        // AVPN (iOS data watch, 141; §5.5 step 1): the first transition to background -
                        // the On-Demand arming may hold background time (features.ios_on_demand_bg_arm).
                        if (!m_hiddenSeen)
                            IosController::Instance()->noteAppBackground(
                                featureEnabled(QStringLiteral("ios_on_demand_bg_arm"), false),
                                avpn::iosOnDemandBgArmMaxSTuned() * 1000);
#endif
                        m_hiddenSeen = true;
                        m_lastHiddenMs = now;
                        return;
                    }
                    if (st == Qt::ApplicationInactive) {
                        if (m_lastInactiveMs < 0)
                            m_lastInactiveMs = now;
                        return;
                    }
                    if (st != Qt::ApplicationActive)
                        return;
                    m_lastResumeMs = now; // P2-2: запросы, начатые раньше, пережили заморозку
                    // AVPN (разбор 2026-09-23): на экране фоновое время не нужно; защёлку истечения
                    // снимаем, чтобы следующий уход в фон посреди перезапуска снова был защищён.
                    m_restartGuard.onForeground();
                    syncRestartGuard();
                    // AVPN (белые списки): foreground-триггер детектора (детектор дебаунсит сам).
                    if (m_whitelistDetector)
                        m_whitelistDetector->noteForeground();
                    const qint64 inactiveFor = m_lastInactiveMs > 0 ? now - m_lastInactiveMs : 0;
                    const bool hidden = m_hiddenSeen;
                    m_hiddenSeen = false;
                    m_lastInactiveMs = -1;
                    if (!foregroundIsReturn(hidden, inactiveFor))
                        return;
#ifdef Q_OS_IOS
                    // AVPN (iOS data watch, 141): refresh the extension's plan (the kill switch too). The
                    // hand-over itself needs no call here: a process that was suspended is recognised by
                    // its overdue tick (TunnelWatchResume.h).
                    writeTunnelWatchPlan("foreground");
#endif
                    m_fgTimer.start();
                });
    }

    if (QNetworkInformation::loadDefaultBackend()) {
        if (auto *ni = QNetworkInformation::instance()) {
            connect(ni, &QNetworkInformation::reachabilityChanged, this,
                    [this](QNetworkInformation::Reachability r) {
                        // Волна-4 (P2-6): наш же utun up/down — не смена сети; замер RTT цел.
                        // Grace-окно HealthLoop и отмена пробы остаются (ревью: без них — ложный DEAD).
                        if (networkChangeIsOwnTunnel(m_op != Op::None, m_lastOwnOpMs,
                                                     QDateTime::currentMSecsSinceEpoch())) {
                            facadeNoteNetworkChange(m_engine);
                            if (m_probe) m_probe->cancel();
                            reliabilityEvent(QStringLiteral("network_change_ignored own_tunnel"));
                        } else {
                            invalidateNetworkMeasurements();
                        }
                        if (r == QNetworkInformation::Reachability::Online) {
                            kickBootstrap();
#if defined(AMNEZIA_DESKTOP) && !defined(MACOS_NE)
                            // AVPN (wake-реконнект): сеть вернулась после сна — ретрай нашего
                            // wake-рестарта (кап внутри wakeKick). 1.5с — DHCP/DNS доседают.
                            if (m_wakeRestartPending)
                                QTimer::singleShot(1500, this, [this]() { wakeKick(); });
#endif
                        }
                    });
            connect(ni, &QNetworkInformation::transportMediumChanged, this,
                    [this](QNetworkInformation::TransportMedium) {
                        if (networkChangeIsOwnTunnel(m_op != Op::None, m_lastOwnOpMs,
                                                     QDateTime::currentMSecsSinceEpoch())) {
                            facadeNoteNetworkChange(m_engine);
                            if (m_probe) m_probe->cancel();
                            reliabilityEvent(QStringLiteral("network_change_ignored own_tunnel"));
                        } else {
                            invalidateNetworkMeasurements();
                        }
                        kickBootstrap();
                    });
        }
    }

    // AVPN (волна-3, 2026-09-28): физический аплинк. Вернулась сеть, а намерение ждёт её
    // (попытки старта без сети не считаются) — поднимаем туннель через 1,5 с (DHCP/DNS доседают).
    connect(avpn::UplinkMonitor::instance(), &avpn::UplinkMonitor::changed, this, [this](bool up) {
        reliabilityEvent(QStringLiteral("uplink %1").arg(up ? QStringLiteral("up") : QStringLiteral("down")));
        if (!up || !m_wantConnected || !m_waitUplink)
            return;
        m_waitUplink = false;
        QTimer::singleShot(1500, this, [this]() {
            if (m_wantConnected && m_lastTunnelState != Vpn::Connected)
                reconcile();
        });
    });
    // Волна-3: §16-сторож десктопа не дождался ответа демона — упал компонент, не пользователь.
    // Следующий Disconnected классифицируется как Component (намерение держим, старт ждёт службу).
    connect(m_conn, &VpnConnection::daemonLost, this, [this]() {
        m_componentLost = true;
        m_componentLostMs = QDateTime::currentMSecsSinceEpoch();
        reliabilityEvent(QStringLiteral("daemon_lost"));
    });

    // AVPN (журнал тестирования, Tribe-Backend docs/specs/2026-09-23-tester-journal-design.md):
    // отправляет только приложение (туннель лишь пишет ne.log по флагу App Group). Досылка: при
    // включении, выходе на экран, раз в 15 минут на экране, при уходе в фон (фоновое время iOS) и
    // кнопкой «Отправить накопленное». Все события — no-op, пока журнал выключен.
    m_journal = new avpn::TribeJournalUploader(
        m_nam, [this]() { return m_baseUrl; }, [this]() { return authToken(); }, this);
    connect(m_journal, &avpn::TribeJournalUploader::statusChanged, this, &AvpnEngineQml::journalChanged);
#ifdef Q_OS_IOS
    // Фоновое время отпускаем, только когда очередь досылок пуста: досылка из очереди без него
    // замерзала посреди запроса (разбор журнала 24.09: «Отправляем…» по полчаса).
    connect(m_journal, &avpn::TribeJournalUploader::idle, this,
            []() { TribeJournalIos_endBackground(); });
#endif
    m_journalTimer.setInterval(15 * 60 * 1000);
    connect(&m_journalTimer, &QTimer::timeout, this, [this]() { m_journal->flush(QStringLiteral("timer")); });
    if (auto *guiApp = qobject_cast<QGuiApplication *>(QCoreApplication::instance())) {
        connect(guiApp, &QGuiApplication::applicationStateChanged, this, [this](Qt::ApplicationState st) {
            if (!avpn::TribeJournal::active())
                return;
            if (st == Qt::ApplicationActive) {
                avpn::TribeJournal::append(QStringLiteral("app_foreground"));
                m_journalTimer.start();
                // Запрос, начатый перед заморозкой iOS, мёртв — не ждём его таймаута.
                m_journal->kickIfStale(15000);
                m_journal->flush(QStringLiteral("foreground"));
            } else if (st == Qt::ApplicationSuspended || st == Qt::ApplicationHidden) {
                avpn::TribeJournal::append(QStringLiteral("app_background"),
                                           {{QStringLiteral("tunnel"), state()}});
                m_journalTimer.stop();
#ifdef Q_OS_IOS
                TribeJournalIos_beginBackground(
                    []() { avpn::TribeJournal::append(QStringLiteral("journal_bg_expired")); });
#endif
                m_journal->flush(QStringLiteral("background"));
            }
        });
    }
    // Start the app's path monitor now (iOS nw_path_monitor, Android ScanAppNetwork): its first path arrives
    // asynchronously, and until then networkKind() can only fall back to the platform medium.
    (void)networkKind();
    if (auto *ni = QNetworkInformation::instance()) {
        auto netEvent = [this, ni]() {
            QString reach;
            switch (ni->reachability()) {
            case QNetworkInformation::Reachability::Online: reach = QStringLiteral("online"); break;
            case QNetworkInformation::Reachability::Disconnected: reach = QStringLiteral("disconnected"); break;
            case QNetworkInformation::Reachability::Local: reach = QStringLiteral("local"); break;
            case QNetworkInformation::Reachability::Site: reach = QStringLiteral("site"); break;
            default: reach = QStringLiteral("unknown"); break;
            }
            // The physical network (networkKind - the Scanner's answer; Qt's medium is Unknown under any VPN on
            // iOS) and the radio generation only on cellular (CoreTelephony names it on Wi-Fi too).
            const QString kind = networkKind();
            // Оператор (MCC-MNC) и поколение сотовой — отличить блокировку оператором от сбоя ноды.
            avpn::TribeJournal::append(QStringLiteral("net"),
                                       {{QStringLiteral("reach"), reach},
                                        {QStringLiteral("medium"), kind.isEmpty() ? QStringLiteral("unknown") : kind},
                                        {QStringLiteral("carrier"), avpn::carrierCode()},
                                        {QStringLiteral("gen"), avpn::cellularGenerationForKind(kind, avpn::cellularGeneration())},
                                        {QStringLiteral("metered"), avpn::meteredState()}});
        };
        connect(ni, &QNetworkInformation::reachabilityChanged, this, netEvent);
        connect(ni, &QNetworkInformation::transportMediumChanged, this, netEvent);
        // Path engine: the network generation (an attempt in flight restarts on the new network).
        auto netKey = [this]() {
            m_engine.observeNetwork(currentNetworkObservation());
            if (syncAttempt())
                QTimer::singleShot(0, this, [this]() { reconcile(); });
        };
        connect(ni, &QNetworkInformation::reachabilityChanged, this, netKey);
        connect(ni, &QNetworkInformation::transportMediumChanged, this, netKey);
        connect(ni, &QNetworkInformation::transportMediumChanged, this, [this]() { scanNotifyNetwork(); }); // AVPN Scanner
    }
    // Ответы control plane: метод, путь без идентификаторов, код. Только пути API (/v1, /admin) —
    // запросы к сторонним хостам (бенч, пробы) сюда не попадают; саму досылку журнала не пишем.
    connect(m_nam, &QNetworkAccessManager::finished, this, [](QNetworkReply *r) {
        if (!avpn::TribeJournal::active())
            return;
        const QString path = r->url().path();
        if (!(path.startsWith(QLatin1String("/v1/")) || path.startsWith(QLatin1String("/admin/")))
            || path == QLatin1String("/v1/diag/journal"))
            return;
        QStringList parts = path.split(QLatin1Char('/'), Qt::SkipEmptyParts);
        static const QRegularExpression word(QStringLiteral("^([a-z_\\-]+|v[0-9]+)$"));
        for (QString &p : parts) {
            if (!word.match(p).hasMatch())
                p = QStringLiteral(":id");
        }
        QString op;
        switch (r->operation()) {
        case QNetworkAccessManager::GetOperation: op = QStringLiteral("GET"); break;
        case QNetworkAccessManager::PostOperation: op = QStringLiteral("POST"); break;
        case QNetworkAccessManager::PutOperation: op = QStringLiteral("PUT"); break;
        case QNetworkAccessManager::DeleteOperation: op = QStringLiteral("DELETE"); break;
        default: op = QStringLiteral("OTHER"); break;
        }
        QJsonObject f{{QStringLiteral("method"), op},
                      {QStringLiteral("path"), QLatin1Char('/') + parts.join(QLatin1Char('/'))},
                      {QStringLiteral("host"), r->url().host()},
                      {QStringLiteral("code"), r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()}};
        // Длительность — у запросов, заведённых через armTimeout (метка старта на reply).
        const QVariant t0 = r->property("avpn_t0");
        if (t0.isValid())
            f.insert(QStringLiteral("ms"), QDateTime::currentMSecsSinceEpoch() - t0.toLongLong());
        if (r->error() != QNetworkReply::NoError)
            f.insert(QStringLiteral("net_error"), int(r->error()));
        avpn::TribeJournal::append(QStringLiteral("http"), f);
    });
    // Переходы туннеля (все переходы автомата заканчиваются changed()).
    connect(this, &AvpnEngineQml::changed, this, [this]() {
        if (!avpn::TribeJournal::active())
            return;
        const QString st = state();
        if (st == m_journalLastState)
            return;
        avpn::TribeJournal::append(QStringLiteral("tunnel"),
                                   {{QStringLiteral("from"), m_journalLastState}, {QStringLiteral("to"), st}});
        m_journalLastState = st;
    });
    syncJournal();
    // 5.1.109 (S4.1): what the load of the stored transport-mode choice wrote, and why Xray is allowed
    // or frozen at this start. Here, not where the cached config and the choice were read above: by
    // now the reliability ring is restored (an earlier line would have overwritten the stored ring)
    // and the tester journal is switched on.
    // "Xray" is not in force yet: it waits for the startup observation - the first tunnel status on
    // iOS / macOS NE, the end of the daemon probe on the macOS service (probeDaemonTunnelOnStartup).
    // Elsewhere Xray is never usable and "Auto" / "Amnezia" are in force from load.
    applyModeChange(avpn::ServiceEngine::ModeChange());
    journalXrayPolicy(/*atStart=*/true);
    // Every transition of the facade ends with changed(): the choice that waits is admitted when
    // nothing is running any more, and what the engine decided for an adopted session is journalled.
    connect(this, &AvpnEngineQml::changed, this, &AvpnEngineQml::syncTransportModeIdle);

    // AVPN (белые списки, спека 2026-07-12): детектор дифф-проб «РКН-whitelist на сотовой».
    // Только мобилки (PLATFORM-SCOPING): на десктопе сотовая — экзотика, гейт снимем позже.
    // m_nam — общий QNAM движка: при опущенном туннеле (единственное состояние, когда детектор
    // пробует — гейт tunnelIdle) запросы идут напрямую по сотовой сети. Создаётся ПОСЛЕ
    // loadDefaultBackend — детектору нужен живой QNetworkInformation::instance().
#if defined(Q_OS_IOS) || defined(Q_OS_ANDROID)
    m_whitelistDetector = new avpn::WhitelistDetector(
        m_nam, [this]() { return state() == QStringLiteral("disconnected"); }, this);
    connect(m_whitelistDetector, &avpn::WhitelistDetector::activeChanged, this, [this](bool on) {
        if (on) {
            m_whitelistEpisodeStartMs = QDateTime::currentMSecsSinceEpoch();
        } else {
            // Эпизод кончился — в локальную очередь телеметрии (кап 10 FIFO; шлём при первом
            // успешном контакте с control plane — в момент эпизода сеть мертва по определению).
            if (m_whitelistEpisodeStartMs > 0) {
                QSettings st;
                QJsonArray arr = QJsonDocument::fromJson(
                    st.value(QStringLiteral("Whitelist/episodes")).toByteArray()).array();
                QJsonObject ep;
                ep.insert(QStringLiteral("started_at"), double(m_whitelistEpisodeStartMs / 1000));
                ep.insert(QStringLiteral("ended_at"),
                          double(QDateTime::currentMSecsSinceEpoch() / 1000));
                ep.insert(QStringLiteral("net_type"), QStringLiteral("cellular"));
                arr.append(ep);
                while (arr.size() > 10)
                    arr.removeFirst();
                st.setValue(QStringLiteral("Whitelist/episodes"),
                            QJsonDocument(arr).toJson(QJsonDocument::Compact));
                st.sync();
                m_whitelistEpisodeStartMs = 0;
                m_whitelistEpisodesSent = false; // свежий эпизод — разрешить отправку
            }
            if (m_whitelistAcked) {
                m_whitelistAcked = false;   // новый эпизод покажет попап снова
                emit whitelistAckedChanged();
            }
            kickBootstrap();                // сеть вернулась — немедленно к нормальному циклу
        }
        emit whitelistModeChanged();
    });
    // Второй источник сигналов control plane — фетчи /v1/config (bootstrap-цепочка — первый).
    if (m_configSvc) {
        connect(m_configSvc, &avpn::ConfigService::transportFailed, m_whitelistDetector,
                &avpn::WhitelistDetector::noteControlPlaneFailure);
        connect(m_configSvc, &avpn::ConfigService::transportOk, m_whitelistDetector,
                &avpn::WhitelistDetector::noteControlPlaneOk);
    }
#endif
}

// AVPN remote-config (T6): фичефлаг/URL из последнего применённого /v1/config (LKG на старте,
// свежий — после первого успешного fetch). Ключ отсутствует на сервере → def.
bool AvpnEngineQml::featureEnabled(const QString &key, bool def) const
{
    return avpn::featureFlag(m_remoteCfg, key, def);
}

QString AvpnEngineQml::configUrl(const QString &key, const QString &def) const
{
    return m_remoteCfg.urls.value(key, def);
}

// AVPN remote-config (T6): магазинная ссылка для баннера апдейта/CTA — urls.store_ios/store_android
// с сервера (можно поменять без ребилда, напр. сменить регион стора), фолбэк вшитый.
// AVPN (реш. владельца 2026-09-02): «Обновить» на десктопном macOS ставит новую версию сама.
// URL образа — server-driven (urls.macos_dmg_url) с вкомпиленным фолбэком; хост-гард и все проверки
// подписи/нотаризации/версии — внутри SelfUpdate (там же причина отказа человеческим текстом).
// Ключ платформы для карт min_app_version/recommended_version. ЕДИНСТВЕННОЕ платформо-специфичное
// место в этом файле (PLATFORM-SCOPING: serviceEngine общий, ветка строго под #ifdef Q_OS_*).
static QString avpnPlatformKey()
{
#if defined(Q_OS_IOS)
    return QStringLiteral("ios");
#elif defined(Q_OS_ANDROID)
    return QStringLiteral("android");
#elif defined(Q_OS_MACOS)
    return QStringLiteral("macos");
#elif defined(Q_OS_WIN)
    return QStringLiteral("windows");
#else
    return QStringLiteral("linux");
#endif
}

QString AvpnEngineQml::appVersion() const
{
    const QStringList parts = QStringLiteral(APP_VERSION).split(QLatin1Char('.'));
    return parts.mid(0, 3).join(QLatin1Char('.'));
}

QString AvpnEngineQml::appBuild() const
{
    const QStringList parts = QStringLiteral(APP_VERSION).split(QLatin1Char('.'));
    return parts.size() >= 4 ? parts.at(3) : QString();
}

QString AvpnEngineQml::availableVersion() const
{
    const QString plat = avpnPlatformKey();
    const QString rec = m_remoteCfg.recommendedVersion.value(plat);
    return rec.isEmpty() ? m_remoteCfg.minAppVersion.value(plat) : rec;
}

void AvpnEngineQml::startSelfUpdate()
{
    startSelfUpdateInternal(/*background=*/false);
}

// ── AVPN (self-update v2) ─────────────────────────────────────────────────────────────────────
bool AvpnEngineQml::autoUpdate() const
{
    return QSettings().value(QStringLiteral("AvpnSettings/autoUpdate"), true).toBool();
}

void AvpnEngineQml::setAutoUpdate(bool on)
{
    if (autoUpdate() == on)
        return;
    QSettings s;
    s.setValue(QStringLiteral("AvpnSettings/autoUpdate"), on);
    s.sync();
    emit autoUpdateChanged();
    if (on)
        QTimer::singleShot(0, this, [this] { maybeAutoUpdate(); });
    else if (m_selfUpdate && m_selfUpdate->running() && m_selfUpdateBackground) {
        m_selfUpdateTunnelCancel = true; // выключили тумблер — не попытка, не пауза
        m_selfUpdate->cancel();
    }
}

bool AvpnEngineQml::canRollback() const
{
    const avpn::LaunchGuard &g = avpn::LaunchGuard::instance();
    if (!g.hasPrevious() || g.previousVersion() == QStringLiteral(APP_VERSION).split(QLatin1Char('.')).mid(0, 3).join(QLatin1Char('.')))
        return false;
    if (avpn::versionBlocked(m_remoteCfg, avpnPlatformKey(), g.previousVersion()))
        return false;
    // Не откатываем ниже min_app_version: человек упрётся в принудительный экран обновления.
    return avpn::compareVersions(g.previousVersion(), m_remoteCfg.minAppVersion.value(avpnPlatformKey()),
                                 QString()) != avpn::UpdateVerdict::Block;
}

bool AvpnEngineQml::newerAvailable() const
{
    const QString plat = avpnPlatformKey();
    const QString target = m_remoteCfg.recommendedVersion.value(plat);
    return !target.isEmpty()
        && avpn::compareVersions(QStringLiteral(APP_VERSION), QString(), target) == avpn::UpdateVerdict::Recommend
        && !avpn::versionBlocked(m_remoteCfg, plat, target);
}

QString AvpnEngineQml::previousVersion() const
{
    return avpn::LaunchGuard::instance().previousVersion();
}

void AvpnEngineQml::dismissRollbackNotice()
{
    if (m_rollbackNotice.isEmpty())
        return;
    m_rollbackNotice.clear();
    QSettings s;
    s.remove(QStringLiteral("AvpnUpdate/notice"));
    s.sync();
    emit rollbackNoticeChanged();
}

void AvpnEngineQml::rollbackToPrevious()
{
    if (!canRollback()) {
        emit selfUpdateFailed(tr("Предыдущей версии для возврата нет"));
        return;
    }
    if (m_selfUpdate && m_selfUpdate->running())
        m_selfUpdate->cancel();
    if (!avpn::LaunchGuard::instance().rollbackToPrevious(QStringLiteral("blocked"))) {
        emit selfUpdateFailed(tr("Не удалось запустить возврат предыдущей версии"));
        return;
    }
    m_selfUpdateStage = tr("Возвращаем предыдущую версию…");
    emit selfUpdateChanged();
    qInfo() << "[launchguard] rollback requested by user (blocked) — quitting";
    m_appExitKind = avpn::AppExitKind::Restart; // upstream nodes (point 15): a relaunch, not a quit
    QTimer::singleShot(1500, qApp, &QCoreApplication::quit);
}

// Отчёт об откате прошлого запуска — тихо в /v1/bench/report (та же схема, что краш-отчёты;
// kill-switch crash_report). Оптимистичный сброс, как у CrashGuard: дубль хуже редкой потери.
void AvpnEngineQml::launchGuardFlushReport()
{
    QSettings st;
    const QString json = st.value(QStringLiteral("AvpnUpdate/pendingReport")).toString();
    if (json.isEmpty())
        return;
    if (!featureEnabled(QStringLiteral("crash_report"), true))
        return;
    if (authToken().isEmpty())
        return; // ещё нет токена — попробуем следующим таймером
    uploadReport(json, /*quiet=*/true);
    st.remove(QStringLiteral("AvpnUpdate/pendingReport"));
    st.sync();
}

// Тихая установка: только при выключенном туннеле, не более 3 попыток на версию, пауза 6 ч
// после неудачи, никогда — версию, с которой уже откатывались, и версию из blocked_versions.
void AvpnEngineQml::maybeAutoUpdate()
{
    if (!avpn::SelfUpdate::isSupported() || !autoUpdate())
        return;
    if (m_updateState != 1 && m_updateState != 3)
        return;
    if (m_selfUpdate && m_selfUpdate->running())
        return;
    if (!m_freshConfig || !m_daemonProbed)
        return; // только по свежему /v1/config и после пробы демона (ревью 2026-09-22)
    if (!tunnelSteadyForUpdate())
        return; // туннель активен — ждём onConnectionStateChanged
    const QString plat = avpnPlatformKey();
    const QString target = m_remoteCfg.recommendedVersion.value(plat);
    const QString marketing = QStringLiteral(APP_VERSION).split(QLatin1Char('.')).mid(0, 3).join(QLatin1Char('.'));
    QSettings st;
    // Финишер (после нашего quit) не смог заменить/запустить версию — он оставил маркер;
    // ставим паузу 6 ч, иначе следующий старт сразу жёг бы следующую попытку.
    {
        const QString marker = avpn::LaunchGuard::instance().stateDir() + QStringLiteral("/finisher_failed");
        QFile f(marker);
        if (f.open(QIODevice::ReadOnly)) {
            const QList<QByteArray> parts = f.readAll().trimmed().split(' ');
            f.close();
            QFile::remove(marker);
            if (parts.size() == 2 && !parts.at(0).isEmpty())
                st.setValue(QStringLiteral("AvpnUpdate/lastFail_") + QString::fromUtf8(parts.at(0)),
                            parts.at(1).toLongLong());
        }
    }
    // Текущая версия отозвана сервером, а рекомендованной новее нет — сами возвращаем
    // сохранённую предыдущую копию (спека §4.2). Один раз: rolledBack помнит эту версию.
    if (m_updateState == 3 && canRollback()
        && !(avpn::compareVersions(marketing, QString(), target) == avpn::UpdateVerdict::Recommend
             && !avpn::versionBlocked(m_remoteCfg, plat, target))
        && st.value(QStringLiteral("AvpnUpdate/rolledBack")).toString() != marketing) {
        st.setValue(QStringLiteral("AvpnUpdate/rolledBack"), marketing);
        st.sync();
        qWarning() << "[selfupdate] current version" << marketing << "is blocked — auto rollback to"
                   << previousVersion();
        rollbackToPrevious();
        return;
    }
    if (target.isEmpty() || target == marketing)
        return;
    if (avpn::compareVersions(marketing, QString(), target) != avpn::UpdateVerdict::Recommend)
        return; // цель не новее текущей — не наш случай
    if (avpn::versionBlocked(m_remoteCfg, plat, target))
        return;
    if (st.value(QStringLiteral("AvpnUpdate/rolledBack")).toString() == target)
        return;
    const int attempts = st.value(QStringLiteral("AvpnUpdate/attempts_") + target, 0).toInt();
    if (attempts >= 3)
        return;
    const qint64 lastFail = st.value(QStringLiteral("AvpnUpdate/lastFail_") + target, 0).toLongLong();
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (lastFail > 0 && now - lastFail < 6 * 3600)
        return;
    st.setValue(QStringLiteral("AvpnUpdate/attempts_") + target, attempts + 1);
    st.sync();
    qInfo() << "[selfupdate] auto-update" << marketing << "->" << target << "attempt" << attempts + 1;
    startSelfUpdateInternal(/*background=*/true);
}

bool AvpnEngineQml::tunnelSteadyForUpdate() const
{
    // Реш. владельца 2026-09-23: обновление качается и ставится и при ВКЛЮЧЁННОМ VPN — в РФ без
    // туннеля tribevpn.com/Apple режутся, и «только при выключенном» не скачивалось никогда. На macOS
    // выход GUI туннель не гасит (root-демон, BUG-6), новая копия адоптирует его
    // (probeDaemonTunnelOnStartup). Нельзя только посреди перехода: подключаемся/переключаемся/
    // гасим или цикл авто-переподключения (Error/Disconnected при желании быть подключённым).
    if (m_op != Op::None)
        return false;
    switch (m_lastTunnelState) {
    case Vpn::Connected:
        return true;
    case Vpn::Disconnected:
    case Vpn::Error:
        return !m_wantConnected;
    case Vpn::Unknown:
        return m_daemonProbed && !m_wantConnected; // до пробы демона Unknown может скрывать туннель
    default:
        return false;
    }
}

void AvpnEngineQml::ensureSelfUpdate()
{
    if (m_selfUpdate)
        return;
    m_selfUpdate = new avpn::SelfUpdate(this);
    connect(m_selfUpdate, &avpn::SelfUpdate::progress, this, [this](const QString &t) {
        m_selfUpdateStage = t;
        emit selfUpdateChanged();
        emit selfUpdateProgress(t);
    });
    connect(m_selfUpdate, &avpn::SelfUpdate::downloadProgress, this, [this](int pct) {
        if (m_selfUpdatePercent == pct)
            return;
        m_selfUpdatePercent = pct;
        emit selfUpdateChanged();
    });
    connect(m_selfUpdate, &avpn::SelfUpdate::failed, this, [this](const QString &r) {
        const bool background = m_selfUpdateBackground;
        m_selfUpdateBackground = false;
        m_selfUpdateStage.clear();
        m_selfUpdatePercent = -1;
        const bool tunnelCancel = m_selfUpdateTunnelCancel;
        m_selfUpdateTunnelCancel = false;
        if (background) {
            // Тихая попытка не удалась: без всплывающих окон, баннер с кнопкой остаётся.
            QSettings st;
            const QString attemptsKey = QStringLiteral("AvpnUpdate/attempts_") + m_selfUpdateTarget;
            if (tunnelCancel || m_selfUpdate->lastFailureDeferred()) {
                // Отложено (включили VPN, сеть, образ не той версии) — попытку не засчитываем.
                st.setValue(attemptsKey, qMax(0, st.value(attemptsKey, 0).toInt() - 1));
            }
            if (!tunnelCancel) // отмена туннелем — без паузы: поставим, как только VPN выключат
                st.setValue(QStringLiteral("AvpnUpdate/lastFail_") + m_selfUpdateTarget,
                            QDateTime::currentSecsSinceEpoch());
            st.sync();
            qWarning() << "[selfupdate] background update failed:" << r
                       << (tunnelCancel ? "(tunnel came up)" : m_selfUpdate->lastFailureDeferred() ? "(deferred)" : "");
        } else {
            emit selfUpdateFailed(r);
        }
        m_selfUpdateTarget.clear();
        emit selfUpdateChanged();
    });
    // installed(): образ проверен и подготовлен; финишер (nohup, скрипт SelfUpdate) ЖДЁТ
    // выхода нашего процесса (до 30 с), затем подменяет бандл и запускает новую версию.
    // Выйти обязаны МЫ: под живым процессом подмена + `open -a` новую копию не запускают —
    // LaunchServices лишь активирует старый инстанс (проверено 2026-09-04, MAC-29), и человек
    // оставался на старой версии до ручного перезапуска. Экрану даём показать «Готово,
    // перезапускаем…», затем штатный quit (aboutToQuit флашит настройки; живой туннель
    // остаётся у демона и адоптируется новой копией, §19).
    connect(m_selfUpdate, &avpn::SelfUpdate::installed, this, [this]() {
        m_selfUpdateStage = tr("Готово, перезапускаем приложение…");
        m_selfUpdatePercent = 100;
        emit selfUpdateChanged();
        emit selfUpdateInstalled();
        qInfo() << "[selfupdate] installed — quitting so the finisher can relaunch the new version";
        m_appExitKind = avpn::AppExitKind::Restart; // upstream nodes (point 15): the new copy adopts the session
        QTimer::singleShot(1500, qApp, &QCoreApplication::quit);
    });
}

void AvpnEngineQml::startSelfUpdateInternal(bool background)
{
#if defined(Q_OS_ANDROID)
    // Android always shows its own confirmation, so there is no silent background attempt.
    if (!background)
        startAndroidSelfUpdate();
    return;
#endif
    if (!avpn::SelfUpdate::isSupported()) {
        if (!background)
            emit selfUpdateFailed(tr("Обновление внутри приложения тут недоступно"));
        return;
    }
    ensureSelfUpdate();
    if (m_selfUpdate->running()) {
        // Уже идёт тихая установка, а человек нажал кнопку — просто показываем её ход.
        if (!background && m_selfUpdateBackground) {
            m_selfUpdateBackground = false;
            emit selfUpdateChanged();
        }
        return;
    }
    // Маркетинговая версия (первые три компонента APP_VERSION) — нижняя граница: образ со
    // старой/равной версией скрипт не поставит.
    const QStringList parts = QStringLiteral(APP_VERSION).split(QLatin1Char('.'));
    const QString marketing = parts.mid(0, 3).join(QLatin1Char('.'));
    const QString plat = avpnPlatformKey();
    avpn::SelfUpdate::StartOptions opts;
    opts.stateDir = avpn::LaunchGuard::instance().stateDir();
    if (opts.stateDir.isEmpty())
        opts.stateDir = avpn::LaunchGuard::defaultStateDir();
    opts.background = background;
    opts.blocked = m_remoteCfg.blockedVersions.value(plat);
    // Ставим ровно рекомендованную сервером версию (ссылка на образ могла разойтись с ней).
    opts.expectedVersion = m_remoteCfg.recommendedVersion.value(plat);
    if (background) // тихая: последний гейт — туннель всё ещё выключен в момент передачи
        opts.mayCommit = [this] {
            // посреди перехода туннеля — отложить без паузы и без сжигания попытки: продолжим,
            // как только туннель встанет (onConnectionStateChanged → maybeAutoUpdate).
            const bool ok = tunnelSteadyForUpdate();
            if (!ok)
                m_selfUpdateTunnelCancel = true;
            return ok;
        };
    m_selfUpdateBackground = background;
    m_selfUpdateTunnelCancel = false;
    m_selfUpdateTarget = availableVersion();
    m_selfUpdatePercent = -1;
    m_selfUpdateStage = tr("Скачиваем и проверяем подпись…");
    emit selfUpdateChanged();
    m_selfUpdate->start(configUrl(QStringLiteral("macos_dmg_url"), avpn::SelfUpdate::defaultDmgUrl()),
                        marketing, opts);
    if (!m_selfUpdate->running()) // отказ до старта (URL/скрипт) — failed() уже эмитирован
        emit selfUpdateChanged();
}


#if defined(Q_OS_ANDROID)
bool AvpnEngineQml::canSelfUpdate() const
{
    return avpn::AndroidSelfUpdate::isSupported();
}

bool AvpnEngineQml::selfUpdateBusy() const
{
    return avpn::AndroidSelfUpdate::instance()->running();
}

// AVPN (owner decision 2026-11-16): «Update» on Android downloads the site APK from /dl/
// (urls.store_android), checks package, signer and version (ApkUpdatePolicy.h) and hands it to
// Android's own installer dialog. Same UI as macOS: TribeUpdateGate/Sheet read selfUpdateStage,
// selfUpdatePercent and selfUpdateFailed.
void AvpnEngineQml::startAndroidSelfUpdate()
{
    auto *up = avpn::AndroidSelfUpdate::instance();
    if (!m_androidUpdateWired) {
        m_androidUpdateWired = true;
        connect(up, &avpn::AndroidSelfUpdate::progress, this, [this](const QString &t) {
            m_selfUpdateStage = t;
            emit selfUpdateChanged();
            emit selfUpdateProgress(t);
        });
        connect(up, &avpn::AndroidSelfUpdate::downloadProgress, this, [this](int pct) {
            if (m_selfUpdatePercent == pct)
                return;
            m_selfUpdatePercent = pct;
            emit selfUpdateChanged();
        });
        connect(up, &avpn::AndroidSelfUpdate::awaitingConfirmation, this, [this] {
            m_selfUpdatePercent = -1;
            m_selfUpdateStage = tr("Подтвердите обновление в окне Android");
            emit selfUpdateChanged();
            emit selfUpdateProgress(m_selfUpdateStage);
        });
        connect(up, &avpn::AndroidSelfUpdate::failed, this, [this](const QString &r) {
            m_selfUpdateStage.clear();
            m_selfUpdatePercent = -1;
            m_selfUpdateTarget.clear();
            emit selfUpdateChanged();
            emit selfUpdateFailed(r);
        });
        connect(up, &avpn::AndroidSelfUpdate::installed, this, [this] {
            m_selfUpdateStage = tr("Готово, откройте приложение заново");
            m_selfUpdatePercent = 100;
            emit selfUpdateChanged();
            emit selfUpdateProgress(m_selfUpdateStage);
        });
    }
    if (up->running())
        return;
    m_selfUpdateBackground = false;
    m_selfUpdateTarget = availableVersion();
    m_selfUpdatePercent = -1;
    m_selfUpdateStage = tr("Скачиваем обновление…");
    emit selfUpdateChanged();
    up->start(configUrl(QStringLiteral("store_android"), QStringLiteral("https://tribevpn.com/dl/TribeVPN.apk")),
              m_remoteCfg.recommendedVersion.value(QStringLiteral("android")));
    emit selfUpdateChanged();
}
#endif

QString AvpnEngineQml::storeUrl() const
{
#if defined(Q_OS_ANDROID)
    return m_remoteCfg.urls.value(QStringLiteral("store_android"),
        QStringLiteral("https://play.google.com/store/apps/details?id=com.tribevpn.client"));
#elif defined(Q_OS_WIN)
    // Connect audit 2026-11-04: Windows has no store; the installer is served from /dl/ (the
    // backend always sends urls.store_windows since PR #570). Before, Windows got the App Store link.
    return m_remoteCfg.urls.value(QStringLiteral("store_windows"),
        QStringLiteral("https://tribevpn.com/dl/TribeVPN.exe"));
#elif defined(Q_OS_LINUX)
    // No Linux build is published (no urls key for it): the site's download section, not the App Store.
    return QStringLiteral("https://tribevpn.com/#download");
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // Desktop macOS updates itself (SelfUpdate); the link is the same image the self-update uses.
    return configUrl(QStringLiteral("macos_dmg_url"), avpn::SelfUpdate::defaultDmgUrl());
#else
    return m_remoteCfg.urls.value(QStringLiteral("store_ios"),
        QStringLiteral("https://apps.apple.com/app/id6778394015"));
#endif
}

// AVPN remote-config (T6): вынесенный API/edge-хост carve-out (см. .h) — применяет вырез к
// КОНКРЕТНОМУ сев-набору sites. Вызывается ВНУТРИ applyRuBypassSplit РОВНО там же, где раньше
// был инлайн-блок — behaviour-preserving extraction, поведение на исходном месте не меняется.
// AVPN: ЕДИНЫЙ источник carve-IP control plane — и для фактического выреза (rebuildApiCarveOut),
// и для стампа сева (bypassSeedStamp). Ревью 2026-07-10: раньше стамп собирал этот же список
// вручную — добавление carve-IP в одном месте без другого дало бы «seed unchanged — skip» при
// реально изменившемся севе (стале-маршрут для control plane = инцидент 2026-07-05).
QStringList AvpnEngineQml::apiCarveIps() const
{
    // Built-in fallback: the live RU edge of api.tribevpn.com (Timeweb, DNS-only; Beget 159.194.214.36
    // is gone). The current address is also carved at runtime: m_apiHostIps holds what the API hosts
    // resolve to (resolveApiCarveHosts), so a later move is covered without a release. It matters
    // only if a server-driven bypass list covers the address (the compiled ru_prefixes does not).
    QStringList ips{QStringLiteral("201.34.134.103")};
    for (const QHostAddress &ip : std::as_const(m_apiHostIps))
        ips << ip.toString();
    return ips;
}

void AvpnEngineQml::rebuildApiCarveOut(QMap<QString, QStringList> &sites) const
{
    // AVPN carve-out (incident 2026-07-05): the API host was then on Beget, inside ru_prefixes, so the
    // control plane went around the tunnel and the operator cut it: an empty app without subscription
    // or nodes while the WG tunnel was alive. The API IPs are carved out of the seed (covering CIDRs
    // split without the /32; the rest of the RU net stays direct). The current Timeweb address
    // 201.34.134.103 is in no compiled ru_prefixes CIDR: the carve is a no-op unless a server-driven
    // list covers it. Compiled fallback + async-resolved IPs = the single list apiCarveIps().
    const QStringList ips = apiCarveIps();
    for (const QString &ip : ips)
        carveOutIpFromSites(sites, QHostAddress(ip));
}

// AVPN remote-config (T6): «новый активный edge — в carve-out». Резолвит host(m_baseUrl) (уже
// переключён вызывающим activeEdgeChanged-обработчиком) в m_apiHostIps (async QHostInfo, тот же
// паттерн, что в конструкторе для исходного m_baseUrl; накопительно — не теряем IP предыдущих
// edge, лишний carve-out безвреден). Вырез применяется при СЛЕДУЮЩЕМ обычном старте:
// guardedStart() → applyRuBypassSplit() → rebuildApiCarveOut(sites) со свежим m_apiHostIps
// (стамп сева учитывает apiCarveIps(), пересев не пропустится).
// AVPN (разбор 2026-09-23, журнал iPhone владельца): раньше здесь стоял reapplyBypass() — смена
// edge передёргивала живой туннель (guardedStop "reconcile_restart"). Ложные «три отказа подряд»
// (запросы, пережившие заморозку iOS или гибель чужого VPN) давали смену edge при каждом возврате
// в приложение, а iOS замораживала приложение между стопом и стартом → VPN выключен до следующего
// открытия. Для текущих edge маршрут от выреза не зависит (IP api.tribevpn.com — во вкомпиленном
// фолбэке apiCarveIps(), vpn.wellwon.hk вне RU-префиксов), поэтому перезапуск ничего не давал.
// Инвариант держит tests/check_edge_switch_no_restart.sh.
void AvpnEngineQml::rebuildApiCarveOut()
{
    resolveApiCarveHosts({QUrl(m_baseUrl).host()});
}

// AVPN (разбор 2026-09-23): IP хостов control plane → m_apiHostIps (накопительно, без дублей).
// Литерал-IP добавляется сразу (раньше не вырезался вовсе), имя — async QHostInfo. Провал резолва
// не страшен: в apiCarveIps() всегда есть вкомпиленный фолбэк. Туннель не трогает.
void AvpnEngineQml::resolveApiCarveHosts(const QStringList &hosts)
{
    for (const QString &host : hosts) {
        if (host.isEmpty())
            continue;
        const QHostAddress literal(host);
        if (!literal.isNull()) {
            if (!m_apiHostIps.contains(literal))
                m_apiHostIps.append(literal);
            QStringList &mine = m_apiHostIpsByHost[host.toLower()]; // AVPN Scanner: knownHostIps
            if (!mine.contains(literal.toString()))
                mine << literal.toString();
            continue;
        }
        QHostInfo::lookupHost(host, this, [this, host](const QHostInfo &info) {
            if (info.error() != QHostInfo::NoError)
                return;
            QStringList &mine = m_apiHostIpsByHost[host.toLower()]; // AVPN Scanner: knownHostIps
            for (const QHostAddress &ip : info.addresses()) {
                if (!m_apiHostIps.contains(ip))
                    m_apiHostIps.append(ip);
                if (!mine.contains(ip.toString()))
                    mine << ip.toString();
            }
        });
    }
}

// AVPN remote-config (T6): сервер может переопределить цели проб чипов (probeTargets из
// /v1/config) — напр. сменить seed-хост без ребилда. МЕРЖ с вшитыми дефолтами, НЕ замещение:
// семантика, kind-гейт (только явные "mtproto"/"goodput"/"https"; "tcp" = данные арбитра — игнор)
// и multi-seed-группировка — в avpn::mergeRemoteProbeTargets (ServiceProbeTargets.h, там же
// разбор инцидента 2026-07-11 «Telegram красный / Instagram серый» и TDD-контракт).
void AvpnEngineQml::applyRemoteProbeTargets(const avpn::RemoteConfig &cfg)
{
    if (!m_svcProbe)
        return;
    // AVPN backend-first (Task 4 + мерж ci-build 9ad41a45): серверные probe-цели МЕРЖАТСЯ с вшитыми
    // дефолтами (avpn::mergeRemoteProbeTargets — kind-гейт, multi-seed-группировка), НЕ замещают их.
    // Результат мержа кладётся в m_svcCfgsAll (полный нефильтрованный набор); rebuildServiceChips()
    // применит lists.service_chips_disabled к смерженному набору и пересоберёт m_svcProbe->setServices
    // + m_serviceStatus (иначе дрейф чипов при remote override). Пустой disabled-список → фильтр
    // прозрачен, поведение байт-в-байт как в 9ad41a45.
    m_svcCfgsAll = avpn::mergeRemoteProbeTargets(avpn::defaultServiceProbeConfigs(), cfg.probeTargets);
    rebuildServiceChips();
}

// AVPN backend-first (T16): цели QualityProbe (живые палочки) следуют за edge-walk и
// urls.quality_probe_url. Свой бэкенд-пинг всегда первый приоритет; публичный generate_204 —
// фолбэк-литерал байт-в-байт как в конструкторном сиде, если сервер URL не прислал.
void AvpnEngineQml::refreshQualityEndpoints()
{
    if (!m_probe)
        return;
    m_probe->setEndpoints({livePingUrl(),
                           configUrl(QStringLiteral("quality_probe_url"),
                                     QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))});
}

// The ping follows the transport like whoami does: on Xray api.tribevpn.com is the entry host of the
// same path (review of 138; routing per platform - WhoamiVerdict.h whoamiBaseUrl).
QString AvpnEngineQml::livePingUrl() const
{
    return avpn::liveProbePingUrl(m_baseUrl, avpn::isXrayProto(m_engine.currentNodeProto()),
                                  !qgetenv("AVPN_API_URL").isEmpty());
}

// The transport is known only once a node is up and may change on a switch inside the location, so
// the target is checked right before each measurement; endpoints() is compared by membership because
// QualityProbe moves the last good endpoint to the front.
void AvpnEngineQml::measureLiveProbe()
{
    if (!m_probe)
        return;
    if (!m_probe->endpoints().contains(livePingUrl()))
        refreshQualityEndpoints();
    m_probe->measure();
}

// AVPN backend-first (Task 4): пер-сервисный kill-switch чипов доступности (lists.service_chips_disabled).
// Отфильтровывает m_svcCfgsAll (полный набор — ctor-дефолт telegram/youtube/instagram ЛИБО remote
// probeTargets из applyRemoteProbeTargets) по серверному списку отключённых ключей:
//   · m_svcProbe получает ТОЛЬКО включённые cfgs → probeAll()/probeOne() физически не пробуют
//     отключённый сервис (не тратят трафик через туннель);
//   · m_serviceStatus ПЕРЕСТРАИВАЕТСЯ ЦЕЛИКОМ (не мержится point-wise) под тот же набор → отключённый
//     чип пропадает из UI (QML TribeServiceChips дата-driven от serviceStatus, правок не требует).
// Уже известные состояния (works/slow/blocked/rttMs) сохраняются по key для сервисов, оставшихся
// включёнными — повторный вызов не сбрасывает их обратно в «неизвестно».
// Пустой/отсутствующий список (TuningStore::listOr «пусто=фолбэк») → фильтр не убирает ничего,
// поведение байт-в-байт как до задачи.
void AvpnEngineQml::rebuildServiceChips()
{
    if (!m_svcProbe)
        return;

    const QStringList disabled =
            avpn::TuningStore::listOr(QStringLiteral("service_chips_disabled"), {});
    QList<ServiceProbeConfig> enabled;
    enabled.reserve(m_svcCfgsAll.size());
    for (const ServiceProbeConfig &c : std::as_const(m_svcCfgsAll)) {
        if (!disabled.contains(c.key))
            enabled.append(c);
    }
    m_svcProbe->setServices(enabled);

    auto labelOf = [](const QString &k) {
        if (k == QLatin1String("telegram"))  return QStringLiteral("Telegram");
        if (k == QLatin1String("youtube"))   return QStringLiteral("YouTube");
        if (k == QLatin1String("instagram")) return QStringLiteral("Instagram");
        if (k == QLatin1String("whatsapp"))  return QStringLiteral("WhatsApp"); // AVPN (Доктор v1)
        return k;
    };
    QHash<QString, QVariantMap> prevByKey;
    for (const QVariant &v : std::as_const(m_serviceStatus)) {
        const QVariantMap m = v.toMap();
        prevByKey.insert(m.value(QStringLiteral("key")).toString(), m);
    }
    QVariantList next;
    next.reserve(enabled.size());
    for (const ServiceProbeConfig &c : std::as_const(enabled)) {
        const auto it = prevByKey.constFind(c.key);
        if (it != prevByKey.constEnd()) {
            next.append(it.value()); // сохраняем известный state/rttMs для уже пробитого сервиса
        } else {
            QVariantMap m;
            m[QStringLiteral("key")] = c.key;
            m[QStringLiteral("label")] = labelOf(c.key);
            m[QStringLiteral("state")] = -1;
            m[QStringLiteral("rttMs")] = -1;
            m[QStringLiteral("stale")] = false; // v2: приглушение QML читает этот флаг
            next.append(m);
        }
    }
    if (next != m_serviceStatus) {
        m_serviceStatus = next;
        emit serviceStatusChanged();
    }
}

// AVPN BUG-13 (2026-07-30): чипы → «не проверено» (синий), гистерезис и бюджеты серии — с нуля.
// Зовётся на входе в connected: вердикты прошлой ноды/сессии к новому туннелю отношения не имеют,
// а показывать их как текущие (особенно красный) — врать пользователю.
void AvpnEngineQml::resetServiceChipsToUnknown()
{
    if (m_svcProbe)
        m_svcProbe->invalidate(); // in-flight результаты прошлой серии не должны дописаться
    m_chipHyst.clear();
    m_chipConfirms.clear();

    bool changed = false;
    for (int i = 0; i < m_serviceStatus.size(); ++i) {
        QVariantMap m = m_serviceStatus.at(i).toMap();
        if (m.value(QStringLiteral("state"), -1).toInt() != -1
            || m.value(QStringLiteral("rttMs"), -1).toInt() != -1
            || m.value(QStringLiteral("stale"), false).toBool()) {
            m[QStringLiteral("state")] = -1;
            m[QStringLiteral("rttMs")] = -1;
            m[QStringLiteral("stale")] = false;
            m_serviceStatus[i] = m;
            changed = true;
        }
    }
    if (changed)
        emit serviceStatusChanged();
}

QString AvpnEngineQml::state() const
{
    // AVPN (Task 7): «paused» — наша надстройка над фазами движка (туннель реально down, ждём
    // авто-возврат). Перекрывает disconnected, чтобы UI отличал паузу-для-покупок от обычного стопа.
    if (m_paused)
        return QStringLiteral("paused");
    return debugSnapshot().value(QStringLiteral("state")).toString();
}

// AVPN (белые списки): активный РКН-режим whitelist (детектор жив только на iOS/Android).
bool AvpnEngineQml::whitelistMode() const
{
    return m_whitelistDetector && m_whitelistDetector->active();
}

void AvpnEngineQml::setWhitelistAcked(bool on)
{
    if (m_whitelistAcked == on)
        return;
    m_whitelistAcked = on;
    emit whitelistAckedChanged();
}

// AVPN: текущее устройство — нативная маркетинговая модель/ОС (DeviceModel.h). Перекрывают
// невнятный backend-label (часто «macos») в разделе «Устройства».
QString AvpnEngineQml::thisDeviceName() const { return avpn::deviceMarketingName(); }
QString AvpnEngineQml::thisDeviceOs() const { return avpn::deviceOsName(); }

// AVPN: статус подписки (Task 3) — единый источник debugSnapshot() (как state()).
qlonglong AvpnEngineQml::trafficUsed() const
{
    return debugSnapshot().value(QStringLiteral("trafficUsed")).toLongLong();
}

qlonglong AvpnEngineQml::trafficLimit() const
{
    return debugSnapshot().value(QStringLiteral("trafficLimit")).toLongLong();
}

// AVPN: JWT подписки из защищённого стора — для редиректа в кабинет с авторизацией.
QString AvpnEngineQml::authToken() const
{
    return Enrollment::loadToken();
}

bool AvpnEngineQml::subActive() const
{
    return debugSnapshot().value(QStringLiteral("subStatus")).toString() == QLatin1String("active");
}

// AVPN (баг 2026-07-10 «вечная загрузка без подписки»): достоверное «подписки нет» = снапшот
// degraded (бэк ставит его ТОЛЬКО по состоянию устройства: expired/over-quota/без tunnel_ip)
// И пул пуст. active+пустой пул (все ноды в дренаже у подписанного) сюда не попадает; до
// первого распарсенного тела subStatus пуст → false («ещё грузится», не CTA).
bool AvpnEngineQml::subMissing() const
{
    return debugSnapshot().value(QStringLiteral("subStatus")).toString() == QLatin1String("degraded")
           && !m_engine.hasSubscription();
}

// AVPN (жалоба 2026-09-29): subStatus пуст ровно до первого разобранного тела (живого или LKG).
bool AvpnEngineQml::subLoaded() const
{
    return !m_engine.debugSnapshot().subStatus.isEmpty();
}

bool AvpnEngineQml::subOffline() const
{
    return decideSubUiState(subLoaded(), m_bootstrapRetries) == SubUiState::Offline;
}

QString AvpnEngineQml::localDeviceId() const
{
    // installation-UUID из secure-store — стабильный, генерится на первом запуске, тот же уходит
    // на backend при enroll (=> совпадает с devices.device_id). Доступен всегда, без сети.
    return Identity::deviceId(m_store);
}

int AvpnEngineQml::daysLeft() const
{
    const QString iso = debugSnapshot().value(QStringLiteral("expiresAt")).toString();
    if (iso.isEmpty())
        return -1; // бессрочно / неизвестно
    const QDateTime exp = QDateTime::fromString(iso, Qt::ISODate);
    if (!exp.isValid())
        return -1;
    const qint64 secs = QDateTime::currentDateTimeUtc().secsTo(exp.toUTC());
    // AVPN: округление ВВЕРХ (ceil), а не вниз — чтобы совпадало с админкой/бэкендом: «осталось
    // 6 дней 18 часов» = «7 дней» (раньше floor давал 6, юзер видел рассинхрон с выданными 7).
    return secs <= 0 ? 0 : static_cast<int>((secs + 86399) / 86400);
}

QString AvpnEngineQml::subExpiresAt() const
{
    return debugSnapshot().value(QStringLiteral("expiresAt")).toString();
}

// AVPN: текущий сервер для карточки Connect. Показываем ноду ТОЛЬКО когда реально подключены/
// переключаемся; до коннекта и после стопа hasNode=false → карточка показывает «Умный выбор сервера»
// (умный выбор происходит в момент connect, выбранная нода видна уже подключённой). Без fallback на
// pool.first() — иначе в простое показывалась «Польша».
QVariantMap AvpnEngineQml::currentNode() const
{
    const DebugSnapshot s = m_engine.debugSnapshot();
    const QString pinned = m_engine.pinnedNodeId();
    const bool connectedNow = (s.state == QLatin1String("connected"));
    // Какой узел показывать на карточке Connect:
    //  • ПОДКЛЮЧЕНЫ → реальный текущий узел (s.currentNodeId) — честно даже если failover увёл
    //    с закреплённого;
    //  • закреплён вручную И НЕ подключены (переключаемся/оффлайн) → закреплённый узел СРАЗУ
    //    (оптимистично): тап по Латвии в пикере мгновенно показывает Латвию + орб «подключаюсь»,
    //    а не висит на старой Польше 1–3 c до нового рукопожатия (жалоба 2026-07-20). Орб
    //    отражает реальное состояние отдельно — обмана нет;
    //  • авто-switching без pin → пока старый узел;
    //  • иначе → ничего (hasNode=false) → карточка «Умный выбор сервера».
    QString showId;
    // AVPN awg31-xray-v1: в verifying туннель поднят на реальной ноде — показываем её (как connected).
    // R4 (device round 4): while the owner walks, the card shows the server being tried now (the choice stays in
    // «Вы выбрали: …»), not the chosen one.
    if ((connectedNow || s.state == QLatin1String("verifying")
         || (m_engine.attemptRunning() && (s.state == QLatin1String("connecting") || s.state == QLatin1String("switching"))))
        && !s.currentNodeId.isEmpty())
        showId = s.currentNodeId;
    else if (!pinned.isEmpty())
        showId = pinned;
    else if (s.state == QLatin1String("switching") && !s.currentNodeId.isEmpty())
        showId = s.currentNodeId;
    const NodeDebugRow *pick = nullptr;
    if (!showId.isEmpty()) {
        for (const NodeDebugRow &r : s.pool)
            if (r.nodeId == showId) { pick = &r; break; }
    }
    // AVPN (A5, жалоба владельца 2026-09-23): туннель поднят и усыновлён, но движок не опознал ноду
    // сессии (нода удалена/пересоздана, сменился порт) — раньше карточка писала «Умный выбор
    // сервера» при работающем VPN. Показываем честный факт из подсказки сессии: ноду пула с тем же
    // id или хостом, иначе сам адрес. Identity движка (health/failover) это не меняет.
    QString hintOnlyEndpoint;
    if (!pick && (connectedNow || s.state == QLatin1String("verifying")) && s.currentNodeId.isEmpty()) {
        const ServiceEngine::SessionHint hint = m_engine.sessionHint();
        const int row = hintedPoolRow(s.pool, hint.nodeId, hint.endpoint);
        if (row >= 0)
            pick = &s.pool.at(row);
        else
            hintOnlyEndpoint = hint.endpoint;
    }
    const bool hintOnly = !pick && !hintOnlyEndpoint.isEmpty();
    // Owner test of 5.1.102: a listener without a label shows its location's label (the AWG
    // sibling), else the country name - never the region code (NodeRanking.h::pickerDisplay).
    QString pickName;
    if (pick) {
        const QString lang = appLang();
        QList<PickerRow> loc{{pick->location, pick->proto, doctor::localizedNodeLabel(pick->name, pick->countryCode, lang),
                              doctor::countryDisplayName(pick->countryCode, lang), -1}};
        if (pick->name.isEmpty() && !pick->location.isEmpty())
            for (const NodeDebugRow &r : s.pool)
                if (&r != pick && r.location == pick->location)
                    loc.append({r.location, r.proto, doctor::localizedNodeLabel(r.name, r.countryCode, lang), QString(), -1});
        pickName = pickerDisplay(loc).constFirst().name;
        if (pick->upstream) // release A: the same name as its row in the server list
            pickName = upstreamRowName(pick->name, pick->upstreamLabelCustom, pick->upstreamOrdinal,
                                       pick->upstreamKind, pick->countryCode);
    }
    QVariantMap node;
    node["nodeId"]    = pick ? pick->nodeId : QString();
    node["region"]    = pick ? pick->region : QString();
    node["name"]      = pick ? pickName : (hintOnly ? tr("Текущий сервер") : QString());
    node["countryCode"] = pick ? pick->countryCode : QString(); // AVPN: для флага-эмодзи
    node["endpoint"]  = pick ? pick->endpoint : hintOnlyEndpoint;
    node["ip"]        = endpointHost(pick ? pick->endpoint : hintOnlyEndpoint);
    // AVPN awg31-xray-v1: транспорт показанного узла — бейдж «Amnezia v3.1»/«Xray» на карточке
    // Connect. Даём из currentNode (а не сканом nodePool в QML): nodePool пересобирает и ранжирует
    // весь снапшот на КАЖДЫЙ changed() (тик ~4с) — биндинг главного экрана этого не стоит.
    node["proto"]        = pick ? pick->proto : QString();
    // AVPN upstream nodes (point 16): the shown node is a provider profile (its own badge, no provider name).
    node["upstream"]     = pick ? pick->upstream : false;
    node["upstreamTier"] = pick ? pick->upstreamTier : 0;
    node["protoVersion"] = pick ? pick->protoVersion : QString(); // "2"/"3"/"3.1"; xray — пусто
    node["connected"] = (s.state == QLatin1String("connected"));
    node["hasNode"]   = (pick != nullptr) || hintOnly;
    // AVPN: бейдж «auto» — показываем ТОЛЬКО когда подключены в авто-режиме (узел выбрал движок, pin
    // пуст). При ручном выборе (pin задан) бейджа нет. pinned — что показанный узел закреплён вручную.
    node["pinned"]    = (!pinned.isEmpty() && pick && pick->nodeId == pinned);
    node["auto"]      = (s.state == QLatin1String("connected") && pinned.isEmpty());
    // 5.1.108: the protocol the next start would raise (ServiceEngine::nextCandidate - the order of
    // connect(), no side effects) for the badge under the node name before connecting. Only when the
    // choice is deterministic: a pinned country or a manual mode (Amnezia/Xray). Auto without a pin
    // picks randomly among equal weights - no badge rather than a flickering one.
    QString nextProto, nextProtoVersion;
    if (!pinned.isEmpty() || m_engine.transportMode() != avpn::TransportMode::Auto) {
        if (const avpn::SubscriptionNode *next = m_engine.nextCandidate()) {
            nextProto = avpn::protoOf(*next);
            nextProtoVersion = avpn::isXrayProto(nextProto) ? QString() : next->awg.protocolMajor();
        }
    }
    node["nextProto"]        = nextProto;
    node["nextProtoVersion"] = nextProtoVersion;
    // The figure its server list row shows (nodePool): a provider node - the Scanner's latest result on this
    // network, own - the off-tunnel ICMP RTT; -1 = none. The card reads it through nodeFigure (one rule).
    int listRtt = -1;
    if (pick)
        listRtt = pick->upstream ? ((m_scanner && m_scanSwitches.scanner) ? m_scanner->listFigures().value(pick->nodeId, -1) : -1)
                                 : m_engine.measuredRtt().value(pick->nodeId, -1);
    node["measuredRttMs"] = listRtt;
    // Chosen vs connected (path engine): the person's choice straight from the attempt owner's UserChoice -
    // "" = Auto; QML shows «Вы выбрали: …» when the connected node differs.
    const avpn::path::UserChoice &choice = m_engine.userChoice();
    QString choiceId, choiceName;
    if (choice.kind != avpn::path::UserChoice::Kind::Auto) {
        choiceId = pinned;
        for (const NodeDebugRow &r : s.pool) {
            if (r.nodeId != pinned)
                continue;
            const QString lang = appLang();
            choiceName = r.upstream ? upstreamRowName(r.name, r.upstreamLabelCustom, r.upstreamOrdinal, r.upstreamKind,
                                                      r.countryCode)
                         : choice.kind == avpn::path::UserChoice::Kind::PreferCountry && choice.pathIds.isEmpty()
                             ? doctor::countryDisplayName(r.countryCode, lang)
                             : pickerDisplay({{r.location, r.proto, doctor::localizedNodeLabel(r.name, r.countryCode, lang),
                                               doctor::countryDisplayName(r.countryCode, lang), -1}}).constFirst().name;
            break;
        }
    }
    bool choiceShown = choiceId.isEmpty();
    if (!choiceShown && pick) {
        if (!choice.pathIds.isEmpty())
            choiceShown = choice.pathIds.contains(pick->nodeId); // an exact path or the preferred server's transports
        else
            choiceShown = pick->countryCode.compare(choice.country, Qt::CaseInsensitive) == 0;
    }
    node["choiceNodeId"] = choiceId;
    node["choiceName"] = choiceName;
    node["choiceIsShown"] = choiceShown;
    return node;
}

QVariantMap AvpnEngineQml::nodeFigure(bool upstream, bool currentLive, bool liveReachable, bool liveDead, int liveRttMs,
                                      int liveBars, int listRttMs) const
{
    const avpn::NodeFigure f = avpn::nodeFigure(upstream, currentLive, liveReachable, liveDead, liveRttMs, liveBars, listRttMs);
    return {{QStringLiteral("ms"), f.ms}, {QStringLiteral("bars"), f.bars}, {QStringLiteral("failed"), f.failed}};
}

// AVPN: весь пул нод для страницы «Серверы» / шторки выбора.
// Обогащаем измеренным RTT (m_nodeRtt) → measuredRttMs + measuredBars (0..5; -1 = не мерили), затем
// сортируем «быстрые ВНИЗУ» (неизмеренные сверху). Без измерений порядок не меняется (все rtt=-1 ⇒
// rankFastestAtBottom стабилен) и палочки берутся из health, как и раньше (поведение идентично).
QVariantList AvpnEngineQml::nodePool() const
{
    QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();

    // Owner test of 5.1.102 (2026-11-05): an Xray row shows its exit host - the RTT and the label of
    // its AWG sibling on the same location, never the shared RU entry's ~14 ms nor the region code
    // (NodeRanking.h::pickerDisplay). Display only: selection keeps the engine's measurements.
    const QHash<QString, int> measured = m_engine.measuredRtt();
    const QString lang = appLang();
    QList<PickerRow> display;
    display.reserve(pool.size());
    for (const QVariant &v : std::as_const(pool)) {
        const QVariantMap n = v.toMap();
        const QString cc = n.value(QStringLiteral("countryCode")).toString();
        display.append({n.value(QStringLiteral("location")).toString(), n.value(QStringLiteral("proto")).toString(),
                        doctor::localizedNodeLabel(n.value(QStringLiteral("name")).toString(), cc, lang),
                        doctor::countryDisplayName(cc, lang),
                        measured.value(n.value(QStringLiteral("nodeId")).toString(), -1)});
    }
    display = pickerDisplay(display);

    // Provider rows (owner 17.11): no ICMP target, so their figure is the Scanner's latest result on THIS network,
    // while the Scanner itself would show it (TribeScanner::listFigures); otherwise none - never invented.
    const QHash<QString, int> scanMs =
        (m_scanner && m_scanSwitches.scanner) ? m_scanner->listFigures() : QHash<QString, int>();

    QHash<QString, QVariantMap> byId;
    QList<RankRow> rows;
    rows.reserve(pool.size());
    for (int i = 0; i < pool.size(); ++i) {
        QVariantMap n = pool.at(i).toMap();
        const QString id = n.value(QStringLiteral("nodeId")).toString();
        const bool upstream = n.value(QStringLiteral("upstream")).toBool();
        // Contract 1.10.0: the provider's balancer is an Auto candidate only - never a row of the manual list.
        // The engine keeps it (pool, Auto, the Connect card); only this list leaves it out.
        const avpn::UpstreamKind kind =
            upstream ? avpn::upstreamKindFromWire(true, n.value(QStringLiteral("upstreamKind")).toString())
                     : avpn::UpstreamKind::Unspecified;
        if (upstream && !avpn::upstreamKindListed(kind))
            continue;
        // R7 (device round 4): one evidence source for the list and the Scanner - an own row without an ICMP figure
        // shows the Scanner's figure on this network, like a provider row («Эстония 3»: a dash here, «Доступно» there).
        int rtt = upstream ? scanMs.value(id, -1)
                           : (display.at(i).rttMs >= 0 ? display.at(i).rttMs : scanMs.value(id, -1));
        // S6 (device round 5): the server we are on has no off-tunnel figure while the tunnel is up - its live RTT
        // through the tunnel is its figure (the remembered working server showed a dash).
        if (rtt < 0 && id == m_engine.currentNodeId() && m_liveRtt >= 0)
            rtt = m_liveRtt;
        // Upstream nodes (release A, 1.10.0): our form of the name - the admin's own label, «<country> <n>» or
        // «Белые списки <n>»; never «Сервер <n>».
        n[QStringLiteral("name")] = upstream
            ? upstreamRowName(n.value(QStringLiteral("name")).toString(),
                              n.value(QStringLiteral("upstreamLabelCustom")).toBool(),
                              n.value(QStringLiteral("upstreamOrdinal")).toInt(), kind,
                              n.value(QStringLiteral("countryCode")).toString())
            : display.at(i).name;
        n[QStringLiteral("measuredRttMs")] = rtt;
        n[QStringLiteral("measuredBars")] = (rtt >= 0) ? barsForNode(rtt) : -1;
        // Per-network evidence (path engine ledger): the node failed on THIS network (suspect / dead).
        const QString here = m_engine.pathStateHere(id);
        n[QStringLiteral("lastAttemptFailed")] = here == QLatin1String("suspect") || here == QLatin1String("dead");
        byId.insert(id, n);
        // A provider row keeps the engine's order (tier, then priority): its Scanner figure is shown, not ranked.
        rows.append({ id, upstream ? -1 : rtt });
    }

    rows = rankFastestAtBottom(rows);
    QVariantList out;
    out.reserve(rows.size());
    for (const RankRow &r : rows)
        out.append(byId.value(r.nodeId));
    return out;
}

// AVPN (выбор по скорости): прямой ICMP-замер RTT до всех живых нод (off-tunnel). См. заголовок.
void AvpnEngineQml::probeNodeRtt()
{
    // Fresh issuance has already been applied by the caller (or the bounded LKG
    // fallback timer fired). A usable manual location does not need fleet ranking.
    // A stale/dead pin still follows the measured Auto fallback.
    if (m_preparingStart && m_engine.hasConnectablePin()) {
        finishStartPreparation(QStringLiteral("pinned_location_ready"));
        return;
    }
    if (!m_rttProbe)
        return;
    // Через поднятый туннель замер к чужим нодам идёт ВНУТРИ туннеля (смазан) — держим кэш, не мерим.
    // AVPN awg31-xray-v1: в verifying туннель тоже поднят (xray ждёт пробу) — тот же гейт.
    if (m_lastTunnelState != Vpn::Disconnected && m_lastTunnelState != Vpn::Unknown) {
        m_rttProbe->cancel();
        return;
    }
    const quint64 epoch = ++m_rttEpoch;
    m_rttProbe->cancel();
    m_rttInFlight = true;
    m_prepRoundDone = false;
    // AVPN (фикс-волна 2026-09-22, A11): прошлый RTT в начале раунда НЕ очищаем — значения
    // заменяются по приходу новых (mergeRttSample / ServiceEngine::mergeMeasuredRtt: «нет ответа»
    // не стирает замер моложе TTL). Раньше очистка + один потерянный пакет исключали EE → US.
    const QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();
    QList<RttTarget> targets;
    for (const QVariant &v : pool) {
        const QVariantMap n = v.toMap();
        if (!n.value(QStringLiteral("alive")).toBool())
            continue; // мёртвые по backend-данным не пингуем
        const QString id = n.value(QStringLiteral("nodeId")).toString();
        const QString host = n.value(QStringLiteral("ip")).toString(); // host без порта (см. debugSnapshot)
        if (id.isEmpty() || host.isEmpty())
            continue;
        targets.append({ id, host, 0 });
    }
    if (targets.isEmpty()) {
        m_rttInFlight = false;
        m_prepRoundDone = true;
        finishStartPreparation(QStringLiteral("no_rtt_targets"));
        return;
    }

    m_rttProbe->probeAll(
        targets, 1500,
        [this, epoch](const QString &nodeId, int rttMs) {
            if (epoch != m_rttEpoch || !m_rttInFlight) return;
            // Журнал тестирования: каждый ICMP-замер (off-tunnel) — по нему выбирается нода.
            avpn::TribeJournal::append(QStringLiteral("rtt"),
                                       {{QStringLiteral("node"), nodeId}, {QStringLiteral("ms"), rttMs}});
            mergeRttSample(m_nodeRtt, nodeId, rttMs);
            // The bars and the Doctor read the RTT (the attempt owner orders nothing by it); merge keeps the
            // other nodes of the cache, «нет ответа» does not erase a fresh earlier figure (K5/B9).
            m_engine.mergeMeasuredRtt({{nodeId, rttMs}});
            emit changed(); // шторка пересортируется + палочки обновятся по мере прихода пингов
        },
        [this, epoch]() {
            if (epoch != m_rttEpoch) return;
            m_rttInFlight = false;
            m_prepRoundDone = true;
            // A11: подготовка старта завершается, когда есть и замер, и ответ refresh (или его провал);
            // бюджет 6 с — страховка (onSelectionBudget).
            if (!m_preparingStart || m_prepPoolSettled)
                finishStartPreparation(QStringLiteral("rtt_round_complete"));
        });
}

void AvpnEngineQml::invalidateNetworkMeasurements()
{
    ++m_rttEpoch;
    m_lastNetChangeMs = QDateTime::currentMSecsSinceEpoch(); // волна-2: момент смены сети
    if (m_rttProbe) m_rttProbe->cancel();
    m_rttInFlight = false;
    // AVPN (фикс-волна 2026-09-22, A11/B9): последний известный RTT сохраняем (движок ранжирует его
    // с учётом возраста) — пустота после смены сети давала выбор по весам (US вместо EE).
    // AVPN (A14, роуминг/звонки — жалоба 3): смена сети (reachability/интерфейс) — окно grace
    // HealthLoop: NE лечит путь сам (bump/rebind ≤ ~15 с), ложный DEAD в этом окне уводил EE→US.
    // Критик полноты (U8): БЕЗ отдельного resetHealthSampling() — выборку сбрасывает сама
    // noteNetworkChange, когда открывает окно; безусловный сброс обходил кап серии и «остывание»
    // HealthLoop, и при флаппинге сети мёртвый туннель не доходил до DEAD никогда.
    facadeNoteNetworkChange(m_engine);
    if (m_probe) m_probe->cancel();
    reliabilityEvent(QStringLiteral("network_measurements_invalidated"));
    if (m_preparingStart) {
        // A11: во время подготовки старта — перезапустить раунд (а не отменить).
        // Волна «как апстрим» (2026-09-28): пул освежаем только без пула — иначе гашение своего же
        // туннеля (смена ноды) заново взводило ожидание refresh, а тот висел до 15 с.
        m_prepRoundDone = false;
        if (prepRefreshOnNetworkChange(m_engine.hasSubscription())) {
            m_prepPoolSettled = false;
            refreshSubscription();
        }
    }
}


// Волна-2: «UI на экране». На macOS Qt::ApplicationActive = фокус приложения (qcocoa: только
// didBecomeActive/didResignActive), а не видимость: окно видно, но фокус в другом приложении —
// Inactive; окно свёрнуто, но приложение активно — Active. Для десктопа берём видимость окон
// (QWindow::isExposed снимается при сворачивании и полном перекрытии); на мобильных состояние
// приложения = видимость.
bool AvpnEngineQml::uiForeground()
{
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    const auto windows = QGuiApplication::topLevelWindows();
    for (const QWindow *w : windows)
        if (w->isVisible() && w->isExposed() && !(w->windowStates() & Qt::WindowMinimized))
            return true;
    return false;
#else
    return QGuiApplication::applicationState() == Qt::ApplicationActive;
#endif
}

// Волна-3: физический аплинк. На macOS — nw_path_monitor без utun (достоверно); на остальных
// платформах — QNetworkInformation (фолбэк UplinkMonitor.cpp).
bool AvpnEngineQml::uplinkUp()
{
    return avpn::UplinkMonitor::instance()->up();
}

void AvpnEngineQml::beginStartPreparation()
{
    if (m_preparingStart) return;
    ++m_rttEpoch;
    if (m_rttProbe) m_rttProbe->cancel();
    m_rttInFlight = false;
    m_preparingStart = true;
    m_prepPoolSettled = false;
    m_prepRoundDone = false;
    m_busy = true;
    const quint64 epoch = ++m_startPreparationEpoch;
    // Волна «как апстрим» (2026-09-28, CONNECT-INVARIANTS §1): пул есть и цель известна (pin или
    // свежий замер) — подключаемся сразу, без сети. До волны здесь каждый Connect ждал ответа
    // refresh, а тот после гашения туннеля висел до 15 с → бюджет 6 с (журнал Mac 26–28.09).
    const StartPrep prep = decideStartPreparation(m_engine.hasSubscription());
    if (prep == StartPrep::ConnectNow) {
        m_prepPoolSettled = true;
        // Волна-2 (ревью 5.1.95, п.3): пул освежаем В ФОНЕ, не дожидаясь ответа — если бэкенд снял
        // ноду, свежая выдача успеет к повтору (applyReseed), а кнопка не ждёт сеть (§1).
        if (!authToken().isEmpty())
            refreshSubscription();
        finishStartPreparation(QStringLiteral("pool_ready"));
        return;
    }
    reliabilityEvent(QStringLiteral("selection_wait_fresh_pool"));
    // Bound control-plane + measurement latency. A usable LKG remains an explicit
    // fallback if the API is unavailable; an empty pool never enters a nested event loop.
    if (authToken().isEmpty()) {
        // AVPN (фикс-волна 2026-09-22, A10): свежая установка — попытка bootstrap СРАЗУ, даже если
        // цепочка ретраев спит (до 60 с) или уже защёлкнута на пустом токене (resetLkg).
        if (m_bootstrapped) m_bootstrapped = false;
        if (!m_bootstrapInFlight)
            bootstrap();
        else if (m_bootstrapRetryTimer.isActive())
            m_bootstrapRetryTimer.start(0);
    } else {
        refreshSubscription();
    }
    QTimer::singleShot(kStartPrepSoftBudgetMs, this, [this, epoch]() { onSelectionBudget(epoch, false); });
    QTimer::singleShot(kStartPrepCeilingMs, this, [this, epoch]() { onSelectionBudget(epoch, true); });
    emit changed();
}

// A10: мягкий бюджет (kStartPrepSoftBudgetMs) завершает подготовку, только если пул есть; без пула
// (свежая установка, enroll+fetch дольше) намерение не снимаем до общего потолка (~20 с).
void AvpnEngineQml::onSelectionBudget(quint64 epoch, bool ceiling)
{
    if (epoch != m_startPreparationEpoch || !m_preparingStart) return;
    switch (decideSelectionBudget(m_engine.hasSubscription(),
                                  ceiling ? kStartPrepCeilingMs : kStartPrepSoftBudgetMs)) {
    case SelectionBudget::Finish:
        finishStartPreparation(QStringLiteral("selection_budget_expired"));
        break;
    case SelectionBudget::GiveUp:
        finishStartPreparation(QStringLiteral("selection_ceiling"));
        break;
    case SelectionBudget::KeepWaiting:
        reliabilityEvent(QStringLiteral("selection_wait_bootstrap"));
        break;
    }
}

// A10/A11: ответ refresh/bootstrap во время подготовки старта. poolWillBeProbed=true — вызывающий
// сам перезапускает раунд RTT на свежем пуле; иначе (пул не менялся/refresh провалился) подготовка
// завершается, как только есть замер (или пригодный pin).
void AvpnEngineQml::notePreparationPoolSettled(bool poolWillBeProbed)
{
    if (!m_preparingStart) return;
    m_prepPoolSettled = true;
    Q_UNUSED(poolWillBeProbed)
    finishStartPreparation(QStringLiteral("pool_settled")); // the pool is what the start waited for
}

void AvpnEngineQml::finishStartPreparation(const QString &reason)
{
    if (!m_preparingStart) return;
    // AVPN (фикс-волна 2026-09-22, A10): пула ещё нет (свежая установка, bootstrap в пути) —
    // ждём finishBootstrapSuccess до потолка, а не снимаем намерение по первому же поводу.
    // Ревью CL-A r2: сервер уже ответил «подписки нет» (degraded, пул пуст) — ждать нечего.
    if (m_wantConnected && !m_engine.hasSubscription() && reason != QLatin1String("selection_ceiling")
        && !subMissing()) {
        reliabilityEvent(QStringLiteral("selection_wait_pool reason=%1").arg(reason));
        return;
    }
    m_preparingStart = false;
    ++m_startPreparationEpoch;
    ++m_rttEpoch;
    if (m_rttProbe) m_rttProbe->cancel();
    m_rttInFlight = false;
    m_busy = false;
    // The order comes from the attempt owner (ledger of this network, server prior) - no RTT round is waited for.
    reliabilityEvent(QStringLiteral("selection_pool=%1 reason=%2").arg(m_engine.poolRevision()).arg(reason));
    m_lastSelectionMeasured = false;
    if (!m_wantConnected) { emit changed(); return; }
    if (!m_engine.hasSubscription()) {
        m_wantConnected = false;
        reliabilityEvent(QStringLiteral("intent_off why=no_subscription")); // U10: кто снял намерение
        if (subMissing())
            emit error(tr("Нет активной подписки. Оформите её, чтобы подключиться."));
        else
            emit error(tr("Не удалось обновить список серверов. Повторите подключение."));
        emit changed();
        return;
    }
    m_startPrepared = true;
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

void AvpnEngineQml::cancelStartPreparation()
{
    if (m_preparingStart) m_busy = false;
    m_preparingStart = false;
    m_startPrepared = false;
    ++m_startPreparationEpoch;
    ++m_rttEpoch;
    if (m_rttProbe) m_rttProbe->cancel();
    m_rttInFlight = false;
}

// ---- Path engine, stage 1 (design 2026-11-17): the facade's side of the attempt owner -----------------------

void AvpnEngineQml::syncChoice()
{
    // Review E8 of 18.11: the person's choice is independent of what the pool or the mode can serve right now -
    // a pin the engine could not apply (the server left the pool, the mode excludes it) is still the choice.
    const QString pin = m_engine.pinnedNodeId().isEmpty() ? m_savedPin : m_engine.pinnedNodeId();
    const avpn::SubscriptionNode *n = m_engine.nodeById(pin);
    avpn::path::UserChoice c;
    if (!pin.isEmpty() && !m_exactRow.isEmpty() && m_exactRow == pin) {
        c = avpn::path::UserChoice::exactPath(pin); // a Scanner row: the one exact node, an honest error if it fails
    } else if (!n && !pin.isEmpty() && !m_savedPinCountry.isEmpty()) {
        c = avpn::path::UserChoice::preferCountry(m_savedPinCountry); // the server is gone: its country stays preferred
    } else if (n) {
        // A server of the list (tapped now or saved by an earlier run): a preferred server - its transports first,
        // then the best available path with a notice; the preference is kept (owner decision of 17.11).
        QStringList paths;
        const QString loc = avpn::locationKeyOf(*n);
        for (const avpn::SubscriptionNode &o : m_engine.candidateNodes())
            if (avpn::locationKeyOf(o) == loc)
                paths << o.nodeId;
        c = avpn::path::UserChoice::preferServer(n->countryCode, paths);
    }
    m_engine.setUserChoice(c);
}

QString AvpnEngineQml::choiceJournal() const
{
    const avpn::path::UserChoice &c = m_engine.userChoice();
    switch (c.kind) {
    case avpn::path::UserChoice::Kind::Auto: return QStringLiteral("auto");
    case avpn::path::UserChoice::Kind::PreferCountry:
        return c.pathIds.isEmpty() ? QStringLiteral("country:") + c.country
                                   : QStringLiteral("prefer:") + c.pathIds.join(QLatin1Char(','));
    case avpn::path::UserChoice::Kind::ExactPath: return QStringLiteral("exact:") + c.pathIds.join(QLatin1Char(','));
    }
    return QString();
}

bool AvpnEngineQml::pinServer(const QString &nodeId, QString &err)
{
    if (!m_engine.setPinnedNode(nodeId, err)) {
        if (!err.startsWith(QLatin1String("no_transport")))
            return false;
        // Decision 9 of 18.11: the server the person tapped wins over the transport mode chosen earlier.
        const QString was = avpn::transportModeToString(m_engine.transportMode());
        setTransportMode(QStringLiteral("auto"));
        if (!m_engine.setPinnedNode(nodeId, err))
            return false;
        reliabilityEvent(QStringLiteral("transport_mode_auto why=server_tap mode_was=%1 node=%2").arg(was, nodeId));
        emit notice(tr("Режим подключения переключён на «Авто», чтобы подключить выбранный сервер"));
    }
    if (m_exactRow != nodeId)
        m_exactRow.clear();
    syncChoice();
    return true;
}

// E10 (device rounds 2-3 of 18.11): while a provider session is up the control plane goes to the edge reachable
// from foreign exits at once (EdgeWalk.h::apiSessionEdgeFor); the direct edge comes back when it ends.
void AvpnEngineQml::syncControlPlaneEdge(bool tunnelUp)
{
    if (!m_configSvc)
        return;
    // R1a: by the route a request takes now - a tunnel in its carrying phase (the leg is checked or connected), not
    // merely "a tunnel reported up": while the owner brings up the next leg, requests are direct.
    const bool carrying = m_engine.isVerifying() || m_engine.state() == avpn::EngineState::Connected;
    const avpn::ApiRoute route = avpn::apiRouteNow(tunnelUp, carrying);
    const QString edge = avpn::apiSessionEdgeFor(route, m_configSvc->isPinned(),
                                                 QString::fromLatin1(avpn::kWhoamiXrayEdge));
    if (edge != m_sessionEdge) {
        reliabilityEvent(QStringLiteral("control_plane_edge session=%1").arg(edge.isEmpty() ? QStringLiteral("-")
                                                                                            : QUrl(edge).host()));
        m_sessionEdge = edge;
        QSettings().setValue(QStringLiteral("avpn/tunnelCarrying"), !edge.isEmpty()); // S5: known at the next launch
    }
    m_configSvc->setSessionEdge(edge);
}

void AvpnEngineQml::attachPathProber(path::IPathProber *prober, std::function<qint64()> bytesLeft,
                                     std::function<void(qint64)> charge)
{
    // the race charges a probe as the Scanner does (ScanBudget.h::scanProbeCostBytes) - one ledger, one price list
    const ScanTunables t;
    path::PathRace::Costs c;
    c.awg = scanProbeCostBytes(ScanProbeKind::AwgMini, false, t);
    c.xray = scanProbeCostBytes(ScanProbeKind::XrayLeg, false, t);
    c.provider = scanProbeCostBytes(ScanProbeKind::XrayFull, false, t) + t.costBatchBytes + t.costConfigBytes;
    m_engine.setProbeCosts(c);
    m_engine.setProbeBudget(std::move(bytesLeft), std::move(charge));
    m_engine.setProber(prober);
    reliabilityEvent(QStringLiteral("race_prober attached=%1").arg(int(prober != nullptr)));
}

void AvpnEngineQml::pathProbeResult(const path::ProbeStamp &stamp, path::PathOutcome outcome, qint64 bytesSpent)
{
    m_engine.onProbeResult(stamp, outcome, bytesSpent);
    // a winner starts the owner's first leg: its journal, the ledger and the progress reach the screen now
    if (syncAttempt())
        QTimer::singleShot(0, this, [this]() { reconcile(); });
}

// S1 (device round 5): the ONE way a Scanner row's request ends without a connect - the row is told it failed and
// the chain is over (a row stayed «Подключение…» for minutes after seat-first failed with the live tunnel kept).
void AvpnEngineQml::endScanRowRequest(const QString &node, const char *why)
{
    if (!m_scanRow.active)
        return;
    m_scanRow.active = false;
    const QString n = node.isEmpty() ? m_scanRow.tapped : node;
    scanJournal(QStringLiteral("scan_row_failed reason=scan_row node=%1 why=%2").arg(n, QLatin1String(why)),
                {{QStringLiteral("event"), QStringLiteral("row_failed")}, {QStringLiteral("reason"), QStringLiteral("scan_row")},
                 {QStringLiteral("node"), n}, {QStringLiteral("why"), QLatin1String(why)}});
    if (m_scanner) {
        if (!n.isEmpty() && !m_scanRow.reported.contains(n))
            m_scanner->connectFailed(n);
        m_scanner->attemptEnded();
    }
}

// R3 (device round 4): the end of a Scanner row's one request.
void AvpnEngineQml::endExactRowRequest(bool connected)
{
    m_exactRestoreArmed = false;
    const QString row = m_exactRow;
    m_exactRow.clear();
    m_exactRestoreReconnectNow = !connected && m_exactRestoreReconnect;
    m_exactRestoreReconnect = false;
    if (!connected) {
        QString err;
        if (m_exactRestorePin.isEmpty())
            m_engine.clearPin();
        else
            m_engine.setPinnedNode(m_exactRestorePin, err); // refused (not in the pool now): the saved choice stays
        m_savedPin = m_exactRestorePin;
        QSettings().setValue(QStringLiteral("avpn/pinnedNode"), m_savedPin);
    }
    syncChoice();
    reliabilityEvent(QStringLiteral("exact_row_request_end row=%1 connected=%2 choice=%3")
                         .arg(row).arg(int(connected)).arg(choiceJournal()));
}

// Review E1 of 18.11: the one place a finished operation releases the facade's latches (the operation in
// flight, its watchdog, a prepared start); "busy" stays only while the owner still walks or checks.
void AvpnEngineQml::settleOperation(const char *why)
{
    if (m_op != Op::None || m_opInFlight)
        reliabilityEvent(QStringLiteral("op_settled op=%1 why=%2").arg(int(m_op)).arg(QLatin1String(why)));
    m_op = Op::None;
    m_opInFlight = false;
    m_watchdog.stop();
    m_busy = m_engine.attemptRunning() || m_engine.isVerifying();
}

bool AvpnEngineQml::syncAttempt()
{
    bool changedAny = false;
    for (const QString &line : m_engine.takeAttemptJournal()) {
        reliabilityEvent(line);
        changedAny = true;
    }
    if (m_engine.pathLedgerDirty()) {
        QSettings().setValue(QLatin1String(kPathLedgerSettingsKey), m_engine.pathLedgerJson());
        m_engine.clearPathLedgerDirty();
    }
    if (m_engine.attemptChecked() != m_attemptCheckedShown || m_engine.attemptTotal() != m_attemptTotalShown) {
        m_attemptCheckedShown = m_engine.attemptChecked();
        m_attemptTotalShown = m_engine.attemptTotal();
        changedAny = true;
    }
    // The owner asked for the data check again on the same tunnel: the running check is void at once (its late
    // answer is dropped by the epoch), the new one starts from the top of the event loop.
    if (m_engine.takeCheckRerun()) {
        ++m_verifyEpoch;
        QTimer::singleShot(0, this, [this]() {
            if (m_engine.isVerifying() && m_lastTunnelState == Vpn::Connected)
                startDataPathVerification();
        });
    }
    syncControlPlaneEdge(m_lastTunnelState == Vpn::Connected); // R1a: a new leg's requests are direct at once
    const int legStartFailures = m_engine.takeLegStartFailures();
    const std::optional<avpn::path::AttemptResult> result = m_engine.takeAttemptResult();
    // Review E1 of 18.11: the owner's terminal result settles the facade's operation - a start whose native
    // commands never published anything must not leave the orb latched (the start watchdog that rescued it is
    // gone). A stop the person asked for is settled by its own stop protocol.
    if (result && (result->connected || result->reason != avpn::path::FailReason::StoppedByUser))
        settleOperation(result->connected ? "attempt_connected" : "attempt_failed");
    if (m_whitelistDetector
        && whitelistTriggerFromAttempt(legStartFailures, result && !result->connected
                                                             && result->reason == avpn::path::FailReason::NothingProven))
        m_whitelistDetector->noteConnectFailure(); // the detector gates its round (cellular, tunnel down, debounce)
    if (const std::optional<avpn::path::AttemptResult> &r = result) {
        changedAny = true;
        if (m_exactRestoreArmed && r->reason != avpn::path::FailReason::StoppedByUser)
            endExactRowRequest(r->connected);
        if (!r->connected && r->reason != avpn::path::FailReason::StoppedByUser)
            endScanRowRequest(QString(), "attempt_failed"); // S1: the owner's terminal result ends the row's request
        const QString lang = appLang();
        if (r->connected) {
            if (r->fallbackNotice) {
                // The preference is kept; the card shows «Вы выбрали: …» next to the server that carries the data.
                const QVariantMap card = currentNode();
                const QString wanted = card.value(QStringLiteral("choiceName")).toString();
                const QString got = card.value(QStringLiteral("name")).toString();
                // R2 (device round 4): "does not work" only on this attempt's own evidence; a preference skipped for a
                // recent failure here says so.
                if (r->preferredTried)
                    emit notice(got.isEmpty() ? tr("«%1» в этой сети не работает — подключено через другой сервер").arg(wanted)
                                              : tr("«%1» в этой сети не работает — подключено через «%2»").arg(wanted, got));
                else
                    emit notice(got.isEmpty()
                                    ? tr("«%1» недавно не работал в этой сети — подключено через другой сервер").arg(wanted)
                                    : tr("«%1» недавно не работал в этой сети — подключено через «%2»").arg(wanted, got));
                Q_UNUSED(lang)
            }
        } else if (r->reason != avpn::path::FailReason::StoppedByUser) {
            m_wantConnected = false;
            m_busy = false;
            reliabilityEvent(QStringLiteral("intent_off why=attempt_failed reason=%1")
                                 .arg(QLatin1String(avpn::path::failReasonName(r->reason))));
            if (std::exchange(m_exactRestoreReconnectNow, false)) {
                // S6: the failed Scanner row does not leave the VPN off - the session before the tap comes back
                // through the ordinary start with the restored choice
                m_wantConnected = true;
                reliabilityEvent(QStringLiteral("exact_row_failed_previous_session_restored"));
                QTimer::singleShot(0, this, [this]() { reconcile(); });
            }
            switch (r->reason) {
            case avpn::path::FailReason::ExactNodeFailed:
                emit error(tr("Выбранный сервер сейчас не работает в этой сети — выберите другой или «Авто»"));
                break;
            case avpn::path::FailReason::NoCandidate:
                // review E8 of 18.11: the mode is kept; an unavailable Xray is named, not replaced by Auto
                emit error(m_engine.transportMode() == avpn::TransportMode::Xray && !avpn::xrayClientSupported()
                               ? tr("Режим Xray сейчас недоступен — включите режим «Авто»")
                               : tr("В выбранном режиме нет ни одного сервера — включите режим «Авто»"));
                break;
            case avpn::path::FailReason::NoNetwork:
                emit error(tr("Нет сети — подключитесь, когда она появится"));
                break;
            default:
                emit error(tr("В этой сети не удалось найти рабочий сервер — проверьте сеть и попробуйте снова"));
                break;
            }
        }
    }
    if (changedAny)
        emit changed();
    return changedAny;
}

// The IPv4 subnet of the physical interface of `kind` ("a.b.c.0/nn"), read from the OS without any permission:
// part of the local network key (iOS gives no gateway or SSID without extra entitlements).
static QString physicalSubnet(const QString &kind)
{
    if (kind != QLatin1String("wifi") && kind != QLatin1String("ethernet"))
        return QString();
    for (const QNetworkInterface &i : QNetworkInterface::allInterfaces()) {
        const auto f = i.flags();
        if (!(f & QNetworkInterface::IsUp) || !(f & QNetworkInterface::IsRunning) || (f & QNetworkInterface::IsLoopBack)
            || avpn::physicalIfaceNameVirtual(i.name()))
            continue;
        for (const QNetworkAddressEntry &e : i.addressEntries()) {
            if (e.ip().protocol() != QAbstractSocket::IPv4Protocol || e.prefixLength() <= 0)
                continue;
            const quint32 mask = e.prefixLength() >= 32 ? 0xffffffffu : ~(0xffffffffu >> e.prefixLength());
            return QHostAddress(e.ip().toIPv4Address() & mask).toString() + QLatin1Char('/')
                 + QString::number(e.prefixLength());
        }
    }
    return QString();
}

QString AvpnEngineQml::ruSitesState() const
{
    return m_ruSentinel ? m_ruSentinel->sitesState() : QStringLiteral("unknown");
}

// The network chip (Scanner variant B): the radio generation of a cellular network, from the same inputs as
// networkKind() and the path engine's network key ("" when the kind is not cellular or the generation is unknown).
QString AvpnEngineQml::netRadio() const
{
    return avpn::cellularGenerationForKind(networkKind(), avpn::cellularGeneration());
}

avpn::path::NetworkObservation AvpnEngineQml::currentNetworkObservation() const
{
    avpn::path::NetworkObservation o;
    const QString kind = networkKind();
    if (kind == QLatin1String("wifi"))
        o.medium = avpn::path::NetMedium::Wifi;
    else if (kind == QLatin1String("ethernet"))
        o.medium = avpn::path::NetMedium::Ethernet;
    else if (kind == QLatin1String("cellular"))
        o.medium = avpn::path::NetMedium::Cellular;
    // nothing known: Unknown keeps the last network (never "offline" from a guess - a leg's own deadline judges)
    o.gateway = netKindInputs().gatewayHash; // the macOS path monitor; "" elsewhere
    o.subnet = physicalSubnet(kind);
    o.carrier = avpn::carrierCode();
    o.radio = avpn::cellularGenerationForKind(kind, avpn::cellularGeneration());
    return o;
}

void AvpnEngineQml::persistPin()
{
#ifdef Q_OS_IOS
    const QString pinBefore = m_savedPin; // AVPN (iOS data watch, 141)
#endif
    m_savedPin = m_engine.pinnedNodeId();
    QSettings().setValue(QStringLiteral("avpn/pinnedNode"), m_savedPin);
    // Review E8 of 18.11: the country of the preference is kept with it - a refresh that removes the server
    // keeps the person's choice (a preferred country) instead of turning it into Auto.
    const avpn::SubscriptionNode *pinned = m_engine.nodeById(m_savedPin);
    m_savedPinCountry = m_savedPin.isEmpty() ? QString() : pinned ? pinned->countryCode : m_savedPinCountry;
    QSettings().setValue(QStringLiteral("avpn/pinnedCountry"), m_savedPinCountry);
    syncChoice();
#ifdef Q_OS_IOS
    if (m_savedPin != pinBefore)
        writeTunnelWatchPlan("pin"); // AVPN (iOS data watch, 141): the extension follows the pin at once
#endif
}

// AVPN (фикс-волна 2026-09-22, A7): сверка pin после применения тела подписки/reseed. Движок мог
// перенести явный pin на соседа той же локации (исчезнувший id) — сохраняем НОВЫЙ id, а не
// стираем его попыткой старого; неявный pin в памяти (rotate/Доктор) не персистим (A6).
void AvpnEngineQml::restorePin(const QString &pinBefore)
{
    if (!m_engine.hasSubscription()) return;
    // 5.1.109 (review R1): the refresh dropped the pin - its listener is gone and the location has no
    // other node the transport mode allows. Persist the empty pin: re-applying the saved one would be
    // refused (no_transport) and leave it saved.
    // Review E8 of 18.11: the saved choice stays - the attempt falls back with the notice (a preferred server) or
    // ends with an honest error (an exact one); nothing broadens it to Auto silently.
    const QString droppedForTransport = m_engine.takePinDroppedForTransport();
    if (!droppedForTransport.isEmpty() && m_engine.pinnedNodeId().isEmpty()) {
        reliabilityEvent(QStringLiteral("pin_unavailable why=reseed kept=1 mode=%1 node=%2")
                             .arg(avpn::transportModeToString(m_engine.transportMode()), droppedForTransport));
        syncChoice();
        return;
    }
    switch (decidePinRestore(m_savedPin, pinBefore, m_engine.pinnedNodeId())) {
    case PinRestoreAction::Nothing:
        return;
    case PinRestoreAction::PersistMigrated:
        reliabilityEvent(QStringLiteral("pin_migrated %1->%2").arg(m_savedPin, m_engine.pinnedNodeId()));
        persistPin();
        return;
    case PinRestoreAction::ApplySaved: {
        QString error;
        // Временно отфильтрованная/отсутствующая нода не стирает сохранённый выбор пользователя.
        // A pin saved by an earlier run is a preference (m_exactRow is of this run only); an exact Scanner row of
        // this run stays exact across a refresh (review E8 of 18.11).
        if (m_engine.setPinnedNode(m_savedPin, error))
            persistPin();
        syncChoice();
        return;
    }
    }
}

// ---- 5.1.109 (S4.1): the stored transport-mode choice and the mode in force (ServiceEngine.h) ----

// What the facade is doing - the one snapshot the gate judges "nothing is running" by
// (TransportModeGate::idle); the engine adds its own phase.
avpn::ModeActivity AvpnEngineQml::modeActivity() const
{
    avpn::ModeActivity a;
    a.wantConnected = m_wantConnected;
    a.operationInFlight = m_op != Op::None || m_opInFlight;
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    a.operationInFlight = a.operationInFlight || m_svcInstallInFlight;
#endif
    a.preparingStart = m_preparingStart || m_startPrepared;
    a.paused = m_paused;
    a.tunnel = modeTunnelOf(observedTunnelOf(m_lastTunnelState), m_latch);
    return a;
}

// Forwards "something changed" to the gate: a config was applied, the runtime gate moved, the app
// came back to the screen, any changed() of the facade. Never touches the tunnel.
void AvpnEngineQml::syncTransportMode(const QString &why)
{
    applyModeChange(m_engine.noteModeActivity(modeActivity(), why));
}

// Applies what the gate decided: the journal, a stored value to rewrite, the macOS runtime gate
// when nothing is running any more. The saved pin is never written here: an admission only
// un-applies a pin in the engine (review of df7f49db8).
void AvpnEngineQml::applyModeChange(const avpn::ServiceEngine::ModeChange &c)
{
    const QStringList journal = m_engine.takeModeJournal();
    for (const QString &line : journal)
        reliabilityEvent(line);
    if (c.storeChoice) {
        QSettings s;
        s.setValue(QStringLiteral("avpn/transportMode"), avpn::transportModeToString(c.storedMode));
        s.setValue(QStringLiteral("avpn/transportModeByChoice"), true);
    }
    bool gateChanged = false;
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (c.idleEntered)
        gateChanged = refreshXrayRuntimeGate(QStringLiteral("idle")); // the service may have got tun2socks
#endif
    if (c.changed || gateChanged || !c.pinUnapplied.isEmpty())
        emit changed(); // the selector, the card and the server list read the mode in force
}

// 5.1.109 (S4.1): why Xray is allowed or frozen by the config in force - one journal line at start
// and one on every change of the reason (ConfigCachePolicy.h::xrayPolicyName). Before the line of
// the start is written (the reliability ring is restored late in the constructor) nothing is logged.
// iOS and macOS only: the other platforms cannot raise Xray and their journal stays as it was.
void AvpnEngineQml::journalXrayPolicy(bool atStart)
{
#if defined(Q_OS_ANDROID) || defined(Q_OS_WIN)
    // Release C: Android/Windows journal it only while their own switch opens Xray (otherwise their journal
    // stays as it was); the first such moment counts as the start line.
    if (!m_configSvc || !avpn::xrayPlatformEnabledBy(m_configSvc->config().features))
        return;
    if (m_xrayPolicyJournaled.isEmpty())
        atStart = true;
#endif
#if defined(Q_OS_IOS) || defined(Q_OS_MACOS) || defined(Q_OS_ANDROID) || defined(Q_OS_WIN)
    if (!m_configSvc)
        return;
    const QString why = QString::fromLatin1(avpn::xrayPolicyName(m_configSvc->xrayPolicy()));
    if (!atStart && (m_xrayPolicyJournaled.isEmpty() || m_xrayPolicyJournaled == why))
        return;
    m_xrayPolicyJournaled = why;
    reliabilityEvent(QStringLiteral("xray_policy allowed=%1 why=%2 age_min=%3")
                         .arg(avpn::TuningStore::flag(QStringLiteral("xray_client"), false) ? 1 : 0)
                         .arg(why)
                         .arg(m_configSvc->cachedConfigAgeMin()));
#else
    Q_UNUSED(atStart)
#endif
}

void AvpnEngineQml::reliabilityEvent(const QString &event)
{
    // Only controlled event labels, enum states and node IDs; never credentials/configs.
    // AVPN (фикс-волна 2026-09-22, A16): подряд идущие одинаковые события схлопываются в одну
    // строку со счётчиком — повторы status_timeout/path_change не вымывают кольцо.
    if (!m_reliabilityClock.isValid()) m_reliabilityClock.start();
    appendReliabilityEvent(m_reliabilityRing,
        QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)
            + QStringLiteral(" mono_ms=%1 build=%2 ")
                .arg(m_reliabilityClock.msecsSinceReference() + m_reliabilityClock.elapsed())
                .arg(QCoreApplication::applicationVersion()),
        event.left(256), 128);
    QSettings().setValue(QStringLiteral("avpn/reliabilityLog"), m_reliabilityRing.lines);
    // AVPN (журнал тестирования): кольцо надёжности целиком — в журнал (no-op, пока выключен).
    avpn::TribeJournal::append(QStringLiteral("ring"), {{QStringLiteral("msg"), event.left(256)}});
}

// AVPN (разбор 2026-09-23): см. RestartGuard.h. Зовётся на каждый changed() (все переходы автомата
// заканчиваются им), из guardedStop до стопа и при выходе на экран. Дёшево: сравнение флагов,
// UIKit — только на фронтах. В кольцо пишем только то, что меняет картину разбора.
void AvpnEngineQml::syncRestartGuard()
{
#ifdef Q_OS_IOS
    avpn::RestartGuardInputs in;
    in.wantConnected = m_wantConnected;
    in.tunnelConnected = (m_lastTunnelState == Vpn::Connected);
    // Свитч движка (down() → continuePendingSwitch → up()) идёт без m_op фасада — тоже «в полёте».
    in.opInFlight = m_opInFlight || m_engine.state() == avpn::EngineState::Switching;
    in.needsRestart = m_needsRestart;
    switch (m_restartGuard.sync(avpn::restartGuardWanted(in))) {
    case avpn::RestartGuardLatch::Action::Begin: {
        QPointer<AvpnEngineQml> self(this);
        const bool ok = AvpnBackgroundGuard_begin([self]() {
            if (!self)
                return;
            self->m_restartGuard.onExpired();
            self->reliabilityEvent(QStringLiteral("restart_guard_expired native=%1 intent_on=%2")
                                       .arg(int(self->m_lastTunnelState)).arg(self->m_wantConnected));
        });
        if (!ok) {
            m_restartGuard.onExpired(); // iOS отказала — не просим снова в этом фоне
            reliabilityEvent(QStringLiteral("restart_guard_denied"));
        }
        break;
    }
    case avpn::RestartGuardLatch::Action::End:
        AvpnBackgroundGuard_end();
        if (QGuiApplication::applicationState() != Qt::ApplicationActive)
            reliabilityEvent(QStringLiteral("restart_guard_done_in_background native=%1")
                                 .arg(int(m_lastTunnelState)));
        break;
    case avpn::RestartGuardLatch::Action::None:
        break;
    }
#endif
}

// ── AVPN (iOS tunnel-side data watch, build 141; design docs/specs/2026-11-14-ios-tunnel-side-data-watch-
// design.md §0, §0a, §5.3-§5.5). The decisions are pure (TunnelWatchPlan.h, TunnelWatchStatus.h, tests
// tunnel_watch_check); here only the glue. Every call site is under Q_OS_IOS; every flag is read with the
// default false; with the flags off nothing here changes a decision of build 139 (the plan file is not even
// created until features.ios_tunnel_watch has been true once on this install). No timer of its own: the
// freeze is judged on the existing 1 s transition tick and on the extension's status replies.

// Plan file for the extension (contract C1). why: start / config / foreground / pin / mode. The write
// itself - whether, with which sequence number, the journal line - is TunnelWatchPlan.h::writeWatchPlan.
void AvpnEngineQml::writeTunnelWatchPlan(const char *why)
{
#ifdef Q_OS_IOS
    const bool watch = featureEnabled(QStringLiteral("ios_tunnel_watch"), false);
    QSettings s;
    const bool everOn = s.value(QLatin1String(avpn::kWatchPlanEverOnSettingsKey), false).toBool();
    if (!watch && !everOn)
        return; // the flag has never been on here: nothing to collect (writeWatchPlan would write nothing)
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const avpn::DebugSnapshot snap = m_engine.debugSnapshot();
    auto countryOf = [&snap](const QString &nodeId) {
        for (const avpn::NodeDebugRow &r : snap.pool)
            if (!nodeId.isEmpty() && r.nodeId == nodeId)
                return r.countryCode;
        return QString();
    };
    avpn::WatchPlanInputs in;
    in.nowMs = now;
    in.configFetchedMs = avpn::ConfigStore::configReceivedAtMs();
    in.watch = watch;
    in.watchSwitch = featureEnabled(QStringLiteral("ios_tunnel_watch_switch"), false);
    in.bgArm = featureEnabled(QStringLiteral("ios_on_demand_bg_arm"), false);
    in.poolRevision = m_engine.poolRevision();
    in.engineTransportMode = avpn::transportModeToString(m_engine.transportMode());
    in.pinNodeId = m_engine.pinnedNodeId();
    in.pinCountry = countryOf(in.pinNodeId);
    in.sessionNodeId = m_engine.currentNodeId();
    in.sessionProto = m_engine.currentNodeProto();
    in.sessionCountry = countryOf(in.sessionNodeId);
    // The extension no longer reads a per-network memory of the app: the attempt owner's ledger is the only one
    // (design 2026-11-17); the plan carries none.
    in.cellularKey = avpn::watchPlanCellularKey(diagCarrier());
    in.numbers = avpn::watchPlanNumbers([](const avpn::TunnelWatchNumberSpec &spec) {
        return avpn::TuningStore::numberOr(QLatin1String(spec.key), spec.def);
    });
    // The white-list detector's own lists (WhitelistDetector.cpp); not set on the server - empty here,
    // and the extension uses its built-in targets, which are the same compiled defaults.
    // Stage 2 (in-place switch by the extension) is inert: the attempt owner is the only one that chooses a path, so
    // the app writes no candidates (the extension's own switch code and the plan's field go in stage 3).
    in.sanityTargets = avpn::watchPlanSanityTargets(
        avpn::TuningStore::listOr(QStringLiteral("ios_tw_sanity_urls"), {}),
        avpn::TuningStore::listOr(QStringLiteral("whitelist_probe_domains"), {}),
        avpn::TuningStore::listOr(QStringLiteral("whitelist_anchor_domains"), {}));
    const avpn::WatchPlanWriteOutcome out = avpn::writeWatchPlan(
        in, everOn, s.value(QLatin1String(avpn::kWatchPlanSeqSettingsKey), 0).toLongLong(), QLatin1String(why),
        [](const QByteArray &body) { return IosController::Instance()->writeTunnelWatchPlanFile(body); });
    if (!out.attempted)
        return;
    s.setValue(QLatin1String(avpn::kWatchPlanEverOnSettingsKey), out.everOnAfter);
    s.setValue(QLatin1String(avpn::kWatchPlanSeqSettingsKey), out.seqAfter);
    reliabilityEvent(out.journal);
#else
    Q_UNUSED(why);
#endif
}

// The hand-over at a return of the app (TunnelWatchResume.h: resume freeze, background hold, deferred
// decisions, the re-check). Here only its effects; built once in the constructor, iOS only.
void AvpnEngineQml::setupTunnelWatchResume()
{
#ifdef Q_OS_IOS
    avpn::TunnelWatchResumeOps ops;
    ops.watchFlag = [this] { return featureEnabled(QStringLiteral("ios_tunnel_watch"), false); };
    ops.nodeScanFlag = [this] { return featureEnabled(QStringLiteral("node_scan"), false); };
    ops.tunnelConnected = [this] { return m_lastTunnelState == Vpn::Connected; };
    // In the background, with the arming flag on and nothing of ours in flight (the restart guard does not
    // hold), the app is awake only for the On-Demand arming.
    ops.backgroundArmOnly = [this] {
        return m_hiddenSeen && featureEnabled(QStringLiteral("ios_on_demand_bg_arm"), false) && !m_restartGuard.held();
    };
    ops.nowMs = [] { return QDateTime::currentMSecsSinceEpoch(); };
    ops.timeoutMs = [] { return qint64(avpn::iosTwResumeWaitMsTuned()); };
    ops.requestSnapshot = [] { IosController::Instance()->requestStatusSnapshot(); };
    ops.appNodeId = [this] { return m_engine.currentNodeId(); };
    ops.sessionGeneration = [] {
        return IosController::Instance()->sessionMetadata().value(QStringLiteral("generation")).toString();
    };
    ops.journal = [this](const QString &line) { reliabilityEvent(line); };
    ops.engineVerifying = [this] { return m_engine.isVerifying(); };
    ops.engineConnected = [this] { return m_engine.state() == avpn::EngineState::Connected; };
    ops.reenterVerifying = [this] { return m_engine.reenterVerifying(); };
    ops.startVerification = [this] {
        refreshDataFlowing();
        startDataPathVerification();
        emit changed();
    };
    // The app's own per-network memory forgets the node (§29 item 7, the same stored-copy function a
    // failed start uses); the key is the attempt's (computed with the tunnel down).
    // Stage 2 is inert (the attempt owner is the only one that chooses a path): the extension never moves the
    // session, so there is nothing to adopt and no way back to take; its no-data verdict reaches the owner through
    // the app's own re-check (reenterVerifying -> the data check -> a lost live session).
    ops.adoptSwitch = [](const QString &, const avpn::WatchSwitchStamp &) { return false; };
    ops.returnFacts = [] { return avpn::WatchReturnInputs{}; };
    ops.restartToChoice = [] {};
    ops.forgetNode = [](const QString &) {};
    m_watchResume = std::make_unique<avpn::TunnelWatchResume>(std::move(ops));
#endif
}

// A decision consults the hand-over first (it also notices a thaw by itself).
bool AvpnEngineQml::tunnelWatchFrozen(const char *site)
{
#ifdef Q_OS_IOS
    return m_watchResume && m_watchResume->held(site, m_lastTransitionTickMs, m_transitionTimer.interval());
#else
    Q_UNUSED(site);
    return false;
#endif
}

bool AvpnEngineQml::deferWhileTunnelWatchFrozen(const char *site, std::function<void()> resume)
{
#ifdef Q_OS_IOS
    return m_watchResume
        && m_watchResume->defer(site, m_lastTransitionTickMs, m_transitionTimer.interval(), std::move(resume));
#else
    Q_UNUSED(site);
    Q_UNUSED(resume);
    return false;
#endif
}

// On the existing 1 s transition tick (sinceMs - time since its previous tick).
void AvpnEngineQml::tickTunnelWatchFreeze(qint64 sinceMs)
{
#ifdef Q_OS_IOS
    if (m_watchResume)
        m_watchResume->onTick(sinceMs, m_transitionTimer.interval());
#else
    Q_UNUSED(sinceMs);
#endif
}

// The status reply said the tunnel has no engine (a failed in-place switch; the extension keeps retrying
// the previous node). The app does what it does for a dead tunnel of its own: the ordinary restart
// through reconcile. Once: the flags below hold until that restart is under way; not in the background.
void AvpnEngineQml::onTunnelEngineDown()
{
#ifdef Q_OS_IOS
    avpn::EngineDownInputs in;
    in.wantConnected = m_wantConnected;
    in.restartPending = m_needsRestart;
    in.opInFlight = m_opInFlight;
    in.paused = m_paused;
    in.foreground = uiForeground();
    in.tunnelConnected = m_lastTunnelState == Vpn::Connected;
    if (!avpn::decideEngineDownRestart(in))
        return;
    reliabilityEvent(QStringLiteral("extension_engine_down node=%1 -> restart").arg(m_engine.currentNodeId()));
    m_needsRestart = true;
    m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch();
    m_restartOrigin = QStringLiteral("engine_down");
    emit changed();
    reconcile();
#endif
}

// The reply to a snapshot request (IosController::tunnelWatchSnapshot; older requests were invalidated).
void AvpnEngineQml::onTunnelWatchSnapshot(const QVariantMap &snapshot)
{
#ifdef Q_OS_IOS
    if (m_watchResume)
        m_watchResume->onSnapshot(snapshot);
#else
    Q_UNUSED(snapshot);
#endif
}

// ── AVPN (журнал тестирования, Tribe-Backend docs/specs/2026-09-23-tester-journal-design.md) ──
// Флаги сервера (is_admin, diag_journal_forced) берутся из последнего ответа /v1/account, а до
// него — из кэша: рестарт оффлайн не должен гасить журнал (выкл→вкл сдвигает смещения в конец).
static bool journalCachedFlag(const QVariantMap &account, const QString &key, const QString &cacheKey)
{
    if (account.contains(key))
        return account.value(key).toBool();
    return QSettings().value(cacheKey, false).toBool();
}

bool AvpnEngineQml::journalForced() const
{
    return journalCachedFlag(m_account, QStringLiteral("diag_journal_forced"),
                             QStringLiteral("avpn/journal/forced"));
}

bool AvpnEngineQml::journalVisible() const
{
    const bool admin = journalCachedFlag(m_account, QStringLiteral("is_admin"), QStringLiteral("avpn/journal/admin"));
    return avpn::journal::journalVisible(avpn::TribeJournal::isTestFlight(), admin, journalForced());
}

bool AvpnEngineQml::journalUserOn() const
{
    return QSettings().value(QStringLiteral("avpn/journal/userOn"), false).toBool();
}

void AvpnEngineQml::setJournalUserOn(bool on)
{
    QSettings().setValue(QStringLiteral("avpn/journal/userOn"), on);
    syncJournal();
}

void AvpnEngineQml::syncJournal()
{
    const bool on = avpn::journal::journalEnabled(journalUserOn(), journalForced(), journalVisible());
    const bool was = avpn::TribeJournal::active();
    avpn::TribeJournal::setActive(on, m_store && m_store->isSaveLogs());
    if (on && !was) {
        m_journalLastState = state();
        const QString netKind = networkKind();
        avpn::TribeJournal::append(QStringLiteral("journal_on"),
                                   {{QStringLiteral("forced"), journalForced()},
                                    {QStringLiteral("testflight"), avpn::TribeJournal::isTestFlight()},
                                    {QStringLiteral("build"), QCoreApplication::applicationVersion()},
                                    {QStringLiteral("platform"), QSysInfo::productType()},
                                    {QStringLiteral("os"), QSysInfo::productVersion()},
                                    {QStringLiteral("device"), avpn::deviceMarketingName()},
                                    {QStringLiteral("carrier"), avpn::carrierCode()},
                                    {QStringLiteral("net"), netKind.isEmpty() ? QStringLiteral("unknown") : netKind},
                                    {QStringLiteral("gen"), avpn::cellularGenerationForKind(netKind, avpn::cellularGeneration())},
                                    {QStringLiteral("tunnel"), m_journalLastState}});
        m_journalTimer.start();
        QTimer::singleShot(0, this, [this]() { m_journal->flush(QStringLiteral("enabled")); });
    } else if (!on && was) {
        m_journalTimer.stop();
    }
    emit journalChanged();
}

QString AvpnEngineQml::journalStatus() const
{
    if (!avpn::TribeJournal::active() || !m_journal)
        return QString();
    if (m_journal->sending())
        return tr("Отправляем…");
    if (!m_journal->lastError().isEmpty())
        return m_journal->lastError();
    const QDateTime at = m_journal->lastSentAt();
    if (!at.isValid())
        return tr("Пишется, ещё не отправлялся");
    const QString when = at.date() == QDate::currentDate() ? at.toString(QStringLiteral("HH:mm"))
                                                           : at.toString(QStringLiteral("dd.MM HH:mm"));
    return tr("Пишется, отправлено в %1").arg(when);
}

void AvpnEngineQml::sendJournalNow()
{
    if (!avpn::TribeJournal::active() || !m_journal)
        return;
    m_journal->flush(QStringLiteral("manual"), buildDiagReport());
    emit journalChanged();
}

// AVPN (фикс-волна 2026-09-22, A1/A4/A5): новые метаданные сессии (runtime-поколение, identity).
// Если движок уже держит адоптированный туннель — только уточнить identity; если туннель жив, но
// ещё не адоптирован (например, поколение отличилось от гашенного — A4), — адоптировать.
void AvpnEngineQml::adoptNativeIdentity()
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (m_lastTunnelState != Vpn::Connected)
        return;
    const avpn::EngineState es = m_engine.state();
    if (es == avpn::EngineState::Connected || es == avpn::EngineState::Verifying) {
        identifyAdoptedSession();
        return;
    }
    if (es == avpn::EngineState::Disconnected || es == avpn::EngineState::Error) {
        // Эффекты «Подключено» уже отработали на самом Connected; здесь только факт адопта.
        if (tryAdoptObservedTunnel("session_metadata")) {
            m_busy = false;
            m_healthTimer.start();
            QTimer::singleShot(0, this, [this]() { reconcile(); });
            emit changed();
        }
    }
#endif
}

// Единая точка адопта наблюдённого живого туннеля (Connected от ОС, не наша операция).
// true = движок принял факт «подключено» (адопт выполнен).
bool AvpnEngineQml::tryAdoptObservedTunnel(const char *why)
{
    if (!avpn::TuningStore::flag(QStringLiteral("adopt_live_tunnel")))
        return false;
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    const QVariantMap metadata = IosController::Instance()->sessionMetadata();
    // Ревью CL-A r2 (A4): сравниваем только однородные поколения (runtime↔runtime или конфигурации).
    const TunnelAdoption verdict = decideTunnelAdoption(
        m_lastTunnelState == Vpn::Connected, m_userIntentKnown, m_wantConnected, m_paused,
        m_latch.awaitingStopConfirm, m_op == Op::None, m_stopGeneration,
        sessionGenerationFrom(metadata));
    if (verdict == TunnelAdoption::Reject)
        return false;
    if (verdict == TunnelAdoption::AdoptNewIntent) {
        // A4: новая сессия ОС/пользователя (Настройки/Shortcuts) после нашего OFF — это НЕ
        // авто-коннект приложения (§13): мы лишь отражаем факт и выравниваем intent-запись, чтобы
        // она не оставалась "off" (корень «липкого intent», C2).
        m_userIntentKnown = true;
        Avpn_recordGuiIntent(true);
    }
    if (m_latch.awaitingStopConfirm) { // адопт при взведённом стопе = другое runtime-поколение
        m_latch.awaitingStopConfirm = false;
        m_stopRetries = 0;
        m_stopRetryTimer.stop();
    }
    m_wantConnected = true;
    m_latch.needStatusBeforeStart = false;
    m_statusRequestAttempts = 0;
    m_statusRetryTimer.stop();
    const QString nodeId = metadata.value(QStringLiteral("node_id")).toString();
    const QString proto = metadata.value(QStringLiteral("proto")).toString();
    const QString endpoint = metadata.value(QStringLiteral("endpoint")).toString();
    if (!m_engine.adoptTunnelConnected(nodeId, proto, endpoint)
        && m_engine.state() != avpn::EngineState::Connected && !m_engine.isVerifying()) {
        // Нода сессии не в пуле (или identity сменилась): факт показываем, identity неизвестна.
        // Health работает и без неё (K5/B3); после reseed движок опознаёт по endpoint (A5).
        m_engine.requestStop();
        m_engine.adoptTunnelConnected();
        reliabilityEvent(QStringLiteral("adopt_identity_pending"));
    }
    identifyAdoptedSession();
    reliabilityEvent(QStringLiteral("adopt_%1 verdict=%2 node=%3")
                         .arg(QLatin1String(why)).arg(int(verdict)).arg(m_engine.currentNodeId()));
    syncAttempt();
    // Decision 6 of 18.11: the adopted tunnel becomes the owner's leg after one in-tunnel data check.
    if (m_engine.isVerifying() && m_lastTunnelState == Vpn::Connected)
        startDataPathVerification();
    return m_engine.state() == avpn::EngineState::Connected || m_engine.isVerifying();
#else
    Q_UNUSED(why)
    // Не-iOS платформы: поведение базы 3c8cc74e — адопт, если наша операция не в полёте.
    if (m_op != Op::None)
        return false;
    m_wantConnected = true;
    const bool adopted = m_engine.adoptTunnelConnected();
    syncAttempt();
    return adopted;
#endif
}

// A5: адоптированная сессия без identity — опознать по sessionMetadata (node_id или endpoint).
void AvpnEngineQml::identifyAdoptedSession()
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (m_engine.currentIdentityKnown() || m_lastTunnelState != Vpn::Connected)
        return;
    const QVariantMap metadata = IosController::Instance()->sessionMetadata();
    if (metadata.value(QStringLiteral("schema_version")).toInt() != 1)
        return;
    const QString proto = metadata.value(QStringLiteral("proto")).toString();
    const QString endpoint = metadata.value(QStringLiteral("endpoint")).toString();
    // В фазе Connected adoptTunnelConnected только уточняет identity (возвращает false).
    m_engine.adoptTunnelConnected(metadata.value(QStringLiteral("node_id")).toString(), proto, endpoint);
    if (!m_engine.currentIdentityKnown())
        m_engine.tryIdentifyCurrentNode(); // по endpoint-подсказке сессии (K5/B3)
    if (m_engine.currentIdentityKnown())
        reliabilityEvent(QStringLiteral("adopt_identity_resolved node=%1").arg(m_engine.currentNodeId()));
#endif
}

void AvpnEngineQml::onTick()
{
    // S2 (device round 5): the identity of an adopted session is looked for on every tick until it is known - after a
    // relaunch the session metadata often arrives after the first Connected (the card had no server name, the
    // Scanner showed «VPN не подключён»).
    identifyAdoptedSession();
    // AVPN upstream nodes: the lease owner's due work (macOS renewals, a provisional seat's retries and
    // deadline) and the standby pack's refresh ride on this existing tick - no timer of their own. Before
    // the health gates: a renewal is due whatever the health sampling does.
    m_tunnel.upstreamTick();
    maybeRefreshStandby("periodic");
    // AVPN (фикс-волна 2026-09-22, A1): health глушит только НАШ стоп в пути или пауза. Error
    // (needStatusBeforeStart) health не выключает — иначе ложный Error убивал DEAD-детект и roaming.
    if (!healthTickAllowed(m_latch, m_lastTunnelState == Vpn::Connected, m_paused)) {
        m_engine.resetHealthSampling();
        return;
    }
    // AVPN seamless roaming (CONNECT-INVARIANTS §23.8): с awg-apple tribe.4 iOS-движок при потере
    // пути НЕ гасится, поэтому в офлайне tx растёт (ретраи handshake), rx стоит, handshake стареет —
    // через 180 с это выглядело бы как DEAD → failover на другую ноду ещё ДО возврата сети (раньше
    // апстрим паузил устройство и статистики просто не было). Пока ОС говорит «сети нет» — health
    // не кормим и обнуляем выборку: DEAD = вердикт о туннеле при живой сети, не об офлайне.
    // kill-switch features.health_pause_offline (default ВКЛ).
    if (avpn::TuningStore::flag(QStringLiteral("health_pause_offline"), true)) {
        // Волна-3: на macOS QNetworkInformation видит наш же utun («online» через 0,4 с после
        // activate при отсутствующем default route) — берём физический аплинк, где он достоверен.
        if (!uplinkUp()) {
            m_engine.resetHealthSampling();
            return;
        }
    }
    // Волна-4 (P2-3, ревью): отложенные эффекты подключения — как только экран снова виден
    // (десктоп: окно развернули при активном приложении, координатор foreground не срабатывает).
    if (m_effectsPending && uiForeground() && state() == QLatin1String("connected"))
        runConnectEffects();
#ifdef Q_OS_IOS
    // AVPN (iOS data watch, 141): after a return / thaw the health verdict waits for the extension's
    // snapshot (features.ios_tunnel_watch; at most ios_tw_resume_wait_ms). Only the verdict waits:
    // the health sample is not fed on this tick, the rest of the tick runs.
    const bool healthHeld = tunnelWatchFrozen("health_tick");
#else
    const bool healthHeld = false;
#endif
    if (healthHeld) {
        // nothing: decided again after the snapshot or the timeout
    } else if (m_engine.tick(QDateTime::currentSecsSinceEpoch())) {
        syncAttempt(); // a dead live session: the failover attempt of the owner
        emit changed();
    }

    // AVPN (реальные палочки): пока соединение активно — мерим RTT через туннель (async, без nested loop).
    // measure() сам игнорит повторный запуск, пока предыдущий в полёте. На не-connected — не мерим
    // и держим бары на 0 (hard-gate сбросит при следующем reachable=false, см. ниже onConnectionStateChanged).
    // Волна «как апстрим» (2026-09-28): на экране — каждый тик (палочки); волна-2 — в фоне не
    // выключаем, а разрежаем до ~60 с: удачная проба единственная сбрасывает счётчик провалов
    // data-plane (feedProbeResult), без неё 4 failover за сессию = «сдаёмся» (ревью 5.1.95, п.1).
    const bool uiActive = uiForeground();
    m_bgProbeTick = uiActive ? 0 : m_bgProbeTick + 1;
    if (m_probe && liveProbeDue(avpn::TuningStore::flag(QStringLiteral("live_rtt")),
                                state() == QLatin1String("connected"), uiActive, m_bgProbeTick))
        measureLiveProbe();
    // AVPN (#35 живой трафик): пока подключены — каждый N-й тик (~20с при N=5, server-tunable
    // numbers.traffic_sync_ticks) освежаем счётчики.
    // ⚠️ ДВОЕ ЧАСОВ: берём /v1/subscription (ЧАСЫ УСТРОЙСТВА — их продлевает оплата), НЕ /v1/account
    // (часы аккаунта: на оплаченном устройстве затирали 36 дн./100ГБ триальными числами аккаунта).
    // refreshSubscription пишет traffic/expires в снапшот + emit changed() → бейдж живой.
    if (state() == QLatin1String("connected")) {
        if (++m_trafficSyncTicks
            >= trafficSyncTicks(int(avpn::TuningStore::numberOr(QStringLiteral("traffic_sync_ticks"), 5)),
                                uiActive)) {
            m_trafficSyncTicks = 0;
            refreshSubscription();
        }
        // Expiry is enforced by the successful refresh callback, never before its response.
    } else {
        m_trafficSyncTicks = 0; // сброс, чтобы первый ре-синк после коннекта был через полный интервал
    }
}

// AVPN (sub-grace): движок сам гасит активный туннель, когда «подписка истекла И грейс прошёл».
// Консервативно by design: пустой/невалидный expiresAt НИКОГДА не рвёт (SubscriptionGate);
// kill-switch features.subscription_grace_enforce (default TRUE — бэк может прислать false и
// выключить всё поведение без релиза); грейс server-tunable (numbers.subscription_grace_hours,
// фолбэк 24 ч, кламп >=1). Остановка — ТЕМ ЖЕ путём, что пользовательский stop(): намерение OFF
// (m_wantConnected=false внутри stop() — иначе reconcile поднял бы туннель обратно) + reconcile()
// (CONNECT-INVARIANTS §2: туннель трогает только reconcile, новых путей teardown не изобретаем).
// Гард m_graceStopInFlight: ровно ОДИН вход, пока идёт остановка (без него залипший в connected
// снапшот при op-in-flight звал бы stop() каждый тик). Сбрасывается явным start().
void AvpnEngineQml::enforceSubscriptionGrace()
{
    if (!avpn::TuningStore::flag(QStringLiteral("subscription_grace_enforce")))
        return; // kill-switch: бэк выключил принудительное отключение целиком
    if (m_graceStopInFlight)
        return; // остановка уже инициирована — не входим повторно
    const QString iso = debugSnapshot().value(QStringLiteral("expiresAt")).toString();
    const int graceHours = avpn::SubscriptionGate::graceHoursTuned();
    if (!avpn::SubscriptionGate::graceExpired(iso, graceHours, QDateTime::currentDateTimeUtc()))
        return;
    m_graceStopInFlight = true;
    m_subEnforcedStop = true;
    qInfo("[AVPN subgate] sub grace expired -> enforced stop (expiresAt=%s, graceHours=%d)",
          qPrintable(iso), graceHours);
    cancelStartPreparation();
    m_wantConnected = false;
    reliabilityEvent(QStringLiteral("intent_off why=sub_grace_expired")); // U10: кто снял намерение
    m_needsRestart = false;
    reconcile();
    emit subscriptionEnforcedStop();
}

void AvpnEngineQml::probeServices()
{
    // AVPN backend-first (T11): kill-switch — гасит и авто-запуск, и ручной тап из UI (осознанно:
    // выключенный флаг должен глушить ВЕСЬ трафик проб, не только фоновый).
    if (!avpn::TuningStore::flag(QStringLiteral("service_probes")))
        return;
    // AVPN backend-first (Task 4): пер-сервисный kill-switch — подхватываем СВЕЖИЙ
    // lists.service_chips_disabled на КАЖДОМ прогоне (живой цикл: сервер выключил сервис ПОСЛЕ того,
    // как чип уже в m_serviceStatus → следующий probeServices() уберёт его без отдельного хука на
    // configApplied). Только при активном туннеле: иначе мерили бы доступность «мимо VPN» (не наша
    // цель — нам нужно «работает ли сервис ЧЕРЕЗ эту ноду»). On-connect (авто) + по тапу из UI; НЕ
    // поллинг (батарея).
    rebuildServiceChips();
    m_svcRetried.clear(); // новая серия → каждый сервис снова имеет право на один авто-ретрай Unknown
    m_chipConfirms.clear(); // и на свежий бюджет confirm-переппроб гистерезиса (v2)
    if (m_svcProbe && state() == QLatin1String("connected")) {
        // Инвалидация перед стартом (v2): застрявшая in-flight серия (напр. долгий goodput при
        // смене ноды) не блокирует новую и не дописывает старые вердикты. Гистерезис НЕ сбрасываем —
        // self-heal каждые 3 мин обязан проходить через него (иначе гистерезис бессмыслен).
        m_svcProbe->invalidate();
        m_svcProbe->probeAll();
    }
}

// AVPN (панель администратора): контекст замера. Пишем ФАКТЫ конфигурации из QSettings (не метки!) —
// иначе замер невозможно интерпретировать постфактум (реальный случай: 4 замера с метками
// baseline/bypass-on/off/amnezia оказались одним и тем же путём — метки врали, extra молчал).
QJsonObject AvpnEngineQml::benchExtra() const
{
    QJsonObject extra;
    extra.insert(QStringLiteral("platform"), QSysInfo::productType());
    extra.insert(QStringLiteral("app_ver"), QCoreApplication::applicationVersion());
    extra.insert(QStringLiteral("tunnel_state"), state());
    extra.insert(QStringLiteral("node_id"), debugSnapshot().value(QStringLiteral("currentNodeId")).toString());
    QSettings s;
    extra.insert(QStringLiteral("bypass_on"), s.value(QStringLiteral("AvpnBypass/masterOn"), true).toBool());
    extra.insert(QStringLiteral("liauto_on"), s.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool());
    extra.insert(QStringLiteral("dns_mask_on"), s.value(QStringLiteral("AvpnBypass/dnsMaskOn"), true).toBool());
    // системная таймзона = где ФИЗИЧЕСКИ устройство (egress loc в network{} — где выход туннеля).
    // Без неё отчёты из разных стран несравнимы: провал RU-direct за границей — норма, в РФ — баг.
    extra.insert(QStringLiteral("tz"), QString::fromUtf8(QTimeZone::systemTimeZoneId()));
    // bench v5 (tunnel.config): фактический конфиг НАШЕГО туннеля — только когда поднят именно он
    // (baseline/amnezia меряют чужой путь — наш последний конфиг там был бы враньём). Санитизирован
    // by construction (AwgConfigBuilder::reportSummary). Даёт A/B с ванилью diff mtu/dns/awg в отчёте.
    // AVPN awg31-xray-v1 (§2.3 «отчёт содержит proto и результат probe»): транспорт текущей ноды,
    // ручной режим, итог верификации xray (probe через туннель: ok/ms) и стрик провалов живой пробы.
    {
        QJsonObject tr;
        tr.insert(QStringLiteral("proto"), m_engine.currentNodeProto());
        tr.insert(QStringLiteral("mode"), avpn::transportModeToString(m_engine.transportMode()));
        tr.insert(QStringLiteral("location"), m_engine.currentLocation());
        tr.insert(QStringLiteral("verifying"), m_engine.isVerifying());
        if (m_lastVerifyOk >= 0) {
            tr.insert(QStringLiteral("verify_ok"), m_lastVerifyOk == 1);
            tr.insert(QStringLiteral("verify_ms"), double(m_lastVerifyMs));
            tr.insert(QStringLiteral("verify_attempts"), m_verifyAttempts);
            // AVPN (ревью волны, MAJOR-3): было ли доказательство rx ЧЕРЕЗ туннель (false =
            // источник статистики молчал, верификацию приняли с оговоркой).
            tr.insert(QStringLiteral("verify_rx_proof"), m_lastVerifyRxProof);
        }
        // Plan v3 step 5: data-path check (whoami) of the current attempt and its raw facts.
        if (!m_pathCheck.isEmpty()) {
            tr.insert(QStringLiteral("path_check"), m_pathCheck);
            if (!m_lastWhoamiFacts.isEmpty())
                tr.insert(QStringLiteral("whoami"), m_lastWhoamiFacts);
        }
        tr.insert(QStringLiteral("probe_fail_streak"), m_liveFailStreak);
        // AVPN (ревью волны, MAJOR-1): подряд идущие провалы data-plane за сессию — паттерн
        // «оператор × сеть × сколько кандидатов не пропустили трафик» ищется по bench_reports.
        tr.insert(QStringLiteral("attempt_checked"), m_engine.attemptChecked());
        tr.insert(QStringLiteral("probe_reachable"), m_liveReachable);
        extra.insert(QStringLiteral("transport"), tr);
    }
    if (state() == QLatin1String("connected")) {
        const QJsonObject tc = m_tunnel.lastConfigReport();
        if (!tc.isEmpty())
            extra.insert(QStringLiteral("tunnel_config"), tc);
        // v5.2 (обогащение): готовые живые сигналы клиента — чипы сервисов (goodput/троттл),
        // сглаженный RTT-бар и off-tunnel RTT-кэш нод (изоляция «нода vs провайдер»: сравнить
        // node_rtt_cache текущей ноды с base_rtt_ms через туннель = чистый оверхед туннеля).
        if (m_liveRtt > 0) {
            QJsonObject lq;
            lq.insert(QStringLiteral("rtt_ms"), m_liveRtt);
            lq.insert(QStringLiteral("bars"), m_liveBars);
            extra.insert(QStringLiteral("live_quality"), lq);
        }
        if (!m_serviceStatus.isEmpty())
            extra.insert(QStringLiteral("services"), QJsonArray::fromVariantList(m_serviceStatus));
        if (!m_nodeRtt.isEmpty()) {
            QJsonObject rtts;
            for (auto it = m_nodeRtt.constBegin(); it != m_nodeRtt.constEnd(); ++it)
                if (it.value() > 0)
                    rtts.insert(it.key(), it.value());
            if (!rtts.isEmpty())
                extra.insert(QStringLiteral("node_rtt_cache"), rtts);
        }
    }
    // тип сети: Wi-Fi и сотовая несравнимы между собой — без этого поля два замера не сопоставить.
    // The physical kind (networkKind, the Scanner's order): Qt's medium is Unknown under any VPN on iOS and
    // CoreTelephony names a radio on Wi-Fi too, so neither alone says what carries the data. Unknown -> the
    // Doctor's manual choice (not persisted: the network may change between launches), else nothing.
    const QString netKind = networkKind();
    if (!netKind.isEmpty())
        extra.insert(QStringLiteral("net_type"), netKind);
    else if (!m_diagNetManual.isEmpty())
        extra.insert(QStringLiteral("net_type"), m_diagNetManual);
    // AVPN (BUG-4 auto-heal): сколько раз за запуск heal ребайндил сокет — в каждый отчёт
    // (паттерн «оператор×нода×heal помог/нет» ищется по bench_reports без релиза).
    if (m_engine.rebindHealTotal() > 0)
        extra.insert(QStringLiteral("rebind_heals"), m_engine.rebindHealTotal());
    // AVPN (Доктор): оператор для паттернов «оператор X режет ноду Y». Приоритет — ручной выбор
    // пользователя (QSettings, единственный путь на iOS 16+, где API оператора закрыт), иначе
    // обезличенный авто-код MCC-MNC. Пусто → поле не пишем (Wi-Fi/десктоп/недоступно).
    QSettings carrierSettings;
    const QString carrierManual = carrierSettings.value(QStringLiteral("AvpnDiag/carrier")).toString();
    const QString carrier = !carrierManual.isEmpty() ? carrierManual : avpn::carrierCode();
    if (!carrier.isEmpty())
        extra.insert(QStringLiteral("carrier"), carrier);
    return extra;
}

// AVPN (панель администратора): in-app бенч. Валиден в ЛЮБОМ состоянии туннеля (baseline = VPN off;
// замер ванильной Amnezia = её NE-туннель системный). extra фиксирует контекст запуска в результат.
// Гард методики: baseline/amnezia — замеры ЧУЖОГО пути, при поднятом Tribe-туннеле они бессмысленны
// (реальный случай: «baseline» с tunnel_state=connected обесценил всю серию). Пустая метка →
// авто-метка по факту: подключены — tribe-bypass-on/off из настроек, отключены — manual.
// v5.5: IP эндпоинта ТЕКУЩЕЙ ноды для ICMP-цели "node-endpoint" (host-route ⇒ off-tunnel);
// пусто, если не подключены — тогда цель не добавляется.
static QString currentNodeEndpointIp(const QVariantMap &node)
{
    return node.value(QStringLiteral("connected")).toBool()
        ? node.value(QStringLiteral("ip")).toString() : QString();
}

void AvpnEngineQml::startBench(const QString &label)
{
    if (m_benchRunning || sweepRunning() || abRunning() || doctorRunning() || !m_bench)
        return;
    const bool connected = (state() == QLatin1String("connected"));
    QString effLabel = label;
    if ((effLabel == QLatin1String("baseline") || effLabel == QLatin1String("amnezia")) && connected) {
        emit error(tr("Метка «%1» — замер БЕЗ нашего туннеля. Сначала отключи Tribe VPN.").arg(effLabel));
        return;
    }
    if (effLabel.isEmpty())
        effLabel = connected
            ? bypassLabel(QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool())
            : QStringLiteral("manual");
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start");
    emit benchChanged();
    m_bench->start(effLabel, benchExtra(), /*lite=*/false, currentNodeEndpointIp(currentNode()));
}

void AvpnEngineQml::cancelBench()
{
    if (!m_bench)
        return;
    m_bench->cancel();
    m_benchRunning = false;
    m_benchStage.clear();
    emit benchChanged();
}

// ── AVPN (панель администратора): авто-свип нод ────────────────────────────────────────────────
// Фазовая машина поверх ПУБЛИЧНЫХ переходов движка: switchToNode() (pin + guardedStop) → start() →
// wait connected → lite-бенч → следующая нода → восстановление исходного pin/подключения.
// Продвижение — из sweepAdvance() (по сигналу changed, queued) и sweepGuardFired() (сторож фазы).
// Инварианты коннекта не трогаем: НИКАКИХ прямых up()/down(), только те же вызовы, что жмёт юзер.

static const int kSweepGuardDownMs = 25000;  // стоп туннеля обязан завершиться быстро
static const int kSweepGuardUpMs = 75000;    // connect: enroll+handshake на медленной сети
static const int kSweepGuardBenchMs = 120000;

// display-имя ноды для прогресса/строк отчёта (из пула снапшота)
QString AvpnEngineQml::sweepNodeLabel(const QString &nodeId) const
{
    const QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();
    for (const QVariant &v : pool) {
        const QVariantMap n = v.toMap();
        if (n.value(QStringLiteral("nodeId")).toString() == nodeId) {
            const QString name = n.value(QStringLiteral("name")).toString();
            return name.isEmpty() ? n.value(QStringLiteral("region")).toString() : name;
        }
    }
    return nodeId;
}

void AvpnEngineQml::startNodeSweep()
{
    if (sweepRunning() || m_benchRunning || abRunning() || doctorRunning() || !m_bench)
        return;
    // очередь: ВСЕ ноды пула (вкл. RU — это тест, не авто-выбор; §14.3 касается выбора, не замера).
    // Task 10 финал: КРОМЕ неподдерживаемых протоколов (xray, ...) — switchToNode к ним невозможен,
    // каждая такая нода лишь выжигала бы сторожа фазы (до 25с) впустую.
    m_sweepQueue.clear();
    const QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();
    for (const QVariant &v : pool) {
        const QVariantMap n = v.toMap();
        if (!avpn::isSupportedProto(n.value(QStringLiteral("proto")).toString()))
            continue;
        // Upstream nodes (R16): a sweep would lease a provider seat per row - not in release A.
        if (n.value(QStringLiteral("upstream")).toBool())
            continue;
        m_sweepQueue << n.value(QStringLiteral("nodeId")).toString();
    }
    m_sweepQueue.removeAll(QString());
    if (m_sweepQueue.isEmpty()) {
        emit error(tr("Свип: пул нод пуст — обнови подписку"));
        return;
    }
    ++m_sweepEpoch;
    m_sweepIdx = -1;
    m_sweepResults = QJsonArray();
    m_sweepOrigPin = m_engine.pinnedNodeId();
    m_sweepOrigConnected = (state() == QLatin1String("connected"));
    sweepNextNode();
}

void AvpnEngineQml::cancelNodeSweep()
{
    if (!sweepRunning())
        return;
    ++m_sweepEpoch;
    m_sweepGuard.stop();
    if (m_benchRunning)
        cancelBench();
    m_sweepPhase = SweepPhase::Idle;
    m_sweepProgress.clear();
    emit sweepChanged();
    // вернуть исходное состояние (без ожиданий — юзер прервал; восстановление цели достаточно)
    if (m_sweepOrigPin.isEmpty()) selectAutoImpl(false); else switchToNodeImpl(m_sweepOrigPin, false);
    if (m_sweepOrigConnected)
        start();
}

void AvpnEngineQml::sweepEnterPhase(SweepPhase ph, int guardMs)
{
    m_sweepPhase = ph;
    m_sweepGuard.start(guardMs);
    emit sweepChanged();
}

void AvpnEngineQml::sweepNextNode()
{
    ++m_sweepIdx;
    if (m_sweepIdx >= m_sweepQueue.size()) {
        sweepBeginRestore();
        return;
    }
    const QString id = m_sweepQueue.at(m_sweepIdx);
    m_sweepProgress = QStringLiteral("%1/%2 · %3").arg(m_sweepIdx + 1).arg(m_sweepQueue.size())
                          .arg(sweepNodeLabel(id));
    switchToNodeImpl(id, false);             // pin + намерение OFF (guardedStop, если были online); A6: только в памяти
    sweepEnterPhase(SweepPhase::WaitDown, kSweepGuardDownMs);
    // возможно, уже disconnected (no-op reconcile) — проверим отложенно, не дожидаясь changed
    QTimer::singleShot(0, this, [this, e = m_sweepEpoch] { if (e == m_sweepEpoch) sweepAdvance(); });
}

void AvpnEngineQml::sweepAdvance()
{
    const QString st = state();
    switch (m_sweepPhase) {
    case SweepPhase::Idle:
        return;
    case SweepPhase::WaitDown:
        if (st == QLatin1String("disconnected") || st == QLatin1String("error")) {
            m_sweepConnT.start();
            start();                          // коннект к запиненной ноде
            sweepEnterPhase(SweepPhase::WaitUp, kSweepGuardUpMs);
        }
        return;
    case SweepPhase::WaitUp:
        if (st == QLatin1String("connected")) {
            m_sweepGuard.stop();
            sweepStartBench();
        } else if (st == QLatin1String("error")) {
            sweepNodeFailed(QStringLiteral("connect-error"));
        }
        return;
    case SweepPhase::Bench:
        return; // продвижение придёт из benchFinished-лямбды
    case SweepPhase::RestoreWaitDown:
        if (st == QLatin1String("disconnected") || st == QLatin1String("error")) {
            if (m_sweepOrigConnected) {
                start();
                sweepEnterPhase(SweepPhase::RestoreWaitUp, kSweepGuardUpMs);
            } else {
                sweepFinish();
            }
        }
        return;
    case SweepPhase::RestoreWaitUp:
        if (st == QLatin1String("connected") || st == QLatin1String("error"))
            sweepFinish();
        return;
    }
}

void AvpnEngineQml::sweepStartBench()
{
    const QString id = m_sweepQueue.at(m_sweepIdx);
    const QString actual = debugSnapshot().value(QStringLiteral("currentNodeId")).toString();
    QJsonObject extra = benchExtra(); // общий контекст (факты конфигурации, сеть) + пер-нодные поля
    extra.insert(QStringLiteral("node_label"), sweepNodeLabel(id));
    extra.insert(QStringLiteral("connect_ms"), double(m_sweepConnT.elapsed()));
    if (actual != id) // движок мог failover'нуться — честно фиксируем (замер не той ноды)
        extra.insert(QStringLiteral("failover_from"), id);
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start");
    emit benchChanged();
    sweepEnterPhase(SweepPhase::Bench, kSweepGuardBenchMs);
    m_bench->start(QStringLiteral("node-%1").arg(id), extra, /*lite=*/true,
                   currentNodeEndpointIp(currentNode()));
}

void AvpnEngineQml::sweepNodeFailed(const QString &reason)
{
    m_sweepGuard.stop();
    QJsonObject r;
    r.insert(QStringLiteral("label"), QStringLiteral("node-%1").arg(m_sweepQueue.value(m_sweepIdx)));
    r.insert(QStringLiteral("extra"), QJsonObject{
        { QStringLiteral("node_id"), m_sweepQueue.value(m_sweepIdx) },
        { QStringLiteral("node_label"), sweepNodeLabel(m_sweepQueue.value(m_sweepIdx)) },
    });
    r.insert(QStringLiteral("error"), reason);
    m_sweepResults.append(r);
    if (m_benchRunning)
        cancelBench();
    stop(); // не оставляем полуподнятый туннель перед следующей нодой
    QTimer::singleShot(0, this, [this, e = m_sweepEpoch] { if (e == m_sweepEpoch) sweepNextNode(); });
}

void AvpnEngineQml::sweepGuardFired()
{
    switch (m_sweepPhase) {
    case SweepPhase::Idle: return;
    case SweepPhase::WaitDown:  sweepNodeFailed(QStringLiteral("stop-timeout")); return;
    case SweepPhase::WaitUp:    sweepNodeFailed(QStringLiteral("connect-timeout")); return;
    case SweepPhase::Bench:     sweepNodeFailed(QStringLiteral("bench-timeout")); return;
    case SweepPhase::RestoreWaitDown:
    case SweepPhase::RestoreWaitUp:
        sweepFinish(); // восстановление зависло — отдаём отчёт, юзер увидит состояние на орбе
        return;
    }
}

void AvpnEngineQml::sweepBeginRestore()
{
    m_sweepProgress = tr("восстановление…");
    if (m_sweepOrigPin.isEmpty()) selectAutoImpl(false); else switchToNodeImpl(m_sweepOrigPin, false);
    sweepEnterPhase(SweepPhase::RestoreWaitDown, kSweepGuardDownMs);
    QTimer::singleShot(0, this, [this, e = m_sweepEpoch] { if (e == m_sweepEpoch) sweepAdvance(); });
}

void AvpnEngineQml::sweepFinish()
{
    m_sweepGuard.stop();
    m_sweepPhase = SweepPhase::Idle;
    m_sweepProgress.clear();

    // строки отчёта: выжимка per node, лучшие сверху (по скорости, ошибки — вниз)
    struct Row { QVariantMap m; double down; bool ok; };
    QList<Row> rows;
    for (const QJsonValue &v : m_sweepResults) {
        const QJsonObject r = v.toObject();
        const QJsonObject extra = r.value(QStringLiteral("extra")).toObject();
        QVariantMap m;
        m.insert(QStringLiteral("node_id"), extra.value(QStringLiteral("node_id")).toString());
        m.insert(QStringLiteral("label"), extra.value(QStringLiteral("node_label")).toString());
        const bool ok = !r.contains(QStringLiteral("error"));
        m.insert(QStringLiteral("ok"), ok);
        if (!ok) {
            m.insert(QStringLiteral("verdict"), r.value(QStringLiteral("error")).toString());
            rows.append({ m, -1, false });
            continue;
        }
        m.insert(QStringLiteral("connect_ms"), extra.value(QStringLiteral("connect_ms")).toDouble());
        m.insert(QStringLiteral("ttfb_ms"), r.value(QStringLiteral("http")).toObject().value(QStringLiteral("median_ttfb_ms")).toDouble(-1));
        const double down = r.value(QStringLiteral("throughput")).toObject().value(QStringLiteral("down_mbit")).toDouble();
        m.insert(QStringLiteral("down_mbit"), down);
        m.insert(QStringLiteral("base_rtt_ms"), r.value(QStringLiteral("network_quality")).toObject().value(QStringLiteral("base_rtt_ms")).toDouble(-1));
        m.insert(QStringLiteral("loaded_rtt_ms"), r.value(QStringLiteral("network_quality")).toObject().value(QStringLiteral("loaded_rtt_ms")).toDouble(-1));
        QString verdict = extra.contains(QStringLiteral("failover_from")) ? QStringLiteral("failover! ") : QString();
        const QJsonArray vs = r.value(QStringLiteral("verdicts")).toArray();
        verdict += vs.isEmpty() ? QStringLiteral("ok")
                                : vs.first().toObject().value(QStringLiteral("code")).toString()
                                      + (vs.size() > 1 ? QStringLiteral(" +%1").arg(vs.size() - 1) : QString());
        m.insert(QStringLiteral("verdict"), verdict);
        rows.append({ m, down, true });
    }
    std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
        if (a.ok != b.ok) return a.ok;
        return a.down > b.down;
    });
    QVariantList outRows;
    for (const Row &r : rows) outRows << r.m;

    QJsonObject report;
    report.insert(QStringLiteral("schema"), 1);
    report.insert(QStringLiteral("type"), QStringLiteral("node-sweep"));
    report.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    report.insert(QStringLiteral("nodes"), m_sweepResults);
    const QString json = QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Compact));
    QSettings().setValue(QStringLiteral("AvpnBench/last_node-sweep"), json);

    emit sweepChanged();
    emit sweepFinished(outRows, json);
}

// ── AVPN (панель администратора): авто-A/B байпаса ─────────────────────────────────────────────
// Одна кнопка при подключённом Tribe: full-бенч на ТЕКУЩЕМ тумблере → setBypassMasterOn(!x)
// (reconcile штатно передёргивает туннель — БЕЗ прямых up/down, CONNECT-INVARIANTS не трогаем) →
// второй full-бенч → возврат тумблера + реконнект → отчёт type:"ab-bypass" (пара + compare +
// длительности реконнектов). Метки выводятся из фактического состояния настроек.

static const int kAbGuardBenchMs = 240000; // full-бенч ~2 мин + запас на медленной сети

void AvpnEngineQml::startBypassAb()
{
    if (abRunning() || m_benchRunning || sweepRunning() || doctorRunning() || !m_bench)
        return;
    if (state() != QLatin1String("connected")) {
        emit error(tr("Авто-A/B байпаса: сначала подключи Tribe VPN"));
        return;
    }
    ++m_abEpoch;
    m_abOrigOn = QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    m_abOrigLiAuto = QSettings().value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool();
    m_abFirst = QJsonObject();
    m_abSecond = QJsonObject();
    m_abSwitchMs = m_abRestoreMs = -1;
    abStartBench(/*second=*/false);
}

void AvpnEngineQml::cancelBypassAb()
{
    if (!abRunning())
        return;
    ++m_abEpoch;
    m_abGuard.stop();
    if (m_benchRunning)
        cancelBench();
    // вернуть исходный тумблер, если успели переключить (реконнект доделает reconcile)
    {
        QSettings st; // v5.5: вернуть liAuto тихо ДО реконсиляции master
        if (st.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool() != m_abOrigLiAuto) {
            st.setValue(QStringLiteral("AvpnBypass/liAutoOn"), m_abOrigLiAuto);
            st.sync();
        }
    }
    if (QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool() != m_abOrigOn)
        setBypassMasterOn(m_abOrigOn);
    m_abPhase = AbPhase::Idle;
    m_abProgress.clear();
    emit abChanged();
}

void AvpnEngineQml::abEnterPhase(AbPhase ph, int guardMs)
{
    m_abPhase = ph;
    m_abGuard.start(guardMs);
    emit abChanged();
}

void AvpnEngineQml::abStartBench(bool second)
{
    const bool on = QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    m_abProgress = tr("замер %1/2 · байпас %2").arg(second ? 2 : 1).arg(on ? tr("ВКЛ") : tr("ВЫКЛ"));
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start");
    emit benchChanged();
    abEnterPhase(second ? AbPhase::BenchB : AbPhase::BenchA, kAbGuardBenchMs);
    m_bench->start(bypassLabel(on), benchExtra(), /*lite=*/false, currentNodeEndpointIp(currentNode()));
}

// benchFinished при фазе BenchA/BenchB (история last_<label> уже записана вызывающей лямбдой)
void AvpnEngineQml::abOnBenchDone(const QJsonObject &result)
{
    m_abGuard.stop();
    const bool wasFirst = (m_abPhase == AbPhase::BenchA);
    (wasFirst ? m_abFirst : m_abSecond) = result;
    m_abProgress = wasFirst ? tr("переключение байпаса и реконнект…")
                            : tr("возврат настроек и реконнект…");
    m_abConnT.start();
    // синхронная запись тумблера + штатный передёрг туннеля (reapplyBypass → reconcile)
    // v5.5 (Li Auto гейт): off-фаза = ЧИСТЫЙ full-tunnel — гасим и liAutoOn, иначе split_on
    // остаётся из-за Li Auto default-ON и «bypass-off» несравним с ванилью (реальный отчёт).
    // Пишем тихо (setValue+sync): реконсиляцию/реконнект делает следующий setBypassMasterOn.
    {
        const bool targetMaster = wasFirst ? !m_abOrigOn : m_abOrigOn;
        QSettings st;
        st.setValue(QStringLiteral("AvpnBypass/liAutoOn"), targetMaster ? m_abOrigLiAuto : false);
        st.sync();
        setBypassMasterOn(targetMaster);
    }
    abEnterPhase(wasFirst ? AbPhase::WaitDown : AbPhase::RestoreDown, kSweepGuardDownMs);
    QTimer::singleShot(0, this, [this, e = m_abEpoch] { if (e == m_abEpoch) abAdvance(); });
}

void AvpnEngineQml::abAdvance()
{
    const QString st = state();
    switch (m_abPhase) {
    case AbPhase::Idle:
    case AbPhase::BenchA:
    case AbPhase::BenchB:
        return; // продвижение придёт из abOnBenchDone
    case AbPhase::WaitDown:
    case AbPhase::RestoreDown:
        // reconcile передёргивает сам; «вниз» мы можем не застать (queued-снапшоты) — фактом начала
        // передёрга считаем ЛЮБОЕ не-connected состояние. Залипший connected отловит сторож фазы.
        if (st == QLatin1String("error")) {
            abFail(QStringLiteral("reconnect-error"));
        } else if (st != QLatin1String("connected")) {
            abEnterPhase(m_abPhase == AbPhase::WaitDown ? AbPhase::WaitUp : AbPhase::RestoreUp,
                         kSweepGuardUpMs);
        }
        return;
    case AbPhase::WaitUp:
        if (st == QLatin1String("connected")) {
            m_abGuard.stop();
            m_abSwitchMs = double(m_abConnT.elapsed());
            abStartBench(/*second=*/true);
        } else if (st == QLatin1String("error")) {
            abFail(QStringLiteral("reconnect-error"));
        }
        return;
    case AbPhase::RestoreUp:
        if (st == QLatin1String("connected")) {
            m_abRestoreMs = double(m_abConnT.elapsed());
            abFinish();
        } else if (st == QLatin1String("error")) {
            abFinish(); // пара уже собрана — отчёт отдаём, состояние юзер увидит на орбе
        }
        return;
    }
}

void AvpnEngineQml::abGuardFired()
{
    switch (m_abPhase) {
    case AbPhase::Idle:
        return;
    case AbPhase::BenchA:
    case AbPhase::BenchB:
        abFail(QStringLiteral("bench-timeout"));
        return;
    case AbPhase::WaitDown:
    case AbPhase::WaitUp:
        abFail(QStringLiteral("reconnect-timeout"));
        return;
    case AbPhase::RestoreDown:
    case AbPhase::RestoreUp:
        abFinish(); // восстановление зависло — отчёт всё равно отдаём
        return;
    }
}

void AvpnEngineQml::abFail(const QString &reason)
{
    m_abGuard.stop();
    ++m_abEpoch;
    if (m_benchRunning)
        cancelBench();
    {
        QSettings st; // v5.5: вернуть liAuto тихо ДО реконсиляции master
        if (st.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool() != m_abOrigLiAuto) {
            st.setValue(QStringLiteral("AvpnBypass/liAutoOn"), m_abOrigLiAuto);
            st.sync();
        }
    }
    if (QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool() != m_abOrigOn)
        setBypassMasterOn(m_abOrigOn);
    m_abPhase = AbPhase::Idle;
    m_abProgress.clear();
    emit abChanged();
    emit error(tr("Авто-A/B прерван: %1. Тумблер байпаса возвращён.").arg(reason));
}

void AvpnEngineQml::abFinish()
{
    m_abGuard.stop();
    m_abPhase = AbPhase::Idle;
    m_abProgress.clear();

    // раскладываем пару по фактическим меткам (первый замер шёл на исходном тумблере)
    const QJsonObject &onRun = m_abOrigOn ? m_abFirst : m_abSecond;
    const QJsonObject &offRun = m_abOrigOn ? m_abSecond : m_abFirst;

    QJsonObject report;
    report.insert(QStringLiteral("schema"), 1);
    report.insert(QStringLiteral("type"), QStringLiteral("ab-bypass"));
    report.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    report.insert(QStringLiteral("orig_bypass_on"), m_abOrigOn);
    if (m_abSwitchMs >= 0) report.insert(QStringLiteral("reconnect_switch_ms"), m_abSwitchMs);
    if (m_abRestoreMs >= 0) report.insert(QStringLiteral("reconnect_restore_ms"), m_abRestoreMs);
    QJsonObject runs;
    runs.insert(QStringLiteral("tribe-bypass-on"), onRun);
    runs.insert(QStringLiteral("tribe-bypass-off"), offRun);
    report.insert(QStringLiteral("runs"), runs);
    // «цена байпаса»: on относительно off (b относительно a в bench::compare)
    const QJsonObject cost = bench::compare(offRun, onRun);
    report.insert(QStringLiteral("bypass_cost"), cost);

    const QString json = QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Compact));
    QSettings().setValue(QStringLiteral("AvpnBench/last_ab-bypass"), json);

    // плоская сводка для UI: пара ключевых метрик + существенные ухудшения
    auto flat = [](const QJsonObject &r) {
        QVariantMap m;
        const QJsonObject http = r.value(QStringLiteral("http")).toObject();
        m.insert(QStringLiteral("ttfb_ms"), http.value(QStringLiteral("median_ttfb_ms")).toVariant());
        m.insert(QStringLiteral("failures"), http.value(QStringLiteral("failures")).toInt());
        const QJsonObject thr = r.value(QStringLiteral("throughput")).toObject();
        m.insert(QStringLiteral("down_mbit"), thr.value(QStringLiteral("down_mbit")).toVariant());
        m.insert(QStringLiteral("up_mbit"), thr.value(QStringLiteral("up_mbit")).toVariant());
        const QJsonObject nq = r.value(QStringLiteral("network_quality")).toObject();
        m.insert(QStringLiteral("base_rtt_ms"), nq.value(QStringLiteral("base_rtt_ms")).toVariant());
        return m;
    };
    QStringList costTexts;
    for (const QJsonValue &v : cost.value(QStringLiteral("significant")).toArray())
        costTexts << v.toString();
    QVariantMap summary;
    summary.insert(QStringLiteral("on"), flat(onRun));
    summary.insert(QStringLiteral("off"), flat(offRun));
    summary.insert(QStringLiteral("cost"), costTexts);
    if (m_abSwitchMs >= 0) summary.insert(QStringLiteral("reconnect_ms"), m_abSwitchMs);

    emit abChanged();
    emit abFinished(summary, json);
}

// ── AVPN bench v5 (connect{}): «Тест коннекта» ────────────────────────────────────────────────
// Меряет САМ коннект (v1–v4 мерили путь после): kCcCycles циклов stop→wait down→start→wait
// connected→handshake→first byte. Только публичные переходы (CONNECT-INVARIANTS не трогаем);
// исторические баги этого класса: «2-й коннект = Network Error» (ios reconnect), залипание
// Connect, медленные сторожа — здесь видны как фейл/тайминг конкретной фазы конкретного цикла.
static const int kCcGuardVerifyMs = 15000;  // HEAD 204 через свежеподнятый туннель
static const int kCcHsPollMs = 500;         // шаг полла handshake
static const int kCcHsPollMax = 20;         // 10с: handshake не свежий → пишем null (desktop не отдаёт)

void AvpnEngineQml::startConnectCycle()
{
    if (ccRunning() || m_benchRunning || sweepRunning() || abRunning() || doctorRunning())
        return;
    if (state() != QLatin1String("connected")) {
        emit error(tr("Тест коннекта: сначала подключи Tribe VPN"));
        return;
    }
    ++m_ccEpoch;
    m_ccCycle = 0;
    m_ccCycles = QJsonArray();
    m_ccCur = QJsonObject();
    m_ccProgress = tr("цикл 1/%1 · отключение…").arg(kCcCycles);
    m_ccT.start();
    stop(); // публичный переход; факт «вниз» ждём по changed()
    ccEnterPhase(CcPhase::Down, 25000);
}

void AvpnEngineQml::cancelConnectCycle()
{
    if (!ccRunning())
        return;
    ++m_ccEpoch;
    m_ccGuard.stop();
    const bool wasDown = (m_ccPhase == CcPhase::Down);
    m_ccPhase = CcPhase::Idle;
    m_ccProgress.clear();
    emit ccChanged();
    if (wasDown || state() != QLatin1String("connected"))
        start(); // не бросаем юзера отключённым посреди цикла
}

void AvpnEngineQml::ccEnterPhase(CcPhase ph, int guardMs)
{
    m_ccPhase = ph;
    m_ccGuard.start(guardMs);
    emit ccChanged();
}

void AvpnEngineQml::ccAdvance()
{
    const QString st = state();
    switch (m_ccPhase) {
    case CcPhase::Idle:
    case CcPhase::Handshake: // продвигается поллом ccPollHandshake
    case CcPhase::Verify:    // продвигается колбэком HEAD в ccVerify
        return;
    case CcPhase::Down:
        if (st == QLatin1String("error")) {
            m_ccCur.insert(QStringLiteral("error"), QStringLiteral("teardown-error"));
            ccNextCycle();
        } else if (st == QLatin1String("disconnected")) {
            // ждём именно disconnected (не «любой не-connected»): реальные данные iOS — «любой»
            // давал teardown_ms=2 (первый же changed), метрика врала. Плюс 1с успокоения NE перед
            // start — не гоним новый up() поверх недоехавшего teardown (класс m_pendingStart).
            m_ccCur.insert(QStringLiteral("teardown_ms"), double(m_ccT.elapsed()));
            m_ccGuard.stop();
            m_ccProgress = tr("цикл %1/%2 · подключение…").arg(m_ccCycle + 1).arg(kCcCycles);
            const int epoch = m_ccEpoch;
            QTimer::singleShot(1000, this, [this, epoch] {
                if (epoch != m_ccEpoch || m_ccPhase != CcPhase::Down)
                    return;
                m_ccT.start();
                start();
                ccEnterPhase(CcPhase::Up, kSweepGuardUpMs);
            });
        }
        return;
    case CcPhase::Up:
        if (st == QLatin1String("connected")) {
            m_ccGuard.stop();
            m_ccCur.insert(QStringLiteral("connect_ms"), double(m_ccT.elapsed()));
            m_ccConnEpochSec = QDateTime::currentSecsSinceEpoch();
            m_ccHsPolls = 0;
            m_ccProgress = tr("цикл %1/%2 · рукопожатие…").arg(m_ccCycle + 1).arg(kCcCycles);
            m_ccT.start();
            ccEnterPhase(CcPhase::Handshake, (kCcHsPollMax + 4) * kCcHsPollMs);
            ccPollHandshake();
        } else if (st == QLatin1String("error")) {
            m_ccCur.insert(QStringLiteral("error"), QStringLiteral("connect-error"));
            ccNextCycle();
        }
        return;
    }
}

// handshake: iOS/Android отдают latestHandshakeEpoch (UAPI/GoBackend), desktop-демон — нет (см.
// VpnConnectionTunnelControl::readStats). Свежий (после момента коннекта) эпох → handshake_ms;
// за kCcHsPollMax поллов не дождались → null (не факт проблемы: desktop просто не отдаёт).
void AvpnEngineQml::ccPollHandshake()
{
    if (m_ccPhase != CcPhase::Handshake)
        return;
    const int epoch = m_ccEpoch;
    const TunnelStats s = m_tunnel.readStats();
    if (s.valid && s.latestHandshakeEpoch >= m_ccConnEpochSec - 3) {
        m_ccCur.insert(QStringLiteral("handshake_ms"), double(m_ccT.elapsed()));
        ccVerify();
        return;
    }
    if (++m_ccHsPolls >= kCcHsPollMax) {
        ccVerify(); // handshake_ms не пишем (null в анализе) — идём проверять данные напрямую
        return;
    }
    QTimer::singleShot(kCcHsPollMs, this, [this, epoch] {
        if (epoch == m_ccEpoch)
            ccPollHandshake();
    });
}

// Правда data-plane: HEAD generate_204 через свежий туннель (first_byte_ms) + вырос ли rx.
// «connected + first byte не прошёл» = класс S4-blackhole («подключено, данных нет»).
void AvpnEngineQml::ccVerify()
{
    m_ccProgress = tr("цикл %1/%2 · проверка данных…").arg(m_ccCycle + 1).arg(kCcCycles);
    ccEnterPhase(CcPhase::Verify, kCcGuardVerifyMs);
    const int epoch = m_ccEpoch;
    const qint64 rxBefore = m_tunnel.readStats().rxBytes;
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(kCcGuardVerifyMs - 2000);
    m_ccT.start();
    QNetworkReply *r = m_nam->head(req);
    connect(r, &QNetworkReply::finished, this, [this, r, epoch, rxBefore] {
        r->deleteLater();
        if (epoch != m_ccEpoch)
            return;
        m_ccGuard.stop();
        const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool ok = (r->error() == QNetworkReply::NoError && (code == 204 || code == 200));
        if (ok)
            m_ccCur.insert(QStringLiteral("first_byte_ms"), double(m_ccT.elapsed()));
        m_ccCur.insert(QStringLiteral("verify_ok"), ok);
        // rx-счётчики обновляются платформой с лагом (реальные данные iOS: чтение сразу после
        // ответа = rx_grew:false при живом трафике) — читаем отложенно
        QTimer::singleShot(1200, this, [this, epoch, rxBefore] {
            if (epoch != m_ccEpoch)
                return;
            const qint64 rxAfter = m_tunnel.readStats().rxBytes;
            if (rxAfter > 0 || rxBefore > 0) // счётчики живы только там, где платформа их отдаёт
                m_ccCur.insert(QStringLiteral("rx_grew"), rxAfter > rxBefore);
            ccNextCycle();
        });
    });
}

void AvpnEngineQml::ccNextCycle()
{
    m_ccGuard.stop();
    m_ccCycles.append(m_ccCur);
    m_ccCur = QJsonObject();
    ++m_ccCycle;
    if (m_ccCycle >= kCcCycles || state() == QLatin1String("error")) {
        ccFinish();
        return;
    }
    m_ccProgress = tr("цикл %1/%2 · отключение…").arg(m_ccCycle + 1).arg(kCcCycles);
    m_ccT.start();
    stop();
    ccEnterPhase(CcPhase::Down, 25000);
}

void AvpnEngineQml::ccGuardFired()
{
    switch (m_ccPhase) {
    case CcPhase::Idle:
        return;
    case CcPhase::Down:
        m_ccCur.insert(QStringLiteral("error"), QStringLiteral("teardown-timeout"));
        break;
    case CcPhase::Up:
        m_ccCur.insert(QStringLiteral("error"), QStringLiteral("connect-timeout"));
        break;
    case CcPhase::Handshake:
        break; // поллы сами уходят в verify; сторож здесь — чистая подстраховка
    case CcPhase::Verify:
        m_ccCur.insert(QStringLiteral("verify_ok"), false);
        m_ccCur.insert(QStringLiteral("error"), QStringLiteral("verify-timeout"));
        break;
    }
    ccNextCycle(); // тайм-аут фазы = данные цикла (это и есть находка), НЕ смерть теста
}

void AvpnEngineQml::ccFail(const QString &reason)
{
    ++m_ccEpoch;
    m_ccGuard.stop();
    m_ccPhase = CcPhase::Idle;
    m_ccProgress.clear();
    emit ccChanged();
    emit error(tr("Тест коннекта прерван: %1").arg(reason));
}

void AvpnEngineQml::ccFinish()
{
    m_ccGuard.stop();
    m_ccPhase = CcPhase::Idle;
    m_ccProgress.clear();

    QVector<double> conn, teardown, firstByte;
    int okCycles = 0;
    for (const QJsonValue &v : m_ccCycles) {
        const QJsonObject c = v.toObject();
        if (c.value(QStringLiteral("connect_ms")).isDouble())
            conn.append(c.value(QStringLiteral("connect_ms")).toDouble());
        if (c.value(QStringLiteral("teardown_ms")).isDouble())
            teardown.append(c.value(QStringLiteral("teardown_ms")).toDouble());
        if (c.value(QStringLiteral("first_byte_ms")).isDouble())
            firstByte.append(c.value(QStringLiteral("first_byte_ms")).toDouble());
        if (c.value(QStringLiteral("verify_ok")).toBool())
            ++okCycles;
    }
    auto num = [](double v) { return v < 0 ? QJsonValue(QJsonValue::Null) : QJsonValue(v); };
    QJsonObject report;
    report.insert(QStringLiteral("schema"), 2);
    report.insert(QStringLiteral("type"), QStringLiteral("connect-cycle"));
    report.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    report.insert(QStringLiteral("cycles"), m_ccCycles);
    report.insert(QStringLiteral("ok_cycles"), okCycles);
    report.insert(QStringLiteral("median_connect_ms"), num(avpn::BenchRunner::median(conn)));
    report.insert(QStringLiteral("median_teardown_ms"), num(avpn::BenchRunner::median(teardown)));
    report.insert(QStringLiteral("median_first_byte_ms"), num(avpn::BenchRunner::median(firstByte)));
    report.insert(QStringLiteral("extra"), benchExtra());

    QVariantMap summary;
    summary.insert(QStringLiteral("cycles"), int(m_ccCycles.size()));
    summary.insert(QStringLiteral("ok_cycles"), okCycles);
    summary.insert(QStringLiteral("median_connect_ms"), report.value(QStringLiteral("median_connect_ms")).toVariant());
    summary.insert(QStringLiteral("median_teardown_ms"), report.value(QStringLiteral("median_teardown_ms")).toVariant());
    summary.insert(QStringLiteral("median_first_byte_ms"), report.value(QStringLiteral("median_first_byte_ms")).toVariant());

    const QString json = QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Compact));
    // история — попадает в единый полный отчёт (buildFullReport), как свип и A/B
    QSettings().setValue(QStringLiteral("AvpnBench/last_connect-cycle"), json);
    emit ccChanged();
    emit ccFinished(summary, json);
}

// ── AVPN bench v5.3: отправка отчёта на control plane ─────────────────────────────────────────
// POST /v1/bench/report (Bearer-токен устройства, тело = отчёт как есть; PII в отчётах нет by
// construction — IP не пишутся ещё на сборке). Сервер копит по device_id — анализ с прода без
// пересылки файлов руками. Бэк-эндпоинт — greenfield (handoff BENCH-REPORT-BACKEND-HANDOFF.md):
// до его выката честно говорим «сервер ещё не принимает отчёты».
void AvpnEngineQml::uploadReport(const QString &json, bool quiet, const QString &outboxFile)
{
    const QByteArray body = json.toUtf8();
    if (body.isEmpty()) return;
    if (quiet && !avpn::TuningStore::flag(QStringLiteral("bench_report_upload"))) return;
    if (body.size() > 3 * 1024 * 1024) {
        emit reportUploadDone(false, tr("Отчёт слишком большой для отправки"));
        return;
    }
    const QString contentId = reportContentId(body);
    const QString stableFile = QDir(reportOutboxDir()).filePath(contentId + QStringLiteral(".json"));
    const QString path = outboxFile.isEmpty() ? stableFile : outboxFile;
    const QString ackKey = QStringLiteral("avpn/reportAcknowledgedHashes");
    if (QSettings().value(ackKey).toStringList().contains(contentId)) {
        QFile::remove(path);
        if (!quiet) emit reportUploadDone(true, tr("Этот отчёт уже доставлен"));
        return;
    }
    if (m_reportsInFlight.contains(contentId)) return;
    // Persist before issuing HTTP: termination during the request must not lose the report.
    if (outboxFile.isEmpty()) outboxEnqueue(json);
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        if (!quiet) emit reportUploadDone(false, tr("Отчёт сохранён; отправим после авторизации"));
        return;
    }
    m_reportsInFlight.insert(contentId);
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/bench/report"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + token.toUtf8());
    QNetworkReply *reply = m_nam->post(req, body);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, quiet, path, stableFile, contentId, ackKey]() {
        reply->deleteLater();
        m_reportsInFlight.remove(contentId);
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool transportOk = reply->error() == QNetworkReply::NoError;
        const QByteArray replyBody = reply->readAll();
        const QString receipt = reportAcknowledgement(code, transportOk, replyBody);
        // AVPN (фикс-волна 2026-09-22, A12): терминальный 4xx (кроме 408/429/401) — повтор
        // бессмыслен; файл удаляем, иначе outbox вечно пересылал бы его на каждом Connected.
        if (receipt.isEmpty()
            && classifyReportResponse(code, transportOk, replyBody) == ReportOutcome::DropTerminal) {
            QFile::remove(path);
            if (stableFile != path) QFile::remove(stableFile);
            reliabilityEvent(QStringLiteral("report_dropped_terminal http=%1").arg(code));
            m_lastUploadStatus = tr("Сервер отклонил отчёт (HTTP %1) — сохраните его файлом").arg(code);
            if (!quiet) emit reportUploadDone(false, m_lastUploadStatus);
            emit ftChanged();
            return;
        }
        if (!receipt.isEmpty()) {
            QSettings settings;
            QStringList acknowledged = settings.value(ackKey).toStringList();
            acknowledged.removeAll(contentId);
            acknowledged.append(contentId);
            while (acknowledged.size() > 128) acknowledged.removeFirst();
            settings.setValue(ackKey, acknowledged);
            settings.sync();
            QFile::remove(path);
            if (stableFile != path) QFile::remove(stableFile);
            reliabilityEvent(QStringLiteral("report_ack id=%1").arg(receipt));
            m_lastUploadStatus = tr("Отправлен на сервер ✓ (%1)")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm")));
            emit reportUploadDone(true, tr("Отчёт отправлен разработчику ✓"));
        } else {
            // Auth/404/429 and missing receipts are not delivery. Keep the bounded outbox.
            reliabilityEvent(QStringLiteral("report_unacknowledged http=%1").arg(code));
            m_lastUploadStatus = QFile::exists(path) ? tr("Доставка не подтверждена — отчёт сохранён")
                                                    : tr("Доставка не подтверждена — сохраните отчёт файлом");
            if (!quiet) emit reportUploadDone(false, m_lastUploadStatus);
        }
        emit ftChanged();
    });
}

// ── BUG-7 (2026-07-24): персистентный outbox отчётов ─────────────────────────────────────────
// Диагностику чаще всего шлют В МОМЕНТ сетевой беды (control plane за мёртвым туннелем) —
// Files use a SHA-256 content ID, QSaveFile atomic persistence and receipt-backed ACK removal.
// flush: старт (+25с), фронт connected (+10с). Кап 20 файлов (старые вытесняются).
// Kill-switch features.report_outbox (default ON).
static QString reportOutboxDir()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                        + QStringLiteral("/report-outbox");
    QDir().mkpath(dir);
    return dir;
}

void AvpnEngineQml::outboxEnqueue(const QString &json)
{
    if (!featureEnabled(QStringLiteral("report_outbox"), true)) return;
    const QByteArray body = json.toUtf8();
    if (body.isEmpty() || body.size() > 3 * 1024 * 1024) return;
    QDir dir(reportOutboxDir());
    const QString path = dir.filePath(reportContentId(body) + QStringLiteral(".json"));
    if (QFile::exists(path)) return; // content dedup, including concurrent manual/automatic upload.
    const QFileInfoList old = dir.entryInfoList({QStringLiteral("*.json")}, QDir::Files,
                                               QDir::Time | QDir::Reversed);
    int count = old.size();
    for (const QFileInfo &file : old) {
        if (count < 20) break;
        if (m_reportsInFlight.contains(file.baseName())) continue;
        if (QFile::remove(file.absoluteFilePath())) --count;
    }
    if (count >= 20) return; // all retained files are being sent; preserve the hard bound.
    QSaveFile file(path);
    if (file.open(QIODevice::WriteOnly) && file.write(body) == body.size()) file.commit();
}

void AvpnEngineQml::outboxFlush()
{
    if (!featureEnabled(QStringLiteral("report_outbox"), true))
        return;
    QDir d(reportOutboxDir());
    const QStringList files = d.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Name);
    for (const QString &name : files) {
        const QString path = d.filePath(name);
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) continue;
        const QString json = QString::fromUtf8(f.readAll());
        f.close();
        if (json.isEmpty()) {
            QFile::remove(path);
            continue;
        }
        uploadReport(json, /*quiet=*/true, /*outboxFile=*/path);
    }
}

// ── AVPN bench v5.2: мастер «Полный тест» ─────────────────────────────────────────────────────
// Дирижёр: этап 1 сам (connect0 → тест коннекта → авто-A/B → свип), два ручных гейта
// (Amnezia / baseline-скип), финал = мега-отчёт одним JSON. Измерительной логики НЕТ —
// только последовательность, ожидание *Finished и сторожа. Ошибка шага НЕ роняет мастер:
// шаг пишется error в methodology, идём дальше (частичный отчёт ценнее прерванного).
static const int kFtGuardConnectMs = 90000;   // connect0: enroll+подключение
static const int kFtGuardCcMs      = 5 * 60000;
static const int kFtGuardAbMs      = 12 * 60000;
static const int kFtGuardSweepMs   = 15 * 60000;
static const int kFtGuardBenchMs   = 5 * 60000;

QString AvpnEngineQml::lastFullTestJson() const
{
    return QSettings().value(QStringLiteral("AvpnBench/last_full_test")).toString();
}

// Доля прогресса текущего бенча по его стадии (порядок = конвейер BenchRunner; веса ~длительности:
// down/up — самые долгие). Грубая, но живая — юзеру важно видеть движение, не точность.
double AvpnEngineQml::benchStageFrac() const
{
    static const struct { const char *st; double frac; } kMap[] = {
        {"start", 0.02}, {"dns", 0.08}, {"tls", 0.16}, {"http", 0.30}, {"ping", 0.45},
        {"split", 0.55}, {"dns_duel", 0.58}, {"mtu", 0.60}, {"rtt", 0.68}, {"down", 0.80},
        {"up", 0.95}, {"done", 1.0},
    };
    for (const auto &m : kMap)
        if (m_benchStage == QLatin1String(m.st))
            return m.frac;
    return 0.0;
}

// Взвешенная шкала мастера: этап 1 (сам) ≈ 0–86, ручные шаги и финальные бенчи — хвост.
void AvpnEngineQml::ftUpdatePercent()
{
    double p = 0;
    switch (m_ftPhase) {
    case FtPhase::Idle:          p = m_ftPercent; break; // не дёргаем после финиша
    case FtPhase::Connect0:      p = 2; break;
    case FtPhase::Cc:            p = 4 + std::min(m_ccCycle, kCcCycles) * (12.0 / kCcCycles); break;
    case FtPhase::Ab:
        switch (m_abPhase) {
        case AbPhase::Idle:
        case AbPhase::BenchA:    p = 18 + benchStageFrac() * 20; break;
        case AbPhase::WaitDown:
        case AbPhase::WaitUp:    p = 40; break;
        case AbPhase::BenchB:    p = 43 + benchStageFrac() * 17; break;
        case AbPhase::RestoreDown:
        case AbPhase::RestoreUp: p = 61; break;
        }
        break;
    case FtPhase::Sweep:
        p = 62 + (m_sweepQueue.isEmpty() ? 0.0
                  : (std::max(m_sweepIdx, 0) + benchStageFrac()) * (24.0 / m_sweepQueue.size()));
        p = std::min(p, 86.0);
        break;
    case FtPhase::WaitAmnezia:   p = 86; break;
    case FtPhase::BenchAmnezia:  p = 87 + benchStageFrac() * 8; break;
    case FtPhase::WaitBaseline:  p = 95; break;
    case FtPhase::BenchBaseline: p = 95 + benchStageFrac() * 5; break;
    }
    const int np = std::clamp(int(p), 0, 100);
    if (np != m_ftPercent) {
        m_ftPercent = np;
        emit ftChanged();
    }
}

QString AvpnEngineQml::ftStage() const
{
    switch (m_ftPhase) {
    case FtPhase::Idle:          return QString();
    case FtPhase::Connect0:      return QStringLiteral("connect0");
    case FtPhase::Cc:            return QStringLiteral("cc");
    case FtPhase::Ab:            return QStringLiteral("ab");
    case FtPhase::Sweep:         return QStringLiteral("sweep");
    case FtPhase::WaitAmnezia:   return QStringLiteral("wait-amnezia");
    case FtPhase::BenchAmnezia:  return QStringLiteral("bench-amnezia");
    case FtPhase::WaitBaseline:  return QStringLiteral("wait-baseline");
    case FtPhase::BenchBaseline: return QStringLiteral("bench-baseline");
    }
    return QString();
}

void AvpnEngineQml::ftEnter(FtPhase ph, int guardMs)
{
    m_ftPhase = ph;
    m_ftGuard.stop();
    if (guardMs > 0)
        m_ftGuard.start(guardMs);
    ftUpdatePercent();
    emit ftChanged();
}

void AvpnEngineQml::ftRecord(const char *step, const char *status)
{
    QJsonObject s;
    s.insert(QStringLiteral("step"), QLatin1String(step));
    s.insert(QStringLiteral("status"), QLatin1String(status));
    s.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    m_ftSteps.append(s);
}

void AvpnEngineQml::startFullTest()
{
    if (ftRunning() || m_benchRunning || sweepRunning() || abRunning() || ccRunning() || doctorRunning())
        return;
    ++m_ftEpoch;
    m_ftSteps = QJsonArray();
    m_ftPercent = 0;
    ftRecord("full-test", "started");
    if (state() == QLatin1String("connected")) {
        probeServices(); // v5.5: чипы (goodput/троттл) греются заранее — к A/B попадут в extra живыми
        m_ftProgress = tr("этап 1/3 · тест коннекта…");
        ftEnter(FtPhase::Cc, kFtGuardCcMs);
        startConnectCycle();
    } else {
        m_ftProgress = tr("этап 1/3 · подключаю Tribe…");
        ftEnter(FtPhase::Connect0, kFtGuardConnectMs);
        start();
    }
}

void AvpnEngineQml::cancelFullTest()
{
    if (!ftRunning())
        return;
    ++m_ftEpoch;
    m_ftGuard.stop();
    // отменить активную под-машину (каждая сама возвращает тумблеры/состояние)
    if (ccRunning()) cancelConnectCycle();
    if (abRunning()) cancelBypassAb();
    if (sweepRunning()) cancelNodeSweep();
    if (m_benchRunning) cancelBench();
    ftRecord("full-test", "cancelled");
    m_ftPhase = FtPhase::Idle;
    m_ftProgress.clear();
    m_ftPercent = 0;
    emit ftChanged();
}

// Продвижение: завершился шаг donePhase (ok/сторож). Ошибка шага не прерывает мастер.
void AvpnEngineQml::ftStepDone(FtPhase donePhase, bool ok)
{
    if (m_ftPhase != donePhase || m_ftPhase == FtPhase::Idle)
        return;
    m_ftGuard.stop();
    // Сторож добил шаг → ОТМЕНИТЬ зависшую под-машину, иначе она живёт параллельно со следующим
    // шагом (реальный прогон 2026-07-06: свип завис на мёртвой Польше, сторож увёл мастер на
    // ручной шаг Amnezia, а свип продолжал реконнектить наш туннель под ногами у юзера).
    if (!ok) {
        switch (donePhase) {
        case FtPhase::Cc:            if (ccRunning()) cancelConnectCycle(); break;
        case FtPhase::Ab:            if (abRunning()) cancelBypassAb(); break;
        case FtPhase::Sweep:         if (sweepRunning()) cancelNodeSweep(); break;
        case FtPhase::BenchAmnezia:
        case FtPhase::BenchBaseline: if (m_benchRunning) cancelBench(); break;
        default: break;
        }
    }
    const int epoch = m_ftEpoch;
    switch (donePhase) {
    case FtPhase::Idle:
        return;
    case FtPhase::Connect0:
        ftRecord("connect0", ok ? "ok" : "error");
        if (!ok) { // подключиться не смогли — этап 1 невозможен, уходим сразу на ручные шаги
            m_ftProgress = tr("этап 2/3 · включи Amnezia и нажми «Продолжить»");
            ftEnter(FtPhase::WaitAmnezia);
            return;
        }
        probeServices(); // v5.5: греем чипы сразу после подключения
        m_ftProgress = tr("этап 1/3 · тест коннекта…");
        ftEnter(FtPhase::Cc, kFtGuardCcMs);
        startConnectCycle();
        return;
    case FtPhase::Cc:
        ftRecord("connect-cycle", ok ? "ok" : "error");
        m_ftProgress = tr("этап 1/3 · авто-A/B байпаса…");
        ftEnter(FtPhase::Ab, kFtGuardAbMs);
        // A/B требует connected; после cc мы connected (последняя фаза — verify)
        QTimer::singleShot(500, this, [this, epoch] {
            if (epoch == m_ftEpoch && m_ftPhase == FtPhase::Ab)
                startBypassAb();
        });
        return;
    case FtPhase::Ab:
        ftRecord("ab-bypass", ok ? "ok" : "error");
        m_ftProgress = tr("этап 1/3 · свип всех нод…");
        ftEnter(FtPhase::Sweep, kFtGuardSweepMs);
        QTimer::singleShot(500, this, [this, epoch] {
            if (epoch == m_ftEpoch && m_ftPhase == FtPhase::Sweep)
                startNodeSweep();
        });
        return;
    case FtPhase::Sweep:
        ftRecord("node-sweep", ok ? "ok" : "error");
        // ручной шаг: сами опускаем наш туннель, юзеру остаётся включить Amnezia
        m_ftProgress = tr("этап 2/3 · включи Amnezia (наш ключ) и нажми «Продолжить»");
        stop();
        ftEnter(FtPhase::WaitAmnezia);
        return;
    case FtPhase::WaitAmnezia:
    case FtPhase::WaitBaseline:
        return; // продвигаются только fullTestContinue/fullTestSkip
    case FtPhase::BenchAmnezia:
        ftRecord("bench-amnezia", ok ? "ok" : "error");
        m_ftProgress = tr("этап 3/3 · выключи ВСЕ VPN и нажми «Продолжить» (или пропусти)");
        ftEnter(FtPhase::WaitBaseline);
        return;
    case FtPhase::BenchBaseline:
        ftRecord("bench-baseline", ok ? "ok" : "error");
        ftFinish();
        return;
    }
}

void AvpnEngineQml::fullTestContinue()
{
    if (m_ftPhase == FtPhase::WaitAmnezia) {
        if (state() == QLatin1String("connected")) // наш ещё поднят — гейт (QML тоже дизейблит)
            return;
        m_ftProgress = tr("этап 2/3 · замер через Amnezia…");
        ftEnter(FtPhase::BenchAmnezia, kFtGuardBenchMs);
        startBench(QStringLiteral("amnezia"));
    } else if (m_ftPhase == FtPhase::WaitBaseline) {
        if (state() == QLatin1String("connected"))
            return;
        m_ftProgress = tr("этап 3/3 · замер без VPN (baseline)…");
        ftEnter(FtPhase::BenchBaseline, kFtGuardBenchMs);
        startBench(QStringLiteral("baseline"));
    }
}

void AvpnEngineQml::fullTestSkip()
{
    if (m_ftPhase != FtPhase::WaitBaseline)
        return;
    ftRecord("bench-baseline", "skipped");
    ftFinish();
}

// Мега-отчёт мастера: buildFullReport (метки+сравнения+свип+cc+A/B) + methodology (шаги/время/
// пропуски — видно, что серия снята одной сессией) + summary (выжимка ВСЕХ вердиктов всех секций —
// анализ начинается с одного блока) + гард методики baseline-suspect (egress baseline == стране
// ноды amnezia-замера ⇒ «похоже, VPN не был выключен» — человеческая ошибка ручного шага).
QString AvpnEngineQml::assembleMegaReport() const
{
    QJsonObject rep = QJsonDocument::fromJson(buildFullReport().toUtf8()).object();
    if (rep.isEmpty()) {
        rep.insert(QStringLiteral("schema"), 2);
        rep.insert(QStringLiteral("type"), QStringLiteral("full-report"));
    }
    QJsonObject meth;
    meth.insert(QStringLiteral("wizard"), true);
    meth.insert(QStringLiteral("steps"), m_ftSteps);
    rep.insert(QStringLiteral("methodology"), meth);

    QJsonArray sum;
    auto addVerdicts = [&sum](const QString &section, const QJsonObject &run) {
        for (const QJsonValue &v : run.value(QStringLiteral("verdicts")).toArray()) {
            QJsonObject o = v.toObject();
            o.insert(QStringLiteral("section"), section);
            sum.append(o);
        }
    };
    const QJsonObject runs = rep.value(QStringLiteral("runs")).toObject();
    for (auto it = runs.constBegin(); it != runs.constEnd(); ++it)
        addVerdicts(it.key(), it.value().toObject());
    const QJsonArray sweepNodes = rep.value(QStringLiteral("node_sweep")).toObject()
                                     .value(QStringLiteral("nodes")).toArray();
    for (const QJsonValue &n : sweepNodes)
        addVerdicts(QStringLiteral("sweep:%1").arg(n.toObject().value(QStringLiteral("label")).toString()),
                    n.toObject());
    const QJsonObject cc = rep.value(QStringLiteral("connect_cycle")).toObject();
    if (!cc.isEmpty()) {
        const int okC = cc.value(QStringLiteral("ok_cycles")).toInt();
        const int allC = cc.value(QStringLiteral("cycles")).toArray().size();
        if (allC > 0 && okC < allC) {
            QJsonObject o = bench::mkVerdict("connect-cycle-failures", "bad",
                tr("Тест коннекта: успешно %1 из %2 циклов").arg(okC).arg(allC));
            o.insert(QStringLiteral("section"), QStringLiteral("connect_cycle"));
            sum.append(o);
        }
    }
    // baseline-suspect: страна egress baseline == стране egress amnezia-замера → VPN не выключали
    const QString baseLoc = runs.value(QStringLiteral("baseline")).toObject()
                                .value(QStringLiteral("network")).toObject()
                                .value(QStringLiteral("egress")).toObject()
                                .value(QStringLiteral("loc")).toString();
    const QString amnLoc = runs.value(QStringLiteral("amnezia")).toObject()
                               .value(QStringLiteral("network")).toObject()
                               .value(QStringLiteral("egress")).toObject()
                               .value(QStringLiteral("loc")).toString();
    const bool baselineSuspect = !baseLoc.isEmpty() && !amnLoc.isEmpty() && baseLoc == amnLoc;
    if (baselineSuspect) {
        QJsonObject o = bench::mkVerdict("baseline-suspect", "warn",
            tr("baseline и amnezia видят один egress (%1) — похоже, VPN не был выключен при baseline-замере").arg(baseLoc));
        o.insert(QStringLiteral("section"), QStringLiteral("methodology"));
        sum.append(o);
    }
    // build 62 (цензура-детект): хост молчит в baseline (без VPN) и открывается через туннель →
    // явный диагноз «оператор блокирует X». Нога «через VPN» = bypass-off (полный туннель);
    // фолбэк bypass-on — внутри bench::censorship() RU-корпус тогда пропускается (шёл мимо туннеля).
    // Гейт: baseline не под подозрением (иначе baseline врёт и сравнение бессмысленно).
    if (!baselineSuspect) {
        QJsonObject vpnRun = runs.value(QStringLiteral("tribe-bypass-off")).toObject();
        if (vpnRun.isEmpty())
            vpnRun = runs.value(QStringLiteral("tribe-bypass-on")).toObject();
        const QJsonArray cens = bench::censorship(runs.value(QStringLiteral("baseline")).toObject(), vpnRun);
        for (const QJsonValue &v : cens) {
            QJsonObject o = v.toObject();
            o.insert(QStringLiteral("section"), QStringLiteral("baseline"));
            sum.append(o);
        }
    }
    rep.insert(QStringLiteral("summary"), sum);
    return QString::fromUtf8(QJsonDocument(rep).toJson(QJsonDocument::Compact));
}

void AvpnEngineQml::ftFinish()
{
    m_ftGuard.stop();
    ftRecord("full-test", "finished");
    m_ftPhase = FtPhase::Idle;
    m_ftProgress.clear();
    m_ftPercent = 100;
    const QString json = assembleMegaReport();
    // v5.4: мега-отчёт живёт в QSettings — переживает навигацию/перезапуск («не сбрасывается»),
    // и уходит на сервер САМ (quiet: пока бэк не принимает — без нытья тостом, только успех/сеть)
    QSettings().setValue(QStringLiteral("AvpnBench/last_full_test"), json);
    emit ftChanged();
    emit ftFinished(json);
    uploadReport(json, /*quiet=*/true);
}

// история замеров (QSettings AvpnBench/last_<label>) — для A/B между запусками
QString AvpnEngineQml::benchLastJson(const QString &label) const
{
    return QSettings().value(QStringLiteral("AvpnBench/last_%1").arg(label)).toString();
}

// AVPN (авто-A/B): сводный отчёт всех собранных меток одним JSON — вместо пересылки 4 файлов.
// compares: baseline↔off (цена туннеля), off↔on (цена байпаса), amnezia↔off (Tribe vs ванилла).
QString AvpnEngineQml::buildFullReport() const
{
    static const char *const kLabels[] = { "baseline", "tribe-bypass-on", "tribe-bypass-off", "amnezia" };
    QJsonObject runs;
    for (const char *l : kLabels) {
        const QString j = benchLastJson(QLatin1String(l));
        if (!j.isEmpty())
            runs.insert(QLatin1String(l), QJsonDocument::fromJson(j.toUtf8()).object());
    }
    QJsonObject report;
    report.insert(QStringLiteral("schema"), 1);
    report.insert(QStringLiteral("type"), QStringLiteral("full-report"));
    report.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    report.insert(QStringLiteral("runs"), runs);
    QJsonObject compares; // bench::compare(a,b) = «b относительно a», significant = ухудшения b
    auto add = [&](const char *name, const char *a, const char *b) {
        if (runs.contains(QLatin1String(a)) && runs.contains(QLatin1String(b)))
            compares.insert(QLatin1String(name),
                            bench::compare(runs.value(QLatin1String(a)).toObject(),
                                           runs.value(QLatin1String(b)).toObject()));
    };
    add("tunnel_cost_off_vs_baseline", "baseline", "tribe-bypass-off");
    add("bypass_cost_on_vs_off", "tribe-bypass-off", "tribe-bypass-on");
    add("tribe_off_vs_amnezia", "amnezia", "tribe-bypass-off");
    report.insert(QStringLiteral("compares"), compares);
    // v5.1 «всё-в-одном» (реальный фидбек: «неудобно каждый отчёт отдельным файлом»): вклеиваем
    // последние свип нод / тест коннекта / авто-A/B — один файл покрывает все шаги методики.
    auto attach = [&report](const char *section, const char *key) {
        const QString j = QSettings().value(QStringLiteral("AvpnBench/last_%1").arg(QLatin1String(key))).toString();
        if (!j.isEmpty())
            report.insert(QLatin1String(section), QJsonDocument::fromJson(j.toUtf8()).object());
    };
    attach("node_sweep", "node-sweep");
    attach("connect_cycle", "connect-cycle");
    attach("ab_bypass", "ab-bypass");
    // пусто только если совсем нечего отдавать (раньше требовали ≥2 метки — свип/коннект пропадали)
    if (runs.isEmpty() && !report.contains(QStringLiteral("node_sweep"))
        && !report.contains(QStringLiteral("connect_cycle"))
        && !report.contains(QStringLiteral("ab_bypass")))
        return {};
    return QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Compact));
}

// Сохранение отчёта файлом — весь платформенный веер уже в SystemController::saveFile (upstream:
// desktop = запись по пути, iOS = temp + share sheet файла, Android = SAF). Здесь только мост в QML.
bool AvpnEngineQml::saveReportFile(const QString &fileName, const QString &json) const
{
    if (fileName.isEmpty() || json.isEmpty())
        return false;
    return SystemController::saveFile(fileName, json);
}

// метка → ts последнего замера (для карточки «собрано N/4»; свежесть видна по датам)
QVariantMap AvpnEngineQml::benchHistoryInfo() const
{
    static const char *const kLabels[] = { "baseline", "tribe-bypass-on", "tribe-bypass-off", "amnezia" };
    QVariantMap out;
    for (const char *l : kLabels) {
        const QString j = benchLastJson(QLatin1String(l));
        if (j.isEmpty())
            continue;
        out.insert(QLatin1String(l),
                   QJsonDocument::fromJson(j.toUtf8()).object().value(QStringLiteral("ts")).toString());
    }
    return out;
}

void AvpnEngineQml::clearBenchHistory()
{
    QSettings s;
    s.beginGroup(QStringLiteral("AvpnBench"));
    s.remove(QString());
    s.endGroup();
}

void AvpnEngineQml::onConnectionStateChanged(Vpn::ConnectionState s) // AVPN
{
    // Review E2 of 18.11: an event of an older leg (a duplicate error, a late answer) is dropped before any state
    // changes; a confirmed teardown of that older tunnel still frees what was held for its stop.
    if (m_engine.nativeEventStale(m_tunnel.nativeLegSeen())) {
        reliabilityEvent(QStringLiteral("native_event_stale state=%1 native_leg=%2 leg=%3")
                             .arg(int(s)).arg(m_tunnel.nativeLegSeen()).arg(m_engine.attemptLeg()));
        if (s == Vpn::Disconnected) {
            syncControlPlaneEdge(false);
            m_tunnel.upstreamTunnelDown();
        }
        return;
    }
    reliabilityEvent(QStringLiteral("native_state=%1 intent_on=%2 engine=%3 node=%4 proto=%5")
        .arg(int(s)).arg(m_wantConnected).arg(m_engine.debugSnapshot().state)
        .arg(m_engine.currentNodeId()).arg(m_engine.currentNodeProto()));
    if (m_probe) m_probe->cancel();
    // Волна «как апстрим» (2026-09-28): keep-alive соединения к API, открытые через туннель, после
    // его гашения мертвы, но QNAM их переиспользует — все запросы висели до таймаута 15 с (журнал
    // Mac: /v1/subscription, /v1/account, /v1/devices после каждой смены ноды). Апстрим чистит кэш на
    // Connected (connectionUiController.cpp); чистим и на Disconnected — путь сменился в обе стороны.
    // Owner test 06.11 (build 134): clearConnectionCache() strands the requests in flight (Qt destroys
    // its HTTP thread; they ended only by the 15 s timeout - /v1/config included, Xray stayed frozen).
    // So: our clear only on a real transition (not the first observed status, not a repeat); the
    // requests in flight are aborted whenever the cache was cleared - by us, or by upstream on every
    // Connected (adoption included) - and their owners re-issue them over the new path.
    // DebugSnapshot.h::transitionNetAction, NetAwait.h::resetApiConnections.
    {
        const TransitionNetAction net = transitionNetAction(observedTunnelOf(m_lastTunnelState), observedTunnelOf(s));
        if (m_nam && (net.clearCache || net.abortInFlight))
            avpn::resetApiConnections(m_nam, net.clearCache, net.abortInFlight);
    }
    // AVPN (фикс-волна 2026-09-22, A1/A9): состояние движка ДО колбэка — Error/Disconnected посреди
    // СВОЕГО свитча/failover движка не является внешним обрывом (решение ниже).
    const QString engineStateBefore = m_engine.debugSnapshot().state;
#ifdef Q_OS_IOS
    // AVPN (iOS data watch, 141, stage 2): Reasserting (shown as Connecting) -> Connected of a session the
    // engine holds: the extension re-applied its network settings, as an in-place switch does. One fresh
    // status reply before the app attributes anything to a node (TunnelWatchResume::onReasserted).
    if (m_watchResume && avpn::sessionReasserted(s == Vpn::Connected, m_lastTunnelState == Vpn::Connecting, engineStateBefore))
        m_watchResume->onReasserted();
#endif
    {
        const bool changedState = (s != m_lastTunnelState);
#if defined(Q_OS_IOS) || defined(MACOS_NE)
        const bool errorProvesTeardown = false; // iOS/MACOS_NE: Error не доказывает teardown
#else
        const bool errorProvesTeardown = true;  // база 3c8cc74e: Error — терминал
#endif
        // One mapping for both uses (audit of 137); Unknown and Transitional are the same no-op here.
        // With the state before it: an Error with no native attempt since the last terminal (a provider seat or
        // profile refused before the core started) proves nothing new and asks for no status (D4 of 16.11).
        observeTunnelState(m_latch, observedTunnelOf(m_lastTunnelState), observedTunnelOf(s), errorProvesTeardown);
        if (s == Vpn::Disconnected) {
            syncControlPlaneEdge(false);   // E10: the stored edge again before the release goes out directly
            m_tunnel.upstreamTunnelDown(); // seat releases held for this stop go now, over the direct path
            m_stopGeneration = SessionGeneration{};
            m_stopRetries = 0;
            m_stopRetryTimer.stop();
            m_lastEffectsNode.clear(); // волна-4 (P2-3, ревью): выкл→вкл той же ноды — новая сессия, чипы пробуем заново
            m_lastEffectsMs = -1;
        }
        if (changedState) { // новое наблюдение — новый бюджет запросов статуса
            m_statusRequestAttempts = 0;
            m_statusRetryTimer.stop();
        }
    }
    if (s != m_lastTunnelState)
        m_lastTunnelTransitionMs = QDateTime::currentMSecsSinceEpoch(); // волна-4: окно «своего» перехода
    m_lastTunnelState = s; // AVPN: кэш реального состояния туннеля (для отложенного start() при смене узла)
    // AVPN (self-update v2): туннель погас — можно тихо поставить ожидающее обновление
    // (условия внутри; отложенно, чтобы не вклиниваться в обработку перехода).
    // Туннель пришёл в устойчивое состояние (вкл или выкл) — можно продолжить отложенную тихую
    // установку. Скачивание переходы НЕ отменяют (реш. 2026-09-23: качаем и через VPN); перезапуск
    // приложения посреди перехода не даст гейт mayCommit в момент передачи финишеру.
    if (s == Vpn::Disconnected || s == Vpn::Error || s == Vpn::Connected)
        QTimer::singleShot(1500, this, [this] { maybeAutoUpdate(); });
    // Правдивый статус: маппим РЕАЛЬНОЕ состояние VpnConnection в фазу движка. up() лишь ставит
    // туннель в очередь (async) и НЕ объявляет Connected — переход прилетает сюда.
    switch (s) {
    case Vpn::Connected:
        // AVPN (BUG-6, адопция живого туннеля): onTunnelConnected() поднимает Connected только из
        // фаз подъёма; false = факт «туннель жив» пришёл, когда движок в терминале и это НЕ наша
        // операция — туннель пережил перезапуск GUI (iOS: NE после смахивания, initialize() эмитит
        // Connected; desktop: демон держит туннель, факт приходит из стартовой пробы). Раньше факт
        // игнорировался (UI «выключен»), а ближайший reconcile ГАСИЛ живой туннель (wantConnected
        // false → guardedStop). Адопт по образцу Android §13a: намерение ПЕРЕД воскрешением —
        // иначе reconcile погасит. §13 цел: это не авто-коннект из OFF, а факт живого СВОЕГО
        // туннеля (iOS-обсервер фильтрует чужие сессии; Android-путь сюда же — идемпотентен).
        // Kill-switch: features.adopt_live_tunnel (default ON).
        // AVPN awg31-xray-v1: повторный Connected в фазе Verifying (iOS Reconnecting→Connected при
        // смене сети) — НЕ адопт (движок и так знает свой туннель), а перезапуск верификации ниже.
        // AVPN (фикс-волна 2026-09-22, A1/A4): решение об адопте — tryAdoptObservedTunnel
        // (DebugSnapshot.h::decideTunnelAdoption): Error адопт не блокирует; OFF-намерение не
        // блокирует НОВУЮ сессию (Настройки/Shortcuts); стоп этой же сессии в пути — блокирует.
        if (!m_engine.onTunnelConnected() && !m_engine.isVerifying())
            tryAdoptObservedTunnel("connected");
        else
            identifyAdoptedSession();
#if defined(AMNEZIA_DESKTOP) && !defined(MACOS_NE)
        // AVPN (wake-реконнект): успешный подъём закрывает wake-операцию (если шла) и заново
        // перехватывает wakeup/networkChanged — createProtocolConnections на КАЖДОМ connectToVpn
        // переподключает ванильный rep→reconnectToVpn, срезать надо после каждого коннекта.
        // Волна-3 (2026-09-28): весь десктоп, не только macOS — Windows/Linux-демон шлёт те же
        // wakeup/networkChanged, и там тот же цикл «ваниль → Reconnecting → сторож → intent off».
        m_wakeRestartPending = false;
        m_wakeTries = 0;
        hookDaemonWakeSignals();
#endif
        if (m_rttProbe)
            m_rttProbe->cancel(); // подключились → off-tunnel ICMP больше не нужен (был бы внутри туннеля)
        // AVPN upstream nodes (contract §2): a provisional session confirms its seat through the tunnel now
        // (after this transition's abort snapshot above - the acquire is not cut by it).
        if (m_engine.currentNodeIsUpstream())
            m_tunnel.upstreamTunnelUp();
        // AVPN awg31-xray-v1 (инвариант волны §4.3): xray поднят платформой → движок в Verifying —
        // «Подключено» и все его эффекты (пуши/чипы/живой RTT/история) ТОЛЬКО после первой удачной
        // пробы через туннель (startXrayVerification → finishVerify → onTunnelUpEffects). awg — сразу.
        // Plan v3 step 5: with features.node_scan awg verifies too (whoami) - startDataPathVerification.
        if (m_engine.isVerifying()) {
            startDataPathVerification();
        } else {
            // No check for this Connected (flag off, adopted session): no "data flows" mark. A
            // repeated Connected of an already connected session keeps the verdict it had.
            if (engineStateBefore != QLatin1String("connected"))
                m_pathCheck.clear();
            onTunnelUpEffects();
        }
        break;
    case Vpn::Error:
        ++m_verifyEpoch; // стейл-ответы верификации xray выбрасываются
        // A1b: статус перед новым стартом запросит reconcile (AwaitStatus, backoff 1/2/4 с).
        // AVPN (анти-авто-коннект): РАНЬШЕ обрыв из Connected → notifyConnectionLost() → реактивный
        // авто-failover (реконнект). Это давало НЕЖЕЛАТЕЛЬНЫЙ авто-коннект, когда туннель гасит ВНЕШНЕ
        // (другой VPN / iOS / пользователь снял VPN): приложение тут же переподнимало туннель, «воюя»
        // с другим VPN и самоподключаясь при входе в приложение. Теперь как обычное VPN-приложение:
        // фиксируем факт, НЕ реконнектим сами. (Failover по РЕАЛЬНОЙ смерти ноды остаётся в health-loop
        // tick — onTick→m_engine.tick, см. §анти-авто-коннект ниже + CONNECT-INVARIANTS §13.)
#if defined(Q_OS_IOS) || defined(MACOS_NE)
        m_engine.onTunnelError(/*tunnelGone=*/false); // iOS/MACOS_NE: Error does not prove the teardown
#else
        m_engine.onTunnelError(/*tunnelGone=*/true);
#endif
        break;
    case Vpn::Disconnected:
        // onTunnelDisconnected САМ продолжит НАМЕРЕННЫЙ свитч ноды (Switching+pendingSwitch → up());
        // если это не свитч — просто «отключено». БЕЗ реактивного failover на внешний обрыв (см. Error).
        ++m_verifyEpoch; // AVPN awg31-xray-v1: верификация xray старой сессии отменена
    {
        const QString pinBefore = m_engine.pinnedNodeId();
        m_engine.onTunnelDisconnected();
        // 5.1.109 (R7e): the engine applied a deferred pool body between the runtimes of its own switch
        // (GAP-1) - the same post-processing as applyPendingReseed: RTT view and the pin (a pin the mode
        // cannot serve is persisted as cleared, pin_cleared why=reseed; a migrated one - its new id).
        if (m_engine.takeReseedAppliedInSwitch()) {
            m_nodeRtt = m_engine.measuredRtt();
            restorePin(pinBefore);
            qInfo() << "[avpn reseed] pool revision" << m_engine.poolRevision() << "applied inside a switch";
        }
    }
        break;
    case Vpn::Reconnecting:
        // Промежуточное iOS-Reconnecting: НЕ инициируем свитч/реконнект — дождёмся терминала.
        break;
    default: // Unknown/Preparing/Connecting/Disconnecting — промежуточные, фазу движка не трогаем.
        break;
    }

    // AVPN (анти-авто-коннект на внешний обрыв): если туннель ушёл в Disconnected/Error, и при этом мы
    // НЕ ведём свою операцию (m_op==None: не наш start/stop) и движок НЕ в намеренном свитче/коннекте
    // (switching/connecting/selecting), значит туннель погас ВНЕШНЕ (другой VPN / iOS / пользователь).
    // Снимаем намерение, чтобы reconcile() НЕ поднял туннель заново — подключение только вручную.
    // AVPN (фикс-волна 2026-09-22, A9): решение — по состоянию движка ДО колбэка (раньше брали
    // состояние ПОСЛЕ onTunnelError — всегда "error", и Error посреди внутреннего failover снимал
    // намерение без тоста) плюс флаг прерванного свитча движка (K5/B5). Внутренний свитч: намерение
    // сохраняется, следующий старт — после подтверждённого терминала (A1b), с m_startAttempts.
    // Ревью CL-A r2 (K3): после liveSessionFound фасад снял свой Op::Starting и ждёт реальный статус.
    // Disconnected/Error до Connected — это сорвавшийся Connect пользователя (намерение сохраняем,
    // попытка считается, reconcile повторит старт), а не внешний обрыв с тихим снятием намерения.
    const bool liveSessionLost = m_liveSessionPending && (s == Vpn::Disconnected || s == Vpn::Error);
    if (s == Vpn::Connected || s == Vpn::Disconnected || s == Vpn::Error) {
        m_liveSessionPending = false;
        m_liveSessionTimer.stop();
    }
    if (liveSessionLost)
        reliabilityEvent(QStringLiteral("live_session_lost native=%1").arg(int(s)));
    if (s == Vpn::Disconnected || s == Vpn::Error) {
        const QString est = m_engine.debugSnapshot().state; // DebugSnapshot-структура (поле, не QVariantMap)
        const bool weAreOperating = (m_op != Op::None) || liveSessionLost; // наш start/stop в полёте
        const bool engineStillSwitching = (s == Vpn::Disconnected && engineOwnTransitionState(est));
        const bool interrupted = m_engine.attemptRunning(); // the attempt owner walks on: our own operation
        // Волна-3 (2026-09-28): класс обрыва вместо «внешний / не внешний». Намерение снимает ТОЛЬКО
        // External (§13); «нет сети» → ждём аплинк; «упал компонент» (демон) → повтор через reconcile.
        const bool componentLost = componentLossFresh(m_componentLost, m_componentLostMs,
                                                      QDateTime::currentMSecsSinceEpoch()); // волна-4: ≤ 30 с
        m_componentLost = false;
        const LossClass loss = classifyLoss(weAreOperating, engineStillSwitching ? est : engineStateBefore,
                                            interrupted, componentLost, uplinkUp());
        if (loss == LossClass::External) {
            m_wantConnected = false;
            // U10: кто снял намерение. Review of 136: our own native stop of a dead adopted session.
            reliabilityEvent(QStringLiteral("intent_off why=external_loss"));
        } else if (loss == LossClass::NoNetwork && m_wantConnected) {
            m_waitUplink = true;
            reliabilityEvent(QStringLiteral("loss class=no_network intent kept"));
        } else if (loss == LossClass::Component && m_wantConnected) {
            reliabilityEvent(QStringLiteral("loss class=component intent kept")); // reconcile starts a new attempt
        } else if (!weAreOperating && !engineStillSwitching && m_wantConnected) {
            reliabilityEvent(QStringLiteral("engine_switch_lost state_before=%1 attempt=%2")
                                 .arg(engineStateBefore).arg(int(m_engine.attemptRunning())));
        }
    }

    // Plan v3 step 5: the tunnel is down and nobody wants it up - the check of that session is over.
    // During the engine's own failover the verdict stays (the caption explains the next path).
    if (s == Vpn::Disconnected && !m_wantConnected)
        m_pathCheck.clear();

    // AVPN (reconcile-машина): терминальное состояние снимает op-in-flight и разрешает следующий шаг;
    // промежуточные (Connecting/Disconnecting/Reconnecting/Preparing) держим «занято» (UI «подбираем…»).
    {
        const bool terminal = (s == Vpn::Connected || s == Vpn::Disconnected
                               || s == Vpn::Error);
        if (terminal) {
            settleOperation("native_terminal");
            m_busy = false;
            if (s == Vpn::Connected)
                m_waitUplink = false;
        } else {
            m_busy = true;                           // идёт переход — занято
        }
        // AVPN awg31-xray-v1: xray поднят, но ещё не подтверждён пробой — орб остаётся «занят»
        // (спиннер «Подключаемся…»/«Проверяем трафик…»), stopping=false (намерение = онлайн).
        if (m_engine.isVerifying() || m_engine.attemptRunning())
            m_busy = true;
        // AVPN awg31-xray-v1 (reseed, инвариант §4.4): терминал → отложенное тело пула применяем
        // с верха цикла событий (никогда из стека колбэка туннеля / Selector::pick).
        if (s == Vpn::Disconnected && m_engine.hasPendingReseed())
            QTimer::singleShot(0, this, [this]() { applyPendingReseed(); });
    }
    syncAttempt(); // path engine: the attempt's journal, ledger and result (no-op when nothing changed)

    // AVPN (реальные палочки): туннель не в Connected → гасим живые палочки (кэш RTT не должен
    // маскировать обрыв). При следующем Connected проба пере-сидирует SignalQuality с нуля.
    if (state() != QLatin1String("connected")
        && (m_liveBars != 0 || m_liveReachable || m_liveProven || m_liveRtt >= 0 || m_liveDead || m_liveFailStreak)) {
        m_signal.reset();
        m_liveBars = 0;
        m_liveRtt = -1;
        m_liveReachable = false;
        m_liveProven = false;      // 5.1.108: a new Connected session proves data again
        m_liveDead = false;        // обрыв/смена ноды → «мертво» снимаем, при новом Connected мерим заново
        m_liveFailStreak = 0;
        emit liveQualityChanged();

        // AVPN чипы v2 (2026-07-12): обрыв/смена ноды → НЕ гасим чипы в серый (источник «то цветные,
        // то серые» на каждом транзиенте iOS Reconnecting), а помечаем последний вердикт stale —
        // QML приглушает чип до первого свежего результата новой ноды. In-flight серию инвалидируем
        // (вердикт старой ноды не должен дописаться в чипы новой), гистерезис сбрасываем (первый
        // вердикт новой ноды принимается сразу — нода могла смениться, старая история не сравнима).
        if (m_svcProbe)
            m_svcProbe->invalidate();
        m_chipHyst.clear();
        m_chipConfirms.clear();
        bool anyFresh = false;
        for (int i = 0; i < m_serviceStatus.size(); ++i) {
            QVariantMap m = m_serviceStatus.at(i).toMap();
            if (!m.value(QStringLiteral("stale"), false).toBool()) {
                m[QStringLiteral("stale")] = true;
                m_serviceStatus[i] = m;
                anyFresh = true;
            }
        }
        if (anyFresh)
            emit serviceStatusChanged();
    }

    // AVPN (ревью CL-A r2, A1a): терминал Connected (или Error на iOS) пришёл на НАШ стоп раньше
    // Disconnected и снял m_op со сторожем — стоп неподтверждён, и его больше никто не ведёт.
    // Ограниченный повтор (2/4 с) либо честное состояние, а не вечный Wait в reconcile.
    if (s == Vpn::Connected || s == Vpn::Error)
        driveUnconfirmedStop(s == Vpn::Connected ? "terminal_connected" : "terminal_error");

    syncControlPlaneEdge(s == Vpn::Connected); // E10: a provider session's control plane uses the reachable edge
    emit changed();

    // AVPN: довести факт до намерения — поднять отложенный старт после Disconnected (смена ноды) или
    // погасить туннель, если намерение изменилось. ОТКЛАДЫВАЕМ через singleShot(0): этот слот вызван из
    // сигнала VpnConnection (возможно — изнутри вложенного QEventLoop сетевого вызова); прямой reconcile()
    // → guardedStart мог бы повторно войти в обработку поверх текущего стека → re-entrancy/abort. Деферим
    // на верх цикла событий. No-op, если op в полёте / состояние промежуточное.
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

void AvpnEngineQml::onVpnProtocolError(amnezia::ErrorCode code) // AVPN
{
    if (m_engine.nativeEventStale(m_tunnel.nativeLegSeen())) { // review E2 of 18.11 (see onConnectionStateChanged)
        reliabilityEvent(QStringLiteral("native_event_stale protocol_error=%1 native_leg=%2 leg=%3")
                             .arg(int(code)).arg(m_tunnel.nativeLegSeen()).arg(m_engine.attemptLeg()));
        return;
    }
    if (m_probe) m_probe->cancel();
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // A1b: ошибка протокола не доказывает teardown — перед новым стартом нужен наблюдённый
    // терминал. Адопт живого туннеля и health это НЕ блокирует.
    m_latch.needStatusBeforeStart = true;
    IosController::Instance()->requestReconcileStatus();
#endif

    // Протокол-уровневая ошибка раньше терялась (сигнал не был подключён). Surface наружу в error().
    // AVPN (анти-авто-коннект): больше НЕ зовём notifyConnectionLost() (реактивный failover/реконнект) —
    // фиксируем факт ошибки; подключение только вручную. См. onConnectionStateChanged выше.
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_engine.onTunnelError(/*tunnelGone=*/false);
#else
    m_engine.onTunnelError(/*tunnelGone=*/true);
#endif
    syncAttempt();
    // AVPN (фикс залипания): ошибка ОБЯЗАНА снять op-in-flight (раньше не трогала m_pendingStart →
    // следующий start() мгновенно return → орб залипал навсегда). Теперь машина разблокируется.
    settleOperation("protocol_error");
    // AVPN: на iOS «InternalError» (код 101) — ЛОЖНЫЙ: m_vpnProtocol там всегда null (туннель ведёт
    // IosController, это норма), а VpnConnection::lastError() из-за этого отдаёт InternalError. Не пугаем
    // им пользователя (он лез тостом при смене сервера/rotateNext). Реальные ошибки показываем.
    if (code != amnezia::ErrorCode::InternalError)
        emit error(errorString(code));
    emit changed();
    // AVPN (аудит N6, §3): только отложенно — слот вызван из сигнала VpnConnection; при живом вложенном
    // цикле (awaitReply в redeemCode/kickDevice) queued-события доставляются ВНУТРЬ него → re-entrancy.
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

void AvpnEngineQml::bootstrap() // AVPN: Task 11 — живой бейдж (ГБ/дней/subActive) ДО первого Connect.
{
    // Дедуп: не стартуем вторую цепочку, если уже успешно прогрузились ИЛИ ретраи в полёте
    // (защита от повторного вызова из QML Component.onCompleted нескольких экранов + дефер-вызова
    // из конструктора). m_bootstrapped теперь ставится ТОЛЬКО при успехе → после исчерпания ретраев
    // повторный заход (навигация/Connect) снова разрешён.
    if (m_bootstrapped || m_bootstrapInFlight)
        return;
    m_bootstrapInFlight = true;
    const bool wasOffline = m_bootstrapRetries >= kBootstrapOfflineAfterFailures;
    m_bootstrapRetries = 0;
    if (wasOffline)
        emit changed(); // новая цепочка: «Нет связи» -> «Загрузка…» (subOffline)

    // Ключи клиента (zero-knowledge) — для enroll и последующего connect; ошибка не фатальна для бейджа.
    QString err;
    if (m_engine.identityEnsureKeys(m_store, err))
        m_tunnel.setClientKeys(m_engine.clientKeys());

    // Тихая прогрузка подписки БЕЗ подъёма туннеля, С РЕТРАЕМ при транзиентном сетевом сбое (см. ниже).
    tryBootstrapSubscription();

    // AVPN (Task 9): если первичный авто-enroll создал subscription_token, а device token уже пришёл
    // из APNs ДО enroll — флашим отложенный push-токен (дедуп защитит от повтора). authToken() пуст →
    // registerPushToken снова тихо отложит до следующего коннекта/ротации.
    flushPendingPushToken();
}

// AVPN: тихий фетч подписки на холодном старте С САМОВОССТАНОВЛЕНИЕМ. Корень бага «после обновления нет
// нод»: одиночный фетч на первом запуске падал транзиентно (сеть/DNS/TLS/NE ещё не прогреты сразу после
// апдейта) → пул пустой до ручного перезапуска ( retry отсутствовал; 401-самохил в ensureSubscription
// сетевые сбои не покрывает). Решение: переарм с бэкоффом 2/4/8/16/30с, затем ВЕЧНЫЙ медленный цикл 60с
// (BootstrapRetry.h), тихо (без error()). Раньше после 5 попыток сдавались навсегда — на сотовой с
// холодным радио первое 60с-окно проваливалось целиком и «∞»/пустой пул жили до перезапуска приложения.
// Ускорение извне — kickBootstrap() (появление сети/foreground) поджимает m_bootstrapRetryTimer.
// АСИНХРОННО (2026-07-07): раньше здесь был m_engine.bootstrap → awaitReply (вложенный QEventLoop,
// до 4с блокировки главного потока НА КАЖДУЮ попытку). С вечным ретраем это недопустимо — перешли
// на armTimeout-цепочку (kNetTimeoutMs 15с: не блокирует UI, и сотовой с холодным радио хватает).
// Успех → m_bootstrapped=true (дедуп), пул наполнен, RTT-проба.
void AvpnEngineQml::tryBootstrapSubscription()
{
    if (m_bootstrapped)
        return;
    const QString token = Enrollment::loadToken();
    if (token.isEmpty()) {
        bootstrapEnrollAsync(/*reEnrolled=*/false); // первый вход: POST /v1/trial → GET /v1/subscription
        return;
    }
    bootstrapFetchAsync(token, /*tokenFromStore=*/true, /*reEnrolled=*/false);
}

// AVPN: async-энролл для bootstrap-цепочки. Повторяет side-эффекты Enrollment::enroll (saveToken,
// clearPendingReferral, Keychain-якорь через saveToken) через те же чистые хелперы, но БЕЗ awaitReply.
void AvpnEngineQml::bootstrapEnrollAsync(bool reEnrolled)
{
    if (!m_nam) { onBootstrapAttemptFailed(); return; }
    QString err;
    if (!m_engine.identityEnsureKeys(m_store, err)) { onBootstrapAttemptFailed(); return; }
    m_tunnel.setClientKeys(m_engine.clientKeys());

    const QByteArray body = Enrollment::buildTrialBody(
        m_engine.identity().publicKey(), Identity::deviceId(m_store), Enrollment::detectPlatform(),
        deviceMarketingName(), Enrollment::loadPendingReferral(),
        DeviceFingerprint::get()); // AVPN (anti-farm, 7eb3467a): паритет с sync-enroll — якорь железа и тут
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/trial"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));

    const quint64 sequence = ++m_subscriptionSequence;
    m_bootstrapSequence = sequence;
    const QString requestToken = Enrollment::loadToken();
    QNetworkReply *reply = m_nam->post(req, body);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, reEnrolled, sequence, requestToken]() {
        reply->deleteLater();
        if (sequence != m_subscriptionSequence || requestToken != Enrollment::loadToken()) {
            reliabilityEvent(QStringLiteral("stale_subscription_response_ignored"));
            if (sequence == m_bootstrapSequence && !m_bootstrapped) {
                m_bootstrapInFlight = false;
                // Let the superseding request finish (15s HTTP deadline), then retry if
                // it did not install a pool. Its success cancels this timer.
                m_bootstrapRetryTimer.start(16000);
            }
            return;
        }
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool netErr = (reply->error() != QNetworkReply::NoError);
        const auto outcome = Enrollment::classifyFetch(code, netErr);
        // Волна-4 (ENG-01): первый запуск при заблокированном основном входе раньше не уходил на
        // зеркало вовсе (bootstrap не репортил в edge-walk) — теперь та же классификация.
        noteApiOutcome(reply);
        if (outcome == FetchOutcome::Transferred) { stopBootstrapTerminal(); return; } // 410: триал не выдаётся
        if (outcome != FetchOutcome::Ok) { onBootstrapAttemptFailed(); return; }
        TrialResponse tr;
        QString perr;
        if (!Enrollment::parseTrialResponse(reply->readAll(), tr, perr)) { onBootstrapAttemptFailed(); return; }
        Enrollment::saveToken(tr.subscriptionToken);
        Enrollment::clearPendingReferral(); // реферал атрибутирован на бэке (first-touch)
        emit changed();                     // authToken появился → зависимые биндинги оживут
        // AVPN (Task 9): device token из APNs мог прийти ДО enroll — теперь authToken есть, флашим.
        flushPendingPushToken();
        bootstrapFetchAsync(tr.subscriptionToken, /*tokenFromStore=*/false, reEnrolled);
    });
}

// AVPN: async GET /v1/subscription для bootstrap-цепочки. Исходы — через те же чистые решатели
// (classifyFetch/decideAuthRecovery, покрыты auth_heal_check), что и синхронный ensureSubscription.
void AvpnEngineQml::bootstrapFetchAsync(const QString &token, bool tokenFromStore, bool reEnrolled)
{
    if (!m_nam) { onBootstrapAttemptFailed(); return; }
    QNetworkRequest req{versionedSubscriptionUrl(
        m_baseUrl, QCoreApplication::applicationVersion())};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    const quint64 sequence = ++m_subscriptionSequence;
    m_bootstrapSequence = sequence;
    const QString requestToken = token;
    const QString requestBase = m_baseUrl;
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, tokenFromStore, reEnrolled, sequence, requestToken, requestBase]() {
        reply->deleteLater();
        noteSubscriptionEdgeOutcome(reply, requestBase); // decision 2026-11-05: stale ones count too
        if (sequence != m_subscriptionSequence || requestToken != Enrollment::loadToken()) {
            reliabilityEvent(QStringLiteral("stale_subscription_response_ignored"));
            if (sequence == m_bootstrapSequence && !m_bootstrapped) {
                m_bootstrapInFlight = false;
                // Let the superseding request finish (15s HTTP deadline), then retry if
                // it did not install a pool. Its success cancels this timer.
                m_bootstrapRetryTimer.start(16000);
            }
            return;
        }
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool netErr = (reply->error() != QNetworkReply::NoError);
        const auto outcome = Enrollment::classifyFetch(code, netErr);
        // Волна-4 (ENG-01): паритет с enroll-путём — edge-walk и детектор через noteApiOutcome.
        noteApiOutcome(reply);
        if (outcome == FetchOutcome::Ok) {
            finishBootstrapSuccess(reply->readAll());
            return;
        }
        if (outcome == FetchOutcome::Transferred) { // 410: подписка уехала — терминально, НЕ ре-энроллим
            if (!m_transferredAway) { m_transferredAway = true; emit changed(); }
            stopBootstrapTerminal();
            return;
        }
        if (Enrollment::decideAuthRecovery(outcome, tokenFromStore, reEnrolled)
            == AuthRecoveryAction::ReEnrollThenRetry) {
            Enrollment::clearToken();               // стейл-токен (ротация secret на бэке) — выкинуть
            bootstrapEnrollAsync(/*reEnrolled=*/true); // один ре-энролл + повторный fetch, без петли
            return;
        }
        if (outcome == FetchOutcome::Unauthorized) { // свежий токен 401 / уже лечили — ретрай не поможет
            stopBootstrapTerminal();
            return;
        }
        onBootstrapAttemptFailed(); // сеть/5xx/429 — транзиентно, вечный ретрай добьёт
    });
}

// AVPN: успех bootstrap-цепочки — единая точка (парс + LKG-персист + пробы + оживление UI).
void AvpnEngineQml::finishBootstrapSuccess(const QByteArray &body)
{
    QString err;
    const QString pinBefore = m_engine.pinnedNodeId();
    const bool parseOk = m_engine.loadSubscription(body, err);
    bool bodyHasNodes = false;
    {
        Subscription parsed;
        QString perr;
        bodyHasNodes = SubscriptionParser::parse(body, parsed, perr) && !parsed.nodes.isEmpty();
    }
    if (parseOk) {
        restorePin(pinBefore);
        m_nodeRtt = m_engine.measuredRtt();
        adoptNativeIdentity();
        refreshAccount(); // волна-4 (ревью): аккаунт один раз после успешного bootstrap (раньше — QML на foreground)
        identifyAdoptedSession(); // A5: пул мог принести ноду адоптированной сессии
    }
    // A10: подготовка старта ждала пул свежей установки — пул пришёл (раунд RTT перезапустит
    // LatchSuccess ниже). Ревью CL-A r2: валидное тело БЕЗ нод и без прежнего пула (устройство без
    // подписки, degraded) — подготовку не держим до потолка 20 с: notePreparationPoolSettled(false)
    // завершает её сразу (finishStartPreparation покажет честную ошибку / CTA подписки).
    notePreparationPoolSettled(parseOk && bodyHasNodes);
    // AVPN (баг 2026-07-10 «начисленный триал не подхватился без перезахода»): исход 200-тела
    // решает чистый decideBootstrapBody (BootstrapRetry.h, покрыт bootstrap_retry_check). Бэк для
    // устройства без подписки отдаёт 200 со status=degraded и nodes:[] — раньше такое тело
    // ЗАЩЁЛКИВАЛО m_bootstrapped=true и навсегда глушило ретрай (kickBootstrap — no-op по защёлке,
    // refreshSubscription пул не наполняет) → начисленная позже подписка жила только после
    // рестарта процесса. Теперь пустой пул = «подписки ещё нет»: стейт применяем (degraded —
    // авторитетная правда, m_subMissingSeen поднимает CTA в UI), но цикл продолжаем — начисление
    // подхватится ближайшим ретраем (≤60с) или kickBootstrap (foreground/сеть).
    switch (avpn::decideBootstrapBody(parseOk, m_engine.hasSubscription())) {
    case avpn::BootstrapBodyAction::RetryTransient:
        onBootstrapAttemptFailed(); // битое тело не затирает LKG-пул и не останавливает ретрай
        return;
    case avpn::BootstrapBodyAction::KeepPollingEmptyPool:
        // Валидное 200-тело (пусть и с пустым пулом) — общие с latch-путём эффекты обязаны
        // случиться и здесь (ревью 2026-07-10): LKG = честный стейт; transferredAway снят
        // (тело валидно = не 410, иначе UI показывал бы «перенесена» вместо CTA после
        // ре-энролла с непровиженным пулом); push-токен флашим (дедуп внутри) — иначе
        // no-sub устройство не получит пуш «подписка активирована».
        saveLkgSubscriptionGuarded(body, bodyHasNodes); // A2: пустое тело не затирает LKG с нодами
        if (m_transferredAway) { m_transferredAway = false; }
        flushPendingPushToken();
        emit changed(); // daysLeft/traffic/subMissing обновятся; защёлку НЕ ставим, таймер жив
        onBootstrapAttemptFailed();
        return;
    case avpn::BootstrapBodyAction::LatchSuccess:
        break;
    }
    saveLkgSubscriptionGuarded(body, bodyHasNodes); // AVPN (LKG): только валидное тело; A2: пустое не затирает ноды
    if (m_transferredAway) { m_transferredAway = false; } // подписка снова валидна (новый ключ/энролл)
    m_bootstrapped = true;
    m_bootstrapInFlight = false;
    m_bootstrapRetries = 0;
    m_bootstrapRetryTimer.stop();
    emit changed(); // подписка наполнена → Q_PROPERTY (daysLeft/traffic*/subActive/nodePool) обновятся
    probeNodeRtt(); // AVPN (выбор по скорости): тёплый off-tunnel ICMP при старте (туннель опущен) —
                    // чтобы ПЕРВЫЙ «Авто (быстрейший)» уже выбирал по реальному RTT, а не по weight.
    flushPendingPushToken(); // токен точно есть — дедуп внутри защитит от повтора
    refreshAnnouncements();  // AVPN (P-ANN): токен есть → подтянуть актуальные объявления
    flushWhitelistEpisodes(); // AVPN (белые списки): сеть жива — отдать накопленные эпизоды
}

// AVPN (фикс-волна 2026-09-22, A2): LKG перезаписываем телом с пустыми nodes, только если в
// текущем дисковом LKG нод тоже нет (иначе degraded/окно readiness стирало рабочий пул и после
// перезапуска — пустой список серверов; дыра была и в базе 3c8cc74e).
void AvpnEngineQml::saveLkgSubscriptionGuarded(const QByteArray &body, bool bodyHasNodes)
{
    bool lkgHasNodes = false;
    if (!bodyHasNodes) {
        const QByteArray lkg = Enrollment::loadLkgSubscription();
        Subscription prev;
        QString perr;
        lkgHasNodes = !lkg.isEmpty() && SubscriptionParser::parse(lkg, prev, perr) && !prev.nodes.isEmpty();
    }
    if (!shouldPersistLkgBody(bodyHasNodes, lkgHasNodes)) {
        reliabilityEvent(QStringLiteral("lkg_empty_body_skipped"));
        return;
    }
    Enrollment::saveLkgSubscription(body);
}

// AVPN (белые списки, спека §7): отправка очереди whitelist-эпизодов после восстановления
// сети. Одна попытка за сессию (m_whitelistEpisodesSent; сброс при новом эпизоде): бэк может
// быть без эндпоинта (handoff WHITELIST-EPISODES-BACKEND-HANDOFF.md) — 404 молчим, очередь
// капнута 10 и не растёт. 2xx -> очередь очищена.
void AvpnEngineQml::flushWhitelistEpisodes()
{
    if (m_whitelistEpisodesSent || !m_nam)
        return;
    QSettings st;
    const QByteArray raw = st.value(QStringLiteral("Whitelist/episodes")).toByteArray();
    const QJsonArray arr = QJsonDocument::fromJson(raw).array();
    if (arr.isEmpty())
        return;
    const QString token = authToken();
    if (token.isEmpty())
        return;
    m_whitelistEpisodesSent = true; // одна попытка за сессию, независимо от исхода
    QJsonObject body;
    body.insert(QStringLiteral("episodes"), arr);
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/telemetry/net-episodes"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + token.toUtf8());
    QNetworkReply *reply = m_nam->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, raw]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300) {
            // Ревью: чистим ТОЛЬКО если очередь не изменилась за время полёта — иначе
            // сотрём эпизод, завершившийся между отправкой и ответом (уйдёт следующей сессией).
            QSettings s;
            if (s.value(QStringLiteral("Whitelist/episodes")).toByteArray() == raw) {
                s.remove(QStringLiteral("Whitelist/episodes"));
                s.sync();
            }
        }
        // 404 (бэк ещё без эндпоинта) / прочее — молчим, очередь останется на следующую сессию
    });
}

// AVPN: провал попытки — тихо переарм: быстрый бэкофф → вечный медленный цикл (никогда не сдаёмся).
void AvpnEngineQml::onBootstrapAttemptFailed()
{
    int delayMs = nextBootstrapDelayMs(m_bootstrapRetries);
    // AVPN (белые списки): в активном режиме сеть мертва для нас ФИЗИЧЕСКИ — растянуть цикл
    // (60с -> ~240с), не жечь батарею/радио. Выход из режима зовёт kickBootstrap() ->
    // немедленный фетч, юзер задержки не видит.
    if (m_whitelistDetector && m_whitelistDetector->active())
        delayMs *= qBound(1, int(avpn::TuningStore::numberOr(
                              QStringLiteral("whitelist_retry_stretch"), 4)), 20);
    m_bootstrapRetryTimer.start(delayMs);
    ++m_bootstrapRetries;
    // AVPN (жалоба 2026-09-29): порог «нет связи» пересечён — UI меняет «Загрузка…» на «Нет связи»
    // (subOffline). Только на переходе: вечный медленный цикл не дёргает биндинги раз в минуту.
    if (m_bootstrapRetries == kBootstrapOfflineAfterFailures)
        emit changed();
}

// AVPN: терминальный исход (410 transferred / невосстановимый 401) — вечный ретрай тут ВРЕДЕН
// (долбил бы бэк каждые 60с заведомо мёртвым запросом). Отпускаем цепочку: следующий заход
// (навигация/kick/Connect/redeem нового ключа) сможет попробовать заново с чистого листа.
void AvpnEngineQml::stopBootstrapTerminal()
{
    m_bootstrapInFlight = false;
    m_bootstrapRetries = 0;
    m_bootstrapRetryTimer.stop();
}

// AVPN (фикс «на сотовой ∞ навсегда»): поджать ретрай bootstrap — сеть появилась/сменилась или
// приложение вышло из фона. СТРОГО про фетч подписки: после успешного bootstrap это no-op, туннель/
// коннект/выбор ноды не трогает (безопасно звать сколь угодно часто). Фетч НЕ запускаем синхронно
// из сигнала: сетевые транзишены/резюм — худший момент для вложенного QEventLoop на главном потоке
// (iOS watchdog, см. NetAwait.h) + сети нужно время устаканиться. Вместо этого взводим таймер.
void AvpnEngineQml::kickBootstrap()
{
    static constexpr int kKickDelayMs = 1200; // как стартовый дефер bootstrap: окно показано, сеть осела
    if (m_bootstrapped)
        return;
    if (!m_bootstrapInFlight) {
        // Цепочка ещё не стартовала (ранний сигнал до дефер-вызова из конструктора) — bootstrap()
        // сам идемпотентен, лишний вызов схлопнется.
        QTimer::singleShot(kKickDelayMs, this, &AvpnEngineQml::bootstrap);
        return;
    }
    // Ретрай спит (до 60с в медленном цикле) — поджать. Если сработает раньше kKickDelayMs сам, не трогаем.
    if (m_bootstrapRetryTimer.isActive() && m_bootstrapRetryTimer.remainingTime() > kKickDelayMs)
        m_bootstrapRetryTimer.start(kKickDelayMs);
}

void AvpnEngineQml::start()
{
    noteUserStart();
    reconcile();
    // reconcile мог ранне-выйти (op-in-flight) без эмита — а направление (stopping) уже сменилось;
    // UI должен увидеть его сразу, не дожидаясь терминального колбэка. // AVPN
    emit changed();
}

// The user-start bookkeeping of start() (AVPN Scanner, plan §2.12: shared with connectToNode, the row tap
// with the VPN off - review F4). Intent on, a fresh series of attempts; the tunnel is moved by reconcile().
void AvpnEngineQml::noteUserStart()
{
    noteIntentChange();
    Avpn_recordGuiIntent(true);
    m_userIntentKnown = true;
    // AVPN (Task 7): явный start() выходит из паузы (пользователь сам поднял VPN).
    m_pauseTimer.stop();
    m_paused = false;
    m_wasConnected = false;
    // AVPN (sub-grace): явный старт снимает состояние «отключено из-за истечения подписки» —
    // и флаг UI, и гард однократности (если подписка всё ещё истекшая, гейт отработает заново).
    m_subEnforcedStop = false;
    m_graceStopInFlight = false;
    // Намерение: хотим быть онлайн (к авто/закреплённой ноде). Факт догонит reconcile() из терминала.
    m_wantConnected = true;
    m_startOrigin = StartOrigin::User; // plan v3 step 5: network memory may be read and written
    m_waitUplink = false;
    m_liveSessionPending = false;
    m_liveSessionTimer.stop();
    // AVPN (фикс-волна 2026-09-22, A1): ручной старт — свежий бюджет запросов статуса. Стоп в пути
    // (awaitingStopConfirm) reconcile дождётся; после Error (needStatusBeforeStart) reconcile сначала
    // спросит статус: наблюдённый Connected = адопт живого туннеля, Disconnected = старт. Раньше здесь
    // был guardedStop() — ручной Connect гасил живой туннель после ложного Error.
    m_statusRequestAttempts = 0;
    m_statusRetryTimer.stop();
}

// AVPN Scanner: every action on the intent moves the serial - the Scanner's own pending connect (and a row
// tap's chain) stops being the Scanner's the moment anything else touches the intent.
void AvpnEngineQml::noteIntentChange()
{
    ++m_intentSerial;
    // Every action on the intent (stop, start, Auto, another pick, ...) ends a seat taken for a switch that has not
    // brought it up yet - before any operation guard (review F1 of 17.11: Stop during the switch's own teardown
    // skipped guardedStop, and the held seat was never given back).
    cancelSeatFirst();
}

// Orb tap (connect audit 2026-11-04, revised P1-4): the single entry point of the orb. The tap does
// what the orb shows, as upstream (decideOrbTap); every tap is journaled (orb_tap) so a double tap
// can be told apart from an app-side restart. Returns the decision name for the QML haptic.
// Programmatic start()/stop() (Doctor, rotation, test tools) do not go through this policy.
QString AvpnEngineQml::orbTap()
{
    const QString st = state();
    const OrbTap d = decideOrbTap(st == QLatin1String("connected"), m_busy, m_wantConnected, ownStopping(),
                                  m_op != Op::None, m_preparingStart, m_liveSessionPending);
    reliabilityEvent(QStringLiteral("orb_tap state=%1 busy=%2 decision=%3 pending=%4")
                         .arg(st).arg(int(m_busy)).arg(QLatin1String(orbTapName(d)))
                         .arg(int(m_liveSessionPending)));
    switch (d) {
    case OrbTap::Start:
        start();
        break;
    case OrbTap::Stop:
    case OrbTap::StopAgain: // idempotent: an in-flight stop is not restarted (stop() checks m_op)
        stop();
        break;
    case OrbTap::Ignore:
        emit changed();
        break;
    }
    return QLatin1String(orbTapName(d));
}

void AvpnEngineQml::stop()
{
    noteIntentChange(); // AVPN Scanner
    Avpn_recordGuiIntent(false);
    m_userIntentKnown = true;
    cancelStartPreparation();
    if (m_probe) m_probe->cancel();
    // Cancel internal failover immediately, even while its down/up is awaiting native.
    m_engine.requestStop();
    // AVPN (Task 7): явный stop() отменяет ожидающую авто-паузу (пользователь сам выключил VPN).
    m_pauseTimer.stop();
    m_paused = false;
    m_wasConnected = false;
    // Намерение: хотим быть офлайн. reconcile() опустит туннель, если он поднят.
    m_wantConnected = false;
    m_needsRestart = false;
    m_waitUplink = false;
    m_statusRequestAttempts = 0;
    m_statusRetryTimer.stop();
    m_liveSessionPending = false;
    m_liveSessionTimer.stop();
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // A4: запоминаем runtime-поколение гасимой сессии — Connected ТОГО ЖЕ поколения до
    // Disconnected = стоп ещё в пути (не адоптировать), ДРУГОГО — новая сессия ОС/пользователя.
    // Unknown (холодный старт, статус ещё не наблюдён) тоже гасим: натив без менеджера отвечает
    // терминалом сам (C1), иначе ранний OFF потерялся бы, а следующий Connected адоптировался.
    const bool stoppable = m_lastTunnelState != Vpn::Disconnected;
#else
    const bool stoppable = m_lastTunnelState != Vpn::Disconnected && m_lastTunnelState != Vpn::Unknown;
#endif
    if (stoppable && m_op != Op::Stopping) {
        m_stopRetries = 0;
        guardedStop("user");
        return;
    }
    reconcile();
    // как в start(): направление (stopping) сменилось сразу, даже если reconcile ранне-вышел
    // (отмена недоехавшего коннекта) — эмитим, чтобы орб мгновенно перестал показывать Connecting. // AVPN
    emit changed();
}

// AVPN (reconcile-машина): ЕДИНСТВЕННАЯ точка, поднимающая/опускающая туннель. Действует ТОЛЬКО из
// терминального состояния (.connected/.disconnected/.error) — никогда не up()/down() поверх перехода
// (back-to-back давало iOS «Operation Cancelled»/«Network error»). Смена ноды: connected + needsRestart
// → guardedStop(); затем на пришедшем Disconnected reconcile() сам поднимет цель (pinned/auto). Зовётся
// из start/stop/switchToNode/rotateNext/selectAuto/reprobe и из onConnectionStateChanged/onWatchdog.
void AvpnEngineQml::reconcile()
{
    if (m_paused)
        return;          // во время авто-паузы туннель ведёт pause-логика — не вмешиваемся
    if (m_opInFlight)
        return;          // операция в полёте — ждём терминального колбэка (debounce, анти-шторм)
    // AVPN (ревью 2026-07-11, гонка «двойной up»): движок ведёт СВОЙ внутренний двухфазный свитч
    // (failover onDead → requestSwitch → down() → на Disconnected continuePendingSwitch → up()),
    // state=Switching держится до Connected/Error. Терминальный Disconnected от down() уже снял
    // m_opInFlight → отложенный reconcile() влезал guardedStart-ом ПОВЕРХ поставленного в очередь
    // up(): второй connectToVpn back-to-back (iOS «Operation Cancelled»), причём второй connect()
    // мог выбрать даже только что признанную DEAD ноду. Из Switching движок выходит ТОЛЬКО через
    // колбэки туннеля (Connected/Error) — каждый снова ставит singleShot(0, reconcile), так что
    // гейт машину не подвешивает.
    // Path engine (design 2026-11-17): while the attempt owner walks its candidates it is the only one that
    // raises and lowers the tunnel; the facade only steps in for the person: an intent off or another choice
    // (a restart) stops the walk through the ordinary stop.
    if (m_engine.attemptRunning() || m_engine.state() == avpn::EngineState::Switching) {
        if ((!m_wantConnected || m_needsRestart) && m_op != Op::Stopping) {
            const bool restart = m_needsRestart;
            m_needsRestart = false;
            m_stopRetries = 0;
            guardedStop(restart ? "attempt_restart" : "attempt_intent_off");
        }
        return;
    }

    const Vpn::ConnectionState s = m_lastTunnelState;
    const ObservedTunnel observed = s == Vpn::Connected ? ObservedTunnel::Connected
        : s == Vpn::Disconnected ? ObservedTunnel::Disconnected
        : s == Vpn::Error ? ObservedTunnel::Error
        : s == Vpn::Unknown ? ObservedTunnel::Unknown : ObservedTunnel::Transitional;
    // AVPN (фикс-волна 2026-09-22, A1): (a) МЫ просили стоп — ждём Disconnected (запрос статуса с
    // backoff; повторы самого стопа ведёт сторож стопа); (b) после Error — перед НОВЫМ стартом
    // наблюдённый терминал. Исчерпанный бюджет (b) = старт разрешён: натив сам проверит владение
    // профилем (K3), вечного «серого» состояния нет.
    switch (reconcileGate(m_latch, observed, m_wantConnected,
                          statusRequestDelayMs(m_statusRequestAttempts) >= 0
                              || m_statusRetryTimer.isActive())) {
    case ReconcileGate::AwaitStatus:
        awaitNativeStatus();
        return;
    case ReconcileGate::Wait:
        driveUnconfirmedStop("reconcile_wait"); // бюджет статуса исчерпан — стоп ведёт повтор, не вечный Wait
        return;
    case ReconcileGate::Proceed:
        if (m_latch.needStatusBeforeStart && s == Vpn::Error && m_wantConnected) {
            m_latch.needStatusBeforeStart = false; // бюджет исчерпан — статус так и не наблюдён
            reliabilityEvent(QStringLiteral("status_unobserved_start_allowed"));
        }
        break;
    }
    const bool connected = (s == Vpn::Connected);
    // iOS/MACOS_NE: Error actionable только без needStatusBeforeStart. Не-iOS: Error — терминал
    // (база 3c8cc74e), анти-зацикливание m_startAttempts ниже. Unknown — начальное, ещё не
    // наблюдённое состояние; native connect сам проверяет владение/статус перед сменой менеджера.
    const bool actionable = reconcileActionable(observed, m_latch);
    if (!connected && !actionable)
        return;          // промежуточное (Connecting/Disconnecting/Reconnecting/Preparing) — ждём

    if (m_wantConnected) {
        if (connected) {
            if (m_needsRestart) {        // надо переехать на другую ноду → сначала чистый teardown
                m_needsRestart = false;
                const qint64 now = QDateTime::currentMSecsSinceEpoch();
                if (restartRequestStale(m_restartRequestedMs, now)) {
                    // Волна-4 (P1-6): запрос пережил фон/заморозку — исполнять его при первом
                    // Connected после разморозки значит перезапустить живой туннель через 1–7 с
                    // после открытия. Сбрасываем; пользователь повторит выбор, если он ещё нужен.
                    reliabilityEvent(QStringLiteral("restart_dropped_stale origin=%1 age_ms=%2")
                                         .arg(m_restartOrigin).arg(now - m_restartRequestedMs));
                    m_restartOrigin.clear();
                    m_restartRequestedMs = -1;
                } else {
                    // Волна-2: источник рестарта — в журнал (раньше «reconcile_restart» был безымянным).
                    const QByteArray why = QByteArrayLiteral("reconcile_restart:") + m_restartOrigin.toUtf8();
                    m_restartOrigin.clear();
                    m_restartRequestedMs = -1;
                    guardedStop(why.constData());
                }
            }
            // connected && !needsRestart → уже где надо
        } else {                         // офлайн, а хотим онлайн → поднимаем выбранную/авто ноду
            if (m_waitUplink && !uplinkUp()) {
                // Волна-3: сети нет — не крутим попытки, старт придёт по событию аплинка.
                reliabilityEvent(QStringLiteral("start_wait_uplink"));
                emit changed();
                return;
            }
            guardedStart();
        }
    } else {                             // хотим офлайн
        if (connected)
            guardedStop("reconcile_intent_off");
        // офлайн → уже отключены
    }
}

// AVPN: поднять туннель. startFlow = enroll→GET /v1/subscription→connect()→up() (async). Помечаем
// op-in-flight + сторож; m_busy держим до прихода Connected (UI «подбираем…»).
void AvpnEngineQml::guardedStart()
{
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // 5.1.109 (S4.1): the runtime gate is looked at BEFORE the start preparation, so the card and
    // connect() read the same value. A start is in flight here (the intent is set): with "Xray"
    // chosen only the loss of tun2socks can take effect, a gain waits for the engine to be idle
    // (TransportModeGate::nextRuntimeGate); with "Auto" / "Amnezia" the gate opens at once.
    if (!m_startPrepared)
        refreshXrayRuntimeGate(QStringLiteral("start"));
#endif
    if (!m_startPrepared) { beginStartPreparation(); return; }
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (BUG-6): реальный старт создаст протокол — дальше stop идёт штатным путём.
    m_adoptedNoProto = false;
#endif
    // AVPN (краш-фикс iOS, анти-реэнтрантность): startFlow ниже крутит вложенный QEventLoop на главном
    // потоке. Если guardedStart переисполнен ИЗ этого цикла (queued onConnectionStateChanged очищает
    // m_opInFlight, затем отложенный reconcile→guardedStart прилетает внутри того же loop.exec()),
    // второй вход застекал бы ещё один loop.exec() → re-entrancy → abort() (см. комментарий ниже + NetAwait.h).
    // Деферим на верх цикла событий — намерение не теряется, повтор отработает после раскрутки стека.
    if (m_inSyncNetCall) {
        QTimer::singleShot(0, this, [this]() { guardedStart(); });
        return;
    }
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN: другой активный VPN (чужой full-tunnel/демон) дерётся за маршрут → «крутится, не
    // подключается». Предупреждаем (не блокируем — на случай ложного срабатывания).
    {
        const QString foreign = avpn::macForeignVpnName();
        if (!foreign.isEmpty())
            emit vpnConflict(foreign);
    }
    // AVPN (ноль терминала): на macOS туннель поднимает root-демон Tribe-service. Ставим/обновляем из
    // ВШИТОГО tarball одним системным промптом пароля (MacServiceInstaller). Триггер: демон не запущен
    // ЛИБО устарел (macServiceOutdated: хэш бинарей вшитого ≠ установленного). Без апдейт-триггера
    // правки логики демона (split-DNS и т.п.) не доезжали бы до юзеров с уже стоящим демоном.
    // Актуальный запущенный демон → мгновенный выход, путь коннекта НЕ меняется.
    //
    // AVPN (beachball-фикс 2026-07-21): установка БОЛЬШЕ НЕ блокирует GUI-поток. Раньше пароль +
    // распаковка tarball + msleep-ожидание демона (до ~5с) жили прямо здесь — окно «висело» с
    // радужным курсором на всё время ввода пароля. Теперь: подтверждение — на главном потоке
    // (macInstallServiceConfirm, display dialog качает события), привилегированная установка +
    // ожидание живого демона — в фоновом QThread (nested QEventLoop нет — CONNECT-INVARIANTS
    // соблюдён), а UI показывает svcInstalling («Устанавливаем службу VPN…»). Продолжение старта —
    // finishSvcInstall → reconcile(): намерение (m_wantConnected) всё это время взведено.
    if (m_svcInstallInFlight)
        return;                       // установка уже идёт — reconcile дождётся finishSvcInstall
    // Волна-3 (2026-09-28): устаревшая, но РАБОТАЮЩАЯ служба — не повод не подключаться. Спрашиваем
    // про обновление один раз за сессию; отказ = подключаемся со старой службой (раньше отказ снимал
    // намерение, и VPN не поднимался вовсе). Неустановленную/неживую службу ставить всё равно надо.
    // DebugSnapshot.h::macServicePlan (AVPN Scanner, item 6: the same decision for the Scanner's explicit tap).
    const avpn::MacServicePlan plan = avpn::macServicePlan(avpn::macServiceInstalled(), avpn::macServiceRunning(),
                                                           avpn::macServiceOutdated(), m_svcUpgradeDeclined);
    const bool outdatedOnly = plan.outdatedOnly;
    const bool needInstall = plan.needInstall;
    if (plan.act) {
        if (needInstall) {
            QString cerr;
            if (!avpn::macInstallServiceConfirm(&cerr)) {
                if (outdatedOnly) {
                    m_svcUpgradeDeclined = true;
                    reliabilityEvent(QStringLiteral("svc_upgrade_declined old_daemon_kept"));
                    // продолжаем старт со старой службой — ниже по функции
                } else {
                    // Службы нет — без установки подключиться невозможно; намерение снимаем честно.
                    m_wantConnected = false;
                    // 5.1.109 (review of df7f49db8): this start is over - its preparation with it.
                    // The flag used to stay set on this return: the next Connect skipped its own
                    // preparation, and until then the facade never looked idle (no mode admission).
                    m_startPrepared = false;
                    reliabilityEvent(QStringLiteral("intent_off why=svc_install_declined"));
                    emit error(cerr.isEmpty() ? tr("Установка службы VPN отменена") : cerr);
                    emit changed();
                    return;
                }
            }
        }
        if (!(outdatedOnly && m_svcUpgradeDeclined)) {
        m_busy = true;               // орб — спиннер; текст даёт svcInstalling
        startSvcWorker(needInstall, [this](bool ok, const QString &ierr) { finishSvcInstall(ok, ierr); });
        return;                       // продолжение старта — из finishSvcInstall (queued)
        }
    }
    // 5.1.108: the service is installed/updated by now - Auto must not spend attempts on an Xray path
    // the installed service cannot start (no tun2socks).
    // 5.1.109 (S4.1): with "Xray" chosen a new service WITH tun2socks does not re-enable Xray here,
    // between the tap and connect() - that waits for the engine to be idle (the card showed a choice
    // made without Xray). With "Auto" / "Amnezia" it does, as before 139: no mode is waiting for it.
    refreshXrayRuntimeGate(QStringLiteral("start"));
#endif

    m_op = Op::Starting;
    m_startPrepared = false;
    m_opInFlight = true;
    m_busy = true;
    m_needsRestart = false;   // свежий старт всегда поднимает целевую (pin/auto) ноду — рестарт не нужен
    // Path engine: no start watchdog - the attempt owner judges every leg by its own deadline (one owner of
    // "this start failed", design 2026-11-17 §7).
    m_lastOwnOpMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P2-6): окно «своего» события сети
    emit changed();

    QString err;
    if (m_engine.identityEnsureKeys(m_store, err))
        m_tunnel.setClientKeys(m_engine.clientKeys());

    // AVPN RU-direct: засеять split-tunnel (рунет CIDR мимо туннеля) ДО подъёма — конфиг должен быть готов
    // к appendSplitTunnelingConfig, который читает routeMode/vpnSites из репозитория при openConnection.
    applyRuBypassSplit();

    // Path engine: the network of this attempt (computed with the tunnel down - the real medium) and the
    // user's choice; the owner reads the ledger of that network.
    m_attemptOrigin = m_startOrigin;
    m_pathCheck.clear();
    m_engine.observeNetwork(currentNetworkObservation());
    syncChoice();
    reliabilityEvent(QStringLiteral("attempt_start origin=%1 net=%2 net_gen=%3 choice=%4 mode=%5")
                         .arg(int(m_attemptOrigin))
                         .arg(m_engine.network().local.isEmpty() ? QStringLiteral("-") : m_engine.network().local)
                         .arg(m_engine.network().generation)
                         .arg(choiceJournal())
                         .arg(avpn::transportModeToString(m_engine.transportMode())));

    // AVPN (КОРНЕВОЙ фикс зависания UI + краша на 2-м коннекте): если подписка УЖЕ загружена
    // (bootstrap при старте или прошлый connect) — поднимаем туннель ЛОКАЛЬНО через m_engine.connect(),
    // БЕЗ синхронного сетевого startFlow. startFlow крутит ВЛОЖЕННЫЙ QEventLoop на ГЛАВНОМ потоке
    // (enroll + GET /v1/subscription); на 2-м коннекте, когда летят сигналы дисконнекта, это давало
    // повторный вход вложенного цикла → «Hang UIKit-runloop» (по логам устройства) → abort(). В Amnezia
    // кнопка коннекта в сеть НЕ ходит — конфиг уже готов, она только поднимает туннель. Делаем так же.
    // AVPN (краш-фикс): startFlow() входит во вложенный QEventLoop (awaitReply). Держим m_inSyncNetCall
    // на время вызова, чтобы переисполнение guardedStart из этого цикла отложилось (см. гард выше), а не
    // застекало второй loop.exec(). QScopedValueRollback гарантирует сброс даже при исключении.
    syncStandbyCandidates(); // upstream nodes: pack candidates against the pool in force (pure, no I/O)
    bool ok;
    {
        QScopedValueRollback<bool> syncGuard(m_inSyncNetCall, true);
        ok = (m_engine.hasSubscription() || !m_engine.candidateNodes().isEmpty()) && m_engine.connect(err);
    }
    if (!ok) {
        // Подъём не удался ДО туннеля (терминального колбэка не будет) — снимаем op-in-flight, считаем
        // попытку, показываем ошибку. Авто-ретрай не запускаем; орб станет «Connect».
        settleOperation("attempt_not_started");
        syncAttempt(); // the attempt's journal lines and its result (ended at once)
        m_wantConnected = false;
        reliabilityEvent(QStringLiteral("intent_off why=attempt_not_started err=%1").arg(err));
        emit error(humanEngineError(err)); // AVPN awg31-xray-v1: no_transport/unsupported_proto → человеческий текст
        emit changed();
        return;
    }
#ifdef Q_OS_IOS
    writeTunnelWatchPlan("start"); // AVPN (iOS data watch, 141): before the queued up() reaches the extension
#endif
    m_healthTimer.start();
    syncAttempt();
    // up() в очереди — реальный Connecting→Connected/Error прилетит в onConnectionStateChanged, где
    // op-in-flight снимется. m_busy остаётся true до тех пор.
    emit changed();
}

// AVPN: опустить туннель. requestStop() гасит фазу/failover ДО down() (иначе прилетевший Disconnected
// переподнял бы ноду); реальный Disconnected снимет op-in-flight и reconcile поднимет цель при смене.
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
// AVPN (beachball-фикс): the privileged part of the service step in a background QThread (no nested
// QEventLoop): needInstall - the bundled installer (password + tarball + bootstrap + waiting for the daemon);
// otherwise launchd is given up to ~5 s to bring an installed daemon up. `done` on the GUI thread. Shared by
// guardedStart (Connect) and scannerEnsureService (the Scanner's explicit tap) - one code path.
void AvpnEngineQml::startSvcWorker(bool needInstall, std::function<void(bool, const QString &)> done)
{
    m_svcInstallInFlight = true;
    m_svcInstalling = true;
    emit changed();
    QThread *worker = QThread::create([this, needInstall, done]() {
        QString ierr;
        bool ok = true;
        if (needInstall) {
            ok = avpn::macInstallServiceRun(&ierr); // пароль + tarball + bootstrap + ожидание демона
        } else {
            // Демон установлен, но не бежит (рестарт/kill) — даём launchd до ~5с поднять его;
            // старт продолжаем в любом случае (паритет с прежним поведением: up() сам упадёт
            // честной ошибкой, если демона так и нет).
            for (int i = 0; i < 16 && !avpn::macServiceRunning(); ++i)
                QThread::msleep(300);
        }
        QMetaObject::invokeMethod(this, [done, ok, ierr]() { done(ok, ierr); }, Qt::QueuedConnection);
    });
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
}

// AVPN (beachball-фикс): финиш фоновой установки root-демона. Главный поток (queued из worker).
void AvpnEngineQml::finishSvcInstall(bool ok, const QString &err)
{
    m_svcInstallInFlight = false;
    m_svcInstalling = false;
    m_busy = false;              // guardedStart сам вернёт busy, если старт продолжится
    if (!ok) {
        m_wantConnected = false;
        reliabilityEvent(QStringLiteral("intent_off why=svc_install_failed"));
        emit error(err.isEmpty() ? tr("Не удалось установить службу VPN") : err);
        emit changed();
        return;
    }
    emit changed();
    // Намерение всё это время было взведено; если пользователь за время установки передумал
    // (нажал «Отключить»), reconcile честно останется no-op. Иначе — штатный guardedStart,
    // теперь по быстрому пути (демон запущен и актуален).
    reconcile();
}

// 5.1.109 (S4.1, reviews of d5d739403 and df7f49db8): losing tun2socks takes effect at once (a start
// must not pick a transport the service cannot raise); gaining it while "Xray" is the choice - only
// while nothing is running: a service updated inside that Connect adds Xray for the next start, the
// start in flight raises what the card showed. With "Auto" / "Amnezia" chosen the gain is taken at
// once (TransportModeGate::nextRuntimeGate).
bool AvpnEngineQml::refreshXrayRuntimeGate(const QString &why)
{
    // Upstream nodes (point 14): the geo pair is a separate input, checked at the same points (start,
    // foreground, idle) - it withholds upstream candidates only. A change is journalled.
    bool geoChanged = false;
    {
        const bool geoNow = avpn::macUpstreamGeoPresent();
        if (geoNow != avpn::upstreamPlatformRuntimeReady().load()) {
            avpn::upstreamPlatformRuntimeReady().store(geoNow);
            reliabilityEvent(QStringLiteral("upstream_geo present=%1 why=%2").arg(geoNow ? 1 : 0).arg(why));
            geoChanged = true;
        }
    }
    const bool readyNow = avpn::xrayPlatformRuntimeReady().load();
    const bool next = m_engine.nextXrayRuntimeGate(readyNow, avpn::macXrayRuntimePresent(), modeActivity());
    if (next == readyNow)
        return geoChanged;
    avpn::xrayPlatformRuntimeReady().store(next);
    reliabilityEvent(QStringLiteral("xray_runtime tun2socks=%1").arg(next ? 1 : 0));
    syncTransportMode(why);
    return true;
}

// ---- AVPN macOS wake-реконнект (спека 2026-07-17-macos-wake-reconnect-design.md) --------------
// Корень «закрыл крышку — утром OFF»: демон туннель через ночь ДЕРЖИТ, а на wakeup ванильный
// reconnectToVpn рвал его stop()+start() в ещё не готовую сеть; 20с-сторож (§16) форсил
// Disconnected, §13 снимал намерение (путь мимо guardedStart, m_op==None) → reconcile не поднимал.
// Фикс: wake — НАША операция. §13/§16 не трогаем (внешние обрывы ведут себя как раньше).

#endif // Q_OS_MACOS && !MACOS_NE (установка службы)

#if defined(AMNEZIA_DESKTOP) && !defined(MACOS_NE)
// Волна-3 (2026-09-28): wake-перехват — общий для macOS/Windows/Linux (демон один, сигналы одни).
void AvpnEngineQml::hookDaemonWakeSignals()
{
    // Kill-switch: features.wake_restart=false — ванильное поведение (подписки не срезаем).
    if (!avpn::TuningStore::flag(QStringLiteral("wake_restart")))
        return;
    // Срез ванильного пути БЕЗ правки апстрима: снимаем все подписки rep→VpnConnection
    // (createProtocolConnections их к тому же копит дубликатами на каждый connectToVpn).
    // Окно между connectToVpn и Connected безопасно: reconnectToVpn игнорирует не-Connected.
    // Волна «как апстрим» (2026-09-28), КОРЕНЬ «VPN сам пропадает» на Mac: IpcClient —
    // thread_local (ipcClient.cpp), у потока VpnConnection своя реплика. Ванильные подписки
    // createProtocolConnections живут на реплике ЕГО потока, а срез шёл по реплике GUI-потока —
    // мимо: в логе 26.09 12:08:14 «Reconnect triggered» и «[wake] networkChanged» в одну мс,
    // 13 накопленных дубликатов → Reconnecting → 20с-сторож §16 → Disconnected → §13 снимал
    // намерение (9 из 9 external_loss за 26–28.09). Срезаем в потоке VpnConnection.
    QMetaObject::invokeMethod(m_conn, [conn = m_conn]() {
        IpcClient::withInterface([conn](QSharedPointer<IpcInterfaceReplica> rep) {
            QObject::disconnect(rep.data(), &IpcInterfaceReplica::wakeup, conn, nullptr);
            QObject::disconnect(rep.data(), &IpcInterfaceReplica::networkChanged, conn, nullptr);
        });
    }, Qt::QueuedConnection);
    // На Connected демон гарантированно жив → waitForSource внутри withInterface мгновенен.
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        // Наши обработчики (UniqueConnection — на каждом Connected хук повторяется).
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &AvpnEngineQml::onDaemonWakeup,
                Qt::ConnectionType(Qt::QueuedConnection | Qt::UniqueConnection));
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this,
                &AvpnEngineQml::onDaemonNetworkChanged,
                Qt::ConnectionType(Qt::QueuedConnection | Qt::UniqueConnection));
    });
}

void AvpnEngineQml::onDaemonWakeup()         { daemonWakeEvent("wakeup"); }
void AvpnEngineQml::onDaemonNetworkChanged() { daemonWakeEvent("networkChanged"); }

void AvpnEngineQml::daemonWakeEvent(const char *why)
{
    // Kill-switch мог флипнуться уже ПОСЛЕ среза ванильных подписок — честно возвращаем ваниль.
    if (!avpn::TuningStore::flag(QStringLiteral("wake_restart"))) {
        // VpnConnection живёт в своём потоке — только queued (ревью 5.1.95, п.6).
        QMetaObject::invokeMethod(m_conn, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
        return;
    }
    if (!m_wantConnected)
        return;                                  // намерения нет — спека §2.1 шаг 1
    if (m_lastTunnelState != Vpn::Connected)
        return;                                  // туннель не поднят — рвать/чинить нечего
    // Ночные дельты rx/tx не должны дать ложный onDead первым же health-tick (спека §2.2).
    m_engine.resetHealthSampling();
    if (m_wakeProbing)
        return;                                  // wakeup+networkChanged летят пачкой — одна проба
    m_wakeProbing = true;
    m_wakeProbeAttempt = 0;                      // новый цикл проб — счётчик повторов с нуля
    qInfo() << "[wake]" << why << "— probing tunnel liveness";
    // Сети после сна нужно время (реассоциация Wi-Fi, DHCP) — пробуем чуть отложенно.
    QTimer::singleShot(2500, this, [this]() { wakeLivenessProbe(); });
}

void AvpnEngineQml::wakeLivenessProbe()
{
    if (!m_wantConnected || m_lastTunnelState != Vpn::Connected) {
        m_wakeProbing = false;                   // состояние уехало, пока ждали — не вмешиваемся
        m_wakeProbeAttempt = 0;
        return;
    }
    // Сначала проверка живости, потом рестарт (спека §2.1 шаг 2): HEAD generate_204 ЧЕРЕЗ туннель
    // (full-tunnel — весь трафик в нём). Успех = туннель пережил сон сам (как у ванили его держал
    // демон) → НИЧЕГО не делаем. Async + transferTimeout — никакого nested QEventLoop (§1).
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(4000);
    QNetworkReply *r = m_nam->head(req);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        r->deleteLater();
        m_wakeProbing = false;
        const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool alive = (r->error() == QNetworkReply::NoError && (code == 204 || code == 200));
        if (alive) {
            m_wakeRestartPending = false;
            m_wakeTries = 0;
            m_wakeProbeAttempt = 0;
            qInfo() << "[wake] tunnel alive — nothing to do";
            return;
        }
        if (!m_wantConnected || m_lastTunnelState != Vpn::Connected)
            return;                              // за время пробы состояние уехало
        // AVPN seamless roaming (§23.9): смена BSSID на mesh — секундный провал радио; одна
        // неудачная проба через 2.5 с = ещё не «мёртв». Повторяем пробу (кап
        // numbers.wake_probe_retries, 0 = как раньше) с шагом 4 с и только потом рестарт.
        if (m_wakeProbeAttempt < avpn::wakeProbeRetriesTuned()) {
            ++m_wakeProbeAttempt;
            m_wakeProbing = true;
            qInfo() << "[wake] probe failed — retry" << m_wakeProbeAttempt << "before restart";
            QTimer::singleShot(4000, this, [this]() { wakeLivenessProbe(); });
            return;
        }
        m_wakeProbeAttempt = 0;
        // Мёртв → штатный рестарт ЧЕРЕЗ reconcile (спека §2.1 шаг 3, паттерн pinAndReconcile):
        // m_needsRestart → guardedStop→Disconnected→guardedStart; m_op взведён → §13-гард
        // weAreOperating держит намерение; сторож — движковый клампованный, не жёсткие 20с.
        qInfo() << "[wake] tunnel dead after sleep — restarting (our operation)";
        m_wakeRestartPending = true;
        m_wakeTries = 1;
        m_needsRestart = true;
        m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P1-6)
        m_restartOrigin = QStringLiteral("wake");
        reconcile();
    });
}

void AvpnEngineQml::wakeKick()
{
    if (!m_wakeRestartPending)
        return;
    if (m_lastTunnelState == Vpn::Connected) {   // уже поднялись (сами или предыдущим ретраем)
        m_wakeRestartPending = false;
        m_wakeTries = 0;
        return;
    }
    if (m_wakeTries >= avpn::wakeRestartMaxTriesTuned()) {
        // Усталость = внешние обстоятельства — честный OFF, подключение вручную (дух §13).
        qInfo() << "[wake] restart tries exhausted — honest OFF";
        m_wakeRestartPending = false;
        return;
    }
    ++m_wakeTries;
    qInfo() << "[wake] network is back — retry" << m_wakeTries;
    // Намерение восстанавливаем: неудача СОБСТВЕННОГО wake-рестарта ≠ «пользователь выключил»
    // (спека §2.1 шаг 4). Это не авто-коннект §13 — операция началась с живого туннеля до сна.
    m_wantConnected = true;
    reconcile();
}

#endif // AMNEZIA_DESKTOP && !MACOS_NE (wake-перехват)

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
// AVPN (BUG-6): путь к сокету демона — тот же, что у LocalSocketController (initializeInternal).
static QString avpnDaemonSocketPath()
{
    const QString primary = QStringLiteral("/var/run/avpn/daemon.socket");
    return QFile::exists(primary) ? primary : QStringLiteral("/tmp/avpn.socket");
}

// AVPN (BUG-6, адопция при перезапуске GUI): демон переживает выход GUI и держит туннель, но
// до клика Connect протокол не существует и статус демона никто не спрашивает — GUI показывал
// «выключено», а reconcile мог погасить живой туннель. Лёгкая async-проба (без nested loop,
// NetAwait-доктрина): connect → {"type":"status"} → connected==true → адопт через общий
// choke-point onConnectionStateChanged(Connected) (там же встанет hookDaemonWakeSignals §18).
void AvpnEngineQml::probeDaemonTunnelOnStartup()
{
    // 5.1.109 (S4.1, review of 3dbe0361f): every way this probe ends is the startup observation of
    // the transport-mode gate - until then a stored "Xray" is not in force (a live tunnel of the
    // daemon may be adopted here, and its transport decides).
    if (!avpn::TuningStore::flag(QStringLiteral("adopt_live_tunnel"))) {
        noteStartupTunnelObserved();
        return;
    }
    if (m_op != Op::None || m_lastTunnelState == Vpn::Connected) {
        noteStartupTunnelObserved();
        return; // уже оперируем/подключены — пробе нечего чинить
    }
    auto *sock = new QLocalSocket(this);
    auto *guard = new QTimer(sock);
    guard->setSingleShot(true);
    connect(guard, &QTimer::timeout, sock, [this, sock]() { // демона нет/молчит — тихо уходим
        noteStartupTunnelObserved();
        sock->deleteLater();
    });
    connect(sock, &QLocalSocket::connected, sock, [sock]() {
        sock->write(QJsonDocument(QJsonObject{ { QStringLiteral("type"), QStringLiteral("status") } })
                        .toJson(QJsonDocument::Compact));
        sock->write("\n");
        sock->flush();
    });
    connect(sock, &QLocalSocket::readyRead, sock, [this, sock]() {
        while (sock->canReadLine()) {
            const QJsonObject o = QJsonDocument::fromJson(sock->readLine()).object();
            if (o.value(QStringLiteral("type")).toString() != QLatin1String("status"))
                continue;
            if (o.value(QStringLiteral("connected")).toBool()
                && m_op == Op::None && m_lastTunnelState != Vpn::Connected) {
                qInfo() << "[adopt] daemon holds a live tunnel — adopting (GUI restart)";
                m_adoptedNoProto = true;
                // AVPN (независимое ревью волны, MINOR-4): если демон держит xray, статистику
                // адоптированной сессии никто не поллит (m_lastUpProto пуст) — HealthLoop слеп.
                m_tunnel.adoptXrayIfRunning();
                onConnectionStateChanged(Vpn::Connected); // адопт внутри (BUG-6 ветка Connected)
            }
            noteStartupTunnelObserved(); // the daemon answered: a tunnel is adopted above, or there is none
            sock->deleteLater();
            return;
        }
    });
    connect(sock, &QLocalSocket::errorOccurred, sock, [this, sock](QLocalSocket::LocalSocketError) {
        noteStartupTunnelObserved(); // демон не установлен/не поднят — штатно, адоптить нечего
        sock->deleteLater();
    });
    guard->start(3000);
    sock->connectToServer(avpnDaemonSocketPath());
}

// AVPN (BUG-6): выключение адоптированного туннеля. Протокола нет (эту GUI-сессию не коннектили),
// m_tunnel.down() дойдёт до VpnConnection с null-протоколом (ноль-оп для демона) — гасим демона
// напрямую его же командой протокола. Иначе пользователь не может выключить VPN (зеркало §13a).
void AvpnEngineQml::daemonDirectDeactivate()
{
    auto *sock = new QLocalSocket(this);
    auto *guard = new QTimer(sock);
    guard->setSingleShot(true);
    connect(guard, &QTimer::timeout, sock, &QObject::deleteLater);
    connect(sock, &QLocalSocket::connected, sock, [sock]() {
        sock->write(QJsonDocument(QJsonObject{ { QStringLiteral("type"), QStringLiteral("deactivate") } })
                        .toJson(QJsonDocument::Compact));
        sock->write("\n");
        sock->flush();
        QTimer::singleShot(300, sock, &QObject::deleteLater); // байты ушли — сокет больше не нужен
    });
    connect(sock, &QLocalSocket::errorOccurred, sock, [sock](QLocalSocket::LocalSocketError) {
        sock->deleteLater();
    });
    guard->start(3000);
    sock->connectToServer(avpnDaemonSocketPath());
}
#endif

void AvpnEngineQml::guardedStop(const char *why)
{
    // Критик полноты (U10, жалоба 2 «сам выключается»): каждый наш стоп подписан причиной —
    // кольцо reliability уходит в отчёты Доктора/краша, по нему видно, КТО погасил туннель.
    m_lastOwnOpMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P2-6): окно «своего» события сети
    reliabilityEvent(QStringLiteral("guarded_stop why=%1 native=%2 intent_on=%3 engine=%4")
                         .arg(QLatin1String(why)).arg(int(m_lastTunnelState)).arg(m_wantConnected)
                         .arg(m_engine.debugSnapshot().state));
    cancelStartPreparation();
    if (m_probe) m_probe->cancel();
    if (!m_wantConnected)
        cancelSeatFirst(); // a stop that does not reconnect: a seat taken for a switch goes back
    // B1 (race measurement 18.11): a stop while nothing native runs - the race prelude, an attempt that ended before
    // any leg - has no Disconnected to wait for: the stop is confirmed at once and the operation settles through the
    // one function (the orb stayed dead until a relaunch).
    if (avpn::stopFindsNothingNative(observedTunnelOf(m_lastTunnelState), m_engine.ownerHoldsNativeLeg())) {
        m_engine.requestStop();
        m_latch.awaitingStopConfirm = false;
        settleOperation("stop_nothing_native");
        m_busy = false;
        reliabilityEvent(QStringLiteral("stop_confirmed_nothing_native why=%1").arg(QLatin1String(why)));
        emit changed();
        return;
    }
    // AVPN (фикс-волна 2026-09-22, A1a/A4): МЫ просим стоп — до Disconnected не адоптим эту сессию
    // и не стартуем; поколение гасимой сессии отличает «стоп в пути» от новой сессии ОС.
    m_latch.awaitingStopConfirm = true;
    m_statusRequestAttempts = 0;
    m_statusRetryTimer.stop();
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    {
        // Ревью CL-A r2: запоминаем и вид поколения (runtime NE или конфигурации из prefs).
        const SessionGeneration generation =
            sessionGenerationFrom(IosController::Instance()->sessionMetadata());
        if (generation.known()) m_stopGeneration = generation;
    }
#endif
    ++m_verifyEpoch; // AVPN awg31-xray-v1: стоп отменяет верификацию xray (стейл-ответ выбросится)
    m_op = Op::Stopping;
    m_opInFlight = true;
    m_busy = true;
    // AVPN backend-first (final review MF-2): свежее значение сторожа на каждый взвод (см. guardedStart).
    // Пол связан с handshake-бюджетом (ConnectTunables.h): watchdog ВСЕГДА > handshake_timeout,
    // иначе сторож рвёт штатный медленный коннект (ревью 2026-07-11).
    armWatchdog(avpn::reconcileWatchdogMsTuned());
    m_healthTimer.stop();
    // The attempt owner learns of the stop (its attempt ends StoppedByUser once the stop is confirmed).
    m_engine.requestStop();
    // AVPN (разбор 2026-09-23): стоп с намерением ON — часть перезапуска; фоновое время iOS берём ДО
    // стопа, чтобы свёрнутое приложение дожило до Disconnected и отправило старт.
    syncRestartGuard();
    m_tunnel.down();
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (BUG-6): туннель был адоптирован без протокола этой GUI-сессии — down() демона не
    // достигнет (null-протокол), гасим напрямую. Терминальный Disconnected приедет ретрансляцией
    // демона? Нет — соединения-слушателя тоже нет, поэтому полагаемся на m_tunnel.down()-путь
    // (null-протокол шлёт синхронный Disconnected) + факт деактивации демона этой командой.
    if (m_adoptedNoProto) {
        m_adoptedNoProto = false;
        // Upstream nodes (contract §6): an adopted upstream session releases its seat through the tunnel
        // first - the direct deactivate waits for that release (bounded 1.5 s).
        m_tunnel.runAfterUpstreamRelease([this]() { daemonDirectDeactivate(); });
    }
#endif
    emit changed();
}

// AVPN: сторож reconcile — терминальный колбэк не пришёл за таймаут (iOS NE иногда «молчит» при
// teardown или connect завис). Разблокируем машину, чтобы не залипнуть навсегда.
void AvpnEngineQml::armWatchdog(int intervalMs, bool freezeRearm)
{
    if (!freezeRearm)
        m_watchdogFreezeRearmed = false;
    m_watchdogArmedMs = QDateTime::currentMSecsSinceEpoch();
    m_watchdog.setInterval(intervalMs);
    m_watchdog.start();
}

void AvpnEngineQml::requestFreshTunnelStatus()
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    IosController::Instance()->requestReconcileStatus();
#endif
}

void AvpnEngineQml::onWatchdog()
{
    if (!m_opInFlight)
        return;
    const Op finished = m_op;
    settleOperation("watchdog");
    m_busy = false;
    if (finished == Op::Stopping) {
#if defined(Q_OS_IOS) || defined(MACOS_NE)
        // AVPN (фикс-волна 2026-09-22, A1a/R-SW3): стоп не подтверждён за дедлайн. Намерение НЕ
        // трогаем (стоп мог быть частью смены ноды — want=true). UI показывает «отключаемся»
        // (m_busy при want=false), статус перечитываем, стоп повторяем ограниченно (2/4 с, 2 раза).
        const int delay = stopRetryDelayMs(m_stopRetries);
        reliabilityEvent(QStringLiteral("stop_deadline_awaiting_native retry=%1").arg(m_stopRetries));
        IosController::Instance()->requestReconcileStatus();
        if (delay >= 0) {
            ++m_stopRetries;
            m_busy = true;
            m_stopRetryTimer.start(delay);
            emit changed();
        } else {
            resolveUnconfirmedStop();
        }
#else
        // Не-iOS (база 3c8cc74e): teardown не отрапортовал чистым Disconnected → считаем опущенным,
        // отложенный старт пойдёт.
        m_latch = TeardownLatch{};
        m_lastTunnelState = Vpn::Disconnected;
        emit changed();
        reconcile();
#endif
    } else {
        emit changed();
        reconcile();
    }
}

// AVPN (фикс-волна 2026-09-22, A1): ограниченный запрос статуса у натива (1/2/4 с, 3 попытки).
// true = ожидание продолжается (запрос отправлен или таймер следующего шага взведён).
bool AvpnEngineQml::awaitNativeStatus()
{
    if (m_statusRetryTimer.isActive())
        return true;
    const int delay = statusRequestDelayMs(m_statusRequestAttempts);
    if (delay < 0)
        return false;
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (m_statusRequestAttempts == 0)
        IosController::Instance()->requestReconcileStatus();
#endif
    ++m_statusRequestAttempts;
    m_statusRetryTimer.start(delay); // по таймеру — следующий запрос + reconcile
    return true;
}

// A1a: повтор стопа после дедлайна (backoff 2/4 с), если сессия всё ещё не опущена.
void AvpnEngineQml::onStopRetryTimer()
{
    if (!m_latch.awaitingStopConfirm || m_lastTunnelState == Vpn::Disconnected || m_op != Op::None)
        return;
    // Ревью CL-A r2 (A4): Connected доказанно ДРУГОЙ сессии (Настройки/Shortcuts) — адопт, а не
    // повторный стоп. Та же сессия/неизвестно — tryAdopt отвергает без побочных эффектов.
    if (m_lastTunnelState == Vpn::Connected && tryAdoptObservedTunnel("stop_retry_new_session")) {
        m_busy = false;
        m_healthTimer.start();
        emit changed();
        return;
    }
    reliabilityEvent(QStringLiteral("stop_retry n=%1 native=%2").arg(m_stopRetries).arg(int(m_lastTunnelState)));
    guardedStop("stop_retry");
}

void AvpnEngineQml::driveUnconfirmedStop(const char *why)
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    const Vpn::ConnectionState s = m_lastTunnelState;
    const ObservedTunnel observed = s == Vpn::Connected ? ObservedTunnel::Connected
        : s == Vpn::Disconnected ? ObservedTunnel::Disconnected
        : s == Vpn::Error ? ObservedTunnel::Error
        : s == Vpn::Unknown ? ObservedTunnel::Unknown : ObservedTunnel::Transitional;
    switch (decideUnconfirmedStop(m_latch, observed, m_op == Op::None && !m_watchdog.isActive(),
                                  m_stopRetryTimer.isActive(), m_stopRetries)) {
    case UnconfirmedStopStep::None:
        return;
    case UnconfirmedStopStep::RetryStop: {
        const int delay = stopRetryDelayMs(m_stopRetries);
        ++m_stopRetries;
        m_busy = true; // UI «отключаемся» (want=false), а не «выкл» при живом туннеле
        m_stopRetryTimer.start(delay);
        reliabilityEvent(QStringLiteral("stop_unconfirmed why=%1 native=%2 retry=%3")
                             .arg(QLatin1String(why)).arg(int(s)).arg(m_stopRetries));
        emit changed();
        return;
    }
    case UnconfirmedStopStep::Resolve:
        resolveUnconfirmedStop();
        return;
    }
#else
    Q_UNUSED(why) // не-iOS: Connected/Error после стопа — терминал (латч снят observeTunnelState)
#endif
}

// Ревью CL-A r2 (K3): liveSessionFound, а реальный терминал так и не пришёл — не держим m_busy
// вечно: перечитываем статус, считаем попытку и отдаём решение reconcile.
void AvpnEngineQml::onLiveSessionTimeout()
{
    if (!m_liveSessionPending)
        return;
    m_liveSessionPending = false;
    m_busy = false;
    reliabilityEvent(QStringLiteral("live_session_status_timeout native=%1").arg(int(m_lastTunnelState)));
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    IosController::Instance()->requestReconcileStatus();
#endif
    emit changed();
    reconcile();
}

// A1a: стоп не подтверждён и после повторов. Честное состояние вместо вечного «серого»:
// туннель наблюдается живым → показываем «подключено» (адопт), пользователь может выключить
// снова; состояние неизвестно → перед новым стартом нужен наблюдённый терминал (A1b).
void AvpnEngineQml::resolveUnconfirmedStop()
{
    m_latch.awaitingStopConfirm = false;
    m_stopRetries = 0;
    m_stopRetryTimer.stop();
    m_busy = false;
    const bool wanted = m_wantConnected;
    reliabilityEvent(QStringLiteral("stop_unconfirmed native=%1 intent_on=%2")
                         .arg(int(m_lastTunnelState)).arg(wanted));
    if (m_lastTunnelState == Vpn::Connected) {
        m_wantConnected = true; // факт: туннель поднят; иначе reconcile гасил бы его по кругу
        if (tryAdoptObservedTunnel("stop_unconfirmed"))
            m_healthTimer.start();
        if (!wanted)
            emit error(tr("Не удалось отключить VPN. Повторите или отключите его в Настройках iOS."));
    } else {
        m_latch.needStatusBeforeStart = true;
        emit error(tr("Отключение ещё не подтверждено системой."));
    }
    emit changed();
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

void AvpnEngineQml::reprobe()
{
    noteIntentChange(); // AVPN Scanner
    // «Авто» clears no evidence (coordinator decision 4 of 18.11): the ledger keeps what this network proved.
    // AVPN: re-pick авто-ноды через единый reconcile (не дёргаем m_engine.connect() напрямую — это
    // обходило бы стейт-машину и давало back-to-back up()). Снимаем pin; если онлайн — перевыбираем.
    m_engine.clearPin();
    m_exactRow.clear();
    persistPin();
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    if (avpn::isTunnelUpStateName(st)) { // AVPN awg31-xray-v1: verifying = туннель поднят
        m_startOrigin = StartOrigin::AutoTap; // plan v3 step 5: explicit «Авто» - fastest, not the memory
        m_wantConnected = true;
        m_needsRestart = true;   // переподнять на свежевыбранной авто-ноде
        m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P1-6)
        m_restartOrigin = QStringLiteral("reprobe");
    }
    emit changed();
    reconcile();
}

void AvpnEngineQml::manualSwitch()
{
    if (m_engine.notifyConnectionLost())
        emit changed();
}

void AvpnEngineQml::resetLkg()
{
    Enrollment::clearToken(); // AVPN: SecureQSettings-backed
    emit changed();
}

// AVPN (Task 10 финал): setPinnedNode отдаёт ТЕХНИЧЕСКУЮ строку (английская, с nodeId/proto) —
// её место в логе, не в тосте. Человеческий текст — здесь, на границе фасада: маппим по
// стабильному префиксу движка; неизвестные причины сворачиваем в общий текст (детали в лог).
static QString humanPinError(const QString &technical)
{
    qWarning() << "avpn: setPinnedNode failed:" << technical;
    if (technical.startsWith(QLatin1String("unsupported_proto")))
        return AvpnEngineQml::tr("Сервер недоступен в этой версии приложения — обновите приложение");
    return AvpnEngineQml::tr("Не удалось выбрать сервер — обновите список серверов");
}

// AVPN awg31-xray-v1: тот же маппер для ошибок connect() (guardedStart): стабильные префиксы движка
// → человеческий текст; всё прочее — как пришло (те же строки, что и раньше).
// AVPN upstream nodes (release A, point 16): the user's text for leaving an upstream node; the code stays in
// the journal. UpstreamEngine.h::upstreamNoticeFor decides the kind.
static QString upstreamNoticeText(avpn::UpstreamNotice n)
{
    switch (n) {
    case avpn::UpstreamNotice::SeatsBusy:
        return AvpnEngineQml::tr("Сейчас все места заняты — подключаем следующую");
    case avpn::UpstreamNotice::NoTraffic:
        return AvpnEngineQml::tr("Сервер не пропускает трафик — подключаем следующий");
    case avpn::UpstreamNotice::Unavailable:
        return AvpnEngineQml::tr("Этот сервер сейчас недоступен — подключаем другой");
    case avpn::UpstreamNotice::None:
        break;
    }
    return QString();
}

static QString humanEngineError(const QString &technical)
{
    if (technical.startsWith(QLatin1String("no_transport")))
        return AvpnEngineQml::tr("В выбранном режиме нет ни одного сервера — включите режим «Авто»");
    if (technical == QLatin1String("no_network"))
        return AvpnEngineQml::tr("Нет сети — подключимся, когда она появится");
    if (technical == QLatin1String("exact_unavailable"))
        return AvpnEngineQml::tr("Этот сервер сейчас недоступен — выберите другой или «Авто»");
    if (technical == QLatin1String("no nodes available"))
        return AvpnEngineQml::tr("Нет доступных серверов — обновите список серверов");
    if (technical.startsWith(QLatin1String("unsupported_proto")))
        return AvpnEngineQml::tr("Сервер недоступен в этой версии приложения — обновите приложение");
    return technical;
}

// AVPN (live-node picker): «Выбрать» сервер из шторки. Модель «выбор = задать цель, коннект —
// ВРУЧНУЮ кнопкой Connect» (по требованию пользователя): НЕ коннектим автоматически. setPinnedNode
// закрепляет узел; если сейчас онлайн — опускаем туннель (намерение «офлайн»), чтобы орб стал OFF и
// показал выбранную ноду. Пользователь подключается сам — это надёжный COLD-connect на закреплённую
// ноду (он не ловит iOS-гонку «старт поверх teardown», в отличие от авто-switch на подключённом).
// Шторка закрывается в QML (sheet.close()).
void AvpnEngineQml::switchToNode(const QString &nodeId)
{
    switchToNodeImpl(nodeId, pinOriginPersists(PinOrigin::UserChoice)); // явный выбор в списке
}

// AVPN (фикс-волна 2026-09-22, A6): persist=false — свип бенча/Доктор: pin только в памяти.
void AvpnEngineQml::switchToNodeImpl(const QString &nodeId, bool persist)
{
    noteIntentChange(); // AVPN Scanner
    QString err;
    if (!pinServer(nodeId, err)) {
        emit error(humanPinError(err));
        return;
    }
    if (persist) persistPin();
    // Намерение: офлайн. Если онлайн — reconcile сделает guardedStop (орб OFF); офлайн — no-op.
    // Цель (pin) запомнена → следующий ручной Connect поднимет именно её.
    m_wantConnected = false;
    reliabilityEvent(QStringLiteral("intent_off why=select_node_offline")); // U10: кто снял намерение
    m_needsRestart = false;
    reconcile();
    emit changed();
}

// AVPN (server picker, спека 2026-07-10): тап по стране на странице выбора = пин + мгновенный
// реконнект (решение пользователя; CONNECT-INVARIANTS §4 обновлён этой волной). Реконнект — ТОЛЬКО
// через reconcile с m_needsRestart (stop→Disconnected→start, тот же iOS-safe путь, что rotateNext);
// НИКОГДА прямой up() поверх teardown. Офлайн — только цель (cold-connect кнопкой Connect).
// Kill-switch: features.picker_instant_reconnect=false (/v1/config, operator-editable) откатывает
// на старую семантику switchToNode без релиза в стор (вкомпиленный фолбэк = true).
void AvpnEngineQml::pinAndReconnect(const QString &nodeId)
{
    pinAndReconnectImpl(nodeId, pinOriginPersists(PinOrigin::UserChoice)); // тап в списке серверов
}

// AVPN (фикс-волна 2026-09-22, A6): Доктор зовёт с persist=false — его пересадки и возвраты
// не становятся постоянным pin (иначе после перезапуска всегда та же нода без замера).
void AvpnEngineQml::pinAndReconnectImpl(const QString &nodeId, bool persist, bool forceConnect,
                                        StartOrigin origin, const QString *pinBefore)
{
    noteIntentChange(); // AVPN Scanner
    cancelSeatFirst();  // a new pick supersedes a seat still being taken for the previous one
    m_startOrigin = origin; // plan v3 step 5: picker tap = user, Doctor alternatives/restore = Doctor
    if (pinReconnectSelectOnly(forceConnect, featureEnabled(QStringLiteral("picker_instant_reconnect"), true))) {
        switchToNodeImpl(nodeId, persist);
        return;
    }
    // The pin to restore on a refused seat: the caller's, when it changed the pin itself before this call (the
    // Scanner's row tap, review F9 of 17.11), else the pin as it is now.
    const QString prevPin = pinBefore ? *pinBefore : m_engine.pinnedNodeId();
    QString err;
    if (!pinServer(nodeId, err)) {
        emit error(humanPinError(err));
        return;
    }
    if (persist) persistPin();
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    const bool up = avpn::isTunnelUpStateName(st); // AVPN awg31-xray-v1: verifying = туннель поднят
    // DebugSnapshot.h::pinReconnectIntent (AVPN Scanner, review F4): down + forceConnect = connect.
    const PinReconnectIntent intent = pinReconnectIntent(up, forceConnect);
    if (intent.wantConnected) {
        m_wantConnected = true;
        m_needsRestart = intent.needsRestart; // поднят: stop→Disconnected→start; лежит: reconcile просто стартует
        m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P1-6)
        m_restartOrigin = QStringLiteral("pin");
        // Seat first (D4 of 16.11): a provider node is not worth the working tunnel until its seat and a valid
        // profile are in hand - the seat is taken through the live tunnel now; onUpstreamPrepared restarts.
        const avpn::SubscriptionNode *target = m_engine.nodeById(nodeId);
        if (avpn::upstreamSeatFirst(intent.needsRestart, target && avpn::isUpstreamNode(*target), m_tunnel.upstreamActive())) {
            if (const quint64 prepareId = m_tunnel.prepareUpstream(m_engine.subscription(), *target)) {
                m_seatFirst = avpn::UpstreamSeatFirst{true, nodeId, prevPin, persist, m_intentSerial, prepareId};
                m_needsRestart = false; // the live tunnel stays until the seat is in hand
                reliabilityEvent(QStringLiteral("upstream_seat_first node=%1").arg(nodeId));
            }
        }
    } else {
        m_wantConnected = false; // офлайн: только цель, туннель не стартуем
        m_needsRestart = false;
    }
    emit changed();
    reconcile();
}

// AVPN (live-node picker): «Авто (быстрейший)» в шторке — СИММЕТРИЧНО ручному выбору узла (switchToNode):
// снимаем закрепление И уводим намерение в OFF. Пользователь жал «Авто» на ПОДКЛЮЧЁННОМ узле (напр.
// Poland) и ждёт, что главный экран ВЫЙДЕТ из «подключено к Польше» в состояние «авто — можно подключиться»
// (а НЕ останется висеть на старом узле — это была жалоба). reconcile сделает чистый guardedStop (орб OFF);
// карточка станет «Умный выбор сервера», следующий РУЧНОЙ Connect поднимет быстрейший по скорингу/weight.
// Модель «выбор = задать цель, коннект — кнопкой»: НЕ реконнектим автоматически (без back-to-back up()).
void AvpnEngineQml::selectAuto()
{
    selectAutoImpl(true); // явный выбор «Авто» пользователем (clears no evidence: decision 4 of 18.11)
}

void AvpnEngineQml::selectAutoImpl(bool persist)
{
    noteIntentChange(); // AVPN Scanner
    m_engine.clearPin();
    m_exactRow.clear();
    if (persist) persistPin();
    m_wantConnected = false;
    reliabilityEvent(QStringLiteral("intent_off why=select_auto")); // U10: кто снял намерение
    m_needsRestart = false;
    reconcile();        // онлайн → guardedStop (орб OFF); оффлайн → no-op
    emit changed();
}

// AVPN (live-node picker): кнопка «Обновить подключение» — round-robin на следующую живую ноду через
// единый reconcile (не дёргаем m_engine.rotateNext() напрямую — он имел свой контур свитча, конфликтуя
// с reconcile). Берём следующую живую ноду (чистый nextLiveNodeId, без side-effects), закрепляем как
// цель и просим переключиться: reconcile сделает stop→Disconnected→start на ней (iOS-safe).
void AvpnEngineQml::rotateNext()
{
    noteIntentChange(); // AVPN Scanner
    const QString next = m_engine.nextLiveNodeId();
    if (next.isEmpty()) {
        emit error(tr("Недостаточно живых серверов для переключения"));
        return;
    }
    QString err;
    if (!pinServer(next, err)) {
        emit error(humanPinError(err));
        return;
    }
    // AVPN (фикс-волна 2026-09-22, A6): «Заменить сервер» — pin только в памяти (как в базе):
    // постоянным он делал US после перезапуска без замера.
    if (pinOriginPersists(PinOrigin::Rotate)) persistPin();
    m_startOrigin = StartOrigin::Rotate; // plan v3 step 5: «Заменить сервер» does not write the memory
    m_wantConnected = true;
    m_needsRestart = true;
    m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P1-6)
    m_restartOrigin = QStringLiteral("rotate");
    emit changed();
    reconcile();
}

// ---- AVPN Scanner (lane L6b; CONNECT-INVARIANTS §32; plan scanner-client-plan.md v2.2 §2.12, §3, §4.4) -----
// The coordinator (TribeScanner) never touches the tunnel; its machine's three tunnel actions arrive here
// through IScanEngine (ScanEngineAdapter above) and nowhere else. Each is journalled with its own reason code:
// scan_row (ConnectRow), scan_open (UserConnectForScan), scan_cancel (CancelPendingConnect). No timer, watchdog
// or retry of this section acts on the tunnel.

namespace {
// Bounds of the report check's Send stage (the existing Doctor stage guard, shorter here: the card waits
// for the support thread's answer, not for a whole stage) and of its diag.log (the attachment cap is 2 MiB;
// the server may announce less, so a second, small copy goes when the queue refuses the first as too large).
constexpr int kScanCheckSendBoundMs = 8000;
constexpr int kScanCheckDiagMaxBytes = 1536 * 1024;
constexpr int kScanCheckDiagSmallBytes = 256 * 1024;
constexpr int kScanCheckStageCount = 6; // network, connect, servers, services, rusplit, speed
constexpr int kScanCheckSpeedTimeoutMs = 15000; // the speed sample's own bound (inside doctor_speed_guard_ms >= 20 s)

QString scanCurrentKey(const ScanCurrent &c)
{
    return QStringList{c.nodeId, QString::number(c.live), QString::number(c.connecting), QString::number(c.dataFlowing),
                       QString::number(c.failed), c.attemptNodeId, QString::number(c.liveRttMs),
                       QString::number(int(c.origin)), c.label, c.countryCode, QString::number(int(c.transport)),
                       c.transportVersion, QString::number(c.tier)}
        .join(QLatin1Char('|'));
}
} // namespace

IScanEngine *AvpnEngineQml::scanEngine() { return m_scanAdapter.get(); }
IScanHost *AvpnEngineQml::scanHost() { return m_scanHost.get(); }

void AvpnEngineQml::setScanHostFactory(const ScanHostCaps &caps, std::function<IScanHost *()> make)
{
    if (m_scanHost)
        m_scanHost->setFactory(caps, std::move(make));
}

void AvpnEngineQml::attachSupport(TribeSupportChat *support)
{
    m_support = support;
    if (!support)
        return;
    // Queued: reserveReport() emits it from inside the coordinator's own action.
    connect(support, &TribeSupportChat::reportQueueChanged, this, [this]() {
        if (m_scanner)
            m_scanner->reportQueueChanged();
    }, Qt::QueuedConnection);
    connect(support, &TribeSupportChat::reportStatusChanged, this, [this](const QString &id, const QString &result) {
        Q_UNUSED(result);
        if (!m_scanCheck.active || !m_scanCheck.submitted || id != m_scanCheck.queueReportId)
            return;
        // Deferred: the queue pumps its next part right after this status (text acked -> log sending).
        QTimer::singleShot(0, this, [this, e = m_docEpoch]() {
            if (e == m_docEpoch)
                scanCheckDelivery(false);
        });
    });
}

void AvpnEngineQml::attachScanner(TribeScanner *scanner)
{
    m_scanner = scanner;
    if (!scanner)
        return;
    scanner->setParent(this); // owned: deleted first in the destructor (it holds the adapter and the host)
    // Stage 2: one fact, one store - a row the Scanner proved (works / slow) on this network is a probe proof in the
    // path engine's ledger, and Auto reads it from there. A Scanner failure is not recorded (a light probe never
    // quarantines a path). The Scanner drops results of an older network itself (its generation tuple).
    scanner->onResultsSaved = [this](const avpn::ScanCachedResult &c) {
        int recorded = 0;
        for (const avpn::ScanCachedRow &r : c.rows) {
            if (r.cls != avpn::ScanClass::Works && r.cls != avpn::ScanClass::Slow)
                continue;
            const QString node = r.origin == avpn::ScanOrigin::Upstream ? avpn::upstreamNodeIdFor(r.profileId) : r.id;
            recorded += m_engine.recordProbeProof(node, QStringLiteral("scanner")) ? 1 : 0;
        }
        reliabilityEvent(QStringLiteral("scan_results_to_ledger rows=%1 recorded=%2").arg(c.rows.size()).arg(recorded));
        syncAttempt(); // the ledger is persisted with the attempt's journal
    };
    scanner->configureApi(m_nam, [this]() { return m_baseUrl; }, [this]() { return m_configPubKeyHex; },
                          [this]() { return authToken(); });
    connect(scanner, &TribeScanner::shadeChanged, this, &AvpnEngineQml::shadeChanged);
    // The server switched the Scanner off (404 of a scan endpoint): fetch /v1/config now (at most once a minute) so
    // the entry points and the page go away with the refreshed switches, not 15 minutes later.
    connect(scanner, &TribeScanner::serverSwitchedOff, this, [this]() {
        if (!m_configSvc)
            return;
        if (facadeScannerOffRefresh(*m_configSvc, m_scannerOffRefreshAskMs, QDateTime::currentMSecsSinceEpoch()))
            reliabilityEvent(QStringLiteral("scanner_off: config refresh asked"));
    });
    scanApplySwitches("attach");
    QTimer::singleShot(0, this, [this]() {
        if (!m_scanner)
            return;
        m_scanner->reportQueueChanged();
        m_scanLastCurrent.clear();
        scanSyncState();
    });
}

AvpnEngineQml::~AvpnEngineQml()
{
    if (m_support && !m_scanCheck.reservation.isEmpty())
        m_support->releaseReport(m_scanCheck.reservation); // an aborted check gives its queue slot back
#ifdef Q_OS_IOS
    if (m_scanNetHooked)
        IosScanHost::setAppGenerationChanged(nullptr);
#endif
    delete m_scanner; // before the adapter and the gated host it points at
    m_scanner = nullptr;
}

void AvpnEngineQml::scanJournal(const QString &line, const QJsonObject &fields)
{
    reliabilityEvent(line);
    avpn::TribeJournal::append(QStringLiteral("scanner"), fields);
}

QVariantMap AvpnEngineQml::shade() const
{
    return (m_scanner && m_scanSwitches.scanner) ? m_scanner->shade() : QVariantMap();
}

void AvpnEngineQml::shadeShow(const QString &kind, const QString &textId, const QStringList &args)
{
    if (!m_scanner || !m_scanSwitches.scanner)
        return; // the switch off = today's toasts (S9)
    m_scanner->showShade(kind, textId, args);
}

void AvpnEngineQml::shadeTapped()
{
    if (m_scanner)
        m_scanner->tapShade();
}

void AvpnEngineQml::scanApplySwitches(const char *why)
{
    const ScannerSwitches next = scannerSwitchesFrom([](const QString &k, bool d) { return avpn::TuningStore::flag(k, d); });
    const bool changedSwitches = next != m_scanSwitches;
    const bool wasOn = m_scanSwitches.scanner;
    m_scanSwitches = next;
    if (changedSwitches)
        reliabilityEvent(QStringLiteral("scanner_switches scanner=%1 return_home=%2 doctor_legacy=%3 connect_on_open=%4 "
                                        "awg_mini=%5 why=%6")
                             .arg(int(next.scanner)).arg(int(next.returnHome)).arg(int(next.doctorLegacy))
                             .arg(int(next.connectOnOpen)).arg(int(next.awgMini)).arg(QLatin1String(why)));
#ifdef Q_OS_IOS
    if (next.scanner && !m_scanNetHooked) { // the app's path monitor starts only with the Scanner
        m_scanNetHooked = true;
        IosScanHost::setAppGenerationChanged([this]() { scanNotifyNetwork(); });
    }
#endif
    // On: the host first, then the coordinator. Off: the coordinator closes (cancelling only a pending
    // connect it started itself) and stops its host scans, then the host goes dark.
    if (next.scanner) {
        if (m_scanHost)
            m_scanHost->setEnabled(true);
        if (m_scanner)
            m_scanner->refreshSwitches();
    } else {
        if (m_scanner)
            m_scanner->refreshSwitches();
        if (m_scanHost)
            m_scanHost->setEnabled(false);
        if (wasOn)
            m_scanRow = ScanRowAttempt();
    }
    if (next.scanner && !wasOn) {
        m_scanLastCurrent.clear();
        if (m_scanner)
            m_scanner->networkChanged(); // switched on: it starts from the network as it is now
        scanSyncState();
    }
    if (changedSwitches) {
        emit scannerSwitchesChanged();
        emit shadeChanged();
    }
}

void AvpnEngineQml::scanServiceDone(const QString &result, const QString &message)
{
    scanJournal(QStringLiteral("scan_service result=%1").arg(result),
                {{QStringLiteral("event"), QStringLiteral("service")}, {QStringLiteral("result"), result}});
    const bool ok = result == QLatin1String("ok");
    if (m_scanHost && ok)
        m_scanHost->poke();
    QString detail;
    if (!ok)
        detail = message.isEmpty() ? result : result + QLatin1Char(':') + message.left(200);
    emit scannerEnsureServiceFinished(ok, detail);
}

QString AvpnEngineQml::scannerServiceAction() const
{
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    return QLatin1String(macServiceActionName(avpn::macServiceInstalled(), avpn::macServiceRunning(), avpn::macServiceOutdated()));
#else
    return QStringLiteral("unsupported");
#endif
}

void AvpnEngineQml::scannerEnsureService()
{
    if (!m_scanSwitches.scanner)
        return;
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (m_svcInstallInFlight) {
        scanServiceDone(QStringLiteral("busy"), QString());
        return;
    }
    const bool installed = avpn::macServiceInstalled(), running = avpn::macServiceRunning(), outdated = avpn::macServiceOutdated();
    // The explicit tap asks again even when the update was declined on Connect in this session.
    const MacServicePlan plan = macServicePlan(installed, running, outdated, /*upgradeDeclined=*/false);
    reliabilityEvent(QStringLiteral("scan_service action=%1").arg(QLatin1String(macServiceActionName(installed, running, outdated))));
    if (!plan.act) {
        scanServiceDone(QStringLiteral("ok"), QString());
        return;
    }
    const bool vpnOnOrComing = m_wantConnected || avpn::isTunnelUpStateName(m_engine.debugSnapshot().state);
    if (!macServiceTapAllowed(plan, vpnOnOrComing)) {
        scanServiceDone(QStringLiteral("vpn_on"), QString()); // the installer would restart the service under the tunnel
        return;
    }
    if (plan.needInstall) {
        QString cerr;
        if (!avpn::macInstallServiceConfirm(&cerr)) { // the same dialog as on Connect
            if (plan.outdatedOnly)
                m_svcUpgradeDeclined = true; // Connect then does not ask again in this session (as its own refusal)
            scanServiceDone(QStringLiteral("declined"), cerr);
            return;
        }
    }
    m_scanSvcBusy = true;
    emit scannerEnsureServiceRunningChanged();
    startSvcWorker(plan.needInstall, [this](bool ok, const QString &err) { finishScannerSvc(ok, err); });
#else
    scanServiceDone(QStringLiteral("unsupported"), QString());
#endif
}

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
void AvpnEngineQml::finishScannerSvc(bool ok, const QString &err)
{
    m_svcInstallInFlight = false;
    m_svcInstalling = false;
    m_scanSvcBusy = false;
    if (ok)
        m_svcUpgradeDeclined = false; // this app's service is installed now
    emit changed();
    emit scannerEnsureServiceRunningChanged();
    const bool running = ok && avpn::macServiceRunning();
    scanServiceDone(running ? QStringLiteral("ok") : QStringLiteral("failed"),
                    ok ? QStringLiteral("not_running") : (err.isEmpty() ? QStringLiteral("installer") : err));
    // A Connect tapped while the service step ran waited for it (guardedStart: m_svcInstallInFlight); the Scanner
    // itself starts nothing - reconcile is a no-op without the user's intent.
    if (m_wantConnected)
        reconcile();
}
#endif

// Coordinator 18.11 (c): the Scanner and the attempt owner see the same network - the generation of the path
// engine's NetworkTracker (the physical medium, gateway and subnet; our own utun is not a network). The app's
// network monitor fires on every up/down of our own tunnel; such a notice is compared once the tunnel settled and
// reaches the Scanner only when the network key really changed (no «Сеть сменилась» on a row tap).
void AvpnEngineQml::scanNotifyNetwork()
{
    if (!m_scanner || !m_scanSwitches.scanner)
        return;
    if (networkChangeIsOwnTunnel(m_op != Op::None || m_engine.attemptRunning(), m_lastOwnOpMs,
                                 QDateTime::currentMSecsSinceEpoch())) {
        if (!m_scanNetCompareArmed) {
            m_scanNetCompareArmed = true;
            QTimer::singleShot(2000, this, [this]() {
                m_scanNetCompareArmed = false;
                scanNotifyNetwork();
            });
        }
        return;
    }
    const quint64 before = m_engine.network().generation;
    m_engine.observeNetwork(currentNetworkObservation());
    if (m_engine.network().generation != before)
        m_scanner->networkChanged();
    else
        reliabilityEvent(QStringLiteral("scan_network_unchanged net_gen=%1").arg(before));
}

// The live status for the coordinator (deduplicated), the own connect's «Подключено» latch and a row tap's
// chain (connectFailed for every node the ladder left, attemptEnded when it cannot go on, the return home).
void AvpnEngineQml::scanSyncState()
{
    noteScanOwnConnectProgress(m_scanOwnConnect, scanOwnConnectShownConnected());
    if (!m_scanner || !m_scanSwitches.scanner)
        return;
    // Seat first: the tapped provider row's chain has not touched the tunnel yet - the live node's data is not its.
    if (m_scanRow.active && !m_seatFirst.pending) {
        const QString engineNode = m_engine.currentNodeId();
        const bool gaveUp = !m_wantConnected
                            || (m_engine.state() == avpn::EngineState::Error && !m_engine.attemptRunning());
        const ScanRowStep st = scanRowAttemptObserve(m_scanRow, m_intentSerial, engineNode, m_dataFlowing, gaveUp);
        for (const QString &n : st.failed) {
            scanJournal(QStringLiteral("scan_row_failed reason=scan_row node=%1").arg(n),
                        {{QStringLiteral("event"), QStringLiteral("row_failed")}, {QStringLiteral("reason"), QStringLiteral("scan_row")},
                         {QStringLiteral("node"), n}});
            m_scanner->connectFailed(n);
        }
        if (st.ended) {
            scanJournal(QStringLiteral("scan_row_ended reason=scan_row"),
                        {{QStringLiteral("event"), QStringLiteral("row_ended")}, {QStringLiteral("reason"), QStringLiteral("scan_row")}});
            m_scanner->attemptEnded();
        }
        if (st.connected) {
            scanJournal(QStringLiteral("scan_row_connected reason=scan_row node=%1 return_home=%2")
                            .arg(st.connectedNode).arg(int(m_scanSwitches.returnHome)),
                        {{QStringLiteral("event"), QStringLiteral("row_connected")}, {QStringLiteral("reason"), QStringLiteral("scan_row")},
                         {QStringLiteral("node"), st.connectedNode}});
            if (m_scanSwitches.returnHome)
                emit scannerReturnHomeRequested();
        }
    }
    const QString key = scanCurrentKey(m_scanAdapter->current());
    if (key == m_scanLastCurrent)
        return;
    m_scanLastCurrent = key;
    m_scanner->engineStateChanged();
}

// Path (b): the ordinary start() from VPN off - «Подключаемся…» of an iPhone / Android Scanner (REQ S3 (b)).
void AvpnEngineQml::scanUserConnect()
{
    const bool upOrComing = avpn::isTunnelUpStateName(m_engine.debugSnapshot().state);
    const bool needsVpn = m_scanHost && m_scanHost->knownCaps().needsVpn;
    const ScanOpenConnect d = decideScanOpenConnect(m_scanSwitches.scanner, needsVpn, m_wantConnected, upOrComing);
    if (d != ScanOpenConnect::Start) {
        const QString why = QLatin1String(scanOpenConnectName(d));
        scanJournal(QStringLiteral("scan_connect_ignored reason=scan_open why=%1").arg(why),
                    {{QStringLiteral("event"), QStringLiteral("connect_ignored")}, {QStringLiteral("reason"), QStringLiteral("scan_open")},
                     {QStringLiteral("why"), why}});
        return;
    }
    const quint64 id = ++m_scanConnectSerial;
    scanJournal(QStringLiteral("scan_connect reason=scan_open attempt=%1").arg(id),
                {{QStringLiteral("event"), QStringLiteral("connect")}, {QStringLiteral("reason"), QStringLiteral("scan_open")},
                 {QStringLiteral("attempt"), double(id)}});
    start(); // StartOrigin::User: network memory first, the ordinary orb path
    m_scanOwnConnect.id = id;
    m_scanOwnConnect.processEpoch = m_processEpoch;
    m_scanOwnConnect.intentSerial = m_intentSerial; // right after its own start(): anything later supersedes it
    m_scanOwnConnect.reachedConnected = scanOwnConnectShownConnected();
}

// «Подключено» as the orb shows it (DebugSnapshot.h::scanShownConnected): the engine Connected on a Connected
// tunnel, with or without the data proof - the same first input as refreshDataFlowing.
bool AvpnEngineQml::scanOwnConnectShownConnected() const
{
    return avpn::scanShownConnected(m_paused, m_engine.state() == EngineState::Connected,
                                    m_lastTunnelState == Vpn::Connected, m_dataFlowing);
}

// Path (c): the ordinary stop() of THAT connect, only before «Подключено» (DebugSnapshot.h::decideScanCancel).
void AvpnEngineQml::scanCancelPendingConnect()
{
    const bool shownConnected = scanOwnConnectShownConnected();
    noteScanOwnConnectProgress(m_scanOwnConnect, shownConnected);
    // No event loop = the app is being terminated (Component.onDestruction of the Scanner page after exec()
    // returned): a stop could not reach the tunnel and is not the person's (decideScanCancel, app_quit).
    const bool eventLoopRunning = QThread::currentThread()->loopLevel() > 0;
    const ScanCancel d = decideScanCancel(m_scanOwnConnect, m_processEpoch, m_intentSerial, m_wantConnected,
                                          shownConnected, eventLoopRunning);
    const QString why = QLatin1String(scanCancelName(d));
    if (d != ScanCancel::Stop) {
        scanJournal(QStringLiteral("scan_cancel_ignored reason=scan_cancel why=%1 attempt=%2").arg(why).arg(m_scanOwnConnect.id),
                    {{QStringLiteral("event"), QStringLiteral("cancel_ignored")}, {QStringLiteral("reason"), QStringLiteral("scan_cancel")},
                     {QStringLiteral("why"), why}, {QStringLiteral("attempt"), double(m_scanOwnConnect.id)}});
        return;
    }
    const quint64 id = m_scanOwnConnect.id;
    m_scanOwnConnect = ScanOwnConnect();
    scanJournal(QStringLiteral("scan_cancel_connect reason=scan_cancel attempt=%1").arg(id),
                {{QStringLiteral("event"), QStringLiteral("cancel")}, {QStringLiteral("reason"), QStringLiteral("scan_cancel")},
                 {QStringLiteral("attempt"), double(id)}});
    stop(); // the orb's stop while connecting: the VPN, which was off, stays off
}

// Path (a): a row tap. The row must connect with the VPN off too (review F4): the user-start bookkeeping of
// start(), then pinAndReconnectImpl with force and a user origin; with the tunnel up the ordinary move
// (reconcile: stop -> Disconnected -> start). The one-attempt hint's head is the tapped row (the pin alone
// is a location), then the rows after it in the visible order.
void AvpnEngineQml::connectToNode(const QString &nodeId, const QStringList &attemptOrder, qint64 hintTtlMs,
                                  bool machineUserOrigin, bool machineForce)
{
    const ScanRowGate g = decideScanRowConnect(m_scanSwitches.scanner, nodeId);
    if (g != ScanRowGate::Connect) {
        const QString why = g == ScanRowGate::IgnoreSwitchOff ? QStringLiteral("switch_off") : QStringLiteral("no_node");
        scanJournal(QStringLiteral("scan_connect_ignored reason=scan_row why=%1").arg(why),
                    {{QStringLiteral("event"), QStringLiteral("connect_ignored")}, {QStringLiteral("reason"), QStringLiteral("scan_row")},
                     {QStringLiteral("why"), why}});
        if (m_scanner)
            m_scanner->connectRefused(nodeId); // a request that is not started ends with a result the Scanner gets
        return;
    }
    // The pin is checked before the intent changes: a row that cannot be pinned leaves everything as it was.
    const QString pinBefore = m_engine.pinnedNodeId(); // before the pin changes: a refused seat restores it
    QString err;
    if (!pinServer(nodeId, err)) {
        scanJournal(QStringLiteral("scan_connect_ignored reason=scan_row why=pin node=%1").arg(nodeId),
                    {{QStringLiteral("event"), QStringLiteral("connect_ignored")}, {QStringLiteral("reason"), QStringLiteral("scan_row")},
                     {QStringLiteral("why"), QStringLiteral("pin")}, {QStringLiteral("node"), nodeId}});
        if (m_scanner)
            m_scanner->connectRefused(nodeId);
        emit error(humanPinError(err));
        return;
    }
    const bool upOrComing = avpn::isTunnelUpStateName(m_engine.debugSnapshot().state);
    const ScannerRowConnect rc = scannerRowConnect(upOrComing);
    if (!machineUserOrigin || !machineForce) // the machine always sets both; the engine decides anyway
        reliabilityEvent(QStringLiteral("scan_connect_flags machine_user=%1 machine_force=%2")
                             .arg(int(machineUserOrigin)).arg(int(machineForce)));
    scanJournal(QStringLiteral("scan_connect reason=scan_row node=%1 up=%2 order=%3")
                    .arg(nodeId).arg(int(upOrComing)).arg(attemptOrder.size()),
                {{QStringLiteral("event"), QStringLiteral("connect")}, {QStringLiteral("reason"), QStringLiteral("scan_row")},
                 {QStringLiteral("node"), nodeId}, {QStringLiteral("up"), upOrComing},
                 {QStringLiteral("order"), int(attemptOrder.size())}});
    if (rc.userStartBookkeeping)
        noteUserStart();
    Q_UNUSED(attemptOrder)
    Q_UNUSED(hintTtlMs)
    // R3 (device round 4): the exact row applies to this one request - the previous choice comes back if it fails,
    // and on success the row stays as an ordinary preferred server (never an exact home choice).
    if (!m_exactRestoreArmed) {
        m_exactRestoreArmed = true;
        m_exactRestorePin = m_savedPin;
        // S6 (device round 5): a live session before the tap comes back if the row fails
        m_exactRestoreReconnect = m_wantConnected && m_engine.state() == avpn::EngineState::Connected;
    }
    m_exactRow = nodeId; // a Scanner row is one exact path (never a fallback to another row or server)
    pinAndReconnectImpl(nodeId, pinOriginPersists(PinOrigin::UserChoice), rc.forceConnect,
                        rc.userOrigin ? StartOrigin::User : StartOrigin::AutoTap, &pinBefore);
    scanRowAttemptBegin(m_scanRow, nodeId, m_intentSerial);
}

// StartReportCheck: «Проверить и отправить отчёт» (withConnection) or the empty state's «Отправить отчёт в
// поддержку». A queue slot first (backpressure: none free = no check), then the Doctor pipeline in scan mode.
void AvpnEngineQml::scanStartReportCheck(const QString &reportId, const QJsonObject &report, bool withConnection)
{
    if (!m_scanSwitches.scanner) {
        scanRefuseReportCheck(reportId, "switch_off");
        return;
    }
    if (doctorRunning() || m_benchRunning || sweepRunning() || abRunning() || ccRunning() || ftRunning()) {
        scanRefuseReportCheck(reportId, "busy");
        return;
    }
    if (!m_support) {
        scanRefuseReportCheck(reportId, "no_support");
        return;
    }
    const QString reservation = m_support->reserveReport();
    if (reservation.isEmpty()) {
        scanRefuseReportCheck(reportId, "queue_full");
        return;
    }
    m_scanCheck = ScanCheck();
    m_scanCheck.active = true;
    m_scanCheck.machineReportId = reportId;
    m_scanCheck.reservation = reservation;
    m_scanCheck.machineReport = report;
    m_scanCheck.withConnection = withConnection;
    scanJournal(QStringLiteral("scan_report_check start with_connection=%1").arg(int(withConnection)),
                {{QStringLiteral("event"), QStringLiteral("report_check")}, {QStringLiteral("with_connection"), withConnection}});
    docBeginRun(/*full=*/false, /*nodeScan=*/true);
    // Deferred: the first stage must not run inside the coordinator's own action.
    QTimer::singleShot(0, this, [this, e = m_docEpoch]() {
        if (e == m_docEpoch && m_scanCheck.active)
            docStartNetwork();
    });
}

// The check could not start (the queue full in a race with the machine's own gate, another diagnostic
// running, the switch off). The machine has no refusal event yet (lane L1): the queue state goes to it and
// the check ends as not sent.
void AvpnEngineQml::scanRefuseReportCheck(const QString &reportId, const char *why)
{
    const QString reason = scanCheckRefusalReason(QLatin1String(why));
    scanJournal(QStringLiteral("scan_report_refused why=%1 reason=%2").arg(QLatin1String(why), reason),
                {{QStringLiteral("event"), QStringLiteral("report_refused")}, {QStringLiteral("why"), QLatin1String(why)}});
    QTimer::singleShot(0, this, [this, reportId, reason]() {
        if (!m_scanner)
            return;
        m_scanner->reportQueueChanged();
        m_scanner->reportCheckRefused(reportId, reason); // a notice, no «sent» text, the card restored
    });
}

void AvpnEngineQml::scanCheckStageDone(const doctor::StageResult &)
{
    if (!m_scanner)
        return;
    m_scanner->reportCheckProgress(int(m_docStages.size()), kScanCheckStageCount);
}

// docFinish of the check: the schema-5 report (the machine's summary as `scan`), validated by the server's
// rules, into the support queue with the human text and diag.log - ALWAYS (REQ S8); the bench copy only when
// valid. Then the card waits for the support thread's answer, bounded by the Send stage guard.
void AvpnEngineQml::scanCheckSubmit()
{
    if (!m_scanCheck.active || m_scanCheck.submitted)
        return;
    docEnter(DoctorPhase::Send);
    m_docGuard.start(qMin(doctor::clampStageTimeoutMs(TuningStore::numberOr(QStringLiteral("diag_stage_timeout_ms"), 0)),
                          kScanCheckSendBoundMs));
    QJsonObject extra = benchExtra();
    extra.insert(QStringLiteral("doctor_mode"), QStringLiteral("check"));
    if (!m_docBenchFull.isEmpty())
        extra.insert(QStringLiteral("bench"), m_docBenchFull);
    const int dirty = CrashGuard::instance().dirtyExitCount();
    if (dirty > 0) {
        extra.insert(QStringLiteral("dirty_exits_since_last"), dirty);
        CrashGuard::instance().resetDirtyExitCount();
    }
    attachReliabilityContext(extra, m_engine.debugSnapshot().switchLog, m_reliabilityRing.lines);
    const QJsonObject mr = m_scanCheck.machineReport;
    extra.insert(QStringLiteral("check"), QJsonObject{{QStringLiteral("id"), mr.value(QStringLiteral("id"))},
                                                      {QStringLiteral("created_at_ms"), mr.value(QStringLiteral("created_at_ms"))},
                                                      {QStringLiteral("with_connection"), m_scanCheck.withConnection},
                                                      {QStringLiteral("scan_stats"), mr.value(QStringLiteral("scan_stats"))}});
    QJsonObject rep = doctor::fitCheckReport(doctor::buildCheckReport(m_docStages, extra, mr.value(QStringLiteral("scan")).toObject()));
    QString why;
    bool valid = doctor::checkReportValid(rep, &why);
    if (!valid && rep.contains(QStringLiteral("scan"))) {
        // A summary the server would refuse must not cost the stages their bench copy.
        QJsonObject noScan = rep;
        noScan.remove(QStringLiteral("scan"));
        QString why2;
        if (doctor::checkReportValid(noScan, &why2)) {
            rep = noScan;
            valid = true;
            why = QStringLiteral("scan_dropped:") + why;
        }
    }
    m_docReport = rep;
    m_docSummary = rep.value(QStringLiteral("summary")).toString();
    m_docHasProblem = doctor::hasProblem(m_docStages);
    avpn::TribeJournal::append(QStringLiteral("doctor_report"),
                               {{QStringLiteral("mode"), QStringLiteral("check")},
                                {QStringLiteral("has_problem"), m_docHasProblem},
                                {QStringLiteral("summary"), m_docSummary},
                                {QStringLiteral("bench_valid"), valid},
                                {QStringLiteral("why"), why},
                                {QStringLiteral("report"), rep}});
    const QString json = QString::fromUtf8(QJsonDocument(rep).toJson(QJsonDocument::Compact));
    const QString human = doctorHumanReport();
    QVariantMap res;
    if (m_support) {
        res = m_support->submitReport(human, doctor::checkDiagText(json, buildDiagReport(), kScanCheckDiagMaxBytes),
                                      valid ? json : QString(), m_scanCheck.reservation);
        m_scanCheck.reservation.clear(); // consumed on "queued", released on every other result
        if (res.value(QStringLiteral("result")).toString() == QLatin1String("too_large")) {
            const QString again = m_support->reserveReport();
            res = m_support->submitReport(human, doctor::checkDiagText(json, QString(), kScanCheckDiagSmallBytes),
                                          valid ? json : QString(), again);
        }
    }
    const QString result = res.value(QStringLiteral("result")).toString();
    m_scanCheck.submitted = true;
    m_scanCheck.queueReportId = res.value(QStringLiteral("id")).toString();
    scanJournal(QStringLiteral("scan_report_check submitted result=%1 bench=%2 why=%3 stages=%4")
                    .arg(result.isEmpty() ? QStringLiteral("none") : result).arg(int(valid)).arg(why)
                    .arg(m_docStages.size()),
                {{QStringLiteral("event"), QStringLiteral("report_submitted")}, {QStringLiteral("result"), result},
                 {QStringLiteral("bench"), valid}, {QStringLiteral("why"), why}});
    // "queued" (on disk) and "unsaved_sending" (not written; ONE direct attempt runs - queue lane F3): the queue's
    // status decides the shade. Anything else never reached the queue: the check is refused with its reason
    // (no «sent», no «уйдёт»).
    if (result != QLatin1String("queued") && result != QLatin1String("unsaved_sending")) {
        const QString machineId = m_scanCheck.machineReportId;
        scanCheckFinish(false, /*notify=*/false);
        scanRefuseReportCheck(machineId, result == QLatin1String("full") ? "queue_full"
                                         : result == QLatin1String("not_saved") ? "not_saved" : "submit_failed");
        return;
    }
    QTimer::singleShot(0, this, [this, e = m_docEpoch]() {
        if (e == m_docEpoch)
            scanCheckDelivery(false);
    });
}

void AvpnEngineQml::scanCheckDelivery(bool boundPassed)
{
    if (!m_scanCheck.active || !m_scanCheck.submitted || m_scanCheck.answered || !m_support)
        return;
    const QVariantMap st = m_support->reportStatus(m_scanCheck.queueReportId);
    const QVariantMap parts = st.value(QStringLiteral("parts")).toMap();
    const doctor::CheckDelivery d = doctor::checkDelivery(st.value(QStringLiteral("result")).toString(),
                                                          parts.value(QStringLiteral("text")).toString(),
                                                          parts.value(QStringLiteral("log")).toString(), boundPassed);
    if (d == doctor::CheckDelivery::Wait)
        return;
    if (d == doctor::CheckDelivery::NotSaved || d == doctor::CheckDelivery::Rejected) {
        const QString machineId = m_scanCheck.machineReportId;
        scanCheckFinish(false, /*notify=*/false);
        scanRefuseReportCheck(machineId, d == doctor::CheckDelivery::NotSaved ? "not_saved" : "rejected");
        return;
    }
    scanCheckFinish(d == doctor::CheckDelivery::Sent);
}

void AvpnEngineQml::scanCheckFinish(bool sent, bool notify)
{
    if (!m_scanCheck.active || m_scanCheck.answered)
        return;
    const QString machineId = m_scanCheck.machineReportId;
    if (m_support && !m_scanCheck.reservation.isEmpty())
        m_support->releaseReport(m_scanCheck.reservation); // nothing was submitted for it
    scanJournal(QStringLiteral("scan_report_check done delivery=%1").arg(sent ? QStringLiteral("sent") : QStringLiteral("queued")),
                {{QStringLiteral("event"), QStringLiteral("report_done")}, {QStringLiteral("sent"), sent}});
    m_scanCheck = ScanCheck();
    m_docGuard.stop();
    m_docPhase = DoctorPhase::Idle;
    m_docPercent = 100;
    CrashGuard::instance().setPhase(state() == QLatin1String("connected") ? "connected" : "idle");
    emit doctorChanged(); // not doctorFinished: the old sheet would send its own copy to the thread
    if (m_scanner && notify)
        m_scanner->reportCheckDone(sent, machineId);
}

// ---- AVPN awg31-xray-v1 (спека 2026-09-01 §2.3): транспорты, verifying, история, reseed ----------

QString AvpnEngineQml::transportMode() const
{
    return avpn::transportModeToString(m_engine.transportMode());
}

bool AvpnEngineQml::verifying() const
{
    return m_engine.isVerifying();
}

QString AvpnEngineQml::activeProto() const
{
    return m_engine.currentNodeProto();
}

void AvpnEngineQml::setTransportMode(const QString &mode)
{
    const avpn::TransportMode m = avpn::transportModeFromString(mode);
    // 5.1.109 (S4.1): a tap is a no-op only when the mode is both the stored CHOICE and in force. A
    // tap on "Auto" while the chosen "Xray" is not in force is a new choice and is stored; a tap on
    // the chosen mode that is still waiting (Xray came back under a live session) puts it in force
    // now - the user asked for it (TransportModeGate::tap).
    const avpn::TransportModeGate::Tap tap = m_engine.tapTransportMode(m);
    if (tap.refused) {
        // Платформа/kill-switch xray_client: режим честно отклоняем, настройку не портим.
        emit error(tr("Xray недоступен в этой версии приложения"));
        return;
    }
    if (tap.noop)
        return;
    QSettings s;
    s.setValue(QStringLiteral("avpn/transportMode"), avpn::transportModeToString(m));
    // Written by a build that stores the user's choice (>= 139): storedTransportChoice honours it.
    s.setValue(QStringLiteral("avpn/transportModeByChoice"), true);
    s.sync();
#ifdef Q_OS_IOS
    writeTunnelWatchPlan("mode"); // AVPN (iOS data watch, 141): the extension follows the mode at once
#endif
    // 5.1.109: a pinned country the new mode cannot serve (Serbia has AmneziaWG only, mode -> Xray)
    // stayed pinned: the card showed it with the new transport's badge and Connect silently raised
    // another country. Such a pin is dropped and persisted (setPinnedNode would refuse it now with
    // no_transport); Auto never drops a pin. A tunnel up/coming up on a transport the new mode
    // excludes is restarted THROUGH reconcile + m_needsRestart (stop -> Disconnected -> start), never a
    // direct up() over a teardown (CONNECT-INVARIANTS §2/§4); the start then picks without that pin.
    // The rule - DebugSnapshot.h::decidePinOnTransportMode (facade_policy_check).
    const avpn::TransportMode effective = m_engine.transportMode();
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    const avpn::PinModeDecision d = avpn::decidePinOnTransportMode(
        avpn::transportModeToString(effective), m_engine.pinnedNodeId(), m_engine.pinLacksTransport(effective),
        avpn::isTunnelUpStateName(st), m_engine.currentNodeProto());
    if (d.clearPin) {
        m_engine.clearPin();
        persistPin();
        reliabilityEvent(d.journal);
    }
    // 5.1.109 (review of df7f49db8): "Auto" serves every country - a saved pin the previous mode
    // could not serve (un-applied by an admission, never erased) comes back with this tap, not at
    // the next pool refresh.
    if (m == avpn::TransportMode::Auto)
        restorePin();
    if (d.restartTunnel) {
        m_wantConnected = true;
        m_needsRestart = true;
        m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P1-6)
        m_restartOrigin = QStringLiteral("transport");
        reconcile();
    }
    emit changed();
}

void AvpnEngineQml::refreshDataFlowing()
{
    const bool now = avpn::dataFlowingNow(!m_paused && m_engine.state() == EngineState::Connected
                                              && m_lastTunnelState == Vpn::Connected,
                                          m_liveDead, m_pathCheck, m_liveProven);
    if (now == m_dataFlowing)
        return;
    m_dataFlowing = now;
    emit dataFlowingChanged();
}

// Побочные эффекты реального «Подключено» — единая точка для awg (Vpn::Connected) и xray (после verify).
void AvpnEngineQml::onTunnelUpEffects()
{
    cancelStartPreparation();
    m_healthTimer.start(); // Cold adoption also needs a health driver.
    // AVPN (Task 9): контекстный запрос разрешения на пуши — в момент очевидной ценности (VPN
    // поднялся), а не на холодном старте. Один раз за установку (persist). Мост дёрнет натив
    // (UNUserNotificationCenter + registerForRemoteNotifications); на desktop — no-op.
    if (!m_pushPermissionAsked) {
        m_pushPermissionAsked = true;
        QSettings().setValue(QStringLiteral("AvpnPush/permissionAsked"), true);
        avpn::AvpnPushBridge::instance()->requestAuthorization();
    }
    // AVPN (Task 9): к моменту Connected subscription_token уже создан (start/bootstrap → enroll).
    // Если device token пришёл из APNs ДО enroll, registerPushToken его отложил (authToken был пуст) —
    // флашим здесь. Дедуп по fingerprint пропустит повтор, если токен уже отправлен (redeem/bootstrap).
    flushPendingPushToken();
    // AVPN: чипы доступности + скорость после поднятия. Чипы youtube/instagram теперь GOODPUT (качают
    // ~128 КБ каждый) — дороже по трафику и дольше (до ~20с при троттле), поэтому ОДНА проба за коннект
    // (~1.5с — DNS/маршруты через свежий туннель уже осели; раньше давало HostNotFound → ложный «заблок»).
    // Дальше — только по тапу «перепроверить» (см. UI), НЕ поллинг: goodput каждые N секунд = лишний трафик.
    // Скорость (RTT-палочки) — через ~1.8с, дальше по каденсу onTick (4с, лёгкий generate_204).
    // AVPN BUG-13 (2026-07-30): на входе в connected обнуляем чипы в «не проверено» (синий).
    // Раньше вердикты прошлой сессии оставались висеть (помеченные stale, но ТОГО ЖЕ цвета),
    // и после подключения пользователь видел красные бейджи живых сервисов, пока не дойдёт
    // первая проба — жалоба «включаю VPN, все бейджи красные, через полминуты зеленеют».
    // Нейтральный синий честен: проверка ещё не проводилась. На транзиентах (обрыв без нового
    // connected) поведение прежнее — stale-приглушение, чипы не мигают.
    // Волна-4 (P2-3): чипы и пробы (2×128 КБ) — только для НОВОЙ сессии и на экране; повторный
    // Connected той же сессии (Reconnecting→Connected при смене сети, подхват) их не запускает,
    // а в фоне они откладываются до выхода на экран (у апстрима на Connected — только сброс кэша).
    {
        const QString node = m_engine.currentNodeId();
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        const qint64 since = m_lastEffectsMs > 0 ? now - m_lastEffectsMs : -1;
        switch (decideConnectEffects(!node.isEmpty() && node == m_lastEffectsNode, since, uiForeground())) {
        case ConnectEffects::RunNow:
            runConnectEffects();
            break;
        case ConnectEffects::Defer:
            m_effectsPending = true;
            reliabilityEvent(QStringLiteral("connect_effects_deferred"));
            break;
        case ConnectEffects::Skip:
            reliabilityEvent(QStringLiteral("connect_effects_skipped same_session"));
            break;
        }
    }
    QTimer::singleShot(1800, this, [this]() {
        if (m_probe && avpn::TuningStore::flag(QStringLiteral("live_rtt"))
            && state() == QLatin1String("connected"))
            measureLiveProbe();
    });
}

void AvpnEngineQml::runConnectEffects()
{
    m_effectsPending = false;
    m_lastEffectsNode = m_engine.currentNodeId();
    m_lastEffectsMs = QDateTime::currentMSecsSinceEpoch();
    resetServiceChipsToUnknown();
    QTimer::singleShot(1500, this, &AvpnEngineQml::probeServices);
}


// Build 142 (review round 2, N4): when the app last froze - the later of the last hide and the last return to
// the screen (the P2-2 boundary of classifyApiOutcome). States and facts from before it are not evidence.
qint64 AvpnEngineQml::freezeBoundaryMs() const
{
    return std::max(m_lastResumeMs, m_lastHiddenMs);
}

void AvpnEngineQml::verifyAttempt(int epoch)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying() || m_lastTunnelState != Vpn::Connected)
        return; // состояние уехало (стоп/обрыв/смена) — серия отменена
#ifdef Q_OS_IOS
    // AVPN (iOS data watch, 141): an attempt due after a freeze waits for the extension's snapshot.
    if (deferWhileTunnelWatchFrozen("verify", [this, epoch]() { verifyAttempt(epoch); }))
        return;
#endif
    const int budget = m_engine.dataCheckMs();
    const qint64 elapsed = m_verifyClock.elapsed();
    if (elapsed >= budget) {
        finishVerify(epoch, false);
        return;
    }
    ++m_verifyAttempts;
    // Та же цель, что у живых палочек (urls.quality_probe_url, фолбэк generate_204). HEAD, без кэша.
    // Async + transferTimeout — никакого nested QEventLoop (§1).
    QNetworkRequest req{QUrl(configUrl(QStringLiteral("quality_probe_url"),
                                       QStringLiteral("https://connectivitycheck.gstatic.com/generate_204")))};
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    const qint64 remaining = budget - elapsed;
    const int transferTimeout = int(remaining < 1500 ? 1500 : (remaining > 4000 ? 4000 : remaining));
    req.setTransferTimeout(transferTimeout);
    QNetworkReply *r = m_nam->head(req);
    const qint64 armedMono = m_verifyClock.elapsed();
    const qint64 armedWall = QDateTime::currentMSecsSinceEpoch();
    connect(r, &QNetworkReply::finished, this, [this, r, epoch, transferTimeout, armedMono, armedWall]() {
        r->deleteLater();
        if (epoch != m_verifyEpoch || !m_engine.isVerifying())
            return;
        const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool ok = (r->error() == QNetworkReply::NoError && (code == 204 || code == 200));
        // Plan v3 step 5 (review N2): the whoami tiebreak's probe got no answer and its timer fired
        // late - the app was suspended mid-request: no evidence, Connected without the mark.
        if (m_whoamiTiebreak && !ok && code == 0
            && avpn::timerFiredLate(std::max(m_verifyClock.elapsed() - armedMono,
                                             QDateTime::currentMSecsSinceEpoch() - armedWall),
                                    transferTimeout)) {
            --m_verifyAttempts; // not a sent request for the verdict
#ifdef Q_OS_IOS
            // AVPN (iOS data watch, 141): "limited" after a freeze only once the extension was asked.
            if (deferWhileTunnelWatchFrozen("tiebreak_reply", [this, epoch]() {
                    if (epoch != m_verifyEpoch || !m_engine.isVerifying())
                        return;
                    m_whoamiTiebreak = false;
                    finishWhoami(epoch, avpn::WhoamiVerdict::CheckLimited,
                                 m_lastWhoamiFacts + QStringLiteral(" tiebreak=suspended"), /*tiebreakDone=*/true);
                }))
                return;
#endif
            m_whoamiTiebreak = false;
            finishWhoami(epoch, avpn::WhoamiVerdict::CheckLimited,
                         m_lastWhoamiFacts + QStringLiteral(" tiebreak=suspended"), /*tiebreakDone=*/true);
            return;
        }
        // AVPN (независимое ревью волны, MAJOR-3; инвариант §22.5): 204/200 доказывает ИНТЕРНЕТ,
        // а не туннель — если tun2socks/маршруты не встали, проба ушла НАПРЯМУЮ мимо xray. Второе
        // условие — реальный rx через туннель (счётчики уже поллятся: macOS — IPC xrayRuntimeStatus,
        // iOS — bytesChanged NE). rx==0 при живом источнике = «доказательства ещё нет» (§17.1:
        // 0 = неизвестно) → ждём следующей попытки; источника нет вовсе → принимаем с оговоркой.
        const avpn::TunnelStats st = m_tunnel.readStats();
        switch (avpn::verifyStepFor(ok, st.valid, st.rxBytes)) {
        case avpn::VerifyStep::Confirmed:
            m_lastVerifyRxProof = true;
            finishVerify(epoch, true);
            return;
        case avpn::VerifyStep::AcceptedWithoutStats:
            qWarning() << "[avpn xray] probe ok, but tunnel stats are unavailable — accepting without rx proof";
            m_lastVerifyRxProof = false;
            finishVerify(epoch, true);
            return;
        case avpn::VerifyStep::KeepTrying:
            break;
        }
        if (m_verifyClock.elapsed() >= m_engine.dataCheckMs()) {
            finishVerify(epoch, false);
            return;
        }
        QTimer::singleShot(1200, this, [this, epoch]() { verifyAttempt(epoch); });
    });
}

void AvpnEngineQml::finishVerify(int epoch, bool ok, const QString &failReason)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying())
        return;
    if (m_whoamiTiebreak) {
        // Plan v3 step 5 (review): this generate_204 run was the whoami tiebreak - its result is a
        // whoami verdict (passes -> CheckLimited: Connected without the mark; fails -> NoData).
        // N2: a failure with no request ever sent (budget spent while suspended) is no evidence.
        m_whoamiTiebreak = false;
        finishWhoami(epoch, avpn::whoamiTiebreakVerdict(ok, m_verifyAttempts),
                     m_lastWhoamiFacts + (ok ? QStringLiteral(" tiebreak=204_ok")
                                             : QStringLiteral(" tiebreak=204_fail requests=%1").arg(m_verifyAttempts)),
                     /*tiebreakDone=*/true);
        return;
    }
    QString reason = failReason;
    if (m_upstreamFallbackVerify) {
        // Upstream node without a probe grant (older server): the generate_204 + rx proof check carried
        // data, but the path cannot be compared - Unverifiable (strict switch decides), else NoData.
        m_upstreamFallbackVerify = false;
        const avpn::UpstreamVerdictResult v = avpn::upstreamFallbackVerdict(ok, avpn::upstreamUnverifiableStrictTuned());
        m_pathCheck = QLatin1String(avpn::upstreamVerdictName(v.verdict));
        reliabilityEvent(QStringLiteral("upstream_verdict verdict=%1 reason=%2 node=%3 fallback=generate_204")
                             .arg(m_pathCheck, v.reason, m_engine.currentNodeId()));
        if (!v.passes) {
            ok = false;
            reason = QStringLiteral("upstream %1 (failover)").arg(m_pathCheck);
        }
    }
    m_lastVerifyMs = m_verifyClock.elapsed();
    m_lastVerifyOk = ok ? 1 : 0;
    if (ok) {
        qInfo() << "[avpn verify]" << m_engine.currentNodeProto() << "data-plane verified in" << m_lastVerifyMs
                << "ms, attempts" << m_verifyAttempts << "rx-proof" << m_lastVerifyRxProof;
        m_engine.verifySucceeded(m_lastVerifyTtfbMs);
        m_lastVerifyTtfbMs = -1;
        syncAttempt();
        if (m_engine.state() == avpn::EngineState::Connected) {
            m_busy = false;
            onTunnelUpEffects();
        }
        emit changed();
        return;
    }
    // R1 (device round 4): a failure that is not the path's own never reaches the ledger - the check did not
    // happen; the owner runs it again on the same tunnel once, then walks on with nothing recorded.
    {
        const avpn::TunnelStats st = m_tunnel.readStats();
        const qint64 rxDelta = (st.valid && m_verifyRxStart >= 0) ? st.rxBytes - m_verifyRxStart : -1;
        const avpn::CheckBlame blame = avpn::checkFailureBlame(
            uplinkUp(), QDateTime::currentMSecsSinceEpoch() - m_verifyWallStartMs, m_engine.dataCheckMs(),
            st.valid && m_verifyRxStart >= 0, rxDelta);
        if (blame != avpn::CheckBlame::Path) {
            reliabilityEvent(QStringLiteral("check_not_attributable blame=%1 node=%2 rx_delta=%3 reason=%4")
                                 .arg(QLatin1String(avpn::checkBlameName(blame)), m_engine.currentNodeId())
                                 .arg(rxDelta).arg(reason));
            finishVerifyInconclusive(epoch);
            return;
        }
    }
    qWarning() << "[avpn verify]" << m_engine.currentNodeProto() << "data-plane NOT verified after"
               << m_lastVerifyMs << "ms — failover" << reason;
    // The one data-check event of the attempt owner (no data): recorded for this network, the leg goes down and
    // the next candidate comes up - or, for a live session's re-check, the failover attempt begins.
    const bool leftUpstream = m_engine.currentNodeIsUpstream(); // release A: before the engine moves on
    m_engine.verifyFailed(reason);
    syncAttempt();
    if (leftUpstream && m_wantConnected && m_engine.attemptRunning())
        noticeUpstreamLeft(m_pathCheck); // a short notice by the verdict; never for own nodes
    m_busy = m_engine.attemptRunning() || m_op != Op::None;
    emit changed();
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

// Plan v3 step 5: one verification phase, two ways to prove it. features.node_scan (fixed per start
// in guardedStart -> ServiceEngine::setVerifyEveryTransport): every transport verifies with ONE
// GET /v1/whoami; flag off: only xray verifies, with the generate_204 loop (as before).
void AvpnEngineQml::startDataPathVerification()
{
    m_upstreamFallbackVerify = false;
    // R1: what the attribution gate of a failure needs - the wall clock and the tunnel's receive counter at the start
    m_verifyWallStartMs = QDateTime::currentMSecsSinceEpoch();
    {
        const avpn::TunnelStats st = m_tunnel.readStats();
        m_verifyRxStart = st.valid ? st.rxBytes : -1;
    }
    // Upstream nodes: their own check (sized /v1/probe through the provider); whoami never applies.
    if (m_engine.currentNodeIsUpstream()) {
        startUpstreamVerification();
        return;
    }
    startWhoamiVerification(); // our node, any transport (path engine: every leg is judged by one data check)
}

void AvpnEngineQml::startWhoamiVerification()
{
    const int epoch = ++m_verifyEpoch;
    m_verifyClock.start();
    m_verifyAttempts = 0;
    m_lastVerifyRxProof = false;
    m_whoamiTiebreak = false;
    m_busy = true;
    m_pathCheck = QStringLiteral("checking");
    qInfo() << "[avpn whoami] tunnel up on" << m_engine.currentNodeId() << m_engine.currentNodeProto()
            << "— checking the data path";
    // Same first-attempt delay as the xray verification: routes/DNS of a fresh tunnel settle within
    // a few hundred ms (chips probed at 0.6 s used to get HostNotFound).
    QTimer::singleShot(800, this, [this, epoch]() { whoamiAttempt(epoch); });
}

void AvpnEngineQml::whoamiAttempt(int epoch)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying() || m_lastTunnelState != Vpn::Connected)
        return; // the state moved on (stop / loss / switch) - this check is cancelled
#ifdef Q_OS_IOS
    // AVPN (iOS data watch, 141): a late attempt after a freeze is judged only after the extension's
    // snapshot (field 13.11: "limited ... no_evidence left_ms=-402760" before anything was asked).
    if (deferWhileTunnelWatchFrozen("whoami", [this, epoch]() { whoamiAttempt(epoch); }))
        return;
#endif
    const QString token = authToken();
    // whoami gets at most ~60 % of the verify budget; the rest is the generate_204 tiebreak's.
    const int budget = m_engine.dataCheckMs();
    const qint64 left = avpn::whoamiBudgetMs(budget) - m_verifyClock.elapsed();
    switch (avpn::whoamiAttemptGate(m_verifyAttempts, left, budget - m_verifyClock.elapsed())) {
    case avpn::WhoamiGate::NoEvidence:
        // The whole budget was gone before any request (the app was suspended, timers fired late):
        // no evidence - no verdict. Connected without the mark; streak and memory untouched.
        finishWhoami(epoch, avpn::WhoamiVerdict::CheckLimited,
                     QStringLiteral("no_evidence left_ms=%1").arg(left), /*tiebreakDone=*/true);
        return;
    case avpn::WhoamiGate::Tiebreak:
        finishWhoami(epoch, avpn::WhoamiVerdict::Inconclusive, QStringLiteral("whoami_budget_spent left_ms=%1").arg(left));
        return;
    case avpn::WhoamiGate::Send:
        break;
    }
    if (!m_nam || token.isEmpty()) {
        finishWhoami(epoch, avpn::WhoamiVerdict::Inconclusive, QStringLiteral("skipped token=%1").arg(int(!token.isEmpty())));
        return;
    }
    ++m_verifyAttempts;
    // Nonce: 128 random bits as hex - inside the contract's [A-Za-z0-9._-]{1,64}.
    QByteArray nonce;
    for (int i = 0; i < 4; ++i)
        nonce += QByteArray::number(QRandomGenerator::system()->generate(), 16).rightJustified(8, '0');
    // The same API client as every /v1 call (Bearer device token, armTimeout); while the tunnel is up
    // it goes through the tunnel like them (the API is carved out of the RU bypass, §14.5). Only the
    // base may differ: on Xray always the alternate edge (whoamiBaseUrl - api.tribevpn.com is the
    // Xray entry, which the macOS split routes past the tunnel); on AWG the active API address.
    const QString base = avpn::whoamiBaseUrl(m_baseUrl, avpn::isXrayProto(m_engine.currentNodeProto()),
                                             !qgetenv("AVPN_API_URL").isEmpty());
    QUrl url(base + QStringLiteral("/v1/whoami"));
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("nonce"), QString::fromLatin1(nonce));
    url.setQuery(q);
    QNetworkRequest req{url};
    req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + token.toUtf8());
    // The body is hashed byte for byte: no transparent decompression, no cache.
    req.setRawHeader(QByteArrayLiteral("Accept-Encoding"), QByteArrayLiteral("identity"));
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *r = m_nam->get(req);
    // S3 (device round 5): judged by progress, not by a hard per-request cut. The first byte must come within the
    // whoami share (`left`); once bytes flow, the request lives while they keep coming (no gap longer than
    // kWhoamiStallMs), up to the whole check budget (the backstop below). A path that moves its payload steadily but
    // slowly is "works (slow)" - it used to flip between pass and "no data" at ~1.6 s from one connect to the next.
    const qint64 budgetLeft = std::max<qint64>(left, qint64(m_engine.dataCheckMs()) - m_verifyClock.elapsed());
    avpn::armTimeout(r, int(budgetLeft));
    // Count and hash what actually arrives (readyRead), so a transfer cut after the headers still
    // reports its real size: < 16 KiB = data does not pass, >= 16 KiB cut by our timeout = slow link.
    struct Received {
        QCryptographicHash hash{QCryptographicHash::Sha256};
        qint64 bytes = 0;
    };
    auto rx = std::make_shared<Received>();
    auto drain = [r, rx]() {
        const QByteArray chunk = r->readAll();
        rx->bytes += chunk.size();
        rx->hash.addData(chunk);
        if (rx->bytes > avpn::kWhoamiMaxBodyBytes && r->isRunning())
            r->abort(); // not our whoami (contract max 256 KiB) - do not download it on metered links
    };
    connect(r, &QNetworkReply::readyRead, r, drain);
    const qint64 t0 = m_verifyClock.elapsed();
    {
        auto lastByteAt = std::make_shared<qint64>(-1);
        connect(r, &QNetworkReply::readyRead, r, [this, lastByteAt]() { *lastByteAt = m_verifyClock.elapsed(); });
        auto *watch = new QTimer(r);
        watch->setInterval(200);
        connect(watch, &QTimer::timeout, r, [this, r, lastByteAt, t0, left]() {
            if (!r->isRunning())
                return;
            // T1: no first byte past the first-byte share - the engine may leave this leg for a proven alternative
            if (*lastByteAt < 0 && m_verifyClock.elapsed() - t0 > avpn::kWhoamiFirstByteShareMs)
                m_engine.noteCheckStarved(true);
            if (avpn::whoamiProgressCut(m_verifyClock.elapsed(), t0, *lastByteAt, left)) {
                r->setProperty("avpn_timed_out", true); // our clock ended it, not the path
                r->abort();
            }
        });
        watch->start();
    }
    const qint64 armedWall = QDateTime::currentMSecsSinceEpoch();
    const bool otherEdge = base != m_baseUrl;
    connect(r, &QNetworkReply::finished, this, [this, r, epoch, nonce, rx, drain, t0, armedWall, left, otherEdge]() {
        r->deleteLater();
        drain();
        if (epoch != m_verifyEpoch || !m_engine.isVerifying())
            return;
        avpn::WhoamiObservation o;
        o.httpStatus = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        o.complete = r->error() == QNetworkReply::NoError;
        o.timedOut = r->property("avpn_timed_out").toBool();
        o.bytesReceived = rx->bytes;
        o.bodySha256Hex = rx->hash.result().toHex();
        o.headerSha256 = r->rawHeader(QByteArrayLiteral("X-Whoami-Sha256"));
        o.sentNonce = nonce;
        o.headerNonce = r->rawHeader(QByteArrayLiteral("X-Whoami-Nonce"));
        o.node = avpn::parseWhoamiNode(r->rawHeader(QByteArrayLiteral("X-Whoami-Node")), &o.nodeHeaderPresent);
        const avpn::WhoamiVerdict v = avpn::whoamiVerdict(o);
        // Facts for the journal and the bench report; the client IP is not written (node + country
        // are enough to tell "which exit", PII stays out of reports).
        const QString facts =
            QStringLiteral("http=%1 err=%2 complete=%3 timeout=%4 bytes=%5 node=%6 country=%7 ms=%8 attempt=%9 edge=%10")
                .arg(o.httpStatus)
                .arg(int(r->error()))
                .arg(int(o.complete))
                .arg(int(o.timedOut))
                .arg(o.bytesReceived)
                .arg(o.nodeHeaderPresent ? QString::number(o.node) : QStringLiteral("-"))
                .arg(QString::fromLatin1(r->rawHeader(QByteArrayLiteral("X-Whoami-Country"))))
                .arg(m_verifyClock.elapsed() - t0)
                .arg(m_verifyAttempts)
                .arg(otherEdge ? QStringLiteral("other") : QStringLiteral("active"));
        // Review N2: cut before a decisive answer and the timer fired late (monotonic or wall clock -
        // the latter also covers device sleep) = the app was suspended mid-request: no evidence.
        // Not counted as a sent request; Connected without the mark; memory and streak untouched.
        const qint64 sinceArm = std::max(m_verifyClock.elapsed() - t0, QDateTime::currentMSecsSinceEpoch() - armedWall);
        // Device round 18.11 (relaunch through devicectl): the check of an adopted tunnel was aborted by our own
        // connection reset (net_error 5, not our timeout) and read as "no data" - the engine left a working node.
        // A request we cancelled is no evidence: the check did not happen (the owner runs it again).
        if (r->error() == QNetworkReply::OperationCanceledError && !o.timedOut) {
            --m_verifyAttempts;
            finishWhoami(epoch, avpn::WhoamiVerdict::CheckLimited, facts + QStringLiteral(" no_evidence=cancelled"),
                         /*tiebreakDone=*/true);
            return;
        }
        if (avpn::whoamiCutBySuspension(v, o, sinceArm, left)) {
            --m_verifyAttempts;
#ifdef Q_OS_IOS
            // AVPN (iOS data watch, 141): "limited" after a freeze only once the extension was asked.
            if (deferWhileTunnelWatchFrozen("whoami_reply", [this, epoch, facts]() {
                    finishWhoami(epoch, avpn::WhoamiVerdict::CheckLimited, facts + QStringLiteral(" suspended=1"),
                                 /*tiebreakDone=*/true);
                }))
                return;
#endif
            finishWhoami(epoch, avpn::WhoamiVerdict::CheckLimited, facts + QStringLiteral(" suspended=1"),
                         /*tiebreakDone=*/true);
            return;
        }
        const qint64 leftNow = avpn::whoamiBudgetMs(m_engine.dataCheckMs()) - m_verifyClock.elapsed();
        if (avpn::whoamiNextStep(v, o.httpStatus, m_verifyAttempts, leftNow) == avpn::WhoamiStep::Retry) {
            // One retry: no answer at all, or "past the VPN" on the first answer (routes of a fresh
            // tunnel may not have settled yet).
            reliabilityEvent(QStringLiteral("whoami_retry verdict=%1 ").arg(avpn::whoamiVerdictName(v)) + facts);
            QTimer::singleShot(avpn::kWhoamiRetryDelayMs, this, [this, epoch]() { whoamiAttempt(epoch); });
            return;
        }
        // S3: the transfer time is the path's speed on this network (the ledger ranks slower working paths lower)
        if (v == avpn::WhoamiVerdict::Works)
            m_lastVerifyTtfbMs = int(m_verifyClock.elapsed() - t0);
        finishWhoami(epoch, v, facts);
    });
}

void AvpnEngineQml::finishWhoami(int epoch, avpn::WhoamiVerdict v, const QString &facts, bool tiebreakDone)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying())
        return;
    const QString node = m_engine.currentNodeId();
    const QString proto = m_engine.currentNodeProto();
    m_lastWhoamiFacts = facts;
    switch (avpn::whoamiAction(v, avpn::isXrayProto(proto), tiebreakDone)) {
    case avpn::WhoamiAction::Tiebreak:
        // Not decided (no answer, other status, no node header - or a bare 429/404 on Xray, which is
        // Connected only after a probe, §22.5): the existing generate_204 check decides with the rest
        // of the verify budget - passes -> CheckLimited, fails -> NoData (finishVerify routes its
        // result back here while m_whoamiTiebreak is set).
        reliabilityEvent(QStringLiteral("whoami verdict=%1 node=%2 proto=%3 tiebreak=generate_204 %4")
                             .arg(avpn::whoamiVerdictName(v), node, proto, facts));
        m_whoamiTiebreak = true;
        verifyAttempt(epoch);
        emit changed();
        return;
    case avpn::WhoamiAction::FailPath:
        // No data / past the VPN: the next path of the SAME attempt - step 3 of the §20 ladder
        // (other transport of this location, then another location), give-up cap and honest error
        // included (finishVerify -> verifyFailed -> onDead).
        m_pathCheck = avpn::whoamiVerdictName(v);
        reliabilityEvent(QStringLiteral("whoami verdict=%1 node=%2 proto=%3 %4").arg(m_pathCheck, node, proto, facts));
        finishVerify(epoch, false, avpn::whoamiFailoverReason(v));
        return;
    case avpn::WhoamiAction::Succeed: {
        m_pathCheck = avpn::whoamiVerdictName(v);
        reliabilityEvent(QStringLiteral("whoami verdict=%1 node=%2 proto=%3 %4").arg(m_pathCheck, node, proto, facts));
        const avpn::TunnelStats st = m_tunnel.readStats();
        m_lastVerifyRxProof = st.valid && st.rxBytes > 0;
        finishVerify(epoch, true);
        return;
    }
    case avpn::WhoamiAction::ConnectUnproven:
        // The check could not decide: Connected without the mark and without counting it as proven
        // data (the give-up streak stays - on a dead network health walks the ladder to the cap).
        m_pathCheck = avpn::whoamiVerdictName(avpn::WhoamiVerdict::CheckLimited);
        reliabilityEvent(QStringLiteral("whoami verdict=%1 node=%2 proto=%3 %4").arg(m_pathCheck, node, proto, facts));
        // An answer that came back through the tunnel (429/404 of our API, generate_204 of the tiebreak) is data;
        // a check the app's suspension cut has no evidence either way.
        if (facts.contains(QLatin1String("suspended")) || facts.contains(QLatin1String("no_evidence"))) {
            finishVerifyInconclusive(epoch);
        } else {
            m_whoamiTiebreak = false;
            finishVerify(epoch, true);
        }
        return;
    }
}

void AvpnEngineQml::finishVerifyInconclusive(int epoch)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying())
        return;
    m_whoamiTiebreak = false;
    m_lastVerifyMs = m_verifyClock.elapsed();
    m_lastVerifyOk = 0; // not verified (bench report verify_ok=false); path_check=limited says why
    qInfo() << "[avpn verify]" << m_engine.currentNodeProto() << "data path not decided in" << m_lastVerifyMs
            << "ms — connected without the data-flows mark";
    m_engine.verifyInconclusive();
    syncAttempt();
    if (m_engine.state() == avpn::EngineState::Connected) { // a live session's re-check: it stays
        m_busy = false;
        onTunnelUpEffects();
    }
    emit changed();
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

// Reseed пула по pool_revision (см. refreshSubscription). Вызывается ТОЛЬКО с верха цикла событий.
void AvpnEngineQml::applyReseed(const avpn::Subscription &sub, quint64 sequence, const QString &token)
{
    if (sequence != m_subscriptionSequence || token != authToken()) return;
    if (m_inSyncNetCall) {
        // Внутри вложенного QEventLoop sync-вызова (redeem/startFlow → Selector::pick) — ещё раз позже.
        QTimer::singleShot(50, this, [this, sub, sequence, token]() { applyReseed(sub, sequence, token); });
        return;
    }
    const QString pinBefore = m_engine.pinnedNodeId();
    const avpn::ReseedResult r = m_engine.reseedPool(sub);
    switch (r) {
    case avpn::ReseedResult::Applied: {
        // RTT-кэш фасада синхронизируем с движком (исчезнувшие узлы обрезаны там).
        m_nodeRtt = m_engine.measuredRtt();
        restorePin(pinBefore); // A7: перенесённый явный pin персистим, неявный — нет (A6)
        identifyAdoptedSession(); // A5: адоптированная сессия без identity — опознать по endpoint
        qInfo() << "[avpn reseed] pool revision" << m_engine.poolRevision() << "applied";
        notePreparationPoolSettled(true);
        emit changed();     // nodePool/currentNode пересчитаются (пикер, карточка)
        probeNodeRtt();     // новые узлы без замера — тёплый off-tunnel RTT (no-op при поднятом туннеле)
        break;
    }
    case avpn::ReseedResult::Unchanged:
        // A3/K5: содержимое пула не изменилось — движок обновил только traffic/expiry/status.
        // Ни changed() (refresh его уже эмитнул за traffic), ни persistPin, ни пробы.
        identifyAdoptedSession();
        notePreparationPoolSettled(false);
        break;
    case avpn::ReseedResult::Deferred:
        qInfo() << "[avpn reseed] pool revision" << sub.poolRevision << "deferred until terminal";
        notePreparationPoolSettled(false);
        break;
    case avpn::ReseedResult::Rejected:
        notePreparationPoolSettled(false);
        break;
    }
}

void AvpnEngineQml::applyPendingReseed()
{
    if (m_inSyncNetCall) {
        QTimer::singleShot(50, this, [this]() { applyPendingReseed(); });
        return;
    }
    if (!m_engine.hasPendingReseed())
        return;
    const QString pinBefore = m_engine.pinnedNodeId();
    if (!m_engine.applyPendingReseed())
        return; // не терминал (уже снова поднимаемся) — применим на следующем терминале
    m_nodeRtt = m_engine.measuredRtt();
    restorePin(pinBefore); // A7
    qInfo() << "[avpn reseed] pending pool revision" << m_engine.poolRevision() << "applied";
    emit changed();
    probeNodeRtt();
}

// AVPN (live-node picker): пере-зачитать подписку/health и обновить nodePool. Тихий no-op при провале
// (оффлайн/нет токена) — как bootstrap, не пугаем пользователя ошибкой при простом обновлении списка.
void AvpnEngineQml::refreshPool()
{
    refreshSubscription(); // one async, authenticated and safely reseeded path.
}

// AVPN (Task C): вход/восстановление по коду доступа (POST /v1/code/redeem). Синхронно (как enroll).
void AvpnEngineQml::redeemCode(const QString &code, const QString &evictDeviceId)
{
    if (m_busy)
        return;
    const QString trimmed = code.trimmed();
    if (trimmed.isEmpty()) {
        emit error(tr("Введите код доступа"));
        return;
    }

    m_busy = true;
    emit changed();

    avpn::CodeRedeemResponse resp;
    QVariantList devices;
    QString err;
    const avpn::CodeRedeemResult res =
        Enrollment::redeemCode(m_nam, m_baseUrl, m_engine.identity(), m_store,
                               trimmed, evictDeviceId, resp, devices, err);

    m_busy = false;

    switch (res) {
    case avpn::CodeRedeemResult::Ok:
        // РОТАЦИЯ токена уже сделана внутри Enrollment::redeemCode (saveToken). Перечитываем подписку
        // под НОВЫМ токеном — напрямую через движок (QML-фасадный bootstrap() идемпотентен и не сработал
        // бы повторно). Провал re-fetch не критичен: лимиты подтянутся при следующем bootstrap/start.
        m_engine.bootstrap(m_nam, m_baseUrl, m_store, err);
        refreshDevices(); // волна-4 (P2-4): устройства/аккаунт под новым токеном — сами
        refreshAccount();
        // AVPN (Task 9): subscription_token ротирован → старый push token на сервере отвязан.
        // Пере-регистрируем известный device token под новым токеном (fingerprint сменился → не дедупнется).
        if (!m_pushToken.isEmpty())
            registerPushToken(m_pushToken, m_pushEnv);
        emit changed(); // daysLeft/traffic*/subActive/nodePool/authToken обновятся
        break;
    case avpn::CodeRedeemResult::BadCode:
        emit error(tr("Неверный код доступа"));
        emit changed();
        break;
    case avpn::CodeRedeemResult::SeatLimit:
        // Мест нет — UI покажет devices[] для выбора кого отключить (повторный redeemCode с evictDeviceId
        // или DELETE /v1/devices/{id}). Не пишем error(), чтобы не дублировать модалкой выбора.
        emit seatLimitReached(devices);
        emit changed();
        break;
    case avpn::CodeRedeemResult::FingerprintMismatch:
        // Rehome-гейт (403): не error() — QML показывает специальное сообщение + кнопку в поддержку.
        emit fingerprintMismatch();
        emit changed();
        break;
    case avpn::CodeRedeemResult::Failed:
    default:
        emit error(err.isEmpty() ? tr("Не удалось активировать код") : err);
        emit changed();
        break;
    }
}

// AVPN (Task 13): принять перенос «как SIM» (POST /v1/transfer/redeem). Зовётся мостом диплинка
// (AvpnDeepLinkBridge) по tribe://transfer?t=… . Синхронно (как redeemCode).
void AvpnEngineQml::redeemTransfer(const QString &transferToken)
{
    // AVPN backend-first-3 (Task 6): kill-switch (features.transfer, default TRUE) — единая
    // воронка для deep-link/Universal Link/QR-скан/ввод в поле (все сходятся сюда через
    // AvpnDeepLinkBridge → coreController). Бэкенд может погасить перенос без релиза.
    if (!avpn::TuningStore::flag(QStringLiteral("transfer"))) {
        emit error(tr("Перенос временно недоступен"));
        return;
    }
    const QString trimmed = transferToken.trimmed();
    if (trimmed.isEmpty()) {
        emit error(tr("Пустая ссылка переноса"));
        return;
    }
    // Дедуп: iOS-сканер может отдать один QR несколько раз подряд (эмит на каждый кадр), плюс
    // возможен дубль скана/ссылки руками. Повторный redeem УЖЕ принятого токена дал бы 401 →
    // тост «Ссылка недействительна» ПОВЕРХ экрана успеха. Токен одноразовый — второй заход глушим.
    if (!m_lastRedeemedToken.isEmpty() && trimmed == m_lastRedeemedToken)
        return;
    if (m_busy) {
        // Холодный старт по диплинку: движок ещё занят bootstrap'ом. Раньше токен МОЛЧА терялся
        // («приложение открылось, а подписка не поменялась») — откладываем и ретраим до ~15 с.
        if (m_pendingRedeemToken == trimmed)
            return; // ретрай этого токена уже запланирован — второй таймер не плодим
        if (m_pendingRedeemAttempts < 20) {
            ++m_pendingRedeemAttempts;
            m_pendingRedeemToken = trimmed;
            QTimer::singleShot(750, this, [this, trimmed]() {
                m_pendingRedeemToken.clear();
                redeemTransfer(trimmed);
            });
        } else {
            m_pendingRedeemAttempts = 0;
            emit error(tr("Не удалось принять перенос — откройте ссылку ещё раз"));
        }
        return;
    }
    m_pendingRedeemAttempts = 0;

    m_busy = true;
    emit changed();

    avpn::TransferRedeemResponse resp;
    QString err;
    const avpn::TransferRedeemResult res =
        Enrollment::redeemTransfer(m_nam, m_baseUrl, m_engine.identity(), m_store,
                                   trimmed, resp, err);

    m_busy = false;

    switch (res) {
    case avpn::TransferRedeemResult::Ok:
        m_lastRedeemedToken = trimmed; // дедуп повторных сканов того же QR (см. вход)
        // РОТАЦИЯ токена уже сделана внутри Enrollment::redeemTransfer (saveToken). Перечитываем
        // подписку под НОВЫМ токеном напрямую через движок (QML-фасадный bootstrap() идемпотентен).
        m_engine.bootstrap(m_nam, m_baseUrl, m_store, err);
        // AVPN (Task 9): токен ротирован переносом → пере-регистрируем push token под новым.
        if (!m_pushToken.isEmpty())
            registerPushToken(m_pushToken, m_pushEnv);
        emit transferRedeemed();
        emit changed(); // daysLeft/traffic*/subActive/nodePool/authToken обновятся
        break;
    case avpn::TransferRedeemResult::BadToken:
        emit error(tr("Ссылка переноса недействительна или истекла"));
        emit changed();
        break;
    case avpn::TransferRedeemResult::FingerprintMismatch:
        // Rehome-гейт (403): специальный UX (не error) — см. onFingerprintMismatch в QML.
        emit fingerprintMismatch();
        emit changed();
        break;
    case avpn::TransferRedeemResult::SeatLimit:
        emit error(tr("Достигнут лимит устройств"));
        emit changed();
        break;
    case avpn::TransferRedeemResult::Failed:
    default:
        emit error(err.isEmpty() ? tr("Не удалось принять перенос") : err);
        emit changed();
        break;
    }
}

// AVPN (Task 13): выпустить перенос с ЭТОГО устройства (POST /v1/transfer, Bearer authToken).
// 401 лечим как fetchSubscription (decideAuthRecovery): один ре-энролл + ретрай — раньше
// стейл-JWT давал сырую ошибку «transfer unauthorized (token)» до перезапуска приложения.
// 410 (после переноса) — законное терминальное состояние: взводим transferredAway, не ошибку.
QVariantMap AvpnEngineQml::createTransfer()
{
    QVariantMap result;
    // AVPN backend-first-3 (Task 6): kill-switch (features.transfer, default TRUE) — симметрично
    // redeemTransfer. Пустая мапа + тост, QML createTransfer() уже трактует пустой deep_link как
    // «onError уже показал тост» (см. PageAccountTribe.qml).
    if (!avpn::TuningStore::flag(QStringLiteral("transfer"))) {
        emit error(tr("Перенос временно недоступен"));
        return result;
    }
    if (m_busy)
        return result;

    m_busy = true;
    emit changed();

    avpn::TransferMintResponse resp;
    QString err;
    avpn::FetchOutcome outcome = avpn::FetchOutcome::NetworkError;
    bool ok = Enrollment::createTransfer(m_nam, m_baseUrl, authToken(), resp, err, &outcome);

    if (!ok
        && Enrollment::decideAuthRecovery(outcome, /*tokenFromStore*/ true, /*alreadyReEnrolled*/ false)
                   == avpn::AuthRecoveryAction::ReEnrollThenRetry) {
        // БЕЗ clearToken: enroll при успехе сам перезапишет токен (saveToken), а при провале
        // (сеть/429) старый токен обязан ОСТАТЬСЯ — иначе после рестарта устройство в лимбе
        // (пустой токен → refreshSubscription молчит → даже 410 «перенесено» не доедет до UI).
        avpn::TrialResponse trial;
        QString enrollErr;
        avpn::FetchOutcome enrollOutcome = avpn::FetchOutcome::NetworkError;
        if (Enrollment::enroll(m_nam, m_baseUrl, m_engine.identity(), m_store, trial, enrollErr,
                               &enrollOutcome)) {
            // device_id идемпотентен на бэке: ре-энролл вернул токен ТОГО ЖЕ аккаунта — ретраим минт.
            ok = Enrollment::createTransfer(m_nam, m_baseUrl, authToken(), resp, err, &outcome);
        } else if (enrollOutcome == avpn::FetchOutcome::Transferred) {
            outcome = avpn::FetchOutcome::Transferred; // перенесённому устройству триал не положен
        }
    }

    m_busy = false;

    if (!ok && outcome == avpn::FetchOutcome::Transferred) {
        if (!m_transferredAway) m_transferredAway = true;
        emit changed(); // UI покажет состояние «Подписка перенесена» вместо тоста ошибки
        return result;
    }
    emit changed();

    if (!ok) {
        emit error(err.isEmpty() ? tr("Не удалось создать перенос") : err);
        return result;
    }
    result.insert(QStringLiteral("transfer_token"), resp.transferToken);
    result.insert(QStringLiteral("deep_link"), resp.deepLink);
    // опциональные (бэк по TRANSFER-KEYS-BACKEND-HANDOFF; пусто/0 пока не докатил)
    result.insert(QStringLiteral("web_link"), resp.webLink);
    result.insert(QStringLiteral("expires_in_s"), resp.expiresInS);
    return result;
}

// AVPN (grant-ключи): активация TRIBE-XXXX-XXXX-XXXX (промо/подарок/компенсация) на текущий аккаунт.
// Токен НЕ ротируется; успех = мапа с начислением, UI показывает «+N дней». Бэк — по handoff §3.B2.
QVariantMap AvpnEngineQml::redeemGrantKey(const QString &key)
{
    QVariantMap result;
    if (m_busy)
        return result;

    m_busy = true;
    emit changed();

    avpn::GrantKeyResponse resp;
    QString err;
    const auto res = Enrollment::redeemGrantKey(m_nam, m_baseUrl, authToken(), key, resp, err);

    m_busy = false;
    emit changed();

    if (res != GrantKeyResult::Ok) {
        QString msg;
        switch (res) {
        case GrantKeyResult::NotFound:    msg = tr("Ключ не найден — проверьте ввод"); break;
        case GrantKeyResult::AlreadyUsed: msg = tr("Этот ключ уже использован"); break;
        case GrantKeyResult::Expired:     msg = tr("Ключ истёк или отозван"); break;
        default: msg = err.isEmpty() ? tr("Не удалось активировать ключ") : err; break;
        }
        emit error(msg);
        return result;
    }

    result.insert(QStringLiteral("granted_days"), resp.grantedDays);
    result.insert(QStringLiteral("granted_gib"), resp.grantedGib);
    result.insert(QStringLiteral("plan"), resp.plan);
    result.insert(QStringLiteral("new_expiry"), resp.newExpiry);
    refreshSubscription(); // async данные-only: шапка (дни/ГБ) обновится, туннель не трогаем
    return result;
}

// AVPN: системный share sheet для текста/ссылки — см. AvpnShareBridge (iOS/Android), desktop → false.
bool AvpnEngineQml::shareText(const QString &text) const
{
    return AvpnShare::shareText(text);
}

// AVPN: share ссылки ВМЕСТЕ с QR-картинкой (перенос подписки: получатель может тапнуть ссылку
// ИЛИ отсканировать картинку с другого экрана). Рендерим qrcodegen-матрицу в PNG (12 px/модуль,
// quiet zone 4 модуля — читается камерой с запасом) в files-dir — на Android его покрывает
// FileProvider qtprovider (см. AvpnShareBridge). false → QML-fallback (shareText → копирование).
bool AvpnEngineQml::shareTextWithQr(const QString &text, const QString &qrPayload) const
{
    if (qrPayload.isEmpty())
        return AvpnShare::shareText(text);
    try {
        const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(qrPayload.toUtf8().constData(),
                                                                   qrcodegen::QrCode::Ecc::MEDIUM);
        constexpr int kScale = 12, kBorder = 4;
        const int size = (qr.getSize() + 2 * kBorder) * kScale;
        QImage img(size, size, QImage::Format_RGB32);
        img.fill(Qt::white);
        for (int y = 0; y < qr.getSize(); ++y)
            for (int x = 0; x < qr.getSize(); ++x)
                if (qr.getModule(x, y))
                    for (int dy = 0; dy < kScale; ++dy)
                        for (int dx = 0; dx < kScale; ++dx)
                            img.setPixel((x + kBorder) * kScale + dx, (y + kBorder) * kScale + dy,
                                         qRgb(0, 0, 0));

        const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(dir);
        const QString path = dir + QStringLiteral("/tribe-transfer-qr.png");
        if (!img.save(path, "PNG"))
            return AvpnShare::shareText(text);
        return AvpnShare::shareTextWithImage(text, path);
    } catch (...) {
        return AvpnShare::shareText(text); // payload не влез в QR — хотя бы ссылка
    }
}

// AVPN: QR для ссылки переноса — СЫРАЯ строка в QR (НЕ generateQrCodeImageSeries: тот заворачивает
// в амнезиевский чанк-конверт magic+base64 для импорта конфигов — системная камера его не поймёт).
// border=2 модуля — quiet zone для считывания. Data-URI SVG (чёрный на белом) для Image.source.
QString AvpnEngineQml::makeQrCode(const QString &text) const
{
    if (text.isEmpty())
        return QString();
    try {
        const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(text.toUtf8().constData(),
                                                                   qrcodegen::QrCode::Ecc::MEDIUM);
        return qrCodeUtils::svgToBase64(QString::fromStdString(qrcodegen::toSvgString(qr, 2)));
    } catch (...) {
        return QString(); // слишком длинно/не влезло — QML покажет плейсхолдер
    }
}

// AVPN (Task 7): тумблер #6 — читаем из ТОГО ЖЕ стора, что QML Settings{category:"AvpnSettings"}.
// QtCore.Settings без своего fileName использует default-конструируемый QSettings (org/app из
// QCoreApplication, выставленные ORGANIZATION_NAME/APPLICATION_NAME в main.cpp) → ключ совпадает.
bool AvpnEngineQml::autoPauseEnabled() const
{
    QSettings s; // org/app берутся из QCoreApplication (как у QML Settings)
    // Дефолт true — совпадает с `property bool autoPauseRu: true` в PageAccountTribe.qml.
    return s.value(QStringLiteral("AvpnSettings/autoPauseRu"), true).toBool();
}

// AVPN RU-direct: сев split-tunnel под единый тумблер «Доступ к сайтам РФ» (AvpnBypass/masterOn, default
// ON). Зовётся из guardedStart ПЕРЕД коннектом → конфиг готов к appendSplitTunnelingConfig. Сеет ВЕСЬ рунет
// CIDR в режим VpnAllExceptSites → рунет мимо туннеля (реальный РФ-IP). Домены отсекает сам движок,
// потому кормим ТОЛЬКО CIDR из ru_prefixes.h: v4 проходит checkIpSubnetFormat везде; v6 — isIpv6Cidr
// на iOS/Android (десктоп-демон v6-сплит не умеет, там v6 отсеется — см. appendSplitTunnelingConfig).
// Пустой список движок сам роняет в VpnAllSites (защита от блэкхола). Сев = РЕКОНСИЛЯЦИЯ
// (replaceVpnSites, полная замена): merge-only addVpnSites копил стейл-CIDR прошлых регенераций
// ru_prefixes навсегда (аудит; инвариант №3 vpn-bypass/README «apply = реконсиляция»). Список
// полностью наш — ручные сайты amnezia-UI затираются осознанно (в Tribe-навигации экрана нет).
// Кросс-платформенно (iOS excludeRoutes / Android excludeRoute / macOS десктоп-маршруты).
// OFF → активное ВЫКЛ флага.
void AvpnEngineQml::applyRuBypassSplit()
{
    if (!m_store)
        return;
    // AVPN win-note (2026-07-07): Windows-путь сева (router_win.cpp routeAddList) доведён до
    // инварианта «apply = реконсиляция»: идемпотентный посев + persist на диск + уборка сирот на
    // старте сервиса + дебаунс RouteMonitor (инцидент: 8646 маршрутов-сирот после краша сервиса).
    using amnezia::RouteMode;
    QSettings s;
    const bool masterOn = s.value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    // AVPN (китайские сервисы, 2026-07-03): второй независимый тумблер «Li Auto» (default ВКЛ). Оба тумблера
    // сеют в один и тот же split-набор (RouteMode::VpnAllExceptSites) — оси не конфликтуют, список объединяется.
    const bool liAutoOn = s.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool();
    // AVPN server-driven АнтиВПН (Task 10): списки с /v1/bypass-lists (подпись+LKG); вкомпиленные
    // массивы ниже — фолбэк (офлайн/первый запуск/kill-switch). Kill-switch remote_bypass_lists
    // гасится ВНУТРИ BypassListService (пустой invalid снапшот) ⇒ здесь достаточно bl.valid.
    const avpn::BypassLists bl = avpn::BypassListStore::get();
    const bool useRemote = bl.valid;
    // AVPN (T2, аудит 2026-07-02): здесь — только СЕВ списка (и активное ВЫКЛ, если ОБА тумблера OFF,
    // иначе прежний seed продолжил бы исключать трафик). Вкл/выкл сплита под РФ-ноду решается ПО
    // ФАКТИЧЕСКОЙ ноде в VpnConnectionTunnelControl::up() (покрывает failover/авто-RU-fallback/мёртвый
    // RU-pin — прежний гейт по pinnedNodeIsRu() тут расходился с реальностью, когда нода ≠ pin).
    if (!masterOn && !liAutoOn) {
        m_store->setSitesSplitTunnelingEnabled(false);
        // Страховка (ревью A5): пока сплит выключен, стор могли мутировать в обход этой функции —
        // сбрасываем стамп, чтобы ре-ВКЛ гарантированно пересеял (цена — один сев на переключение).
        m_lastBypassSeedStamp.clear();
        return;
    }
    m_store->setRouteMode(RouteMode::VpnAllExceptSites);
    m_store->setSitesSplitTunnelingEnabled(true);
    // AVPN (тормоза коннекта, 2026-07-10): сев ~10801 CIDR (QMap + carve по всем ключам + полная
    // запись в QSettings/plist) на GUI-потоке — на КАЖДОМ guardedStart/реконнекте/failover, при
    // неизменных входах (список обновляется раз в 6ч, тумблеры — руками). Стамп входов
    // (BypassSeedStamp.h, покрыт bypass_seed_check) совпал с прошлым севом этого процесса →
    // содержимое sites в сторе уже ровно такое → пропускаем сев целиком. Смена тумблера/версии
    // списка/carve-IP (async-резолв edge) меняет стамп → честный пересев. Стамп живёт только в
    // памяти процесса — первый сев после запуска всегда выполняется (стор мог меняться извне).
    // Оба-OFF выше чистят стамп (страховка от мутаций стора при выключенном сплите) — ре-ВКЛ
    // всегда пересеет. Carve-IP — из apiCarveIps(), ЕДИНОГО источника с rebuildApiCarveOut.
    const QString seedStamp =
            avpn::bypassSeedStamp(masterOn, liAutoOn, useRemote, bl.version, apiCarveIps());
    if (seedStamp == m_lastBypassSeedStamp) {
        qInfo("[AVPN bypass] seed unchanged — skip (v=%d)", useRemote ? bl.version : -1);
        return;
    }
    QMap<QString, QStringList> sites; // AVPN: формат значений апстрима f73697d3 (QStringList IP), CIDR = единственный элемент
    // AVPN Task 10 (per-group fallback): та же политика, что у парсера split_dns — "пусто =
    // нет override". Сервер может курировать любую из групп (ru_cidrs/bypass_extra/cn_liauto),
    // но если конкретная группа в валидном снапшоте пуста, это НЕ значит "выключить группу" —
    // это значит "сервер её не переопределяет", и группа падает на вкомпиленный дефолт. Раньше
    // useRemote гасил bypassExtra/liAuto целиком одним пустым полем на сервере (даже при живом
    // вкомпиленном фолбэке) — Госуслуги-carve и LiAuto молча исчезали. usedRemote* ниже — per-group
    // источник для лога (см. qInfo в конце функции).
    bool usedRemoteRu = false, usedRemoteExtra = false, usedRemoteLiAuto = false;
    if (masterOn) {
        // AVPN Task 10: рунет CIDR — серверный (bl.ruCidrs) при валидном снапшоте, иначе вкомпиленный.
        usedRemoteRu = useRemote;
        const QStringList ru = useRemote ? bl.ruCidrs : avpn::ruPrefixes();
        for (const QString &cidr : ru)
            sites.insert(cidr, {cidr});   // key=CIDR (checkIpSubnetFormat пройдёт), value=[CIDR]

        // AVPN RU-direct: foreign-эндпоинты, которые РФ-приложения дёргают для гео/анти-фрод проверок и которые
        // ПАЛЯТ загран-IP → гоним их тоже direct (residential РФ-IP), иначе приложение видит «VPN». Найдено
        // ЗАХВАТОМ (rvi0/PKTAP, 2026-07-01): процесс Gosuslugi через туннель ходит ТОЛЬКО в эти два, оба отвечают
        // (видят наш выход). Узкие /24 — не весь Google/Level3. Расширять по мере находок из захватов др. РФ-прил.
        // ⚠️ НЕ добавлять сюда CIDR, куда резолвятся эндпоинты НАШИХ проб (ServiceProbe/QualityProbe):
        // 216.239.38.0/24 уже накрывал youtubei.googleapis.com (216.239.38.223) → резолв YouTube-пробы уходил
        // мимо туннеля через РФ и таймаутился → «вечно серый чип» (2026-07-03; проба ушла на www.youtube.com).
        static const char *const kBypassExtra[] = {
            "216.239.38.0/24", // Google (QUIC 443) — Госуслуги attestation/Firebase-класс
            "8.6.112.0/24",    // Level3 (TLS 443)  — Госуслуги телеметрия/анти-фрод (POST ~1.5КБ)
        };
        // AVPN Task 10: foreign-эндпоинты — серверные (bl.bypassExtra) при валидном снапшоте И
        // непустые (сервер может курировать список, но пусто = "нет override", НЕ "выключить
        // Госуслуги-carve" — иначе пустое поле на сервере молча гасило бы вкомпиленный дефолт).
        // Массив выше остаётся вкомпиленным фолбэком на офлайн/первый запуск/kill-switch/пустой ответ.
        QStringList extraFallback;
        for (const char *cidr : kBypassExtra)
            extraFallback << QString::fromLatin1(cidr);
        usedRemoteExtra = useRemote && !bl.bypassExtra.isEmpty();
        const QStringList bypassExtra = usedRemoteExtra ? bl.bypassExtra : extraFallback;
        for (const QString &cidr : bypassExtra)
            sites.insert(cidr, {cidr});
    }

    // AVPN (китайские сервисы, 2026-07-03): узкие /24 серверов Li Auto (理想汽车, app com.chehejia.oc.m01) →
    // direct через РФ-IP. Из-за границы команды управления авто не проходят; с прямого РФ-IP работают.
    // Харвест «глазами РФ» (Google DoH + EDNS РФ-операторов), проверено стабильным для 6 операторов и на
    // пересечение с never-bypass — docs/amnezia-fork/CN-SERVICES-HARVEST.md. Только IPv4-CIDR (checkIpSubnetFormat).
    // Все /24 — на carrier-IDC/Baidu самого Li Auto, НЕ общий CDN (побочки на чужие сервисы нет: китайская
    // инфра из РФ и так direct). Хост команд api-app.lixiang.com за GSLB Baidu — при протухании регенерить
    // (см. gen-скрипт в HARVEST-доке). НЕ брать announced-префикс целиком (там /18–/23 carrier — пол-Китая).
    if (liAutoOn) {
        static const char *const kLiAutoCidrs[] = {
            "175.12.90.0/24",   // api-app.lixiang.com — КОМАНДЫ АВТО (CT Centralsouth AS151823)
            "183.60.227.0/24",  // api-app.lixiang.com — КОМАНДЫ АВТО (CHINANET Guangdong IDC AS134763)
            "103.103.244.0/24", // id.lixiang.com + account.lixiang.com — ЛОГИН/SSO (AS151373, РФ-вид)
            "180.76.97.0/24",   // api.lixiang.com — general API (Baidu AS38365)
            "106.13.244.0/23",  // likey-open/mindgpt/manage.chehejia.com — open-API apisix (CHINANET-IDC-BJ AS23724)
            "106.12.251.0/24",  // ssai-apis.chehejia.com — AI/ASR API (CHINANET Nanjing AS134756)
            "114.111.24.0/24",  // lianshan.lixiang.com / mindgpt — apisix gw (CT Hebei AS140903)
            "193.118.54.0/24",  // account.lixiang.com — заграничный GSLB-edge логина, запасной (Zenlayer AS21859)
        };
        // AVPN Task 10: Li Auto CIDR — серверные (bl.cnLiAutoCidrs) при валидном снапшоте И
        // непустые (та же политика "пусто = нет override" — сервер может курировать список Li Auto,
        // но пустое поле не должно молча гасить вкомпиленный дефолт при живом фолбэке).
        // Массив выше — вкомпиленный фолбэк на офлайн/первый запуск/kill-switch/пустой ответ.
        QStringList liAutoFallback;
        for (const char *cidr : kLiAutoCidrs)
            liAutoFallback << QString::fromLatin1(cidr);
        usedRemoteLiAuto = useRemote && !bl.cnLiAutoCidrs.isEmpty();
        const QStringList liAuto = usedRemoteLiAuto ? bl.cnLiAutoCidrs : liAutoFallback;
        for (const QString &cidr : liAuto)
            sites.insert(cidr, {cidr});
    }

    // AVPN carve-out (incident 2026-07-05, extracted in T6 — rebuildApiCarveOut(sites) above): the API
    // host was then on Beget, inside ru_prefixes (159.194.208.0/20), and the control plane went around
    // the tunnel. The API / active edge IPs are carved out of the seed HERE, where the inline block
    // used to be (same order of operations on the same `sites`). See rebuildApiCarveOut for the
    // current address.
    rebuildApiCarveOut(sites);

    // AVPN Task 10 (per-group fallback): источник — ПО ГРУППАМ, не одним общим useRemote — с тех пор
    // как пустая группа на сервере падает на вкомпиленный дефолт, а не на пустой список (см. выше).
    // ru/extra/liauto=1 → взят серверный снапшот для этой группы, =0 → вкомпиленный фолбэк.
    qInfo("[AVPN bypass] seed source cidrs=%d (master=%d liauto=%d) remote{ru=%d extra=%d liauto=%d} v=%d",
          int(sites.size()), masterOn ? 1 : 0, liAutoOn ? 1 : 0,
          usedRemoteRu ? 1 : 0, usedRemoteExtra ? 1 : 0, usedRemoteLiAuto ? 1 : 0,
          useRemote ? bl.version : -1);

    m_store->replaceVpnSites(RouteMode::VpnAllExceptSites, sites); // AVPN: реконсиляция, не merge
    m_lastBypassSeedStamp = seedStamp; // сев доехал до стора — только теперь входы можно считать применёнными
}

// AVPN RU-direct: применить смену тумблера «АвтоVPN» на живом туннеле. Если намерение — быть онлайн
// (подключены/подключаемся), передёргиваем через reconcile-машину: needsRestart → guardedStop → на
// пришедшем Disconnected reconcile сам поднимет заново (applyRuBypassSplit пересеет новый сплит-конфиг).
// Без back-to-back down+up (CONNECT-INVARIANTS). Офлайн → no-op (применится при следующем Connect).
// AVPN RU-direct (фикс «тумблер на лету не применяется», 2026-07-02): QML Settings (QtCore) пишет в
// QSettings с батч-задержкой ~500 мс (settingsWriteDelay в qqmlsettings), а NE-туннель на iOS гасится
// быстрее → applyRuBypassSplit (guardedStart) и DNS-гейт в up() читали СТАРЫЙ masterOn и поднимали
// туннель со старым сплит-конфигом. Симптом: тумблер на подключённом VPN → реконнект есть, сплит нет;
// ручной stop→toggle→start работал (запись успевала флашнуться). Пишем СИНХРОННО до передёрга —
// движок не должен зависеть от дебаунса UI-стора.
void AvpnEngineQml::setBypassMasterOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnBypass/masterOn"), on);
    s.sync();
    reapplyBypass();
}

// AVPN (звонки): «RU-DNS маскировка» — гейт Яндекс-DNS-подмены (читается в
// VpnConnectionTunnelControl::up). Синхронная запись + передёрг туннеля, как setBypassMasterOn.
bool AvpnEngineQml::bypassDnsMaskOn() const
{
    return QSettings().value(QStringLiteral("AvpnBypass/dnsMaskOn"), true).toBool();
}

void AvpnEngineQml::setBypassDnsMaskOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnBypass/dnsMaskOn"), on);
    s.sync();
    reapplyBypass();
}

// AVPN (китайские сервисы): «Li Auto» — узкие /24 серверов Li Auto мимо туннеля (default ВКЛ).
// Синхронная запись + передёрг туннеля, как setBypassMasterOn (QML Settings лагает ~500 мс).
bool AvpnEngineQml::bypassLiAutoOn() const
{
    return QSettings().value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool();
}

void AvpnEngineQml::setBypassLiAutoOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnBypass/liAutoOn"), on);
    s.sync();
    reapplyBypass();
}

// AVPN split-DNS форвардер: синхронная запись (грабля QML Settings ~500мс) + штатная реконсиляция
// (смена DNS-механики требует передёрга туннеля — reapplyBypass сам решит needsRestart).
bool AvpnEngineQml::bypassDnsFwdOn() const
{
    return QSettings().value(QStringLiteral("AvpnBypass/dnsFwd"), true).toBool();
}

void AvpnEngineQml::setBypassDnsFwdOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnBypass/dnsFwd"), on);
    s.sync();
    reapplyBypass();
}

void AvpnEngineQml::reapplyBypass()
{
    if (!m_wantConnected)
        return;
    m_needsRestart = true;
    m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P1-6)
    m_restartOrigin = QStringLiteral("bypass");
    reconcile();
    emit changed();
}

// AVPN (Task 7): пауза туннеля «для покупок». Будет дёргаться iOS App Intent (Task 8).
// Семантика бездействия БЕЗ foreground-API: ставим одноразовый таймер на `seconds`; если за это
// время пользователь не вернул туннель руками (resumeFromPause) и не остановил VPN — считаем, что
// он «не трогал» → авто-поднимаем обратно. Это и есть «бездействие → вернулись».
void AvpnEngineQml::pauseForShopping(int seconds)
{
    // Тумблер управляет лишь АВТО-триггером со стороны системы. Ручной/intent-вызов работает всегда —
    // если бы мы блокировали по autoPauseEnabled(), кнопка «пауза для покупок» молча не сработала бы.
    // (Авто-инициатор на стороне iOS-интента сам проверит тумблер перед вызовом — Task 8.)

    if (m_paused) {
        // Уже на паузе — продлеваем окно (пользователь «ещё не закончил покупки»).
        m_pauseTimer.start(qMax(1, seconds) * 1000);
        return;
    }

    // AVPN (аудит N7): не роняем туннель ПОВЕРХ незавершённой операции — down() поверх поднимающегося
    // = iOS-churn (§2). Пауза в момент перехода бессмысленна (туннель ещё/уже не несёт трафик) — игнор.
    if (m_opInFlight)
        return;

    // Запоминаем, был ли активный туннель: только тогда есть смысл поднимать его обратно по таймауту.
    // Если VPN и так не был поднят — пауза вырождается в no-op подъёма (просто ничего не роняем).
    // AVPN (независимое ревью волны, MINOR-7): фаза verifying — туннель ПОДНЯТ (xray ждёт первой
    // пробы). Без неё пауза для покупок считала xray-сессию «не поднятой» и после паузы туннель
    // не возвращался. Единый предикат — avpn::isTunnelUpStateName (DebugSnapshot.h).
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    m_wasConnected = avpn::isTunnelUpStateName(st);

    m_paused = true;
    // Реально опускаем туннель: на паузе utun-детект ДОЛЖЕН показывать туннель опущенным (трафик
    // покупки идёт мимо VPN). AVPN (аудит N7): через guardedStop() — та же последовательность
    // (healthTimer.stop + requestStop + down), но с Op::Stopping/opInFlight/watchdog, т.е. внутри
    // reconcile-машины; на пришедшем Disconnected reconcile no-op по гейту m_paused.
    guardedStop("pause_shopping");

    m_pauseTimer.start(qMax(1, seconds) * 1000);
    emit changed();
}

// AVPN (Task 7): ручной выход из паузы — поднять туннель сразу, не дожидаясь таймера.
void AvpnEngineQml::resumeFromPause()
{
    if (!m_paused)
        return;
    m_pauseTimer.stop();
    m_paused = false;
    // Поднимаем туннель обратно только если до паузы он был активен. Иначе — просто снимаем флаг.
    if (m_wasConnected) {
        m_wantConnected = true;
        reconcile();
    }
    m_wasConnected = false;
    emit changed();
}

// AVPN (Task 7): таймер паузы истёк → бездействие → возвращаемся (поднимаем туннель обратно).
void AvpnEngineQml::onPauseTimeout()
{
    resumeFromPause();
}

// AVPN (Devices+Account): GET /v1/devices АСИНХРОННО → property `devices` + devicesChanged().
// Контракт отдаёт ГОЛЫЙ JSON-массив DeviceInfo (не обёртку {devices:[…]}, как в 409-теле redeem).
// Bearer = authToken() (subscription_token). Нет токена / 401 / сеть / таймаут → пустой список.
// КРИТИЧНО: БЕЗ вложенного QEventLoop — зовётся из QML-таймера (settingsLoadTimer); nested loop
// на GUI-потоке прокручивал чужие события и при destroy объекта в его теле → re-entrancy краш
// («Object destroyed while one of its QML signal handlers is in progress / nested event loop»).
void AvpnEngineQml::refreshDevices()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        if (!m_devices.isEmpty()) { m_devices.clear(); emit devicesChanged(); }
        return;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/devices"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply); // жёсткий таймаут без nested loop (abort → finished с code==0)
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QVariantList list;
        if (code >= 200 && code < 300) {
            const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (doc.isArray()) {
                for (const QJsonValue &v : doc.array()) {
                    const QJsonObject d = v.toObject();
                    QVariantMap m;
                    m.insert(QStringLiteral("device_id"), d.value(QStringLiteral("device_id")).toString());
                    // AVPN: device_uuid (install-UUID = localDeviceId) — публичный «ID устройства»
                    // для UI и операций extend/delete; device_id (PK) deprecated. Контракт LIVE.
                    m.insert(QStringLiteral("device_uuid"), d.value(QStringLiteral("device_uuid")).toString());
                    m.insert(QStringLiteral("platform"), d.value(QStringLiteral("platform")).toString());
                    m.insert(QStringLiteral("label"), d.value(QStringLiteral("label")).toString());
                    m.insert(QStringLiteral("last_seen"), d.value(QStringLiteral("last_seen")).toString());
                    m.insert(QStringLiteral("is_current"), d.value(QStringLiteral("is_current")).toBool());
                    list.append(m);
                }
            }
        }
        // 401/сеть/таймаут → пустой список (как в синхронной версии). Эмитим всегда, чтобы UI
        // мог снять «загрузку» и забиндиться на актуальное значение.
        m_devices = list;
        emit devicesChanged();
    });
}

// AVPN (Devices+Account): DELETE /v1/devices/{id} → кик устройства (его токен убит, peer снят на
// каждой ноде). 204 → true + emit changed() (UI перечитает listDevices()). 401/404/сеть → false +
// emit error. Account-scoped: чужой/несуществующий id отдаёт 404 (BOLA-защита бэка).
bool AvpnEngineQml::kickDevice(const QString &deviceId)
{
    const QString id = deviceId.trimmed();
    if (id.isEmpty()) {
        emit error(tr("Не указано устройство"));
        return false;
    }
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        emit error(tr("Нет авторизации"));
        return false;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/devices/")
                            + QString::fromUtf8(QUrl::toPercentEncoding(id)))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->deleteResource(req);
    awaitReply(reply); // AVPN: было QEventLoop без таймаута → фриз при зависшем бэке

    const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QNetworkReply::NetworkError netErr = reply->error();
    const QString netErrStr = reply->errorString();
    reply->deleteLater();

    if (netErr != QNetworkReply::NoError && code == 0) {
        emit error(tr("Сеть недоступна: %1").arg(netErrStr));
        return false;
    }
    if (code == 401) {
        emit error(tr("Сессия истекла"));
        return false;
    }
    if (code == 404) {
        emit error(tr("Устройство не найдено"));
        return false;
    }
    if (code < 200 || code >= 300) {
        emit error(tr("Не удалось отключить устройство (HTTP %1)").arg(code));
        return false;
    }
    emit changed(); // Настройки перечитывают устройства сами сразу после успешного kick
    return true;
}

// AVPN (Devices+Account): GET /v1/account АСИНХРОННО → property `account` + accountChanged().
// Bearer = authToken(). Нет токена / 401 / сеть / таймаут → пустая мапа (UI покажет дефолты).
// Формат: {account_id, status, expires_at?, traffic_limit, traffic_used}. БЕЗ nested loop
// (как refreshDevices — зовётся из QML-таймера, nested loop = re-entrancy краш).
void AvpnEngineQml::refreshAccount()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        if (!m_account.isEmpty()) { m_account.clear(); emit accountChanged(); }
        return;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/account"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // AVPN remote-config (T6, edge-walk) + белые списки: волна-4 — одна классификация
        // (noteApiOutcome): 0/5xx = отказ входа, любой иной ответ доказывает, что вход жив; наши
        // abort'ы и таймауты из-под заморозки отказом не считаются.
        noteApiOutcome(reply);
        // AVPN (перенос «как SIM»): 410 transferred — см. refreshSubscription (тот же флаг).
        if (code == 410 && !m_transferredAway) { m_transferredAway = true; emit changed(); }
        QVariantMap result;
        if (code >= 200 && code < 300) {
            const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (doc.isObject()) {
                const QJsonObject o = doc.object();
                result.insert(QStringLiteral("account_id"), o.value(QStringLiteral("account_id")).toString());
                result.insert(QStringLiteral("status"), o.value(QStringLiteral("status")).toString());
                result.insert(QStringLiteral("expires_at"), o.value(QStringLiteral("expires_at")).toString());
                result.insert(QStringLiteral("traffic_limit"),
                              static_cast<qlonglong>(o.value(QStringLiteral("traffic_limit")).toDouble()));
                result.insert(QStringLiteral("traffic_used"),
                              static_cast<qlonglong>(o.value(QStringLiteral("traffic_used")).toDouble()));
                // AVPN (admin-гейт): devices.is_admin с бэка. Отсутствие ключа/оффлайн/401 →
                // пустая мапа → isAdminDevice()==false — панель администратора скрыта.
                result.insert(QStringLiteral("is_admin"), o.value(QStringLiteral("is_admin")).toBool());
                // AVPN (журнал тестирования): удалённое включение из /panel. Флаги кэшируются —
                // до первого ответа после рестарта (или оффлайн) журнал не выключается.
                result.insert(QStringLiteral("diag_journal_forced"),
                              o.value(QStringLiteral("diag_journal_forced")).toBool());
                QSettings cache;
                cache.setValue(QStringLiteral("avpn/journal/forced"),
                               result.value(QStringLiteral("diag_journal_forced")));
                cache.setValue(QStringLiteral("avpn/journal/admin"), result.value(QStringLiteral("is_admin")));
                // AVPN (короткий ID, канон 2026-07-21): порядковый числовой Account.id —
                // ЕГО показываем юзеру (шапка чата, карточка «Статус доступа»); длинный
                // hex account_id — технический (копия/перенос). 0/нет поля = старый бэк →
                // UI падает на фолбэк (первые 8 hex).
                result.insert(QStringLiteral("account_number"),
                              o.value(QStringLiteral("account_number")).toInt(0));
                // AVPN (плашка группы, group-aware волна): операторская группа аккаунта —
                // бейдж карточки показывает её имя вместо Премиум/Пробный/Истекла.
                // null/нет поля → ключ не пишем, UI рисует обычный бейдж.
                const QJsonValue gv = o.value(QStringLiteral("group"));
                if (gv.isObject()) {
                    const QJsonObject g = gv.toObject();
                    QVariantMap gm;
                    gm.insert(QStringLiteral("name"), g.value(QStringLiteral("name")).toString());
                    gm.insert(QStringLiteral("color"), g.value(QStringLiteral("color")).toString());
                    gm.insert(QStringLiteral("unlimited"),
                              g.value(QStringLiteral("unlimited")).toBool());
                    result.insert(QStringLiteral("group"), gm);
                }
            }
        }
        m_account = result;
        emit accountChanged();
        syncJournal(); // AVPN (журнал тестирования)
        // AVPN (оплата, ДВОЕ ЧАСОВ): числа /v1/account — ЧАСЫ АККАУНТА, а платёж продлевает ЧАСЫ
        // УСТРОЙСТВА (apply_paid → device.expires_at/traffic; account.status/expires не трогает).
        // Прежний merge updateSubscriptionTraffic(/v1/account) ЗАТИРАЛ device-часы шапки аккаунт-
        // часами: на оплаченном устройстве бейдж флипался «36 дн./100ГБ → триальные». Живой бейдж
        // теперь кормит refreshSubscription() (device-часы); сюда merge НЕ возвращать.
        // property account (account_id для саппорта, списки в Настройках) остаётся как есть.
    });
}

// AVPN (i18n): язык приложения для переключателя в Tribe-настройках. Свои enum/модели не заводим —
// пишем локаль напрямую в SecureAppSettingsRepository (тот же инстанс, что у coreController);
// его сигнал appLanguageChanged запускает штатную цепочку ретрансляции апстрима.
QString AvpnEngineQml::appLang() const
{
    return m_store ? m_store->getAppLanguage().name().split(QLatin1Char('_')).first()
                   : QStringLiteral("ru");
}

QString AvpnEngineQml::upstreamRowName(const QString &label, bool labelCustom, int ordinal, avpn::UpstreamKind rowKind,
                                       const QString &countryCode) const
{
    return avpn::upstreamDisplayName(label, labelCustom, ordinal, rowKind,
                                     doctor::countryDisplayName(countryCode, appLang()),
                                     tr("Белые списки"), tr("Авто"));
}

void AvpnEngineQml::setAppLang(const QString &lang)
{
    if (!m_store || appLang() == lang)
        return;
    m_store->setAppLanguage(QLocale(lang));
    emit appLangChanged();
    // AVPN backend-first-3 (Task 7): incidentText/hotTexts — функции от appLang (localizedOr).
    // Их NOTIFY = changed, appLangChanged его не покрывает — эмитим явно, иначе баннер/CTA
    // остаются на старом языке до следующего configApplied.
    emit changed();
}

// AVPN backend-first-3 (Task 7): server-driven hot-тексты CTA оплаты. Ключи фиксированы
// (контракт с PageConnectTribe.qml), значение — localizedOr("<key>", appLang(), "") по цепочке
// _<lang> → _en → base. Пустые НЕ кладём в map: в QML `hotTexts["key"]` даёт undefined →
// falsy → срабатывает вкомпиленный qsTr-фолбэк (byte-for-byte прежний текст).
QVariantMap AvpnEngineQml::hotTexts() const
{
    static const QString kCtaKeys[] = { QStringLiteral("cta_renew_traffic"),
                                        QStringLiteral("cta_renew_access"),
                                        QStringLiteral("cta_how_traffic"),
                                        QStringLiteral("cta_how_access") };
    QVariantMap out;
    const QString lang = appLang();
    for (const QString &key : kCtaKeys) {
        const QString v = avpn::TuningStore::localizedOr(key, lang, QString());
        if (!v.isEmpty())
            out.insert(key, v);
    }
    return out;
}

// AVPN (оплата, ДВОЕ ЧАСОВ): лёгкий рефетч GET /v1/subscription — ЧАСЫ УСТРОЙСТВА (их продлевает
// платёж) для бейджа ГБ/дней и CTA «Обновить ключ». Обновляет ТОЛЬКО traffic/expires снапшота
// (updateSubscriptionTraffic) — пул нод/туннель/стейт-машину НЕ трогает (CONNECT-INVARIANTS:
// никакой реконфигурации на лету). АСИНХРОННО (armTimeout, без nested loop). Зовётся: (а) возврат
// в foreground — после оплаты в кабинете приедет новый expires_at и CTA погаснет сам; (б) тик #35.
// Волна-4 (P2-4): одна пачка на возврат на экран — kickBootstrap (дёшев, no-op после успеха),
// подписка с троттлом 30 с (device-часы: бейдж/CTA после оплаты в браузере), конфиг раз в 15 мин
// (ENG-03) и отложенные эффекты подключения (P2-3). Настройки/аккаунт — по открытию экрана.
void AvpnEngineQml::onForegroundDebounced()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const ForegroundPlan plan = planForeground(m_lastFgRefreshMs > 0 ? now - m_lastFgRefreshMs : -1, -1);
    reliabilityEvent(QStringLiteral("foreground_return sub=%1").arg(plan.refreshSubscription));
    kickBootstrap();
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // Connect audit 2026-11-04 (VPN-SELF-OFF-ANALYSIS-2026-09-27 plan item 6, partial: status refresh
    // only; re-arming the watchdog while an operation is in flight is not done): while the app was
    // suspended the extension may have stopped, restarted or replaced the session; ask the
    // NetworkExtension for the real status once per return instead of showing the pre-suspend state.
    // The answer comes through the usual observation path (vpnStatusDidChange ->
    // onConnectionStateChanged): adoption and the §13 loss rules decide, nothing here touches the
    // tunnel. Our own start/stop in flight observes the status itself.
    if (m_op == Op::None) {
        reliabilityEvent(QStringLiteral("foreground_status_refresh"));
        IosController::Instance()->requestReconcileStatus();
    }
#endif
    if (plan.refreshSubscription) {
        m_lastFgRefreshMs = now;
        refreshSubscription();
        refreshAccount(); // ревью: удалённое включение журнала, ID в чате поддержки, бейдж группы
    }
    if (m_configSvc)
        m_configSvc->refreshIfStale(kFgConfigThrottleMs);
    // 5.1.109 (S4.1): on macOS the service may have got tun2socks while the app was hidden; a choice
    // that waited is admitted if nothing is running.
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (refreshXrayRuntimeGate(QStringLiteral("foreground")))
        emit changed(); // Xray nodes became (un)supported: the server list reads it from the pool
#endif
    maybeRefreshStandby("foreground"); // AVPN upstream nodes: the pack while the API is reachable
    syncTransportMode(QStringLiteral("foreground"));
    if (m_effectsPending && state() == QLatin1String("connected") && uiForeground())
        runConnectEffects();
}

// Decision 2026-11-05: /v1/subscription has its own per-edge failure streak that small calls do not
// reset (DebugSnapshot.h::classifySubscriptionEdgeOutcome, EdgeWalk.h::SubscriptionEdgeStreak): two
// transport failures in a row on the active edge switch it (ConfigService rotation). Owner's journal:
// 0 of 23 subscriptions on direct cellular to vpn.wellwon.hk while /v1/account passed.
void AvpnEngineQml::noteSubscriptionEdgeOutcome(QNetworkReply *reply, const QString &requestBase)
{
    if (!m_configSvc || !reply)
        return;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const SubscriptionEdgeOutcome o = classifySubscriptionEdgeOutcome(
        int(reply->error()), reply->property("avpn_timed_out").toBool(), reply->property("avpn_t0").toLongLong(),
        std::max(m_lastResumeMs, m_lastHiddenMs), m_lastTunnelTransitionMs, now);
    if (o == SubscriptionEdgeOutcome::Ignore)
        return;
    const QString before = m_configSvc->activeBaseUrl();
    if (m_configSvc->reportSubscriptionOutcome(requestBase, o == SubscriptionEdgeOutcome::Failure))
        reliabilityEvent(QStringLiteral("edge_switch why=subscription_streak from=%1 to=%2")
                             .arg(QUrl(before).host(), QUrl(m_configSvc->activeBaseUrl()).host()));
}

// Волна-4 (P2-2/ENG-01): единая классификация исхода запроса к API. Edge-walk: Failure →
// reportNetworkFailure, Success → reportNetworkSuccess, Ignore → ничего (наш abort при смене
// ноды, запрос из-под заморозки, окно своего перехода туннеля). Детектор белых списков: любой
// дошедший HTTP-статус (вкл. 5xx) = control plane достижим; фейл — только честный транспортный.
void AvpnEngineQml::noteApiOutcome(QNetworkReply *reply)
{
    const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const bool canceled = reply->error() == QNetworkReply::OperationCanceledError;
    const bool timedOut = reply->property("avpn_timed_out").toBool();
    const qint64 t0 = reply->property("avpn_t0").toLongLong();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    // Ревью: просроченный таймер запроса может сработать после разморозки раньше Active — граница
    // заморозки = последний уход в фон или выход на экран, что позже.
    const ApiOutcome o = classifyApiOutcome(code, canceled, timedOut, t0, std::max(m_lastResumeMs, m_lastHiddenMs),
                                            m_lastTunnelTransitionMs, now);
    if (m_configSvc) {
        if (o == ApiOutcome::Failure)
            m_configSvc->reportNetworkFailure();
        // 5.1.109 (S4.1, iOS and macOS): an API path works again while the process is still on the
        // cached config - the config is asked for now, not on the next return to the screen.
        else if (o == ApiOutcome::Success && m_configSvc->reportNetworkSuccess())
            reliabilityEvent(QStringLiteral("config_refetch why=api_path_back"));
    }
    if (m_whitelistDetector) {
        if (code > 0)
            m_whitelistDetector->noteControlPlaneOk();
        else if (o == ApiOutcome::Failure)
            m_whitelistDetector->noteControlPlaneFailure();
    }
    if (o == ApiOutcome::Ignore)
        reliabilityEvent(QStringLiteral("api_failure_ignored code=%1 canceled=%2 timeout=%3")
                             .arg(code).arg(canceled).arg(timedOut));
}

void AvpnEngineQml::refreshSubscription()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty())
        return;

    QNetworkRequest req{versionedSubscriptionUrl(
        m_baseUrl, QCoreApplication::applicationVersion())};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    const quint64 sequence = ++m_subscriptionSequence;
    const QString requestToken = token;
    const QString requestBase = m_baseUrl;
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, sequence, requestToken, requestBase]() {
        reply->deleteLater();
        // Decision 2026-11-05: the per-edge subscription streak counts a stale response too - only
        // the response handling below drops it.
        noteSubscriptionEdgeOutcome(reply, requestBase);
        if (sequence != m_subscriptionSequence || requestToken != Enrollment::loadToken()) {
            reliabilityEvent(QStringLiteral("stale_subscription_response_ignored"));
            return;
        }
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // AVPN remote-config (T6, edge-walk) + белые списки: см. noteApiOutcome (волна-4).
        noteApiOutcome(reply);
        // Decision 2026-11-05: we aborted it ourselves on a tunnel transition - re-issue it once over
        // the new path (the next one is a new request with its own sequence).
        if (reissueAfterOwnAbort(reply->error() == QNetworkReply::OperationCanceledError,
                                 reply->property("avpn_timed_out").toBool())) {
            reliabilityEvent(QStringLiteral("subscription_reissue after_own_abort"));
            QTimer::singleShot(0, this, [this]() { refreshSubscription(); });
            return;
        }
        // AVPN (перенос «как SIM»): 410 transferred — подписка уехала на другое устройство.
        // Взводим терминальный флаг для UI («Подписка перенесена»); НЕ ре-энроллим.
        if (code == 410) {
            if (!m_transferredAway) { m_transferredAway = true; emit changed(); }
            notePreparationPoolSettled(false);
            return;
        }
        if (reply->error() != QNetworkReply::NoError || code < 200 || code >= 300) {
            notePreparationPoolSettled(false); // A11: подготовка старта не ждёт провалившийся refresh
            return; // 401/сеть/таймаут → тихо; данные обновятся при следующем connect/bootstrap
        }
        if (m_transferredAway) { m_transferredAway = false; emit changed(); } // подписка снова валидна (новый ключ/энролл)
        const QByteArray body = reply->readAll();
        Subscription sub;
        QString err;
        if (!SubscriptionParser::parse(body, sub, err)) {
            notePreparationPoolSettled(false);
            return; // битый ответ не затирает валидные числа
        }
        m_engine.updateSubscriptionTraffic(sub.trafficUsed, sub.trafficLimit, sub.expiresAt);
        // AVPN (LKG, HARDENING-BACKLOG H-3): каждый удачный фетч освежает дисковый кэш — после
        // долгой фоновой жизни холодный старт покажет свежие цифры, а не данные последнего bootstrap.
        // Тело уже валидно (parse выше); m_pool этот путь трогает ТОЛЬКО через reseed ниже.
        // AVPN (фикс-волна 2026-09-22, A2): тело с пустыми nodes не перезаписывает LKG с нодами.
        saveLkgSubscriptionGuarded(body, !sub.nodes.isEmpty());
        emit changed(); // daysLeft/traffic*/subExpired в QML пересчитаются
        // AVPN awg31-xray-v1 (спека §2.3, инвариант §4.4): reseed пула на живом приложении по смене
        // pool_revision. Три опоры: kill-switch features.subscription_reseed_pool (default ВЫКЛ —
        // включает бэк), ревизия > 0 (старый бэк/LKG без поля — не трогаем), непустой пул (пустое/
        // degraded-тело пул не затирает). Применение — с верха цикла событий (QTimer::singleShot(0)):
        // этот колбэк может прийти изнутри вложенного QEventLoop sync-вызова (redeem/startFlow),
        // а движок мог быть в Selector::pick. Терминал/неизменная текущая нода решает сам движок.
        QTimer::singleShot(0, this, [this, sub, body, sequence, requestToken]() {
            if (sequence != m_subscriptionSequence || requestToken != authToken()) return;
            // AVPN (фикс-волна 2026-09-22, A2/A3): порядок ответов — только m_subscriptionSequence
            // (серверная pool_revision не глобальный монотонный счётчик, K5). Пустые nodes при
            // имеющемся пуле обновляют только traffic/expiry/status — loadSubscription по K5 пул
            // сохраняет; без probe/restorePin (пул не менялся).
            switch (routeSubscriptionBody(!sub.nodes.isEmpty(), m_engine.hasSubscription(),
                                          sub.poolRevision)) {
            case SubscriptionBodyRoute::KeepPoolUpdateMeta: {
                QString error;
                m_engine.loadSubscription(body, error);
                reliabilityEvent(QStringLiteral("subscription_empty_pool_kept"));
                notePreparationPoolSettled(false);
                break;
            }
            case SubscriptionBodyRoute::LoadFull: {
                QString error;
                const QString pinBefore = m_engine.pinnedNodeId();
                m_engine.loadSubscription(body, error);
                restorePin(pinBefore);
                identifyAdoptedSession();
                const bool poolArrived = !sub.nodes.isEmpty();
                notePreparationPoolSettled(poolArrived);
                if (poolArrived) probeNodeRtt();
                break;
            }
            case SubscriptionBodyRoute::Reseed:
                applyReseed(sub, sequence, requestToken);
                break;
            }
            if (m_engine.hasSubscription()) {
                m_bootstrapped = true;
                m_bootstrapInFlight = false;
                m_bootstrapRetryTimer.stop();
            }
            enforceSubscriptionGrace(); // only after an authenticated, ordered fresh response.
        });
    });
}

// AVPN (#37 рефералы): GET /v1/referral → {code, link, invited, days_earned, gb_earned,
// days_per_friend, gb_per_friend, invitee_days} (openapi 0.9.0). Тот же async-паттерн,
// что refreshAccount (без вложенного QEventLoop). Код привязывается к устройству при первом вызове
// (issued lazily) — поэтому бонус-дни от установки друга падают на ЭТО устройство.
void AvpnEngineQml::refreshReferral()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        if (!m_referral.isEmpty()) { m_referral.clear(); emit referralChanged(); }
        return;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/referral"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QVariantMap result;
        if (code >= 200 && code < 300) {
            const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (doc.isObject()) {
                const QJsonObject o = doc.object();
                result.insert(QStringLiteral("code"), o.value(QStringLiteral("code")).toString());
                result.insert(QStringLiteral("link"), o.value(QStringLiteral("link")).toString());
                result.insert(QStringLiteral("invited"),
                              static_cast<int>(o.value(QStringLiteral("invited")).toDouble()));
                result.insert(QStringLiteral("days_earned"),
                              static_cast<int>(o.value(QStringLiteral("days_earned")).toDouble()));
                result.insert(QStringLiteral("gb_earned"),
                              static_cast<int>(o.value(QStringLiteral("gb_earned")).toDouble()));
                // Server-driven размер оффера — пробрасываем ТОЛЬКО если бэк прислал (QML по
                // undefined откатывается на вкомпиленный фолбэк — старые бэки без полей).
                for (const char *key : { "days_per_friend", "gb_per_friend", "invitee_days" }) {
                    const QString k = QString::fromLatin1(key);
                    if (o.contains(k))
                        result.insert(k, static_cast<int>(o.value(k).toDouble()));
                }
            }
        }
        // 401/сеть/таймаут → пустая мапа (баннер покажет дефолтный оффер). Эмитим всегда.
        m_referral = result;
        emit referralChanged();
    });
}

// ---------------------------------------------------------------------------
// AVPN (объявления P-ANN): server-driven важные сообщения — попап поверх главного
// экрана + карточки колокольчика. Контент настраивается в админке; новые
// объявления НЕ требуют обновления приложения. Спека: tribe-front
// docs/superpowers/specs/2026-07-09-announcements-design.md.
// ---------------------------------------------------------------------------

namespace {
QString announcePlatform()
{
#if defined(Q_OS_IOS)
    return QStringLiteral("ios");
#elif defined(Q_OS_ANDROID)
    return QStringLiteral("android");
#elif defined(Q_OS_MACOS)
    return QStringLiteral("macos");
#elif defined(Q_OS_WIN)
    return QStringLiteral("windows");
#else
    return QStringLiteral("linux");
#endif
}
} // namespace

// AVPN (announce-quiet): отметка «онбординг пройден» — якорь тихого окна попапов.
// Синхронный QSettings (грабля 500мс QML-Settings: quiet-проверка идёт уже через 900мс).
// Идемпотентно: НЕ сдвигаем отметку, если уже стоит (повторные onRequestStart/дев-сбросы
// онбординга не продлевают тишину).
void AvpnEngineQml::markOnboardingDone()
{
    QSettings s;
    const QString key = QStringLiteral("AvpnAnnounce/onboardDoneAt");
    if (s.value(key, 0).toLongLong() > 0)
        return;
    s.setValue(key, QDateTime::currentSecsSinceEpoch());
    s.sync();
}

// AVPN (announce-quiet): попапы объявлений сейчас молчат? Kill-switch первой строкой
// (default TRUE — бэк может прислать false и вернуть старое поведение без релиза);
// размер окна server-tunable (кап 7 суток в AnnounceGate::quietMinTuned). Глушится только
// автопоказ попапа — бейдж колокольчика, лента и пуши работают как раньше.
bool AvpnEngineQml::announcementsQuietNow() const
{
    if (!avpn::TuningStore::flag(QStringLiteral("announce_onboarding_quiet")))
        return false;
    const qint64 doneAt = QSettings().value(QStringLiteral("AvpnAnnounce/onboardDoneAt"), 0).toLongLong();
    return avpn::AnnounceGate::quietActive(doneAt, avpn::AnnounceGate::quietMinTuned(),
                                           QDateTime::currentSecsSinceEpoch());
}

// LKG-персист текущего списка (мгновенный показ до сети при следующем старте — паттерн
// saveLkgSubscription). Синхронный QSettings::sync — движок владеет записью, не QML.
void AvpnEngineQml::persistAnnouncementsLkg()
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnAnnounce/lkg"),
               QString::fromUtf8(QJsonDocument(QJsonArray::fromVariantList(m_announcements))
                                     .toJson(QJsonDocument::Compact)));
    s.sync();
}

void AvpnEngineQml::loadAnnouncementsLkg()
{
    QSettings s;
    const QByteArray raw = s.value(QStringLiteral("AvpnAnnounce/lkg")).toString().toUtf8();
    if (raw.isEmpty())
        return;
    const QJsonDocument doc = QJsonDocument::fromJson(raw);
    if (!doc.isArray())
        return;
    QVariantList items;
    for (const QJsonValue &v : doc.array()) {
        const QVariantMap item = v.toObject().toVariantMap();
        // Прочитанное после сохранения LKG отфильтровываем на загрузке.
        if (!announcementRead(item.value(QStringLiteral("id")).toInt()))
            items.append(item);
    }
    if (!items.isEmpty()) {
        m_announcements = items;
        emit announcementsChanged();
    }
}

void AvpnEngineQml::refreshAnnouncements()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty())
        return; // без токена не ходим; LKG уже показан, bootstrap дотянет позже

    QUrl url(m_baseUrl + QStringLiteral("/v1/announcements"));
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("platform"), announcePlatform());
    q.addQueryItem(QStringLiteral("lang"), appLang());
    q.addQueryItem(QStringLiteral("app_version"), QCoreApplication::applicationVersion());
    url.setQuery(q);
    QNetworkRequest req{url};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code < 200 || code >= 300)
            return; // сеть/401 → тихо, текущий список (LKG) не трогаем
        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        if (!doc.isObject())
            return;
        QVariantList items;
        const QJsonArray arr = doc.object().value(QStringLiteral("items")).toArray();
        for (const QJsonValue &v : arr) {
            const QVariantMap item = v.toObject().toVariantMap();
            // Серверный фильтр уже исключает прочитанные ЭТИМ устройством; локальный дубль —
            // страховка от гонки «read-ack ещё не долетел, а fetch уже вернул старый список».
            if (!announcementRead(item.value(QStringLiteral("id")).toInt()))
                items.append(item);
        }
        m_announcements = items;
        persistAnnouncementsLkg();
        emit announcementsChanged();
    });
}

bool AvpnEngineQml::announcementRead(int id) const
{
    QSettings s;
    return s.value(QStringLiteral("AvpnAnnounce/read_%1").arg(id), false).toBool();
}

void AvpnEngineQml::ackAnnouncement(int id, const QString &event, const QString &buttonId)
{
    if (id <= 0)
        return;
    if (event == QLatin1String("shown")) {
        if (m_announceShownAcked.contains(id))
            return; // один shown-ack на объявление за сессию
        m_announceShownAcked.insert(id);
    }
    if (event == QLatin1String("read")) {
        // Локальный дубль серверного read_at — СИНХРОННО (движок, не QML Settings):
        // попап не должен всплыть повторно даже офлайн/до следующего fetch.
        {
            QSettings s;
            s.setValue(QStringLiteral("AvpnAnnounce/read_%1").arg(id), true);
            s.sync();
        }
        QVariantList rest;
        for (const QVariant &v : std::as_const(m_announcements))
            if (v.toMap().value(QStringLiteral("id")).toInt() != id)
                rest.append(v);
        if (rest.size() != m_announcements.size()) {
            m_announcements = rest;
            persistAnnouncementsLkg();
            emit announcementsChanged();
        }
    }

    const QString token = authToken();
    if (!m_nam || token.isEmpty())
        return; // локальный read уже сохранён; серверная квитанция догонит при следующем показе
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/announcements/%1/ack").arg(id))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    QJsonObject body{{QStringLiteral("event"), event}};
    if (!buttonId.isEmpty())
        body.insert(QStringLiteral("button_id"), buttonId);
    QNetworkReply *reply = m_nam->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater); // fire-and-forget
}

// AVPN (оплата): POST /v1/cabinet/web-link (Bearer, тело пустое) → { url: "…?wl=<token>", expires_in }.
// Тот же async-паттерн, что refreshReferral (armTimeout, без вложенного QEventLoop). Сигнал
// cabinetLinkReady эмитится на ЛЮБОМ исходе: успех → url бэка как есть (устройство вшито в wl-токен,
// бэк PR #257), провал → fallback https://tribevpn.com/account. device_uuid в URL не дописываем.
void AvpnEngineQml::requestCabinetLink(const QString &intent)
{
    // intent → query-параметр (реш. 2026-07-03): "renew" (золотая CTA) — кабинет сразу выдвигает шит
    // тарифов; пусто («Управлять подпиской») — чистый ЛК. lang = язык приложения → кабинет открывается
    // на нём же (i18n ЛК, 2026-07-07). Дописываем к ЛЮБОМУ исходу (и к fallback). Захват по значению:
    // лямбда живёт дольше вызова (async-коллбэк ниже).
    const QString lang = appLang();
    const auto withIntent = [intent, lang](const QString &url) {
        QString out = url;
        const auto add = [&out](const QString &kv) {
            out += (out.contains(QLatin1Char('?')) ? QLatin1Char('&') : QLatin1Char('?'));
            out += kv;
        };
        if (!intent.isEmpty())
            add(QStringLiteral("intent=") + QString::fromLatin1(QUrl::toPercentEncoding(intent)));
        if (!lang.isEmpty())
            add(QStringLiteral("lang=") + lang);
        return out;
    };
    // ПРИВАТНОСТЬ: URL кабинета идёт БЕЗ device_uuid — устройство вшито в сам wl-токен
    // (бэк PR #257: кабинет берёт цель авто-продления из wl-сессии), а fallback без wl
    // кабинет всё равно не аутентифицирует. Стабильный install-id в query засветился бы
    // в access-логах зря (docs/amnezia-fork/WEBLINK-DEVICE-BINDING-HANDOFF.md).
    // Домен фолбэка — cabinetUrl() (server-driven urls.cabinet через TuningStore, 0a6c1408), НЕ
    // литерал: та же канон-точка, что уже читают PageConnectTribe/PageAccountTribe напрямую.
    const QString fallback = withIntent(cabinetUrl());
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        emit cabinetLinkReady(fallback);
        return;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/cabinet/web-link"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->post(req, QByteArray());
    armTimeout(reply); // жёсткий таймаут без nested loop
    connect(reply, &QNetworkReply::finished, this, [this, reply, fallback, withIntent]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QString url = fallback;
        if (code >= 200 && code < 300) {
            WebLinkResponse wl;
            QString err;
            if (Enrollment::parseWebLinkResponse(reply->readAll(), wl, err))
                url = withIntent(wl.url);
        }
        emit cabinetLinkReady(url);
    });
}

// AVPN (Task 9 — APNs): POST /v1/devices/push-token (Bearer = subscription_token). АСИНХРОННО (как
// refreshAccount — без вложенного QEventLoop: зовётся из сигнала моста на GUI-потоке). body
// {token, platform:"ios", environment, app_version}. Нет токена подписки / сеть / таймаут → тихо
// (повторится при следующем коннекте или ротации токена). Дедуп: один POST на пару (token,env) за сессию.
void AvpnEngineQml::registerPushToken(const QString &token, const QString &environment)
{
    if (token.isEmpty())
        return;
    // Запоминаем последний токен/окружение для ПЕРЕ-регистрации после ротации subscription_token.
    m_pushToken = token;
    m_pushEnv = environment;

    const QString auth = authToken();
    if (!m_nam || auth.isEmpty())
        return; // ещё не enrolled — зарегистрируем, когда появится subscription_token (коннект/redeem)

    // Дедуп: не дёргаем бэк повторно тем же токеном+окружением под тем же subscription_token.
    const QString fingerprint = token + QLatin1Char('|') + environment + QLatin1Char('|') + auth;
    if (m_pushTokenSent == fingerprint)
        return;

    QJsonObject body;
    body.insert(QStringLiteral("token"), token);
    // Платформа из моста (deviceTokenReady); пусто = легаси-путь iOS (до FCM-волны).
    body.insert(QStringLiteral("platform"),
                m_pushPlatform.isEmpty() ? QStringLiteral("ios") : m_pushPlatform);
    if (!environment.isEmpty())
        body.insert(QStringLiteral("environment"), environment);
    const QString ver = QCoreApplication::applicationVersion();
    if (!ver.isEmpty())
        body.insert(QStringLiteral("app_version"), ver);
    // AVPN (P-ANN): язык UI — кормит таргетинг объявлений/пушей на бэке.
    if (!appLang().isEmpty())
        body.insert(QStringLiteral("lang"), appLang());

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/devices/push-token"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());

    QNetworkReply *reply = m_nam->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    armTimeout(reply); // жёсткий таймаут без nested loop
    connect(reply, &QNetworkReply::finished, this, [this, reply, fingerprint]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300)
            m_pushTokenSent = fingerprint; // успех → больше не дублируем
        // 401/сеть/таймаут → НЕ помечаем отправленным: повторим при ротации/реконнекте. Тихо (фоновая
        // best-effort регистрация не должна показывать пользователю ошибку).
    });
}

// DEV TOOL (TEMPORARY — remove with backend routers/devtools.py): POST /v1/dev/reset-trial
// (Bearer = subscription_token, пустое тело). Заводской сброс триала ЭТОГО аккаунта; при успехе
// перечитываем account+подписку, чтобы шапка (дни/трафик) обновилась. 404 = флаг выключен на сервере.
// Изолировано: один метод + один пункт в настройках; удаляется вместе с бэкенд-роутером devtools.
void AvpnEngineQml::resetTrialDev()
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty()) {
        emit error(tr("Сначала войдите или подключитесь"));
        return;
    }
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/dev/reset-trial"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());

    QNetworkReply *reply = m_nam->post(req, QByteArrayLiteral("{}"));
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300) {
            refreshAccount(); // обновить property account (дни/трафик)
            // AVPN (фикс ревью 2026-07-07): фасадный bootstrap() идемпотентен (m_bootstrapped
            // после первого успеха) — прямой вызов был вечным no-op, бейдж после сброса не
            // обновлялся. Принудительно перезапускаем async-цепочку под новым состоянием бэка.
            m_bootstrapped = false;
            m_bootstrapInFlight = false;
            m_bootstrapRetryTimer.stop();
            bootstrap();      // перечитать подписку (async-цепочка)
            emit changed();
        } else if (code == 404) {
            emit error(tr("Сброс триала выключен на сервере"));
        } else {
            emit error(tr("Не удалось сбросить триал (код %1)").arg(code));
        }
    });
}

// AVPN (Task 9 — APNs): флаш отложенного push-токена после появления subscription_token. Закрывает
// гэп первичного авто-enroll: device token пришёл из APNs ДО enroll (registerPushToken запомнил
// m_pushToken, но не отправил, т.к. authToken был пуст). После успешного bootstrap/enroll subscription_token
// уже есть → отправляем. Дедуп по fingerprint (token|env|auth) защищает от лишнего POST, если токен
// уже ушёл по redeem-пути. No-op при пустом push-токене (desktop / разрешение не выдано).
void AvpnEngineQml::flushPendingPushToken()
{
    if (m_pushToken.isEmpty())
        return;
    registerPushToken(m_pushToken, m_pushEnv);
}

// AVPN (Task 9 — APNs): POST /v1/notifications/read (Bearer) — обнулить серверный счётчик непрочитанных.
// Без тела. АСИНХРОННО, тихо (фоновое действие). Вызывается по AvpnPushBridge::readRequested
// (QML: AvpnPush.markAllRead()). Локальный бейдж иконки уже снят натив-clearer'ом в мосте.
void AvpnEngineQml::markNotificationsRead()
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty())
        return;

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/notifications/read"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());

    QNetworkReply *reply = m_nam->post(req, QByteArray());
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [reply]() { reply->deleteLater(); });
}

// AVPN (read per-элемент): POST /v1/notifications/read {"ids":[id],"read":read} — read-статус
// ОДНОГО уведомления в обе стороны (бэк пересчитывает unread_count по остатку). Вызывается по
// readItemRequested моста (деталь открыта / свайп-тоггл). АСИНХРОННО, тихо: офлайн-провал не
// страшен — локальный флаг уже сохранён, серверный догонит следующий mark.
void AvpnEngineQml::markNotificationReadById(qlonglong id, bool read)
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty() || id <= 0)
        return;

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/notifications/read"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    const QByteArray body = QJsonDocument(QJsonObject{
        {QStringLiteral("ids"), QJsonArray{static_cast<double>(id)}},
        {QStringLiteral("read"), read}}).toJson(QJsonDocument::Compact);
    QNetworkReply *reply = m_nam->post(req, body);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [reply]() { reply->deleteLater(); });
}

// AVPN (свайп «Удалить»): POST /v1/notifications/delete {"ids":[id]} — удалить строку на бэке
// (unread_count пересчитает бэк). АСИНХРОННО, тихо; локально элемент уже убран мостом.
void AvpnEngineQml::deleteNotificationById(qlonglong id)
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty() || id <= 0)
        return;

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/notifications/delete"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    const QByteArray body = QJsonDocument(QJsonObject{
        {QStringLiteral("ids"), QJsonArray{static_cast<double>(id)}}}).toJson(QJsonDocument::Compact);
    QNetworkReply *reply = m_nam->post(req, body);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [reply]() { reply->deleteLater(); });
}

// AVPN (центр уведомлений, серверная история): GET /v1/notifications?limit=50 → мост setServerItems.
// См. коммент в .h (фикс «строка в БД есть, центр пуст» — история доезжает и без доставленного пуша).
void AvpnEngineQml::refreshNotifications()
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty())
        return; // не enrolled — серверной истории всё равно нет; локальная лента остаётся
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/notifications?limit=50"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code < 200 || code >= 300)
            return; // офлайн/401 → локальная лента живёт, ничего не затираем
        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        if (!doc.isArray())
            return;
        QVariantList items;
        for (const QJsonValue &v : doc.array()) {
            const QJsonObject o = v.toObject();
            const QString title = o.value(QStringLiteral("title")).toString();
            const QString body = o.value(QStringLiteral("body")).toString();
            if (title.isEmpty() && body.isEmpty())
                continue;
            QVariantMap item;
            // Серверный id строки — ключ поэлементного mark-read (markItemRead в мосте).
            item[QStringLiteral("id")] = static_cast<qlonglong>(o.value(QStringLiteral("id")).toDouble());
            item[QStringLiteral("title")] = title;
            item[QStringLiteral("body")] = body;
            // Эталон 2026-07-12: сегодня/вчера — HH:mm, раньше — «10 июл»; плюс секция-группа
            // (Сегодня/Вчера/Ранее) и полная дата для детальной страницы.
            const QDateTime dt = QDateTime::fromString(o.value(QStringLiteral("created_at")).toString(),
                                                       Qt::ISODate).toLocalTime();
            const QDate today = QDate::currentDate();
            const QLocale loc;
            if (!dt.isValid()) {
                item[QStringLiteral("time")] = QString();
                item[QStringLiteral("group")] = QStringLiteral("earlier");
                item[QStringLiteral("dateFull")] = QString();
            } else if (dt.date() == today) {
                item[QStringLiteral("time")] = dt.toString(QStringLiteral("HH:mm"));
                item[QStringLiteral("group")] = QStringLiteral("today");
                item[QStringLiteral("dateFull")] =
                    tr("Сегодня в %1").arg(dt.toString(QStringLiteral("HH:mm")));
            } else if (dt.date() == today.addDays(-1)) {
                item[QStringLiteral("time")] = dt.toString(QStringLiteral("HH:mm"));
                item[QStringLiteral("group")] = QStringLiteral("yesterday");
                item[QStringLiteral("dateFull")] =
                    tr("Вчера в %1").arg(dt.toString(QStringLiteral("HH:mm")));
            } else {
                item[QStringLiteral("time")] = loc.toString(dt.date(), QStringLiteral("d MMM"));
                item[QStringLiteral("group")] = QStringLiteral("earlier");
                item[QStringLiteral("dateFull")] =
                    tr("%1 в %2").arg(loc.toString(dt.date(), QStringLiteral("d MMMM")),
                                      dt.toString(QStringLiteral("HH:mm")));
            }
            item[QStringLiteral("read")] = o.value(QStringLiteral("read")).toBool();
            // Контракт NotificationOut: неизвестный тип = generic-строка title+body, НЕ скрывать
            // (делегат QML стилизует только известные kind, остальным даёт общий вид).
            const QString type = o.value(QStringLiteral("type")).toString();
            item[QStringLiteral("type")] = type.isEmpty() ? QStringLiteral("generic") : type;
            item[QStringLiteral("days")] = static_cast<int>(o.value(QStringLiteral("days")).toDouble());
            items.append(item);
        }
        avpn::AvpnPushBridge::instance()->setServerItems(items);
    });
}

QVariantMap AvpnEngineQml::debugSnapshot() const
{
    const DebugSnapshot s = m_engine.debugSnapshot();
    QVariantMap m;
    m["state"] = s.state;
    m["currentNodeId"] = s.currentNodeId;
    m["latestHandshakeAgeSec"] = static_cast<qlonglong>(s.latestHandshakeAgeSec);
    m["rxBytes"] = static_cast<qlonglong>(s.rxBytes);
    m["txBytes"] = static_cast<qlonglong>(s.txBytes);
    m["subStatus"] = s.subStatus;
    m["lkgStale"] = s.lkgStale;
    m["trafficUsed"] = static_cast<qlonglong>(s.trafficUsed);
    m["trafficLimit"] = static_cast<qlonglong>(s.trafficLimit);
    m["expiresAt"] = s.expiresAt; // AVPN: для daysLeft()
    // AVPN awg31-xray-v1: транспорт текущей ноды / ручной режим / фаза verifying / ревизия пула.
    m["activeProto"] = s.activeProto;
    m["transportMode"] = s.transportMode;
    m["verifying"] = s.verifying;
    m["poolRevision"] = static_cast<qlonglong>(s.poolRevision);
    m["rttCacheAgeMs"] = m_engine.measuredRttAgeMs();
    m["rttCandidateIds"] = m_engine.measuredRtt().keys();
    // AVPN (фикс-волна 2026-09-22, A1/A11): латч подтверждения и источник последнего авто-выбора.
    m["awaitingStopConfirm"] = m_latch.awaitingStopConfirm;
    m["needStatusBeforeStart"] = m_latch.needStatusBeforeStart;
    m["stopRetries"] = m_stopRetries;
    m["permissionPromptPending"] = m_permissionPromptPending;
    m["liveSessionPending"] = m_liveSessionPending;
    m["lastSelectionMeasured"] = m_lastSelectionMeasured;
    m["reseedPending"] = s.reseedPending;

    QVariantList pool;
    for (const NodeDebugRow &r : s.pool) {
        QVariantMap n;
        n["nodeId"] = r.nodeId;
        n["region"] = r.region;
        n["name"] = r.name;                                          // AVPN: имя сервера (опц.)
        n["countryCode"] = r.countryCode;                            // AVPN: ISO-3166 alpha-2 → флаг-эмодзи

        n["endpoint"] = r.endpoint;                                   // AVPN: реальный host:port
        n["ip"] = r.endpoint.section(QLatin1Char(':'), 0, 0);         // AVPN: только host для показа
        n["scoreMs"] = r.scoreMs;
        n["healthy"] = r.healthy;
        // AVPN (live-node picker): обогащённые поля для шторки выбора сервера (weight/health/alive/current).
        n["weight"] = r.weight;
        n["health"] = r.healthAgg;  // 0..1 агрегат backend-health → 0..4 бара в UI
        n["alive"] = r.alive;       // жив по backend-данным (фильтр «только живые» в шторке)
        n["current"] = r.current;   // == текущая нода → акцент #7CA2D0 + галка
        n["reason"] = r.reason;
        // AVPN (Task 10 финал): протокол ноды — QML-пикер и админ-свип скипают неподдерживаемые
        // (xray, ...): коннект к ним невозможен, тап/свип упирался бы в сторожа. Пусто = awg.
        n["proto"] = r.proto;
        n["protoVersion"] = r.protoVersion; // AVPN AWG 3.0/3.1: "1"/"2"/"3"/"3.1" → метка «Amnezia vN» в пикере; xray — пусто
        n["manualOnly"] = r.manualOnly; // AVPN (Доктор): manual/RU скипаются в авто-очередях
        // AVPN awg31-xray-v1 (§2.3, пикер «локации × транспорты»): группировка строк по location
        // (host_id, фолбэк country_code+region), бейджи транспортов локации (transports: порядок =
        // transport_rank), активный транспорт локации (activeProto = proto текущей ноды, если она из
        // этой локации), серверный ранг ноды и поддерживается ли её proto этим клиентом
        // (transportSupported=false → строка серая «недоступно в этой версии»).
        n["hostId"] = r.hostId;
        n["location"] = r.location;
        n["transports"] = r.transports;
        n["activeProto"] = r.activeProto;
        n["transportRank"] = r.transportRank;
        n["transportSupported"] = r.transportSupported;
        // AVPN upstream nodes (point 16): roles for the UI lane - a provider profile row and its tier.
        n["upstream"] = r.upstream;
        n["upstreamTier"] = r.upstreamTier;
        n["packSourced"] = r.packSourced;
        n["upstreamOrdinal"] = r.upstreamOrdinal;
        n["upstreamLabelCustom"] = r.upstreamLabelCustom;
        // contract 1.10.0: "country" | "whitelist" | "auto" ("" for own rows); auto is never a list row
        n["upstreamKind"] = QString::fromLatin1(avpn::upstreamKindName(r.upstreamKind));
        pool.append(n);
    }
    m["pool"] = pool;
    // AVPN upstream nodes: the lease owner's status (contract §5) and the standby pack - debug only.
    {
        QVariantMap up = m_tunnel.upstreamStatus().toVariantMap();
        up["node"] = m_tunnel.upstreamNodeId();
        up["standbyEntries"] = m_standbyEntries;
        up["standbyAgeMin"] = m_standbyFetchedWallMs > 0
            ? int((QDateTime::currentMSecsSinceEpoch() - m_standbyFetchedWallMs) / 60000) : -1;
        up["standbyNet"] = m_standbyNetKey;
        m["upstream"] = up;
    }

    QVariantList log;
    for (const QString &l : s.switchLog)
        log.append(l);
    m["switchLog"] = log;
    return m;
}

// AVPN (diag-report, Task 4 bff-3): полный диагностический отчёт — юзер отправляет его в чат
// поддержки. Снапшот движка (уже обогащён RTT-кэшем/proto/grace в ServiceEngine::debugSnapshot) +
// версия серверных bypass-списков (движок BypassListService не знает — сеем здесь) + bypassMasterOn
// (QSettings в QML-домене, как applyRuBypassSplit) + хвост лога приложения. Сборка/кламп — в
// header-only TribeDiagReport (покрыт tests/test_diag_report.cpp).
QString AvpnEngineQml::buildDiagReport() const
{
    avpn::DebugSnapshot s = m_engine.debugSnapshot();
    if (m_bypassListSvc)
        s.bypassListVersion = m_bypassListSvc->lkgVersion();

    avpn::DiagMeta meta;
    meta.appVersion = QCoreApplication::applicationVersion(); // tribe_version — как в bench-отчёте (benchExtra)
    meta.platform = QSysInfo::productType() + QLatin1Char(' ') + QSysInfo::productVersion();
    meta.lang = appLang();
    meta.configAppliedAgeSec = (m_lastConfigAppliedEpoch > 0)
        ? (QDateTime::currentSecsSinceEpoch() - m_lastConfigAppliedEpoch)
        : -1; // конфиг ещё не применялся → ключ опускается

    const bool bypassOn =
        QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    const QString logTail = avpn::TribeDiagReport::readLogTail(Logger::userLogsFilePath());
    QString report = avpn::TribeDiagReport::build(s, bypassOn, logTail, meta)
        + QStringLiteral("\n[reliability transitions]\n") + m_reliabilityRing.lines.join(QLatin1Char('\n'));
#ifdef Q_OS_IOS
    report += QStringLiteral("\n[native lifecycle]\n") + Avpn_lifecycleLogTail();
#endif
    return report;
}

// ── AVPN in-app Legal (Privacy/Terms) ────────────────────────────────────────
// PageLegalTribe: qrc-снапшот → legalDocCached() поверх → legalDocFetch() тихо
// обновляет. Кэш: AppDataLocation/legal/<doc>.<lang>.md. Ошибки сети молчаливые.

static QString legalCacheDir()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + QStringLiteral("/legal");
}

QString AvpnEngineQml::legalDocCached(const QString &doc, const QString &lang) const
{
    if (!LegalDocs::isValidDoc(doc) || !LegalDocs::isValidLang(lang))
        return {};
    // 1) дисковый кэш прошлого fetch; 2) qrc-снапшот из сборки. Читаем здесь, а не XHR
    // из QML: XMLHttpRequest к file:/qrc: по умолчанию ЗАПРЕЩЁН (QML_XHR_ALLOW_FILE_READ),
    // в проде qrc-фоллбек обязан работать без env-хаков.
    const QString name = LegalDocs::cacheFileName(doc, lang);
    for (const QString &path : { legalCacheDir() + QLatin1Char('/') + name,
                                 QStringLiteral(":/ui/qml/Tribe/legal/") + name }) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly))
            continue;
        const QByteArray body = f.readAll();
        if (LegalDocs::looksLikeMarkdown(body))
            return QString::fromUtf8(body);
    }
    return {};
}

void AvpnEngineQml::legalDocFetch(const QString &doc, const QString &lang)
{
    if (!m_nam || !LegalDocs::isValidDoc(doc) || !LegalDocs::isValidLang(lang))
        return;
    // без дедупа запросов: страница дёргает fetch один раз на открытие, ответы идемпотентны
    QNetworkRequest req{QUrl(LegalDocs::url(doc, lang, configUrl(QStringLiteral("legal_base"), QStringLiteral("https://tribevpn.com/legal"))))};
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply); // жёсткий таймаут без nested loop (abort → finished с code==0)
    connect(reply, &QNetworkReply::finished, this, [this, reply, doc, lang]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code != 200)
            return; // тихо: остаёмся на кэше/снапшоте
        const QByteArray body = reply->readAll();
        if (!LegalDocs::looksLikeMarkdown(body))
            return; // captive portal / страница ошибки — кэш не портим
        QDir().mkpath(legalCacheDir());
        QSaveFile f(legalCacheDir() + QLatin1Char('/') + LegalDocs::cacheFileName(doc, lang));
        if (f.open(QIODevice::WriteOnly)) {
            f.write(body);
            f.commit();
        }
        emit legalDocReady(doc, lang, QString::fromUtf8(body));
    });
}

// ── AVPN (Доктор v1, 2026-07-17): пользовательская диагностика ─────────────────────────────
// Канон машин (enum+epoch+guard) + дирижёр поверх готовых блоков: rx/tx-дельты снапшота,
// off-tunnel RTT (probeNodeRtt/кеш m_nodeRtt), reach-кворум + cdn-cgi/trace (только loc,
// IP отброшен), вердикт WhitelistDetector, lite-бенч. Вердикты стадий — чистый DoctorReport.h
// (юнит tests/doctor_report_check.cpp). Спека: specs/2026-07-17-doctor-v1-design.md.

void AvpnEngineQml::startDoctor(bool full)
{
    if (doctorRunning())
        return;
    if (!featureEnabled(QStringLiteral("diag_v2"), true))
        return; // kill-switch: бэк может выключить фичу без релиза
    // взаимоисключение с бенч-машинами: доктор делит BenchRunner и туннельные переходы
    if (m_benchRunning || sweepRunning() || abRunning() || ccRunning() || ftRunning())
        return;
    // Plan v3 step 5: the Doctor trims (services end with the probe series, no speed test without a
    // working connection) are part of features.node_scan; off = the previous Doctor, unchanged.
    docBeginRun(full && featureEnabled(QStringLiteral("doctor_full"), true), featureEnabled(QStringLiteral("node_scan"), false));
    docStartNetwork();
}

// The run state of one Doctor run (startDoctor; AVPN Scanner: the report check shares it).
void AvpnEngineQml::docBeginRun(bool full, bool nodeScan)
{
    ++m_docEpoch;
    m_docFull = full;
    m_docNodeScan = nodeScan;
    m_docStages.clear();
    m_docReport = QJsonObject();
    m_docBenchFull = QJsonObject();
    m_docSummary.clear();
    m_docBenchStarted = false;
    m_docConnecting = false;
    m_docWasConnected = (state() == QLatin1String("connected"));
    // D-3: сброс партиалов новых стадий
    m_docNetCaptive = -1;
    m_docNetWl = -1;
    m_docNetPending = 0;
    m_docTunIcmpMs = -1;
    m_docEpMs = -1; m_docEpBig = -1; m_docEpTried = false;          // D-6
    m_docAltEpMs = -1; m_docAltEpBig = -1; m_docAltEpTried = false; // D-6
    m_docSpeedDown = -1;
    m_docSpeedIdle = 0;
    m_docSpeedLoaded = 0;
    m_docSpeedCollapsed = false;
    CrashGuard::instance().setPhase("doctor");
}

// D-3: стадия 0 — сеть клиента ДО подъёма туннеля. Captive + сигналы платформы + форс-прогон
// дифф-проб белых списков. При уже поднятом туннеле captive/whitelist не валидны (пробы пойдут
// через VPN) — честные "-1", собираем только сигналы.
void AvpnEngineQml::docStartNetwork()
{
    docEnter(DoctorPhase::Network);
    const bool tunnelUp = m_docWasConnected;
    if (!tunnelUp) {
        // captive-детект: generate_204 МИМО туннеля; редирект/200 = портал подменяет ответы
        ++m_docNetPending;
        QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
        req.setTransferTimeout(5000);
        req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        QNetworkReply *rep = m_nam->head(req);
        connect(rep, &QNetworkReply::finished, this, [this, rep, e = m_docEpoch] {
            rep->deleteLater();
            if (e != m_docEpoch || m_docPhase != DoctorPhase::Network) return;
            const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (code == 204)                    m_docNetCaptive = 0;
            else if (code >= 200 && code < 400) m_docNetCaptive = 1; // портал перехватил
            // сетевой фейл -> остаётся -1: «нет сети» != captive (не врём)
            docNetMaybeDone();
        });
        // форс-раунд белых списков (только мобилки+сотовая+опущенный туннель — гейты внутри)
        if (m_whitelistDetector) {
            const bool started = m_whitelistDetector->runRoundNow(
                [this, e = m_docEpoch](WlVerdict v, bool /*marginal*/) {
                    if (e != m_docEpoch || m_docPhase != DoctorPhase::Network) return;
                    m_docNetWl = (v == WlVerdict::Candidate) ? 1
                               : (v == WlVerdict::Normal || v == WlVerdict::SocialOnly) ? 0 : -1;
                    docNetMaybeDone();
                });
            if (started)
                ++m_docNetPending;
        }
    }
    if (m_docNetPending == 0)
        docNetMaybeDone();
}

int AvpnEngineQml::detectLanIpv6() const
{
    // Kill-switch: бэкенд может убрать фразу про IPv6 из Доктора без релиза.
    if (!avpn::TuningStore::flag(QStringLiteral("ipv6_notice"), true))
        return -1;

    QList<QPair<QString, QString>> snapshot;
    const auto ifaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface &iface : ifaces) {
        const auto flags = iface.flags();
        // Погашенный или loopback-интерфейс — не «сеть пользователя».
        if (!flags.testFlag(QNetworkInterface::IsUp)
            || !flags.testFlag(QNetworkInterface::IsRunning)
            || flags.testFlag(QNetworkInterface::IsLoopBack))
            continue;
        const auto entries = iface.addressEntries();
        for (const QNetworkAddressEntry &entry : entries)
            snapshot.append({iface.name(), entry.ip().toString()});
    }
    return avpn::hasOffTunnelGlobalV6(snapshot);
}

void AvpnEngineQml::docNetMaybeDone()
{
    if (m_docNetPending > 0 && --m_docNetPending > 0)
        return; // ждём вторую параллельную пробу
    const QJsonObject extra = benchExtra();
    const QString netType = extra.value(QStringLiteral("net_type")).toString();
    docStageDone(doctor::networkStage(
        m_docNetCaptive, netType,
        avpn::cellularGenerationForKind(netType, avpn::cellularGeneration()), avpn::meteredState(), avpn::roamingState(), m_docNetWl,
        extra.value(QStringLiteral("carrier")).toString(), detectLanIpv6()));
}

void AvpnEngineQml::docStartConnect()
{
    docEnter(DoctorPhase::Connect);
    if (m_scanCheck.active && !m_docWasConnected) {
        // AVPN Scanner (§32 п. 1): the Scanner's check never raises the VPN - with it off the stage is skipped.
        docStageDone(doctor::connectStageNoVpn());
        return;
    }
    if (m_docWasConnected) {
        // VPN уже поднят — сразу проверяем, идут ли данные через туннель. Сторож ОБЯЗАТЕЛЕН:
        // у QNetworkReply нет таймаута общей длительности (урок NetAwait.h), а docEnter для
        // Connect guard не ставит — без него зависшая проба вешала Доктора навсегда (ревью v2 #1).
        m_docRx0 = m_tunnel.readStats().rxBytes;
        m_docGuard.start(15000);
        QTimer::singleShot(300, this, [this, e = m_docEpoch] {
            if (e == m_docEpoch && m_docPhase == DoctorPhase::Connect) docVerifyDataplane();
        });
    } else {
        // АКТИВНО: поднимаем VPN (авто-выбор лучшего по measuredRtt внутри start) и ждём connected
        m_docConnecting = true;
        m_docSawProgress = false;
        start();
        // сторож фазы Connect отдельный — подъём может занять дольше стандартной стадии
        m_docGuard.start(45000);
        // вдруг уже перескочило в connected до подписки — толкнём проверку
        QTimer::singleShot(0, this, [this, e = m_docEpoch] {
            if (e == m_docEpoch && m_docConnecting) docConnectAdvance();
        });
    }
}

// AVPN (фикс-волна 2026-09-22, A6): Доктор возвращает исходный выбор, pin — только в памяти.
// Исходно был pin → вернуть его. Исходно был авто → снять pin (семантика selectAuto «pin снят»),
// но, в отличие от selectAuto, намерение НЕ снимаем: selectAuto гасит VPN (намерение OFF), а
// Доктор запускали на поднятом VPN — по окончании он не должен «сам выключаться» (жалоба 2).
// Туннель уже на исходной ноде — только снять pin; на альтернативе — переподнять авто-выбором.
void AvpnEngineQml::docRestoreSelection()
{
    // Разбор журнала 26.09 (устр. 64, 11:53 МСК): после неудачной последней альтернативы туннель
    // лежал (его остановил сам Доктор), и возврат по правилу пикера снимал намерение — VPN оставался
    // выключенным, хотя был включён до Доктора. Теперь держим состояние со старта Доктора.
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    const bool up = avpn::isTunnelUpStateName(st);
    const bool keep = doctor::restoreKeepsConnected(m_docWasConnected, up);
    reliabilityEvent(QStringLiteral("doctor_restore was_connected=%1 up=%2 keep=%3 orig_pin=%4")
                         .arg(m_docWasConnected).arg(up).arg(keep).arg(!m_docOrigPin.isEmpty()));
    if (!m_docOrigPin.isEmpty()) {
        pinAndReconnectImpl(m_docOrigPin, pinOriginPersists(PinOrigin::Doctor), /*forceConnect=*/keep,
                            StartOrigin::Doctor);
        return;
    }
    m_engine.clearPin();
    m_startOrigin = StartOrigin::Doctor; // plan v3 step 5: the restore is not a user start
    const bool movedAway = !m_docOrigNode.isEmpty() && m_engine.currentNodeId() != m_docOrigNode;
    if (up && movedAway) {
        m_wantConnected = true;
        m_needsRestart = true; // reconcile: stop→Disconnected→start на авто-выборе
        m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch(); // волна-4 (P1-6)
        m_restartOrigin = QStringLiteral("doctor_restore");
    } else if (!up && keep) {
        m_wantConnected = true; // туннель лежит после альтернатив — просто поднять на авто-выборе
        m_needsRestart = false;
    }
    emit changed();
    reconcile();
}

void AvpnEngineQml::cancelDoctor()
{
    if (!doctorRunning())
        return;
    if (m_scanCheck.active) {
        // AVPN Scanner: the report is always sent (REQ S8) - an interrupted check sends what it has.
        if (m_scanCheck.submitted)
            return;
        ++m_docEpoch;
        m_docGuard.stop();
        m_docConnecting = false;
        if (m_docBenchStarted) {
            m_bench->cancel();
            m_docBenchStarted = false;
            m_benchRunning = false;
            emit benchChanged();
        }
        scanCheckSubmit();
        return;
    }
    ++m_docEpoch; // стейл-колбэки всех стадий отбрасываются
    m_docGuard.stop();
    // отмена посреди перебора альтернатив — вернуть исходный выбор (fire-and-forget)
    if (m_docPhase == DoctorPhase::AltNodes)
        docRestoreSelection();
    m_docConnecting = false;
    if (m_docBenchStarted) {
        m_bench->cancel(); // после cancel сигналов НЕ будет — флаг бенча гасим сами
        m_docBenchStarted = false;
        m_benchRunning = false;
        emit benchChanged();
    }
    m_docPhase = DoctorPhase::Idle;
    CrashGuard::instance().setPhase(state() == QLatin1String("connected") ? "connected" : "idle");
    emit doctorChanged();
}

void AvpnEngineQml::docEnter(DoctorPhase ph)
{
    m_docPhase = ph;
    // базовый процент стадии (Speed дотикивает по benchStageFrac в проводке конструктора)
    switch (ph) {
    case DoctorPhase::Network:  m_docPercent = 3;  break;
    case DoctorPhase::Connect:  m_docPercent = 8;  break;
    case DoctorPhase::Servers:  m_docPercent = 36; break;
    case DoctorPhase::Services: m_docPercent = 46; break;
    case DoctorPhase::RuSplit:  m_docPercent = 58; break;
    case DoctorPhase::Speed:    m_docPercent = 66; break;
    case DoctorPhase::AltNodes: m_docPercent = 88; break;
    case DoctorPhase::Send:     m_docPercent = 97; break;
    case DoctorPhase::Idle:     break;
    }
    // сторож: server-tunable с клампом. Бенч-стадии нужен свой запас — numbers.doctor_speed_guard_ms
    // (жалоба владельца «иногда скорость проверяется очень долго»: было 60с намертво, теперь 45с
    // по умолчанию и рычаг у бэка). Фазы Connect и AltNodes ведут сторожа сами — НЕ перетираем.
    if (ph != DoctorPhase::Connect && ph != DoctorPhase::AltNodes) {
        const int base = doctor::clampStageTimeoutMs(
            TuningStore::numberOr(QStringLiteral("diag_stage_timeout_ms"), 0));
        const int spd = qBound(20000, int(TuningStore::numberOr(
                                   QStringLiteral("doctor_speed_guard_ms"), 45000.0)), 90000);
        m_docGuard.start(ph == DoctorPhase::Speed ? spd : base);
    }
    emit doctorChanged();
}

void AvpnEngineQml::docConnectAdvance()
{
    if (!m_docConnecting)
        return;
    // AltNodes: ждём подъёма на альтернативе (после pinAndReconnect)
    if (m_docPhase == DoctorPhase::AltNodes) {
        const QString st = state();
        if (st == QLatin1String("connected")) {
            m_docConnecting = false;
            m_docAltUp = true;
            m_docAltRx0 = m_tunnel.readStats().rxBytes; // база для «данные идут» (рост rx)
            m_docAltProbe1 = false; m_docAltIcmpMs = -1; m_docAltHsSec = -1;
            m_docAltEpMs = -1; m_docAltEpBig = -1; m_docAltEpTried = false; // D-6
            // сторож накрывает обе пробы: 800мс прогрев + проба1 + re-probe-гэп + проба2
            const int gap = qBound(3000, int(avpn::TuningStore::numberOr(
                                       QStringLiteral("doctor_alt_reprobe_ms"), 12000.0)), 30000);
            m_docGuard.start(gap + 16000);
            QTimer::singleShot(800, this, [this, e = m_docEpoch] {
                if (e == m_docEpoch && m_docPhase == DoctorPhase::AltNodes) docAltVerify();
            });
        } else if (st == QLatin1String("error")
                   || (st == QLatin1String("disconnected") && m_docSawProgress)) {
            m_docConnecting = false;
            m_docGuard.stop();
            m_docAltProbe1 = false; // альтернатива не поднялась — обе пробы «мимо»
            docAltRecord(/*probe2=*/false);
        } else if (st != QLatin1String("disconnected")) {
            m_docSawProgress = true;
        }
        return;
    }
    if (m_docPhase != DoctorPhase::Connect)
        return;
    const QString st = state();
    if (st == QLatin1String("connected")) {
        m_docConnecting = false;
        m_docRx0 = m_tunnel.readStats().rxBytes;
        // сторож ПЕРЕВЗВОДИМ на пробу данных (не гасим: зависший reply без него вешал бы фазу)
        m_docGuard.start(15000);
        // дать data-plane секунду прогреться перед пробой
        QTimer::singleShot(1000, this, [this, e = m_docEpoch] {
            if (e == m_docEpoch && m_docPhase == DoctorPhase::Connect) docVerifyDataplane();
        });
    } else if (st == QLatin1String("error")
               || (st == QLatin1String("disconnected") && m_docSawProgress)) {
        // error — коннект не удался; disconnected ПОСЛЕ начала подъёма — туннель остановили
        // извне (виджет/App Intent/grace-энфорс): честный вердикт сразу, не ждать 45с сторожа
        // (ревью v2 #3). Стартовый disconnected (start() ещё не перевёл машину) — НЕ провал.
        m_docConnecting = false;
        m_docGuard.stop();
        docStageDone(doctor::connectStage(/*couldConnect=*/false, false, -1));
    } else if (st != QLatin1String("disconnected")) {
        m_docSawProgress = true; // connecting/switching/selecting — подъём реально начался
    }
}

// D-6 (блок-профиль эндпоинта): запуск проб до IP ТЕКУЩЕЙ ноды МИМО туннеля — host-route WG
// выводит пакеты к эндпоинту в физический интерфейс даже при full-tunnel. Вместе с handshake/rx
// стадии различает ПРИЧИНУ смерти ноды у оператора: IP-блэкхол (echo мимо) vs фильтр по размеру
// пакета (маленький ок, большой DF-echo ~1400Б дропнут — профиль ТСПУ/DPI) vs верхние слои
// (оба ок, а 204 мимо). Возвращает IP для цели "ep" в общий probeAll вызывающего (пусто = не
// пробуем); большой echo уходит тут же отдельным сокетом (probeMtuOne самодостаточна, состояние
// probeAll не трогает). bigSink(ok) зовётся ТОЛЬКО для IPv4-литерала (probeMtuOne не резолвит
// хосты; не звался = «не мерили», не ложное «дропнут»). false при payload>MTU интерфейса =
// локальный EMSGSIZE — тоже честное «не проходит» (дефолт 1372+28=1400 < реальных MTU).
// Гейт features.doctor_ep_probe; размер — numbers.doctor_ep_big_payload (REMOTE-TUNING §1).
QString AvpnEngineQml::docEpProbeStart(std::function<void(bool)> bigSink)
{
    if (!m_docPing || !featureEnabled(QStringLiteral("doctor_ep_probe"), true))
        return QString();
    const QString epIp = currentNodeEndpointIp(currentNode());
    if (epIp.isEmpty())
        return QString();
    const QHostAddress lit(epIp);
    if (!lit.isNull() && lit.protocol() == QAbstractSocket::IPv4Protocol) {
        const int payload = qBound(200, int(avpn::TuningStore::numberOr(
                                       QStringLiteral("doctor_ep_big_payload"), 1372.0)), 1400);
        m_docPing->probeMtuOne(epIp, payload, 4000, std::move(bigSink));
    }
    return epIp;
}

void AvpnEngineQml::docVerifyDataplane()
{
    // проба generate_204 ЧЕРЕЗ туннель: первый байт получен ⇒ данные идут; параллельно смотрим
    // рост rx (сигнатура S4-blackhole: handshake есть, но rx стоит).
    const qint64 hsAge = debugSnapshot().value(QStringLiteral("latestHandshakeAgeSec")).toLongLong();
    // D-3 п.3: ICMP к 1.1.1.1 ЧЕРЕЗ туннель (default-route) — fire-and-collect, отдельный
    // инстанс (m_rttProbe гейтится connected⇒cancel). L3-жив != L7-жив: различает «туннель
    // доводит пакеты» от «HTTPS зарезан за нодой». Windows — стаб, результат просто не пишется.
    m_docTunIcmpMs = -1;
    m_docEpMs = -1; m_docEpBig = -1;
    const QString epIp = docEpProbeStart([this, e = m_docEpoch](bool ok) {
        if (e == m_docEpoch) m_docEpBig = ok ? 1 : 0;
    });
    m_docEpTried = !epIp.isEmpty();
    if (m_docPing) {
        QList<avpn::RttTarget> targets{{QStringLiteral("tunnel"), QStringLiteral("1.1.1.1"), 0}};
        if (!epIp.isEmpty())
            targets.append({QStringLiteral("ep"), epIp, 0});
        m_docPing->probeAll(targets, 3000,
            [this, e = m_docEpoch](const QString &id, int rttMs) {
                if (e != m_docEpoch || rttMs < 0) return;
                if (id == QLatin1String("ep")) {
                    if (m_docEpMs < 0 || rttMs < m_docEpMs) m_docEpMs = rttMs;
                } else if (m_docTunIcmpMs < 0 || rttMs < m_docTunIcmpMs) {
                    m_docTunIcmpMs = rttMs;
                }
            },
            [] {});
    }
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(6000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep, hsAge, e = m_docEpoch] {
        rep->deleteLater();
        if (e != m_docEpoch || m_docPhase != DoctorPhase::Connect) return;
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool httpOk = rep->error() == QNetworkReply::NoError && code > 0;
        const qint64 rxNow = m_tunnel.readStats().rxBytes;
        const bool rxGrew = rxNow > m_docRx0;
        doctor::StageResult r = doctor::connectStage(/*couldConnect=*/true, httpOk || rxGrew, hsAge);
        if (m_docTunIcmpMs >= 0)
            r.data.insert(QStringLiteral("tunnel_icmp_ms"), m_docTunIcmpMs);
        if (m_docEpTried) { // D-6: блок-профиль эндпоинта текущей ноды (docEpProbeStart)
            r.data.insert(QStringLiteral("ep_icmp_ms"), m_docEpMs); // -1 = IP молчит мимо туннеля
            if (m_docEpBig != -1)
                r.data.insert(QStringLiteral("ep_icmp_big"), m_docEpBig == 1);
        }
        docStageDone(r);
    });
}

void AvpnEngineQml::docStageDone(const doctor::StageResult &r)
{
    m_docGuard.stop();
    m_docStages.append(r);
    // Журнал тестирования: стадия Доктора с сырыми фактами (метод, цели, RTT, вердикт).
    avpn::TribeJournal::append(QStringLiteral("doctor_stage"),
                               {{QStringLiteral("id"), r.id},
                                {QStringLiteral("status"), r.status},
                                {QStringLiteral("note"), r.note},
                                {QStringLiteral("data"), r.data}});
    emit doctorChanged();
    if (m_scanCheck.active)
        scanCheckStageDone(r); // AVPN Scanner: the check's progress
    const DoctorPhase donePh = m_docPhase;
    QTimer::singleShot(0, this, [this, e = m_docEpoch, donePh] {
        if (e != m_docEpoch)
            return;
        switch (donePh) {
        case DoctorPhase::Network:  docStartConnect();  break;
        case DoctorPhase::Connect:  docStartServers();  break;
        case DoctorPhase::Servers:  docStartServices(); break;
        case DoctorPhase::Services: docStartRuSplit();  break; // при вкл. сплите — RU-корпус
        case DoctorPhase::RuSplit:  docStartSpeed();    break;
        case DoctorPhase::Speed:    docStartAltNodes(); break; // при проблеме — до 2 альтернатив
        case DoctorPhase::AltNodes: docFinish();        break;
        default: break;
        }
    });
}

void AvpnEngineQml::docGuardFired()
{
    // стадия не уложилась в сторож: честный частичный вердикт, диагностика продолжается
    switch (m_docPhase) {
    case DoctorPhase::Network: {
        // собираем что успели (незавершённые пробы останутся -1 — честно)
        m_docNetPending = 0;
        const QJsonObject extra = benchExtra();
        const QString netType = extra.value(QStringLiteral("net_type")).toString();
        docStageDone(doctor::networkStage(
            m_docNetCaptive, netType,
            avpn::cellularGenerationForKind(netType, avpn::cellularGeneration()), avpn::meteredState(), avpn::roamingState(), m_docNetWl,
            extra.value(QStringLiteral("carrier")).toString(), detectLanIpv6()));
        break;
    }
    case DoctorPhase::Connect: {
        // сторож: либо не поднялись (45с), либо зависла проба данных (15с) — вердикт по факту
        m_docConnecting = false;
        const bool up = (state() == QLatin1String("connected"));
        docStageDone(doctor::connectStage(/*couldConnect=*/up, /*dataFlows=*/false,
            up ? debugSnapshot().value(QStringLiteral("latestHandshakeAgeSec")).toLongLong() : -1));
        break;
    }
    case DoctorPhase::Servers: {
        const QVariantMap cur = currentNode();
        QString nm = cur.value(QStringLiteral("name")).toString();
        const QString cc = cur.value(QStringLiteral("countryCode")).toString();
        if (nm.isEmpty()) nm = doctor::countryDisplayName(cc, appLang());
        docStageDone(doctor::serverStage(nm, cc, -1));
        break;
    }
    case DoctorPhase::Services:
        // Plan v3 step 5 (node_scan): the series hung past the guard - verdict from the chips that
        // did answer (with allDone there is no fixed 9 s wait that always beat the guard).
        if (m_docNodeScan)
            docServicesDone();
        else
            docStageDone(doctor::servicesStage(0, 0, {}, false, false));
        break;
    case DoctorPhase::Speed:
        if (m_docBenchStarted) { // сторож добил бенч: cancel молчалив — флаг гасим сами
            m_bench->cancel();
            m_docBenchStarted = false;
            m_benchRunning = false;
            emit benchChanged();
            docStageDone(doctor::speedStage(-1, 0, 0));
        } else {
            // бенч УСПЕЛ, завис A/B-замер мимо туннеля — не терять реальный результат бенча
            docStageDone(doctor::speedStage(m_docSpeedDown, m_docSpeedIdle, m_docSpeedLoaded,
                                            m_docSpeedCollapsed, -1));
        }
        break;
    case DoctorPhase::RuSplit:
        // не все пробы успели — вердикт по собранному (m_docRuOks предзаполнен false по индексам)
        docStageDone(doctor::ruSplitStage(m_docRuNames, m_docRuOks));
        break;
    case DoctorPhase::AltNodes:
        // подъём/проба альтернативы не уложились в сторож. Если проба 1 уже прошла (зависла
        // проба 2) — это нестабильная нода (одна проба), не мёртвая: docAltRecord с probe2=false.
        m_docConnecting = false;
        docAltRecord(/*probe2=*/false);
        break;
    case DoctorPhase::Send:
        if (m_scanCheck.active && m_scanCheck.submitted)
            scanCheckDelivery(/*boundPassed=*/true); // AVPN Scanner: no answer from the thread yet -> queued
        else
            docFinish();
        break;
    case DoctorPhase::Idle:
        break;
    }
}

void AvpnEngineQml::docStartServers()
{
    docEnter(DoctorPhase::Servers);
    // туннель поднят (фаза Connect его подняла/подтвердила) — показываем текущий сервер и его
    // live-отклик (app-layer RTT через туннель; off-tunnel ICMP при connected смазан, §11).
    QTimer::singleShot(500, this, [this, e = m_docEpoch] {
        if (e != m_docEpoch || m_docPhase != DoctorPhase::Servers) return;
        const QVariantMap cur = currentNode();
        QString nm = cur.value(QStringLiteral("name")).toString();
        const QString cc = cur.value(QStringLiteral("countryCode")).toString();
        if (nm.isEmpty()) nm = doctor::countryDisplayName(cc, appLang()); // «lv» → «Латвия» + флаг по cc в UI
        const int rtt = liveReachable() ? liveRttMs() : -1;
        // порог жёлтого server-driven (пересмотр владельца: до ~секунды — зелёный)
        const int warnMs = qBound(300, int(avpn::TuningStore::numberOr(
                                      QStringLiteral("doctor_rtt_warn_ms"), 800.0)), 3000);
        docStageDone(doctor::serverStage(nm, cc, rtt, warnMs));
    });
}

void AvpnEngineQml::docStartServices()
{
    docEnter(DoctorPhase::Services);
    // Туннель не поднят (Connect провалился) — probeServices() тихо no-op'нется, а
    // m_serviceStatus хранит СТАРЫЕ вердикты прошлой сессии: читать их = ложное
    // «мессенджеры работают» рядом с «не удалось подключиться» (ревью v2 #2). Честный Skip.
    if (state() != QLatin1String("connected")) {
        docStageDone(doctor::servicesStage(0, 0, {}, false, false));
        return;
    }
    // РЕАЛЬНАЯ проверка сервисов ЧЕРЕЗ туннель: WhatsApp/Telegram/YouTube/Instagram (те же
    // чипы, что на главном экране). Запускаем пробу и ждём заполнения m_serviceStatus.
    probeServices();
    if (!m_docNodeScan) {
        // features.node_scan off: the previous Doctor - a fixed 9 s wait for the chips, then the same
        // verdict as the flag path (docServicesDone; was a copy of its body).
        QTimer::singleShot(9000, this, [this, e = m_docEpoch] {
            if (e != m_docEpoch || m_docPhase != DoctorPhase::Services) return;
            docServicesDone();
        });
        return;
    }
    // Plan v3 step 5 (node_scan): the stage ends when the probe series ends (ServiceProbe::allDone),
    // not after a fixed 9 s wait - on a working network that is 1-3 s. A hung series is bounded by
    // the stage guard (diag_stage_timeout_ms), which then gives the same partial verdict.
    // Probes off (service_probes) or nothing to probe -> the verdict from what is known right away.
    if (!m_svcProbe || !m_svcProbe->inFlight()) {
        docServicesDone();
        return;
    }
    connect(m_svcProbe, &ServiceProbe::allDone, this, [this, e = m_docEpoch] {
        if (e != m_docEpoch || m_docPhase != DoctorPhase::Services) return;
        docServicesDone();
    }, Qt::SingleShotConnection);
}

void AvpnEngineQml::docServicesDone()
{
    // One verdict per run: the stage guard and allDone can land in the same event-loop turn.
    if (m_docPhase != DoctorPhase::Services
        || (!m_docStages.isEmpty() && m_docStages.constLast().id == QLatin1String("services")))
        return;
    int works = 0, total = 0;
    QStringList blocked;
    for (const QVariant &v : std::as_const(m_serviceStatus)) {
        const QVariantMap m = v.toMap();
        const int stt = m.value(QStringLiteral("state")).toInt();
        const QString label = m.value(QStringLiteral("label")).toString();
        if (stt < 0) continue; // unknown/не измерено — не считаем ни за, ни против
        ++total;
        if (stt == 0)      blocked.append(label);  // Blocked
        else if (stt >= 2) ++works;                // Works (Slow не блок, но и не «недоступно»)
    }
    const QString net = benchExtra().value(QStringLiteral("net_type")).toString();
    const bool wlApplicable = (m_whitelistDetector != nullptr) && net == QLatin1String("cellular");
    const bool wlActive = m_whitelistDetector && m_whitelistDetector->active();
    docStageDone(doctor::servicesStage(works, total, blocked, wlApplicable, wlActive));
}

void AvpnEngineQml::docStartSpeed()
{
    docEnter(DoctorPhase::Speed);
    // Plan v3 step 5 (node_scan): no speed test without a working connection - the bench would
    // measure the path past the tunnel or wait out its guard (up to 45 s) for nothing.
    if (m_docNodeScan && !doctor::speedStageApplicable(m_docStages, state() == QLatin1String("connected"))) {
        docStageDone(doctor::speedStageSkippedNoConnection());
        return;
    }
    if (m_benchRunning) { // гонка с админ-панелью — честный Skip, не второй бенч
        docStageDone(doctor::speedStage(-1, 0, 0));
        return;
    }
    if (m_scanCheck.active) {
        // AVPN Scanner (plan §3): ONE sized /v1/probe through the live tunnel (TribeScanner::sampleSpeed, size
        // scan_check_speed_bytes of the manifest, compiled fallback 1 MiB) - own nodes and provider profiles alike;
        // the old ~9.5 MB bench below stays with the old Doctor sheet (doctor_legacy) only.
        if (!m_scanner) {
            docStageDone(doctor::speedStageFromSample(false, 0, -1, false, QStringLiteral("no_base")));
            return;
        }
        const qint64 bytes = m_scanner->machine().tunables().checkSpeedBytes;
        m_scanner->sampleSpeed(bytes, kScanCheckSpeedTimeoutMs, [this, e = m_docEpoch](const ScanSpeedSample &sm) {
            if (e != m_docEpoch || m_docPhase != DoctorPhase::Speed)
                return;
            docStageDone(doctor::speedStageFromSample(sm.ok, sm.bytes, sm.ms, sm.digestOk, sm.error));
        });
        return;
    }
    m_docBenchStarted = true;
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start"); // benchStageFrac() тикает процент Speed-стадии
    emit benchChanged();
    const bool lite = TuningStore::numberOr(QStringLiteral("diag_bench_lite"), 1) != 0;
    m_bench->start(QStringLiteral("doctor"), benchExtra(), lite,
                   currentNodeEndpointIp(currentNode()));
}

// D-3 п.19: A/B — тот же класс замера МИМО туннеля. На мобилках off-tunnel HTTP возможен
// только маршрутом байпаса (RU-endpoint при включённом «Доступе к РФ»), поэтому гейты:
// подозрение (коллапс/медленно) + server-driven urls.diag_ru_speed_url задан (пустой
// фолбэк = стадия без A/B, бэк включает без релиза) + сплит включён. Кап: 8с транспортом.
void AvpnEngineQml::docDirectSpeed(double down, int idle, int loaded, bool collapsed)
{
    m_docSpeedDown = down; // партиалы: сторож фазы не должен терять готовый бенч
    m_docSpeedIdle = idle;
    m_docSpeedLoaded = loaded;
    m_docSpeedCollapsed = collapsed;
    const bool suspicious = collapsed || (down >= 0 && down < 5.0);
    const QString url = configUrl(QStringLiteral("diag_ru_speed_url"), QString());
    bool masterOn = false;
    {
        QSettings st;
        masterOn = st.value(QStringLiteral("AvpnBypass/masterOn"), false).toBool();
    }
    if (!suspicious || url.isEmpty() || !masterOn) {
        docStageDone(doctor::speedStage(down, idle, loaded, collapsed, -1));
        return;
    }
    m_docGuard.start(15000); // свой сторож на контрольный замер (Speed-сторож мог истечь)
    QNetworkRequest req{QUrl(url)};
    req.setTransferTimeout(8000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    auto *t = new QElapsedTimer();
    t->start();
    QNetworkReply *rep = m_nam->get(req);
    auto bytes = std::make_shared<qint64>(0);
    connect(rep, &QNetworkReply::readyRead, this, [rep, bytes] {
        *bytes += rep->readAll().size();
        if (*bytes > 6 * 1024 * 1024)
            rep->abort(); // кап трафика: 6 МБ хватает для оценки, замер закончит finished
    });
    connect(rep, &QNetworkReply::finished, this,
            [this, rep, t, bytes, down, idle, loaded, collapsed, e = m_docEpoch] {
        rep->deleteLater();
        const qint64 ms = t->elapsed();
        delete t;
        if (e != m_docEpoch || m_docPhase != DoctorPhase::Speed) return;
        // abort после капа — валидный замер; настоящий фейл = байтов почти нет
        const double direct = (*bytes > 64 * 1024 && ms > 300)
                                  ? avpn::BenchRunner::mbit(*bytes, ms) : -1.0;
        docStageDone(doctor::speedStage(down, idle, loaded, collapsed, direct));
    });
}

void AvpnEngineQml::docStartRuSplit()
{
    docEnter(DoctorPhase::RuSplit);
    if (m_scanCheck.active && state() != QLatin1String("connected")) {
        // AVPN Scanner: with the VPN off the corpus would only show the direct path, not the split.
        docStageDone(doctor::stageSkippedNoVpn(QStringLiteral("rusplit")));
        return;
    }
    // Выключенный «Доступ к сайтам РФ» — честный Skip с причиной (раньше фаза молча
    // пропускалась, и поддержка не видела, что сплит у клиента вовсе не включён).
    bool masterOn = false;
    {
        QSettings st;
        masterOn = st.value(QStringLiteral("AvpnBypass/masterOn"), false).toBool();
    }
    if (!masterOn) {
        docStageDone(doctor::ruSplitStage({}, {}, /*enabled=*/false));
        return;
    }
    // Корпус server-driven — ЕДИНЫЙ ключ lists.rusplit_watch с дозорным RuSplitSentinel
    // (фолбэк rusentinel::defaultWatch: Яндекс/Ozon/Wildberries/Госуслуги, "Имя|URL").
    // BUG-5 (2026-07-22): было HEAD + требование error()==NoError — бот-защита VK/Аэрофлота
    // отвечает 418/403 на HEAD ⇒ вечное ложное «Не открылись» в КАЖДОМ отчёте на любой сети.
    // Теперь GET (обрываем после заголовков — тело не тянем) + успех = ЛЮБОЙ HTTP-код <500
    // (семантика rusentinel::classifyProbe: ответ дошёл ⇒ маршрут до сайта работает).
    const QStringList raw =
        TuningStore::listOr(QStringLiteral("rusplit_watch"), rusentinel::defaultWatch());
    m_docRuNames.clear(); m_docRuOks.clear();
    m_docRuPending = 0;
    QStringList urls;
    for (const QString &entry : raw) {
        QString name, url;
        if (!rusentinel::parseWatchEntry(entry, name, url))
            continue;
        m_docRuNames.append(name);
        m_docRuOks.append(false); // предзаполнение по индексам (параллельные колбэки)
        urls.append(url);
    }
    if (m_docRuNames.isEmpty()) {
        docStageDone(doctor::ruSplitStage({}, {}));
        return;
    }
    for (int i = 0; i < urls.size(); ++i) {
        ++m_docRuPending;
        QNetworkRequest req{QUrl(urls.at(i))};
        req.setTransferTimeout(6000);
        req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        QNetworkReply *rep = m_nam->get(req);
        auto code = std::make_shared<int>(0);
        connect(rep, &QNetworkReply::metaDataChanged, this, [rep, code] {
            if (*code > 0)
                return;
            *code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (*code > 0)
                rep->abort(); // заголовков достаточно для вердикта — трафик не жжём
        });
        connect(rep, &QNetworkReply::finished, this, [this, rep, code, i, e = m_docEpoch] {
            rep->deleteLater();
            if (e != m_docEpoch || m_docPhase != DoctorPhase::RuSplit) return;
            int c = *code;
            if (c <= 0)
                c = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (i < m_docRuOks.size())
                m_docRuOks[i] = (c > 0 && c < 500);
            if (--m_docRuPending <= 0)
                docStageDone(doctor::ruSplitStage(m_docRuNames, m_docRuOks));
        });
    }
}

void AvpnEngineQml::docStartAltNodes()
{
    if (m_scanCheck.active) { // AVPN Scanner (plan §3): no alternatives - the scan rows are the alternatives
        docFinish();
        return;
    }
    // Триггер (быстрый режим): только при реальной проблеме на текущей ноде И наличии
    // альтернатив. Различает «нода сломана» (альтернатива работает → остаёмся на ней) от
    // «сеть/оператор» (все мертвы → честный вердикт + возврат исходного выбора).
    // Полный режим (m_docFull): обзор ВСЕХ кандидатов независимо от проблемы — без ранней
    // остановки на первой рабочей; в конце пересадка только если проблема БЫЛА.
    // Критик полноты (U1, жалоба 1 «сами перекидываются ноды»): триггер — проблема САМОЙ ноды
    // (doctorNodeProblem: data-plane Bad на connect/services или «далеко» при альтернативе на 30 %+
    // быстрее), а не любой Warn/Bad (сайты РФ, «медленно и без VPN», 3G, IPv6-заметка уводили
    // рабочую EE на US). RTT сравниваем одной мерой — последний известный off-tunnel ICMP.
    const QVariantMap cur = currentNode();
    const QString curId = cur.value(QStringLiteral("nodeId")).toString();
    // Fresh measurement over the last known one (as failover). Decision 2026-11-05: an Xray
    // listener's own ICMP is the shared RU entry - the queue is ordered by the ranking RTT (exit
    // host, TransportPick.h::rankingRtt) and every compared/shown value is the honest exit RTT.
    QHash<QString, int> rawRtt = m_engine.lastKnownRtt();
    const QHash<QString, int> freshRtt = m_engine.measuredRtt();
    for (auto it = freshRtt.constBegin(); it != freshRtt.constEnd(); ++it)
        rawRtt.insert(it.key(), it.value());
    const QHash<QString, int> exitRtt = m_engine.exitRtt(rawRtt);
    const QHash<QString, int> rankRtt = m_engine.rankingRtt(rawRtt);
    m_docAltCurRtt = exitRtt.value(curId, -1);
    if (m_docAltCurRtt < 0) {
        for (const auto &st : m_docStages)
            if (st.id == QLatin1String("servers"))
                m_docAltCurRtt = st.data.value(QStringLiteral("rtt_ms")).toInt(-1);
    }
    // очередь: живые поддерживаемые ноды, отсортированные по RTT выхода (кеш), != текущей
    QStringList candIds;
    QHash<QString, QVariantMap> candById;
    const QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();
    for (const QVariant &v : pool) {
        const QVariantMap n = v.toMap();
        if (!n.value(QStringLiteral("alive")).toBool()) continue;
        const QString id = n.value(QStringLiteral("nodeId")).toString();
        if (id.isEmpty() || id == curId) continue;
        if (!avpn::isSupportedProto(n.value(QStringLiteral("proto")).toString())) continue;
        // Upstream nodes (R16): Doctor alternatives are OUR nodes - trying a provider row leases a seat.
        if (n.value(QStringLiteral("upstream")).toBool()) continue;
        // manual_only/RU (§14.3) — вне авто-выбора ВЕЗДЕ: иначе Доктор проверял бы RU-ноду и,
        // пройди её проба, пересадил бы пользователя на RU-egress (реальный случай 2026-07-20).
        if (n.value(QStringLiteral("manualOnly")).toBool()) continue;
        // Канон владельца (полная диагностика): RU-нода ВСЕГДА в исключениях — ремень поверх
        // manual_only на случай, если флаг у RU-ноды когда-нибудь снимут на бэке.
        if (n.value(QStringLiteral("countryCode")).toString()
                .compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0) continue;
        candIds << id;
        candById.insert(id, n);
    }
    // first = honest exit RTT (99999 = unknown), order = ranking RTT (stable).
    QList<QPair<int, QVariantMap>> cand;
    for (const QString &id : orderByRankingRtt(candIds, rankRtt))
        cand.append({exitRtt.value(id, 99999), candById.value(id)});
    const int bestAltRtt = (!cand.isEmpty() && cand.first().first < 99999) ? cand.first().first : -1;
    m_docAltHadProblem = doctorNodeProblem(m_docStages, m_docAltCurRtt, bestAltRtt);
    m_docAltFarOnly = m_docAltHadProblem && !doctorDataPlaneProblem(m_docStages);
    reliabilityEvent(QStringLiteral("doctor_node_problem=%1 far_only=%2 cur_rtt=%3 best_alt_rtt=%4")
                         .arg(m_docAltHadProblem).arg(m_docAltFarOnly).arg(m_docAltCurRtt).arg(bestAltRtt));
    if (!m_docFull && !m_docAltHadProblem) {
        docFinish();
        return;
    }
    m_docAltQueue.clear(); m_docAltNames.clear(); m_docAltOks.clear();
    m_docAltDetails.clear(); m_docAltCand.clear();
    m_docAltIdx = -1;
    // Быстрый режим: до 3 самых быстрых альтернатив (doctor_alt_max). Полный: все кандидаты
    // (кап doctor_full_max — предохранитель от гигантского пула). Каждую держим и пробуем
    // ДВАЖДЫ (сразу + после ~keepalive) — ловит «handshake есть, данные пропали через 20с».
    const int altMax = m_docFull
        ? qBound(3, int(avpn::TuningStore::numberOr(
                      QStringLiteral("doctor_full_max"), 12.0)), 20)
        : qBound(1, int(avpn::TuningStore::numberOr(
                      QStringLiteral("doctor_alt_max"), 3.0)), 5);
    for (const auto &c : cand) {
        if (m_docAltQueue.size() >= altMax) break;
        // Быстрый режим, проблема только «далеко»: пробуем лишь альтернативы, заметно ближе текущей.
        if (!m_docFull && m_docAltFarOnly
            && !doctorAltRttBetterEnough(m_docAltCurRtt, c.first < 99999 ? c.first : -1))
            continue;
        const QString id = c.second.value(QStringLiteral("nodeId")).toString();
        m_docAltQueue.append(id);
        QString nm = c.second.value(QStringLiteral("name")).toString();
        const QString cc = c.second.value(QStringLiteral("countryCode")).toString();
        if (nm.isEmpty()) // 5.1.108: on the app's language (was always Russian - an es/en Doctor showed «Эстония»)
            nm = doctor::countryDisplayName(cc, appLang());
        m_docAltNames.append(nm);
        QVariantMap meta;
        meta.insert(QStringLiteral("name"), nm);
        meta.insert(QStringLiteral("cc"), cc);
        meta.insert(QStringLiteral("nodeId"), id);
        meta.insert(QStringLiteral("proto"), c.second.value(QStringLiteral("proto")).toString());
        meta.insert(QStringLiteral("rtt_ms"), c.first < 99999 ? c.first : -1);
        m_docAltCand.append(meta);
    }
    if (m_docAltQueue.isEmpty()) {
        docFinish();
        return;
    }
    m_docOrigNode = curId;
    m_docOrigPin = m_engine.pinnedNodeId();
    docEnter(DoctorPhase::AltNodes);
    docAltNext();
}

void AvpnEngineQml::docAltNext()
{
    // Быстрый режим: предыдущая альтернатива оказалась СТАБИЛЬНОЙ (обе пробы) → остаёмся на
    // ней (юзеру сразу хорошо), дальше не перебираем. Нестабильная (одна проба из двух =
    // задержанный blackhole) НЕ считается рабочей — перебираем дальше, ищем по-настоящему
    // живую. Полный режим ранней остановки НЕ делает — обзор всех кандидатов до конца.
    if (!m_docFull
        && m_docAltIdx >= 0 && m_docAltIdx < m_docAltOks.size() && m_docAltOks.at(m_docAltIdx)) {
        docStageDone(doctor::altNodesStage(
            m_docAltNames.mid(0, m_docAltIdx + 1), m_docAltOks,
            /*switchedTo=*/m_docAltNames.at(m_docAltIdx),
            QJsonArray::fromVariantList(m_docAltDetails)));
        return;
    }
    ++m_docAltIdx;
    if (m_docAltIdx >= m_docAltQueue.size()) {
        // Конец очереди. Пересадка ТОЛЬКО если проблема была (в полном режиме сюда доходим
        // всегда — обзор без проблемы не должен молча менять сервер пользователю): сначала
        // лучшая стабильная (полный режим), потом нестабильная (хоть что-то), иначе — возврат
        // исходного выбора. Fire-and-forget.
        // Критик полноты (U1): при проблеме только «далеко» пересадка — лишь на заметно более
        // близкую ноду (полный режим обозревает и дальние); нестабильная туда не годится вовсе.
        auto eligible = [this](int i) {
            if (!m_docAltFarOnly)
                return true;
            const int rtt = i < m_docAltCand.size()
                ? m_docAltCand.at(i).toMap().value(QStringLiteral("rtt_ms")).toInt() : -1;
            return doctorAltRttBetterEnough(m_docAltCurRtt, rtt);
        };
        int bestStable = -1;
        for (int i = 0; i < m_docAltOks.size(); ++i)
            if (m_docAltOks.at(i) && eligible(i)) { bestStable = i; break; } // первый = самый быстрый по RTT
        int bestShaky = -1;
        for (int i = 0; i < m_docAltDetails.size() && !m_docAltFarOnly; ++i)
            if (m_docAltDetails.at(i).toMap().value(QStringLiteral("verdict")).toInt() == 1) {
                bestShaky = i; break;
            }
        QString switchedTo;
        if (m_docAltHadProblem && bestStable >= 0 && bestStable < m_docAltQueue.size()) {
            pinAndReconnectImpl(m_docAltQueue.at(bestStable), pinOriginPersists(PinOrigin::Doctor),
                                /*forceConnect=*/true, StartOrigin::Doctor);
            switchedTo = m_docAltNames.value(bestStable);
        } else if (m_docAltHadProblem && bestShaky >= 0 && bestShaky < m_docAltQueue.size()) {
            pinAndReconnectImpl(m_docAltQueue.at(bestShaky), pinOriginPersists(PinOrigin::Doctor),
                                /*forceConnect=*/true, StartOrigin::Doctor);
            switchedTo = m_docAltNames.value(bestShaky);
        } else {
            docRestoreSelection();
        }
        docStageDone(doctor::altNodesStage(m_docAltNames, m_docAltOks, switchedTo,
                                           QJsonArray::fromVariantList(m_docAltDetails)));
        return;
    }
    // полный обзор долгий — прогресс тикает по числу пройденных нод (70..96%)
    if (m_docFull && !m_docAltQueue.isEmpty())
        m_docPercent = 70 + (26 * m_docAltIdx) / m_docAltQueue.size();
    m_docConnecting = true;
    m_docSawProgress = false;
    m_docAltUp = false;
    m_docGuard.start(40000); // подъём альтернативы
    emit doctorChanged();    // note текущей стадии в UI обновится (docStage прежний)
    // stop→start на выбранную; forceConnect — проверяемая альтернатива поднимается, даже если
    // туннель в этот момент лежит после прошлой (иначе намерение снималось и проба была ложной).
    pinAndReconnectImpl(m_docAltQueue.at(m_docAltIdx), pinOriginPersists(PinOrigin::Doctor),
                        /*forceConnect=*/true, StartOrigin::Doctor);
}

// Проба 1 сразу после connected: HEAD 204 + ICMP через туннель + возраст handshake. Результат
// НЕ финализируем — планируем пробу 2 после ~keepalive (задержанный blackhole S4/ТСПУ виден
// только тогда: handshake жив, data-плейн умирает через ~20-28с).
void AvpnEngineQml::docAltVerify()
{
    m_docAltHsSec = debugSnapshot().value(QStringLiteral("latestHandshakeAgeSec")).toLongLong();
    // D-6: блок-профиль эндпоинта альтернативы — мы к ней подключены, host-route активен
    const QString epIp = docEpProbeStart([this, e = m_docEpoch](bool ok) {
        if (e == m_docEpoch) m_docAltEpBig = ok ? 1 : 0;
    });
    m_docAltEpTried = !epIp.isEmpty();
    if (m_docPing) {
        QList<avpn::RttTarget> targets{{QStringLiteral("tunnel"), QStringLiteral("1.1.1.1"), 0}};
        if (!epIp.isEmpty())
            targets.append({QStringLiteral("ep"), epIp, 0});
        m_docPing->probeAll(targets, 3000,
            [this, e = m_docEpoch](const QString &id, int rttMs) {
                if (e != m_docEpoch || rttMs < 0) return;
                if (id == QLatin1String("ep")) {
                    if (m_docAltEpMs < 0 || rttMs < m_docAltEpMs) m_docAltEpMs = rttMs;
                } else if (m_docAltIcmpMs < 0 || rttMs < m_docAltIcmpMs) {
                    m_docAltIcmpMs = rttMs;
                }
            },
            [] {});
    }
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(6000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep, e = m_docEpoch] {
        rep->deleteLater();
        if (e != m_docEpoch || m_docPhase != DoctorPhase::AltNodes) return;
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        m_docAltProbe1 = rep->error() == QNetworkReply::NoError && code > 0;
        const int gap = qBound(3000, int(avpn::TuningStore::numberOr(
                                   QStringLiteral("doctor_alt_reprobe_ms"), 12000.0)), 30000);
        QTimer::singleShot(gap, this, [this, e = m_docEpoch] {
            if (e == m_docEpoch && m_docPhase == DoctorPhase::AltNodes) docAltVerify2();
        });
    });
}

// Проба 2 (после гэпа): второй HEAD 204. verdict сводит обе.
void AvpnEngineQml::docAltVerify2()
{
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(6000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep, e = m_docEpoch] {
        rep->deleteLater();
        if (e != m_docEpoch || m_docPhase != DoctorPhase::AltNodes) return;
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        docAltRecord(/*probe2=*/rep->error() == QNetworkReply::NoError && code > 0);
    });
}

// Свести обе пробы в per-нода деталь. verdict: 2=обе прошли (стабильна), 1=одна (нестабильна,
// задержанный blackhole), 0=обе мимо (мертва). m_docAltOks[idx] = стабильна (для switch-логики).
void AvpnEngineQml::docAltRecord(bool probe2)
{
    m_docGuard.stop();
    const qint64 rxNow = m_tunnel.readStats().rxBytes;
    const bool rxGrew = rxNow > m_docAltRx0;
    const int hits = (m_docAltProbe1 ? 1 : 0) + (probe2 ? 1 : 0);
    const int verdict = hits >= 2 ? 2 : (hits == 1 ? 1 : 0);
    QVariantMap d = (m_docAltIdx >= 0 && m_docAltIdx < m_docAltCand.size())
                        ? m_docAltCand.at(m_docAltIdx).toMap() : QVariantMap{};
    d.insert(QStringLiteral("probe1"), m_docAltProbe1);
    d.insert(QStringLiteral("probe2"), probe2);
    d.insert(QStringLiteral("rx_grew"), rxGrew);
    d.insert(QStringLiteral("handshake_sec"), double(m_docAltHsSec));
    if (m_docAltIcmpMs >= 0) d.insert(QStringLiteral("tunnel_icmp_ms"), m_docAltIcmpMs);
    if (m_docAltEpTried) { // D-6: блок-профиль эндпоинта (docEpProbeStart)
        d.insert(QStringLiteral("ep_icmp_ms"), m_docAltEpMs); // -1 = IP молчит мимо туннеля
        if (m_docAltEpBig != -1)
            d.insert(QStringLiteral("ep_icmp_big"), m_docAltEpBig == 1);
    }
    d.insert(QStringLiteral("verdict"), verdict);
    d.insert(QStringLiteral("up"), m_docAltUp); // owner test of 5.1.102: "unreachable" vs "no data"
    avpn::TribeJournal::append(QStringLiteral("doctor_alt"), QJsonObject::fromVariantMap(d));
    m_docAltDetails.append(d);
    m_docAltOks.append(verdict >= 2); // РАБОЧАЯ только если стабильна (обе пробы)
    docAltNext();
}

void AvpnEngineQml::docFinish()
{
    if (m_scanCheck.active) {
        scanCheckSubmit(); // AVPN Scanner: schema 5 into the support queue, no bench upload of its own
        return;
    }
    docEnter(DoctorPhase::Send);
    {
        QJsonObject extra = benchExtra();
        extra.insert(QStringLiteral("doctor_mode"),
                     m_docFull ? QStringLiteral("full") : QStringLiteral("quick"));
        if (!m_docBenchFull.isEmpty()) // полный lite-бенч: разложение dns/tls/http/ping для анализа
            extra.insert(QStringLiteral("bench"), m_docBenchFull);
        // CR-1: локальный счётчик аварийных смертей на мобилках (dirty_exit там не шлётся
        // отдельным отчётом — ОС штатно убивает фон; но в контексте Доктора он информативен)
        const int dirty = CrashGuard::instance().dirtyExitCount();
        if (dirty > 0) {
            extra.insert(QStringLiteral("dirty_exits_since_last"), dirty);
            CrashGuard::instance().resetDirtyExitCount();
        }
        // Критик полноты (U10): кто и почему гасил/переключал туннель — журнал свитчей движка и
        // кольцо reliability фасада (guarded_stop why=...), хвост с капом по байтам.
        attachReliabilityContext(extra, m_engine.debugSnapshot().switchLog, m_reliabilityRing.lines);
        m_docReport = doctor::buildReport(m_docStages, extra);
    }
    m_docSummary = m_docReport.value(QStringLiteral("summary")).toString();
    m_docHasProblem = doctor::hasProblem(m_docStages);
    avpn::TribeJournal::append(QStringLiteral("doctor_report"),
                               {{QStringLiteral("mode"), m_docFull ? QStringLiteral("full") : QStringLiteral("quick")},
                                {QStringLiteral("has_problem"), m_docHasProblem},
                                {QStringLiteral("summary"), m_docSummary},
                                {QStringLiteral("report"), m_docReport}});
    // Анонимный отчёт на control plane ВСЕГДА (наш анализ /v1/bench/report — все прогоны,
    // и удачные, и проблемные, для улучшения пула). В ТРЕД поддержки шлёт QML — и ТОЛЬКО
    // при проблеме (нет сбоев ⇒ не дёргаем поддержку и не пишем «ожидайте ответа»).
    if (featureEnabled(QStringLiteral("diag_upload"), true))
        uploadReport(QString::fromUtf8(
                         QJsonDocument(m_docReport).toJson(QJsonDocument::Compact)),
                     /*quiet=*/true);
    m_docGuard.stop();
    m_docPhase = DoctorPhase::Idle;
    m_docPercent = 100;
    CrashGuard::instance().setPhase(state() == QLatin1String("connected") ? "connected" : "idle");
    emit doctorChanged();
    emit doctorFinished();
}

// CR-1: отправить накопленные краш-отчёты прошлых запусков. Best-effort + оптимистичный
// markSent (дубликаты в телеметрии хуже редкой потери — отчёт уже классифицирован локально).
void AvpnEngineQml::crashFlushPending()
{
    if (!featureEnabled(QStringLiteral("crash_report"), true))
        return; // kill-switch: бэк глушит поток без релиза
    const QList<QJsonObject> pend = CrashGuard::instance().takePendingReports();
    // Критик полноты (U10): кольцо reliability персистентно (QSettings avpn/reliabilityLog) —
    // переходы ДО краша доезжают вместе с отчётом; журнал свитчей — текущей сессии движка.
    const QStringList switchLog = pend.isEmpty() ? QStringList() : m_engine.debugSnapshot().switchLog;
    for (QJsonObject r : pend) {
        const QString id = r.take(QStringLiteral("_pending_id")).toString();
        if (id.isEmpty())
            continue;
        attachReliabilityContext(r, switchLog, m_reliabilityRing.lines);
        uploadReport(QString::fromUtf8(QJsonDocument(r).toJson(QJsonDocument::Compact)),
                     /*quiet=*/true);
        CrashGuard::instance().markSent(id);
    }
}

QString AvpnEngineQml::doctorReportJson() const
{
    if (m_docReport.isEmpty())
        return {};
    return QString::fromUtf8(QJsonDocument(m_docReport).toJson(QJsonDocument::Compact));
}

// AVPN (Доктор): ручной оператор — QSettings AvpnDiag/carrier (benchExtra отдаёт ему приоритет
// над авто MCC-MNC). На iOS 16+ Apple закрыл CTCarrier → это единственный способ узнать оператора.
void AvpnEngineQml::setDiagCarrier(const QString &code)
{
    QSettings s;
    if (code.isEmpty())
        s.remove(QStringLiteral("AvpnDiag/carrier"));
    else
        s.setValue(QStringLiteral("AvpnDiag/carrier"), code);
    s.sync();
    emit changed();
}

QString AvpnEngineQml::diagCarrier() const
{
    const QString manual = QSettings().value(QStringLiteral("AvpnDiag/carrier")).toString();
    return manual.isEmpty() ? avpn::carrierCode() : manual;
}

QString AvpnEngineQml::diagCarrierAuto() const
{
    return avpn::carrierCode();
}

// AVPN (волна UX Доктора 07-22): авто-тип сети для интро-шагов. БЕЗ ручного фолбэка — по нему
// интро решает, задавать ли вопрос «какой у вас интернет» (авто знает → не спрашиваем).
QString AvpnEngineQml::doctorNetType() const
{
    static const bool niLoaded = QNetworkInformation::loadDefaultBackend();
    if (niLoaded) {
        if (auto *ni = QNetworkInformation::instance()) {
            switch (ni->transportMedium()) {
            case QNetworkInformation::TransportMedium::Ethernet: return QStringLiteral("ethernet");
            case QNetworkInformation::TransportMedium::WiFi:     return QStringLiteral("wifi");
            case QNetworkInformation::TransportMedium::Cellular: return QStringLiteral("cellular");
            default: break;
            }
        }
    }
    // iOS на сотовой: Qt отдаёт Unknown, CoreTelephony знает (работает и под VPN)
    if (!avpn::cellularGeneration().isEmpty())
        return QStringLiteral("cellular");
    return {};
}

QString AvpnEngineQml::platformNetKind() const
{
    QString qtMedium;
    static const bool niLoaded = QNetworkInformation::loadDefaultBackend();
    if (niLoaded) {
        if (auto *ni = QNetworkInformation::instance()) {
            switch (ni->transportMedium()) {
            case QNetworkInformation::TransportMedium::Ethernet: qtMedium = QStringLiteral("ethernet"); break;
            case QNetworkInformation::TransportMedium::WiFi:     qtMedium = QStringLiteral("wifi"); break;
            case QNetworkInformation::TransportMedium::Cellular: qtMedium = QStringLiteral("cellular"); break;
            default: break;
            }
        }
    }
    const bool ownTunnelUp = m_lastTunnelState != Vpn::Disconnected && m_lastTunnelState != Vpn::Unknown;
    return avpn::platformNetworkKind(qtMedium, avpn::cellularGeneration(), ownTunnelUp);
}

QString AvpnEngineQml::networkKind() const
{
    const NetKindInputs in = netKindInputs();
    return avpn::scanNetworkKindPick(in.pathKind, in.interfacesKind, platformNetKind()).kind;
}

// Ручной тип сети из интро. НЕ персистится (сеть меняется между запусками) — живёт до
// перезапуска приложения; benchExtra берёт его только когда авто-детект промолчал.
void AvpnEngineQml::setDiagNetType(const QString &t)
{
    const QString v = (t == QLatin1String("wifi") || t == QLatin1String("cellular"))
                          ? t : QString();
    if (m_diagNetManual == v)
        return;
    m_diagNetManual = v;
    emit changed();
}

// Операторы РФ для плашки интро (server-driven lists.doctor_operators, формат "MCC-MNC|Имя").
// Фолбэк — актуальные операторы 2026: большая четвёрка + заметные MVNO (Т-Мобайл экс-Тинькофф,
// СберМобайл, МОТИВ, Ростелеком). "other" = «Другой»: ценность выбора — категория для паттернов
// «оператор X режет ноду Y», точный MNC не обязателен.
QVariantList AvpnEngineQml::diagOperators() const
{
    static const QStringList def{
        QStringLiteral("250-01|МТС"),
        QStringLiteral("250-02|МегаФон"),
        QStringLiteral("250-99|Билайн"),
        QStringLiteral("250-20|T2"),
        QStringLiteral("250-11|Yota"),
        QStringLiteral("250-62|Т-Мобайл"),
        QStringLiteral("250-40|СберМобайл"),
        QStringLiteral("250-35|МОТИВ"),
        QStringLiteral("250-39|Ростелеком"),
        QStringLiteral("other|Другой"),
    };
    QVariantList out;
    const QStringList raw = TuningStore::listOr(QStringLiteral("doctor_operators"), def);
    for (const QString &e : raw) {
        const int sep = e.indexOf(QLatin1Char('|'));
        if (sep <= 0)
            continue;
        QVariantMap m;
        m.insert(QStringLiteral("code"), e.left(sep).trimmed());
        m.insert(QStringLiteral("name"), e.mid(sep + 1).trimmed());
        out.append(m);
    }
    return out;
}

QString AvpnEngineQml::doctorHumanReport() const
{
    // Читаемое резюме для менеджера поддержки: текст-СООБЩЕНИЕ в тред (сырой diag.log
    // оператору бесполезен — вложение остаётся для разработчика).
    const QJsonObject extra = benchExtra();
    return doctor::humanReport(m_docStages,
                               extra.value(QStringLiteral("net_type")).toString(),
                               extra.value(QStringLiteral("tz")).toString());
}

QString AvpnEngineQml::doctorDiagText() const
{
    QString txt = buildDiagReport();
    const QString json = doctorReportJson();
    if (!json.isEmpty())
        txt += QStringLiteral("\n=== DOCTOR v1 ===\n") + json + QStringLiteral("\n");
    return txt;
}

QString AvpnEngineQml::doctorStage() const
{
    switch (m_docPhase) {
    case DoctorPhase::Network:  return QStringLiteral("network");
    case DoctorPhase::Connect:  return QStringLiteral("connect");
    case DoctorPhase::Servers:  return QStringLiteral("servers");
    case DoctorPhase::Services: return QStringLiteral("services");
    case DoctorPhase::RuSplit:  return QStringLiteral("rusplit");
    case DoctorPhase::Speed:    return QStringLiteral("speed");
    case DoctorPhase::AltNodes: return QStringLiteral("altnodes");
    case DoctorPhase::Send:     return QStringLiteral("send");
    case DoctorPhase::Idle:     break;
    }
    return {};
}

// Owner test of 5.1.102 (2026-11-05): the alternatives stage showed only «Проверяю другие
// серверы» for a minute. The sheet now shows which server is being checked («Проверяем: …, 2 из 4»)
// and each result as soon as docAltRecord has it. Same checks and timeouts as before.
QVariantMap AvpnEngineQml::doctorAltProgress() const
{
    if (m_docPhase != DoctorPhase::AltNodes || m_docAltQueue.isEmpty())
        return {};
    QVariantList done;
    for (const QVariant &v : m_docAltDetails) {
        const QVariantMap d = v.toMap();
        done.append(QVariantMap{
            {QStringLiteral("name"), d.value(QStringLiteral("name"))},
            {QStringLiteral("cc"), d.value(QStringLiteral("cc"))},
            {QStringLiteral("proto"), d.value(QStringLiteral("proto"))},
            {QStringLiteral("result"), doctor::altNodeResult(d.value(QStringLiteral("verdict")).toInt(),
                                                             d.value(QStringLiteral("up")).toBool())}});
    }
    QVariantMap m{{QStringLiteral("total"), int(m_docAltQueue.size())}, {QStringLiteral("done"), done}};
    // The alternative being checked now: started (index set) and not recorded yet.
    if (m_docAltIdx >= 0 && m_docAltIdx < m_docAltCand.size() && m_docAltDetails.size() <= m_docAltIdx) {
        const QVariantMap c = m_docAltCand.at(m_docAltIdx).toMap();
        m.insert(QStringLiteral("number"), m_docAltIdx + 1);
        m.insert(QStringLiteral("name"), c.value(QStringLiteral("name")));
        m.insert(QStringLiteral("cc"), c.value(QStringLiteral("cc")));
        m.insert(QStringLiteral("proto"), c.value(QStringLiteral("proto")));
    }
    return m;
}

QVariantList AvpnEngineQml::doctorStages() const
{
    QVariantList out;
    for (const auto &s : m_docStages) {
        QVariantMap m;
        m.insert(QStringLiteral("id"), s.id);
        m.insert(QStringLiteral("status"), s.status);
        m.insert(QStringLiteral("note"), s.note);
        // серверная стадия несёт country_code/region/rtt — попап рисует «Сервер: [флаг] Страна · мс»
        const QString cc = s.data.value(QStringLiteral("country_code")).toString();
        if (!cc.isEmpty()) {
            m.insert(QStringLiteral("countryCode"), cc);
            m.insert(QStringLiteral("region"), s.data.value(QStringLiteral("region")).toString());
            m.insert(QStringLiteral("rttMs"), s.data.value(QStringLiteral("rtt_ms")).toInt(-1));
        }
        // волна UX 07-22: факты текущей ноды (вкладка «текущий сервер» в финале попапа)
        if (s.id == QLatin1String("connect")) {
            m.insert(QStringLiteral("dataFlows"),
                     s.data.value(QStringLiteral("data_flows")).toBool());
            if (s.data.contains(QStringLiteral("tunnel_icmp_ms")))
                m.insert(QStringLiteral("tunnelIcmpMs"),
                         s.data.value(QStringLiteral("tunnel_icmp_ms")).toInt(-1));
            if (s.data.contains(QStringLiteral("ep_icmp_ms")))
                m.insert(QStringLiteral("epIcmpMs"),
                         s.data.value(QStringLiteral("ep_icmp_ms")).toInt(-1));
            if (s.data.contains(QStringLiteral("ep_icmp_big")))
                m.insert(QStringLiteral("epIcmpBig"),
                         s.data.value(QStringLiteral("ep_icmp_big")).toBool());
        }
        // per-нода факты обзора альтернатив — вкладки по серверам в финале попапа
        if (s.id == QLatin1String("altnodes") && s.data.contains(QStringLiteral("details")))
            m.insert(QStringLiteral("details"),
                     s.data.value(QStringLiteral("details")).toArray().toVariantList());
        out.append(m);
    }
    return out;
}

// ---- AVPN upstream nodes (plan provider-pool v2, lane L1) ---------------------------------------------

void AvpnEngineQml::startUpstreamVerification()
{
    const int epoch = ++m_verifyEpoch;
    m_whoamiTiebreak = false;
    m_upstreamFallbackVerify = false;
    m_verifyClock.start();
    m_verifyAttempts = 0;
    m_upstreamVerifyAttempts = 0;
    m_lastVerifyRxProof = false;
    m_busy = true;
    m_pathCheck = QStringLiteral("checking");
    qInfo() << "[avpn upstream] tunnel up on" << m_engine.currentNodeId() << "- checking the data path";
    // The same first-attempt delay as the other checks: routes/DNS of a fresh tunnel settle.
    QTimer::singleShot(800, this, [this, epoch]() { upstreamVerifyAttempt(epoch); });
}

void AvpnEngineQml::upstreamVerifyAttempt(int epoch)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying() || m_lastTunnelState != Vpn::Connected)
        return;
    const int budget = m_engine.dataCheckMs();
    const qint64 left = budget - m_verifyClock.elapsed();
    // Lab 14.11 D3: the poll is also the clock of the seat confirmation's short early retries (the lease
    // owner's due work, normally on the 4 s health tick) - this loop's epoch and budget, no timer of its own.
    m_tunnel.upstreamTick();
    const avpn::UpstreamProbeGrant grant = m_tunnel.upstreamProbeGrant();
    constexpr int kGrantPollMs = 300;
    switch (avpn::decideUpstreamVerifyRoute(grant.present, m_tunnel.upstreamProvisionalPending(), left - kGrantPollMs)) {
    case avpn::UpstreamVerifyRoute::WaitForGrant:
        // A provisional session: the seat (and with it the scan token) arrives through the tunnel.
        QTimer::singleShot(kGrantPollMs, this, [this, epoch]() { upstreamVerifyAttempt(epoch); });
        return;
    case avpn::UpstreamVerifyRoute::Fallback204:
        // Older server (no probe grant): the generate_204 + rx-proof loop of this same epoch and budget;
        // finishVerify turns its result into Unverifiable / NoData (upstreamFallbackVerdict).
        reliabilityEvent(QStringLiteral("upstream_verify fallback=generate_204 node=%1").arg(m_engine.currentNodeId()));
        m_upstreamFallbackVerify = true;
        verifyAttempt(epoch);
        return;
    case avpn::UpstreamVerifyRoute::Probe:
        break;
    }
    if (left <= 0 || !m_tunnel.upstreamClient()) {
        avpn::UpstreamVerdictResult v;
        v.reason = QStringLiteral("budget");
        finishUpstreamVerify(epoch, v, QStringLiteral("budget_spent"));
        return;
    }
    ++m_upstreamVerifyAttempts;
    QByteArray nonce;
    for (int i = 0; i < 4; ++i)
        nonce += QByteArray::number(QRandomGenerator::system()->generate(), 16).rightJustified(8, '0');
    avpn::UpstreamLeaseClient::ProbeRequest pr;
    pr.base = m_tunnel.upstreamTunnelApiBase();
    if (pr.base.isEmpty()) // older lease without tunnel_api_base: the alternate edge (never the Xray entry, R5)
        pr.base = avpn::whoamiBaseUrl(m_baseUrl, true, !qgetenv("AVPN_API_URL").isEmpty());
    pr.path = grant.path;
    pr.scanToken = grant.scanToken;
    pr.bytes = avpn::upstreamVerifyBytesTuned();
    pr.nonce = nonce;
    pr.profileId = m_tunnel.upstreamProfileId();
    pr.accessAsn = grant.accessAsn;
    pr.accessNetToken = grant.accessNetToken;
    const avpn::UpstreamCheckLimits limits;
    pr.timeoutMs = int(qMin<qint64>(left, limits.totalMs + 1000));
    m_tunnel.upstreamClient()->runProbe(pr, [this, epoch, grant, limits](const avpn::UpstreamProbeFacts &f) {
        if (epoch != m_verifyEpoch || !m_engine.isVerifying())
            return;
        const avpn::UpstreamCheckInput in =
            avpn::upstreamCheckInputFrom(f, grant, avpn::upstreamUnverifiableStrictTuned(), limits);
        const avpn::UpstreamVerdictResult v = avpn::judgeUpstreamCheck(in);
        m_lastUpstreamTtfbMs = int(f.ttfbMs);
        // Facts for the journal: codes and timings only - no host, token, address or lease id.
        const QString facts = QStringLiteral("http=%1 bytes=%2/%3 ms=%4 ttfb=%5 stall=%6 class=%7 asn_known=%8 attempt=%9")
                                  .arg(f.httpStatus).arg(f.bytesReceived).arg(f.bytesRequested).arg(f.elapsedMs)
                                  .arg(f.ttfbMs).arg(f.maxStallMs)
                                  .arg(f.egressClass.isEmpty() ? QStringLiteral("-") : f.egressClass.left(16))
                                  .arg(int(in.egressAsn > 0 && in.accessAsn > 0)).arg(m_upstreamVerifyAttempts);
        const qint64 leftNow = m_engine.dataCheckMs() - m_verifyClock.elapsed();
        // Lab 14.11 D3: a profile may refuse every connection in its first seconds - an attempt that got
        // nothing yet is retried inside this check's budget on a short growing spacing; a complete answer
        // (also a bad one: not through the provider, wrong digest) decides at once; when the budget is
        // spent the last outcome decides.
        const avpn::UpstreamEarlyRetry next =
            avpn::decideUpstreamEarlyRetry(avpn::upstreamProbeNotYet(f), m_upstreamVerifyAttempts - 1, leftNow);
        if (next.retry) {
            reliabilityEvent(QStringLiteral("upstream_verify_retry in_ms=%1 ").arg(next.delayMs) + facts);
            QTimer::singleShot(int(next.delayMs), this, [this, epoch]() { upstreamVerifyAttempt(epoch); });
            return;
        }
        finishUpstreamVerify(epoch, v, facts);
    });
}

void AvpnEngineQml::finishUpstreamVerify(int epoch, const avpn::UpstreamVerdictResult &v, const QString &facts)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying())
        return;
    const QString node = m_engine.currentNodeId();
    m_pathCheck = QLatin1String(avpn::upstreamVerdictName(v.verdict));
    reliabilityEvent(QStringLiteral("upstream_verdict verdict=%1 reason=%2 path=%3 node=%4 %5")
                         .arg(m_pathCheck, v.reason, v.pathReason.isEmpty() ? QStringLiteral("-") : v.pathReason, node,
                              facts));
    if (v.passes) {
        const avpn::TunnelStats st = m_tunnel.readStats();
        m_lastVerifyRxProof = st.valid && st.rxBytes > 0;
        m_lastVerifyTtfbMs = m_lastUpstreamTtfbMs;
        finishVerify(epoch, true);
        return;
    }
    // No data / not through the provider / strict unverifiable: the leg's no-data outcome.
    finishVerify(epoch, false, QStringLiteral("upstream %1 (failover)").arg(m_pathCheck));
}

// Upstream nodes (point 15, owner 15.11; UpstreamEngine.h::runUpstreamQuit): on aboutToQuit of the macOS GUI.
// The stop is the user's stop (stop(): intent off - no notice, the release with the final report, then the
// tunnel down; journal "guarded_stop why=user") plus one line "upstream session ended on app quit"; the event
// loop runs nested for at most kUpstreamQuitStopBoundMs, then the exit goes on regardless. A crash or a force
// kill never gets here: the seat is freed at TTL and the next start adopts the session by its lease record.
void AvpnEngineQml::endUpstreamSessionOnQuit()
{
#if AVPN_UPSTREAM_GUI_OWNER
    const bool tunnelUp = m_lastTunnelState != Vpn::Disconnected && m_lastTunnelState != Vpn::Unknown;
    const bool upstreamSession = tunnelUp && (m_engine.currentNodeIsUpstream() || m_tunnel.upstreamActive());
    QElapsedTimer clock;
    clock.start();
    avpn::UpstreamQuitHooks h;
    h.userStop = [this]() { stop(); };
    h.stopped = [this]() { return m_lastTunnelState == Vpn::Disconnected; };
    h.pump = [](int ms) {
        QEventLoop loop;
        QTimer::singleShot(ms, &loop, &QEventLoop::quit);
        loop.exec(QEventLoop::ExcludeUserInputEvents);
    };
    h.nowMs = [&clock]() { return clock.elapsed(); };
    h.journal = [this](const QString &line) { reliabilityEvent(line); };
    if (avpn::runUpstreamQuit(m_appExitKind, avpn::upstreamNodesEnabled(), upstreamSession, h))
        reliabilityEvent(QStringLiteral("upstream_quit_stop stopped=%1 ms=%2")
                             .arg(int(m_lastTunnelState == Vpn::Disconnected)).arg(clock.elapsed()));
#endif
}

void AvpnEngineQml::noticeUpstreamLeft(const QString &code)
{
    const QString text = upstreamNoticeText(avpn::upstreamNoticeFor(code));
    if (text.isEmpty())
        return;
    reliabilityEvent(QStringLiteral("upstream_notice code=%1").arg(code.section(QLatin1Char('/'), 0, 0)));
    QTimer::singleShot(0, this, [this, text]() { emit notice(text); });
}

void AvpnEngineQml::onUpstreamLeave(const QString &code, const QString &detail)
{
    const QString node = m_engine.currentNodeId();
    if (!m_engine.leaveUpstreamNode(code, detail))
        return; // not (any more) connected on an upstream node
    reliabilityEvent(QStringLiteral("upstream_leave code=%1 detail=%2 node=%3")
                         .arg(code, detail.isEmpty() ? QStringLiteral("-") : detail, node));
    ++m_verifyEpoch; // a check of the left session is over
    syncAttempt(); // the failover attempt of the owner walks on (or its result tells the person)
    if (m_wantConnected && m_engine.attemptRunning())
        noticeUpstreamLeft(code); // release A: moving on to the next node
    m_busy = m_engine.attemptRunning() || m_op != Op::None;
    emit changed();
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

void AvpnEngineQml::cancelSeatFirst()
{
    if (m_seatFirst.pending)
        reliabilityEvent(QStringLiteral("upstream_seat_first_dropped node=%1").arg(m_seatFirst.nodeId));
    m_seatFirst = avpn::UpstreamSeatFirst();
    m_tunnel.cancelUpstreamPrepare();
}

void AvpnEngineQml::onUpstreamPrepared(const QString &nodeId, quint64 prepareId, bool ok, const QString &code)
{
    switch (avpn::decideSeatFirstReply(m_seatFirst, nodeId, prepareId, m_intentSerial, ok)) {
    case avpn::SeatFirstStep::Ignore:
        return;
    case avpn::SeatFirstStep::Drop:
        cancelSeatFirst();
        return;
    case avpn::SeatFirstStep::Switch:
        // The ordinary pin restart from here (stop -> Disconnected -> start); up() brings the held seat up.
        m_seatFirst = avpn::UpstreamSeatFirst();
        reliabilityEvent(QStringLiteral("upstream_seat_first_ready node=%1").arg(nodeId));
        m_needsRestart = true;
        m_restartRequestedMs = QDateTime::currentMSecsSinceEpoch();
        m_restartOrigin = QStringLiteral("pin");
        emit changed();
        reconcile();
        return;
    case avpn::SeatFirstStep::Stay: {
        // The working tunnel was never touched: the node is out for this attempt, the pick is undone.
        const avpn::UpstreamSeatFirst p = m_seatFirst;
        m_seatFirst = avpn::UpstreamSeatFirst();
        reliabilityEvent(QStringLiteral("upstream_start_failed node=%1 code=%2 live_kept=1").arg(nodeId, code));
        QString err;
        if (p.prevPin.isEmpty())
            m_engine.clearPin();
        else if (!m_engine.setPinnedNode(p.prevPin, err))
            m_engine.clearPin();
        if (p.persistPin)
            persistPin();
        // S1 (device round 5): the tapped row's request ends here - it never reached the owner, the live tunnel stays
        if (m_exactRestoreArmed) {
            m_exactRestoreArmed = false;
            m_exactRow.clear();
            syncChoice();
        }
        endScanRowRequest(nodeId, "seat_first_failed");
        emit changed();
        return;
    }
    }
}

void AvpnEngineQml::noteUpstreamRevision(qint64 revision)
{
    if (m_scanner)
        m_scanner->noteUpstreamRevision(revision); // AVPN Scanner: stored manifests of an older revision go
    if (!avpn::upstreamRevisionNeedsRefresh(revision, m_engine.upstreamRevision(), m_upstreamRefreshAskedRev))
        return;
    m_upstreamRefreshAskedRev = revision;
    reliabilityEvent(QStringLiteral("upstream_revision moved: subscription refresh"));
    QTimer::singleShot(0, this, [this]() { refreshSubscription(); });
    maybeRefreshStandby("revision", /*force=*/true);
}

void AvpnEngineQml::applyUpstreamTunnelStatus(const QJsonObject &upstream)
{
    const avpn::UpstreamStatusDecision d =
        avpn::decideUpstreamStatus(upstream, qMax(m_engine.upstreamRevision(), m_upstreamRefreshAskedRev));
    if (!d.valid)
        return;
    if (d.refreshRevision > 0)
        noteUpstreamRevision(d.refreshRevision);
    if (d.configChanged)
        reliabilityEvent(QStringLiteral("upstream_config_changed node=%1").arg(m_engine.currentNodeId()));
    if (!d.leaveCode.isEmpty()) {
        const QString code = d.leaveCode;
        QTimer::singleShot(0, this, [this, code]() { onUpstreamLeave(code); });
    }
}

QString AvpnEngineQml::upstreamNetworkKeyNow() const
{
    // With our tunnel up the platform reports the tunnel's medium (macOS utun, iOS Wi-Fi as cellular):
    // the key of the last fetch made with the tunnel down is the honest one then.
    if (m_lastTunnelState != Vpn::Disconnected && m_lastTunnelState != Vpn::Unknown)
        return m_standbyNetKey.isEmpty() ? QStringLiteral("unknown") : m_standbyNetKey;
    return avpn::upstreamNetworkKey(doctorNetType(), diagCarrierAuto(), avpn::cellularGeneration(),
                                    m_accessAsnByNet.value(m_engine.network().local));
}

void AvpnEngineQml::loadStandbyPackFromDisk()
{
    avpn::UpstreamLeaseClient *client = m_tunnel.upstreamClient();
    if (!client || !avpn::upstreamNodesEnabled())
        return;
    avpn::StandbyStored st;
    if (!avpn::UpstreamLeaseClient::loadStandby(st)) {
        m_tunnel.setStandbyPack(std::nullopt);
        m_standbyEntries = -1;
        return;
    }
    const avpn::StandbyParse p = avpn::parseStandbyPack(st.body, st.sigB64, client->publicKeyHex());
    if (!p.ok()) {
        reliabilityEvent(QStringLiteral("upstream_standby_load refused=%1").arg(p.code()));
        m_tunnel.setStandbyPack(std::nullopt);
        m_standbyEntries = -1;
        return;
    }
    m_tunnel.setStandbyPack(p.pack); // the age is judged at every bring-up (standbyCandidateFor)
    m_standbyEntries = int(p.pack.entries.size());
    m_standbyFetchedWallMs = st.fetchedWallMs;
    m_standbyNetKey = st.networkKey;
    syncStandbyCandidates();
}

void AvpnEngineQml::syncStandbyCandidates()
{
    const std::optional<avpn::StandbyPack> &pack = m_tunnel.standbyPack();
    QList<avpn::SubscriptionNode> c;
    if (pack && avpn::upstreamNodesEnabled())
        c = avpn::standbyPackCandidates(*pack, m_engine.subscriptionNodes(), m_engine.upstreamRevision(),
                                        QDateTime::currentMSecsSinceEpoch(), avpn::upstreamStandbyMaxAgeSTuned());
    // contract 1.14.0: the Scanner's offered profiles join the pool (pin / connect); Auto does not start them itself
    if (avpn::upstreamNodesEnabled())
        for (const avpn::SubscriptionNode &n : m_engine.scanOfferedNodes()) {
            bool dup = false;
            for (const avpn::SubscriptionNode &o : std::as_const(c))
                dup = dup || o.nodeId == n.nodeId;
            if (!dup)
                c << n;
        }
    m_engine.setStandbyCandidates(c);
}

void AvpnEngineQml::maybeRefreshStandby(const char *why, bool force)
{
    if (!avpn::upstreamNodesEnabled() || !m_configSvc || !m_configSvc->isFresh())
        return;
    avpn::UpstreamLeaseClient *client = m_tunnel.upstreamClient();
    if (!client || client->standbyInFlight() || authToken().isEmpty())
        return;
    // "While the API is reachable" and not through a provider: no fetch during an upstream session or
    // while our own start/stop is in flight (its transitions abort running requests anyway).
    if (m_engine.currentNodeIsUpstream() || m_op != Op::None)
        return;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 intervalMs = qint64(avpn::upstreamStandbyRefreshSTuned()) * 1000;
    // Server limit 12/h per device: a failed attempt waits 5 min, even a forced one 1 min.
    const qint64 sinceTry = m_standbyLastTryWallMs > 0 ? now - m_standbyLastTryWallMs : -1;
    if (!force) {
        if (m_standbyFetchedWallMs > 0 && now - m_standbyFetchedWallMs >= 0 && now - m_standbyFetchedWallMs < intervalMs)
            return;
        if (sinceTry >= 0 && sinceTry < 300000)
            return;
    } else if (sinceTry >= 0 && sinceTry < 60000) {
        return;
    }
    m_standbyLastTryWallMs = now;
    const QString key = upstreamNetworkKeyNow();
    const QString reason = QLatin1String(why);
    client->fetchStandby(key, [this, key, reason](int status, const QByteArray &body, const QByteArray &sig) {
        avpn::UpstreamLeaseClient *c = m_tunnel.upstreamClient();
        if (!c)
            return;
        if (status == 200) {
            const avpn::StandbyParse p = avpn::parseStandbyPack(body, sig, c->publicKeyHex());
            if (!p.ok()) {
                reliabilityEvent(QStringLiteral("upstream_standby refused=%1 detail=%2").arg(p.code(), p.detail.left(32)));
                return;
            }
            avpn::StandbyStored st;
            st.body = body;
            st.sigB64 = sig;
            st.networkKey = key;
            st.fetchedWallMs = QDateTime::currentMSecsSinceEpoch();
            avpn::UpstreamLeaseClient::saveStandby(st);
            m_standbyFetchedWallMs = st.fetchedWallMs;
            m_standbyEntries = int(p.pack.entries.size());
            m_standbyNetKey = key;
            m_tunnel.setStandbyPack(p.pack);
            syncStandbyCandidates();
            reliabilityEvent(QStringLiteral("upstream_standby entries=%1 net=%2 why=%3").arg(m_standbyEntries).arg(key, reason));
            if (avpn::upstreamRevisionNeedsRefresh(p.pack.upstreamRevision, m_engine.upstreamRevision(), m_upstreamRefreshAskedRev)) {
                m_upstreamRefreshAskedRev = p.pack.upstreamRevision;
                QTimer::singleShot(0, this, [this]() { refreshSubscription(); });
            }
            return;
        }
        if (status == 403 || status == 410) {
            // Not entitled / over quota: no standby start for this device - drop the pack.
            avpn::UpstreamLeaseClient::clearStandby();
            m_tunnel.setStandbyPack(std::nullopt);
            m_standbyEntries = -1;
            syncStandbyCandidates();
        }
        reliabilityEvent(QStringLiteral("upstream_standby http=%1 why=%2").arg(status).arg(reason));
    });
}

} // namespace avpn
