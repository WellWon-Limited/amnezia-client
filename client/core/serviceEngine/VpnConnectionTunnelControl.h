// AVPN serviceEngine — УНИВЕРСАЛЬНАЯ реализация ITunnelControl поверх VpnConnection.
// VpnConnection уже скрывает desktop-daemon / iOS-NE / Android за #ifdef → ОДИН адаптер на все платформы.
// [IN-FORK BUILD] зависит от типов форка (VpnConnection, DockerContainer) — компилируется в сборке приложения.
#pragma once

#include "AwgConfigBuilder.h"
#include "ITunnelControl.h"
#include "UpstreamLeaseOwner.h"   // AVPN upstream nodes: the app-side lease owner (pure)
#include "UpstreamStandbyPack.h"

#include "core/utils/containerEnum.h" // AVPN awg31-xray-v1: DockerContainer по proto ноды (unscoped enum — форвард невозможен)

#include <QObject>
#include <QJsonObject>

#include <functional>
#include <optional>

class VpnConnection;               // forward (vpnConnection.h в форке)
class SecureAppSettingsRepository; // forward (core/repositories) — RU-direct-гейт в up()
class QTimer;
class QNetworkAccessManager;

namespace avpn {

class UpstreamLeaseClient;

class VpnConnectionTunnelControl : public QObject, public ITunnelControl {
    Q_OBJECT
public:
    explicit VpnConnectionTunnelControl(VpnConnection *conn, QObject *parent = nullptr);

    // Ключи из Identity (приватный — из Keychain; на бэкенд не уходит).
    void setClientKeys(const ClientKeys &keys) { m_keys = keys; }

    // AVPN RU-direct: репозиторий настроек для гейта сплита ПО ФАКТИЧЕСКОЙ ноде в up() (см. .cpp).
    // Сев списка CIDR остаётся в AvpnEngineQml::applyRuBypassSplit; здесь — только вкл/выкл флага.
    void setStore(SecureAppSettingsRepository *store) { m_appStore = store; }

    // up: построить конфиг и вызвать connectToVpn (async; фактический исход — через connectionStateChanged,
    // его слушает ServiceEngine). Возвращает success(), если вызов поставлен в очередь.
    // AVPN awg31-xray-v1: диспетчер по proto ноды — awg (AwgConfigBuilder, DockerContainer::Awg) /
    // xray (XrayConfigBuilder, DockerContainer::Xray); на Apple перед NE незнакомые wg-quick ключи
    // вырезаются (awg-apple 3.1.4 бросает invalidLine).
    TunnelResult up(const Subscription &sub, const SubscriptionNode &node) override;

    // TODO(оптимизация in-place): desktop — switchServer (держать gateway/device const); iOS — слать
    // wg-quick через sendProviderMessage→WireGuardAdapter.update; Android — новый JNI awgSetConfig (см. README).

    // readStats: rx/tx из bytesChanged; latestHandshakeEpoch — из платформенного сигнала handshakeChanged.
    //   iOS:     IosController::checkStatus парсит UAPI last_handshake_time_sec → handshakeChanged.
    //   Android: GoBackend.awgGetConfig → Statistics.lastHandshakeSec → JNI onStatisticsUpdate → handshakeUpdated.
    //   desktop: handshake живёт в daemon (getPeerStatus), в наш адаптер не доходит → HealthLoop на rx/tx.
    //   AVPN awg31-xray-v1, xray: handshake не существует (эпоха 0 = «неизвестно», НЕ сеется на
    //   Connected); rx/tx — iOS: bytesChanged NE (счётчики tun hev-socks5, этап D3); macOS-демон:
    //   поллинг IPC xrayRuntimeStatus (кумулятивы utun tun2socks, этап D2).
    TunnelStats readStats() override;

    // AVPN (BUG-4 auto-heal): ребайнд UDP-сокета живого туннеля (новый локальный порт = новый
    // 5-tuple flow). iOS/MACOS_NE — provider message "rebind" в NE (wgSetConfig listen_port=0);
    // macOS-демон — {"type":"rebind"} его локальным протоколом (fire-and-forget, старый демон
    // молча игнорирует). Android/Win — примитива нет, false (движок сразу уходит в failover).
    bool rebindSocket() override;

    void down() override;

    // Review E2 of 18.11: a marker through the VpnConnection thread ahead of the leg's connectToVpn (both queued
    // to that thread in order, so every event of the previous leg reaches the GUI thread before the marker).
    void beginNativeOp(quint64 leg) override;

    // AVPN bench v5 (tunnel.config): санитизированный снапшот ПОСЛЕДНЕГО реально ушедшего в
    // connectToVpn конфига (reportSummary + факты сева: split/split-DNS/dns-override). up() —
    // единственная точка каждого подъёма, поэтому снапшот всегда соответствует живому туннелю.
    // Пустой объект = туннель ещё не поднимали. Ключей/IP внутри нет by construction.
    QJsonObject lastConfigReport() const { return m_lastConfigReport; }

    // AVPN awg31-xray-v1: proto последнего up() ("awg"/"xray"; пусто = ещё не поднимали).
    QString lastUpProto() const { return m_lastUpProto; }

    // AVPN awg31-xray-v1 (независимое ревью волны, MINOR-4; §19 + §22.5): адопт ЖИВОГО xray-туннеля
    // после перезапуска GUI. Эта GUI-сессия туннель не поднимала ⇒ m_lastUpProto пуст ⇒ поллинг
    // статистики демона не стартовал бы, и HealthLoop остался бы слеп (rx/tx нули, «0 = неизвестно»
    // навсегда). Спрашиваем демона один раз: running ⇒ считаем текущий путь xray и запускаем
    // поллинг. macOS-демон; на прочих платформах — no-op (там адопт xray в этой волне не живёт).
    void adoptXrayIfRunning();

    // ---- Upstream nodes (plan provider-pool v2, lane L1: decisions A/B, points 6, 7, 9) ----
    // up() of an upstream stub never builds a config from the subscription: it acquires the seat lease
    // asynchronously (Connecting stays Connecting; the acquire's bound is below the reconcile watchdog),
    // verifies, sanitizes and binds the signed config, and only then calls connectToVpn. A start that
    // cannot happen (no seat, refused, bad answer, sanitizer refusal) is reported through the existing
    // path: startFailureSink(nodeId, code) (the engine excludes the node for the attempt) and then a
    // queued VpnConnection::setConnectionState(Error) - no new state anywhere.
    void configureUpstream(QNetworkAccessManager *nam, std::function<QString()> directBase,
                           const QString &pubKeyHex, std::function<QString()> token);
    void setUpstreamStartFailureSink(std::function<void(const QString &, const QString &)> sink)
    {
        m_upStartFailureSink = std::move(sink);
    }
    // The standby pack in force (validated by the facade; nullopt = none). Looked up at bring-up only.
    void setStandbyPack(const std::optional<StandbyPack> &pack) { m_standbyPack = pack; }
    const std::optional<StandbyPack> &standbyPack() const { return m_standbyPack; }
    UpstreamLeaseClient *upstreamClient() const { return m_leaseClient; }
    // The platform reported the tunnel of the current session up (facade, Connected): a provisional
    // session confirms its seat through the tunnel now.
    void upstreamTunnelUp();
    // The tunnel's stop is confirmed (the facade's Disconnected): the seat releases held for it go now.
    void upstreamTunnelDown(bool endsSession = true);
    // macOS: adoption of a live upstream session after a GUI restart (decision B, point 9). Called from
    // adoptXrayIfRunning; retryUpstreamAdoption asks the daemon again (the switch turned on later than the
    // startup probe: it is frozen off on a cached config).
    void adoptUpstreamFromRecord(qint64 daemonStartedAtWallMs);
    // Runs fn once the release sent by the last down() answered (or at once when none is pending) -
    // for a stop that bypasses down()'s own deferred disconnect (macOS adopted-without-protocol path).
    void runAfterUpstreamRelease(std::function<void()> fn);
    void retryUpstreamAdoption();
    // iOS (device round 24.11, C3): the engine adopted the live tunnel after a relaunch. When the session is THE provider start
    // the record names (node and start order, UpstreamEngine.h::upstreamHandedOverRecordMatches), the seat's owner is restored
    // handed over (the extension renews; the app releases after the confirmed stop). No-op elsewhere and when nothing matches.
    void adoptUpstreamSession();
    // The stub of the ADOPTED provider session (its record's, in the /v1/subscription node form; empty when no adopted session or
    // the record had none): the facade gives it to the engine so the adoption names the node even when the node is not in the
    // pool after the relaunch (a Scanner row, a standby-pack candidate - device round air-D 25.11, S2).
    QJsonObject adoptedUpstreamStub() const
    {
        return (m_upOwner.active() && m_upOwner.adopted()) ? m_upOwner.stubWire() : QJsonObject();
    }
    // Seat first (owner's iPhone 16.11, D4): the user picked provider node `node` while another node's tunnel works.
    // The seat is acquired now, through that live tunnel, and the profile checked by the connect's own rule; the
    // answer comes back as upstreamPrepared(nodeId, ok, code) and the facade switches only on ok. The next up() of
    // the node brings the held seat up; up() of anything else, cancelUpstreamPrepare() or the seat's first renewal
    // falling due releases it. A down() keeps it (it is the stop of the old tunnel before that up()).
    // Returns the prepare's identity (its answer carries it); 0 = not possible now (switched off, client not
    // configured, a provider session is live): the caller switches the old way.
    quint64 prepareUpstream(const Subscription &sub, const SubscriptionNode &node);
    void cancelUpstreamPrepare();
    bool upstreamRequestSent() const override { return m_upOwner.requestSent(); }
    void startRefused() override; // ITunnelControl: the native start never happened (Android permission refused)
    bool upstreamPreparing() const { return m_upOwner.preparing(); }
    // macOS GUI owner (decision B): the facade's existing tick drives renewals at upstreamWakeAtMs().
    void upstreamTick();
    qint64 upstreamWakeAtMs() const { return m_upOwner.wakeAtMs(); }
    bool upstreamActive() const { return m_upOwner.active(); }
    // The direct control plane answered (ConfigService reach became Reachable): kept seat releases go out on the direct route.
    void upstreamDirectRouteProved()
    {
        m_upOwner.directRouteProved(upstreamClockMs());
        noteSeatDebts();
    }
    // The ledger keeps something for a proof of the direct route and no start runs (UpstreamLeaseOwner::proofOwed): read by
    // ConfigService before every ask of the direct route (its proof-owed source).
    bool upstreamProofOwed() { return m_upOwner.proofOwed(upstreamClockMs()); }
    bool upstreamProvisionalPending() const { return m_upOwner.provisionalPending(); }
    QString upstreamNodeId() const { return m_upOwner.active() ? m_upOwner.nodeId() : QString(); }
    QString upstreamProfileId() const { return m_upOwner.active() ? m_upOwner.profileId() : QString(); }
    UpstreamProbeGrant upstreamProbeGrant() const { return m_upOwner.probeGrant(upstreamClockMs()); }
    QString upstreamLeaseId() const { return m_upOwner.leaseId(); }
    QString upstreamTunnelApiBase() const { return m_upOwner.tunnelApiBase(); }
    // Contract §5 status of the in-process owner (macOS) - debug snapshot and the same rules as iOS.
    QJsonObject upstreamStatus() const { return m_upOwner.statusJson(upstreamClockMs()); }
    // Milliseconds of a clock that keeps running while the device sleeps (contract §7): Darwin
    // clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW); elsewhere the boot-time clock of the platform.
    static qint64 upstreamClockMs();
    // The lease record for adoption after a GUI restart / an app relaunch (QSettings avpn/upstreamLease; no token): macOS and
    // Windows GUI owners, and iOS (keepRecord, C3 of 24.11).
    static constexpr const char *kUpstreamLeaseRecordKey = "avpn/upstreamLease";
    // The last start order (UpstreamLeaseWire.h::UpstreamSessionOrder): persisted so it only ever grows, across relaunches and
    // clock jumps backwards (contract 1.20.0: the server refuses an acquire whose order is behind the highest it has seen).
    static constexpr const char *kUpstreamSessionOrderKey = "avpn/upstreamSessionOrder";

signals:
    // The running upstream session must leave its node (lease terminal / no seat on re-acquire / seat
    // never confirmed). The facade leaves through the engine's dead-session path, deferred.
    // code = the stable reason (the server's terminal code, no_seat_reacquire, standby_unconfirmed, …);
    // detail = the server's optional reason (lease_gone shortly before expiry: the seat was taken; a
    // source over capacity) - switch log only.
    void upstreamLeaveRequested(const QString &code, const QString &detail);
    // A lease answer, a renewal or the status carried an upstream_revision newer than known.
    void upstreamRevisionSeen(qint64 revision);
    // Seam for the iOS bridge (contract §2): a provisional session's seat was granted through the tunnel;
    // the tunnel owner (the extension) must receive it as {"action":"upstream_lease_set","upstream_lease":…}.
    // Emitted only where the app does not own renewals (iOS / macOS NE).
    void upstreamLeaseHandover(const QJsonObject &upstreamLease);
    // macOS: a restarted GUI found the daemon's Xray tunnel and a record of this upstream node - the
    // facade identifies the engine's session by it (ServiceEngine::adoptTunnelConnected).
    void upstreamSessionAdopted(const QString &nodeId);
    // A direct acquire answered with the device's own access network facts (network key of the pack).
    void upstreamAccessFacts(qint64 accessAsn);
    // prepareUpstream's answer: ok = the seat is held and the profile passed the connect's check; else code =
    // the refusal (the lease code, transport, profile_<sanitizer code>) - the seat is already given back.
    void upstreamPrepared(const QString &nodeId, quint64 prepareId, bool ok, const QString &code);
    // upstreamProofOwed() is true after a step of the lease owner: the control plane is asked for a proof of the direct route
    // (ConfigService::noteProofOwed - rate-bounded there; emitted again on every such step, never by a timer).
    void upstreamRouteProofOwed();

private slots:
    void onBytesChanged(quint64 rx, quint64 tx);

private:
    bool invokeConnect(const QJsonObject &cfg, const QString &serverId, amnezia::DockerContainer container);
    TunnelResult upUpstream(const Subscription &sub, const SubscriptionNode &node);
    void applyUpstreamEvents(const QVector<UpstreamOwnerEvent> &events);
    void bringUpUpstream(const UpstreamOwnerEvent &e);
    void failUpstreamStart(const QString &code, const QString &detail = QString());
    void noteSeatDebts();
    int m_seatDebtsTold = 0; // seats owed by nonce as last written to the journal (noteSeatDebts; decides nothing)
    QString m_adoptMismatchTold; // the live session whose record mismatch was last written (adoptUpstreamSession; decides nothing)
#if AVPN_UPSTREAM_GUI_OWNER // macOS desktop; Windows since release C (UpstreamEngine.h)
    // AVPN awg31-xray-v1 (этап D2): статистика xray-пути демона — async QtRO-вызов xrayRuntimeStatus
    // по таймеру, пока поднят xray (кумулятивы rx/tx с подъёма сессии, §17.1). Без nested QEventLoop.
    void pollXrayRuntimeStatus();
    QTimer *m_xrayStatsTimer = nullptr;
#endif

    VpnConnection *m_conn = nullptr;
#if defined(Q_OS_ANDROID)
    quint64 m_startLeg = 0; // android2 V2: the leg of the start being sent (beginNativeOp -> invokeConnect)
#endif
    ClientKeys     m_keys;
    TunnelStats    m_stats;
    // AVPN (девайс-разбор 2026-09-02): текст причины, по которой ядро Xray не поднялось (iOS NE).
    QString        m_lastXrayStartFailure;
    QJsonObject    m_lastConfigReport; // AVPN bench v5: снапшот конфига последнего up()
    QString        m_lastUpProto;      // AVPN awg31-xray-v1: proto последнего подъёма
    quint64        m_statsSession = 0; // tunnel session of a statistics request (down / connect move it)
    ::SecureAppSettingsRepository *m_appStore = nullptr; // AVPN RU-direct: флаг сплита по факт-ноде
    // AVPN upstream nodes:
    UpstreamLeaseClient *m_leaseClient = nullptr;  // owned (QObject child)
    UpstreamLeaseOwner m_upOwner;
    SubscriptionNode m_upStub;                     // the stub of the session being brought up / running
    std::optional<StandbyPack> m_standbyPack;
    std::function<void(const QString &, const QString &)> m_upStartFailureSink;
};

} // namespace avpn
