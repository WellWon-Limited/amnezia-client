// AVPN serviceEngine — УНИВЕРСАЛЬНАЯ реализация ITunnelControl поверх VpnConnection.
// VpnConnection уже скрывает desktop-daemon / iOS-NE / Android за #ifdef → ОДИН адаптер на все платформы.
// [IN-FORK BUILD] зависит от типов форка (VpnConnection, DockerContainer) — компилируется в сборке приложения.
#pragma once

#include "AwgConfigBuilder.h"
#include "ITunnelControl.h"

#include "core/utils/containerEnum.h" // AVPN awg31-xray-v1: DockerContainer по proto ноды (unscoped enum — форвард невозможен)

#include <QObject>
#include <QJsonObject>

class VpnConnection;               // forward (vpnConnection.h в форке)
class SecureAppSettingsRepository; // forward (core/repositories) — RU-direct-гейт в up()
class QTimer;

namespace avpn {

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

    // applyPeer (MVP): «быстрый reconnect» = down + up с новым узлом. На стабильном /32 адрес tun не меняется.
    // TODO(оптимизация in-place): desktop — switchServer (держать gateway/device const); iOS — слать
    // wg-quick через sendProviderMessage→WireGuardAdapter.update; Android — новый JNI awgSetConfig (см. README).
    TunnelResult applyPeer(const Subscription &sub, const SubscriptionNode &node) override;

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

private slots:
    void onBytesChanged(quint64 rx, quint64 tx);

private:
    bool invokeConnect(const QJsonObject &cfg, const QString &serverId, amnezia::DockerContainer container);
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN awg31-xray-v1 (этап D2): статистика xray-пути демона — async QtRO-вызов xrayRuntimeStatus
    // по таймеру, пока поднят xray (кумулятивы rx/tx с подъёма сессии, §17.1). Без nested QEventLoop.
    void pollXrayRuntimeStatus();
    QTimer *m_xrayStatsTimer = nullptr;
#endif

    VpnConnection *m_conn = nullptr;
    ClientKeys     m_keys;
    TunnelStats    m_stats;
    // AVPN (девайс-разбор 2026-09-02): текст причины, по которой ядро Xray не поднялось (iOS NE).
    QString        m_lastXrayStartFailure;
    QJsonObject    m_lastConfigReport; // AVPN bench v5: снапшот конфига последнего up()
    QString        m_lastUpProto;      // AVPN awg31-xray-v1: proto последнего подъёма
    ::SecureAppSettingsRepository *m_appStore = nullptr; // AVPN RU-direct: флаг сплита по факт-ноде
};

} // namespace avpn
