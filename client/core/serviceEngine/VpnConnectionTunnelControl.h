// AVPN serviceEngine — УНИВЕРСАЛЬНАЯ реализация ITunnelControl поверх VpnConnection.
// VpnConnection уже скрывает desktop-daemon / iOS-NE / Android за #ifdef → ОДИН адаптер на все платформы.
// [IN-FORK BUILD] зависит от типов форка (VpnConnection, DockerContainer) — компилируется в сборке приложения.
#pragma once

#include "AwgConfigBuilder.h"
#include "ITunnelControl.h"

#include <QObject>
#include <QJsonObject>

class VpnConnection;               // forward (vpnConnection.h в форке)
class SecureAppSettingsRepository; // forward (core/repositories) — RU-direct-гейт в up()

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
    TunnelResult up(const Subscription &sub, const SubscriptionNode &node) override;

    // applyPeer (MVP): «быстрый reconnect» = down + up с новым узлом. На стабильном /32 адрес tun не меняется.
    // TODO(оптимизация in-place): desktop — switchServer (держать gateway/device const); iOS — слать
    // wg-quick через sendProviderMessage→WireGuardAdapter.update; Android — новый JNI awgSetConfig (см. README).
    TunnelResult applyPeer(const Subscription &sub, const SubscriptionNode &node) override;

    // readStats: rx/tx из bytesChanged; latestHandshakeEpoch — из платформенного сигнала handshakeChanged.
    //   iOS:     IosController::checkStatus парсит UAPI last_handshake_time_sec → handshakeChanged.
    //   Android: GoBackend.awgGetConfig → Statistics.lastHandshakeSec → JNI onStatisticsUpdate → handshakeUpdated.
    //   desktop: handshake живёт в daemon (getPeerStatus), в наш адаптер не доходит → HealthLoop на rx/tx.
    TunnelStats readStats() override;

    void down() override;

    // AVPN bench v5 (tunnel.config): санитизированный снапшот ПОСЛЕДНЕГО реально ушедшего в
    // connectToVpn конфига (reportSummary + факты сева: split/split-DNS/dns-override). up() —
    // единственная точка каждого подъёма, поэтому снапшот всегда соответствует живому туннелю.
    // Пустой объект = туннель ещё не поднимали. Ключей/IP внутри нет by construction.
    QJsonObject lastConfigReport() const { return m_lastConfigReport; }

private slots:
    void onBytesChanged(quint64 rx, quint64 tx);

private:
    bool invokeConnect(const QJsonObject &cfg, const QString &serverId);

    VpnConnection *m_conn = nullptr;
    ClientKeys     m_keys;
    TunnelStats    m_stats;
    QJsonObject    m_lastConfigReport; // AVPN bench v5: снапшот конфига последнего up()
    ::SecureAppSettingsRepository *m_appStore = nullptr; // AVPN RU-direct: флаг сплита по факт-ноде
};

} // namespace avpn
