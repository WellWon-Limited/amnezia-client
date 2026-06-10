// AVPN serviceEngine — УНИВЕРСАЛЬНАЯ реализация ITunnelControl поверх VpnConnection.
// VpnConnection уже скрывает desktop-daemon / iOS-NE / Android за #ifdef → ОДИН адаптер на все платформы.
// [IN-FORK BUILD] зависит от типов форка (VpnConnection, DockerContainer) — компилируется в сборке приложения.
#pragma once

#include "AwgConfigBuilder.h"
#include "ITunnelControl.h"

#include <QObject>
#include <QJsonObject>

class VpnConnection; // forward (vpnConnection.h в форке)

namespace avpn {

class VpnConnectionTunnelControl : public QObject, public ITunnelControl {
    Q_OBJECT
public:
    explicit VpnConnectionTunnelControl(VpnConnection *conn, QObject *parent = nullptr);

    // Ключи из Identity (приватный — из Keychain; на бэкенд не уходит).
    void setClientKeys(const ClientKeys &keys) { m_keys = keys; }

    // up: построить конфиг и вызвать connectToVpn (async; фактический исход — через connectionStateChanged,
    // его слушает ServiceEngine). Возвращает success(), если вызов поставлен в очередь.
    TunnelResult up(const Subscription &sub, const SubscriptionNode &node) override;

    // applyPeer (MVP): «быстрый reconnect» = down + up с новым узлом. На стабильном /32 адрес tun не меняется.
    // TODO(оптимизация in-place): desktop — switchServer (держать gateway/device const); iOS — слать
    // wg-quick через sendProviderMessage→WireGuardAdapter.update; Android — новый JNI awgSetConfig (см. README).
    TunnelResult applyPeer(const Subscription &sub, const SubscriptionNode &node) override;

    // readStats: rx/tx из bytesChanged. latestHandshake на этом слое не отдаётся — для DEAD-детекта
    // по handshake нужен платформенный status (desktop getStatus / iOS checkStatus / android getLastHandshake).
    TunnelStats readStats() override;

    void down() override;

private slots:
    void onBytesChanged(quint64 rx, quint64 tx);

private:
    bool invokeConnect(const QJsonObject &cfg, const QString &serverId);

    VpnConnection *m_conn = nullptr;
    ClientKeys     m_keys;
    TunnelStats    m_stats;
};

} // namespace avpn
