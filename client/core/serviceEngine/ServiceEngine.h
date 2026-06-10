// AVPN serviceEngine — оркестратор сервисной модели поверх движка Amnezia. [СКАФФОЛД C-1]
// Overlay: НЕ часть апстрима. Интеграция в UI/туннель — через тонкие адаптеры, см. README.md.
// TODO: сделать QObject в фоновом QThread (как VpnConnection), когда подключим к приложению.
#pragma once

#include "DebugSnapshot.h"
#include "Enrollment.h"
#include "HealthLoop.h"
#include "ITunnelControl.h"
#include "Identity.h"
#include "NodePool.h"
#include "Selector.h"
#include "Switcher.h"
#include "dto/Subscription.h"

#include <QByteArray>
#include <QString>

namespace avpn {

enum class EngineState { Disconnected, Selecting, Connecting, Connected, Switching, Error };

class ServiceEngine {
public:
    ServiceEngine() : m_switcher(nullptr) {}

    // Платформенный туннель-адаптер (владение — у вызывающего).
    void setTunnel(ITunnelControl *tunnel) { m_tunnel = tunnel; m_switcher = Switcher(tunnel); }

    // Первый вход: genkey (Identity, reuse форка) → POST /v1/trial → сохранить токен. [IN-FORK]
    // store/nam отдаёт приложение (SecureAppSettingsRepository, amnApp->networkManager()).
    bool enroll(QNetworkAccessManager *nam, const QString &baseUrl,
                SecureAppSettingsRepository *store, QString &error);
    QString subscriptionToken() const { return m_token; }

    // Загрузить подписку (тело GET /v1/subscription). Заполняет NodePool. false + error при провале.
    bool loadSubscription(const QByteArray &json, QString &error);

    // Список не-фатальных проблем текущей подписки (см. SubscriptionParser::validate).
    QStringList subscriptionIssues() const;

    // Подключиться: выбрать ноду и поднять туннель. [СКАФФОЛД: выбор=первый, реальный скоринг в C-4]
    bool connect(QString &error);

    EngineState state() const { return m_state; }
    DebugSnapshot debugSnapshot() const;

    // C-5 health-loop:
    //  tick() — периодический (QTimer 3–5с в in-fork обвязке): читает stats, кормит HealthLoop,
    //           при DEAD → onDead() (свитч на лучшего кандидата, исключая мёртвую ноду).
    //  notifyConnectionLost() — реактивный: дёргать из onConnectionStateChanged при неожиданном
    //           Error/Disconnected, пока state==Connected → немедленный свитч.
    //  Возвращают true, если произошёл свитч/обработка DEAD.
    bool tick(qint64 nowEpoch);
    bool notifyConnectionLost();
    QString currentNodeId() const { return m_currentNodeId; }

    // Полный flow «одной кнопки» (in-fork): enroll (если нет токена) → GET /v1/subscription → load → connect.
    // store/nam — из приложения; baseUrl — control plane. nowEpoch — для health/snapshot.
    bool startFlow(QNetworkAccessManager *nam, const QString &baseUrl,
                   SecureAppSettingsRepository *store, QString &error);

    QStringList switchLog() const { return m_switchLog; }
    TunnelStats currentStats() const { return m_tunnel ? m_tunnel->readStats() : TunnelStats{}; }

    // Ключи клиента (zero-knowledge) — фасад прокидывает их в туннель-адаптер до connect.
    bool identityEnsureKeys(SecureAppSettingsRepository *store, QString &error)
    {
        return m_identity.ensureKeys(store, error);
    }
    ClientKeys clientKeys() const { return m_identity.keys(); }

private:
    bool onDead(); // выбрать кандидата (исключая текущую) и переключиться

    Identity      m_identity;
    NodePool      m_pool;
    Selector      m_selector;
    Switcher      m_switcher;
    HealthLoop    m_health;
    ITunnelControl *m_tunnel = nullptr;
    EngineState   m_state = EngineState::Disconnected;
    QString       m_currentNodeId;
    QString       m_token;
    QString       m_accountId;
    QStringList   m_switchLog;
};

} // namespace avpn
