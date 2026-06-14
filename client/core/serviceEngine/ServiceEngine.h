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

    // AVPN (live-node picker): ручной выбор/ротация поверх авто-логики.
    //  setPinnedNode(nodeId) — «Выбрать»: только закрепляет узел (m_pinnedNodeId=nodeId), НЕ коннектит.
    //    Модель «выбор = задать цель, коннект — кнопкой»: следующий connect() (orb «Connect») поднимет
    //    закреплённую ноду. Тиар-даун текущего туннеля (если был онлайн другой узел) делает мост
    //    (AvpnEngineQml::switchToNode), чтобы избежать back-to-back up() без down() (iOS-storm).
    //  rotateNext() — round-robin по живым нодам (сортировка weight↓/health↓/nodeId↑), круговой индекс
    //    от текущей → следующая (заворот). Кнопка «Обновить подключение». 2 узла → пинг-понг.
    //  pinnedNodeId() — закреплённая пользователем нода (пусто = авто).
    // Возвращают true при успешном свитче/старте; false + error — нет такой/живой ноды или провал.
    bool setPinnedNode(const QString &nodeId, QString &error); // AVPN (был switchToNode: коннектил сам)
    bool rotateNext(QString &error);                          // AVPN
    QString pinnedNodeId() const { return m_pinnedNodeId; }   // AVPN
    // AVPN: снять закрепление (вернуться в авто). «Авто (быстрейший)» (reprobe) и ручная ротация
    // (rotateNext) снимают pin — иначе connect() всегда отдаёт приоритет закреплённой ноде, и
    // возврат-в-авто / offline-ротация молча ломаются (reselect закреплённой).
    void clearPin() { m_pinnedNodeId.clear(); }               // AVPN

    // AVPN: правдивый статус. up() ставит туннель в очередь (async), поэтому connect() остаётся в
    // Connecting; реальные переходы прилетают из VpnConnection::connectionStateChanged через
    // AvpnEngineQml. Вызывать ТОЛЬКО из onConnectionStateChanged (enum-free, без зависимости на Vpn::).
    //  onTunnelConnected()    — туннель реально поднялся (Connecting/Switching → Connected).
    //  onTunnelError()        — туннель упал с ошибкой (любая фаза → Error).
    //  onTunnelDisconnected() — туннель отключился (Connected/… → Disconnected, без свитча).
    // Возвращают true, если фаза изменилась (вызывающий шлёт changed()).
    bool onTunnelConnected();
    bool onTunnelError();
    bool onTunnelDisconnected();

    // AVPN: пользователь нажал «стоп». Помечаем НАМЕРЕННОЕ отключение (state→Disconnected,
    // сбрасываем текущую ноду) ДО m_tunnel.down(), иначе прилетевший Disconnected уйдёт в
    // notifyConnectionLost()→onDead()→switchTo() и туннель переподнимется сразу после стопа.
    void requestStop();

    // Полный flow «одной кнопки» (in-fork): enroll (если нет токена) → GET /v1/subscription → load → connect.
    // store/nam — из приложения; baseUrl — control plane. nowEpoch — для health/snapshot.
    bool startFlow(QNetworkAccessManager *nam, const QString &baseUrl,
                   SecureAppSettingsRepository *store, QString &error);

    // AVPN: «тихий» bootstrap при старте приложения (Task 11) — наполнить подписку ДО первого Connect,
    // чтобы бейдж ГБ/дней/subActive был живой сразу. Шаги: токен из хранилища (иначе enroll) →
    // GET /v1/subscription → loadSubscription. БЕЗ connect() (туннель не поднимаем). Состояние движка
    // НЕ трогаем (остаётся Disconnected). Возвращает true, если подписка наполнена; false + error —
    // при оффлайне/отсутствии токена (вызывающий трактует мягко, это не фатальная ошибка).
    bool bootstrap(QNetworkAccessManager *nam, const QString &baseUrl,
                   SecureAppSettingsRepository *store, QString &error);

    QStringList switchLog() const { return m_switchLog; }
    TunnelStats currentStats() const { return m_tunnel ? m_tunnel->readStats() : TunnelStats{}; }

    // Ключи клиента (zero-knowledge) — фасад прокидывает их в туннель-адаптер до connect.
    bool identityEnsureKeys(SecureAppSettingsRepository *store, QString &error)
    {
        return m_identity.ensureKeys(store, error);
    }
    ClientKeys clientKeys() const { return m_identity.keys(); }
    // AVPN: доступ к Identity для in-fork сетевых вызовов фасада (redeem по коду — Enrollment::redeemCode).
    Identity &identity() { return m_identity; }

private:
    // tunnelStillUp=true (health-DEAD из tick — туннель ещё «поднят») → down()→ждём Disconnected→up();
    // false (failover из реального Disconnected/Error — туннель уже опущен) → up() сразу.
    bool onDead(bool tunnelStillUp); // выбрать кандидата (исключая текущую) и переключиться

    // AVPN (live-node picker): backend-фолбэк выбор по max weight среди ЖИВЫХ нод, исключая exclA/exclB
    // (мёртвая/текущая). Живой = health-агрегат > 0; пустой health = живой (бэкенд провижинит живыми).
    // Не делает I/O (в отличие от Selector::pick) — чистый выбор по данным подписки. nullptr = нет.
    const SubscriptionNode *pickByWeight(const QString &exclA, const QString &exclB) const; // AVPN

    // AVPN (фикс iOS-шторма свитча): двухфазный секвенс-свитч. requestSwitch ставит m_state=Switching
    // (→ transient Disconnected/Error от down() НЕ запускает failover) и: при tunnelUp — down(), ждём
    // реальный Disconnected (onTunnelDisconnected→continuePendingSwitch→up); при !tunnelUp — up() сразу.
    // НЕЛЬЗЯ up() сразу после down() на iOS (NEVPNManager «Operation Cancelled»). reason — для switchLog.
    bool requestSwitch(const QString &targetNodeId, bool tunnelUp, const QString &reason); // AVPN
    bool continuePendingSwitch(); // AVPN: поднять up() на отложенную целевую ноду (туннель уже опущен)

    Identity      m_identity;
    NodePool      m_pool;
    Selector      m_selector;
    Switcher      m_switcher;
    HealthLoop    m_health;
    ITunnelControl *m_tunnel = nullptr;
    EngineState   m_state = EngineState::Disconnected;
    QString       m_currentNodeId;
    QString       m_pinnedNodeId; // AVPN: закреплённая пользователем нода (switchToNode); пусто = авто
    QString       m_pendingSwitchNodeId; // AVPN: целевая нода во время двухфазного свитча (пусто = нет)
    QString       m_pendingSwitchReason; // AVPN: причина для switchLog (pinned/rotate/dead)
    QString       m_token;
    QString       m_accountId;
    QStringList   m_switchLog;
};

} // namespace avpn
