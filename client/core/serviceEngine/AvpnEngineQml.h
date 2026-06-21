// AVPN serviceEngine — тонкий QObject-фасад движка для QML (context property "AvpnEngine").
// Владеет ServiceEngine + VpnConnectionTunnelControl; гоняет health-tick (QTimer) и слушает
// VpnConnection::connectionStateChanged (реактивный failover). Конвертит DebugSnapshot → QVariantMap
// для PageDiagnostics.qml. Overlay: апстрим не трогаем, только публичные API форка. [IN-FORK build]
#pragma once

#include "ServiceEngine.h"
#include "SignalQuality.h"   // AVPN: RTT→0..5 баров (EWMA+гистерезис)
#include "VpnConnectionTunnelControl.h"

#include "core/protocols/vpnProtocol.h" // AVPN: Vpn::ConnectionState
#include "core/utils/errorCodes.h"      // AVPN: amnezia::ErrorCode

#include <QHash>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

class VpnConnection;
class SecureAppSettingsRepository;
class QNetworkAccessManager;

namespace avpn {

class QualityProbe; // AVPN: app-layer RTT-проба через туннель (QualityProbe.h)
class ServiceProbe; // AVPN: проба доступности сервисов (Telegram/YouTube) через туннель (ServiceProbe.h)
class IRttProbe;    // AVPN (выбор по скорости): прямой RTT до нод off-tunnel (IRttProbe.h / RttProbeIcmp)

class AvpnEngineQml : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    // AVPN: статус подписки для бейджа Connect (читается из загруженной Subscription через движок).
    Q_PROPERTY(int daysLeft READ daysLeft NOTIFY changed)
    Q_PROPERTY(qlonglong trafficUsed READ trafficUsed NOTIFY changed)
    Q_PROPERTY(qlonglong trafficLimit READ trafficLimit NOTIFY changed)
    Q_PROPERTY(bool subActive READ subActive NOTIFY changed)
    // AVPN: JWT подписки — для авторизованного редиректа в кабинет (кнопка «Обновить ключ»).
    Q_PROPERTY(QString authToken READ authToken NOTIFY changed)
    // AVPN: реальные серверы (вместо хардкода). currentNode = {region,endpoint,ip,connected,hasNode};
    // nodePool = список нод [{nodeId,region,endpoint,...}] из живой подписки.
    Q_PROPERTY(QVariantMap currentNode READ currentNode NOTIFY changed)
    Q_PROPERTY(QVariantList nodePool READ nodePool NOTIFY changed)
    // AVPN (live-node picker): Pro-гейт-заглушка. Сейчас всегда true (trial выбирает уже сейчас);
    // позже выбор сервера гейтится этим одним флагом. CONSTANT — значение не меняется в рантайме.
    Q_PROPERTY(bool proSelectionEnabled READ proSelectionEnabled CONSTANT)
    // AVPN (анти-фриз/анти-краш): устройства и статус аккаунта грузятся АСИНХРОННО (без вложенного
    // QEventLoop на GUI-потоке). UI биндится на эти property; refreshDevices()/refreshAccount() лишь
    // запускают фоновый GET, результат прилетает через devicesChanged()/accountChanged().
    Q_PROPERTY(QVariantList devices READ devices NOTIFY devicesChanged)
    Q_PROPERTY(QVariantMap account READ account NOTIFY accountChanged)
    // AVPN (Task 7): туннель на «авто-паузе для покупок» (реально down, ждём авто-возврат). // AVPN
    Q_PROPERTY(bool paused READ paused NOTIFY changed)
    // AVPN (реальные палочки): живое качество ТЕКУЩЕГО соединения, измеренное app-layer RTT-пробой
    // ЧЕРЕЗ туннель (TCP-пинг до AWG-UDP-порта не достукивается; per-node RTT остальных нод off-tunnel
    // меряет RttProbeIcmp, см. probeNodeRtt). liveBars 0..5 (EWMA+гистерезис),
    // liveRttMs — сглаженный RTT (−1 = ещё не мерили/нет связи), liveReachable — дошла ли проба.
    Q_PROPERTY(int liveRttMs READ liveRttMs NOTIFY liveQualityChanged)
    Q_PROPERTY(int liveBars READ liveBars NOTIFY liveQualityChanged)
    Q_PROPERTY(bool liveReachable READ liveReachable NOTIFY liveQualityChanged)
    // AVPN (красные палочки): true ТОЛЬКО когда проба подтверждённо не доходит (kLiveDeadStreak подряд) —
    // отличает «ещё мерю / только подключились» от «связь мертва». UI рисует 0 зелёных + все красные.
    Q_PROPERTY(bool liveDead READ liveDead NOTIFY liveQualityChanged)
    // AVPN (чипы доступности): статус сервисов через ЭТУ ноду. Список [{key,label,state,rttMs}],
    // state: -1 неизв / 0 заблок / 1 медленно(троттл) / 2 работает. Замер — с устройства через туннель.
    Q_PROPERTY(QVariantList serviceStatus READ serviceStatus NOTIFY serviceStatusChanged)
public:
    AvpnEngineQml(VpnConnection *conn, SecureAppSettingsRepository *store,
                  QNetworkAccessManager *nam, QObject *parent = nullptr);

    QString state() const;
    bool busy() const { return m_busy; }

    // AVPN: статус подписки (Task 3). daysLeft<0 = бессрочно/неизвестно; trafficLimit==0 = безлимит.
    int daysLeft() const;
    qlonglong trafficUsed() const;
    qlonglong trafficLimit() const;
    bool subActive() const;
    QString authToken() const;  // AVPN: JWT из защищённого стора (Enrollment::loadToken)

    // AVPN: реальные серверы для UI (карточка Connect + страница Серверы).
    QVariantMap currentNode() const;
    QVariantList nodePool() const;
    // AVPN (live-node picker): Pro-гейт-заглушка — выбор сервера доступен (сейчас всегда true).
    bool proSelectionEnabled() const { return true; }

    // AVPN: кэш последнего async-ответа /v1/devices и /v1/account (для биндинга в QML).
    QVariantList devices() const { return m_devices; }
    QVariantMap account() const { return m_account; }

    // Control plane base URL (BACKEND §2). Можно переопределить из настроек.
    void setBaseUrl(const QString &url) { m_baseUrl = url; }

    // --- QML API (для PageHomeTribe / PageDiagnostics) ---
    Q_INVOKABLE QVariantMap debugSnapshot() const;  // форма = DebugSnapshot.h / PageDiagnostics
    Q_INVOKABLE void bootstrap();                    // AVPN: тихая прогрузка подписки при старте (Task 11; без connect)
    Q_INVOKABLE void start();                        // «одна кнопка»: enroll→subscription→connect (async)
    Q_INVOKABLE void stop();
    Q_INVOKABLE void reprobe();                      // повторный выбор ноды (re-pick)
    Q_INVOKABLE void manualSwitch();                 // принудительный свитч (как DEAD)
    Q_INVOKABLE void resetLkg();                     // очистить кэш токена/подписки (re-enroll при start)

    // AVPN (live-node picker): ручной выбор сервера из шторки + кнопка «Обновить подключение».
    //  switchToNode(nodeId) — «Закрепить» выбранную ноду (переключиться/подключиться к ней).
    //  rotateNext()         — round-robin на следующую живую ноду (кнопка «Обновить подключение»).
    //  refreshPool()        — пере-зачитать подписку/health и обновить nodePool (NOTIFY changed).
    Q_INVOKABLE void switchToNode(const QString &nodeId);
    Q_INVOKABLE void selectAuto();   // AVPN: «Авто (быстрейший)» — авто-режим без реконнекта (снять pin)
    Q_INVOKABLE void rotateNext();
    Q_INVOKABLE void refreshPool();

    // AVPN (Task C): вход/восстановление по коду доступа (POST /v1/code/redeem). Синхронно.
    // 200 → РОТАЦИЯ токена (Enrollment::saveToken) → re-fetch подписки → emit changed().
    // 401 → emit error («неверный код»). 409 → emit seatLimitReached(devices[]) (UI-выбор кого отключить).
    // evictDeviceId — backend-id из devices[] для 1-seat «перенести сюда» (пусто = обычный redeem).
    Q_INVOKABLE void redeemCode(const QString &code, const QString &evictDeviceId = QString());

    // AVPN (Task 13): принять перенос «как SIM» на ЭТО устройство (POST /v1/transfer/redeem). Зовётся
    // мостом диплинка (AvpnDeepLinkBridge) при tribe://transfer?t=… . 200 → РОТАЦИЯ токена внутри
    // Enrollment::redeemTransfer (saveToken) → re-fetch подписки → emit transferRedeemed()+changed().
    // 401 → error («ссылка переноса недействительна»). 409 → error («достигнут лимит устройств»).
    Q_INVOKABLE void redeemTransfer(const QString &transferToken);

    // AVPN (Task 13): выпустить перенос с ЭТОГО устройства (POST /v1/transfer, Bearer authToken).
    // Возвращает { transfer_token, deep_link } для рендера QR/копирования в UI. Пустая мапа при ошибке
    // (+ emit error). Синхронно (QEventLoop).
    Q_INVOKABLE QVariantMap createTransfer();

    // AVPN (Task 7): авто-пауза «для покупок». Опускает туннель (m_tunnel.down(), state→Paused) на
    // время покупки в РФ-приложении и АВТО-ВОЗВРАЩАЕТ его через `seconds` секунд бездействия
    // (нет foreground-API → «истёк таймер паузы» = «пользователь не дёргал → возвращаемся»).
    // Будет вызываться iOS App Intent (Task 8). Если тумблер AvpnSettings/autoPauseRu выключен —
    // intent-пауза всё равно отрабатывает (ручной вызов), просто без авто-триггера со стороны системы.
    Q_INVOKABLE void pauseForShopping(int seconds = 90);
    // AVPN: ручной выход из паузы (поднять туннель сразу, не дожидаясь таймера).
    Q_INVOKABLE void resumeFromPause();

    // AVPN (Task: Devices+Account): управление устройствами аккаунта и его статусом. Все три —
    // синхронные (QEventLoop как fetchSubscription), Bearer = authToken() (subscription_token).
    // 401/сеть → пустой результат (+ emit error для kick); UI обновляет список по changed().

    // GET /v1/devices (АСИНХРОННО) → наполняет property `devices` [{device_id, platform, label,
    // last_seen, is_current}] и эмитит devicesChanged(). Нет токена / 401 / сеть / таймаут → пустой
    // список. БЕЗ вложенного QEventLoop: зовётся из QML-таймера, nested loop здесь = re-entrancy краш.
    Q_INVOKABLE void refreshDevices();

    // DELETE /v1/devices/{id} → true при 204 (токен устройства убит, peer снят на всех нодах).
    // false при 401/404/сети (+ emit error). При успехе emit changed() (UI перечитает список).
    Q_INVOKABLE bool kickDevice(const QString &deviceId);

    // GET /v1/account (АСИНХРОННО) → наполняет property `account` {account_id, status, expires_at,
    // traffic_limit, traffic_used} и эмитит accountChanged(). Нет токена / 401 / сеть → пустая мапа.
    Q_INVOKABLE void refreshAccount();

    // AVPN (Task 9 — APNs): зарегистрировать push device token на бэке (POST /v1/devices/push-token,
    // Bearer = authToken()). body {token, platform:"ios", environment, app_version}. АСИНХРОННО (как
    // refreshAccount, без nested loop). environment: "sandbox"|"production" (TestFlight/Debug vs App
    // Store). Нет токена подписки / сеть → тихий no-op (повторится при ротации токена/реконнекте).
    // Обычно зовётся не из QML, а из движка по сигналу AvpnPushBridge::deviceTokenReady.
    Q_INVOKABLE void registerPushToken(const QString &token, const QString &environment);

    // AVPN (Task 9 — APNs): флаш отложенного push-токена ПОСЛЕ появления subscription_token.
    // Сценарий гэпа: APNs отдал device token ДО первичного авто-enroll (authToken пуст →
    // registerPushToken запомнил m_pushToken, но НЕ отправил). После успешного bootstrap/enroll
    // (Connected) subscription_token уже есть → дёргаем registerPushToken повторно; дедуп по
    // fingerprint (token|env|auth) пропустит лишний POST, если он уже ушёл (redeem-пути). No-op,
    // если push-токен пуст (desktop / разрешение не выдано).
    void flushPendingPushToken();

    // AVPN (Task 9 — APNs): отметить уведомления прочитанными на сервере (POST /v1/notifications/read,
    // Bearer). Обнуляет серверный счётчик непрочитанных → следующий пуш придёт с низким aps.badge.
    // Связан с AvpnPushBridge::readRequested (QML зовёт AvpnPush.markAllRead()). АСИНХРОННО.
    Q_INVOKABLE void markNotificationsRead();
    // AVPN: читается тумблером #6 — отражает текущую фазу «на паузе» для UI.
    bool paused() const { return m_paused; }
    // AVPN (реальные палочки): живое качество текущего соединения.
    int liveRttMs() const { return m_liveRtt; }
    int liveBars() const { return m_liveBars; }
    bool liveReachable() const { return m_liveReachable; }
    bool liveDead() const { return m_liveDead; }
    // AVPN (чипы доступности): текущий статус сервисов (кэш последней пробы).
    QVariantList serviceStatus() const { return m_serviceStatus; }
    // Запустить пробу сервисов через туннель (on-connect авто + по тапу из UI). No-op, если не Connected.
    Q_INVOKABLE void probeServices();
    // AVPN (выбор по скорости): прямой ICMP-замер RTT до ВСЕХ живых нод (off-tunnel). Зовётся при
    // открытии шторки выбора сервера. No-op при connected (через туннель замер смазан — держим кэш) и
    // если пул пуст. Каждый ответ → m_nodeRtt[nodeId] + emit changed() (шторка пересортируется/обновит
    // палочки вживую по мере прихода пингов). Неизмеренные/недостижимые → -1 (фолбэк на health в UI).
    Q_INVOKABLE void probeNodeRtt();
    // AVPN (Task 7): состояние тумблера #6 (AvpnSettings/autoPauseRu) — для авто-инициатора (iOS
    // App Intent / Shortcuts, Task 8): проверить ПЕРЕД авто-вызовом pauseForShopping. Ручной/intent
    // вызов pauseForShopping работает независимо от этого флага.
    Q_INVOKABLE bool autoPauseEnabled() const;

signals:
    void changed();
    void error(const QString &message);
    // AVPN (Task C): redeem вернул 409 (мест нет) — devices[] для UI-выбора кого отключить
    // (DELETE /v1/devices/{id} или повторный redeemCode(code, evictDeviceId)). Каждый элемент —
    // QVariantMap {deviceId, platform, label, lastSeen, isCurrent}.
    void seatLimitReached(const QVariantList &devices);
    // AVPN (Task 13): перенос «как SIM» успешно принят на это устройство (токен уже ротирован,
    // подписка перечитана). UI может показать тост/перейти на Connect.
    void transferRedeemed();
    // AVPN: async-ответ /v1/devices и /v1/account готов (property devices/account обновлены).
    void devicesChanged();
    void accountChanged();
    // AVPN (реальные палочки): прилетел новый замер качества (liveBars/liveRttMs/liveReachable).
    void liveQualityChanged();
    // AVPN (чипы доступности): обновился статус сервисов (serviceStatus).
    void serviceStatusChanged();

private slots:
    void onTick();
    // AVPN: правдивый статус — реальное состояние VpnConnection (не маска успеха up()).
    void onConnectionStateChanged(Vpn::ConnectionState state);
    // AVPN: протокол-уровневые ошибки туннеля (ErrorCode) — наружу в error().
    void onVpnProtocolError(amnezia::ErrorCode code);
    // AVPN (Task 7): таймер паузы истёк → бездействие → поднять туннель обратно.
    void onPauseTimeout();
    // AVPN (reconcile-машина): терминальный колбэк туннеля не пришёл за таймаут → разблокировать.
    void onWatchdog();

private:
    // AVPN (reconcile-машина смены ноды): единый контур «намерение vs факт». ВСЕ подъёмы/опускания
    // туннеля идут ТОЛЬКО из терминального состояния (.connected/.disconnected/.error); смена ноды =
    // stop → дождаться Disconnected → start (никогда не up() поверх незакрытой iOS-NE-сессии). Это
    // убирает «подбираем сервер»→«Network Error» и залипания. См. memory tribe-server-switch-fix.
    void reconcile();      // привести факт (m_lastTunnelState) к намерению (m_wantConnected + pin)
    void guardedStart();   // поднять туннель (startFlow→connect→up): op-in-flight + сторож
    void guardedStop();    // опустить туннель (requestStop+down): op-in-flight + сторож

    ServiceEngine               m_engine;
    VpnConnectionTunnelControl  m_tunnel;     // живёт здесь, отдаётся движку
    SecureAppSettingsRepository *m_store = nullptr;
    QNetworkAccessManager       *m_nam = nullptr;
    VpnConnection               *m_conn = nullptr;
    QTimer                       m_healthTimer;
    // AVPN (реальные палочки): app-layer RTT-проба через туннель + сглаживание в 0..5 баров.
    QualityProbe                *m_probe = nullptr;   // создаётся в конструкторе (владелец — this)
    SignalQuality                m_signal;            // EWMA+гистерезис (чистая логика, протестирована)
    int                          m_liveRtt = -1;      // сглаженный RTT, мс (−1 = нет данных)
    int                          m_liveBars = 0;      // 0..5
    bool                         m_liveReachable = false;
    bool                         m_liveDead = false;     // проба подтверждённо не доходит → 0 зелёных + все красные
    int                          m_liveFailStreak = 0;   // неуспешных проб подряд (анти-фликер до «мертво»)
    static constexpr int         kLiveDeadStreak = 2;    // столько неудач подряд = связь мертва (≈1-я проба+1 тик)
    // AVPN (чипы доступности): проба сервисов через туннель + кэш статусов для QML.
    ServiceProbe                *m_svcProbe = nullptr;
    QVariantList                 m_serviceStatus;     // [{key,label,state,rttMs}] — обновляется по месту
    // AVPN (выбор по скорости): прямой RTT до нод (off-tunnel) + кэш измерений по nodeId.
    IRttProbe                   *m_rttProbe = nullptr; // владелец — this (QObject-parent)
    QHash<QString, int>          m_nodeRtt;            // nodeId → измеренный RTT мс (−1/нет = неизвестно)
    QString                      m_baseUrl = QStringLiteral("https://api.tribevpn.com");
    bool                         m_busy = false;
    // AVPN (reconcile-машина смены ноды): намерение vs факт + защита от гонок/шторма. См. reconcile().
    Vpn::ConnectionState         m_lastTunnelState = Vpn::Unknown; // ФАКТ: реальное состояние туннеля
    bool                         m_wantConnected = false;          // НАМЕРЕНИЕ: туннель должен быть поднят
    bool                         m_needsRestart  = false;          // цель сменилась на подключённом → stop→start
    bool                         m_opInFlight    = false;          // start/stop в полёте — ждём терминального
    int                          m_startAttempts = 0;              // подряд неудачных connect — анти-зацикливание
    enum class Op { None, Starting, Stopping };
    Op                           m_op = Op::None;                  // что сейчас в полёте (для обработки терминала)
    QTimer                       m_watchdog;                       // единый сторож (НЕ накапливаем singleShot)
    bool                         m_bootstrapped = false; // AVPN: bootstrap() выполняем один раз (Task 11)
    // AVPN (Task 7): авто-пауза «для покупок».
    QTimer                       m_pauseTimer;           // singleShot: истёк → бездействие → resume
    bool                         m_paused = false;       // туннель реально down, ждём авто-возврат
    bool                         m_wasConnected = false; // был ли активный туннель ДО паузы (нужно ли поднимать)
    // AVPN: кэш последних async-ответов /v1/devices и /v1/account (см. refreshDevices/refreshAccount).
    QVariantList                 m_devices;
    QVariantMap                  m_account;
    // AVPN (Task 9 — APNs): последний device token/окружение от AvpnPushBridge — для ПЕРЕ-регистрации
    // после ротации subscription_token (redeemCode/redeemTransfer: старый токен на сервере сброшен).
    QString                      m_pushToken;
    QString                      m_pushEnv;
    // AVPN (Task 9): запрос разрешения на пуши — один раз, после первого успешного коннекта (persist).
    bool                         m_pushPermissionAsked = false;
    // AVPN (Task 9): один device token-POST за сессию на пару (token,env) — без дублей на каждый коннект.
    QString                      m_pushTokenSent;
};

} // namespace avpn
