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
#include "NodeRotation.h"
#include "Selector.h"
#include "Switcher.h"
#include "TransportPick.h"
#include "dto/Subscription.h"

#include <QByteArray>
#include <QElapsedTimer>
#include <QHash>
#include <QSet>
#include <QString>

#include <functional>
#include <optional>

namespace avpn {

// AVPN awg31-xray-v1: Verifying — xray-туннель поднят платформой, но «Подключено» ещё НЕ показываем:
// ждём первую удачную пробу (DNS+HTTPS) ЧЕРЕЗ туннель (инвариант волны §4.3). Фасад ведёт пробу
// (async, бюджет xray_verify_timeout_ms) и зовёт verifySucceeded()/verifyFailed().
enum class EngineState { Disconnected, Selecting, Connecting, Verifying, Connected, Switching, Error };

// AVPN awg31-xray-v1: исход reseedPool (см. ниже).
// AVPN (фикс-волна 2026-09-22, K5): Unchanged — тело по содержимому совпало с текущим пулом
// (состав, identity и метаданные нод, адрес): обновлены только traffic/expiry/status, switchLog не
// трогаем (равная ревизия каждые ~20 с вымывала его), фасаду — ни changed(), ни persistPin, ни проб.
enum class ReseedResult { Applied, Deferred, Rejected, Unchanged };

class ServiceEngine {
public:
    ServiceEngine() : m_switcher(nullptr) {}

    // Платформенный туннель-адаптер (владение — у вызывающего).
    void setTunnel(ITunnelControl *tunnel) { m_tunnel = tunnel; m_switcher = Switcher(tunnel); }

    // AVPN (фикс-волна 2026-09-22): инъекция часов (epoch ms) для тестов — TTL кэша RTT и часы
    // фаз свитча. Пусто = QDateTime::currentMSecsSinceEpoch().
    void setNowMsForTest(std::function<qint64()> nowMs) { m_nowMsFn = std::move(nowMs); }

    // AVPN (выбор по скорости): кэш измеренного RTT по nodeId (off-tunnel ICMP, из AvpnEngineQml::probeNodeRtt).
    // connect() предпочитает ноду с минимальным RTT отсюда (pickByMeasuredRtt); пусто → фолбэк на weight.
    // AVPN (фикс-волна 2026-09-22, B9): у каждой ноды свой возраст замера (TTL kRttTtlMs).
    //  setMeasuredRtt(map) — заменить свежий кэш: ноды вне map забываются; значение <0 («нет ответа в
    //    этом раунде») НЕ затирает прошлый замер этой ноды, если он моложе TTL (один потерянный пакет не
    //    исключает ноду из ранжирования);
    //  mergeMeasuredRtt(map) — то же, но ноды вне map сохраняются (раунд дополняет кэш);
    //  measuredRtt() — только значения >=0 моложе TTL;
    //  lastKnownRtt() — последний известный замер каждой ноды БЕЗ TTL (failover при запрете замеров в
    //    connected: лучше старый RTT с пометкой возраста в switchLog, чем монета по весам).
    static constexpr qint64 kRttTtlMs = 120000;
    void setMeasuredRtt(const QHash<QString, int> &rtt);
    void mergeMeasuredRtt(const QHash<QString, int> &rtt);
    qint64 measuredRttAgeMs() const;
    QHash<QString, int> measuredRtt() const;
    QHash<QString, int> lastKnownRtt() const;
    qint64 lastKnownRttAgeMs(const QString &nodeId) const; // -1 = замера не было

    // Первый вход: genkey (Identity, reuse форка) → POST /v1/trial → сохранить токен. [IN-FORK]
    // store/nam отдаёт приложение (SecureAppSettingsRepository, amnApp->networkManager()).
    bool enroll(QNetworkAccessManager *nam, const QString &baseUrl,
                SecureAppSettingsRepository *store, QString &error);
    QString subscriptionToken() const { return m_token; }

    // Загрузить подписку (тело GET /v1/subscription). Заполняет NodePool. false + error при провале.
    // AVPN (фикс-волна 2026-09-22, K5/B1): false — ТОЛЬКО битое тело (парс). Серверная pool_revision
    // не глобальный монотонный счётчик — по ней не отвергаем (порядок ответов гарантирует фасад по
    // m_subscriptionSequence). Пустые nodes при непустом пуле ТОГО ЖЕ аккаунта (address совпал):
    // обновляются только traffic/expiry/status/grace, пул и pending-reseed сохраняются (degraded/окно
    // readiness не затирает рабочий пул). Пустые nodes с ДРУГИМ address (redeem/transfer → новый
    // аккаунт в окне readiness) — обычный путь применения/отложения: чужой пул и /32 не сохраняем.
    bool loadSubscription(const QByteArray &json, QString &error);

    // AVPN (фикс-волна 2026-09-22, K5/B1, ревью CL-B): правило перезаписи дискового LKG телом ответа
    // (то же, что shouldPersistLkgBody фасада): тело с нодами — пишем; пустое — только если в текущем
    // дисковом LKG нод нет или LKG принадлежит другому аккаунту (другой address).
    static bool lkgWriteAllowed(const Subscription &body, const QByteArray &diskLkg);

    // AVPN (LKG, C-7): загрузить подписку из ДИСКОВОГО кэша (последний удачный ответ) — мгновенный
    // бейдж/пул при старте до сетевого bootstrap. Помечает снапшот lkgStale=true; свежий сетевой
    // loadSubscription (ensureSubscription) перезаписывает данные и снимает флаг.
    bool loadSubscriptionFromLkg(const QByteArray &json, QString &error);

    // Список не-фатальных проблем текущей подписки (см. SubscriptionParser::validate).
    QStringList subscriptionIssues() const;

    // AVPN (#35 живой трафик): освежить счётчики подписки из GET /v1/account (used/limit/expires),
    // не перезагружая ноды. Зовётся периодически из onTick, пока подключены → бейдж ГБ/дней «живой».
    void updateSubscriptionTraffic(qint64 used, qint64 limit, const QString &expiresAt)
    {
        m_pool.updateTraffic(used, limit, expiresAt);
    }

    // AVPN awg31-xray-v1 (спека §2.3, инвариант §4.4): reseed пула на ЖИВОМ приложении по смене
    // pool_revision (refreshSubscription фасада; kill-switch features.subscription_reseed_pool —
    // проверяет фасад). Правила: применяем СРАЗУ только в терминале (Disconnected/Error) ИЛИ если
    // текущая нода (и цель незавершённого свитча) в новом пуле НЕ изменилась (endpoint +
    // server_pubkey / xray uuid); иначе Deferred — тело откладывается и применяется при переходе в
    // терминал (applyPendingReseed, фасад зовёт через QTimer::singleShot(0) — никогда из-под
    // Selector::pick). Rejected: пустой пул / нет ревизии — пул НЕ затирается.
    // AVPN (фикс-волна 2026-09-22, K5/B2): меньшая ревизия допустима (ревизия не монотонна — удаление
    // ноды опускает max); Unchanged — содержимое совпало с текущим пулом (см. enum).
    // При применении: ревалидация pin по локации (узел исчез → сосед той же локации, иначе снять;
    // актуальный pin — pinnedNodeId(), фасад персистит его, а не старый id), сброс RTT-кэша и
    // сессионных провалов для исчезнувших узлов, запись в switchLog (только при смене состава/identity
    // или ревизии). Адоптированный туннель без identity: после применения — попытка опознать текущую
    // ноду по endpoint сессии (подсказка из adoptTunnelConnected).
    ReseedResult reseedPool(const Subscription &sub);
    bool hasPendingReseed() const { return m_pendingReseed.has_value(); }
    bool applyPendingReseed();
    // GAP-1: отложенное тело reseed движок применяет сам МЕЖДУ рантаймами своего свитча (DEAD →
    // переподъём/другая нода; туннель гасится или уже погашен) — иначе переподъём «той же ноды» шёл
    // по старому конфигу (порт/awg_params/pubkey) и поднимался мёртвым. Чистая операция в памяти (без
    // I/O). Фасад, у которого после этого hasPendingReseed()==false, забирает флаг и делает свою
    // пост-обработку applyPendingReseed (m_nodeRtt, persist актуального pin, changed()). true = было.
    bool takeReseedAppliedInSwitch()
    {
        const bool was = m_reseedAppliedInSwitch;
        m_reseedAppliedInSwitch = false;
        return was;
    }
    qint64 poolRevision() const { return m_pool.subscription().poolRevision; }

    // Подключиться: выбрать ноду и поднять туннель. [СКАФФОЛД: выбор=первый, реальный скоринг в C-4]
    bool connect(QString &error);

    EngineState state() const { return m_state; }
    // AVPN: подписка уже загружена (есть ноды) → connect() можно звать ЛОКАЛЬНО, без сетевого startFlow
    // (enroll/GET subscription). Нужно, чтобы реконнект не ходил в сеть на главном потоке (вложенный
    // QEventLoop → Hang UIKit + abort на 2-м коннекте). Как Amnezia: коннект-кнопка только поднимает туннель.
    bool hasSubscription() const { return !m_pool.nodes().isEmpty(); }
    DebugSnapshot debugSnapshot() const;

    // C-5 health-loop:
    //  tick() — периодический (QTimer 3–5с в in-fork обвязке): читает stats, кормит HealthLoop,
    //           при DEAD → onDead() (свитч на лучшего кандидата, исключая мёртвую ноду).
    //  notifyConnectionLost() — реактивный: дёргать из onConnectionStateChanged при неожиданном
    //           Error/Disconnected, пока state==Connected → немедленный свитч.
    //  Возвращают true, если произошёл свитч/обработка DEAD.
    // AVPN (фикс-волна 2026-09-22, K5/B3): tick работает и для адоптированного туннеля без identity
    // (нода сессии не найдена в пуле) — DEAD → лечение/failover на авто-выбор, лог «dead (unknown identity)».
    bool tick(qint64 nowEpoch);
    bool notifyConnectionLost();
    // AVPN (macOS wake-реконнект, спека 2026-07-17 §2.2): сброс prev-сэмпла HealthLoop на
    // пробуждении — ночные дельты rx/tx против свежего замера дали бы ложный onDead (up() в ещё
    // не готовую сеть). Аналог общий с iOS P1 (foreground-ресинк). Только сэмплинг, фазу не трогает.
    void resetHealthSampling() { m_health.reset(); }
    // AVPN (фикс-волна 2026-09-22, K5/B8, роуминг): смена сети (reachability/интерфейс/путь) —
    // сброс выборки HealthLoop и запрет DEAD-вердикта в окне grace (health_network_grace_s, деф. 20 с):
    // NE лечит путь сам (bump/rebind ≤ ~15 с), ложный DEAD в этом окне уводил EE→US.
    // nowEpoch <0 → текущее время (сек).
    void noteNetworkChange(qint64 nowEpoch = -1);

    // AVPN (фикс-волна 2026-09-22, K4/B7): итог rebind в NE (IosController::rebindFinished →
    // фасад). performed=false (NE отказал по бюджету / адаптер не запущен / нет ответа за 3 с) =
    // провал шага лечения: следующий DEAD-цикл сразу идёт на шаг 2/3 (переподъём / другая нода).
    // Ответ без ожидающего rebind (поздний/чужой) игнорируется. true = учтено.
    // GAP-2: reason — причина отказа из ответа NE ({"rebind":"denied","reason":…}). "offline" = у NE
    // путь unsatisfied (телефон без сети, нода ни при чём): это НЕ провал шага — попытка rebind не
    // тратится, m_rebindDenied не ставится, открывается окно grace смены сети (как noteNetworkChange);
    // следующий DEAD снова делает rebind. Кап kRebindOfflineDeferMax таких отсрочек на сессию лечения
    // (страховка от вечной петли при ложном "offline"). "budget"/"not_started"/пусто — провал (как было).
    bool onRebindResult(bool performed, const QString &reason = QString());
    static constexpr int kRebindOfflineDeferMax = 10;
    bool rebindAwaitingResult() const { return m_rebindAwaiting; }
    QString currentNodeId() const { return m_currentNodeId; }

    // AVPN awg31-xray-v1: транспорт текущей ноды ("awg"/"xray"; пусто = нет текущей) и её локация.
    QString currentNodeProto() const;
    bool currentNodeIsXray() const { return isXrayProto(currentNodeProto()); }
    QString currentLocation() const;

    // AVPN awg31-xray-v1 (§2.3 «Connected по xray только после probe»):
    //  isVerifying()      — фаза Verifying (xray поднят, ждём пробу через туннель);
    //  verifySucceeded()  — проба прошла → Connected (история: успех + время до трафика);
    //  verifyFailed()     — бюджет исчерпан → провал data-plane: другой транспорт той же локации,
    //                       потом соседняя (onDead, tunnelStillUp=true — down()→Disconnected→up()).
    //  feedProbeResult()  — живая проба через туннель в Connected (QualityProbe фасада): для xray
    //                       N провалов подряд (xray_probe_fail_cycles) = DEAD → failover; awg — no-op
    //                       (у него handshake-критерий HealthLoop). true = произошёл свитч.
    // Все — без I/O; переходы туннеля, как всегда, приходят колбэками onTunnel*().
    bool isVerifying() const { return m_state == EngineState::Verifying; }
    bool verifySucceeded();
    bool verifyFailed();
    bool feedProbeResult(bool ok);

    // AVPN awg31-xray-v1: ручной режим транспорта (Авто / Amnezia / Xray). Локальная настройка —
    // персистит фасад (QSettings avpn/transportMode). В ручном режиме — hard-filter по proto на
    // всех путях выбора (connect/failover/ротация/pin); нет кандидатов → честная ошибка no_transport.
    // AVPN (независимое ревью волны, MAJOR-2): недоступный Xray (kill-switch features.xray_client
    // или платформа) всегда читается как Auto — и при загрузке сохранённой настройки, и в UI, и на
    // всех путях выбора (normalizeTransportMode зовётся в начале connect()/onDead()).
    void setTransportMode(TransportMode m) { m_transportMode = effectiveTransportMode(m); }
    TransportMode transportMode() const { return effectiveTransportMode(m_transportMode); }
    void normalizeTransportMode() { m_transportMode = effectiveTransportMode(m_transportMode); }

    // AVPN awg31-xray-v1: локальная история транспортов (EWMA успеха/времени до трафика по паре
    // локация×proto, TransportPick.h). Персистит фасад (QSettings avpn/transportHistory):
    // load на старте, serialize — когда transportHistoryDirty().
    //  recordTransportOutcome(ok) — исход подъёма ТЕКУЩЕЙ ноды: ok=true на реальном Connected
    //    (awg — фасад на Vpn::Connected; xray — сам движок в verifySucceeded), ok=false на провале
    //    (Error при старте — фасад; DEAD/verify/probe — сам движок). Один успех и один провал на
    //    сессию подъёма (повторы игнорируются). true = записано.
    const TransportHistory &transportHistory() const { return m_transportHistory; }
    TransportHistory &transportHistory() { return m_transportHistory; }
    void loadTransportHistory(const QByteArray &bytes)
    {
        m_transportHistory = TransportHistory::deserialize(bytes);
        m_historyDirty = false;
    }
    QByteArray transportHistoryJson() const { return m_transportHistory.serialize(); }
    bool transportHistoryDirty() const { return m_historyDirty; }
    void clearTransportHistoryDirty() { m_historyDirty = false; }
    bool recordTransportOutcome(bool ok);

    // AVPN (live-node picker): ручной выбор/ротация поверх авто-логики.
    //  setPinnedNode(nodeId) — «Выбрать»: только закрепляет узел (m_pinnedNodeId=nodeId), НЕ коннектит.
    //    Модель «выбор = задать цель, коннект — кнопкой»: следующий connect() (orb «Connect») поднимет
    //    закреплённую ноду. Тиар-даун текущего туннеля (если был онлайн другой узел) делает мост
    //    (AvpnEngineQml::switchToNode), чтобы избежать back-to-back up() без down() (iOS-storm).
    //    AVPN awg31-xray-v1: PIN — ПО ЛОКАЦИИ (host_id), не по узлу: закрепить можно любой узел
    //    локации (даже xray-строку при выключенном xray_client — если в локации есть awg); фактический
    //    транспорт выбирает connect() (transport_rank + история + ручной режим). Ошибки (технические
    //    строки, человеческий текст — AvpnEngineQml::humanPinError): unsupported_proto — в локации нет
    //    ни одного поднимаемого узла; no_transport — есть, но ручной режим их отфильтровал.
    //  rotateNext() — round-robin по живым ЛОКАЦИЯМ (NodeRotation.h::nextLiveNodeId), круговой индекс
    //    от текущей → следующая (заворот). Кнопка «Сменить сервер».
    //  pinnedNodeId() — закреплённая пользователем нода (пусто = авто); pinnedLocation() — её локация.
    // Возвращают true при успешном свитче/старте; false + error — нет такой/живой ноды или провал.
    bool setPinnedNode(const QString &nodeId, QString &error); // AVPN (был switchToNode: коннектил сам)
    bool rotateNext(QString &error);                          // AVPN
    // AVPN: следующая живая локация после текущей (та же логика, что rotateNext, но БЕЗ side-effects —
    // фасад использует для «Обновить подключение» через единый reconcile). Пусто = некуда ротировать.
    QString nextLiveNodeId() const;
    QString pinnedNodeId() const { return m_pinnedNodeId; }   // AVPN
    bool hasConnectablePin() const { return pinnedCandidate() != nullptr; }
    QString pinnedLocation() const;                           // AVPN awg31-xray-v1
    // AVPN (RU-нода): закреплена ли сейчас РФ-нода (countryCode==RU). RU достижима ТОЛЬКО через ручной pin
    // (авто-выбор её исключает) → по этому флагу RU-direct-сплит отключается (full-tunnel через РФ).
    bool pinnedNodeIsRu() const;
    // AVPN: снять закрепление (вернуться в авто). «Авто (быстрейший)» (reprobe) и ручная ротация
    // (rotateNext) снимают pin — иначе connect() всегда отдаёт приоритет закреплённой ноде, и
    // возврат-в-авто / offline-ротация молча ломаются (reselect закреплённой).
    void clearPin() { m_pinnedNodeId.clear(); }               // AVPN

    // AVPN: правдивый статус. up() ставит туннель в очередь (async), поэтому connect() остаётся в
    // Connecting; реальные переходы прилетают из VpnConnection::connectionStateChanged через
    // AvpnEngineQml. Вызывать ТОЛЬКО из onConnectionStateChanged (enum-free, без зависимости на Vpn::).
    //  onTunnelConnected()    — туннель реально поднялся (Connecting/Switching → Connected; для xray →
    //                           Verifying, см. выше).
    //  onTunnelError()        — туннель упал с ошибкой (любая фаза → Error).
    //  onTunnelDisconnected() — туннель отключился (Connected/Verifying/… → Disconnected, без свитча).
    // Возвращают true, если фаза изменилась (вызывающий шлёт changed()).
    bool onTunnelConnected();
    bool onTunnelError();
    bool onTunnelDisconnected();

    // AVPN (Android-адопт): туннель ФАКТИЧЕСКИ жив (AndroidController::initConnectionState после
    // ре-байнда мессенджера/холодного старта), а движок — в терминале после фейкового Disconnected
    // (обрыв байндинга при уходе в фон). Единственный легальный «воскреситель» Connected извне фаз
    // подъёма; обычный onTunnelConnected терминалы намеренно НЕ воскрешает.
    // AVPN (фикс-волна 2026-09-22, A5/B3): нода сессии не найдена в пуле (или её endpoint/proto уже
    // другие) → адопт с НЕИЗВЕСТНОЙ identity (true), подсказка {nodeId, proto, endpoint} запоминается:
    // после reseed движок пытается опознать текущую ноду по ней (tryIdentifyCurrentNode). В фазе
    // Connected — только обновление identity/подсказки (false, как раньше).
    bool adoptTunnelConnected(const QString &nodeId = {}, const QString &proto = {},
                              const QString &endpoint = {});
    bool currentIdentityKnown() const { return !m_currentNodeId.isEmpty(); }
    bool tryIdentifyCurrentNode();
    // AVPN (A5): подсказка сессии {node_id, proto, endpoint} неопознанного адопта — только для
    // показа на карточке (DebugSnapshot.h::hintedPoolRow); пусто, когда identity известна.
    struct SessionHint { QString nodeId, proto, endpoint; };
    SessionHint sessionHint() const
    {
        return {m_sessionHintNodeId, m_sessionHintProto, m_sessionHintEndpoint};
    }

    // Poll independently of health sampling (including when the uplink is offline).
    // AVPN (фикс-волна 2026-09-22, K5/B4): часы свитча — ПО ФАЗАМ: фаза down (ждём Disconnected
    // старого рантайма) — бюджет timeoutMs; фаза up (up() на цель отправлен) — часы перезапускаются,
    // бюджет max(timeoutMs, reconcileWatchdogMsTuned()) — не меньше сторожа коннекта. Истечение →
    // Error + interruptedSwitch (фасад повторяет старт с анти-зацикливанием, намерение НЕ снимает).
    bool expireSwitch(int timeoutMs = 30000);
    bool switchInUpPhase() const { return m_state == EngineState::Switching && m_switchUpPhase; }

    // AVPN (фикс-волна 2026-09-22, K5/B4/B5): внутренний свитч/failover движка прерван (Error или
    // дедлайн фазы). Фасад по hasInterruptedSwitch() понимает, что шёл НАШ свитч (не внешний обрыв):
    // намерение сохраняется, следующий старт — после подтверждённого down, с анти-зацикливанием.
    //  interruptedSwitchTarget() — цель, которую стоит повторить (прервано в фазе down: цель ещё не
    //    пробовали — в том числе переподъём той же ноды, шаг 2 лестницы; фаза up переподъёма в окне
    //    grace смены сети — тоже: сеть не готова, нода не виновата); пусто — цель провалила подъём
    //    (фаза up: нода в сессионных провалах). connect() сам предпочитает сохранённую цель
    //    (одноразово), авто-выбор повтора ранжирует по failoverRtt (свежий поверх последнего
    //    известного: в connected замеров не было), сессию лечения той же ноды и счётчик провалов
    //    data-plane НЕ сбрасывает (повтор — не действие пользователя); запись сбрасывается там же и
    //    в requestStop()/setPinnedNode()/адопте.
    //  interruptedSwitchCause() — "error_down" / "error_up" / "deadline_down" / "deadline_up".
    bool hasInterruptedSwitch() const { return m_interrupted.active; }
    QString interruptedSwitchTarget() const { return m_interrupted.target; }
    QString interruptedSwitchReason() const { return m_interrupted.reason; }
    QString interruptedSwitchCause() const { return m_interrupted.cause; }
    void clearInterruptedSwitch() { m_interrupted = InterruptedSwitch{}; }

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
    // AVPN (BUG-4 auto-heal): счётчики ребайнд-попыток — текущей ноды-сессии и суммарно с запуска
    // (телеметрия benchExtra: паттерн «оператор×нода×heal помог/нет» ищется по отчётам).
    int rebindHealTries() const { return m_rebindHealTries; }

    // AVPN (независимое ревью волны, MAJOR-1): подряд идущие провалы data-plane за сессию
    // (health-DEAD / провал verify / провал живой пробы) и признак «кап исчерпан» — движок ушёл в
    // Error вместо очередного круга failover. Сбрасываются успешной пробой через туннель
    // (verifySucceeded / feedProbeResult(true)) и явным действием пользователя (connect/stop/адопт).
    int dataPlaneFailStreak() const { return m_dataPlaneFailStreak; }
    bool dataPlaneExhausted() const { return m_dataPlaneExhausted; }
    int rebindHealTotal() const { return m_rebindHealTotal; }
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
    // AVPN (auth self-heal): общий путь startFlow/bootstrap — токен (из стора / enroll) → GET
    // /v1/subscription → loadSubscription. На 401 от токена ИЗ СТОРА: clearToken + один ре-энролл +
    // ретрай (стейл-токен после ротации secret на бэкенде; корень бага «unauthorized (token)»).
    // Решения вынесены в Enrollment::classifyFetch/decideAuthRecovery (покрыты auth_heal_check).
    bool ensureSubscription(QNetworkAccessManager *nam, const QString &baseUrl,
                            SecureAppSettingsRepository *store, QString &error);

    // tunnelStillUp=true (health-DEAD из tick — туннель ещё «поднят») → down()→ждём Disconnected→up();
    // false (failover из реального Disconnected/Error — туннель уже опущен) → up() сразу.
    // reason — для switchLog (dead / verify failed / probe failed).
    // AVPN (фикс-волна 2026-09-22, B6): лестница лечения на health-DEAD при живом туннеле —
    // шаг 1 rebind (новый порт в NE, кап rebind_heal_max_tries, отказ NE → шаг пропускается);
    // шаг 2 переподъём ТОЙ ЖЕ ноды (down→up, кап dead_reup_max_tries, kill-switch
    // features.dead_reup_same_node); шаг 3 — другая нода, сначала та же локация, RTT — последний
    // известный (с пометкой возраста). Неизвестная identity: шаг 1, затем авто-выбор из пула.
    bool onDead(bool tunnelStillUp, const QString &reason = QString()); // выбрать кандидата (исключая текущую) и переключиться

    // AVPN (live-node picker): backend-фолбэк выбор по max weight среди ЖИВЫХ нод, исключая exclA/exclB
    // (мёртвая/текущая). Живой = health-агрегат > 0; пустой health = живой (бэкенд провижинит живыми).
    // Не делает I/O (в отличие от Selector::pick) — чистый выбор по данным подписки. nullptr = нет.
    // Легаси-цепочка (kill-switch transport_auto_pick=false).
    const SubscriptionNode *pickByWeight(const QString &exclA, const QString &exclB) const; // AVPN

    // AVPN (выбор по скорости): среди ЖИВЫХ нод (health-агрегат > 0, исключая exclA/exclB) выбрать с
    // МИНИМАЛЬНЫМ измеренным RTT (m_measuredRtt, off-tunnel ICMP). nullptr = ни одна не измерена → caller
    // откатывается на Selector::pick/pickByWeight. Без I/O (использует уже накопленный кэш — CONNECT-INVARIANTS §1).
    // Легаси-цепочка (kill-switch transport_auto_pick=false).
    const SubscriptionNode *pickByMeasuredRtt(const QString &exclA, const QString &exclB) const; // AVPN

    // AVPN awg31-xray-v1: выбор транспорта по локациям (TransportPick.h) — pin-локация / та же
    // локация при failover / соседние; учитывает ручной режим, сессионные провалы, историю.
    // withExclusions=false — повторная попытка без сессионных провалов (иначе «нет нод» после
    // круга failover'ов). nullptr = кандидатов нет.
    // useLastKnownRtt=true (failover) — RTT без TTL (свежий поверх последнего известного).
    const SubscriptionNode *pickTransport(const QString &preferLocation, const QString &preferNodeId,
                                          const QString &exclA, bool withExclusions,
                                          bool useLastKnownRtt = false) const;
    QHash<QString, int> failoverRtt() const;
    const SubscriptionNode *findNode(const QString &nodeId) const;
    const SubscriptionNode *pinnedCandidate() const;
    bool anySupportedNode() const;
    // Провал data-plane текущей ноды: история + сессионный список провалов.
    void noteDataPlaneFailure();
    // AVPN awg31-xray-v1 (reseed): применимо ли тело сейчас (терминал ИЛИ текущая/целевая нода без изменений).
    bool reseedApplicableNow(const Subscription &sub) const;
    static bool sameNodeIdentity(const SubscriptionNode &a, const SubscriptionNode &b);
    // AVPN (фикс-волна 2026-09-22, B2): полное совпадение содержимого (identity + метаданные выбора/
    // отображения) и совпадение состава пула/адреса — основа ReseedResult::Unchanged.
    static bool sameNodeContent(const SubscriptionNode &a, const SubscriptionNode &b);
    bool samePoolContent(const Subscription &sub) const;
    // Обновить только «аккаунтные» поля (traffic/expiry/status/grace/ревизию), пул не трогая.
    void updateAccountFields(const Subscription &sub, bool includeRevision);
    void applyReseedNow(const Subscription &sub);
    // GAP-1: применить m_pendingReseed (с нодами) между рантаймами свитча; true = применено.
    bool applyPendingReseedBetweenRuntimes();
    void markUpStarted();
    void appendSwitchLog(const QString &line);
    qint64 nowMs() const;
    // Сессия лечения (rebind/переподъём) принадлежит ноде: сбрасывается при смене ноды, стопе,
    // connect() и адопте — переподъём той же ноды бюджет НЕ возвращает (иначе вечная лестница).
    // Ревью CL-B (REV-1): бюджет возвращается и сам — после heal_budget_restore_s здорового туннеля
    // на той же ноде (rx растёт или свежий handshake, ни одного плохого цикла), см. noteHealthyTick.
    void resetHealSession(const QString &nodeId);
    void noteHealStep();
    void noteHealthyTick(const TunnelStats &stats, qint64 nowEpoch);
    bool applyLoadedSubscription(const Subscription &sub);
    // Внутренний свитч прерван (Error/дедлайн): фиксируем для фасада (см. hasInterruptedSwitch).
    void noteSwitchInterrupted(const QString &cause);

    // AVPN (фикс iOS-шторма свитча): двухфазный секвенс-свитч. requestSwitch ставит m_state=Switching
    // (→ transient Disconnected/Error от down() НЕ запускает failover) и: при tunnelUp — down(), ждём
    // реальный Disconnected (onTunnelDisconnected→continuePendingSwitch→up); при !tunnelUp — up() сразу.
    // НЕЛЬЗЯ up() сразу после down() на iOS (NEVPNManager «Operation Cancelled»). reason — для switchLog.
    bool requestSwitch(const QString &targetNodeId, bool tunnelUp, const QString &reason); // AVPN
    bool continuePendingSwitch(); // AVPN: поднять up() на отложенную целевую ноду (туннель уже опущен)

    Identity      m_identity;
    NodePool      m_pool;
    Selector      m_selector;
    bool          m_lkgActive = false; // AVPN (LKG): пул наполнен из дискового кэша, свежего фетча ещё не было
    Switcher      m_switcher;
    HealthLoop    m_health;
    ITunnelControl *m_tunnel = nullptr;
    EngineState   m_state = EngineState::Disconnected;
    QString       m_currentNodeId;
    QString       m_pinnedNodeId; // AVPN: закреплённая пользователем нода (switchToNode); пусто = авто
    // AVPN (выбор по скорости): off-tunnel ICMP RTT по nodeId. B9: у каждого замера свой момент (epoch ms).
    struct RttSample { int ms = -1; qint64 atMs = 0; };
    QHash<QString, RttSample> m_rttFresh;     // свежий кэш (читается с TTL kRttTtlMs)
    QHash<QString, RttSample> m_rttLastKnown; // последний известный замер без TTL (failover)
    qint64        m_rttSetAtMs = -1;          // момент последнего set/merge (measuredRttAgeMs)
    std::function<qint64()> m_nowMsFn;        // тестовые часы (пусто = системные)
    qint64        m_switchStartedMs = -1;     // B4: начало ТЕКУЩЕЙ фазы свитча (-1 = часы не идут)
    bool          m_switchUpPhase = false;    // B4: фаза up (up() на цель отправлен)
    bool          m_pendingSwitchIsReup = false; // B6: текущий свитч — переподъём той же ноды
    QString       m_upPhaseReason;            // B4/B5: причина свитча в фазе up (для interruptedSwitch)
    QString       m_pendingSwitchNodeId; // AVPN: целевая нода во время двухфазного свитча (пусто = нет)
    QString       m_pendingSwitchReason; // AVPN: причина для switchLog (pinned/rotate/dead)
    struct InterruptedSwitch { bool active = false; QString target, reason, cause; };
    InterruptedSwitch m_interrupted;     // B4/B5: прерванный внутренний свитч (решает фасад)
    // A5/B3: подсказка identity адоптированной сессии (sessionMetadata), когда нода не опознана.
    QString       m_sessionHintNodeId, m_sessionHintProto, m_sessionHintEndpoint;
    QString       m_token;
    QString       m_accountId;
    QStringList   m_switchLog;
    int           m_rebindHealTries = 0; // AVPN BUG-4: попытки heal на текущей ноде-сессии (кап tunable)
    int           m_rebindHealTotal = 0; // AVPN BUG-4: суммарно с запуска (в benchExtra отчётов)
    QString       m_healNodeId;          // B6: нода, которой принадлежит текущая сессия лечения
    int           m_sameNodeReupTries = 0; // B6: переподъёмы той же ноды в этой сессии лечения
    bool          m_rebindAwaiting = false; // B7: rebind отправлен, ждём итог NE
    bool          m_rebindDenied = false;   // B7: NE отказал — шаг rebind в этой сессии лечения пропускаем
    int           m_rebindOfflineDefers = 0; // GAP-2: отказы NE "offline" в этой сессии лечения (кап)
    bool          m_reseedAppliedInSwitch = false; // GAP-1: pending-reseed применён движком в свитче
    // REV-1: восстановление бюджета лечения по времени здорового туннеля (epoch сек, 0 = нет).
    qint64        m_lastTickEpoch = 0;      // момент последнего tick (шаги лечения зовутся из него)
    qint64        m_healStepEpoch = 0;      // последний шаг лечения (rebind/переподъём) этой сессии
    qint64        m_healthySinceEpoch = 0;  // начало непрерывного здорового отрезка после шага
    qint64        m_tickPrevRx = -1;        // rx прошлого tick (рост rx = доказательство живого туннеля)
    // AVPN awg31-xray-v1:
    TransportMode m_transportMode = TransportMode::Auto;
    TransportHistory m_transportHistory;
    bool          m_historyDirty = false;
    QSet<QString> m_failedThisSession;   // узлы, провалившие data-plane с последнего стопа (failover не ходит по кругу)
    int           m_probeFailStreak = 0; // xray: провалы живой пробы подряд (feedProbeResult)
    int           m_dataPlaneFailStreak = 0; // провалы data-plane подряд за сессию (кап — ConnectTunables.h)
    bool          m_dataPlaneExhausted = false; // кап исчерпан: Error вместо очередного failover
    qint64        m_upStartedMs = 0;     // момент последнего up() — время до «реального трафика» для истории
    bool          m_okRecorded = false;  // один успех / один провал на сессию подъёма
    bool          m_failRecorded = false;
    std::optional<Subscription> m_pendingReseed; // отложенное тело reseed (применить в терминале)
};

} // namespace avpn
