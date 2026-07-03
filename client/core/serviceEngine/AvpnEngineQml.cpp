#include "AvpnEngineQml.h"

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/utils/errorStrings.h" // AVPN: errorString(ErrorCode) → текст для error()
#include "vpnConnection.h"
#include "Enrollment.h" // AVPN: authToken() → Enrollment::loadToken()
#include "Identity.h"   // AVPN: localDeviceId() → installation-UUID (раздел «Устройства» всегда показывает ID)
#include "DeviceModel.h" // AVPN: нативные имя/ОС текущего устройства (раздел «Устройства»)
#include "QualityProbe.h" // AVPN (реальные палочки): app-layer RTT-проба через туннель
#include "ServiceProbe.h" // AVPN (чипы доступности): проба Telegram/YouTube через туннель
#include "NodeRanking.h"  // AVPN (выбор по скорости): RTT→палочки + сортировка «быстрые внизу»
#include "RttProbeIcmp.h" // AVPN (выбор по скорости): прямой ICMP-замер RTT до нод off-tunnel
#include "BenchRunner.h"  // AVPN (панель администратора): in-app бенч соединения
#include "AvpnIntentBridge.h" // AVPN (Task E): консьюмер «намерений» App Intent авто-паузы → pause/resume
#include "AvpnPushBridge.h" // AVPN (Task 9): device token → /v1/devices/push-token; markAllRead → /v1/notifications/read
#include "ru_prefixes.h"          // AVPN RU-direct: весь рунет CIDR для split-tunnel (applyRuBypassSplit)
#include "core/utils/routeModes.h" // AVPN RU-direct: amnezia::RouteMode::VpnAllExceptSites
#include <QMap>                    // AVPN RU-direct: bulk addVpnSites

#include <QCoreApplication> // AVPN (Task 9): applicationVersion() → app_version в push-token
#include <QDateTime>
#include <QJsonDocument> // AVPN (панель администратора): сериализация результата бенча
#include <QSysInfo>      // AVPN (панель администратора): platform в extra{} бенча
#include <QSettings> // AVPN (Task 7): чтение тумблера AvpnSettings/autoPauseRu (общий стор с QML Settings)
#include <QVariantList>
#include <QScopedValueRollback> // AVPN (краш-фикс): RAII-флаг m_inSyncNetCall вокруг вложенного QEventLoop
// AVPN (Devices+Account): синхронные REST-вызовы к control plane, как fetchSubscription.
#include "NetAwait.h" // AVPN: awaitReply() — ожидание с таймаутом (анти-фриз GUI)
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
#include "MacServiceInstaller.h" // AVPN (macOS desktop): авто-установка root-демона из вшитого pkg (ноль терминала)
#include <QThread>
#endif

namespace avpn {

AvpnEngineQml::AvpnEngineQml(VpnConnection *conn, SecureAppSettingsRepository *store,
                             QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent), m_tunnel(conn, this), m_store(store), m_nam(nam), m_conn(conn)
{
    // dev/E2E: переопределение control plane (напр. http://127.0.0.1:48480 — локальный бэкенд)
    const QByteArray envUrl = qgetenv("AVPN_API_URL");
    if (!envUrl.isEmpty())
        m_baseUrl = QString::fromUtf8(envUrl);

    m_engine.setTunnel(&m_tunnel);
    m_tunnel.setStore(store); // AVPN RU-direct: гейт сплита по фактической ноде — в up() (T2)

    // AVPN (выбор по скорости): прямой ICMP-пробер RTT до нод (off-tunnel). Кроссплатформенный за швом
    // IRttProbe; Windows — graceful-стаб (нет измерения → health-фолбэк). Запуск — из probeNodeRtt().
    m_rttProbe = new RttProbeIcmp(this);

    // AVPN (панель администратора): in-app бенч соединения. Запуск ТОЛЬКО вручную (startBench из QML),
    // коннект-путь не трогает; результат — schema:1 (сводится с Mac-замерами tools/connect-bench).
    m_bench = new BenchRunner(m_nam, this);
    connect(m_bench, &BenchRunner::stageChanged, this, [this](const QString &st) {
        m_benchStage = st;
        emit benchChanged();
    });
    connect(m_bench, &BenchRunner::finished, this, [this](const QJsonObject &result) {
        m_benchRunning = false;
        emit benchChanged();
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
        emit benchFinished(s, QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact)));
    });

    // health-loop driver: периодический tick (3–5с).
    m_healthTimer.setInterval(4000);
    connect(&m_healthTimer, &QTimer::timeout, this, &AvpnEngineQml::onTick);

    // AVPN (реальные палочки): app-layer RTT-проба ЧЕРЕЗ туннель. AWG UDP-only ⇒ ICMP/TCP-пинг до
    // эндпоинта пуст; реальный RTT даёт крошечный HTTPS-запрос к generate_204 через поднятый full-tunnel.
    // Эндпоинты по приоритету: свой бэкенд-пинг (тот же путь, что и control plane) → публичный фолбэк.
    // Поток RTT → m_signal (EWMA+гистерезис) → liveBars 0..5. Запуск — из onTick(), когда Connected.
    m_probe = new QualityProbe(m_nam, this);
    m_probe->setEndpoints({m_baseUrl + QStringLiteral("/v1/ping"),
                           QStringLiteral("https://connectivitycheck.gstatic.com/generate_204")});
    connect(m_probe, &QualityProbe::result, this, [this](int rttMs, bool reachable) {
        m_liveBars = m_signal.feed(rttMs, reachable);
        m_liveRtt = m_signal.smoothedRtt();
        m_liveReachable = reachable;
        // AVPN (красные палочки): различаем «ещё мерю» (m_liveDead=false → плейсхолдер 1 зелёная)
        // и «связь подтверждённо мертва» (m_liveDead=true → 0 зелёных + все красные). Один таймаут
        // в «мертво» НЕ роняем — ждём kLiveDeadStreak неудач подряд (анти-фликер на транзиентном дропе).
        if (reachable) {
            m_liveFailStreak = 0;
            m_liveDead = false;
        } else if (++m_liveFailStreak >= kLiveDeadStreak) {
            m_liveDead = true;
        }
        emit liveQualityChanged();
    });

    // AVPN (чипы доступности): проба «работает ли сервис через ЭТУ ноду» — с устройства через туннель
    // (бэкенд знать не может: доступность = f(юзер,сеть,регион,нода,время)). Все три меряются РЕАЛЬНОЙ
    // работоспособностью, а не reachability (иначе ложно-зелёный при DPI-троттлинге):
    //   • Telegram — login-free MTProto-handshake к seed-DC-IP (resPQ ⇒ дата-плейн жив);
    //   • YouTube/Instagram — GOODPUT: качаем ~128 КБ с реального душимого CDN (googlevideo/cdninstagram)
    //     и меряем kbit/s (RU-троттл ~128 кбит/с ⇒ slow; норм ⇒ works; путь срезан ⇒ blocked). См. ServiceProbe.h.
    {
        QList<ServiceProbeConfig> cfgs;
        // Telegram: несколько seed-DC-IP (OONI-стабильные DC2/DC4/DC5) — первый ответивший resPQ ⇒
        // works; так один сменившийся/легший IP не даёт ложный «заблок». Рефреш через help.getConfig — TODO.
        cfgs.append({QStringLiteral("telegram"),  ServiceProbeConfig::Mtproto,
                     QStringLiteral("149.154.167.51"), 443, 1500,
                     QStringList{QStringLiteral("149.154.167.91"), QStringLiteral("91.108.56.130")}});
        // host = fallback-SNI на душимом CDN (reachability, если byte-source не резолвится). port по умолчанию,
        // sampleBytes/пороги goodput — дефолтные (128 КБ; works≥1000, slow≥100 кбит/с).
        cfgs.append({QStringLiteral("youtube"),   ServiceProbeConfig::Goodput,
                     QStringLiteral("redirector.googlevideo.com")});
        cfgs.append({QStringLiteral("instagram"), ServiceProbeConfig::Goodput,
                     QStringLiteral("static.cdninstagram.com")});
        m_svcProbe = new ServiceProbe(m_nam, this);
        m_svcProbe->setServices(cfgs);

        // Сидируем список статусов (state=-1 «неизвестно») в порядке cfgs — UI рисует чипы сразу.
        auto labelOf = [](const QString &k) {
            if (k == QLatin1String("telegram"))  return QStringLiteral("Telegram");
            if (k == QLatin1String("youtube"))   return QStringLiteral("YouTube");
            if (k == QLatin1String("instagram")) return QStringLiteral("Instagram");
            return k;
        };
        for (const ServiceProbeConfig &c : cfgs) {
            QVariantMap m;
            m[QStringLiteral("key")] = c.key;
            m[QStringLiteral("label")] = labelOf(c.key);
            m[QStringLiteral("state")] = -1;
            m[QStringLiteral("rttMs")] = -1;
            m_serviceStatus.append(m);
        }
        connect(m_svcProbe, &ServiceProbe::result, this,
                [this](const QString &key, int state, int rttMs) {
                    // rttMs для goodput-сервисов (youtube/instagram) несёт kbit/s, для telegram — RTT в мс.
                    static const char *stName[] = {"blocked", "slow", "works"};
                    qInfo("[AVPN svc] %s state=%s metric=%d",
                          key.toUtf8().constData(),
                          (state >= 0 && state <= 2) ? stName[state] : "unknown", rttMs);
                    for (int i = 0; i < m_serviceStatus.size(); ++i) {
                        QVariantMap m = m_serviceStatus.at(i).toMap();
                        if (m.value(QStringLiteral("key")).toString() == key) {
                            m[QStringLiteral("state")] = state;
                            m[QStringLiteral("rttMs")] = rttMs;
                            m_serviceStatus[i] = m;
                            break;
                        }
                    }
                    emit serviceStatusChanged();
                });
    }

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

    // AVPN (Task E): консьюмер «намерений» фонового iOS App Intent (Task 8). Интент в фоне уже
    // реально опустил/поднял туннель и записал флаг в App Group; при выходе в foreground натив-слой
    // (QtAppDelegate.mm → Avpn_consumeIntentFlags → AvpnIntentController.mm) эмитит сигналы моста.
    // Здесь согласуем СВОЁ состояние: pause → pauseForShopping (m_paused + гасим failover),
    // resume → resumeFromPause. На desktop мост молчит (Avpn_consumeIntentFlags — no-op).
    connect(avpn::AvpnIntentBridge::instance(), &avpn::AvpnIntentBridge::pauseRequested,
            this, [this]() { pauseForShopping(); });
    connect(avpn::AvpnIntentBridge::instance(), &avpn::AvpnIntentBridge::resumeRequested,
            this, &AvpnEngineQml::resumeFromPause);

    // AVPN (Task 9 — APNs): мост пушей. Натив (AvpnPushController.mm) кладёт device token + окружение в
    // мост; здесь, получив deviceTokenReady, шлём токен на бэк авторизованно (Bearer subscription_token).
    // На desktop мост молчит (нет натив-регистратора). markAllRead из QML → readRequested → сброс
    // серверного счётчика. Singleton-мост, как AvpnIntentBridge.
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::deviceTokenReady,
            this, [this](const QString &token, const QString &platform, const QString &environment) {
                if (platform == QLatin1String("ios")) // Android-FCM пойдёт своим путём позже
                    registerPushToken(token, environment);
            });
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::readRequested,
            this, &AvpnEngineQml::markNotificationsRead);

    // AVPN (Task 9): разрешение на пуши спрашиваем ОДИН раз — после первого успешного коннекта (UX:
    // контекстный запрос). Persist, чтобы не пытаться при каждом коннекте (iOS и так дедупит промпт).
    {
        QSettings s;
        m_pushPermissionAsked = s.value(QStringLiteral("AvpnPush/permissionAsked"), false).toBool();
    }

    // реактивный failover + правдивый статус: реальное состояние туннеля. // AVPN
    if (m_conn) {
        connect(m_conn, &VpnConnection::connectionStateChanged,
                this, &AvpnEngineQml::onConnectionStateChanged, Qt::QueuedConnection);
        // AVPN: протокол-уровневые ошибки (ErrorCode) идут отдельным сигналом — раньше терялись.
        connect(m_conn, &VpnConnection::vpnProtocolError,
                this, &AvpnEngineQml::onVpnProtocolError, Qt::QueuedConnection);
    }

    // AVPN (Task 11): тихий bootstrap при создании движка — наполнить подписку ДО первого Connect,
    // чтобы бейдж ГБ/дней/subActive был живой сразу. Дефер через singleShot(0): bootstrap() делает
    // синхронный сетевой вызов (QEventLoop), поэтому не блокируем конструктор/инициализацию UI —
    // отдаём управление циклу событий. КРАШ-ФИКС: singleShot(0) слишком рано — bootstrap крутит
    // вложенный QEventLoop, и если он сработает во время загрузки/показа QML, вложенный цикл
    // прокручивает чужие события (таймеры/фокус) на недостроенном дереве → re-entrancy SIGSEGV
    // (QQuickItem::setFocus). 1200мс гарантируют, что окно показано и loop простаивает (как при
    // пользовательском start()). Идемпотентно (m_bootstrapped). // AVPN
    QTimer::singleShot(1200, this, &AvpnEngineQml::bootstrap);
}

QString AvpnEngineQml::state() const
{
    // AVPN (Task 7): «paused» — наша надстройка над фазами движка (туннель реально down, ждём
    // авто-возврат). Перекрывает disconnected, чтобы UI отличал паузу-для-покупок от обычного стопа.
    if (m_paused)
        return QStringLiteral("paused");
    return debugSnapshot().value(QStringLiteral("state")).toString();
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

// AVPN: текущий сервер для карточки Connect. Показываем ноду ТОЛЬКО когда реально подключены/
// переключаемся; до коннекта и после стопа hasNode=false → карточка показывает «Умный выбор сервера»
// (умный выбор происходит в момент connect, выбранная нода видна уже подключённой). Без fallback на
// pool.first() — иначе в простое показывалась «Польша».
QVariantMap AvpnEngineQml::currentNode() const
{
    const DebugSnapshot s = m_engine.debugSnapshot();
    const bool live = (s.state == QLatin1String("connected") || s.state == QLatin1String("switching"));
    const QString pinned = m_engine.pinnedNodeId();
    // Какой узел показывать на карточке Connect:
    //  • онлайн (connected/switching) → реальный текущий узел (s.currentNodeId);
    //  • НЕ онлайн, но закреплён пользователем → закреплённый (виден сразу после выбора в шторке,
    //    ещё ДО нажатия Connect — модель «выбор = задать цель, коннект — кнопкой»);
    //  • иначе → ничего (hasNode=false) → карточка показывает «Умный выбор сервера».
    QString showId;
    if (live && !s.currentNodeId.isEmpty())
        showId = s.currentNodeId;
    else if (!pinned.isEmpty())
        showId = pinned;
    const NodeDebugRow *pick = nullptr;
    if (!showId.isEmpty()) {
        for (const NodeDebugRow &r : s.pool)
            if (r.nodeId == showId) { pick = &r; break; }
    }
    QVariantMap node;
    node["nodeId"]    = pick ? pick->nodeId : QString();
    node["region"]    = pick ? pick->region : QString();
    node["name"]      = pick ? pick->name : QString();
    node["countryCode"] = pick ? pick->countryCode : QString(); // AVPN: для флага-эмодзи
    node["endpoint"]  = pick ? pick->endpoint : QString();
    node["ip"]        = pick ? pick->endpoint.section(QLatin1Char(':'), 0, 0) : QString();
    node["connected"] = (s.state == QLatin1String("connected"));
    node["hasNode"]   = (pick != nullptr);
    // AVPN: бейдж «auto» — показываем ТОЛЬКО когда подключены в авто-режиме (узел выбрал движок, pin
    // пуст). При ручном выборе (pin задан) бейджа нет. pinned — что показанный узел закреплён вручную.
    node["pinned"]    = (!pinned.isEmpty() && pick && pick->nodeId == pinned);
    node["auto"]      = (s.state == QLatin1String("connected") && pinned.isEmpty());
    return node;
}

// AVPN: весь пул нод для страницы «Серверы» / шторки выбора.
// Обогащаем измеренным RTT (m_nodeRtt) → measuredRttMs + measuredBars (0..5; -1 = не мерили), затем
// сортируем «быстрые ВНИЗУ» (неизмеренные сверху). Без измерений порядок не меняется (все rtt=-1 ⇒
// rankFastestAtBottom стабилен) и палочки берутся из health, как и раньше (поведение идентично).
QVariantList AvpnEngineQml::nodePool() const
{
    QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();

    QHash<QString, QVariantMap> byId;
    QList<RankRow> rows;
    rows.reserve(pool.size());
    for (const QVariant &v : pool) {
        QVariantMap n = v.toMap();
        const QString id = n.value(QStringLiteral("nodeId")).toString();
        const int rtt = m_nodeRtt.value(id, -1);
        n[QStringLiteral("measuredRttMs")] = rtt;
        n[QStringLiteral("measuredBars")] = (rtt >= 0) ? barsForNode(rtt) : -1;
        byId.insert(id, n);
        rows.append({ id, rtt });
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
    if (!m_rttProbe)
        return;
    // Через поднятый туннель замер к чужим нодам идёт ВНУТРИ туннеля (смазан) — держим кэш, не мерим.
    if (state() == QLatin1String("connected")) {
        m_rttProbe->cancel();
        return;
    }
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
    if (targets.isEmpty())
        return;

    m_rttProbe->probeAll(
        targets, 1500,
        [this](const QString &nodeId, int rttMs) {
            m_nodeRtt.insert(nodeId, rttMs);
            m_engine.setMeasuredRtt(m_nodeRtt); // AVPN: авто-выбор «быстрейший» берёт RTT отсюда (pickByMeasuredRtt)
            emit changed(); // шторка пересортируется + палочки обновятся по мере прихода пингов
        },
        []() {});
}

void AvpnEngineQml::onTick()
{
    if (m_engine.tick(QDateTime::currentSecsSinceEpoch()))
        emit changed(); // произошёл свитч

    // AVPN (реальные палочки): пока соединение активно — мерим RTT через туннель (async, без nested loop).
    // measure() сам игнорит повторный запуск, пока предыдущий в полёте. На не-connected — не мерим
    // и держим бары на 0 (hard-gate сбросит при следующем reachable=false, см. ниже onConnectionStateChanged).
    if (m_probe && state() == QLatin1String("connected"))
        m_probe->measure();

    // AVPN (#35 живой трафик): пока подключены — каждый 5-й тик (~20с) освежаем счётчики из /v1/account
    // (бэк-истина; used растёт по мере расхода). refreshAccount пишет назад в подписку + emit changed()
    // → бейдж «остаток ГБ» убывает постепенно (3.1→2.9→…). Не каждый тик — беречь батарею/трафик.
    if (state() == QLatin1String("connected")) {
        if (++m_trafficSyncTicks >= 5) {
            m_trafficSyncTicks = 0;
            refreshAccount();
        }
    } else {
        m_trafficSyncTicks = 0; // сброс, чтобы первый ре-синк после коннекта был через полный интервал
    }
}

void AvpnEngineQml::probeServices()
{
    // Только при активном туннеле: иначе мерили бы доступность «мимо VPN» (не наша цель — нам нужно
    // «работает ли сервис ЧЕРЕЗ эту ноду»). On-connect (авто) + по тапу из UI; НЕ поллинг (батарея).
    if (m_svcProbe && state() == QLatin1String("connected"))
        m_svcProbe->probeAll();
}

// AVPN (панель администратора): in-app бенч. Валиден в ЛЮБОМ состоянии туннеля (baseline = VPN off;
// замер ванильной Amnezia = её NE-туннель системный). extra фиксирует контекст запуска в результат.
void AvpnEngineQml::startBench(const QString &label)
{
    if (m_benchRunning || !m_bench)
        return;
    QJsonObject extra;
    extra.insert(QStringLiteral("platform"), QSysInfo::productType());
    extra.insert(QStringLiteral("app_ver"), QCoreApplication::applicationVersion());
    extra.insert(QStringLiteral("tunnel_state"), state());
    extra.insert(QStringLiteral("node_id"), debugSnapshot().value(QStringLiteral("currentNodeId")).toString());
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start");
    emit benchChanged();
    m_bench->start(label, extra);
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

void AvpnEngineQml::onConnectionStateChanged(Vpn::ConnectionState s) // AVPN
{
    m_lastTunnelState = s; // AVPN: кэш реального состояния туннеля (для отложенного start() при смене узла)
    // Правдивый статус: маппим РЕАЛЬНОЕ состояние VpnConnection в фазу движка. up() лишь ставит
    // туннель в очередь (async) и НЕ объявляет Connected — переход прилетает сюда.
    switch (s) {
    case Vpn::Connected:
        m_engine.onTunnelConnected();
        if (m_rttProbe)
            m_rttProbe->cancel(); // подключились → off-tunnel ICMP больше не нужен (был бы внутри туннеля)
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
        QTimer::singleShot(1500, this, &AvpnEngineQml::probeServices);
        QTimer::singleShot(1800, this, [this]() {
            if (m_probe && state() == QLatin1String("connected"))
                m_probe->measure();
        });
        break;
    case Vpn::Error:
        // AVPN (анти-авто-коннект): РАНЬШЕ обрыв из Connected → notifyConnectionLost() → реактивный
        // авто-failover (реконнект). Это давало НЕЖЕЛАТЕЛЬНЫЙ авто-коннект, когда туннель гасит ВНЕШНЕ
        // (другой VPN / iOS / пользователь снял VPN): приложение тут же переподнимало туннель, «воюя»
        // с другим VPN и самоподключаясь при входе в приложение. Теперь как обычное VPN-приложение:
        // фиксируем факт, НЕ реконнектим сами. (Failover по РЕАЛЬНОЙ смерти ноды остаётся в health-loop
        // tick — onTick→m_engine.tick, см. §анти-авто-коннект ниже + CONNECT-INVARIANTS §13.)
        m_engine.onTunnelError();
        break;
    case Vpn::Disconnected:
        // onTunnelDisconnected САМ продолжит НАМЕРЕННЫЙ свитч ноды (Switching+pendingSwitch → up());
        // если это не свитч — просто «отключено». БЕЗ реактивного failover на внешний обрыв (см. Error).
        m_engine.onTunnelDisconnected();
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
    if (s == Vpn::Disconnected || s == Vpn::Error) {
        const QString est = m_engine.debugSnapshot().state; // DebugSnapshot-структура (поле, не QVariantMap)
        const bool weAreOperating = (m_op != Op::None); // наш guardedStart/guardedStop в полёте
        const bool engineSwitching = (est == QLatin1String("switching")
                                   || est == QLatin1String("connecting")
                                   || est == QLatin1String("selecting"));
        if (!weAreOperating && !engineSwitching)
            m_wantConnected = false;
    }

    // AVPN (reconcile-машина): терминальное состояние снимает op-in-flight и разрешает следующий шаг;
    // промежуточные (Connecting/Disconnecting/Reconnecting/Preparing) держим «занято» (UI «подбираем…»).
    {
        const bool terminal = (s == Vpn::Connected || s == Vpn::Disconnected
                               || s == Vpn::Error || s == Vpn::Unknown);
        if (terminal) {
            const Op finished = m_op;
            m_op = Op::None;
            m_opInFlight = false;
            m_busy = false;
            m_watchdog.stop();
            if (s == Vpn::Connected)
                m_startAttempts = 0;                 // успех — счётчик попыток сброшен
            else if (s == Vpn::Error && finished == Op::Starting)
                ++m_startAttempts;                   // connect не удался — считаем попытку (анти-зацикливание)
        } else {
            m_busy = true;                           // идёт переход — занято
        }
    }

    // AVPN (реальные палочки): туннель не в Connected → гасим живые палочки (кэш RTT не должен
    // маскировать обрыв). При следующем Connected проба пере-сидирует SignalQuality с нуля.
    if (state() != QLatin1String("connected")
        && (m_liveBars != 0 || m_liveReachable || m_liveRtt >= 0 || m_liveDead || m_liveFailStreak)) {
        m_signal.reset();
        m_liveBars = 0;
        m_liveRtt = -1;
        m_liveReachable = false;
        m_liveDead = false;        // обрыв/смена ноды → «мертво» снимаем, при новом Connected мерим заново
        m_liveFailStreak = 0;
        emit liveQualityChanged();

        // AVPN (чипы доступности): обрыв/смена ноды → статусы сервисов больше не актуальны → «неизвестно».
        bool anyKnown = false;
        for (int i = 0; i < m_serviceStatus.size(); ++i) {
            QVariantMap m = m_serviceStatus.at(i).toMap();
            if (m.value(QStringLiteral("state")).toInt() != -1) {
                m[QStringLiteral("state")] = -1;
                m[QStringLiteral("rttMs")] = -1;
                m_serviceStatus[i] = m;
                anyKnown = true;
            }
        }
        if (anyKnown)
            emit serviceStatusChanged();
    }

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
    // Протокол-уровневая ошибка раньше терялась (сигнал не был подключён). Surface наружу в error().
    // AVPN (анти-авто-коннект): больше НЕ зовём notifyConnectionLost() (реактивный failover/реконнект) —
    // фиксируем факт ошибки; подключение только вручную. См. onConnectionStateChanged выше.
    m_engine.onTunnelError();
    // AVPN (фикс залипания): ошибка ОБЯЗАНА снять op-in-flight (раньше не трогала m_pendingStart →
    // следующий start() мгновенно return → орб залипал навсегда). Теперь машина разблокируется.
    const Op finished = m_op;
    m_op = Op::None;
    m_opInFlight = false;
    m_busy = false;
    m_watchdog.stop();
    if (finished == Op::Starting)
        ++m_startAttempts;
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
    m_bootstrapRetries = 0;

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
// сетевые сбои не покрывает). Решение: переарм с бэкоффом 2/4/8/16/30с (кап 5 попыток ≈ 60с покрытия),
// тихо (без error()). Успех → m_bootstrapped=true (дедуп), пул наполнен, RTT-проба. Исчерпали → отпускаем
// m_bootstrapInFlight, чтобы следующий заход/Connect мог попробовать заново.
void AvpnEngineQml::tryBootstrapSubscription()
{
    QString err;
    if (m_engine.bootstrap(m_nam, m_baseUrl, m_store, err)) {
        m_bootstrapped = true;
        m_bootstrapInFlight = false;
        m_bootstrapRetries = 0;
        emit changed(); // подписка наполнена → Q_PROPERTY (daysLeft/traffic*/subActive/nodePool) обновятся
        probeNodeRtt(); // AVPN (выбор по скорости): тёплый off-tunnel ICMP при старте (туннель опущен) —
                        // чтобы ПЕРВЫЙ «Авто (быстрейший)» уже выбирал по реальному RTT, а не по weight.
        return;
    }
    // Провал — тихо. Переарм с бэкоффом, пока не исчерпаем кап.
    static constexpr int kBootstrapBackoffMs[] = {2000, 4000, 8000, 16000, 30000};
    static constexpr int kBootstrapMaxRetries = 5;
    if (m_bootstrapRetries >= kBootstrapMaxRetries) {
        m_bootstrapInFlight = false; // сдались тихо; следующий заход/ручной Connect попробует снова
        return;
    }
    const int delayMs = kBootstrapBackoffMs[m_bootstrapRetries];
    ++m_bootstrapRetries;
    QTimer::singleShot(delayMs, this, &AvpnEngineQml::tryBootstrapSubscription);
}

void AvpnEngineQml::start()
{
    // AVPN (Task 7): явный start() выходит из паузы (пользователь сам поднял VPN).
    m_pauseTimer.stop();
    m_paused = false;
    m_wasConnected = false;
    // Намерение: хотим быть онлайн (к авто/закреплённой ноде). Факт догонит reconcile() из терминала.
    m_wantConnected = true;
    m_startAttempts = 0;        // ручной запуск — свежая серия попыток
    reconcile();
}

void AvpnEngineQml::stop()
{
    // AVPN (Task 7): явный stop() отменяет ожидающую авто-паузу (пользователь сам выключил VPN).
    m_pauseTimer.stop();
    m_paused = false;
    m_wasConnected = false;
    // Намерение: хотим быть офлайн. reconcile() опустит туннель, если он поднят.
    m_wantConnected = false;
    m_needsRestart = false;
    m_startAttempts = 0;
    reconcile();
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

    const Vpn::ConnectionState s = m_lastTunnelState;
    const bool connected = (s == Vpn::Connected);
    // Error/Unknown/Disconnected = «можно действовать» (туннель де-факто не поднят). Error трактуем так
    // же, как Disconnected, иначе после ошибки teardown машина залипла бы (старый баг).
    const bool actionable = (s == Vpn::Disconnected || s == Vpn::Unknown || s == Vpn::Error);
    if (!connected && !actionable)
        return;          // промежуточное (Connecting/Disconnecting/Reconnecting/Preparing) — ждём

    if (m_wantConnected) {
        if (connected) {
            if (m_needsRestart) {        // надо переехать на другую ноду → сначала чистый teardown
                m_needsRestart = false;
                guardedStop();
            }
            // connected && !needsRestart → уже где надо
        } else {                         // офлайн, а хотим онлайн → поднимаем выбранную/авто ноду
            if (m_startAttempts >= 3) {  // постоянный провал connect — не зацикливаемся (ошибка уже показана)
                m_wantConnected = false;
                m_startAttempts = 0;
                return;
            }
            guardedStart();
        }
    } else {                             // хотим офлайн
        if (connected)
            guardedStop();
        // офлайн → уже отключены
    }
}

// AVPN: поднять туннель. startFlow = enroll→GET /v1/subscription→connect()→up() (async). Помечаем
// op-in-flight + сторож; m_busy держим до прихода Connected (UI «подбираем…»).
void AvpnEngineQml::guardedStart()
{
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
    // AVPN (ноль терминала): на macOS туннель поднимает root-демон Tribe-service. Нет демона —
    // ставим из ВШИТОГО pkg одним системным промптом пароля (MacServiceInstaller). Если демон уже
    // установлен/запущен — мгновенный выход, рабочий путь коннекта НЕ меняется. NB: без nested
    // QEventLoop/processEvents (CONNECT-INVARIANTS) — только короткий msleep на первом запуске.
    if (!avpn::macServiceRunning()) {
        if (!avpn::macServiceInstalled()) {
            QString ierr;
            if (!avpn::macInstallService(&ierr)) {
                ++m_startAttempts;
                emit error(ierr.isEmpty() ? tr("Не удалось установить службу VPN") : ierr);
                emit changed();
                return;
            }
        }
        // installer синхронно отработал postinstall (bootstrap демона) — ждём живой процесс до ~5с.
        for (int i = 0; i < 16 && !avpn::macServiceRunning(); ++i)
            QThread::msleep(300);
    }
#endif

    m_op = Op::Starting;
    m_opInFlight = true;
    m_busy = true;
    m_needsRestart = false;   // свежий старт всегда поднимает целевую (pin/auto) ноду — рестарт не нужен
    m_watchdog.start();
    emit changed();

    QString err;
    if (m_engine.identityEnsureKeys(m_store, err))
        m_tunnel.setClientKeys(m_engine.clientKeys());

    // AVPN RU-direct: засеять split-tunnel (рунет CIDR мимо туннеля) ДО подъёма — конфиг должен быть готов
    // к appendSplitTunnelingConfig, который читает routeMode/vpnSites из репозитория при openConnection.
    applyRuBypassSplit();

    // AVPN (КОРНЕВОЙ фикс зависания UI + краша на 2-м коннекте): если подписка УЖЕ загружена
    // (bootstrap при старте или прошлый connect) — поднимаем туннель ЛОКАЛЬНО через m_engine.connect(),
    // БЕЗ синхронного сетевого startFlow. startFlow крутит ВЛОЖЕННЫЙ QEventLoop на ГЛАВНОМ потоке
    // (enroll + GET /v1/subscription); на 2-м коннекте, когда летят сигналы дисконнекта, это давало
    // повторный вход вложенного цикла → «Hang UIKit-runloop» (по логам устройства) → abort(). В Amnezia
    // кнопка коннекта в сеть НЕ ходит — конфиг уже готов, она только поднимает туннель. Делаем так же.
    // AVPN (краш-фикс): startFlow() входит во вложенный QEventLoop (awaitReply). Держим m_inSyncNetCall
    // на время вызова, чтобы переисполнение guardedStart из этого цикла отложилось (см. гард выше), а не
    // застекало второй loop.exec(). QScopedValueRollback гарантирует сброс даже при исключении.
    bool ok;
    {
        QScopedValueRollback<bool> syncGuard(m_inSyncNetCall, true);
        ok = m_engine.hasSubscription() ? m_engine.connect(err)
                                        : m_engine.startFlow(m_nam, m_baseUrl, m_store, err);
    }
    if (!ok) {
        // Подъём не удался ДО туннеля (терминального колбэка не будет) — снимаем op-in-flight, считаем
        // попытку, показываем ошибку. Авто-ретрай не запускаем; орб станет «Connect».
        m_op = Op::None;
        m_opInFlight = false;
        m_busy = false;
        m_watchdog.stop();
        ++m_startAttempts;
        emit error(err);
        emit changed();
        return;
    }
    m_healthTimer.start();
    // up() в очереди — реальный Connecting→Connected/Error прилетит в onConnectionStateChanged, где
    // op-in-flight снимется. m_busy остаётся true до тех пор.
    emit changed();
}

// AVPN: опустить туннель. requestStop() гасит фазу/failover ДО down() (иначе прилетевший Disconnected
// переподнял бы ноду); реальный Disconnected снимет op-in-flight и reconcile поднимет цель при смене.
void AvpnEngineQml::guardedStop()
{
    m_op = Op::Stopping;
    m_opInFlight = true;
    m_busy = true;
    m_watchdog.start();
    m_healthTimer.stop();
    m_engine.requestStop();
    m_tunnel.down();
    emit changed();
}

// AVPN: сторож reconcile — терминальный колбэк не пришёл за таймаут (iOS NE иногда «молчит» при
// teardown или connect завис). Разблокируем машину, чтобы не залипнуть навсегда.
void AvpnEngineQml::onWatchdog()
{
    if (!m_opInFlight)
        return;
    const Op finished = m_op;
    m_op = Op::None;
    m_opInFlight = false;
    m_busy = false;
    if (finished == Op::Stopping) {
        // teardown не отрапортовал чистым Disconnected → считаем опущенным, отложенный старт пойдёт.
        m_lastTunnelState = Vpn::Disconnected;
        emit changed();
        reconcile();
    } else if (finished == Op::Starting && m_lastTunnelState != Vpn::Connected) {
        // connect завис без терминала → принудительный teardown (→ Disconnected → reconcile ретрайнет
        // с учётом анти-зацикливания m_startAttempts, либо остановится, если попытки исчерпаны).
        ++m_startAttempts;
        m_healthTimer.stop();
        m_engine.requestStop();
        m_tunnel.down();
        emit changed();
    } else {
        emit changed();
        reconcile();
    }
}

void AvpnEngineQml::reprobe()
{
    // AVPN: re-pick авто-ноды через единый reconcile (не дёргаем m_engine.connect() напрямую — это
    // обходило бы стейт-машину и давало back-to-back up()). Снимаем pin; если онлайн — перевыбираем.
    m_engine.clearPin();
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    if (st == QLatin1String("connected") || st == QLatin1String("connecting")
        || st == QLatin1String("switching") || st == QLatin1String("selecting")) {
        m_wantConnected = true;
        m_needsRestart = true;   // переподнять на свежевыбранной авто-ноде
        m_startAttempts = 0;
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

// AVPN (live-node picker): «Выбрать» сервер из шторки. Модель «выбор = задать цель, коннект —
// ВРУЧНУЮ кнопкой Connect» (по требованию пользователя): НЕ коннектим автоматически. setPinnedNode
// закрепляет узел; если сейчас онлайн — опускаем туннель (намерение «офлайн»), чтобы орб стал OFF и
// показал выбранную ноду. Пользователь подключается сам — это надёжный COLD-connect на закреплённую
// ноду (он не ловит iOS-гонку «старт поверх teardown», в отличие от авто-switch на подключённом).
// Шторка закрывается в QML (sheet.close()).
void AvpnEngineQml::switchToNode(const QString &nodeId)
{
    QString err;
    if (!m_engine.setPinnedNode(nodeId, err)) {
        emit error(err);
        return;
    }
    // Намерение: офлайн. Если онлайн — reconcile сделает guardedStop (орб OFF); офлайн — no-op.
    // Цель (pin) запомнена → следующий ручной Connect поднимет именно её.
    m_wantConnected = false;
    m_needsRestart = false;
    m_startAttempts = 0;
    reconcile();
    emit changed();
}

// AVPN (live-node picker): «Авто (быстрейший)» в шторке — СИММЕТРИЧНО ручному выбору узла (switchToNode):
// снимаем закрепление И уводим намерение в OFF. Пользователь жал «Авто» на ПОДКЛЮЧЁННОМ узле (напр.
// Poland) и ждёт, что главный экран ВЫЙДЕТ из «подключено к Польше» в состояние «авто — можно подключиться»
// (а НЕ останется висеть на старом узле — это была жалоба). reconcile сделает чистый guardedStop (орб OFF);
// карточка станет «Умный выбор сервера», следующий РУЧНОЙ Connect поднимет быстрейший по скорингу/weight.
// Модель «выбор = задать цель, коннект — кнопкой»: НЕ реконнектим автоматически (без back-to-back up()).
void AvpnEngineQml::selectAuto()
{
    m_engine.clearPin();
    m_wantConnected = false;
    m_needsRestart = false;
    m_startAttempts = 0;
    reconcile();        // онлайн → guardedStop (орб OFF); оффлайн → no-op
    emit changed();
}

// AVPN (live-node picker): кнопка «Обновить подключение» — round-robin на следующую живую ноду через
// единый reconcile (не дёргаем m_engine.rotateNext() напрямую — он имел свой контур свитча, конфликтуя
// с reconcile). Берём следующую живую ноду (чистый nextLiveNodeId, без side-effects), закрепляем как
// цель и просим переключиться: reconcile сделает stop→Disconnected→start на ней (iOS-safe).
void AvpnEngineQml::rotateNext()
{
    const QString next = m_engine.nextLiveNodeId();
    if (next.isEmpty()) {
        emit error(QStringLiteral("Недостаточно живых серверов для переключения"));
        return;
    }
    QString err;
    if (!m_engine.setPinnedNode(next, err)) {
        emit error(err);
        return;
    }
    m_wantConnected = true;
    m_needsRestart = true;
    m_startAttempts = 0;
    emit changed();
    reconcile();
}

// AVPN (live-node picker): пере-зачитать подписку/health и обновить nodePool. Тихий no-op при провале
// (оффлайн/нет токена) — как bootstrap, не пугаем пользователя ошибкой при простом обновлении списка.
void AvpnEngineQml::refreshPool()
{
    QString err;
    if (m_engine.bootstrap(m_nam, m_baseUrl, m_store, err)) {
        emit changed(); // nodePool/health обновлены → шторка перерисуется
        probeNodeRtt(); // AVPN (выбор по скорости): тёплый прямой замер RTT (no-op при connected)
    }
    // при провале — тихо (silent fail)
}

// AVPN (Task C): вход/восстановление по коду доступа (POST /v1/code/redeem). Синхронно (как enroll).
void AvpnEngineQml::redeemCode(const QString &code, const QString &evictDeviceId)
{
    if (m_busy)
        return;
    const QString trimmed = code.trimmed();
    if (trimmed.isEmpty()) {
        emit error(QStringLiteral("Введите код доступа"));
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
        // AVPN (Task 9): subscription_token ротирован → старый push token на сервере отвязан.
        // Пере-регистрируем известный device token под новым токеном (fingerprint сменился → не дедупнется).
        if (!m_pushToken.isEmpty())
            registerPushToken(m_pushToken, m_pushEnv);
        emit changed(); // daysLeft/traffic*/subActive/nodePool/authToken обновятся
        break;
    case avpn::CodeRedeemResult::BadCode:
        emit error(QStringLiteral("Неверный код доступа"));
        emit changed();
        break;
    case avpn::CodeRedeemResult::SeatLimit:
        // Мест нет — UI покажет devices[] для выбора кого отключить (повторный redeemCode с evictDeviceId
        // или DELETE /v1/devices/{id}). Не пишем error(), чтобы не дублировать модалкой выбора.
        emit seatLimitReached(devices);
        emit changed();
        break;
    case avpn::CodeRedeemResult::Failed:
    default:
        emit error(err.isEmpty() ? QStringLiteral("Не удалось активировать код") : err);
        emit changed();
        break;
    }
}

// AVPN (Task 13): принять перенос «как SIM» (POST /v1/transfer/redeem). Зовётся мостом диплинка
// (AvpnDeepLinkBridge) по tribe://transfer?t=… . Синхронно (как redeemCode).
void AvpnEngineQml::redeemTransfer(const QString &transferToken)
{
    if (m_busy)
        return;
    const QString trimmed = transferToken.trimmed();
    if (trimmed.isEmpty()) {
        emit error(QStringLiteral("Пустая ссылка переноса"));
        return;
    }

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
        emit error(QStringLiteral("Ссылка переноса недействительна или истекла"));
        emit changed();
        break;
    case avpn::TransferRedeemResult::SeatLimit:
        emit error(QStringLiteral("Достигнут лимит устройств"));
        emit changed();
        break;
    case avpn::TransferRedeemResult::Failed:
    default:
        emit error(err.isEmpty() ? QStringLiteral("Не удалось принять перенос") : err);
        emit changed();
        break;
    }
}

// AVPN (Task 13): выпустить перенос с ЭТОГО устройства (POST /v1/transfer, Bearer authToken).
QVariantMap AvpnEngineQml::createTransfer()
{
    QVariantMap result;
    if (m_busy)
        return result;

    m_busy = true;
    emit changed();

    avpn::TransferMintResponse resp;
    QString err;
    const bool ok = Enrollment::createTransfer(m_nam, m_baseUrl, authToken(), resp, err);

    m_busy = false;
    emit changed();

    if (!ok) {
        emit error(err.isEmpty() ? QStringLiteral("Не удалось создать перенос") : err);
        return result;
    }
    result.insert(QStringLiteral("transfer_token"), resp.transferToken);
    result.insert(QStringLiteral("deep_link"), resp.deepLink);
    return result;
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
    using amnezia::RouteMode;
    QSettings s;
    const bool masterOn = s.value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    // AVPN (T2, аудит 2026-07-02): здесь — только СЕВ списка при masterOn (и активное ВЫКЛ при OFF,
    // иначе прежний seed продолжил бы исключать рунет). Вкл/выкл сплита под РФ-ноду решается ПО
    // ФАКТИЧЕСКОЙ ноде в VpnConnectionTunnelControl::up() (покрывает failover/авто-RU-fallback/мёртвый
    // RU-pin — прежний гейт по pinnedNodeIsRu() тут расходился с реальностью, когда нода ≠ pin).
    if (!masterOn) {
        m_store->setSitesSplitTunnelingEnabled(false);
        return;
    }
    m_store->setRouteMode(RouteMode::VpnAllExceptSites);
    m_store->setSitesSplitTunnelingEnabled(true);
    QMap<QString, QString> sites;
    const QStringList ru = avpn::ruPrefixes();
    for (const QString &cidr : ru)
        sites.insert(cidr, cidr);   // key=CIDR (checkIpSubnetFormat пройдёт), value=CIDR

    // AVPN RU-direct: foreign-эндпоинты, которые РФ-приложения дёргают для гео/анти-фрод проверок и которые
    // ПАЛЯТ загран-IP → гоним их тоже direct (residential РФ-IP), иначе приложение видит «VPN». Найдено
    // ЗАХВАТОМ (rvi0/PKTAP, 2026-07-01): процесс Gosuslugi через туннель ходит ТОЛЬКО в эти два, оба отвечают
    // (видят наш выход). Узкие /24 — не весь Google/Level3. Расширять по мере находок из захватов др. РФ-прил.
    static const char *const kBypassExtra[] = {
        "216.239.38.0/24", // Google (QUIC 443) — Госуслуги attestation/Firebase-класс
        "8.6.112.0/24",    // Level3 (TLS 443)  — Госуслуги телеметрия/анти-фрод (POST ~1.5КБ)
    };
    for (const char *cidr : kBypassExtra)
        sites.insert(QString::fromLatin1(cidr), QString::fromLatin1(cidr));

    m_store->replaceVpnSites(RouteMode::VpnAllExceptSites, sites); // AVPN: реконсиляция, не merge
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

void AvpnEngineQml::reapplyBypass()
{
    if (!m_wantConnected)
        return;
    m_needsRestart = true;
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
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    m_wasConnected = (st == QLatin1String("connected") || st == QLatin1String("connecting")
                      || st == QLatin1String("switching") || st == QLatin1String("selecting"));

    m_paused = true;
    // Реально опускаем туннель: на паузе utun-детект ДОЛЖЕН показывать туннель опущенным (трафик
    // покупки идёт мимо VPN). AVPN (аудит N7): через guardedStop() — та же последовательность
    // (healthTimer.stop + requestStop + down), но с Op::Stopping/opInFlight/watchdog, т.е. внутри
    // reconcile-машины; на пришедшем Disconnected reconcile no-op по гейту m_paused.
    guardedStop();

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
    if (m_wasConnected)
        start(); // enroll→subscription→connect (идемпотентно по busy); поднимет лучшую ноду
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
        emit error(QStringLiteral("Не указано устройство"));
        return false;
    }
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        emit error(QStringLiteral("Нет авторизации"));
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
        emit error(QStringLiteral("Сеть недоступна: %1").arg(netErrStr));
        return false;
    }
    if (code == 401) {
        emit error(QStringLiteral("Сессия истекла"));
        return false;
    }
    if (code == 404) {
        emit error(QStringLiteral("Устройство не найдено"));
        return false;
    }
    if (code < 200 || code >= 300) {
        emit error(QStringLiteral("Не удалось отключить устройство (HTTP %1)").arg(code));
        return false;
    }
    emit changed(); // UI перечитает список устройств
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
            }
        }
        m_account = result;
        emit accountChanged();
        // AVPN (#35 живой трафик): свежие used/limit/expires из /v1/account — назад в подписку движка,
        // чтобы ЕДИНЫЙ источник числа (Q_PROPERTY trafficUsed/trafficLimit/daysLeft, читают snapshot →
        // подписку) обновился на ОБЕИХ страницах. changed() уведомляет бейдж/бар. Только при успешном
        // парсе (иначе не затираем валидные значения нулями от сетевого сбоя).
        if (!result.isEmpty()) {
            m_engine.updateSubscriptionTraffic(
                result.value(QStringLiteral("traffic_used")).toLongLong(),
                result.value(QStringLiteral("traffic_limit")).toLongLong(),
                result.value(QStringLiteral("expires_at")).toString());
            emit changed();
        }
    });
}

// AVPN (#37 рефералы): GET /v1/referral → {code, link, invited, days_earned}. Тот же async-паттерн,
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
            }
        }
        // 401/сеть/таймаут → пустая мапа (баннер покажет дефолтный оффер). Эмитим всегда.
        m_referral = result;
        emit referralChanged();
    });
}

// AVPN (оплата): POST /v1/cabinet/web-link (Bearer, тело пустое) → { url: "…?wl=<token>", expires_in }.
// Тот же async-паттерн, что refreshReferral (armTimeout, без вложенного QEventLoop). Сигнал
// cabinetLinkReady эмитится на ЛЮБОМ исходе: успех → url бэка + device_uuid (кабинет откроет шит
// тарифов на этом устройстве), провал → fallback https://tribevpn.com/account + device_uuid.
void AvpnEngineQml::requestCabinetLink()
{
    const QString fallback = Enrollment::appendDeviceUuid(
        QStringLiteral("https://tribevpn.com/account"), localDeviceId());
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
    connect(reply, &QNetworkReply::finished, this, [this, reply, fallback]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QString url = fallback;
        if (code >= 200 && code < 300) {
            WebLinkResponse wl;
            QString err;
            if (Enrollment::parseWebLinkResponse(reply->readAll(), wl, err))
                url = Enrollment::appendDeviceUuid(wl.url, localDeviceId());
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
    body.insert(QStringLiteral("platform"), QStringLiteral("ios"));
    if (!environment.isEmpty())
        body.insert(QStringLiteral("environment"), environment);
    const QString ver = QCoreApplication::applicationVersion();
    if (!ver.isEmpty())
        body.insert(QStringLiteral("app_version"), ver);

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
        emit error(QStringLiteral("Сначала войдите или подключитесь"));
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
            bootstrap();      // перечитать подписку
            emit changed();
        } else if (code == 404) {
            emit error(QStringLiteral("Сброс триала выключен на сервере"));
        } else {
            emit error(QStringLiteral("Не удалось сбросить триал (код %1)").arg(code));
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
        pool.append(n);
    }
    m["pool"] = pool;

    QVariantList log;
    for (const QString &l : s.switchLog)
        log.append(l);
    m["switchLog"] = log;
    return m;
}

} // namespace avpn
