# serviceEngine — умный движок ANTI VPN (overlay поверх Amnezia)

Наш C++-движок сервисной модели: подписка/пул → выбор ноды → health/failover. **Overlay-код:**
живёт целиком здесь, апстрим Amnezia не модифицирует. Цель — чтобы обновления Amnezia (включая
протоколы) накатывались легко, не ломая нас. «Приложение над приложением».

> Источник правды по дизайну/контракту — `~/IdeaProjects/AntiVPN-Backend/documents/` (implimintation.md,
> backend_plan.md, CLIENT.md) + контракт `api/openapi.yaml`. Этот модуль реализует клиентскую часть.

## Overlay-принцип (как не сломаться при обновлении Amnezia)
1. **Весь наш код — в отдельных папках/файлах:** `core/serviceEngine/*`, наши QML `Pages2/*Avpn.qml`,
   `Pages2/PageDiagnostics.qml`. Апстрим-файлы по возможности НЕ редактируем.
2. **Каждое неизбежное касание апстрима — помечать `// AVPN`** (грепается), чтобы после `git pull`
   из upstream легко найти и переприменить. Текущие касания см. ниже.
3. **Композиция, не модификация:** новые страницы вместо правки чужих; роутинг на наши экраны вместо
   переписывания PageHome; вызовы движка через тонкий адаптер вместо переплетения с VpnConnection.
4. **Движок не зависит от внутренних имён Amnezia.** Контракт бэкенда — «чистый», маппинг в реальные
   ключи Amnezia (`client_ip`/`Jc..I5`/…) делает адаптер `ITunnelControl` (см. implimintation §6.3).
5. Туннель/обфускацию (amneziawg) **переиспользуем как есть** — свой только слой решений сверху.

## Касания апстрима (держать минимальными, все помечены `// AVPN`)
- `cmake/avpn.cmake` — наши сорсы (изолировано); включается 1 строкой `include(...avpn.cmake)` в CMakeLists.
- `Pages2/PageStart.qml` — роутинг на `PageHomeTribe` (метки `// AVPN`).
- `Pages2/PageHome.qml` — временная кнопка «‹ AntiVPN» (метка `// AVPN`, потом убрать).
- (план) `ui/controllers/connectionUiController` — тонкий вызов `ServiceEngine` вместо прямого openConnection.
- (план) `ITunnelControl`-реализации поверх штатного awg: desktop `daemon switchServer/updatePeer`,
  iOS `WireGuardAdapter.update` via `sendProviderMessage`, Android — новый JNI `set/syncconf`.

## Структура
```
dto/Subscription.h            — структуры контракта (Subscription/Node/AwgParams)
SubscriptionParser.{h,cpp}    — парсинг тела GET /v1/subscription (Qt JSON) + валидация граблей §6.4
AwgConfigBuilder.{h,cpp}      — DTO → QJsonObject для VpnConnection::connectToVpn (+ wg-quick текст)  ✅ протестирован
ITunnelControl.h              — граница с туннелем (up/applyPeer/readStats/down)
VpnConnectionTunnelControl.{h,cpp} — УНИВЕРСАЛЬНАЯ реализация поверх VpnConnection (in-fork build)
Identity.{h,cpp}              — ключи: REUSE WireguardConfigurator::genClientKeys + SecureAppSettingsRepository [in-fork]
Enrollment.{h,cpp}            — /v1/trial: REUSE networkManager форка; чистые builders/parsers ✅ протестированы
NodePool.h                    — реестр нод текущей подписки                                        [stub]
Prober.{h,cpp}                — TCP-ping пула (QtNetwork), параллельно + таймаут                   ✅ протестирован (вкл. live)
Selector.h                    — выбор: score=rtt/weight + гистерезис + джиттер (чистые score/choose) ✅ протестирован
IRttProbe.h                   — шов прямого per-node RTT off-tunnel (как ITunnelControl)
RttProbeIcmp.{h,cpp}          — ICMP-пробер: POSIX unprivileged (Darwin/iOS/Linux/Android), Win=стаб ✅ протестирован (live ICMP)
NodeRanking.h                 — RTT→палочки + сортировка «быстрые внизу» для шторки выбора          ✅ протестирован
HealthLoop.h                  — DEAD-детект (one-way death: tx растёт+rx стоит+handshake устарел, N циклов) ✅ протестирован
Switcher.h                    — переключение на кандидата через applyPeer (MVP: down+up)
DebugSnapshot.h               — данные для диагностической панели (5 тапов); UI — Pages2/PageDiagnostics.qml ✅
ServiceEngine.{h,cpp}         — оркестратор (+ startFlow: enroll→subscription→connect; switchLog; snapshot)
AvpnEngineQml.{h,cpp}         — QObject-фасад для QML (context property "AvpnEngine"): start/stop/reprobe/
                                manualSwitch/resetLkg + debugSnapshot()→QVariantMap; health-QTimer; реактивный failover
tests/                        — фикстура + автономная проверка (парсер + билдер + enrollment + selector + health
                                + node_ranking_check + rtt_icmp_check[live ICMP])

## Интеграция в приложение (C-7, выполнена)
- **Сборка:** `client/cmake/avpn.cmake` подключён 1 строкой в `CMakeLists.txt` (`// AVPN`). Опция
  **`AVPN_ENGINE`** (по умолчанию ON) ставит `AVPN_ENGINE_ENABLED=1`; `-DAVPN_ENGINE=OFF` = ванильный форк (kill-switch).
- **Регистрация:** `CoreController::initialize` под `#ifdef AVPN_ENGINE_ENABLED` создаёт `AvpnEngineQml`
  (переиспользуя `m_vpnConnection`, `m_appSettingsRepository`, `amnApp->networkManager()`) и
  `setQmlContextProperty("AvpnEngine", …)`. Касание апстрима — 1 ifdef-блок + 1 include.
- **QML:** `PageHomeTribe` зовёт `AvpnEngine.start()`; `PageDiagnostics` читает `AvpnEngine.debugSnapshot()`
  (бейдж `engine` вместо `demo`). Панель уже грациозно деградирует, если `AvpnEngine` нет (демо-режим).
- **Статус:** код написан; **первая полная in-fork сборка — на стороне сборки форка** (здесь не компилируется:
  тяжёлый Conan/Qt). Автономный регресс (pure-части) зелёный. При ошибке компиляции overlay → `-DAVPN_ENGINE=OFF`.
```

## Интеграция с туннелем (C-2) — один адаптер на все платформы
Подтверждено разведкой: единая кросс-платформенная точка — **`VpnConnection::connectToVpn(serverId,
container, QJsonObject)`** / `disconnectFromVpn()` (внутри уже #ifdef desktop-daemon / iOS-NE / Android).
Поэтому `ITunnelControl` реализован ОДНИМ классом `VpnConnectionTunnelControl` — он строит конфиг
(`AwgConfigBuilder`) и зовёт `connectToVpn` через очередь (VpnConnection в своём QThread). Никаких
трёх реализаций: платформенную разницу уже держит сам VpnConnection.

**In-place peer swap (быстрее, чем reconnect) — стадированная оптимизация** (наружу VpnConnection
switch не отдаёт; MVP `applyPeer` = down+up):

| Платформа | Готовность swap | Что доделать |
|---|---|---|
| Desktop (mac/win/linux) | есть в демоне (`Daemon::switchServer`→`updatePeer`) | держать `serverIpv4Gateway`/`deviceIpv4Address` const (стабильный /32), иначе `supportServerSwitching` откажет |
| iOS | NE умеет (`WireGuardAdapter.update`) | дописать app-сторону: слать wg-quick через `sendVpnExtensionMessage` → `handleWireguardAppMessage` |
| Android | нет | новый JNI `awgSetConfig(handle, uapi)` в `GoBackend.kt` (`set=`/syncconf) + Kotlin-обёртка |

Стат handshake для DEAD-детекта на этом слое не отдаётся (только rx/tx). Источники по платформам:
desktop `Daemon::getStatus`/`getPeerStatus`, iOS `checkStatus`→`handleWireguardStatusMessage`,
android `getLastHandshake` — подключим в C-5.

## Проверить парсер локально (без тяжёлой сборки форка)
```bash
core/serviceEngine/tests/build_check.sh    # QtCore-only; парсит fixtures/subscription.example.json
```
Ожидаемо: `OK: subscription parsed & validated cleanly`.

## Дорожная карта (фазы плана)
- **C-1:** структура + DTO + парсер + валидация. ✅ компилируется/парсит.
- **C-2:** `AwgConfigBuilder` (DTO→QJsonObject) ✅ протестирован; `VpnConnectionTunnelControl`
  (универсальный адаптер над VpnConnection) написан [in-fork build]; in-place swap по платформам — стадирован (таблица выше).
- **C-3:** enrollment — `Identity` (REUSE `genClientKeys` + `SecureAppSettingsRepository`/`getInstallationUuid`),
  `Enrollment` (REUSE `networkManager` форка, POST /v1/trial), подключён в `ServiceEngine::enroll`.
  Чистые builders/parsers ✅ протестированы; сетевой `enroll()` — in-fork. **Ноль правок кода форка** —
  только вызовы публичных API (принцип: надстройка модульно-поверхностная).
- **C-4 ✅:** `Prober` (TCP-ping пула, QtNetwork) + `Selector` (score=rtt/weight + гистерезис + джиттер);
  подключён в `ServiceEngine::connect`. Чистые score/choose протестированы; TCP-ping проверен вживую.
  URL-test через туннель (proactive в connected) + off-tunnel при поднятом full-tunnel — позже (спайк §9.3).
- **C-5 ✅:** `HealthLoop` (DEAD-детект: tx↑ + rx стоит + handshake устарел/неизвестен, N циклов подряд;
  простой/свежий-handshake → alive) + `Switcher` (свитч на кандидата с исключением мёртвой ноды).
  Подключено в `ServiceEngine`: `tick(now)` (периодический, читает stats→feed→onDead) +
  `notifyConnectionLost()` (реактивный). Чистая логика протестирована. Драйвер QTimer 3–5с и платформенный
  источник handshake (desktop getStatus / iOS checkStatus / android getLastHandshake) — тонкая обвязка in-fork.
- **C-6 ✅:** `Pages2/PageDiagnostics.qml` — скрытый developer-экран (5 тапов по логотипу на `PageHomeTribe`,
  push через `StackView.view`, без C++/enum). Секции: состояние/подписка/пул(score+health)/лог свитчей/оверрайды.
  Источник — `AvpnEngine.debugSnapshot()`; пока движок не зарегистрирован QML context property `AvpnEngine` →
  демо-заглушка (бейдж `demo`/`engine`). Маскировка секретов (план §7). qmllint чистый, превью без ошибок.
