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
dto/Catalog.h                 — protocol-neutral DTO подписанного `/v2/catalog/resolve` (AWG/Xray)
CatalogParser.{h,cpp}         — Ed25519 envelope, строгий JSON/UTF-8/base64url, typed profiles          ✅ pure tests
CatalogTrust.h                — epoch/revision/generation anti-downgrade + encrypted atomic LKG API    ✅ pure tests
CatalogCompatibility.h        — capability firewall и exact transport→native-container mapping         ✅ pure tests
CatalogAcceptance.h           — единая fail-closed verify→parse→trust→compatibility граница              ✅ pure tests
CatalogResolve.h              — strict app/adapter/engine/capability inventory → resolve request JSON     ✅ pure tests
CandidateSelector.h           — immutable multi-transport ranking/fallback (real-tunnel history first)  ✅ pure tests
TransportAdapter.h            — AWG/Xray sanitizer/compiler/runtime registry; незарегистрирован = deny   ✅ pure tests
NativeProfileCompiler.{h,cpp} — typed AWG3.1/Xray → штатные native envelopes + strict post-sanitizer ✅
ConnectionReducer.{h,cpp}     — единый async start→DNS→HTTPS/egress→fallback lifecycle, token/guard ✅
VpnConnectionTransportAdapter.{h,cpp} — concrete AWG+Xray dispatch через VpnConnection/container ✅ syntax
LegacyCatalogFallback.h       — v1 AWG только bootstrap; после принятого v2 downgrade запрещён           ✅ pure tests
ITunnelControl.h              — граница с туннелем (up/applyPeer/readStats/down)
VpnConnectionTunnelControl.{h,cpp} — УНИВЕРСАЛЬНАЯ реализация поверх VpnConnection (in-fork build)
Identity.{h,cpp}              — ключи: REUSE WireguardConfigurator::genClientKeys + SecureAppSettingsRepository [in-fork]
IdentityAnchor.{h,cpp}        — iOS keychain-якорь identity (uuid+ключи+токен+fpSeed, переживает переустановку);
                                прямой SecItem (ThisDeviceOnly, без iCloud; НЕ QtKeychain — тот не умеет
                                kSecAttrAccessible); канон: tribe-front docs/amnezia-fork/DEVICE-FINGERPRINT.md ✅ протестирован
DeviceFingerprint.{h,cpp}     — device_fingerprint: sha256 якоря железа (iOS fpSeed / ANDROID_ID / IOPlatformUUID /
                                MachineGuid) в trial/code-redeem/transfer-redeem; пусто → поле не слать ✅ протестирован
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
WhitelistVerdict.h            — чистый вердикт детекта РКН-«белых списков» (2 яруса whitelist: маркетплейсы
                                решают, соц-значимые = SocialOnly «нулевой баланс»; гистерезис; guard слабой
                                сети); спека tribe-front docs/superpowers/specs/2026-07-12-whitelist-mode-
                                detector-design.md ✅ протестирован (build_whitelist_verdict.sh, матрица §2)
WhitelistDetector.{h,cpp}     — драйвер проб вердикта: HTTPS-HEAD 4 наборов (инфра/якоря/маркетплейсы/
                                соц-значимые) при Cellular+опущенном туннеле, по триггерам (не поллинг),
                                gen-инвалидация раундов, exit-пробы; kill-switch features.whitelist_detector;
                                UI = TribeWhitelistSheet.qml (попап на PageStart)
TribeSupportChat.{h,cpp}      — чат поддержки (context property "TribeSupport"): поллинг /v1/support/*
                                (device-Bearer), оптимистичные эхо, QHttpMultiPart-аплоад фото/видео
                                (JPEG-рекомпресс, HEIC→JPEG), превью data:-URL, ручной 302→R2 без Bearer,
                                бэкофф-поллер постера видео; спека — tribe-backend
                                documents/SUPPORT-CHAT.md (+SUPPORT-CHAT-NATIVE-HANDOFF.md) ✅ E2E
tests/                        — фикстура + автономная проверка (парсер + билдер + enrollment + selector + health
                                + node_ranking_check + rtt_icmp_check[live ICMP]
                                + build_e2e_support.sh — ЖИВОЙ E2E чата против локального бэкенда)

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
Поэтому legacy-v1 `ITunnelControl` реализован классом `VpnConnectionTunnelControl` (AWG), а v2
использует protocol-neutral `VpnConnectionTransportAdapter`: typed compiler выбирает exact
`DockerContainer::Awg` либо `DockerContainer::Xray`, после чего вызывает тот же `connectToVpn`
через очередь. Платформенную разницу по-прежнему держит `VpnConnection`; Xray не получает
WG-handshake/rebind, а AWG не получает Xray JSON.

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
core/serviceEngine/tests/build_catalog_v2.sh # QtCore+QtNetwork+OpenSSL; v2 trust/compat/selector
core/serviceEngine/tests/build_transport_runtime.sh # typed compilers/sanitizers + reducer/fallback
```
Ожидаемо: `OK: subscription parsed & validated cleanly`.

## `/v2/catalog/resolve`: hard non-ship gates

Typed core runtime и concrete AWG/Xray adapters готовы, но намеренно **не изображают весь product
runtime готовым**. До production rollout обязательны внешние production-слои:

1. Сетевой catalog service: authenticated POST с `CatalogResolve.h`, новым случайным canonical
   32-byte `request_nonce` на каждый resolve, cancellation/timeout, typed обработкой
   `202/403/426/503`, `Cache-Control: no-store` и запретом body/credential logs. Online acceptance
   сверяет signed nonce и pinned opaque `device_audience` до persist/use; только
   `CatalogAcceptance.h` может передать ответ дальше.
2. Реализация `ICatalogLkgStore`, которая одним atomic transaction AEAD-шифрует envelope **вместе** с
   monotonic trust state и pinned audience. Обычный `QSettings`/plist/SharedPreferences запрещён:
   payload содержит device-scoped Xray UUID. LKG повторно сверяет audience, но не требует совпадения
   старого response nonce с новым запросом. При недоступном secure storage v2 fail-closed без LKG.
3. Реальная реализация `IConnectionSessionGuard` на каждой платформе. Reducer требует arm **до**
   первого start и держит guard через AWG↔Xray fallback; без platform-owned blocking routes он
   fail-closed. Обычный kill-switch, создаваемый внутри нового core, не доказывает no-leak окно.
4. Реальная `IPostTunnelVerifier`: отдельная DNS-стадия, HTTPS receipt без cache, signed/opaque
   expected egress, cancellation/deadline. Tunnel-ready/handshake никогда не делают UI зелёным;
   глобальная недоступность verifier оставляет guarded tunnel жёлтым и не портит fleet score.
5. Async coordinator должен соединить acceptance/LKG/runtime и exact platform engine manifest,
   сохранить generation-scoped outcome/cooldown, завести таймеры с immutable verification token,
   разрешить auth/verifier endpoints для local route policy и записать durable v2-authority gate.
   Runtime reducer уже сериализует `stop → typed native Stopped → start`, повторно ранжирует после
   hard failure и отбрасывает stale operation/verification/opaque-native-session callbacks; nested
   `QEventLoop` в нём отсутствует. Платформа без typed runtime session identity не регистрируется.
6. Ротация catalog-ключей требует root-anchored signed keyset manifest (bounded kids/epochs/
   validity/revocations) и monotonic secure trust state. Статический bundled current+next keyring —
   только bootstrap fallback, не долгосрочный механизм ротации/compromise recovery.

Concrete compilers уже принимают только typed `awg31`/`xray_vless_reality_vision_tcp`. AWG v2 не
использует legacy `extra`. Xray собирается из bounded полей через штатный `XrayClientConfig` envelope
и проходит exact post-sanitizer: один loopback SOCKS, один VLESS Reality/TCP/Vision outbound,
совпадающие endpoint/SNI/binding; raw server JSON, routing/api/stats/file/access-log запрещены.
Root `extensions[]` — единственная bounded evolution-зона: неизвестное non-critical значение
игнорируется, неизвестное critical fail-closed; `value` никогда не попадает в native compiler.

Legacy `/v1/subscription` и AWG builder сохранены для bootstrap/parity. Его `AwgParams::extra`
deprecated и никогда не используется v2: новые protocol semantics требуют нового typed
`profile_kind`/capability и уже встроенного adapter, иначе candidate отбрасывается.

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
