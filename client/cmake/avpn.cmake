# AVPN overlay — исходники нашего serviceEngine (НЕ часть апстрима Amnezia).
# Изолировано: всё наше перечислено здесь; в апстрим-файлы НЕ лезем.
#
# Подключение в client/CMakeLists.txt (рядом с include(cmake/sources.cmake)):
#   include(${CMAKE_CURRENT_LIST_DIR}/cmake/avpn.cmake)   # AVPN overlay
#
# KILL-SWITCH: опция AVPN_ENGINE (по умолчанию ON). Если наш overlay не собирается — собрать форк
# как раньше можно так:  cmake ... -DAVPN_ENGINE=OFF   (тогда наши файлы и регистрация выключены).
option(AVPN_ENGINE "Build AVPN serviceEngine overlay (smart pool/failover)" ON)

if(NOT AVPN_ENGINE)
    message(STATUS "AVPN overlay: DISABLED (-DAVPN_ENGINE=OFF) — собираем чистый форк")
    return()
endif()
message(STATUS "AVPN overlay: ENABLED")

# Компайл-деф, по которому апстрим-точки (coreController) включают регистрацию AvpnEngine.
add_compile_definitions(AVPN_ENGINE_ENABLED=1)

# AVPN (store-flow, 2026-07-09): сборка для СТОРОВ (Google Play AAB / App Store). В store-билде
# в приложении НЕТ прямых платёжных переходов (полиси Google Play Payments / Apple §3.1.1):
# «Управлять подпиской» скрыта (бейдж-инфо остаётся), золотая CTA ведёт на карточку «Активировать
# ключ» (redeem) + чат поддержки. Sideload-APK / macOS-dmg / Windows / TestFlight-dev собираются
# БЕЗ флага — там прямая кнопка web-кабинета остаётся. Это COMPILE-TIME разница (не рантайм-флаг
# с сервера: удалённое переключение поведения после ревью = cloaking → бан аккаунта).
# env-переопределение для сборочной обвязки: апстримный deploy/build.sh не пробрасывает
# произвольные -D, поэтому store-сборка включается окружением ДО первого конфига:
#   TRIBE_STORE_BUILD=ON scripts/build-android.sh   (значение ложится в CMake-кеш build-папки
# и живёт там до явного -DTRIBE_STORE_BUILD=OFF / удаления папки — у store-сборок СВОЙ build-dir).
if(DEFINED ENV{TRIBE_STORE_BUILD})
    set(TRIBE_STORE_BUILD "$ENV{TRIBE_STORE_BUILD}" CACHE BOOL "Store build (env override)")
endif()
option(TRIBE_STORE_BUILD "Store build (Google Play / App Store): no direct payment surfaces in-app" OFF)
if(TRIBE_STORE_BUILD)
    add_compile_definitions(TRIBE_STORE_BUILD=1)
    message(STATUS "AVPN overlay: TRIBE_STORE_BUILD=ON (store flow, payment surfaces gated)")
endif()

set(AVPN_SE ${CMAKE_CURRENT_LIST_DIR}/../core/serviceEngine)

list(APPEND HEADERS
    ${AVPN_SE}/dto/Subscription.h
    ${AVPN_SE}/SubscriptionParser.h
    ${AVPN_SE}/AwgConfigBuilder.h
    ${AVPN_SE}/SelfUpdate.h
    ${AVPN_SE}/LaunchGuard.h
    ${AVPN_SE}/XrayConfigBuilder.h
    ${AVPN_SE}/ITunnelControl.h
    ${AVPN_SE}/VpnConnectionTunnelControl.h
    ${AVPN_SE}/Identity.h
    ${AVPN_SE}/IdentityAnchor.h
    ${AVPN_SE}/DeviceFingerprint.h
    ${AVPN_SE}/Enrollment.h
    ${AVPN_SE}/NodePool.h
    ${AVPN_SE}/Prober.h
    ${AVPN_SE}/HealthLoop.h
    ${AVPN_SE}/ConnectTunables.h
    ${AVPN_SE}/SignalQuality.h
    ${AVPN_SE}/MtprotoProbe.h
    ${AVPN_SE}/QualityProbe.h
    ${AVPN_SE}/ServiceProbe.h
    ${AVPN_SE}/ServiceProbeTargets.h
    ${AVPN_SE}/NodeRanking.h
    ${AVPN_SE}/NodeRotation.h
    ${AVPN_SE}/TransportModeGate.h
    ${AVPN_SE}/TransportPick.h
    ${AVPN_SE}/IRttProbe.h
    ${AVPN_SE}/RttProbeIcmp.h
    ${AVPN_SE}/BenchRunner.h
    ${AVPN_SE}/BenchAnalysis.h
    ${AVPN_SE}/DebugSnapshot.h
    ${AVPN_SE}/TribeDiagReport.h
    ${AVPN_SE}/ServiceEngine.h
    ${AVPN_SE}/AvpnEngineQml.h
    ${AVPN_SE}/TribeSupportChat.h
    ${AVPN_SE}/SupportReportQueue.h
    ${AVPN_SE}/AvpnPushBridge.h
    ${AVPN_SE}/AvpnDeepLinkBridge.h
    ${AVPN_SE}/AvpnIntentBridge.h
    ${AVPN_SE}/AvpnShareBridge.h
    ${AVPN_SE}/ConfigTypes.h
    ${AVPN_SE}/Ed25519Verify.h
    ${AVPN_SE}/ConfigStore.h
    ${AVPN_SE}/EdgeWalk.h
    ${AVPN_SE}/ConfigCachePolicy.h
    ${AVPN_SE}/ConfigService.h
    ${AVPN_SE}/BypassListTypes.h
    ${AVPN_SE}/BypassListLkg.h
    ${AVPN_SE}/BypassListService.h
    ${AVPN_SE}/TribeHaptics.h
    ${AVPN_SE}/WhitelistVerdict.h
    ${AVPN_SE}/WhitelistDetector.h
    ${AVPN_SE}/DoctorReport.h
    ${AVPN_SE}/WhoamiVerdict.h
    ${AVPN_SE}/Ipv6Presence.h
    ${AVPN_SE}/CrashGuard.h
    ${AVPN_SE}/TribeNetInfo.h
    ${AVPN_SE}/RuSplitSentinel.h
    ${AVPN_SE}/JournalPolicy.h
    ${AVPN_SE}/TribeJournal.h
    ${AVPN_SE}/UplinkMonitor.h
    ${AVPN_SE}/SignedContext.h
    ${AVPN_SE}/UpstreamNode.h
    ${AVPN_SE}/UpstreamLeaseWire.h
    ${AVPN_SE}/UpstreamLeaseMachine.h
    ${AVPN_SE}/UpstreamVerdict.h
    ${AVPN_SE}/UpstreamStandbyPack.h
    ${AVPN_SE}/UpstreamEngine.h
    ${AVPN_SE}/UpstreamLeaseOwner.h
    ${AVPN_SE}/UpstreamLeaseClient.h
    ${AVPN_SE}/XrayProfileSanitizer.h
    # AVPN Scanner (plan scanner-client-plan.md §5.4; writers in order L6a -> L9 -> L4 -> L5)
    ${AVPN_SE}/ScanTypes.h
    ${AVPN_SE}/ScanTunables.h
    ${AVPN_SE}/ScanNetworkGeneration.h
    ${AVPN_SE}/ScanClass.h
    ${AVPN_SE}/ScanPlan.h
    ${AVPN_SE}/ScanBudget.h
    ${AVPN_SE}/ScanOutcomes.h
    ${AVPN_SE}/ScanHostContract.h
    ${AVPN_SE}/ShadeQueue.h
    ${AVPN_SE}/ScanMachine.h
    ${AVPN_SE}/IScanHost.h
    ${AVPN_SE}/ScanApiClient.h
    ${AVPN_SE}/TribeScanner.h
    ${AVPN_SE}/ScanPathProber.h
    ${AVPN_SE}/ScanPathProberApi.h
)

set(AVPN_ENGINE_SRC
    ${AVPN_SE}/SubscriptionParser.cpp
    ${AVPN_SE}/AwgConfigBuilder.cpp
    ${AVPN_SE}/SelfUpdate.cpp
    ${AVPN_SE}/LaunchGuard.cpp
    ${AVPN_SE}/XrayConfigBuilder.cpp
    ${AVPN_SE}/Prober.cpp
    ${AVPN_SE}/QualityProbe.cpp
    ${AVPN_SE}/ServiceProbe.cpp
    ${AVPN_SE}/RttProbeIcmp.cpp
    ${AVPN_SE}/BenchRunner.cpp
    ${AVPN_SE}/Identity.cpp
    ${AVPN_SE}/IdentityAnchor.cpp
    ${AVPN_SE}/DeviceFingerprint.cpp
    ${AVPN_SE}/Enrollment.cpp
    ${AVPN_SE}/VpnConnectionTunnelControl.cpp
    ${AVPN_SE}/ServiceEngine.cpp
    ${AVPN_SE}/AvpnEngineQml.cpp
    ${AVPN_SE}/TribeSupportChat.cpp
    ${AVPN_SE}/AvpnPushBridge.cpp
    ${AVPN_SE}/AvpnDeepLinkBridge.cpp
    ${AVPN_SE}/AvpnIntentBridge.cpp
    ${AVPN_SE}/AvpnShareBridge.cpp
    ${AVPN_SE}/Ed25519Verify.cpp
    ${AVPN_SE}/ConfigService.cpp
    ${AVPN_SE}/BypassListService.cpp
    ${AVPN_SE}/TribeHaptics.cpp
    ${AVPN_SE}/WhitelistDetector.cpp
    ${AVPN_SE}/CrashGuard.cpp
    ${AVPN_SE}/TribeNetInfo.cpp
    ${AVPN_SE}/RuSplitSentinel.cpp
    ${AVPN_SE}/TribeJournal.cpp
    ${AVPN_SE}/UpstreamLeaseClient.cpp
    ${AVPN_SE}/ScanApiClient.cpp
    ${AVPN_SE}/TribeScanner.cpp
    ${AVPN_SE}/ScanPathProber.cpp
    ${AVPN_SE}/ScanPathProberApi.cpp
)
list(APPEND SOURCES ${AVPN_ENGINE_SRC})

# AVPN Scanner (19.11): ScanQnamHttp asks gzip itself and inflates the answer, so its byte counts and cuts are wire
# bytes (QNAM's own decoding hides the compressed size). zlib is a conan requirement on every platform (conanfile.py).
find_package(ZLIB REQUIRED)
list(APPEND LIBS ZLIB::ZLIB)

# AVPN (волна-3): физический аплинк — nw_path_monitor на macOS-desktop, QNetworkInformation везде ещё.
if(APPLE AND NOT IOS AND NOT MACOS_NE)
    list(APPEND SOURCES ${AVPN_SE}/UplinkMonitor.mm)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/UplinkMonitor.mm)
else()
    list(APPEND SOURCES ${AVPN_SE}/UplinkMonitor.cpp)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/UplinkMonitor.cpp)
endif()

# AVPN: авто-установка root-демона из вшитого pkg — только macOS-desktop (НЕ NE, НЕ iOS).
if(APPLE AND NOT IOS AND NOT MACOS_NE)
    list(APPEND HEADERS ${AVPN_SE}/MacServiceInstaller.h)
    list(APPEND SOURCES ${AVPN_SE}/MacServiceInstaller.mm)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/MacServiceInstaller.mm)
    # AVPN (P-ANN): бейдж непрочитанных на иконке дока (NSApp.dockTile).
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/macos/AvpnDockBadge.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/macos/AvpnDockBadge.mm)
endif()

# AVPN Scanner (plan scanner-client-plan.md §2.4, §2.6, §5.4; after L6a's entries): the desktop probe host
# over the root service's QtRO source IpcScanInterface (ipc/ipc_scan_interface.rep) - macOS desktop and
# Windows (Linux desktop compiles it too: the same service).
if(NOT IOS AND NOT ANDROID AND NOT MACOS_NE)
    list(APPEND HEADERS ${AVPN_SE}/DaemonScanHost.h)
    list(APPEND SOURCES ${AVPN_SE}/DaemonScanHost.cpp)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/DaemonScanHost.cpp)
    qt_add_repc_replicas(${PROJECT} ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipc_scan_interface.rep)
endif()

# AVPN Scanner (lane A3, plan §2.5): the Android probe host over AndroidController's scan channel to the Xray
# service process (client/android/xray/src/main/kotlin/scan/).
if(ANDROID)
    list(APPEND HEADERS ${AVPN_SE}/AndroidScanHost.h)
    list(APPEND SOURCES ${AVPN_SE}/AndroidScanHost.cpp)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/AndroidScanHost.cpp)
endif()

# AVPN: нативные iOS-исходники — только для iOS-таргета.
if(IOS)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnSafeArea.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnSafeArea.mm)
    # AVPN (клавиатура): гаситель авто-сдвига окна QIOSInputContext (телеграм-схема чата).
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnKeyboardFix.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnKeyboardFix.mm)
    # AVPN: нативный share sheet (UIActivityViewController) для ссылок — рефералка/перенос.
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnShare.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnShare.mm)
    # AVPN (Support): нативный PHPicker фото/видео для чата поддержки (без пермишена).
    # PhotosUI/UniformTypeIdentifiers авто-линкуются clang-модулями, как MetricKit ниже.
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeMediaPicker.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeMediaPicker.mm)
    # AVPN (Support): нативный просмотр скачанного вложения — QLPreviewController (видео-плеер/зум
    # фото). QuickLook линкуется явно в ios.cmake (#import не авто-линкует, как PhotosUI).
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeMediaViewer.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeMediaViewer.mm)
    # AVPN (Task 9): APNs контроллер (auth + device token + входящие пуши).
    list(APPEND HEADERS ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnPushController.h)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnPushController.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnPushController.mm)
    # AVPN (Task E): консьюмер «намерений» App Intent авто-паузы — читает App Group NSUserDefaults.
    # Здесь же реализован extern "C" Avpn_consumeIntentFlags() (на desktop — no-op в AvpnIntentBridge.cpp).
    list(APPEND HEADERS ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnIntentController.h)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnIntentController.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnIntentController.mm)
    # AVPN: авто-сбор диагностики вылетов (MetricKit, iOS 14+) → POST /v1/diag/crash. MetricKit.framework
    # авто-линкуется clang-модулем (@import MetricKit) — отдельный target_link_libraries не нужен.
    list(APPEND HEADERS ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnDiagnostics.h)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnDiagnostics.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnDiagnostics.mm)
    # AVPN (разбор 2026-09-23): фоновое время iOS на перезапуск туннеля, начатый приложением
    # (решение — serviceEngine/RestartGuard.h). UIKit уже линкуется.
    list(APPEND HEADERS ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnBackgroundGuard.h)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnBackgroundGuard.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnBackgroundGuard.mm)
    # AVPN (журнал тестирования, 2026-09-23): App Group (ne.log), флаг лога NE, фоновое время досылки.
    list(APPEND HEADERS ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeJournalIos.h)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeJournalIos.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeJournalIos.mm)
    # AVPN (haptics): тактильный отклик — UIFeedbackGenerator (UIKit уже линкуется).
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeHapticsIos.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeHapticsIos.mm)
    # AVPN (Доктор D-3): поколение сотовой — CoreTelephony (авто-линк clang-модулем).
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeNetInfoIos.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeNetInfoIos.mm)
    # AVPN Scanner (lane L4, plan scanner-client-plan.md §5.4): the probe host over the tunnel extension
    # (IScanHost) + the app process's network generation source.
    list(APPEND HEADERS ${AVPN_SE}/IosScanHost.h)
    list(APPEND SOURCES ${AVPN_SE}/IosScanHost.mm)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/IosScanHost.mm)
    # AVPN (path engine stage 0, design 2026-11-17 §5 variant A): the Scanner's probe engine in the APP process
    # (IosAppScanHost.h). OFF = the app references no Go symbol and libwg-go.a stays out of the app binary.
    # Environment override for the dev scripts (run-on-iphone.sh passes no -D): AVPN_IOS_APP_SCAN_HOST=ON before the
    # first configure of a build dir (the value stays in that dir's cache).
    if(DEFINED ENV{AVPN_IOS_APP_SCAN_HOST})
        set(AVPN_IOS_APP_SCAN_HOST "$ENV{AVPN_IOS_APP_SCAN_HOST}" CACHE BOOL "In-app Scanner probe host (env override)")
    endif()
    # Default ON for iOS (19.11): a release made by the canonical scripts ships the in-app probe host (the race, the
    # country scan, «Найти ещё»); OFF only by an explicit -D / environment override. This block is iOS-only.
    option(AVPN_IOS_APP_SCAN_HOST "iOS: run the Scanner's probe engine in the app process" ON)
    if(AVPN_IOS_APP_SCAN_HOST)
        add_compile_definitions(AVPN_IOS_APP_SCAN_HOST=1)
        list(APPEND HEADERS ${AVPN_SE}/IosAppScanHost.h)
        list(APPEND SOURCES ${AVPN_SE}/IosAppScanHost.mm)
        list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/IosAppScanHost.mm)
        message(STATUS "AVPN overlay: AVPN_IOS_APP_SCAN_HOST=ON (in-app Scanner probe host)")
    endif()
endif()

# R6 (device round 4): developer tools in development builds only (default OFF; never in a store build). Today: a
# control file Documents/tribe-reset-ledger makes the next launch start from an empty path ledger, so a true first
# walk can be measured (the ledger survives reinstalls for users, as it should). Environment override like
# AVPN_IOS_APP_SCAN_HOST for the dev scripts.
if(DEFINED ENV{AVPN_DEV_TOOLS})
    set(AVPN_DEV_TOOLS "$ENV{AVPN_DEV_TOOLS}" CACHE BOOL "Developer tools (env override)")
endif()
option(AVPN_DEV_TOOLS "Developer tools in development builds (empty-ledger control file)" OFF)
if(AVPN_DEV_TOOLS)
    add_compile_definitions(AVPN_DEV_TOOLS=1)
    message(STATUS "AVPN overlay: AVPN_DEV_TOOLS=ON (development build tools)")
endif()

# Device round 19.11: the commit label ("Started AVPN version 5.1.110.140 <commit>", About screen) came from a
# configure-time git call, so an incremental build of a newer commit kept the old label (the phone ran 74da6399f and
# said 76015d714). The label is now written on every build into a generated header that only the three upstream files
# printing it force-include (it overrides their -DGIT_COMMIT_HASH); the header changes only with the commit, so only
# those three files recompile. No upstream file is touched.
set(AVPN_GIT_COMMIT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/avpn_git_commit.h")
execute_process(COMMAND ${CMAKE_COMMAND} -DSRC=${CMAKE_SOURCE_DIR} -DOUT=${AVPN_GIT_COMMIT_HEADER}
                        -P ${CMAKE_CURRENT_LIST_DIR}/avpn_git_commit.cmake)
add_custom_target(avpn_git_commit ALL
    COMMAND ${CMAKE_COMMAND} -DSRC=${CMAKE_SOURCE_DIR} -DOUT=${AVPN_GIT_COMMIT_HEADER}
            -P ${CMAKE_CURRENT_LIST_DIR}/avpn_git_commit.cmake
    BYPRODUCTS ${AVPN_GIT_COMMIT_HEADER}
    COMMENT "AVPN: commit label"
    VERBATIM)
add_dependencies(${PROJECT} avpn_git_commit)
# Force-include spelling per compiler: "-include" is clang/gcc only; MSVC (the Windows build) has /FI and would
# ignore "-include" and take the header for an input file, so the label would silently stay the configure-time one.
if(MSVC)
    set(AVPN_GIT_COMMIT_FORCE_INCLUDE " /FI\"${AVPN_GIT_COMMIT_HEADER}\"")
else()
    set(AVPN_GIT_COMMIT_FORCE_INCLUDE " -include ${AVPN_GIT_COMMIT_HEADER}")
endif()
foreach(avpn_label_src main.cpp ui/controllers/settingsUiController.cpp core/controllers/settingsController.cpp)
    # COMPILE_FLAGS, not COMPILE_OPTIONS: the Xcode generator passes a per-file "SHELL:" option to clang verbatim
    set_property(SOURCE ${CMAKE_CURRENT_LIST_DIR}/../${avpn_label_src} APPEND_STRING PROPERTY
                 COMPILE_FLAGS "${AVPN_GIT_COMMIT_FORCE_INCLUDE}")
    set_property(SOURCE ${CMAKE_CURRENT_LIST_DIR}/../${avpn_label_src} APPEND PROPERTY
                 OBJECT_DEPENDS ${AVPN_GIT_COMMIT_HEADER})
endforeach()

# AVPN (аудит N3, 2026-07-02): «нет return в non-void функции» = UB — в НАШИХ исходниках это
# ошибка компиляции, не warning. Апстрим-TU не трогаем. MSVC не покрываем (наши платформы — clang).
if(NOT MSVC)
    set_source_files_properties(${AVPN_ENGINE_SRC} PROPERTIES COMPILE_OPTIONS "-Werror=return-type")
endif()

# AVPN (i18n): переводы Tribe-слоя (tribe_en.qm/tribe_es.qm; русский — исходник строк).
# .qm заранее скомпилированы и закоммичены (client/translations/tribe/update-translations.sh) —
# lupdate/lrelease-таргеты НЕ заводим (имена заняты апстримным qt6_add_translations, и его
# update_translations гонять по нашим файлам нельзя). Свой .qrc — через отдельную переменную
# (в QRC уже лежат сгенерированные .cpp) → в SOURCES, который уходит в target_sources
# ПОСЛЕ include(avpn.cmake) (client/CMakeLists.txt:204).
qt6_add_resources(AVPN_I18N_QRC ${CMAKE_CURRENT_LIST_DIR}/../translations/tribe/tribe_translations.qrc)
list(APPEND SOURCES ${AVPN_I18N_QRC})
