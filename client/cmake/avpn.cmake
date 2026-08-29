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

# AVPN catalog v2: the standalone macOS GUI consumes an authenticated
# engine_manifest_v1 from the privileged daemon.  Compile the independently exported Conan
# receipt into the GUI as the comparison lock; never trust version strings supplied by IPC on
# their own.  App-Store macOS-NE and iOS use the awg-apple/amnezia-libxray lock below instead.
if(APPLE AND NOT IOS AND NOT MACOS_NE)
    find_package(awg-go REQUIRED)
    find_package(amnezia-xray-bindings REQUIRED)
    foreach(_required
            AWG_GO_ENGINE_VERSION AWG_GO_SOURCE_COMMIT AWG_GO_UAPI_ABI
            XRAY_BINDINGS_VERSION XRAY_BINDINGS_SOURCE_COMMIT XRAY_CORE_VERSION
            XRAY_BINDINGS_C_ABI)
        if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
            message(FATAL_ERROR
                "macOS catalog-v2 engine package did not export ${_required}") # AVPN
        endif()
    endforeach()
    add_compile_definitions(
        TRIBE_MACOS_AWG_ADAPTER_VERSION="${AWG_GO_ENGINE_VERSION}"
        TRIBE_MACOS_AWG_CORE_VERSION="${AWG_GO_ENGINE_VERSION}"
        TRIBE_MACOS_AWG_SOURCE_COMMIT="${AWG_GO_SOURCE_COMMIT}"
        TRIBE_MACOS_AWG_ABI="${AWG_GO_UAPI_ABI}"
        TRIBE_MACOS_XRAY_ADAPTER_VERSION="${XRAY_BINDINGS_VERSION}"
        TRIBE_MACOS_XRAY_CORE_VERSION="${XRAY_CORE_VERSION}"
        TRIBE_MACOS_XRAY_SOURCE_COMMIT="${XRAY_BINDINGS_SOURCE_COMMIT}"
        TRIBE_MACOS_XRAY_ABI="${XRAY_BINDINGS_C_ABI}")
endif()

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

# AVPN catalog v2 offline trust anchor. It is public material but must come from the audited
# release pipeline; test fixtures, QSettings and online responses are never valid defaults.
set(TRIBE_CATALOG_ROOT_KID "" CACHE STRING "Bundled catalog keyset root key id")
set(TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX "" CACHE STRING
    "Bundled Ed25519 catalog keyset root public key (64 lowercase hex chars)")
if((TRIBE_CATALOG_ROOT_KID STREQUAL "" AND
    NOT TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX STREQUAL "") OR
   (NOT TRIBE_CATALOG_ROOT_KID STREQUAL "" AND
    TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX STREQUAL ""))
    message(FATAL_ERROR "Catalog v2 root kid/public key must be supplied together")
endif()
if(NOT TRIBE_CATALOG_ROOT_KID STREQUAL "")
    string(LENGTH "${TRIBE_CATALOG_ROOT_KID}" _tribe_catalog_root_kid_length)
    string(LENGTH "${TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX}"
           _tribe_catalog_root_public_key_length)
    if(_tribe_catalog_root_kid_length LESS 1
       OR _tribe_catalog_root_kid_length GREATER 64
       OR NOT TRIBE_CATALOG_ROOT_KID MATCHES "^[A-Za-z0-9][A-Za-z0-9.+_-]*$"
       OR NOT _tribe_catalog_root_public_key_length EQUAL 64
       OR NOT TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX MATCHES "^[0-9a-f]+$"
       OR TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX STREQUAL
          "0000000000000000000000000000000000000000000000000000000000000000")
        message(FATAL_ERROR "Catalog v2 offline root compile definition is malformed")
    endif()
    add_compile_definitions(
        TRIBE_CATALOG_ROOT_KID="${TRIBE_CATALOG_ROOT_KID}"
        TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX="${TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX}")
elseif(TRIBE_STORE_BUILD OR DEPLOY)
    message(FATAL_ERROR
        "Release/store build requires an audited compile-time catalog v2 offline root")
else()
    message(STATUS "Catalog v2 network runtime disabled: no compile-time offline root")
endif()

set(AVPN_SE ${CMAKE_CURRENT_LIST_DIR}/../core/serviceEngine)

list(APPEND HEADERS
    ${AVPN_SE}/dto/Subscription.h
    ${AVPN_SE}/dto/Catalog.h
    ${AVPN_SE}/SubscriptionParser.h
    ${AVPN_SE}/AwgConfigBuilder.h
    ${AVPN_SE}/CatalogParser.h
    ${AVPN_SE}/CatalogTrust.h
    ${AVPN_SE}/CatalogCompatibility.h
    ${AVPN_SE}/CatalogAcceptance.h
    ${AVPN_SE}/CatalogResolve.h
    ${AVPN_SE}/SignedEnvelope.h
    ${AVPN_SE}/CatalogKeyset.h
    ${AVPN_SE}/CatalogKeysetClient.h
    ${AVPN_SE}/CatalogSecureStore.h
    ${AVPN_SE}/CatalogResolveClient.h
    ${AVPN_SE}/CatalogOutcomeClient.h
    ${AVPN_SE}/CatalogRuntimeState.h
    ${AVPN_SE}/CatalogTrustedClock.h
    ${AVPN_SE}/CatalogConnectionFacade.h
    ${AVPN_SE}/CatalogCoordinator.h
    ${AVPN_SE}/CatalogProductRuntime.h
    ${AVPN_SE}/RuntimeEngineManifest.h
    ${AVPN_SE}/PostTunnelReceiptVerifier.h
    ${AVPN_SE}/CandidateSelector.h
    ${AVPN_SE}/LegacyCatalogFallback.h
    ${AVPN_SE}/LegacyNativeOwnershipPolicy.h
    ${AVPN_SE}/TransportAdapter.h
    ${AVPN_SE}/NativeProfileCompiler.h
    ${AVPN_SE}/NativeConnectionPolicy.h
    ${AVPN_SE}/NativeDispatchPolicyDigest.h
    ${AVPN_SE}/NativeRuntimeIdentity.h
    ${AVPN_SE}/NativeSessionGuardEvent.h
    ${AVPN_SE}/ConnectionReducer.h
    ${AVPN_SE}/VpnConnectionTransportAdapter.h
    ${AVPN_SE}/ITunnelControl.h
    ${AVPN_SE}/VpnConnectionTunnelControl.h
    ${AVPN_SE}/Identity.h
    ${AVPN_SE}/IdentityAnchor.h
    ${AVPN_SE}/DeviceFingerprint.h
    ${AVPN_SE}/Enrollment.h
    ${AVPN_SE}/NodePool.h
    ${AVPN_SE}/Prober.h
    ${AVPN_SE}/Selector.h
    ${AVPN_SE}/HealthLoop.h
    ${AVPN_SE}/ConnectTunables.h
    ${AVPN_SE}/SignalQuality.h
    ${AVPN_SE}/MtprotoProbe.h
    ${AVPN_SE}/QualityProbe.h
    ${AVPN_SE}/ServiceProbe.h
    ${AVPN_SE}/ServiceProbeTargets.h
    ${AVPN_SE}/NodeRanking.h
    ${AVPN_SE}/NodeRotation.h
    ${AVPN_SE}/IRttProbe.h
    ${AVPN_SE}/RttProbeIcmp.h
    ${AVPN_SE}/BenchRunner.h
    ${AVPN_SE}/BenchAnalysis.h
    ${AVPN_SE}/Switcher.h
    ${AVPN_SE}/DebugSnapshot.h
    ${AVPN_SE}/TribeDiagReport.h
    ${AVPN_SE}/ServiceEngine.h
    ${AVPN_SE}/AvpnEngineQml.h
    ${AVPN_SE}/TribeSupportChat.h
    ${AVPN_SE}/AvpnPushBridge.h
    ${AVPN_SE}/AvpnDeepLinkBridge.h
    ${AVPN_SE}/AvpnIntentBridge.h
    ${AVPN_SE}/AvpnShareBridge.h
    ${AVPN_SE}/ConfigTypes.h
    ${AVPN_SE}/Ed25519Verify.h
    ${AVPN_SE}/ConfigStore.h
    ${AVPN_SE}/EdgeWalk.h
    ${AVPN_SE}/ConfigService.h
    ${AVPN_SE}/BypassListTypes.h
    ${AVPN_SE}/BypassListLkg.h
    ${AVPN_SE}/BypassListService.h
    ${AVPN_SE}/TribeHaptics.h
    ${AVPN_SE}/WhitelistVerdict.h
    ${AVPN_SE}/WhitelistDetector.h
    ${AVPN_SE}/DoctorReport.h
    ${AVPN_SE}/CrashGuard.h
    ${AVPN_SE}/TribeNetInfo.h
    ${AVPN_SE}/RuSplitSentinel.h
)

set(AVPN_ENGINE_SRC
    ${AVPN_SE}/SubscriptionParser.cpp
    ${AVPN_SE}/AwgConfigBuilder.cpp
    ${AVPN_SE}/CatalogParser.cpp
    ${AVPN_SE}/SignedEnvelope.cpp
    ${AVPN_SE}/CatalogKeyset.cpp
    ${AVPN_SE}/CatalogKeysetClient.cpp
    ${AVPN_SE}/CatalogSecureStore.cpp
    ${AVPN_SE}/CatalogResolveClient.cpp
    ${AVPN_SE}/CatalogOutcomeClient.cpp
    ${AVPN_SE}/CatalogRuntimeState.cpp
    ${AVPN_SE}/CatalogTrustedClock.cpp
    ${AVPN_SE}/CatalogConnectionFacade.cpp
    ${AVPN_SE}/CatalogCoordinator.cpp
    ${AVPN_SE}/CatalogProductRuntime.cpp
    ${AVPN_SE}/RuntimeEngineManifest.cpp
    ${AVPN_SE}/PostTunnelReceiptVerifier.cpp
    ${AVPN_SE}/NativeProfileCompiler.cpp
    ${AVPN_SE}/NativeConnectionPolicy.cpp
    ${AVPN_SE}/NativeDispatchPolicyDigest.cpp
    ${AVPN_SE}/NativeSessionGuardEvent.cpp
    ${AVPN_SE}/ConnectionReducer.cpp
    ${AVPN_SE}/VpnConnectionTransportAdapter.cpp
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
)
list(APPEND SOURCES ${AVPN_ENGINE_SRC})

# AVPN: авто-установка root-демона из вшитого pkg — только macOS-desktop (НЕ NE, НЕ iOS).
if(APPLE AND NOT IOS AND NOT MACOS_NE)
    list(APPEND HEADERS ${AVPN_SE}/MacServiceInstaller.h)
    list(APPEND SOURCES ${AVPN_SE}/MacServiceInstaller.mm)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/MacServiceInstaller.mm)
    # AVPN (P-ANN): бейдж непрочитанных на иконке дока (NSApp.dockTile).
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/macos/AvpnDockBadge.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/macos/AvpnDockBadge.mm)
endif()

# AVPN v2: app-only Keychain custody for the encrypted catalog LKG. The Network Extension never
# reads this vault; it receives only a sanitized active native profile.
if(APPLE)
    list(APPEND HEADERS ${AVPN_SE}/AppleCatalogSecureStorage.h)
    list(APPEND SOURCES ${AVPN_SE}/AppleCatalogSecureStorage.mm)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/AppleCatalogSecureStorage.mm)
endif()

if(ANDROID)
    list(APPEND HEADERS ${AVPN_SE}/AndroidCatalogSecureStorage.h)
    list(APPEND SOURCES ${AVPN_SE}/AndroidCatalogSecureStorage.cpp)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/AndroidCatalogSecureStorage.cpp)
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
    # AVPN (haptics): тактильный отклик — UIFeedbackGenerator (UIKit уже линкуется).
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeHapticsIos.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeHapticsIos.mm)
    # AVPN (Доктор D-3): поколение сотовой — CoreTelephony (авто-линк clang-модулем).
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeNetInfoIos.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/TribeNetInfoIos.mm)
endif()

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
