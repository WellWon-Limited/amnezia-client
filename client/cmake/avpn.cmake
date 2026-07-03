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

set(AVPN_SE ${CMAKE_CURRENT_LIST_DIR}/../core/serviceEngine)

list(APPEND HEADERS
    ${AVPN_SE}/dto/Subscription.h
    ${AVPN_SE}/SubscriptionParser.h
    ${AVPN_SE}/AwgConfigBuilder.h
    ${AVPN_SE}/ITunnelControl.h
    ${AVPN_SE}/VpnConnectionTunnelControl.h
    ${AVPN_SE}/Identity.h
    ${AVPN_SE}/IdentityAnchor.h
    ${AVPN_SE}/Enrollment.h
    ${AVPN_SE}/NodePool.h
    ${AVPN_SE}/Prober.h
    ${AVPN_SE}/Selector.h
    ${AVPN_SE}/HealthLoop.h
    ${AVPN_SE}/SignalQuality.h
    ${AVPN_SE}/MtprotoProbe.h
    ${AVPN_SE}/QualityProbe.h
    ${AVPN_SE}/ServiceProbe.h
    ${AVPN_SE}/NodeRanking.h
    ${AVPN_SE}/NodeRotation.h
    ${AVPN_SE}/IRttProbe.h
    ${AVPN_SE}/RttProbeIcmp.h
    ${AVPN_SE}/BenchRunner.h
    ${AVPN_SE}/BenchAnalysis.h
    ${AVPN_SE}/Switcher.h
    ${AVPN_SE}/DebugSnapshot.h
    ${AVPN_SE}/ServiceEngine.h
    ${AVPN_SE}/AvpnEngineQml.h
    ${AVPN_SE}/AvpnPushBridge.h
    ${AVPN_SE}/AvpnDeepLinkBridge.h
    ${AVPN_SE}/AvpnIntentBridge.h
)

set(AVPN_ENGINE_SRC
    ${AVPN_SE}/SubscriptionParser.cpp
    ${AVPN_SE}/AwgConfigBuilder.cpp
    ${AVPN_SE}/Prober.cpp
    ${AVPN_SE}/QualityProbe.cpp
    ${AVPN_SE}/ServiceProbe.cpp
    ${AVPN_SE}/RttProbeIcmp.cpp
    ${AVPN_SE}/BenchRunner.cpp
    ${AVPN_SE}/Identity.cpp
    ${AVPN_SE}/IdentityAnchor.cpp
    ${AVPN_SE}/Enrollment.cpp
    ${AVPN_SE}/VpnConnectionTunnelControl.cpp
    ${AVPN_SE}/ServiceEngine.cpp
    ${AVPN_SE}/AvpnEngineQml.cpp
    ${AVPN_SE}/AvpnPushBridge.cpp
    ${AVPN_SE}/AvpnDeepLinkBridge.cpp
    ${AVPN_SE}/AvpnIntentBridge.cpp
)
list(APPEND SOURCES ${AVPN_ENGINE_SRC})

# AVPN: авто-установка root-демона из вшитого pkg — только macOS-desktop (НЕ NE, НЕ iOS).
if(APPLE AND NOT IOS AND NOT MACOS_NE)
    list(APPEND HEADERS ${AVPN_SE}/MacServiceInstaller.h)
    list(APPEND SOURCES ${AVPN_SE}/MacServiceInstaller.mm)
    list(APPEND AVPN_ENGINE_SRC ${AVPN_SE}/MacServiceInstaller.mm)
endif()

# AVPN: нативные iOS-исходники — только для iOS-таргета.
if(IOS)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnSafeArea.mm)
    list(APPEND AVPN_ENGINE_SRC ${CMAKE_CURRENT_LIST_DIR}/../platforms/ios/AvpnSafeArea.mm)
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
endif()

# AVPN (аудит N3, 2026-07-02): «нет return в non-void функции» = UB — в НАШИХ исходниках это
# ошибка компиляции, не warning. Апстрим-TU не трогаем. MSVC не покрываем (наши платформы — clang).
if(NOT MSVC)
    set_source_files_properties(${AVPN_ENGINE_SRC} PROPERTIES COMPILE_OPTIONS "-Werror=return-type")
endif()
