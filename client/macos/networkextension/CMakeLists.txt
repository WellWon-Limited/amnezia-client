enable_language(Swift)
message("Client message >> macos build >> AmneziaVPNNetworkExtension")
set(CLIENT_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)

add_executable(AmneziaVPNNetworkExtension)

message("executable_path is: @executable_path/../../Frameworks")
set_target_properties(AmneziaVPNNetworkExtension PROPERTIES
    # AVPN: System Extension (Developer ID/dmg вне App Store требует sysext, не appex).
    XCODE_PRODUCT_TYPE com.apple.product-type.system-extension
    # MACOSX_BUNDLE YES
    BUNDLE_EXTENSION systemextension
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${APPLE_PROJECT_VERSION}"
    MACOSX_BUNDLE_INFO_STRING "AmneziaVPNNetworkExtension"
    MACOSX_BUNDLE_BUNDLE_NAME "AmneziaVPNNetworkExtension"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "${BUILD_IOS_APP_IDENTIFIER}.network-extension"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_NAME "${BUILD_IOS_APP_IDENTIFIER}.network-extension"
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS ${CMAKE_CURRENT_SOURCE_DIR}/AmneziaVPNNetworkExtension.entitlements
    XCODE_ATTRIBUTE_MARKETING_VERSION "${APP_MAJOR_VERSION}"
    XCODE_ATTRIBUTE_CURRENT_PROJECT_VERSION "${CMAKE_PROJECT_VERSION_TWEAK}"
    XCODE_ATTRIBUTE_PRODUCT_NAME "AmneziaVPNNetworkExtension"

    XCODE_ATTRIBUTE_APPLICATION_EXTENSION_API_ONLY "YES"
    XCODE_ATTRIBUTE_ENABLE_BITCODE "NO"
    XCODE_ATTRIBUTE_MACOSX_DEPLOYMENT_TARGET "11.0"
    # AVPN: дубли cgo-рантайма (openvpnadapter ↔ awg) решены точечной локализацией 9 символов
    # ниже (ld -r -unexported_symbols_list libwg-go.a). -ld_classic убран — он deprecated (Xcode 26.5
    # сыпал warning и больше не давил эти дубли). Локализация — единственный и достаточный фикс.

    XCODE_ATTRIBUTE_INFOPLIST_FILE ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in
    # AVPN: sysext на уровень глубже appex (Contents/Library/SystemExtensions/X.systemextension/…) → +1 ../
    XCODE_ATTRIBUTE_LD_RUNPATH_SEARCH_PATHS "@executable_path/../../../../../Frameworks @loader_path/../../../../../Frameworks"
)

if(DEPLOY)
    message("DEPLOY is ON")
    set_target_properties(AmneziaVPNNetworkExtension PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Apple Distribution"
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY[variant=Debug] "Apple Development"
        XCODE_ATTRIBUTE_CODE_SIGN_STYLE Manual
        XCODE_ATTRIBUTE_PROVISIONING_PROFILE_SPECIFIER "distr macos.org.amnezia.amneziaVPN.NE"
        XCODE_ATTRIBUTE_PROVISIONING_PROFILE_SPECIFIER[variant=Debug] "dev macos.org.amnezia.amneziaVPN.NE"
    )
else()
    set_target_properties(AmneziaVPNNetworkExtension PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_STYLE Automatic
    )
endif()

set_target_properties(AmneziaVPNNetworkExtension PROPERTIES
    XCODE_ATTRIBUTE_SWIFT_VERSION "5.0"
    XCODE_ATTRIBUTE_CLANG_ENABLE_MODULES "YES"
    XCODE_ATTRIBUTE_SWIFT_OBJC_BRIDGING_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/WireGuardNetworkExtension-Bridging-Header.h"
    XCODE_ATTRIBUTE_SWIFT_OPTIMIZATION_LEVEL "-Onone"
    XCODE_ATTRIBUTE_SWIFT_PRECOMPILE_BRIDGING_HEADER "NO"
)

set_target_properties("AmneziaVPNNetworkExtension" PROPERTIES
    XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "X7UJ388FXK"
)

find_library(FW_ASSETS_LIBRARY AssetsLibrary)
find_library(FW_MOBILE_CORE MobileCoreServices)
find_library(FW_UI_KIT UIKit)
find_library(FW_LIBRESOLV libresolv.9.tbd)


# Set the root directory
set(CLIENT_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)

target_link_libraries(AmneziaVPNNetworkExtension PRIVATE ${FW_LIBRESOLV})

target_compile_options(AmneziaVPNNetworkExtension PRIVATE -DGROUP_ID=\"${BUILD_IOS_GROUP_IDENTIFIER}\")
target_compile_options(AmneziaVPNNetworkExtension PRIVATE -DNETWORK_EXTENSION=1)

set(WG_APPLE_SOURCE_DIR ${CLIENT_ROOT_DIR}/3rd/amneziawg-apple/Sources)

message("WG_APPLE_SOURCE_DIR is: ${WG_APPLE_SOURCE_DIR}")
message("CLIENT_ROOT_DIR is: ${CLIENT_ROOT_DIR}")

target_sources(AmneziaVPNNetworkExtension PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/main.swift   # AVPN: точка входа sysext (startSystemExtensionMode)
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/WireGuardAdapter.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/PacketTunnelSettingsGenerator.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/DNSResolver.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardNetworkExtension/ErrorNotifier.swift
    ${WG_APPLE_SOURCE_DIR}/Shared/Keychain.swift
    ${WG_APPLE_SOURCE_DIR}/Shared/Model/TunnelConfiguration+WgQuickConfig.swift
    ${WG_APPLE_SOURCE_DIR}/Shared/Model/NETunnelProviderProtocol+Extension.swift
    ${WG_APPLE_SOURCE_DIR}/Shared/Model/String+ArrayConversion.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/TunnelConfiguration.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/IPAddressRange.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/Endpoint.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/DNSServer.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/InterfaceConfiguration.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/PeerConfiguration.swift
    ${WG_APPLE_SOURCE_DIR}/Shared/FileManager+Extension.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKitC/x25519.c
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/Array+ConcurrentMap.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/IPAddress+AddrInfo.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKit/PrivateKey.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/HevSocksTunnel.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/NELogController.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/Log.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/LogRecord.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider+WireGuard.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider+OpenVPN.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider+Xray.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/WGConfig.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/iosglue.mm
    ${CLIENT_ROOT_DIR}/platforms/ios/XrayConfig.swift
)

target_sources(AmneziaVPNNetworkExtension PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/PrivacyInfo.xcprivacy
)

set_property(TARGET AmneziaVPNNetworkExtension APPEND PROPERTY RESOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/PrivacyInfo.xcprivacy
)

target_include_directories(AmneziaVPNNetworkExtension PRIVATE ${CLIENT_ROOT_DIR})
target_include_directories(AmneziaVPNNetworkExtension PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

find_package(openvpnadapter REQUIRED)
target_link_libraries(AmneziaVPNNetworkExtension PRIVATE amnezia::openvpnadapter)

find_package(awg-apple REQUIRED)
# AVPN (macOS NE линк-фикс): libwg-go.a (awg) и OpenVPNAdapter оба статически тащат Go cgo-рантайм →
# 9 дублей символов (_x_crosscall2_ptr, __cgo_set_stacklo, …) после обновления amneziawg (#2743).
# -ld_classic это больше НЕ давит (deprecated). -load_hidden (спрятать ВСЁ) ломает API (_wgTurnOn/LibXray*).
# Решение: предлинк libwg-go.a в один .o, локализовав ТОЛЬКО 9 cgo-рантайм-символов (-unexported_symbols_list):
# они становятся local и не конфликтуют с OpenVPNAdapter; внутренние ссылки awg резолвятся к своим копиям,
# а ПУБЛИЧНОЕ API awg/Xray (_wgTurnOn, _LibXray*) остаётся глобальным для Swift. Заголовки awg — из таргета.
get_target_property(_AWG_INC amnezia::awg-apple INTERFACE_INCLUDE_DIRECTORIES)
if(_AWG_INC)
    target_include_directories(AmneziaVPNNetworkExtension PRIVATE ${_AWG_INC})
endif()
set(_AWG_CGO_SYMS "${CMAKE_CURRENT_BINARY_DIR}/awg_cgo_localize.txt")
file(WRITE "${_AWG_CGO_SYMS}"
"__cgo_get_context_function\n__cgo_set_stacklo\n__cgo_try_pthread_create\n__cgo_wait_runtime_init_done\n_x_cgo_bindm\n_x_cgo_notify_runtime_init_done\n_x_cgo_pthread_key_created\n_x_cgo_sys_thread_create\n_x_crosscall2_ptr\n")
set(_AWG_LOCALIZED "${CMAKE_CURRENT_BINARY_DIR}/libwg-go-localized.o")
add_custom_command(OUTPUT "${_AWG_LOCALIZED}"
    COMMAND ld -r -arch arm64 -platform_version macos 11.0 11.0 -all_load "$<TARGET_FILE:amnezia::awg-apple>"
            -unexported_symbols_list "${_AWG_CGO_SYMS}" -o "${_AWG_LOCALIZED}"
    DEPENDS amnezia::awg-apple "${_AWG_CGO_SYMS}"
    COMMENT "AVPN: локализую 9 cgo-дублей в libwg-go (anti-collision с OpenVPNAdapter)"
    VERBATIM)
add_custom_target(awg_localize_ne DEPENDS "${_AWG_LOCALIZED}")
add_dependencies(AmneziaVPNNetworkExtension awg_localize_ne)
target_link_libraries(AmneziaVPNNetworkExtension PRIVATE "${_AWG_LOCALIZED}")

find_package(hev-socks5-tunnel REQUIRED)
target_link_libraries(AmneziaVPNNetworkExtension PRIVATE heiher::hev-socks5-tunnel)
