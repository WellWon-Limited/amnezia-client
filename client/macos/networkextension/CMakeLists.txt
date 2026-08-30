enable_language(Swift)
message("Client message >> macos build >> AmneziaVPNNetworkExtension")
set(CLIENT_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)

# Xcode does not expand CMake's ${...} placeholders when an .in file is used
# directly as INFOPLIST_FILE. Materialize the template first so the extension
# always carries its executable name and shared app-group identifiers.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in
    ${CMAKE_CURRENT_BINARY_DIR}/Info.plist
)

add_executable(AmneziaVPNNetworkExtension)

message("executable_path is: @executable_path/../../Frameworks")
set_target_properties(AmneziaVPNNetworkExtension PROPERTIES
    XCODE_PRODUCT_TYPE com.apple.product-type.app-extension
    BUNDLE_EXTENSION appex
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "${BUILD_IOS_APP_IDENTIFIER}.network-extension"
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS ${CMAKE_CURRENT_SOURCE_DIR}/AmneziaVPNNetworkExtension.entitlements
    XCODE_ATTRIBUTE_MARKETING_VERSION "${APP_MAJOR_VERSION}"
    XCODE_ATTRIBUTE_CURRENT_PROJECT_VERSION "${CMAKE_PROJECT_VERSION_TWEAK}"
    XCODE_ATTRIBUTE_PRODUCT_NAME "AmneziaVPNNetworkExtension"
    XCODE_ATTRIBUTE_APPLICATION_EXTENSION_API_ONLY "YES"

    XCODE_ATTRIBUTE_INFOPLIST_FILE ${CMAKE_CURRENT_BINARY_DIR}/Info.plist
    XCODE_ATTRIBUTE_LD_RUNPATH_SEARCH_PATHS "@executable_path/../../../../Frameworks @loader_path/../../../../Frameworks"

    XCODE_LINK_BUILD_PHASE_MODE KNOWN_LOCATION
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
    XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${BUILD_VPN_DEVELOPMENT_TEAM}"
)

find_library(FW_ASSETS_LIBRARY AssetsLibrary)
find_library(FW_MOBILE_CORE MobileCoreServices)
find_library(FW_UI_KIT UIKit)
find_library(FW_LIBRESOLV libresolv.9.tbd)
find_library(FW_CRYPTOKIT CryptoKit)


# Set the root directory
set(CLIENT_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)

target_link_libraries(AmneziaVPNNetworkExtension PRIVATE ${FW_LIBRESOLV} ${FW_CRYPTOKIT})

target_compile_definitions(AmneziaVPNNetworkExtension PRIVATE
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:GROUP_ID=\"${BUILD_IOS_GROUP_IDENTIFIER}\">
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:NETWORK_EXTENSION=1>
)

if(NOT DEFINED AWG_APPLE_SOURCE_DIR OR NOT EXISTS "${AWG_APPLE_SOURCE_DIR}/WireGuardKit/WireGuardAdapter.swift")
    message(FATAL_ERROR "networkextension requires AWG_APPLE_SOURCE_DIR from awg-apple Conan package") # AVPN
endif()

foreach(_required AWG_APPLE_ADAPTER_VERSION AWG_APPLE_UPSTREAM_VERSION AWG_APPLE_SOURCE_COMMIT
                  AWG_APPLE_AWG_CORE_VERSION AWG_APPLE_XRAY_ADAPTER_VERSION AWG_APPLE_XRAY_CORE_VERSION
                  AWG_APPLE_XRAY_SOCKET_ABI)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "awg-apple package did not export ${_required}") # AVPN
    endif()
endforeach()
configure_file(
    ${CLIENT_ROOT_DIR}/platforms/ios/TribeEngineManifest.swift.in
    ${CMAKE_CURRENT_BINARY_DIR}/TribeEngineManifest.swift
    @ONLY
) # AVPN

message("AWG_APPLE_SOURCE_DIR is: ${AWG_APPLE_SOURCE_DIR}")
message("CLIENT_ROOT_DIR is: ${CLIENT_ROOT_DIR}")

target_sources(AmneziaVPNNetworkExtension PRIVATE
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/WireGuardAdapter.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/PacketTunnelSettingsGenerator.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/DNSResolver.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardNetworkExtension/ErrorNotifier.swift
    ${AWG_APPLE_SOURCE_DIR}/Shared/Keychain.swift
    ${AWG_APPLE_SOURCE_DIR}/Shared/Model/TunnelConfiguration+WgQuickConfig.swift
    ${AWG_APPLE_SOURCE_DIR}/Shared/Model/NETunnelProviderProtocol+Extension.swift
    ${AWG_APPLE_SOURCE_DIR}/Shared/Model/String+ArrayConversion.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/TunnelConfiguration.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/IPAddressRange.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/Endpoint.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/DNSServer.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/InterfaceConfiguration.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/PeerConfiguration.swift
    ${AWG_APPLE_SOURCE_DIR}/Shared/FileManager+Extension.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKitC/x25519.c
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/Array+ConcurrentMap.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/IPAddress+AddrInfo.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKit/PrivateKey.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/HevSocksTunnel.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/Socks5TunnelLifecycle.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/NELogController.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/Log.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/LogRecord.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/TunnelRuntimeStatus.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/NativeDispatchPolicy.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/TribeNativeSessionGuard.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/TribeRuntimeAuthorityLease.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/TribeRuntimeAuthorityRenewal.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/TribeRuntimeAuthorityWatchdog.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/TribeProtectedSplitPolicy.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/XraySocketCallbackLifecycle.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider+NativeGuard.swift
    # Compiles the same closed provider surface as iOS, but the shipping macOS
    # flavor has no matching app-group entitlement, so staging fails closed and
    # no macOS-NE guard receipt can be issued.
    ${CLIENT_ROOT_DIR}/platforms/ios/TribeTunnelConfigVault.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider+WireGuard.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider+OpenVPN.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/PacketTunnelProvider+Xray.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/WGConfig.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/iosglue.mm
    ${CLIENT_ROOT_DIR}/platforms/ios/XrayConfig.swift
    ${CMAKE_CURRENT_BINARY_DIR}/TribeEngineManifest.swift
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
# FIXME(ygurov): https://github.com/conan-io/conan/issues/20034
set_property(TARGET amnezia::openvpnadapter APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_property(TARGET amnezia::openvpnadapter APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_property(TARGET amnezia::openvpnadapter APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_property(TARGET amnezia::openvpnadapter APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
target_link_libraries(AmneziaVPNNetworkExtension PRIVATE amnezia::openvpnadapter)

find_package(awg-apple REQUIRED)
target_link_libraries(AmneziaVPNNetworkExtension PRIVATE amnezia::awg-apple)

find_package(hev-socks5-tunnel REQUIRED)
# FIXME(ygurov): https://github.com/conan-io/conan/issues/20034
set_property(TARGET heiher::hev-socks5-tunnel APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_property(TARGET heiher::hev-socks5-tunnel APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_property(TARGET heiher::hev-socks5-tunnel APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_property(TARGET heiher::hev-socks5-tunnel APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
target_link_libraries(AmneziaVPNNetworkExtension PRIVATE heiher::hev-socks5-tunnel)
