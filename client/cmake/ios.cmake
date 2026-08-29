message("Client iOS build")
set(APPLE_PROJECT_VERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH})

enable_language(OBJC)
enable_language(OBJCXX)
enable_language(Swift)

find_package(Qt6 REQUIRED COMPONENTS ShaderTools)
find_package(awg-apple REQUIRED) # AVPN: exports the immutable patched source tree used below/NE.
foreach(_required AWG_APPLE_ADAPTER_VERSION AWG_APPLE_SOURCE_COMMIT
                  AWG_APPLE_AWG_CORE_VERSION AWG_APPLE_XRAY_ADAPTER_VERSION
                  AWG_APPLE_XRAY_SOURCE_COMMIT AWG_APPLE_XRAY_CORE_VERSION
                  AWG_APPLE_XRAY_SOCKET_ABI)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "awg-apple package did not export ${_required}")
    endif()
endforeach()
set(LIBS ${LIBS} Qt6::ShaderTools)
get_target_property(AWG_APPLE_INCLUDE_DIRS amnezia::awg-apple INTERFACE_INCLUDE_DIRECTORIES)
if(NOT AWG_APPLE_INCLUDE_DIRS)
    message(FATAL_ERROR "awg-apple package did not export public C headers") # AVPN
endif()

find_library(FW_AUTHENTICATIONSERVICES AuthenticationServices)
find_library(FW_UIKIT UIKit)
find_library(FW_AVFOUNDATION AVFoundation)
find_library(FW_FOUNDATION Foundation)
find_library(FW_STOREKIT StoreKit)
find_library(FW_USERNOTIFICATIONS UserNotifications)
find_library(FW_NETWORKEXTENSION NetworkExtension)
find_library(FW_METRICKIT MetricKit)   # AVPN: авто-диагностика вылетов (AvpnDiagnostics.mm); @import заменён на #import → нужен явный линк
find_library(FW_PHOTOSUI PhotosUI)     # AVPN (Support): PHPicker фото/видео (TribeMediaPicker.mm); #import не авто-линкует → явный линк
find_library(FW_UTTYPES UniformTypeIdentifiers) # AVPN (Support): UTType для фильтров пикера (TribeMediaPicker.mm)
find_library(FW_COREMEDIA CoreMedia)   # AVPN (Support): CMTimeMakeWithSeconds — кадр-превью видео (TribeMediaPicker.mm)
find_library(FW_QUICKLOOK QuickLook)   # AVPN (Support): QLPreviewController — просмотр вложений (TribeMediaViewer.mm)
find_library(FW_CORETELEPHONY CoreTelephony) # AVPN (Доктор D-3): поколение сотовой (TribeNetInfoIos.mm); #import не авто-линкует → явный линк
find_library(FW_CRYPTOKIT CryptoKit) # AVPN: encrypted app↔NE one-shot profile handoff.
find_library(FW_SECURITY Security)

set(LIBS ${LIBS}
    ${FW_AUTHENTICATIONSERVICES}
    ${FW_UIKIT}
    ${FW_AVFOUNDATION}
    ${FW_FOUNDATION}
    ${FW_STOREKIT}
    ${FW_USERNOTIFICATIONS}
    ${FW_NETWORKEXTENSION}
    ${FW_METRICKIT}
    ${FW_PHOTOSUI}
    ${FW_UTTYPES}
    ${FW_COREMEDIA}
    ${FW_QUICKLOOK}
    ${FW_CORETELEPHONY}
    ${FW_CRYPTOKIT}
    ${FW_SECURITY}
)


set(HEADERS ${HEADERS}
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ios_controller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ios_controller_wrapper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/iosnotificationhandler.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ioscontextmenu.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/QtAppDelegate.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/StoreKitController.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/QtAppDelegate-C-Interface.h
)
set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ios_controller.h PROPERTIES OBJECTIVE_CPP_HEADER TRUE)


set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ios_controller.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ios_controller_wrapper.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/iosnotificationhandler.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ioscontextmenu.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/iosglue.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/QRCodeReaderBase.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/QtAppDelegate.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/StoreKitController.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/AmneziaSceneDelegateHooks.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/TribePasteMenuFix.mm
)

# The context menu helper uses ARC-only constructs (weak references); the
# rest of the Objective-C++ sources build with manual reference counting.
set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ioscontextmenu.mm
    PROPERTIES COMPILE_OPTIONS "-fobjc-arc"
)


target_include_directories(${PROJECT} PRIVATE
    ${Qt6Gui_PRIVATE_INCLUDE_DIRS}
    ${AWG_APPLE_INCLUDE_DIRS}
)


set_target_properties(${PROJECT} PROPERTIES
    MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/Info.plist.in
    MACOSX_BUNDLE_ICON_FILE "AppIcon"
    MACOSX_BUNDLE_INFO_STRING "AmneziaVPN"
    MACOSX_BUNDLE_BUNDLE_NAME "AmneziaVPN"
    MACOSX_BUNDLE_GUI_IDENTIFIER "${BUILD_IOS_APP_IDENTIFIER}"
    MACOSX_BUNDLE_BUNDLE_VERSION "${CMAKE_PROJECT_VERSION_TWEAK}"
    MACOSX_BUNDLE_LONG_VERSION_STRING "${APPLE_PROJECT_VERSION}-${CMAKE_PROJECT_VERSION_TWEAK}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${APPLE_PROJECT_VERSION}"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "${BUILD_IOS_APP_IDENTIFIER}"
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "${CMAKE_CURRENT_SOURCE_DIR}/ios/app/main.entitlements"
    XCODE_ATTRIBUTE_MARKETING_VERSION "${APPLE_PROJECT_VERSION}"
    XCODE_ATTRIBUTE_CURRENT_PROJECT_VERSION "${CMAKE_PROJECT_VERSION_TWEAK}"
    XCODE_ATTRIBUTE_PRODUCT_NAME "AmneziaVPN"
    XCODE_ATTRIBUTE_BUNDLE_INFO_STRING "AmneziaVPN"
    XCODE_GENERATE_SCHEME TRUE
    XCODE_ATTRIBUTE_ASSETCATALOG_COMPILER_APPICON_NAME "AppIcon"
    XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
    XCODE_EMBED_FRAMEWORKS_CODE_SIGN_ON_COPY ON
    XCODE_LINK_BUILD_PHASE_MODE KNOWN_LOCATION
    XCODE_ATTRIBUTE_LD_RUNPATH_SEARCH_PATHS "@executable_path/Frameworks"
    XCODE_EMBED_APP_EXTENSIONS networkextension
    # AVPN (фикс краша ЗАПУСКА, билд 24): App Intents Extension временно НЕ встраиваем — он крашил старт
    # приложения на устройстве (появилось в билде 21). Десктоп-сборка из qrc подтвердила: QML и движок
    # грузятся чисто ⇒ виновато именно iOS-расширение (ExtensionKit через CMake). Вернём после починки.
    # XCODE_EMBED_EXTENSIONKIT_EXTENSIONS appintentsextension
)

# AVPN: подпись ВСЕГДА Automatic + team WellWon — амнезийные manual-профили (DEPLOY-ветка апстрима)
# нам не подходят и ломают headless-архив. // AVPN
set_target_properties(${PROJECT} PROPERTIES
    XCODE_ATTRIBUTE_CODE_SIGN_STYLE Automatic
)

set_target_properties(${PROJECT} PROPERTIES
    XCODE_ATTRIBUTE_SWIFT_VERSION "5.0"
    XCODE_ATTRIBUTE_CLANG_ENABLE_MODULES "YES"
    XCODE_ATTRIBUTE_SWIFT_PRECOMPILE_BRIDGING_HEADER "NO"
    XCODE_ATTRIBUTE_SWIFT_OBJC_INTERFACE_HEADER_NAME "AmneziaVPN-Swift.h"
    XCODE_ATTRIBUTE_SWIFT_OBJC_INTEROP_MODE "objcxx"
)
set_target_properties(${PROJECT} PROPERTIES
    XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "Q7DVH5MCWF"  # AVPN: WellWon Limited (НЕ апстрим X7UJ388FXK, НЕ личный 6D75W6GFC2). Сборка дополнительно переопределяет DEVELOPMENT_TEAM=Q7DVH5MCWF (archive-*.sh).
)
target_include_directories(${PROJECT} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_compile_definitions(${PROJECT} PRIVATE
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:GROUP_ID=\"${BUILD_IOS_GROUP_IDENTIFIER}\">
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:VPN_NE_BUNDLEID=\"${BUILD_IOS_APP_IDENTIFIER}.network-extension\">
)
target_compile_definitions(${PROJECT} PRIVATE
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:TRIBE_APPLE_AWG_ADAPTER_VERSION="${AWG_APPLE_ADAPTER_VERSION}">
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:TRIBE_APPLE_AWG_SOURCE_COMMIT="${AWG_APPLE_SOURCE_COMMIT}">
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:TRIBE_APPLE_AWG_CORE_VERSION="${AWG_APPLE_AWG_CORE_VERSION}">
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:TRIBE_APPLE_XRAY_ADAPTER_VERSION="${AWG_APPLE_XRAY_ADAPTER_VERSION}">
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:TRIBE_APPLE_XRAY_SOURCE_COMMIT="${AWG_APPLE_XRAY_SOURCE_COMMIT}">
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:TRIBE_APPLE_XRAY_CORE_VERSION="${AWG_APPLE_XRAY_CORE_VERSION}">
    $<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:TRIBE_APPLE_XRAY_SOCKET_ABI="${AWG_APPLE_XRAY_SOCKET_ABI}">
)

if(NOT DEFINED AWG_APPLE_SOURCE_DIR OR NOT EXISTS "${AWG_APPLE_SOURCE_DIR}/WireGuardKitC/x25519.c")
    message(FATAL_ERROR "awg-apple package did not export a valid AWG_APPLE_SOURCE_DIR") # AVPN
endif()

target_sources(${PROJECT} PRIVATE
#    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/iosvpnprotocol.swift
    ${AWG_APPLE_SOURCE_DIR}/WireGuardKitC/x25519.c
    ${CLIENT_ROOT_DIR}/platforms/ios/LogController.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/Log.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/LogRecord.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/ScreenProtection.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/VPNCController.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/StoreKit2Helper.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/TribeTunnelConfigVault.swift
    # AVPN: AvpnAppIntents.swift ПЕРЕНЕСЁН в App Intents Extension (ios/appintentsextension) —
    # в основном таргете iOS поднимал всё Qt-приложение в фоне ради фоновой команды → краш. Тут НЕ компилируем.
)

set_source_files_properties(
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/Media.xcassets
    PROPERTIES MACOSX_PACKAGE_LOCATION Resources
)

target_sources(${PROJECT} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/AmneziaVPNLaunchScreen.storyboard
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/Media.xcassets
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/PrivacyInfo.xcprivacy
)

set_property(TARGET ${PROJECT} APPEND PROPERTY RESOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/AmneziaVPNLaunchScreen.storyboard
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/PrivacyInfo.xcprivacy
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/Media.xcassets
)

add_subdirectory(ios/networkextension)
add_dependencies(${PROJECT} networkextension)

# AVPN (фикс краша ЗАПУСКА, билд 24): App Intents Extension ВРЕМЕННО ОТКЛЮЧЁН — он крашил запуск
# приложения на устройстве (появилось в билде 21; 22/23 унаследовали). Десктоп-сборка из qrc БЕЗ
# dev-превью подтвердила: QML и serviceEngine грузятся чисто ⇒ виновато именно iOS-расширение
# (App Intents/ExtensionKit, собранный не нативным Xcode-шаблоном, а через CMake). Команд Shortcuts
# пока не будет — это НЕ роняет запуск (в app-таргете их нет, AvpnAppIntents.swift только в расширении).
# Вернём расширение после починки причины краша (нужна сигнатура краша с устройства).
# add_subdirectory(ios/appintentsextension)
# add_dependencies(${PROJECT} appintentsextension)

# A release receipt is useful only if the final signed app preserves what CMake
# consumed. Embed the same closed build manifest in both signed code bundles;
# metadata/check_ios_release_artifact.py independently compares it with Git,
# engine-lock.json and the CI-pinned device/runtime receipt after IPA export.
set(_tribe_ios_source_commit "")
execute_process(
    COMMAND git rev-parse --verify HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE _tribe_ios_source_commit
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _tribe_ios_git_result
)
string(LENGTH "${_tribe_ios_source_commit}" _tribe_ios_source_commit_length)
if(_tribe_ios_git_result
   OR NOT _tribe_ios_source_commit MATCHES "^[0-9a-f][0-9a-f]*$"
   OR NOT _tribe_ios_source_commit_length EQUAL 40)
    message(FATAL_ERROR "iOS build manifest requires a full Git source commit")
endif()
set(_tribe_ios_engine_lock "${CMAKE_SOURCE_DIR}/metadata/engine-lock.json")
if(NOT EXISTS "${_tribe_ios_engine_lock}")
    message(FATAL_ERROR "iOS build manifest requires metadata/engine-lock.json")
endif()
file(SHA256 "${_tribe_ios_engine_lock}" TRIBE_IOS_ENGINE_LOCK_SHA256)

set(TRIBE_IOS_STORE_BUILD_XML "<false/>")
if(TRIBE_STORE_BUILD)
    set(TRIBE_IOS_STORE_BUILD_XML "<true/>")
endif()
set(TRIBE_IOS_AWG_GUARD_XML "<false/>")
if(TRIBE_IOS_AWG_GUARD_RECEIPT EQUAL 1)
    set(TRIBE_IOS_AWG_GUARD_XML "<true/>")
endif()
set(TRIBE_IOS_XRAY_GUARD_XML "<false/>")
if(TRIBE_IOS_XRAY_GUARD_RECEIPT EQUAL 1)
    set(TRIBE_IOS_XRAY_GUARD_XML "<true/>")
endif()
set(TRIBE_IOS_RUNTIME_RECEIPT_SHA256 "${TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256}")
string(LENGTH "${TRIBE_IOS_RUNTIME_RECEIPT_SHA256}"
       _tribe_ios_runtime_receipt_sha256_length)
if(TRIBE_STORE_BUILD
   AND (NOT TRIBE_IOS_AWG_GUARD_RECEIPT EQUAL 1
        OR NOT TRIBE_IOS_XRAY_GUARD_RECEIPT EQUAL 1
        OR NOT TRIBE_IOS_RUNTIME_RECEIPT_SHA256 MATCHES "^[0-9a-f][0-9a-f]*$"
        OR NOT _tribe_ios_runtime_receipt_sha256_length EQUAL 64))
    message(FATAL_ERROR
        "iOS store manifest requires passed AWG/Xray guards and a pinned runtime receipt")
endif()

set(TRIBE_IOS_SOURCE_COMMIT "${_tribe_ios_source_commit}")
set(TRIBE_IOS_BUILD_MANIFEST
    "${CMAKE_CURRENT_BINARY_DIR}/TribeBuildManifest.plist")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/ios/TribeBuildManifest.plist.in"
    "${TRIBE_IOS_BUILD_MANIFEST}"
    @ONLY
)
target_sources(${PROJECT} PRIVATE "${TRIBE_IOS_BUILD_MANIFEST}")
target_sources(networkextension PRIVATE "${TRIBE_IOS_BUILD_MANIFEST}")
set_source_files_properties("${TRIBE_IOS_BUILD_MANIFEST}"
    PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
set_property(TARGET ${PROJECT} APPEND PROPERTY RESOURCE "${TRIBE_IOS_BUILD_MANIFEST}")
set_property(TARGET networkextension APPEND PROPERTY RESOURCE "${TRIBE_IOS_BUILD_MANIFEST}")

# Store archives use two separately pinned distribution profiles. Keep normal
# developer builds automatic, but never let a store build fall back to Xcode's
# account/network-managed signing or one global profile for both executables.
if(TRIBE_STORE_BUILD)
    foreach(_profile_var TRIBE_IOS_APP_PROFILE_UUID TRIBE_IOS_NE_PROFILE_UUID)
        if(NOT DEFINED ${_profile_var}
           OR NOT "${${_profile_var}}" MATCHES
                  "^[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9A-Fa-f]+$")
            message(FATAL_ERROR "${_profile_var} must be a canonical profile UUID")
        endif()
        string(REPLACE "-" ";" _profile_parts "${${_profile_var}}")
        list(LENGTH _profile_parts _profile_part_count)
        if(NOT _profile_part_count EQUAL 5)
            message(FATAL_ERROR "${_profile_var} must be a canonical profile UUID")
        endif()
        set(_profile_part_lengths 8 4 4 4 12)
        foreach(_profile_part_index RANGE 0 4)
            list(GET _profile_parts ${_profile_part_index} _profile_part)
            list(GET _profile_part_lengths ${_profile_part_index} _profile_part_length_expected)
            string(LENGTH "${_profile_part}" _profile_part_length)
            if(NOT _profile_part_length EQUAL _profile_part_length_expected)
                message(FATAL_ERROR "${_profile_var} must be a canonical profile UUID")
            endif()
        endforeach()
    endforeach()
    set_target_properties(${PROJECT} PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_STYLE Manual
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Apple Distribution"
        XCODE_ATTRIBUTE_PROVISIONING_PROFILE_SPECIFIER "${TRIBE_IOS_APP_PROFILE_UUID}"
    )
    set_target_properties(networkextension PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_STYLE Manual
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Apple Distribution"
        XCODE_ATTRIBUTE_PROVISIONING_PROFILE_SPECIFIER "${TRIBE_IOS_NE_PROFILE_UUID}"
    )
endif()
