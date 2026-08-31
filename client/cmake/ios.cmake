message("Client iOS build")
set(APPLE_PROJECT_VERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH})

enable_language(OBJC)
enable_language(OBJCXX)
enable_language(Swift)

find_package(Qt6 REQUIRED COMPONENTS ShaderTools)
set(LIBS ${LIBS} Qt6::ShaderTools)

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
)


set(HEADERS ${HEADERS}
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ios_controller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ios_controller_wrapper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/iosnotificationhandler.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ioscontextmenu.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/QtAppDelegate.h
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
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/AmneziaSceneDelegateHooks.mm
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/TribePasteMenuFix.mm
)

# The context menu helper uses ARC-only constructs (weak references); the
# rest of the Objective-C++ sources build with manual reference counting.
set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/ioscontextmenu.mm
    PROPERTIES COMPILE_OPTIONS "-fobjc-arc"
)


target_include_directories(${PROJECT} PRIVATE ${Qt6Gui_PRIVATE_INCLUDE_DIRS})


set_target_properties(${PROJECT} PROPERTIES
    MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/Info.plist.in
    MACOSX_BUNDLE_ICON_FILE "AppIcon"
    MACOSX_BUNDLE_INFO_STRING "${CLIENT_APPLICATION_NAME}"
    MACOSX_BUNDLE_BUNDLE_NAME "${CLIENT_APPLICATION_NAME}"
    MACOSX_BUNDLE_GUI_IDENTIFIER "${BUILD_IOS_APP_IDENTIFIER}"
    MACOSX_BUNDLE_BUNDLE_VERSION "${CMAKE_PROJECT_VERSION_TWEAK}"
    MACOSX_BUNDLE_LONG_VERSION_STRING "${APPLE_PROJECT_VERSION}-${CMAKE_PROJECT_VERSION_TWEAK}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${APPLE_PROJECT_VERSION}"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "${BUILD_IOS_APP_IDENTIFIER}"
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "${CLIENT_IOS_APP_ENTITLEMENTS_PATH}"
    XCODE_ATTRIBUTE_MARKETING_VERSION "${APPLE_PROJECT_VERSION}"
    XCODE_ATTRIBUTE_CURRENT_PROJECT_VERSION "${CMAKE_PROJECT_VERSION_TWEAK}"
    XCODE_ATTRIBUTE_PRODUCT_NAME "${CLIENT_APPLICATION_NAME}"
    XCODE_ATTRIBUTE_BUNDLE_INFO_STRING "${CLIENT_APPLICATION_NAME}"
    XCODE_GENERATE_SCHEME TRUE
    XCODE_ATTRIBUTE_ASSETCATALOG_COMPILER_APPICON_NAME "AppIcon"
    XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
    XCODE_EMBED_FRAMEWORKS_CODE_SIGN_ON_COPY ON
    XCODE_LINK_BUILD_PHASE_MODE KNOWN_LOCATION
    XCODE_ATTRIBUTE_LD_RUNPATH_SEARCH_PATHS "@executable_path/Frameworks"
    XCODE_EMBED_APP_EXTENSIONS ${CLIENT_IOS_NE_TARGET_NAME}
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
    XCODE_ATTRIBUTE_SWIFT_OBJC_INTERFACE_HEADER_NAME "${CLIENT_SWIFT_OBJC_HEADER_NAME}"
    XCODE_ATTRIBUTE_SWIFT_OBJC_INTEROP_MODE "objcxx"
)
set_target_properties(${PROJECT} PROPERTIES
    XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${BUILD_VPN_DEVELOPMENT_TEAM}"
)
target_include_directories(${PROJECT} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_compile_options(${PROJECT} PRIVATE
    -DGROUP_ID=\"${BUILD_IOS_GROUP_IDENTIFIER}\"
    -DVPN_NE_BUNDLEID=\"${BUILD_IOS_APP_IDENTIFIER}.network-extension\"
)

set(WG_APPLE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rd/amneziawg-apple/Sources)

target_sources(${PROJECT} PRIVATE
#    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/ios/iosvpnprotocol.swift
    ${WG_APPLE_SOURCE_DIR}/WireGuardKitC/x25519.c
    ${CLIENT_ROOT_DIR}/platforms/ios/LogController.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/Log.swift
    ${CLIENT_GROUP_IDENTIFIER_SWIFT_FILE}
    ${CLIENT_ROOT_DIR}/platforms/ios/LogRecord.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/ScreenProtection.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/VPNCController.swift
    ${CLIENT_ROOT_DIR}/platforms/ios/StoreKit2Helper.swift
    # AVPN: AvpnAppIntents.swift ПЕРЕНЕСЁН в App Intents Extension (ios/appintentsextension) —
    # в основном таргете iOS поднимал всё Qt-приложение в фоне ради фоновой команды → краш. Тут НЕ компилируем.
)

set_source_files_properties(
    ${CLIENT_IOS_MEDIA_ASSETS_PATH}
    PROPERTIES MACOSX_PACKAGE_LOCATION Resources
)

target_sources(${PROJECT} PRIVATE
    ${CLIENT_IOS_LAUNCHSCREEN_PATH}
    ${CLIENT_IOS_MEDIA_ASSETS_PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/PrivacyInfo.xcprivacy
)

set_property(TARGET ${PROJECT} APPEND PROPERTY RESOURCE
    ${CLIENT_IOS_LAUNCHSCREEN_PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/PrivacyInfo.xcprivacy
    ${CMAKE_CURRENT_SOURCE_DIR}/ios/app/Media.xcassets
)

add_subdirectory(ios/networkextension)
add_dependencies(${PROJECT} ${CLIENT_IOS_NE_TARGET_NAME})

# AVPN (фикс краша ЗАПУСКА, билд 24): App Intents Extension ВРЕМЕННО ОТКЛЮЧЁН — он крашил запуск
# приложения на устройстве (появилось в билде 21; 22/23 унаследовали). Десктоп-сборка из qrc БЕЗ
# dev-превью подтвердила: QML и serviceEngine грузятся чисто ⇒ виновато именно iOS-расширение
# (App Intents/ExtensionKit, собранный не нативным Xcode-шаблоном, а через CMake). Команд Shortcuts
# пока не будет — это НЕ роняет запуск (в app-таргете их нет, AvpnAppIntents.swift только в расширении).
# Вернём расширение после починки причины краша (нужна сигнатура краша с устройства).
# add_subdirectory(ios/appintentsextension)
# add_dependencies(${PROJECT} appintentsextension)
