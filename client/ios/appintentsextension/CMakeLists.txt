enable_language(Swift)

set(CLIENT_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)

# AVPN: App Intents Extension — команды Shortcuts (TribeEnable/TribePause + AppShortcutsProvider)
# выполняются ЗДЕСЬ, в отдельном процессе. Так iOS НЕ поднимает основное Qt-приложение в фоне ради
# фоновой команды (это давало краш «Сбой приложения Tribe VPN»). Интенты управляют туннелем напрямую
# через NETunnelProviderManager + кладут мост в App Group. Apple-требование: AppShortcutsProvider и
# интенты в ОДНОМ таргете — здесь они вместе (AvpnAppIntents.swift). Чистый Swift, без Qt/C++.
add_executable(appintentsextension)
set_target_properties(appintentsextension PROPERTIES
    XCODE_PRODUCT_TYPE com.apple.product-type.app-extension
    BUNDLE_EXTENSION appex

    MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in
    MACOSX_BUNDLE_INFO_STRING "TribeAppIntentsExtension"
    MACOSX_BUNDLE_BUNDLE_NAME "TribeAppIntentsExtension"
    MACOSX_BUNDLE_GUI_IDENTIFIER "${BUILD_IOS_APP_IDENTIFIER}.AppIntentsExtension"
    MACOSX_BUNDLE_BUNDLE_VERSION "${CMAKE_PROJECT_VERSION_TWEAK}"
    MACOSX_BUNDLE_LONG_VERSION_STRING "${APPLE_PROJECT_VERSION}-${CMAKE_PROJECT_VERSION_TWEAK}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${APPLE_PROJECT_VERSION}"

    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "${BUILD_IOS_APP_IDENTIFIER}.AppIntentsExtension"
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS ${CMAKE_CURRENT_SOURCE_DIR}/TribeAppIntentsExtension.entitlements
    XCODE_ATTRIBUTE_MARKETING_VERSION "${APP_MAJOR_VERSION}"
    XCODE_ATTRIBUTE_CURRENT_PROJECT_VERSION "${BUILD_ID}"
    XCODE_ATTRIBUTE_PRODUCT_NAME "TribeAppIntentsExtension"

    XCODE_ATTRIBUTE_APPLICATION_EXTENSION_API_ONLY "YES"
    XCODE_ATTRIBUTE_ENABLE_BITCODE "NO"
    XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"

    XCODE_ATTRIBUTE_LD_RUNPATH_SEARCH_PATHS "@executable_path/../../Frameworks"
    XCODE_LINK_BUILD_PHASE_MODE KNOWN_LOCATION
)

set_target_properties(appintentsextension PROPERTIES
    XCODE_ATTRIBUTE_CODE_SIGN_STYLE Automatic
    # AVPN: подпись ТОЛЬКО WellWon Q7DVH5MCWF (НЕ личный 6D75W6GFC2 — см. memory tribe-signing-wellwon-only).
    XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "Q7DVH5MCWF"
)

set_target_properties(appintentsextension PROPERTIES
    XCODE_ATTRIBUTE_SWIFT_VERSION "5.0"
    XCODE_ATTRIBUTE_CLANG_ENABLE_MODULES "YES"
    XCODE_ATTRIBUTE_SWIFT_OPTIMIZATION_LEVEL "-Onone"
)

# Системные фреймворки (Swift auto-link обычно тянет сам, но указываем явно для Xcode-генератора).
find_library(FW_APP_INTENTS AppIntents)
find_library(FW_NETWORK_EXTENSION NetworkExtension)
target_link_libraries(appintentsextension PRIVATE ${FW_APP_INTENTS})
target_link_libraries(appintentsextension PRIVATE ${FW_NETWORK_EXTENSION})

# Общий App Group id — для UserDefaults(suiteName:) внутри интентов (мост к движку).
target_compile_options(appintentsextension PRIVATE -DGROUP_ID=\"${BUILD_IOS_GROUP_IDENTIFIER}\")

target_sources(appintentsextension PRIVATE
    ${CLIENT_ROOT_DIR}/platforms/ios/AvpnAppIntents.swift
)
