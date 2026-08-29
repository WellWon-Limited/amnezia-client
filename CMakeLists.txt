cmake_minimum_required(VERSION 3.25.0 FATAL_ERROR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT AmneziaVPN)
set(AMNEZIAVPN_VERSION 5.0.1.1)

# AVPN: Tribe — СОБСТВЕННАЯ версия (ВСЕ платформы: iOS/macOS/Android/Windows) перекрывает upstream
# Amnezia. НИКОГДА не откатываемся на 4.9.x. Значение живёт в tribe_version.cmake (наш файл — апстрим
# его не трогает → merge не перетрёт). Бампать ТОЛЬКО там. См. docs/amnezia-fork/VERSIONING.md. // AVPN
include(${CMAKE_CURRENT_LIST_DIR}/tribe_version.cmake)
set(AMNEZIAVPN_VERSION ${TRIBE_VERSION})

set(QT_CREATOR_SKIP_PACKAGE_MANAGER_SETUP ON CACHE BOOL "" FORCE)
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
    ${CMAKE_SOURCE_DIR}/cmake/platform_settings.cmake
    ${CMAKE_SOURCE_DIR}/cmake/recipes_bootstrap.cmake
    ${CMAKE_SOURCE_DIR}/cmake/conan_provider.cmake
    CACHE STRING "" FORCE)

project(${PROJECT} VERSION ${AMNEZIAVPN_VERSION}
        DESCRIPTION "AmneziaVPN"
        HOMEPAGE_URL "https://amnezia.org/"
)

# trigger conan to kick off `conan install` globally
find_package(OpenSSL REQUIRED)
if (PREBUILTS_ONLY)
    return()
endif()

string(TIMESTAMP CURRENT_DATE "%Y-%m-%d")
set(RELEASE_DATE "${CURRENT_DATE}")

set(APP_MAJOR_VERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH})

# AVPN: Android versionCode starts at the monotonic Tribe value.  The Play
# matrix publishes two mutually exclusive SDK tracks, so its non-negative
# offset must be applied after selecting our base instead of being overwritten.
set(APP_ANDROID_VERSION_CODE ${TRIBE_ANDROID_VERSION_CODE})
if(DEFINED APP_ANDROID_VERSION_CODE_OFFSET
   AND NOT "${APP_ANDROID_VERSION_CODE_OFFSET}" STREQUAL "")
    if(NOT "${APP_ANDROID_VERSION_CODE_OFFSET}" MATCHES "^[0-9]+$")
        message(FATAL_ERROR "APP_ANDROID_VERSION_CODE_OFFSET must be a non-negative integer")
    endif()
    math(EXPR APP_ANDROID_VERSION_CODE
         "${APP_ANDROID_VERSION_CODE} + ${APP_ANDROID_VERSION_CODE_OFFSET}")
endif()
# Export the computed, source-owned value for release automation. INTERNAL +
# FORCE prevents a stale/user cache override while keeping CMakeCache evidence
# for the mutually exclusive 2158/2159 Play tracks.
set(APP_ANDROID_VERSION_CODE "${APP_ANDROID_VERSION_CODE}" CACHE INTERNAL
    "Computed Tribe Android versionCode" FORCE)

# AVPN: compatibility reporting needs a monotonic store/build number distinct
# from APP_VERSION.  Android uses Play's versionCode; Apple/desktop use the
# fourth CMake project component (CFBundleVersion on Apple).
if(ANDROID)
    set(APP_BUILD_NUMBER ${APP_ANDROID_VERSION_CODE})
else()
    set(APP_BUILD_NUMBER ${CMAKE_PROJECT_VERSION_TWEAK})
endif()

# Fail-closed platform runtime capability facts. A release CI receipt is source-commit and
# device-evidence bound; absent receipts compile all transport guard capabilities false.
include(${CMAKE_CURRENT_LIST_DIR}/cmake/platform_runtime_receipts.cmake)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(MZ_PLATFORM_NAME "linux")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set(MZ_PLATFORM_NAME "windows")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    set(MZ_PLATFORM_NAME "macos")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    set(MZ_PLATFORM_NAME "android")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "iOS")
    set(MZ_PLATFORM_NAME "ios")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Emscripten")
    set(MZ_PLATFORM_NAME "wasm")
endif()

set(QT_BUILD_TOOLS_WHEN_CROSS_COMPILING ON)

if(APPLE AND NOT IOS)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(AMN_PF_RULE_IDENTITY "user { root }")
    else()
        # AVPN: своя группа — не делить amnvpn с официальной Amnezia
        set(AMN_PF_RULE_IDENTITY "group { tribevpn }")
    endif()

    # AVPN: pf-файлы переименованы amn.* -> tribe.* (= BRAND_IDENTIFIER в macosfirewall.cpp)
    configure_file(
        "${CMAKE_SOURCE_DIR}/deploy/data/pf-templates/tribe.400.allowPIA.conf.in"
        "${CMAKE_CURRENT_BINARY_DIR}/tribe.400.allowPIA.conf"
        @ONLY
    )
endif()


add_subdirectory(client)

if(NOT IOS AND NOT ANDROID AND NOT MACOS_NE)
    add_subdirectory(service)
endif()

if ((LINUX AND NOT ANDROID) OR (APPLE AND NOT IOS AND NOT MACOS_NE) OR (WIN32))
    include(${CMAKE_SOURCE_DIR}/cmake/CPack.cmake)
endif()
