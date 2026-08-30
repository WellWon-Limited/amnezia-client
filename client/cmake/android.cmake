message("Client android ${CMAKE_ANDROID_ARCH_ABI} build")
find_package(Python3 REQUIRED COMPONENTS Interpreter)

if(NOT DEFINED APP_ANDROID_MIN_SDK)
    set(APP_ANDROID_MIN_SDK 28)
endif()

# Option to build Play variant (with Google Play Billing) instead of OSS
# When ON, adds target android_play_apk: cmake --build . --target android_play_apk
option(ANDROID_BUILD_PLAY "Add android_play_apk target for Google Play Billing build" OFF)
set(ANDROID_PLATFORM "android-${APP_ANDROID_MIN_SDK}" CACHE STRING
    "The minimum API level supported by the application or library" FORCE)

# set QTP0002 policy: target properties that specify Android-specific paths may contain generator expressions
qt_policy(SET QTP0002 NEW)

set_target_properties(${PROJECT} PROPERTIES
    QT_ANDROID_VERSION_NAME ${CMAKE_PROJECT_VERSION}
    QT_ANDROID_VERSION_CODE ${APP_ANDROID_VERSION_CODE}
    QT_ANDROID_MIN_SDK_VERSION ${APP_ANDROID_MIN_SDK}
    QT_ANDROID_TARGET_SDK_VERSION 36
    QT_ANDROID_SDK_BUILD_TOOLS_REVISION 36.0.0
)

# Qt configures every extra Android ABI in a separate nested build, often in
# parallel.  Never materialize generated engine artifacts in the shared source
# tree: an AAR and its checksum can otherwise be copied by different ABI
# configures at the same time and Gradle may observe a torn pair.  Each CMake
# build receives a private Android package source tree instead.
set(APP_ANDROID_PACKAGE_SOURCE_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/android-package-source)
file(REMOVE_RECURSE "${APP_ANDROID_PACKAGE_SOURCE_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/android/"
     DESTINATION "${APP_ANDROID_PACKAGE_SOURCE_DIR}"
     PATTERN ".gradle" EXCLUDE
     PATTERN "build" EXCLUDE)

# Qt configures every non-primary ABI as a separate CMake project.  Forward
# every release/security input that changes the generated app contract; otherwise
# one universal AAB can silently contain ABI slices compiled for a different
# Play SDK track, catalog root or runtime-receipt capability set.
set(QT_ANDROID_MULTI_ABI_FORWARD_VARS
    QT_NO_GLOBAL_APK_TARGET_PART_OF_ALL
    CMAKE_BUILD_TYPE
    CONAN_COMMAND
    CONAN_HOST_PROFILE
    CONAN_BUILD_PROFILE
    ANDROID_PLATFORM
    APP_ANDROID_MIN_SDK
    APP_ANDROID_MAX_SDK
    APP_ANDROID_VERSION_CODE_OFFSET
    AVPN_ENGINE
    TRIBE_STORE_BUILD
    DEPLOY
    TRIBE_CATALOG_ROOT_KID
    TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX
    TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE
    TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256
    TRIBE_REQUIRED_RUNTIME_PLATFORM
    PROD_AGW_PUBLIC_KEY
    PROD_S3_ENDPOINT
    FALLBACK_S3_ENDPOINT
    DEV_AGW_PUBLIC_KEY
    DEV_AGW_ENDPOINT
    DEV_S3_ENDPOINT
    FREE_V2_ENDPOINT
    PREM_V1_ENDPOINT
)

# We need to include qtprivate api's
# As QAndroidBinder is not yet implemented with a public api
# Check if Qt6::CorePrivate is available (may not be in all Qt versions/configurations)
if(TARGET Qt6::CorePrivate)
    set(LIBS ${LIBS} Qt6::CorePrivate)
endif()
set(LIBS ${LIBS} -ljnigraphics)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/platforms/android)

set(HEADERS ${HEADERS}
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/android/android_controller.h
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/android/android_utils.h
    ${CMAKE_CURRENT_SOURCE_DIR}/core/protocols/androidVpnProtocol.h
    ${CMAKE_CURRENT_SOURCE_DIR}/core/utils/installedAppsImageProvider.h
)

set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/android/android_controller.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/android/avpn_fcm_bridge.cpp # AVPN (Task 9): FCM-мост
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms/android/android_utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/core/protocols/androidVpnProtocol.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/core/utils/installedAppsImageProvider.cpp
)


find_package(awg-android REQUIRED)
set(LIBS ${LIBS} amnezia::awg-android)
set_property(TARGET ${PROJECT} APPEND PROPERTY QT_ANDROID_EXTRA_LIBS ${AMNEZIA_ANDROID_LIBWG_PATH} ${AMNEZIA_ANDROID_LIBWG_QUICK_PATH})

find_package(amnezia-libxray REQUIRED)
foreach(_required AWG_ANDROID_ADAPTER_VERSION AWG_ANDROID_SOURCE_COMMIT
                  AWG_ANDROID_UAPI_ABI AMNEZIA_LIBXRAY_ADAPTER_VERSION
                  AMNEZIA_LIBXRAY_SOURCE_COMMIT AMNEZIA_LIBXRAY_CORE_VERSION
                  AMNEZIA_LIBXRAY_ABI)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "Android engine package did not export ${_required}")
    endif()
endforeach()
target_compile_definitions(${PROJECT} PRIVATE
    TRIBE_ANDROID_AWG_ADAPTER_VERSION="${AWG_ANDROID_ADAPTER_VERSION}"
    TRIBE_ANDROID_AWG_SOURCE_COMMIT="${AWG_ANDROID_SOURCE_COMMIT}"
    TRIBE_ANDROID_AWG_CORE_VERSION="${AWG_ANDROID_ADAPTER_VERSION}"
    TRIBE_ANDROID_AWG_ABI="${AWG_ANDROID_UAPI_ABI}"
    TRIBE_ANDROID_XRAY_ADAPTER_VERSION="${AMNEZIA_LIBXRAY_ADAPTER_VERSION}"
    TRIBE_ANDROID_XRAY_SOURCE_COMMIT="${AMNEZIA_LIBXRAY_SOURCE_COMMIT}"
    TRIBE_ANDROID_XRAY_CORE_VERSION="${AMNEZIA_LIBXRAY_CORE_VERSION}"
    TRIBE_ANDROID_XRAY_ABI="${AMNEZIA_LIBXRAY_ABI}"
)
string(LENGTH "${AMNEZIA_LIBXRAY_ARTIFACT_SHA256}" _libxray_artifact_sha256_length)
if(NOT DEFINED AMNEZIA_LIBXRAY_ARTIFACT_SHA256
   OR NOT _libxray_artifact_sha256_length EQUAL 64
   OR NOT AMNEZIA_LIBXRAY_ARTIFACT_SHA256 MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "amnezia-libxray/1.0.3-tribe.1 package did not export its artifact SHA-256")
endif()
set(_libxray_destination
    ${APP_ANDROID_PACKAGE_SOURCE_DIR}/xray/libXray/libxray.aar)
execute_process(
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/metadata/check_android_xray_aar.py"
            "${AMNEZIA_LIBXRAY_PATH}" --sha256 "${AMNEZIA_LIBXRAY_ARTIFACT_SHA256}"
    RESULT_VARIABLE _libxray_check
    OUTPUT_VARIABLE _libxray_check_output
    ERROR_VARIABLE _libxray_check_error
)
if(NOT _libxray_check EQUAL 0)
    message(FATAL_ERROR "Pinned libxray AAR rejected: ${_libxray_check_error}")
endif()
file(COPY_FILE "${AMNEZIA_LIBXRAY_PATH}" "${_libxray_destination}" ONLY_IF_DIFFERENT)
file(WRITE "${_libxray_destination}.sha256" "${AMNEZIA_LIBXRAY_ARTIFACT_SHA256}\n")

find_package(openvpn-pt-android REQUIRED)
set(LIBS ${LIBS} amnezia::openvpn-pt-android)
set_property(TARGET ${PROJECT} APPEND PROPERTY QT_ANDROID_EXTRA_LIBS ${OPENVPN_PT_ANDROID_LIBCK_OVPN_PLUGIN_PATH})

if(APP_ANDROID_MAX_SDK)
    if(NOT "${APP_ANDROID_MAX_SDK}" MATCHES "^[0-9]+$")
        message(FATAL_ERROR "APP_ANDROID_MAX_SDK must be a non-negative integer")
    endif()
    if(APP_ANDROID_MAX_SDK LESS APP_ANDROID_MIN_SDK)
        message(FATAL_ERROR
            "APP_ANDROID_MAX_SDK must be greater than or equal to APP_ANDROID_MIN_SDK")
    endif()
    set(manifest_path ${APP_ANDROID_PACKAGE_SOURCE_DIR}/AndroidManifest.xml)
    set(manifest_anchor "android:installLocation=\"auto\">")
    file(READ ${manifest_path} manifest_contents)
    string(REPLACE
        "${manifest_anchor}"
        "${manifest_anchor}\n\n    <uses-sdk android:maxSdkVersion=\"${APP_ANDROID_MAX_SDK}\" />"
        patched_contents "${manifest_contents}")
    if(patched_contents STREQUAL manifest_contents)
        message(FATAL_ERROR
            "Failed to set maxSdkVersion=${APP_ANDROID_MAX_SDK}: anchor '${manifest_anchor}' "
            "not found in ${CMAKE_CURRENT_SOURCE_DIR}/android/AndroidManifest.xml")
    endif()
    file(WRITE ${manifest_path} "${patched_contents}")
endif()

set_property(TARGET ${PROJECT} PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR ${APP_ANDROID_PACKAGE_SOURCE_DIR})

if(QT_USE_TARGET_ANDROID_BUILD_DIR)
    set(_android_build_dir "${CMAKE_CURRENT_BINARY_DIR}/android-build-${PROJECT}")
else()
    set(_android_build_dir "${CMAKE_CURRENT_BINARY_DIR}/android-build")
endif()

add_custom_target(android_gradle_clean
    COMMAND ./gradlew clean
    WORKING_DIRECTORY "${_android_build_dir}"
    COMMENT "Cleaning Android Gradle build cache"
)

# Always-available debug target: build Play Debug APK and copy to standard output path
# so Qt Creator's deploy step picks it up automatically
add_custom_target(android_play_debug_install
    COMMAND ./gradlew assemblePlayDebug
    COMMAND sh -c "cp build/outputs/apk/play/debug/*.apk build/outputs/apk/android-build-${PROJECT}-debug.apk"
    WORKING_DIRECTORY "${_android_build_dir}"
    COMMENT "Building Android Play Debug APK and copying to deploy path"
    DEPENDS ${PROJECT}
)

if(ANDROID_BUILD_PLAY)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(_gradle_suffix "Debug")
    else()
        set(_gradle_suffix "Release")
    endif()
    add_custom_target(android_play_apk
        COMMAND ./gradlew assemblePlay${_gradle_suffix}
        WORKING_DIRECTORY "${_android_build_dir}"
        COMMENT "Building Android Play APK (assemblePlay${_gradle_suffix})"
        DEPENDS ${PROJECT}
    )
    add_custom_target(android_play_aab
        COMMAND ./gradlew bundlePlay${_gradle_suffix}
        WORKING_DIRECTORY "${_android_build_dir}"
        COMMENT "Building Android Play AAB (bundlePlay${_gradle_suffix})"
        DEPENDS ${PROJECT}
    )
endif()
