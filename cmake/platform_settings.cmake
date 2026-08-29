if(APPLE)
    get_property(generator_is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
    if (generator_is_multi_config)
        # Respect an explicit single-configuration Xcode build.  The Conan
        # provider otherwise installs every configuration before CMake can
        # compile the requested target, turning compile-only Apple proofs into
        # four unrelated package graphs.  With the normal Xcode default,
        # CMAKE_CONFIGURATION_TYPES already contains the full matrix, so the
        # existing developer behaviour is preserved.
        if(DEFINED CMAKE_CONFIGURATION_TYPES
           AND NOT "${CMAKE_CONFIGURATION_TYPES}" STREQUAL "")
            set(CONAN_INSTALL_BUILD_CONFIGURATIONS ${CMAKE_CONFIGURATION_TYPES})
        else()
            set(CONAN_INSTALL_BUILD_CONFIGURATIONS
                Release Debug MinSizeRel RelWithDebInfo)
        endif()
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        # Qt 6.11.1's official iOS frameworks are built with min iOS 17.  Advertising
        # 16 here produces a deceptively linked app containing incompatible Qt slices.
        set(CMAKE_OSX_DEPLOYMENT_TARGET "17.0" CACHE STRING "" FORCE)
        set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
    elseif(MACOS_NE)
        set(_CONAN_INSTALL_ARGS "-o=&:macos_ne=True")
        # The official Qt 6.11.1 macOS frameworks have min macOS 13.
        set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "" FORCE)
        # Conan has a scalar settings.arch; a semicolon list becomes the
        # invalid value armv8|x86_64. Compile-only CI therefore proves each
        # architecture in an independent build/package graph.
        if(NOT DEFINED TRIBE_MACOS_NE_ARCH OR "${TRIBE_MACOS_NE_ARCH}" STREQUAL "")
            set(TRIBE_MACOS_NE_ARCH "$ENV{TRIBE_MACOS_NE_ARCH}")
        endif()
        if("${TRIBE_MACOS_NE_ARCH}" STREQUAL "")
            set(TRIBE_MACOS_NE_ARCH "arm64")
        endif()
        if(NOT TRIBE_MACOS_NE_ARCH MATCHES "^(arm64|x86_64)$")
            message(FATAL_ERROR
                "TRIBE_MACOS_NE_ARCH must be one scalar architecture: arm64 or x86_64")
        endif()
        set(TRIBE_MACOS_NE_ARCH "${TRIBE_MACOS_NE_ARCH}" CACHE STRING
            "Non-shipping macOS NE compile architecture" FORCE)
        set(CMAKE_OSX_ARCHITECTURES "${TRIBE_MACOS_NE_ARCH}" CACHE STRING "" FORCE)
    else()
        set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "" FORCE)
        set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)  # AVPN: desktop форсим arm64-only (апстрим вернулся к universal 12.0/x86_64;arm64 — осознанно НЕ берём, conan --build=missing пересоберёт arm64-слайс)
    endif()

    # Keep release/debug symbols useful without embedding the checkout or
    # per-run build directory in any Apple executable. SDK/toolchain paths are
    # intentionally left intact for symbolicators.
    foreach(_tribe_prefix_root "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}")
        add_compile_options(
            "$<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:-ffile-prefix-map=${_tribe_prefix_root}=.>"
            "$<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:-fdebug-prefix-map=${_tribe_prefix_root}=.>"
            "$<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:-fmacro-prefix-map=${_tribe_prefix_root}=.>"
        )
    endforeach()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    # This include runs before the Conan dependency provider. Pin and validate
    # the native API here, rather than later in client/cmake/android.cmake, so
    # every ABI resolves packages for exactly the Play track it advertises.
    if(NOT DEFINED APP_ANDROID_MIN_SDK OR "${APP_ANDROID_MIN_SDK}" STREQUAL "")
        set(APP_ANDROID_MIN_SDK 28 CACHE STRING "Android minimum SDK" FORCE)
    endif()
    if(NOT "${APP_ANDROID_MIN_SDK}" MATCHES "^[0-9]+$")
        message(FATAL_ERROR "APP_ANDROID_MIN_SDK must be a non-negative integer")
    endif()
    set(_TRIBE_EXPECTED_ANDROID_PLATFORM "android-${APP_ANDROID_MIN_SDK}")
    if(DEFINED ANDROID_PLATFORM AND NOT "${ANDROID_PLATFORM}" STREQUAL ""
       AND NOT "${ANDROID_PLATFORM}" STREQUAL "${_TRIBE_EXPECTED_ANDROID_PLATFORM}")
        message(FATAL_ERROR
            "ANDROID_PLATFORM=${ANDROID_PLATFORM} disagrees with "
            "APP_ANDROID_MIN_SDK=${APP_ANDROID_MIN_SDK}")
    endif()
    set(ANDROID_PLATFORM "${_TRIBE_EXPECTED_ANDROID_PLATFORM}" CACHE STRING
        "Android native API level" FORCE)
    set(_CONAN_INSTALL_ARGS
        "-c=tools.android:cmake_legacy_toolchain=false"
        "-c=tools.build:sharedlinkflags=['-Wl,-z,max-page-size=16384']"
        "-c=tools.build:exelinkflags=['-Wl,-z,max-page-size=16384']")
    set(CMAKE_ANDROID_STL_TYPE "c++_shared" CACHE STRING "")
endif()

if (WIN32 OR APPLE)
    set(CMAKE_INSTALL_BINDIR ".")
endif()

# Apple NE-based apps do not support any dylibs or variations
# So Qt would use the openssl bundled with system, not application
if (NOT(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR (APPLE AND MACOS_NE)))
    list(APPEND _CONAN_INSTALL_ARGS "-o=openssl/*:shared=True")
endif()

list(PREPEND _CONAN_INSTALL_ARGS "--build=missing")
list(JOIN _CONAN_INSTALL_ARGS ";" _CONAN_INSTALL_ARGS_JOINED)
set(CONAN_INSTALL_ARGS ${_CONAN_INSTALL_ARGS_JOINED} CACHE STRING "" FORCE)
