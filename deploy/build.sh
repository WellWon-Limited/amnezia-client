#!/bin/bash
set -o errexit
set +o xtrace

run_traced() {
    PS4='\033[1;34m+ \033[0m'
    set -o xtrace
    "$@"
    { set +o xtrace; } 2>/dev/null
}

all_abis_set="arm64-v8a armeabi-v7a x86_64 x86"
get_abi_folder() {
    case $1 in
        arm64-v8a)   echo "android_arm64_v8a" ;;
        armeabi-v7a) echo "android_armv7"     ;;
        x86)         echo "android_x86"       ;;
        all|x86_64)  echo "android_x86_64"    ;;
        *)           echo ""                  ;;
    esac
}

abis=()
installers=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--build)         : ${BUILD_PATH:="$2"};   shift 2 ;;
        -s|--source)        : ${SOURCE_PATH:="$2"};  shift 2 ;;
        -t|--target)        TARGET="$2";             shift 2 ;;
        -f|--force)         : ${FORCE=true};         shift   ;;
        -g|--generator)     : ${CMAKE_GENERATOR=$2}; shift 2 ;;
        --installer)        installers+=("$2");      shift 2 ;;
        --abi)              abis+=("$2");            shift 2 ;;
        --sign)             : ${SIGN:=true};         shift   ;;
        --aab)              : ${BUILD_AAB=true};     shift   ;;
        --compile-only)     : ${COMPILE_ONLY=true};  shift   ;;
        --catalog-root-kid) TRIBE_CATALOG_ROOT_KID="$2"; shift 2 ;;
        --catalog-root-public-key-hex) TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX="$2"; shift 2 ;;
        --runtime-receipt) TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE="$2"; shift 2 ;;
        --runtime-receipt-sha256) TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256="$2"; shift 2 ;;
        --help|-h|?)
            echo "Usage: $0 [options]"
            echo "  Options:"
            echo "  -b|--build <path>         - specify build folder"
            echo "  -s|--source <path>        - specify path to amnezia-client root folder"
            echo "  -t|--target <name>        - specify build target"
            echo "  -f|--force                - force removal of build folder prior cmake configuration"
            echo "  -g|--generator <name>     - use specified generator for CMake"
            echo "  --installer <name|all>    - specify an installer(s) to build. allowed to be used multiple times"
            echo "  --abi                     - specify Android ABIs for target to build for. all by default"
            echo "  --sign                    - whether to sign the resulting files. only appicable to Android"
            echo "  --aab                     - whether to build AAB. only applicable to Android"
            echo "  --compile-only            - unsigned, non-package macOS NE compile proof"
            echo "  --catalog-root-kid <id>   - audited catalog-v2 offline root key id"
            echo "  --catalog-root-public-key-hex <hex> - audited Ed25519 root public key"
            echo "  --runtime-receipt <path>  - absolute device/runtime evidence receipt"
            echo "  --runtime-receipt-sha256 <hex> - CI-pinned receipt SHA-256"
            exit 0
            ;;
        *) echo "Unknown arg \"$1\". Use $0 -h to get help"; exit 1 ;;
    esac
done

: ${SOURCE_PATH:=$(pwd)}
: ${BUILD_PATH:="$SOURCE_PATH/deploy/build"}
: ${INSTALLERS:="${installers[@]}"}
: ${ABIS:="${abis[@]}"}
: ${ABIS:="all"}
: ${HOST:="$(uname -s)"}
: ${TARGET:="$HOST"}

HOST=$(echo "$HOST" | tr '[:upper:]' '[:lower:]')
TARGET=$(echo "$TARGET" | tr '[:upper:]' '[:lower:]')

bases=(~/Qt /opt/Qt)
[ -n "${QT_INSTALL_DIR}" ] && bases=("${QT_INSTALL_DIR}/Qt" "${bases[@]}")

# seek for Qt installation in bases folders
qt_folders=()
qif_folders=()
for base in "${bases[@]}"; do
    for dir in "$base"/${QT_VERSION:-6.*}; do
        [ -d "$dir" ] && qt_folders+=("$dir")
    done
    for dir in "$base"/Tools/QtInstallerFramework/${QIF_VERSION:-*}; do
        [ -d "$dir" ] && qif_folders+=("$dir")
    done
done

: ${QT_ROOT_PATH:=$(printf '%s\n' "${qt_folders[@]}" | awk -F'/' '{print $NF, $0}' | sort -V | tail -1 | awk '{print $2}')}
: ${QIF_ROOT_PATH:=$(printf '%s\n' "${qif_folders[@]}" | awk -F'/' '{print $NF, $0}' | sort -V | tail -1 | awk '{print $2}')}

if [[ -z "$QT_ROOT_PATH" ]]; then
    echo "* Qt not found in standard paths and in QT_INSTALL_DIR"
    echo "  Please install the suitable version of Qt"
    echo "  or specify it by using QT_ROOT_PATH/QT_INSTALL_DIR variables"
    exit 1
fi

# add host options
case "$HOST" in
    linux)  [[ "$HOST" != "$TARGET" ]] && [[ -n "${QT_ROOT_PATH}" ]] && : ${QT_HOST_PATH:="$QT_ROOT_PATH/gcc_64"} ;;
    darwin) [[ "$HOST" != "$TARGET" ]] && [[ -n "${QT_ROOT_PATH}" ]] && : ${QT_HOST_PATH:="$QT_ROOT_PATH/macos"} ;;
    *) echo "Unsupported host \"$HOST\""; exit 1 ;;
esac

# add custom per-target options
case "$TARGET" in
    linux)
        [ "$INSTALLERS" = "all" ] && INSTALLERS="IFW"
        : ${CMAKE_GENERATOR:="Unix Makefiles"}
        : ${CMAKE_PREFIX_PATH:="$QT_ROOT_PATH"/gcc_64}
        ;;
    darwin|macos)
        [ "$INSTALLERS" = "all" ] && INSTALLERS="productbuild"
        : ${CMAKE_GENERATOR:="Unix Makefiles"}
        : ${CMAKE_PREFIX_PATH:="$QT_ROOT_PATH"/macos}
        ;;
    macos-ne)
        MACOS_NE=TRUE
        # macOS NE has no reviewed platform runtime receipt. It is kept as a
        # compile-only portability proof and must not silently become a signed
        # or distributable flavor.
        if [[ "${COMPILE_ONLY:-}" != true ]]; then
            echo "macOS NE is unsupported for release; use --compile-only for an unsigned build proof"
            exit 1
        fi
        DEPLOY=0
        no_installers=1
        CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO
        CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED=NO
        : ${CMAKE_GENERATOR:="Xcode"}
        : ${CMAKE_PREFIX_PATH:="$QT_ROOT_PATH"/macos}
        ;;
    ios)
        DEPLOY=1
        no_installers=1
        : ${CMAKE_GENERATOR:="Xcode"}
        : ${CMAKE_OSX_SYSROOT=iphoneos}
        : ${CMAKE_TOOLCHAIN_FILE:="$QT_ROOT_PATH/ios/lib/cmake/Qt6/qt.toolchain.cmake"}
        ;;
    android)
        no_installers=1
        : ${CMAKE_GENERATOR:="Ninja"}
        : ${ANDROID_PLATFORM:="android-${APP_ANDROID_MIN_SDK:-28}"}

        if [[ -n "$SIGN" ]]; then
            QT_ANDROID_SIGN_APK=TRUE
            QT_ANDROID_SIGN_AAB=TRUE
        fi

        [[ "$ABIS" == "all" ]] && ABIS="$all_abis_set"

        toolchain_abi=""
        for abi in $ABIS; do
            abi_exists=$(get_abi_folder "$abi")
            if [[ -z "$abi_exists" ]]; then
                echo "Unsupported ABI \"${abi}\""
                exit 1
            fi
            : ${toolchain_abi:="$abi"}
        done

        if [[ "$ABIS" == "$all_abis_set" ]]; then
            QT_ANDROID_BUILD_ALL_ABIS=TRUE
        else
            QT_ANDROID_ABIS="${ABIS// /;}"
        fi

        toolchain_dir=$(get_abi_folder "$toolchain_abi")
        : ${CMAKE_PREFIX_PATH:="$QT_ROOT_PATH/$toolchain_dir/lib/cmake/Qt6/qt.toolchain.cmake"}
        : ${CMAKE_TOOLCHAIN_FILE:="$QT_ROOT_PATH/$toolchain_dir/lib/cmake/Qt6/qt.toolchain.cmake"}
        ;;
    *) echo "Unsupported target \"$TARGET\""; exit 1 ;;
esac

if [[ -n "${COMPILE_ONLY:-}" && "$TARGET" != "macos-ne" ]]; then
    echo "--compile-only is reserved for the unsupported macOS NE compile proof"
    exit 1
fi

# Production catalog-v2 builds are deliberately fail closed. The application
# may only advertise a transport when the offline trust root and commit-bound
# device/runtime evidence for both AWG and Xray reached this exact build.
TRIBE_REQUIRED_RUNTIME_PLATFORM=""
case "$TARGET" in
    ios)      TRIBE_REQUIRED_RUNTIME_PLATFORM="ios" ;;
    darwin|macos)
        [[ "$INSTALLERS" != "" ]] && TRIBE_REQUIRED_RUNTIME_PLATFORM="macos_daemon"
        ;;
    android)
        if [[ -n "${SIGN:-}" || -n "${BUILD_AAB:-}" ]]; then
            TRIBE_REQUIRED_RUNTIME_PLATFORM="android"
        fi
        ;;
esac
case "${TRIBE_STORE_BUILD:-}" in
    1|ON|on|TRUE|true|YES|yes)
        case "$TARGET" in
            ios) TRIBE_REQUIRED_RUNTIME_PLATFORM="ios" ;;
            android) TRIBE_REQUIRED_RUNTIME_PLATFORM="android" ;;
            darwin|macos) TRIBE_REQUIRED_RUNTIME_PLATFORM="macos_daemon" ;;
            macos-ne)
                echo "macOS NE cannot be a store build until its runtime flavor is supported and receipted"
                exit 1
                ;;
        esac
        ;;
esac

if [[ -n "${TRIBE_CATALOG_ROOT_KID:-}" || -n "${TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX:-}" ]]; then
    if [[ ! "${TRIBE_CATALOG_ROOT_KID:-}" =~ ^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$ ||
          ! "${TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX:-}" =~ ^[0-9a-f]{64}$ ||
          "${TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX:-}" == "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
        echo "Catalog root id/public key must be supplied together in canonical form"
        exit 1
    fi
fi
if [[ -n "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE:-}" ||
      -n "${TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256:-}" ]]; then
    if [[ "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE:-}" != /* ||
          ! -f "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE:-}" ||
          ! "${TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]]; then
        echo "Runtime receipt requires an existing absolute path and lowercase SHA-256"
        exit 1
    fi
fi
if [[ -n "$TRIBE_REQUIRED_RUNTIME_PLATFORM" ]]; then
    if [[ -z "${TRIBE_CATALOG_ROOT_KID:-}" ||
          -z "${TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX:-}" ||
          -z "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE:-}" ||
          -z "${TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256:-}" ]]; then
        echo "Release target $TARGET requires catalog root plus commit-bound platform receipt"
        exit 1
    fi
    python3 "$SOURCE_PATH/metadata/check_platform_runtime_receipt.py" \
        --file "$TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE" \
        --sha256 "$TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256" \
        --platform "$TRIBE_REQUIRED_RUNTIME_PLATFORM" \
        --source-root "$SOURCE_PATH"
    QT_ROOT="${QT_ROOT:-$QT_ROOT_PATH/macos}" \
        bash "$SOURCE_PATH/metadata/run_tribe_release_gates.sh" \
        --release "$TRIBE_REQUIRED_RUNTIME_PLATFORM"
fi

if [[ "$INSTALLERS" =~ IFW ]] && [[ -z "$QIF_ROOT_PATH" ]]; then
    echo "* Qt Installer Framework not found in standard paths and in QT_INSTALL_DIR"
    echo "  Please install the suitable version of Qt Installer Framework"
    echo "  or specify it by using QIF_ROOT_PATH/QT_INSTALL_DIR variables"
    exit 1
fi

# search for Android SDK and NDK
if [[ "$TARGET" == "android" ]]; then
    bases=()
    case "$HOST" in
        linux)  bases=(~/Android/sdk)         ;;
        darwin) bases=(~/Library/Android/sdk) ;;
    esac
    [[ -n "$ANDROID_HOME" ]] && bases=("$ANDROID_HOME" "${bases[@]}")

    ndk_dirs=()
    for base in "${bases[@]}"; do
        for ndk_dir in "$base"/ndk/${ANDROID_NDK_VERSION:-*}; do
            [[ -d "$ndk_dir" ]] && ndk_dirs+=("$ndk_dir")
        done
    done

    : ${ANDROID_NDK_ROOT:=$(printf '%s\n' "${ndk_dirs[@]}" | awk -F'/' '{print $NF, $0}' | sort -V | tail -1 | awk '{print $2}')}
    : ${ANDROID_SDK_ROOT:="$ANDROID_NDK_ROOT/../.."}
fi

: ${CMAKE_BUILD_TYPE:=Release}
: ${JOBS:=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)}

# Xcode is multi-config even when --config names a single target.  Pin its
# configure-time matrix to the requested build type so the Conan dependency
# provider does not materialize three unused package graphs first.  Callers
# may still provide an explicit list when they intentionally need a matrix.
if [[ "$CMAKE_GENERATOR" == "Xcode" ]]; then
    : ${CMAKE_CONFIGURATION_TYPES:="$CMAKE_BUILD_TYPE"}
fi

args=()
[[ -n "$CMAKE_GENERATOR" ]]           && args+=("-G" "$CMAKE_GENERATOR")
[[ -n "$CMAKE_BUILD_TYPE" ]]          && args+=("-DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE")
[[ -n "${CMAKE_CONFIGURATION_TYPES:-}" ]] && args+=("-DCMAKE_CONFIGURATION_TYPES=$CMAKE_CONFIGURATION_TYPES")
[[ -n "$CMAKE_PREFIX_PATH" ]]         && args+=("-DCMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH")
[[ -n "$CMAKE_TOOLCHAIN_FILE" ]]      && args+=("-DCMAKE_TOOLCHAIN_FILE=$CMAKE_TOOLCHAIN_FILE")
[[ -n "$QT_HOST_PATH" ]]              && args+=("-DQT_HOST_PATH=$QT_HOST_PATH")
[[ -n "$CMAKE_OSX_SYSROOT" ]]         && args+=("-DCMAKE_OSX_SYSROOT=$CMAKE_OSX_SYSROOT")
[[ -n "$MACOS_NE" ]]                  && args+=("-DMACOS_NE=$MACOS_NE")
[[ -n "${TRIBE_MACOS_NE_ARCH:-}" ]]    && args+=("-DTRIBE_MACOS_NE_ARCH=$TRIBE_MACOS_NE_ARCH")
[[ -n "$DEPLOY" ]]                    && args+=("-DDEPLOY=$DEPLOY")
[[ -n "${CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED:-}" ]] && args+=("-DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=$CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED")
[[ -n "${CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED:-}" ]] && args+=("-DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED=$CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED")
[[ -n "$ANDROID_ABI" ]]               && args+=("-DANDROID_ABI=$ANDROID_ABI")
[[ -n "$ANDROID_SDK_ROOT" ]]          && args+=("-DANDROID_SDK_ROOT=$ANDROID_SDK_ROOT")
[[ -n "$ANDROID_NDK_ROOT" ]]          && args+=("-DANDROID_NDK_ROOT=$ANDROID_NDK_ROOT")
[[ -n "$ANDROID_PLATFORM" ]]          && args+=("-DANDROID_PLATFORM=$ANDROID_PLATFORM")
[[ -n "$APP_ANDROID_MIN_SDK" ]]       && args+=("-DAPP_ANDROID_MIN_SDK=$APP_ANDROID_MIN_SDK")
[[ -n "$APP_ANDROID_MAX_SDK" ]]       && args+=("-DAPP_ANDROID_MAX_SDK=$APP_ANDROID_MAX_SDK")
[[ -n "$APP_ANDROID_VERSION_CODE_OFFSET" ]] && args+=("-DAPP_ANDROID_VERSION_CODE_OFFSET=$APP_ANDROID_VERSION_CODE_OFFSET")
[[ -n "$QT_ANDROID_SIGN_APK" ]]       && args+=("-DQT_ANDROID_SIGN_APK=$QT_ANDROID_SIGN_APK")
[[ -n "$QT_ANDROID_SIGN_AAB" ]]       && args+=("-DQT_ANDROID_SIGN_AAB=$QT_ANDROID_SIGN_AAB")
[[ -n "$QT_ANDROID_ABIS" ]]           && args+=("-DQT_ANDROID_ABIS=$QT_ANDROID_ABIS")
[[ -n "$QT_ANDROID_BUILD_ALL_ABIS" ]] && args+=("-DQT_ANDROID_BUILD_ALL_ABIS=$QT_ANDROID_BUILD_ALL_ABIS")
[[ -n "${TRIBE_CATALOG_ROOT_KID:-}" ]] && args+=("-DTRIBE_CATALOG_ROOT_KID=$TRIBE_CATALOG_ROOT_KID")
[[ -n "${TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX:-}" ]] && args+=("-DTRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX=$TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX")
[[ -n "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE:-}" ]] && args+=("-DTRIBE_PLATFORM_RUNTIME_RECEIPT_FILE=$TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE")
[[ -n "${TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256:-}" ]] && args+=("-DTRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256=$TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256")
[[ -n "$TRIBE_REQUIRED_RUNTIME_PLATFORM" ]] && args+=("-DTRIBE_REQUIRED_RUNTIME_PLATFORM=$TRIBE_REQUIRED_RUNTIME_PLATFORM")
[[ -n "${TRIBE_IOS_APP_PROFILE_UUID:-}" ]] && args+=("-DTRIBE_IOS_APP_PROFILE_UUID=$TRIBE_IOS_APP_PROFILE_UUID")
[[ -n "${TRIBE_IOS_NE_PROFILE_UUID:-}" ]] && args+=("-DTRIBE_IOS_NE_PROFILE_UUID=$TRIBE_IOS_NE_PROFILE_UUID")

if [[ -n "$FORCE" ]]; then
    run_traced rm -rf "$BUILD_PATH"
fi

run_traced cmake -S "$SOURCE_PATH" -B "$BUILD_PATH" "${args[@]}"
build_args=(--build "$BUILD_PATH" --config "$CMAKE_BUILD_TYPE" --parallel "$JOBS")
if [[ "$TARGET" == "macos-ne" ]]; then
    # This flavor is a portability proof for the extension only. Building
    # Xcode's ALL_BUILD also recompiles the unrelated desktop GUI and obscures
    # whether the actual Network Extension target closed successfully.
    build_args+=(--target AmneziaVPNNetworkExtension)
fi
run_traced cmake "${build_args[@]}"

[[ -n "$BUILD_AAB" ]] && run_traced cmake --build "$BUILD_PATH" --config "$CMAKE_BUILD_TYPE" --parallel "$JOBS" -t "aab"

if [ -z "$no_installers" ]; then
    for installer in $INSTALLERS; do
        args=()
        [[ "$installer" == IFW ]] && args+=(-D "QTIFWDIR=$QIF_ROOT_PATH")

        (cd "$BUILD_PATH" && run_traced cpack -G "$installer" "${args[@]}")
    done
fi
