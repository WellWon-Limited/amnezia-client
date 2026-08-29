# AVPN: свои имена пакета/каталога установки — иначе инсталлятор встаёт поверх официальной Amnezia
set(CPACK_PACKAGE_VENDOR            Tribe)
set(CPACK_PACKAGE_NAME              TribeVPN)
set(CPACK_PACKAGE_VERSION           ${AMNEZIAVPN_VERSION})
if(WIN32)
    set(CPACK_PACKAGE_FILE_NAME "TribeVPN_${AMNEZIAVPN_VERSION}_windows_x64")
elseif(APPLE AND NOT IOS AND NOT MACOS_NE)
    # platform_settings.cmake deliberately ships the daemon flavor as arm64.
    # Do not label an arm64-only package as x64.
    set(CPACK_PACKAGE_FILE_NAME "TribeVPN_${AMNEZIAVPN_VERSION}_macos_arm64")
    if(NOT "${AMNEZIAVPN_VERSION}" MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+\\.([0-9]+)$")
        message(FATAL_ERROR
            "macOS release version must have a monotonic fourth build component")
    endif()
    set(CPACK_TRIBE_INSTALL_EPOCH "${CMAKE_MATCH_1}")
elseif(LINUX AND NOT ANDROID)
    set(CPACK_PACKAGE_FILE_NAME "TribeVPN_${AMNEZIAVPN_VERSION}_linux_x64")
endif()
set(CPACK_PACKAGE_INSTALL_DIRECTORY TribeVPN)
if(APPLE AND NOT IOS AND NOT MACOS_NE)
    set(CPACK_PACKAGE_EXECUTABLES   TribeVPN "Tribe VPN")
else()
    # Linux/Windows targets retain their upstream executable name.  Do not
    # point IFW/WIX shortcuts at a macOS-only OUTPUT_NAME.
    set(CPACK_PACKAGE_EXECUTABLES   AmneziaVPN "Tribe VPN")
endif()
set(CPACK_PRE_BUILD_SCRIPTS         ${CMAKE_CURRENT_LIST_DIR}/sign_binaries.cmake)
set(CPACK_POST_BUILD_SCRIPTS        ${CMAKE_CURRENT_LIST_DIR}/sign_packages.cmake)
set(CPACK_PROJECT_CONFIG_FILE       ${CMAKE_CURRENT_LIST_DIR}/CPackOptions.cmake)
set(CPACK_RESOURCE_FILE_LICENSE     ${CMAKE_SOURCE_DIR}/deploy/data/LICENSE.txt)

list(PREPEND CPACK_COMPONENTS_ALL AmneziaVPN)

if(APPLE)
    set(CPACK_GENERATOR productbuild)
    # The productbuild postflight and app self-updater both operate on the
    # canonical application bundle. CPack otherwise defaults to /usr/local.
    set(CPACK_PACKAGING_INSTALL_PREFIX "/Applications")
    set(CPACK_PRODUCTBUILD_DOMAINS ON)
    set(CPACK_PRODUCTBUILD_DOMAINS_ANYWHERE OFF)
    set(CPACK_PRODUCTBUILD_DOMAINS_USER OFF)
    set(CPACK_PRODUCTBUILD_DOMAINS_ROOT ON)
    # The GUI does not link every daemon-only Qt module (notably QtDBus).
    # Preserve the configured Qt lib root in CPackConfig so the pre-sign hook
    # can materialize the complete helper closure in the staged app.
    if(NOT Qt6Core_DIR)
        message(FATAL_ERROR "Qt6Core_DIR is required for the macOS daemon package")
    endif()
    get_filename_component(_tribe_qt_cmake_dir "${Qt6Core_DIR}" DIRECTORY)
    get_filename_component(CPACK_TRIBE_QT_LIB_DIR "${_tribe_qt_cmake_dir}" DIRECTORY)
    get_filename_component(CPACK_TRIBE_SOURCE_DIR "${CMAKE_SOURCE_DIR}" REALPATH)
    get_filename_component(CPACK_TRIBE_BUILD_DIR "${CMAKE_BINARY_DIR}" REALPATH)
    if(NOT EXISTS "${CPACK_TRIBE_QT_LIB_DIR}/QtCore.framework")
        message(FATAL_ERROR
            "Configured Qt Framework root is invalid: ${CPACK_TRIBE_QT_LIB_DIR}")
    endif()
else()
    set(CPACK_GENERATOR IFW)
endif()

# === CPack IFW generator settings ===
set(CPACK_IFW_PACKAGE_NAME                          TribeVPN)
set(CPACK_IFW_PACKAGE_TITLE                         TribeVPN)
set(CPACK_IFW_PACKAGE_WIZARD_DEFAULT_WIDTH          600)
set(CPACK_IFW_PACKAGE_WIZARD_DEFAULT_HEIGHT         380)
set(CPACK_IFW_PACKAGE_WIZARD_STYLE                  Modern)
set(CPACK_IFW_PACKAGE_REMOVE_TARGET_DIR             ON)
set(CPACK_IFW_PACKAGE_ALLOW_SPACE_IN_PATH           ON)
set(CPACK_IFW_PACKAGE_ALLOW_NON_ASCII_CHARACTERS    ON)
set(CPACK_IFW_PACKAGE_CONTROL_SCRIPT                ${CMAKE_SOURCE_DIR}/deploy/installer/qif/controlscript.js)

# === CPack WIX generator settings ===
set(CPACK_WIX_VERSION               4)
# AVPN: СВОЙ upgrade GUID — с GUID апстрима наш MSI «обновил» бы (заменил) официальную Amnezia
set(CPACK_WIX_UPGRADE_GUID          "{77E5BF8B-8424-4826-A14C-F2788313DC20}")
set(CPACK_WIX_PRODUCT_ICON          ${CMAKE_SOURCE_DIR}/client/images/app.ico)
set(CPACK_WIX_CUSTOM_XMLNS          "util=http://wixtoolset.org/schemas/v4/wxs/util")
set(_AMNEZIA_WIX_PATCH_SERVICE      ${CMAKE_SOURCE_DIR}/deploy/installer/wix/service_install_patch.xml)
set(_AMNEZIA_WIX_PATCH_CLOSE_APP    ${CMAKE_SOURCE_DIR}/deploy/installer/wix/close_client_patch.xml)
file(TO_CMAKE_PATH                  "${_AMNEZIA_WIX_PATCH_SERVICE}" _AMNEZIA_WIX_PATCH_SERVICE_CMAKE)
file(TO_CMAKE_PATH                  "${_AMNEZIA_WIX_PATCH_CLOSE_APP}" _AMNEZIA_WIX_PATCH_CLOSE_APP_CMAKE)
list(APPEND CPACK_WIX_PATCH_FILE    "${_AMNEZIA_WIX_PATCH_SERVICE_CMAKE}" "${_AMNEZIA_WIX_PATCH_CLOSE_APP_CMAKE}")
list(APPEND CPACK_WIX_EXTENSIONS    "WixToolset.Util.wixext")

# === CPack productbuild generator settings ===
set(CPACK_PRODUCTBUILD_IDENTIFIER       org.antivpn.pkg) # AVPN: свой pkg-receipt, не org.amneziavpn
# An upgrade preflight must not destroy the currently working app/service.
# productbuild may still fail before postflight; destructive uninstall is a
# separate operator action and is never selectable inside the shipping pkg.
set(CPACK_PREFLIGHT_AMNEZIAVPN_SCRIPT   ${CMAKE_SOURCE_DIR}/deploy/data/macos/pre_install.sh)
if(APPLE AND NOT IOS AND NOT MACOS_NE)
    configure_file(
        ${CMAKE_SOURCE_DIR}/deploy/data/macos/post_install.sh
        ${CMAKE_BINARY_DIR}/deploy/data/macos/post_install.sh
        @ONLY
    )
    set(CPACK_POSTFLIGHT_AMNEZIAVPN_SCRIPT
        ${CMAKE_BINARY_DIR}/deploy/data/macos/post_install.sh)
else()
    set(CPACK_POSTFLIGHT_AMNEZIAVPN_SCRIPT
        ${CMAKE_SOURCE_DIR}/deploy/data/macos/post_install.sh)
endif()
# provide custom CPack.distribution.dist.in
list(APPEND CMAKE_MODULE_PATH           ${CMAKE_SOURCE_DIR}/deploy/data/macos)

if(LINUX AND NOT ANDROID)
    install(FILES
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/TribeVPN.service
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/TribeVPN.png
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/TribeVPN.desktop
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/post_install.sh
        ${CMAKE_SOURCE_DIR}/deploy/data/linux/post_uninstall.sh
        DESTINATION "."
        COMPONENT AmneziaVPN
    )
endif()

if(WIN32)
    install(FILES
        ${CMAKE_SOURCE_DIR}/deploy/data/windows/post_install.cmd
        ${CMAKE_SOURCE_DIR}/deploy/data/windows/post_uninstall.cmd
        DESTINATION "."
        COMPONENT AmneziaVPN
    )

    set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
    include(InstallRequiredSystemLibraries)
    if(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
        install(PROGRAMS ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}
            DESTINATION "."
            COMPONENT AmneziaVPN
        )
    else()
        message(WARNING "MSVC runtime libraries were not found, packages will not ship them")
    endif()
endif()

# AVPN: апстримный блок install(FILES deploy/data/macos/AmneziaVPN.plist → AmneziaVPN.app/…) удалён.
# Наш pkg-postflight ставит закрытый receipt-gated payload; его транзакционный
# installer САМ генерирует /Library/LaunchDaemons/Tribe-service.plist — статический plist не нужен,
# а под legacy-именем AntiVPN он создавал фантомный /Applications/AntiVPN.app в payload (аудит 2026-07-02).

include(CPackIFW)
cpack_ifw_configure_component(AmneziaVPN
    # AVPN: имя компонента AmneziaVPN load-bearing (install(... COMPONENT) по всему дереву),
    # а видимое юзеру имя в визарде («Установка компонента …») задаём своё
    DISPLAY_NAME "Tribe VPN"
    DESCRIPTION "Tribe VPN"
    VERSION ${AMNEZIAVPN_VERSION}
    RELEASE_DATE ${RELEASE_DATE}
    REQUIRES_ADMIN_RIGHTS
    FORCED_INSTALLATION
    SCRIPT ${CMAKE_SOURCE_DIR}/deploy/installer/qif/componentscript.js
)

include(CPackComponent)
cpack_add_component(AmneziaVPN
    DISPLAY_NAME "Tribe VPN"
    DESCRIPTION "Tribe VPN"
    REQUIRED
    PLIST ${CMAKE_SOURCE_DIR}/deploy/data/macos/TribeVPN-component.plist
)

include(CPack)
