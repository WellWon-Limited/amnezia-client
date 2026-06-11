# AVPN: свои имена пакета/каталога установки — иначе инсталлятор встаёт поверх официальной Amnezia
set(CPACK_PACKAGE_VENDOR            Tribe)
set(CPACK_PACKAGE_VERSION           ${AMNEZIAVPN_VERSION})
if(WIN32)
    set(CPACK_PACKAGE_FILE_NAME "TribeVPN_${AMNEZIAVPN_VERSION}_windows_x64")
elseif(APPLE AND NOT IOS AND NOT MACOS_NE)
    set(CPACK_PACKAGE_FILE_NAME "TribeVPN_${AMNEZIAVPN_VERSION}_macos_x64")
elseif(LINUX AND NOT ANDROID)
    set(CPACK_PACKAGE_FILE_NAME "TribeVPN_${AMNEZIAVPN_VERSION}_linux_x64")
endif()
set(CPACK_PACKAGE_INSTALL_DIRECTORY TribeVPN)
set(CPACK_PACKAGE_EXECUTABLES       AmneziaVPN AmneziaVPN)
set(CPACK_PRE_BUILD_SCRIPTS         ${CMAKE_CURRENT_LIST_DIR}/sign_binaries.cmake)
set(CPACK_POST_BUILD_SCRIPTS        ${CMAKE_CURRENT_LIST_DIR}/sign_packages.cmake)
set(CPACK_PROJECT_CONFIG_FILE       ${CMAKE_CURRENT_LIST_DIR}/CPackOptions.cmake)
set(CPACK_RESOURCE_FILE_LICENSE     ${CMAKE_SOURCE_DIR}/deploy/data/LICENSE.txt)

list(PREPEND CPACK_COMPONENTS_ALL AmneziaVPN)

if(APPLE)
    set(CPACK_GENERATOR productbuild)
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
set(CPACK_PREFLIGHT_AMNEZIAVPN_SCRIPT   ${CMAKE_SOURCE_DIR}/deploy/data/macos/post_uninstall.sh)
set(CPACK_POSTFLIGHT_AMNEZIAVPN_SCRIPT  ${CMAKE_SOURCE_DIR}/deploy/data/macos/post_install.sh)
set(CPACK_POSTFLIGHT_UNINSTALL_SCRIPT   ${CMAKE_SOURCE_DIR}/deploy/data/macos/post_uninstall.sh)
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
endif()

if (APPLE AND NOT IOS AND NOT MACOS_NE)
    install(FILES ${CMAKE_SOURCE_DIR}/deploy/data/macos/AntiVPN.plist
        DESTINATION "AntiVPN.app/Contents/Resources"
        COMPONENT AmneziaVPN
    )
endif()

include(CPackIFW)
cpack_ifw_configure_component(AmneziaVPN
    VERSION ${AMNEZIAVPN_VERSION}
    RELEASE_DATE ${RELEASE_DATE}
    REQUIRES_ADMIN_RIGHTS
    FORCED_INSTALLATION
    SCRIPT ${CMAKE_SOURCE_DIR}/deploy/installer/qif/componentscript.js
)

include(CPack)
cpack_add_component(Uninstall
    DISPLAY_NAME "Uninstall TribeVPN"
    REQUIRES_ADMIN_RIGHTS
    DISABLED
)
