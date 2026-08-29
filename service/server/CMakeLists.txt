cmake_minimum_required(VERSION 3.25.0 FATAL_ERROR)

set(PROJECT Tribe-service) # AVPN: своё имя демона (= SERVICE_NAME в version.h.in, проверка isServiceReady)
project(${PROJECT} VERSION ${AMNEZIAVPN_VERSION})

if (APPLE)
    # CMAKE_INSTALL_BINDIR must be called before find_package(Qt6) for
    # Qt to configure prefixes properly
    # FIXME: make Amnezia-service a bundle and remove this hack completely
    # The desktop GUI target is rebranded to TribeVPN.app. Installing the
    # service into the upstream name creates a second, non-runnable app and
    # leaves the shipping Tribe bundle without AWG/OpenVPN/Xray helpers.
    set(CMAKE_INSTALL_BINDIR "TribeVPN.app/Contents/MacOS")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS DBus Core Network Widgets RemoteObjects Core5Compat Concurrent)
qt_standard_project_setup()

configure_file(${CMAKE_SOURCE_DIR}/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/version.h)

set(HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/../../client/core/utils/utilities.h
    ${CMAKE_CURRENT_LIST_DIR}/../../common/crypto/cryptoUtils.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/secureQSettings.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/core/utils/networkUtilities.h
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipc.h
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipcsecurity.h
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/openvpnconfigsecurity.h
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipcserver.h
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipcserverprocess.h
    ${CMAKE_CURRENT_LIST_DIR}/localserver.h
    ${CMAKE_CURRENT_LIST_DIR}/../../common/logger/logger.h
    ${CMAKE_CURRENT_LIST_DIR}/router.h
    ${CMAKE_CURRENT_LIST_DIR}/killswitch.h
    ${CMAKE_CURRENT_LIST_DIR}/systemservice.h
    ${CMAKE_CURRENT_LIST_DIR}/xray.h
    ${CMAKE_CURRENT_BINARY_DIR}/version.h
)

set(SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/../../client/core/utils/utilities.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../common/crypto/cryptoUtils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../client/secureQSettings.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../client/core/utils/networkUtilities.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipcserver.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipcserverprocess.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipcsecurity.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc/openvpnconfigsecurity.cpp
    ${CMAKE_CURRENT_LIST_DIR}/localserver.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../common/logger/logger.cpp
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp
    ${CMAKE_CURRENT_LIST_DIR}/router.cpp
    ${CMAKE_CURRENT_LIST_DIR}/killswitch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/systemservice.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xray.cpp
)

# Mozilla headres
set(HEADERS ${HEADERS}
    ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/dnsutils.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/iputils.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/interfaceconfig.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/wireguardutils.h

    ${CMAKE_CURRENT_LIST_DIR}/../../client/platforms/dummy/dummynetworkwatcher.h

    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/shared/ipaddress.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/shared/loglevel.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/shared/leakdetector.h

    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/models/server.h

    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/controllerimpl.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/dnspingsender.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/networkwatcher.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/networkwatcherimpl.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/pinghelper.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/pingsender.h
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/pingsenderfactory.h
)

include_directories(../../client/mozilla)
include_directories(../../client/mozilla/shared)
include_directories(../../client/mozilla/models)
include_directories(../../client/platforms/)

# Mozilla sources
set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/models/server.cpp

    ${CMAKE_CURRENT_LIST_DIR}/../../client/platforms/dummy/dummynetworkwatcher.cpp
    
    ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/interfaceconfig.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/shared/ipaddress.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/shared/leakdetector.cpp

    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/dnspingsender.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/networkwatcher.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/pinghelper.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/pingsender.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/pingsenderfactory.cpp
)

if(UNIX)
    set(HEADERS ${HEADERS}
        ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/shared/signalhandler.h
    )
    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/../../client/mozilla/shared/signalhandler.cpp
    )
endif()

if (WIN32 OR APPLE OR LINUX)
    set(HEADERS ${HEADERS}
        ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/daemon.h
        ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/daemonlocalserver.h
        ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/daemonlocalserverconnection.h
    )
    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/daemon.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/daemonlocalserver.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/daemonlocalserverconnection.cpp
    )
endif()

set(RESOURCES)

if(WIN32)
    configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/amneziavpn-service.rc.in
        ${CMAKE_CURRENT_BINARY_DIR}/amneziavpn-service.rc
    )

    set(HEADERS ${HEADERS}
        ${CMAKE_CURRENT_LIST_DIR}/tapcontroller_win.h
        ${CMAKE_CURRENT_LIST_DIR}/router_win.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowsdaemon.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowsdaemontunnel.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowsfirewall.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowscommons.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowsservicemanager.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/dnsutilswindows.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowssplittunnel.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowstunnelservice.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/wireguardutilswindows.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowstunnellogger.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowsroutemonitor.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowsutils.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowspingsender.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowsnetworkwatcher.h
        ${CMAKE_CURRENT_LIST_DIR}/../../client/daemon/daemonerrors.h
    )

    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/tapcontroller_win.cpp
        ${CMAKE_CURRENT_LIST_DIR}/router_win.cpp

        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowsdaemon.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowsdaemontunnel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowsfirewall.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowscommons.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowsservicemanager.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/dnsutilswindows.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowssplittunnel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowstunnelservice.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/wireguardutilswindows.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowstunnellogger.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/daemon/windowsroutemonitor.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowspingsender.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowsnetworkwatcher.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/windows/windowsutils.cpp
    )

    set(RESOURCES ${RESOURCES}
        ${CMAKE_CURRENT_BINARY_DIR}/amneziavpn-service.rc
    )

    set(LIBS
        user32
        rasapi32
        shlwapi
        iphlpapi
        ws2_32
        iphlpapi
        gdi32
        Advapi32
        Kernel32
        qt6keychain
    )

    add_compile_definitions(_WINSOCKAPI_)
endif()

if(APPLE)
    set(HEADERS ${HEADERS}
        ${CMAKE_CURRENT_LIST_DIR}/helper_route_mac.h
        ${CMAKE_CURRENT_LIST_DIR}/router_mac.h
        ${CMAKE_CURRENT_LIST_DIR}/openvpndnssecurity.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/macosnativesessionguard.h
    )

    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/helper_route_mac.c
        ${CMAKE_CURRENT_LIST_DIR}/router_mac.cpp
        ${CMAKE_CURRENT_LIST_DIR}/openvpndnssecurity.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/macosnativesessionguard.cpp
    )

    #Mozilla
    set(HEADERS ${HEADERS}
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/ios/iosnetworkwatcher.h

        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/macosnetworkwatcher.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/macospingsender.h

        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/dnsutilsmacos.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/iputilsmacos.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/macosdaemon.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/macosroutemonitor.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/wireguardutilsmacos.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/macosfirewall.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/splitdnsresolverfiles.h # AVPN (Tribe split-DNS)
    )

    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/ios/iosnetworkwatcher.mm

        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/macosnetworkwatcher.mm
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/macospingsender.cpp

        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/dnsutilsmacos.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/iputilsmacos.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/macosdaemon.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/macosroutemonitor.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/wireguardutilsmacos.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/macosfirewall.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/macos/daemon/splitdnsresolverfiles.cpp # AVPN (Tribe split-DNS)
    )

    set(LIBS
        resolv
        qt6keychain
    )

endif()

if(LINUX)

    set(HEADERS ${HEADERS}
        ${CMAKE_CURRENT_LIST_DIR}/router_linux.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/linuxnetworkwatcher.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/linuxnetworkwatcherworker.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/linuxdependencies.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/linuxpingsender.h 
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/iputilslinux.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/dbustypeslinux.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/linuxdaemon.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/dnsutilslinux.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/wireguardutilslinux.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/linuxroutemonitor.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/linuxfirewall.h        
    )

    set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/router_linux.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/linuxnetworkwatcher.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/linuxnetworkwatcherworker.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/linuxdependencies.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/linuxpingsender.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/dnsutilslinux.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/iputilslinux.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/linuxdaemon.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/wireguardutilslinux.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/linuxroutemonitor.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../../client/platforms/linux/daemon/linuxfirewall.cpp
    )

    set(LIBS
        ${OPENSSL_LIB_CRYPTO_PATH}
        qt6keychain
        -static-libstdc++
        -static-libgcc
        -ldl
    )

endif()

include(${CMAKE_CURRENT_LIST_DIR}/../src/qtservice.cmake)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../../client
    ${CMAKE_CURRENT_LIST_DIR}/../../ipc
    ${CMAKE_CURRENT_LIST_DIR}/../../common/logger
    ${CMAKE_CURRENT_LIST_DIR}/../../common/crypto
    ${CMAKE_CURRENT_BINARY_DIR}
)


add_executable(${PROJECT} ${SOURCES} ${HEADERS} ${RESOURCES})
target_link_libraries(${PROJECT} PRIVATE Qt6::Core Qt6::Widgets Qt6::Network Qt6::RemoteObjects Qt6::Core5Compat Qt6::DBus Qt6::Concurrent ${LIBS})
target_compile_definitions(${PROJECT} PRIVATE "MZ_$<UPPER_CASE:${MZ_PLATFORM_NAME}>")

find_package(amnezia-xray-bindings REQUIRED)
target_link_libraries(${PROJECT} PRIVATE amnezia::xray-bindings)

foreach(_required XRAY_BINDINGS_VERSION XRAY_BINDINGS_SOURCE_COMMIT XRAY_CORE_VERSION XRAY_BINDINGS_C_ABI)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "xray-bindings package did not export ${_required}") # AVPN
    endif()
endforeach()
target_compile_definitions(${PROJECT} PRIVATE
    TRIBE_XRAY_BINDINGS_VERSION="${XRAY_BINDINGS_VERSION}"
    TRIBE_XRAY_BINDINGS_COMMIT="${XRAY_BINDINGS_SOURCE_COMMIT}"
    TRIBE_XRAY_CORE_VERSION="${XRAY_CORE_VERSION}"
    TRIBE_XRAY_BINDINGS_ABI="${XRAY_BINDINGS_C_ABI}"
)

find_package(OpenSSL REQUIRED)
target_link_libraries(${PROJECT} PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(${PROJECT} PRIVATE "MZ_DEBUG")
endif()

target_compile_definitions(${PROJECT} PRIVATE
    TRIBE_MAC_GUI_IDENTIFIER="hk.wellwon.vpn"
    TRIBE_MAC_TEAM_IDENTIFIER="Q7DVH5MCWF"
)

if(APPLE)
    set_target_properties(${PROJECT} PROPERTIES
        INSTALL_RPATH "@executable_path/../Frameworks"
    )

    find_library(FW_COREFOUNDATION CoreFoundation)
    find_library(FW_SYSTEMCONFIG SystemConfiguration)
    find_library(FW_SERVICEMGMT ServiceManagement)
    find_library(FW_SECURITY Security)
    find_library(FW_COREWLAN CoreWLAN)
    find_library(FW_NETWORK Network)
    find_library(FW_USER_NOTIFICATIONS UserNotifications)

    target_link_libraries(${PROJECT} PRIVATE ${FW_COREFOUNDATION})
    target_link_libraries(${PROJECT} PRIVATE ${FW_SYSTEMCONFIG})
    target_link_libraries(${PROJECT} PRIVATE ${FW_SERVICEMGMT})
    target_link_libraries(${PROJECT} PRIVATE ${FW_SECURITY})
    target_link_libraries(${PROJECT} PRIVATE ${FW_COREWLAN})
    target_link_libraries(${PROJECT} PRIVATE ${FW_NETWORK})
    target_link_libraries(${PROJECT} PRIVATE ${FW_USER_NOTIFICATIONS})


endif()

qt_add_repc_sources(${PROJECT} ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipc_interface.rep)
qt_add_repc_sources(${PROJECT} ${CMAKE_CURRENT_LIST_DIR}/../../ipc/ipc_process_interface.rep)

if(APPLE)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/deploy/data/macos/pf
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT AmneziaVPN
    )
    # The identity-specific rule is generated per build. Keep it in the build/install
    # tree; configuring Debug must never rewrite a tracked production PF rule.
    install(FILES ${CMAKE_BINARY_DIR}/tribe.400.allowPIA.conf
        DESTINATION ${CMAKE_INSTALL_BINDIR}/pf
        COMPONENT AmneziaVPN
    )
    add_custom_command(TARGET ${PROJECT} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/deploy/data/macos/pf
        "$<TARGET_FILE_DIR:${PROJECT}>/pf"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/tribe.400.allowPIA.conf
        "$<TARGET_FILE_DIR:${PROJECT}>/pf/tribe.400.allowPIA.conf"
    )
endif()

# install non-linked dependencies
if(WIN32)
    find_package(awg-windows REQUIRED)
    list(APPEND CONAN_EXECS $<TARGET_FILE:amnezia::awg-windows>)

    find_package(wintun REQUIRED)
    list(APPEND CONAN_BINS $<TARGET_FILE:zx2c4::wintun>)

    list(APPEND CONAN_BINS $<TARGET_FILE:OpenSSL::SSL> $<TARGET_FILE:OpenSSL::Crypto>)
else()
    find_package(awg-go REQUIRED)
    list(APPEND CONAN_EXECS $<TARGET_FILE:amnezia::awg-go>)
    if(APPLE)
        foreach(_required AWG_GO_ENGINE_VERSION AWG_GO_SOURCE_COMMIT AWG_GO_UAPI_ABI)
            if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
                message(FATAL_ERROR "awg-go package did not export ${_required}") # AVPN
            endif()
        endforeach()
        target_compile_definitions(${PROJECT} PRIVATE
            TRIBE_ENGINE_MANIFEST_ENABLED=1
            TRIBE_AWG_ENGINE_VERSION="${AWG_GO_ENGINE_VERSION}"
            TRIBE_AWG_CORE_VERSION="${AWG_GO_ENGINE_VERSION}"
            TRIBE_AWG_ENGINE_COMMIT="${AWG_GO_SOURCE_COMMIT}"
            TRIBE_AWG_UAPI_ABI="${AWG_GO_UAPI_ABI}"
        )
    endif()
endif()

find_package(openvpn REQUIRED)
list(APPEND CONAN_EXECS $<TARGET_FILE:openvpn::openvpn>)

find_package(tun2socks REQUIRED)
list(APPEND CONAN_EXECS $<TARGET_FILE:xjasonlyu::tun2socks>)

find_package(v2ray-rules-dat REQUIRED)
list(APPEND CONAN_BINS ${GEOSITE_DAT_PATH} ${GEOIP_DAT_PATH})

add_custom_command(TARGET ${PROJECT} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CONAN_EXECS} ${CONAN_BINS}
        "$<TARGET_FILE_DIR:${PROJECT}>"
)

# prebuilt openvpn carries the rpath of whatever machine baked it; point the
# build-tree copy at the local conan openssl (install rewrites it to $ORIGIN)
if(LINUX)
    file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/set_openvpn_rpath.cmake
        CONTENT "file(RPATH_SET FILE \"$<TARGET_FILE_DIR:${PROJECT}>/openvpn\" NEW_RPATH \"$<TARGET_FILE_DIR:OpenSSL::SSL>\")\n"
    )
    add_custom_command(TARGET ${PROJECT} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/set_openvpn_rpath.cmake
    )
elseif(APPLE)
    # AVPN: апстрим захардкодил имя таргета AmneziaVPN-service в bracket-литерале — у нас демон
    # переименован (Tribe-service, строка 3); держим НАШЕ имя (§14 C.7: апстрим-дифф на наше имя).
    file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/set_openvpn_rpath.cmake CONTENT
[=[
set(ovpn "$<TARGET_FILE_DIR:Tribe-service>/openvpn")
set(dir "$<TARGET_FILE_DIR:OpenSSL::SSL>")
execute_process(COMMAND install_name_tool -delete_rpath "${dir}" "${ovpn}" ERROR_QUIET)
execute_process(COMMAND install_name_tool -add_rpath "${dir}" "${ovpn}")
]=]
    )
    add_custom_command(TARGET ${PROJECT} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/set_openvpn_rpath.cmake
    )
endif()

if(WIN32)
    # using PERMISSIONS on Windows appends read-only flag
    # to the files so just omit it for it
    install(FILES ${CONAN_EXECS}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT AmneziaVPN
    )
else()
    set(CONAN_EXECS_INSTALL ${CONAN_EXECS})
    if(LINUX)
        list(REMOVE_ITEM CONAN_EXECS_INSTALL "$<TARGET_FILE:openvpn::openvpn>")
    endif()
    install(FILES ${CONAN_EXECS_INSTALL}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT AmneziaVPN
        PERMISSIONS
            OWNER_READ OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
    )
endif()
install(FILES ${CONAN_BINS}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT AmneziaVPN
)

# install openvpn via the service's dep set to ship its openssl, then
# rewrite conan's absolute build rpath to a relative one for the package
if(LINUX)
    install(IMPORTED_RUNTIME_ARTIFACTS openvpn::openvpn
        RUNTIME_DEPENDENCY_SET service_deps
        PERMISSIONS
            OWNER_READ OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
        COMPONENT AmneziaVPN
    )
    install(CODE "
        set(_ovpn \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/openvpn\")
        file(CHMOD \"\${_ovpn}\" PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
        file(RPATH_SET FILE \"\${_ovpn}\" NEW_RPATH \"$ORIGIN:$ORIGIN/../lib\")
        file(CHMOD \"\${_ovpn}\" PERMISSIONS
            OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    "
        COMPONENT AmneziaVPN
    )
elseif(APPLE)
    install(CODE "
        set(_ovpn \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/openvpn\")
        execute_process(COMMAND install_name_tool -delete_rpath \"$<TARGET_FILE_DIR:OpenSSL::SSL>\" \"\${_ovpn}\" ERROR_QUIET)
        execute_process(COMMAND install_name_tool -add_rpath \"@executable_path/../Frameworks\" \"\${_ovpn}\")
    "
        COMPONENT AmneziaVPN
    )
endif()

# install drivers
if (WIN32)
    find_package(tap-windows6 REQUIRED)
    add_custom_command(TARGET ${PROJECT} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${TAP_WINDOWS6_BIN}"
            "$<TARGET_FILE_DIR:${PROJECT}>/tap"
    )
    install(DIRECTORY "${TAP_WINDOWS6_BIN}/"
        DESTINATION "${CMAKE_INSTALL_BINDIR}/tap"
        COMPONENT AmneziaVPN
    )

    find_package(win-split-tunnel REQUIRED)
    add_custom_command(TARGET ${PROJECT} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${WIN_SPLIT_TUNNEL_BIN}"
            "$<TARGET_FILE_DIR:${PROJECT}>"
    )
    install(DIRECTORY "${WIN_SPLIT_TUNNEL_BIN}/"
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT AmneziaVPN
    )
endif()

# install target
install(TARGETS ${PROJECT}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    RUNTIME_DEPENDENCY_SET service_deps
    COMPONENT AmneziaVPN
)

if(APPLE)
    set(RUNTIME_DEPS_DIR ${CMAKE_INSTALL_BINDIR}/../Frameworks)
else()
    set(RUNTIME_DEPS_DIR ${CMAKE_INSTALL_BINDIR})
endif()

install(RUNTIME_DEPENDENCY_SET service_deps
    PRE_EXCLUDE_REGEXES
        [[api-ms-win-.*]]
        [[ext-ms-.*]]
        [[kernel32\.dll]]
        [[hvsifiletrust\.dll]]
        [[libc\.so\..*]] [[libgcc_s\.so\..*]] [[libm\.so\..*]] [[libstdc\+\+\.so\..*]]
        [[.*\.framework]]
        [[^(lib)?[Qq]t.*]]
    POST_EXCLUDE_REGEXES
        # AVPN win-fix: только DLL непосредственно из system32\ (см. client/CMakeLists.txt) —
        # иначе conan-кеш SYSTEM-пользователя (C:\Windows\System32\config\systemprofile\.conan2)
        # молча выпадает из бандла (amnezia_xray/libssl терялись у сервиса).
        [[^.*[\\/][Ss]ystem32[\\/][^\\/]*\.dll$]]
        [[^/lib.*]]
        [[^/usr/lib.*]]
    DIRECTORIES ${CONAN_RUNTIME_LIB_DIRS}
    COMPONENT AmneziaVPN
    DESTINATION "${RUNTIME_DEPS_DIR}"
)

qt_generate_deploy_app_script(
    TARGET ${PROJECT}
    OUTPUT_SCRIPT QT_DEPLOY_SCRIPT
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${QT_DEPLOY_SCRIPT}
    COMPONENT AmneziaVPN
)
