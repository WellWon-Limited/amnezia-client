#!/usr/bin/env python3
"""Focused source-contract gates for AWG/Xray native platform integration.

These checks intentionally complement (not replace) target builds/device tests:
they pin security/lifecycle invariants that previously regressed through small
signal-name, session-token and string-replacement edits.
"""

from pathlib import Path
import json
import re


ROOT = Path(__file__).resolve().parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"platform runtime gate failed: {message}")


ipc = source("ipc/ipc_interface.rep")
process_ipc = source("ipc/ipc_process_interface.rep")
mac_client = source("client/core/protocols/xrayProtocol.cpp")
mac_service = source("service/server/xray.cpp")
mac_router = source("service/server/router_mac.cpp")
process_service = source("ipc/ipcserverprocess.cpp")
ipc_server = source("ipc/ipcserver.cpp")
local_server = source("service/server/localserver.cpp")
openvpn_config_security = source("ipc/openvpnconfigsecurity.cpp")
openvpn_dns_security = source("service/server/openvpndnssecurity.cpp")
openvpn_configurator = source("client/core/configurators/openVpnConfigurator.cpp")
openvpn_client = source("client/core/protocols/openVpnProtocol.cpp")
service_main = source("service/server/main.cpp")
daemon_ipc = source("client/daemon/daemonlocalserverconnection.cpp")
kill_switch = source("service/server/killswitch.cpp")
mac_firewall = source("client/platforms/macos/daemon/macosfirewall.cpp")
mac_pf_root = source("deploy/data/macos/pf/tribe.conf")
mac_pf_quarantine = source("deploy/data/macos/pf/tribe.999.quarantine.conf")
vpn_connection = source("client/vpnConnection.cpp")
ios_controller = source("client/platforms/ios/ios_controller.mm")
ios_xray = source("client/platforms/ios/PacketTunnelProvider+Xray.swift")
ios_wireguard = source("client/platforms/ios/PacketTunnelProvider+WireGuard.swift")
ios_hev = source("client/platforms/ios/HevSocksTunnel.swift")
ios_provider = source("client/platforms/ios/PacketTunnelProvider+NativeGuard.swift")
ios_guard = source("client/platforms/ios/TribeNativeSessionGuard.swift")
ios_callback_lifecycle = source("client/platforms/ios/XraySocketCallbackLifecycle.swift")
apple_recipe_patch = source("recipes/awg-apple/patches/0001-tribe-dnsfwd-warmup-rebind.patch")
apple_socket_patch = source("recipes/awg-apple/patches/0002-xray-socket-protection-result.patch")
apple_guarded_settings_patch = source(
    "recipes/awg-apple/patches/0003-guarded-network-settings-owner.patch"
)
xray_core_controller_patch = source(
    "recipes/amnezia-libxray/patches/0004-xray-core-controller-errors.patch"
)
apple_recipe = source("recipes/awg-apple/conanfile.py")
apple_conandata = source("recipes/awg-apple/conandata.yml")
ios_authority = source("client/platforms/ios/TribeRuntimeAuthorityLease.swift")
ios_vault = source("client/platforms/ios/TribeTunnelConfigVault.swift")
android_xray = source("client/android/xray/src/main/kotlin/Xray.kt")
android_xray_teardown = source(
    "client/android/xray/src/main/kotlin/XrayNativeTeardown.kt"
)
android_wireguard = source(
    "client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt"
)
android_protocol = source("client/android/protocolApi/src/main/kotlin/Protocol.kt")
android_engine_manifest = source(
    "client/android/protocolApi/src/main/kotlin/EngineManifest.kt"
)
android_session_guard = source("client/android/src/org/amnezia/vpn/AndroidSessionGuard.kt")
android_activity = source("client/android/src/org/amnezia/vpn/AmneziaActivity.kt")
android_service = source("client/android/src/org/amnezia/vpn/AmneziaVpnService.kt")
android_vpn_vault = source("client/android/src/org/amnezia/vpn/AndroidVpnConfigVault.kt")
android_catalog_vault = source("client/android/src/org/amnezia/vpn/CatalogSecureMetadataVault.kt")
android_guard_reconciliation = source(
    "client/android/src/org/amnezia/vpn/NativeGuardReconciliationJournal.kt"
)
android_manifest = source("client/android/AndroidManifest.xml")
android_controller = source("client/platforms/android/android_controller.cpp")
product_runtime = source("client/core/serviceEngine/CatalogProductRuntime.cpp")
apple_manifest = source("client/platforms/ios/TribeEngineManifest.swift.in")
runtime_receipts = source("cmake/platform_runtime_receipts.cmake")
platform_settings = source("cmake/platform_settings.cmake")
app_intents_cmake = source("client/ios/appintentsextension/CMakeLists.txt")
android_versions = source("client/android/gradle/libs.versions.toml")
android_settings = source("client/android/settings.gradle.kts")
android_wrapper = source("client/android/gradle/wrapper/gradle-wrapper.properties")
android_cmake = source("client/cmake/android.cmake")
ios_cmake = source("client/cmake/ios.cmake")
macos_cmake = source("client/cmake/macos.cmake")
macos_ne_cmake = source("client/cmake/macos_ne.cmake")
ios_ne_cmake = source("client/ios/networkextension/CMakeLists.txt")
ios_ne_info = source("client/ios/networkextension/Info.plist.in")
ios_build_manifest = source("client/ios/TribeBuildManifest.plist.in")
ios_release_checker = source("metadata/check_ios_release_artifact.py")
ios_appicon_checker = source("metadata/check_ios_appicon.py")
ios_export_options = source("deploy/data/ios/ExportOptions.plist")
apple_profile_action = source(".github/actions/apple-setup-provisioning-profile/action.yml")
apple_cert_action = source(".github/actions/apple-install-cert/action.yml")
macos_ne_target_cmake = source("client/macos/networkextension/CMakeLists.txt")
android_xray_gradle = source("client/android/xray/libXray/build.gradle.kts")
android_xray_recipe = source("recipes/amnezia-libxray/conanfile.py")
engine_lock = json.loads(source("metadata/engine-lock.json"))
android_16kb_checker = source("metadata/check_android_16kb_artifact.py")
client_project = source("client/CMakeLists.txt")
root_cmake = source("CMakeLists.txt")
tribe_version = source("tribe_version.cmake")
service_cmake = source("service/server/CMakeLists.txt")
openvpnadapter_recipe = source("recipes/openvpnadapter/conanfile.py")
deploy_workflow = source(".github/workflows/deploy.yml")
legacy_release_workflow = source(".github/workflows/tag-deploy.yml")
protocol_workflow = source(".github/workflows/tribe-protocol-gates.yml")
build_wrapper = source("deploy/build.sh")
release_gates = source("metadata/run_tribe_release_gates.sh")
release_version_gate = source("metadata/check_release_version.py")
catalog_release_facts = json.loads(
    source("metadata/catalog-release-request-facts.json")
)
ios_swift_host_tests = source(
    "client/platforms/ios/tests/run_swift_host_tests.sh"
)
macos_guard_host_tests = source(
    "client/platforms/macos/tests/run_macos_native_session_guard_tests.sh"
)
macos_dist = source("deploy/tribe/make-macos-dist.sh")
macos_bundle = source("deploy/tribe/bundle-daemon-qt.sh")
macos_installer = source("deploy/tribe/tribe-svc-install.sh")
macos_dev_installer = source("deploy/tribe/install-tribe-service.sh")
macos_payload = source("deploy/tribe/macos-service-payload.sh")
macos_payload_tests = source("metadata/tests/test_macos_service_payload.py")
macos_runtime = source("deploy/tribe/verify-macos-runtime.sh")
macos_sanitizer = source("deploy/tribe/sanitize-macos-app.sh")
macos_path_privacy = source("deploy/tribe/verify-macos-build-paths.sh")
macos_symbols = source("deploy/tribe/prepare-macos-symbols.sh")
macos_engine_artifact = source("metadata/check_macos_engine_artifact.py")
macos_engine_artifact_tests = source("metadata/tests/test_macos_engine_artifact.py")
macos_prepare = source("deploy/tribe/prepare-macos-service-payload.sh")
macos_pre_install = source("deploy/data/macos/pre_install.sh")
macos_post_install = source("deploy/data/macos/post_install.sh")
macos_uninstall = source("deploy/data/macos/post_uninstall.sh")
macos_migrator = source("deploy/tribe/migrate-macos-legacy-app.sh")
macos_launchctl_parser = source("deploy/tribe/launchctl-job-field.sh")
macos_component_plist = source("deploy/data/macos/TribeVPN-component.plist")
mac_service_installer = source("client/core/serviceEngine/MacServiceInstaller.mm")
avpn_engine_qml = source("client/core/serviceEngine/AvpnEngineQml.cpp")
subscription_request = source("client/core/serviceEngine/SubscriptionRequest.h")
enrollment = source("client/core/serviceEngine/Enrollment.cpp")
catalog_resolve = source("client/core/serviceEngine/CatalogResolve.h")
client_main = source("client/main.cpp")
account_qml = source("client/ui/qml/Tribe/Pages/PageAccountTribe.qml")
recipes_bootstrap = source("cmake/recipes_bootstrap.cmake")
client_cmake = source("client/CMakeLists.txt")
cpack = source("cmake/CPack.cmake")
cpack_sign = source("cmake/sign_binaries.cmake")
cpack_options = source("cmake/CPackOptions.cmake")
cpack_packages = source("cmake/sign_packages.cmake")
notarytool = source("cmake/util/notarytool.cmake")
awg_go_recipe = source("recipes/awg-go/conanfile.py")
xray_bindings_recipe = source("recipes/amnezia-xray-bindings/conanfile.py")
tun2socks_recipe = source("recipes/tun2socks/conanfile.py")
openvpn_recipe = source("recipes/openvpn/conanfile.py")
openssl_recipe = source("recipes/openssl/conanfile.py")
libssh_recipe = source("recipes/libssh/conanfile.py")

require("xrayStartSession(const QString &sessionId" in ipc,
        "desktop start must carry an opaque native session")
require("xrayStopSession(const QString &sessionId)" in ipc,
        "desktop stop must target the exact native session")
require("xrayRuntimeStatusV1(const QString &sessionId)" in ipc,
        "runtime status must not accept a caller-selected interface")
require("xrayRuntimeStatusV1(const QString &sessionId, const QString &tunName)" not in ipc,
        "caller-selected TUN counter source is forbidden")
require("QProcess::ProcessState state()" in process_ipc,
        "desktop teardown must prove the exact child process is not running")

for needle in ("O_NOFOLLOW", "st_nlink != 1", "openvpn_config_forbidden_directive",
               "setenv TRIBE_DNS_SESSION", "--tribe-openvpn-dns-hook-v1",
               "/Library/PrivilegedHelperTools/TribeVPN/Tribe-service"):
    require(needle in openvpn_config_security,
            f"root OpenVPN config boundary lost {needle}")
require("openvpn-config-XXXXXX.ovpn" in process_service
        and "snapshotMetadata.st_uid != 0" in process_service
        and "::fsync(snapshotFd)" in process_service
        and "randomCapability()" in process_service,
        "macOS root OpenVPN must execute an fsynced root snapshot with a fresh DNS owner token")
require("m_openVpnPrepared" in process_service
        and "m_startAttempted" in process_service
        and "Every privileged descriptor is one-shot" in process_service,
        "prepared privileged process descriptors must be immutable and one-shot")
require('privileged.append(" --tribe-openvpn-dns-hook-v1\\n")' in openvpn_config_security
        and 'privileged.append(" --tribe-openvpn-dns-hook-v1\\ndown ")'
            not in openvpn_config_security
        and "down-pre" not in openvpn_config_security,
        "OpenVPN root snapshot may inject only the up hook")
require("defined(MZ_MACOS) || defined(MZ_LINUX)" not in openvpn_configurator
        and "#if defined(MZ_LINUX)" in openvpn_configurator,
        "macOS must not inject a mutable app-bundle OpenVPN script")
for needle in ("/private/var/db/TribeVPN", "O_NOFOLLOW", "::flock",
               "PrimaryService", "SCDynamicStoreSetValue", "writeState(*state",
               "tribe_openvpn_dns_journal_v3", "preimage_plist",
               "JournalPhase::Prepared",
               "protectedServices", "readbackMatches", "recoverSession",
               "Setup:/Network/Service/.*", "restoreOwnedFields",
               "shouldRestoreOwnedField"):
    require(needle in openvpn_dns_security,
            f"native OpenVPN DNS transaction lost {needle}")
require(openvpn_dns_security.index("writeState(*state")
        < openvpn_dns_security.index("SCDynamicStoreSetValue(store, key, applied)"),
        "durable DNS recovery state must commit before changing macOS DNS")
require("SCDynamicStore has no compare-and-set primitive" in openvpn_dns_security
        and "readbackMatches(store, key, true, applied" in openvpn_dns_security,
        "DNS pre-write recheck/readback contract must not claim a false atomic CAS")
require(openvpn_dns_security.index('if (action == QLatin1String("down"))')
        < openvpn_dns_security.index("prepareStateDirectory(error)"),
        "validated OpenVPN down compatibility hook must be a state-free no-op")
require("openvpndnssecurity::recover" in service_main
        and "kHookArgument" in service_main
        and "kRecoveryArgument" in service_main,
        "Tribe-service must own OpenVPN DNS hook and crash recovery lifecycle")
require("openVpnDnsSession" in process_service
        and "restoreProcessDns" in ipc_server
        and "failClosedOpenVpnDns" in ipc_server
        and "allChildrenStopped" in ipc_server
        and "if (allChildrenStopped)" in ipc_server
        and "Tribe DNS shutdown recovery failed" not in service_main
        and "shutdownPrivilegedChildren" in local_server
        and "m_openVpnDnsMonitor.stop()" in local_server,
        "OpenVPN child death/GUI loss/shutdown must restore DNS only after every child is dead")
require("OpenVPN terminal DNS recovery failed" in ipc_server
        and ipc_server.index("restoreProcessDns(*descriptor")
            < ipc_server.index("QTimer::singleShot(0, this, [this, descriptorId]")
        and "Refusing PF release while privileged child is running" in ipc_server,
        "terminal DNS recovery must precede deferred descriptor deletion and PF release")
require("waitForFinished(5000)" in openvpn_client
        and "QProcess::NotRunning" in openvpn_client
        and "QThread::msleep(10)" not in openvpn_client,
        "OpenVPN client teardown must prove exact child death before PF release")
require("localServer.isReady()" in service_main
        and "m_ready = true" in local_server
        and "m_consoleUserWatchdog" in local_server
        and "Console user changed; restarting secure IPC" in local_server,
        "macOS daemon must exit failed startup and rebind across console-user changes")
require('anchor "999.quarantine"' in mac_pf_root
        and "block drop quick all" in mac_pf_quarantine
        and "isQuarantineEnabled" in mac_firewall
        and "flushAllStates" in mac_firewall
        and "MacOSFirewall::flushAllStates()" in kill_switch,
        "emergency PF quarantine must be terminal, exact-readback and state-flushing")
require("m_nativeSessionGuardOwned" in source("service/server/killswitch.h")
        and "quarantineNativeSessionGuard" in kill_switch
        and "if (m_nativeSessionGuardOwned)" in kill_switch
        and "quarantineNativeSessionGuard" in ipc_server
        and local_server.index("restoreNativeSessionGuardAfterDaemonStart")
            < local_server.index("KillSwitch::instance()->init()"),
        "durable macOS outer guard must survive inner cleanup and daemon restart")
require("openvpndnssecurity.cpp" in service_cmake
        and "build_openvpn_config_security.sh" in release_gates,
        "native OpenVPN/DNS security code must be built and adversarially gated")
require("bash client/platforms/ios/tests/run_swift_host_tests.sh" in release_gates
        and "Apple Swift host suites passed (8 executable + 2 provider typechecks)"
            in ios_swift_host_tests
        and ios_swift_host_tests.count("run_suite ") == 8
        and ios_swift_host_tests.count("typecheck_suite ") == 2
        and "-warnings-as-errors" in ios_swift_host_tests
        and "TribeRuntimeAuthorityRenewalTests.swift" in ios_swift_host_tests
        and "XraySocketCallbackLifecycleTests.swift" in ios_swift_host_tests
        and "XrayProviderTypecheckStubs.swift" in ios_swift_host_tests
        and "WireGuardProviderTypecheckStubs.swift" in ios_swift_host_tests,
        "Darwin release gate must run eight Swift suites and typecheck both live providers")
require("bash client/platforms/macos/tests/run_macos_native_session_guard_tests.sh"
            in release_gates
        and 'QT_VERSION" != "6.11.1"' in macos_guard_host_tests
        and "-Wall -Wextra -Werror" in macos_guard_host_tests
        and "MacosNativeSessionGuardTests.cpp" in macos_guard_host_tests,
        "Darwin release gate must compile/run the Qt 6.11.1 macOS native guard suite")
require(deploy_workflow.count("PYTHONDONTWRITEBYTECODE: '1'") == 4,
        "all Apple/Android shipping or compile jobs must keep Conan/Python out of the source tree")
for name, cmake_source in {
    "ios app": ios_cmake,
    "macos app": macos_cmake,
    "macos-ne app": macos_ne_cmake,
    "ios network extension": ios_ne_cmake,
    "macos network extension": macos_ne_target_cmake,
}.items():
    require("$<$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>:" in cmake_source,
            f"{name} must not pass C preprocessor definitions to Swift")

for swift_source in (
    "TribeRuntimeAuthorityRenewal.swift",
    "TribeRuntimeAuthorityWatchdog.swift",
    "TribeProtectedSplitPolicy.swift",
    "XraySocketCallbackLifecycle.swift",
):
    source_entry = f"${{CLIENT_ROOT_DIR}}/platforms/ios/{swift_source}"
    require(source_entry in ios_ne_cmake,
            f"iOS network extension target lost required {swift_source}")
    require(source_entry in macos_ne_target_cmake,
            f"macOS network extension target lost required {swift_source}")

require("QObject::disconnect(m_tunReadyConnection)" in mac_client,
        "tun2socks readiness callback must disconnect its exact stderr connection")
require("readyReadStandardOutput, this, nullptr" not in mac_client,
        "old wrong-signal disconnect regression returned")
require("const QWeakPointer<IpcProcessInterfaceReplica> weakProcess" in mac_client,
        "process callbacks must use immutable attempt identity")
require("sessionId == m_runtimeSessionId" in mac_client,
        "queued desktop callbacks must reject stale sessions")
require("value.isString()" in mac_client and "QString::number(parsed) != text" in mac_client,
        "desktop canonical uint64 parser must reject JSON doubles/noncanonical strings")
require(mac_client.index("cleanupRouting()")
        < mac_client.index("emit runtimeStatusChanged(terminalStatus)"),
        "desktop stopped receipt must be published only after local cleanup")
require("qobject_cast<XrayProtocol *>" in vpn_connection
        and "&XrayProtocol::runtimeStatusChanged" in vpn_connection,
        "production desktop Xray status must reach the GUI/reducer bridge")
require("nativeRuntimeIdentitySupported(Proto proto)" in vpn_connection,
        "runtime identity support must be protocol-specific")
require("requestDesktopEngineManifest" in vpn_connection
        and '"engine_manifest_v1"' in vpn_connection
        and "performClientHandshake" in vpn_connection,
        "desktop pre-connect manifest must use authenticated daemon IPC")

require("preflightSocketProtection" in mac_service,
        "macOS core cannot become ready without socket-scope preflight")
require("getsockname" in mac_service and "socket_protection_failed" in mac_service,
        "actual Xray socket bind failures must poison the active session")
require("details redacted" in mac_service and "QString::fromUtf8(str)" not in mac_service,
        "Xray core errors/log callbacks must not expose bearer configuration")
require("routeAddXray(m_uplinkIfaceName" in mac_service,
        "macOS escape route transaction is required")
require("if (!invokeRouteCommand" in mac_router and "roll back partial Xray route" in mac_router,
        "two-route install must be checked and rolled back")
require("<< m_process->arguments();" not in process_service,
        "privileged process logs must not print SOCKS credentials")

require("readinessGate" not in ios_hev,
        "idle iOS startup must not wait for first outbound socket/user packet")
require("throw XrayErrors.missingSocksInbound" in ios_xray,
        "iOS must fail when credentials cannot be injected into a SOCKS inbound")
require("os_tunnel_disconnected" in ios_controller
        and "emit runtimeStatusChanged(terminal)" in ios_controller,
        "definitive NE disconnect must publish the pinned typed terminal")
require("min(max(connectTimeoutMs" in ios_xray
        and "min(max(readWriteTimeoutMs" in ios_xray,
        "server-provided HEV timeouts must be bounded")
for path_name, implementation in (
    ("outer guard", ios_provider), ("AWG inner", ios_wireguard), ("Xray inner", ios_xray),
):
    require("TribeProtectedSplitPolicy.validateMode2" in implementation,
            f"iOS guarded mode-2 exclusions lost the shared protected-IP proof in {path_name}")
require("excludeIPs = excludeIPs" in ios_wireguard
        and "excludedRoutes = ipv4" in ios_xray
        and "v4.excludedRoutes" in ios_provider,
        "iOS guarded mode-2 exclusions must be applied by the outer guard and both inner paths")

# Upstream xray-core stores RegisterDialerController callbacks in an append-only slice. The recipe
# patch must install one controller, hold a read lock throughout the C callback, and make clear use
# the exclusive lock so its return is a native drain receipt before Swift releases the raw context.
for needle in (
    "+\txraySockCallbackOnce            sync.Once",
    "+\t\t\t\txraySockCallbackMu.RLock()",
    "+\t\t\t\tdefer xraySockCallbackMu.RUnlock()",
    "+\txraySockCallbackMu.Lock()",
    "+\txraySockCallback = cb",
    "+\txraySockCallbackContext = ctx",
    "+\tif (cb == nil) != (ctx == nil)",
):
    require(needle in apple_recipe_patch,
            f"Apple Xray singleton/replace/drain recipe contract lost {needle!r}")
for needle in (
    "TestTribeXraySockCallbackSlotSingleton",
    "TestTribeXraySockCallbackSlotDrain",
    "before=%d after=%d",
    "clear returned while an invocation still held the callback read lock",
):
    require(needle in apple_recipe_patch,
            f"Apple Xray actual Go callback-slot test lost {needle!r}")
require("go test -tags tribe_callback_test -count=1 " in apple_recipe
        and "-run '^TestTribeXraySockCallbackSlot' " in apple_recipe
        and "api-xray.go api-xray_testhelper.go api-xray_callback_test.go"
            in apple_recipe,
        "awg-apple package build must execute the focused Go singleton/drain test")
for needle in (
    "typedef int32_t (*libxray_sockcallback)",
    "protected := false",
    "errXraySockCallbackRejected",
    "tribe_test_rejecting_sockcallback",
    "protect=false callback was not rejected",
):
    require(needle in apple_socket_patch,
            f"Apple Xray socket-protection result patch lost {needle!r}")
for needle in (
    "applyExternalControllers",
    "TestTribeExternalControllerErrorsArePropagated",
    "return err",
):
    require(needle in xray_core_controller_patch,
            f"vendored Xray core fail-closed controller patch lost {needle!r}")
require('prep_env.define("GOFLAGS", "")' in apple_recipe
        and 'vendor_env.define("GOFLAGS", "-mod=vendor -trimpath -buildvcs=false")'
            in apple_recipe
        and apple_recipe.index("with vendor_env.vars(self).apply():")
            < apple_recipe.index("TestTribeExternalControllerErrorsArePropagated")
            < apple_recipe.index("TestTribeXraySockCallbackSlot")
            < apple_recipe.index("autotools.make()"),
        "Apple Xray tests and final archive must force the patched vendored core")
require("0003-guarded-network-settings-owner.patch" in apple_conandata,
        "awg-apple package must apply the guarded NetworkExtension settings-owner patch")
for needle in (
    "public final class WireGuardGuardPreparation",
    "public static func prepareGuardedTunnel",
    "private let managesNetworkSettings: Bool",
    "private let guardPreparation: WireGuardGuardPreparation?",
    "guard self.guardPreparation == nil else",
    "Network settings (resume): owned by outer guard",
):
    require(needle in apple_guarded_settings_patch,
            f"Apple guarded AWG settings-owner patch lost {needle!r}")
require(apple_guarded_settings_patch.count("if self.managesNetworkSettings") >= 3
        and "+                fatalError()" not in apple_guarded_settings_patch,
        "guarded AWG start/update/resume must preserve outer settings ownership without traps")
require(apple_guarded_settings_patch.count(
            "Self.reresolveEndpoint(endpoint: endpoint)") == 2
        and "Self.reresolveEndpoint(endpoint)" not in apple_guarded_settings_patch,
        "guarded AWG frozen-endpoint patch must retain Swift's required endpoint label")
require("prepareGuardedWireguard" in ios_wireguard
        and "WireGuardAdapter.prepareGuardedTunnel" in ios_wireguard
        and "guardPreparation: prepared.wireGuardPreparation" in ios_provider,
        "iOS PREPARE/ACTIVATE must pass one frozen AWG endpoint/settings object")
require("fatalError" not in ios_wireguard
        and "fatalError" not in ios_xray
        and "fatalError" not in ios_provider,
        "guarded iOS AWG/Xray provider paths must return typed failures, never trap")
require("guard let result else { return true }" in ios_callback_lifecycle
        and "defer { free(result) }" in ios_callback_lifecycle
        and "return result.pointee == 0" in ios_callback_lifecycle,
        "Apple Xray C-result consumer must accept nil/allocated-empty success and free non-nil")
for call in ("LibXraySetSockCallback(cb, ctx)",
             "LibXrayRunXray(nil, configURL.path, memoryLimit)",
             "LibXrayStopXray()", "LibXraySetSockCallback(nil, nil)"):
    require(re.search(
                r"XrayNativeCStringResult\.consume\(\s*" + re.escape(call), ios_xray
            ) is not None,
            f"iOS Xray native result is not consumed safely: {call}")
require(ios_xray.count("xrayNativeLifecycleGate.withExclusive") >= 3
        and "Socks5Tunnel.start(" in ios_xray,
        "one native lifecycle gate must serialize Xray Set/Run, tun2socks start and teardown")
teardown_start = ios_callback_lifecycle.index("static func execute(stopCore:")
teardown_end = ios_callback_lifecycle.index("enum XraySocketFailureContainmentAction", teardown_start)
teardown_body = ios_callback_lifecycle[teardown_start:teardown_end]
require(teardown_body.index("guard stopCore()")
        < teardown_body.index("let drained = drain()")
        < teardown_body.index("return retireContext()"),
        "iOS Xray teardown must prove Stop, drain the callback slot, then retire context")
require("xraySocketCallbackRegistry" in ios_xray
        and "drainStopAndRetireXrayCallback" in ios_xray
        and "LibXraySetSockCallback(nil, nil)" in ios_xray
        and "maximumXrayCallbackContexts" not in ios_xray
        and "maximumXrayCallbackContexts" not in source(
            "client/platforms/ios/PacketTunnelProvider.swift"),
        "iOS Xray callback contexts must drain then remove, without a lifetime session cap")
require("identity.generation == currentGeneration" in ios_callback_lifecycle
        and "identity.sessionId == currentSessionId" in ios_callback_lifecycle,
        "late Xray callbacks must be fenced by exact generation and runtime session")
quarantine_body = ios_xray[ios_xray.index(
    "private func quarantineGuardedXraySocketFailure"):]
require("cancelTunnelWithError" not in quarantine_body
        and "setTunnelNetworkSettings(nil)" not in quarantine_body
        and 'lostEvent(reason: "socket_protection_failed")' in quarantine_body,
        "guarded Xray bind failure must quarantine without cancelling/releasing the outer NE")
require("case .cancelLegacyProvider:" in ios_xray
        and "cancelTunnelWithError(XrayErrors.socketProtectionUnavailable)" in ios_xray,
        "legacy Xray bind failure no-regression cancellation path is missing")
for action in ("kActionNativeGuardPrepare", "kActionNativeSessionActivate",
               "kActionNativeSessionStop", "kActionNativeGuardRelease",
               "kActionNativeGuardRecoveryResolve"):
    require(action in ios_provider, f"iOS same-NE bridge missing {action}")
require("setTunnelNetworkSettings(nil)" in ios_provider
        and "proveRecoveryStopped" in ios_guard,
        "iOS recovery may release routes only after exact inner teardown")
require("reconcileRecovery" in ios_authority and "installAuthorityWatchdog" in ios_provider,
        "iOS running provider must retain and enforce runtime authority")
for api in ("requestSessionGuardArm", "activateNativeSession", "stopNativeSession",
            "requestSessionGuardRelease", "requestSessionGuardRecoveryResolution"):
    require(f"IosController::{api}" in ios_controller,
            f"iOS app bridge missing {api}")
require("m_guardRecoveryEvent = event" in ios_controller
        and "nativeSessionGuardRecoveryPending" in vpn_connection
        and "nativeSessionGuardRecoveryResolved" in vpn_connection,
        "iOS relaunch ownership must be level-triggered and explicitly resolved")
require("m_guardRecoveryUnresolved = false" in ios_controller
        and "stopped_released" in ios_controller and "adopted" in ios_controller,
        "iOS recovery latch must clear only on a terminal strict receipt")
require('@"wireguard":' not in ios_controller and '@"xray":' not in ios_controller
        and 'provider.keys.count == 5' in source("client/platforms/ios/PacketTunnelProvider.swift")
        and "rename(source.path, claim.path) == 0" in ios_vault,
        "iOS AWG/Xray providerConfiguration must carry only an atomically claimed vault reference")
require("keyBegin()" not in ios_controller and "keyEnd()" not in ios_controller,
        "Apple controller must compile on Qt versions without QJson key iterators")
require("xrayConfigString.replace(hostName" not in android_xray,
        "Android must never globally replace endpoint host/SNI in bearer JSON")
for method in ("prepareNativeSessionGuard", "activateNativeSession",
               "stopNativeSession", "releaseNativeSessionGuard"):
    require(f"fun {method}(" in android_activity,
            f"Android Activity JNI bridge missing {method}")
require("ServiceEvent.NATIVE_SESSION_GUARD" in android_activity,
        "Android guard receipts must reach JNI independently of notifications")
for action in ("PREPARE_NATIVE_SESSION_GUARD", "ACTIVATE_NATIVE_SESSION",
               "STOP_NATIVE_SESSION", "RELEASE_NATIVE_SESSION_GUARD"):
    require(f"Action.{action}" in android_service,
            f"Android service state machine missing {action}")
require("sessionId == controller->m_expectedCatalogRuntimeSessionId" in android_controller,
        "Android v2 runtime identity must byte-match the reducer-issued UUID")
require("publishGuardChannelLoss" in android_controller
        and "service_channel_lost" in android_controller,
        "Android Binder loss must emit an exact fail-closed guard terminal")
require("QSet<QString>(eventKeys.cbegin(), eventKeys.cend()) == exactKeys" in android_controller,
        "Android JNI guard event parser must enforce a closed schema")
require("keyBegin()" not in android_controller and "keyEnd()" not in android_controller,
        "Android controller must compile on Qt versions without QJson key iterators")
for vault_name, vault in (("VPN profile", android_vpn_vault),
                          ("catalog metadata", android_catalog_vault)):
    require("ANDROID_ID" not in vault and "Settings.Secure" not in vault
            and "contentResolver" not in vault,
            f"Android {vault_name} vault must not collect a hardware identifier")
require('return listOf(\n            AAD_DOMAIN,\n            packageName,\n            purpose,\n            recordId,'
        in android_vpn_vault,
        "Android VPN profile AAD lost domain/package/record binding")
require('return listOf(AAD_DOMAIN, packageName, RECORD_NAME)' in android_catalog_vault,
        "Android catalog AAD lost domain/package/record binding")
require('<action android:name="android.intent.action.OPEN_DOCUMENT" />' in android_manifest
        and "android.permission.QUERY_ALL_PACKAGES" not in android_manifest,
        "Android SAF visibility must stay action-scoped and never query all packages")
require('@SuppressLint("ApplySharedPref", "UseKtx")' in android_service
        and 'Prefs.prefs.edit().remove("LAST_CONF").commit()' in android_service,
        "legacy plaintext preference removal must remain explicitly synchronous")

# The service must not expose a successful native start before the exact running
# receipt is durable, and an ambiguous stop must retain exact ownership in quarantine.
activate_start = android_service.index("private suspend fun executeActivateNativeSession")
activate_end = android_service.index("private fun stopNativeSession", activate_start)
activate_body = android_service[activate_start:activate_end]
activate_receipt = activate_body.index("require(receipt.exactSessionToken == innerToken)")
activate_persist = activate_body.index('persistCatalogGuardLease(lease, "running")')
activate_ready = activate_body.index("sessionGuard.markInnerReady(")
activate_watchdog = activate_body.index("launchAuthorityWatchdog(lease.serviceSessionId)")
require(activate_receipt < activate_persist < activate_ready < activate_watchdog
        and "protocol.abortInnerStart(innerToken)" in activate_body,
        "Android activate must persist exact running before readiness/watchdog and retain abort")

stop_start = android_service.index("private suspend fun executeStopNativeSession")
stop_end = android_service.index("private fun releaseNativeSessionGuard", stop_start)
stop_body = android_service[stop_start:stop_end]
begin_stop = stop_body.index("sessionGuard.beginInnerStop(outer, token)")
stop_call = stop_body.index("lease.protocol.stopInner(token)", begin_stop)
quarantine_stop = stop_body.index("sessionGuard.quarantineStoppingInner(outer, token)", stop_call)
persist_quarantine = stop_body.index(
    'persistCatalogGuardLease(lease, "quarantined")', quarantine_stop,
)
require(begin_stop < stop_call < quarantine_stop < persist_quarantine
        and "current.state == \"stopping\"" in android_session_guard
        and "current.activeInnerToken == exactInnerToken" in android_session_guard,
        "Android thrown stop must quarantine/persist only the exact stopping token")

# Detached-TUN ownership transfers to Protocol.startWithTun at call entry. The
# service must never close after a throw: native teardown may already have closed
# and the integer may have been reused by an unrelated descriptor.
duplicate_start = android_service.index("private fun startWithDuplicatedTun")
duplicate_end = android_service.index("private suspend fun startSessionOwnedProtocol", duplicate_start)
duplicate_body = android_service[duplicate_start:duplicate_end]
require("ParcelFileDescriptor.adoptFd" not in duplicate_body
        and "ParcelFileDescriptor.dup(owner.fileDescriptor).use" in duplicate_body
        and "val protectCallback: (Int) -> Boolean = ::protect" in duplicate_body
        and re.search(
            r"protocol\.startWithTun\(\s*prepared, duplicate\.detachFd\(\), "
            r"exactSessionToken, protectCallback,",
            duplicate_body,
        ) is not None
        and "Ownership of [tunFd] transfers to the protocol at call entry" in android_protocol,
        "Android service/protocol detached-TUN ownership contract drift")
destroy_start = android_service.index("override fun onDestroy()")
destroy_end = android_service.index("private fun stopService", destroy_start)
destroy_body = android_service[destroy_start:destroy_end]
require(destroy_body.index("nativeGuardCommands.close()")
        < destroy_body.index(
            'boundedCatalogGuardTeardownForProcessLoss(lease, "service_destroyed")')
        < destroy_body.index("connectionScope.cancel()")
        and "stopNativeSession(" not in destroy_body
        and 'terminateVpnProcessFailClosed("service_destroyed")' in destroy_body
        and 'terminateVpnProcessFailClosed("service_destroyed_legacy_guard")'
            in destroy_body,
        "Android Service destruction must prove queued catalog stop before scope cancellation")
revoke_start = android_service.index("override fun onRevoke()")
revoke_body = android_service[revoke_start:destroy_start]
require("runCatching { lease.protocol.stopInner" not in revoke_body
        and 'boundedCatalogGuardTeardownForProcessLoss(lease, "vpn_permission_revoked")'
            in revoke_body
        and 'terminateVpnProcessFailClosed("vpn_permission_revoked")' in revoke_body
        and 'terminateVpnProcessFailClosed("vpn_permission_revoked_legacy_guard")'
            in revoke_body
        and revoke_body.index("nativeGuardCommands.close()")
            < revoke_body.index(
                'boundedCatalogGuardTeardownForProcessLoss(lease, "vpn_permission_revoked")')
        and revoke_body.index("publishNativeGuardEvent(")
            < revoke_body.index("stopSelf()")
        and "android.os.Process.killProcess(android.os.Process.myPid())" in android_service,
        "Android revoke must not release a catalog lease after an ambiguous inner stop")
process_loss_start = android_service.index(
    "private fun boundedCatalogGuardTeardownForProcessLoss")
process_loss_end = android_service.index(
    "private fun terminateVpnProcessFailClosed", process_loss_start)
process_loss_body = android_service[process_loss_start:process_loss_end]
require(process_loss_body.index("nativeGuardCommandJob?.cancelAndJoin()")
        < process_loss_body.index("protocolOperationMutex.withLock")
        < process_loss_body.index("proveCatalogInnerStoppedForProcessLoss")
        < process_loss_body.index('persistCatalogGuardLease(exactLease, "blackhole")')
        < process_loss_body.index("masterTun?.close()")
        and 'persistCatalogGuardLease(exactLease, "quarantined")' in process_loss_body
        and "retainCatalogGuardAmbiguity" in process_loss_body,
        "Android process-loss stop must be exact, durable and fail-closed")
require("durableGuardBootstrap.await()" in android_service
        and android_service.index("durableGuardBootstrap.await()")
            < android_service.index("for (command in nativeGuardCommands)")
        and android_service.index("executeRestoreNativeSessionGuard(recovery)")
            < android_service.index("durableGuardBootstrap.complete(Unit)")
        and "val releaseAlreadyCommitted" in android_service
        and android_service.index("val releaseAlreadyCommitted")
            < android_service.index(
                "executeRestoreNativeSessionGuard(recovery)",
                android_service.index("val releaseAlreadyCommitted"),
            ),
        "Android guard commands must wait for one-shot durable recovery/journal bootstrap")
require("Outcome.ARM_REJECTED" in android_guard_reconciliation
        and "Outcome.RELEASED" in android_guard_reconciliation
        and "MAX_RECORDS = 16" in android_guard_reconciliation
        and "storeGuardReconciliationJournal" in android_vpn_vault
        and "loadGuardReconciliationJournal" in android_vpn_vault,
        "Android timeout reconciliation requires a bounded encrypted exact tombstone ledger")
prepare_reconcile_start = android_service.index(
    "private suspend fun executeReconcileNativeSessionGuardArm")
prepare_reconcile_end = android_service.index(
    "private fun reconcileNativeSessionGuardRelease", prepare_reconcile_start)
prepare_reconcile = android_service[prepare_reconcile_start:prepare_reconcile_end]
require("if (!exactGuardLease(lease, identity, policy, outer)) return" in prepare_reconcile
        and prepare_reconcile.index("rememberArmRejected")
            < prepare_reconcile.index("persistGuardReconciliationJournal()")
            < prepare_reconcile.rindex("publishNativeGuardEvent("),
        "Android arm timeout must seal exact rejection before its terminal receipt")
release_reconcile_start = android_service.index(
    "private suspend fun executeReconcileNativeSessionGuardRelease")
release_reconcile_end = android_service.index(
    "private fun exactGuardLease", release_reconcile_start)
release_reconcile = android_service[release_reconcile_start:release_reconcile_end]
require("if (!exactGuardLease(lease, identity, policy, outer)) return" in release_reconcile
        and 'identity, "release_rejected", policy, outer' in release_reconcile
        and "NativeGuardReconciliationJournal.Outcome.RELEASED" in release_reconcile
        and "clearCatalogGuardLease" not in release_reconcile,
        "Android release timeout must retain exact owners and accept only a durable Released proof")
release_start = android_service.index(
    "private suspend fun executeReleaseNativeSessionGuard")
release_end = android_service.index(
    "private fun reconcileNativeSessionGuardArm", release_start)
release_body = android_service[release_start:release_end]
require(release_body.index('persistCatalogGuardLease(lease, "releasing")')
        < release_body.index("tun.close()")
        < release_body.index("sessionGuard.disarm")
        < release_body.index("guardReconciliationJournal.rememberReleased")
        < release_body.index("persistGuardReconciliationJournal()")
        < release_body.index("clearCatalogGuardLease(lease)")
        < release_body.index("publishNativeGuardEvent(")
        and 'terminateVpnProcessFailClosed("guard_release_commit_ambiguous")'
            in release_body
        and '"releasing"' in android_vpn_vault,
        "Android RELEASE must durably tombstone the exact identity before clearing/publishing")
require("requestSessionGuardReconcileArm" in android_controller
        and "requestSessionGuardReconcileRelease" in android_controller
        and "m_pendingGuardReleaseRequest.isEmpty()" in android_controller
        and "if (!pendingLoss && !armedLoss) return" in android_controller
        and "A syntactically valid stale/mismatched receipt" in android_controller,
        "Android Qt bridge must retain timeout identity until an exact receipt")
require(re.search(
            r'<service\s+android:name="\.TribeVpnService"\s+'
            r'android:process=":tribeVpnService"',
            android_manifest,
        ) is not None,
        "fail-closed native termination requires TribeVpnService's dedicated process")
require("val ownedTun = ParcelFileDescriptor.adoptFd(tunFd)" in android_wireguard
        and android_wireguard.index("config.toWgUserspaceString()")
            < android_wireguard.index("val tunFd = ownedTun.detachFd()")
            < android_wireguard.index("GoBackend.awgPrepareProtected(")
        and re.search(
            r"val tunFd = ownedTun\.detachFd\(\)\s+"
            r"tunnelHandle = GoBackend\.awgPrepareProtected\(",
            android_wireguard,
        ) is not None,
        "AWG must own pre-JNI failures and detach only at its exact native boundary")
require("val ownedTun = ParcelFileDescriptor.adoptFd(tunFd)" in android_xray
        and "tunFdTransferred" not in android_xray
        and re.search(
            r"val transferredFd = ownedTun\.detachFd\(\)\s+"
            r"LibXray\.startTun2Socks\(",
            android_xray,
        ) is not None,
        "Xray must own pre-JNI failures and detach only at its exact gomobile boundary")
xray_stop_start = android_xray.index("private fun stopNative()")
xray_stop_end = android_xray.index("private fun stopAdapterForStartRollback", xray_stop_start)
xray_stop_body = android_xray[xray_stop_start:xray_stop_end]
require("val receipt = XrayNativeTeardown.execute(" in xray_stop_body
        and xray_stop_body.index(
            "clearControllers = { LibXray.clearSocketControllers() }")
            < xray_stop_body.index("stopAdapter = { LibXray.stopTun2Socks() }")
            < xray_stop_body.index("stopCore = { LibXray.stopXray() }")
            < xray_stop_body.index("if (!receipt.proven)")
        and android_xray_teardown.count("executeLeg(") == 4
        and "catch (_: Throwable)" in android_xray_teardown
        and "controllers.proven && adapter.proven && core.proven" in android_xray_teardown,
        "Android Xray stop must attempt and aggregate all three exact native teardown legs")

xray_abi = engine_lock["engines"]["amnezia-libxray"]["abi"]
require(f'abi = "{xray_abi}"' in android_engine_manifest
        and f'"AMNEZIA_LIBXRAY_ABI": "{xray_abi}"' in android_xray_recipe
        and android_controller.count(f'QLatin1String("{xray_abi}")') == 2,
        "Android Xray lock/Kotlin/recipe/both Qt ABI allowlists drifted")
obsolete_xray_abi = "gomobile-libxray-" + "v1"
require(obsolete_xray_abi not in android_engine_manifest
        and obsolete_xray_abi not in android_xray_recipe
        and obsolete_xray_abi not in android_controller,
        "obsolete Android Xray v1 ABI remains in shipping runtime source")

guarded_settings_owner = "tribe.guarded_settings_owner"
require(all(
            guarded_settings_owner in engine_lock["engines"][name]["capabilities"]
            for name in ("awg-android", "amnezia-libxray")
        )
        and android_engine_manifest.count(f'"{guarded_settings_owner}"') == 2
        and android_controller.count(
            f'caps.contains(QStringLiteral("{guarded_settings_owner}"))') == 2,
        "both Android adapters and Qt allowlists must bind settings ownership to the outer guard")
require(f'contains(QStringLiteral("{guarded_settings_owner}"))' in catalog_resolve
        and "runtime adapter is missing guarded settings ownership" in catalog_resolve,
        "catalog v2 resolve must reject any inventory without outer-guard settings ownership")
require("QString productArchitecture(QString &error)" in product_runtime
        and "QSysInfo::currentCpuArchitecture().toLower()" in product_runtime
        and 'architecture == QLatin1String("arm64")' in product_runtime
        and 'architecture == QLatin1String("arm")' in product_runtime
        and 'architecture == QLatin1String("x86")' in product_runtime
        and 'architecture == QLatin1String("x86_64")' in product_runtime
        and 'app.arch = productArchitecture(error);' in product_runtime
        and "arm64-v8a" not in product_runtime
        and "armeabi-v7a" not in product_runtime,
        "catalog request architecture must use the closed Qt CPU namespace")
require("validate_catalog_release_facts(" in release_version_gate
        and "catalog-release-request-facts.json" in release_version_gate
        and catalog_release_facts == {
            "marketing_version": "5.1.68",
            "release_version": "5.1.68.97",
            "schema": 1,
            "shipping_flavors": [
                {"adapter": "apple_network_extension", "app_builds": [97],
                 "architectures": ["arm64"], "platform": "ios"},
                {"adapter": "android_vpn_service", "app_builds": [2158, 2159],
                 "architectures": ["arm64", "arm", "x86", "x86_64"],
                 "platform": "android"},
                {"adapter": "macos_daemon_ipc", "app_builds": [97],
                 "architectures": ["arm64"], "platform": "macos"},
            ],
        },
        "release source and catalog request fact artifact drifted")

macos_lock_start = product_runtime.rfind("#elif defined(Q_OS_MACOS)")
macos_lock_end = product_runtime.find("#else", macos_lock_start)
require(all(
            guarded_settings_owner in engine_lock["engines"][name]["capabilities"]
            for name in ("awg-go", "amnezia-xray-bindings")
        )
        and macos_lock_start >= 0 and macos_lock_end > macos_lock_start
        and product_runtime[macos_lock_start:macos_lock_end].count(
            f'QStringLiteral("{guarded_settings_owner}")') == 2
        and daemon_ipc.count(f'"{guarded_settings_owner}"') == 2
        and service_main.count(f'QStringLiteral("{guarded_settings_owner}")') == 2,
        "macOS lock, runtime IPC and side-effect-free artifact manifest capability drifted")

require('"sourceCommit": "@AWG_APPLE_XRAY_SOURCE_COMMIT@"' in apple_manifest,
        "Apple Xray manifest must carry the immutable source commit")
require('"abi": "@AWG_APPLE_XRAY_SOCKET_ABI@"' in apple_manifest,
        "Apple Xray signed runtime manifest must carry the exact patched callback ABI")
require('#include "SubscriptionRequest.h"' in avpn_engine_qml
        and '#include "SubscriptionRequest.h"' in enrollment
        and avpn_engine_qml.count("versionedSubscriptionUrl(") == 2
        and enrollment.count("versionedSubscriptionUrl(") == 1,
        "every synchronous/asynchronous subscription request must use the shared versioned URL")
require('QStringLiteral("^[0-9]+(?:\\\\.[0-9]+){2,3}$")' in subscription_request
        and "applicationVersion.size() > 32" in subscription_request
        and 'query.addQueryItem(QStringLiteral("app_version"), applicationVersion)'
            in subscription_request
        and "return {};" in subscription_request,
        "subscription helper must fail closed on anything outside backend N.N.N[.N] grammar")
require("QCoreApplication::setApplicationVersion(QStringLiteral(APP_VERSION))" in client_main
        and "QCoreApplication::applicationVersion()" in avpn_engine_qml
        and "QStringLiteral(APP_VERSION)" in enrollment,
        "packaged APP_VERSION must feed both async and pre-application subscription cohorts")
require("TRIBE_IOS_AWG_GUARD_RECEIPT == 1" in vpn_connection
        and "TRIBE_ANDROID_XRAY_GUARD_RECEIPT == 1" in vpn_connection,
        "guard support must be driven by generated release receipts")
require('_tribe_import_guard_receipt("platforms;macos_ne' not in runtime_receipts,
        "the unsupported macOS Network Extension flavor must not be receipt-enabled")
require('_tribe_import_guard_receipt("platforms;macos_daemon;awg"' in runtime_receipts
        and '_tribe_import_guard_receipt("platforms;macos_daemon;xray"' in runtime_receipts,
        "the normal macOS daemon guard must require per-transport release receipts")

require("SOURCE_ENTRIES = frozenset" in ios_appicon_checker
        and "ios-marketing" in ios_appicon_checker
        and "contains alpha/transparency" in ios_appicon_checker
        and '"/usr/bin/assetutil", "--info"' in ios_appicon_checker
        and '"/usr/bin/xcrun", "actool"' in ios_appicon_checker,
        "iOS AppIcon gate must close source PNGs and inspect compiled marketing renditions")
require("metadata/check_ios_appicon.py" in release_gates
        and "metadata/check_ios_appicon.py --compile-source" in release_gates,
        "source/release gates must validate and compile the iOS AppIcon catalog")
require('"--assets-car", str(assets)' in ios_release_checker
        and '"assets_car_sha256": assets_car_sha256' in ios_release_checker
        and 'info.get("CFBundleIconName") == "AppIcon"' in ios_release_checker,
        "signed iOS artifact gate must inspect exact Info.plist and Assets.car icon closure")

# Official Qt 6.11.1 binary slices require iOS 17 and macOS 13.  Lower project targets can
# still link while producing an artifact that crashes or refuses to load on the advertised OS.
require('set(CMAKE_OSX_DEPLOYMENT_TARGET "17.0" CACHE STRING "" FORCE)'
        in platform_settings,
        "iOS deployment target must match the official Qt 6.11.1 minimum")
require(platform_settings.count(
        'set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "" FORCE)') >= 2,
        "both macOS NE and daemon targets must match the official Qt 6.11.1 minimum")
require("DEFINED CMAKE_CONFIGURATION_TYPES" in platform_settings
        and "set(CONAN_INSTALL_BUILD_CONFIGURATIONS ${CMAKE_CONFIGURATION_TYPES})"
            in platform_settings
        and "Release Debug MinSizeRel RelWithDebInfo" in platform_settings,
        "Apple multi-config builds must honor an explicit configuration while preserving "
        "the default Conan configuration matrix")
require('if [[ "$CMAKE_GENERATOR" == "Xcode" ]]' in build_wrapper
        and ': ${CMAKE_CONFIGURATION_TYPES:="$CMAKE_BUILD_TYPE"}' in build_wrapper
        and '-DCMAKE_CONFIGURATION_TYPES=$CMAKE_CONFIGURATION_TYPES' in build_wrapper,
        "the Apple build wrapper must request only the intended Xcode configuration")
require('XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "17.0"' in app_intents_cmake,
        "App Intents extension deployment target must match the containing iOS app")

# Store/release automation must use the exact toolchain that produced the local target
# build evidence. Keep the native Android minimum matrix while compiling/targeting API 36.
require(deploy_workflow.count("QT_VERSION: 6.11.1") >= 3,
        "iOS, macOS daemon and macOS NE compile jobs must use Qt 6.11.1")
require("bash deploy/build.sh -t ios" in deploy_workflow
        and re.search(r"(?m)^\s*sh deploy/build\.sh -t ios", deploy_workflow) is None,
        "iOS release CI must honor deploy/build.sh's bash interpreter")
_ios_build_pipeline = deploy_workflow.split("bash deploy/build.sh -t ios", 1)[0]
require(_ios_build_pipeline.rstrip().endswith("set -o pipefail"),
        "iOS redaction pipeline must propagate a failed build exit status")
require("environment: tribe-ios-release" in deploy_workflow
        and "github.event_name == 'workflow_dispatch'" in deploy_workflow
        and "inputs.release_platform == 'ios'" in deploy_workflow
        and "startsWith(github.ref, 'refs/tags/ios-v')" in deploy_workflow,
        "signed iOS secrets/artifacts must be restricted to the protected release environment")
for platform, tag, environment in (
    ("macOS", "macos-v", "tribe-macos-release"),
    ("Android", "android-v", "tribe-android-release"),
):
    require(f"environment: {environment}" in deploy_workflow
            and f"startsWith(github.ref, 'refs/tags/{tag}')" in deploy_workflow
            and f"inputs.release_platform == '{tag.removesuffix('-v')}'" in deploy_workflow
            and f"- '{tag}*'" in deploy_workflow,
            f"signed {platform} shipping must be manual/tag-only in a protected environment")
require(deploy_workflow.count(
            "bash metadata/run_tribe_release_gates.sh --release") == 3
        and "--release ios" in deploy_workflow
        and "--release macos_daemon" in deploy_workflow
        and "--release android" in deploy_workflow
        and deploy_workflow.count(
            "git status --porcelain=v1 --untracked-files=all") >= 3
        and deploy_workflow.count(
            '[[ "$(git rev-parse --verify HEAD)" == "$GITHUB_SHA" ]]') >= 3
        and "bash metadata/run_tribe_release_gates.sh --source-only" in protocol_workflow,
        "shipping jobs must be commit-bound and ordinary branch CI must stay source-only")
require("python3 metadata/check_release_version.py" in release_gates
        and deploy_workflow.count(
            "run: python3 metadata/check_release_version.py") == 3
        and deploy_workflow.count("fetch-tags: true") == 3
        and "Bind iOS release tag to source version and commit" in deploy_workflow
        and "Bind macOS release tag to source version and commit" in deploy_workflow
        and "Bind Android release tag to source version and commit" in deploy_workflow
        and "refs/tags/(ios|macos|android)-v" in release_version_gate
        and "tagged_version != version.full" in release_version_gate
        and "tagged_commit != head" in release_version_gate
        and "head != expected_head" in release_version_gate,
        "release tags must byte-match the source version and resolve to the exact CI commit")
require('bash "$SOURCE_PATH/metadata/run_tribe_release_gates.sh"' in build_wrapper
        and re.search(
            r'(?m)^\s*sh "\$SOURCE_PATH/metadata/run_tribe_release_gates\.sh"',
            build_wrapper) is None,
        "the Linux Android build wrapper must not run the bash release gate through dash")
require('@unittest.skipUnless(sys.platform == "darwin"' in macos_payload_tests,
        "Linux Android source gates must skip the BSD-only macOS payload fixture")
require("TRIBE_STORE_BUILD: ON" in deploy_workflow
        and "TRIBE_IOS_APP_PROFILE_UUID:" in deploy_workflow
        and "TRIBE_IOS_NE_PROFILE_UUID:" in deploy_workflow
        and 'XCODE_ATTRIBUTE_CODE_SIGN_STYLE Manual' in ios_cmake
        and 'XCODE_ATTRIBUTE_PROVISIONING_PROFILE_SPECIFIER' in ios_cmake,
        "iOS App Store archive must use the store policy and two deterministic profiles")
require("xcodebuild archive" in deploy_workflow
        and "-destination 'generic/platform=iOS'" in deploy_workflow
        and "xcodebuild -exportArchive" in deploy_workflow
        and "metadata/check_ios_release_artifact.py" in deploy_workflow
        and deploy_workflow.count("--artifact \"$RUNNER_TEMP/TribeVPN") == 2
        and "TribeVPN-ios-release.ipa" in deploy_workflow
        and "TribeVPN-ipa-attestation.json" in deploy_workflow
        and "actions/upload-artifact@v4" in deploy_workflow,
        "iOS release CI must archive, verify, locally export and reverify one IPA")
require("<string>app-store-connect</string>" in ios_export_options
        and "<string>export</string>" in ios_export_options
        and "<string>manual</string>" in ios_export_options
        and "<key>provisioningProfiles</key>" in ios_export_options
        and "manageAppVersionAndBuildNumber" in ios_export_options
        and "APPSTORE_CONNECT_" not in deploy_workflow
        and "-allowProvisioningUpdates" not in deploy_workflow
        and "destination=upload" not in deploy_workflow
        and "iTMSTransporter" not in deploy_workflow,
        "iOS artifact job must be deterministic local export with no Store upload capability")
for needle in ("duplicate ZIP member names", "case/Unicode-colliding",
               "special/symlink IPA member", "Apple Distribution",
               "signed build manifest mismatch", "validate_macho_closure",
               "SwiftSupport runtime does not byte-match the app",
               "provisioning profile SHA-256 mismatch", "PrivacyInfo.xcprivacy",
               'EXPECTED_QT = "6.11.1"', 'EXPECTED_XCODE_CODE = "2640"'):
    require(needle in ios_release_checker,
            f"iOS final-artifact validator lost {needle}")
require("TribeBuildManifest.plist" in ios_cmake
        and "target_sources(${PROJECT} PRIVATE \"${TRIBE_IOS_BUILD_MANIFEST}\")" in ios_cmake
        and "target_sources(networkextension PRIVATE \"${TRIBE_IOS_BUILD_MANIFEST}\")" in ios_cmake
        and "TRIBE_IOS_AWG_GUARD_XML" in ios_cmake
        and "TRIBE_IOS_XRAY_GUARD_XML" in ios_cmake
        and "RuntimeReceiptSHA256" in ios_build_manifest
        and "EngineLockSHA256" in ios_build_manifest
        and "StoreBuild" in ios_build_manifest
        and "@Qt6_VERSION@" in ios_build_manifest,
        "both signed iOS bundles must embed the receipt/engine/store build manifest")
require("<string>${BUILD_IOS_GROUP_IDENTIFIER}</string>" in ios_ne_info
        and "group.${BUILD_IOS_APP_IDENTIFIER}" not in ios_ne_info,
        "iOS Network Extension Info.plist app group must match its signed Tribe entitlement")
for action_name, action, needles in (
    ("profile", apple_profile_action,
     ("security cms -D", "EXPECTED_SHA256", "DeveloperCertificates",
      "ProvisionedDevices", "get-task-allow", "expected-certificate-sha256")),
    ("certificate", apple_cert_action,
     ("EXPECTED_LEAF_SHA256", "Apple Distribution:", "openssl x509",
      "security find-identity", "developer-id-application",
      "developer-id-installer", "IDENTITY_POLICY",
      "certificate/private key mismatch")),
):
    for needle in needles:
        require(needle in action, f"Apple {action_name} import lost {needle}")
require("MAC_APP_CERT_SHA256" in deploy_workflow
        and "MAC_INSTALLER_CERT_SHA256" in deploy_workflow
        and deploy_workflow.count("expected-team-id: Q7DVH5MCWF") >= 3
        and "expected-certificate-kind: developer-id-application" in deploy_workflow
        and "expected-certificate-kind: developer-id-installer" in deploy_workflow
        and "NOTARY_TEAM_ID: Q7DVH5MCWF" in deploy_workflow,
        "macOS app/installer import and notarization must bind the exact Tribe team and leaf pins")
require("xcode-version: '26.0'" not in deploy_workflow
        and "xcode-version: '26.3.0'" not in deploy_workflow
        and deploy_workflow.count("xcode-version: '26.4'") >= 3
        and deploy_workflow.count("runs-on: macos-26") >= 3,
        "shipping iOS/macOS and macOS NE compile jobs must use Xcode 26.4")
require(deploy_workflow.count("qt_version: '6.11.1'") == 2,
        "both supported Android minimum-SDK tracks must use Qt 6.11.1")
require("ANDROID_COMPILE_PLATFORM: android-36" in deploy_workflow
        and "platforms;${{ env.ANDROID_COMPILE_PLATFORM }}" in deploy_workflow
        and "build-tools;36.0.0" in deploy_workflow,
        "Android CI must install API 36 without replacing the native min-SDK platform")
require("${{ runner.temp }}/android.keystore" in deploy_workflow
        and "${{ github.workspace }}/android.keystore" not in deploy_workflow,
        "release keystore must not dirty the receipt-gated Git checkout")
require("$RUNNER_TEMP/tribe-android-artifacts-" in deploy_workflow
        and "deploy/artifacts" not in deploy_workflow
        and deploy_workflow.count("if-no-files-found: error") >= 7,
        "Android release outputs must stay outside the commit-bound checkout and fail on empty globs")
require("testReleaseUnitTest lintRelease" in deploy_workflow,
        "Android artifacts must be gated by generated-tree Release unit tests and lint")
_android_release_job = deploy_workflow.split("  Build-Android:", 1)[1]
require("set -euo pipefail\n        STORE_BUILD=" in _android_release_job
        and "TRIBE_STORE_BUILD: ON" not in _android_release_job
        and "TRIBE_STORE_BUILD=ON deploy/build.sh" in _android_release_job
        and _android_release_job.count("TRIBE_STORE_BUILD=OFF deploy/build.sh") == 2
        and "build-store-aab-" in deploy_workflow
        and "build-sideload-universal-" in deploy_workflow,
        "Play AAB and sideload APKs must use separate clean store-policy build trees")
require("QT_ANDROID_KEYSTORE_STORE_PASS:" in deploy_workflow
        and "QT_ANDROID_KEYSTORE_KEY_PASS:" in deploy_workflow
        and "ANDROID_RELEASE_SIGNING_CERT_SHA256" in deploy_workflow
        and "EXPECTED_CERT_SHA256" in deploy_workflow
        and "PINNED_CERT_SHA256" in deploy_workflow
        and 'chmod 600 "$RUNNER_TEMP/android.keystore"' in deploy_workflow,
        "Android signing must use both Qt passwords and an independent pinned certificate")
require(deploy_workflow.count('validate_android_engine_payload "') == 2
        and "metadata/check_android_awg_artifacts.py" in deploy_workflow
        and "metadata/check_android_xray_aar.py" in deploy_workflow
        and deploy_workflow.count("--packaged-artifact") >= 2,
        "both clean universal flavors must validate raw and release-packaged AWG/Xray")
require(deploy_workflow.count("metadata/check_android_16kb_artifact.py") >= 5
        and '--required-abi "$abi"' in deploy_workflow
        and 'python3 metadata/check_android_16kb_artifact.py "$AAB"' in deploy_workflow
        and "artifact contains duplicate ZIP member names" in android_16kb_checker
        and 'zipalign" -c -P 16 -v 4' in deploy_workflow,
        "universal/store and shipped 64-bit per-ABI artifacts must prove 16-KiB ELF/ZIP alignment")
require("validate_final_apk" in deploy_workflow
        and deploy_workflow.count("validate_final_engine_archive") >= 4
        and "android_release_packaged_sha256" in deploy_workflow
        and "duplicate ZIP member names are forbidden" in deploy_workflow
        and "archive.infolist()" in deploy_workflow
        and "maxSdkVersion" in deploy_workflow
        and "targetSdkVersion" in deploy_workflow,
        "every shipped APK must bind ABI hashes and the min/max/target/version track")
require('version: "6.11.1"' in protocol_workflow,
        "Apple source gates must compile against the shipping Qt version")
require("deploy/build_macos_ne.sh" not in deploy_workflow
        and "Compile-MacOS-NE:" in deploy_workflow
        and "--target macos-ne --compile-only" in deploy_workflow
        and deploy_workflow.count("arch: [arm64, x86_64]") == 2
        and "TRIBE_MACOS_NE_ARCH: ${{ matrix.arch }}" in deploy_workflow
        and "TRIBE_MACOS_NE_ARCH must be one scalar architecture" in platform_settings
        and 'CMAKE_OSX_ARCHITECTURES "arm64;x86_64"' not in platform_settings,
        "macOS NE CI must remain a real, unsigned compile-only proof")
require("MAC_NE_PROVISIONING_PROFILE" not in deploy_workflow
        and "name: AmneziaVPN_MacOS_unpacked" not in deploy_workflow,
        "unsupported macOS NE CI must not receive signing inputs or upload an app")
require("--compile-only" in build_wrapper
        and "macOS NE is unsupported for release" in build_wrapper
        and "build_args+=(--target AmneziaVPNNetworkExtension)" in build_wrapper
        and 'macos-ne) TRIBE_REQUIRED_RUNTIME_PLATFORM="macos_ne"' not in build_wrapper,
        "build wrapper must fail closed and compile the exact macOS NE target instead of "
        "inventing release support or rebuilding the desktop GUI")
require("PYTHONDONTWRITEBYTECODE=1" in release_gates
        and "SOURCE_BASELINE" in release_gates
        and "SOURCE_AFTER" in release_gates
        and "release gates changed the source tree" in release_gates,
        "release gates must preserve an exact clean source snapshot without Python bytecode")
require("legacy-release-disabled" in legacy_release_workflow
        and "debug keystore" in legacy_release_workflow
        and "deploy/build_android.sh" not in legacy_release_workflow,
        "obsolete Qt 6.4/API-23 Android release route must stay disabled")

# API 36 must not regress to the unsupported AGP 8.6/Gradle 8.10 pairing. Keep every AGP
# coordinate in lock-step because settings and app/library plugins load in the same build.
require('agp = "8.11.1"' in android_versions,
        "Android app/library plugins must use the API-36-compatible AGP pin")
require('id("com.android.settings") version "8.11.1"' in android_settings,
        "Android settings plugin must match the app/library AGP pin")
require("gradle-8.13-bin.zip" in android_wrapper,
        "AGP 8.11.1 requires the Gradle 8.13 wrapper")

# A universal Qt Android artifact is built by independent nested CMake projects.
# They must receive the same Play-track and trust/receipt inputs, while keeping
# generated manifests and AAR sidecars private to each build directory.
multi_abi_match = re.search(
    r"set\(QT_ANDROID_MULTI_ABI_FORWARD_VARS\s+(.*?)\)", android_cmake, re.DOTALL)
require(multi_abi_match is not None,
        "Android multi-ABI forwarding contract is missing")
forwarded_vars = set(re.findall(r"\b[A-Z][A-Z0-9_]+\b", multi_abi_match.group(1)))
required_forwarded_vars = {
    "QT_NO_GLOBAL_APK_TARGET_PART_OF_ALL",
    "CMAKE_BUILD_TYPE",
    "CONAN_COMMAND",
    "CONAN_HOST_PROFILE",
    "CONAN_BUILD_PROFILE",
    "ANDROID_PLATFORM",
    "APP_ANDROID_MIN_SDK",
    "APP_ANDROID_MAX_SDK",
    "APP_ANDROID_VERSION_CODE_OFFSET",
    "AVPN_ENGINE",
    "TRIBE_STORE_BUILD",
    "DEPLOY",
    "TRIBE_CATALOG_ROOT_KID",
    "TRIBE_CATALOG_ROOT_PUBLIC_KEY_HEX",
    "TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE",
    "TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256",
    "TRIBE_REQUIRED_RUNTIME_PLATFORM",
    "PROD_AGW_PUBLIC_KEY",
    "PROD_S3_ENDPOINT",
    "FALLBACK_S3_ENDPOINT",
    "DEV_AGW_PUBLIC_KEY",
    "DEV_AGW_ENDPOINT",
    "DEV_S3_ENDPOINT",
    "FREE_V2_ENDPOINT",
    "PREM_V1_ENDPOINT",
}
require(required_forwarded_vars <= forwarded_vars,
        "non-primary Android ABIs lost Play-track or trust/receipt inputs: "
        f"{sorted(required_forwarded_vars - forwarded_vars)}")
for endpoint_var in ("PROD_AGW_PUBLIC_KEY", "PROD_S3_ENDPOINT", "FALLBACK_S3_ENDPOINT",
                     "DEV_AGW_PUBLIC_KEY", "DEV_AGW_ENDPOINT", "DEV_S3_ENDPOINT",
                     "FREE_V2_ENDPOINT", "PREM_V1_ENDPOINT"):
    require(f'set({endpoint_var} "$ENV{{{endpoint_var}}}" CACHE STRING' in client_project
            and f'-D{endpoint_var}="${{{endpoint_var}}}"' in client_project,
            f"{endpoint_var} must be cached once before Android ABI forwarding")
require("_TRIBE_EXPECTED_ANDROID_PLATFORM" in platform_settings
        and "ANDROID_PLATFORM=${ANDROID_PLATFORM} disagrees" in platform_settings
        and platform_settings.index("_TRIBE_EXPECTED_ANDROID_PLATFORM")
            < platform_settings.index("set(_CONAN_INSTALL_ARGS", platform_settings.index(
                'if(CMAKE_SYSTEM_NAME STREQUAL "Android")')),
        "Android native API/min-SDK agreement must be checked before Conan resolution")
require("${CMAKE_CURRENT_BINARY_DIR}/android-package-source" in android_cmake
        and "set(APP_ANDROID_PACKAGE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/android)"
        not in android_cmake,
        "Android package source must be private to every ABI build")
for needle in ('PATTERN ".gradle" EXCLUDE', 'PATTERN "build" EXCLUDE',
               '${APP_ANDROID_PACKAGE_SOURCE_DIR}/xray/libXray/libxray.aar',
               'QT_ANDROID_PACKAGE_SOURCE_DIR ${APP_ANDROID_PACKAGE_SOURCE_DIR}'):
    require(needle in android_cmake,
            f"Android private package/AAR staging lost {needle}")
require("APP_ANDROID_MAX_SDK must be a non-negative integer" in android_cmake
        and "APP_ANDROID_MAX_SDK must be greater than or equal" in android_cmake,
        "Android max-SDK track bounds must fail closed")
require(android_cmake.index("file(REMOVE_RECURSE")
        < android_cmake.index('file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/android/"')
        < android_cmake.index('file(COPY_FILE "${AMNEZIA_LIBXRAY_PATH}"'),
        "Android private package staging must be recreated before copying the pinned AAR")

base_version = "set(APP_ANDROID_VERSION_CODE ${TRIBE_ANDROID_VERSION_CODE})"
offset_version = "math(EXPR APP_ANDROID_VERSION_CODE"
require(root_cmake.count(base_version) == 1
        and root_cmake.index(base_version) < root_cmake.index(offset_version)
        and "APP_ANDROID_VERSION_CODE_OFFSET must be a non-negative integer" in root_cmake
        and 'CACHE INTERNAL\n    "Computed Tribe Android versionCode" FORCE' in root_cmake
        and "set(APP_ANDROID_VERSION_CODE 2144)" not in root_cmake,
        "Android versionCode must apply a validated track offset after the Tribe base")
_android_base_match = re.search(
    r"set\(TRIBE_ANDROID_VERSION_CODE\s+([0-9]+)\)", tribe_version)
_android_offsets = {
    int(value) for value in re.findall(r"version_code_offset:\s*([0-9]+)", deploy_workflow)
}
require(_android_base_match is not None and _android_offsets == {0, 1},
        "Android release matrix must expose exactly the base and base+1 Play tracks")
android_track_version_codes = sorted(
    int(_android_base_match.group(1)) + offset for offset in _android_offsets)
require("containsAbsoluteGoReplacement" in android_xray_gradle
        and "/.conan2/" in android_xray_gradle
        and "absolute local Go module replacement path" in android_xray_gradle,
        "Gradle must reject Xray AARs containing local Go build paths")
require("file(COPY_FILE" not in root_cmake,
        "configuring a Debug build must not rewrite the tracked production PF rule")
require(service_cmake.count("${CMAKE_BINARY_DIR}/tribe.400.allowPIA.conf") >= 2,
        "the generated PF identity rule must reach both install and daemon build trees")
for needle in ("MACOSX_DEPLOYMENT_TARGET", "IPHONEOS_DEPLOYMENT_TARGET",
               "20b82af890bdf946f82d6efaacb5acc07c61f8de",
               "12563d7853384983de50f12ff7f679a95f547aaa"):
    require(needle in openvpnadapter_recipe,
            f"OpenVPNAdapter recipe lost pinned source/target evidence: {needle}")

# The desktop daemon payload is a transport runtime, not just two binaries. Its closed
# manifest/version anchor covers AWG, Xray, OpenVPN, dependencies,
# monotonic epoch and PF state. CPack is the only packaging implementation.
for runtime_file in ("Tribe-service", "amneziawg-go", "openvpn", "tun2socks",
                     "geoip.dat", "geosite.dat", "INSTALL-EPOCH"):
    require(runtime_file in macos_installer and runtime_file in macos_prepare
            and runtime_file in macos_payload,
            f"macOS sealed runtime contract lost {runtime_file}")
for runtime_file in ("amneziawg-go", "openvpn", "tun2socks", "geoip.dat", "geosite.dat"):
    require(runtime_file in macos_dev_installer,
            f"macOS dev installer lost runtime file {runtime_file}")
for needle in ("PAYLOAD-MANIFEST.sha256", "PAYLOAD-SYMLINKS",
               "INSTALL-CONTRACT", "mode_contract=",
               "tribe.999.quarantine.conf",
               "payload does not match the signed app version anchor",
               "manifest file set is incomplete or has extras"):
    require(needle in macos_payload, f"macOS payload seal lost invariant: {needle}")
require('.TribeVPN.install-transaction"' in macos_installer
        and ".TribeVPN.new.XXXXXX" not in macos_installer
        and "schema=3" in macos_installer
        and "runtime_version=" in macos_installer
        and "group_created=" in macos_installer
        and "write_journal old_stopped" in macos_installer
        and "write_journal old_saved" in macos_installer
        and "write_journal new_runtime" in macos_installer
        and "write_journal new_plist" in macos_installer
        and "write_journal healthy" in macos_installer
        and "write_journal committed" in macos_installer
        and "discard_unstarted_transaction" in macos_installer
        and "journal-less transaction contains staged/live state" in macos_installer
        and macos_installer.index("recover_pending_transaction")
            < macos_installer.index('if [ -e "$DEST/INSTALL-EPOCH" ]')
        and "/bin/sync" in macos_installer
        and "restoring previous service" in macos_installer
        and 'stable_pid="$launch_pid"' in macos_installer
        and 'launch_job_state" = running' in macos_installer
        and '/usr/sbin/lsof -a -p "$launch_pid" -d txt -Fn' in macos_installer
        and "launchctl-job-field.sh" in macos_installer
        and "top_indent" in macos_launchctl_parser
        and "matches != 1" in macos_launchctl_parser
        and "normalize \"$NEW\"" in macos_installer,
        "macOS installer must stage atomically and roll back a failed launch")
require("validate_launchd_parent" in macos_installer
        and "root:wheel:755" in macos_installer
        and "root:wheel:644:1" in macos_installer,
        "launchd plist reads and bootout must be protected by exact immutable provenance")
require("--chroot" in macos_installer
        and "--no-same-owner" in macos_installer
        and "--no-same-permissions" in macos_installer
        and "--no-acls" in macos_installer
        and "--no-fflags" in macos_installer
        and "--no-mac-metadata" in macos_installer
        and "--no-xattrs" in macos_installer
        and macos_installer.index("umask 022") < macos_installer.index("/usr/bin/bsdtar -xzf")
        and "hard-linked payload file" in macos_payload,
        "privileged extraction must be root-confined and preserve the exact mode contract")
require("same install epoch is bound to a different payload" in macos_installer
        and "refusing signed daemon downgrade" in macos_installer
        and "CPACK_TRIBE_INSTALL_EPOCH" in cpack
        and "CPACK_TRIBE_INSTALL_EPOCH" in cpack_sign
        and "CFBundleVersion/install epoch mismatch" in macos_post_install,
        "signed daemon payloads need a monotonic, non-equivocating install epoch")
_journal_recovery = macos_installer[
    macos_installer.index("recover_pending_transaction() {"):
    macos_installer.index("finalize_pending_transaction() {")
]
_journal_older = _journal_recovery[
    _journal_recovery.index('if [ "$incoming_epoch" -lt "$JOURNAL_EPOCH" ]'):
    _journal_recovery.index('if [ "$incoming_epoch" -eq "$JOURNAL_EPOCH" ]')
]
require("refusing signed daemon downgrade against committed journal" in _journal_older
        and "return 1" in _journal_older
        and "rollback_transaction" not in _journal_older,
        "retained macOS rollback state must never authorize a lower signed install epoch")
require("GroupMembers" in macos_installer and "NestedGroups" in macos_installer
        and "PrimaryGroupID" in macos_installer
        and "GROUP_CREATED" in macos_installer,
        "privileged PF group must reject memberships/GID collisions and roll back creation")
require("6.10.2" not in macos_dist and "6.10.2" not in macos_bundle,
        "macOS packaging scripts must not fall back to the old Qt runtime")
require("amnezia-client" not in macos_bundle
        and "TRIBE_APP_FRAMEWORKS_DIR" in macos_bundle
        and "TRIBE_QT_LIB_DIR" in macos_bundle
        and 'LAYOUT="${4:-service}"' in macos_bundle
        and "@loader_path/../Frameworks" in macos_bundle,
        "daemon bundler must use explicit artifact/Qt roots instead of one developer checkout")
require("libqsqlite.dylib" in macos_sanitizer
        and "libqsqlmimer.dylib" in macos_sanitizer
        and "verify-macos-runtime.sh" in macos_sanitizer,
        "macOS app packaging must remove qsqlmimer and verify dependency closure")
require("canonical_macho_path" in macos_runtime
        and "independent dyld root" in macos_runtime
        and "exactly one @loader_path/Frameworks" in macos_runtime
        and "incomplete macOS deployment-target metadata" in macos_runtime,
        "macOS closure gate must validate independent roots, Mach-O targets, arches and min OS")
require("require_thin_arm64" in macos_runtime
        and 'if [ -f "$ROOT/Contents/MacOS/Tribe-service" ]' in macos_runtime
        and 'require_thin_arm64 "$ROOT/Tribe-service"' in macos_runtime
        and 'set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)  # AVPN:'
            in platform_settings
        and "The only shippable macOS flavor is the normal daemon-based, arm64"
            in source("deploy/tribe/MACOS_RELEASE_RUNBOOK.md"),
        "shipping macOS GUI/daemon/transport roots must remain honestly thin arm64")
require("sanitize-macos-app.sh" in client_cmake
        and "sanitize-macos-app.sh" in source("client/cmake/macos_ne.cmake"),
        "both daemon and compile-only NE packaging paths must run the SQL/runtime gate")
require("macos_arm64" in cpack and "macos_x64" not in cpack,
        "arm64 daemon package must not be mislabeled x64")
require('set(CPACK_PACKAGING_INSTALL_PREFIX "/Applications")' in cpack,
        "macOS productbuild must install the app where its postflight expects it")
require("Applications/TribeVPN.app" in macos_component_plist
        and "<true/>" in macos_component_plist
        and "BundleIsRelocatable" in macos_component_plist
        and "<false/>" in macos_component_plist
        and "BundleHasStrictIdentifier" in macos_component_plist,
        "productbuild component must be non-relocatable, strict and version-checked")
require("deploy/data/macos/pre_install.sh" in cpack
        and "CPACK_POSTFLIGHT_UNINSTALL_SCRIPT" not in cpack
        and "rm -rf" not in macos_pre_install
        and "Tribe-service" not in macos_pre_install,
        "macOS upgrade preflight must stop only the GUI and preserve known-good runtime")
require("post_uninstall.sh is retired" in macos_uninstall
        and "rm -rf" not in macos_uninstall
        and "launchctl" not in macos_uninstall,
        "dormant package uninstall must fail closed instead of deleting unauthenticated paths")
require('set(CMAKE_INSTALL_BINDIR "TribeVPN.app/Contents/MacOS")' in service_cmake
        and 'set(CMAKE_INSTALL_BINDIR "AmneziaVPN.app/Contents/MacOS")' not in service_cmake
        and "${CMAKE_INSTALL_BINDIR}/TribeVPN.app/Contents/Frameworks" in client_cmake,
        "CPack must install GUI, daemon and every transport runtime into one TribeVPN.app")
_nested_sign = cpack_sign.find('codesign_sign_files("${nested_files}"')
_payload_prepare = cpack_sign.find("prepare-macos-service-payload.sh")
_outer_sign = cpack_sign.find("RESULT_VARIABLE _tribe_app_sign_result")
_app_daemon_closure = cpack_sign.find("_tribe_app_daemon_closure_result")
_app_sanitize = cpack_sign.find("_tribe_sanitize_result")
_symbol_prepare = cpack_sign.find("prepare-macos-symbols.sh")
_engine_identity = cpack_sign.find("check_macos_engine_artifact.py")
require("prepare-macos-service-payload.sh" in cpack_sign
        and 'Contents/MacOS/tun2socks' in cpack_sign
        and 'file(GLOB_RECURSE execs' not in cpack_sign
        and -1 not in (_app_daemon_closure, _app_sanitize, _symbol_prepare,
                       _engine_identity, _nested_sign,
                       _payload_prepare, _outer_sign)
        and _app_daemon_closure < _app_sanitize < _symbol_prepare \
            < _engine_identity < _nested_sign \
            < _payload_prepare < _outer_sign
        and "CPACK_TRIBE_QT_LIB_DIR" in cpack
        and "CPACK_TRIBE_QT_LIB_DIR" in cpack_sign
        and '--entitlements "${_tribe_entitlements}"' in cpack_sign
        and "certificate leaf[subject.OU]" in cpack_sign,
        "CPack must seal already-signed helpers before signing the containing app")
require("TRIBE_MACOS_DSYM_OUTPUT_DIR" in cpack_sign
        and "dsymutil" in macos_symbols
        and "dwarfdump --uuid" in macos_symbols
        and "/usr/bin/strip -S" in macos_symbols
        and macos_symbols.index("dsymutil") < macos_symbols.index("/usr/bin/strip -S")
        and "verify-macos-build-paths.sh" in macos_symbols
        and "per-user Conan cache path leaked" in macos_path_privacy
        and "TRIBE_MACOS_DSYM_OUTPUT_DIR" in deploy_workflow
        and "TribeVPN-macOS-dSYMs" in deploy_workflow
        and '[[ "$DSYM_COUNT" == 5 ]]' in deploy_workflow
        and "shasum -a 256 -c SHA256SUMS" in deploy_workflow,
        "macOS release must detach/verify symbols, strip before signing and reject private paths")
_manifest_dispatch = service_main.find("std::strcmp(argv[1], kEngineManifestArgument)")
_dns_hook_dispatch = service_main.find("openvpndnssecurity::kHookArgument")
_path_initialization = service_main.find("Utils::initializePath")
_manifest_function_start = service_main.find("int writeEngineManifestV1()")
_manifest_function_end = service_main.find("\n#endif", _manifest_function_start)
require(-1 not in (_manifest_dispatch, _dns_hook_dispatch, _path_initialization,
                   _manifest_function_start, _manifest_function_end)
        and _manifest_dispatch < _dns_hook_dispatch < _path_initialization
        and "QCoreApplication" not in service_main[
            _manifest_function_start:_manifest_function_end]
        and "openvpndnssecurity" not in service_main[
            _manifest_function_start:_manifest_function_end]
        and "argc != 2" in service_main[_manifest_dispatch:_dns_hook_dispatch],
        "macOS artifact identity ABI must return before path/DNS/PF/IPC initialization")
for needle in ("(deny network*)", "(deny file-write*)", "tree_snapshot(artifact_root)",
               '"_amnezia_xray_configure"', "engine-lock.json",
               "service_result.stdout.count", "AWG artifact version",
               "OpenVPN/OpenSSL runtime versions", "tun2socks runtime version/commit",
               "github.com/amnezia-vpn/amnezia-xray-core",
               "pinned desktop geodata"):
    require(needle in macos_engine_artifact,
            f"macOS engine artifact side-effect/identity gate lost {needle}")
require(deploy_workflow.count("metadata/check_macos_engine_artifact.py") == 1
        and '--app "$PAYLOAD_APP"' in deploy_workflow,
        "final expanded product must repeat the staged AWG/Xray identity gate")
require("check_macos_engine_artifact.py" in macos_prepare
        and '--runtime-root "$STAGING"' in macos_prepare
        and macos_prepare.index("verify-macos-runtime.sh")
            < macos_prepare.index("check_macos_engine_artifact.py")
            < macos_prepare.index("macos-service-payload.sh\" seal"),
        "relocated privileged payload must pass runtime identity before sealing")
require("test_sandbox_denies_write_and_network_side_effects" in macos_engine_artifact_tests
        and "test_extra_key_and_engine_drift_fail_closed" in macos_engine_artifact_tests,
        "macOS engine artifact gate lost executable negative regression tests")
for recipe_name, recipe in (("awg-go", awg_go_recipe),
                            ("xray-bindings", xray_bindings_recipe),
                            ("tun2socks", tun2socks_recipe)):
    require("-trimpath" in recipe and "-buildvcs=false" in recipe
            and "-buildid=" in recipe,
            f"{recipe_name} macOS Go build lost reproducible path/build-id flags")
require("BUILD_VERSION=v{self.version}" in tun2socks_recipe
        and "BUILD_COMMIT={self._source_commit}" in tun2socks_recipe
        and '"LDFLAGS += -w -s -buildid=",' in tun2socks_recipe
        and '"LDFLAGS += -buildid=",' in tun2socks_recipe
        and 'if [ "$name" != tun2socks ]' not in macos_symbols,
        "tun2socks must expose locked identity and retain DWARF until post-dSYM strip")
require('go build -trimpath -buildvcs=false -ldflags="-buildid="' in xray_bindings_recipe,
        "desktop Xray must retain Go DWARF until post-dSYM strip")
for recipe_name, recipe in (("openvpn", openvpn_recipe),
                            ("libssh", libssh_recipe)):
    require("-ffile-prefix-map=" in recipe
            and "-fdebug-prefix-map=" in recipe
            and "-fmacro-prefix-map=" in recipe,
            f"{recipe_name} macOS build lost C/C++ prefix maps")
require('self.settings.os in ("Linux", "Macos")' in openssl_recipe
        and 'include_path = ".tribe-zlib/include"' in openssl_recipe
        and 'zlib_lib_flag = ".tribe-zlib/lib"' in openssl_recipe,
        "macOS OpenSSL must not publish Conan cache paths as OPENSSLDIR/compiler flags")
require("CODESIGN_INSTALLER_SIGNATURE" in cpack_options
        and "explicit installer signing keychain" in cpack_options
        and "validated notarytool keychain profile" in cpack_packages
        and "stapler validate" in notarytool
        and 'xcrun stapler validate "$PACKAGE"' in deploy_workflow
        and 'spctl --assess --type install --verbose=4 "$PACKAGE"' in deploy_workflow
        and "--password" not in notarytool,
        "macOS installer signing/notarization and final Gatekeeper proof must fail closed")
require("ipc/tests/run_openvpn_hook_argv_smoke.sh" in deploy_workflow
        and '"$PAYLOAD_APP/Contents/MacOS/openvpn"' in deploy_workflow
        and "OpenVPN real hook argv smoke passed" in source(
            "ipc/tests/run_openvpn_hook_argv_smoke.sh"),
        "the packaged OpenVPN binary must exercise the exact native DNS hook argv ABI")
require("retired unsafe release route" in macos_dist
        and "make-macos-dist.sh is retired" in macos_dist
        and "notarytool submit" not in macos_dist
        and "dmgbuild" not in macos_dist and "codesign " not in macos_dist,
        "legacy local macOS helper must not retain a second packaging/signing path")
require("tribe-svc-install.sh" in macos_post_install
        and "tribe-svc.tar.gz" in macos_post_install
        and "tribe-daemon.sh install" not in macos_post_install,
        "productbuild postflight must install the sealed full runtime, not the legacy partial daemon")
require("configure_file(" in cpack
        and "@AMNEZIAVPN_VERSION@" in macos_post_install
        and "SNAPSHOT_APP_SHORT.$SNAPSHOT_APP_BUILD" in macos_post_install,
        "productbuild must configure and bind postflight to marketing+build version")
mac_service_bootstrap = mac_service_installer.replace(r'\"', '"')
require("/private/var/tmp/tribevpn-bootstrap.XXXXXX" in mac_service_bootstrap
        and "/usr/bin/ditto --norsrc --noqtn" in mac_service_bootstrap
        and "test ! -L \"$trusted_app\"" in mac_service_bootstrap
        and "--deep --strict --all-architectures" in mac_service_bootstrap
        and 'identifier \"hk.wellwon.vpn\"' in mac_service_bootstrap
        and "-links +1" in mac_service_bootstrap
        and mac_service_bootstrap.index("codesign --verify")
            < mac_service_bootstrap.index('/bin/bash \"$installer\"'),
        "self install/uninstall must execute only an exact-signed root-owned app snapshot")
require("const bool needRepair = !serviceRunning;" in avpn_engine_qml
        and "if (needInstall || needRepair)" in avpn_engine_qml
        and "const bool ok = avpn::macInstallServiceRun(&ierr);" in avpn_engine_qml
        and "system/Tribe-service" in mac_service_installer
        and "/usr/sbin/lsof" in mac_service_installer
        and "pgrep -x Tribe-service" not in mac_service_installer,
        "a stopped same-version daemon must run sealed repair and exact launchd/vnode health proof")
require("/private/var/tmp/tribevpn-pkg-bootstrap.XXXXXX" in macos_post_install
        and '[ ! -L "$TRUSTED_APP" ]' in macos_post_install
        and macos_post_install.index("codesign --verify")
            < macos_post_install.index('bash \"$INSTALLER\"'),
        "productbuild postflight must not execute mutable /Applications resources")
_legacy_preflight = macos_post_install.index("legacy migration preflight")
_service_install = macos_post_install.index(
        'bash "$INSTALLER" "$TARBALL" --defer-finalize')
_post_health = macos_post_install.index("PRECOMMIT_HEALTHY", _service_install)
_service_finalize = macos_post_install.index(
        'bash "$INSTALLER" "$TARBALL" --finalize-pending', _post_health)
_legacy_migrate = macos_post_install.rindex('"$EXPECTED_APP_VERSION" migrate')
require(_legacy_preflight < _service_install < _post_health
        < _service_finalize < _legacy_migrate
        and 'bash "$INSTALLER" --rollback-pending' in macos_post_install
        and "SERVICE_COMMITTED=1" in macos_post_install
        and 'bash "$INSTALLER" --cleanup-committed' not in macos_post_install
        and "WARNING: legacy app migration unresolved after daemon commit" in macos_post_install
        and "same-volume rename" in macos_migrator
        and "MIGRATION_COMMITTED" in macos_migrator
        and "identity/signature changed during quarantine" in macos_migrator
        and "refusing to remove newer signed legacy" in macos_migrator,
        "legacy app migration must be ordered, anti-downgrade and rollback-safe")
require("com.antivpn.helper" not in macos_installer
        and "com.antivpn.helper" not in macos_uninstall,
        "Tribe cleanup must never touch the separate NeVPN helper product")
require("--tribe-openvpn-dns-recover-v1" in macos_installer
        and macos_installer.index("--tribe-openvpn-dns-recover-v1")
            < macos_installer.index('rm -rf "$dns_state_dir"')
            < macos_installer.index('rm -rf "$DEST"'),
        "uninstall must recover exact native DNS state before deleting its state/runtime")
require("macUninstallServiceRun" in mac_service_installer
        and "removeMacSystemService" in account_qml
        and "onMacSystemServiceRemovalFinished" in account_qml
        and 'visible: Qt.platform.os === "osx"' in account_qml,
        "signed macOS service removal must be reachable from a macOS-only user action")
for bake in ("Linux", "Windows", "iOS", "MacOS", "MacOS-NE", "Android"):
    consumer = "Compile-MacOS-NE" if bake == "MacOS-NE" else f"Build-{bake}"
    require(f"needs: [Detect-Changes, Bake-Prebuilts-{bake}]" in deploy_workflow
            and "needs.Detect-Changes.result == 'success'" in deploy_workflow,
            f"{consumer} must not consume stale prebuilts after failed change detection/bake")
require("file(LOCK" in recipes_bootstrap
        and "tribe-recipes-bootstrap.lock" in recipes_bootstrap
        and "RESULT_VARIABLE _tribe_conan_result" in recipes_bootstrap
        and "Conan ${description} failed" in recipes_bootstrap,
        "Conan recipe bootstrap must serialize shared-cache writes and fail closed")
require("deploy/build/AmneziaVPN_*_linux_x64" not in deploy_workflow
        and "deploy/build/AmneziaVPN_*_windows_x64" not in deploy_workflow
        and "Expected exactly one Tribe WIX artifact" in deploy_workflow,
        "desktop CI upload names/counts must match CPack outputs")
for xpath in ("bundle-version/bundle", "strict-identifier/bundle",
              "upgrade-bundle/bundle", "relocate/bundle",
              "atomic-update/bundle"):
    require(xpath in deploy_workflow,
            f"final product archive policy lost PackageInfo assertion {xpath}")
for evidence in ("string(/pkg-info/@version)", "CFBundleIdentifier",
                 "CFBundleExecutable", "CFBundleShortVersionString",
                 "CFBundleVersion", "codesign --verify --deep --strict",
                 "tribe-svc.tar.sha256", "migrate-macos-legacy-app.sh"):
    require(evidence in deploy_workflow,
            f"final expanded macOS artifact gate lost {evidence}")

print("Platform runtime static gates passed; Android Play versionCodes: "
      + ",".join(str(value) for value in android_track_version_codes))
