from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def section(source: str, start: str, end: str) -> str:
    start_offset = source.index(start)
    return source[start_offset:source.index(end, start_offset)]


class AndroidGuardLifecycleSourceTest(unittest.TestCase):
    def test_activate_persists_running_before_ready_and_watchdog(self) -> None:
        service = read("client/android/src/org/amnezia/vpn/AmneziaVpnService.kt")
        body = section(
            service,
            "private suspend fun executeActivateNativeSession",
            "private fun stopNativeSession",
        )
        order = [
            body.index("require(receipt.exactSessionToken == innerToken)"),
            body.index('persistCatalogGuardLease(lease, "running")'),
            body.index("sessionGuard.markInnerReady("),
            body.index("launchAuthorityWatchdog(lease.serviceSessionId)"),
        ]
        self.assertEqual(sorted(order), order)
        self.assertIn("protocol.abortInnerStart(innerToken)", body)

    def test_thrown_exact_stop_quarantines_and_persists_before_failure_escape(self) -> None:
        service = read("client/android/src/org/amnezia/vpn/AmneziaVpnService.kt")
        body = section(
            service,
            "private suspend fun executeStopNativeSession",
            "private fun releaseNativeSessionGuard",
        )
        begin = body.index("sessionGuard.beginInnerStop(outer, token)")
        stop = body.index("lease.protocol.stopInner(token)", begin)
        quarantine = body.index("sessionGuard.quarantineStoppingInner(outer, token)", stop)
        persist = body.index('persistCatalogGuardLease(lease, "quarantined")', quarantine)
        rethrow = body.index("throw error", persist)
        self.assertEqual(sorted((begin, stop, quarantine, persist, rethrow)),
                         [begin, stop, quarantine, persist, rethrow])

    def test_pre_native_failures_remain_owned_and_detach_only_at_jni_seams(self) -> None:
        service = read("client/android/src/org/amnezia/vpn/AmneziaVpnService.kt")
        duplicate = section(
            service,
            "private fun startWithDuplicatedTun",
            "private suspend fun startSessionOwnedProtocol",
        )
        self.assertNotIn("ParcelFileDescriptor.adoptFd", duplicate)
        self.assertIn("ParcelFileDescriptor.dup(owner.fileDescriptor).use", duplicate)
        self.assertIn("val protectCallback: (Int) -> Boolean = ::protect", duplicate)
        self.assertRegex(
            duplicate,
            r"protocol\.startWithTun\(\s*prepared, duplicate\.detachFd\(\), "
            r"exactSessionToken, protectCallback,",
        )

        protocol = read("client/android/protocolApi/src/main/kotlin/Protocol.kt")
        self.assertIn("Ownership of [tunFd] transfers to the protocol at call entry", protocol)
        self.assertIn("ParcelFileDescriptor.adoptFd(tunFd).use", protocol)

        awg = read(
            "client/android/wireguard/src/main/kotlin/"
            "org/amnezia/vpn/protocol/wireguard/Wireguard.kt"
        )
        self.assertIn("val ownedTun = ParcelFileDescriptor.adoptFd(tunFd)", awg)
        self.assertLess(awg.index("config.toWgUserspaceString()"),
                        awg.index("val tunFd = ownedTun.detachFd()"))
        self.assertRegex(
            awg,
            r"val tunFd = ownedTun\.detachFd\(\)\s+"
            r"tunnelHandle = GoBackend\.awgPrepareProtected\(",
        )

        xray = read("client/android/xray/src/main/kotlin/Xray.kt")
        self.assertIn("val ownedTun = ParcelFileDescriptor.adoptFd(tunFd)", xray)
        self.assertNotIn("tunFdTransferred", xray)
        self.assertRegex(
            xray,
            r"val transferredFd = ownedTun\.detachFd\(\)\s+"
            r"LibXray\.startTun2Socks\(",
        )

    def test_process_loss_proves_catalog_stop_before_scope_cancel_or_kills(self) -> None:
        service = read("client/android/src/org/amnezia/vpn/AmneziaVpnService.kt")
        destroy = section(service, "override fun onDestroy()", "private fun stopService")
        close = destroy.index("nativeGuardCommands.close()")
        proof = destroy.index(
            'boundedCatalogGuardTeardownForProcessLoss(lease, "service_destroyed")'
        )
        cancel = destroy.index("connectionScope.cancel()")
        self.assertLess(close, proof)
        self.assertLess(proof, cancel)
        self.assertNotIn("stopNativeSession(", destroy)
        self.assertIn('terminateVpnProcessFailClosed("service_destroyed")', destroy)
        self.assertIn(
            'terminateVpnProcessFailClosed("service_destroyed_legacy_guard")',
            destroy,
        )

        revoke = section(service, "override fun onRevoke()", "override fun onDestroy()")
        self.assertNotIn("runCatching { lease.protocol.stopInner", revoke)
        self.assertIn(
            'boundedCatalogGuardTeardownForProcessLoss(lease, "vpn_permission_revoked")',
            revoke,
        )
        self.assertIn('terminateVpnProcessFailClosed("vpn_permission_revoked")', revoke)
        self.assertIn(
            'terminateVpnProcessFailClosed("vpn_permission_revoked_legacy_guard")',
            revoke,
        )
        self.assertLess(revoke.index("nativeGuardCommands.close()"),
                        revoke.index(
                            'boundedCatalogGuardTeardownForProcessLoss('
                            'lease, "vpn_permission_revoked")'))
        self.assertLess(revoke.index("publishNativeGuardEvent("),
                        revoke.index("stopSelf()"))

        proof_body = section(
            service,
            "private fun boundedCatalogGuardTeardownForProcessLoss",
            "private fun terminateVpnProcessFailClosed",
        )
        self.assertLess(proof_body.index("nativeGuardCommandJob?.cancelAndJoin()"),
                        proof_body.index("protocolOperationMutex.withLock"))
        self.assertLess(proof_body.index("proveCatalogInnerStoppedForProcessLoss"),
                        proof_body.index('persistCatalogGuardLease(exactLease, "blackhole")'))
        self.assertLess(proof_body.index('persistCatalogGuardLease(exactLease, "blackhole")'),
                        proof_body.index("masterTun?.close()"))
        self.assertIn('persistCatalogGuardLease(exactLease, "quarantined")', proof_body)
        self.assertIn("android.os.Process.killProcess(android.os.Process.myPid())", service)
        manifest = read("client/android/AndroidManifest.xml")
        self.assertRegex(
            manifest,
            r'<service\s+android:name="\.TribeVpnService"\s+'
            r'android:process=":tribeVpnService"',
        )

    def test_xray_stop_attempts_all_native_legs_and_aggregates_receipt(self) -> None:
        xray = read("client/android/xray/src/main/kotlin/Xray.kt")
        body = section(xray, "private fun stopNative()", "private fun stopAdapterForStartRollback")
        self.assertIn("val receipt = XrayNativeTeardown.execute(", body)
        order = [
            body.index("clearControllers = { LibXray.clearSocketControllers() }"),
            body.index("stopAdapter = { LibXray.stopTun2Socks() }"),
            body.index("stopCore = { LibXray.stopXray() }"),
            body.index("if (!receipt.proven)"),
        ]
        self.assertEqual(sorted(order), order)

        teardown = read("client/android/xray/src/main/kotlin/XrayNativeTeardown.kt")
        self.assertEqual(teardown.count("executeLeg("), 4)  # declaration + three calls
        self.assertIn("catch (_: Throwable)", teardown)
        self.assertIn("controllers.proven && adapter.proven && core.proven", teardown)

    def test_timeout_reconciliation_is_exact_durable_and_never_clears_on_mismatch(self) -> None:
        service = read("client/android/src/org/amnezia/vpn/AmneziaVpnService.kt")
        on_create = section(service, "override fun onCreate()", "private fun unregister")
        self.assertLess(on_create.index("durableGuardBootstrap.await()"),
                        on_create.index("for (command in nativeGuardCommands)"))
        self.assertLess(on_create.index("executeRestoreNativeSessionGuard(recovery)"),
                        on_create.index("durableGuardBootstrap.complete(Unit)"))

        prepare = section(
            service,
            "private suspend fun executePrepareNativeSessionGuard",
            "private fun activateNativeSession",
        )
        self.assertIn("guardReconciliationJournal.blocksPrepare", prepare)
        self.assertIn('"arm_timeout_fenced"', prepare)

        release = section(
            service,
            "private suspend fun executeReleaseNativeSessionGuard",
            "private fun reconcileNativeSessionGuardArm",
        )
        release_order = [
            release.index('persistCatalogGuardLease(lease, "releasing")'),
            release.index("tun.close()"),
            release.index("sessionGuard.disarm"),
            release.index("guardReconciliationJournal.rememberReleased"),
            release.index("persistGuardReconciliationJournal()"),
            release.index("clearCatalogGuardLease(lease)"),
            release.index("publishNativeGuardEvent("),
        ]
        self.assertEqual(sorted(release_order), release_order)
        self.assertIn("releaseMutationStarted", release)
        self.assertIn(
            'terminateVpnProcessFailClosed("guard_release_commit_ambiguous")', release,
        )

        on_create = section(service, "override fun onCreate()", "private fun unregister")
        committed = on_create.index("val releaseAlreadyCommitted")
        committed_wipe = on_create.index("AndroidVpnConfigVault.wipe(applicationContext)", committed)
        restore = on_create.index("executeRestoreNativeSessionGuard(recovery)", committed)
        self.assertLess(committed, committed_wipe)
        self.assertLess(committed_wipe, restore)
        self.assertIn("NativeGuardReconciliationJournal.Outcome.RELEASED", on_create)

        arm_query = section(
            service,
            "private suspend fun executeReconcileNativeSessionGuardArm",
            "private fun reconcileNativeSessionGuardRelease",
        )
        self.assertLess(arm_query.index("rememberArmRejected"),
                        arm_query.index("persistGuardReconciliationJournal()"))
        self.assertLess(arm_query.index("persistGuardReconciliationJournal()"),
                        arm_query.rindex("publishNativeGuardEvent("))
        self.assertIn("if (!exactGuardLease(lease, identity, policy, outer)) return", arm_query)

        release_query = section(
            service,
            "private suspend fun executeReconcileNativeSessionGuardRelease",
            "private fun exactGuardLease",
        )
        self.assertIn("if (!exactGuardLease(lease, identity, policy, outer)) return", release_query)
        self.assertIn('identity, "release_rejected", policy, outer', release_query)
        self.assertIn("NativeGuardReconciliationJournal.Outcome.RELEASED", release_query)
        self.assertNotIn("clearCatalogGuardLease", release_query)

        controller = read("client/platforms/android/android_controller.cpp")
        controller_release = section(
            controller,
            "bool AndroidController::requestSessionGuardReconcileRelease",
            "void AndroidController::requestSessionGuardRecoveryStatus",
        )
        self.assertIn("m_pendingGuardReleaseRequest.isEmpty()", controller_release)
        self.assertIn('"policy_sha256"', controller_release)
        event = section(
            controller,
            "void AndroidController::onSessionGuardEvent",
            "void AndroidController::onSessionGuardRecoveryReceipt",
        )
        self.assertIn("if (!pendingLoss && !armedLoss) return", event)
        self.assertIn("A syntactically valid stale/mismatched receipt", event)

        vault = read("client/android/src/org/amnezia/vpn/AndroidVpnConfigVault.kt")
        wipe = section(vault, "fun wipe(context: Context)", "private fun writeEnvelope")
        self.assertNotIn("guardReconciliationFile", wipe)
        self.assertIn('"releasing"', vault)
        self.assertIn("storeGuardReconciliationJournal", vault)
        self.assertIn("loadGuardReconciliationJournal", vault)


if __name__ == "__main__":
    unittest.main()
