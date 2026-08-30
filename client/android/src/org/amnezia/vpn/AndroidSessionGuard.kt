package org.amnezia.vpn

/**
 * Exact identity/policy state for the service-owned Android TUN guard.
 * This class is framework-free on purpose so transition races are host-testable.
 */
class AndroidSessionGuard {
    data class Snapshot(
        val ownerSessionId: String? = null,
        val policyHash: String? = null,
        val activeInnerToken: String? = null,
        val state: String = "disarmed",
    ) {
        val armed: Boolean get() = ownerSessionId != null
        val blackholed: Boolean get() = armed && activeInnerToken == null
    }

    private var current = Snapshot()

    @Synchronized
    fun snapshot(): Snapshot = current.copy()

    @Synchronized
    fun arm(ownerSessionId: String, policyHash: String) {
        require(current.state == "disarmed") { "Session guard is already armed" }
        require(validToken(ownerSessionId) && validHash(policyHash)) { "Invalid guard identity" }
        current = Snapshot(ownerSessionId, policyHash, null, "blackhole")
    }

    /** Transfers an unchanged, still-established blackholed TUN to a new coordinator attempt. */
    @Synchronized
    fun replaceBlackhole(
        exactPreviousOwnerSessionId: String,
        replacementOwnerSessionId: String,
        replacementPolicyHash: String,
    ) {
        requireOwner(exactPreviousOwnerSessionId)
        require(current.state == "blackhole" && current.activeInnerToken == null) {
            "Outer guard replacement requires an exact blackhole receipt"
        }
        require(validToken(replacementOwnerSessionId) && replacementOwnerSessionId != exactPreviousOwnerSessionId) {
            "Invalid replacement guard identity"
        }
        require(replacementPolicyHash == current.policyHash) {
            "Android outer policy cannot change without rebuilding the TUN"
        }
        current = Snapshot(replacementOwnerSessionId, replacementPolicyHash, null, "blackhole")
    }

    /**
     * Validates the state immediately before Android's documented seamless-handover establish().
     * The caller must not commit below unless Builder.establish() returned a new descriptor: on
     * failure Android leaves the old interface and descriptor untouched.
     */
    @Synchronized
    fun validateBlackholeTunHandover(
        exactPreviousOwnerSessionId: String,
        replacementOwnerSessionId: String,
        replacementPolicyHash: String,
    ) {
        requireOwner(exactPreviousOwnerSessionId)
        require(current.state == "blackhole" && current.activeInnerToken == null) {
            "Outer TUN handover requires an exact blackhole receipt"
        }
        require(validToken(replacementOwnerSessionId)
            && replacementOwnerSessionId != exactPreviousOwnerSessionId
            && validHash(replacementPolicyHash)) {
            "Invalid replacement guard identity"
        }
    }

    /** Commits ownership only after the OS atomically activated the replacement interface. */
    @Synchronized
    fun commitBlackholeTunHandover(
        exactPreviousOwnerSessionId: String,
        replacementOwnerSessionId: String,
        replacementPolicyHash: String,
    ) {
        validateBlackholeTunHandover(
            exactPreviousOwnerSessionId, replacementOwnerSessionId, replacementPolicyHash,
        )
        current = Snapshot(replacementOwnerSessionId, replacementPolicyHash, null, "blackhole")
    }

    @Synchronized
    fun markInnerReady(
        ownerSessionId: String,
        innerToken: String,
        receiptPolicyHash: String,
    ) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == innerToken && current.state == "starting") {
            "Inner start receipt does not match the pending engine"
        }
        require(validToken(innerToken) && receiptPolicyHash == current.policyHash) {
            "Inner receipt does not match guarded policy"
        }
        current = current.copy(activeInnerToken = innerToken, state = "running")
    }

    @Synchronized
    fun beginInnerStart(ownerSessionId: String, innerToken: String, policyHash: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == null && current.state == "blackhole") {
            "Inner replacement overlaps an active engine"
        }
        require(validToken(innerToken) && policyHash == current.policyHash) {
            "Inner start does not match guarded policy"
        }
        current = current.copy(activeInnerToken = innerToken, state = "starting")
    }

    @Synchronized
    fun confirmInnerStartAborted(ownerSessionId: String, innerToken: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == innerToken && current.state == "starting") {
            "Inner abort receipt mismatch"
        }
        current = current.copy(activeInnerToken = null, state = "blackhole")
    }

    @Synchronized
    fun quarantineInnerStart(ownerSessionId: String, innerToken: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == innerToken && current.state == "starting") {
            "Inner start quarantine mismatch"
        }
        current = current.copy(state = "quarantined")
    }

    /** Deadline/bind failures quarantine ownership before native teardown is attempted. */
    @Synchronized
    fun quarantineActiveInner(ownerSessionId: String, exactInnerToken: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == exactInnerToken
            && current.state in setOf("starting", "running", "stopping")) {
            "Active inner quarantine mismatch"
        }
        current = current.copy(state = "quarantined")
    }

    /** Positive native stop receipt retains quarantine until the reducer sends exact recovery. */
    @Synchronized
    fun confirmQuarantinedInnerStopped(ownerSessionId: String, exactInnerToken: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == exactInnerToken && current.state == "quarantined") {
            "Quarantined inner stop receipt mismatch"
        }
        current = current.copy(activeInnerToken = null)
    }

    @Synchronized
    fun proveQuarantinedInnerStopped(ownerSessionId: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == null && current.state == "quarantined") {
            "Quarantined inner teardown is not proven"
        }
        current = current.copy(state = "blackhole")
    }

    @Synchronized
    fun beginInnerStop(ownerSessionId: String, exactInnerToken: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == exactInnerToken && current.state == "running") {
            "Stale inner stop"
        }
        current = current.copy(state = "stopping")
    }

    /** A thrown native stop is ambiguous; retain the exact inner owner behind the outer TUN. */
    @Synchronized
    fun quarantineStoppingInner(ownerSessionId: String, exactInnerToken: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == exactInnerToken && current.state == "stopping") {
            "Stopping inner quarantine mismatch"
        }
        current = current.copy(state = "quarantined")
    }

    @Synchronized
    fun confirmInnerStopped(ownerSessionId: String, exactInnerToken: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == exactInnerToken && current.state == "stopping") {
            "Inner stop receipt mismatch"
        }
        current = current.copy(activeInnerToken = null, state = "blackhole")
    }

    @Synchronized
    fun markInnerCrash(ownerSessionId: String, exactInnerToken: String) {
        requireOwner(ownerSessionId)
        require(current.activeInnerToken == exactInnerToken) { "Stale inner crash" }
        current = current.copy(activeInnerToken = null, state = "blackhole")
    }

    @Synchronized
    fun validateReplacement(ownerSessionId: String, policyHash: String) {
        requireOwner(ownerSessionId)
        require(current.state == "blackhole" && current.activeInnerToken == null) {
            "Outer guard is not in replacement blackhole state"
        }
        require(policyHash == current.policyHash) { "Replacement policy mismatch" }
    }

    @Synchronized
    fun disarm(ownerSessionId: String) {
        requireOwner(ownerSessionId)
        require(current.state == "blackhole" && current.activeInnerToken == null) {
            "Cannot disarm before exact inner teardown"
        }
        current = Snapshot()
    }

    /** OS revoke/process-owner loss is not a clean release and may occur in any inner state. */
    @Synchronized
    fun markOuterLost(exactOwnerSessionId: String) {
        requireOwner(exactOwnerSessionId)
        current = Snapshot()
    }

    @Synchronized
    fun canAdopt(ownerSessionId: String, policyHash: String): Boolean =
        current.ownerSessionId == ownerSessionId && current.policyHash == policyHash &&
            current.state in setOf("blackhole", "starting", "running", "stopping", "quarantined")

    private fun requireOwner(ownerSessionId: String) {
        require(current.ownerSessionId == ownerSessionId) { "Foreign outer VPN session" }
    }

    private fun validToken(value: String): Boolean =
        value.isNotBlank() && value.length <= 200 && value.all {
            it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' ||
                it == '-' || it == '_' || it == ':' || it == '.'
        }

    private fun validHash(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
}
