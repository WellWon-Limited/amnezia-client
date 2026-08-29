package org.amnezia.vpn

import android.content.Context
import android.os.Build
import android.os.Process
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject

/**
 * Versioned Android-Keystore envelope for bearer VPN profiles.
 *
 * Nothing secret is stored in SharedPreferences, an Intent, or a caller
 * supplied path.  Handoff records are one-shot and recovery is an explicit
 * encrypted record in noBackupFilesDir.  There is deliberately no plaintext
 * fallback when the keystore is locked, missing, or corrupt.
 */
object AndroidVpnConfigVault {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "tribe.vpn.profile.aes-gcm.v1"
    private const val MAGIC = 0x54525631 // TRV1
    // Schema 2 authenticates the independent C++ dispatch digest and Android Builder policy.
    // Schema-1 records are intentionally not migrated: ambiguity after an upgrade is fail-closed.
    private const val SCHEMA = 2
    private const val MAX_PROFILE_BYTES = 2 * 1024 * 1024
    private const val MAX_RECOVERY_METADATA_BYTES = 32 * 1024
    private const val MAX_PLAINTEXT_BYTES = MAX_PROFILE_BYTES + MAX_RECOVERY_METADATA_BYTES
    private const val MAX_RECORD_BYTES = MAX_PLAINTEXT_BYTES + 16 * 1024
    private const val NONCE_BYTES = 12
    private const val PURPOSE_HANDOFF = "handoff"
    private const val PURPOSE_RECOVERY = "recovery"
    private const val PURPOSE_GUARD_RECONCILIATION = "guard-reconciliation"
    private const val GUARD_RECONCILIATION_RECORD_ID = "active"
    private const val GUARD_RECONCILIATION_GENERATION = "journal-v1"
    private val EMPTY_SHA256 = "0".repeat(64)
    private const val AAD_DOMAIN = "tribe-vpn-profile-v2"
    private val random = SecureRandom()

    data class RecoveryRecord(
        val config: String,
        val sessionGeneration: String,
        val dispatchPolicySha256: String,
        val tunnelPolicySha256: String,
        val authority: RuntimeAuthority,
        val clockAnchor: RuntimeAuthorityAnchor,
        val nativeGuardLease: NativeGuardLease? = null,
    )

    /**
     * Bearer-free exact owner snapshot for app/service process recovery.  The enclosing
     * AES-GCM record already authenticates the full native profile and both policy hashes.
     */
    data class NativeGuardLease(
        val operation: String,
        val session: String,
        val outerSessionId: String,
        val expectedRuntimeSessionId: String,
        val state: String,
    ) {
        init {
            NativeSessionGuardContract.RequestIdentity(
                operation, session, expectedRuntimeSessionId,
            )
            NativeSessionGuardContract.requireOuterSessionId(outerSessionId)
            require(state in setOf(
                    "blackhole", "running", "starting", "stopping", "quarantined", "releasing",
                )) {
                "Invalid persisted native guard state"
            }
        }

        fun toJson(): JSONObject = JSONObject()
            .put("operation", operation)
            .put("session", session)
            .put("outer_session_id", outerSessionId)
            .put("expected_runtime_session_id", expectedRuntimeSessionId)
            .put("state", state)

        companion object {
            fun fromJson(value: JSONObject): NativeGuardLease {
                require(value.keys().asSequence().toSet() == setOf(
                    "operation", "session", "outer_session_id",
                    "expected_runtime_session_id", "state",
                )) { "Invalid encrypted native guard lease shape" }
                return NativeGuardLease(
                    value.getString("operation"),
                    value.getString("session"),
                    value.getString("outer_session_id"),
                    value.getString("expected_runtime_session_id"),
                    value.getString("state"),
                )
            }
        }
    }

    private data class EnvelopeHeader(
        val purpose: String,
        val recordId: String,
        val sessionGeneration: String,
        val dispatchPolicySha256: String,
        val tunnelPolicySha256: String,
        val nonce: ByteArray,
        val ciphertext: ByteArray,
    )

    fun stage(context: Context, config: String): String {
        validateConfig(config)
        val recordId = canonicalUuid(UUID.randomUUID().toString())
        val destination = handoffFile(context, recordId)
        writeEnvelope(
            context,
            destination,
            PURPOSE_HANDOFF,
            recordId,
            sessionGeneration = "pending",
            dispatchPolicySha256 = "pending",
            tunnelPolicySha256 = "pending",
            plaintext = config,
        )
        return recordId
    }

    fun consume(context: Context, opaqueReference: String?): String? {
        val recordId = opaqueReference?.let(::canonicalUuid) ?: return null
        val file = handoffFile(context, recordId)
        val claim = File(vaultDirectory(context),
            "claimed-$recordId-${UUID.randomUUID().toString().lowercase()}.v1")
        return try {
            Files.move(file.toPath(), claim.toPath(), StandardCopyOption.ATOMIC_MOVE)
            val envelope = readEnvelope(context, claim, PURPOSE_HANDOFF, recordId)
            decrypt(context, envelope).also(::validateConfig)
        } finally {
            secureDelete(claim)
        }
    }

    fun storeRecovery(
        context: Context,
        config: String,
        sessionGeneration: String,
        dispatchPolicySha256: String,
        tunnelPolicySha256: String,
        authority: RuntimeAuthority,
        clockAnchor: RuntimeAuthorityAnchor,
        nativeGuardLease: NativeGuardLease? = null,
    ) {
        validateConfig(config)
        require(isBoundedToken(sessionGeneration, 160)) { "Invalid session generation" }
        require(isSha256(dispatchPolicySha256) && isSha256(tunnelPolicySha256)) {
            "Invalid recovery policy digest"
        }
        require(dispatchPolicySha256 == authority.dispatchPolicySha256) {
            "Recovery dispatch digest does not match authority"
        }
        require(clockAnchor.trustedEpochMillis >= authority.trustedUtcAtDispatch.toEpochMilli()
            && clockAnchor.trustedEpochMillis < authority.hardDeadline.toEpochMilli()) {
            "Runtime authority anchor mismatch"
        }
        val recoveryPayload = JSONObject()
            .put("schema_version", 2)
            .put("config", config)
            .put("clock_anchor", JSONObject()
                .put("trusted_epoch_ms", canonicalLong(clockAnchor.trustedEpochMillis))
                .put("observed_wall_ms", canonicalLong(clockAnchor.observedWallMillis))
                .put("elapsed_realtime_ms", canonicalLong(clockAnchor.elapsedRealtimeMillis))
                .put("boot_id", clockAnchor.bootId))
            .put("native_guard_lease", nativeGuardLease?.toJson() ?: JSONObject.NULL)
            .toString()
        require(recoveryPayload.toByteArray(StandardCharsets.UTF_8).size <= MAX_PLAINTEXT_BYTES) {
            "Encrypted recovery payload is oversized"
        }
        writeEnvelope(
            context,
            recoveryFile(context),
            PURPOSE_RECOVERY,
            recordId = "active",
            sessionGeneration = sessionGeneration,
            dispatchPolicySha256 = dispatchPolicySha256,
            tunnelPolicySha256 = tunnelPolicySha256,
            plaintext = recoveryPayload,
        )
    }

    fun loadRecovery(context: Context): RecoveryRecord? {
        val file = recoveryFile(context)
        if (!file.exists()) return null
        val envelope = readEnvelope(context, file, PURPOSE_RECOVERY, "active")
        val payload = parseRecoveryPayload(decrypt(context, envelope))
        val config = payload.getString("config")
        validateConfig(config)
        val authority = RuntimeAuthority.fromConfig(JSONObject(config))
            ?: throw SecurityException("Encrypted recovery has no runtime authority")
        require(envelope.dispatchPolicySha256 == authority.dispatchPolicySha256) {
            "Encrypted recovery dispatch digest mismatch"
        }
        val clock = payload.getJSONObject("clock_anchor")
        require(clock.keys().asSequence().toSet() == setOf(
            "trusted_epoch_ms", "observed_wall_ms", "elapsed_realtime_ms", "boot_id",
        )) { "Invalid runtime authority anchor shape" }
        val anchor = RuntimeAuthorityAnchor(
            parseCanonicalLong(clock.getString("trusted_epoch_ms")),
            parseCanonicalLong(clock.getString("observed_wall_ms")),
            parseCanonicalLong(clock.getString("elapsed_realtime_ms")),
            clock.getString("boot_id"),
        )
        require(anchor.trustedEpochMillis >= authority.trustedUtcAtDispatch.toEpochMilli()
            && anchor.trustedEpochMillis < authority.hardDeadline.toEpochMilli()) {
            "Encrypted runtime authority anchor mismatch"
        }
        return RecoveryRecord(
            config = config,
            sessionGeneration = envelope.sessionGeneration,
            dispatchPolicySha256 = envelope.dispatchPolicySha256,
            tunnelPolicySha256 = envelope.tunnelPolicySha256,
            authority = authority,
            clockAnchor = anchor,
            nativeGuardLease = payload.optJSONObject("native_guard_lease")
                ?.let(NativeGuardLease::fromJson),
        )
    }

    /**
     * Persists only bearer-free exact terminal guard facts.  It deliberately survives
     * [wipe], which clears the active VPN profile during RELEASE: the reducer may need this
     * tombstone after the original Released event was lost or the service process restarted.
     */
    fun storeGuardReconciliationJournal(
        context: Context,
        records: List<NativeGuardReconciliationJournal.Record>,
    ) {
        require(records.size <= NativeGuardReconciliationJournal.MAX_RECORDS) {
            "Oversized guard reconciliation journal"
        }
        // Reconstruct once to reject duplicate identities before sealing the journal.
        NativeGuardReconciliationJournal(records)
        val payload = JSONObject()
            .put("schema_version", 1)
            .put("records", JSONArray().also { array ->
                records.forEach { record ->
                    array.put(JSONObject()
                        .put("operation", record.operation)
                        .put("session", record.session)
                        .put("policy_sha256", record.policySha256)
                        .put("outer_session_id", record.outerSessionId)
                        .put("expected_runtime_session_id", record.expectedRuntimeSessionId)
                        .put("outcome", record.outcome.wireValue))
                }
            })
            .toString()
        writeEnvelope(
            context,
            guardReconciliationFile(context),
            PURPOSE_GUARD_RECONCILIATION,
            GUARD_RECONCILIATION_RECORD_ID,
            GUARD_RECONCILIATION_GENERATION,
            EMPTY_SHA256,
            EMPTY_SHA256,
            payload,
        )
    }

    fun loadGuardReconciliationJournal(
        context: Context,
    ): List<NativeGuardReconciliationJournal.Record> {
        val file = guardReconciliationFile(context)
        if (!file.exists()) return emptyList()
        val envelope = readEnvelope(
            context, file, PURPOSE_GUARD_RECONCILIATION,
            GUARD_RECONCILIATION_RECORD_ID,
        )
        require(envelope.sessionGeneration == GUARD_RECONCILIATION_GENERATION
            && envelope.dispatchPolicySha256 == EMPTY_SHA256
            && envelope.tunnelPolicySha256 == EMPTY_SHA256) {
            "Guard reconciliation journal metadata mismatch"
        }
        val root = JSONObject(decrypt(context, envelope))
        require(root.keys().asSequence().toSet() == setOf("schema_version", "records")
            && root.opt("schema_version") is Int && root.getInt("schema_version") == 1
            && root.opt("records") is JSONArray) {
            "Invalid guard reconciliation journal shape"
        }
        val array = root.getJSONArray("records")
        require(array.length() <= NativeGuardReconciliationJournal.MAX_RECORDS) {
            "Oversized guard reconciliation journal"
        }
        val records = (0 until array.length()).map { index ->
            val record = array.getJSONObject(index)
            require(record.keys().asSequence().toSet() == setOf(
                "operation", "session", "policy_sha256", "outer_session_id",
                "expected_runtime_session_id", "outcome",
            )) { "Invalid guard reconciliation record shape" }
            NativeGuardReconciliationJournal.Record(
                record.getString("operation"),
                record.getString("session"),
                record.getString("policy_sha256"),
                record.getString("outer_session_id"),
                record.getString("expected_runtime_session_id"),
                NativeGuardReconciliationJournal.Outcome.fromWireValue(
                    record.getString("outcome"),
                ),
            )
        }
        return NativeGuardReconciliationJournal(records).snapshot()
    }

    fun wipe(context: Context) {
        secureDelete(recoveryFile(context))
        vaultDirectory(context).listFiles()?.forEach { file ->
            if (file.name.startsWith("handoff-") || file.name.startsWith("claimed-")
                || file.name.endsWith(".tmp")) {
                secureDelete(file)
            }
        }
    }

    private fun writeEnvelope(
        context: Context,
        destination: File,
        purpose: String,
        recordId: String,
        sessionGeneration: String,
        dispatchPolicySha256: String,
        tunnelPolicySha256: String,
        plaintext: String,
    ) {
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        // Some providers replace the supplied nonce; persist the actual one.
        val actualNonce = cipher.iv ?: nonce
        val aad = aad(
            context, purpose, recordId, sessionGeneration,
            dispatchPolicySha256, tunnelPolicySha256,
        )
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))

        val bytes = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { output ->
                output.writeInt(MAGIC)
                output.writeInt(SCHEMA)
                output.writeUTF(purpose)
                output.writeUTF(recordId)
                output.writeUTF(sessionGeneration)
                output.writeUTF(dispatchPolicySha256)
                output.writeUTF(tunnelPolicySha256)
                output.writeInt(actualNonce.size)
                output.write(actualNonce)
                output.writeInt(ciphertext.size)
                output.write(ciphertext)
            }
            buffer.toByteArray()
        }
        require(bytes.size <= MAX_RECORD_BYTES) { "Encrypted profile is oversized" }

        val directory = vaultDirectory(context)
        val temporary = File(directory, ".${destination.name}.${UUID.randomUUID()}.tmp")
        try {
            temporary.outputStream().use { stream ->
                stream.write(bytes)
                stream.flush()
                stream.fd.sync()
            }
            setOwnerOnly(temporary)
            Files.move(temporary.toPath(), destination.toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            setOwnerOnly(destination)
            syncDirectory(directory)
        } finally {
            secureDelete(temporary)
        }
    }

    private fun readEnvelope(
        context: Context,
        file: File,
        expectedPurpose: String,
        expectedRecordId: String,
    ): EnvelopeHeader {
        val canonicalParent = file.parentFile?.canonicalFile
        require(canonicalParent == vaultDirectory(context).canonicalFile) { "Invalid vault path" }
        val descriptor = Os.open(file.absolutePath,
            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
        var streamOwnsDescriptor = false
        val bytes = try {
            val stat = Os.fstat(descriptor)
            require((stat.st_mode and OsConstants.S_IFMT) == OsConstants.S_IFREG
                && stat.st_uid == Process.myUid()
                && (stat.st_mode and 0x1FF) == 0x180
                && stat.st_nlink == 1L
                && stat.st_size in 1..MAX_RECORD_BYTES.toLong()) {
                "Invalid encrypted VPN profile record"
            }
            val stream = FileInputStream(descriptor)
            streamOwnsDescriptor = true
            stream.use { it.readBytes(MAX_RECORD_BYTES + 1) }
        } finally {
            if (!streamOwnsDescriptor) runCatching { Os.close(descriptor) }
        }
        require(bytes.size <= MAX_RECORD_BYTES) { "Encrypted VPN profile is oversized" }
        return DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            require(input.readInt() == MAGIC && input.readInt() == SCHEMA) { "Unsupported vault schema" }
            val purpose = input.readUTF()
            val recordId = input.readUTF()
            val sessionGeneration = input.readUTF()
            val dispatchPolicySha256 = input.readUTF()
            val tunnelPolicySha256 = input.readUTF()
            require(purpose == expectedPurpose && recordId == expectedRecordId) { "Vault binding mismatch" }
            require(isBoundedToken(sessionGeneration, 160)
                && ((dispatchPolicySha256 == "pending" && tunnelPolicySha256 == "pending")
                    || (isSha256(dispatchPolicySha256) && isSha256(tunnelPolicySha256)))) {
                "Invalid vault metadata"
            }
            val nonceSize = input.readInt()
            require(nonceSize == NONCE_BYTES) { "Invalid vault nonce" }
            val nonce = ByteArray(nonceSize).also(input::readFully)
            val ciphertextSize = input.readInt()
            require(ciphertextSize in 16..MAX_PLAINTEXT_BYTES + 32) { "Invalid vault ciphertext" }
            val ciphertext = ByteArray(ciphertextSize).also(input::readFully)
            require(input.read() == -1) { "Trailing vault data" }
            EnvelopeHeader(
                purpose, recordId, sessionGeneration,
                dispatchPolicySha256, tunnelPolicySha256, nonce, ciphertext,
            )
        }
    }

    private fun decrypt(context: Context, envelope: EnvelopeHeader): String {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, envelope.nonce))
            cipher.updateAAD(aad(
                context,
                envelope.purpose,
                envelope.recordId,
                envelope.sessionGeneration,
                envelope.dispatchPolicySha256,
                envelope.tunnelPolicySha256,
            ))
            val plaintext = cipher.doFinal(envelope.ciphertext)
            require(plaintext.size <= MAX_PLAINTEXT_BYTES) { "VPN profile payload is oversized" }
            plaintext.toString(StandardCharsets.UTF_8).also {
                require(it.isNotBlank()) { "Blank VPN profile payload" }
            }
        } catch (error: AEADBadTagException) {
            throw SecurityException("Encrypted VPN profile authentication failed", error)
        }
    }

    private fun key(): SecretKey {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) { "Android Keystore AES-GCM unavailable" }
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build()
        )
        return generator.generateKey()
    }

    private fun aad(
        context: Context,
        purpose: String,
        recordId: String,
        sessionGeneration: String,
        dispatchPolicySha256: String,
        tunnelPolicySha256: String,
    ): ByteArray = aadComponents(
        context.packageName,
        purpose,
        recordId,
        sessionGeneration,
        dispatchPolicySha256,
        tunnelPolicySha256,
    ).joinToString("\u0000").toByteArray(StandardCharsets.UTF_8)

    /**
     * Stable authenticated binding for an app-private Keystore record. The non-exportable
     * Android Keystore key and owner-only noBackupFilesDir already bind ciphertext to this app
     * installation; adding a hardware identifier would provide no additional security boundary.
     */
    internal fun aadComponents(
        packageName: String,
        purpose: String,
        recordId: String,
        sessionGeneration: String,
        dispatchPolicySha256: String,
        tunnelPolicySha256: String,
    ): List<String> {
        require(packageName.isNotBlank()) { "VPN vault package binding unavailable" }
        return listOf(
            AAD_DOMAIN,
            packageName,
            purpose,
            recordId,
            sessionGeneration,
            dispatchPolicySha256,
            tunnelPolicySha256,
        )
    }

    private fun vaultDirectory(context: Context): File =
        File(context.noBackupFilesDir, "tribe-vpn-vault").also { directory ->
            require(directory.exists() || directory.mkdirs()) { "Unable to create VPN vault" }
            setOwnerOnly(directory)
            val stat = Os.lstat(directory.absolutePath)
            require((stat.st_mode and OsConstants.S_IFMT) == OsConstants.S_IFDIR
                && stat.st_uid == Process.myUid()
                && (stat.st_mode and 0x1FF) == 0x1C0) { "Insecure VPN vault directory" }
        }

    private fun handoffFile(context: Context, recordId: String) =
        File(vaultDirectory(context), "handoff-$recordId.v1")

    private fun recoveryFile(context: Context) = File(vaultDirectory(context), "recovery.v1")

    private fun guardReconciliationFile(context: Context) =
        File(vaultDirectory(context), "guard-reconciliation.v1")

    private fun setOwnerOnly(file: File) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Os.chmod(file.absolutePath, if (file.isDirectory) 0x1C0 else 0x180) // 0700 / 0600
        } else {
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setExecutable(false, false)
            file.setReadable(true, true)
            file.setWritable(true, true)
            if (file.isDirectory) file.setExecutable(true, true)
        }
    }

    private fun syncDirectory(directory: File) {
        val descriptor = Os.open(directory.absolutePath,
            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
        try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
    }

    private fun secureDelete(file: File) {
        runCatching { if (file.exists()) file.delete() }
    }

    private fun canonicalUuid(value: String): String {
        val parsed = UUID.fromString(value)
        val canonical = parsed.toString().lowercase()
        require(value == canonical) { "Non-canonical opaque VPN config reference" }
        return canonical
    }

    private fun validateConfig(config: String) {
        require(config.isNotBlank()) { "Blank VPN profile" }
        require(config.toByteArray(StandardCharsets.UTF_8).size <= MAX_PROFILE_BYTES) {
            "VPN profile is oversized"
        }
    }

    private fun parseRecoveryPayload(value: String): JSONObject {
        val payload = JSONObject(value)
        require(payload.keys().asSequence().toSet()
            == setOf("schema_version", "config", "clock_anchor", "native_guard_lease")) {
            "Invalid encrypted recovery payload shape"
        }
        val schema = payload.opt("schema_version")
        require(schema is Int && schema == 2
            && payload.opt("config") is String
            && payload.opt("clock_anchor") is JSONObject
            && (payload.isNull("native_guard_lease")
                || payload.opt("native_guard_lease") is JSONObject)) {
            "Invalid encrypted recovery payload"
        }
        return payload
    }

    private fun canonicalLong(value: Long): String {
        require(value >= 0L) { "Negative runtime authority anchor" }
        return value.toString()
    }

    private fun parseCanonicalLong(value: String): Long {
        require(value == "0" || (value.firstOrNull() in '1'..'9' && value.all { it in '0'..'9' })) {
            "Non-canonical runtime authority anchor"
        }
        return value.toLongOrNull()
            ?: throw IllegalArgumentException("Runtime authority anchor overflow")
    }

    private fun isBoundedToken(value: String, maximum: Int): Boolean =
        value.isNotBlank() && value.length <= maximum && value.all {
            it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' ||
                it == '-' || it == '_' || it == ':' || it == '.'
        }

    private fun isSha256(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
}

private fun java.io.InputStream.readBytes(limit: Int): ByteArray {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    var total = 0
    while (true) {
        val count = read(buffer)
        if (count < 0) break
        total += count
        require(total <= limit) { "Input is oversized" }
        output.write(buffer, 0, count)
    }
    return output.toByteArray()
}
