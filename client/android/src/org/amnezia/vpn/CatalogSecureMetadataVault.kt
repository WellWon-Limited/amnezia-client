package org.amnezia.vpn

import android.content.Context
import android.os.Process
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
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
import java.util.Base64
import java.util.UUID
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

/**
 * One Android-Keystore protected item containing the catalog AEAD key and all rollback high-water
 * metadata. This intentionally does not use Prefs/SharedPreferences and has no plaintext fallback.
 */
object CatalogSecureMetadataVault {
    private const val KEY_ALIAS = "tribe.catalog.secure-metadata.aes-gcm.v2"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val FILE_MAGIC = 0x54434d4b // TCMK
    private const val FILE_SCHEMA = 1
    private const val PLAIN_MAGIC = 0x54434d32 // TCM2
    private const val PLAIN_BYTES = 4 + 1 + 8 + 8 + 32 + 32 + 32
    private const val NONCE_BYTES = 12
    private const val MAX_FILE_BYTES = 4096
    private const val MAX_SAFE_REVISION = 9_007_199_254_740_991uL
    private const val AAD_DOMAIN = "tribe-catalog-secure-metadata-v2"
    private const val RECORD_NAME = "metadata.v2"
    private val random = SecureRandom()
    private val mutex = Any()

    internal data class Metadata(
        val key32: ByteArray,
        val storageRevision: ULong,
        val authenticatedRecordSha256: ByteArray,
        val cleared: Boolean,
        val pendingRevision: ULong,
        val pendingRecordSha256: ByteArray,
    ) {
        fun sameAs(other: Metadata): Boolean =
            key32.contentEquals(other.key32)
                && storageRevision == other.storageRevision
                && authenticatedRecordSha256.contentEquals(other.authenticatedRecordSha256)
                && cleared == other.cleared
                && pendingRevision == other.pendingRevision
                && pendingRecordSha256.contentEquals(other.pendingRecordSha256)
    }

    /** Closed result consumed by AndroidCatalogSecureKeyProvider; never throws across JNI. */
    @JvmStatic
    fun load(context: Context, createIfMissing: Boolean): String = synchronized(mutex) {
        try {
            val file = recordFile(context)
            val metadata = if (!file.exists()) {
                if (!createIfMissing) return@synchronized result("missing")
                val initial = Metadata(
                    ByteArray(32).also(random::nextBytes), 0u, byteArrayOf(), true, 0u, byteArrayOf(),
                )
                write(context, initial)
                initial
            } else {
                read(context)
            }
            result("available", metadata)
        } catch (_: UserNotAuthenticatedException) {
            result("unavailable", reason = "keystore_locked")
        } catch (_: KeyPermanentlyInvalidatedException) {
            result("unavailable", reason = "keystore_invalidated")
        } catch (_: AEADBadTagException) {
            result("error", reason = "metadata_authentication_failed")
        } catch (_: SecurityException) {
            result("error", reason = "metadata_security_rejected")
        } catch (_: Throwable) {
            result("error", reason = "metadata_io_failed")
        }
    }

    /** Compare-and-replace while C++ holds the dedicated catalog cross-process lock. */
    @JvmStatic
    fun replace(context: Context, expectedJson: String, replacementJson: String): String =
        synchronized(mutex) {
            try {
                val expected = parseMetadata(JSONObject(expectedJson))
                val replacement = parseMetadata(JSONObject(replacementJson))
                val current = read(context)
                if (!current.sameAs(expected)) {
                    return@synchronized result("error", reason = "metadata_compare_mismatch")
                }
                write(context, replacement)
                result("available", replacement)
            } catch (_: UserNotAuthenticatedException) {
                result("unavailable", reason = "keystore_locked")
            } catch (_: KeyPermanentlyInvalidatedException) {
                result("unavailable", reason = "keystore_invalidated")
            } catch (_: AEADBadTagException) {
                result("error", reason = "metadata_authentication_failed")
            } catch (_: SecurityException) {
                result("error", reason = "metadata_security_rejected")
            } catch (_: Throwable) {
                result("error", reason = "metadata_replace_failed")
            }
        }

    private fun write(context: Context, metadata: Metadata) {
        validate(metadata)
        val plain = encode(metadata)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(create = true))
        cipher.updateAAD(aad(context))
        val encrypted = cipher.doFinal(plain)
        val nonce = cipher.iv ?: throw SecurityException("Catalog metadata nonce unavailable")
        require(nonce.size == NONCE_BYTES && encrypted.size <= MAX_FILE_BYTES) {
            "Catalog metadata envelope invalid"
        }
        val bytes = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { output ->
                output.writeInt(FILE_MAGIC)
                output.writeInt(FILE_SCHEMA)
                output.writeInt(nonce.size)
                output.write(nonce)
                output.writeInt(encrypted.size)
                output.write(encrypted)
            }
            buffer.toByteArray()
        }
        val directory = secureDirectory(context)
        val destination = recordFile(context)
        val temporary = File(directory, ".metadata-${UUID.randomUUID()}.tmp")
        try {
            temporary.outputStream().use { stream ->
                stream.write(bytes)
                stream.flush()
                stream.fd.sync()
            }
            ownerOnly(temporary, false)
            Files.move(
                temporary.toPath(), destination.toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING,
            )
            ownerOnly(destination, false)
            syncDirectory(directory)
        } finally {
            temporary.delete()
            plain.fill(0)
        }
    }

    private fun read(context: Context): Metadata {
        val file = recordFile(context)
        val parent = file.parentFile?.canonicalFile
        require(parent == secureDirectory(context).canonicalFile) { "Catalog metadata path rejected" }
        val descriptor = Os.open(
            file.absolutePath,
            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW,
            0,
        )
        var streamOwnsDescriptor = false
        val bytes = try {
            val stat = Os.fstat(descriptor)
            require((stat.st_mode and OsConstants.S_IFMT) == OsConstants.S_IFREG
                && stat.st_uid == Process.myUid() && (stat.st_mode and 0x1ff) == 0x180
                && stat.st_nlink == 1L && stat.st_size in 1..MAX_FILE_BYTES.toLong()) {
                "Catalog metadata file rejected"
            }
            val stream = FileInputStream(descriptor)
            streamOwnsDescriptor = true
            stream.use { it.readBoundedCatalogBytes(MAX_FILE_BYTES + 1) }
        } finally {
            if (!streamOwnsDescriptor) runCatching { Os.close(descriptor) }
        }
        require(bytes.size <= MAX_FILE_BYTES) { "Catalog metadata envelope oversized" }
        val (nonce, encrypted) = DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            require(input.readInt() == FILE_MAGIC && input.readInt() == FILE_SCHEMA) {
                "Catalog metadata schema rejected"
            }
            val nonceSize = input.readInt()
            require(nonceSize == NONCE_BYTES) { "Catalog metadata nonce rejected" }
            val nonce = ByteArray(nonceSize).also(input::readFully)
            val encryptedSize = input.readInt()
            require(encryptedSize in 16..MAX_FILE_BYTES) { "Catalog metadata cipher rejected" }
            val encrypted = ByteArray(encryptedSize).also(input::readFully)
            require(input.read() == -1) { "Catalog metadata trailing bytes rejected" }
            nonce to encrypted
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(create = false), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad(context))
        val plain = cipher.doFinal(encrypted)
        return try {
            decode(plain).also(::validate)
        } finally {
            plain.fill(0)
        }
    }

    internal fun encode(metadata: Metadata): ByteArray = ByteArrayOutputStream(PLAIN_BYTES).use { buffer ->
        DataOutputStream(buffer).use { output ->
            output.writeInt(PLAIN_MAGIC)
            output.writeByte(if (metadata.cleared) 1 else 0)
            output.writeLong(metadata.storageRevision.toLong())
            output.writeLong(metadata.pendingRevision.toLong())
            output.write(metadata.key32)
            output.write(
                if (metadata.authenticatedRecordSha256.isEmpty()) ByteArray(32)
                else metadata.authenticatedRecordSha256,
            )
            output.write(
                if (metadata.pendingRecordSha256.isEmpty()) ByteArray(32)
                else metadata.pendingRecordSha256,
            )
        }
        buffer.toByteArray().also { require(it.size == PLAIN_BYTES) }
    }

    internal fun decode(bytes: ByteArray): Metadata = DataInputStream(ByteArrayInputStream(bytes)).use { input ->
        require(bytes.size == PLAIN_BYTES && input.readInt() == PLAIN_MAGIC) {
            "Catalog metadata plaintext schema rejected"
        }
        val flags = input.readUnsignedByte()
        require(flags == 0 || flags == 1) { "Catalog metadata flags rejected" }
        val revision = input.readLong().toULong()
        val pending = input.readLong().toULong()
        val key = ByteArray(32).also(input::readFully)
        val record = ByteArray(32).also(input::readFully)
        val pendingRecord = ByteArray(32).also(input::readFully)
        require(input.read() == -1) { "Catalog metadata plaintext trailing data" }
        Metadata(
            key,
            revision,
            record.takeUnless { revision == 0uL && it.all { byte -> byte == 0.toByte() } }
                ?: byteArrayOf(),
            flags == 1,
            pending,
            pendingRecord.takeUnless { pending == 0uL && it.all { byte -> byte == 0.toByte() } }
                ?: byteArrayOf(),
        )
    }

    internal fun validate(metadata: Metadata) {
        require(metadata.key32.size == 32) { "Catalog metadata key rejected" }
        require(metadata.storageRevision <= MAX_SAFE_REVISION
            && metadata.pendingRevision <= MAX_SAFE_REVISION) {
            "Catalog metadata revision rejected"
        }
        if (metadata.storageRevision == 0uL) {
            require(metadata.authenticatedRecordSha256.isEmpty() && metadata.cleared) {
                "Initial catalog metadata rejected"
            }
        } else {
            require(metadata.authenticatedRecordSha256.size == 32) {
                "Catalog metadata record digest rejected"
            }
        }
        require((metadata.pendingRevision == 0uL) == metadata.pendingRecordSha256.isEmpty()) {
            "Catalog pending metadata rejected"
        }
        if (metadata.pendingRevision != 0uL) {
            require(metadata.pendingRevision == metadata.storageRevision + 1uL
                && metadata.pendingRecordSha256.size == 32) {
                "Catalog pending revision rejected"
            }
        }
    }

    private fun parseMetadata(value: JSONObject): Metadata {
        require(value.keys().asSequence().toSet() == setOf(
            "key_b64", "storage_revision", "record_sha256_b64", "cleared",
            "pending_revision", "pending_sha256_b64",
        )) { "Catalog metadata JSON shape rejected" }
        fun canonicalRevision(name: String): ULong {
            val text = value.opt(name) as? String
                ?: throw IllegalArgumentException("Catalog revision missing")
            require(text == "0" || (text.firstOrNull() in '1'..'9' && text.all(Char::isDigit))) {
                "Catalog revision noncanonical"
            }
            return text.toULongOrNull() ?: throw IllegalArgumentException("Catalog revision overflow")
        }
        fun bytes(name: String, exactSize: Int, emptyAllowed: Boolean): ByteArray {
            val text = value.opt(name) as? String
                ?: throw IllegalArgumentException("Catalog metadata bytes missing")
            if (emptyAllowed && text.isEmpty()) return byteArrayOf()
            require('=' !in text) { "Catalog metadata base64 padding rejected" }
            val decoded = Base64.getUrlDecoder().decode(
                text + "=".repeat((4 - text.length % 4) % 4),
            )
            require(decoded.size == exactSize && b64(decoded) == text) {
                "Catalog metadata base64 rejected"
            }
            return decoded
        }
        val cleared = value.opt("cleared") as? Boolean
            ?: throw IllegalArgumentException("Catalog cleared flag missing")
        return Metadata(
            bytes("key_b64", 32, false),
            canonicalRevision("storage_revision"),
            bytes("record_sha256_b64", 32, true),
            cleared,
            canonicalRevision("pending_revision"),
            bytes("pending_sha256_b64", 32, true),
        ).also(::validate)
    }

    private fun result(status: String, metadata: Metadata? = null, reason: String = ""): String {
        require(status in setOf("available", "missing", "unavailable", "error"))
        val value = JSONObject()
            .put("type", "catalog_secure_metadata_result_v1")
            .put("schema", 1)
            .put("status", status)
            .put("reason", reason)
        metadata?.let {
            value.put("metadata", JSONObject()
                .put("key_b64", b64(it.key32))
                .put("storage_revision", it.storageRevision.toString())
                .put("record_sha256_b64", b64(it.authenticatedRecordSha256))
                .put("cleared", it.cleared)
                .put("pending_revision", it.pendingRevision.toString())
                .put("pending_sha256_b64", b64(it.pendingRecordSha256)))
        }
        return value.toString()
    }

    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) throw SecurityException("Catalog metadata Keystore key missing")
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(KeyGenParameterSpec.Builder(
            KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .build())
        return generator.generateKey()
    }

    private fun aad(context: Context): ByteArray = aadComponents(context.packageName)
        .joinToString("\u0000").toByteArray(StandardCharsets.UTF_8)

    /**
     * Stable authenticated binding for the single app-private metadata record. Keystore and
     * noBackupFilesDir provide installation/device confinement without collecting an identifier.
     */
    internal fun aadComponents(packageName: String): List<String> {
        require(packageName.isNotBlank()) { "Catalog metadata package binding unavailable" }
        return listOf(AAD_DOMAIN, packageName, RECORD_NAME)
    }

    private fun secureDirectory(context: Context): File =
        File(context.noBackupFilesDir, "tribe-catalog-secure").also { directory ->
            require(directory.exists() || directory.mkdirs()) { "Catalog metadata directory unavailable" }
            ownerOnly(directory, true)
            val stat = Os.lstat(directory.absolutePath)
            require((stat.st_mode and OsConstants.S_IFMT) == OsConstants.S_IFDIR
                && stat.st_uid == Process.myUid() && (stat.st_mode and 0x1ff) == 0x1c0) {
                "Catalog metadata directory insecure"
            }
        }

    private fun recordFile(context: Context) = File(secureDirectory(context), RECORD_NAME)

    private fun ownerOnly(file: File, directory: Boolean) {
        Os.chmod(file.absolutePath, if (directory) 0x1c0 else 0x180)
    }

    private fun syncDirectory(directory: File) {
        val descriptor = Os.open(
            directory.absolutePath,
            OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW,
            0,
        )
        try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
    }

    private fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(bytes)
}

private fun java.io.InputStream.readBoundedCatalogBytes(limit: Int): ByteArray {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(1024)
    var total = 0
    while (true) {
        val count = read(buffer)
        if (count < 0) break
        total += count
        require(total <= limit) { "Catalog metadata input oversized" }
        output.write(buffer, 0, count)
    }
    return output.toByteArray()
}
