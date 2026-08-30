@file:Suppress("UnstableApiUsage")

import java.security.MessageDigest
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

configurations {
    maybeCreate("default")
}

val artifactPath = providers.gradleProperty("amneziaLibXrayAar")
    .orElse(providers.environmentVariable("AMNEZIA_LIBXRAY_PATH"))
    .orElse(layout.projectDirectory.file("libxray.aar").asFile.absolutePath)
val artifactSha = providers.gradleProperty("amneziaLibXrayAarSha256")
    .orElse(providers.environmentVariable("AMNEZIA_LIBXRAY_ARTIFACT_SHA256"))
    .orElse(providers.provider {
        val sidecar = file("libxray.aar.sha256")
        if (sidecar.isFile) sidecar.readText().trim() else ""
    })

val aar = file(artifactPath.get())
val expectedSha = artifactSha.get()
require(expectedSha.matches(Regex("^[0-9a-f]{64}$"))) {
    "Pinned amnezia-libxray/1.0.3-tribe.1 SHA-256 is missing. Materialize it via the Conan " +
        "Android CMake configure, or pass -PamneziaLibXrayAar and " +
        "-PamneziaLibXrayAarSha256."
}
require(aar.isFile && !java.nio.file.Files.isSymbolicLink(aar.toPath())) {
    "Pinned amnezia-libxray/1.0.3-tribe.1 AAR is missing or is a symlink: $aar"
}
val actualSha = MessageDigest.getInstance("SHA-256").digest(aar.readBytes())
    .joinToString("") { "%02x".format(it.toInt() and 0xff) }
require(actualSha == expectedSha) {
    "amnezia-libxray AAR SHA-256 mismatch: expected $expectedSha, got $actualSha"
}
ZipFile(aar).use { archive ->
    fun ByteArray.indexOfSequence(needle: ByteArray, fromIndex: Int = 0): Int {
        if (needle.isEmpty() || needle.size > size) return -1
        val lastStart = size - needle.size
        for (start in fromIndex.coerceAtLeast(0)..lastStart) {
            var matched = true
            for (offset in needle.indices) {
                if (this[start + offset] != needle[offset]) {
                    matched = false
                    break
                }
            }
            if (matched) return start
        }
        return -1
    }
    fun ByteArray.containsAbsoluteGoReplacement(): Boolean {
        val marker = "=>\t".toByteArray(Charsets.US_ASCII)
        var searchFrom = 0
        while (true) {
            val markerIndex = indexOfSequence(marker, searchFrom)
            if (markerIndex < 0) return false
            val valueIndex = markerIndex + marker.size
            if (valueIndex < size && this[valueIndex] == '/'.code.toByte()) return true
            if (valueIndex + 2 < size
                    && this[valueIndex].toInt().toChar().isLetter()
                    && this[valueIndex + 1] == ':'.code.toByte()
                    && (this[valueIndex + 2] == '/'.code.toByte()
                        || this[valueIndex + 2] == '\\'.code.toByte())) return true
            searchFrom = markerIndex + marker.size
        }
    }
    val entries = archive.entries().asSequence().map { it.name }.toSet()
    val expectedAbis = setOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
    val actualAbis = entries.mapNotNull { name ->
        Regex("^jni/([^/]+)/libgojni\\.so$").matchEntire(name)?.groupValues?.get(1)
    }.toSet()
    require(actualAbis == expectedAbis) {
        "amnezia-libxray AAR ABI matrix mismatch: expected $expectedAbis, got $actualAbis"
    }
    fun loadAlignments(bytes: ByteArray, abi: String): List<Long> {
        require(bytes.size >= 64 && bytes[0] == 0x7f.toByte()
                && bytes.copyOfRange(1, 4).contentEquals("ELF".toByteArray())
                && bytes[5] == 1.toByte()) { "$abi libgojni.so is not little-endian ELF" }
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val elfClass = bytes[4].toInt()
        val phoff: Long
        val phentsize: Int
        val phnum: Int
        val alignOffset: Int
        if (elfClass == 1) {
            phoff = buffer.getInt(28).toLong() and 0xffff_ffffL
            phentsize = buffer.getShort(42).toInt() and 0xffff
            phnum = buffer.getShort(44).toInt() and 0xffff
            alignOffset = 28
            require(phentsize >= 32) { "$abi malformed ELF32 program headers" }
        } else {
            require(elfClass == 2) { "$abi unsupported ELF class $elfClass" }
            phoff = buffer.getLong(32)
            phentsize = buffer.getShort(54).toInt() and 0xffff
            phnum = buffer.getShort(56).toInt() and 0xffff
            alignOffset = 48
            require(phentsize >= 56) { "$abi malformed ELF64 program headers" }
        }
        require(phoff >= 0 && phnum > 0 && phoff + phentsize.toLong() * phnum <= bytes.size) {
            "$abi malformed ELF program-header range"
        }
        return (0 until phnum).mapNotNull { index ->
            val offset = Math.toIntExact(phoff + index.toLong() * phentsize)
            if (buffer.getInt(offset) != 1) null else if (elfClass == 1)
                buffer.getInt(offset + alignOffset).toLong() and 0xffff_ffffL
            else buffer.getLong(offset + alignOffset)
        }
    }
    actualAbis.forEach { abi ->
        val entry = archive.getEntry("jni/$abi/libgojni.so")
        val nativeBinary = archive.getInputStream(entry).use { it.readBytes() }
        require(!nativeBinary.containsAbsoluteGoReplacement()
                && nativeBinary.indexOfSequence("/.conan2/".toByteArray(Charsets.US_ASCII)) < 0
                && nativeBinary.indexOfSequence("\\.conan2\\".toByteArray(Charsets.US_ASCII)) < 0) {
            "$abi libgojni.so contains an absolute local Go module replacement path"
        }
        val alignments = loadAlignments(nativeBinary, abi)
        require(alignments.isNotEmpty()
                && alignments.all { it >= 0x4000L && it and (it - 1) == 0L }) {
            "$abi libgojni.so is not 16 KiB page compatible: $alignments"
        }
    }
    require("classes.jar" in entries) { "amnezia-libxray AAR has no classes.jar" }
    val classes = mutableSetOf<String>()
    ZipInputStream(archive.getInputStream(archive.getEntry("classes.jar"))).use { jar ->
        while (true) {
            val entry = jar.nextEntry ?: break
            classes += entry.name
        }
    }
    val requiredClasses = setOf(
        "org/amnezia/vpn/protocol/xray/libXray/LibXray.class",
        "org/amnezia/vpn/protocol/xray/libXray/DialerController.class",
        "org/amnezia/vpn/protocol/xray/libXray/Logger.class",
        "org/amnezia/vpn/protocol/xray/libXray/Tun2SocksConfig.class",
    )
    require(classes.containsAll(requiredClasses)) {
        "amnezia-libxray gomobile API classes are incomplete: ${requiredClasses - classes}"
    }
}

artifacts.add("default", aar)
