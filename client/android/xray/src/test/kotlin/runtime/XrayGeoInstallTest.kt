package org.amnezia.vpn.protocol.xray.runtime

import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.security.MessageDigest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.amnezia.vpn.protocol.xray.XrayGeoAssets
import org.amnezia.vpn.protocol.xray.XrayGeoInstall

// AVPN (decision A-6): the cut geo pair is installed from the APK assets into a directory on disk, hashes
// checked, temp file + rename; XrayGeoAssets cases are the Kotlin twin of testGeo() in UpstreamLeaseTests.swift.
class XrayGeoInstallTest {

    private lateinit var dir: File
    private val geoip = "geoip-bytes".toByteArray()
    private val geosite = "geosite-bytes".toByteArray()

    private fun sha(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun sums(ip: ByteArray = geoip, site: ByteArray = geosite) = "${sha(ip)}  geoip.dat\n${sha(site)}  geosite.dat\n"

    private fun assets(files: Map<String, ByteArray?>, opened: MutableList<String> = mutableListOf()): (String) -> InputStream? =
        { name -> opened += name; files[name]?.let { ByteArrayInputStream(it) } }

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("tribe-geo-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    @Test
    fun parsesTheRecipeSums() {
        val parsed = XrayGeoInstall.parseSums(
            "c13c6463b5203768a94693d176d97f3e9b3fff93ecd288b6c215908baec0faee  geoip.dat\n" +
                "C0AFBBC3B8C307E3FE5700EA941BA258319508F545CFA0E6B75A154520622162 *geosite.dat\n\nnot a line\n"
        )
        assertEquals(
            mapOf(
                "geoip.dat" to "c13c6463b5203768a94693d176d97f3e9b3fff93ecd288b6c215908baec0faee",
                "geosite.dat" to "c0afbbc3b8c307e3fe5700ea941ba258319508f545cfa0e6b75a154520622162",
            ),
            parsed,
        )
    }

    @Test
    fun installsBothFilesAndKeepsThemNextTime() {
        val target = File(dir, XrayGeoInstall.DISK_DIR)
        val first = XrayGeoInstall.install(target, assets(mapOf("SHA256SUMS" to sums().toByteArray(), "geoip.dat" to geoip, "geosite.dat" to geosite)))
        assertTrue(first.ok, first.error)
        assertEquals(setOf("geoip.dat", "geosite.dat"), first.files)
        assertTrue(File(target, "geoip.dat").readBytes().contentEquals(geoip))
        assertTrue(File(target, "geosite.dat").readBytes().contentEquals(geosite))
        assertFalse(target.listFiles()!!.any { it.name.endsWith(".tmp") }, "no temp file left")

        val opened = mutableListOf<String>()
        val second = XrayGeoInstall.install(target, assets(mapOf("SHA256SUMS" to sums().toByteArray()), opened))
        assertTrue(second.ok, "verified files on disk are kept")
        assertEquals(listOf("SHA256SUMS"), opened, "no copy when the hashes match")
    }

    @Test
    fun aStaleOrDamagedFileIsReplaced() {
        File(dir, "geoip.dat").writeBytes("old".toByteArray())
        File(dir, "geosite.dat").writeBytes(geosite)
        val result = XrayGeoInstall.install(dir, assets(mapOf("SHA256SUMS" to sums().toByteArray(), "geoip.dat" to geoip, "geosite.dat" to geosite)))
        assertTrue(result.ok, result.error)
        assertTrue(File(dir, "geoip.dat").readBytes().contentEquals(geoip))
    }

    @Test
    fun aWrongAssetNeverReplacesAFile() {
        File(dir, "geoip.dat").writeBytes("old".toByteArray())
        val result = XrayGeoInstall.install(dir, assets(mapOf("SHA256SUMS" to sums().toByteArray(), "geoip.dat" to "tampered".toByteArray(), "geosite.dat" to geosite)))
        assertEquals("${XrayGeoInstall.ERR_HASH}:geoip.dat", result.error)
        assertTrue(File(dir, "geoip.dat").readBytes().contentEquals("old".toByteArray()), "the old file stays, no half file")
        assertFalse(File(dir, ".geoip.dat.tmp").exists())
        assertFalse("geoip.dat" in result.files)
    }

    @Test
    fun missingInputsAreNamed() {
        assertEquals(XrayGeoInstall.ERR_SUMS, XrayGeoInstall.install(dir, assets(emptyMap())).error, "APK without the pair")
        val noSite = XrayGeoInstall.install(dir, assets(mapOf("SHA256SUMS" to sums().toByteArray(), "geoip.dat" to geoip)))
        assertEquals("${XrayGeoInstall.ERR_ASSET}:geosite.dat", noSite.error)
        assertEquals(setOf("geoip.dat"), noSite.files, "what was verified is reported")
        val shortSums = XrayGeoInstall.install(dir, assets(mapOf("SHA256SUMS" to "${sha(geoip)}  geoip.dat\n".toByteArray(), "geoip.dat" to geoip)))
        assertEquals("${XrayGeoInstall.ERR_SUMS}:geosite.dat", shortSums.error)
        // geoip.dat is verified in `dir` by now and kept; a fresh directory sees the first copy fail.
        val throwing = XrayGeoInstall.install(File(dir, "fresh")) { name ->
            if (name == "SHA256SUMS") ByteArrayInputStream(sums().toByteArray()) else throw java.io.IOException("x")
        }
        assertEquals("${XrayGeoInstall.ERR_IO}:geoip.dat", throwing.error)
        val keptThenThrowing = XrayGeoInstall.install(dir) { name ->
            if (name == "SHA256SUMS") ByteArrayInputStream(sums().toByteArray()) else throw java.io.IOException("x")
        }
        assertEquals("${XrayGeoInstall.ERR_IO}:geosite.dat", keptThenThrowing.error, "a verified file is never re-copied")
    }

    @Test
    fun startDecisionFromTheInstalledFiles() {
        val config = """{"routing":{"rules":[{"ip":["geoip:ru"],"outboundTag":"direct"},{"domain":["geosite:category-ru"]}]}}"""
        assertEquals(listOf("geoip.dat", "geosite.dat"), XrayGeoAssets.missing(config, emptySet()), "install failed: the start fails by name")
        assertEquals(listOf("geosite.dat"), XrayGeoAssets.missing(config, setOf("geoip.dat")))
        assertEquals(emptyList(), XrayGeoAssets.missing(config, setOf("geoip.dat", "geosite.dat")))
        assertEquals(emptyList(), XrayGeoAssets.missing("""{"outbounds":[{"protocol":"vless"}]}""", emptySet()),
            "a config without geo rules starts")
    }

    @Test
    fun geoFilesOfAConfig() {
        val config = """{"routing":{"rules":[{"domain":["geosite:category-ru","ext:custom.dat:x"],"outboundTag":"direct"},""" +
            """{"ip":["geoip:ru","!geoip:private"],"outboundTag":"direct"}]},"dns":{"servers":[{"domains":["notgeosite:x"]}]}}"""
        val pair = setOf("geoip.dat", "geosite.dat")
        assertEquals(listOf("custom.dat", "geoip.dat", "geosite.dat"), XrayGeoAssets.files(config))
        assertEquals(emptyList(), XrayGeoAssets.files("""{"outbounds":[{"protocol":"vless"}]}"""), "no geo")
        assertEquals(listOf("custom.dat", "geoip.dat", "geosite.dat"), XrayGeoAssets.missing(config, emptySet()), "all missing")
        assertEquals(listOf("custom.dat"), XrayGeoAssets.missing(config, pair), "only the ext file missing")
        assertEquals(listOf("../geoip.dat"), XrayGeoAssets.missing("""["ext:../geoip.dat:x"]""", pair), "a path is never a plain file")
        assertEquals(listOf("geosite.dat"), XrayGeoAssets.files("""["ext-site:geosite.dat:cn","ext-ip:geosite.dat:x"]"""))
    }
}
