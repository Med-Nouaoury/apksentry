package io.github.mednouaoury.apksentry.core

import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CoreTest {
    @Test
    fun domainExtraction() {
        assertEquals("www.foo.com", ByteScanner.domainOf("www.foo.com-bar"))
        assertEquals("apkvision.org", ByteScanner.domainOf("apkvision.org"))
        assertNull(ByteScanner.domainOf("198.51.100.7"))
        assertEquals("198.51.100.7", ByteScanner.ipOf("198.51.100.7"))
    }

    @Test
    fun byteScannerFindsUnknownDomainsOnly() {
        val data = "x https://apkvision.org/api y http://www.google.com/z http://8.8.4.4/ stratum+tcp://p".toByteArray()
        val s = ByteScanner()
        s.scan(data, data.size, "t")
        assertEquals(listOf("apkvision.org"), s.domains.toList())
        assertEquals(listOf("8.8.4.4"), s.ips.toList())
        assertEquals(listOf("t"), s.minerHits.toList())
    }

    @Test
    fun originClassification() {
        val own = listOf("Lcom/rockstargames/rdr/", "Lcom/rockstargames/")
        assertEquals("known", Scanner.origin("Landroidx/core/A;", own))
        assertEquals("known", Scanner.origin("Lcom/rockstargames/x/B;", own))
        assertEquals("obf", Scanner.origin("La/b/C;", own))
        assertEquals("unknown", Scanner.origin("Lapkvision/Loader;", own))
        assertEquals("np.dcc.protect", Scanner.pkgOf("Lnp/dcc/protect/EntryPoint;"))
        assertEquals("np.dcc", Scanner.pkgOf("Lnp/dcc/protect/EntryPoint;", 2))
        assertEquals("System.loadLibrary", Scanner.shortApi("Ljava/lang/System;->loadLibrary"))
    }

    @Test
    fun virusTotalParsing() {
        val json = """{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"suspicious":0,"undetected":60},
            "last_analysis_results":{"AhnLab-V3":{"category":"malicious","result":"PUP/Android.Malct.1270574"},
            "ESET":{"category":"undetected","result":null}}}}}"""
        val r = VirusTotal.parse(json)!!
        assertEquals(1, r.bad)
        assertEquals(listOf("AhnLab-V3: PUP/Android.Malct.1270574"), r.detections)
        assertTrue(Rules.WEAK_DET.containsMatchIn(r.detections[0]))
    }

    @Test
    fun zipStoredAndDeflated() {
        val stored = "stored-content".toByteArray()
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            val e = ZipEntry("a.bin").apply {
                method = ZipEntry.STORED
                size = stored.size.toLong()
                compressedSize = stored.size.toLong()
                crc = CRC32().apply { update(stored) }.value
            }
            z.putNextEntry(e); z.write(stored); z.closeEntry()
            z.putNextEntry(ZipEntry("dir/b.txt")); z.write(ByteArray(100_000) { (it % 7).toByte() }); z.closeEntry()
        }
        val zip = ZipArchive(ByteArraySource(bos.toByteArray()))
        assertEquals(2, zip.entries.size)
        val a = zip.entry("a.bin")!!
        assertTrue(a.isStored)
        assertEquals("stored-content", String(zip.readBytes(a)))
        assertEquals("stored-content", String(zip.sourceOf(a)!!.readFully(0, stored.size)))
        val b = zip.readBytes(zip.entry("dir/b.txt")!!)
        assertEquals(100_000, b.size)
        assertEquals(6.toByte(), b[6])
        assertEquals(3, zip.readHead(zip.entry("dir/b.txt")!!, 3).size)
    }

    @Test
    fun riskLevels() {
        assertEquals(RiskLevel.LOW, RiskLevel.of(5))
        assertEquals(RiskLevel.LOW_MEDIUM, RiskLevel.of(15))
        assertEquals(RiskLevel.MEDIUM, RiskLevel.of(53))
        assertEquals(RiskLevel.HIGH, RiskLevel.of(60))
    }
}

class EngineV2Test {
    @Test
    fun arm64SyscallsAreNamed() {
        // mov w8, #198 ; svc #0 ; mov x8, #221 ; svc #0
        val words = intArrayOf(0x52800008 or (198 shl 5), 0xD4000001.toInt(), 0xD2800008.toInt() or (221 shl 5), 0xD4000001.toInt())
        val buf = ByteArray(words.size * 4)
        words.forEachIndexed { i, w -> for (b in 0..3) buf[i * 4 + b] = (w ushr (8 * b)).toByte() }
        val s = SyscallScanner(Elf.EM_AARCH64, listOf(0L until buf.size.toLong()))
        // نقسم البيانات على دفعتين غير منتظمتين لنختبر الكلمات المقطوعة
        s.feed(buf.copyOfRange(0, 6), 6, 0)
        s.feed(buf.copyOfRange(6, buf.size), buf.size - 6, 6)
        assertEquals(2, s.total)
        assertEquals(setOf("socket", "execve"), s.found.keys)
    }

    @Test
    fun paramSlotsHandleWideTypes() {
        val slots = TaintAnalyzer.paramSlots("(JLjava/lang/String;D[I)V", isStatic = false)
        assertEquals(listOf(1 to "J", 3 to "Ljava/lang/String;", 4 to "D", 6 to "[I"), slots)
    }

    @Test
    fun aospTestKeyDetected() {
        assertTrue(Scanner.isAospTestKey("1.2.840.113549.1.9.1=#1612616e64726f696440616e64726f69642e636f6d,CN=Android,OU=Android,O=Android,L=Mountain View,ST=California,C=US"))
        assertTrue(!Scanner.isAospTestKey("CN=Android Debug,O=Android,C=US"))
    }

    @Test
    fun entropyRanges() {
        assertTrue(Behavior.entropy(ByteArray(4096)) < 0.01)
        assertTrue(Behavior.entropy(ByteArray(65536) { (it * 2654435761L ushr 13).toByte() }) > 7.5)
    }
}
