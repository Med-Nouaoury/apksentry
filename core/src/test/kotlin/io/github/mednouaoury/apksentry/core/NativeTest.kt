package io.github.mednouaoury.apksentry.core

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** محاكي ARM64 والبابان (JNI و libc): صحة الحساب، فك الأغلفة native، ومنع الهروب. */
class NativeTest {
    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/fixtures/$name")!!.use { it.readBytes() }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).toHex()

    private fun h(s: String): Long = java.lang.Long.parseUnsignedLong(s, 16)

    /**
     * كل تعليمة نُفّذت في Unicorn (محاكي مرجعي) وسُجّلت نتيجتها: يجب أن نعطي نفس السجلات والذاكرة بالضبط.
     * (الملف مولَّد بـ tools/armfuzz/gen.py)
     */
    @Test
    fun arm64MatchesUnicorn() {
        val dlo = 0xF8000L; val dhi = 0x118000L
        val fill = ByteArray((dhi - dlo).toInt()) { (((it.toLong() * 2654435761L) ushr 13) and 0xff).toByte() }
        val lines = java.util.zip.GZIPInputStream(javaClass.getResourceAsStream("/fixtures/arm64_cases.txt.gz")!!).bufferedReader().readLines()
        var checked = 0
        for (line in lines) {
            val t = line.split(' ')
            val m = ArmMemory()
            m.map(0x10000, 0x1000); m.write(0x10000, 4, h(t[0]))
            m.map(dlo, dhi - dlo); m.put(dlo, fill)
            val c = Arm64(m)
            c.pc = 0x10000; c.sp = h(t[2]); c.nzcv = h(t[3]).toInt(); c.tpidr = h(t[4])
            for (i in 0 until 31) c.x[i] = h(t[5 + i])
            for (i in 0 until 32) { val b = java.math.BigInteger(t[36 + i], 16); c.vlo[i] = b.toLong(); c.vhi[i] = b.shiftRight(64).toLong() }
            val got = try { c.step(); "ok" } catch (e: ArmFault) { "fault" } catch (e: EmuUnsupported) { continue }
            assertEquals(t[68], got, "${t[0]} ${t.last()}")
            if (got == "ok") {
                assertEquals(h(t[70]), c.pc, "pc ${t.last()}")
                assertEquals(h(t[69]), c.sp, "sp ${t.last()}")
                assertEquals(h(t[71]).toInt(), c.nzcv, "nzcv ${t.last()}")
                for (i in 0 until 31) assertEquals(h(t[72 + i]), c.x[i], "x$i ${t.last()}")
                for (i in 0 until 32) {
                    val b = java.math.BigInteger(t[103 + i], 16)
                    assertTrue(c.vlo[i] == b.toLong() && c.vhi[i] == b.shiftRight(64).toLong(), "v$i ${t.last()}")
                }
                val want = fill.copyOf()
                if (t[135] != "-") for (w in t[135].split(',')) {
                    val a = h(w.substringBefore(':'))
                    w.substringAfter(':').chunked(2).forEachIndexed { k, hx -> want[(a - dlo).toInt() + k] = hx.toInt(16).toByte() }
                }
                assertTrue(m.bytes(dlo, (dhi - dlo).toInt()).contentEquals(want), "memory ${t.last()}")
            }
            checked++
        }
        assertTrue(checked > 350, "checked $checked")
    }

    @Test
    fun registerNativesAndStringDecryption() {
        val rt = NativeRuntime("com.reg", null, null)
        val lib = rt.load("libreg.so", resource("libreg.so"))!!
        rt.runJniOnLoad(lib)
        val fn = rt.findNative("Lcom/x/Hidden;", "a", "(I)Ljava/lang/String;")!!
        assertEquals("https://c2.example/api/v2/upload", rt.callJava(fn, true, null, "Lcom/x/Hidden;", listOf("I"), "Ljava/lang/String;", listOf(77)))
        // حساب 64 بت (ضرب عالٍ، قسمة، باقي) مطابق للحساب المرجعي، عبر snprintf
        assertTrue(rt.strings.contains("LOG: mix=-123454942960 ok ff"), rt.strings.toString())
    }

    @Test
    fun assetZlibDropperIsCaptured() {
        val bos = java.io.ByteArrayOutputStream()
        java.util.zip.ZipOutputStream(bos).use { z -> z.putNextEntry(java.util.zip.ZipEntry("assets/core.bin")); z.write(resource("core.bin")); z.closeEntry() }
        val rt = NativeRuntime("com.asset", ZipArchive(ByteArraySource(bos.toByteArray())), null)
        rt.load("libasset.so", resource("libasset.so"))
        val fn = rt.findNative("Lcom/asset/Loader;", "init", "(Landroid/content/res/AssetManager;)V")!!
        rt.callJava(fn, true, null, "Lcom/asset/Loader;", listOf("Landroid/content/res/AssetManager;"), "V", listOf(AssetsStub()))
        assertTrue(rt.captured.any { sha(it.bytes) == sha(resource("synthetic.dex")) }, rt.stops.toString())
    }

    @Test
    fun nativePackerIsUnpackedEndToEnd() {
        // Java يحمّل المكتبة → JNI_OnLoad يفك dex مشفّراً → NewDirectByteBuffer → InMemoryDexClassLoader
        val r = Scanner(ScanOptions(dataFlow = true)).scan(ByteArraySource(resource("npack.apk")), "npack.apk")
        assertTrue(r.dangers.any { "فككناه" in it.message }, r.toText())
        assertTrue(r.behaviors.isNotEmpty() && r.riskScore >= 60, r.toText())
    }

    @Test
    fun hiddenNativeSmsFraudIsCaught() {
        val r = Scanner(ScanOptions()).scan(ByteArraySource(resource("nspy.apk")), "nspy.apk")
        val text = r.toText()
        assertTrue("+15550001111" in text && "PAY 50 TO 1234" in text, text)
        assertTrue("c2.evil-panel.example" in text, text)
        assertTrue(r.riskScore >= 60, "${r.riskScore}\n$text")
        assertTrue(r.summary.any { "native" in it.text }, text)
    }

    @Test
    fun nativeSandboxCannotEscape() {
        val m1 = File("/tmp/apksentry_native_pwned"); val m2 = File("/tmp/apksentry_native_pwned2")
        m1.delete(); m2.delete()
        val rt = NativeRuntime("com.esc", null, null, maxSteps = 2_000_000)
        rt.load("libesc.so", resource("libesc.so"))
        val fn = rt.findNative("Lcom/esc/E;", "run", "()I")!!
        rt.guarded("run") { rt.callJava(fn, true, null, "Lcom/esc/E;", emptyList(), "I", emptyList()) }
        assertTrue(!m1.exists() && !m2.exists(), "لا تنفيذ ولا كتابة حقيقية")
        assertTrue(rt.events.any { "system" in it }, rt.events.toString())
        assertTrue(rt.events.any { "execve" in it }, rt.events.toString())
        // الحلقة اللانهائية أوقفها حد الخطوات
        assertTrue(rt.stops.any { "الخطوات" in it }, rt.stops.toString())
        // الكتابة ذهبت إلى نظام الملفات الوهمي فقط
        assertTrue(rt.written.containsKey("/tmp/apksentry_native_pwned2"))
    }
}
