package io.github.mednouaoury.apksentry.core

import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** طبقة البصمة التقريبية وطبقة انتحال الهوية. */
class LayersTest {
    private fun gen(n: Int, seed: Long): ByteArray {
        var x = seed
        return ByteArray(n) {
            x = (x * 1103515245 + 12345) and 0x7fffffff
            ((x shr 16) and 0xff).toByte()
        }
    }

    // القيم المتوقعة محسوبة بمكتبة py-tlsh الرسمية
    @Test
    fun tlshMatchesReferenceImplementation() {
        val a = gen(5000, 1)
        val b = a.copyOf().also { for (i in 100 until 140) it[i] = 'X'.code.toByte() }
        val txt = "the quick brown fox jumps over the lazy dog ".repeat(200).toByteArray()
        assertEquals("T180A19DFF062DD5716844F010D1F5067C7B2897F2DACD3D2AD8144590A6A83C3D2EE848", Tlsh.of(a))
        assertEquals("T1BDA18CFF062DD572A884FC10D1F5067C3B2896B2DACD3C2A9814449096A83F3D6DE848", Tlsh.of(b))
        assertEquals("T12C02024A211813A5648A1884438D94F282C8C910A1321411643060025808531DC98492", Tlsh.of(txt))
        assertEquals(27, Tlsh.distance(Tlsh.of(a)!!, Tlsh.of(b)!!))
        // NewPipe الأصلي مقابل نسخة أُعيد توقيعها، ومقابل ملف لا علاقة له
        val np = "T16BC6CF9B739CDF2AC4720076C4493676965D4E399F83C3937808371DB5B39E88E296E8"
        assertEquals(13, Tlsh.distance(np, "T12FC6CF9A339CDF26C4730076C9493672965D4E399F83D3877808370DB5B79E88E296E8"))
        assertEquals(273, Tlsh.distance(np, "T155669E0272ADABA9D15BA0340ECFE5036379F4B17E35306733865F2D1ABA97547E9320"))
        assertNull(Tlsh.of(ByteArray(40)), "صغير جداً")
        assertNull(Tlsh.of(ByteArray(10_000)), "بلا تنوّع")
    }

    @Test
    fun similarityDbRoundTrip() {
        val db = SimilarityDb.parse("# c\nT1BDA18CFF062DD572A884FC10D1F5067C3B2896B2DACD3C2A9814449096A83F3D6DE848,AAA,Anatsa\nbad,x\n")
        assertEquals(1, db.size)
        val m = db.nearest(Tlsh.of(gen(5000, 1))!!)!!
        assertEquals("Anatsa", m.entry.family)
        assertEquals(27, m.distance)
        val merged = db.merge(listOf(SimEntry(Tlsh.of(gen(4000, 7))!!, "bbb", "Joker"), SimEntry(db.entries[0].tlsh, "aaa", "x")))
        assertEquals(2, merged.size)
        assertEquals(2, SimilarityDb.parse(merged.serialize()).size)
    }

    private fun hit(label: String, pkg: String) = Impersonation.check(listOf(label), pkg)

    @Test
    fun impersonationRules() {
        assertEquals(ImpStrength.STRONG, hit("WhatsApp", "com.wh4tsapp.update")?.strength)
        assertNull(hit("WhatsApp", "com.whatsapp"), "التطبيق الحقيقي")
        assertNull(hit("WhatsApp Business", "com.whatsapp.w4b"))
        assertEquals(ImpStrength.STRONG, hit("Whatsaap", "a.b")?.strength, "خطأ إملائي")
        assertEquals(ImpStrength.STRONG, hit("WhatsАpp", "a.b")?.strength, "حرف سيريلي")
        assertEquals(ImpStrength.STRONG, hit("Wh4tsApp", "a.b")?.strength, "رقم بدل حرف")
        assertEquals(ImpStrength.STRONG, hit("واتساب", "a.b")?.strength)
        assertEquals(ImpStrength.STRONG, hit("انستقرام", "a.b")?.strength)
        assertEquals(ImpStrength.WEAK, hit("GBWhatsApp Pro", "com.gbwhatsapp")?.strength)
        assertEquals(ImpStrength.STRONG, hit("Update", "com.whatsapq")?.strength, "حزمة مقلّدة")
        assertEquals(ImpStrength.STRONG, hit("Signal", "a.b")?.strength)
        // لا إنذارات كاذبة
        assertNull(hit("YouTube Music", "com.google.android.apps.youtube.music"), "تطبيق آخر من نفس الشركة")
        assertNull(hit("Google Play services", "com.google.android.gms"))
        assertNull(hit("Telegraph", "x.telegraph"))
        assertNull(hit("Signal Strength Meter", "a.b"), "اسم عام")
        assertNull(hit("Chroma", "a.b"))
        assertNull(hit("NewPipe", "org.schabi.newpipe"))
        assertNull(hit("Revolt", "chat.revolt"))
        assertNull(hit("KeePassDX", "com.kunzisoft.keepass.libre"))
    }

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/fixtures/$name")!!.use { it.readBytes() }

    private fun fakeWhatsApp(): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            z.putNextEntry(ZipEntry("AndroidManifest.xml")); z.write(resource("fake_whatsapp_manifest.bin")); z.closeEntry()
            z.putNextEntry(ZipEntry("resources.arsc")); z.write(resource("fake_whatsapp.arsc")); z.closeEntry()
            z.putNextEntry(ZipEntry("classes.dex")); z.write(resource("synthetic.dex")); z.closeEntry()
        }
        return bos.toByteArray()
    }

    @Test
    fun arscResolvesAppLabel() {
        val arsc = assertNotNull(Arsc.parse(resource("fake_whatsapp.arsc")))
        val m = assertNotNull(Axml.parse(resource("fake_whatsapp_manifest.bin")))
        val ref = m.walk().first { it.tag == "application" }.attr("label")!!
        assertTrue(ref.startsWith("@0x7f"), ref)
        assertEquals("WhatsApp", arsc.strings(ref.substring(3).toLong(16).toInt()).first().second)
    }

    @Test
    fun fakeWhatsAppIsCaught() {
        val r = Scanner(ScanOptions(dataFlow = false)).scan(ByteArraySource(fakeWhatsApp()), "wa.apk")
        assertEquals("WhatsApp", r.appLabel)
        assertTrue(r.dangers.any { it.message.startsWith("ينتحل هوية WhatsApp") }, r.toText())
        assertTrue(r.behaviors.any { "يستعمل اسم WhatsApp ويطلب صلاحيات خطيرة" in it.message })
        // الخلاصة البسيطة والصلاحيات للواجهة
        assertTrue(r.summary.any { it.tone == Tone.BAD && "يتنكّر" in it.text }, r.summary.joinToString { it.text })
        assertEquals("لا تثبّته.", r.action)
        assertTrue("android.permission.BIND_ACCESSIBILITY_SERVICE" in r.permissions)
        assertTrue("android.permission.SEND_SMS" in r.permissions)
    }

    @Test
    fun knownMalwareVariantIsCaughtOffline() {
        val apk = fakeWhatsApp()
        val t = Tlsh.of(apk)!!
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(apk).toHex()
        // نفس البصمة التقريبية ولكن ملف مختلف = نسخة معدّلة
        val near = Scanner(ScanOptions(dataFlow = false, similarity = SimilarityDb(listOf(SimEntry(t, "00" + sha.drop(2), "SpyNote")))))
            .scan(ByteArraySource(apk), "wa.apk")
        assertTrue(near.dangers.any { "نسخة معدّلة قليلاً من فيروس معروف (SpyNote)" in it.message }, near.toText())
        assertEquals(t, near.tlsh)
        // نفس الملف بالضبط
        val exact = Scanner(ScanOptions(dataFlow = false, similarity = SimilarityDb(listOf(SimEntry(t, sha, "SpyNote")))))
            .scan(ByteArraySource(apk), "wa.apk")
        assertTrue(exact.dangers.any { it.weight == 100 && "SpyNote" in it.message })
    }

    /** حيلة "طريقة الضغط المزيّفة": الملفات مخزّنة بلا ضغط ولكن رقم الطريقة مزيّف. */
    private fun badPack(): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            for ((n, d) in listOf("AndroidManifest.xml" to resource("AndroidManifest.bin"), "classes.dex" to resource("synthetic.dex"))) {
                val e = ZipEntry(n)
                e.method = ZipEntry.STORED
                e.size = d.size.toLong(); e.compressedSize = d.size.toLong()
                e.crc = java.util.zip.CRC32().also { it.update(d) }.value
                z.putNextEntry(e); z.write(d); z.closeEntry()
            }
        }
        val b = bos.toByteArray()
        // نبدّل رقم الطريقة ف الترويسات المحلية (offset 8) والفهرس المركزي (offset 10)
        for (i in 0 until b.size - 4) {
            val sig = (b[i].toInt() and 0xff) or ((b[i + 1].toInt() and 0xff) shl 8) or ((b[i + 2].toInt() and 0xff) shl 16) or ((b[i + 3].toInt() and 0xff) shl 24)
            val at = when (sig) { 0x04034b50 -> i + 8; 0x02014b50 -> i + 10; else -> -1 }
            if (at > 0) { b[at] = 0x4d; b[at + 1] = 0x5a }
        }
        return b
    }

    @Test
    fun fakeCompressionTrickIsReadAndFlagged() {
        val r = Scanner(ScanOptions(dataFlow = false)).scan(ByteArraySource(badPack()), "bp.apk")
        assertTrue(r.dangers.any { "طريقة ضغط مزيّفة" in it.message }, r.toText())
        assertTrue(r.packageName != null, "قرينا الـ manifest رغم الحيلة")
        assertTrue(r.behaviors.isNotEmpty(), "وقرينا الكود")
        assertTrue(r.riskScore >= 60)
    }

    @Test
    fun hiddenCharactersOnlyCountInsideWords() {
        val zw = Regex("[\u200B\u2060-\u2064\uFEFF]")
        assertTrue(zw.containsMatchIn("TikT\u2062\u200Bok18+"))
        // علامة الاتجاه ف ترجمة عربية عادية ماشي حيلة
        assertTrue(!zw.containsMatchIn("\u200Fالملفات"))
    }

    @Test
    fun reputationNeedsEverySignerToMatch() {
        val known = setOf("aa", "bb")
        assertTrue(Reputation.matches(known, listOf("AA")))
        assertTrue(!Reputation.matches(known, listOf("aa", "cc")), "توقيع إضافي غريب")
        assertTrue(!Reputation.matches(known, emptyList()), "بلا توقيع")
        assertTrue(!Reputation.matches(null, listOf("aa")), "حزمة ماشي ف F-Droid")
    }
}
