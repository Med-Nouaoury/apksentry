package io.github.mednouaoury.apksentry.core

import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** يبني APK صغيراً من العيّنة الاصطناعية ويتأكد أن كل نمط خبيث يُكشف. */
class EndToEndTest {
    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/fixtures/$name")!!.use { it.readBytes() }

    private fun buildApk(): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            z.putNextEntry(ZipEntry("AndroidManifest.xml")); z.write(resource("AndroidManifest.bin")); z.closeEntry()
            z.putNextEntry(ZipEntry("classes.dex")); z.write(resource("synthetic.dex")); z.closeEntry()
        }
        return bos.toByteArray()
    }

    private val result by lazy { Scanner().scan(ByteArraySource(buildApk()), "synthetic.apk") }

    @Test
    fun dataLeaksAreTraced() {
        val text = result.toText()
        assertTrue("معرّفات الهاتف أو رقمه تصل إلى الإنترنت" in text, "IMEI -> network")
        assertTrue("الحافظة (ما تنسخه) تصل إلى رسائل SMS" in text, "clipboard -> SMS")
        assertTrue("جهات الاتصال أو الرسائل أو سجل المكالمات تصل إلى الإنترنت" in text, "contacts -> network")
    }

    @Test
    fun malwareBehavioursAreMatched() {
        val titles = result.behaviors.map { it.message }
        assertTrue(titles.any { "حصان طروادة بنكي" in it }, "banking trojan")
        assertTrue(titles.any { "OTP" in it }, "OTP interception")
        assertTrue(titles.any { "يسرق الرسائل" in it }, "SMS/contacts theft")
        assertEquals(100, result.riskScore)
    }

    @Test
    fun vulnerabilitiesAndSecretsAreFound() {
        val v = result.vulns.map { it.title }
        assertTrue(v.any { "TrustManager" in it })
        assertTrue(v.any { "HostnameVerifier" in it })
        assertTrue(v.any { "WebView يتجاهل أخطاء" in it })
        assertTrue(v.any { "مفتاح تشفير مكتوب" in it })
        assertTrue(v.any { "ECB" in it })
        assertTrue(result.secrets.any { it.suspicious && "تيليغرام" in it.kind })
    }

    @Test
    fun stringDecryptorIsDetected() {
        assertTrue("com.evil.Spy.dec(): 30 نص" in result.toText())
    }

    @Test
    fun corruptedInputNeverCrashes() {
        val apk = buildApk()
        val rnd = java.util.Random(7)
        repeat(60) {
            val bad = apk.copyOf()
            repeat(8) { bad[rnd.nextInt(bad.size)] = rnd.nextInt(256).toByte() }
            try {
                Scanner().scan(ByteArraySource(bad), "bad.apk")
            } catch (e: java.io.IOException) {
            } catch (e: IllegalArgumentException) {
            }
        }
    }
}
