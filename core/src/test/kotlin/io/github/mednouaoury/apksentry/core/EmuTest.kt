package io.github.mednouaoury.apksentry.core

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** المحاكي: صحة الحساب، فك الأغلفة، ومنع أي هروب من الصندوق. */
class EmuTest {
    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/fixtures/$name")!!.use { it.readBytes() }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).toHex()

    private fun emulator(): Pair<DalvikEmulator, EmuRuntime> {
        val zip = ZipArchive(ByteArraySource(resource("pack1.apk")))
        val rt = EmuRuntime("emu.test", null, zip, maxSteps = 2_000_000, maxMillis = 10_000, maxAlloc = 64L * 1024 * 1024)
        val emu = DalvikEmulator(listOf(DexFile(resource("emu.dex"))), rt)
        rt.emu = emu
        return emu to rt
    }

    private fun call(emu: DalvikEmulator, cls: String, name: String, params: List<String>, ret: String, vararg args: Any?): Any? =
        emu.dispatch(cls, name, params, ret, args.toList(), virtual = false)

    // نفس الحساب بـ Kotlin للمقارنة
    private fun mix(a: Int, b: Long): Long {
        var r = b * 31 + a.toLong()
        r = r xor (r ushr 7)
        var x = (r shr 3).toInt() * -7
        x = x / 3 + x % 5
        r += (x shl 2).toLong()
        r -= a.toLong() shl 40
        return r xor (r shl 13)
    }

    @Test
    fun arithmeticMatchesTheJvm() {
        val (emu, _) = emulator()
        for ((a, b) in listOf(0 to 0L, 7 to 123456789L, -5 to -98765432123L, Int.MAX_VALUE to Long.MIN_VALUE, 1234 to 42L)) {
            assertEquals(mix(a, b), call(emu, "Lemu/Calc;", "mix", listOf("I", "J"), "J", a, b), "mix($a, $b)")
        }
        val sw = { k: Int -> call(emu, "Lemu/Calc;", "sw", listOf("I"), "I", k) }
        assertEquals(100, sw(5)); assertEquals(200, sw(6)); assertEquals(1000, sw(-100)); assertEquals(200, sw(0x7fff0000)); assertEquals(-1, sw(7))
        assertEquals(-1, call(emu, "Lemu/Calc;", "div0", emptyList(), "I"), "try/catch على القسمة على صفر")
        assertEquals("B42Z", call(emu, "Lemu/Calc;", "str", emptyList(), "Ljava/lang/String;"))
        val f = 1.5f; val d = 10.25
        val want = (f.toDouble() * d / 2.0).let { it + it.toInt().toFloat().toDouble() }
        assertEquals(want, Double.fromBits(call(emu, "Lemu/Calc;", "fl", listOf("F", "D"), "D", f.toRawBits(), d.toRawBits()) as Long))
        assertEquals(-1, call(emu, "Lemu/Calc;", "chars", emptyList(), "I"))
    }

    @Test
    fun unpacksXorAesAndRc4Packers() {
        val want = sha(resource("synthetic.dex"))
        for ((apk, pkg) in listOf("pack1.apk" to "com.pack1", "pack2.apk" to "com.pack2", "pack3.apk" to "com.pack3")) {
            val bytes = resource(apk)
            val zip = ZipArchive(ByteArraySource(bytes))
            val dexes = listOf(DexFile(zip.readBytes(zip.entry("classes.dex")!!)))
            val r = Unpacker.run(zip, bytes, dexes, pkg, "$pkg.App", null)
            assertTrue(r.payloads.any { sha(it.bytes) == want }, "$apk: ${r.stops} ${r.events}")
        }
    }

    @Test
    fun sandboxCannotEscape() {
        val (emu, rt) = emulator()
        val marker = File("/tmp/apksentry_pwned")
        val marker2 = File("/tmp/apksentry_pwned2")
        marker.delete(); marker2.delete()

        call(emu, "Lemu/Esc;", "exec", emptyList(), "V")
        call(emu, "Lemu/Esc;", "refl", emptyList(), "V")
        Thread.sleep(200)
        assertTrue(!marker.exists() && !marker2.exists(), "لا تنفيذ أوامر حقيقية")
        assertTrue(rt.events.any { "Runtime" in it })

        // نظام ملفات وهمي: لا قراءة لملفات الجهاز
        val ex = assertFailsWith<EmuThrow> { call(emu, "Lemu/Esc;", "readEtc", emptyList(), "I") }
        assertTrue(ex.ex is java.io.FileNotFoundException)

        // لا وصول لـ ClassLoader حقيقي
        val cl = call(emu, "Lemu/Esc;", "cl", emptyList(), "Ljava/lang/Object;")
        assertTrue(cl is ClassLoaderStub, "حصلنا على $cl")

        // لا شبكة
        assertFailsWith<EmuUnsupported> { call(emu, "Lemu/Esc;", "net", emptyList(), "V") }

        // حدود: حلقة لا نهائية، ذاكرة، عمق
        assertFailsWith<EmuLimit> { call(emu, "Lemu/Esc;", "loop", emptyList(), "V") }
        assertFailsWith<EmuLimit> { emulator().first.let { call(it, "Lemu/Esc;", "bomb", emptyList(), "[B") } }
        assertFailsWith<EmuLimit> { emulator().first.let { call(it, "Lemu/Esc;", "recurse", emptyList(), "V") } }
    }

    @Test
    fun packedAppIsFlaggedWithItsHiddenBehaviour() {
        for (apk in listOf("pack2.apk", "pack3.apk")) {
            val r = Scanner(ScanOptions(dataFlow = true)).scan(ByteArraySource(resource(apk)), apk)
            val text = r.toText()
            assertTrue(r.dangers.any { "فككناه" in it.message }, text)
            // سلوك الكود المخفي (حصان طروادة بنكي، اعتراض OTP...) يظهر رغم أنه كان مشفّراً
            assertTrue(r.behaviors.isNotEmpty(), text)
            assertTrue(r.riskScore >= 60, "$apk ${r.riskScore}")
        }
    }
}
