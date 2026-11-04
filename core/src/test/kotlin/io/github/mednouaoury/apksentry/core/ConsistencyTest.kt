package io.github.mednouaoury.apksentry.core

import kotlin.test.Test
import kotlin.test.assertTrue

/** لا تقرير يناقض نفسه، على كل ملفات الاختبار (نظيفة وخبيثة ومعدّلة). */
class ConsistencyTest {
    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/fixtures/$name")!!.use { it.readBytes() }

    @Test
    fun noReportContradictsItself() {
        val apks = listOf("pack1.apk", "pack2.apk", "pack3.apk", "pack4.apk", "pack5.apk", "npack.apk", "nspy.apk", "rotated.apk", "mixed.apk")
        val problems = ArrayList<String>()
        for (a in apks) {
            val r = Scanner(ScanOptions(dataFlow = true)).scan(ByteArraySource(resource(a)), a)
            for (c in Consistency.check(r)) problems.add("$a: $c")
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }

    @Test
    fun checkerCatchesTheContradictionsWeSaw() {
        fun result(risk: Int, mod: Int, summary: List<Line>, action: String, trusted: String? = null, behaviors: List<Finding> = emptyList()) =
            ScanResult(fileName = "x.apk", packageName = "x", sections = emptyList(), dangers = emptyList(),
                mods = emptyList(), behaviors = behaviors, signers = listOf("a"), vulns = emptyList(), secrets = emptyList(),
                integrityVerified = true, riskScore = risk, modScore = mod, unusualDomains = emptyList(), notes = emptyList(), advice = emptyList(),
                durationMs = 1, trustedSource = trusted, summary = summary, action = action)
        // ARMSX3: "يتصرّف مثل الفيروسات" + "يمكن تثبيته بحذر"
        assertTrue(Consistency.check(result(29, 15, listOf(Line("يتصرّف مثل الفيروسات: ينزّل ويثبّت تطبيقات أخرى.", Tone.BAD)), "يمكن تثبيته بحذر.")).isNotEmpty())
        // TikTok: نسخة Google Play الرسمية + معدّل 100
        assertTrue(Consistency.check(result(0, 100, emptyList(), "", trusted = "Google Play")).isNotEmpty())
        // GTA III: فكرة الكود المخفي مرتين
        assertTrue(Consistency.check(result(25, 18, listOf(Line("في الكود الذي استطعنا قراءته، لم نجد سلوك فيروس. لكن جزءاً منه مخفي، ولا نعرف ما يفعله.", Tone.WARN),
            Line("جزء من الكود مخفي أو مشفّر، فلا يمكن فحصه بالكامل.", Tone.WARN)), "يمكن تثبيته بحذر.")).isNotEmpty())
    }
}
