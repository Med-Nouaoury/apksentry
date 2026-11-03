package io.github.mednouaoury.apksentry.core

/** ADDED = خطر من كود غير معروف، لا يُحسب إلا إذا ظهر أن التطبيق معدّل. */
enum class Kind { DANGER, MOD, INFO, ADDED }

enum class Tone { HEAD, NORMAL, OK, WARN, BAD, INFO, MUTED }

class Line(val text: String, val tone: Tone = Tone.NORMAL, val indent: Int = 0)

class Section(val title: String) {
    val lines = ArrayList<Line>()
}

class Finding(val weight: Int, val message: String, val kind: Kind)

enum class RiskLevel(val label: String, val explanation: String) {
    LOW("منخفض ✔", "لا توجد علامات سلوك خبيث."),
    LOW_MEDIUM("منخفض إلى متوسط", "ملاحظات بسيطة، راجعها، لكن لا دليل قوي على سلوك خبيث."),
    MEDIUM("متوسط ⚠", "توجد علامات تستحق الحذر، راجع التفاصيل قبل التثبيت."),
    HIGH("مرتفع ⛔", "علامات خطر قوية، لا تثبّته.");

    companion object {
        fun of(score: Int) = when {
            score < 10 -> LOW
            score < 35 -> LOW_MEDIUM
            score < 60 -> MEDIUM
            else -> HIGH
        }
    }
}

class ScanResult(
    val fileName: String,
    val packageName: String?,
    val sections: List<Section>,
    val dangers: List<Finding>,
    val mods: List<Finding>,
    /** سلوكيات تشبه برامج خبيثة معروفة (جزء من [dangers]). */
    val behaviors: List<Finding>,
    /** بصمات شهادات التوقيع. */
    val signers: List<String>,
    /** ثغرات أمنية في التطبيق نفسه (لا تدخل في درجة الخطر). */
    val vulns: List<Vuln>,
    val secrets: List<Secret>,
    /** تم التحقق من سلامة التوقيع v2/v3 بنجاح. */
    val integrityVerified: Boolean,
    val riskScore: Int,
    val modScore: Int,
    val unusualDomains: List<String>,
    val notes: List<String>,
    val advice: List<String>,
    val durationMs: Long,
) {
    val level: RiskLevel get() = RiskLevel.of(riskScore)
    val isModified: Boolean get() = modScore >= 10

    /** التقرير نصياً، بنفس شكل تقرير السكربت. */
    fun toText(): String {
        val sb = StringBuilder()
        sb.append("ApkSentry ${Scanner.VERSION}\n")
        sb.append("الملف: $fileName\n")
        for (s in sections) {
            sb.append("\n===== ${s.title} =====\n")
            for (l in s.lines) sb.append("  ".repeat(l.indent)).append(l.text).append('\n')
        }
        sb.append("\n===== النتيجة =====\n")
        if (unusualDomains.isNotEmpty()) {
            sb.append("مواقع غير مألوفة في الكود (${unusualDomains.size}):\n")
            unusualDomains.take(40).forEach { sb.append("  ").append(it).append('\n') }
            if (unusualDomains.size > 40) sb.append("  ... و${unusualDomains.size - 40} أخرى\n")
        }
        notes.forEach { sb.append("ملاحظة: ").append(it).append('\n') }
        if (behaviors.isNotEmpty()) {
            sb.append("\n🧬 سلوكيات تشبه برامج خبيثة معروفة:\n")
            behaviors.forEach { sb.append("  [${it.weight}] ${it.message}\n") }
        }
        if (vulns.isNotEmpty()) {
            sb.append("\n🛡 ثغرات أمنية في التطبيق نفسه (${vulns.size}):\n")
            vulns.forEach { v ->
                val sev = when (v.severity) { 3 -> "عالية"; 2 -> "متوسطة"; else -> "منخفضة" }
                sb.append("  [$sev] ${v.title}").append(if (v.where.isNotEmpty()) " (${v.where})" else "").append('\n')
            }
        }
        if (secrets.isNotEmpty()) {
            sb.append("\n🔑 أسرار مكتوبة داخل التطبيق:\n")
            secrets.forEach { sb.append("  ${it.kind}: ${it.masked}\n") }
        }
        sb.append(if (dangers.isEmpty()) "\n⛔ علامات خطر: لا شيء ✔\n" else "\n⛔ علامات خطر:\n")
        dangers.forEach { sb.append("  [${it.weight}] ${it.message}\n") }
        sb.append(if (mods.isEmpty()) "\n🔧 علامات تعديل: لا شيء، يبدو أصلياً ✔\n" else "\n🔧 علامات تعديل (ليست خطراً بحد ذاتها):\n")
        mods.forEach { sb.append("  [${it.weight}] ${it.message}\n") }
        sb.append("\nدرجة الخطر: $riskScore/100 - ${level.label}\n")
        sb.append(level.explanation).append('\n')
        sb.append("درجة التعديل: $modScore/100 - ").append(if (isModified) "معدّل" else "أصلي على الأرجح").append('\n')
        if (advice.isNotEmpty()) {
            sb.append("\nنصائح:\n")
            advice.forEach { sb.append("  • ").append(it).append('\n') }
        }
        sb.append("\nتذكير: هذا فحص ثابت (لا يشغّل التطبيق)، ولا يوجد فحص يضمن الأمان 100%.\n")
        return sb.toString()
    }
}
