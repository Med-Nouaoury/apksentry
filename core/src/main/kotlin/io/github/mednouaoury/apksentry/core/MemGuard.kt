package io.github.mednouaoury.apksentry.core

/** الذاكرة على وشك النفاد: نوقف المرحلة الحالية بهدوء بدل أن يسقط التطبيق كله. */
class LowMemoryException : RuntimeException("ذاكرة الهاتف قاربت على النفاد")

/**
 * حارس الذاكرة: الحدود الثابتة لا تكفي، لأن الذاكرة المتاحة تختلف من هاتف لآخر ومن ملف لآخر
 * (تطبيق ضخم مثل TikTok يستهلك نصفها قبل أي محاكاة). نقيس الذاكرة الحرة فعلاً، ونترك دائماً هامشاً.
 */
object MemGuard {
    /** الهامش الذي لا نلمسه أبداً (لباقي التطبيق والواجهة). */
    const val RESERVE = 72L * 1024 * 1024
    @Volatile private var lastGc = 0L
    private var calls = 0

    fun free(): Long {
        val r = Runtime.getRuntime()
        return r.maxMemory() - (r.totalMemory() - r.freeMemory())
    }

    /** الذاكرة الحرة بعد تنظيف (يُستعمل قبل قرار كبير، مثل تشغيل المحاكاة). */
    fun freeAfterGc(): Long {
        System.gc()
        lastGc = System.currentTimeMillis()
        return free()
    }

    /** يرمي [LowMemoryException] إذا نزلت الذاكرة الحرة تحت الهامش. خفيف: يقيس مرة كل [every] استدعاء. */
    fun check(every: Int = 256) {
        if (++calls % every != 0) return
        if (free() >= RESERVE) return
        // قد تكون ذاكرة غير محرّرة بعد: ننظّف مرة (ليس أكثر من مرة كل ثانيتين) ثم نعيد القياس
        val now = System.currentTimeMillis()
        if (now - lastGc > 2000) { System.gc(); lastGc = now }
        if (free() < RESERVE) throw LowMemoryException()
    }
}
