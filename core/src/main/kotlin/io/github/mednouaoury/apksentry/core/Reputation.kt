package io.github.mednouaoury.apksentry.core

/**
 * السمعة: واش هاد النسخة بالضبط جات من مصدر كيبني التطبيقات من الكود المصدري ويراجعها؟
 * المطابقة على التوقيع، ماشي على السمية: اللي عدّل التطبيق ما يقدرش يوقّع بنفس المفتاح.
 */
object Reputation {
    class Match(val source: String)

    private val fdroid: Map<String, Set<String>> by lazy { load("/reputation/fdroid-signers.tsv") }

    val fdroidSize: Int get() = fdroid.size

    /** كل التوقيعات خاصها تكون ديال هاد الحزمة ف F-Droid. */
    fun lookup(pkg: String, signers: Collection<String>): Match? {
        return if (matches(fdroid[pkg], signers)) Match("F-Droid") else null
    }

    internal fun matches(known: Set<String>?, signers: Collection<String>): Boolean =
        known != null && signers.isNotEmpty() && signers.all { it.lowercase() in known }

    private fun load(path: String): Map<String, Set<String>> = try {
        Reputation::class.java.getResourceAsStream(path)?.bufferedReader(Charsets.UTF_8)?.useLines { lines ->
            lines.filter { it.isNotBlank() && !it.startsWith("#") }.mapNotNull { l ->
                val tab = l.indexOf('\t')
                if (tab <= 0) null else l.substring(0, tab) to l.substring(tab + 1).split(',').map { it.trim() }.toSet()
            }.toMap()
        } ?: emptyMap()
    } catch (e: Exception) {
        emptyMap()
    }
}
