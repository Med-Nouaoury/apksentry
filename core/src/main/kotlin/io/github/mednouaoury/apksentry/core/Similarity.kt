package io.github.mednouaoury.apksentry.core

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** فيروس معروف: بصمته التقريبية واسم عائلته. */
class SimEntry(val tlsh: String, val sha256: String, val family: String) {
    internal val digest: Tlsh.Digest? = Tlsh.parse(tlsh)
}

class SimMatch(val entry: SimEntry, val distance: Int)

/**
 * قاعدة البصمات التقريبية للفيروسات المعروفة (محفوظة على الهاتف).
 * كل سطر: tlsh,sha256,العائلة
 */
class SimilarityDb(entries: List<SimEntry>) {
    val entries: List<SimEntry> = entries.filter { it.digest != null }
    val size get() = entries.size

    /** أقرب فيروس معروف لهذه البصمة. */
    fun nearest(tlsh: String): SimMatch? {
        val d = Tlsh.parse(tlsh) ?: return null
        var best: SimMatch? = null
        for (e in entries) {
            val dist = Tlsh.distance(d, e.digest!!)
            if (best == null || dist < best.distance) best = SimMatch(e, dist)
        }
        return best
    }

    fun serialize(): String = buildString {
        append("# ApkSentry: بصمات TLSH لفيروسات أندرويد معروفة (المصدر: MalwareBazaar)\n")
        for (e in entries) append(e.tlsh).append(',').append(e.sha256).append(',').append(e.family.replace(',', ' ')).append('\n')
    }

    /** يدمج عينات جديدة مع القديمة (بدون تكرار)، ويحتفظ بالأحدث إذا تجاوزنا الحد. */
    fun merge(fresh: List<SimEntry>, max: Int = 50_000): SimilarityDb {
        val map = LinkedHashMap<String, SimEntry>()
        for (e in fresh) map[e.sha256] = e
        for (e in entries) map.putIfAbsent(e.sha256, e)
        return SimilarityDb(map.values.take(max))
    }

    companion object {
        val EMPTY = SimilarityDb(emptyList())

        fun parse(text: String): SimilarityDb = SimilarityDb(text.lineSequence().mapNotNull { l ->
            val t = l.trim()
            if (t.isEmpty() || t.startsWith("#")) return@mapNotNull null
            val p = t.split(',', limit = 3)
            if (p.size < 2) null else SimEntry(p[0].trim(), p[1].trim().lowercase(), p.getOrNull(2)?.trim().orEmpty().ifEmpty { "غير مسمّى" })
        }.toList())

        /**
         * المسافة TLSH بين ملفّي APK كاملين. جرّبناها: نسخة معدّلة من تطبيق تبعد عنه ~13،
         * وتطبيقات لا علاقة بينها تبعد 250 فما فوق.
         */
        const val VERY_CLOSE = 40
        const val CLOSE = 70
    }
}

/** جلب أحدث عينات APK من MalwareBazaar مع بصماتها التقريبية. */
object MalwareBazaarFeed {
@Suppress("UNCHECKED_CAST")
fun recentApks(authKey: String, limit: Int = 1000): List<SimEntry> {
    val conn = URL("https://mb-api.abuse.ch/api/v1/").openConnection() as HttpURLConnection
    conn.requestMethod = "POST"
    conn.doOutput = true
    conn.connectTimeout = 30_000
    conn.readTimeout = 120_000
    conn.setRequestProperty("Auth-Key", authKey)
    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
    try {
        conn.outputStream.use { it.write("query=get_file_type&file_type=apk&limit=$limit".toByteArray()) }
        val code = conn.responseCode
        if (code == 401 || code == 403) throw IOException("مفتاح MalwareBazaar غير صحيح")
        if (code != 200) throw IOException("MalwareBazaar أرجع الرمز $code")
        val root = Json.parse(conn.inputStream.use { String(it.readAllCompat(), Charsets.UTF_8) }) as? Map<String, Any?>
            ?: throw IOException("رد غير مفهوم من MalwareBazaar")
        when (val status = root["query_status"]) {
            "ok" -> {}
            "unknown_auth_key", "no_api_key" -> throw IOException("مفتاح MalwareBazaar غير صحيح")
            else -> throw IOException("MalwareBazaar: $status")
        }
        return (root["data"] as? List<Any?>).orEmpty().mapNotNull { it as? Map<String, Any?> }.mapNotNull { m ->
            val t = m["tlsh"] as? String ?: return@mapNotNull null
            val sha = m["sha256_hash"] as? String ?: return@mapNotNull null
            val fam = (m["signature"] as? String) ?: (m["tags"] as? List<Any?>)?.firstOrNull { it is String && it.lowercase() != "apk" } as? String ?: "غير مسمّى"
            SimEntry(t, sha.lowercase(), fam)
        }.filter { it.digest != null }
    } finally {
        conn.disconnect()
    }
}
}
