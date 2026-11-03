package io.github.mednouaoury.apksentry.core

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class VtResult(val malicious: Int, val suspicious: Int, val detections: List<String>) {
    val bad get() = malicious + suspicious
}

/**
 * يبحث عن البصمة (SHA-256) فقط في VirusTotal. لا يرفع أي ملف.
 * الحساب المجاني: 4 طلبات في الدقيقة، لذلك ننتظر بين الطلبات.
 */
class VirusTotal(private val apiKey: String, private val checkCancel: () -> Unit = {}) {
    private var lastRequest = 0L

    /** يرجع null إذا لم يكن الملف معروفاً لديهم. */
    fun lookup(sha256: String): VtResult? {
        repeat(2) { attempt ->
            waitTurn()
            val conn = URL("https://www.virustotal.com/api/v3/files/$sha256").openConnection() as HttpURLConnection
            conn.setRequestProperty("x-apikey", apiKey)
            conn.connectTimeout = 30_000
            conn.readTimeout = 60_000
            try {
                when (val code = conn.responseCode) {
                    200 -> return parse(conn.inputStream.use { String(it.readAllCompat(), Charsets.UTF_8) })
                    404 -> return null
                    401, 403 -> throw IOException("مفتاح VirusTotal غير صحيح")
                    429 -> if (attempt == 0) sleepChecked(60_000) else throw IOException("تجاوزت حد الطلبات في VirusTotal")
                    else -> throw IOException("VirusTotal أرجع الرمز $code")
                }
            } finally {
                conn.disconnect()
            }
        }
        throw IOException("تجاوزت حد الطلبات في VirusTotal")
    }

    private fun waitTurn() {
        val wait = lastRequest + 15_500 - System.currentTimeMillis()
        if (wait > 0) sleepChecked(wait)
        lastRequest = System.currentTimeMillis()
    }

    private fun sleepChecked(ms: Long) {
        val until = System.currentTimeMillis() + ms
        while (System.currentTimeMillis() < until) {
            checkCancel()
            Thread.sleep(minOf(500L, until - System.currentTimeMillis()).coerceAtLeast(1))
        }
    }

    companion object {
        @Suppress("UNCHECKED_CAST")
        fun parse(json: String): VtResult? {
            val root = Json.parse(json) as? Map<String, Any?> ?: return null
            val attrs = ((root["data"] as? Map<String, Any?>)?.get("attributes") as? Map<String, Any?>) ?: return null
            val stats = attrs["last_analysis_stats"] as? Map<String, Any?> ?: return null
            val results = attrs["last_analysis_results"] as? Map<String, Any?> ?: emptyMap()
            val dets = results.mapNotNull { (engine, v) ->
                val r = v as? Map<String, Any?> ?: return@mapNotNull null
                val cat = r["category"] as? String
                if (cat == "malicious" || cat == "suspicious") "$engine: ${r["result"]}" else null
            }.sorted()
            fun n(k: String) = (stats[k] as? Number)?.toInt() ?: 0
            return VtResult(n("malicious"), n("suspicious"), dets)
        }
    }
}

/** محلل JSON صغير (لا نريد مكتبات إضافية). */
object Json {
    fun parse(s: String): Any? = P(s).run { ws(); value() }

    private class P(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && s[i].isWhitespace()) i++ }
        fun value(): Any? {
            ws()
            if (i >= s.length) throw IOException("bad json")
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> { i += 4; true }
                'f' -> { i += 5; false }
                'n' -> { i += 4; null }
                else -> num()
            }
        }
        fun obj(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++; ws()
            if (s[i] == '}') { i++; return m }
            while (true) {
                ws(); val k = str(); ws(); i++ // ':'
                m[k] = value(); ws()
                if (s[i] == ',') { i++; continue }
                i++; return m
            }
        }
        fun arr(): List<Any?> {
            val l = ArrayList<Any?>()
            i++; ws()
            if (s[i] == ']') { i++; return l }
            while (true) {
                l.add(value()); ws()
                if (s[i] == ',') { i++; continue }
                i++; return l
            }
        }
        fun str(): String {
            val sb = StringBuilder()
            i++
            while (s[i] != '"') {
                val c = s[i++]
                if (c == '\\') {
                    when (val e = s[i++]) {
                        'n' -> sb.append('\n'); 't' -> sb.append('\t'); 'r' -> sb.append('\r')
                        'b' -> sb.append('\b'); 'f' -> sb.append('\u000c')
                        'u' -> { sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                        else -> sb.append(e)
                    }
                } else sb.append(c)
            }
            i++
            return sb.toString()
        }
        fun num(): Number {
            val st = i
            while (i < s.length && (s[i].isDigit() || s[i] in "+-.eE")) i++
            val t = s.substring(st, i)
            return t.toLongOrNull() ?: t.toDouble()
        }
    }
}

class MbResult(val signature: String?, val tags: List<String>)

/**
 * MalwareBazaar (abuse.ch): قاعدة بيانات مجانية لعينات الفيروسات.
 * نبحث بالبصمة فقط. يحتاج مفتاحاً مجانياً من auth.abuse.ch.
 */
class MalwareBazaar(private val authKey: String) {
    /** يرجع null إذا لم تكن البصمة معروفة كفيروس. */
    @Suppress("UNCHECKED_CAST")
    fun lookup(sha256: String): MbResult? {
        val conn = URL("https://mb-api.abuse.ch/api/v1/").openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.connectTimeout = 30_000
        conn.readTimeout = 60_000
        conn.setRequestProperty("Auth-Key", authKey)
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        try {
            conn.outputStream.use { it.write("query=get_info&hash=$sha256".toByteArray()) }
            val code = conn.responseCode
            if (code == 401 || code == 403) throw IOException("مفتاح MalwareBazaar غير صحيح")
            if (code != 200) throw IOException("MalwareBazaar أرجع الرمز $code")
            val root = Json.parse(conn.inputStream.use { String(it.readAllCompat(), Charsets.UTF_8) }) as? Map<String, Any?>
                ?: throw IOException("رد غير مفهوم من MalwareBazaar")
            return when (val status = root["query_status"]) {
                "ok" -> {
                    val item = (root["data"] as? List<Any?>)?.firstOrNull() as? Map<String, Any?>
                    MbResult(item?.get("signature") as? String, (item?.get("tags") as? List<Any?>)?.mapNotNull { it as? String } ?: emptyList())
                }
                "hash_not_found", "no_results" -> null
                "unknown_auth_key", "no_api_key" -> throw IOException("مفتاح MalwareBazaar غير صحيح")
                else -> throw IOException("MalwareBazaar: $status")
            }
        } finally {
            conn.disconnect()
        }
    }
}
