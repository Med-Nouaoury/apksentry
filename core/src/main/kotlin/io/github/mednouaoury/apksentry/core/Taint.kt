package io.github.mednouaoury.apksentry.core

/** مصادر البيانات الشخصية. */
enum class Src(val label: String) {
    DEVICE_ID("معرّفات الهاتف أو رقمه"),
    LOCATION("موقعك"),
    CONTACTS_SMS("جهات الاتصال أو سجل المكالمات"),
    ACCOUNTS("حساباتك"),
    CLIPBOARD("الحافظة (ما تنسخه)"),
    APP_LIST("قائمة تطبيقاتك"),
    SMS_IN("الرسائل الواردة"),
    AUDIO("صوت الميكروفون"),
    NOTIFICATIONS("إشعاراتك"),
    SCREEN_TEXT("نصوص الشاشة (عبر إمكانية الوصول)"),
    COOKIES("كوكيز المتصفح"),
    SMS_DB("رسائلك SMS المحفوظة"),
}

/** أماكن خروج البيانات. */
enum class Sink(val label: String, val weight: Int) {
    NETWORK("الإنترنت", 30),
    SMS("رسائل SMS", 35),
    WEBVIEW("صفحة ويب", 20),
    LOG("سجل النظام (Log)", 0),
}

/** تسرّب: بيانات من [sources] تصل إلى [sink] داخل الوظيفة [where]. */
class Flow(val sources: Set<Src>, val sink: Sink, val where: String, val origin: String)

class Decryptor(val method: String, val calls: Int, val origin: String)

class TaintResult(
    val flows: List<Flow>,
    val decryptors: List<Decryptor>,
    val analyzedMethods: Int,
    val totalMethods: Int,
    val truncated: Boolean,
)

/**
 * تحليل تدفّق البيانات (taint analysis):
 * نتبع القيم من المصادر (IMEI، الموقع، الحافظة...) عبر السجلات والحقول واستدعاء الوظائف،
 * حتى تصل إلى مخرج (الإنترنت، SMS...). التحليل حسب ترتيب التنفيذ (flow-sensitive) داخل كل وظيفة،
 * ومع ملخّصات للوظائف (inter-procedural) تُعاد حتى تستقر.
 */
class TaintAnalyzer(
    private val dexes: List<DexFile>,
    private val own: List<String>,
    private val checkCancel: () -> Unit,
    private val maxMethods: Int = 60_000,
    /** حد زمني حتى لا يعلق الفحص في تطبيقات ضخمة أو مُعدّة لإبطاء التحليل. */
    private val maxMillis: Long = 120_000,
) {
    companion object {
        private const val SRC_MASK = (1L shl 20) - 1
        private const val NETSTREAM = 1L shl 20
        private const val PRIVATE_URI = 1L shl 21
        private const val SMS_URI = 1L shl 22
        private val SMS_URI_RE = Regex("content://(sms|mms)", RegexOption.IGNORE_CASE)
        private const val LOCAL_MASK = (1L shl 32) - 1
        private const val PARAM_MASK = LOCAL_MASK.inv()
        private fun bit(s: Src) = 1L shl s.ordinal
        private fun paramBit(slot: Int) = if (slot < 32) 1L shl (32 + slot) else 0L

        private fun names(cls: List<String>, vararg ms: String) = cls.flatMap { c -> ms.map { "$c->$it" } }

        private val SOURCES: Map<String, Src> = buildMap {
            names(listOf("Landroid/telephony/TelephonyManager;"), "getDeviceId", "getImei", "getMeid", "getSubscriberId",
                "getLine1Number", "getSimSerialNumber", "getVoiceMailNumber").forEach { put(it, Src.DEVICE_ID) }
            names(listOf("Landroid/location/LocationManager;"), "getLastKnownLocation").forEach { put(it, Src.LOCATION) }
            names(listOf("Lcom/google/android/gms/location/FusedLocationProviderClient;"), "getLastLocation", "getCurrentLocation").forEach { put(it, Src.LOCATION) }
            names(listOf("Landroid/accounts/AccountManager;"), "getAccounts", "getAccountsByType", "getAuthToken",
                "blockingGetAuthToken", "getPassword", "peekAuthToken").forEach { put(it, Src.ACCOUNTS) }
            names(listOf("Landroid/content/ClipboardManager;", "Landroid/text/ClipboardManager;"), "getPrimaryClip", "getText").forEach { put(it, Src.CLIPBOARD) }
            names(listOf("Landroid/content/pm/PackageManager;"), "getInstalledPackages", "getInstalledApplications").forEach { put(it, Src.APP_LIST) }
            names(listOf("Landroid/telephony/SmsMessage;", "Landroid/telephony/gsm/SmsMessage;"), "createFromPdu", "getMessageBody",
                "getDisplayMessageBody", "getOriginatingAddress", "getDisplayOriginatingAddress").forEach { put(it, Src.SMS_IN) }
            names(listOf("Landroid/provider/Telephony\$Sms\$Intents;"), "getMessagesFromIntent").forEach { put(it, Src.SMS_IN) }
            names(listOf("Landroid/service/notification/StatusBarNotification;"), "getNotification").forEach { put(it, Src.NOTIFICATIONS) }
            names(listOf("Landroid/view/accessibility/AccessibilityEvent;", "Landroid/view/accessibility/AccessibilityNodeInfo;",
                "Landroid/view/accessibility/AccessibilityRecord;"), "getText", "getContentDescription").forEach { put(it, Src.SCREEN_TEXT) }
            names(listOf("Landroid/webkit/CookieManager;"), "getCookie").forEach { put(it, Src.COOKIES) }
        }

        /** مصادر تملأ أحد الوسائط بدل أن ترجع قيمة (مثل AudioRecord.read(buffer)). */
        private val ARG_SOURCES = mapOf("Landroid/media/AudioRecord;->read" to (1 to Src.AUDIO))

        private val CONNECTIONS = listOf("Ljava/net/URLConnection;", "Ljava/net/HttpURLConnection;", "Ljavax/net/ssl/HttpsURLConnection;")

        private val SINKS: Map<String, Sink> = buildMap {
            names(listOf("Ljava/net/URL;"), "<init>").forEach { put(it, Sink.NETWORK) }
            names(CONNECTIONS, "setRequestProperty", "addRequestProperty").forEach { put(it, Sink.NETWORK) }
            names(listOf("Lokhttp3/Request\$Builder;"), "url", "header", "addHeader", "post", "put", "patch").forEach { put(it, Sink.NETWORK) }
            names(listOf("Lokhttp3/RequestBody;", "Lokhttp3/RequestBody\$Companion;"), "create").forEach { put(it, Sink.NETWORK) }
            names(listOf("Lokhttp3/FormBody\$Builder;"), "add", "addEncoded").forEach { put(it, Sink.NETWORK) }
            names(listOf("Lokhttp3/MultipartBody\$Builder;"), "addFormDataPart").forEach { put(it, Sink.NETWORK) }
            names(listOf("Lokhttp3/HttpUrl\$Builder;"), "addQueryParameter", "addEncodedQueryParameter").forEach { put(it, Sink.NETWORK) }
            names(listOf("Ljava/net/DatagramPacket;"), "<init>").forEach { put(it, Sink.NETWORK) }
            names(listOf("Lorg/apache/http/entity/StringEntity;", "Lorg/apache/http/client/entity/UrlEncodedFormEntity;"), "<init>").forEach { put(it, Sink.NETWORK) }
            names(listOf("Landroid/telephony/SmsManager;"), "sendTextMessage", "sendMultipartTextMessage", "sendDataMessage").forEach { put(it, Sink.SMS) }
            names(listOf("Landroid/webkit/WebView;"), "loadUrl", "postUrl", "evaluateJavascript", "loadDataWithBaseURL").forEach { put(it, Sink.WEBVIEW) }
            names(listOf("Landroid/util/Log;"), "d", "i", "v", "w", "e", "wtf").forEach { put(it, Sink.LOG) }
        }

        private val NETSTREAM_PRODUCERS = (names(CONNECTIONS, "getOutputStream") +
            names(listOf("Ljava/net/Socket;", "Ljavax/net/ssl/SSLSocket;"), "getOutputStream")).toSet()

        private val STREAM_WRITES = setOf("write", "print", "println", "append", "writeBytes", "writeUTF", "writeChars", "format", "printf")

        private val PRIVATE_URI_CLASSES = listOf("Landroid/provider/ContactsContract", "Landroid/provider/CallLog", "Landroid/provider/Telephony")

        private val CALLBACK_PARAM_TYPES = mapOf(
            "Landroid/location/Location;" to Src.LOCATION,
            "Lcom/google/android/gms/location/LocationResult;" to Src.LOCATION,
            "Landroid/view/accessibility/AccessibilityEvent;" to Src.SCREEN_TEXT,
            "Landroid/service/notification/StatusBarNotification;" to Src.NOTIFICATIONS,
        )

        private val DECRYPT_ARG = setOf("Ljava/lang/String;", "[B", "[C")

        /** فك نوع المعاملات إلى مواقعها (slots). long و double تأخذ موقعين. */
        fun paramSlots(proto: String, isStatic: Boolean): List<Pair<Int, String>> {
            val out = ArrayList<Pair<Int, String>>()
            var slot = if (isStatic) 0 else 1
            var i = 1
            while (i < proto.length && proto[i] != ')') {
                val start = i
                while (proto[i] == '[') i++
                if (proto[i] == 'L') i = proto.indexOf(';', i)
                i++
                val t = proto.substring(start, i)
                out.add(slot to t)
                slot += if (t == "J" || t == "D") 2 else 1
            }
            return out
        }

        fun readable(key: String): String {
            val cls = key.substringBefore("->").trim('L', ';').replace('/', '.')
            val name = key.substringAfter("->").substringBefore('(')
            return "$cls.$name()"
        }
    }

    private class MethodInfo(val dex: DexFile, val idx: Int, val access: Int, val codeOff: Int, val key: String, val origin: String) {
        val isStatic get() = access and 0x8 != 0
        var relevant = false
        var callees: IntArray = Insn.EMPTY
    }

    private class Summary {
        var ret = 0L
        val toSink = LongArray(Sink.entries.size)
    }

    private val methods = ArrayList<MethodInfo>()
    private val byKey = HashMap<String, Int>()
    private val summaries = HashMap<Int, Summary>()
    private val fields = HashMap<String, Long>()
    private val flows = LinkedHashMap<String, Flow>()
    private val decryptCalls = HashMap<String, Int>()
    private val decryptGarbled = HashMap<String, Int>()

    fun run(): TaintResult {
        // 1) كل الوظائف التي لها كود (كود مشترك بين وظيفتين = ملف مُعدّ للإبطاء، نتجاهل التكرار)
        for (dex in dexes) {
            val seenCode = HashSet<Int>()
            for (c in 0 until dex.classCount) {
                if (c % 256 == 0) checkCancel()
                val cls = dex.className(c)
                val origin = Scanner.origin(cls, own)
                dex.forEachMethod(c) { m, access, code ->
                    if (code > 0 && seenCode.add(code)) {
                        val key = dex.methodKey(m)
                        if (key !in byKey) {
                            byKey[key] = methods.size
                            methods.add(MethodInfo(dex, m, access, code, key, origin))
                        }
                    }
                }
            }
        }
        // 2) مرور أول: الوظائف المهمة (تلمس مصدراً أو مخرجاً) + كشف دوال فك التشفير
        val callers = HashMap<Int, MutableList<Int>>()
        for ((i, mi) in methods.withIndex()) {
            if (i % 512 == 0) checkCancel()
            val code = DexDecoder.decode(mi.dex, mi.codeOff) ?: continue
            val callees = ArrayList<Int>()
            val constReg = HashMap<Int, Int>()
            for (x in code.insns) {
                when (x.op) {
                    Op.INVOKE -> if (x.idx >= 0) {
                        val name = mi.dex.methodFull(x.idx)
                        if (name in SOURCES || name in SINKS || name in NETSTREAM_PRODUCERS || name in ARG_SOURCES) mi.relevant = true
                        val k = mi.dex.methodKey(x.idx)
                        byKey[k]?.let { callees.add(it) }
                        if (x.static && x.srcs.isNotEmpty()) checkDecryptor(mi.dex, x, k, constReg)
                    }
                    Op.SGET -> if (PRIVATE_URI_CLASSES.any { mi.dex.fieldFull(x.idx).startsWith(it) }) mi.relevant = true
                    Op.CONST_STRING -> {
                        val s = mi.dex.string(x.idx)
                        if (Rules.PRIVATE_URIS.containsMatchIn(s)) mi.relevant = true
                        constReg[x.dst] = x.idx
                        continue
                    }
                    else -> {}
                }
                if (x.dst >= 0) constReg.remove(x.dst)
            }
            if (!mi.relevant) mi.relevant = paramSlots(mi.dex.methodProto(mi.idx), mi.isStatic).any { it.second in CALLBACK_PARAM_TYPES }
            mi.callees = callees.toIntArray()
            for (c in callees) callers.getOrPut(c) { ArrayList() }.add(i)
        }
        // من يستدعي وظيفة مهمة يصبح مهماً
        val queue = ArrayDeque(methods.indices.filter { methods[it].relevant })
        while (queue.isNotEmpty()) {
            val m = queue.removeFirst()
            callers[m]?.forEach { c -> if (!methods[c].relevant) { methods[c].relevant = true; queue.add(c) } }
        }
        val relevant = methods.indices.filter { methods[it].relevant }
        var truncated = relevant.size > maxMethods
        val work = if (truncated) relevant.take(maxMethods) else relevant
        val deadline = System.currentTimeMillis() + maxMillis
        // 3) جولات حتى تستقر الملخّصات
        rounds@ for (round in 0 until 6) {
            var changed = false
            for ((n, i) in work.withIndex()) {
                if (n % 128 == 0) {
                    checkCancel()
                    if (System.currentTimeMillis() > deadline) { truncated = true; break@rounds }
                }
                if (analyze(i)) changed = true
            }
            if (!changed) break
        }
        val decryptors = decryptCalls.filter { (k, n) ->
            n >= 25 && (decryptGarbled[k] ?: 0) * 10 >= n * 8 && k in byKey
        }.map { (k, n) -> Decryptor(readable(k), n, methods[byKey.getValue(k)].origin) }.sortedByDescending { it.calls }
        return TaintResult(flows.values.toList(), decryptors, work.size, methods.size, truncated)
    }

    private fun checkDecryptor(dex: DexFile, x: Insn, key: String, constReg: Map<Int, Int>) {
        val proto = key.substring(key.indexOf('('))
        if (!proto.endsWith(")Ljava/lang/String;")) return
        val params = paramSlots(proto, true)
        if (params.isEmpty() || params.size > 3 || params.none { it.second in DECRYPT_ARG }) return
        val strArg = x.srcs.asList().firstNotNullOfOrNull { constReg[it] } ?: return
        decryptCalls.merge(key, 1, Int::plus)
        if (garbled(dex.string(strArg))) decryptGarbled.merge(key, 1, Int::plus)
    }

    /** نص يبدو مشفّراً: رموز غير مقروءة، أو نص طويل عشوائي بلا مسافات. */
    private fun garbled(s: String): Boolean {
        if (s.isEmpty()) return false
        // رموز التحكم (مثل تسلسلات الطرفية) عادية؛ المشفّر يظهر كرموز من مناطق غريبة
        val odd = s.count { it.code in 0x7f..0x9f || it.code in 0xd800..0xdfff || it.code in 0xe000..0xf8ff || (it.code > 0x2000 && !it.isLetter() && !it.isWhitespace()) }
        if (odd * 4 >= s.length) return true
        if (s.length >= 16 && ' ' !in s) {
            val freq = s.groupingBy { it }.eachCount()
            val ent = freq.values.sumOf { c -> val p = c.toDouble() / s.length; -p * kotlin.math.ln(p) / kotlin.math.ln(2.0) }
            if (ent >= 4.2) return true
        }
        return false
    }

    /** يحلّل وظيفة واحدة، ويرجع true إذا تغيّر ملخّصها أو الحقول. */
    private fun analyze(i: Int): Boolean {
        val mi = methods[i]
        val dex = mi.dex
        val code = DexDecoder.decode(dex, mi.codeOff) ?: return false
        if (code.registers > 4096 || code.insns.isEmpty()) return false
        val cfg = Cfg(code)
        val R = code.registers // آخر خانة = نتيجة آخر استدعاء
        val summary = summaries.getOrPut(i) { Summary() }
        val oldRet = summary.ret
        val oldSinks = summary.toSink.copyOf()
        var fieldsChanged = false

        val entry = LongArray(R + 1)
        val slots = paramSlots(dex.methodProto(mi.idx), mi.isStatic)
        for (s in 0 until code.ins) entry[code.firstParam + s] = paramBit(s)
        for ((slot, type) in slots) CALLBACK_PARAM_TYPES[type]?.let { src -> if (code.firstParam + slot < R) entry[code.firstParam + slot] = entry[code.firstParam + slot] or bit(src) }

        val inState = arrayOfNulls<LongArray>(cfg.size)
        inState[0] = entry
        val work = ArrayDeque<Int>().apply { add(0) }
        val queued = BooleanArray(cfg.size).also { it[0] = true }
        var steps = 0
        while (work.isNotEmpty() && steps++ < 20_000) {
            val b = work.removeFirst(); queued[b] = false
            val st = inState[b]!!.copyOf()
            for (k in cfg.blockStart[b] until cfg.blockEnd[b]) {
                transfer(mi, code.insns[k], st, summary, R)?.let { fieldsChanged = true }
            }
            for (s in cfg.succ[b]) {
                val cur = inState[s]
                if (cur == null) {
                    inState[s] = st.copyOf()
                    if (!queued[s]) { queued[s] = true; work.add(s) }
                } else {
                    var grew = false
                    for (r in 0..R) {
                        val v = cur[r] or st[r]
                        if (v != cur[r]) { cur[r] = v; grew = true }
                    }
                    if (grew && !queued[s]) { queued[s] = true; work.add(s) }
                }
            }
        }
        return fieldsChanged || summary.ret != oldRet || !summary.toSink.contentEquals(oldSinks)
    }

    /** أثر تعليمة واحدة على الحالة. يرجع Unit إذا تغيّرت الحقول العامة. */
    private fun transfer(mi: MethodInfo, x: Insn, st: LongArray, summary: Summary, R: Int): Unit? {
        val dex = mi.dex
        fun g(r: Int) = if (r in 0 until R) st[r] else 0L
        fun set(r: Int, v: Long) { if (r in 0 until R) st[r] = v }
        when (x.op) {
            Op.CONST, Op.NEW_INSTANCE, Op.NEW_ARRAY, Op.INSTANCE_OF, Op.ARRAY_LENGTH, Op.CONST_CLASS, Op.MOVE_EXCEPTION -> set(x.dst, 0)
            Op.CONST_STRING -> {
                val s = dex.string(x.idx)
                set(x.dst, when {
                    SMS_URI_RE.containsMatchIn(s) -> SMS_URI
                    Rules.PRIVATE_URIS.containsMatchIn(s) -> PRIVATE_URI
                    else -> 0
                })
            }
            Op.MOVE, Op.CHECK_CAST, Op.UNOP -> set(x.dst, g(x.srcs[0]))
            Op.BINOP -> set(x.dst, x.srcs.fold(0L) { a, r -> a or g(r) })
            Op.MOVE_RESULT -> set(x.dst, st[R])
            Op.AGET -> set(x.dst, g(x.srcs[0]))
            Op.APUT -> set(x.srcs[1], g(x.srcs[1]) or g(x.srcs[0]))
            Op.FILLED_NEW_ARRAY -> st[R] = x.srcs.fold(0L) { a, r -> a or g(r) }
            Op.RETURN -> summary.ret = summary.ret or g(x.srcs[0])
            Op.IGET, Op.SGET -> {
                val f = dex.fieldFull(x.idx)
                var v = fields[f] ?: 0L
                if (x.op == Op.SGET && PRIVATE_URI_CLASSES.any { f.startsWith(it) } && f.contains("URI"))
                    v = v or if (f.startsWith("Landroid/provider/Telephony")) SMS_URI else PRIVATE_URI
                set(x.dst, v)
            }
            Op.IPUT, Op.SPUT -> {
                val v = g(x.srcs[0]) and LOCAL_MASK
                if (v != 0L) {
                    val f = dex.fieldFull(x.idx)
                    val old = fields[f] ?: 0L
                    if (old or v != old) { fields[f] = old or v; return Unit }
                }
            }
            Op.INVOKE -> invoke(mi, x, st, summary, R)
            else -> {}
        }
        return null
    }

    private fun invoke(mi: MethodInfo, x: Insn, st: LongArray, summary: Summary, R: Int) {
        val dex = mi.dex
        fun g(r: Int) = if (r in 0 until R) st[r] else 0L
        val args = LongArray(x.srcs.size) { g(x.srcs[it]) }
        if (x.idx < 0) { st[R] = args.fold(0L) { a, v -> a or v }; return }
        val name = dex.methodFull(x.idx)
        val key = dex.methodKey(x.idx)
        val dataFrom = if (x.static) 0 else 1

        SINKS[name]?.let { sink -> hitSink(mi, summary, sink, args, dataFrom, readable(key)) }
        if (!x.static && args.isNotEmpty() && args[0] and NETSTREAM != 0L && name.substringAfter("->") in STREAM_WRITES) {
            hitSink(mi, summary, Sink.NETWORK, args, 1, "network stream")
        }
        ARG_SOURCES[name]?.let { (slot, src) -> if (slot < x.srcs.size) x.srcs[slot].let { r -> if (r in 0 until R) st[r] = st[r] or bit(src) } }

        val callee = byKey[key]?.let { summaries[it] }
        var result: Long
        if (callee != null) {
            result = callee.ret and LOCAL_MASK
            forParams(callee.ret) { p -> if (p < args.size) result = result or args[p] }
            for (s in Sink.entries) {
                val pk = callee.toSink[s.ordinal]
                if (pk == 0L) continue
                var m = 0L
                forParams(pk) { p -> if (p < args.size) m = m or args[p] }
                record(mi, summary, s, m, readable(key))
            }
        } else {
            // وظيفة من خارج التطبيق: النتيجة مشتقة من الوسائط، والكائن يأخذ ما أُضيف إليه
            result = args.fold(0L) { a, v -> a or v }
            if (!x.static && args.size > 1) {
                var rest = 0L
                for (k in 1 until args.size) rest = rest or args[k]
                if (rest != 0L) x.srcs[0].let { r -> if (r in 0 until R) st[r] = st[r] or rest }
            }
        }
        SOURCES[name]?.let { result = result or bit(it) }
        if (name in NETSTREAM_PRODUCERS) result = result or NETSTREAM
        if (name == "Landroid/content/ContentResolver;->query") {
            if (args.any { it and PRIVATE_URI != 0L }) result = result or bit(Src.CONTACTS_SMS)
            if (args.any { it and SMS_URI != 0L }) result = result or bit(Src.SMS_DB)
        }
        st[R] = result
    }

    private fun hitSink(mi: MethodInfo, summary: Summary, sink: Sink, args: LongArray, from: Int, via: String) {
        var m = 0L
        for (k in from until args.size) m = m or args[k]
        record(mi, summary, sink, m, via)
    }

    private fun record(mi: MethodInfo, summary: Summary, sink: Sink, m: Long, @Suppress("UNUSED_PARAMETER") via: String) {
        val src = m and SRC_MASK
        if (src != 0L) {
            val set = Src.entries.filter { src and bit(it) != 0L }.toSet()
            val k = "${mi.key}|${sink.name}|$src"
            if (k !in flows) flows[k] = Flow(set, sink, readable(mi.key), mi.origin)
        }
        summary.toSink[sink.ordinal] = summary.toSink[sink.ordinal] or (m and PARAM_MASK)
    }

    private inline fun forParams(mask: Long, f: (Int) -> Unit) {
        var m = (mask and PARAM_MASK) ushr 32
        var p = 0
        while (m != 0L) {
            if (m and 1L != 0L) f(p)
            m = m ushr 1; p++
        }
    }
}
