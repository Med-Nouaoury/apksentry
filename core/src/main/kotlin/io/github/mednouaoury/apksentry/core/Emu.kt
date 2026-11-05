package io.github.mednouaoury.apksentry.core

/**
 * محاكي Dalvik صغير لفك الكود المخفي (unpacking).
 *
 * الفكرة: الفيروس "المغلّف" يحمل كوده الحقيقي مشفّراً، ويفكّه عند التشغيل ثم يحمّله
 * بـ DexClassLoader. نحن ننفّذ كود الفك نفسه داخل هذا المحاكي، ونلتقط الكود الحقيقي
 * لحظة تحميله، ثم نفحصه بنفس المحرك.
 *
 * الأمان: المحاكي لا يشغّل أي كود حقيقي من التطبيق. كل تعليمة يفسّرها هو، وكل استدعاء
 * للنظام يمر عبر [EmuRuntime] الذي لا يسمح إلا بكلاسات آمنة (نصوص، تشفير، ضغط في الذاكرة)
 * ونظام ملفات وهمي. لا إنترنت، لا ملفات حقيقية، لا عمليات، وحدود صارمة للخطوات والذاكرة.
 */

/** تجاوزنا حدود المحاكاة (خطوات، عمق، ذاكرة، وقت). */
class EmuLimit(msg: String) : RuntimeException(msg)

/** شيء لا يدعمه المحاكي: نوقف هذا المسار. */
class EmuUnsupported(msg: String) : RuntimeException(msg)

/** استثناء داخل الكود المُحاكى (يمكن أن يلتقطه try/catch في الكود نفسه). */
class EmuThrow(val ex: Any?) : RuntimeException(null, null, false, false)

/** كائن من كلاس معرّف في التطبيق. */
class EObj(val cls: String) {
    val fields = HashMap<String, Any?>()
    override fun toString() = cls
}

/** كائن من النظام أُنشئ بـ new-instance ولم يُستدعَ مُنشئه بعد. */
class Pending(val cls: String) {
    var real: Any? = null
}

/** علامة النصف الثاني من سجل 64 بت. */
object WideHi

/** كلاس كما يراه الكود (Class.forName وغيره). */
class EClass(val desc: String) {
    override fun equals(other: Any?) = other is EClass && other.desc == desc
    override fun hashCode() = desc.hashCode()
    override fun toString() = desc
}

class AppMethod(val dex: DexFile, val cls: String, val name: String, val params: List<String>, val ret: String,
                val access: Int, val codeOff: Int) {
    val isStatic get() = access and 0x8 != 0
    val key get() = "$name(${params.joinToString("")})$ret"
}

class AppClass(val name: String, val dex: DexFile, val def: Int, val superName: String?) {
    val methods = HashMap<String, AppMethod>()
    val byName = HashMap<String, MutableList<AppMethod>>()
}

/** شيفرة وظيفة جاهزة للتنفيذ. */
private class Code(val regs: Int, val ins: Int, val units: IntArray, val triesOff: Int, val triesSize: Int, val handlersBase: Int)

class DalvikEmulator(dexes: List<DexFile>, private val rt: EmuRuntime) {
    val classes = HashMap<String, AppClass>()
    private val statics = HashMap<String, Any?>()
    private val initialized = HashSet<String>()
    private val codeCache = HashMap<Pair<DexFile, Int>, Code?>()
    var steps = 0L
        private set
    private var depth = 0

    init {
        dexes.forEach(::addDex)
    }

    fun addDex(dex: DexFile) {
        for (c in 0 until dex.classCount) {
            val name = dex.className(c)
            if (name in classes) continue
            val ac = AppClass(name, dex, c, dex.superName(c))
            dex.forEachMethod(c) { mi, access, codeOff ->
                val m = AppMethod(dex, name, dex.methodName(mi), dex.methodParams(mi), dex.methodReturn(mi), access, codeOff)
                ac.methods[m.key] = m
                ac.byName.getOrPut(m.name) { ArrayList() }.add(m)
            }
            classes[name] = ac
        }
    }

    fun isApp(cls: String) = cls in classes

    /** هل الكلاس (أو أحد آبائه في التطبيق) يرث من [base] (كلاس نظام)؟ */
    fun extends(cls: String, base: String): Boolean {
        var c: String? = cls
        var guard = 0
        while (c != null && guard++ < 64) {
            if (c == base) return true
            c = classes[c]?.superName
        }
        return false
    }

    /** أول كلاس نظام في سلسلة الوراثة. */
    fun frameworkBase(cls: String): String {
        var c: String = cls
        var guard = 0
        while (guard++ < 64) {
            val ac = classes[c] ?: return c
            c = ac.superName ?: return "Ljava/lang/Object;"
        }
        return "Ljava/lang/Object;"
    }

    fun findMethod(cls: String, key: String): AppMethod? {
        var c: String? = cls
        var guard = 0
        while (c != null && guard++ < 64) {
            val ac = classes[c] ?: return null
            ac.methods[key]?.let { return it }
            c = ac.superName
        }
        return null
    }

    // ---------------- الحقول الثابتة ----------------
    fun ensureInit(cls: String) {
        if (cls in initialized) return
        val ac = classes[cls] ?: return
        initialized.add(cls)
        ac.superName?.let { ensureInit(it) }
        loadStaticValues(ac)
        ac.methods["<clinit>()V"]?.let { invoke(it, emptyList()) }
    }

    private fun loadStaticValues(ac: AppClass) {
        val dex = ac.dex
        val fields = dex.staticFields(ac.def)
        for (f in fields) statics[dex.fieldFull(f)] = defaultOf(dex.fieldType(f))
        val off = dex.staticValuesOff(ac.def)
        if (off <= 0 || off >= dex.bytes.size) return
        try {
            val r = EncodedReader(dex, off)
            val n = r.uleb()
            for (i in 0 until minOf(n, fields.size)) statics[dex.fieldFull(fields[i])] = r.value()
        } catch (e: Exception) {
        }
    }

    fun getStatic(dex: DexFile, idx: Int): Any? {
        val cls = dex.fieldClass(idx)
        val key = dex.fieldFull(idx)
        if (isApp(cls)) {
            ensureInit(cls)
            // الحقل قد يكون معرّفاً في كلاس أب
            var c: String? = cls
            var guard = 0
            while (c != null && guard++ < 64) {
                val k = c + "->" + dex.fieldName(idx)
                if (statics.containsKey(k)) return statics[k]
                c = classes[c]?.superName
            }
            return statics[key] ?: defaultOf(dex.fieldType(idx))
        }
        return rt.getStatic(cls, dex.fieldName(idx), dex.fieldType(idx))
    }

    /** حقل ثابت بالاسم (لـ JNI). */
    fun staticByName(cls: String, name: String, type: String): Any? {
        if (!isApp(cls)) return rt.getStatic(cls, name, type)
        ensureInit(cls)
        var c: String? = cls
        var guard = 0
        while (c != null && guard++ < 64) {
            val k = "$c->$name"
            if (statics.containsKey(k)) return statics[k]
            c = classes[c]?.superName
        }
        return defaultOf(type)
    }

    fun putStaticByName(cls: String, name: String, v: Any?) { if (isApp(cls)) { ensureInit(cls); statics["$cls->$name"] = v } }

    fun putStatic(dex: DexFile, idx: Int, v: Any?) {
        val cls = dex.fieldClass(idx)
        if (isApp(cls)) ensureInit(cls)
        statics[dex.fieldFull(idx)] = v
    }

    // ---------------- الاستدعاء ----------------
    /** ينفّذ وظيفة من التطبيق. [args] بدون أنصاف السجلات العريضة؛ أولها this إن لم تكن ثابتة. */
    fun invoke(m: AppMethod, args: List<Any?>): Any? {
        if (m.codeOff == 0) {
            // native أو abstract
            if (m.access and 0x100 != 0) {
                // وظيفة native: ننفّذها في محاكي ARM64 (نفس الصندوق)
                val nat = rt.native() ?: throw EmuUnsupported("native ${m.cls}->${m.name}")
                frames.add(m)
                try { return nat.callFromJava(m, args) } finally { frames.removeAt(frames.size - 1) }
            }
            throw EmuUnsupported("abstract ${m.cls}->${m.name}")
        }
        val code = codeCache.getOrPut(m.dex to m.codeOff) { readCode(m.dex, m.codeOff) } ?: throw EmuUnsupported("bad code")
        if (++depth > 120) { depth--; throw EmuLimit("عمق الاستدعاءات") }
        frames.add(m)
        try {
            val regs = arrayOfNulls<Any?>(code.regs)
            var r = code.regs - code.ins
            var ai = 0
            if (!m.isStatic) { if (r < regs.size) regs[r] = args.getOrNull(0); r++; ai = 1 }
            for (p in m.params) {
                if (r >= regs.size) break
                regs[r] = args.getOrNull(ai++)
                if (p == "J" || p == "D") { if (r + 1 < regs.size) regs[r + 1] = WideHi; r += 2 } else r++
            }
            val result = run(m, code, regs)
            if (result is ByteArray) rt.inspectBytes(result, "${m.cls}->${m.name}")
            return result
        } finally {
            depth--
            frames.removeAt(frames.size - 1)
        }
    }

    /** الوظائف التي ننفّذها الآن (للـ stack trace: بعض الأغلفة تتحقق من هوية من استدعاها). */
    val frames = ArrayList<AppMethod>()

    /** يستدعي وظيفة باسمها (للمرجع من reflection أو من الكود). */
    fun dispatch(cls: String, name: String, params: List<String>, ret: String, args: List<Any?>, virtual: Boolean, isSuper: Boolean = false): Any? {
        val key = "$name(${params.joinToString("")})$ret"
        val recv = if (virtual || name == "<init>") args.getOrNull(0) else null
        if (virtual && !isSuper) {
            val target = deref(recv)
            if (target is EObj) {
                findMethod(target.cls, key)?.let { return invoke(it, args) }
                return rt.call(frameworkBase(target.cls), name, params, ret, target, args.drop(1), this)
            }
        }
        if (isApp(cls)) {
            if (!virtual) ensureInit(cls)
            val m = findMethod(cls, key)
            if (m != null) return invoke(m, args)
            if (isSuper || name == "<init>") {
                // استدعاء مُنشئ أو وظيفة أب من النظام (مثل super.attachBaseContext)
                return rt.call(frameworkBase(cls), name, params, ret, recv, args.drop(1), this)
            }
        }
        return if (virtual || name == "<init>") rt.call(cls, name, params, ret, recv, args.drop(1), this)
        else rt.call(cls, name, params, ret, null, args, this)
    }

    // ---------------- قراءة الشيفرة ----------------
    private fun readCode(dex: DexFile, off: Int): Code? {
        val d = dex.bytes
        if (off <= 0 || off + 16 > d.size) return null
        val regs = d.u16(off)
        val ins = d.u16(off + 2)
        val tries = d.u16(off + 6)
        val n = d.i32(off + 12)
        if (n <= 0 || n > 1_000_000 || off + 16 + n.toLong() * 2 > d.size || regs > 65535) return null
        val units = IntArray(n) { d.u16(off + 16 + it * 2) }
        var triesOff = off + 16 + n * 2
        if (n % 2 == 1) triesOff += 2
        return Code(regs, ins, units, triesOff, tries, triesOff + tries * 8)
    }

    // ---------------- حلقة التنفيذ ----------------
    private fun run(m: AppMethod, c: Code, v: Array<Any?>): Any? {
        val u = c.units
        val dex = m.dex
        var pc = 0
        var last: Any? = null
        var exception: Any? = null
        while (true) {
            if (pc < 0 || pc >= u.size) throw EmuUnsupported("pc خارج الحدود")
            if (++steps > rt.maxSteps) throw EmuLimit("عدد الخطوات")
            if (steps and 0xffff == 0L) rt.checkTime()
            val w = u[pc]
            val op = w and 0xff
            val a = (w ushr 8) and 0xff
            val a4 = (w ushr 8) and 0xf
            val b4 = (w ushr 12) and 0xf
            var next = pc + LEN[op]
            try {
                when (op) {
                    0x00 -> {
                        // payload أو nop: لا يُنفّذ عادة
                        if (w != 0) throw EmuUnsupported("تنفيذ بيانات")
                    }
                    0x01, 0x04, 0x07 -> { v[a4] = v[b4]; if (op == 0x04) v[a4 + 1] = WideHi }
                    0x02, 0x05, 0x08 -> { v[a] = v[u[pc + 1]]; if (op == 0x05) v[a + 1] = WideHi }
                    0x03, 0x06, 0x09 -> { v[u[pc + 1]] = v[u[pc + 2]]; if (op == 0x06) v[u[pc + 1] + 1] = WideHi }
                    0x0a, 0x0c -> v[a] = last
                    0x0b -> { v[a] = last; v[a + 1] = WideHi }
                    0x0d -> v[a] = exception
                    0x0e -> return null
                    0x0f, 0x10, 0x11 -> return deref(v[a])
                    0x12 -> v[a4] = (b4 shl 28) shr 28
                    0x13 -> v[a] = u[pc + 1].toShort().toInt()
                    0x14 -> v[a] = u[pc + 1] or (u[pc + 2] shl 16)
                    0x15 -> v[a] = u[pc + 1] shl 16
                    0x16 -> { v[a] = u[pc + 1].toShort().toLong(); v[a + 1] = WideHi }
                    0x17 -> { v[a] = (u[pc + 1] or (u[pc + 2] shl 16)).toLong(); v[a + 1] = WideHi }
                    0x18 -> {
                        v[a] = u[pc + 1].toLong() or (u[pc + 2].toLong() shl 16) or (u[pc + 3].toLong() shl 32) or (u[pc + 4].toLong() shl 48)
                        v[a + 1] = WideHi
                    }
                    0x19 -> { v[a] = u[pc + 1].toLong() shl 48; v[a + 1] = WideHi }
                    0x1a -> v[a] = dex.string(u[pc + 1])
                    0x1b -> v[a] = dex.string(u[pc + 1] or (u[pc + 2] shl 16))
                    0x1c -> v[a] = EClass(dex.type(u[pc + 1]))
                    0x1d, 0x1e -> {}
                    0x1f -> {} // check-cast: نثق في الكود
                    0x20 -> v[a4] = if (instanceOf(deref(v[b4]), dex.type(u[pc + 1]))) 1 else 0
                    0x21 -> v[a4] = arrayLength(v[b4])
                    0x22 -> {
                        val t = dex.type(u[pc + 1])
                        if (isApp(t)) { ensureInit(t); v[a] = EObj(t) } else v[a] = Pending(t)
                    }
                    0x23 -> v[a4] = newArray(dex.type(u[pc + 1]), asInt(v[b4]))
                    0x24, 0x25 -> {
                        val t = dex.type(u[pc + 1])
                        val regs = if (op == 0x24) args35c(w, u[pc + 2]) else IntArray(a) { u[pc + 2] + it }
                        last = when (t) {
                            "[I" -> IntArray(regs.size) { asInt(v[regs[it]]) }
                            else -> arrayOfNulls<Any?>(regs.size).also { arr -> regs.forEachIndexed { i, r -> arr[i] = v[r] } }
                        }
                    }
                    0x26 -> fillArray(v[a], u, pc + (u[pc + 1] or (u[pc + 2] shl 16)))
                    0x27 -> throw EmuThrow(deref(v[a]))
                    0x28 -> next = pc + a.toByte().toInt()
                    0x29 -> next = pc + u[pc + 1].toShort().toInt()
                    0x2a -> next = pc + (u[pc + 1] or (u[pc + 2] shl 16))
                    0x2b, 0x2c -> {
                        val p = pc + (u[pc + 1] or (u[pc + 2] shl 16))
                        val key = asInt(v[a])
                        val size = u[p + 1]
                        if (op == 0x2b) {
                            val first = u[p + 2] or (u[p + 3] shl 16)
                            val i = key - first
                            if (i in 0 until size) next = pc + (u[p + 4 + i * 2] or (u[p + 5 + i * 2] shl 16))
                        } else {
                            for (i in 0 until size) {
                                if ((u[p + 2 + i * 2] or (u[p + 3 + i * 2] shl 16)) == key) {
                                    val t = p + 2 + size * 2 + i * 2
                                    next = pc + (u[t] or (u[t + 1] shl 16)); break
                                }
                            }
                        }
                    }
                    in 0x2d..0x31 -> {
                        val b = u[pc + 1] and 0xff
                        val cc = u[pc + 1] ushr 8
                        v[a] = when (op) {
                            0x2d, 0x2e -> { val x = f(v[b]); val y = f(v[cc]); if (x.isNaN() || y.isNaN()) (if (op == 0x2d) -1 else 1) else x.compareTo(y) }
                            0x2f, 0x30 -> { val x = dd(v[b]); val y = dd(v[cc]); if (x.isNaN() || y.isNaN()) (if (op == 0x2f) -1 else 1) else x.compareTo(y) }
                            else -> asLong(v[b]).compareTo(asLong(v[cc]))
                        }
                    }
                    in 0x32..0x37 -> if (cmpIf(op - 0x32, v[a4], v[b4])) next = pc + u[pc + 1].toShort().toInt()
                    in 0x38..0x3d -> if (cmpIfZ(op - 0x38, v[a])) next = pc + u[pc + 1].toShort().toInt()
                    in 0x44..0x4a -> {
                        val arr = deref(v[u[pc + 1] and 0xff])
                        val i = asInt(v[u[pc + 1] ushr 8])
                        v[a] = aget(arr, i)
                        if (op == 0x45) v[a + 1] = WideHi
                    }
                    in 0x4b..0x51 -> aput(deref(v[u[pc + 1] and 0xff]), asInt(v[u[pc + 1] ushr 8]), v[a], op)
                    in 0x52..0x58 -> {
                        val fi = u[pc + 1]
                        v[a4] = iget(deref(v[b4]), dex, fi)
                        if (op == 0x53) v[a4 + 1] = WideHi
                    }
                    in 0x59..0x5f -> iput(deref(v[b4]), dex, u[pc + 1], v[a4])
                    in 0x60..0x66 -> { v[a] = getStatic(dex, u[pc + 1]); if (op == 0x61) v[a + 1] = WideHi }
                    in 0x67..0x6d -> putStatic(dex, u[pc + 1], v[a])
                    in 0x6e..0x72, in 0x74..0x78 -> {
                        val mi = u[pc + 1]
                        val regs = if (op <= 0x72) args35c(w, u[pc + 2]) else IntArray(a) { u[pc + 2] + it }
                        val kind = if (op <= 0x72) op - 0x6e else op - 0x74 // 0 virtual 1 super 2 direct 3 static 4 interface
                        val params = dex.methodParams(mi)
                        val args = ArrayList<Any?>(params.size + 1)
                        var r = 0
                        if (kind != 3) args.add(v[regs.getOrElse(r++) { 0 }])
                        for (p in params) {
                            args.add(v[regs.getOrElse(r) { 0 }])
                            r += if (p == "J" || p == "D") 2 else 1
                        }
                        val cls = dex.methodClass(mi)
                        val name = dex.methodName(mi)
                        val ret = dex.methodReturn(mi)
                        last = dispatch(cls, name, params, ret, args, virtual = kind == 0 || kind == 4 || kind == 1, isSuper = kind == 1)
                        if (name == "<init>" && kind == 2) {
                            // نربط الكائن الحقيقي بكل السجلات التي تشير إلى نفس Pending
                            val recv = args[0]
                            if (recv is Pending && recv.real == null) recv.real = last ?: recv
                        }
                    }
                    in 0x7b..0x8f -> v[a4] = unop(op, v[b4]).also { if (it is Long && op in WIDE_UNOP) v[a4 + 1] = WideHi }
                    in 0x90..0xaf -> {
                        val r = binop(op - 0x90, v[u[pc + 1] and 0xff], v[u[pc + 1] ushr 8])
                        v[a] = r; if (r is Long) v[a + 1] = WideHi
                    }
                    in 0xb0..0xcf -> {
                        val r = binop(op - 0xb0, v[a4], v[b4])
                        v[a4] = r; if (r is Long) v[a4 + 1] = WideHi
                    }
                    in 0xd0..0xd7 -> v[a4] = litop(op - 0xd0, asInt(v[b4]), u[pc + 1].toShort().toInt(), lit16 = true)
                    in 0xd8..0xe2 -> v[a] = litop(op - 0xd8, asInt(v[u[pc + 1] and 0xff]), (u[pc + 1] ushr 8).toByte().toInt(), lit16 = false)
                    else -> throw EmuUnsupported("تعليمة غير مدعومة 0x${op.toString(16)}")
                }
            } catch (t: EmuThrow) {
                val h = findHandler(dex, c, pc, t.ex) ?: throw t
                exception = t.ex
                next = h
            } catch (e: ArithmeticException) {
                val h = findHandler(dex, c, pc, e) ?: throw EmuThrow(e)
                exception = e
                next = h
            } catch (e: IndexOutOfBoundsException) {
                val h = findHandler(dex, c, pc, e) ?: throw EmuThrow(e)
                exception = e
                next = h
            } catch (e: NullPointerException) {
                val h = findHandler(dex, c, pc, e) ?: throw EmuThrow(e)
                exception = e
                next = h
            }
            pc = next
        }
    }

    /** يبحث عن معالج استثناء يغطي [pc]. نقبل المعالج إذا كان عاماً أو من نفس النوع. */
    private fun findHandler(dex: DexFile, c: Code, pc: Int, ex: Any?): Int? {
        val d = dex.bytes
        for (i in 0 until c.triesSize) {
            val o = c.triesOff + i * 8
            if (o + 8 > d.size) return null
            val start = d.i32(o)
            val count = d.u16(o + 4)
            if (pc < start || pc >= start + count) continue
            val r = EncodedReader(dex, c.handlersBase + d.u16(o + 6))
            val size = r.sleb()
            repeat(minOf(kotlin.math.abs(size), 64)) {
                val type = dex.type(r.uleb())
                val addr = r.uleb()
                if (catches(type, ex)) return addr
            }
            if (size <= 0) return r.uleb()
        }
        return null
    }

    private fun catches(type: String, ex: Any?): Boolean {
        if (type in BROAD_CATCH) return true
        val name = when (ex) {
            is EObj -> ex.cls
            is Throwable -> "L" + ex.javaClass.name.replace('.', '/') + ";"
            else -> return false
        }
        if (name == type) return true
        if (ex is EObj) return extends(ex.cls, type)
        if (ex is Throwable) {
            var k: Class<*>? = ex.javaClass
            while (k != null) {
                if ("L" + k.name.replace('.', '/') + ";" == type) return true
                k = k.superclass
            }
        }
        return false
    }

    // ---------------- أدوات ----------------
    fun deref(x: Any?): Any? = if (x is Pending) (x.real ?: x) else x

    private fun instanceOf(x: Any?, t: String): Boolean = when {
        x == null || x == 0 -> false
        x is EObj -> extends(x.cls, t) || t == "Ljava/lang/Object;"
        x is ByteArray -> t == "[B"
        x is IntArray -> t == "[I"
        x is String -> t == "Ljava/lang/String;" || t == "Ljava/lang/CharSequence;" || t == "Ljava/lang/Object;"
        else -> rt.instanceOf(x, t)
    }

    private fun arrayLength(x: Any?): Int = when (val o = deref(x)) {
        is ByteArray -> o.size; is IntArray -> o.size; is CharArray -> o.size; is ShortArray -> o.size
        is LongArray -> o.size; is FloatArray -> o.size; is DoubleArray -> o.size; is BooleanArray -> o.size
        is Array<*> -> o.size
        null, 0 -> throw NullPointerException()
        else -> throw EmuUnsupported("array-length على ${o.javaClass.simpleName}")
    }

    fun newArray(t: String, n: Int): Any {
        if (n < 0) throw EmuThrow(NegativeArraySizeException())
        rt.allocate(n.toLong() * when (t) { "[J", "[D" -> 8; "[I", "[F" -> 4; "[C", "[S" -> 2; else -> 1 })
        return when (t) {
            "[B" -> ByteArray(n); "[I" -> IntArray(n); "[C" -> CharArray(n); "[S" -> ShortArray(n)
            "[J" -> LongArray(n); "[F" -> FloatArray(n); "[D" -> DoubleArray(n); "[Z" -> BooleanArray(n)
            else -> arrayOfNulls<Any?>(n)
        }
    }

    private fun aget(arr: Any?, i: Int): Any? = when (arr) {
        is ByteArray -> arr[i].toInt()
        is IntArray -> arr[i]
        is CharArray -> arr[i].code
        is ShortArray -> arr[i].toInt()
        is BooleanArray -> if (arr[i]) 1 else 0
        is LongArray -> arr[i]
        is FloatArray -> arr[i].toRawBits()
        is DoubleArray -> arr[i].toRawBits()
        is Array<*> -> arr[i]
        null, 0 -> throw NullPointerException()
        else -> throw EmuUnsupported("aget على ${arr.javaClass.simpleName}")
    }

    private fun aput(arr: Any?, i: Int, x: Any?, op: Int) {
        when (arr) {
            is ByteArray -> arr[i] = asInt(x).toByte()
            is IntArray -> arr[i] = asInt(x)
            is CharArray -> arr[i] = asInt(x).toChar()
            is ShortArray -> arr[i] = asInt(x).toShort()
            is BooleanArray -> arr[i] = asInt(x) != 0
            is LongArray -> arr[i] = asLong(x)
            is FloatArray -> arr[i] = Float.fromBits(asInt(x))
            is DoubleArray -> arr[i] = Double.fromBits(asLong(x))
            is Array<*> -> @Suppress("UNCHECKED_CAST") (arr as Array<Any?>).set(i, if (op == 0x4d) deref(x) else x)
            null, 0 -> throw NullPointerException()
            else -> throw EmuUnsupported("aput على ${arr.javaClass.simpleName}")
        }
    }

    private fun fillArray(target: Any?, u: IntArray, p: Int) {
        if (p < 0 || p + 4 > u.size || u[p] != 0x0300) throw EmuUnsupported("fill-array-data")
        val width = u[p + 1]
        val count = u[p + 2] or (u[p + 3] shl 16)
        fun byteAt(i: Int): Int { val unit = u[p + 4 + i / 2]; return if (i % 2 == 0) unit and 0xff else unit ushr 8 }
        fun elem(k: Int): Long {
            var x = 0L
            for (b in 0 until width) x = x or (byteAt(k * width + b).toLong() shl (8 * b))
            return x
        }
        when (val arr = deref(target)) {
            is ByteArray -> for (k in 0 until minOf(count, arr.size)) arr[k] = elem(k).toByte()
            is BooleanArray -> for (k in 0 until minOf(count, arr.size)) arr[k] = elem(k) != 0L
            is ShortArray -> for (k in 0 until minOf(count, arr.size)) arr[k] = elem(k).toShort()
            is CharArray -> for (k in 0 until minOf(count, arr.size)) arr[k] = elem(k).toInt().toChar()
            is IntArray -> for (k in 0 until minOf(count, arr.size)) arr[k] = elem(k).toInt()
            is FloatArray -> for (k in 0 until minOf(count, arr.size)) arr[k] = Float.fromBits(elem(k).toInt())
            is LongArray -> for (k in 0 until minOf(count, arr.size)) arr[k] = elem(k)
            is DoubleArray -> for (k in 0 until minOf(count, arr.size)) arr[k] = Double.fromBits(elem(k))
            else -> throw EmuUnsupported("fill-array-data على نوع غير معروف")
        }
    }

    private fun iget(obj: Any?, dex: DexFile, fi: Int): Any? = when (obj) {
        is EObj -> if (obj.fields.containsKey(dex.fieldName(fi))) obj.fields[dex.fieldName(fi)] else defaultOf(dex.fieldType(fi))
        null, 0 -> throw NullPointerException()
        else -> rt.getField(obj, dex.fieldClass(fi), dex.fieldName(fi), dex.fieldType(fi))
    }

    private fun iput(obj: Any?, dex: DexFile, fi: Int, x: Any?) {
        when (obj) {
            is EObj -> obj.fields[dex.fieldName(fi)] = x
            null, 0 -> throw NullPointerException()
            else -> rt.setField(obj, dex.fieldName(fi), x)
        }
    }

    private fun isZero(x: Any?): Boolean = when (val o = deref(x)) {
        null -> true
        is Int -> o == 0
        is Long -> o == 0L
        else -> false
    }

    private fun cmpIfZ(k: Int, x: Any?): Boolean {
        if (k == 0) return isZero(x)
        if (k == 1) return !isZero(x)
        val i = asInt(x)
        return when (k) { 2 -> i < 0; 3 -> i >= 0; 4 -> i > 0; else -> i <= 0 }
    }

    private fun cmpIf(k: Int, x: Any?, y: Any?): Boolean {
        val dx = deref(x)
        val dy = deref(y)
        if (k <= 1 && (dx !is Int || dy !is Int)) {
            val eq = if (isZero(dx) && isZero(dy)) true else dx === dy || (dx is Int && dy is Int && dx == dy)
            return if (k == 0) eq else !eq
        }
        val i = asInt(dx)
        val j = asInt(dy)
        return when (k) { 0 -> i == j; 1 -> i != j; 2 -> i < j; 3 -> i >= j; 4 -> i > j; else -> i <= j }
    }

    private fun unop(op: Int, x: Any?): Any = when (op) {
        0x7b -> -asInt(x); 0x7c -> asInt(x).inv(); 0x7d -> -asLong(x); 0x7e -> asLong(x).inv()
        0x7f -> (-f(x)).toRawBits(); 0x80 -> (-dd(x)).toRawBits()
        0x81 -> asInt(x).toLong(); 0x82 -> asInt(x).toFloat().toRawBits(); 0x83 -> asInt(x).toDouble().toRawBits()
        0x84 -> asLong(x).toInt(); 0x85 -> asLong(x).toFloat().toRawBits(); 0x86 -> asLong(x).toDouble().toRawBits()
        0x87 -> f(x).toInt(); 0x88 -> f(x).toLong(); 0x89 -> f(x).toDouble().toRawBits()
        0x8a -> dd(x).toInt(); 0x8b -> dd(x).toLong(); 0x8c -> dd(x).toFloat().toRawBits()
        0x8d -> asInt(x).toByte().toInt(); 0x8e -> asInt(x) and 0xffff; 0x8f -> asInt(x).toShort().toInt()
        else -> throw EmuUnsupported("unop")
    }

    /** k: 0-10 int، 11-21 long، 22-26 float، 27-31 double (نفس ترتيب Dalvik). */
    private fun binop(k: Int, x: Any?, y: Any?): Any = when {
        k <= 10 -> { val a = asInt(x); val b = asInt(y)
            when (k) { 0 -> a + b; 1 -> a - b; 2 -> a * b; 3 -> a / b; 4 -> a % b; 5 -> a and b; 6 -> a or b; 7 -> a xor b
                8 -> a shl (b and 31); 9 -> a shr (b and 31); else -> a ushr (b and 31) } }
        k <= 21 -> { val a = asLong(x)
            when (k - 11) {
                8 -> a shl (asInt(y) and 63); 9 -> a shr (asInt(y) and 63); 10 -> a ushr (asInt(y) and 63)
                else -> { val b = asLong(y)
                    when (k - 11) { 0 -> a + b; 1 -> a - b; 2 -> a * b; 3 -> a / b; 4 -> a % b; 5 -> a and b; 6 -> a or b; else -> a xor b } }
            } }
        k <= 26 -> { val a = f(x); val b = f(y)
            when (k - 22) { 0 -> a + b; 1 -> a - b; 2 -> a * b; 3 -> a / b; else -> a.IEEErem(b) }.toRawBits() }
        else -> { val a = dd(x); val b = dd(y)
            when (k - 27) { 0 -> a + b; 1 -> a - b; 2 -> a * b; 3 -> a / b; else -> a.IEEErem(b) }.toRawBits() }
    }

    private fun Float.IEEErem(o: Float): Float = this % o
    private fun Double.IEEErem(o: Double): Double = this % o

    private fun litop(k: Int, a: Int, lit: Int, lit16: Boolean): Int = when (k) {
        0 -> a + lit; 1 -> lit - a; 2 -> a * lit; 3 -> a / lit; 4 -> a % lit; 5 -> a and lit; 6 -> a or lit; 7 -> a xor lit
        8 -> if (lit16) throw EmuUnsupported("lit16") else a shl (lit and 31)
        9 -> a shr (lit and 31)
        else -> a ushr (lit and 31)
    }

    companion object {
        private val BROAD_CATCH = setOf("Ljava/lang/Throwable;", "Ljava/lang/Exception;", "Ljava/lang/RuntimeException;",
            "Ljava/lang/Error;")
        private val WIDE_UNOP = setOf(0x7d, 0x7e, 0x80, 0x81, 0x83, 0x86, 0x88, 0x89, 0x8b)

        fun asInt(x: Any?): Int = when (val o = if (x is Pending) x.real else x) {
            is Int -> o; is Long -> o.toInt(); is Boolean -> if (o) 1 else 0; is Char -> o.code
            is Byte -> o.toInt(); is Short -> o.toInt(); is Float -> o.toRawBits(); null -> 0
            else -> throw EmuUnsupported("قيمة ليست رقماً: ${o.javaClass.simpleName}")
        }

        fun asLong(x: Any?): Long = when (x) {
            is Long -> x; is Int -> x.toLong(); is Double -> x.toRawBits(); null -> 0L
            else -> throw EmuUnsupported("قيمة ليست رقماً طويلاً")
        }

        fun f(x: Any?): Float = Float.fromBits(asInt(x))
        fun dd(x: Any?): Double = Double.fromBits(asLong(x))

        fun defaultOf(t: String): Any? = when (t) { "J", "D" -> 0L; "I", "Z", "B", "S", "C", "F" -> 0; else -> null }

        private fun args35c(w: Int, regs: Int): IntArray {
            val count = (w ushr 12) and 0xf
            val g = (w ushr 8) and 0xf
            val all = intArrayOf(regs and 0xf, (regs ushr 4) and 0xf, (regs ushr 8) and 0xf, (regs ushr 12) and 0xf, g)
            return all.copyOf(minOf(count, 5))
        }

        private val LEN = IntArray(256) { 1 }.also { t ->
            fun set(r: IntRange, v: Int) { for (i in r) t[i] = v }
            t[0x02] = 2; t[0x03] = 3; t[0x05] = 2; t[0x06] = 3; t[0x08] = 2; t[0x09] = 3
            t[0x13] = 2; t[0x14] = 3; t[0x15] = 2; t[0x16] = 2; t[0x17] = 3; t[0x18] = 5; t[0x19] = 2
            t[0x1a] = 2; t[0x1b] = 3; t[0x1c] = 2; t[0x1f] = 2; t[0x20] = 2; t[0x22] = 2; t[0x23] = 2
            t[0x24] = 3; t[0x25] = 3; t[0x26] = 3; t[0x29] = 2; t[0x2a] = 3; t[0x2b] = 3; t[0x2c] = 3
            set(0x2d..0x3d, 2)
            set(0x44..0x6d, 2)
            set(0x6e..0x72, 3); set(0x74..0x78, 3)
            set(0x90..0xaf, 2); set(0xd0..0xe2, 2)
            t[0xfa] = 4; t[0xfb] = 4; t[0xfc] = 3; t[0xfd] = 3; t[0xfe] = 2; t[0xff] = 2
        }
    }
}

/** قارئ encoded_value و encoded_array (القيم الابتدائية للحقول الثابتة). */
internal class EncodedReader(private val dex: DexFile, var p: Int) {
    private val d = dex.bytes

    fun uleb(): Int {
        var r = 0; var s = 0
        while (p < d.size) {
            val b = d.u8(p++)
            r = r or ((b and 0x7f) shl s)
            if (b and 0x80 == 0 || s >= 28) break
            s += 7
        }
        return r
    }

    fun sleb(): Int {
        var r = 0; var s = 0; var b: Int
        do {
            if (p >= d.size) return r
            b = d.u8(p++)
            r = r or ((b and 0x7f) shl s)
            s += 7
        } while (b and 0x80 != 0 && s < 35)
        if (s < 32 && b and 0x40 != 0) r = r or (-1 shl s)
        return r
    }

    private fun raw(n: Int, signExtend: Boolean): Long {
        var x = 0L
        for (i in 0 until n) x = x or (d.u8(p++).toLong() shl (8 * i))
        if (signExtend && n < 8) { val sh = 64 - 8 * n; x = (x shl sh) shr sh }
        return x
    }

    fun value(): Any? {
        val h = d.u8(p++)
        val type = h and 0x1f
        val arg = h ushr 5
        val n = arg + 1
        return when (type) {
            0x00 -> raw(1, true).toInt()
            0x02 -> raw(n, true).toInt()
            0x03 -> raw(n, false).toInt()
            0x04 -> raw(n, true).toInt()
            0x06 -> raw(n, true)
            0x10 -> (raw(n, false) shl (8 * (4 - n))).toInt()
            0x11 -> raw(n, false) shl (8 * (8 - n))
            0x17 -> dex.string(raw(n, false).toInt())
            0x18 -> EClass(dex.type(raw(n, false).toInt()))
            0x1c -> { val c = uleb(); arrayOfNulls<Any?>(minOf(c, 100_000)).also { a -> for (i in a.indices) a[i] = value() } }
            0x1e -> null
            0x1f -> arg
            else -> { p += n; null }
        }
    }
}
