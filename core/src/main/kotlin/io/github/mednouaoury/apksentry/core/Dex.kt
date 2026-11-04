package io.github.mednouaoury.apksentry.core

import java.io.IOException

/**
 * قارئ لملفات classes.dex: يعرف الكلاسات المعرّفة في الملف، ولكل كلاس:
 * أي وظائف يستدعي (invoke) وأي نصوص يستعمل (const-string).
 */
class DexFile(private val d: ByteArray) {
    internal val bytes: ByteArray get() = d
    private val stringIdsOff: Int
    val stringCount: Int
    private val typeIdsOff: Int
    private val typeCount: Int
    private val protoIdsOff: Int
    private val protoCount: Int
    private val fieldIdsOff: Int
    val fieldCount: Int
    private val methodIdsOff: Int
    val methodCount: Int
    private val classDefsOff: Int
    val classCount: Int
    private val stringCache: Array<String?>

    init {
        if (d.size < 0x70 || d[0] != 'd'.code.toByte() || d[1] != 'e'.code.toByte() || d[2] != 'x'.code.toByte())
            throw IOException("ليس ملف dex")
        stringCount = d.i32(56); stringIdsOff = d.i32(60)
        typeCount = d.i32(64); typeIdsOff = d.i32(68)
        protoCount = d.i32(72); protoIdsOff = d.i32(76)
        fieldCount = d.i32(80); fieldIdsOff = d.i32(84)
        methodCount = d.i32(88); methodIdsOff = d.i32(92)
        classCount = d.i32(96); classDefsOff = d.i32(100)
        if (stringCount < 0 || typeCount < 0 || methodCount < 0 || classCount < 0 || protoCount < 0 || fieldCount < 0 ||
            stringIdsOff + 4L * stringCount > d.size || methodIdsOff + 8L * methodCount > d.size ||
            classDefsOff + 32L * classCount > d.size || protoIdsOff + 12L * protoCount > d.size ||
            fieldIdsOff + 8L * fieldCount > d.size
        ) throw IOException("ترويسة dex غير صالحة")
        stringCache = arrayOfNulls(stringCount)
    }

    /** "Lcls;->name" للحقل. */
    fun fieldFull(idx: Int): String =
        if (idx < 0 || idx >= fieldCount) "" else
            type(d.u16(fieldIdsOff + idx * 8)) + "->" + string(d.i32(fieldIdsOff + idx * 8 + 4))

    /** "(params)ret" للنموذج. */
    fun protoString(idx: Int): String {
        if (idx < 0 || idx >= protoCount) return "()V"
        val o = protoIdsOff + idx * 12
        val ret = type(d.i32(o + 4))
        val paramsOff = d.i32(o + 8)
        val sb = StringBuilder("(")
        if (paramsOff > 0 && paramsOff + 4 <= d.size) {
            val n = d.i32(paramsOff)
            for (i in 0 until n) {
                if (paramsOff + 4 + i * 2 + 2 > d.size) break
                sb.append(type(d.u16(paramsOff + 4 + i * 2)))
            }
        }
        return sb.append(")").append(ret).toString()
    }

    fun methodProto(idx: Int): String =
        if (idx < 0 || idx >= methodCount) "()V" else protoString(d.u16(methodIdsOff + idx * 8 + 2))

    /** المفتاح الكامل للوظيفة: "Lcls;->name(params)ret" (نفسه عبر كل ملفات dex). */
    fun methodKey(idx: Int): String = methodFull(idx) + methodProto(idx)

    /** يمر على وظائف الكلاس: (رقم الوظيفة، الخصائص، موقع الكود). */
    fun forEachMethod(classDef: Int, block: (methodIdx: Int, access: Int, codeOff: Int) -> Unit) {
        val dataOff = d.i32(classDefsOff + classDef * 32 + 24)
        if (dataOff <= 0 || dataOff >= d.size) return
        val c = Cursor(dataOff)
        val sf = c.uleb(); val inf = c.uleb(); val dm = c.uleb(); val vm = c.uleb()
        if (!sane(sf, inf, dm, vm)) return
        repeat(sf + inf) { c.uleb(); c.uleb() }
        for (group in intArrayOf(dm, vm)) {
            var idx = 0
            repeat(group) {
                idx += c.uleb()
                val access = c.uleb()
                val codeOff = c.uleb()
                block(idx, access, codeOff)
            }
        }
    }

    // ---------- للمحاكي ----------
    internal fun fieldType(idx: Int): String =
        if (idx < 0 || idx >= fieldCount) "" else type(d.u16(fieldIdsOff + idx * 8 + 2))

    internal fun fieldName(idx: Int): String =
        if (idx < 0 || idx >= fieldCount) "" else string(d.i32(fieldIdsOff + idx * 8 + 4))

    internal fun fieldClass(idx: Int): String =
        if (idx < 0 || idx >= fieldCount) "" else type(d.u16(fieldIdsOff + idx * 8))

    /** أنواع معاملات الوظيفة ونوع ما ترجعه. */
    internal fun methodParams(idx: Int): List<String> {
        if (idx < 0 || idx >= methodCount) return emptyList()
        val o = protoIdsOff + d.u16(methodIdsOff + idx * 8 + 2) * 12
        val paramsOff = d.i32(o + 8)
        if (paramsOff <= 0 || paramsOff + 4 > d.size) return emptyList()
        val n = d.i32(paramsOff)
        if (n < 0 || n > 255 || paramsOff + 4 + n * 2 > d.size) return emptyList()
        return List(n) { type(d.u16(paramsOff + 4 + it * 2)) }
    }

    internal fun methodReturn(idx: Int): String =
        if (idx < 0 || idx >= methodCount) "V" else type(d.i32(protoIdsOff + d.u16(methodIdsOff + idx * 8 + 2) * 12 + 4))

    internal fun classDefOf(classDef: Int): Int = classDefsOff + classDef * 32

    /** الحقول الثابتة للكلاس بالترتيب (لربطها بالقيم الابتدائية). */
    internal fun staticFields(classDef: Int): List<Int> {
        val dataOff = d.i32(classDefsOff + classDef * 32 + 24)
        if (dataOff <= 0 || dataOff >= d.size) return emptyList()
        val c = Cursor(dataOff)
        val sf = c.uleb(); val inf = c.uleb(); val dm = c.uleb(); val vm = c.uleb()
        if (!sane(sf, inf, dm, vm)) return emptyList()
        var idx = 0
        return List(sf) { idx += c.uleb(); c.uleb(); idx }
    }

    internal fun staticValuesOff(classDef: Int): Int = d.i32(classDefsOff + classDef * 32 + 28)

    fun string(idx: Int): String {
        if (idx < 0 || idx >= stringCount) return ""
        stringCache[idx]?.let { return it }
        val off = d.i32(stringIdsOff + idx * 4)
        val s = try {
            var p = off
            while (p < d.size && d[p] < 0) p++ // تخطّي طول uleb128
            mutf8(p + 1)
        } catch (e: Exception) {
            ""
        }
        stringCache[idx] = s
        return s
    }

    fun type(idx: Int): String =
        if (idx < 0 || idx >= typeCount) "" else string(d.i32(typeIdsOff + idx * 4))

    fun methodClass(idx: Int): String =
        if (idx < 0 || idx >= methodCount) "" else type(d.u16(methodIdsOff + idx * 8))

    fun methodName(idx: Int): String =
        if (idx < 0 || idx >= methodCount) "" else string(d.i32(methodIdsOff + idx * 8 + 4))
    fun methodFull(idx: Int): String = methodClass(idx) + "->" + methodName(idx)

    fun className(classDef: Int): String = type(d.i32(classDefsOff + classDef * 32))

    fun superName(classDef: Int): String? {
        val idx = d.i32(classDefsOff + classDef * 32 + 8)
        return if (idx < 0 || idx >= typeCount) null else type(idx)
    }

    /** يمر على كل تعليمات الكلاس ويبلّغ عن الوظائف المستدعاة والنصوص المستعملة. */
    fun scanClass(classDef: Int, onInvoke: (methodIdx: Int) -> Unit, onString: (stringIdx: Int) -> Unit) {
        val dataOff = d.i32(classDefsOff + classDef * 32 + 24)
        if (dataOff <= 0 || dataOff >= d.size) return
        val c = Cursor(dataOff)
        val sf = c.uleb(); val inf = c.uleb(); val dm = c.uleb(); val vm = c.uleb()
        if (!sane(sf, inf, dm, vm)) return
        repeat(sf + inf) { c.uleb(); c.uleb() }
        for (group in intArrayOf(dm, vm)) {
            repeat(group) {
                c.uleb(); c.uleb()
                val codeOff = c.uleb()
                if (codeOff > 0) scanCode(codeOff, onInvoke, onString)
            }
        }
    }

    /** مجموع التعليمات الممسوحة: حماية من ملفات مُعدّة لإبطاء التحليل إلى ما لا نهاية. */
    private var scannedUnits = 0L

    private fun scanCode(codeOff: Int, onInvoke: (Int) -> Unit, onString: (Int) -> Unit) {
        if (codeOff + 16 > d.size) return
        val units = d.i32(codeOff + 12)
        val base = codeOff + 16
        if (units < 0 || units > 65_536 || base + units.toLong() * 2 > d.size) return
        scannedUnits += units
        if (scannedUnits > 4L * d.size + 1_000_000) throw IOException("ملف dex مُعقّد بشكل غير طبيعي")
        fun u(i: Int) = d.u16(base + i * 2)
        var pc = 0
        while (pc < units) {
            val w = u(pc)
            val op = w and 0xff
            var len = LEN[op]
            if (pc + len > units) return
            when (op) {
                0x00 -> when (w) {
                    0x0100 -> len = if (pc + 1 < units) u(pc + 1) * 2 + 4 else return
                    0x0200 -> len = if (pc + 1 < units) u(pc + 1) * 4 + 2 else return
                    0x0300 -> len = if (pc + 3 < units) {
                        val width = u(pc + 1)
                        val count = u(pc + 2).toLong() or (u(pc + 3).toLong() shl 16)
                        ((count * width + 1) / 2 + 4).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                    } else return
                }
                in 0x6e..0x72, in 0x74..0x78, 0xfa, 0xfb -> onInvoke(u(pc + 1))
                0x1a -> onString(u(pc + 1))
                0x1b -> onString(u(pc + 1) or (u(pc + 2) shl 16))
            }
            if (len <= 0 || len > units - pc) return
            pc += len
        }
    }

    /** أعداد غير معقولة = ملف تالف أو مُعدّ لإسقاط أدوات التحليل. */
    private fun sane(vararg counts: Int): Boolean =
        counts.all { it in 0..65_535 } && counts.sum().toLong() * 2 <= d.size

    private inner class Cursor(var p: Int) {
        fun uleb(): Int {
            var result = 0
            var shift = 0
            while (true) {
                if (p >= d.size) throw IOException("بيانات dex مقطوعة")
                val b = d.u8(p++)
                result = result or ((b and 0x7f) shl shift)
                if (b and 0x80 == 0 || shift >= 28) return result
                shift += 7
            }
        }
    }

    private fun mutf8(start: Int): String {
        val sb = StringBuilder()
        var i = start
        while (i < d.size) {
            val a = d.u8(i)
            if (a == 0) break
            when {
                a < 0x80 -> { sb.append(a.toChar()); i++ }
                a and 0xe0 == 0xc0 && i + 1 < d.size -> {
                    sb.append((((a and 0x1f) shl 6) or (d.u8(i + 1) and 0x3f)).toChar()); i += 2
                }
                a and 0xf0 == 0xe0 && i + 2 < d.size -> {
                    sb.append((((a and 0x0f) shl 12) or ((d.u8(i + 1) and 0x3f) shl 6) or (d.u8(i + 2) and 0x3f)).toChar()); i += 3
                }
                else -> i++
            }
            if (sb.length > 100_000) break
        }
        return sb.toString()
    }

    companion object {
        /** طول كل تعليمة بوحدات 16 بت حسب رقمها (opcode). */
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
