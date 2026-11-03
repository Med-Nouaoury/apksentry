package io.github.mednouaoury.apksentry.core

/** نوع التعليمة من ناحية تدفّق البيانات. */
enum class Op {
    NOP, CONST, CONST_STRING, MOVE, MOVE_RESULT, MOVE_EXCEPTION, RETURN, RETURN_VOID, THROW,
    GOTO, IF, SWITCH, INVOKE, IGET, IPUT, SGET, SPUT, AGET, APUT, NEW_INSTANCE, NEW_ARRAY,
    FILLED_NEW_ARRAY, FILL_ARRAY, UNOP, BINOP, CHECK_CAST, INSTANCE_OF, ARRAY_LENGTH, MONITOR, CONST_CLASS,
}

/**
 * تعليمة مفكوكة.
 * [dst] السجل الذي تكتب فيه (أو -1)، [srcs] السجلات التي تقرأها،
 * [idx] رقم الوظيفة/الحقل/النص/النوع، [targets] عناوين القفز.
 */
class Insn(
    val pc: Int,
    val opcode: Int,
    val op: Op,
    val dst: Int = -1,
    val srcs: IntArray = EMPTY,
    val idx: Int = -1,
    val targets: IntArray = EMPTY,
    val static: Boolean = false,
    /** القيمة الثابتة في تعليمات const. */
    val lit: Long = 0,
) {
    companion object {
        val EMPTY = IntArray(0)
    }
}

class TryBlock(val start: Int, val end: Int, val handlers: IntArray)

/** كود وظيفة واحدة بعد فك تعليماتها. */
class MethodCode(
    val registers: Int,
    val ins: Int,
    val insns: List<Insn>,
    val tries: List<TryBlock>,
) {
    /** موقع التعليمة في القائمة حسب عنوانها. */
    val indexOfPc: Map<Int, Int> = HashMap<Int, Int>(insns.size * 2).also { m -> insns.forEachIndexed { i, x -> m[x.pc] = i } }

    /** أول سجل من سجلات المعاملات (parameters). */
    val firstParam get() = registers - ins
}

/** فك تعليمات Dalvik كاملة (كل الصيغ). */
object DexDecoder {
    private const val MAX_UNITS = 65_536

    fun decode(dex: DexFile, codeOff: Int): MethodCode? {
        val d = dex.bytes
        if (codeOff <= 0 || codeOff + 16 > d.size) return null
        val registers = d.u16(codeOff)
        val ins = d.u16(codeOff + 2)
        val triesSize = d.u16(codeOff + 6)
        val units = d.i32(codeOff + 12)
        val base = codeOff + 16
        if (units <= 0 || units > MAX_UNITS || base + units.toLong() * 2 > d.size) return null
        fun u(i: Int) = d.u16(base + i * 2)
        fun s16(i: Int) = u(i).toShort().toInt()
        fun s32(i: Int) = u(i) or (u(i + 1) shl 16)

        val out = ArrayList<Insn>(units / 2)
        var pc = 0
        while (pc < units) {
            val w = u(pc)
            val op = w and 0xff
            val aa = (w ushr 8) and 0xff
            val a4 = (w ushr 8) and 0xf
            val b4 = (w ushr 12) and 0xf
            var len = LEN[op]
            if (op == 0 && w != 0) {
                len = when (w) {
                    0x0100 -> if (pc + 1 < units) u(pc + 1) * 2 + 4 else return null
                    0x0200 -> if (pc + 1 < units) u(pc + 1) * 4 + 2 else return null
                    0x0300 -> if (pc + 3 < units) {
                        val count = u(pc + 2).toLong() or (u(pc + 3).toLong() shl 16)
                        ((count * u(pc + 1) + 1) / 2 + 4).coerceAtMost(units.toLong()).toInt()
                    } else return null
                    else -> 1
                }
                if (len <= 0 || len > units - pc) break
                pc += len
                continue
            }
            if (pc + len > units) break
            val x: Insn = when (op) {
                0x00 -> Insn(pc, op, Op.NOP)
                0x01, 0x04, 0x07 -> Insn(pc, op, Op.MOVE, a4, intArrayOf(b4))
                0x02, 0x05, 0x08 -> Insn(pc, op, Op.MOVE, aa, intArrayOf(u(pc + 1)))
                0x03, 0x06, 0x09 -> Insn(pc, op, Op.MOVE, u(pc + 1), intArrayOf(u(pc + 2)))
                in 0x0a..0x0c -> Insn(pc, op, Op.MOVE_RESULT, aa)
                0x0d -> Insn(pc, op, Op.MOVE_EXCEPTION, aa)
                0x0e -> Insn(pc, op, Op.RETURN_VOID)
                in 0x0f..0x11 -> Insn(pc, op, Op.RETURN, srcs = intArrayOf(aa))
                0x12 -> Insn(pc, op, Op.CONST, a4, lit = (if (b4 >= 8) b4 - 16 else b4).toLong())
                0x13 -> Insn(pc, op, Op.CONST, aa, lit = s16(pc + 1).toLong())
                0x14 -> Insn(pc, op, Op.CONST, aa, lit = s32(pc + 1).toLong())
                in 0x15..0x19 -> Insn(pc, op, Op.CONST, aa)
                0x1a -> Insn(pc, op, Op.CONST_STRING, aa, idx = u(pc + 1))
                0x1b -> Insn(pc, op, Op.CONST_STRING, aa, idx = s32(pc + 1))
                0x1c -> Insn(pc, op, Op.CONST_CLASS, aa, idx = u(pc + 1))
                0x1d, 0x1e -> Insn(pc, op, Op.MONITOR, srcs = intArrayOf(aa))
                0x1f -> Insn(pc, op, Op.CHECK_CAST, aa, intArrayOf(aa), idx = u(pc + 1))
                0x20 -> Insn(pc, op, Op.INSTANCE_OF, a4, intArrayOf(b4), idx = u(pc + 1))
                0x21 -> Insn(pc, op, Op.ARRAY_LENGTH, a4, intArrayOf(b4))
                0x22 -> Insn(pc, op, Op.NEW_INSTANCE, aa, idx = u(pc + 1))
                0x23 -> Insn(pc, op, Op.NEW_ARRAY, a4, intArrayOf(b4), idx = u(pc + 1))
                0x24 -> Insn(pc, op, Op.FILLED_NEW_ARRAY, srcs = args35c(w, u(pc + 2)), idx = u(pc + 1))
                0x25 -> Insn(pc, op, Op.FILLED_NEW_ARRAY, srcs = IntArray(aa) { u(pc + 2) + it }, idx = u(pc + 1))
                0x26 -> Insn(pc, op, Op.FILL_ARRAY, srcs = intArrayOf(aa))
                0x27 -> Insn(pc, op, Op.THROW, srcs = intArrayOf(aa))
                0x28 -> Insn(pc, op, Op.GOTO, targets = intArrayOf(pc + aa.toByte().toInt()))
                0x29 -> Insn(pc, op, Op.GOTO, targets = intArrayOf(pc + s16(pc + 1)))
                0x2a -> Insn(pc, op, Op.GOTO, targets = intArrayOf(pc + s32(pc + 1)))
                0x2b, 0x2c -> Insn(pc, op, Op.SWITCH, srcs = intArrayOf(aa), targets = switchTargets(d, base, units, pc, pc + s32(pc + 1)))
                in 0x2d..0x31 -> Insn(pc, op, Op.BINOP, aa, intArrayOf(u(pc + 1) and 0xff, u(pc + 1) ushr 8))
                in 0x32..0x37 -> Insn(pc, op, Op.IF, srcs = intArrayOf(a4, b4), targets = intArrayOf(pc + s16(pc + 1)))
                in 0x38..0x3d -> Insn(pc, op, Op.IF, srcs = intArrayOf(aa), targets = intArrayOf(pc + s16(pc + 1)))
                in 0x44..0x4a -> Insn(pc, op, Op.AGET, aa, intArrayOf(u(pc + 1) and 0xff, u(pc + 1) ushr 8))
                in 0x4b..0x51 -> Insn(pc, op, Op.APUT, srcs = intArrayOf(aa, u(pc + 1) and 0xff, u(pc + 1) ushr 8))
                in 0x52..0x58 -> Insn(pc, op, Op.IGET, a4, intArrayOf(b4), idx = u(pc + 1))
                in 0x59..0x5f -> Insn(pc, op, Op.IPUT, srcs = intArrayOf(a4, b4), idx = u(pc + 1))
                in 0x60..0x66 -> Insn(pc, op, Op.SGET, aa, idx = u(pc + 1))
                in 0x67..0x6d -> Insn(pc, op, Op.SPUT, srcs = intArrayOf(aa), idx = u(pc + 1))
                in 0x6e..0x72 -> Insn(pc, op, Op.INVOKE, srcs = args35c(w, u(pc + 2)), idx = u(pc + 1), static = op == 0x71)
                in 0x74..0x78 -> Insn(pc, op, Op.INVOKE, srcs = IntArray(aa) { u(pc + 2) + it }, idx = u(pc + 1), static = op == 0x77)
                0xfa -> Insn(pc, op, Op.INVOKE, srcs = args35c(w, u(pc + 2)), idx = u(pc + 1))
                0xfb -> Insn(pc, op, Op.INVOKE, srcs = IntArray(aa) { u(pc + 2) + it }, idx = u(pc + 1))
                0xfc -> Insn(pc, op, Op.INVOKE, srcs = args35c(w, u(pc + 2)), idx = -1, static = true)
                0xfd -> Insn(pc, op, Op.INVOKE, srcs = IntArray(aa) { u(pc + 2) + it }, idx = -1, static = true)
                in 0x7b..0x8f -> Insn(pc, op, Op.UNOP, a4, intArrayOf(b4))
                in 0x90..0xaf -> Insn(pc, op, Op.BINOP, aa, intArrayOf(u(pc + 1) and 0xff, u(pc + 1) ushr 8))
                in 0xb0..0xcf -> Insn(pc, op, Op.BINOP, a4, intArrayOf(a4, b4))
                in 0xd0..0xd7 -> Insn(pc, op, Op.UNOP, a4, intArrayOf(b4))
                in 0xd8..0xe2 -> Insn(pc, op, Op.UNOP, aa, intArrayOf(u(pc + 1) and 0xff))
                0xfe, 0xff -> Insn(pc, op, Op.CONST, aa)
                else -> Insn(pc, op, Op.NOP)
            }
            out.add(x)
            pc += len
        }

        val tries = ArrayList<TryBlock>()
        // عدد try غير معقول = بيانات تالفة أو مُعدّة لإبطاء التحليل
        if (triesSize in 1..minOf(units, 2000) && base + units * 2L + 4 + triesSize * 8L <= d.size) {
            var t = base + units * 2
            if (units % 2 == 1) t += 2
            val handlersBase = t + triesSize * 8
            for (i in 0 until triesSize) {
                val o = t + i * 8
                if (o + 8 > d.size) break
                val start = d.i32(o)
                val count = d.u16(o + 4)
                val hOff = d.u16(o + 6)
                tries.add(TryBlock(start, start + count, readHandlers(d, handlersBase + hOff)))
            }
        }
        return MethodCode(registers, ins, out, tries)
    }

    /** وسائط invoke بصيغة 35c: العدد في البتات 12-15 والسجلات C D E F G. */
    private fun args35c(w: Int, regs: Int): IntArray {
        val count = (w ushr 12) and 0xf
        val g = (w ushr 8) and 0xf
        val all = intArrayOf(regs and 0xf, (regs ushr 4) and 0xf, (regs ushr 8) and 0xf, (regs ushr 12) and 0xf, g)
        return all.copyOf(minOf(count, 5))
    }

    private fun switchTargets(d: ByteArray, base: Int, units: Int, pc: Int, payload: Int): IntArray {
        if (payload < 0 || payload + 2 > units) return Insn.EMPTY
        val p = base + payload * 2
        val ident = d.u16(p)
        val size = d.u16(p + 2)
        if (p + 8 + size * 8L > d.size) return Insn.EMPTY
        return when (ident) {
            0x0100 -> IntArray(size) { pc + d.i32(p + 8 + it * 4) }
            0x0200 -> IntArray(size) { pc + d.i32(p + 4 + size * 4 + it * 4) }
            else -> Insn.EMPTY
        }.filter { it in 0 until units }.toIntArray()
    }

    private fun readHandlers(d: ByteArray, off: Int): IntArray {
        if (off < 0 || off >= d.size) return Insn.EMPTY
        var p = off
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
        val size = sleb()
        val out = ArrayList<Int>()
        repeat(minOf(kotlin.math.abs(size), 64)) { uleb(); out.add(uleb()) }
        if (size <= 0) out.add(uleb())
        return out.toIntArray()
    }

    /** طول كل تعليمة بوحدات 16 بت. */
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

/** الكتل الأساسية (basic blocks) وما يليها، لتحليل تدفّق البيانات. */
class Cfg(val code: MethodCode) {
    /** بداية كل كتلة (موقعها في قائمة التعليمات). */
    val blockStart: IntArray
    val blockEnd: IntArray
    val succ: Array<IntArray>

    init {
        val insns = code.insns
        val n = insns.size
        val leader = BooleanArray(n + 1)
        if (n > 0) leader[0] = true
        fun mark(pc: Int) { code.indexOfPc[pc]?.let { leader[it] = true } }
        for ((i, x) in insns.withIndex()) {
            when (x.op) {
                Op.GOTO, Op.IF, Op.SWITCH, Op.RETURN, Op.RETURN_VOID, Op.THROW -> {
                    x.targets.forEach(::mark)
                    if (i + 1 < n) leader[i + 1] = true
                }
                Op.INVOKE -> if (code.tries.isNotEmpty() && i + 1 < n) leader[i + 1] = true
                else -> {}
            }
        }
        for (t in code.tries) {
            mark(t.start); mark(t.end)
            t.handlers.forEach(::mark)
        }
        val starts = (0 until n).filter { leader[it] }
        blockStart = starts.toIntArray()
        blockEnd = IntArray(starts.size) { if (it + 1 < starts.size) starts[it + 1] else n }
        val blockOf = IntArray(n)
        for (b in starts.indices) for (i in blockStart[b] until blockEnd[b]) blockOf[i] = b
        fun blk(pc: Int): Int? = code.indexOfPc[pc]?.let { blockOf[it] }
        succ = Array(starts.size) { b ->
            val last = insns[blockEnd[b] - 1]
            val s = LinkedHashSet<Int>()
            when (last.op) {
                Op.GOTO -> last.targets.forEach { pc -> blk(pc)?.let(s::add) }
                Op.IF, Op.SWITCH -> {
                    last.targets.forEach { pc -> blk(pc)?.let(s::add) }
                    if (b + 1 < starts.size) s.add(b + 1)
                }
                Op.RETURN, Op.RETURN_VOID, Op.THROW -> {}
                else -> if (b + 1 < starts.size) s.add(b + 1)
            }
            val firstPc = insns[blockStart[b]].pc
            for (t in code.tries) if (firstPc >= t.start && firstPc < t.end) t.handlers.forEach { pc -> blk(pc)?.let(s::add) }
            s.toIntArray()
        }
    }

    val size get() = blockStart.size
}
