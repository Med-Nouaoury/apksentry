package io.github.mednouaoury.apksentry.core

/**
 * محاكي ARM64 (AArch64) مكتوب من الصفر، لتشغيل كود native داخل صندوق مغلق.
 *
 * لا يلمس الجهاز أبداً: الذاكرة وهمية (صفحات في مصفوفات)، وكل خروج من الكود
 * (استدعاء مكتبة، syscall) يمر عبر [hooks] أو [onSvc] التي يكتبها المضيف.
 * التعليمات غير المدعومة توقف المحاكاة بـ [EmuUnsupported] بدل تخمين نتيجتها.
 */
class ArmFault(msg: String) : RuntimeException(msg)

/** ذاكرة وهمية بصفحات 4 كيلو. القراءة من عنوان غير محجوز = خطأ (كما في الجهاز الحقيقي). */
class ArmMemory(private val maxBytes: Long = 256L * 1024 * 1024) {
    private val pages = HashMap<Long, ByteArray>()
    private var lastKey = -1L
    private var lastPage: ByteArray? = null
    var mapped = 0L
        private set

    fun map(addr: Long, size: Long) {
        if (size <= 0) return
        var p = addr ushr 12
        val end = (addr + size - 1) ushr 12
        while (p <= end) {
            if (!pages.containsKey(p)) {
                mapped += 4096
                if (mapped > maxBytes) throw EmuLimit("الذاكرة")
                if (mapped and 0x3fffff == 0L && MemGuard.free() < MemGuard.RESERVE) throw EmuLimit("ذاكرة الهاتف")
                pages[p] = ByteArray(4096)
            }
            p++
        }
    }

    fun isMapped(addr: Long) = pages.containsKey(addr ushr 12)

    private fun page(addr: Long): ByteArray {
        val k = addr ushr 12
        if (k == lastKey) return lastPage!!
        val p = pages[k] ?: throw ArmFault("قراءة/كتابة في عنوان غير محجوز 0x${addr.toString(16)}")
        lastKey = k; lastPage = p
        return p
    }

    fun u8(a: Long): Int = page(a)[(a and 0xfff).toInt()].toInt() and 0xff
    fun w8(a: Long, v: Int) { page(a)[(a and 0xfff).toInt()] = v.toByte() }

    fun read(a: Long, n: Int): Long {
        val off = (a and 0xfff).toInt()
        if (off + n <= 4096) {
            val p = page(a)
            var r = 0L
            for (i in n - 1 downTo 0) r = (r shl 8) or (p[off + i].toLong() and 0xff)
            return r
        }
        var r = 0L
        for (i in n - 1 downTo 0) r = (r shl 8) or u8(a + i).toLong()
        return r
    }

    fun write(a: Long, n: Int, v: Long) {
        val off = (a and 0xfff).toInt()
        if (off + n <= 4096) {
            val p = page(a)
            for (i in 0 until n) p[off + i] = (v ushr (8 * i)).toByte()
            return
        }
        for (i in 0 until n) w8(a + i, (v ushr (8 * i)).toInt())
    }

    fun bytes(a: Long, n: Int): ByteArray = ByteArray(n) { u8(a + it).toByte() }
    fun put(a: Long, b: ByteArray, off: Int = 0, len: Int = b.size - off) { for (i in 0 until len) w8(a + i, b[off + i].toInt()) }

    /** نص C ينتهي بصفر (بحد أقصى). */
    fun cString(a: Long, max: Int = 4096): String {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < max) {
            val c = u8(a + i)
            if (c == 0) break
            out.write(c); i++
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }
}

class Arm64(val mem: ArmMemory) {
    val x = LongArray(31)
    var sp = 0L
    var pc = 0L
    var n = false; var z = false; var c = false; var v = false
    /** سجلات SIMD: 128 بت = جزء منخفض وجزء مرتفع. */
    val vlo = LongArray(32)
    val vhi = LongArray(32)
    var tpidr = 0L
    var steps = 0L
    var maxSteps = 50_000_000L
    /** دوال المضيف: إذا وصل pc إلى أحد هذه العناوين، ننفّذ الدالة ثم نرجع إلى LR. */
    val hooks = HashMap<Long, (Arm64) -> Unit>()
    var onSvc: ((Arm64, Int) -> Unit)? = null
    var checkTime: () -> Unit = {}
    /** عناوين التعليمات التي نُفّذت (لقياس التغطية). */
    val executed = HashSet<Long>()
    var trackCoverage = false
    private var exclusive: Long = -1

    // ---------------- السجلات ----------------
    fun reg(r: Int): Long = if (r == 31) 0 else x[r]
    fun regSp(r: Int): Long = if (r == 31) sp else x[r]
    fun setReg(r: Int, value: Long) { if (r != 31) x[r] = value }
    fun setRegSp(r: Int, value: Long) { if (r == 31) sp = value else x[r] = value }
    private fun r(sf: Boolean, i: Int) = if (sf) reg(i) else reg(i) and 0xffffffffL
    private fun wr(sf: Boolean, i: Int, value: Long) = setReg(i, if (sf) value else value and 0xffffffffL)
    private fun wrSp(sf: Boolean, i: Int, value: Long) = setRegSp(i, if (sf) value else value and 0xffffffffL)

    var nzcv: Int
        get() = (if (n) 8 else 0) or (if (z) 4 else 0) or (if (c) 2 else 0) or (if (v) 1 else 0)
        set(f) { n = f and 8 != 0; z = f and 4 != 0; c = f and 2 != 0; v = f and 1 != 0 }

    /** ينفّذ حتى يرجع إلى [stopAt] (عنوان وهمي نضعه في LR). */
    fun run(stopAt: Long) {
        while (pc != stopAt) step()
    }

    fun step() {
        if (++steps > maxSteps) throw EmuLimit("عدد الخطوات")
        if (steps and 0xffff == 0L) checkTime()
        val h = hooks[pc]
        if (h != null) {
            val before = pc
            h(this)
            if (pc == before) pc = x[30]
            return
        }
        if (pc and 3 != 0L) throw ArmFault("عنوان تعليمة غير صالح 0x${pc.toString(16)}")
        val ins = mem.read(pc, 4).toInt()
        if (trackCoverage) executed.add(pc)
        exec(ins)
    }

    private fun unsupported(ins: Int): Nothing =
        throw EmuUnsupported("تعليمة ARM64 غير مدعومة 0x${Integer.toHexString(ins)} في 0x${pc.toString(16)}")

    private fun bits(ins: Int, hi: Int, lo: Int): Int = (ins ushr lo) and ((1 shl (hi - lo + 1)) - 1)
    private fun bit(ins: Int, b: Int): Boolean = (ins ushr b) and 1 != 0
    private fun sext(value: Long, width: Int): Long = (value shl (64 - width)) shr (64 - width)

    fun exec(ins: Int) {
        val op0 = bits(ins, 28, 25)
        when {
            op0 and 0b1110 == 0b1000 -> dpImm(ins)
            op0 and 0b1110 == 0b1010 -> branch(ins)
            op0 and 0b0101 == 0b0100 -> loadStore(ins)
            op0 and 0b0111 == 0b0101 -> dpReg(ins)
            op0 and 0b0111 == 0b0111 -> simd(ins)
            else -> unsupported(ins)
        }
    }

    // ---------------- الشروط والأعلام ----------------
    fun cond(cnd: Int): Boolean {
        val res = when (cnd shr 1) {
            0 -> z
            1 -> c
            2 -> n
            3 -> v
            4 -> c && !z
            5 -> n == v
            6 -> n == v && !z
            else -> true
        }
        return if (cnd and 1 == 1 && cnd != 15) !res else res
    }

    /** AddWithCarry من مواصفات ARM: النتيجة والأعلام. */
    private fun addc(sf: Boolean, a: Long, b: Long, carry: Int, setFlags: Boolean): Long {
        if (sf) {
            val s1 = a + b
            val res = s1 + carry
            if (setFlags) {
                n = res < 0; z = res == 0L
                c = java.lang.Long.compareUnsigned(s1, a) < 0 || (carry == 1 && s1 == -1L)
                v = ((a xor res) and (b xor res)) < 0
            }
            return res
        }
        val ua = a and 0xffffffffL; val ub = b and 0xffffffffL
        val us = ua + ub + carry
        val res = us and 0xffffffffL
        if (setFlags) {
            val r32 = res.toInt()
            n = r32 < 0; z = r32 == 0
            c = us > 0xffffffffL
            val ss = a.toInt().toLong() + b.toInt().toLong() + carry
            v = ss != r32.toLong()
        }
        return res
    }

    private fun logicFlags(sf: Boolean, res: Long) {
        n = if (sf) res < 0 else res.toInt() < 0
        z = if (sf) res == 0L else res.toInt() == 0
        c = false; v = false
    }

    // ---------------- معالجة البيانات بقيمة فورية ----------------
    private fun ror(value: Long, sh: Int, size: Int): Long {
        val s = sh % size
        if (s == 0) return if (size == 64) value else value and ((1L shl size) - 1)
        if (size == 64) return java.lang.Long.rotateRight(value, s)
        val m = (1L shl size) - 1
        val v0 = value and m
        return ((v0 ushr s) or (v0 shl (size - s))) and m
    }

    private fun ones(nb: Int): Long = if (nb >= 64) -1L else (1L shl nb) - 1

    private fun replicate(value: Long, esize: Int, size: Int): Long {
        var r = 0L
        var i = 0
        while (i < size) { r = r or (value shl i); i += esize }
        return if (size == 64) r else r and ((1L shl size) - 1)
    }

    /** DecodeBitMasks: يرجع (wmask, tmask) أو null إذا كانت القيمة محجوزة. */
    private fun bitMasks(nBit: Int, imms: Int, immr: Int, immediate: Boolean, size: Int): LongArray? {
        val combined = (nBit shl 6) or (imms.inv() and 0x3f)
        if (combined == 0) return null
        val len = 31 - Integer.numberOfLeadingZeros(combined)
        if (len < 1) return null
        val esize = 1 shl len
        if (esize > size) return null
        val levels = esize - 1
        val s = imms and levels
        val rr = immr and levels
        if (immediate && s == levels) return null
        val d = (s - rr) and levels
        val welem = ones(s + 1)
        val telem = ones(d + 1)
        val wmask = replicate(ror(welem, rr, esize), esize, size)
        val tmask = replicate(telem, esize, size)
        return longArrayOf(wmask, tmask)
    }

    private fun dpImm(ins: Int) {
        val sf = bit(ins, 31)
        val rd = bits(ins, 4, 0)
        val rn = bits(ins, 9, 5)
        when (bits(ins, 25, 23)) {
            0b000, 0b001 -> { // ADR / ADRP
                val imm = sext(((bits(ins, 23, 5).toLong() shl 2) or bits(ins, 30, 29).toLong()), 21)
                if (bit(ins, 31)) setReg(rd, (pc and 0xfff.inv().toLong()) + (imm shl 12))
                else setReg(rd, pc + imm)
            }
            0b010 -> { // ADD/SUB immediate
                if (bit(ins, 23)) unsupported(ins)
                val sub = bit(ins, 30); val s = bit(ins, 29)
                var imm = bits(ins, 21, 10).toLong()
                if (bit(ins, 22)) imm = imm shl 12
                val a = if (sf) regSp(rn) else regSp(rn) and 0xffffffffL
                val res = if (sub) addc(sf, a, imm.inv(), 1, s) else addc(sf, a, imm, 0, s)
                if (s) wr(sf, rd, res) else wrSp(sf, rd, res)
            }
            0b100 -> { // logical immediate
                val size = if (sf) 64 else 32
                if (!sf && bit(ins, 22)) unsupported(ins)
                val m = bitMasks(bits(ins, 22, 22), bits(ins, 15, 10), bits(ins, 21, 16), true, size) ?: unsupported(ins)
                val a = r(sf, rn)
                when (bits(ins, 30, 29)) {
                    0 -> wrSp(sf, rd, a and m[0])
                    1 -> wrSp(sf, rd, a or m[0])
                    2 -> wrSp(sf, rd, a xor m[0])
                    else -> { val res = a and m[0]; logicFlags(sf, res); wr(sf, rd, res) }
                }
            }
            0b101 -> { // move wide
                val hw = bits(ins, 22, 21)
                if (!sf && hw > 1) unsupported(ins)
                val imm = bits(ins, 20, 5).toLong()
                val sh = hw * 16
                when (bits(ins, 30, 29)) {
                    0 -> wr(sf, rd, (imm shl sh).inv())
                    2 -> wr(sf, rd, imm shl sh)
                    3 -> wr(sf, rd, (reg(rd) and (0xffffL shl sh).inv()) or (imm shl sh))
                    else -> unsupported(ins)
                }
            }
            0b110 -> { // bitfield
                val size = if (sf) 64 else 32
                if (bit(ins, 22) != sf) unsupported(ins)
                val immr = bits(ins, 21, 16); val imms = bits(ins, 15, 10)
                if (!sf && (immr > 31 || imms > 31)) unsupported(ins)
                val m = bitMasks(bits(ins, 22, 22), imms, immr, false, size) ?: unsupported(ins)
                val opc = bits(ins, 30, 29)
                if (opc == 3) unsupported(ins)
                val src = r(sf, rn)
                val dst = if (opc == 1) r(sf, rd) else 0L
                val bot = (dst and m[0].inv()) or (ror(src, immr, size) and m[0])
                val top = if (opc == 0) (if ((src ushr imms) and 1 == 1L) -1L else 0L) else dst
                wr(sf, rd, (top and m[1].inv()) or (bot and m[1]))
            }
            0b111 -> { // EXTR
                val size = if (sf) 64 else 32
                if (bits(ins, 30, 29) != 0 || bit(ins, 22) != sf || bit(ins, 21)) unsupported(ins)
                val lsb = bits(ins, 15, 10)
                if (lsb >= size) unsupported(ins)
                val hi = r(sf, rn); val lo = r(sf, bits(ins, 20, 16))
                val res = if (lsb == 0) lo else if (sf) (lo ushr lsb) or (hi shl (64 - lsb)) else ((lo ushr lsb) or (hi shl (32 - lsb)))
                wr(sf, rd, res)
            }
            else -> unsupported(ins)
        }
        pc += 4
    }

    // ---------------- التفرعات والنظام ----------------
    private fun branch(ins: Int) {
        val top = bits(ins, 31, 26)
        when {
            top == 0b000101 -> { pc += sext(bits(ins, 25, 0).toLong() shl 2, 28); return }
            top == 0b100101 -> { x[30] = pc + 4; pc += sext(bits(ins, 25, 0).toLong() shl 2, 28); return }
            bits(ins, 31, 24) == 0b01010100 && !bit(ins, 4) -> {
                pc += if (cond(bits(ins, 3, 0))) sext(bits(ins, 23, 5).toLong() shl 2, 21) else 4; return
            }
            bits(ins, 30, 25) == 0b011010 -> { // CBZ/CBNZ
                val value = r(bit(ins, 31), bits(ins, 4, 0))
                val take = (value == 0L) != bit(ins, 24)
                pc += if (take) sext(bits(ins, 23, 5).toLong() shl 2, 21) else 4; return
            }
            bits(ins, 30, 25) == 0b011011 -> { // TBZ/TBNZ
                val b = (bits(ins, 31, 31) shl 5) or bits(ins, 23, 19)
                val set = (reg(bits(ins, 4, 0)) ushr b) and 1 == 1L
                pc += if (set == bit(ins, 24)) sext(bits(ins, 18, 5).toLong() shl 2, 16) else 4; return
            }
            bits(ins, 31, 24) == 0b11010100 -> { // exceptions
                val opc = bits(ins, 23, 21); val ll = bits(ins, 1, 0)
                if (opc == 0 && ll == 1) {
                    pc += 4
                    (onSvc ?: throw EmuUnsupported("syscall بدون معالج"))(this, bits(ins, 20, 5))
                    return
                }
                if (opc == 1) throw ArmFault("BRK: توقّف الكود عمداً")
                unsupported(ins)
            }
            bits(ins, 31, 22) == 0b1101010100 -> { system(ins); pc += 4; return }
            bits(ins, 31, 25) == 0b1101011 -> { // branch to register
                val opc = bits(ins, 24, 21)
                val op3 = bits(ins, 15, 10)
                if (bits(ins, 20, 16) != 0b11111) unsupported(ins)
                // نقبل صيغ PAC (BRAA، RETAA...) كقفز عادي: التحقق من التوقيع لا يغيّر سلوك الكود السليم
                val rn = bits(ins, 9, 5)
                val target = when {
                    op3 == 0 -> reg(rn)
                    op3 == 2 || op3 == 3 -> if (opc == 2 && rn == 31) x[30] else reg(rn)
                    else -> unsupported(ins)
                }
                when (opc) {
                    0, 8 -> pc = target
                    1, 9 -> { x[30] = pc + 4; pc = target }
                    2 -> pc = if (op3 == 0) reg(rn) else x[30]
                    else -> unsupported(ins)
                }
                return
            }
            else -> unsupported(ins)
        }
    }

    private var fakeCounter = 0L

    private fun system(ins: Int) {
        val l = bit(ins, 21)
        val op0 = bits(ins, 20, 19); val op1 = bits(ins, 18, 16)
        val crn = bits(ins, 15, 12); val crm = bits(ins, 11, 8); val op2 = bits(ins, 7, 5)
        val rt = bits(ins, 4, 0)
        if (op0 == 0) {
            // hints (NOP، PAC، BTI...)، الحواجز، و MSR على PSTATE: لا أثر على الحساب
            if (crn == 2 || crn == 3 || crn == 4) return
            unsupported(ins)
        }
        if (op0 == 1 && !l && crn == 7) {
            // صيانة الذاكرة المؤقتة (تستعملها الأغلفة بعد كتابة كود جديد): لا أثر هنا، ما عدا DC ZVA
            if (op1 == 3 && crm == 4 && op2 == 1) { val a = reg(rt) and 63L.inv(); for (i in 0 until 8) mem.write(a + 8 * i, 8, 0) }
            return
        }
        val key = (op0 shl 14) or (op1 shl 11) or (crn shl 7) or (crm shl 3) or op2
        val tpidrKey = (3 shl 14) or (3 shl 11) or (13 shl 7) or (0 shl 3) or 2
        val nzcvKey = (3 shl 14) or (3 shl 11) or (4 shl 7) or (2 shl 3) or 0
        val fpcr = (3 shl 14) or (3 shl 11) or (4 shl 7) or (4 shl 3) or 0
        val fpsr = fpcr + 1
        val cntvct = (3 shl 14) or (3 shl 11) or (14 shl 7) or (0 shl 3) or 2
        val cntfrq = (3 shl 14) or (3 shl 11) or (14 shl 7) or (0 shl 3) or 0
        val midr = (3 shl 14) or (0 shl 11) or (0 shl 7) or (0 shl 3) or 0
        if (l) {
            setReg(rt, when (key) {
                tpidrKey -> tpidr
                nzcvKey -> nzcv.toLong() shl 28
                fpcr, fpsr -> 0
                cntvct -> { fakeCounter += 1000; fakeCounter }
                cntfrq -> 19_200_000
                midr -> 0x410fd034 // Cortex-A53 نموذجي
                (3 shl 14) or (3 shl 11) or (0 shl 7) or (0 shl 3) or 7 -> 4 // DCZID_EL0: كتل 64 بايت
                else -> unsupported(ins)
            })
        } else {
            when (key) {
                tpidrKey -> tpidr = reg(rt)
                nzcvKey -> nzcv = ((reg(rt) ushr 28) and 0xf).toInt()
                fpcr, fpsr -> {}
                else -> unsupported(ins)
            }
        }
    }

    // ---------------- القراءة والكتابة في الذاكرة ----------------
    private fun extendReg(value: Long, option: Int, shift: Int): Long {
        val v0 = when (option) {
            0 -> value and 0xff
            1 -> value and 0xffff
            2 -> value and 0xffffffffL
            3 -> value
            4 -> value.toByte().toLong()
            5 -> value.toShort().toLong()
            6 -> value.toInt().toLong()
            else -> value
        }
        return v0 shl shift
    }

    private fun loadStore(ins: Int) {
        val b29_24 = bits(ins, 29, 24)
        val vec = bit(ins, 26)
        when {
            bits(ins, 29, 24) == 0b001000 && !vec -> exclusiveOp(ins)
            b29_24 and 0b111011 == 0b011000 -> literal(ins)
            bits(ins, 29, 27) == 0b101 -> pair(ins)
            bits(ins, 29, 27) == 0b111 -> single(ins)
            bits(ins, 31, 31) == 0 && bits(ins, 29, 24) == 0b001100 -> simdMulti(ins)
            else -> unsupported(ins)
        }
        pc += 4
    }

    private fun exclusiveOp(ins: Int) {
        val size = bits(ins, 31, 30)
        val o2 = bit(ins, 23); val load = bit(ins, 22); val o1 = bit(ins, 21)
        val rs = bits(ins, 20, 16); val rt2 = bits(ins, 14, 10); val rn = bits(ins, 9, 5); val rt = bits(ins, 4, 0)
        val addr = regSp(rn)
        val nb = 1 shl size
        if (o1) {
            if (o2 || size < 2) unsupported(ins) // CAS و أخواتها: غير مدعومة بعد
            // LDXP/STXP
            if (load) {
                setReg(rt, mem.read(addr, nb)); setReg(rt2, mem.read(addr + nb, nb)); exclusive = addr
            } else if (exclusive == addr) {
                mem.write(addr, nb, reg(rt)); mem.write(addr + nb, nb, reg(rt2)); setReg(rs, 0); exclusive = -1
            } else setReg(rs, 1)
            return
        }
        if (load) {
            setReg(rt, mem.read(addr, nb))
            if (!o2) exclusive = addr
        } else if (o2) {
            mem.write(addr, nb, reg(rt)) // STLR
        } else if (exclusive == addr) {
            // STXR: ينجح فقط بعد LDXR على نفس العنوان (كما في المعالج الحقيقي)
            mem.write(addr, nb, reg(rt)); setReg(rs, 0); exclusive = -1
        } else setReg(rs, 1)
    }

    private fun literal(ins: Int) {
        val opc = bits(ins, 31, 30)
        val addr = pc + sext(bits(ins, 23, 5).toLong() shl 2, 21)
        val rt = bits(ins, 4, 0)
        if (bit(ins, 26)) {
            when (opc) {
                0 -> setV(rt, mem.read(addr, 4), 0)
                1 -> setV(rt, mem.read(addr, 8), 0)
                2 -> setV(rt, mem.read(addr, 8), mem.read(addr + 8, 8))
                else -> unsupported(ins)
            }
            return
        }
        when (opc) {
            0 -> setReg(rt, mem.read(addr, 4))
            1 -> setReg(rt, mem.read(addr, 8))
            2 -> setReg(rt, mem.read(addr, 4).toInt().toLong())
            3 -> {} // PRFM
        }
    }

    private fun setV(i: Int, lo: Long, hi: Long) { vlo[i] = lo; vhi[i] = hi }

    private fun pair(ins: Int) {
        val opc = bits(ins, 31, 30)
        val vec = bit(ins, 26)
        val type = bits(ins, 24, 23)
        val load = bit(ins, 22)
        val rt2 = bits(ins, 14, 10); val rn = bits(ins, 9, 5); val rt = bits(ins, 4, 0)
        val scale: Int
        var signed = false
        if (vec) {
            if (opc == 3) unsupported(ins)
            scale = 2 + opc
        } else {
            when (opc) {
                0 -> scale = 2
                1 -> { if (!load) unsupported(ins); scale = 2; signed = true }
                2 -> scale = 3
                else -> unsupported(ins)
            }
        }
        val off = sext(bits(ins, 21, 15).toLong(), 7) shl scale
        val base = regSp(rn)
        val addr = when (type) { 1 -> base; 0, 2, 3 -> base + off; else -> base }
        val nb = 1 shl scale
        if (vec) {
            if (load) {
                val a = loadV(addr, nb); val b = loadV(addr + nb, nb)
                setV(rt, a[0], a[1]); setV(rt2, b[0], b[1])
            } else {
                storeV(addr, nb, rt); storeV(addr + nb, nb, rt2)
            }
        } else if (load) {
            val a = mem.read(addr, nb); val b = mem.read(addr + nb, nb)
            setReg(rt, if (signed) a.toInt().toLong() else a)
            setReg(rt2, if (signed) b.toInt().toLong() else b)
        } else {
            mem.write(addr, nb, reg(rt)); mem.write(addr + nb, nb, reg(rt2))
        }
        if (type == 1 || type == 3) setRegSp(rn, base + off)
    }

    private fun loadV(addr: Long, nb: Int): LongArray =
        if (nb == 16) longArrayOf(mem.read(addr, 8), mem.read(addr + 8, 8)) else longArrayOf(mem.read(addr, nb), 0)

    private fun storeV(addr: Long, nb: Int, i: Int) {
        if (nb == 16) { mem.write(addr, 8, vlo[i]); mem.write(addr + 8, 8, vhi[i]) } else mem.write(addr, nb, vlo[i])
    }

    private fun single(ins: Int) {
        val size = bits(ins, 31, 30)
        val vec = bit(ins, 26)
        val opc = bits(ins, 23, 22)
        val rn = bits(ins, 9, 5); val rt = bits(ins, 4, 0)
        // حجم البيانات
        val vec128 = vec && size == 0 && opc and 2 != 0
        val scale = if (vec128) 4 else size
        val nb = 1 shl scale
        val base = regSp(rn)
        var addr: Long
        var wb = false
        var post = false
        val mode = bits(ins, 25, 24)
        when {
            mode == 1 -> addr = base + (bits(ins, 21, 10).toLong() shl scale)
            mode == 0 && !bit(ins, 21) -> {
                val imm9 = sext(bits(ins, 20, 12).toLong(), 9)
                when (bits(ins, 11, 10)) {
                    0, 2 -> addr = base + imm9
                    1 -> { addr = base; wb = true; post = true }
                    else -> { addr = base + imm9; wb = true }
                }
                if (wb) {
                    val nb2 = base + imm9
                    doSingle(ins, vec, vec128, size, opc, nb, addr, rt)
                    setRegSp(rn, nb2)
                    return
                }
            }
            mode == 0 && bit(ins, 21) && bits(ins, 11, 10) == 2 -> {
                val option = bits(ins, 15, 13)
                if (option and 2 == 0) unsupported(ins)
                val sh = if (bit(ins, 12)) scale else 0
                addr = base + extendReg(reg(bits(ins, 20, 16)), option, sh)
            }
            else -> unsupported(ins)
        }
        if (post) return
        doSingle(ins, vec, vec128, size, opc, nb, addr, rt)
    }

    private fun doSingle(ins: Int, vec: Boolean, vec128: Boolean, size: Int, opc: Int, nb: Int, addr: Long, rt: Int) {
        if (vec) {
            val load = if (vec128) opc == 3 else opc == 1
            if (!vec128 && opc and 2 != 0) unsupported(ins)
            if (load) { val a = loadV(addr, nb); setV(rt, a[0], a[1]) } else storeV(addr, nb, rt)
            return
        }
        when (opc) {
            0 -> mem.write(addr, nb, reg(rt))
            1 -> setReg(rt, mem.read(addr, nb))
            2 -> if (size == 3) {} /* PRFM */ else setReg(rt, sext(mem.read(addr, nb), nb * 8))
            3 -> if (size >= 2) unsupported(ins) else setReg(rt, sext(mem.read(addr, nb), nb * 8) and 0xffffffffL)
        }
    }

    // ---------------- معالجة البيانات بالسجلات ----------------
    private fun shiftReg(value: Long, type: Int, amt: Int, sf: Boolean): Long {
        if (sf) return when (type) {
            0 -> value shl amt
            1 -> value ushr amt
            2 -> value shr amt
            else -> java.lang.Long.rotateRight(value, amt)
        }
        val w = value.toInt()
        return when (type) {
            0 -> (w shl amt).toLong() and 0xffffffffL
            1 -> (w ushr amt).toLong() and 0xffffffffL
            2 -> (w shr amt).toLong() and 0xffffffffL
            else -> Integer.rotateRight(w, amt).toLong() and 0xffffffffL
        }
    }

    private fun dpReg(ins: Int) {
        val sf = bit(ins, 31)
        val rd = bits(ins, 4, 0); val rn = bits(ins, 9, 5); val rm = bits(ins, 20, 16)
        val op1 = bit(ins, 28)
        val op2 = bits(ins, 24, 21)
        if (!op1) {
            if (!bit(ins, 24)) { // logical shifted register
                val amt = bits(ins, 15, 10)
                if (!sf && amt > 31) unsupported(ins)
                var b = shiftReg(r(sf, rm), bits(ins, 23, 22), amt, sf)
                if (bit(ins, 21)) b = if (sf) b.inv() else b.inv() and 0xffffffffL
                val a = r(sf, rn)
                when (bits(ins, 30, 29)) {
                    0 -> wr(sf, rd, a and b)
                    1 -> wr(sf, rd, a or b)
                    2 -> wr(sf, rd, a xor b)
                    else -> { val res = a and b; logicFlags(sf, res); wr(sf, rd, res) }
                }
            } else if (!bit(ins, 21)) { // add/sub shifted register
                val type = bits(ins, 23, 22)
                val amt = bits(ins, 15, 10)
                if (type == 3 || (!sf && amt > 31)) unsupported(ins)
                val b = shiftReg(r(sf, rm), type, amt, sf)
                val sub = bit(ins, 30); val s = bit(ins, 29)
                val a = r(sf, rn)
                val res = if (sub) addc(sf, a, b.inv(), 1, s) else addc(sf, a, b, 0, s)
                wr(sf, rd, res)
            } else { // add/sub extended register
                if (bits(ins, 23, 22) != 0) unsupported(ins)
                val sh = bits(ins, 12, 10)
                if (sh > 4) unsupported(ins)
                val b = extendReg(reg(rm), bits(ins, 15, 13), sh)
                val sub = bit(ins, 30); val s = bit(ins, 29)
                val a = if (sf) regSp(rn) else regSp(rn) and 0xffffffffL
                val bb = if (sf) b else b and 0xffffffffL
                val res = if (sub) addc(sf, a, bb.inv(), 1, s) else addc(sf, a, bb, 0, s)
                if (s) wr(sf, rd, res) else wrSp(sf, rd, res)
            }
            pc += 4
            return
        }
        if (bit(ins, 24)) { dp3(ins, sf, rd, rn, rm); pc += 4; return }
        when (op2) {
            0b0000 -> { // ADC/SBC
                if (bits(ins, 15, 10) != 0) unsupported(ins)
                val sub = bit(ins, 30); val s = bit(ins, 29)
                val a = r(sf, rn); val b = r(sf, rm)
                val res = addc(sf, a, if (sub) b.inv() else b, if (c) 1 else 0, s)
                wr(sf, rd, res)
            }
            0b0010 -> { // CCMN/CCMP
                if (!bit(ins, 29) || bit(ins, 10) || bit(ins, 4)) unsupported(ins)
                if (cond(bits(ins, 15, 12))) {
                    val a = r(sf, rn)
                    val b = if (bit(ins, 11)) bits(ins, 20, 16).toLong() else r(sf, rm)
                    if (bit(ins, 30)) addc(sf, a, b.inv(), 1, true) else addc(sf, a, b, 0, true)
                } else nzcv = bits(ins, 3, 0)
            }
            0b0100 -> { // CSEL/CSINC/CSINV/CSNEG
                if (bit(ins, 29) || bit(ins, 11)) unsupported(ins)
                val o = (bits(ins, 30, 30) shl 1) or bits(ins, 10, 10)
                val res = if (cond(bits(ins, 15, 12))) r(sf, rn) else {
                    val b = r(sf, rm)
                    when (o) { 0 -> b; 1 -> b + 1; 2 -> b.inv(); else -> -b }
                }
                wr(sf, rd, res)
            }
            0b0110 -> if (bit(ins, 30)) dp1(ins, sf, rd, rn) else dp2(ins, sf, rd, rn, rm)
            else -> unsupported(ins)
        }
        pc += 4
    }

    private fun dp1(ins: Int, sf: Boolean, rd: Int, rn: Int) {
        if (bit(ins, 29) || bits(ins, 20, 16) != 0) unsupported(ins)
        val a = r(sf, rn)
        val res = when (bits(ins, 15, 10)) {
            0 -> if (sf) java.lang.Long.reverse(a) else (Integer.reverse(a.toInt()).toLong() and 0xffffffffL)
            1 -> { // REV16
                var o = 0L
                for (i in 0 until (if (sf) 4 else 2)) {
                    val h = (a ushr (16 * i)) and 0xffff
                    o = o or ((((h and 0xff) shl 8) or (h ushr 8)) shl (16 * i))
                }
                o
            }
            2 -> if (sf) { // REV32
                val lo = Integer.reverseBytes(a.toInt()).toLong() and 0xffffffffL
                val hi = Integer.reverseBytes((a ushr 32).toInt()).toLong() and 0xffffffffL
                lo or (hi shl 32)
            } else Integer.reverseBytes(a.toInt()).toLong() and 0xffffffffL
            3 -> if (sf) java.lang.Long.reverseBytes(a) else unsupported(ins)
            4 -> if (sf) java.lang.Long.numberOfLeadingZeros(a).toLong() else Integer.numberOfLeadingZeros(a.toInt()).toLong()
            5 -> if (sf) (java.lang.Long.numberOfLeadingZeros(a xor (a shr 1)) - 1).toLong()
                 else { val w = a.toInt(); (Integer.numberOfLeadingZeros(w xor (w shr 1)) - 1).toLong() }
            else -> unsupported(ins)
        }
        wr(sf, rd, res)
    }

    private fun dp2(ins: Int, sf: Boolean, rd: Int, rn: Int, rm: Int) {
        if (bit(ins, 29)) unsupported(ins)
        val a = r(sf, rn); val b = r(sf, rm)
        val size = if (sf) 64 else 32
        val op = bits(ins, 15, 10)
        val res = when (op) {
            2 -> if (b == 0L) 0 else if (sf) java.lang.Long.divideUnsigned(a, b) else a / b
            3 -> if (b == 0L) 0 else if (sf) { if (a == Long.MIN_VALUE && b == -1L) a else a / b }
                 else { val x0 = a.toInt(); val y0 = b.toInt(); (if (x0 == Int.MIN_VALUE && y0 == -1) x0 else x0 / y0).toLong() }
            8 -> shiftReg(a, 0, (b and (size - 1).toLong()).toInt(), sf)
            9 -> shiftReg(a, 1, (b and (size - 1).toLong()).toInt(), sf)
            10 -> shiftReg(a, 2, (b and (size - 1).toLong()).toInt(), sf)
            11 -> shiftReg(a, 3, (b and (size - 1).toLong()).toInt(), sf)
            in 16..23 -> crc32(op, sf, a, b)
            else -> unsupported(ins)
        }
        wr(sf, rd, res)
    }

    private fun crc32(op: Int, sf: Boolean, acc: Long, value: Long): Long {
        val sz = op and 3
        if ((sz == 3) != sf) throw EmuUnsupported("CRC32 بصيغة غير صالحة")
        val poly = if (op and 4 != 0) 0x82F63B78L else 0xEDB88320L
        var crc = acc and 0xffffffffL
        val nb = 1 shl sz
        for (i in 0 until nb) {
            crc = crc xor ((value ushr (8 * i)) and 0xff)
            repeat(8) { crc = if (crc and 1 == 1L) (crc ushr 1) xor poly else crc ushr 1 }
        }
        return crc
    }

    private fun dp3(ins: Int, sf: Boolean, rd: Int, rn: Int, rm: Int) {
        val ra = bits(ins, 14, 10)
        val o0 = bit(ins, 15)
        val op31 = bits(ins, 23, 21)
        if (bits(ins, 30, 29) != 0) unsupported(ins)
        val res: Long = when (op31) {
            0 -> { val p = r(sf, rn) * r(sf, rm); if (o0) r(sf, ra) - p else r(sf, ra) + p }
            1 -> { if (!sf) unsupported(ins); val p = reg(rn).toInt().toLong() * reg(rm).toInt().toLong(); if (o0) reg(ra) - p else reg(ra) + p }
            5 -> { if (!sf) unsupported(ins); val p = (reg(rn) and 0xffffffffL) * (reg(rm) and 0xffffffffL); if (o0) reg(ra) - p else reg(ra) + p }
            2 -> { if (!sf || o0) unsupported(ins); smulh(reg(rn), reg(rm)) }
            6 -> { if (!sf || o0) unsupported(ins); umulh(reg(rn), reg(rm)) }
            else -> unsupported(ins)
        }
        wr(sf, rd, res)
    }

    private fun smulh(a: Long, b: Long): Long {
        val a1 = a shr 32; val a0 = a and 0xffffffffL
        val b1 = b shr 32; val b0 = b and 0xffffffffL
        val w0 = a0 * b0
        val t = a1 * b0 + (w0 ushr 32)
        var w1 = t and 0xffffffffL
        val w2 = t shr 32
        w1 += a0 * b1
        return a1 * b1 + w2 + (w1 shr 32)
    }

    private fun umulh(a: Long, b: Long): Long {
        val hi = smulh(a, b)
        return hi + ((a shr 63) and b) + ((b shr 63) and a)
    }

    // ---------------- SIMD ----------------
    private fun simd(ins: Int) {
        ArmSimd.exec(this, ins)
        pc += 4
    }

    internal fun fail(ins: Int): Nothing = unsupported(ins)

    private fun simdMulti(ins: Int) = ArmSimd.multi(this, ins)
}
