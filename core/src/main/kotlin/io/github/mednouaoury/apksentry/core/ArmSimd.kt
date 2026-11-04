package io.github.mednouaoury.apksentry.core

/**
 * تعليمات SIMD والفاصلة العائمة في ARM64: الجزء الذي يستعمله المترجم كثيراً في حلقات
 * فك التشفير (XOR على 16 بايت دفعة واحدة، نسخ الذاكرة، الجداول).
 * كل سجل 128 بت نعامله كـ 16 بايت (little-endian) لتبسيط العمليات على العناصر.
 */
internal object ArmSimd {
    private fun bits(ins: Int, hi: Int, lo: Int): Int = (ins ushr lo) and ((1 shl (hi - lo + 1)) - 1)
    private fun bit(ins: Int, b: Int): Boolean = (ins ushr b) and 1 != 0

    private fun load(c: Arm64, r: Int): ByteArray {
        val b = ByteArray(16)
        for (i in 0 until 8) { b[i] = (c.vlo[r] ushr (8 * i)).toByte(); b[8 + i] = (c.vhi[r] ushr (8 * i)).toByte() }
        return b
    }

    private fun store(c: Arm64, r: Int, b: ByteArray, q: Boolean = true) {
        var lo = 0L; var hi = 0L
        for (i in 7 downTo 0) { lo = (lo shl 8) or (b[i].toLong() and 0xff); hi = (hi shl 8) or (b[8 + i].toLong() and 0xff) }
        c.vlo[r] = lo; c.vhi[r] = if (q) hi else 0
    }

    private fun el(b: ByteArray, i: Int, eb: Int): Long {
        var r = 0L
        for (k in eb - 1 downTo 0) r = (r shl 8) or (b[i * eb + k].toLong() and 0xff)
        return r
    }

    private fun setEl(b: ByteArray, i: Int, eb: Int, v: Long) { for (k in 0 until eb) b[i * eb + k] = (v ushr (8 * k)).toByte() }

    private fun sx(v: Long, bitsN: Int): Long = if (bitsN == 64) v else (v shl (64 - bitsN)) shr (64 - bitsN)
    private fun mask(bitsN: Int): Long = if (bitsN == 64) -1L else (1L shl bitsN) - 1

    fun exec(c: Arm64, ins: Int) {
        when {
            // FMOV / تحويلات بين السجلات العامة والفاصلة العائمة
            bits(ins, 30, 24) == 0b0011110 && bit(ins, 21) && bits(ins, 15, 10) == 0 && !bit(ins, 29) -> fpConvert(c, ins)
            bits(ins, 31, 24) == 0b00011110 && bit(ins, 21) -> fpScalar(c, ins)
            bit(ins, 31) -> c.fail(ins)
            bits(ins, 28, 21) == 0b01110000 && !bit(ins, 15) && bit(ins, 10) -> copy(c, ins)
            bits(ins, 28, 19) == 0b0111100000 && bit(ins, 10) -> modImm(c, ins)
            bits(ins, 28, 24) == 0b01110 && bit(ins, 21) && bit(ins, 10) -> threeSame(c, ins)
            bits(ins, 28, 24) == 0b01110 && bits(ins, 21, 17) == 0b10000 && bits(ins, 11, 10) == 2 -> twoMisc(c, ins)
            bits(ins, 28, 24) == 0b01110 && bits(ins, 21, 17) == 0b11000 && bits(ins, 11, 10) == 2 -> acrossLanes(c, ins)
            bits(ins, 28, 23) == 0b011110 && bit(ins, 10) && bits(ins, 22, 19) != 0 -> shiftImm(c, ins)
            bits(ins, 29, 24) == 0b001110 && !bit(ins, 21) && !bit(ins, 15) && bits(ins, 11, 10) == 2 -> permute(c, ins)
            bits(ins, 29, 24) == 0b001110 && bits(ins, 23, 21) == 0 && !bit(ins, 15) && bits(ins, 11, 10) == 0 -> tbl(c, ins)
            bits(ins, 29, 24) == 0b101110 && bits(ins, 23, 21) == 0 && !bit(ins, 15) && !bit(ins, 10) -> ext(c, ins)
            bits(ins, 28, 24) == 0b11110 && bit(ins, 30) -> scalar(c, ins)
            else -> c.fail(ins)
        }
    }

    // ---- نقل عناصر بين السجلات ----
    private fun copy(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val op = bit(ins, 29)
        val imm5 = bits(ins, 20, 16); val imm4 = bits(ins, 14, 11)
        val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        val sz = Integer.numberOfTrailingZeros(imm5)
        if (sz > 3) c.fail(ins)
        val eb = 1 shl sz
        val idx = imm5 ushr (sz + 1)
        val count = (if (q) 16 else 8) / eb
        if (op) { // INS (element)
            if (!q) c.fail(ins)
            val src = load(c, rn); val dst = load(c, rd)
            setEl(dst, idx, eb, el(src, imm4 ushr sz, eb))
            store(c, rd, dst)
            return
        }
        when (imm4) {
            0 -> { val s = el(load(c, rn), idx, eb); val d = ByteArray(16); for (i in 0 until count) setEl(d, i, eb, s); store(c, rd, d, q) }
            1 -> { if (sz == 3 && !q) c.fail(ins); val s = c.reg(rn); val d = ByteArray(16); for (i in 0 until count) setEl(d, i, eb, s); store(c, rd, d, q) }
            3 -> { if (!q) c.fail(ins); val d = load(c, rd); setEl(d, idx, eb, c.reg(rn)); store(c, rd, d) }
            5 -> { // SMOV
                if (sz == 3 || (sz == 2 && !q)) c.fail(ins)
                val v = sx(el(load(c, rn), idx, eb), eb * 8)
                c.setReg(rd, if (q) v else v and 0xffffffffL)
            }
            7 -> { // UMOV
                if ((sz == 3) != q) c.fail(ins)
                c.setReg(rd, el(load(c, rn), idx, eb))
            }
            else -> c.fail(ins)
        }
    }

    // ---- قيم فورية للمتجهات (MOVI، MVNI، ORR، BIC، FMOV) ----
    private fun modImm(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val op = bit(ins, 29)
        val cmode = bits(ins, 15, 12)
        if (bit(ins, 11)) c.fail(ins)
        val imm8 = (bits(ins, 18, 16) shl 5) or bits(ins, 9, 5)
        val rd = bits(ins, 4, 0)
        val imm: Long = when (cmode ushr 1) {
            0 -> imm8.toLong().let { it or (it shl 32) }
            1 -> (imm8.toLong() shl 8).let { it or (it shl 32) }
            2 -> (imm8.toLong() shl 16).let { it or (it shl 32) }
            3 -> (imm8.toLong() shl 24).let { it or (it shl 32) }
            4 -> imm8.toLong().let { var r = 0L; for (i in 0 until 4) r = r or (it shl (16 * i)); r }
            5 -> (imm8.toLong() shl 8).let { var r = 0L; for (i in 0 until 4) r = r or (it shl (16 * i)); r }
            6 -> (if (cmode and 1 == 0) (imm8.toLong() shl 8) or 0xff else (imm8.toLong() shl 16) or 0xffff).let { it or (it shl 32) }
            else -> if (cmode and 1 == 0) {
                if (!op) { var r = 0L; for (i in 0 until 8) r = r or (imm8.toLong() shl (8 * i)); r }
                else { var r = 0L; for (i in 0 until 8) if ((imm8 ushr i) and 1 == 1) r = r or (0xffL shl (8 * i)); r }
            } else {
                if (!op) {
                    // FMOV (vector, single)
                    val s = vfpImm32(imm8).toLong() and 0xffffffffL
                    s or (s shl 32)
                } else {
                    if (!q) c.fail(ins)
                    vfpImm64(imm8)
                }
            }
        }
        val isOrrBic = cmode < 12 && cmode and 1 == 1
        val lo = c.vlo[rd]; val hi = c.vhi[rd]
        if (isOrrBic) {
            if (op) { c.vlo[rd] = lo and imm.inv(); c.vhi[rd] = if (q) hi and imm.inv() else 0 }
            else { c.vlo[rd] = lo or imm; c.vhi[rd] = if (q) hi or imm else 0 }
            return
        }
        val value = if (op && cmode < 14) imm.inv() else imm
        c.vlo[rd] = value; c.vhi[rd] = if (q) value else 0
    }

    fun vfpImm32(imm8: Int): Int {
        val sign = (imm8 ushr 7) and 1
        val b6 = (imm8 ushr 6) and 1
        val exp = ((b6 xor 1) shl 7) or ((if (b6 == 1) 0x1f else 0) shl 2) or ((imm8 ushr 4) and 3)
        val frac = (imm8 and 0xf) shl 19
        return (sign shl 31) or (exp shl 23) or frac
    }

    fun vfpImm64(imm8: Int): Long {
        val sign = ((imm8 ushr 7) and 1).toLong()
        val b6 = (imm8 ushr 6) and 1
        val exp = ((b6 xor 1).toLong() shl 10) or ((if (b6 == 1) 0xffL else 0L) shl 2) or ((imm8 ushr 4) and 3).toLong()
        val frac = (imm8 and 0xf).toLong() shl 48
        return (sign shl 63) or (exp shl 52) or frac
    }

    // ---- عمليات على العناصر: نفس الحجم ----
    private fun threeSame(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val u = bit(ins, 29)
        val size = bits(ins, 23, 22); val rm = bits(ins, 20, 16); val opc = bits(ins, 15, 11)
        val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        val a = load(c, rn); val b = load(c, rm); val d = load(c, rd)
        val out = ByteArray(16)
        val n = if (q) 16 else 8
        if (opc == 0b00011) { // منطقية على البايتات
            for (i in 0 until n) {
                val x = a[i].toInt(); val y = b[i].toInt(); val z = d[i].toInt()
                out[i] = (if (!u) when (size) {
                    0 -> x and y          // AND
                    1 -> x and y.inv()    // BIC
                    2 -> x or y           // ORR
                    else -> x or y.inv()  // ORN
                } else when (size) {
                    0 -> x xor y                          // EOR
                    1 -> (z and x) or (z.inv() and y)     // BSL
                    2 -> (z and y.inv()) or (x and y)     // BIT
                    else -> (z and y) or (x and y.inv())  // BIF
                }).toByte()
            }
            store(c, rd, out, q)
            return
        }
        val eb = 1 shl size
        val ebits = eb * 8
        val count = n / eb
        if (size == 3 && !q) c.fail(ins)
        val m = mask(ebits)
        if (opc == 0b10111 && !u) { // ADDP
            val tmp = ByteArray(32)
            System.arraycopy(a, 0, tmp, 0, n); System.arraycopy(b, 0, tmp, n, n)
            for (i in 0 until count) setEl(out, i, eb, (el(tmp, 2 * i, eb) + el(tmp, 2 * i + 1, eb)) and m)
            store(c, rd, out, q)
            return
        }
        for (i in 0 until count) {
            val x = el(a, i, eb); val y = el(b, i, eb)
            val sxv = sx(x, ebits); val syv = sx(y, ebits)
            val r: Long = when (opc) {
                0b10000 -> if (u) x - y else x + y
                0b10001 -> if (u) (if (x == y) -1 else 0) else (if (x and y != 0L) -1 else 0)
                0b00110 -> if (u) (if (java.lang.Long.compareUnsigned(x, y) > 0) -1 else 0) else (if (sxv > syv) -1 else 0)
                0b00111 -> if (u) (if (java.lang.Long.compareUnsigned(x, y) >= 0) -1 else 0) else (if (sxv >= syv) -1 else 0)
                0b01100 -> if (u) (if (java.lang.Long.compareUnsigned(x, y) >= 0) x else y) else (if (sxv >= syv) x else y)
                0b01101 -> if (u) (if (java.lang.Long.compareUnsigned(x, y) <= 0) x else y) else (if (sxv <= syv) x else y)
                0b10011 -> if (u || size == 3) c.fail(ins) else x * y
                0b10010 -> if (size == 3) c.fail(ins) else { val z = el(d, i, eb); if (u) z - x * y else z + x * y }
                0b01000 -> { // SSHL/USHL: الإزاحة = البايت السفلي (بإشارة) من العنصر الثاني
                    val sh = y.toByte().toInt()
                    when {
                        sh >= 0 -> if (sh >= ebits) 0 else x shl sh
                        u -> if (-sh >= ebits) 0 else x ushr (-sh)
                        else -> if (-sh >= ebits) (if (sxv < 0) -1 else 0) else sxv shr (-sh)
                    }
                }
                else -> c.fail(ins)
            }
            setEl(out, i, eb, r and m)
        }
        store(c, rd, out, q)
    }

    private fun twoMisc(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val u = bit(ins, 29)
        val size = bits(ins, 23, 22); val opc = bits(ins, 16, 12)
        val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        val a = load(c, rn)
        val n = if (q) 16 else 8
        val out = ByteArray(16)
        val eb = 1 shl size; val ebits = eb * 8; val count = n / eb; val m = mask(ebits)
        when (opc) {
            0b00101 -> {
                if (size == 0) for (i in 0 until n) out[i] = (if (u) a[i].toInt().inv() else Integer.bitCount(a[i].toInt() and 0xff)).toByte()
                else if (u && size == 1) for (i in 0 until n) out[i] = (Integer.reverse(a[i].toInt() and 0xff) ushr 24).toByte()
                else c.fail(ins)
            }
            0b00000, 0b00001 -> { // REV64 / REV32 / REV16
                val container = when { opc == 0 && !u -> 8; opc == 0 && u -> 4; opc == 1 && !u -> 2; else -> c.fail(ins) }
                if (eb >= container) c.fail(ins)
                for (base in 0 until n step container) for (i in 0 until container / eb) {
                    val j = container / eb - 1 - i
                    for (k in 0 until eb) out[base + j * eb + k] = a[base + i * eb + k]
                }
            }
            0b00100 -> for (i in 0 until count) { // CLS / CLZ
                val x = el(a, i, eb)
                val r = if (u) java.lang.Long.numberOfLeadingZeros(x) - (64 - ebits)
                        else { val s = sx(x, ebits); java.lang.Long.numberOfLeadingZeros(s xor (s shr 1)) - 1 - (64 - ebits) }
                setEl(out, i, eb, r.toLong())
            }
            0b01000, 0b01001, 0b01010, 0b01011 -> for (i in 0 until count) {
                val x = el(a, i, eb); val s = sx(x, ebits)
                val r: Long = when {
                    opc == 0b01000 -> if (if (u) s >= 0 else s > 0) -1 else 0
                    opc == 0b01001 -> if (if (u) s <= 0 else s == 0L) -1 else 0
                    opc == 0b01010 && !u -> if (s < 0) -1 else 0
                    opc == 0b01011 -> if (u) -s else kotlin.math.abs(s)
                    else -> c.fail(ins)
                }
                setEl(out, i, eb, r and m)
            }
            0b10010 -> { // XTN / XTN2
                if (u || size == 3) c.fail(ins)
                val d = load(c, rd)
                val half = 8 / eb
                val res = if (q) d else ByteArray(16)
                for (i in 0 until half) setEl(res, i + (if (q) half else 0), eb, el(a, i, eb * 2) and m)
                store(c, rd, res, q)
                return
            }
            else -> c.fail(ins)
        }
        store(c, rd, out, q)
    }

    private fun acrossLanes(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val u = bit(ins, 29)
        val size = bits(ins, 23, 22); val opc = bits(ins, 16, 12)
        val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        if (size == 3 || (size == 2 && !q)) c.fail(ins)
        val a = load(c, rn)
        val eb = 1 shl size; val ebits = eb * 8; val count = (if (q) 16 else 8) / eb
        var acc = el(a, 0, eb)
        for (i in 1 until count) {
            val x = el(a, i, eb)
            acc = when (opc) {
                0b11011 -> if (u) c.fail(ins) else acc + x
                0b01010 -> if (u) (if (java.lang.Long.compareUnsigned(x, acc) > 0) x else acc) else (if (sx(x, ebits) > sx(acc, ebits)) x else acc)
                0b11010 -> if (u) (if (java.lang.Long.compareUnsigned(x, acc) < 0) x else acc) else (if (sx(x, ebits) < sx(acc, ebits)) x else acc)
                else -> c.fail(ins)
            }
        }
        c.vlo[rd] = acc and mask(ebits); c.vhi[rd] = 0
    }

    private fun shiftImm(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val u = bit(ins, 29)
        val immh = bits(ins, 22, 19); val immb = bits(ins, 18, 16); val opc = bits(ins, 15, 11)
        val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        val hb = 31 - Integer.numberOfLeadingZeros(immh)
        val eb = 1 shl hb; val ebits = eb * 8
        if (hb == 3 && !q && opc != 0b10100 && opc != 0b10000) c.fail(ins)
        val immhb = (immh shl 3) or immb
        val a = load(c, rn); val d = load(c, rd)
        val n = if (q) 16 else 8
        val out = ByteArray(16)
        val m = mask(ebits)
        when (opc) {
            0b00000, 0b00010 -> { // SSHR/USHR, SSRA/USRA
                val sh = 2 * ebits - immhb
                for (i in 0 until n / eb) {
                    val x = el(a, i, eb)
                    val r = if (u) (if (sh >= 64) 0 else x ushr sh) else sx(x, ebits) shr minOf(sh, 63)
                    setEl(out, i, eb, ((if (opc == 0b00010) el(d, i, eb) + r else r)) and m)
                }
            }
            0b01010 -> { // SHL / SLI
                val sh = immhb - ebits
                for (i in 0 until n / eb) {
                    val x = el(a, i, eb)
                    val r = if (u) ((x shl sh) or (el(d, i, eb) and ones(sh))) else x shl sh
                    setEl(out, i, eb, r and m)
                }
            }
            0b01000 -> { // SRI
                if (!u) c.fail(ins)
                val sh = 2 * ebits - immhb
                val keep = if (sh >= ebits) m else m xor (m ushr sh)
                for (i in 0 until n / eb) {
                    val r = (if (sh >= 64) 0 else el(a, i, eb) ushr sh) or (el(d, i, eb) and keep)
                    setEl(out, i, eb, r and m)
                }
            }
            0b10100 -> { // SSHLL/USHLL (UXTL...)
                if (hb == 3) c.fail(ins)
                val sh = immhb - ebits
                val src = if (q) 8 else 0
                for (i in 0 until 8 / eb) {
                    val x = el(a, i + src / eb, eb)
                    val w = if (u) x else sx(x, ebits)
                    setEl(out, i, eb * 2, (w shl sh) and mask(ebits * 2))
                }
                store(c, rd, out, true)
                return
            }
            0b10000 -> { // SHRN
                if (u || hb == 3) c.fail(ins)
                val sh = 2 * ebits - immhb
                val res = if (q) d else ByteArray(16)
                val half = 8 / eb
                for (i in 0 until half) setEl(res, i + (if (q) half else 0), eb, (el(a, i, eb * 2) ushr sh) and m)
                store(c, rd, res, q)
                return
            }
            else -> c.fail(ins)
        }
        store(c, rd, out, q)
    }

    private fun ones(nb: Int): Long = if (nb >= 64) -1L else (1L shl nb) - 1

    private fun permute(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val size = bits(ins, 23, 22); val opc = bits(ins, 14, 12)
        val rm = bits(ins, 20, 16); val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        if (size == 3 && !q) c.fail(ins)
        val a = load(c, rn); val b = load(c, rm)
        val eb = 1 shl size; val count = (if (q) 16 else 8) / eb
        val out = ByteArray(16)
        val part = if (opc and 4 != 0) 1 else 0
        when (opc and 3) {
            1 -> for (i in 0 until count) { // UZP
                val src = 2 * i + part
                setEl(out, i, eb, if (src < count) el(a, src, eb) else el(b, src - count, eb))
            }
            2 -> for (p in 0 until count / 2) { // TRN
                setEl(out, 2 * p, eb, el(a, 2 * p + part, eb)); setEl(out, 2 * p + 1, eb, el(b, 2 * p + part, eb))
            }
            3 -> { val base = part * count / 2; for (p in 0 until count / 2) { // ZIP
                setEl(out, 2 * p, eb, el(a, base + p, eb)); setEl(out, 2 * p + 1, eb, el(b, base + p, eb)) } }
            else -> c.fail(ins)
        }
        store(c, rd, out, q)
    }

    private fun tbl(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val len = bits(ins, 14, 13) + 1; val tbx = bit(ins, 12)
        val rm = bits(ins, 20, 16); val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        val table = ByteArray(16 * len)
        for (i in 0 until len) System.arraycopy(load(c, (rn + i) % 32), 0, table, 16 * i, 16)
        val idx = load(c, rm); val d = load(c, rd)
        val out = ByteArray(16)
        for (i in 0 until (if (q) 16 else 8)) {
            val k = idx[i].toInt() and 0xff
            out[i] = if (k < table.size) table[k] else if (tbx) d[i] else 0
        }
        store(c, rd, out, q)
    }

    private fun ext(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val pos = bits(ins, 14, 11)
        if (!q && pos > 7) c.fail(ins)
        val a = load(c, bits(ins, 9, 5)); val b = load(c, bits(ins, 20, 16))
        val n = if (q) 16 else 8
        val cat = ByteArray(2 * n)
        System.arraycopy(a, 0, cat, 0, n); System.arraycopy(b, 0, cat, n, n)
        val out = ByteArray(16)
        System.arraycopy(cat, pos, out, 0, n)
        store(c, bits(ins, 4, 0), out, q)
    }

    // ---- العمليات العددية (scalar) على سجلات SIMD ----
    private fun scalar(c: Arm64, ins: Int) {
        val u = bit(ins, 29)
        val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        when {
            // DUP (element) scalar = MOV
            !u && bits(ins, 23, 21) == 0 && bits(ins, 15, 10) == 1 -> {
                val imm5 = bits(ins, 20, 16); val sz = Integer.numberOfTrailingZeros(imm5)
                if (sz > 3) c.fail(ins)
                val eb = 1 shl sz
                c.vlo[rd] = el(load(c, rn), imm5 ushr (sz + 1), eb); c.vhi[rd] = 0
            }
            // ADDP (scalar)
            !u && bits(ins, 23, 22) == 3 && bits(ins, 21, 10) == 0b110001101110 -> { c.vlo[rd] = c.vlo[rn] + c.vhi[rn]; c.vhi[rd] = 0 }
            // three same: ADD/SUB/CMEQ/CMTST على 64 بت
            bit(ins, 21) && bit(ins, 10) && bits(ins, 23, 22) == 3 -> {
                val x = c.vlo[rn]; val y = c.vlo[bits(ins, 20, 16)]
                c.vlo[rd] = when (bits(ins, 15, 11)) {
                    0b10000 -> if (u) x - y else x + y
                    0b10001 -> if (u) (if (x == y) -1 else 0) else (if (x and y != 0L) -1 else 0)
                    0b00110 -> if (u) (if (java.lang.Long.compareUnsigned(x, y) > 0) -1 else 0) else (if (x > y) -1 else 0)
                    0b00111 -> if (u) (if (java.lang.Long.compareUnsigned(x, y) >= 0) -1 else 0) else (if (x >= y) -1 else 0)
                    else -> c.fail(ins)
                }
                c.vhi[rd] = 0
            }
            // shift by immediate على 64 بت (SHL، USHR، SSHR)
            bits(ins, 28, 23) == 0b111110 && bit(ins, 10) && bit(ins, 22) -> {
                val immhb = bits(ins, 22, 16); val x = c.vlo[rn]
                c.vlo[rd] = when (bits(ins, 15, 11)) {
                    0b01010 -> if (u) c.fail(ins) else x shl (immhb - 64)
                    0b00000 -> { val sh = 128 - immhb; if (u) (if (sh >= 64) 0 else x ushr sh) else x shr minOf(sh, 63) }
                    0b00010 -> { val sh = 128 - immhb; c.vlo[rd] + (if (u) (if (sh >= 64) 0 else x ushr sh) else x shr minOf(sh, 63)) }
                    else -> c.fail(ins)
                }
                c.vhi[rd] = 0
            }
            else -> c.fail(ins)
        }
    }

    // ---- الفاصلة العائمة ----
    private fun fpConvert(c: Arm64, ins: Int) {
        val sf = bit(ins, 31); val type = bits(ins, 23, 22)
        val rmode = bits(ins, 20, 19); val op = bits(ins, 18, 16)
        val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0)
        when {
            op == 6 && rmode == 0 && type == 0 && !sf -> c.setReg(rd, c.vlo[rn] and 0xffffffffL)
            op == 6 && rmode == 0 && type == 1 && sf -> c.setReg(rd, c.vlo[rn])
            op == 7 && rmode == 0 && type == 0 && !sf -> { c.vlo[rd] = c.reg(rn) and 0xffffffffL; c.vhi[rd] = 0 }
            op == 7 && rmode == 0 && type == 1 && sf -> { c.vlo[rd] = c.reg(rn); c.vhi[rd] = 0 }
            op == 6 && rmode == 1 && type == 2 && sf -> c.setReg(rd, c.vhi[rn])
            op == 7 && rmode == 1 && type == 2 && sf -> c.vhi[rd] = c.reg(rn)
            (op == 2 || op == 3) && rmode == 0 && type < 2 -> { // SCVTF/UCVTF
                val src = c.reg(rn).let { if (sf) it else if (op == 2) it.toInt().toLong() else it and 0xffffffffL }
                val unsignedBig = op == 3 && sf && src < 0
                if (type == 0) {
                    val f = if (unsignedBig) java.math.BigDecimal(java.lang.Long.toUnsignedString(src)).toFloat() else src.toFloat()
                    c.vlo[rd] = f.toRawBits().toLong() and 0xffffffffL
                } else {
                    val d = if (unsignedBig) java.math.BigDecimal(java.lang.Long.toUnsignedString(src)).toDouble() else src.toDouble()
                    c.vlo[rd] = d.toRawBits()
                }
                c.vhi[rd] = 0
            }
            (op == 0 || op == 1) && rmode == 3 && type < 2 -> { // FCVTZS/FCVTZU
                val d = if (type == 0) Float.fromBits(c.vlo[rn].toInt()).toDouble() else Double.fromBits(c.vlo[rn])
                val r: Long = when {
                    d.isNaN() -> 0
                    op == 0 -> if (sf) (if (d >= 9.223372036854775807E18) Long.MAX_VALUE else if (d <= -9.223372036854775808E18) Long.MIN_VALUE else d.toLong())
                               else d.toInt().toLong() and 0xffffffffL
                    else -> if (d <= 0) 0 else if (sf) (if (d >= 1.8446744073709552E19) -1L else java.math.BigDecimal(d).toBigInteger().toLong())
                            else (if (d >= 4294967295.0) 0xffffffffL else d.toLong())
                }
                c.setReg(rd, r)
            }
            else -> c.fail(ins)
        }
    }

    private fun fpScalar(c: Arm64, ins: Int) {
        val type = bits(ins, 23, 22)
        if (type > 1) c.fail(ins)
        val dbl = type == 1
        val rn = bits(ins, 9, 5); val rd = bits(ins, 4, 0); val rm = bits(ins, 20, 16)
        fun get(r: Int): Double = if (dbl) Double.fromBits(c.vlo[r]) else Float.fromBits(c.vlo[r].toInt()).toDouble()
        fun put(r: Int, value: Double) {
            c.vlo[r] = if (dbl) value.toRawBits() else value.toFloat().toRawBits().toLong() and 0xffffffffL
            c.vhi[r] = 0
        }
        fun putF(r: Int, value: Float) { c.vlo[r] = value.toRawBits().toLong() and 0xffffffffL; c.vhi[r] = 0 }
        when {
            bits(ins, 14, 10) == 0b10000 -> { // 1-source
                when (bits(ins, 20, 15)) {
                    0 -> { c.vlo[rd] = if (dbl) c.vlo[rn] else c.vlo[rn] and 0xffffffffL; c.vhi[rd] = 0 } // FMOV
                    1 -> { c.vlo[rd] = if (dbl) c.vlo[rn] and Long.MAX_VALUE else c.vlo[rn] and 0x7fffffffL; c.vhi[rd] = 0 } // FABS
                    2 -> { c.vlo[rd] = if (dbl) c.vlo[rn] xor Long.MIN_VALUE else (c.vlo[rn] xor 0x80000000L) and 0xffffffffL; c.vhi[rd] = 0 } // FNEG
                    3 -> if (dbl) put(rd, kotlin.math.sqrt(get(rn))) else putF(rd, kotlin.math.sqrt(Float.fromBits(c.vlo[rn].toInt())))
                    4 -> { if (dbl) c.fail(ins); val f = Float.fromBits(c.vlo[rn].toInt()); c.vlo[rd] = f.toDouble().toRawBits(); c.vhi[rd] = 0 } // FCVT d, s
                    5 -> { if (!dbl) c.fail(ins); putF(rd, Double.fromBits(c.vlo[rn]).toFloat()) } // FCVT s, d
                    else -> c.fail(ins)
                }
            }
            bits(ins, 11, 10) == 2 -> { // 2-source
                if (dbl) {
                    val a = get(rn); val b = get(rm)
                    put(rd, when (bits(ins, 15, 12)) { 0 -> a * b; 1 -> a / b; 2 -> a + b; 3 -> a - b; else -> c.fail(ins) })
                } else {
                    val a = Float.fromBits(c.vlo[rn].toInt()); val b = Float.fromBits(c.vlo[rm].toInt())
                    putF(rd, when (bits(ins, 15, 12)) { 0 -> a * b; 1 -> a / b; 2 -> a + b; 3 -> a - b; else -> c.fail(ins) })
                }
            }
            bits(ins, 13, 10) == 0b1000 && bits(ins, 15, 14) == 0 -> { // FCMP / FCMPE
                val a = get(rn); val b = if (bits(ins, 4, 3) and 1 == 1) 0.0 else get(rm)
                c.nzcv = when { a.isNaN() || b.isNaN() -> 0b0011; a == b -> 0b0110; a < b -> 0b1000; else -> 0b0010 }
            }
            bits(ins, 11, 10) == 3 -> { // FCSEL
                val pick = if (c.cond(bits(ins, 15, 12))) rn else rm
                c.vlo[rd] = if (dbl) c.vlo[pick] else c.vlo[pick] and 0xffffffffL; c.vhi[rd] = 0
            }
            bits(ins, 12, 10) == 0b100 && bits(ins, 9, 5) == 0 -> { // FMOV imm
                val imm8 = bits(ins, 20, 13)
                c.vlo[rd] = if (dbl) vfpImm64(imm8) else vfpImm32(imm8).toLong() and 0xffffffffL; c.vhi[rd] = 0
            }
            else -> c.fail(ins)
        }
    }

    // ---- LD1/ST1 ... LD4/ST4 (عدة عناصر) ----
    fun multi(c: Arm64, ins: Int) {
        val q = bit(ins, 30); val load = bit(ins, 22); val post = bit(ins, 23)
        val opc = bits(ins, 15, 12); val size = bits(ins, 11, 10)
        val rm = bits(ins, 20, 16); val rn = bits(ins, 9, 5); val rt = bits(ins, 4, 0)
        if (!post && rm != 0) c.fail(ins)
        val (rpt, selem) = when (opc) {
            0b0000 -> 1 to 4; 0b0010 -> 4 to 1; 0b0100 -> 1 to 3; 0b0110 -> 3 to 1
            0b0111 -> 1 to 1; 0b1000 -> 1 to 2; 0b1010 -> 2 to 1
            else -> c.fail(ins)
        }
        if (size == 3 && !q && selem != 1) c.fail(ins)
        val eb = 1 shl size
        val elements = (if (q) 16 else 8) / eb
        val base = c.regSp(rn)
        var offs = 0L
        val regs = HashMap<Int, ByteArray>()
        fun regOf(i: Int) = regs.getOrPut(i) { if (load) ByteArray(16) else load(c, i) }
        for (r in 0 until rpt) for (e in 0 until elements) {
            var tt = (rt + r) % 32
            for (s in 0 until selem) {
                val buf = regOf(tt)
                if (load) setEl(buf, e, eb, c.mem.read(base + offs, eb)) else c.mem.write(base + offs, eb, el(buf, e, eb))
                offs += eb
                tt = (tt + 1) % 32
            }
        }
        if (load) for ((i, b) in regs) store(c, i, b, q)
        if (post) c.setRegSp(rn, base + if (rm == 31) offs else c.reg(rm))
    }
}
