package io.github.mednouaoury.apksentry.core

import java.io.InputStream

/**
 * TLSH (Trend Micro Locality Sensitive Hash): بصمة "تقريبية".
 * عكس SHA-256، ملفّان متشابهان يعطيان بصمتين قريبتين، فنعرف النسخ المعدّلة قليلاً من فيروس معروف.
 * النسخة القياسية T1 (128 خانة، checksum بايت واحد) كما تستعملها MalwareBazaar وVirusTotal.
 * منقولة من الكود المرجعي (Apache/BSD) ومُتحقَّق منها مقابل py-tlsh.
 */
class Tlsh {
    private val buckets = LongArray(256)
    private val win = IntArray(5)
    private var len = 0L
    private var checksum = 0

    fun update(data: ByteArray, off: Int = 0, n: Int = data.size) {
        val t = V
        for (i in off until off + n) {
            val j = (len % 5).toInt()
            win[j] = data[i].toInt() and 0xff
            if (len >= 4) {
                val a0 = win[j]
                val a1 = win[(j + 4) % 5]
                val a2 = win[(j + 3) % 5]
                val a3 = win[(j + 2) % 5]
                val a4 = win[(j + 1) % 5]
                checksum = t[t[t[1 xor a0] xor a1] xor checksum]
                buckets[t[t[t[49 xor a0] xor a1] xor a2]]++
                buckets[t[t[t[12 xor a0] xor a1] xor a3]]++
                buckets[t[t[t[178 xor a0] xor a2] xor a3]]++
                buckets[t[t[t[166 xor a0] xor a2] xor a4]]++
                buckets[t[t[t[84 xor a0] xor a1] xor a4]]++
                buckets[t[t[t[230 xor a0] xor a3] xor a4]]++
            }
            len++
        }
    }

    fun update(input: InputStream, check: () -> Unit = {}) {
        val buf = ByteArray(1 shl 20)
        input.use { s ->
            while (true) {
                check()
                val r = s.read(buf)
                if (r < 0) break
                update(buf, 0, r)
            }
        }
    }

    /** البصمة بصيغة "T1..." أو null إذا كان الملف صغيراً جداً أو بلا تنوّع كافٍ. */
    fun digest(): String? {
        if (len < 50 || len > 0xFFFFFFFFL) return null
        val b = LongArray(128) { buckets[it] }
        val sorted = b.sortedArray()
        val q1 = sorted[31]
        val q2 = sorted[63]
        val q3 = sorted[95]
        if (q3 == 0L) return null
        if (b.count { it > 0 } <= 64) return null
        val code = IntArray(32)
        for (i in 0 until 32) {
            var h = 0
            for (j in 0 until 4) {
                val k = b[4 * i + j]
                h += when {
                    q3 < k -> 3 shl (j * 2)
                    q2 < k -> 2 shl (j * 2)
                    q1 < k -> 1 shl (j * 2)
                    else -> 0
                }
            }
            code[i] = h
        }
        val l = lCapture(len)
        val qr1 = ((q1 * 100 / q3) % 16).toInt()
        val qr2 = ((q2 * 100 / q3) % 16).toInt()
        val sb = StringBuilder("T1")
        sb.hex(swap(checksum)).hex(swap(l)).hex(swap(qr1 or (qr2 shl 4)))
        for (i in 31 downTo 0) sb.hex(code[i])
        return sb.toString()
    }

    /** بصمة مفكوكة للمقارنة. */
    class Digest(val checksum: Int, val lvalue: Int, val q1: Int, val q2: Int, val code: IntArray)

    companion object {
        private val V = intArrayOf(
            1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
            14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
            110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
            25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
            97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
            174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
            132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
            119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
            138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
            170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
            125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
            118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
            27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
            233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
            140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
            51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209
        )

        private val TOPVAL = longArrayOf(
        1L, 2L, 3L, 5L, 7L, 11L, 17L, 25L, 38L, 57L,
        86L, 129L, 194L, 291L, 437L, 656L, 854L, 1110L, 1443L, 1876L,
        2439L, 3171L, 3475L, 3823L, 4205L, 4626L, 5088L, 5597L, 6157L, 6772L,
        7450L, 8195L, 9014L, 9916L, 10907L, 11998L, 13198L, 14518L, 15970L, 17567L,
        19323L, 21256L, 23382L, 25720L, 28292L, 31121L, 34233L, 37656L, 41422L, 45564L,
        50121L, 55133L, 60646L, 66711L, 73382L, 80721L, 88793L, 97672L, 107439L, 118183L,
        130002L, 143002L, 157302L, 173032L, 190335L, 209369L, 230306L, 253337L, 278670L, 306538L,
        337191L, 370911L, 408002L, 448802L, 493682L, 543050L, 597356L, 657091L, 722800L, 795081L,
        874589L, 962048L, 1058252L, 1164078L, 1280486L, 1408534L, 1549388L, 1704327L, 1874759L, 2062236L,
        2268459L, 2495305L, 2744836L, 3019320L, 3321252L, 3653374L, 4018711L, 4420582L, 4862641L, 5348905L,
        5883796L, 6472176L, 7119394L, 7831333L, 8614467L, 9475909L, 10423501L, 11465851L, 12612437L, 13873681L,
        15261050L, 16787154L, 18465870L, 20312458L, 22343706L, 24578077L, 27035886L, 29739474L, 32713425L, 35984770L,
        39583245L, 43541573L, 47895730L, 52685306L, 57953837L, 63749221L, 70124148L, 77136564L, 84850228L, 93335252L,
        102668779L, 112935659L, 124229227L, 136652151L, 150317384L, 165349128L, 181884040L, 200072456L, 220079703L, 242087671L,
        266296456L, 292926096L, 322218735L, 354440623L, 389884688L, 428873168L, 471760495L, 518936559L, 570830240L, 627913311L,
        690704607L, 759775136L, 835752671L, 919327967L, 1011260767L, 1112386880L, 1223623232L, 1345985727L, 1480584256L, 1628642751L,
        1791507135L, 1970657856L, 2167723648L, 2384496256L, 2622945920L, 2885240448L, 3173764736L, 3491141248L, 3840255616L, 4224281216L,
        )

        /** جدول الفرق بين بايتين (كل بايت = 4 أزواج بتات). */
        private val PAIR_DIFF: Array<IntArray> = Array(256) { x -> IntArray(256) { y -> byteDiff(x, y) } }

        private fun pairDiff(a: Int, b: Int): Int = when (Math.abs(a - b)) { 0 -> 0; 1 -> 1; 2 -> 2; else -> 6 }

        private fun byteDiff(x: Int, y: Int): Int {
            var d = 0
            for (s in intArrayOf(6, 4, 2, 0)) d += pairDiff((x shr s) and 3, (y shr s) and 3)
            return d
        }

        private fun swap(b: Int): Int = ((b and 0xF0) shr 4) or ((b and 0x0F) shl 4)

        private fun StringBuilder.hex(b: Int): StringBuilder {
            val h = "0123456789ABCDEF"
            append(h[(b shr 4) and 15]).append(h[b and 15])
            return this
        }

        private fun lCapture(len: Long): Int {
            var bottom = 0
            var top = 170
            var idx = 85
            while (true) {
                if (idx == 0) return 0
                if (len <= TOPVAL[idx] && len > TOPVAL[idx - 1]) return idx
                if (len < TOPVAL[idx]) top = idx - 1 else bottom = idx + 1
                idx = (bottom + top) / 2
                if (idx < 0 || idx >= 170) return 0
            }
        }

        fun of(data: ByteArray): String? = Tlsh().also { it.update(data) }.digest()

        /** يفك بصمة نصية (مع أو بدون T1). */
        fun parse(s: String): Digest? {
            val h = s.trim().let { if (it.startsWith("T1", ignoreCase = true)) it.substring(2) else it }
            if (h.length != 70 || !h.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return null
            fun byte(i: Int) = h.substring(i * 2, i * 2 + 2).toInt(16)
            val qb = swap(byte(2))
            val code = IntArray(32) { byte(3 + 31 - it) }
            return Digest(swap(byte(0)), swap(byte(1)), qb and 15, (qb shr 4) and 15, code)
        }

        private fun modDiff(x: Int, y: Int, r: Int): Int {
            val dl = Math.abs(x - y)
            return minOf(dl, r - dl)
        }

        /** المسافة بين بصمتين: 0 = متطابقتان، أقل من ~50 = متشابهتان جداً، فوق 200 = لا علاقة. */
        fun distance(a: Digest, b: Digest): Int {
            var diff = 0
            val ld = modDiff(a.lvalue, b.lvalue, 256)
            diff += if (ld <= 1) ld else ld * 12
            val q1 = modDiff(a.q1, b.q1, 16)
            diff += if (q1 <= 1) q1 else (q1 - 1) * 12
            val q2 = modDiff(a.q2, b.q2, 16)
            diff += if (q2 <= 1) q2 else (q2 - 1) * 12
            if (a.checksum != b.checksum) diff++
            for (i in 0 until 32) diff += PAIR_DIFF[a.code[i]][b.code[i]]
            return diff
        }

        fun distance(a: String, b: String): Int? {
            val x = parse(a) ?: return null
            val y = parse(b) ?: return null
            return distance(x, y)
        }
    }
}
