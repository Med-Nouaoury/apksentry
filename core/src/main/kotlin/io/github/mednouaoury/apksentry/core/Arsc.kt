package io.github.mednouaoury.apksentry.core

/**
 * قارئ صغير لملف resources.arsc: يحوّل رقم مورد (مثل @0x7f120034) إلى النصوص المقابلة له
 * بكل اللغات. نحتاجه لمعرفة اسم التطبيق الظاهر للمستخدم.
 */
class Arsc private constructor(private val d: ByteArray) {
    private var globalStrings: Array<String> = emptyArray()
    /** (حزمة، نوع) -> قائمة كتل TYPE */
    private val types = HashMap<Int, MutableList<Int>>()

    companion object {
        private const val RES_STRING_POOL = 0x0001
        private const val RES_TABLE = 0x0002
        private const val RES_TABLE_PACKAGE = 0x0200
        private const val RES_TABLE_TYPE = 0x0201
        private const val FLAG_SPARSE = 0x01
        private const val FLAG_OFFSET16 = 0x02
        private const val ENTRY_COMPLEX = 0x0001
        private const val ENTRY_COMPACT = 0x0008
        private const val NO_ENTRY = -1

        fun parse(data: ByteArray): Arsc? = try {
            Arsc(data).takeIf { it.load() }
        } catch (e: Exception) {
            null
        }
    }

    private fun load(): Boolean {
        if (d.size < 12 || d.u16(0) != RES_TABLE) return false
        var p = d.u16(2)
        while (p + 8 <= d.size) {
            val type = d.u16(p)
            val size = d.i32(p + 4)
            if (size < 8 || p.toLong() + size > d.size) break
            when (type) {
                RES_STRING_POOL -> if (globalStrings.isEmpty()) globalStrings = Axml.readStringPool(d, p)
                RES_TABLE_PACKAGE -> loadPackage(p, size)
            }
            p += size
        }
        return types.isNotEmpty()
    }

    private fun loadPackage(start: Int, size: Int) {
        val pkgId = d.i32(start + 8) and 0xff
        val headerSize = d.u16(start + 2)
        var p = start + headerSize
        val end = start + size
        var guard = 0
        while (p + 8 <= end && guard++ < 100_000) {
            val type = d.u16(p)
            val csize = d.i32(p + 4)
            if (csize < 8 || p.toLong() + csize > end) break
            if (type == RES_TABLE_TYPE) {
                val typeId = d.u8(p + 8)
                types.getOrPut((pkgId shl 8) or typeId) { ArrayList() }.add(p)
            }
            p += csize
        }
    }

    /** كل النصوص المقابلة للمورد [id] في كل الإعدادات (اللغات)، مع اللغة. الافتراضي أولاً. */
    fun strings(id: Int, depth: Int = 0): List<Pair<String, String>> {
        if (depth > 4) return emptyList()
        val blocks = types[(id ushr 24 shl 8) or ((id ushr 16) and 0xff)] ?: return emptyList()
        val entry = id and 0xffff
        val out = ArrayList<Pair<String, String>>()
        for (b in blocks) {
            // ملف تالف أو مُعقّد عمداً: نتجاهل الكتلة ونكمل
            val v = try { value(b, entry) } catch (e: IndexOutOfBoundsException) { null } ?: continue
            val lang = try { lang(b) } catch (e: IndexOutOfBoundsException) { "" }
            when (v.first) {
                0x03 -> globalStrings.getOrNull(v.second)?.let { out.add(lang to it) }
                0x01 -> if (v.second != id) strings(v.second, depth + 1).forEach { out.add((if (lang.isEmpty()) it.first else lang) to it.second) }
            }
        }
        return out.sortedBy { if (it.first.isEmpty()) 0 else 1 }
    }

    private fun lang(block: Int): String {
        val cfg = block + 20
        if (cfg + 12 > d.size) return ""
        val a = d.u8(cfg + 8)
        val b = d.u8(cfg + 9)
        if (a == 0) return ""
        return if (a and 0x80 == 0) "${a.toChar()}${b.toChar()}" else "?"
    }

    /** نوع القيمة وقيمتها للمدخل [entry] في الكتلة، أو null. */
    private fun value(block: Int, entry: Int): Pair<Int, Int>? {
        val headerSize = d.u16(block + 2)
        val chunkSize = d.i32(block + 4)
        val flags = d.u8(block + 9)
        val count = d.i32(block + 12)
        val entriesStart = d.i32(block + 16)
        if (count <= 0 || count > 1_000_000) return null
        val idx = block + headerSize
        val off: Int = when {
            flags and FLAG_SPARSE != 0 -> {
                // أزواج (رقم، إزاحة/4) مرتّبة
                var lo = 0
                var hi = count - 1
                var found = NO_ENTRY
                while (lo <= hi) {
                    val mid = (lo + hi) ushr 1
                    val e = d.u16(idx + mid * 4)
                    when {
                        e < entry -> lo = mid + 1
                        e > entry -> hi = mid - 1
                        else -> { found = d.u16(idx + mid * 4 + 2) * 4; break }
                    }
                }
                found
            }
            entry >= count -> NO_ENTRY
            flags and FLAG_OFFSET16 != 0 -> d.u16(idx + entry * 2).let { if (it == 0xffff) NO_ENTRY else it * 4 }
            else -> d.i32(idx + entry * 4)
        }
        if (off == NO_ENTRY || off < 0) return null
        val e = block + entriesStart + off
        if (e < block || e + 8 > block + chunkSize) return null
        val eflags = d.u16(e + 2)
        if (eflags and ENTRY_COMPACT != 0) {
            // مدخل مضغوط (أندرويد 14+): المفتاح 16 بت، ونوع القيمة في البايت العلوي للأعلام
            return (eflags ushr 8) to d.i32(e + 4)
        }
        if (eflags and ENTRY_COMPLEX != 0) return null
        val esize = d.u16(e)
        val v = e + esize
        if (v + 8 > block + chunkSize) return null
        return d.u8(v + 3) to d.i32(v + 4)
    }
}
