package io.github.mednouaoury.apksentry.core

import java.io.InputStream

/** قراءة مكتبات .so (ELF): الوظائف المستوردة والمصدّرة، المقاطع التنفيذية، والنصوص. */
object Elf {
    const val EM_ARM = 40
    const val EM_AARCH64 = 183
    const val EM_386 = 3
    const val EM_X86_64 = 62

    class Header(
        val is64: Boolean,
        val machine: Int,
        val phoff: Long,
        val phentsize: Int,
        val phnum: Int,
        val shoff: Long,
        val shentsize: Int,
        val shnum: Int,
    ) {
        val tableSize: Long get() = shentsize.toLong() * shnum
        val phTableEnd: Long get() = phoff + phentsize.toLong() * phnum
        val arch: String
            get() = when (machine) {
                EM_AARCH64 -> "arm64"; EM_ARM -> "arm"; EM_X86_64 -> "x86_64"; EM_386 -> "x86"; else -> "?"
            }
    }

    class Section(val type: Long, val flags: Long, val offset: Long, val size: Long, val link: Int)

    /** مقطع يُحمَّل في الذاكرة. [exec] = فيه كود قابل للتنفيذ. */
    class Segment(val offset: Long, val size: Long, val exec: Boolean)

    fun header(h: ByteArray): Header? {
        if (h.size < 52 || h[0] != 0x7f.toByte() || h[1] != 'E'.code.toByte() ||
            h[2] != 'L'.code.toByte() || h[3] != 'F'.code.toByte()
        ) return null
        if (h.u8(5) != 1) return null // big-endian غير موجود عملياً في أندرويد
        return when (h.u8(4)) {
            2 -> if (h.size < 64) null else Header(true, h.u16(18), h.u64(32), h.u16(54), h.u16(56), h.u64(40), h.u16(58), h.u16(60))
            1 -> Header(false, h.u16(18), h.u32(28), h.u16(42), h.u16(44), h.u32(32), h.u16(46), h.u16(48))
            else -> null
        }
    }

    fun segments(ph: ByteArray, h: Header): List<Segment> = (0 until h.phnum).mapNotNull { i ->
        val o = (h.phoff + i.toLong() * h.phentsize).toInt()
        if (h.is64) {
            if (o + 56 > ph.size || ph.u32(o) != 1L) null
            else Segment(ph.u64(o + 8), ph.u64(o + 32), ph.u32(o + 4) and 1L != 0L)
        } else {
            if (o + 32 > ph.size || ph.u32(o) != 1L) null
            else Segment(ph.u32(o + 4), ph.u32(o + 16), ph.u32(o + 24) and 1L != 0L)
        }
    }

    fun sections(table: ByteArray, h: Header): List<Section> = (0 until h.shnum).mapNotNull { i ->
        val o = i * h.shentsize
        if (h.is64) {
            if (o + 64 > table.size) null
            else Section(table.u32(o + 4), table.u64(o + 8), table.u64(o + 24), table.u64(o + 32), table.i32(o + 40))
        } else {
            if (o + 40 > table.size) null
            else Section(table.u32(o + 4), table.u32(o + 8), table.u32(o + 16), table.u32(o + 20), table.i32(o + 24))
        }
    }

    /** يرجع قسمي .dynsym و .dynstr إن وُجدا. */
    fun dynamicTables(secs: List<Section>): Pair<Section, Section>? {
        val sym = secs.firstOrNull { it.type == 11L } ?: return null // SHT_DYNSYM
        val str = secs.getOrNull(sym.link) ?: return null
        if (sym.size <= 0 || str.size <= 0 || sym.size > 256L * 1024 * 1024 || str.size > 256L * 1024 * 1024) return null
        return sym to str
    }

    /** أقسام البيانات للقراءة فقط (مثل .rodata، حيث توجد النصوص)، حتى [budget] بايت. */
    fun readOnlyData(secs: List<Section>, budget: Long): List<Section> {
        var left = budget
        return secs.filter { it.type == 1L && it.flags and 2L != 0L && it.flags and 1L == 0L && it.flags and 4L == 0L && it.size > 0 }
            .sortedBy { it.offset }
            .filter { s -> if (s.size <= left) { left -= s.size; true } else false }
    }

    class Symbols(val imports: Set<String>, val exports: Set<String>)

    fun symbols(sym: ByteArray, str: ByteArray, is64: Boolean): Symbols {
        val imports = HashSet<String>()
        val exports = HashSet<String>()
        val ent = if (is64) 24 else 16
        var o = 0
        while (o + ent <= sym.size) {
            val nameOff = sym.i32(o)
            val shndx = if (is64) sym.u16(o + 6) else sym.u16(o + 14)
            if (nameOff > 0 && nameOff < str.size) {
                var e = nameOff
                while (e < str.size && str[e] != 0.toByte()) e++
                if (e > nameOff) {
                    val name = String(str, nameOff, e - nameOff, Charsets.ISO_8859_1)
                    if (shndx == 0) imports.add(name) else exports.add(name)
                }
            }
            o += ent
        }
        return Symbols(imports, exports)
    }

    fun undefinedSymbols(sym: ByteArray, str: ByteArray, is64: Boolean): Set<String> = symbols(sym, str, is64).imports
}

/**
 * يبحث داخل الكود التنفيذي عن استدعاءات النظام المباشرة (syscalls) بدون المرور بمكتبة النظام.
 * هذا أسلوب تستعمله أدوات الحماية والبرامج الخبيثة لتجاوز المراقبة.
 */
class SyscallScanner(private val machine: Int, private val ranges: List<LongRange>) {
    val found = HashMap<String, Int>()
    var total = 0
        private set
    private val entropyHist = IntArray(256)
    private var entropyBytes = 0L
    private val window = IntArray(8)
    private var wpos = 0
    private val pending = ByteArray(4)
    private var pendingLen = 0
    private var pendingPos = 0L

    val supported get() = machine == Elf.EM_AARCH64 || machine == Elf.EM_ARM || machine == Elf.EM_X86_64

    /** إنتروبيا أول 4 ميجا من الكود التنفيذي. */
    val codeEntropy: Double
        get() {
            if (entropyBytes < 4096) return 0.0
            var e = 0.0
            for (n in entropyHist) if (n > 0) { val p = n.toDouble() / entropyBytes; e -= p * kotlin.math.ln(p) }
            return e / kotlin.math.ln(2.0)
        }

    fun feed(buf: ByteArray, len: Int, pos: Long) {
        for (r in ranges) {
            val from = maxOf(r.first, pos)
            val to = minOf(r.last + 1, pos + len)
            if (from >= to) continue
            val off = (from - pos).toInt()
            val n = (to - from).toInt()
            if (entropyBytes < 4L * 1024 * 1024) {
                val k = minOf(n.toLong(), 4L * 1024 * 1024 - entropyBytes).toInt()
                for (i in 0 until k) entropyHist[buf[off + i].toInt() and 0xff]++
                entropyBytes += k
            }
            when (machine) {
                Elf.EM_AARCH64, Elf.EM_ARM -> words(buf, off, n, from)
                Elf.EM_X86_64 -> x64(buf, off, n)
            }
        }
    }

    private fun words(buf: ByteArray, off: Int, n: Int, absStart: Long) {
        var i = off
        val end = off + n
        // نكمل كلمة ناقصة من الدفعة السابقة
        if (pendingLen > 0 && pendingPos + pendingLen == absStart) {
            while (pendingLen < 4 && i < end) pending[pendingLen++] = buf[i++]
            if (pendingLen == 4) { word(pending.i32(0)); pendingLen = 0 }
        } else pendingLen = 0
        val misalign = ((absStart + (i - off)) and 3L).toInt()
        if (misalign != 0) i += (4 - misalign).coerceAtMost(end - i)
        while (i + 4 <= end) {
            word(buf.i32(i)); i += 4
        }
        if (i < end) {
            pendingPos = absStart + (i - off)
            pendingLen = 0
            while (i < end) pending[pendingLen++] = buf[i++]
        }
    }

    private fun word(w: Int) {
        val isSvc = if (machine == Elf.EM_AARCH64) w == 0xD4000001.toInt() else w == 0xEF000000.toInt()
        if (isSvc) {
            total++
            var num = -1
            for (k in 1..8) {
                val p = window[(wpos - k + 8 * 8) % 8]
                if (machine == Elf.EM_AARCH64) {
                    if (p and 0xFFE0001F.toInt() == 0x52800008 || p and 0xFFE0001F.toInt() == 0xD2800008.toInt()) { num = (p ushr 5) and 0xFFFF; break }
                } else {
                    if (p and 0xFFFFF000.toInt() == 0xE3A07000.toInt()) { num = p and 0xFF; break }
                }
            }
            name(num)?.let { found.merge(it, 1, Int::plus) }
        }
        window[wpos % 8] = w
        wpos++
    }

    private fun x64(buf: ByteArray, off: Int, n: Int) {
        var i = off + 5
        val end = off + n
        while (i + 1 < end) {
            if (buf[i] == 0x0F.toByte() && buf[i + 1] == 0x05.toByte()) {
                // في x86 البايتين 0F 05 قد يظهران صدفة، فنحسب فقط ما سبقه mov eax برقم استدعاء معروف
                for (j in i - 5 downTo maxOf(off, i - 24)) {
                    if (buf[j] == 0xB8.toByte()) {
                        val n = buf.i32(j + 1)
                        val nm = if (n in 0..512) name(n) else null
                        if (nm != null) { total++; found.merge(nm, 1, Int::plus); break }
                    }
                }
            }
            i++
        }
    }

    private fun name(num: Int): String? = when (machine) {
        Elf.EM_AARCH64 -> A64[num]
        Elf.EM_ARM -> A32[num]
        Elf.EM_X86_64 -> X64[num]
        else -> null
    }

    companion object {
        private val A64 = mapOf(198 to "socket", 203 to "connect", 206 to "sendto", 200 to "bind", 201 to "listen",
            221 to "execve", 117 to "ptrace", 220 to "clone", 226 to "mprotect", 279 to "memfd_create", 129 to "kill",
            56 to "openat", 63 to "read", 64 to "write", 167 to "prctl")
        private val A32 = mapOf(281 to "socket", 283 to "connect", 290 to "sendto", 11 to "execve", 26 to "ptrace",
            2 to "fork", 120 to "clone", 125 to "mprotect", 37 to "kill", 5 to "open", 3 to "read", 4 to "write", 172 to "prctl")
        private val X64 = mapOf(41 to "socket", 42 to "connect", 44 to "sendto", 59 to "execve", 101 to "ptrace",
            57 to "fork", 56 to "clone", 10 to "mprotect", 319 to "memfd_create", 62 to "kill", 257 to "openat", 157 to "prctl")

        /** مجموعات تهمّنا مع وصفها. */
        val GROUPS = linkedMapOf(
            "network" to (setOf("socket", "connect", "sendto", "bind", "listen") to "اتصال بالشبكة"),
            "exec" to (setOf("execve", "fork") to "تشغيل برامج"),
            "debug" to (setOf("ptrace") to "ptrace (مكافحة التحليل أو مراقبة عمليات)"),
            "memexec" to (setOf("mprotect", "memfd_create") to "تغيير صلاحيات الذاكرة (فك كود مشفّر وقت التشغيل)"),
        )
    }
}

/** كلمات مشبوهة داخل نصوص المكتبات native. */
object NativeKeywords {
    val LIST = mapOf(
        "/proc/self/maps" to "يفحص ذاكرته (كشف أدوات التحليل)",
        "TracerPid" to "يكتشف المراقبة (anti-debug)",
        "frida-server" to "يبحث عن Frida",
        "frida-gadget" to "يبحث عن Frida",
        "libfrida" to "يبحث عن Frida",
        "XposedBridge" to "يبحث عن Xposed",
        "libsubstrate" to "يبحث عن Substrate",
        "magisk" to "يبحث عن Magisk/الروت",
        "/system/xbin/su" to "يبحث عن الروت",
        "/system/bin/sh" to "يشغّل أوامر shell",
        "pm install" to "يثبّت تطبيقات بأمر shell",
        "chmod 777" to "يغيّر صلاحيات ملفات",
        "/data/local/tmp" to "يستعمل مجلد /data/local/tmp",
        "LD_PRELOAD" to "حقن مكتبات (LD_PRELOAD)",
        "InMemoryDexClassLoader" to "يحمّل كود dex من الذاكرة",
        "DexClassLoader" to "يحمّل كود dex",
    )
    private val bytes = LIST.keys.associateWith { it.lowercase().toByteArray() }

    fun scan(data: ByteArray, len: Int = data.size): Set<String> {
        val low = ByteArray(len) { val b = data[it]; if (b in 'A'.code.toByte()..'Z'.code.toByte()) (b + 32).toByte() else b }
        return bytes.filter { (_, p) -> low.indexOf(p, 0, len) >= 0 }.keys
    }
}

/** مقطع نريد التقاطه أثناء قراءة متسلسلة. */
class Capture(val start: Long, val len: Int) {
    val data = ByteArray(len)
    var filled = 0
    val done get() = filled >= len
}

/**
 * يقرأ تياراً من البداية للنهاية مرة واحدة ويلتقط المقاطع المطلوبة.
 * إذا لم يكن هناك [onChunk] يتوقف بعد آخر مقطع ويقفز فوق الفراغات.
 */
internal fun streamPass(
    input: InputStream,
    captures: List<Capture>,
    checkCancel: () -> Unit,
    onChunk: ((buf: ByteArray, len: Int, pos: Long) -> Unit)? = null,
) {
    val sorted = captures.sortedBy { it.start }
    val buf = ByteArray(1 shl 20)
    var pos = 0L
    input.use { s ->
        while (true) {
            checkCancel()
            if (onChunk == null) {
                val next = sorted.firstOrNull { !it.done } ?: return
                val target = next.start + next.filled
                while (pos < target) {
                    val k = s.skip(target - pos)
                    if (k <= 0) {
                        if (s.read() < 0) return
                        pos++
                    } else pos += k
                }
            }
            val r = s.read(buf, 0, buf.size)
            if (r < 0) return
            for (c in sorted) {
                if (c.done) continue
                val cs = c.start + c.filled
                val ce = c.start + c.len
                val from = maxOf(cs, pos)
                val to = minOf(ce, pos + r)
                if (from < to && from == cs) {
                    System.arraycopy(buf, (from - pos).toInt(), c.data, c.filled, (to - from).toInt())
                    c.filled += (to - from).toInt()
                }
            }
            onChunk?.invoke(buf, r, pos)
            pos += r
        }
    }
}
