package io.github.mednouaoury.apksentry.core

import java.security.MessageDigest

/**
 * تشغيل مكتبات native (ARM64) داخل صندوق مغلق.
 *
 * الفكرة: الكود native صندوق أسود، لكنه لا يستطيع فعل أي شيء خطير إلا عبر بابين:
 *  1. باب أندرويد (JNI): FindClass، GetMethodID، Call*Method... بأسماء صريحة.
 *  2. باب النظام (libc / syscalls): open، connect، execve، dlsym...
 * نحن نكتب البابين بأنفسنا: كل طلب يُسجَّل، ولا شيء يصل إلى الجهاز الحقيقي.
 * وما يفكّه الكود في الذاكرة (dex، نصوص) نلتقطه ونحلّله.
 */
class NativeLib(val name: String, val base: Long, val end: Long, val exports: Map<String, Long>, val needed: List<String>)

/** واجهة الربط مع محاكي Dalvik: استدعاءات JNI تمر من هنا إلى نفس الصندوق. */
interface JavaBridge {
    fun call(cls: String, name: String, params: List<String>, ret: String, recv: Any?, args: List<Any?>, isStatic: Boolean): Any?
    fun getStatic(cls: String, name: String, type: String): Any?
    fun getField(obj: Any?, cls: String, name: String, type: String): Any?
    fun setField(obj: Any?, cls: String, name: String, value: Any?)
    fun newObject(cls: String, params: List<String>, args: List<Any?>): Any?
    fun isApp(cls: String): Boolean
    fun inspect(bytes: ByteArray, source: String)
}

/** مرجع JNI لوظيفة أو حقل (الكلاسات نمثّلها بـ EClass مثل محاكي Dalvik). */
class JMethodId(val cls: String, val name: String, val sig: String, val isStatic: Boolean) {
    val params: List<String> get() = parseParams(sig)
    val ret: String get() = sig.substringAfter(')')
}
class JFieldId(val cls: String, val name: String, val type: String, val isStatic: Boolean)

internal fun parseParams(sig: String): List<String> {
    val out = ArrayList<String>()
    var i = sig.indexOf('(') + 1
    while (i < sig.length && sig[i] != ')') {
        val start = i
        while (sig[i] == '[') i++
        if (sig[i] == 'L') i = sig.indexOf(';', i)
        i++
        out.add(sig.substring(start, i))
    }
    return out
}

class NativeRuntime(
    val pkg: String,
    private val zip: ZipArchive?,
    private val apkBytes: ByteArray?,
    maxSteps: Long = 40_000_000,
    private val maxMillis: Long = 15_000,
) {
    companion object {
        const val LIB_BASE = 0x7000_0000L
        const val HEAP = 0x2_0000_0000L
        const val HEAP_MAX = 96L * 1024 * 1024
        const val MMAP = 0x3_0000_0000L
        const val STACK_TOP = 0x7f_ff00_0000L
        const val STACK_SIZE = 2L * 1024 * 1024
        const val TLS = 0x7f_fe00_0000L
        const val STUBS = 0x7e_0000_0000L
        const val RET = 0x7d_0000_0000L
        const val HANDLES = 0x71_0000_0000L
        const val STACK_GUARD = 0x1d2c3b4a59687706L
        val ENGINE_LIBS = setOf("libunity.so", "libil2cpp.so", "libmain.so", "libflutter.so", "libapp.so", "libc++_shared.so",
            "libreactnativejni.so", "libhermes.so", "libjsc.so", "libmonosgen-2.0.so", "libxamarin-app.so", "libUE4.so", "libgdx.so",
            "libcocos2dcpp.so", "libfmod.so", "libvklayer_khronos_validation.so", "libtensorflowlite_jni.so", "libsqlcipher.so")
    }

    val mem = ArmMemory(160L * 1024 * 1024)
    val cpu = Arm64(mem).also { it.maxSteps = maxSteps }
    private val t0 = System.currentTimeMillis()

    /** ما فعله الكود native (بكلام بسيط). */
    val events = LinkedHashSet<String>()
    /** طلبات باب أندرويد: "Landroid/telephony/SmsManager;->sendTextMessage". */
    val jniCalls = LinkedHashSet<String>()
    /** نصوص مرّت عبر البابين (غالباً كانت مشفّرة في الملف). */
    val strings = LinkedHashSet<String>()
    val captured = ArrayList<Captured>()
    val stops = ArrayList<String>()
    val libs = LinkedHashMap<String, NativeLib>()
    val registered = HashMap<String, Long>()
    var bridge: JavaBridge? = null
    /** بصمات dex معروفة (الكود الأصلي): لا نعتبرها كوداً مخفياً. */
    val known = HashSet<String>()

    val apkPath = "/data/app/$pkg/base.apk"
    val dataDir = "/data/user/0/$pkg"

    init {
        cpu.checkTime = { if (System.currentTimeMillis() - t0 > maxMillis) throw EmuLimit("الوقت") }
        mem.map(STACK_TOP - STACK_SIZE, STACK_SIZE)
        mem.map(TLS, 0x1000)
        cpu.tpidr = TLS + 0x100
        mem.write(cpu.tpidr + 0x28, 8, STACK_GUARD) // TLS_SLOT_STACK_GUARD في bionic
        cpu.sp = STACK_TOP - 0x100
        cpu.onSvc = { c, _ -> syscall(c) }
    }

    // ---------------- الذاكرة ----------------
    private var heapTop = HEAP
    private var mmapTop = MMAP
    private val allocSize = HashMap<Long, Long>()
    private val heapRanges = ArrayList<LongRange>()

    fun malloc(size: Long): Long {
        val n = ((maxOf(size, 1L) + 15) and 15L.inv())
        if (heapTop + n + 16 - HEAP > HEAP_MAX) throw EmuLimit("الذاكرة")
        val p = heapTop + 16
        mem.map(heapTop, n + 16)
        heapTop += n + 16
        allocSize[p] = size
        return p
    }

    private fun mmapAlloc(size: Long): Long {
        val n = (size + 0xfff) and 0xfffL.inv()
        val p = mmapTop
        mem.map(p, n)
        mmapTop += n + 0x1000
        heapRanges.add(p until p + n)
        return p
    }

    fun cstr(s: String): Long {
        val b = s.toByteArray(Charsets.UTF_8)
        val p = malloc(b.size + 1L)
        mem.put(p, b)
        return p
    }

    private fun str(p: Long): String = if (p == 0L) "" else mem.cString(p).also { note(it) }

    /** نسجّل النصوص المفهومة التي تمر عبر البابين. */
    private fun note(s: String) {
        if (s.length in 3..300 && strings.size < 400 && s.count { it.code in 32..126 || it.code > 0x600 } >= s.length * 0.9) strings.add(s)
    }

    // ---------------- الدوال الوهمية (الأبواب) ----------------
    private val stubAddr = HashMap<String, Long>()
    private var stubCount = 0L

    fun stub(name: String, handler: (Arm64) -> Unit): Long = stubAddr.getOrPut(name) {
        val a = STUBS + stubCount * 16
        if (stubCount % 256 == 0L) {
            mem.map(a, 4096)
            for (i in 0 until 1024) mem.write(a + 4L * i, 4, 0xd65f03c0) // ret
        }
        stubCount++
        cpu.hooks[a] = handler
        a
    }

    // ---------------- تشغيل دالة ----------------
    private var depth = 0

    /** يستدعي دالة من الكود native ويرجع x0. يحفظ حالة المعالج (للاستدعاءات المتداخلة). */
    fun callFunction(addr: Long, vararg args: Long): Long {
        if (depth > 40) throw EmuLimit("عمق الاستدعاءات")
        val savedX = cpu.x.copyOf(); val savedPc = cpu.pc; val savedSp = cpu.sp; val savedFlags = cpu.nzcv
        val ret = RET + depth * 16L
        depth++
        try {
            for ((i, a) in args.withIndex()) if (i < 8) cpu.x[i] = a
            cpu.sp = (cpu.sp - 0x200) and 15L.inv()
            if (args.size > 8) for (i in 8 until args.size) mem.write(cpu.sp + 8L * (i - 8), 8, args[i])
            cpu.x[30] = ret
            cpu.pc = addr
            cpu.run(ret)
            return cpu.x[0]
        } finally {
            depth--
            val r0 = cpu.x[0]
            System.arraycopy(savedX, 0, cpu.x, 0, 31)
            cpu.x[0] = r0
            cpu.pc = savedPc; cpu.sp = savedSp; cpu.nzcv = savedFlags
        }
    }

    // ---------------- تحميل ELF ----------------
    private var nextBase = LIB_BASE
    private val tlsBlocks = HashMap<String, Long>()

    private fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
    private fun u32(b: ByteArray, o: Int) = (u16(b, o).toLong()) or (u16(b, o + 2).toLong() shl 16)
    private fun u64(b: ByteArray, o: Int) = u32(b, o) or (u32(b, o + 4) shl 32)

    /** يحمّل مكتبة ARM64 ويطبّق التحويلات ويشغّل دوال البداية. */
    fun load(name: String, bytes: ByteArray, runInit: Boolean = true): NativeLib? {
        libs[name]?.let { return it }
        if (bytes.size < 64 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() || bytes[4] != 2.toByte()) return null
        if (u16(bytes, 18) != 183) return null // ليس AArch64
        val phoff = u64(bytes, 32).toInt(); val phent = u16(bytes, 54); val phnum = u16(bytes, 56)
        var lo = Long.MAX_VALUE; var hi = 0L
        var dynVaddr = -1L
        var tls: LongArray? = null
        for (i in 0 until phnum) {
            val o = phoff + i * phent
            if (o + 56 > bytes.size) return null
            val type = u32(bytes, o)
            val vaddr = u64(bytes, o + 16); val memsz = u64(bytes, o + 40)
            when (type) {
                1L -> { lo = minOf(lo, vaddr and 0xfffL.inv()); hi = maxOf(hi, vaddr + memsz) }
                2L -> dynVaddr = vaddr
                7L -> tls = longArrayOf(vaddr, u64(bytes, o + 32), memsz)
            }
        }
        if (hi <= lo || hi - lo > 256L * 1024 * 1024) return null
        val base = nextBase - lo
        mem.map(base + lo, hi - lo)
        nextBase = (base + hi + 0x10_0000 + 0xffffff) and 0xffffffL.inv()
        for (i in 0 until phnum) {
            val o = phoff + i * phent
            if (u32(bytes, o) != 1L) continue
            val off = u64(bytes, o + 8); val vaddr = u64(bytes, o + 16); val filesz = u64(bytes, o + 32)
            val n = minOf(filesz, bytes.size - off).toInt()
            if (off >= 0 && n > 0) mem.put(base + vaddr, bytes, off.toInt(), n)
        }
        if (tls != null) {
            // كتلة TLS لهذه المكتبة: نسخة من القالب
            val block = malloc(tls[2] + 64)
            val n = minOf(tls[1], tls[2]).toInt()
            if (n > 0) for (k in 0 until n) mem.w8(block + k, mem.u8(base + tls[0] + k))
            tlsBlocks[name] = block
        }
        if (dynVaddr < 0) return null
        // جدول dynamic
        val dyn = HashMap<Long, Long>()
        val needed = ArrayList<Long>()
        var initArray = 0L; var initArraySz = 0L
        var p = base + dynVaddr
        for (k in 0 until 512) {
            val tag = mem.read(p, 8); val v = mem.read(p + 8, 8)
            if (tag == 0L) break
            if (tag == 1L) needed.add(v) else dyn[tag] = v
            p += 16
        }
        val strtab = base + (dyn[5] ?: return null)
        val symtab = base + (dyn[6] ?: return null)
        initArray = dyn[25]?.let { base + it } ?: 0; initArraySz = dyn[27] ?: 0
        val neededNames = needed.map { mem.cString(strtab + it) }
        // عدد الرموز من جدول hash
        val nsyms = dyn[4]?.let { mem.read(base + it + 4, 4).toInt() } ?: dyn[0x6ffffef5]?.let { gnuHashCount(base + it) } ?: 0
        val exports = HashMap<String, Long>()
        val symName = arrayOfNulls<String>(nsyms)
        val symVal = LongArray(nsyms); val symInfo = IntArray(nsyms); val symShn = IntArray(nsyms)
        for (s in 0 until minOf(nsyms, 200_000)) {
            val so = symtab + s * 24L
            val nm = mem.read(so, 4)
            symInfo[s] = mem.u8(so + 4); symShn[s] = mem.read(so + 6, 2).toInt(); symVal[s] = mem.read(so + 8, 8)
            symName[s] = if (nm == 0L) "" else mem.cString(strtab + nm, 512)
            if (symShn[s] != 0 && symName[s]!!.isNotEmpty() && (symInfo[s] and 0xf) != 6) exports[symName[s]!!] = base + symVal[s]
        }
        val lib = NativeLib(name, base + lo, base + hi, exports, neededNames)
        libs[name] = lib
        // المكتبات المطلوبة من نفس التطبيق نحمّلها قبل التحويلات
        for (n in neededNames) if (n !in libs && n !in SYSTEM_LIBS) libBytes(n)?.let { load(n, it, runInit) }

        fun resolve(s: Int): Long {
            if (s == 0 || s >= nsyms) return 0
            if (symShn[s] != 0) return base + symVal[s]
            val nm = symName[s] ?: return 0
            for (l in libs.values) l.exports[nm]?.let { return it }
            return if ((symInfo[s] and 0xf) == 1) dataImport(nm) else funcImport(nm)
        }
        fun apply(where: Long, info: Long, addend: Long) {
            val type = (info and 0xffffffffL).toInt(); val s = (info ushr 32).toInt()
            when (type) {
                0 -> {}
                1027 -> mem.write(where, 8, base + addend)
                1025, 1026, 257 -> mem.write(where, 8, resolve(s) + addend)
                1030 -> mem.write(where, 8, tlsOffset(name, s, symVal, addend))
                1031 -> { // TLSDESC
                    mem.write(where, 8, stub("tlsdesc") { c -> c.x[0] = mem.read(c.x[0] + 8, 8) })
                    mem.write(where + 8, 8, tlsOffset(name, s, symVal, addend))
                }
                1032 -> mem.write(where, 8, try { callFunction(base + addend) } catch (e: RuntimeException) { 0L })
                else -> events.add("تحويل ELF غير مدعوم $type في $name")
            }
        }
        // RELA + JMPREL
        dyn[7]?.let { off -> val sz = dyn[8] ?: 0; var q = base + off; val e = q + sz; while (q < e) { apply(base + mem.read(q, 8), mem.read(q + 8, 8), mem.read(q + 16, 8)); q += 24 } }
        dyn[23]?.let { off -> val sz = dyn[2] ?: 0; var q = base + off; val e = q + sz; while (q < e) { apply(base + mem.read(q, 8), mem.read(q + 8, 8), mem.read(q + 16, 8)); q += 24 } }
        // صيغة أندرويد المضغوطة APS2
        (dyn[0x60000011] ?: dyn[0x6000000f])?.let { off -> androidRelocs(base + off, dyn[0x60000012] ?: dyn[0x60000010] ?: 0) { w, i, a -> apply(base + w, i, a) } }
        // RELR
        (dyn[36] ?: dyn[0x6fffe000])?.let { off -> relr(base, base + off, dyn[35] ?: dyn[0x6fffe001] ?: 0) }

        if (runInit) {
            val inits = ArrayList<Long>()
            dyn[12]?.let { inits.add(base + it) }
            for (k in 0 until (initArraySz / 8).toInt().coerceAtMost(256)) {
                val f = mem.read(initArray + 8L * k, 8)
                if (f != 0L && f != -1L) inits.add(f)
            }
            for (f in inits) guarded("$name: init") { callFunction(f) }
        }
        return lib
    }

    private fun tlsOffset(lib: String, s: Int, symVal: LongArray, addend: Long): Long {
        val block = tlsBlocks[lib] ?: malloc(256).also { tlsBlocks[lib] = it }
        return block + (if (s in symVal.indices) symVal[s] else 0) + addend - cpu.tpidr
    }

    private fun gnuHashCount(h: Long): Int {
        val nbuckets = mem.read(h, 4).toInt(); val symoffset = mem.read(h + 4, 4).toInt()
        val bloomSize = mem.read(h + 8, 4).toInt()
        if (nbuckets <= 0 || nbuckets > 1_000_000) return 0
        val buckets = h + 16 + 8L * bloomSize
        var max = 0
        for (b in 0 until nbuckets) max = maxOf(max, mem.read(buckets + 4L * b, 4).toInt())
        if (max < symoffset) return symoffset
        val chains = buckets + 4L * nbuckets
        var i = max
        while (mem.read(chains + 4L * (i - symoffset), 4) and 1 == 0L) i++
        return i + 1
    }

    private fun androidRelocs(start: Long, size: Long, apply: (Long, Long, Long) -> Unit) {
        if (mem.read(start, 4) != 0x32535041L) return // "APS2"
        var p = start + 4
        val end = start + size
        fun sleb(): Long {
            var r = 0L; var sh = 0; var b: Int
            do { b = mem.u8(p++); r = r or ((b and 0x7f).toLong() shl sh); sh += 7 } while (b and 0x80 != 0 && p <= end)
            if (sh < 64 && b and 0x40 != 0) r = r or (-1L shl sh)
            return r
        }
        val count = sleb()
        var off = sleb(); var info = 0L; var addend = 0L
        var done = 0L
        while (done < count && p < end) {
            val gsize = sleb(); val flags = sleb()
            val byOffset = flags and 2 != 0L; val byInfo = flags and 1 != 0L
            val byAddend = flags and 4 != 0L; val hasAddend = flags and 8 != 0L
            val gdelta = if (byOffset) sleb() else 0
            if (byInfo) info = sleb()
            if (hasAddend && byAddend) addend += sleb() else if (!hasAddend) addend = 0
            for (k in 0 until gsize) {
                off += if (byOffset) gdelta else sleb()
                if (!byInfo) info = sleb()
                if (hasAddend && !byAddend) addend += sleb()
                apply(off, info, addend)
                done++
            }
        }
    }

    private fun relr(base: Long, start: Long, size: Long) {
        var where = 0L
        var q = start
        while (q < start + size) {
            val e = mem.read(q, 8)
            if (e and 1 == 0L) {
                where = base + e
                mem.write(where, 8, mem.read(where, 8) + base)
                where += 8
            } else {
                var bm = e ushr 1
                var k = 0
                while (bm != 0L) {
                    if (bm and 1 == 1L) { val w = where + 8L * k; mem.write(w, 8, mem.read(w, 8) + base) }
                    bm = bm ushr 1; k++
                }
                where += 63 * 8
            }
            q += 8
        }
    }

    fun zipAsset(name: String): ByteArray? {
        val z = zip ?: return null
        val e = z.entry("assets/" + name.trimStart('/')) ?: return null
        if (e.size > 128L * 1024 * 1024) return null
        return try { z.readBytes(e) } catch (ex: Exception) { null }
    }

    fun libBytes(name: String): ByteArray? {
        val z = zip ?: return null
        for (abi in listOf("arm64-v8a")) {
            val e = z.entry("lib/$abi/$name") ?: continue
            if (e.size > 64L * 1024 * 1024) return null
            return try { z.readBytes(e) } catch (ex: Exception) { null }
        }
        return null
    }

    /** يشغّل خطوة مع حماية: الأخطاء تُسجَّل ولا توقف الفحص. */
    fun guarded(label: String, block: () -> Unit) {
        try { block() }
        catch (e: EmuLimit) { stops.add("$label: توقّف (${e.message})") }
        catch (e: EmuUnsupported) { stops.add("$label: ${e.message}") }
        catch (e: ArmFault) { stops.add("$label: ${e.message}") }
        catch (e: EmuThrow) { stops.add("$label: استثناء Java") }
        catch (e: StackOverflowError) { stops.add("$label: عمق كبير") }
        catch (e: ScanCancelledException) { throw e }
        catch (e: RuntimeException) { stops.add("$label: ${e.javaClass.simpleName}") }
    }

    // ---------------- الدوال المستوردة ----------------
    private val SYSTEM_LIBS = setOf("libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so", "libandroid.so", "libGLESv2.so",
        "libGLESv3.so", "libEGL.so", "libOpenSLES.so", "libjnigraphics.so", "libvulkan.so", "libmediandk.so", "libaaudio.so", "libcamera2ndk.so", "libstdc++.so")

    private val dataImports = HashMap<String, Long>()

    private fun dataImport(name: String): Long = dataImports.getOrPut(name) {
        when (name) {
            "__stack_chk_guard" -> malloc(8).also { mem.write(it, 8, STACK_GUARD) }
            "__sF" -> malloc(3 * 152)
            "environ" -> malloc(16)
            else -> malloc(256)
        }
    }

    private val libc by lazy { Libc(this) }

    private fun funcImport(name: String): Long = stub(name, libc.handler(name) ?: { c ->
        events.add("استدعى دالة نظام غير معروفة: $name")
        c.x[0] = 0
    })

    // ---------------- syscalls مباشرة (svc) ----------------
    private fun syscall(c: Arm64) {
        val nr = c.x[8].toInt()
        c.x[0] = when (nr) {
            56 -> sysOpen(str(c.x[1]))                           // openat
            57 -> 0                                              // close
            63 -> sysRead(c.x[0].toInt(), c.x[1], c.x[2])        // read
            64 -> sysWrite(c.x[0].toInt(), c.x[1], c.x[2])       // write
            62 -> sysSeek(c.x[0].toInt(), c.x[1], c.x[2].toInt())
            172, 174, 175, 176, 177, 178 -> 4321                 // getpid، getuid...
            222 -> { val p = mmapAlloc(c.x[1]); if (c.x[4].toInt() >= 0 && c.x[3] and 0x20 == 0L) fileInto(c.x[4].toInt(), p, c.x[1], c.x[5]); p }
            215, 226 -> 0                                        // munmap، mprotect
            117 -> { events.add("يحاول كشف أدوات التحليل (ptrace)"); 0 }
            198, 203 -> { events.add("يحاول فتح اتصال شبكة مباشرة (socket/connect)"); -1 }
            221 -> { events.add("يحاول تشغيل برنامج (execve): ${str(c.x[0])}"); -1 }
            129, 131 -> { events.add("يحاول قتل عملية (kill)"); 0 }
            93, 94 -> throw EmuLimit("خروج الكود (exit)")
            113 -> { mem.write(c.x[1], 8, 1_700_000_000); mem.write(c.x[1] + 8, 8, 0); 0 }
            167 -> 0 // prctl
            else -> { events.add("syscall مباشر رقم $nr"); -38 }
        }
    }

    // ---------------- نظام الملفات الوهمي ----------------
    class VFile(val path: String, var data: ByteArray, var pos: Long = 0, val writable: Boolean = false)
    val files = HashMap<Int, VFile>()
    private var nextFd = 3
    val written = HashMap<String, java.io.ByteArrayOutputStream>()

    fun fileData(path: String): ByteArray? = when {
        path == apkPath || path.endsWith("/base.apk") -> apkBytes
        path == "/proc/self/status" || path.matches(Regex("/proc/\\d+/status")) -> "Name:\t$pkg\nState:\tS\nTracerPid:\t0\n".toByteArray()
        path == "/proc/self/cmdline" -> (pkg + "\u0000").toByteArray()
        path == "/proc/self/maps" -> libs.values.joinToString("") { "%x-%x r-xp 00000000 00:00 0 /data/app/%s/lib/arm64/%s\n".format(it.base, it.end, pkg, it.name) }.toByteArray()
        written.containsKey(path) -> written[path]!!.toByteArray()
        path.startsWith("/data/app/") && path.contains("/lib/") -> libBytes(path.substringAfterLast('/'))
        else -> null
    }

    fun sysOpen(path: String, write: Boolean = false): Long {
        note(path)
        if (path.startsWith("/proc/") && (path.contains("maps") || path.contains("status"))) events.add("يقرأ $path (فحص إذا كان تحت المراقبة)")
        if (write) {
            val fd = nextFd++
            written[path] = java.io.ByteArrayOutputStream()
            files[fd] = VFile(path, ByteArray(0), writable = true)
            return fd.toLong()
        }
        val d = fileData(path) ?: return -2 // ENOENT
        val fd = nextFd++
        files[fd] = VFile(path, d)
        return fd.toLong()
    }

    fun sysRead(fd: Int, buf: Long, n: Long): Long {
        val f = files[fd] ?: return -9
        val k = minOf(n, f.data.size - f.pos).toInt().coerceAtLeast(0)
        if (k > 0) mem.put(buf, f.data, f.pos.toInt(), k)
        f.pos += k
        return k.toLong()
    }

    fun sysWrite(fd: Int, buf: Long, n: Long): Long {
        if (n < 0 || n > 64L * 1024 * 1024) return -22
        val f = files[fd]
        val data = mem.bytes(buf, n.toInt())
        if (f == null) { if (fd == 1 || fd == 2) note(String(data)); return n }
        val out = written.getOrPut(f.path) { java.io.ByteArrayOutputStream() }
        out.write(data)
        return n
    }

    fun sysSeek(fd: Int, off: Long, whence: Int): Long {
        val f = files[fd] ?: return -9
        f.pos = when (whence) { 0 -> off; 1 -> f.pos + off; else -> f.data.size + off }
        return f.pos
    }

    fun sysClose(fd: Int) {
        val f = files.remove(fd) ?: return
        if (f.writable) written[f.path]?.toByteArray()?.let { inspect(it, "كتابة ملف ${f.path}") }
    }

    private fun fileInto(fd: Int, p: Long, len: Long, off: Long) {
        val f = files[fd] ?: return
        val n = minOf(len, f.data.size - off).toInt()
        if (n > 0) mem.put(p, f.data, off.toInt(), n)
    }

    // ---------------- الالتقاط ----------------
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).toHex()
    private val seen = HashSet<String>()

    /** إذا كانت البيانات كود dex أو أرشيفاً فيه dex، نلتقطها. */
    fun inspect(b: ByteArray, source: String) {
        bridge?.let { it.inspect(b, source); return }
        if (b.size < 0x70) return
        val isDex = b[0] == 'd'.code.toByte() && b[1] == 'e'.code.toByte() && b[2] == 'x'.code.toByte() && b[3] == '\n'.code.toByte()
        if (!isDex) return
        val h = sha(b)
        if (h in known || !seen.add(h)) return
        captured.add(Captured(source, b))
    }

    /** بعد التشغيل: نبحث في الذاكرة التي كتبها الكود عن ملفات dex مفكوكة. */
    fun scanMemoryForDex() {
        val ranges = ArrayList<LongRange>(heapRanges)
        if (heapTop > HEAP) ranges.add(HEAP until heapTop)
        for (r in ranges) {
            var a = r.first
            while (a + 0x70 < r.last) {
                if (mem.isMapped(a) && mem.read(a, 4) == 0x0a786564L) { // "dex\n"
                    val size = mem.read(a + 32, 4)
                    if (size in 0x70..(r.last - a + 1) && size < 64L * 1024 * 1024)
                        inspect(mem.bytes(a, size.toInt()), "فك في الذاكرة (native)")
                }
                a += 4
            }
        }
    }

    // ---------------- JNI ----------------
    private val handles = HashMap<Long, Any?>()
    private val handleOf = java.util.IdentityHashMap<Any, Long>()
    private var nextHandle = 1L

    fun handle(o: Any?): Long {
        if (o == null) return 0
        handleOf[o]?.let { return it }
        val h = HANDLES + (nextHandle++ shl 4)
        handles[h] = o; handleOf[o] = h
        return h
    }

    fun obj(h: Long): Any? = handles[h]

    val env: Long by lazy { Jni.makeEnv(this) }
    val vm: Long by lazy { Jni.makeVm(this) }

    /** يشغّل JNI_OnLoad إن وُجد. */
    fun runJniOnLoad(lib: NativeLib) {
        val f = lib.exports["JNI_OnLoad"] ?: return
        guarded("${lib.name}: JNI_OnLoad") { callFunction(f, vm, 0) }
    }

    /** يستدعي وظيفة native كما يستدعيها ART. */
    fun callJava(fn: Long, isStatic: Boolean, recv: Any?, cls: String, params: List<String>, ret: String, args: List<Any?>): Any? {
        val regs = ArrayList<Long>()
        regs.add(env)
        regs.add(if (isStatic) handle(EClass(cls)) else handle(recv ?: Opaque))
        val fps = ArrayList<Long>()
        for ((i, p) in params.withIndex()) {
            val a = args.getOrNull(i)
            when (p) {
                "F" -> fps.add((a as? Int)?.toLong() ?: 0)
                "D" -> fps.add(a as? Long ?: 0)
                "J" -> regs.add(a as? Long ?: 0)
                "Z", "B", "C", "S", "I" -> regs.add(((a as? Number)?.toLong() ?: 0) and 0xffffffffL)
                else -> regs.add(handle(a))
            }
        }
        for ((i, v) in fps.withIndex()) if (i < 8) { cpu.vlo[i] = v; cpu.vhi[i] = 0 }
        val r = callFunction(fn, *regs.toLongArray())
        return when (ret) {
            "V" -> null
            "J" -> r
            "F" -> cpu.vlo[0].toInt()
            "D" -> cpu.vlo[0]
            "Z", "B", "C", "S", "I" -> r.toInt()
            else -> obj(r)
        }
    }

    /** اسم دالة JNI المعيارية: Java_pkg_Class_method. */
    fun findNative(cls: String, name: String, sig: String): Long? {
        registered["$cls->$name$sig"]?.let { return it }
        registered.entries.firstOrNull { it.key.startsWith("$cls->$name(") }?.let { return it.value }
        val mangled = "Java_" + mangle(cls.trim('L', ';').replace('/', '.')) + "_" + mangle(name)
        for (l in libs.values) {
            l.exports[mangled]?.let { return it }
            l.exports.entries.firstOrNull { it.key.startsWith("${mangled}__") }?.let { return it.value }
        }
        return null
    }

    private fun mangle(s: String): String = buildString {
        for (ch in s) when {
            ch == '.' || ch == '/' -> append('_')
            ch == '_' -> append("_1")
            ch == ';' -> append("_2")
            ch == '[' -> append("_3")
            ch.code in 48..57 || ch.code in 65..90 || ch.code in 97..122 -> append(ch)
            else -> append("_0%04x".format(ch.code))
        }
    }
}
