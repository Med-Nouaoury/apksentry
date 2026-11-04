package io.github.mednouaoury.apksentry.core

/**
 * يشغّل كود بداية التطبيق داخل المحاكي ليلتقط الكود المخفي لحظة تحميله.
 */
object Unpacker {
    class Result(
        val payloads: List<Captured>,
        val events: Set<String>,
        val steps: Long,
        /** لماذا توقّفت المحاكاة (إن توقّفت قبل النهاية). */
        val stops: List<String>,
        val native: NativeReport? = null,
    )

    /** ما رأيناه من تشغيل الكود native (ARM64). */
    class NativeReport(
        val libs: List<String>,
        val calls: Int,
        val jniCalls: Set<String>,
        val events: Set<String>,
        val strings: Set<String>,
        val stops: List<String>,
        val steps: Long,
        val coverage: Int,
    )

    val LOADERS = setOf(
        "Ldalvik/system/DexClassLoader;-><init>", "Ldalvik/system/InMemoryDexClassLoader;-><init>",
        "Ldalvik/system/PathClassLoader;-><init>", "Ldalvik/system/DexFile;->loadDex", "Ldalvik/system/DexFile;-><init>",
        "Ldalvik/system/BaseDexClassLoader;-><init>", "Ldalvik/system/DelegateLastClassLoader;-><init>",
    )

    /** كلاسات يشغّلها الأندرويد بنفسه عند بداية التطبيق. */
    private val STAGE_BASES = listOf("Landroid/app/Application;", "Landroid/app/AppComponentFactory;", "Landroid/content/ContextWrapper;")

    /** وظائف تدل أن الكلاس يفك شيئاً. */
    private val DECRYPT_HINTS = setOf("Ljavax/crypto/Cipher;->doFinal", "Ljava/util/zip/Inflater;->inflate",
        "Landroid/content/res/AssetManager;->open", "Landroid/util/Base64;->decode")

    fun run(
        zip: ZipArchive,
        apkBytes: ByteArray?,
        dexes: List<DexFile>,
        pkg: String,
        appClass: String?,
        factoryClass: String?,
        plain: Set<String> = emptySet(),
        checkCancel: () -> Unit = {},
        runNative: Boolean = true,
    ): Result {
        val rt = EmuRuntime(pkg, apkBytes, zip)
        rt.nativeEnabled = runNative
        for (d in dexes) rt.known.add(java.security.MessageDigest.getInstance("SHA-256").digest(d.bytes).toHex())
        rt.known.addAll(plain)
        val emu = DalvikEmulator(dexes, rt)
        rt.emu = emu
        val stops = ArrayList<String>()

        // كل طبقة تتوقف حين تفك شيئاً جديداً؛ الطبقة التالية تكمل من هناك
        var until = 0
        fun attempt(label: String, block: () -> Unit) {
            if (rt.captured.size > until) return
            checkCancel()
            try {
                block()
            } catch (e: EmuLimit) {
                stops.add("$label: توقّف (${e.message})")
            } catch (e: EmuUnsupported) {
                stops.add("$label: ${e.message}")
            } catch (e: EmuThrow) {
                stops.add("$label: استثناء ${(e.ex as? Throwable)?.javaClass?.simpleName ?: e.ex}")
            } catch (e: StackOverflowError) {
                stops.add("$label: عمق كبير")
            } catch (e: OutOfMemoryError) {
                stops.add("$label: الذاكرة")
            } catch (e: ScanCancelledException) {
                throw e
            } catch (e: Exception) {
                stops.add("$label: ${e.javaClass.simpleName}")
            }
        }

        fun desc(name: String?): String? {
            if (name.isNullOrBlank()) return null
            val full = if (name.startsWith(".")) pkg + name else if (!name.contains('.')) "$pkg.$name" else name
            return "L" + full.replace('.', '/') + ";"
        }

        fun runApplication(app: String) {
            var obj: EObj? = null
            attempt("<clinit>") { emu.ensureInit(app) }
            attempt("<init>") {
                val o = EObj(app)
                obj = o
                emu.dispatch(app, "<init>", emptyList(), "V", listOf(o), virtual = false)
            }
            val self = obj ?: EObj(app)
            attempt("attachBaseContext") {
                emu.dispatch(app, "attachBaseContext", listOf("Landroid/content/Context;"), "V", listOf(self, ContextStub()), virtual = true)
            }
            attempt("onCreate") { emu.dispatch(app, "onCreate", emptyList(), "V", listOf(self), virtual = true) }
        }

        fun runMethod(m: AppMethod) {
            attempt("${m.cls.substringAfterLast('/').trimEnd(';')}.${m.name}") {
                val args = ArrayList<Any?>()
                if (!m.isStatic) args.add(EObj(m.cls))
                for (p in m.params) args.add(when {
                    p in EmuRuntime.CONTEXT_TYPES || p == "Landroid/app/Application;" -> ContextStub()
                    p == "Ljava/lang/String;" -> ""
                    p == "Ljava/lang/ClassLoader;" -> ClassLoaderStub("parent")
                    else -> DalvikEmulator.defaultOf(p)
                })
                emu.ensureInit(m.cls)
                emu.invoke(m, args)
            }
        }

        // 1) كلاس التطبيق: attachBaseContext ثم onCreate (هنا تفك أغلب الأغلفة كودها)
        val app = desc(appClass)
        if (app != null && emu.isApp(app)) runApplication(app)

        // 2) AppComponentFactory (تستعمله بعض الأغلفة الحديثة)
        val factory = desc(factoryClass)
        if (factory != null && emu.isApp(factory)) {
            attempt("AppComponentFactory") {
                val f = EObj(factory)
                emu.dispatch(factory, "<init>", emptyList(), "V", listOf(f), virtual = false)
                emu.dispatch(factory, "instantiateClassLoader", listOf("Ljava/lang/ClassLoader;", "Landroid/content/pm/ApplicationInfo;"),
                    "Ljava/lang/ClassLoader;", listOf(f, ClassLoaderStub("parent"), AppInfoStub()), virtual = true)
            }
        }

        // 3) أي وظيفة تحمّل كوداً: ننفّذها مباشرة بمعاملات افتراضية
        if (rt.captured.isEmpty()) {
            val targets = ArrayList<AppMethod>()
            for (d in dexes) {
                for (c in 0 until d.classCount) {
                    val cls = d.className(c)
                    if (Rules.KNOWN_PREFIXES.any { cls.startsWith(it) }) continue
                    var hit = false
                    d.scanClass(c, onInvoke = { mi -> if (d.methodFull(mi) in LOADERS) hit = true }, onString = {})
                    if (hit) emu.classes[cls]?.methods?.values?.filter { it.codeOff != 0 }?.let(targets::addAll)
                }
            }
            for (m in targets.take(24)) {
                if (rt.captured.isNotEmpty()) break
                runMethod(m)
            }
        }

        // 4) الكود native: نحمّل مكتبات التطبيق (غير المحركات المعروفة) ونشغّل كل وظيفة native يعلنها كوده
        var nativeCalls = 0
        val natLibs = ArrayList<String>()
        rt.native()?.let { nat ->
            val cands = zip.entries.filter { e ->
                e.name.startsWith("lib/arm64-v8a/") && e.name.endsWith(".so") && e.size in 1..(8L * 1024 * 1024) &&
                    e.name.substringAfterLast('/') !in NativeRuntime.ENGINE_LIBS
            }.sortedBy { it.size }.take(4)
            for (e in cands) {
                checkCancel()
                val n = e.name.substringAfterLast('/')
                if (n !in nat.rt.libs) rt.loadNative(n)
                if (n in nat.rt.libs) natLibs.add(n)
            }
            val natives = emu.classes.values.asSequence().flatMap { it.methods.values.asSequence() }
                .filter { it.access and 0x100 != 0 && Rules.KNOWN_PREFIXES.none { p -> it.cls.startsWith(p) } }
                .take(40).toList()
            for (m in natives) {
                checkCancel()
                if (nat.rt.findNative(m.cls, m.name, "(" + m.params.joinToString("") + ")" + m.ret) == null) continue
                nativeCalls++
                val args = ArrayList<Any?>()
                if (!m.isStatic) args.add(EObj(m.cls))
                for (p in m.params) args.add(when {
                    p in EmuRuntime.CONTEXT_TYPES || p == "Landroid/app/Application;" -> ContextStub()
                    p == "Landroid/content/res/AssetManager;" -> AssetsStub()
                    p == "Ljava/lang/String;" -> ""
                    else -> DalvikEmulator.defaultOf(p)
                })
                nat.rt.guarded("native ${m.cls.substringAfterLast('/').trimEnd(';')}.${m.name}") {
                    try { nat.callFromJava(m, args) } catch (e: EmuThrow) { }
                }
            }
            nat.rt.guarded("بحث في الذاكرة") { nat.rt.scanMemoryForDex() }
        }

        // 5) طبقات متعددة: الكود المفكوك قد يكون غلافاً آخر. الأندرويد كان سيشغّل كلاس التطبيق الحقيقي
        //    الموجود فيه، فنشغّله نحن أيضاً، ونكرر حتى 3 طبقات.
        var stage = 0
        var done = 0
        while (rt.captured.size > done && stage < 3) {
            val fresh = rt.captured.subList(done, rt.captured.size).toList()
            done = rt.captured.size
            until = done
            stage++
            for (p in fresh) {
                val dex = try { DexFile(p.bytes) } catch (e: Exception) { continue }
                for (c in 0 until dex.classCount) {
                    if (rt.captured.size > until) break
                    val cls = dex.className(c)
                    val ac = emu.classes[cls] ?: continue
                    if (STAGE_BASES.any { emu.extends(cls, it) }) { runApplication(cls); continue }
                    var loads = false
                    dex.scanClass(c, onInvoke = { mi -> if (dex.methodFull(mi) in LOADERS || dex.methodFull(mi) in DECRYPT_HINTS) loads = true }, onString = {})
                    if (loads) ac.methods.values.filter { it.codeOff != 0 && it.name != "<clinit>" }.take(8).forEach(::runMethod)
                }
                // طبقة صغيرة لا تظهر فيها علامات واضحة (reflection، نصوص مقسّمة): نجرّب كل وظائفها
                if (rt.captured.size == until && dex.classCount <= 60) {
                    var budget = 40
                    for (c in 0 until dex.classCount) {
                        val ac = emu.classes[dex.className(c)] ?: continue
                        for (m in ac.methods.values) {
                            if (budget <= 0 || rt.captured.size > until) break
                            if (m.codeOff == 0 || m.name == "<clinit>") continue
                            budget--
                            runMethod(m)
                        }
                    }
                }
            }
        }
        val nr = rt.nativeRuntime
        val native = if (nr == null || nr.libs.isEmpty()) null else {
            nr.cpu.trackCoverage = false
            NativeReport(natLibs.ifEmpty { nr.libs.keys.toList() }, nativeCalls, nr.jniCalls.toSet(), nr.events.toSet(), nr.strings.toSet(), nr.stops.toList(), nr.cpu.steps, 0)
        }
        return Result(rt.captured.toList(), rt.events, emu.steps, stops, native)
    }
}
