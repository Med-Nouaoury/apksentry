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
    )

    val LOADERS = setOf(
        "Ldalvik/system/DexClassLoader;-><init>", "Ldalvik/system/InMemoryDexClassLoader;-><init>",
        "Ldalvik/system/PathClassLoader;-><init>", "Ldalvik/system/DexFile;->loadDex", "Ldalvik/system/DexFile;-><init>",
        "Ldalvik/system/BaseDexClassLoader;-><init>", "Ldalvik/system/DelegateLastClassLoader;-><init>",
    )

    fun run(
        zip: ZipArchive,
        apkBytes: ByteArray?,
        dexes: List<DexFile>,
        pkg: String,
        appClass: String?,
        factoryClass: String?,
        plain: Set<String> = emptySet(),
        checkCancel: () -> Unit = {},
    ): Result {
        val rt = EmuRuntime(pkg, apkBytes, zip)
        for (d in dexes) rt.known.add(java.security.MessageDigest.getInstance("SHA-256").digest(d.bytes).toHex())
        rt.known.addAll(plain)
        val emu = DalvikEmulator(dexes, rt)
        rt.emu = emu
        val stops = ArrayList<String>()

        fun attempt(label: String, block: () -> Unit) {
            if (rt.captured.isNotEmpty()) return
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

        // 1) كلاس التطبيق: attachBaseContext ثم onCreate (هنا تفك أغلب الأغلفة كودها)
        val app = desc(appClass)
        if (app != null && emu.isApp(app)) {
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
        }
        return Result(rt.captured.toList(), rt.events, emu.steps, stops)
    }
}
