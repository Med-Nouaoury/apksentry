package io.github.mednouaoury.apksentry.core

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64

/** كود وجدناه وقت المحاكاة (الكود الحقيقي المخفي). */
class Captured(val source: String, val bytes: ByteArray)

// ---------------- كائنات وهمية تمثّل أجزاء النظام ----------------
class ContextStub { override fun toString() = "Context" }
class AssetsStub
class ResourcesStub
class AppInfoStub
class PrefsStub
class ClassLoaderStub(val tag: String)
/** شيء من النظام لا يهمنا: كل ما يُطلب منه يرجع قيمة فارغة. */
object Opaque
class ThreadStub(val runnable: Any?)
class EMethod(val cls: String, val name: String, val params: List<String>?)
class ECtor(val cls: String, val params: List<String>?)
class EField(val cls: String, val name: String)

/** ملف في نظام الملفات الوهمي. */
class VFile(val path: String) { override fun toString() = path }

/** كتابة في ملف وهمي: تُحفظ في الذاكرة فقط. */
class VfsOut(private val rt: EmuRuntime, val path: String, append: Boolean) : ByteArrayOutputStream() {
    init {
        if (append) rt.vfs[path]?.let { write(it, 0, it.size) }
    }

    override fun write(b: Int) { rt.allocate(1); super.write(b) }
    override fun write(b: ByteArray, off: Int, len: Int) { rt.allocate(len.toLong()); super.write(b, off, len) }
    override fun flush() { rt.vfs[path] = toByteArray() }
    override fun close() {
        val data = toByteArray()
        rt.vfs[path] = data
        rt.inspectBytes(data, "كتابة $path")
    }
}

/** RandomAccessFile للقراءة فقط من ملف وهمي (تستعمله بعض الأغلفة لقراءة ذيل ملف APK). */
class RafStub(val data: ByteArray) { var pos = 0L }

class ZipStub(val bytes: ByteArray) {
    val zip = ZipArchive(ByteArraySource(bytes))
}

/**
 * البيئة التي يرى فيها الكود المُحاكى "النظام".
 * لا يُنفَّذ شيء حقيقي إلا كلاسات القائمة البيضاء (نصوص، تشفير، ضغط، تدفّقات في الذاكرة).
 */
class EmuRuntime(
    val pkg: String,
    apkBytes: ByteArray?,
    private val zip: ZipArchive,
    val maxSteps: Long = 30_000_000,
    private val maxMillis: Long = 15_000,
    private val maxAlloc: Long = 192L * 1024 * 1024,
) {
    val captured = ArrayList<Captured>()
    val events = LinkedHashSet<String>()
    val vfs = HashMap<String, ByteArray>()
    /** بصمات الكود الأصلي للتطبيق (لا نعتبره كوداً مخفياً). */
    val known = HashSet<String>()
    var emu: DalvikEmulator? = null
    private val t0 = System.currentTimeMillis()
    private var allocated = 0L
    private val seen = HashSet<String>()

    val dataDir = "/data/user/0/$pkg"
    val apkPath = "/data/app/$pkg/base.apk"
    private val libDir = "/data/app/$pkg/lib/arm64"

    init {
        if (apkBytes != null) vfs[apkPath] = apkBytes
    }

    // ---------------- الربط مع محاكي ARM64 ----------------
    private val apkBytesRef = apkBytes
    private var nativeRt: NativeRuntime? = null
    /** هل نسمح بتشغيل الكود native؟ (يتحكم فيه Unpacker) */
    var nativeEnabled = false

    fun native(): NativeBridge? {
        if (!nativeEnabled) return null
        val e = emu ?: return null
        nativeRt?.let { return NativeBridge(it, this, e) }
        // على الهاتف: لا نشغّل المحاكي native إلا إذا بقيت ذاكرة كافية (وإلا يقتل النظام التطبيق)
        val free = MemGuard.free() - MemGuard.RESERVE
        if (free < nativeMemory + 32L * 1024 * 1024 || nativeMemory < 24L * 1024 * 1024) {
            events.add("لم نشغّل الكود native: الذاكرة المتاحة لا تكفي (${free / (1024 * 1024)} ميجا)")
            nativeEnabled = false
            return null
        }
        val n = NativeRuntime(pkg, zip, apkBytesRef, memLimit = nativeMemory)
        nativeRt = n
        val b = NativeBridge(n, this, e)
        n.bridge = b
        return b
    }

    val nativeRuntime: NativeRuntime? get() = nativeRt

    fun loadNative(name: String) {
        val b = native() ?: return
        val lib = if (name.endsWith(".so")) name.substringAfterLast('/') else "lib$name.so"
        if (lib in NativeRuntime.ENGINE_LIBS) return
        val bytes = b.rt.libBytes(lib) ?: return
        b.rt.guarded(lib) {
            val l = b.rt.load(lib, bytes)
            if (l != null) b.rt.runJniOnLoad(l)
        }
    }

    fun checkTime() {
        if (System.currentTimeMillis() - t0 > maxMillis) throw EmuLimit("الوقت")
    }

    private var sinceCheck = 0L

    fun allocate(n: Long) {
        allocated += n
        if (allocated > maxAlloc) throw EmuLimit("الذاكرة")
        sinceCheck += n
        if (sinceCheck > 4L * 1024 * 1024) { sinceCheck = 0; if (MemGuard.free() < MemGuard.RESERVE) throw EmuLimit("ذاكرة الهاتف") }
    }

    /** حد ذاكرة المحاكي native (يحدّده Unpacker حسب الذاكرة الحرة). */
    var nativeMemory = 96L * 1024 * 1024

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).toHex()

    /** كل مصفوفة bytes تمر من هنا: إذا كانت كود dex أو أرشيف فيه dex، نلتقطها. */
    fun inspectBytes(b: ByteArray, source: String) {
        if (b.size < 0x70) return
        val isDex = b[0] == 'd'.code.toByte() && b[1] == 'e'.code.toByte() && b[2] == 'x'.code.toByte() && b[3] == '\n'.code.toByte()
        val isZip = b[0] == 'P'.code.toByte() && b[1] == 'K'.code.toByte() && b[2].toInt() == 3 && b[3].toInt() == 4
        if (!isDex && !isZip) return
        val h = sha(b)
        if (h in known || !seen.add(h)) return
        if (isDex) {
            captured.add(Captured(source, b))
            try { emu?.addDex(DexFile(b)) } catch (e: Exception) { }
        } else {
            try {
                val z = ZipArchive(ByteArraySource(b))
                for (e in z.entries) {
                    if (!Regex("classes\\d*\\.dex").matches(e.name.substringAfterLast('/')) || e.size > 64L * 1024 * 1024) continue
                    inspectBytes(z.readBytes(e), "$source!${e.name}")
                }
            } catch (e: Exception) {
            }
        }
    }

    // ---------------- الحقول ----------------
    fun getStatic(cls: String, name: String, type: String): Any? {
        when (cls) {
            "Landroid/os/Build\$VERSION;" -> return when (name) { "SDK_INT" -> 33; "RELEASE" -> "13"; "CODENAME" -> "REL"; else -> DalvikEmulator.defaultOf(type) ?: "" }
            "Landroid/os/Build;" -> return when (name) {
                "MODEL" -> "Pixel 7"; "MANUFACTURER" -> "Google"; "BRAND" -> "google"; "DEVICE" -> "panther"; "PRODUCT" -> "panther"
                "HARDWARE" -> "panther"; "FINGERPRINT" -> "google/panther/panther:13/TQ3A.230805.001/10316531:user/release-keys"
                "CPU_ABI" -> "arm64-v8a"; "SUPPORTED_ABIS" -> arrayOf<Any?>("arm64-v8a"); "TAGS" -> "release-keys"; "TYPE" -> "user"
                else -> DalvikEmulator.defaultOf(type) ?: ""
            }
        }
        PRIM_TYPE[cls]?.let { if (name == "TYPE") return EClass(it) }
        val jc = allowedClass(cls)
        if (jc != null) {
            try {
                val f = jc.getField(name)
                if (Modifier.isStatic(f.modifiers)) return toEmu(f.get(null))
            } catch (e: Exception) { }
        }
        return DalvikEmulator.defaultOf(type) ?: if (type.startsWith("Landroid") || type.startsWith("Ljava")) Opaque else null
    }

    fun getField(obj: Any, cls: String, name: String, type: String): Any? {
        if (obj is AppInfoStub) return when (name) {
            "sourceDir", "publicSourceDir" -> apkPath
            "nativeLibraryDir" -> libDir
            "dataDir" -> dataDir
            "packageName", "processName" -> pkg
            "targetSdkVersion" -> 33
            "uid" -> 10123
            else -> DalvikEmulator.defaultOf(type)
        }
        return DalvikEmulator.defaultOf(type) ?: Opaque
    }

    fun setField(obj: Any, name: String, v: Any?) {}

    fun instanceOf(x: Any, t: String): Boolean {
        if (x is ContextStub) return t in CONTEXT_TYPES
        if (x is VFile) return t == "Ljava/io/File;"
        if (x is Opaque) return true
        val jc = javaClassOf(t) ?: return false
        return jc.isInstance(x)
    }

    // ---------------- الاستدعاءات ----------------
    fun call(cls: String, name: String, params: List<String>, ret: String, recvRaw: Any?, args: List<Any?>, emu: DalvikEmulator): Any? {
        val recv = emu.deref(recvRaw)
        val a = args.map { emu.deref(it) }

        // مُنشئ لكلاس من النظام
        if (name == "<init>") {
            if (recv is EObj) return null // super() من كلاس التطبيق
            return construct(cls, params, a, emu)
        }

        // Object
        if (recv != null && name == "getClass" && params.isEmpty()) return EClass(descOfObj(recv))
        if (name == "hashCode" && params.isEmpty() && (recv is EObj || recv is EClass)) return System.identityHashCode(recv)
        if (name == "equals" && params.size == 1 && (recv is EObj || recv is EClass)) return if (recv == a[0]) 1 else 0
        if (name == "toString" && params.isEmpty() && recv is EObj) return recv.cls
        if (name == "wait" || name == "notify" || name == "notifyAll") return null

        // Context (التطبيق نفسه أو كائن وهمي)
        if (recv is ContextStub || (recv is EObj && CONTEXT_TYPES.any { emu.extends(recv.cls, it) }))
            return context(recv, name, params, ret, a)
        if (recv is EObj && emu.extends(recv.cls, "Ljava/lang/Thread;") && name == "start") return runRunnable(recv, emu)

        when (recv) {
            is AssetsStub -> return assets(name, a)
            is ResourcesStub -> return when (name) { "getAssets" -> AssetsStub(); else -> defaultFor(ret) }
            is AppInfoStub -> return defaultFor(ret)
            is PrefsStub -> return prefs(name, params, ret, a)
            is VFile -> return file(recv, name, a)
            is ZipStub -> return zipFile(recv, name, a)
            is RafStub -> return raf(recv, name, a)
            is ClassLoaderStub -> return when (name) {
                "loadClass", "findClass" -> EClass(descOf(a[0] as? String ?: ""))
                "getParent" -> ClassLoaderStub("parent")
                else -> defaultFor(ret)
            }
            is EClass -> return klass(recv, name, a, emu)
            is EMethod -> return when (name) {
                "invoke" -> reflectInvoke(recv, a.getOrNull(0), a.getOrNull(1) as? Array<*>, emu)
                "getName" -> recv.name
                else -> defaultFor(ret)
            }
            is ECtor -> return when (name) {
                "newInstance" -> instantiate(recv.cls, recv.params, (a.getOrNull(0) as? Array<*>)?.toList() ?: emptyList(), emu)
                else -> defaultFor(ret)
            }
            is EField -> return when {
                name.startsWith("get") -> { val o = a.getOrNull(0); if (o is EObj) o.fields[recv.name] else if (emu.isApp(recv.cls)) null else Opaque }
                name.startsWith("set") -> { val o = a.getOrNull(0); if (o is EObj) o.fields[recv.name] = a.getOrNull(1); null }
                else -> defaultFor(ret)
            }
            is ThreadStub -> return when (name) {
                "start", "run" -> runRunnable(recv.runnable, emu)
                "getContextClassLoader" -> ClassLoaderStub("ctx")
                else -> defaultFor(ret)
            }
            is Opaque -> return defaultFor(ret)
        }

        // استدعاءات ثابتة وكلاسات خاصة
        when (cls) {
            "Landroid/util/Base64;" -> return base64(name, a)
            "Landroid/util/Log;" -> return 0
            "Landroid/text/TextUtils;" -> if (name == "isEmpty") return if ((a[0] as? CharSequence).isNullOrEmpty()) 1 else 0
            "Ljava/lang/System;" -> return system(name, a)
            "Ljava/lang/Thread;" -> return when (name) {
                "currentThread" -> ThreadStub(null)
                "sleep", "yield" -> null
                else -> defaultFor(ret)
            }
            "Landroid/os/Process;" -> return when (name) { "myPid" -> 4321; "myUid" -> 10123; "myTid" -> 4321; else -> defaultFor(ret) }
            "Ljava/lang/Class;" -> if (name == "forName") return EClass(descOf(a[0] as? String ?: ""))
            "Ljava/lang/reflect/Array;" -> if (name == "newInstance" && a[0] is EClass) return emu.newArray("[" + (a[0] as EClass).desc, DalvikEmulator.asInt(a[1]))
            "Ldalvik/system/DexFile;" -> if (name == "loadDex") { loadPath(a.getOrNull(0) as? String, "DexFile.loadDex"); return Opaque }
            "Ljava/lang/ClassLoader;" -> if (name == "getSystemClassLoader") return ClassLoaderStub("system")
            "Ljava/lang/Runtime;" -> { events.add("يحاول تنفيذ أوامر نظام (Runtime)"); return if (name == "getRuntime") Opaque else defaultFor(ret) }
        }
        if (cls.startsWith("Ljava/net/") || cls.startsWith("Ljavax/net/") || cls == "Ljava/lang/ProcessBuilder;") {
            events.add("يحاول الاتصال أو التنفيذ: ${cls.trim('L', ';').replace('/', '.')}")
            return defaultFor(ret)
        }

        // القائمة البيضاء: ننفّذها حقيقياً (آمنة: ذاكرة فقط)
        reflectCall(cls, name, params, ret, recv, a)?.let { return if (it === NOTHING) null else it }

        // باقي النظام: لا نعرفه، نرجع قيمة فارغة ونكمل
        if (cls.startsWith("Landroid/") || cls.startsWith("Landroidx/") || cls.startsWith("Lcom/android/") || cls.startsWith("Ldalvik/") ||
            cls.startsWith("Ljava/lang/reflect/") || cls == "Ljava/lang/ref/WeakReference;" || cls == "Ljava/lang/Object;") {
            events.add("تجاهلنا ${cls.trim('L', ';').substringAfterLast('/')}.$name")
            return defaultFor(ret)
        }
        throw EmuUnsupported("${cls.trim('L', ';').replace('/', '.')}.$name")
    }

    private fun defaultFor(ret: String): Any? = when (ret) {
        "V" -> null
        "Ljava/lang/String;" -> ""
        else -> DalvikEmulator.defaultOf(ret) ?: Opaque
    }

    private fun runRunnable(r: Any?, emu: DalvikEmulator): Any? {
        if (r is EObj) emu.dispatch(r.cls, "run", emptyList(), "V", listOf(r), virtual = true)
        return null
    }

    // ---------------- المُنشئات ----------------
    private fun construct(cls: String, params: List<String>, a: List<Any?>, emu: DalvikEmulator): Any? = when (cls) {
        "Ljava/lang/Object;" -> Any()
        "Ljava/io/File;" -> VFile(filePath(a))
        "Ljava/io/FileOutputStream;" -> VfsOut(this, pathOf(a[0]), a.getOrNull(1)?.let { DalvikEmulator.asInt(it) != 0 } ?: false)
        "Ljava/io/FileInputStream;" -> ByteArrayInputStream(vfs[pathOf(a[0])] ?: throw EmuThrow(FileNotFoundException(pathOf(a[0]))))
        "Ljava/io/RandomAccessFile;" -> RafStub(vfs[pathOf(a[0])] ?: throw EmuThrow(FileNotFoundException(pathOf(a[0]))))
        "Ljava/util/zip/ZipFile;", "Ljava/util/jar/JarFile;" -> ZipStub(vfs[pathOf(a[0])] ?: throw EmuThrow(IOException("zip")))
        "Ldalvik/system/DexClassLoader;", "Ldalvik/system/PathClassLoader;", "Ldalvik/system/BaseDexClassLoader;", "Ldalvik/system/DelegateLastClassLoader;" -> {
            loadPath(a.getOrNull(0) as? String, cls.substringAfterLast('/').trimEnd(';'))
            ClassLoaderStub("dex")
        }
        "Ldalvik/system/InMemoryDexClassLoader;" -> {
            val bufs = when (val b = a.getOrNull(0)) { is ByteBuffer -> listOf(b); is Array<*> -> b.filterIsInstance<ByteBuffer>(); else -> emptyList() }
            for (bb in bufs) {
                val d = bb.duplicate()
                val bytes = ByteArray(d.remaining()).also { d.get(it) }
                inspectBytes(bytes, "InMemoryDexClassLoader")
            }
            ClassLoaderStub("memory")
        }
        "Ldalvik/system/DexFile;" -> { loadPath(pathOf(a[0]), "DexFile"); Opaque }
        "Ljava/lang/Thread;" -> ThreadStub(a.firstOrNull { it is EObj })
        else -> {
            val r = reflectCall(cls, "<init>", params, "V", null, a)
            when {
                r != null && r !== NOTHING -> r
                cls.startsWith("Landroid/") || cls.startsWith("Landroidx/") || cls.startsWith("Ljava/lang/ref/") -> Opaque
                else -> throw EmuUnsupported("new ${cls.trim('L', ';').replace('/', '.')}")
            }
        }
    }

    private fun loadPath(path: String?, how: String) {
        if (path == null) return
        for (p in path.split(':')) {
            val b = vfs[p]
            if (b != null) inspectBytes(b, "$how($p)") else events.add("$how: ملف غير موجود $p")
        }
    }

    private fun pathOf(x: Any?): String = when (x) {
        is VFile -> x.path
        is String -> x
        else -> throw EmuUnsupported("مسار غير معروف")
    }

    private fun filePath(a: List<Any?>): String = when (a.size) {
        1 -> pathOf(a[0])
        else -> (a[0]?.let { pathOf(it) } ?: "") + "/" + (a[1] as? String ?: "")
    }.replace("//", "/")

    // ---------------- Context ----------------
    private fun context(self: Any?, name: String, params: List<String>, ret: String, a: List<Any?>): Any? = when (name) {
        "getAssets" -> AssetsStub()
        "getResources" -> ResourcesStub()
        "getApplicationInfo" -> AppInfoStub()
        "getPackageName", "getOpPackageName", "getBasePackageName" -> pkg
        "getPackageCodePath", "getPackageResourcePath" -> apkPath
        "getFilesDir" -> VFile("$dataDir/files")
        "getCacheDir" -> VFile("$dataDir/cache")
        "getCodeCacheDir" -> VFile("$dataDir/code_cache")
        "getNoBackupFilesDir" -> VFile("$dataDir/no_backup")
        "getDataDir" -> VFile(dataDir)
        "getDir" -> VFile("$dataDir/app_${a[0]}")
        "getExternalFilesDir" -> VFile("/sdcard/Android/data/$pkg/files")
        "getExternalCacheDir" -> VFile("/sdcard/Android/data/$pkg/cache")
        "getDatabasePath" -> VFile("$dataDir/databases/${a[0]}")
        "getFileStreamPath" -> VFile("$dataDir/files/${a[0]}")
        "openFileOutput" -> VfsOut(this, "$dataDir/files/${a[0]}", (DalvikEmulator.asInt(a.getOrNull(1)) and 0x8000) != 0)
        "openFileInput" -> ByteArrayInputStream(vfs["$dataDir/files/${a[0]}"] ?: throw EmuThrow(FileNotFoundException(a[0].toString())))
        "deleteFile" -> 1
        "getClassLoader" -> ClassLoaderStub("app")
        "getApplicationContext", "getBaseContext" -> self ?: ContextStub()
        "getSharedPreferences" -> PrefsStub()
        "checkSelfPermission", "checkCallingOrSelfPermission" -> 0
        else -> defaultFor(ret)
    }

    private fun assets(name: String, a: List<Any?>): Any? = when (name) {
        "open" -> {
            val p = (a[0] as? String ?: "").trimStart('/')
            val e = zip.entry("assets/$p") ?: throw EmuThrow(FileNotFoundException(p))
            if (e.size > 128L * 1024 * 1024) throw EmuLimit("ملف كبير")
            allocate(e.size)
            ByteArrayInputStream(zip.readBytes(e))
        }
        "list" -> {
            val dir = (a[0] as? String ?: "").trim('/')
            val prefix = if (dir.isEmpty()) "assets/" else "assets/$dir/"
            zip.entries.filter { it.name.startsWith(prefix) }.map { it.name.removePrefix(prefix).substringBefore('/') }.distinct().toTypedArray<Any?>()
        }
        "close" -> null
        else -> throw EmuUnsupported("AssetManager.$name")
    }

    private fun prefs(name: String, params: List<String>, ret: String, a: List<Any?>): Any? = when {
        name.startsWith("get") && a.size >= 2 -> a[1]
        name == "edit" || name.startsWith("put") || name == "remove" || name == "clear" -> PrefsStub()
        name == "commit" -> 1
        name == "contains" -> 0
        else -> defaultFor(ret)
    }

    // ---------------- الملفات الوهمية ----------------
    private fun file(f: VFile, name: String, a: List<Any?>): Any? {
        val p = f.path
        return when (name) {
            "getPath", "getAbsolutePath", "getCanonicalPath", "toString" -> p
            "getAbsoluteFile", "getCanonicalFile" -> f
            "getName" -> p.substringAfterLast('/')
            "getParent" -> p.substringBeforeLast('/', "")
            "getParentFile" -> VFile(p.substringBeforeLast('/', "/"))
            "exists" -> if (vfs.containsKey(p) || vfs.keys.any { it.startsWith("$p/") } || p.startsWith(dataDir)) 1 else 0
            "isFile" -> if (vfs.containsKey(p)) 1 else 0
            "isDirectory" -> if (vfs.containsKey(p)) 0 else 1
            "length" -> (vfs[p]?.size ?: 0).toLong()
            "delete" -> { vfs.remove(p); 1 }
            "mkdir", "mkdirs", "createNewFile", "canRead", "canWrite", "setReadable", "setWritable", "setExecutable",
            "setReadOnly", "setLastModified" -> 1
            "renameTo" -> { (a[0] as? VFile)?.let { t -> vfs.remove(p)?.let { vfs[t.path] = it } }; 1 }
            "lastModified" -> 1_700_000_000_000L
            "list" -> vfs.keys.filter { it.startsWith("$p/") }.map { it.removePrefix("$p/").substringBefore('/') }.distinct().toTypedArray<Any?>()
            "listFiles" -> vfs.keys.filter { it.startsWith("$p/") }.map { "$p/" + it.removePrefix("$p/").substringBefore('/') }.distinct().map { VFile(it) }.toTypedArray<Any?>()
            "toURI", "toPath" -> throw EmuUnsupported("File.$name")
            "hashCode" -> p.hashCode()
            "equals" -> if ((a[0] as? VFile)?.path == p) 1 else 0
            else -> throw EmuUnsupported("File.$name")
        }
    }

    private fun zipFile(z: ZipStub, name: String, a: List<Any?>): Any? = when (name) {
        "getEntry", "getJarEntry" -> z.zip.entry(a[0] as? String ?: "")?.let { e -> java.util.zip.ZipEntry(e.name).also { it.size = e.size } }
        "getInputStream" -> {
            val n = (a[0] as? java.util.zip.ZipEntry)?.name ?: throw EmuUnsupported("ZipFile.getInputStream")
            val e = z.zip.entry(n) ?: throw EmuThrow(IOException(n))
            allocate(e.size)
            ByteArrayInputStream(z.zip.readBytes(e))
        }
        "entries" -> java.util.Collections.enumeration(z.zip.entries.map { e -> java.util.zip.ZipEntry(e.name).also { it.size = e.size } })
        "size" -> z.zip.entries.size
        "close" -> null
        "getName" -> apkPath
        else -> throw EmuUnsupported("ZipFile.$name")
    }

    private fun raf(r: RafStub, name: String, a: List<Any?>): Any? {
        fun readInto(b: ByteArray, off: Int, len: Int): Int {
            if (r.pos >= r.data.size) return -1
            val n = minOf(len.toLong(), r.data.size - r.pos).toInt()
            System.arraycopy(r.data, r.pos.toInt(), b, off, n)
            r.pos += n
            return n
        }
        return when (name) {
            "length" -> r.data.size.toLong()
            "seek" -> { r.pos = DalvikEmulator.asLong(a[0]); null }
            "getFilePointer" -> r.pos
            "read" -> when (a.size) {
                0 -> if (r.pos < r.data.size) r.data[(r.pos++).toInt()].toInt() and 0xff else -1
                1 -> readInto(a[0] as ByteArray, 0, (a[0] as ByteArray).size)
                else -> readInto(a[0] as ByteArray, DalvikEmulator.asInt(a[1]), DalvikEmulator.asInt(a[2]))
            }
            "readFully" -> {
                val b = a[0] as ByteArray
                val off = if (a.size > 1) DalvikEmulator.asInt(a[1]) else 0
                val len = if (a.size > 2) DalvikEmulator.asInt(a[2]) else b.size
                if (readInto(b, off, len) < len) throw EmuThrow(java.io.EOFException())
                null
            }
            "readInt" -> { val b = ByteArray(4); if (readInto(b, 0, 4) < 4) throw EmuThrow(java.io.EOFException()); ByteBuffer.wrap(b).int }
            "readLong" -> { val b = ByteArray(8); if (readInto(b, 0, 8) < 8) throw EmuThrow(java.io.EOFException()); ByteBuffer.wrap(b).long }
            "skipBytes" -> { val n = DalvikEmulator.asInt(a[0]); r.pos += n; n }
            "close" -> null
            else -> throw EmuUnsupported("RandomAccessFile.$name")
        }
    }

    // ---------------- Reflection (داخل المحاكي فقط) ----------------
    private fun klass(c: EClass, name: String, a: List<Any?>, emu: DalvikEmulator): Any? = when (name) {
        "getName", "getCanonicalName" -> c.desc.trim('L', ';').replace('/', '.')
        "getSimpleName" -> c.desc.trim('L', ';').substringAfterLast('/')
        "getMethod", "getDeclaredMethod" -> EMethod(c.desc, a[0] as? String ?: "", paramDescs(a.getOrNull(1)))
        "getConstructor", "getDeclaredConstructor" -> ECtor(c.desc, paramDescs(a.getOrNull(0)))
        "getField", "getDeclaredField" -> EField(c.desc, a[0] as? String ?: "")
        "newInstance" -> instantiate(c.desc, emptyList(), emptyList(), emu)
        "getClassLoader" -> ClassLoaderStub("app")
        "isInstance" -> { val o = a[0]; if (o is EObj && emu.extends(o.cls, c.desc)) 1 else 0 }
        "getSuperclass" -> emu.classes[c.desc]?.superName?.let { EClass(it) }
        "desiredAssertionStatus", "isInterface", "isArray", "isPrimitive" -> 0
        else -> Opaque
    }

    private fun paramDescs(x: Any?): List<String>? = (x as? Array<*>)?.map { (it as? EClass)?.desc ?: return null }

    private fun instantiate(cls: String, params: List<String>?, args: List<Any?>, emu: DalvikEmulator): Any? {
        if (emu.isApp(cls)) {
            emu.ensureInit(cls)
            val o = EObj(cls)
            val ctors = emu.classes[cls]?.byName?.get("<init>").orEmpty()
            val m = ctors.firstOrNull { params == null || it.params == params } ?: ctors.firstOrNull { it.params.size == args.size }
            if (m != null) emu.invoke(m, listOf<Any?>(o) + args)
            return o
        }
        val p = Pending(cls)
        return construct(cls, params ?: args.map { inferDesc(it) }, args, emu).also { p.real = it }
    }

    private fun reflectInvoke(m: EMethod, obj: Any?, args: Array<*>?, emu: DalvikEmulator): Any? {
        val list = args?.toList() ?: emptyList()
        if (emu.isApp(m.cls) || (obj is EObj)) {
            val owner = (obj as? EObj)?.cls ?: m.cls
            var c: String? = owner
            var guard = 0
            while (c != null && guard++ < 64) {
                val cands = emu.classes[c]?.byName?.get(m.name).orEmpty()
                val target = cands.firstOrNull { m.params != null && it.params == m.params } ?: cands.firstOrNull { it.params.size == list.size }
                if (target != null) return emu.invoke(target, if (target.isStatic) list else listOf(obj) + list)
                c = emu.classes[c]?.superName
            }
        }
        val params = m.params ?: list.map { inferDesc(it) }
        return call(m.cls, m.name, params, "Ljava/lang/Object;", obj, list, emu)
    }

    private fun inferDesc(x: Any?): String = when (x) {
        is String -> "Ljava/lang/String;"; is ByteArray -> "[B"; is Int -> "I"; is Long -> "J"
        is ByteBuffer -> "Ljava/nio/ByteBuffer;"; is ClassLoaderStub -> "Ljava/lang/ClassLoader;"
        else -> "Ljava/lang/Object;"
    }

    // ---------------- Base64 / System ----------------
    private fun base64(name: String, a: List<Any?>): Any? {
        val flags = DalvikEmulator.asInt(a.last())
        val url = flags and 8 != 0
        return try {
            when (name) {
                "decode" -> {
                    val raw: String = when (val x = a[0]) {
                        is String -> x
                        is ByteArray -> if (a.size == 4) String(x, DalvikEmulator.asInt(a[1]), DalvikEmulator.asInt(a[2]), Charsets.ISO_8859_1) else String(x, Charsets.ISO_8859_1)
                        else -> throw EmuUnsupported("Base64.decode")
                    }
                    val clean = raw.filterNot { it.isWhitespace() }
                    val padded = clean + "=".repeat((4 - clean.length % 4) % 4)
                    (if (url) Base64.getUrlDecoder() else Base64.getDecoder()).decode(padded).also { allocate(it.size.toLong()); inspectBytes(it, "Base64.decode") }
                }
                "encode", "encodeToString" -> {
                    val src = a[0] as? ByteArray ?: throw EmuUnsupported("Base64.encode")
                    val data = if (a.size == 4) src.copyOfRange(DalvikEmulator.asInt(a[1]), DalvikEmulator.asInt(a[1]) + DalvikEmulator.asInt(a[2])) else src
                    var enc = if (url) Base64.getUrlEncoder() else if (flags and 2 != 0) Base64.getEncoder() else Base64.getMimeEncoder(76, "\n".toByteArray())
                    if (flags and 1 != 0) enc = enc.withoutPadding()
                    var s = enc.encodeToString(data)
                    if (flags and 2 == 0 && !url) s += "\n"
                    if (name == "encode") s.toByteArray(Charsets.ISO_8859_1) else s
                }
                else -> throw EmuUnsupported("Base64.$name")
            }
        } catch (e: IllegalArgumentException) {
            throw EmuThrow(e)
        }
    }

    private fun system(name: String, a: List<Any?>): Any? = when (name) {
        "arraycopy" -> {
            try {
                System.arraycopy(a[0], DalvikEmulator.asInt(a[1]), a[2], DalvikEmulator.asInt(a[3]), DalvikEmulator.asInt(a[4]))
            } catch (e: IndexOutOfBoundsException) { throw EmuThrow(e) } catch (e: ArrayStoreException) { throw EmuThrow(e) } catch (e: NullPointerException) { throw EmuThrow(e) }
            null
        }
        "currentTimeMillis" -> 1_700_000_000_000L
        "nanoTime" -> 1_000_000_000L
        "identityHashCode" -> System.identityHashCode(a[0])
        "getProperty" -> when (a[0]) { "java.vm.version" -> "2.1.0"; "os.arch" -> "aarch64"; "line.separator" -> "\n"; "file.separator" -> "/"; else -> a.getOrNull(1) }
        "lineSeparator" -> "\n"
        "getenv" -> null
        "loadLibrary", "load" -> { events.add("يحمّل مكتبة native: ${a[0]}"); (a[0] as? String)?.let(::loadNative); null }
        "exit" -> throw EmuLimit("System.exit")
        "gc", "runFinalization" -> null
        else -> throw EmuUnsupported("System.$name")
    }

    // ---------------- القائمة البيضاء (تنفيذ حقيقي آمن) ----------------
    private object Nothing0
    private val NOTHING: Any = Nothing0

    private fun allowedClass(desc: String): Class<*>? {
        val name = javaName(desc) ?: return null
        if (name !in ALLOW) return null
        return try { Class.forName(name, false, EmuRuntime::class.java.classLoader) } catch (e: Throwable) { null }
    }

    private fun javaClassOf(desc: String): Class<*>? {
        PRIM_CLASS[desc]?.let { return it }
        if (desc.startsWith("[")) {
            return try { Class.forName(desc.replace('/', '.'), false, EmuRuntime::class.java.classLoader) } catch (e: Throwable) { null }
        }
        val name = javaName(desc) ?: return null
        if (!name.startsWith("java.") && !name.startsWith("javax.")) return null
        return try { Class.forName(name, false, EmuRuntime::class.java.classLoader) } catch (e: Throwable) { null }
    }

    /** يرجع null إذا لم يكن الاستدعاء من القائمة البيضاء، و NOTHING لنتيجة void. */
    private fun reflectCall(cls: String, name: String, params: List<String>, ret: String, recv: Any?, a: List<Any?>): Any? {
        if (recv is EObj || recv is Pending) return null
        val pClasses = params.map { javaClassOf(it) ?: return null }.toTypedArray()
        val candidates = LinkedHashSet<Class<*>>()
        allowedClass(cls)?.let { candidates.add(it) }
        if (recv != null) {
            var k: Class<*>? = recv.javaClass
            while (k != null) {
                if (k.name in ALLOW) candidates.add(k)
                k.interfaces.filter { it.name in ALLOW }.forEach { candidates.add(it) }
                k = k.superclass
            }
        }
        if (candidates.isEmpty()) return null
        val args = Array(a.size) { toJava(a[it], params[it]) }
        for (k in candidates) {
            try {
                if (name == "<init>") {
                    val c = k.getConstructor(*pClasses)
                    return c.newInstance(*args)
                }
                val m = k.getMethod(name, *pClasses)
                if (m.declaringClass.name !in ALLOW && m.declaringClass != Any::class.java) continue
                if (BLOCKED_RET.any { it.isAssignableFrom(m.returnType) }) return null
                val isStatic = Modifier.isStatic(m.modifiers)
                if (!isStatic && (recv == null || !k.isInstance(recv))) continue
                val r = m.invoke(if (isStatic) null else recv, *args)
                if (m.returnType == Void.TYPE) return NOTHING
                return toEmu(r) ?: NOTHING
            } catch (e: NoSuchMethodException) {
                continue
            } catch (e: InvocationTargetException) {
                val cause = e.cause
                if (cause is OutOfMemoryError) throw EmuLimit("الذاكرة")
                throw EmuThrow(cause)
            } catch (e: IllegalArgumentException) {
                throw EmuUnsupported("وسائط غير متوافقة: $name")
            } catch (e: IllegalAccessException) {
                continue
            }
        }
        return null
    }

    private fun toJava(x: Any?, desc: String): Any? = when (desc) {
        "Z" -> DalvikEmulator.asInt(x) != 0
        "B" -> DalvikEmulator.asInt(x).toByte()
        "S" -> DalvikEmulator.asInt(x).toShort()
        "C" -> DalvikEmulator.asInt(x).toChar()
        "I" -> DalvikEmulator.asInt(x)
        "J" -> DalvikEmulator.asLong(x)
        "F" -> Float.fromBits(DalvikEmulator.asInt(x))
        "D" -> Double.fromBits(DalvikEmulator.asLong(x))
        else -> if (x == 0) null else x
    }

    private fun toEmu(r: Any?): Any? = when (r) {
        is Boolean -> if (r) 1 else 0
        is Char -> r.code
        is Byte -> r.toInt()
        is Short -> r.toInt()
        is Float -> r.toRawBits()
        is Double -> r.toRawBits()
        is ByteArray -> { inspectBytes(r, "ناتج فك"); r }
        else -> r
    }

    private fun descOfObj(o: Any): String = when (o) {
        is EObj -> o.cls
        is String -> "Ljava/lang/String;"
        is ContextStub -> "Landroid/app/ContextImpl;"
        else -> "L" + o.javaClass.name.replace('.', '/') + ";"
    }

    companion object {
        val CONTEXT_TYPES = setOf("Landroid/content/Context;", "Landroid/content/ContextWrapper;", "Landroid/app/Application;",
            "Landroid/app/Activity;", "Landroid/app/Service;", "Landroid/view/ContextThemeWrapper;", "Landroid/app/ContextImpl;",
            "Landroidx/multidex/MultiDexApplication;", "Landroid/support/multidex/MultiDexApplication;")

        private val PRIM_TYPE = mapOf("Ljava/lang/Integer;" to "I", "Ljava/lang/Long;" to "J", "Ljava/lang/Boolean;" to "Z",
            "Ljava/lang/Byte;" to "B", "Ljava/lang/Character;" to "C", "Ljava/lang/Short;" to "S", "Ljava/lang/Float;" to "F",
            "Ljava/lang/Double;" to "D", "Ljava/lang/Void;" to "V")

        private val PRIM_CLASS = mapOf("I" to Int::class.javaPrimitiveType!!, "J" to Long::class.javaPrimitiveType!!,
            "Z" to Boolean::class.javaPrimitiveType!!, "B" to Byte::class.javaPrimitiveType!!, "C" to Char::class.javaPrimitiveType!!,
            "S" to Short::class.javaPrimitiveType!!, "F" to Float::class.javaPrimitiveType!!, "D" to Double::class.javaPrimitiveType!!)

        /** كلاسات آمنة: تعمل في الذاكرة فقط (لا ملفات، لا شبكة، لا عمليات، لا reflection، لا تحميل كود). */
        val ALLOW = setOf(
            "java.lang.String", "java.lang.StringBuilder", "java.lang.StringBuffer", "java.lang.CharSequence", "java.lang.AbstractStringBuilder",
            "java.lang.Integer", "java.lang.Long", "java.lang.Short", "java.lang.Byte", "java.lang.Character", "java.lang.Boolean",
            "java.lang.Float", "java.lang.Double", "java.lang.Number", "java.lang.Math", "java.lang.Comparable", "java.lang.Iterable",
            "java.util.Arrays", "java.util.ArrayList", "java.util.LinkedList", "java.util.HashMap", "java.util.LinkedHashMap",
            "java.util.TreeMap", "java.util.HashSet", "java.util.List", "java.util.Map", "java.util.Set", "java.util.Collection",
            "java.util.Iterator", "java.util.Enumeration", "java.util.Map\$Entry", "java.util.AbstractMap", "java.util.AbstractList",
            "java.util.AbstractCollection", "java.util.Collections", "java.util.Locale", "java.util.UUID", "java.util.Random", "java.util.Objects",
            "java.util.zip.Inflater", "java.util.zip.Deflater", "java.util.zip.InflaterInputStream", "java.util.zip.GZIPInputStream",
            "java.util.zip.ZipInputStream", "java.util.zip.ZipEntry", "java.util.zip.CRC32", "java.util.zip.Adler32", "java.util.zip.Checksum",
            "java.io.InputStream", "java.io.OutputStream", "java.io.ByteArrayInputStream", "java.io.ByteArrayOutputStream",
            "java.io.DataInputStream", "java.io.BufferedInputStream", "java.io.FilterInputStream", "java.io.BufferedOutputStream",
            "java.io.FilterOutputStream", "java.io.Closeable", "java.lang.AutoCloseable", "java.io.Flushable", "java.io.DataInput",
            "java.nio.ByteBuffer", "java.nio.Buffer", "java.nio.ByteOrder", "java.nio.charset.Charset", "java.nio.charset.StandardCharsets",
            "javax.crypto.Cipher", "javax.crypto.spec.SecretKeySpec", "javax.crypto.spec.IvParameterSpec", "javax.crypto.spec.GCMParameterSpec",
            "javax.crypto.spec.PBEKeySpec", "javax.crypto.SecretKeyFactory", "javax.crypto.SecretKey", "javax.crypto.Mac",
            "java.security.Key", "java.security.MessageDigest", "java.security.spec.AlgorithmParameterSpec", "java.security.spec.KeySpec",
            "java.util.Base64", "java.util.Base64\$Decoder", "java.util.Base64\$Encoder",
        )

        /** حتى من القائمة البيضاء: لا نرجع أبداً كائنات تفتح باب reflection أو تحميل الكود أو الخيوط. */
        private val BLOCKED_RET = listOf(Class::class.java, ClassLoader::class.java, java.lang.reflect.Member::class.java,
            Thread::class.java, java.lang.reflect.AnnotatedElement::class.java)

        fun javaName(desc: String): String? =
            if (desc.startsWith("L") && desc.endsWith(";")) desc.substring(1, desc.length - 1).replace('/', '.') else null

        fun descOf(dotted: String): String = when {
            dotted.isEmpty() -> "Ljava/lang/Object;"
            dotted.startsWith("[") -> dotted.replace('.', '/')
            else -> "L" + dotted.replace('.', '/') + ";"
        }
    }
}

/** يربط محاكي ARM64 بمحاكي Dalvik: JNI ← → Java داخل نفس الصندوق. */
class NativeBridge(val rt: NativeRuntime, private val jrt: EmuRuntime, private val emu: DalvikEmulator) : JavaBridge {
    override fun call(cls: String, name: String, params: List<String>, ret: String, recv: Any?, args: List<Any?>, isStatic: Boolean): Any? {
        jrt.checkTime()
        return if (isStatic) emu.dispatch(cls, name, params, ret, args, virtual = false)
        else emu.dispatch(cls, name, params, ret, listOf(recv) + args, virtual = true)
    }

    override fun getStatic(cls: String, name: String, type: String): Any? = emu.staticByName(cls, name, type)

    override fun getField(obj: Any?, cls: String, name: String, type: String): Any? {
        val o = emu.deref(obj)
        return if (o is EObj) o.fields[name] ?: DalvikEmulator.defaultOf(type) else jrt.getField(o ?: return null, cls, name, type)
    }

    override fun setField(obj: Any?, cls: String, name: String, value: Any?) {
        val o = emu.deref(obj)
        if (o is EObj) o.fields[name] = value else if (o == null) emu.putStaticByName(cls, name, value)
    }

    override fun newObject(cls: String, params: List<String>, args: List<Any?>): Any? {
        if (emu.isApp(cls)) {
            val o = EObj(cls)
            emu.dispatch(cls, "<init>", params, "V", listOf(o) + args, virtual = false)
            return o
        }
        return jrt.call(cls, "<init>", params, "V", null, args, emu)
    }

    override fun isApp(cls: String) = emu.isApp(cls)

    override fun inspect(bytes: ByteArray, source: String) = jrt.inspectBytes(bytes, source)

    /** Java يستدعي وظيفة native. */
    fun callFromJava(m: AppMethod, args: List<Any?>): Any? {
        val sig = "(" + m.params.joinToString("") + ")" + m.ret
        val fn = rt.findNative(m.cls, m.name, sig) ?: throw EmuUnsupported("native ${m.cls}->${m.name} (لم نجد الدالة)")
        val recv = if (m.isStatic) null else args.getOrNull(0)
        val a = if (m.isStatic) args else args.drop(1)
        return rt.callJava(fn, m.isStatic, recv, m.cls, m.params, m.ret, a)
    }
}
