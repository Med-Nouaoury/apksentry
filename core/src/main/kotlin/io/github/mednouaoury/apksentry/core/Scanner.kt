package io.github.mednouaoury.apksentry.core

import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.TreeMap
import java.util.TreeSet

/** شهادة رسمية معروفة لتطبيق، ومصدر معرفتنا بها. */
class OfficialCert(val sha256: String, val source: String)

class ScanOptions(
    /** مفتاح VirusTotal (اختياري). نرسل البصمات فقط، لا الملفات. */
    val virusTotalKey: String? = null,
    /** مفتاح MalwareBazaar من auth.abuse.ch (اختياري). */
    val malwareBazaarKey: String? = null,
    /** بصمة SHA-256 لشهادة المطور الرسمية (اختياري). */
    val expectedCert: String? = null,
    /** الشهادات الرسمية المعروفة لحزمة ما (من التطبيق المثبت أو من قائمة موثوقة). */
    val officialCerts: (packageName: String) -> List<OfficialCert> = { emptyList() },
    /** مجلد مؤقت لفك ملفات APK المضغوطة داخل الحزم. */
    val tempDir: File = File(System.getProperty("java.io.tmpdir")),
    /** تحليل تدفّق البيانات (أبطأ لكنه أعمق). */
    val dataFlow: Boolean = true,
)

fun interface ProgressListener {
    /** [fraction] بين 0 و 1، أو null إذا لم يكن معروفاً. */
    fun onProgress(message: String, fraction: Float?)
}

class ScanCancelledException : RuntimeException("تم إلغاء الفحص")

/** الفحص الكامل لملف APK أو APKS أو XAPK. */
class Scanner(
    private val opts: ScanOptions = ScanOptions(),
    private val progress: ProgressListener = ProgressListener { _, _ -> },
    private val isCancelled: () -> Boolean = { false },
) {
    companion object {
        const val VERSION = "3.1.0"
        private val DEX_RE = Regex("classes\\d*\\.dex")
        private val B64_RE = Regex("[A-Za-z0-9+/=]{80,}")
        private val PATH_RE = Regex("\\.so$|^lib\\w+$|/data/|/sdcard|/storage/|/system/|\\.dex$|\\.apk$|\\.jar$")
        private val SUBJ_UNOFFICIAL = Regex("\\btest(key)?\\b|apktool|mt ?manager|np ?manager|lucky", RegexOption.IGNORE_CASE)
        private val SUBJ_DEBUG = Regex("android debug", RegexOption.IGNORE_CASE)
        private val SUBJ_SITE = Regex("apk|\\bmod\\b|\\.(org|com|net|io|co)\\b", RegexOption.IGNORE_CASE)
        private val APP_CLASS_SUSPECT = Regex("signature|killer|hook|fake|patch", RegexOption.IGNORE_CASE)
        private val COMPONENT_TAGS = mapOf(
            "activity" to "activity", "activity-alias" to "activity",
            "service" to "service", "receiver" to "receiver", "provider" to "provider",
        )
        private const val MB = 1024L * 1024

        /** حزم أدوات التعديل المعروفة: تُعتبر كوداً مضافاً دائماً. */
        private val INJECT_NAMES = listOf("bin.mt", "np.dcc", "np.manager", "com.chelpus", "com.android.support.menu")

        /** علامات تدل أن التطبيق أُعيد تجميعه من طرف غير المطور. */
        private val REPACK_SIGNS = listOf("أُعيد توقيعه", "شهادة توقيع غير رسمية", "MT Manager", "NP Manager", "Lucky Patcher",
            "كلاس تشغيل يُستعمل لتجاوز", "التوقيع يختلف عن", "التوقيع لا يطابق", "مفتاح الاختبار العلني")

        fun origin(cls: String, own: List<String>): String {
            if (Rules.KNOWN_PREFIXES.any { cls.startsWith(it) } || own.any { cls.startsWith(it) }) return "known"
            val parts = packageParts(cls)
            if (parts.isEmpty() || parts.all { it.length <= 2 }) return "obf"
            return "unknown"
        }

        private fun packageParts(cls: String): List<String> {
            val inner = if (cls.length >= 2) cls.substring(1, cls.length - 1) else ""
            return inner.split('/').dropLast(1)
        }

        fun pkgOf(cls: String, depth: Int = 3): String =
            packageParts(cls).take(depth).joinToString(".").ifEmpty { "(بدون حزمة)" }

        fun shortApi(api: String): String {
            val cls = api.substringBefore("->").trim('L', ';').substringAfterLast('/')
            return cls + "." + api.substringAfter("->")
        }

        fun interesting(v: String): Boolean =
            ByteScanner.containsAnyUrl(v) || Rules.PRIVATE_URIS.containsMatchIn(v) ||
                PATH_RE.containsMatchIn(v) || B64_RE.matches(v)

        fun sizeText(bytes: Long): String = when {
            bytes >= 1024 * MB -> String.format(java.util.Locale.US, "%.2f جيجا", bytes / (1024.0 * MB))
            bytes >= MB -> String.format(java.util.Locale.US, "%.1f ميجا", bytes / MB.toDouble())
            else -> String.format(java.util.Locale.US, "%.1f كيلو", bytes / 1024.0)
        }

        /** شهادة الاختبار العلنية في AOSP: مفتاحها الخاص منشور، فأي شخص يستطيع التوقيع بها. */
        fun isAospTestKey(subject: String): Boolean =
            (subject.contains("android@android.com") || subject.contains("616e64726f696440616e64726f69642e636f6d")) &&
                subject.contains("O=Android") && subject.contains("Mountain View")
    }

    // ---------------- الحالة ----------------
    private val sections = ArrayList<Section>()
    private lateinit var sec: Section
    private val findings = LinkedHashMap<String, Finding>()
    private val notes = ArrayList<String>()
    private val bytes = ByteScanner()
    private val unknownStrings = HashSet<String>()
    /**
     * الحزم التي حقنها من عدّل التطبيق: أدوات تعديل معروفة، أو حزمة تحمل اسم من أعاد التوقيع (مثل apkvision).
     * باقي الحزم غير المعروفة غالباً مكتبات التطبيق الأصلي (مثل محرك Unreal)، فلا نحسبها خطراً.
     */
    private var injected: Set<String> = emptySet()
    private val injectedTokens = HashSet<String>()
    private val pendingComponents = ArrayList<String>()
    private val fingerprints = LinkedHashSet<String>()
    private val facts = Facts()
    private val behaviors = ArrayList<Finding>()
    private val protectorsFound = LinkedHashSet<String>()
    private val checkedHashes = HashSet<String>()
    private val vulns = ArrayList<Vuln>()
    private val secrets = ArrayList<Secret>()
    private var integrityVerified = 0
    private var integrityUnchecked = 0
    private var packageName: String? = null
    private var hidingTool = false
    private var addedNativeLib = false
    private var packedDex = false
    private var progressBase = 0f
    private var progressSpan = 1f
    private var progressBaseLocal = 0f
    private var progressSpanLocal = 0f
    private val vt: VirusTotal? = opts.virusTotalKey?.trim()?.takeIf { it.isNotEmpty() }?.let { VirusTotal(it, ::checkCancel) }
    private val mb: MalwareBazaar? = opts.malwareBazaarKey?.trim()?.takeIf { it.isNotEmpty() }?.let { MalwareBazaar(it) }
    private var vtDisabled = false
    private var mbDisabled = false
    private val intel get() = (vt != null && !vtDisabled) || (mb != null && !mbDisabled)

    private fun checkCancel() {
        if (isCancelled()) throw ScanCancelledException()
    }

    private fun out(text: String, tone: Tone = Tone.NORMAL, indent: Int = 0) {
        sec.lines.add(Line(text, tone, indent))
    }

    private fun flag(weight: Int, msg: String, kind: Kind = Kind.DANGER) {
        val old = findings[msg]?.weight ?: 0
        findings[msg] = Finding(maxOf(weight, old), msg, kind)
    }

    /**
     * كل مرحلة معزولة: إذا فشلت (ملف تالف أو مُعدّ لإسقاط أدوات الفحص) نسجّل ذلك ونكمل الباقي.
     */
    private inline fun phase(label: String, block: () -> Unit) {
        try {
            block()
        } catch (e: ScanCancelledException) {
            throw e
        } catch (e: OutOfMemoryError) {
            notes.add("$label: توقّف لأن الذاكرة لا تكفي")
            out("$label: توقّف لأن الذاكرة لا تكفي", Tone.WARN)
        } catch (e: Exception) {
            notes.add("$label: تعذّر إكماله (${e.javaClass.simpleName})")
            out("$label: تعذّر إكماله، الملف تالف أو مُعقّد عمداً", Tone.WARN)
            failedPhases++
        } catch (e: StackOverflowError) {
            notes.add("$label: تعذّر إكماله (بنية معقّدة جداً)")
            failedPhases++
        }
    }

    private var failedPhases = 0

    private fun report(msg: String, within: Float? = null) {
        progress.onProgress(msg, within?.let { progressBase + progressSpan * it.coerceIn(0f, 1f) } ?: progressBase)
    }

    // ---------------- نقطة البداية ----------------
    fun scan(src: ByteSource, fileName: String): ScanResult {
        val t0 = System.currentTimeMillis()
        sec = Section("الملف").also { sections.add(it) }
        out("الاسم: $fileName")
        out("الحجم: ${sizeText(src.size)}")
        report("قراءة الملف...", 0f)
        val outer = ZipArchive(src)
        if (intel) {
            progressSpan = 0f
            report("حساب بصمة الملف كاملاً...")
            val sha = sha256(src.openStream())
            out("البصمة SHA-256: $sha", Tone.MUTED)
            hashIntel(sha, "الملف كاملاً")
        }
        if (outer.entry("AndroidManifest.xml") != null) {
            out("النوع: APK عادي")
            progressBase = 0f; progressSpan = 1f
            phase("فحص $fileName") { checkApk(src, fileName, inBundle = false) }
        } else {
            val nested = outer.entries.filter { !it.isDirectory && it.name.lowercase().endsWith(".apk") }
                .sortedBy { rank(it.name) }
            if (nested.isEmpty()) throw IllegalArgumentException("هذا الملف ليس APK ولا حزمة APKS/XAPK")
            val type = when {
                outer.entry("manifest.json") != null -> "XAPK"
                outer.entry("info.json") != null || outer.entry("meta.sai_v2.json") != null -> "APKS"
                else -> "حزمة APK مقسّمة (APKS)"
            }
            out("النوع: $type، فيها ${nested.size} ملفات APK")
            nested.forEachIndexed { i, e ->
                checkCancel()
                progressBase = i.toFloat() / nested.size
                progressSpan = 1f / nested.size
                val label = e.name.substringAfterLast('/')
                phase("فحص $label") {
                    val stored = outer.sourceOf(e)
                    if (stored != null) {
                        checkApk(stored, label, inBundle = true)
                    } else {
                        val tmp = extract(outer, e, label)
                        if (tmp != null) {
                            try {
                                FileChannelSource.open(tmp).use { checkApk(it, label, inBundle = true) }
                            } finally {
                                tmp.delete()
                            }
                        }
                    }
                }
            }
        }
        progressBase = 1f; progressSpan = 0f
        report("كتابة النتيجة...")
        return finish(fileName, System.currentTimeMillis() - t0)
    }

    private fun rank(name: String): Int {
        val n = name.substringAfterLast('/').lowercase()
        return when {
            n == "base.apk" -> 0
            n.startsWith("split_") || n.startsWith("config.") -> 2
            else -> 1
        }
    }

    private fun extract(outer: ZipArchive, e: ZipEntryInfo, label: String): File? {
        val free = opts.tempDir.usableSpace
        if (free in 1 until e.size + 64 * MB) {
            notes.add("لم نفحص $label: لا توجد مساحة كافية لفكه (يحتاج ${sizeText(e.size)})")
            return null
        }
        val f = File.createTempFile("apksentry_", ".apk", opts.tempDir)
        try {
            outer.open(e).use { inp ->
                FileOutputStream(f).use { o ->
                    val buf = ByteArray(1 shl 20)
                    var done = 0L
                    while (true) {
                        checkCancel()
                        val r = inp.read(buf)
                        if (r < 0) break
                        o.write(buf, 0, r)
                        done += r
                        if (e.size > 0) report("فك $label...", done.toFloat() / e.size * 0.2f)
                    }
                }
            }
        } catch (t: Throwable) {
            f.delete()
            throw t
        }
        return f
    }

    // ---------------- فحص ملف APK واحد ----------------
    private fun checkApk(src: ByteSource, name: String, inBundle: Boolean) {
        sec = Section(name).also { sections.add(it) }
        report("فحص $name...", 0f)
        val zip = ZipArchive(src)
        try { Signing.read(zip).forEach { injectedTokens.addAll(DomainIntel.repackTokens(it.subject)) } } catch (_: Exception) { }
        val dexEntries = zip.entries.filter { DEX_RE.matches(it.name) }
        val libs = zip.entries.filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
        val manifest = zip.entry("AndroidManifest.xml")?.let {
            try { Axml.parse(zip.readBytes(it, 64 * MB)) } catch (e: Exception) { null }
        }
        if (manifest == null) {
            out("تعذّرت قراءة AndroidManifest.xml", Tone.WARN)
            flag(10, "$name: ملف AndroidManifest.xml تالف أو مُعقّد عمداً", Kind.MOD)
        }
        val isBase = manifest != null && manifest.attr("split") == null
        var own = emptyList<String>()
        if (isBase) {
            var pkg = ""
            phase("قراءة الصلاحيات") { pkg = checkManifest(manifest!!) }
            if (pkg.isNotEmpty()) {
                if (packageName == null) packageName = pkg
                own = listOf("L" + pkg.replace('.', '/') + "/", "L" + pkg.split('.').take(2).joinToString("/") + "/")
            }
            phase("قراءة المكوّنات") { checkComponents(manifest!!, pkg, own) }
        } else if (dexEntries.isNotEmpty()) {
            flag(15, "$name: ملف إضافي يحتوي كوداً (dex)، غير معتاد")
        }
        out("ملفات الكود: ${dexEntries.size} dex، ${libs.size} مكتبة so")
        phase("قراءة التوقيع") { checkSignature(zip) }
        phase("التحقق من سلامة التوقيع") { checkIntegrity(zip, name) }
        phase("البحث عن ملفات مخفية") { checkHidden(zip, name) }

        // ---- الكود ----
        val deep = if (isBase) Deep(own) else null
        val baseDexes = ArrayList<DexFile>()
        var dexBytes = 0L
        dexEntries.forEachIndexed { i, e ->
            checkCancel()
            report("قراءة ${e.name}...", 0.05f + 0.15f * i / dexEntries.size)
            phase("قراءة ${e.name}") {
                val data = zip.readBytes(e)
                dexBytes += data.size
                for (t in Rules.MOD_TOOLS) {
                    if (data.contains(t.signature)) {
                        flag(t.weight, t.desc, t.kind)
                        if (t.desc in Rules.HIDING_TOOLS) hidingTool = true
                    }
                }
                bytes.scan(data, data.size, "$name/${e.name}")
                if (intel) hashIntel(sha256(data), "$name/${e.name}")
                phase("تحليل ${e.name}") {
                    val dex = DexFile(data)
                    facts.addDex(dex, ::checkCancel)
                    if (deep != null) {
                        deep.add(dex)
                        baseDexes.add(dex)
                    }
                }
            }
        }
        if (deep != null) phase("التحليل المعمّق") { deep.report() }
        if (isBase && baseDexes.isNotEmpty() && opts.dataFlow) {
            report("تحليل تدفّق البيانات...", 0.25f)
            phase("تتبّع البيانات") { dataFlow(baseDexes, own) }
        }
        if (isBase && baseDexes.isNotEmpty()) phase("فحص الثغرات") { checkVulns(baseDexes, own, manifest, zip) }
        if (isBase) {
            phase("كشف أدوات الحماية") { checkProtectors(zip, deep, libs) }
            phase("كشف التشفير") { checkPacked(zip, dexBytes) }
        }

        // ---- المكتبات ----
        if (libs.isNotEmpty()) {
            out("")
            out("فحص المكتبات native من الداخل:", Tone.HEAD)
        }
        libs.forEachIndexed { i, e ->
            checkCancel()
            progressBaseLocal = 0.4f + 0.55f * i / libs.size
            progressSpanLocal = 0.55f / libs.size
            phase("تحليل ${e.name}") { checkLib(zip, e, name) }
        }
        if (intel && inBundle) {
            report("حساب بصمة $name...", 0.95f)
            phase("بصمة $name") { hashIntel(sha256(src.openStream()), name) }
        }
    }

    private fun checkManifest(m: XmlElement): String {
        val pkg = m.attr("package") ?: ""
        out("الحزمة: ${pkg.ifEmpty { "?" }}")
        val vName = m.attr("versionName")
        val vCode = m.attr("versionCode")
        if (vName != null || vCode != null) out("الإصدار: ${vName ?: "?"} (${vCode ?: "?"})")
        m.walk().firstOrNull { it.tag == "uses-sdk" }?.let {
            out("أندرويد: من ${it.attr("minSdkVersion") ?: "?"}، مستهدف ${it.attr("targetSdkVersion") ?: "?"}")
        }
        val perms = m.walk().filter { it.tag == "uses-permission" || it.tag == "uses-permission-sdk-23" }
            .mapNotNull { it.attr("name") }.toSortedSet()
        out("الصلاحيات (${perms.size}):", Tone.HEAD)
        var risky = 0
        for (p in perms) {
            val short = p.substringAfterLast('.')
            facts.perms.add(short)
            val desc = Rules.RISKY_PERMS[short]
            if (desc != null) risky++
            out("- $p" + (desc?.let { "  ⚠ $it" } ?: ""), if (desc != null) Tone.WARN else Tone.NORMAL, 1)
        }
        // الصلاحية قدرة وليست سلوكاً: وزنها صغير، والسلوك الفعلي تكشفه القواعد وتتبّع البيانات
        if (risky > 0) flag(minOf(12, risky * 3), "$risky صلاحيات حساسة")
        val allValues = m.walk().flatMap { it.attrs.values.asSequence() }.toList()
        facts.manifestValues.addAll(allValues)
        for ((b, desc) in Rules.DANGER_BINDS) if (allValues.any { it.contains(b) }) flag(15, "يطلب $desc")
        for ((act, wd) in Rules.AUTO_ACTIONS) if (allValues.any { it == act }) flag(wd.first, wd.second)
        val app = m.walk().firstOrNull { it.tag == "application" }
        app?.attr("name")?.let {
            out("كلاس التشغيل: $it")
            if (APP_CLASS_SUSPECT.containsMatchIn(it)) flag(25, "كلاس تشغيل يُستعمل لتجاوز فحص التوقيع: $it", Kind.MOD)
        }
        if (app?.attr("debuggable") == "true") flag(10, "التطبيق في وضع التصحيح (debuggable)", Kind.MOD)
        if (app?.attr("usesCleartextTraffic") == "true") notes.add("يسمح باتصالات إنترنت غير مشفّرة")
        return pkg
    }

    private fun checkComponents(m: XmlElement, pkg: String, own: List<String>) {
        val comps = m.walk().filter { it.tag in COMPONENT_TAGS }.toList()
        out("المكوّنات: ${comps.size}")
        var found = false
        for (c in comps) {
            val raw = c.attr("name") ?: continue
            val n = when {
                raw.startsWith(".") -> pkg + raw
                !raw.contains('.') -> "$pkg.$raw"
                else -> raw
            }
            if (origin("L" + n.replace('.', '/') + ";", own) != "unknown") continue
            found = true
            val kind = COMPONENT_TAGS.getValue(c.tag)
            val exported = c.attr("exported") == "true"
            out("مكوّن مضاف: $kind $n" + if (exported) " (مفتوح للتطبيقات الأخرى)" else "", Tone.WARN, 1)
            if (exported && (kind == "service" || kind == "receiver")) pendingComponents.add(n)
        }
        if (!found) out("كل المكوّنات من المطور أو مكتبات مشهورة ✔", Tone.OK, 1)
    }

    private fun checkSignature(zip: ZipArchive) {
        val certs = Signing.read(zip)
        if (certs.isEmpty()) {
            out("لا يوجد توقيع (لا يمكن تثبيته كما هو)", Tone.WARN)
            return
        }
        for ((fp, group) in certs.groupBy { it.sha256 }) {
            val c = group.first()
            val schemes = group.map { it.scheme }.distinct().joinToString("، ")
            if (fp in fingerprints) {
                out("الموقِّع: نفس شهادة الملفات السابقة ✔ ($schemes)", Tone.OK)
            } else {
                val (nb, na) = c.dates()
                out("الموقِّع: ${c.subject}")
                out("البصمة SHA-256: $fp", Tone.MUTED)
                out("صالحة من $nb إلى $na، المفتاح ${c.keyBits ?: "?"} بت، التوقيع: $schemes", Tone.MUTED)
            }
            fingerprints.add(fp)
            when {
                isAospTestKey(c.subject) ->
                    flag(25, "موقّع بمفتاح الاختبار العلني لـ AOSP (مفتاح منشور، أي شخص يستطيع التوقيع به)", Kind.MOD)
                SUBJ_UNOFFICIAL.containsMatchIn(c.subject) -> flag(20, "شهادة توقيع غير رسمية: ${c.subject}", Kind.MOD)
                SUBJ_DEBUG.containsMatchIn(c.subject) -> flag(10, "موقّع بشهادة debug (نسخة تجريبية وليست نسخة نشر)", Kind.MOD)
                SUBJ_SITE.containsMatchIn(c.subject) -> flag(10, "أُعيد توقيعه من موقع تحميل وليس من المطور: ${Regex("CN=([^,]+)").find(c.subject)?.groupValues?.get(1) ?: c.subject}", Kind.MOD)
            }
        }
    }

    private fun checkHidden(zip: ZipArchive, name: String) {
        for (e in zip.entries) {
            if (e.isDirectory || !(e.name.startsWith("assets/") || e.name.startsWith("res/raw/"))) continue
            checkCancel()
            val low = e.name.lowercase()
            if (low.endsWith(".apk") || low.endsWith(".jar") || low.endsWith(".dex")) {
                flag(20, "$name: تطبيق أو كود مدمج داخل الموارد: ${e.name}")
                continue
            }
            if (e.size < 4) continue
            val magic = try { zip.readHead(e, 4) } catch (ex: Exception) { continue }
            if (magic.size < 4) continue
            if (magic[0] == 'd'.code.toByte() && magic[1] == 'e'.code.toByte() && magic[2] == 'x'.code.toByte() && magic[3] == '\n'.code.toByte())
                flag(25, "$name: ملف كود مخفي باسم مموّه: ${e.name}")
            else if (magic[0] == 0x7f.toByte() && magic[1] == 'E'.code.toByte() && magic[2] == 'L'.code.toByte() && magic[3] == 'F'.code.toByte())
                flag(10, "$name: ملف تنفيذي داخل الموارد: ${e.name}")
        }
    }

    /** التحقق الحقيقي من التوقيع: هل تغيّر الملف بعد توقيعه؟ */
    private fun checkIntegrity(zip: ZipArchive, name: String) {
        report("التحقق من سلامة توقيع $name...", 0.02f)
        val r = ApkVerifier.verify(zip, ::checkCancel) { f -> report("التحقق من توقيع $name: ${(f * 100).toInt()}%", 0.02f + 0.03f * f) }
        when (r.status) {
            IntegrityStatus.VERIFIED -> {
                integrityVerified++
                out("✔ التوقيع سليم (${r.scheme}): الملف لم يتغيّر بعد توقيعه", Tone.OK)
            }
            IntegrityStatus.FAILED -> {
                out("✘ فشل التحقق من التوقيع ${r.scheme}: ${r.detail}", Tone.BAD)
                flag(50, "$name: ${r.detail}، الملف تالف أو عُدِّل بعد توقيعه")
            }
            IntegrityStatus.UNSUPPORTED -> {
                integrityUnchecked++
                out("لم نستطع التحقق من التوقيع (${r.detail.ifEmpty { "خوارزمية غير مدعومة" }})", Tone.MUTED)
            }
            IntegrityStatus.NO_V2 -> {
                integrityUnchecked++
                out("توقيع قديم v1 فقط: لم نتحقق من سلامته", Tone.MUTED)
            }
        }
    }

    /** الثغرات الأمنية والأسرار المكتوبة داخل التطبيق. */
    private fun checkVulns(dexes: List<DexFile>, @Suppress("UNUSED_PARAMETER") own: List<String>, manifest: XmlElement?, zip: ZipArchive) {
        report("فحص الثغرات والأسرار...", 0.33f)
        val v = VulnScanner(dexes, manifest, zip, ::checkCancel)
        v.run()
        vulns.addAll(v.vulns)
        secrets.addAll(v.secrets)
        out("")
        out("الثغرات الأمنية في التطبيق نفسه:", Tone.HEAD)
        if (v.vulns.isEmpty()) out("لم نجد ثغرات معروفة ✔", Tone.OK, 1)
        for (x in v.vulns.sortedByDescending { it.severity }) {
            val sev = when (x.severity) { 3 -> "عالية"; 2 -> "متوسطة"; else -> "منخفضة" }
            out("- [$sev] ${x.title}" + if (x.where.isNotEmpty()) " (${x.where})" else "",
                when (x.severity) { 3 -> Tone.BAD; 2 -> Tone.WARN; else -> Tone.MUTED }, 1)
        }
        if (v.secrets.isNotEmpty()) {
            out("")
            out("أسرار مكتوبة داخل التطبيق:", Tone.HEAD)
            for (sct in v.secrets) {
                out("- ${sct.kind}: ${sct.masked}", if (sct.suspicious) Tone.BAD else if (sct.severity >= 3) Tone.WARN else Tone.MUTED, 1)
                if (sct.suspicious) flag(15, "يحتوي ${sct.kind}")
            }
        }
    }

    /** أدوات الحماية والتشفير المعروفة. */
    private fun checkProtectors(zip: ZipArchive, deep: Deep?, libs: List<ZipEntryInfo>) {
        val libNames = libs.map { it.name.substringAfterLast('/').lowercase() }
        val hits = Behavior.PROTECTORS.filter { p ->
            p.libs.any { l -> libNames.any { it.startsWith(l) } } || (deep != null && p.classes.any { it in deep.protectorHits })
        }
        if (hits.isEmpty()) return
        out("")
        out("أدوات حماية أو تشفير:", Tone.HEAD)
        for (p in hits) {
            protectorsFound.add(p.name)
            out("- ${p.name}: ${p.note}", if (p.weight > 0) Tone.WARN else Tone.INFO, 1)
            if (p.weight > 0) flag(p.weight, "محمي بـ ${p.name}: ${p.note} (يصعّب الفحص)", Kind.MOD)
        }
    }

    /** كود صغير جداً + ملف كبير مشفّر في الموارد = الكود الحقيقي مخفي (packer). */
    private fun checkPacked(zip: ZipArchive, dexBytes: Long) {
        if (dexBytes > 400 * 1024) return
        for (e in zip.entries) {
            if (!e.name.startsWith("assets/") || e.size < 512 * 1024) continue
            checkCancel()
            val head = try { zip.readHead(e, 65536) } catch (ex: Exception) { continue }
            val ent = Behavior.entropy(head)
            if (ent > 7.6 && !e.name.lowercase().let { n -> listOf(".png", ".jpg", ".ogg", ".mp3", ".mp4", ".webp", ".zip", ".gz", ".pak", ".obb", ".bundle", ".unity3d", ".ttf", ".otf").any { n.endsWith(it) } }) {
                packedDex = true
                out("")
                out("الكود صغير جداً (${sizeText(dexBytes)}) مع ملف مشفّر كبير: ${e.name}", Tone.WARN)
                flag(15, "الكود الحقيقي غالباً مشفّر داخل ${e.name} ويُفك وقت التشغيل (packer)", Kind.MOD)
                return
            }
        }
    }

    // ---------------- التحليل المعمّق للكود ----------------
    private inner class Deep(private val own: List<String>) {
        val counts = HashMap<String, Int>()
        val counts2 = HashMap<String, Int>()
        val callers = Array(Rules.SENSITIVE_APIS.size) { HashSet<String>() }
        val beh = TreeMap<String, LinkedHashMap<String, TreeSet<String>>>()
        val strs = TreeMap<String, TreeSet<String>>()
        val protectorHits = HashSet<String>()
        private val protectorPrefixes = Behavior.PROTECTORS.flatMap { it.classes }
        private val catCache = HashMap<String, String?>()
        private val sensitiveClasses = Rules.SENSITIVE_APIS.map { it.cls }.toSet()

        fun add(dex: DexFile) {
            val sens = IntArray(dex.methodCount) { -1 }
            for (m in 0 until dex.methodCount) {
                val cls = dex.methodClass(m)
                if (cls !in sensitiveClasses) continue
                val nm = dex.methodName(m)
                sens[m] = Rules.SENSITIVE_APIS.indexOfFirst { it.cls == cls && nm in it.methods }
            }
            for (c in 0 until dex.classCount) {
                if (c % 256 == 0) checkCancel()
                val cname = dex.className(c)
                for (p in protectorPrefixes) if (cname.startsWith(p)) protectorHits.add(p)
                val unknown = origin(cname, own) == "unknown"
                if (unknown) {
                    counts.merge(pkgOf(cname), 1, Int::plus)
                    counts2.merge(pkgOf(cname, 2), 1, Int::plus)
                }
                val pkg2 = if (unknown) pkgOf(cname, 2) else ""
                dex.scanClass(c,
                    onInvoke = { m ->
                        if (m in sens.indices && sens[m] >= 0) callers[sens[m]].add(cname)
                        if (unknown) {
                            val api = dex.methodFull(m)
                            val cat = if (catCache.containsKey(api)) catCache[api]
                            else Rules.API_RULES.firstOrNull { it.first.containsMatchIn(api) }?.second.also { catCache[api] = it }
                            if (cat != null) beh.getOrPut(pkg2) { LinkedHashMap() }.getOrPut(cat) { TreeSet() }.add(api)
                        }
                    },
                    onString = { si ->
                        if (unknown) {
                            val v = dex.string(si)
                            strs.getOrPut(pkg2) { TreeSet() }.add(v)
                        }
                    })
            }
        }

        fun isInjected(pkg2: String) =
            INJECT_NAMES.any { pkg2 == it || pkg2.startsWith("$it.") || it.startsWith("$pkg2.") } ||
                injectedTokens.any { t -> pkg2.split('.').any { it == t } }

        fun report() {
            injected = counts2.keys.filter { isInjected(it) }.toSet()
            for (p in injected) strs[p]?.let { unknownStrings.addAll(it) }
            out("")
            out("تحليل معمّق للكود:", Tone.HEAD)
            if (counts.isNotEmpty()) {
                out("كود ليس من المطور ولا من مكتبات نعرفها:", Tone.WARN)
                counts.entries.sortedWith(compareByDescending<Map.Entry<String, Int>> { it.value }.thenBy { it.key })
                    .take(20).forEach {
                        val inj = pkgOf("L" + it.key.replace('.', '/') + "/X;", 2) in injected
                        out("- ${it.key} (${it.value} كلاس)" + if (inj) "  ← مضاف (أداة تعديل أو موقع التحميل)" else "  (غالباً مكتبة من التطبيق الأصلي)",
                            if (inj) Tone.WARN else Tone.MUTED, 1)
                    }
            } else {
                out("كل الكود من المطور أو مكتبات مشهورة أو مُعمّى ✔", Tone.OK)
            }

            out("")
            out("الوظائف الحساسة ومن يستدعيها:", Tone.HEAD)
            var any = false
            Rules.SENSITIVE_APIS.forEachIndexed { i, api ->
                if (callers[i].isEmpty()) return@forEachIndexed
                any = true
                val kinds = HashMap<String, TreeSet<String>>()
                for (c in callers[i]) kinds.getOrPut(origin(c, own)) { TreeSet() }.add(pkgOf(c))
                val all = TreeSet<String>().apply { kinds.values.forEach { addAll(it) } }
                val unk = callers[i].filter { origin(it, own) == "unknown" && pkgOf(it, 2) in injected }.map { pkgOf(it) }.toSortedSet()
                out("- ${api.desc}: من ${all.take(6).joinToString(", ")}", if (unk.isNotEmpty()) Tone.WARN else Tone.NORMAL, 1)
                if (unk.isNotEmpty()) flag(api.weight, "${api.desc} من كود مضاف: ${unk.take(5).joinToString(", ")}", Kind.ADDED)
                else if (kinds["obf"] != null) flag(maxOf(3, api.weight / 3), "${api.desc} من كود مُعمّى (لا يمكن معرفة مصدره)")
            }
            if (!any) out("لا شيء ✔", Tone.OK, 1)

            for (pkg in (beh.keys + strs.keys).toSortedSet()) {
                val inj = pkg in injected
                out("")
                out(if (inj) "سلوك الكود المضاف [$pkg]:" else "مكتبة غير معروفة [$pkg] (${counts2[pkg] ?: 0} كلاس):", Tone.HEAD)
                val cats = beh[pkg] ?: LinkedHashMap()
                if (cats.keys.none { Rules.CATS.getValue(it).weight > 0 }) out("لا يستدعي أي وظيفة خطيرة ✔", Tone.OK, 1)
                for ((cat, apis) in cats) {
                    val c = Rules.CATS.getValue(cat)
                    val tag = if (c.weight > 0) "⚠ " else "ℹ "
                    out(tag + c.desc + ": " + apis.map { shortApi(it) }.sorted().take(4).joinToString(", "),
                        if (c.weight > 0) Tone.BAD else Tone.INFO, 1)
                    if (c.weight > 0 && inj) flag(c.weight, "كود مضاف [$pkg]: ${c.desc}", Kind.ADDED)
                }
                val hits = (strs[pkg] ?: TreeSet()).filter { interesting(it) }
                if (hits.isNotEmpty()) {
                    out("نصوص مهمة يستعملها:", Tone.NORMAL, 1)
                    hits.take(15).forEach { out("\"${it.take(80)}\"", Tone.MUTED, 2) }
                }
                val unknownUrls = hits.filter { v ->
                    val b = v.toByteArray(Charsets.UTF_8)
                    ByteScanner().apply { scan(b, b.size, "") }.let { it.domains.isNotEmpty() || it.ips.isNotEmpty() }
                }
                if (!inj) continue
                if (unknownUrls.isNotEmpty())
                    flag(15, "كود مضاف [$pkg] يحتوي ${unknownUrls.size} رابط لمواقع غير مألوفة، مثل: ${unknownUrls.first().take(60)}", Kind.ADDED)
                for (v in hits) {
                    when {
                        Rules.PRIVATE_URIS.containsMatchIn(v) -> flag(20, "كود مضاف [$pkg] يشير إلى رسائلك أو جهات اتصالك: ${v.take(60)}", Kind.ADDED)
                        B64_RE.matches(v) -> flag(5, "كود مضاف [$pkg] يحتوي نصاً مُرمّزاً طويلاً (قد يُخفي شيئاً)", Kind.ADDED)
                    }
                }
            }
        }
    }

    // ---------------- تدفّق البيانات ----------------
    private fun dataFlow(dexes: List<DexFile>, own: List<String>) {
        val r = TaintAnalyzer(dexes, own, ::checkCancel).run()
        out("")
        out("تدفّق بياناتك الشخصية:", Tone.HEAD)
        val shown = r.flows.filter { it.origin != "known" }
        if (shown.none { it.sink != Sink.LOG }) out("لم نجد مساراً من بياناتك إلى الإنترنت أو SMS ✔", Tone.OK, 1)
        for (f in shown.sortedByDescending { it.sink.weight }) {
            val inj = f.origin == "unknown" && f.where.split('.').take(2).joinToString(".") in injected
            val tag = when {
                inj -> " [كود مضاف]"
                f.origin == "unknown" -> " [مكتبة غير معروفة]"
                f.origin == "obf" -> " [كود مُعمّى]"
                else -> ""
            }
            val tone = when {
                f.sink == Sink.LOG -> Tone.MUTED
                inj -> Tone.BAD
                else -> Tone.WARN
            }
            out("- ${f.sources.joinToString("، ") { it.label }} تصل إلى ${f.sink.label}، في ${f.where}$tag", tone, 1)
            if (f.sink != Sink.LOG) {
                facts.flows.add(f)
                if (inj) flag(15, "كود مضاف (ليس من المطور) يرسل ${f.sources.joinToString("، ") { it.label }} إلى ${f.sink.label}", Kind.ADDED)
            }
        }
        out("حلّلنا ${r.analyzedMethods} وظيفة تلمس بياناتك من أصل ${r.totalMethods}", Tone.MUTED, 1)
        if (r.truncated) notes.add("التطبيق ضخم: حلّلنا تدفّق البيانات لجزء من الوظائف فقط")
        if (r.decryptors.isNotEmpty()) {
            out("")
            out("نصوص مشفّرة تُفك وقت التشغيل:", Tone.HEAD)
            for (d in r.decryptors.take(5)) {
                val unknown = d.origin == "unknown" && d.method.split('.').take(2).joinToString(".") in injected
                out("- ${d.method}: ${d.calls} نص", if (unknown) Tone.BAD else Tone.WARN, 1)
                if (unknown) flag(10, "كود مضاف يُخفي نصوصه ويفكّها وقت التشغيل (${d.method})", Kind.ADDED)
                else flag(5, "النصوص مشفّرة داخل الكود (تعمية تُصعّب الفحص)", Kind.MOD)
            }
        }
    }

    // ---------------- المكتبات native ----------------
    private fun checkLib(zip: ZipArchive, e: ZipEntryInfo, name: String) {
        val low = e.name.substringAfterLast('/').lowercase()
        val label = "$name/${e.name}"
        for ((k, wd) in Rules.LIB_MARKERS) if (low.contains(k)) flag(wd.first, "$name: مكتبة ${wd.second} ($low)")
        val stem = if (low.startsWith("lib")) low.substring(3, maxOf(3, low.length - 3)) else low.dropLast(3)
        val added = stem in unknownStrings || low in unknownStrings
        if (added) addedNativeLib = true
        val known = Rules.KNOWN_LIBS.any { low.startsWith(it) }

        val hdr = Elf.header(zip.readHead(e, 64))
        val segs = if (hdr != null && hdr.phnum in 1..256 && hdr.phTableEnd in 1..(1 * MB) && hdr.phTableEnd <= e.size)
            Elf.segments(zip.readHead(e, hdr.phTableEnd.toInt()), hdr) else emptyList()
        val sys = hdr?.let { h -> SyscallScanner(h.machine, segs.filter { it.exec && it.size > 0 }.map { it.offset until it.offset + it.size }) }
            ?.takeIf { it.supported }
        val shCap = hdr?.takeIf { it.shoff > 0 && it.shnum > 0 && it.tableSize in 1..(16 * MB) && it.shoff + it.tableSize <= e.size }
            ?.let { Capture(it.shoff, it.tableSize.toInt()) }
        val digest = if (intel) MessageDigest.getInstance("SHA-256") else null
        val tail = ByteArray(512)
        var tailLen = 0
        var lastReport = 0L
        streamPass(zip.open(e), listOfNotNull(shCap), ::checkCancel) { buf, len, pos ->
            digest?.update(buf, 0, len)
            sys?.feed(buf, len, pos)
            val joined = ByteArray(tailLen + len)
            System.arraycopy(tail, 0, joined, 0, tailLen)
            System.arraycopy(buf, 0, joined, tailLen, len)
            bytes.scan(joined, joined.size, label)
            tailLen = minOf(512, joined.size)
            System.arraycopy(joined, joined.size - tailLen, tail, 0, tailLen)
            if (e.size > 0 && pos - lastReport >= 32 * MB) {
                lastReport = pos
                val f = pos.toFloat() / e.size
                progress.onProgress("فحص $low: ${(f * 100).toInt()}%", progressBase + progressSpan * (progressBaseLocal + progressSpanLocal * f))
            }
        }

        var caps = emptyList<String>()
        var symbols: Elf.Symbols? = null
        var kwHits = emptySet<String>()
        var textEntropy = 0.0
        var desc: String
        var tone = Tone.OK
        if (hdr == null) {
            desc = "ليست مكتبة ELF عادية (قد تكون مشفّرة)"
            tone = Tone.WARN
            flag(5, "المكتبة $low ليست بصيغة ELF عادية (قد تكون مشفّرة)", Kind.MOD)
        } else {
            val secs = shCap?.takeIf { it.done }?.let { Elf.sections(it.data, hdr) } ?: emptyList()
            val tables = Elf.dynamicTables(secs)
            val roCaps = Elf.readOnlyData(secs, 32 * MB).filter { it.offset + it.size <= e.size }.map { Capture(it.offset, it.size.toInt()) }
            val symCap = tables?.let { Capture(it.first.offset, it.first.size.toInt()) }
            val strCap = tables?.let { Capture(it.second.offset, it.second.size.toInt()) }
            val text = secs.filter { it.type == 1L && it.flags and 4L != 0L && it.size > 4096 && it.offset + it.size <= e.size }.maxByOrNull { it.size }
            val textCap = text?.let { Capture(it.offset, minOf(it.size, 1 * MB).toInt()) }
            val caps2 = listOfNotNull(symCap, strCap, textCap) + roCaps
            if (caps2.isNotEmpty()) streamPass(zip.open(e), caps2, ::checkCancel)
            if (symCap != null && strCap != null) symbols = Elf.symbols(symCap.data, strCap.data, hdr.is64)
            kwHits = roCaps.filter { it.done }.flatMap { NativeKeywords.scan(it.data) }.toSet()
            if (textCap != null && textCap.done) textEntropy = Behavior.entropy(textCap.data)
            if (symbols == null) {
                desc = "لا يوجد جدول وظائف ظاهر (قد تكون محمية)"
                tone = Tone.WARN
            } else {
                caps = Rules.NATIVE_CATS.filter { (_, v) -> v.first.any { it in symbols.imports } }.keys.toList()
                desc = caps.joinToString("، ") { Rules.NATIVE_CATS.getValue(it).second }.ifEmpty { "لا وظائف نظام حساسة ✔" }
                if (caps.isNotEmpty()) tone = Tone.NORMAL
            }
        }
        val note = if (added) "  ← يحمّلها الكود المضاف!" else if (known) "  (مكتبة معروفة)" else ""
        if (added) tone = Tone.WARN
        out("$low (${sizeText(e.size)}، ${hdr?.arch ?: "?"}): $desc$note", tone, 1)
        for (c in caps) {
            if (c != "exec" && c != "network") continue
            val what = Rules.NATIVE_CATS.getValue(c).second
            if (added) flag(15, "المكتبة $low (من الكود المضاف) تستطيع $what", Kind.ADDED)
            else if (!known) flag(5, "المكتبة $low تستطيع $what (عادي غالباً لمحرك لعبة)")
        }

        // وظائف JNI
        symbols?.let { s ->
            val jni = s.exports.count { it.startsWith("Java_") }
            val onLoad = "JNI_OnLoad" in s.exports
            if (jni > 0) out("يصدّر $jni وظيفة JNI للكود Java", Tone.MUTED, 2)
            if (onLoad && jni == 0) {
                out("يربط وظائفه بـ Java سراً عبر JNI_OnLoad (بدون أسماء ظاهرة)", if (added) Tone.WARN else Tone.MUTED, 2)
                if (added) flag(5, "المكتبة $low (من الكود المضاف) تُخفي أسماء وظائفها", Kind.ADDED)
            }
        }
        // استدعاءات النظام المباشرة
        if (sys != null && sys.total > 0) {
            val named = sys.found.entries.sortedByDescending { it.value }.joinToString("، ") { "${it.key}×${it.value}" }
            out("استدعاءات نظام مباشرة (بدون مكتبة النظام): ${sys.total}" + if (named.isNotEmpty()) " ($named)" else "",
                if (added) Tone.BAD else Tone.WARN, 2)
            for ((g, sv) in SyscallScanner.GROUPS) {
                if (sv.first.none { it in sys.found }) continue
                when {
                    added -> flag(20, "المكتبة $low (من الكود المضاف) تستعمل استدعاءات نظام مباشرة لـ ${sv.second}", Kind.ADDED)
                    known -> {}
                    g == "network" || g == "exec" -> flag(5, "المكتبة $low تستدعي النظام مباشرة لـ ${sv.second}")
                    else -> flag(5, "المكتبة $low تستعمل ${sv.second}", Kind.MOD)
                }
            }
        }
        if (textEntropy > 7.5) {
            out("الكود التنفيذي مشفّر أو مضغوط (إنتروبيا ${String.format(java.util.Locale.US, "%.2f", textEntropy)} من 8)", Tone.WARN, 2)
            flag(10, "المكتبة $low كودها مشفّر ويُفك وقت التشغيل", if (added) Kind.ADDED else Kind.MOD)
        }
        // كلمات مشبوهة
        if (kwHits.isNotEmpty()) {
            facts.nativeKeywordHits.addAll(kwHits.map { it.lowercase() })
            out("نصوص لافتة: " + kwHits.joinToString("، ") { NativeKeywords.LIST.getValue(it) }, Tone.MUTED, 2)
            if (added) for (k in kwHits) if (k in setOf("/system/bin/sh", "pm install", "chmod 777", "LD_PRELOAD", "/data/local/tmp"))
                flag(10, "المكتبة $low (من الكود المضاف): ${NativeKeywords.LIST.getValue(k)}", Kind.ADDED)
        }
        symbols?.imports?.let { facts.nativeSymbols.addAll(it) }
        if (digest != null) hashIntel(digest.digest().toHex(), label)
    }

    // ---------------- قواعد البيانات (VirusTotal و MalwareBazaar) ----------------
    private fun sha256(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data).toHex()

    private fun sha256(input: java.io.InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        input.use { s ->
            val buf = ByteArray(1 shl 20)
            while (true) {
                checkCancel()
                val r = s.read(buf)
                if (r < 0) break
                md.update(buf, 0, r)
            }
        }
        return md.digest().toHex()
    }

    private fun hashIntel(sha: String, label: String) {
        if (!checkedHashes.add(sha)) return
        mbCheck(sha, label)
        vtCheck(sha, label)
    }

    private fun mbCheck(sha: String, label: String) {
        val client = mb ?: return
        if (mbDisabled) return
        report("MalwareBazaar: $label")
        val res = try {
            client.lookup(sha)
        } catch (ex: Exception) {
            out("MalwareBazaar $label: خطأ (${ex.message})", Tone.WARN, 1)
            if (ex.message?.contains("مفتاح") == true) { mbDisabled = true; notes.add("أوقفنا MalwareBazaar: ${ex.message}") }
            return
        }
        if (res == null) {
            out("MalwareBazaar $label: ليس في قائمة الفيروسات ✔", Tone.OK, 1)
            return
        }
        val fam = res.signature ?: res.tags.firstOrNull() ?: "غير مسمّى"
        out("MalwareBazaar $label: فيروس معروف! العائلة: $fam" + if (res.tags.isNotEmpty()) " (${res.tags.take(5).joinToString(", ")})" else "", Tone.BAD, 1)
        flag(100, "MalwareBazaar: $label فيروس معروف من عائلة $fam")
    }

    private fun vtCheck(sha: String, label: String) {
        val client = vt ?: return
        if (vtDisabled) return
        report("VirusTotal: $label")
        val res = try {
            client.lookup(sha)
        } catch (ex: ScanCancelledException) {
            throw ex
        } catch (ex: Exception) {
            out("VirusTotal $label: خطأ (${ex.message})", Tone.WARN, 1)
            if (ex.message?.contains("مفتاح") == true) {
                vtDisabled = true
                notes.add("أوقفنا VirusTotal: ${ex.message}")
            }
            return
        }
        if (res == null) {
            out("VirusTotal $label: غير معروف لديهم", Tone.MUTED, 1)
            return
        }
        out("VirusTotal $label: ${res.bad} اكتشاف - https://www.virustotal.com/gui/file/$sha",
            if (res.bad == 0) Tone.OK else Tone.BAD, 1)
        res.detections.forEach { out("↳ $it", Tone.BAD, 2) }
        if (res.bad > 0) {
            val weak = res.detections.isNotEmpty() && res.detections.all { Rules.WEAK_DET.containsMatchIn(it) }
            if (res.bad <= 2 && weak)
                flag(5, "VirusTotal: اكتشاف ضعيف في $label (تصنيف عام/PUP، غالباً إنذار كاذب): ${res.detections.joinToString("; ")}")
            else
                flag(if (res.bad == 1) 10 else if (res.bad <= 3) 25 else 50,
                    "VirusTotal: ${res.bad} اكتشاف في $label: ${res.detections.take(5).joinToString("; ")}")
        }
    }

    // ---------------- النتيجة ----------------
    private fun finish(fileName: String, ms: Long): ScanResult {
        val first = sections.first()
        if (fingerprints.size > 1) flag(40, "ملفات الحزمة موقَّعة بشهادات مختلفة!")

        // التوقيع الرسمي
        opts.expectedCert?.lowercase()?.replace(Regex("[^0-9a-f]"), "")?.takeIf { it.isNotEmpty() }?.let { exp ->
            if (exp in fingerprints) first.lines.add(Line("✔ التوقيع يطابق البصمة التي أدخلتها للمطور", Tone.OK))
            else flag(30, "التوقيع لا يطابق البصمة التي أدخلتها للمطور", Kind.MOD)
        }
        val pkg = packageName
        if (pkg != null && fingerprints.isNotEmpty()) {
            val official = try { opts.officialCerts(pkg) } catch (e: Exception) { emptyList() }
            if (official.isNotEmpty()) {
                val match = official.firstOrNull { it.sha256.lowercase() in fingerprints }
                if (match != null) {
                    first.lines.add(Line("✔ موقّع بنفس شهادة ${match.source}: النسخة من المطور الحقيقي", Tone.OK))
                } else {
                    val src = official.first().source
                    first.lines.add(Line("✘ التوقيع يختلف عن ${src}: هذه النسخة ليست من المطور الرسمي", Tone.BAD))
                    flag(35, "التوقيع يختلف عن $src (النسخة ليست من المطور الرسمي)", Kind.MOD)
                }
            }
        }

        if (bytes.ips.isNotEmpty()) flag(10, "عناوين IP مكتوبة مباشرة في الكود: ${bytes.ips.take(10).joinToString(", ")}")
        for (w in bytes.minerHits) flag(40, "آثار برنامج تعدين عملات رقمية في $w")

        // قواعد السلوك
        facts.resolveInherited()
        for (r in Behavior.RULES) {
            if (r.conditions.all { it(facts) }) {
                val msg = "سلوك: ${r.title}"
                flag(r.weight, msg, r.kind)
                if (r.kind == Kind.DANGER) behaviors.add(Finding(r.weight, r.title, r.kind))
            }
        }
        if (integrityUnchecked > 0)
            notes.add("بعض الملفات بتوقيع قديم (v1) لم نتحقق من سلامته؛ الأندرويد يتحقق منه عند التثبيت")
        if (failedPhases > 0) {
            notes.add("$failedPhases مرحلة من الفحص لم تكتمل بسبب بيانات تالفة أو مُعقّدة عمداً")
            // البرامج الخبيثة تتعمّد أحياناً إفساد بنية الملف لإسقاط أدوات الفحص؛ لا نعطي حكماً مطمئناً في هذه الحالة
            flag(15, "تعذّر تحليل جزء من التطبيق (ملف تالف أو مُعدّ لإفشال أدوات الفحص)")
        }

        for (n in pendingComponents) {
            if (pkgOf("L" + n.replace('.', '/') + ";", 2) in injected) flag(5, "خدمة أو مستقبِل مفتوح من كود مضاف: $n", Kind.ADDED)
        }
        // الكود غير المعروف يُحسب خطراً فقط إذا ظهر أن التطبيق معدّل (وإلا فهو غالباً مكتبات خارجية عادية)
        val repack = findings.values.any { f -> f.kind == Kind.MOD && REPACK_SIGNS.any { f.message.contains(it) } }
        val added = findings.values.filter { it.kind == Kind.ADDED }
        for (f in added) findings[f.message] = Finding(f.weight, f.message, if (repack) Kind.DANGER else Kind.INFO)
        if (!repack && added.isNotEmpty())
            notes.add("فيه مكتبات خارجية غير معروفة لدينا، ولأن التطبيق لا يبدو معدّلاً لم نحسبها خطراً (التفاصيل في الأقسام)")

        val order = compareByDescending<Finding> { it.weight }.thenByDescending { it.message }
        val dangers = findings.values.filter { it.kind == Kind.DANGER }.sortedWith(order)
        val mods = findings.values.filter { it.kind == Kind.MOD }.sortedWith(order)
        val risk = minOf(100, dangers.sumOf { it.weight })
        val mod = minOf(100, mods.sumOf { it.weight })

        val advice = ArrayList<String>()
        if (hidingTool || addedNativeLib || packedDex || protectorsFound.any { it != "Google Play (pairip)" })
            advice.add("جزء من الكود مُخفى أو مشفّر، والفحص الثابت لا يرى ما يفعله وقت التشغيل (مثلاً الاتصال بموقع التحميل). راقب اتصالات التطبيق بـ PCAPdroid في أول تشغيل، وجرّبه بدون إنترنت.")
        if (mod >= 10)
            advice.add("التطبيق معدّل أو أُعيد توقيعه: لا تسجّل الدخول بحساب مهم داخله، ولا تعطه صلاحيات جديدة يطلبها.")
        if (behaviors.isNotEmpty())
            advice.add("وجدنا سلوكيات تشبه برامج خبيثة معروفة. لا تثبّته إلا إذا كنت تعرف المطور وتثق به.")
        else if (risk >= 30)
            advice.add("لا تثبّته قبل مراجعة علامات الخطر واحدة واحدة.")
        if (bytes.domains.isNotEmpty())
            advice.add("راجع المواقع غير المألوفة: إذا كان التطبيق لا يحتاج الإنترنت، امنعه منه بعد التثبيت.")
        if (vulns.any { it.severity >= 3 })
            advice.add("التطبيق فيه ثغرات أمنية عالية: لا تستعمله على شبكات Wi-Fi عامة، ولا تدخل فيه بيانات حساسة.")
        if (vt == null && mb == null)
            advice.add("لمقارنة الملف بقواعد بيانات الفيروسات المعروفة، أضف مفتاح MalwareBazaar أو VirusTotal في الإعدادات.")

        return ScanResult(
            fileName = fileName,
            packageName = packageName,
            sections = sections,
            dangers = dangers,
            mods = mods,
            behaviors = behaviors.sortedByDescending { it.weight },
            signers = fingerprints.toList(),
            vulns = vulns.sortedByDescending { it.severity },
            secrets = secrets,
            integrityVerified = integrityVerified > 0 && findings.keys.none { it.contains("عُدِّل بعد توقيعه") },
            riskScore = risk,
            modScore = mod,
            unusualDomains = bytes.domains.toList(),
            notes = notes,
            advice = advice,
            durationMs = ms,
        )
    }
}
