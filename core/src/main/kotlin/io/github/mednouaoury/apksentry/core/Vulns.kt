package io.github.mednouaoury.apksentry.core

/** ثغرة تجعل التطبيق نفسه غير آمن. [severity]: 3 عالية، 2 متوسطة، 1 منخفضة. */
class Vuln(val severity: Int, val title: String, val where: String = "")

/** سر مكتوب داخل التطبيق (مفتاح، توكن...). */
class Secret(val kind: String, val masked: String, val suspicious: Boolean, val severity: Int)

/**
 * فحص أمني للتطبيق (مثل ما تفعله أدوات تدقيق الأمان):
 * SSL مكسور، WebView خطير، تشفير ضعيف، مكوّنات مفتوحة، إعدادات الشبكة، وأسرار مكتوبة في الكود.
 */
class VulnScanner(
    private val dexes: List<DexFile>,
    private val manifest: XmlElement?,
    private val zip: ZipArchive,
    private val checkCancel: () -> Unit,
) {
    val vulns = ArrayList<Vuln>()
    val secrets = ArrayList<Secret>()
    private val seen = HashSet<String>()

    private fun add(sev: Int, title: String, where: String = "") {
        if (seen.add("$title|$where")) vulns.add(Vuln(sev, title, where))
    }

    private fun isLibrary(cls: String) = Rules.KNOWN_PREFIXES.any { cls.startsWith(it) }

    fun run() {
        for (dex in dexes) code(dex)
        manifestChecks()
        networkConfig()
        secretsScan()
    }

    // ---------------- الكود ----------------
    private fun code(dex: DexFile) {
        val seenCode = HashSet<Int>()
        for (c in 0 until dex.classCount) {
            if (c % 256 == 0) checkCancel()
            val cls = dex.className(c)
            if (isLibrary(cls)) continue
            val where = TaintAnalyzer.readable("$cls->x").removeSuffix(".x()")
            dex.forEachMethod(c) { m, _, codeOff ->
                if (codeOff <= 0 || !seenCode.add(codeOff)) return@forEachMethod
                val name = dex.methodName(m)
                val proto = dex.methodProto(m)
                val code = DexDecoder.decode(dex, codeOff) ?: return@forEachMethod
                val real = code.insns.filter { it.op != Op.NOP }
                when {
                    name == "checkServerTrusted" && proto == "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V" &&
                        real.all { it.op == Op.RETURN_VOID } ->
                        add(3, "يقبل أي شهادة SSL (TrustManager فارغ): أي شخص على نفس الشبكة يستطيع قراءة اتصالاته وتغييرها", where)
                    name == "verify" && proto == "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z" &&
                        real.size == 2 && real[0].op == Op.CONST && real[0].lit == 1L && real[1].op == Op.RETURN ->
                        add(3, "يقبل أي اسم خادم (HostnameVerifier يرجع true دائماً)", where)
                    name == "onReceivedSslError" && real.any { it.op == Op.INVOKE && it.idx >= 0 && dex.methodFull(it.idx).endsWith("SslErrorHandler;->proceed") } ->
                        add(3, "WebView يتجاهل أخطاء شهادة SSL ويكمل الاتصال", where)
                }
                linear(dex, code, where)
            }
        }
    }

    /** تتبّع بسيط داخل الوظيفة للنصوص الثابتة (لكشف التشفير الضعيف والمفاتيح المكتوبة). */
    private fun linear(dex: DexFile, code: MethodCode, where: String) {
        val constStr = HashMap<Int, String>()
        val constBytes = HashSet<Int>()
        var lastResultBytes = false
        for (x in code.insns) {
            when (x.op) {
                Op.CONST_STRING -> { constStr[x.dst] = dex.string(x.idx); constBytes.remove(x.dst); continue }
                Op.MOVE_RESULT -> {
                    if (lastResultBytes) constBytes.add(x.dst) else constBytes.remove(x.dst)
                    constStr.remove(x.dst)
                    continue
                }
                Op.FILL_ARRAY -> { x.srcs.firstOrNull()?.let { constBytes.add(it) }; continue }
                Op.INVOKE -> if (x.idx >= 0) {
                    val api = dex.methodFull(x.idx)
                    val args = x.srcs
                    lastResultBytes = false
                    when (api) {
                        "Ljavax/crypto/Cipher;->getInstance" -> args.firstOrNull()?.let { constStr[it] }?.let { t ->
                            val u = t.uppercase()
                            when {
                                "/ECB" in u || u == "AES" || u == "DES" -> add(2, "تشفير بنمط ضعيف ($t): البيانات المتشابهة تبقى متشابهة بعد التشفير", where)
                                u.startsWith("DES") || u.startsWith("RC4") || u.startsWith("ARCFOUR") || u.startsWith("BLOWFISH") ->
                                    add(2, "خوارزمية تشفير قديمة ومكسورة ($t)", where)
                            }
                        }
                        "Ljava/lang/String;->getBytes" -> lastResultBytes = args.firstOrNull()?.let { it in constStr } == true
                        "Ljavax/crypto/spec/SecretKeySpec;-><init>" ->
                            if (args.size > 1 && args[1] in constBytes) add(2, "مفتاح تشفير مكتوب داخل الكود (أي شخص يستطيع استخراجه)", where)
                        "Ljavax/crypto/spec/IvParameterSpec;-><init>" ->
                            if (args.size > 1 && args[1] in constBytes) add(1, "متجه تهيئة (IV) ثابت في التشفير", where)
                        "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs",
                        "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs" ->
                            add(2, "WebView يسمح لملفات محلية بالوصول لكل شيء (خطر سرقة ملفات التطبيق)", where)
                        "Landroid/webkit/WebView;->addJavascriptInterface" ->
                            add(1, "WebView يفتح جسراً بين JavaScript والتطبيق (خطير إذا عرض صفحات غير موثوقة)", where)
                    }
                }
                else -> {}
            }
            if (x.op != Op.INVOKE) lastResultBytes = false
            if (x.dst >= 0) { constStr.remove(x.dst); constBytes.remove(x.dst) }
        }
    }

    // ---------------- الملف التعريفي ----------------
    private fun manifestChecks() {
        val m = manifest ?: return
        val app = m.walk().firstOrNull { it.tag == "application" }
        if (app?.attr("usesCleartextTraffic") == "true") add(2, "يسمح باتصالات HTTP غير مشفّرة (يمكن التجسس عليها)")
        if (app?.attr("debuggable") == "true") add(3, "وضع التصحيح مفعّل: أي شخص عنده الهاتف يستطيع قراءة بيانات التطبيق")
        if (app?.attr("allowBackup") == "true") add(1, "يسمح بنسخ بياناته احتياطياً عبر adb")
        val pkg = m.attr("package") ?: ""
        for (p in m.walk().filter { it.tag == "provider" }) {
            val exported = p.attr("exported") == "true"
            val protected = p.attr("permission") != null || p.attr("readPermission") != null
            val name = p.attr("name") ?: continue
            if (exported && !protected && !isLibrary("L" + name.replace('.', '/') + ";"))
                add(2, "مزوّد بيانات (ContentProvider) مفتوح لأي تطبيق بدون صلاحية", if (name.startsWith(".")) pkg + name else name)
        }
    }

    /** ملف network_security_config: الثقة بشهادات المستخدم أو السماح بـ HTTP. */
    private fun networkConfig() {
        for (e in zip.entries) {
            if (!e.name.startsWith("res/xml") || !e.name.endsWith(".xml") || e.size > 512 * 1024) continue
            val root = try { Axml.parse(zip.readBytes(e, 1024 * 1024)) } catch (ex: Exception) { null } ?: continue
            if (root.tag != "network-security-config") continue
            for (el in root.walk()) {
                if ((el.tag == "base-config" || el.tag == "domain-config") && el.attr("cleartextTrafficPermitted") == "true")
                    add(2, "إعدادات الشبكة تسمح بـ HTTP غير المشفّر", e.name)
                if (el.tag == "certificates" && el.attr("src") == "user" && generateSequence(el.parent) { it.parent }.none { it.tag == "debug-overrides" })
                    add(2, "يثق بشهادات يضيفها المستخدم (يسهل التجسس على اتصالاته بشهادة مزيّفة)", e.name)
            }
        }
    }

    // ---------------- الأسرار ----------------
    private class Pattern(val kind: String, val rx: Regex, val severity: Int, val suspicious: Boolean = false)

    private val patterns = listOf(
        Pattern("مفتاح خاص (private key)", Regex("-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), 3),
        Pattern("مفتاح AWS", Regex("\\b(AKIA|ASIA)[0-9A-Z]{16}\\b"), 3),
        Pattern("مفتاح Stripe السري", Regex("\\bsk_live_[0-9a-zA-Z]{24,}"), 3),
        Pattern("توكن GitHub", Regex("\\bgh[pousr]_[0-9A-Za-z]{36}\\b"), 3),
        Pattern("توكن Slack", Regex("\\bxox[baprs]-[0-9A-Za-z-]{10,}"), 3),
        Pattern("توكن بوت تيليغرام (تستعمله برامج التجسس لإرسال البيانات)", Regex("(?<![0-9])\\d{8,10}:AA[0-9A-Za-z_-]{33}(?![0-9A-Za-z_-])"), 2, suspicious = true),
        Pattern("Discord webhook (قناة لإرسال البيانات)", Regex("https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d+/[\\w-]+"), 2, suspicious = true),
        Pattern("JWT token", Regex("\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"), 2),
        Pattern("مفتاح Google API (عادي غالباً)", Regex("\\bAIza[0-9A-Za-z_-]{35}\\b"), 1),
    )

    private fun secretsScan() {
        val found = LinkedHashMap<String, Secret>()
        fun check(v: String) {
            if (v.length < 20 || v.length > 4096) return
            for (p in patterns) {
                val m = p.rx.find(v) ?: continue
                val s = m.value
                val masked = s.take(8) + "…" + s.takeLast(4).takeIf { s.length > 16 }.orEmpty()
                found.getOrPut(p.kind + s) { Secret(p.kind, masked, p.suspicious, p.severity) }
            }
        }
        for (dex in dexes) for (i in 0 until dex.stringCount) {
            if (i % 4096 == 0) checkCancel()
            check(dex.string(i))
        }
        // نصوص الموارد (strings.xml تُجمع في resources.arsc)
        zip.entry("resources.arsc")?.takeIf { it.size in 12..(64L * 1024 * 1024) }?.let { e ->
            try {
                val d = zip.readBytes(e)
                if (d.u16(0) == 0x0002 && d.size > 20 && d.u16(12) == 0x0001) Axml.readStringPool(d, 12).forEach(::check)
            } catch (ex: Exception) {
            }
        }
        secrets.addAll(found.values.take(30))
    }
}
