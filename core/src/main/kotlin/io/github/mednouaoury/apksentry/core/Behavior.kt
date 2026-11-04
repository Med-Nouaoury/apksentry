package io.github.mednouaoury.apksentry.core

/** كل ما عرفناه عن التطبيق، لتطبيق قواعد السلوك عليه. */
class Facts {
    val perms = HashSet<String>()
    val manifestValues = HashSet<String>()
    val apis = HashSet<String>()
    /** الوظائف التي يستدعيها كود التطبيق نفسه (بدون المكتبات المعروفة). */
    val appApis = HashSet<String>()
    /** كلاس يقرأ الحافظة ويكتب فيها ويحتوي عنوان محفظة رقمية = clipper. */
    var clipperClass: String? = null
    /** فيه ملف APK/DEX مخبّي ف الموارد. */
    var embeddedApk = false
    val keywordHits = HashSet<String>()
    val regexHits = HashSet<String>()
    val flows = ArrayList<Flow>()
    val nativeSymbols = HashSet<String>()
    val nativeKeywordHits = HashSet<String>()

    private val superOf = HashMap<String, String>()
    private val appRefs = HashSet<String>()

    /** يسجّل الوظائف والنصوص الموجودة في ملف dex. */
    fun addDex(dex: DexFile, checkCancel: () -> Unit) {
        for (c in 0 until dex.classCount) dex.superName(c)?.let { superOf[dex.className(c)] = it }
        for (c in 0 until dex.classCount) {
            if (c % 256 == 0) checkCancel()
            val cls = dex.className(c)
            if (Rules.KNOWN_PREFIXES.any { cls.startsWith(it) }) continue
            var getClip = false
            var setClip = false
            var wallet = false
            dex.scanClass(c,
                onInvoke = { m ->
                    val api = dex.methodFull(m)
                    appApis.add(api)
                    if (api == "Landroid/content/ClipboardManager;->getPrimaryClip") getClip = true
                    if (api == "Landroid/content/ClipboardManager;->setPrimaryClip") setClip = true
                },
                onString = { si ->
                    if (!wallet) {
                        val v = dex.string(si)
                        if (v.length in 25..100 && Behavior.REGEXES.any { it.second.matches(v) }) wallet = true
                    }
                })
            if (getClip && setClip && wallet && clipperClass == null) clipperClass = cls
        }
        for (m in 0 until dex.methodCount) {
            val full = dex.methodFull(m)
            apis.add(full)
            if (!full.startsWith("Landroid") && !full.startsWith("Ljava")) appRefs.add(full)
        }
        val kws = Behavior.KEYWORDS
        for (s in 0 until dex.stringCount) {
            if (s % 4096 == 0) checkCancel()
            val v = dex.string(s)
            if (v.length > 2000) continue
            val low = v.lowercase()
            for (k in kws) if (low.contains(k)) keywordHits.add(k)
            if (v.length in 25..100) for ((name, rx) in Behavior.REGEXES) if (rx.matches(v)) regexHits.add(name)
        }
    }

    /**
     * الكود يستدعي الوظائف الموروثة باسم كلاسه هو (مثلاً MyReceiver.abortBroadcast)،
     * فنصعد في شجرة الوراثة لنعرف الوظيفة الأصلية في النظام.
     */
    fun resolveInherited() {
        for (ref in appRefs) {
            var cls = ref.substringBefore("->")
            val name = ref.substringAfter("->")
            val fromApp = ref in appApis
            for (depth in 0 until 12) {
                val sup = superOf[cls] ?: break
                apis.add("$sup->$name")
                if (fromApp) appApis.add("$sup->$name")
                cls = sup
            }
        }
    }
}

/** قاعدة: مجموعة شروط يجب أن تتحقق كلها. */
class BehaviorRule(val title: String, val weight: Int, val conditions: List<(Facts) -> Boolean>, val kind: Kind = Kind.DANGER)

class Protector(val name: String, val libs: List<String>, val classes: List<String>, val weight: Int, val note: String)

/** قواعد كشف السلوك الخبيث المعروف (عائلات الفيروسات الشائعة في أندرويد). */
object Behavior {
    private fun perm(vararg p: String): (Facts) -> Boolean = { f -> p.any { it in f.perms } }
    /** الوظيفة مستعملة من كود التطبيق نفسه (وليس من مكتبة معروفة). */
    private fun api(vararg a: String): (Facts) -> Boolean = { f -> a.any { it in f.appApis } }
    private fun kw(vararg k: String): (Facts) -> Boolean = { f -> k.any { it in f.keywordHits || it in f.nativeKeywordHits } }
    private fun mf(vararg v: String): (Facts) -> Boolean = { f -> v.any { x -> f.manifestValues.any { it.contains(x) } } }
    private fun flow(srcs: Set<Src>, sinks: Set<Sink>): (Facts) -> Boolean =
        { f -> f.flows.any { fl -> fl.sink in sinks && fl.sources.any { it in srcs } } }
    private fun not(c: (Facts) -> Boolean): (Facts) -> Boolean = { f -> !c(f) }
    private fun any(vararg c: (Facts) -> Boolean): (Facts) -> Boolean = { f -> c.any { it(f) } }

    private val NET = setOf(Sink.NETWORK, Sink.SMS)
    private val accessibility = mf("BIND_ACCESSIBILITY_SERVICE")
    private val readSms = any(perm("RECEIVE_SMS", "READ_SMS"), api("Landroid/telephony/SmsMessage;->createFromPdu"))
    private val network = any(
        api("Ljava/net/URL;->openConnection", "Lokhttp3/OkHttpClient;->newCall", "Ljava/net/Socket;-><init>",
            "Lorg/apache/http/impl/client/DefaultHttpClient;-><init>", "Lcom/android/volley/RequestQueue;->add"),
    )
    private val dynLoad = api("Ldalvik/system/DexClassLoader;-><init>", "Ldalvik/system/InMemoryDexClassLoader;-><init>",
        "Ldalvik/system/DexFile;->loadDex")
    private val exec = api("Ljava/lang/Runtime;->exec", "Ljava/lang/ProcessBuilder;->start")

    val RULES: List<BehaviorRule> = listOf(
        BehaviorRule("صفات حصان طروادة بنكي: يتحكم بالشاشة، ويظهر فوق التطبيقات، ويقرأ الرسائل", 45,
            listOf(accessibility, perm("SYSTEM_ALERT_WINDOW"), readSms)),
        BehaviorRule("يسجّل ما يظهر على الشاشة أو ما تكتبه ويرسله (keylogger)", 45,
            listOf(flow(setOf(Src.SCREEN_TEXT), NET))),
        BehaviorRule("يتحكم بالهاتف عن بُعد عبر إمكانية الوصول (نقرات وإيماءات آلية)", 25,
            listOf(accessibility, api("Landroid/accessibilityservice/AccessibilityService;->dispatchGesture",
                "Landroid/accessibilityservice/AccessibilityService;->performGlobalAction"),
                api("Landroid/view/accessibility/AccessibilityNodeInfo;->performAction"), network)),
        BehaviorRule("يسرق الرسائل الواردة ويرسلها", 45,
            listOf(flow(setOf(Src.SMS_IN), NET))),
        BehaviorRule("يقرأ رسائلك SMS المحفوظة ويرسلها", 45,
            listOf(flow(setOf(Src.SMS_DB), NET))),
        BehaviorRule("يرسل جهات الاتصال أو سجل المكالمات (عادي ف تطبيقات المراسلة، مشبوه ف غيرها)", 10,
            listOf(flow(setOf(Src.CONTACTS_SMS), NET))),
        BehaviorRule("يخفي الرسائل الواردة عنك (مثل رموز التحقق OTP)", 35,
            listOf(mf("android.provider.Telephony.SMS_RECEIVED"), api("Landroid/content/BroadcastReceiver;->abortBroadcast"))),
        BehaviorRule("يرسل رسائل SMS حسب شركة الاتصالات (صفة احتيال الرسائل المدفوعة)", 30,
            listOf(perm("SEND_SMS"), api("Landroid/telephony/SmsManager;->sendTextMessage", "Landroid/telephony/SmsManager;->sendDataMessage"),
                api("Landroid/telephony/TelephonyManager;->getSimOperator", "Landroid/telephony/TelephonyManager;->getNetworkOperator",
                    "Landroid/telephony/TelephonyManager;->getSimCountryIso"))),
        BehaviorRule("يسرق كوكيز حسابات التواصل الاجتماعي (Facebook...) ويرسلها", 45,
            listOf(flow(setOf(Src.COOKIES), NET), kw("c_user", "datr="))),
        BehaviorRule("يرسل بيانات تسجيل الدخول ديال حساباتك (عادي ف تطبيقات المزامنة)", 10,
            listOf(flow(setOf(Src.ACCOUNTS, Src.COOKIES), NET))),
        BehaviorRule("يقرأ إشعاراتك ويرسلها", 40,
            listOf(mf("BIND_NOTIFICATION_LISTENER_SERVICE"), flow(setOf(Src.NOTIFICATIONS), NET))),
        BehaviorRule("يغيّر ما تنسخه (سرقة عناوين المحافظ الرقمية clipper)", 45,
            listOf({ f -> f.clipperClass != null })),
        BehaviorRule("يرسل الحافظة (ما تنسخه) إلى الخارج", 30,
            listOf(flow(setOf(Src.CLIPBOARD), NET))),
        BehaviorRule("يسجّل الصوت ويستطيع العمل في الخلفية", 10,
            listOf(perm("RECORD_AUDIO"), api("Landroid/media/MediaRecorder;->setAudioSource", "Landroid/media/AudioRecord;->startRecording"),
                any(mf("android.intent.action.BOOT_COMPLETED"), perm("FOREGROUND_SERVICE_MICROPHONE")), network)),
        BehaviorRule("يرسل صوت الميكروفون", 40, listOf(flow(setOf(Src.AUDIO), NET))),
        BehaviorRule("يرسل معرّفات هاتفك أو رقمك", 15, listOf(flow(setOf(Src.DEVICE_ID), NET))),
        BehaviorRule("يرسل موقعك", 10, listOf(flow(setOf(Src.LOCATION), NET))),
        BehaviorRule("يرسل قائمة تطبيقاتك", 10, listOf(flow(setOf(Src.APP_LIST), NET))),
        BehaviorRule("يستطيع تغيير كلمة سر قفل الهاتف (صفة برامج الفدية)", 40,
            listOf(mf("BIND_DEVICE_ADMIN"), api("Landroid/app/admin/DevicePolicyManager;->resetPassword",
                "Landroid/app/admin/DevicePolicyManager;->resetPasswordWithToken"))),
        BehaviorRule("يستطيع مسح كل بيانات الهاتف", 15,
            listOf(mf("BIND_DEVICE_ADMIN"), api("Landroid/app/admin/DevicePolicyManager;->wipeData"))),
        BehaviorRule("صفات برنامج فدية: يشفّر الملفات ويحتوي رسائل دفع", 45,
            listOf(api("Ljavax/crypto/Cipher;->doFinal"), api("Ljava/io/File;->listFiles"), api("Ljava/io/File;->delete"),
                kw("your files", "files have been encrypted", "ransom", "pay the", "bitcoin"), kw("your files", "files have been encrypted", "ransom"))),
        BehaviorRule("يحمّل كوداً من الإنترنت ويشغّله", 35,
            listOf(dynLoad, network, kw(".dex", ".jar", ".apk"))),
        BehaviorRule("ينزّل ويثبّت تطبيقات أخرى (dropper)", 20,
            listOf(perm("REQUEST_INSTALL_PACKAGES"), any(api("Landroid/content/pm/PackageInstaller;->createSession"),
                kw("application/vnd.android.package-archive")), network)),
        BehaviorRule("فيه تطبيق مخبّي داخلو وكيقدر يثبّتو (dropper)", 30,
            listOf(perm("REQUEST_INSTALL_PACKAGES"), { f -> f.embeddedApk })),
        BehaviorRule("ينفّذ أوامر shell ويتصل بالشبكة مباشرة (طبيعي في تطبيقات الطرفية، وخطير في غيرها)", 25,
            listOf(exec, api("Ljava/net/Socket;-><init>", "Ljava/net/ServerSocket;-><init>"), kw("/system/bin/sh"))),
        BehaviorRule("يخفي أيقونته ويشتغل تلقائياً (صفة برامج التجسس)", 20,
            listOf(api("Landroid/content/pm/PackageManager;->setComponentEnabledSetting"), mf("android.intent.action.BOOT_COMPLETED"),
                not(mf("android.intent.category.HOME")),
                any(mf("BIND_DEVICE_ADMIN"), mf("BIND_NOTIFICATION_LISTENER_SERVICE"), readSms))),
        BehaviorRule("يحوّل أو يراقب مكالماتك", 30,
            listOf(any(mf("android.intent.action.NEW_OUTGOING_CALL"), perm("PROCESS_OUTGOING_CALLS")),
                api("Landroid/content/BroadcastReceiver;->setResultData"))),
        BehaviorRule("قد يعرض شاشات مزيّفة لسرقة بيانات بطاقتك", 35,
            listOf(perm("SYSTEM_ALERT_WINDOW"), kw("cvv", "cvc"), kw("card number", "expiry", "exp date"), not(perm("NFC")),
                any(accessibility, readSms))),
        BehaviorRule("يتحقق إن كان يعمل تحت التحليل أو مع أدوات الحقن (anti-analysis)", 5,
            listOf({ f -> ANTI.count { it in f.keywordHits || it in f.nativeKeywordHits } >= 2 }), Kind.MOD),
    )

    /** كل الكلمات التي تحتاجها القواعد (بحروف صغيرة). */
    val KEYWORDS: List<String> = listOf(
        "c_user", "datr=", "bitcoin", "your files", "files have been encrypted", "ransom", "pay the", ".dex", ".jar", ".apk",
        "application/vnd.android.package-archive", "/system/bin/sh", "cvv", "cvc", "card number", "expiry", "exp date",
        "frida-server", "frida-gadget", "re.frida.server", "libfrida", "de.robv.android.xposed", "xposedbridge",
        "/proc/self/maps", "tracerpid", "libsubstrate",
    )

    private val ANTI = listOf("frida-server", "frida-gadget", "re.frida.server", "libfrida", "de.robv.android.xposed",
        "xposedbridge", "/proc/self/maps", "tracerpid", "libsubstrate")

    /** عناوين المحافظ الرقمية (لكشف الـ clipper). */
    val REGEXES = listOf(
        "bitcoin" to Regex("(bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})"),
        "ethereum" to Regex("0x[a-fA-F0-9]{40}"),
        "tron" to Regex("T[1-9A-HJ-NP-Za-km-z]{33}"),
    )

    /** أدوات الحماية والتشفير المعروفة (packers / protectors). */
    val PROTECTORS = listOf(
        Protector("Jiagu 360", listOf("libjiagu"), listOf("Lcom/qihoo/util/", "Lcom/stub/StubApp;"), 15, "يشفّر الكود الحقيقي ويفكّه وقت التشغيل"),
        Protector("Bangcle / SecNeo", listOf("libsecexe", "libsecmain", "libdexhelper"), listOf("Lcom/secneo/", "Lcom/secshell/"), 15, "يشفّر الكود الحقيقي"),
        Protector("Tencent Legu", listOf("libshella", "libshellx", "libtup"), listOf("Lcom/tencent/StubShell/"), 15, "يشفّر الكود الحقيقي"),
        Protector("Baidu Protect", listOf("libbaiduprotect"), listOf("Lcom/baidu/protect/"), 15, "يشفّر الكود الحقيقي"),
        Protector("Ijiami", listOf("libexecmain", "libijm"), listOf("Lcom/shell/SuperApplication;", "Ls/h/e/l/l/"), 15, "يشفّر الكود الحقيقي"),
        Protector("Alibaba MobiSec", listOf("libmobisec"), listOf("Lcom/ali/mobisecenhance/"), 15, "يشفّر الكود الحقيقي"),
        Protector("NetEase", listOf("libnesec"), listOf("Lcom/netease/nis/wrapper/"), 15, "يشفّر الكود الحقيقي"),
        Protector("DexProtector", listOf("libdexprotector"), listOf("Lcom/dexprotector/"), 10, "حماية تجارية تشفّر الكود والنصوص"),
        Protector("AppSealing", listOf("libcovault"), listOf("Lcom/inka/appsealing/"), 10, "حماية تجارية ضد التعديل"),
        Protector("Allatori", emptyList(), listOf("Lcom/allatori/"), 5, "تعمية الأسماء والنصوص"),
        Protector("Google Play (pairip)", listOf("libpairipcore"), listOf("Lcom/pairip/"), 0, "حماية Google Play الرسمية ضد النسخ (عادية)"),
    )

    /** إنتروبيا شانون (0 إلى 8): أكثر من 7.5 يعني بيانات مشفّرة أو مضغوطة. */
    fun entropy(b: ByteArray, len: Int = b.size): Double {
        if (len <= 0) return 0.0
        val c = IntArray(256)
        for (i in 0 until len) c[b[i].toInt() and 0xff]++
        var e = 0.0
        for (n in c) if (n > 0) { val p = n.toDouble() / len; e -= p * kotlin.math.ln(p) }
        return e / kotlin.math.ln(2.0)
    }
}
