package io.github.mednouaoury.apksentry.core

/** قواعد الفحص، منقولة من apk_check.py v4.1 مع بعض الإضافات. */
object Rules {
    val RISKY_PERMS = mapOf(
        "SEND_SMS" to "إرسال رسائل", "READ_SMS" to "قراءة الرسائل", "RECEIVE_SMS" to "استقبال الرسائل",
        "READ_CONTACTS" to "جهات الاتصال", "READ_CALL_LOG" to "سجل المكالمات", "CALL_PHONE" to "إجراء مكالمات",
        "RECORD_AUDIO" to "الميكروفون", "CAMERA" to "الكاميرا", "ACCESS_FINE_LOCATION" to "الموقع الدقيق",
        "REQUEST_INSTALL_PACKAGES" to "تثبيت تطبيقات أخرى", "SYSTEM_ALERT_WINDOW" to "الظهور فوق التطبيقات",
        "QUERY_ALL_PACKAGES" to "رؤية كل تطبيقاتك", "READ_PHONE_STATE" to "معلومات الهاتف",
        "GET_ACCOUNTS" to "حساباتك", "PACKAGE_USAGE_STATS" to "مراقبة استخدامك",
        "READ_MEDIA_IMAGES" to "صورك", "READ_MEDIA_VIDEO" to "فيديوهاتك", "MANAGE_EXTERNAL_STORAGE" to "كل ملفاتك",
    )

    val DANGER_BINDS = mapOf(
        "BIND_ACCESSIBILITY_SERVICE" to "إمكانية الوصول (تحكم كامل بالهاتف)",
        "BIND_DEVICE_ADMIN" to "صلاحية مدير الجهاز",
        "BIND_NOTIFICATION_LISTENER_SERVICE" to "قراءة إشعاراتك",
    )

    val AUTO_ACTIONS = mapOf(
        "android.intent.action.BOOT_COMPLETED" to (3 to "يشتغل تلقائياً عند تشغيل الهاتف"),
        "android.provider.Telephony.SMS_RECEIVED" to (25 to "يراقب الرسائل الواردة"),
        "android.intent.action.NEW_OUTGOING_CALL" to (20 to "يراقب المكالمات الصادرة"),
        "android.intent.action.PHONE_STATE" to (10 to "يراقب حالة المكالمات"),
        "android.intent.action.PACKAGE_ADDED" to (5 to "يراقب تثبيت التطبيقات"),
        "android.app.action.DEVICE_ADMIN_ENABLED" to (5 to "يحاول أن يصبح مدير الجهاز"),
    )

    class ModTool(val signature: ByteArray, val weight: Int, val kind: Kind, val desc: String)

    val MOD_TOOLS = listOf(
        ModTool("Lde/tu_darmstadt/seemoo/nfcgate/".toByteArray(), 45, Kind.DANGER,
            "يحتوي أداة NFCGate: تنقل بيانات بطاقتك البنكية عبر NFC إلى هاتف آخر (أسلوب فيروس NGate)"),
        ModTool("Lbin/mt/signature/".toByteArray(), 25, Kind.MOD, "MT Manager: تجاوز فحص التوقيع"),
        ModTool("Lbin/mt/".toByteArray(), 3, Kind.MOD, "MT Manager (أداة تعديل، مثل إضافة الوصول لملفات اللعبة)"),
        ModTool("Lnp/dcc/".toByteArray(), 8, Kind.MOD, "NP Manager: جزء من الكود مُخفى داخل مكتبة native"),
        ModTool("Lnp/manager/".toByteArray(), 8, Kind.MOD, "NP Manager (أداة تعديل)"),
        ModTool("Lcom/chelpus/".toByteArray(), 15, Kind.MOD, "Lucky Patcher"),
        ModTool("Lcom/android/support/Menu;".toByteArray(), 15, Kind.MOD, "قائمة غش مضافة (Mod Menu)"),
        ModTool("Lde/robv/android/xposed/".toByteArray(), 15, Kind.DANGER, "إطار Xposed للتلاعب بالتطبيق"),
        ModTool("Ltop/canyie/pine/".toByteArray(), 15, Kind.DANGER, "إطار Pine للتلاعب بالكود"),
        ModTool("Lcom/swift/sandhook/".toByteArray(), 15, Kind.DANGER, "إطار SandHook للتلاعب بالكود"),
        ModTool("/system/xbin/su".toByteArray(), 0, Kind.INFO, "يتحقق من وجود الروت (شائع في تطبيقات البنوك والحماية)"),
    )

    /** الأدوات التي تُخفي جزءاً من الكود: الفحص الثابت لا يرى سلوكه. */
    val HIDING_TOOLS = setOf("NP Manager: جزء من الكود مُخفى داخل مكتبة native")

    class SensitiveApi(val cls: String, val methods: Set<String>, val weight: Int, val desc: String)

    val SENSITIVE_APIS = listOf(
        SensitiveApi("Ljava/lang/Runtime;", setOf("exec"), 15, "تنفيذ أوامر في النظام"),
        SensitiveApi("Ljava/lang/ProcessBuilder;", setOf("start"), 15, "تشغيل عمليات في النظام"),
        SensitiveApi("Ldalvik/system/DexClassLoader;", setOf("<init>"), 10, "تحميل كود إضافي وقت التشغيل"),
        SensitiveApi("Ldalvik/system/InMemoryDexClassLoader;", setOf("<init>"), 15, "تحميل كود من الذاكرة"),
        SensitiveApi("Landroid/telephony/SmsManager;", setOf("sendTextMessage", "sendMultipartTextMessage"), 25, "إرسال رسائل SMS"),
        SensitiveApi("Landroid/telephony/TelephonyManager;", setOf("getDeviceId", "getImei", "getSubscriberId", "getLine1Number", "getSimSerialNumber"), 10, "قراءة معرّفات الهاتف أو رقمه"),
        SensitiveApi("Landroid/content/pm/PackageManager;", setOf("getInstalledPackages", "getInstalledApplications"), 5, "قراءة قائمة تطبيقاتك"),
        SensitiveApi("Landroid/content/ClipboardManager;", setOf("getPrimaryClip"), 10, "قراءة الحافظة (ما تنسخه)"),
        SensitiveApi("Landroid/accounts/AccountManager;", setOf("getAccounts", "getAccountsByType", "getAuthToken", "getPassword"), 10, "قراءة حساباتك"),
        SensitiveApi("Landroid/app/admin/DevicePolicyManager;", setOf("lockNow", "wipeData", "resetPassword"), 25, "قفل أو مسح الجهاز"),
        SensitiveApi("Landroid/content/pm/PackageInstaller;", setOf("createSession"), 15, "تثبيت تطبيقات أخرى"),
    )

    val API_RULES: List<Pair<Regex, String>> = listOf(
        "^Ljava/net/(URL;->open|HttpURLConnection;|URLConnection;->connect|Socket;|ServerSocket;|DatagramSocket;|InetAddress;->getBy)" to "network",
        "^Ljavax/net/ssl/(HttpsURLConnection;|SSLSocket)" to "network",
        "^Lokhttp3/(OkHttpClient;|Call;|RealCall;)" to "network",
        "^Landroid/webkit/WebView;->(loadUrl|postUrl|loadData)" to "network",
        "^Ljava/lang/Runtime;->exec|^Ljava/lang/ProcessBuilder;->start" to "exec",
        "^Ldalvik/system/(DexClassLoader|InMemoryDexClassLoader|DexFile);" to "dynload",
        "^Landroid/telephony/TelephonyManager;->(getDeviceId|getImei|getSubscriberId|getLine1Number|getSimSerialNumber)" to "private",
        "^Landroid/telephony/SmsManager;->send" to "private",
        "^Landroid/accounts/AccountManager;->get(Accounts|AuthToken|Password)" to "private",
        "^Landroid/content/ClipboardManager;->getPrimaryClip" to "private",
        "^Landroid/app/admin/DevicePolicyManager;->(lockNow|wipeData|resetPassword)" to "control",
        "^Landroid/accessibilityservice/AccessibilityService;->(performGlobalAction|dispatchGesture)" to "control",
        "^Ljava/lang/System;->(loadLibrary|load)$" to "native",
        "^Ljava/lang/reflect/|^Ljava/lang/Class;->(forName|getDeclared)" to "reflect",
        "^Ljavax/crypto/" to "crypto",
        "^Ljava/io/File|^Ljava/nio/file/" to "file",
        "^Landroid/content/pm/PackageManager;->getPackageInfo|^Landroid/content/pm/Signature;" to "signature",
    ).map { Regex(it.first) to it.second }

    class Cat(val weight: Int, val kind: Kind, val desc: String)

    /** الوزن 0 = معلومة فقط. */
    val CATS = mapOf(
        "network" to Cat(15, Kind.DANGER, "يفتح اتصالات إنترنت"),
        "exec" to Cat(15, Kind.DANGER, "ينفّذ أوامر نظام"),
        "dynload" to Cat(15, Kind.DANGER, "يحمّل كوداً إضافياً"),
        "private" to Cat(20, Kind.DANGER, "يصل لبيانات شخصية (معرّفات، حسابات، حافظة، SMS)"),
        "control" to Cat(25, Kind.DANGER, "يتحكم بالجهاز"),
        "native" to Cat(0, Kind.INFO, "يحمّل مكتبة native"),
        "reflect" to Cat(0, Kind.INFO, "يستدعي وظائف بشكل غير مباشر (reflection)"),
        "crypto" to Cat(0, Kind.INFO, "يستعمل التشفير"),
        "file" to Cat(0, Kind.INFO, "يقرأ أو يكتب ملفات"),
        "signature" to Cat(0, Kind.INFO, "يقرأ معلومات التطبيق أو توقيعه"),
    )

    val PRIVATE_URIS = Regex("content://(sms|mms|call_log|contacts|com\\.android\\.contacts)|ContactsContract", RegexOption.IGNORE_CASE)

    val KNOWN_PREFIXES = listOf(
        "Landroidx/", "Landroid/", "Lcom/google/", "Lkotlin/", "Lkotlinx/", "Lorg/jetbrains/",
        "Lorg/intellij/", "Ljava/", "Ljavax/", "Ldalvik/", "Lcom/android/", "Lcom/pairip/",
        "Lio/backtrace/", "Lbacktraceio/", "L_COROUTINE/", "Lokhttp3/", "Lokio/",
        "Lcom/squareup/", "Lorg/json/", "Lorg/apache/",
        // مكتبات مفتوحة المصدر شائعة جداً
        "Lorg/bouncycastle/", "Lorg/spongycastle/", "Lorg/conscrypt/", "Lorg/mozilla/", "Lorg/jsoup/", "Lio/reactivex/",
        "Lj\$/", "Lorg/acra/", "Lcom/bumptech/", "Lretrofit2/", "Lcom/fasterxml/", "Lcom/facebook/", "Lcom/airbnb/",
        "Lcoil/", "Lio/coil/", "Lcom/jakewharton/", "Lorg/greenrobot/", "Lio/realm/", "Lnet/sqlcipher/", "Lnet/zetetic/",
        "Lorg/chromium/", "Lorg/xmlpull/", "Lorg/w3c/", "Lorg/xml/", "Lorg/slf4j/", "Lch/qos/", "Ltimber/",
        "Lcom/microsoft/", "Lcom/amazonaws/", "Lcom/unity3d/", "Lcom/applovin/", "Lcom/ironsource/", "Lcom/vungle/",
        "Lcom/adjust/", "Lcom/appsflyer/", "Lcom/onesignal/", "Lio/sentry/", "Lcom/crashlytics/", "Lio/fabric/",
        "Lcom/mixpanel/", "Lcom/segment/", "Lcom/stripe/", "Lcom/paypal/", "Lcom/braintreepayments/", "Lio/flutter/",
        "Lorg/joda/", "Lorg/threeten/", "Lcom/caverock/", "Lcom/afollestad/", "Lorg/commonmark/", "Lio/noties/",
        "Lorg/checkerframework/", "Lcom/sun/", "Lsun/", "Ldagger/", "Ljavax/inject/", "Lorg/koin/", "Lio/ktor/",
        "Lorg/reactivestreams/", "Lio/grpc/", "Lio/opencensus/", "Lio/perfmark/", "Lcom/bytedance/", "Lcom/mbridge/",
        "Lcom/chartboost/", "Lcom/inmobi/", "Lcom/yandex/", "Lorg/tensorflow/", "Lcom/journeyapps/", "Lorg/webrtc/",
        "Lcom/github/", "Lorg/kxml2/", "Lorg/ccil/", "Lnet/i2p/", "Lorg/minidns/", "Lorg/jivesoftware/",
        "Lcom/nimbusds/", "Lnet/minidev/", "Lorg/yaml/", "Lcom/thoughtworks/", "Lorg/bitcoinj/", "Lcom/zaxxer/",
        "Lorg/osmdroid/", "Lcom/mapbox/", "Lorg/maplibre/", "Lio/requery/", "Landroid/support/", "Lcom/android/",
    )

    val LIB_MARKERS = mapOf(
        "frida-gadget" to (25 to "Frida (أداة حقن وتعديل)"), "libsubstrate" to (20 to "Substrate (أداة حقن)"),
        "libdobby" to (15 to "Dobby (أداة حقن، شائعة في قوائم الغش)"), "libpine" to (15 to "Pine (أداة حقن)"),
        "libsandhook" to (15 to "SandHook (أداة حقن)"), "libjiagu" to (10 to "تشفير Jiagu (يُخفي الكود)"),
        "libsecexe" to (10 to "تشفير Bangcle (يُخفي الكود)"), "libdexhelper" to (10 to "تشفير DexHelper (يُخفي الكود)"),
    )

    val KNOWN_LIBS = listOf(
        "libc++_shared", "libbacktrace", "libplaycore", "libpairipcore", "libvklayer",
        "libcrashpad", "libunity", "libil2cpp", "libmain", "libfirebase",
    )

    val NATIVE_CATS = linkedMapOf(
        "exec" to (setOf("execve", "execv", "execl", "execlp", "execvp", "system", "popen") to "تنفيذ أوامر"),
        "network" to (setOf("socket", "connect", "getaddrinfo", "gethostbyname", "SSL_connect") to "اتصال بالإنترنت"),
        "debug" to (setOf("ptrace") to "مراقبة عمليات (ptrace)"),
        "fork" to (setOf("fork") to "إنشاء عمليات"),
    )

    val MINER = listOf("stratum+tcp", "xmrig", "coinhive", "cryptonight").map { it.toByteArray() }

    val KNOWN_DOMAINS = listOf(
        "google.com", "googleapis.com", "gstatic.com", "android.com", "firebaseio.com",
        "firebase.com", "app.goo.gl", "goo.gl", "w3.org", "apache.org", "xml.org",
        "rockstargames.com", "take2games.com", "youtube.com", "facebook.com", "unity3d.com",
        "unity.com", "microsoft.com", "apple.com", "mozilla.org", "khronos.org", "llvm.org",
        "gnu.org", "openssl.org", "chromium.org", "vulkan.org", "backtrace.io",
        "app-measurement.com", "googlesource.com", "firebaseapp.com", "crashlytics.com", "flutter.dev", "dart.dev",
        "example.com", "example.org", "example.net", "unrealengine.com", "epicgames.com", "github.com", "githubusercontent.com",
    )

    val WEAK_DET = Regex("PUP|Adware|Riskware|HackTool|Generic|Heur|Unwanted|Malct", RegexOption.IGNORE_CASE)

    fun knownDomain(d: String) = KNOWN_DOMAINS.any { d == it || d.endsWith(".$it") }
}
