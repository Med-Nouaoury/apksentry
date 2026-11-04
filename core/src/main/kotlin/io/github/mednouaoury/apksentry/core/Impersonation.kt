package io.github.mednouaoury.apksentry.core

import java.text.Normalizer

/**
 * تطبيق مشهور تنتحله الفيروسات كثيراً.
 * @param keys أسماء التطبيق (تُطبَّع قبل المقارنة).
 * @param packages الحزم الرسمية المؤكدة.
 * @param vendors بدايات حزم الشركة نفسها (تطبيقاتها الأخرى). لا نعتبرها انتحالاً.
 * @param distinct اسم مميّز: نقبل الأخطاء الإملائية واحتواء الاسم. الأسماء العامة (Signal، Zoom) نقارنها حرفياً فقط.
 */
class FamousApp(
    val name: String,
    private val keys: List<String>,
    val packages: Set<String>,
    val vendors: List<String> = emptyList(),
    val distinct: Boolean = true,
) {
    val normKeys: List<String> by lazy { keys.map { Impersonation.skeleton(it) }.distinct() }
}

enum class ImpStrength { STRONG, WEAK }

class ImpersonationHit(val app: FamousApp, val label: String, val strength: ImpStrength, val reason: String)

object Impersonation {
    /** أسماء وحزم مؤكدة فقط: حزمة خاطئة هنا تعني إنذاراً كاذباً على التطبيق الحقيقي. */
    val APPS: List<FamousApp> = listOf(
        FamousApp("WhatsApp", listOf("WhatsApp", "واتساب", "واتس اب", "واتس آب"),
            setOf("com.whatsapp", "com.whatsapp.w4b"), listOf("com.whatsapp.w4b", "com.facebook.")),
        FamousApp("Facebook", listOf("Facebook", "فيسبوك", "فيس بوك"),
            setOf("com.facebook.katana", "com.facebook.lite"), listOf("com.facebook.")),
        FamousApp("Messenger", listOf("Messenger", "Facebook Messenger"),
            setOf("com.facebook.orca", "com.facebook.mlite"), listOf("com.facebook."), distinct = false),
        FamousApp("Instagram", listOf("Instagram", "انستغرام", "انستقرام", "انستجرام"),
            setOf("com.instagram.android", "com.instagram.lite"), listOf("com.instagram.", "com.facebook.")),
        FamousApp("Telegram", listOf("Telegram", "تيليجرام", "تلجرام", "تيليغرام", "تلغرام"),
            setOf("org.telegram.messenger", "org.telegram.messenger.web", "org.telegram.messenger.beta", "org.thunderdog.challegram"),
            listOf("org.telegram.")),
        FamousApp("TikTok", listOf("TikTok", "تيك توك"),
            setOf("com.zhiliaoapp.musically", "com.ss.android.ugc.trill", "com.zhiliaoapp.musically.go"),
            listOf("com.zhiliaoapp.", "com.ss.android.", "com.bytedance.")),
        FamousApp("Snapchat", listOf("Snapchat", "سناب شات"), setOf("com.snapchat.android"), listOf("com.snapchat.")),
        FamousApp("YouTube", listOf("YouTube", "يوتيوب"), setOf("com.google.android.youtube"), listOf("com.google.")),
        FamousApp("Gmail", listOf("Gmail"), setOf("com.google.android.gm"), listOf("com.google."), distinct = false),
        FamousApp("Google Play", listOf("Google Play", "Play Store", "Google Play Store", "متجر Play", "متجر بلاي"),
            setOf("com.android.vending"), listOf("com.google.", "com.android.vending")),
        FamousApp("Google Chrome", listOf("Chrome", "Google Chrome", "كروم"),
            setOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary"),
            listOf("com.google.", "com.android.chrome", "com.chrome.")),
        FamousApp("Google Maps", listOf("Google Maps"), setOf("com.google.android.apps.maps"), listOf("com.google.")),
        FamousApp("Google Wallet", listOf("Google Wallet", "Google Pay"), setOf("com.google.android.apps.walletnfcrel"),
            listOf("com.google.")),
        FamousApp("Google Authenticator", listOf("Google Authenticator"), setOf("com.google.android.apps.authenticator2"),
            listOf("com.google.")),
        FamousApp("Netflix", listOf("Netflix", "نتفليكس"), setOf("com.netflix.mediaclient"), listOf("com.netflix.")),
        FamousApp("Spotify", listOf("Spotify"), setOf("com.spotify.music"), listOf("com.spotify.")),
        FamousApp("PayPal", listOf("PayPal", "باي بال"), setOf("com.paypal.android.p2pmobile"), listOf("com.paypal.")),
        FamousApp("Binance", listOf("Binance", "بينانس"), setOf("com.binance.dev"), listOf("com.binance.")),
        FamousApp("Trust Wallet", listOf("Trust Wallet"), setOf("com.wallet.crypto.trustapp"), listOf("com.wallet.crypto.")),
        FamousApp("MetaMask", listOf("MetaMask"), setOf("io.metamask"), listOf("io.metamask")),
        FamousApp("Coinbase", listOf("Coinbase"), setOf("com.coinbase.android"), listOf("com.coinbase.", "org.toshi")),
        FamousApp("Revolut", listOf("Revolut"), setOf("com.revolut.revolut"), listOf("com.revolut."), distinct = false),
        FamousApp("X (Twitter)", listOf("Twitter", "تويتر"), setOf("com.twitter.android"), listOf("com.twitter.")),
        FamousApp("Signal", listOf("Signal"), setOf("org.thoughtcrime.securesms"), distinct = false),
        FamousApp("Viber", listOf("Viber", "فايبر"), setOf("com.viber.voip"), listOf("com.viber.")),
        FamousApp("Discord", listOf("Discord"), setOf("com.discord"), listOf("com.discord")),
        FamousApp("Zoom", listOf("Zoom", "Zoom Workplace"), setOf("us.zoom.videomeetings"), listOf("us.zoom."), distinct = false),
        FamousApp("Microsoft Outlook", listOf("Outlook", "Microsoft Outlook"), setOf("com.microsoft.office.outlook"),
            listOf("com.microsoft."), distinct = false),
        FamousApp("Microsoft Authenticator", listOf("Microsoft Authenticator"), setOf("com.azure.authenticator"),
            listOf("com.microsoft.", "com.azure.")),
        FamousApp("LinkedIn", listOf("LinkedIn"), setOf("com.linkedin.android"), listOf("com.linkedin.")),
        FamousApp("Amazon Shopping", listOf("Amazon", "Amazon Shopping"), setOf("com.amazon.mShop.android.shopping"),
            listOf("com.amazon."), distinct = false),
        FamousApp("AliExpress", listOf("AliExpress"), setOf("com.alibaba.aliexpresshd"), listOf("com.alibaba.")),
        FamousApp("SHEIN", listOf("SHEIN"), setOf("com.zzkko"), listOf("com.zzkko"), distinct = false),
        FamousApp("Temu", listOf("Temu"), setOf("com.einnovation.temu"), listOf("com.einnovation."), distinct = false),
        FamousApp("Free Fire", listOf("Free Fire", "Free Fire MAX", "فري فاير"), setOf("com.dts.freefireth", "com.dts.freefiremax"),
            listOf("com.dts.")),
        FamousApp("PUBG Mobile", listOf("PUBG Mobile", "PUBG MOBILE", "ببجي"), setOf("com.tencent.ig"),
            listOf("com.tencent.", "com.pubg.", "com.vng.", "com.rekoo.")),
        FamousApp("Minecraft", listOf("Minecraft", "ماين كرافت"), setOf("com.mojang.minecraftpe"), listOf("com.mojang.")),
        FamousApp("Roblox", listOf("Roblox"), setOf("com.roblox.client"), listOf("com.roblox.")),
        FamousApp("Clash of Clans", listOf("Clash of Clans", "كلاش اوف كلانس"), setOf("com.supercell.clashofclans"),
            listOf("com.supercell.")),
    )

    /** صلاحيات تجعل الانتحال خطيراً: هذا هو أسلوب الفيروسات البنكية بالضبط. */
    val DANGEROUS_WITH_IMPERSONATION = mapOf(
        "BIND_ACCESSIBILITY_SERVICE" to "خدمة الوصول (التحكم في الشاشة)",
        "BIND_DEVICE_ADMIN" to "مدير الجهاز",
        "READ_SMS" to "قراءة الرسائل",
        "RECEIVE_SMS" to "استقبال الرسائل",
        "SEND_SMS" to "إرسال الرسائل",
        "REQUEST_INSTALL_PACKAGES" to "تثبيت تطبيقات أخرى",
        "SYSTEM_ALERT_WINDOW" to "الرسم فوق التطبيقات",
        "BIND_NOTIFICATION_LISTENER_SERVICE" to "قراءة الإشعارات",
    )

    private val CONFUSABLES: Map<Char, String> = buildMap {
        // أرقام ورموز تشبه الحروف
        put('0', "o"); put('1', "i"); put('3', "e"); put('4', "a"); put('5', "s"); put('7', "t")
        put('@', "a"); put('$', "s"); put('|', "i"); put('!', "i")
        put('l', "i")
        // حروف سيريلية ويونانية تشبه اللاتينية
        val pairs = "аaеeоoрpсcхxуyіiјjѕsԁdһhӏiνvοoαaεeρpτtκkιiϲcհhոnսuᴜuɑaɡg"
        var i = 0
        while (i + 1 < pairs.length) { put(pairs[i], pairs[i + 1].toString()); i += 2 }
        // توحيد الحروف العربية
        put('أ', "ا"); put('إ', "ا"); put('آ', "ا"); put('ٱ', "ا"); put('ى', "ي"); put('ئ', "ي"); put('ؤ', "و")
        put('ة', "ه"); put('ڤ', "ف"); put('ک', "ك"); put('ی', "ي"); put('گ', "ك"); put('ق', "ك"); put('غ', "ج")
    }

    /** يحوّل الاسم لهيكل موحّد: حروف صغيرة، بلا مسافات ولا رموز، والحروف المتشابهة شكلاً تصبح نفس الحرف. */
    fun skeleton(s: String): String {
        val n = Normalizer.normalize(s, Normalizer.Form.NFKC).lowercase()
        val sb = StringBuilder()
        for (c in n) {
            val m = CONFUSABLES[c]
            when {
                m != null -> sb.append(m)
                c in 'ً'..'ٟ' || c == 'ـ' -> {} // التشكيل والتطويل
                c.isLetter() -> sb.append(c)
            }
        }
        return sb.toString().replace("rn", "m").replace("vv", "w")
    }

    /** مسافة Damerau-Levenshtein (حذف، إضافة، تبديل، أو قلب حرفين متجاورين). */
    fun editDistance(a: String, b: String): Int {
        val d = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) d[i][0] = i
        for (j in 0..b.length) d[0][j] = j
        for (i in 1..a.length) for (j in 1..b.length) {
            val cost = if (a[i - 1] == b[j - 1]) 0 else 1
            d[i][j] = minOf(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) d[i][j] = minOf(d[i][j], d[i - 2][j - 2] + 1)
        }
        return d[a.length][b.length]
    }

    /**
     * هل هذا التطبيق يدّعي أنه تطبيق مشهور وهو ليس هو؟
     * [labels] كل أسماء التطبيق الظاهرة (بكل اللغات)، [pkg] اسم الحزمة.
     */
    fun check(labels: List<String>, pkg: String): ImpersonationHit? {
        // حزمة تطبيق مشهور فعلاً: التوقيع هو اللي كيحسم، ماشي الاسم
        if (APPS.any { pkg in it.packages }) return null
        var best: ImpersonationHit? = null
        for (app in APPS) {
            if (app.vendors.any { pkg.startsWith(it) }) continue
            val hit = matchLabel(app, labels) ?: matchPackage(app, pkg) ?: continue
            if (best == null || (hit.strength == ImpStrength.STRONG && best.strength == ImpStrength.WEAK)) best = hit
        }
        return best
    }

    private fun matchLabel(app: FamousApp, labels: List<String>): ImpersonationHit? {
        var weak: ImpersonationHit? = null
        for (label in labels) {
            val s = skeleton(label)
            if (s.isEmpty()) continue
            for (k in app.normKeys) {
                if (s == k) return ImpersonationHit(app, label, ImpStrength.STRONG, "الاسم \"$label\" هو اسم ${app.name}")
                if (!app.distinct) continue
                if (k.length >= 8 && Math.abs(s.length - k.length) <= 1 && editDistance(s, k) == 1)
                    return ImpersonationHit(app, label, ImpStrength.STRONG, "الاسم \"$label\" مكتوب بطريقة تشبه ${app.name} (خطأ إملائي مقصود)")
                if (k.length >= 6 && s.contains(k) && weak == null)
                    weak = ImpersonationHit(app, label, ImpStrength.WEAK, "الاسم \"$label\" يحتوي على اسم ${app.name}")
            }
        }
        return weak
    }

    private fun matchPackage(app: FamousApp, pkg: String): ImpersonationHit? {
        if (!app.distinct) return null
        for (off in app.packages) {
            if (off.length < 12) continue
            if (Math.abs(pkg.length - off.length) <= 1 && editDistance(pkg, off) == 1)
                return ImpersonationHit(app, pkg, ImpStrength.STRONG, "اسم الحزمة $pkg يشبه حزمة ${app.name} الرسمية $off بفرق حرف واحد")
        }
        return null
    }
}
