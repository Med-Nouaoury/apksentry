package io.github.mednouaoury.apksentry.core

/** طلب DNS مستخرج من حزمة IPv4/UDP. */
class DnsQuery(
    val domain: String,
    val qtype: Int,
    /** بيانات DNS كما هي (بدون ترويسة IP و UDP). */
    val payload: ByteArray,
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
) {
    val typeName: String
        get() = when (qtype) { 1 -> "A"; 28 -> "AAAA"; 5 -> "CNAME"; 65 -> "HTTPS"; 15 -> "MX"; 16 -> "TXT"; 33 -> "SRV"; else -> qtype.toString() }
}

/** اتصال مباشر (بدون DNS) رأيناه في وضع المنع الكامل. */
class RawConnection(val dstIp: String, val dstPort: Int, val protocol: String)

/**
 * التعامل مع حزم الشبكة الخام التي تمر عبر VPN:
 * نقرأ طلبات DNS، نرد عليها، ونبني حزم IPv4/UDP صحيحة.
 */
object DnsPackets {
    /** يقرأ حزمة IPv4 فيها طلب DNS (UDP إلى المنفذ 53). يرجع null لأي شيء آخر. */
    fun parseQuery(pkt: ByteArray, len: Int = pkt.size): DnsQuery? {
        if (len < 28 || (pkt[0].toInt() ushr 4) != 4) return null
        val ihl = (pkt[0].toInt() and 0x0f) * 4
        if (ihl < 20 || len < ihl + 8 + 12 || pkt[9].toInt() != 17) return null
        val dstPort = pkt.u16be(ihl + 2)
        if (dstPort != 53) return null
        val udpLen = pkt.u16be(ihl + 4)
        val end = minOf(len, ihl + udpLen)
        if (end < ihl + 8 + 12) return null
        val payload = pkt.copyOfRange(ihl + 8, end)
        val (domain, qtype) = question(payload) ?: return null
        return DnsQuery(domain, qtype, payload, pkt.copyOfRange(12, 16), pkt.copyOfRange(16, 20), pkt.u16be(ihl), dstPort)
    }

    /** اتصال غير DNS (TCP أو UDP) في وضع المنع الكامل: نسجّله فقط. */
    fun parseRaw(pkt: ByteArray, len: Int = pkt.size): RawConnection? {
        if (len < 20) return null
        return when (pkt[0].toInt() ushr 4) {
            4 -> {
                val ihl = (pkt[0].toInt() and 0x0f) * 4
                val proto = pkt[9].toInt() and 0xff
                if (len < ihl + 4 || (proto != 6 && proto != 17)) return null
                // نسجّل فقط بداية اتصال TCP (SYN) حتى لا نكرر نفس الاتصال
                if (proto == 6 && (len < ihl + 14 || pkt[ihl + 13].toInt() and 0x02 == 0)) return null
                RawConnection(ipv4(pkt, 16), pkt.u16be(ihl + 2), if (proto == 6) "TCP" else "UDP")
            }
            6 -> {
                if (len < 44) return null
                val next = pkt[6].toInt() and 0xff
                if (next != 6 && next != 17) return null
                if (next == 6 && (len < 54 || pkt[40 + 13].toInt() and 0x02 == 0)) return null
                RawConnection(ipv6(pkt, 24), pkt.u16be(42), if (next == 6) "TCP" else "UDP")
            }
            else -> null
        }
    }

    /** يستخرج اسم الموقع ونوع الطلب من رسالة DNS. */
    fun question(dns: ByteArray): Pair<String, Int>? {
        if (dns.size < 12 || dns.u16be(4) < 1) return null
        val sb = StringBuilder()
        var p = 12
        var labels = 0
        while (true) {
            if (p >= dns.size) return null
            val n = dns[p].toInt() and 0xff
            if (n == 0) { p++; break }
            if (n and 0xc0 != 0 || p + 1 + n > dns.size || ++labels > 127) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..n) {
                val c = (dns[p + i].toInt() and 0xff).toChar()
                sb.append(if (c in ' '..'~') c.lowercaseChar() else '?')
            }
            p += 1 + n
        }
        if (p + 4 > dns.size) return null
        return sb.toString() to dns.u16be(p)
    }

    /** نهاية قسم السؤال في رسالة DNS. */
    private fun questionEnd(dns: ByteArray): Int {
        var p = 12
        while (p < dns.size) {
            val n = dns[p].toInt() and 0xff
            if (n == 0) return p + 5
            p += 1 + n
        }
        return dns.size
    }

    /** رد "الموقع غير موجود" (NXDOMAIN): هكذا نمنع الموقع. */
    fun nxdomain(q: DnsQuery): ByteArray {
        val end = minOf(questionEnd(q.payload), q.payload.size)
        val r = q.payload.copyOf(end)
        r[2] = (0x80 or (q.payload[2].toInt() and 0x01)).toByte() // QR=1 + RD كما في الطلب
        r[3] = 0x83.toByte() // RA=1, RCODE=3
        r[4] = 0; r[5] = 1
        for (i in 6..11) r[i] = 0
        return r
    }

    /** يبني حزمة IPv4/UDP تحمل رد DNS من الخادم الوهمي إلى التطبيق. */
    fun wrapResponse(q: DnsQuery, dns: ByteArray): ByteArray {
        val total = 20 + 8 + dns.size
        val p = ByteArray(total)
        p[0] = 0x45
        p.put16(2, total)
        p[6] = 0x40 // لا تجزئة
        p[8] = 64
        p[9] = 17
        System.arraycopy(q.dstIp, 0, p, 12, 4)
        System.arraycopy(q.srcIp, 0, p, 16, 4)
        p.put16(10, checksum(p, 0, 20))
        p.put16(20, q.dstPort)
        p.put16(22, q.srcPort)
        p.put16(24, 8 + dns.size)
        // checksum الخاص بـ UDP اختياري في IPv4 (صفر = غير مستعمل)
        System.arraycopy(dns, 0, p, 28, dns.size)
        return p
    }

    /** عناوين IPv4 في رد DNS (سجلات A). */
    fun answerIps(dns: ByteArray): List<String> {
        if (dns.size < 12) return emptyList()
        val an = dns.u16be(6)
        var p = questionEnd(dns)
        val out = ArrayList<String>()
        repeat(minOf(an, 32)) {
            if (p >= dns.size) return out
            // الاسم: مؤشر مضغوط أو تسميات
            if (dns[p].toInt() and 0xc0 == 0xc0) p += 2 else {
                while (p < dns.size && dns[p].toInt() != 0) p += 1 + (dns[p].toInt() and 0xff)
                p++
            }
            if (p + 10 > dns.size) return out
            val type = dns.u16be(p)
            val rdlen = dns.u16be(p + 8)
            p += 10
            if (type == 1 && rdlen == 4 && p + 4 <= dns.size) out.add(ipv4(dns, p))
            p += rdlen
        }
        return out
    }

    fun rcode(dns: ByteArray): Int = if (dns.size >= 4) dns[3].toInt() and 0x0f else -1

    fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i + 1 < off + len) { sum += ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff); i += 2 }
        if (i < off + len) sum += (b[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }

    private fun ipv4(b: ByteArray, o: Int) = "${b[o].toInt() and 0xff}.${b[o + 1].toInt() and 0xff}.${b[o + 2].toInt() and 0xff}.${b[o + 3].toInt() and 0xff}"

    private fun ipv6(b: ByteArray, o: Int): String =
        (0 until 8).joinToString(":") { Integer.toHexString(b.u16be(o + it * 2)) }

    private fun ByteArray.u16be(o: Int) = ((this[o].toInt() and 0xff) shl 8) or (this[o + 1].toInt() and 0xff)
    private fun ByteArray.put16(o: Int, v: Int) { this[o] = (v ushr 8).toByte(); this[o + 1] = v.toByte() }
}

/** تصنيف المواقع التي يتصل بها التطبيق. */
enum class DomainKind(val label: String) {
    SUSPICIOUS("مشبوه"),
    UNUSUAL("غير مألوف"),
    TRACKING("إعلانات أو تتبّع"),
    KNOWN("معروف"),
}

object DomainIntel {
    private val TRACKING = listOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "app-measurement.com", "google-analytics.com",
        "admob.com", "applovin.com", "applvn.com", "unityads.unity3d.com", "adjust.com", "appsflyer.com", "branch.io",
        "onesignal.com", "mixpanel.com", "amplitude.com", "vungle.com", "ironsrc.com", "supersonicads.com",
        "chartboost.com", "inmobi.com", "mopub.com", "adcolony.com", "fyber.com", "moloco.com", "liftoff.io",
        "bytedance.com", "pangle.io", "facebook.net", "graph.facebook.com", "crashlytics.com", "sentry.io",
    )
    private val KNOWN = Rules.KNOWN_DOMAINS + listOf(
        "googleusercontent.com", "googlevideo.com", "ytimg.com", "ggpht.com", "gvt1.com", "gvt2.com",
        "fbcdn.net", "instagram.com", "whatsapp.net", "cloudflare.com", "cloudfront.net", "akamaized.net",
        "akamaihd.net", "amazonaws.com", "azureedge.net", "fastly.net", "jsdelivr.net", "github.com",
        "githubusercontent.com", "play.google.com", "rockstargames.com", "epicgames.com", "steamcontent.com",
        "playstation.net", "xboxlive.com", "ea.com", "ubisoft.com", "netflix.com", "nflxvideo.net", "spotify.com",
    )
    /** كلمات عامة لا تكفي للربط مع اسم الموقِّع. */
    private val GENERIC = setOf("android", "google", "unknown", "apps", "mobile", "studio", "games", "group", "limited", "company")

    private fun matches(d: String, list: List<String>) = list.any { d == it || d.endsWith(".$it") }

    /**
     * [signerTokens]: كلمات من شهادة توقيع التطبيق (مثل APKVISION.ORG).
     * إذا اتصل التطبيق بموقع اسمه من نفس الكلمات، فهو غالباً موقع التحميل الذي عدّله.
     */
    fun classify(domain: String, signerTokens: Set<String>): DomainKind {
        val d = domain.lowercase().trimEnd('.')
        val sld = d.split('.').let { if (it.size >= 2) it[it.size - 2] else d }
        if (signerTokens.any { it.length >= 4 && it !in GENERIC && (sld == it || d.contains(it)) }) return DomainKind.SUSPICIOUS
        if (matches(d, TRACKING)) return DomainKind.TRACKING
        if (matches(d, KNOWN)) return DomainKind.KNOWN
        return DomainKind.UNUSUAL
    }

    private val SITE_SIGNER = Regex("apk|\\bmod\\b|\\.(org|com|net|io|co)\\b", RegexOption.IGNORE_CASE)

    /**
     * كلمات الموقِّع فقط إذا كان الموقِّع موقع تحميل (أعاد توقيع التطبيق).
     * المطور الحقيقي يتصل بموقعه بشكل طبيعي، فلا نقارن في حالته.
     */
    fun repackTokens(subject: String): Set<String> =
        if (SITE_SIGNER.containsMatchIn(subject)) signerTokens(subject) else emptySet()

    /** كلمات من نص الشهادة: CN=APKVISION.ORG,O=... → {apkvision} */
    fun signerTokens(subject: String): Set<String> =
        Regex("(?:CN|O|OU)=([^,]+)").findAll(subject).flatMap { m ->
            m.groupValues[1].lowercase().split(Regex("[^a-z0-9]+"))
        }.filter { it.length >= 4 && it !in setOf("org", "com", "net", "www") && it !in GENERIC }.toSet()
}
