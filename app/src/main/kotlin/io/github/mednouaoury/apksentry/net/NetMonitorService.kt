package io.github.mednouaoury.apksentry.net

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import io.github.mednouaoury.apksentry.core.DnsPackets
import io.github.mednouaoury.apksentry.core.DnsQuery
import io.github.mednouaoury.apksentry.core.DomainIntel
import io.github.mednouaoury.apksentry.core.DomainKind
import java.io.ByteArrayInputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * VPN محلي يعمل كجدار حماية لكل تطبيق على حدة، وكأداة مراقبة:
 * - التطبيقات المحظورة (قائمة [Firewall] المحفوظة): كل اتصالاتها تمر عبرنا ولا نمرّر شيئاً.
 *   يبقى الحظر بعد إغلاق ApkSentry، وبعد إعادة تشغيل الهاتف (BootReceiver أو "VPN دائم التشغيل").
 * - جلسة مراقبة لتطبيق واحد: نمرّر طلبات DNS عبرنا فنرى كل موقع يطلبه، ونمنع ما يختاره المستخدم.
 * لا نغادر الهاتف ولا نرسل أي شيء لأي خادم غير خادم DNS الأصلي للشبكة.
 */
class NetMonitorService : VpnService() {
    companion object {
        const val ACTION_START = "io.github.mednouaoury.apksentry.START"
        const val ACTION_STOP = "io.github.mednouaoury.apksentry.STOP"
        const val ACTION_REFRESH = "io.github.mednouaoury.apksentry.REFRESH"
        const val EXTRA_PKG = "pkg"
        const val EXTRA_LABEL = "label"
        const val EXTRA_MODE = "mode"
        private const val VPN_ADDR = "10.111.222.1"
        private const val DNS_ADDR = "10.111.222.2"
        private const val VPN_ADDR6 = "fd00:5e47:1::1"

        fun start(ctx: Context, pkg: String, label: String, mode: MonitorMode) {
            ctx.startService(Intent(ctx, NetMonitorService::class.java).setAction(ACTION_START)
                .putExtra(EXTRA_PKG, pkg).putExtra(EXTRA_LABEL, label).putExtra(EXTRA_MODE, mode.name))
        }

        /** ينهي جلسة العرض. التطبيقات المحظورة تبقى محظورة. */
        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, NetMonitorService::class.java).setAction(ACTION_STOP))
        }

        /** يعيد تطبيق قائمة الحظر (بعد إضافة أو حذف تطبيق، أو بعد إعادة التشغيل). */
        fun refresh(ctx: Context) {
            ctx.startService(Intent(ctx, NetMonitorService::class.java).setAction(ACTION_REFRESH))
        }
    }

    @Volatile
    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var pool: ExecutorService? = null
    private var upstream: List<InetAddress> = emptyList()
    private val writeLock = Any()

    /** جلسة العرض الحالية (إن وجدت). */
    @Volatile
    private var session: MonitorSession? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Firewall.load(this)
        when (intent?.action) {
            ACTION_START -> {
                val pkg = intent.getStringExtra(EXTRA_PKG)
                if (pkg != null) {
                    val label = intent.getStringExtra(EXTRA_LABEL) ?: pkg
                    val mode = runCatching { MonitorMode.valueOf(intent.getStringExtra(EXTRA_MODE) ?: "") }.getOrDefault(MonitorMode.WATCH)
                    NetMonitor.reset()
                    val s = MonitorSession(pkg, label, mode, signerTokens(pkg))
                    session = s
                    NetMonitor.session.value = s
                    if (mode == MonitorMode.BLOCK_ALL && !Firewall.isBlocked(this, pkg)) {
                        // "قطع الإنترنت" دائم: نحفظه في القائمة
                        Firewall.block(this, pkg)
                        return START_STICKY
                    }
                }
                apply()
            }
            ACTION_STOP -> {
                session = null
                NetMonitor.session.value = null
                apply()
            }
            // REFRESH، أو تشغيل من النظام ("VPN دائم التشغيل")، أو إعادة تشغيل الخدمة بعد قتلها
            else -> apply()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // المستخدم أوقف الـ VPN، أو شغّل VPN آخر: نتوقف ونبقي القائمة محفوظة
        stopVpn()
        session = null
        NetMonitor.session.value = null
        NetMonitor.error.value = "توقّف جدار الحماية (أُوقف الـ VPN أو شُغّل VPN آخر). التطبيقات المحظورة لها إنترنت الآن."
        super.onRevoke()
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    /** يبني الـ VPN حسب القائمة المحفوظة وجلسة المراقبة الحالية. */
    private fun apply() {
        val blocked = Firewall.blocked.value - packageName
        val s = session
        val watch = s?.takeIf { it.mode == MonitorMode.WATCH && it.pkg !in blocked }
        if (blocked.isEmpty() && watch == null) {
            stopVpn()
            stopSelf()
            return
        }
        stopVpn()
        upstream = currentDns()
        val builder = Builder()
            .setSession(if (watch != null) "ApkSentry: ${watch.label}" else "ApkSentry: جدار الحماية")
            .addAddress(VPN_ADDR, 32)
            .addDnsServer(DNS_ADDR)
            .addRoute(DNS_ADDR, 32)
            .setBlocking(true)
        if (watch == null) {
            // كل التطبيقات داخل الـ VPN محظورة: نوجّه كل اتصالاتها إلينا ولا نمرّر شيئاً
            builder.addRoute("0.0.0.0", 0)
            builder.addAddress(VPN_ADDR6, 128)
            builder.addRoute("::", 0)
        }
        // أثناء مراقبة تطبيق آخر نوجّه DNS فقط؛ التطبيقات المحظورة تبقى بدون أسماء مواقع (بدون إنترنت تقريباً)
        var added = 0
        for (p in blocked + listOfNotNull(watch?.pkg)) {
            try { builder.addAllowedApplication(p); added++ } catch (e: PackageManager.NameNotFoundException) { }
        }
        if (added == 0) {
            stopSelf()
            return
        }
        val pfd = try { builder.establish() } catch (e: Exception) { null }
        if (pfd == null) {
            NetMonitor.error.value = "تعذّر تشغيل جدار الحماية. تأكد أنك قبلت طلب VPN، وأنه لا يوجد VPN آخر يعمل."
            Firewall.running.value = false
            stopSelf()
            return
        }
        tun = pfd
        Firewall.running.value = blocked.isNotEmpty()
        pool = Executors.newFixedThreadPool(4)
        reader = Thread({ loop(pfd, blocked, watch) }, "apksentry-vpn").also { it.start() }
    }

    private fun stopVpn() {
        reader?.interrupt()
        reader = null
        try { tun?.close() } catch (_: IOException) { }
        tun = null
        pool?.shutdownNow()
        pool = null
        Firewall.running.value = false
    }

    private fun loop(pfd: ParcelFileDescriptor, blocked: Set<String>, watch: MonitorSession?) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val buf = ByteArray(32_767)
        val tokens = (session?.signerTokens ?: emptySet())
        val shown = session?.pkg
        // تطبيق واحد فقط داخل الـ VPN: نعرف صاحب كل حزمة بدون سؤال النظام
        val only = (blocked + listOfNotNull(watch?.pkg)).singleOrNull()
        try {
            while (!Thread.currentThread().isInterrupted) {
                val n = input.read(buf)
                if (n < 0) break
                if (n == 0) continue
                val q = DnsPackets.parseQuery(buf, n)
                if (q != null) {
                    val owner = only ?: ownerOf(17, ipOf(q.srcIp), q.srcPort, ipOf(q.dstIp), q.dstPort)
                    val kind = DomainIntel.classify(q.domain, tokens)
                    val isBlockedApp = watch == null || (owner != null && owner in blocked)
                    if (isBlockedApp || NetMonitor.isBlocked(q.domain)) {
                        write(output, DnsPackets.wrapResponse(q, DnsPackets.nxdomain(q)))
                        if (isBlockedApp) owner?.let(Firewall::recordAttempt)
                        if (owner == shown || owner == null) NetMonitor.record(q.domain, kind, true)
                    } else {
                        forwardAsync(q, output, kind)
                    }
                } else if (watch == null) {
                    // اتصال مباشر بعنوان IP: نسجّله ولا نمرّره
                    DnsPackets.parseRaw(buf, n)?.let { c ->
                        val owner = only ?: ownerOf(c.protoNumber, c.srcIp, c.srcPort, c.dstIp, c.dstPort)
                        owner?.let(Firewall::recordAttempt)
                        if (owner == shown || owner == null) NetMonitor.record("${c.dstIp}:${c.dstPort} (${c.protocol})", DomainKind.UNUSUAL, true, direct = true)
                    }
                }
            }
        } catch (_: IOException) {
        } catch (_: Exception) {
        }
    }

    private fun forwardAsync(q: DnsQuery, out: FileOutputStream, kind: DomainKind) {
        val executor = pool ?: return
        try {
            executor.execute {
                val resp = forward(q.payload)
                if (resp != null) {
                    write(out, DnsPackets.wrapResponse(q, resp))
                    NetMonitor.record(q.domain, kind, false, DnsPackets.answerIps(resp))
                } else {
                    NetMonitor.record(q.domain, kind, false)
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun ipOf(b: ByteArray): String = InetAddress.getByAddress(b).hostAddress ?: ""

    /** أندرويد 10+: يسأل النظام عن التطبيق صاحب الاتصال. */
    private val ownerCache = object : LinkedHashMap<String, String?>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String?>?) = size > 512
    }

    private fun ownerOf(proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): String? {
        if (Build.VERSION.SDK_INT < 29) return null
        val key = "$proto/$srcIp:$srcPort>$dstIp:$dstPort"
        synchronized(ownerCache) { if (ownerCache.containsKey(key)) return ownerCache[key] }
        val pkg = try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val uid = cm.getConnectionOwnerUid(proto, InetSocketAddress(srcIp, srcPort), InetSocketAddress(dstIp, dstPort))
            if (uid < 0) null else packageManager.getPackagesForUid(uid)?.firstOrNull()
        } catch (e: Exception) {
            null
        }
        synchronized(ownerCache) { ownerCache[key] = pkg }
        return pkg
    }

    /** نرسل الطلب لخادم DNS الحقيقي للشبكة. */
    private fun forward(payload: ByteArray): ByteArray? {
        val servers = upstream.ifEmpty { listOf(InetAddress.getByName("1.1.1.1"), InetAddress.getByName("8.8.8.8")) }
        for (server in servers) {
            try {
                DatagramSocket().use { s ->
                    protect(s)
                    s.soTimeout = 4000
                    s.send(DatagramPacket(payload, payload.size, server, 53))
                    val rb = ByteArray(4096)
                    val rp = DatagramPacket(rb, rb.size)
                    s.receive(rp)
                    return rb.copyOf(rp.length)
                }
            } catch (_: Exception) {
            }
        }
        return null
    }

    private fun write(out: FileOutputStream, data: ByteArray) {
        synchronized(writeLock) {
            try { out.write(data) } catch (_: IOException) { }
        }
    }

    private fun currentDns(): List<InetAddress> = try {
        val cm = getSystemService(ConnectivityManager::class.java)
        val net = cm.activeNetwork
        val servers = net?.let { cm.getLinkProperties(it)?.dnsServers } ?: emptyList()
        servers.sortedBy { if (it is Inet4Address) 0 else 1 }
    } catch (e: Exception) {
        emptyList()
    }

    /** كلمات شهادة توقيع التطبيق المراقَب (لنعرف إذا اتصل بموقع التحميل الذي عدّله). */
    private fun signerTokens(pkg: String): Set<String> = try {
        val pm = packageManager
        val bytes: ByteArray? = if (Build.VERSION.SDK_INT >= 28) {
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.let { si ->
                (if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory).firstOrNull()?.toByteArray()
            }
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures?.firstOrNull()?.toByteArray()
        }
        if (bytes == null) emptySet() else {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
            DomainIntel.repackTokens(cert.subjectX500Principal.name)
        }
    } catch (e: Exception) {
        emptySet()
    }
}
